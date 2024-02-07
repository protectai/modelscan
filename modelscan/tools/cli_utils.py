import click
from click import Command, Context, HelpFormatter
from typing import List, Optional, Tuple, Any, Union


class DefaultGroup(click.Group):
    """Invokes a subcommand marked with `default=True` if any subcommand not
    chosen.

    :param default_if_no_args: resolves to the default command if no arguments
                               passed.

    """

    def __init__(self, *args: object, **kwargs) -> None:  # type: ignore
        # To resolve as the default command.
        if not kwargs.get("ignore_unknown_options", True):
            raise ValueError("Default group accepts unknown options")
        self.ignore_unknown_options = True
        self.default_cmd_name = kwargs.pop("default", None)
        self.default_if_no_args = kwargs.pop("default_if_no_args", False)
        super(DefaultGroup, self).__init__(*args, **kwargs)  # type: ignore

    def set_default_command(self, command: Command) -> None:
        """Sets a command function as the default command."""
        cmd_name = command.name
        self.add_command(command)
        self.default_cmd_name = cmd_name

    def parse_args(self, ctx: Context, args: Any) -> List[str]:
        if not args and self.default_if_no_args:
            args.insert(0, self.default_cmd_name)
        return super(DefaultGroup, self).parse_args(ctx, args)

    def get_command(self, ctx: Context, cmd_name: str) -> Optional[Command]:
        if cmd_name not in self.commands:
            # No command name matched.
            ctx.arg0 = cmd_name  # type: ignore
            cmd_name = self.default_cmd_name
        return super(DefaultGroup, self).get_command(ctx, cmd_name)

    def resolve_command(
        self, ctx: Context, args: Any
    ) -> Tuple[Optional[str], Optional[Command], List[str]]:
        base = super(DefaultGroup, self)
        cmd_name, cmd, args = base.resolve_command(ctx, args)  # type: ignore
        if hasattr(ctx, "arg0"):
            args.insert(0, ctx.arg0)
            cmd_name = cmd.name
        return cmd_name, cmd, args

    def format_commands(self, ctx: Context, formatter: HelpFormatter) -> None:
        formatter = DefaultCommandFormatter(self, formatter, mark="*")
        return super(DefaultGroup, self).format_commands(ctx, formatter)

    def command(self, *args: Any, **kwargs: Any) -> Union[Any, Command]:
        default = kwargs.pop("default", False)
        decorator = super(DefaultGroup, self).command(*args, **kwargs)
        if not default:
            return decorator

        def _decorator(f: Command) -> Union[Any, Command]:
            cmd = decorator(f)
            self.set_default_command(cmd)
            return cmd

        return _decorator


class DefaultCommandFormatter(HelpFormatter):
    """Wraps a formatter to mark a default command."""

    def __init__(self, group: DefaultGroup, formatter: HelpFormatter, mark: str = "*"):
        self.group = group
        self.formatter = formatter
        self.mark = mark

    def __getattr__(self, attr):  # type: ignore
        return getattr(self.formatter, attr)

    def write_dl(self, rows, *args, **kwargs):  # type: ignore
        rows_ = []  # type: ignore
        for cmd_name, help in rows:
            if cmd_name == self.group.default_cmd_name:
                rows_.insert(0, (cmd_name + self.mark, help))
            else:
                rows_.append((cmd_name, help))
        return self.formatter.write_dl(rows_, *args, **kwargs)
