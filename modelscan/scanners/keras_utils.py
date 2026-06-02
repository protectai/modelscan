from typing import Any, List


def get_keras_layer_names(config: Any) -> List[str]:
    layer_names: List[str] = []

    if isinstance(config, dict):
        class_name = config.get("class_name")
        if isinstance(class_name, str):
            layer_names.append(class_name)

        for value in config.values():
            layer_names.extend(get_keras_layer_names(value))

    elif isinstance(config, list):
        for item in config:
            layer_names.extend(get_keras_layer_names(item))

    return layer_names
