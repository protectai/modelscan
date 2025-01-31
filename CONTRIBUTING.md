# 👩‍💻 CONTRIBUTING

Welcome! We're glad to have you. If you would like to report a bug, request a new feature or enhancement, follow [this link](https://github.com/protectai/modelscan/issues/new/choose).

## ❗️ Requirements

1. Python

   `modelscan` requires python version `>=3.9` and `<3.13`

2. Poetry

   The following install commands require [Poetry](https://python-poetry.org/). To install Poetry you can follow [this installation guide](https://python-poetry.org/docs/#installation). Poetry can also be installed with brew using the command `brew install poetry`.

## 💪 Developing with modelscan

1. Clone the repo

   ```bash
   git clone git@github.com:protectai/modelscan.git
   ```

2. To install development dependencies to your environment and set up the cli for live updates, run the following command in the root of the `modelscan` directory:

   ```bash
   make install-dev
   ```

3. You are now ready to start developing!

   Run a scan with the cli with the following command:

   ```bash
   modelscan -p /path/to/file
   ```

## 📝 Submitting Changes

Thanks for contributing! In order to open a PR into the `modelscan` project, you'll have to follow these steps:

1. Fork the repo and clone your fork locally
2. Run `make install-dev` from the root of your forked repo to setup your environment
3. Make your changes
4. Submit a pull request

After these steps have been completed, someone on our team at Protect AI will review the code and help merge in your changes!