![ModelScan Banner](https://github.com/protectai/modelscan/raw/main/imgs/PAI-ModelScan-banner-080323-space.png)
[![bandit](https://github.com/protectai/modelscan/actions/workflows/bandit.yml/badge.svg)](https://github.com/protectai/modelscan/actions/workflows/bandit.yml)
[![build](https://github.com/protectai/modelscan/actions/workflows/build.yml/badge.svg)](https://github.com/protectai/modelscan/actions/workflows/build.yml)
[![black](https://github.com/protectai/modelscan/actions/workflows/black.yml/badge.svg)](https://github.com/protectai/modelscan/actions/workflows/black.yml)
[![mypy](https://github.com/protectai/modelscan/actions/workflows/mypy.yml/badge.svg)](https://github.com/protectai/modelscan/actions/workflows/mypy.yml)
[![tests](https://github.com/protectai/modelscan/actions/workflows/test.yml/badge.svg)](https://github.com/protectai/modelscan/actions/workflows/test.yml)
[![Supported Versions](https://img.shields.io/pypi/pyversions/modelscan.svg)](https://pypi.org/project/modelscan)
[![pypi Version](https://img.shields.io/pypi/v/modelscan)](https://pypi.org/project/modelscan)
[![License: Apache 2.0](https://img.shields.io/crates/l/apa)](https://opensource.org/license/apache-2-0/)
# ModelScan: Protection Against Model Serialization Attacks
Machine Learning (ML) models are shared publicly over the internet, within teams and across teams. The rise of Foundation Models have resulted in public ML models being increasingly consumed for further training/fine tuning. ML Models are increasingly used to make critical decisions and power mission-critical applications.
Despite this, models are not scanned with the rigor of a PDF file in your inbox.

This needs to change, and proper tooling is the first step.

![ModelScan Preview](/imgs/modelscan-unsafe-model.gif)

ModelScan is an open source project that scans models to determine if they contain 
unsafe code. It is the first model scanning tool to support multiple model formats. 
ModelScan currently supports: H5, Pickle, and SavedModel formats. This protects you 
when using PyTorch, TensorFlow, Keras, Sklearn, XGBoost, with more on the way.

## TL;DR

If you are ready to get started scanning your models, it is simple:

```bash
pip install modelscan
```

With it installed, scan a model:

```bash
modelscan -p /path/to/model_file.h5
```

## Why You Should Scan Models

Models are often created from automated pipelines, others may come from a data scientist’s laptop. In either case the model needs to move from one machine to another before it is used. That process of saving a model to disk is called serialization.

A **Model Serialization Attack** is where malicious code is added to the contents of a model during serialization(saving) before distribution — a modern version of the Trojan Horse. 

The attack functions by exploiting the saving and loading process of models. When you load a model with `model = torch.load(PATH)`, PyTorch opens the contents of the file and begins to running the code within. The second you load the model the exploit has executed. 

A **Model Serialization Attack** can be used to execute:

- Credential Theft(Cloud credentials for writing and reading data to other systems in your environment)
- Data Theft(the request sent to the model)
- Data Poisoning(the data sent after the model has performed its task)
- Model Poisoning(altering the results of the model itself)

These attacks are incredibly simple to execute and you can view working examples in our 📓[notebooks](https://github.com/protectai/modelscan/tree/main/notebooks) folder.

## Getting Started

### How ModelScan Works

If loading a model with your machine learning framework automatically executes the attack, 
how does ModelScan check the content without loading the malicious code?

Simple, it reads the content of the file one byte at a time just like a string, looking for 
code signatures that are unsafe. This makes it incredibly fast, scanning models in the time it
takes for your computer to process the total filesize from disk(seconds in most cases). It also secure.

ModelScan ranks the unsafe code as:

* CRITICAL
* HIGH
* MEDIUM
* LOW

![ModelScan Flow Chart](/imgs/model_scan_flow_chart.png)

If an issue is detected, reach out to the author's of the model immediately to determine the cause.

In some cases, code may be embedded in the model to make things easier to reproduce as a data scientist, but
it opens you up for attack. Use your discretion to determine if that is appropriate for your workloads.

### What Models and Frameworks Are Supported?

This will be expanding continually, so look out for changes in our release notes. 

At present, ModelScan supports any Pickle derived format and many others:

| ML Library                                   | API                                                                                                        | Serialization Format                | modelscan support |
|----------------------------------------------|------------------------------------------------------------------------------------------------------------|-------------------------------------|-------------------|
| Pytorch                                      | [torch.save() and torch.load()](https://pytorch.org/tutorials/beginner/saving_loading_models.html )        | Pickle                              | Yes               |
| Tensorflow                                   | [tf.saved_model.save()](https://www.tensorflow.org/guide/saved_model)                                      | Protocol Buffer                     | Yes               |
| Keras                                        | [keras.models.save(save_format= 'h5')](https://www.tensorflow.org/guide/keras/serialization_and_saving)    | HD5 (Hierarchical Data Format)      | Yes               |
|                                              | [keras.models.save(save_format= 'keras')](https://www.tensorflow.org/guide/keras/serialization_and_saving) | Keras V3 (Hierarchical Data Format) | Yes               |
| Classic ML Libraries (Sklearn, XGBoost etc.) | pickle.dump(), dill.dump(), joblib.dump(), cloudpickle.dump()                                              | Pickle, Cloudpickle, Dill, Joblib   | Yes               |

### Installation 
ModelScan is installed on your systems as a Python package(Python 3.8 to 3.11 supported). As shown from above you can install
it by running this in your terminal:

```bash
pip install modelscan
```

To include it in your project's dependencies so it is available for everyone, add it to your `requirements.txt`
or `pyproject.toml` like this:

```toml
modelscan = ">=0.1.1"
```

### Using ModelScan via CLI

ModelScan supports the following arguments via the CLI:

| Usage                                                                            | Argument         | Explanation                                             | 
|----------------------------------------------------------------------------------|------------------|---------------------------------------------------------|
| ```modelscan -h ```                                                              | -h or --help     | View usage help                                         |
| ```modelscan -v ```                                                              | -v or --version  | View version information                                |
| ```modelscan -p /path/to/model_file```                                           | -p or --path     | Scan a locally stored model                             |
| ```modelscan -p /path/to/model_file --settings-file ./modelscan-settings.toml``` | --settings-file  | Scan a locally stored model using custom configurations |
| ```modelscan create-settings-file```                                             | -l or --location | Create a configurable settings file                     |
| ```modelscan -r```                                             | -r or --reporting-format | Format of the output. Options are console,       json, or custom (to be defined in settings-file). Default is console                    |
| ```modelscan -r reporting-format -o file-name```                                             | -o or --output-file | Optional file name for output report                  |
| ```modelscan --show-skipped```                          | --show-skipped | Print a list of files that were skipped      during the scan   |


Remember models are just like any other form of digital media, you should scan content from any untrusted source before use.

##### CLI Exit Codes
The CLI exit status codes are:
- `0`: Scan completed successfully, no vulnerabilities found
- `1`: Scan completed successfully, vulnerabilities found
- `2`: Scan failed, modelscan threw an error while scanning
- `3`: No supported files were passed to the tool
- `4`: Usage error, CLI was passed invalid or incomplete options

### Understanding The Results

Once a scan has been completed you'll see output like this if an issue is found:

![ModelScan Scan Output](https://github.com/protectai/modelscan/raw/main/imgs/cli_output.png)

Here we have a model that has an unsafe operator for both `ReadFile` and `WriteFile` in the model.
Clearly we do not want our models reading and writing files arbitrarily. We would now reach out 
to the creator of this model to determine what they expected this to do. In this particular case
it allows an attacker to read our AWS credentials and write them to another place. 

That is a firm NO for usage.

## Integrating ModelScan In Your ML Pipelines and CI/CD Pipelines

Ad-hoc scanning is a great first step, please drill it into yourself, peers, and friends to do
this whenever they pull down a new model to explore. It is not sufficient to improve security
for production MLOps processes.

Model scanning needs to be performed more than once to accomplish the following:

1. Scan all pre-trained models before loading it for further work to prevent a compromised
model from impacting your model building or data science environments.
2. Scan all models after training to detect a supply chain attack that compromises new models.
3. Scan all models before deploying to an endpoint to ensure that the model has not been compromised after storage.

The red blocks below highlight this in a traditional ML Pipeline.
![MLOps Pipeline with ModelScan](https://github.com/protectai/modelscan/raw/main/imgs/ml_ops_pipeline_model_scan.png)

The processes would be the same for fine-tuning or any modifications of LLMs, foundational models, or external model.

Embed scans into deployment processes in your CI/CD systems to secure usage
as models are deployed as well if this is done outside your ML Pipelines.

## Diving Deeper

Inside the 📓[**notebooks**](https://github.com/protectai/modelscan/tree/main/notebooks) folder you can explore a number of notebooks that showcase
exactly how Model Serialization Attacks can be performed against various ML Frameworks like TensorFlow and PyTorch.

To dig more into the meat of how exactly these attacks work check out 🖹 [**Model Serialization Attack Explainer**](https://github.com/protectai/modelscan/blob/main/docs/model_serialization_attacks.md).

If you encounter any other approaches for evaluating models in a static context, please reach out, we'd love
to learn more!

## Licensing

Copyright 2023 Protect AI 

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

   http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

## Acknowledgements

We were heavily inspired by [Matthieu Maitre](http://mmaitre314.github.io) who built [PickleScan](https://github.com/mmaitre314/picklescan).
We appreciate the work and have extended it significantly with ModelScan. ModelScan is OSS’ed in the similar spirit as PickleScan.

## Contributing 

We would love to have you contribute to our open source ModelScan project. 
If you would like to contribute, please follow the details on [Contribution page](https://github.com/protectai/modelscan/blob/main/CONTRIBUTING.md). 

 
