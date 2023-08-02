
# modelscan
<p align="center">
<a href="https://github.com/protectai/modelscan/blob/main/imgs/logo.png">
  <img src="https://github.com/protectai/modelscan/blob/main/imgs/logo.png?raw=true" width="200">  
</a>

```python
# malicious code injection 
command = "system"
malicious_code = """cat ~/.aws/secrets""" 
```

<a href="https://github.com/protectai/modelscan/blob/main/imgs/attack_example.png">
  <img src="https://github.com/protectai/modelscan/blob/main/imgs/attack_example.png?raw=true" width="700">
</a>

</p>
<br />


<p align="center"> modelscan is an open-source tool for scanning Machine Learning (ML) models. With modelscan, the ML models can be scanned *without* loading them in your machines: saving you from potential malicious   [code injection attacks](/docs/CodeInjectionAttacks.md)


<br /><br />

<p align="center">
<a href="https://github.com/protectai/modelscan/blob/main/imgs/cli_output.png">
  <img src="https://github.com/protectai/modelscan/blob/main/imgs/cli_output.png?raw=true" width="700">
</a>


</p>

<br /><br />

```
Scanning /Users/Documents/models_to_scan/model.pkl 

--- Summary ---

Total Issues: 1

Total Issues by Severity:
  - LOW: 0
  - MEDIUM: 0
  - HIGH: 0
  - CRITICAL: 1

--- Issues by Severity ---

--- CRITICAL ---

Unsafe operator found:
  - Severity: CRITICAL
  - Description: Use of unsafe operator 'system' from module 'posix'
  - Source: /Users/Documents/models_to_scan/model.pkl
```





<br /><br />

## How modelscan works 
<br /><br />

<p align="center">
<a href="https://github.com/protectai/modelscan/blob/main/imgs/flow_chart.png">
  <img src="https://github.com/protectai/modelscan/blob/main/imgs/flow_chart.png?raw=true" width="700">
</a>
<br />
Fig 1: An outline for scanning models using modelscan.
</p>
<br />


<br /><br />

## Getting Started 
1. Install modelscan:

    ```shell
    pip install modelscan
    ```

2. Scan the model:

    For scanning model from local directory:

    ```shell
    modelscan -p /path/to/model_file
    ```

    For scanning model from huggingface:

    ```shell
    modelscan -hf /repo_id/model_file
    ```

3. Inspect the modelscan result:

    The modelscan results include:
    
    - List of files scanned. 
    - List of files _not_ scanned. 
    - A summary of scan results categorized using modelscan severity levels of: CRITICAL, HIGH, MEDIUM, and LOW. 
    - A detailed description of potentially malicious code found under each severity level. 

    More information about modelscan severity levels can be found [here](docs/SeverityLevels.md).

    
   

<br /><br />

## [Which ML Models can be Scanned using modelscan](#which-ml-models-can-be-scanned-using-modelscan)
At the moment, modelscan supports the following ML libraries, and their corresponding serialization formats:
| ML Library | API | Serialization Format| modelscan support 
| ----| ----|  ----| ----|
| Pytorch | [torch.save() and torch.load()](https://pytorch.org/tutorials/beginner/saving_loading_models.html )| Pickle | Yes 
| Tensorflow| [tf.saved_model.save()](https://www.tensorflow.org/guide/saved_model)| Protocol Buffer | Yes 
| Keras| [keras.models.save(save_format= 'h5')](https://www.tensorflow.org/guide/keras/serialization_and_saving)| HD5 (Hierarchical Data Format) | Yes 
| | [keras.models.save(save_format= 'keras')](https://www.tensorflow.org/guide/keras/serialization_and_saving)| HD5 (Hierarchical Data Format) | No
| Classic ML Libraries (Sklearn, XGBoost etc.)| pickle.dump(), dill.dump(), joblib.dump(), cloudpickle.dump() | Pickle, Cloudpickle, Dill, Joblib | Yes 






<br /><br />
## Example Notebooks

Example notebooks outlining code injection attacks on ML models from the following libraries are in `./examples`:
<br /><br />
### PyTorch   

Pytorch models can be saved and loaded using pickle. modelscan can scan models saved using pickle. A notebook to illustrate the modelscan usage and expected results with a pytorch (GPT2) model (downloaded from huggingface) is added here: `./examples/pytorch_sentiment_analysis.ipynb`
<br /><br />
### Tensorflow

Tensorflow uses saved_model for model serialization. modelscan can scan models saved using saved_model. A notebook to illustrate the modelscan usage and expected results with tensorflow model is added here: `examples/tensorflow_fashion_mnist.ipynb`
<br /><br />
### Keras
Keras uses saved_model and h5 for model serialization. modelscan can scan models saved using saved_model and h5. A notebook to illustrate the modelscan usage and expected results with keras model is added here: `examples/keras_fashion_mnist.ipynb` 
<br /><br />
### Classical ML libraries
modelscan also supports all ML libraries that support pickle for their model serialization, such as Sklearn, XGBoost, Catboost etc. A notebook to illustrate the modelscan usage and expected results with XGBoost model is added here: `./examples/xgboost_diabetes_classification.ipynb`. 


<br /><br />

## modelscan CLI arguments:

The modelscan CLI arguments and their usage is as follows:

| argument | Explanation| Usage 
| ----| ----| ----|
| --help | For getting help | ```modelscan --help ```
| -p or --path | For scanning a model file in local directory | ```modelscan -p /path/to/model_file```
| -hf or --huggingface | For scanning a model file on hugging face| ```modelscan -hf /repo/model_file```
|-l or --log |Level of log messages to be disaplyed (default: INFO) | ``` modelscan -p path/to/model/file -l [CRITICAL\|ERROR\|WARNING\|INFO\|DEBUG] ```

<br /><br />

## Contributing 

We would love to have you contribute to our open source modelscan project. If you would like to contribute, please follow the details on [Contribution page](./CONTRIBUTING.md). 

 