# Notebooks demonstarting Model Serialization Attacks

To learn more about model serialization attacks, please see [Model Serialization Attacks](../docs/model_serialization_attacks.md). 

In the notebooks directory, the notebooks included focus on model serialization attack on a particular ML library. We carry out a stealth mock exfiltration attack. Stealth, because the model still works as before the attack. Mock, because we don't actually carry out an exfiltration attack but show a POC where it can be carried out. 

In addition to demonstrate the model serialization attacks, the safe and unsafe modelscan results are also outlined. The ML libraries covered are:

<br></br>
# PyTorch
Pytorch models can be saved and loaded using pickle. modelscan can scan models saved using pickle. A notebook to illustrate the following is added. 

- Exfiltrate AWS secret on a PyTorch model using `os.system()`
- modelscan usage and expected scan results with safe and unsafe PyTorch models

📓 Notebook:[pytorch_sentiment_analysis.ipynb](pytorch_sentiment_analysis.ipynb)

🔗 Model: [cardiffnlp/twitter-roberta-base-sentiment](https://huggingface.co/cardiffnlp/twitter-roberta-base-sentiment)

<br> </br>
# Tensorflow
Tensorflow uses saved_model for model serialization. modelscan can scan models saved using saved_model. A notebook to illustrate the following is added. 

- Exfiltrate AWS secret on a Tensorflow model `tf.io.read_file()` and `tf.io.write_file()`
- ModelScan usage and expected scan results with safe and unsafe tensorflow models

📓 Notebook: [tensorflow_fashion_mnist.ipynb](./tensorflow_fashion_mnist.ipynb)

🔗 Model: Classification of fashion mnist dataset. [Reference to Tensorflow tutorial](https://www.tensorflow.org/tutorials/keras/classification). 

<br></br>
# Keras
Keras uses saved_model and h5 for model serialization. A notebook to illustrate the following is added. 

- Exfiltrate AWS secret on a Keras model using `keras.layers.lambda()`
- ModelScan usage and expected scan results with safe and unsafe Keras models

📓 Notebook: [keras_fashion_mnist.ipynb](./keras_fashion_mnist.ipynb).

🔗 Model: Classification of fashion mnist dataset. [Reference to Tensorflow tutorial](https://www.tensorflow.org/tutorials/keras/classification). 

<br></br>
# Classical ML libraries

modelscan also supports all ML libraries that support pickle for their model serialization, such as Sklearn, XGBoost, Catboost etc. A notebook to illustrate the following is added. 

- Exfiltrate AWS secret on a XGBoost model using `os.system()`
- ModelScan usage and expected scan results with safe and unsafe XGBoost models

📓 Notebook: [xgboost_diabetes_classification.ipynb](./xgboost_diabetes_classification.ipynb)

🔗 Model: Classification of diabetes. [Link to PIMA Indian diabetes dataset](https://www.kaggle.com/datasets/uciml/pima-indians-diabetes-database)



