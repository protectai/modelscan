# Notebooks demonstarting Model Serialization Attacks

To learn more about model serialization attacks, please follow the [link](./docs/model_serialization_attacks.md). 

In the notebooks directory, the notebooks included focus on model serialization attack on a particular ML library. To this end, both safe and unsafe models of a given ML library behave the same way performance wise i.e., the unsafe model can also predict/classify as well as the safe model albeit also executes the malicious code injected in it. 

In addition to demonstrate the model serialization attacks, the safe and unsafe modelscan results are also outlined. The ML libraries covered are:

# PyTorch
Pytorch models can be saved and loaded using pickle. modelscan can scan models saved using pickle. A notebook to illustrate:

- PyTorch model serialization attack using `os.system()`
- modelscan usage and expected scan results with safe and unsafe PyTorch models

is added here: [./notebooks/pytorch_sentiment_analysis.ipynb](pytorch_sentiment_analysis.ipynb). The PyTorch model used in the notebook is for sentiment analysis of tweets and downloaded from [Hugging Face](https://huggingface.co/cardiffnlp/twitter-roberta-base-sentiment). 


# Tensorflow
Tensorflow uses saved_model for model serialization. modelscan can scan models saved using saved_model. A notebook to illustrate

- Tensorflow model serializationa attack using `tf.io.read_file()` and `tf.io.write_file()`
- ModelScan usage and expected scan results with safe and unsafe tensorflow models

is added here: [./notebooks/tensorflow_fashion_mnist.ipynb](./tensorflow_fashion_mnist.ipynb). The tensorflow model used in the notebook is for classification of fashion/clothing items and trained on fashion mnist dataset. [Reference to Tensorflow tutorial](https://www.tensorflow.org/tutorials/keras/classification). 


# Keras
Keras uses saved_model and h5 for model serialization. A notebook to illustrate

- Keras model serializationa attack using `keras.layers.lambda()`
- ModelScan usage and expected scan results with safe and unsafe Keras models

is added here: [./notebooks/keras_fashion_mnist.ipynb](./keras_fashion_mnist.ipynb). The Keras model used in the notebook is for classification of fashion/clothing items and trained on fashion mnist dataset. [Reference to Keras tutorial](https://www.tensorflow.org/tutorials/keras/classification). 


# Classical ML libraries

modelscan also supports all ML libraries that support pickle for their model serialization, such as Sklearn, XGBoost, Catboost etc. A notebook to illustrate

- XGBoost model serializationa attack using `os.system()`
- ModelScan usage and expected scan results with safe and unsafe XGBoost models

is added here: [./notebooks/xgboost_diabetes_classification.ipynb](./xgboost_diabetes_classification.ipynb). The XGBoost model used in the notebook is for classification of [diabetic patients](https://www.kaggle.com/datasets/uciml/pima-indians-diabetes-database). 


