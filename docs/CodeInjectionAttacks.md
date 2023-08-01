# Code Injection Attacks

A key ML asset is a ML model, and the ability to store, and retrieve models efficiently and securely is crucial.  There are various ways in which a ML model can be saved. Depending on the ML library, and well as the intended use, some of the common formats in which a ML model can be saved are: Pickle, HDF5 (Hierarchical Data Format), TensorFlow SavedModel, Model Checkpoints, and ONNX (Open Neural Network Exchange). 

There are many ways ML models can be compromised such as using adversarial machine learning, denial of service attacks, and/or code injection attacks. Though all aforementioned attacks pose significant threat, in this repo, we will be focussing on code injection attacks.  In code injection attacks, malicious code is injected in a model, and saved. When a user loads the model, the malicious code is executed whilst the model behaves as expected. In this sense, compromised models can become an effective attack vector. 

Some of the popular ML libraries, and their model serialization formats are explained next

- PyTorch
    
    PyTorch models can be saved and loaded using `torch.save()` and `torch.load()` . PyTorch save and load commands use pickle for saving and loading data/models.
    
    Pickle allows serialization (conversion to byte stream) and deserialization (conversion from byte stream to Python objects), which means that models can move across different systems and platforms. This makes model portability a breeze, which is essential for ML projects that require models to be deployed in different environments. However, pickled files can have malicious code injected into them. Upon unpickling, the injected code gets executed, and systems may get compromised. 
    
- Tensorflow
    
    Tensorflow models can be saved using SavedModel (`model.save()`). The Tensorflow operators of `ReadFile()` and `WriteFile()` can be used to access files from different directories such as local directory as well as `~/.ssh`  and `/tmp/`
    
    In addition, Tensorflow allows for custom operators to be loaded using `tf.load_op_library()` . The shared object file can execute code when loaded using `tf.load_op_library()`
    
- Keras
    
    Keras is high level API of Tensorflow. Keras models can be saved using Tensorflow savedmodel as well as the (older) h5 format. Keras models can have a lambda layer added to them which can be used for arbitrary code execution. 
    
- ONNX
    
    ONNX stands for Open Neural Network Exchange, and is designed to make it easier to move ML models across frameworks and different hardwares. ONNX has a predefined set of operators, making it one of the most secure formats for model storage and sharing. Though ONNX also allows for cutom operators to be loaded using `custom_op_library`
    
    Custom operators in ONNX are also shared object files, and hence capable of executing code when loaded.