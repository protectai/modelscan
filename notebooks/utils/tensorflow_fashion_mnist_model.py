import tensorflow as tf
import numpy as np
import matplotlib.pyplot as plt

tf.compat.v1.logging.set_verbosity(tf.compat.v1.logging.ERROR)


class_names = [
    "T-shirt/top",
    "Trouser",
    "Pullover",
    "Dress",
    "Coat",
    "Sandal",
    "Shirt",
    "Sneaker",
    "Bag",
    "Ankle boot",
]


def get_data(test_data_only=False):
    fashion_mnist = tf.keras.datasets.fashion_mnist
    (train_images, train_labels), (test_images, test_labels) = fashion_mnist.load_data()
    train_images = train_images / 255.0
    test_images = test_images / 255.0

    if test_data_only:
        return test_images, test_labels
    else:
        return train_images, train_labels, test_images, test_labels


def plot_image(pred, img):
    plt.grid(False)
    plt.xticks([])
    plt.yticks([])

    plt.imshow(img, cmap=plt.cm.binary)
    plt.xlabel("{}".format(pred), color="blue")


def train_model():
    model = tf.keras.Sequential(
        [
            tf.keras.layers.Flatten(input_shape=(28, 28)),
            tf.keras.layers.Dense(128, activation="relu"),
            tf.keras.layers.Dense(10),
            tf.keras.layers.Softmax(),
        ]
    )

    model.compile(
        optimizer="adam",
        loss=tf.keras.losses.SparseCategoricalCrossentropy(from_logits=False),
        metrics=["accuracy"],
    )

    train_images, train_labels, test_images, test_labels = get_data()

    model.fit(train_images, train_labels, epochs=10)

    _, test_acc = model.evaluate(test_images, test_labels, verbose=1)

    print("\nModel trained with test accuracy:", test_acc)

    return model


def get_predictions(model, number_of_predictions):
    get_test_data_only = True
    test_images, test_labels = get_data(get_test_data_only)

    model_output = model.predict(test_images[0:number_of_predictions])
    prediction_probabilities = [np.max(prob) for prob in model_output]
    prediction_labels = [class_names[np.argmax(pred)] for pred in model_output]
    print(
        f"\nThe model predicts: {prediction_labels} with probabilities: {np.round(prediction_probabilities,5)*100}"
    )
    true_labels = [class_names[label] for label in test_labels[0:number_of_predictions]]
    print(f"\nThe true labels are {true_labels}")
    plot_predictions(
        number_of_predictions, test_images[0:number_of_predictions], prediction_labels
    )

    return None


def plot_predictions(number_of_predictions, test_data, model_predictions):
    for index in range(0, number_of_predictions):
        plt.subplot(1, number_of_predictions, index + 1)
        plot_image(model_predictions[index], test_data[index])
