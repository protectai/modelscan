from numpy import loadtxt
from xgboost import XGBClassifier
from sklearn.model_selection import train_test_split


def get_data():
    dataset = loadtxt("utils/pima-indians-diabetes.csv", delimiter=",")
    X = dataset[:, 0:8]
    Y = dataset[:, 8]
    # split data into train and test sets
    seed = 7
    test_size = 0.33
    x_train, x_test, y_train, y_test = train_test_split(
        X, Y, test_size=test_size, random_state=seed
    )

    return x_train, x_test, y_train, y_test


def train_model():
    x_train, _, y_train, _ = get_data()
    # fit model no training data
    model = XGBClassifier()
    model.fit(x_train, y_train)
    return model


def get_predictions(number_of_predictions, model):
    _, x_test, _, y_test = get_data()

    ypred = [int(x) for x in model.predict(x_test[0:number_of_predictions])]
    print(f"The model predicts: {ypred}")
    print(f"The true labels are: {y_test[0:number_of_predictions]}")
