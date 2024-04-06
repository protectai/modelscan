from typing import Any, Final
from transformers import AutoModelForSequenceClassification
from transformers import AutoTokenizer
import numpy as np
from scipy.special import softmax
import csv
import urllib.request
import torch

SENTIMENT_TASK: Final[str] = "sentiment"


def _preprocess(text: str) -> str:
    """
    Preprocess the given text by replacing usernames starting with '@' with '@user'
    and replacing URLs starting with 'http' with 'http'.

    Args:
        text: The input text to be preprocessed.

    Returns:
        The preprocessed text.
    """
    new_text: list[str] = []

    for t in text.split(" "):
        t = "@user" if t.startswith("@") and len(t) > 1 else t
        t = "http" if t.startswith("http") else t
        new_text.append(t)
    return " ".join(new_text)


def download_model(safe_model_path: str) -> None:
    """
    Download a pre-trained model and saves it to the specified path.

    Args:
        safe_model_path: The path where the model will be saved.
    """
    pretrained_model_name = f"cardiffnlp/twitter-roberta-base-{SENTIMENT_TASK}"
    model = AutoModelForSequenceClassification.from_pretrained(pretrained_model_name)
    torch.save(model, safe_model_path)


def predict_sentiment(text: str, model: Any) -> None:
    """
    Predict the sentiment of a given text using a pre-trained sentiment analysis model.

    Args:
        text: The input text to analyze.
        model: The sentiment analysis model.
    """
    pretrained_model_name = "cardiffnlp/twitter-roberta-base-sentiment"
    tokenizer = AutoTokenizer.from_pretrained(pretrained_model_name)

    text = _preprocess(text)
    encoded_input = tokenizer(text, return_tensors="pt")
    output = model(**encoded_input)
    scores = output[0][0].detach().numpy()
    scores = softmax(scores)

    labels: list[str] = []
    mapping_link = f"https://raw.githubusercontent.com/cardiffnlp/tweeteval/main/datasets/{SENTIMENT_TASK}/mapping.txt"
    with urllib.request.urlopen(mapping_link) as f:
        html = f.read().decode("utf-8").split("\n")
        csvreader = csv.reader(html, delimiter="\t")
    labels = [row[1] for row in csvreader if len(row) > 1]

    ranking = np.argsort(scores)
    ranking = ranking[::-1]

    print(
        f"The overall sentiment is: {labels[ranking[0]]} with a score of: {np.round(float(scores[ranking[0]])*100, 1)}%"
    )
