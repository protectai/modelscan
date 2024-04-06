from transformers import AutoModelForSequenceClassification
from transformers import AutoTokenizer
import numpy as np
from scipy.special import softmax
import csv
import urllib.request
import torch


# Preprocess text (username and link placeholders)
def preprocess(text):
    new_text = []

    for t in text.split(" "):
        t = "@user" if t.startswith("@") and len(t) > 1 else t
        t = "http" if t.startswith("http") else t
        new_text.append(t)
    return " ".join(new_text)


def download_model(safe_model_path):
    task = "sentiment"
    MODEL = f"cardiffnlp/twitter-roberta-base-{task}"
    # PT
    model = AutoModelForSequenceClassification.from_pretrained(MODEL)
    torch.save(model, safe_model_path)


def predict_sentiment(text: str, model):
    task = "sentiment"
    MODEL = "cardiffnlp/twitter-roberta-base-sentiment"
    tokenizer = AutoTokenizer.from_pretrained(MODEL)

    text = preprocess(text)
    encoded_input = tokenizer(text, return_tensors="pt")
    output = model(**encoded_input)
    scores = output[0][0].detach().numpy()
    scores = softmax(scores)

    labels = []
    mapping_link = f"https://raw.githubusercontent.com/cardiffnlp/tweeteval/main/datasets/{task}/mapping.txt"
    with urllib.request.urlopen(mapping_link) as f:
        html = f.read().decode("utf-8").split("\n")
        csvreader = csv.reader(html, delimiter="\t")
    labels = [row[1] for row in csvreader if len(row) > 1]

    ranking = np.argsort(scores)
    ranking = ranking[::-1]

    print(
        f"The overall sentiment is: {labels[ranking[0]]} with a score of: {np.round(float(scores[ranking[0]])*100, 1)}%"
    )
