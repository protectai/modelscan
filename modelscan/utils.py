import requests
import logging
import json
from typing import Union, Optional, Generator, List, Tuple

logger = logging.getLogger("modelscan")


def fetch_url(url: str, allow_redirect: bool = False) -> Union[None, bytes]:
    try:
        response = requests.get(url, allow_redirects=allow_redirect, timeout=10)
        response.raise_for_status()
        return response.content
    except requests.exceptions.HTTPError as e:
        logger.error("Error with request: %s", e.response.status_code)
        logger.error(e.response.text)
        return None
    except requests.exceptions.JSONDecodeError as e:
        logger.error("Response was not valid JSON")
        return None
    except requests.exceptions.Timeout as e:
        logger.error("Request timed out")
        return None
    except Exception as e:
        logger.error("Unexpected error during request to %s: %s", url, str(e))
        return None


def fetch_huggingface_repo_files(
    repo_id: str,
) -> Union[None, List[str]]:
    # Return list of model files
    url = f"https://huggingface.co/api/models/{repo_id}"
    data = fetch_url(url)
    if not data:
        return None

    try:
        model = json.loads(data.decode("utf-8"))
        filenames = []
        for sibling in model.get("siblings", []):
            if sibling.get("rfilename"):
                filenames.append(sibling.get("rfilename"))
        return filenames
    except json.decoder.JSONDecodeError as e:
        logger.error(f"Failed to parse response for HuggingFace model repo {repo_id}")

    return None


def read_huggingface_file(repo_id: str, file_name: str) -> Union[None, bytes]:
    url = f"https://huggingface.co/{repo_id}/resolve/main/{file_name}"
    return fetch_url(url, True)
