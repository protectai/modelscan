import requests
import logging
from typing import Union

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
