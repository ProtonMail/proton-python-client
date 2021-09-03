import logging
import os
from logging.handlers import RotatingFileHandler

from .constants import LOG_DIR_PATH, CACHE_DIR_PATH

import time


def get_logger():
    """Create the logger."""
    FORMATTER = logging.Formatter(
        "%(asctime)s — %(filename)s — %(levelname)s — %(funcName)s:%(lineno)d — %(message)s" # noqa
    )
    FORMATTER.converter = time.gmtime

    if not os.path.isdir(LOG_DIR_PATH):
        os.makedirs(LOG_DIR_PATH)

    if not os.path.isdir(CACHE_DIR_PATH):
        os.makedirs(CACHE_DIR_PATH)

    LOGFILE = os.path.join(LOG_DIR_PATH, "proton-client.log")

    logger = logging.getLogger("proton-client")

    console_handler = logging.StreamHandler()
    console_handler.setFormatter(FORMATTER)

    logging_level = logging.INFO

    logger.setLevel(logging_level)
    # Starts a new file at 3MB size limit
    file_handler = RotatingFileHandler(
        LOGFILE, maxBytes=3145728, backupCount=3
    )
    file_handler.setFormatter(FORMATTER)
    logger.addHandler(file_handler)

    return logger


logger = get_logger()
