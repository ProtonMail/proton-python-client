import logging
import os
from logging.handlers import RotatingFileHandler
from .utils import Singleton


import time


class CustomLogger(metaclass=Singleton):
    def __init__(self, log_dir_path):
        self.__log_dir_path = log_dir_path
        self.__logger = None
        self.__create_logger()

    def __create_logger(self):
        """Create the logger."""
        FORMATTER = logging.Formatter(
            "%(asctime)s — %(filename)s — %(levelname)s — %(funcName)s:%(lineno)d — %(message)s" # noqa
        )
        FORMATTER.converter = time.gmtime

        if not os.path.isdir(self.__log_dir_path):
            os.makedirs(self.__log_dir_path)

        LOGFILE = os.path.join(self.__log_dir_path, "proton-client.log")

        self.__logger = logging.getLogger("proton-client")

        console_handler = logging.StreamHandler()
        console_handler.setFormatter(FORMATTER)

        logging_level = logging.INFO

        self.__logger.setLevel(logging_level)
        # Starts a new file at 3MB size limit
        file_handler = RotatingFileHandler(
            LOGFILE, maxBytes=3145728, backupCount=3
        )
        file_handler.setFormatter(FORMATTER)
        self.__logger.addHandler(file_handler)

    @property
    def logger(self):
        return self.__logger
