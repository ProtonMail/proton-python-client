
import json
import os
import time

from .metadata import MetadataBackend
from ..logger import logger


class TextfileMetdataHandler(MetadataBackend):
    """
    TextfileMetdataHandler. Stores
    metadata for Alternative Routing purposes.
    """
    metadata_backend = "default"
    METADATA_FILEPATH = None
    ONE_DAY_IN_SECONDS = 86400

    def store_alternative_route(self, url):
        """Save connected time metadata."""
        metadata = self.__get_metadata_from_file()
        metadata["last_api_call_time"] = str(
            int(time.time())
        )
        metadata["url"] = url

        self.__write_metadata_to_file(metadata)
        logger.info("Saved last API attempt with original URL")

    def try_original_url(self, is_alt_routing_enabled, force_skip_alt_routing):
        """Determine if next api call should use the original URL or not.

        Check API_URL constant to determine what is original URL.
        """
        try:
            time_since_last_original_api = int(
                self.__get_metadata_from_file()["last_api_call_time"]
            )
        except KeyError:
            time_since_last_original_api = (self.ONE_DAY_IN_SECONDS * 2) - int(time.time())

        if (
            (time_since_last_original_api + self.ONE_DAY_IN_SECONDS) > time.time()
            and is_alt_routing_enabled is True
            and not force_skip_alt_routing
        ):
            return False

        if self.__check_metadata_exists():
            self.__remove_metadata_file()

        return True

    def get_alternative_url(self):
        """Get alternative URL from metadata file."""
        try:
            return self.__get_metadata_from_file()["url"]
        except KeyError:
            return ""

    @property
    def cache_dir_path(self):
        """Getter for cache directory path."""
        return self.METADATA_FILEPATH

    @cache_dir_path.setter
    def cache_dir_path(self, newvalue):
        """Setter for cache directory path."""
        import os
        self.METADATA_FILEPATH = os.path.join(
            newvalue, "metadata.json"
        )

    def __get_metadata_from_file(self):
        """Get metadata.

        Returns:
            json/dict
        """
        logger.debug("Getting metadata")
        try:
            with open(self.METADATA_FILEPATH) as f:
                metadata = json.load(f)
                logger.debug("Successfully fetched metadata from file")
                return metadata
        except Exception as e:
            logger.exception(e)
            return {}

    def __write_metadata_to_file(self, metadata):
        """Save metadata to file."""
        try:
            with open(self.METADATA_FILEPATH, "w") as f:
                json.dump(metadata, f)
                logger.debug("Successfully saved metadata")
        except Exception as e:
            logger.exception(e)
            return {}

    def __remove_metadata_file(self):
        """Remove metadata file."""
        if os.path.isfile(self.METADATA_FILEPATH):
            os.remove(self.METADATA_FILEPATH)

    def __check_metadata_exists(self):
        """Check if metadata file exists."""
        logger.debug("Checking if metadata exists.")

        found_metadata_file = False
        if os.path.isfile(self.METADATA_FILEPATH):
            found_metadata_file = True

        logger.debug(
            "Metadata \"{}\"".format(
                ("exists" if found_metadata_file else "does not exist")
            )
        )
        return found_metadata_file
