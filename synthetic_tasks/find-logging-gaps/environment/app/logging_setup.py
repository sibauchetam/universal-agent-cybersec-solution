import logging

def setup_logging():
    # No timestamps, no module names; only ERROR survives
    logging.basicConfig(
        level=logging.ERROR,
        format="%(message)s",
    )
