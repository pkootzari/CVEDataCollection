import logging

def generate_logger(logger_name, log_file_name="app.log"):

    # Create a logger
    logger = logging.getLogger(logger_name)
    logger.setLevel(logging.DEBUG)

    # File handler
    file_handler = logging.FileHandler(log_file_name)
    file_handler.setLevel(logging.DEBUG)

    error_handler_file_name = log_file_name.split(".")[0] + "_error" + ".log"
    error_handler = logging.FileHandler(error_handler_file_name)
    error_handler.setLevel(logging.ERROR)

    # Console handler
    # console_handler = logging.StreamHandler()
    # console_handler.setLevel(logging.WARNING)

    # Formatter
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    file_handler.setFormatter(formatter)
    error_handler.setFormatter(formatter)
    # console_handler.setFormatter(formatter)

    # Add handlers to the logger
    logger.addHandler(file_handler)
    logger.addHandler(error_handler)
    # logger.addHandler(console_handler)

    # Example log messages
    # logger.debug("This is logged to the file only.")
    # logger.error("This is logged to both console and file.")

    return logger

# generate_logger("aqua")