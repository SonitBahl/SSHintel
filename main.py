import logging
from logging.handlers import RotatingFileHandler

logging_format = logging.Formatter('%(message)s')
funnel_logger = logging.getLogger('FunnelLogger')
funnel_logger.setLevel(logging.INFO)

funnel_handler = RotatingFileHandler('audit.log', maxBytes = 2000, backupCount = 5)
funnel_handler.setFormatter(logging_format)

funnel_logger.addHandler(funnel_handler)