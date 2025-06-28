import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path

base_dir = Path(__file__).parent.parent
log_dir = base_dir / 'log_files'
log_dir.mkdir(exist_ok=True)

creds_log_path = log_dir / 'creds_audits.log'
cmd_log_path = log_dir / 'cmd_audits.log'

logging_format = logging.Formatter('%(message)s')

funnel_logger = logging.getLogger('FunnelLogger')
funnel_logger.setLevel(logging.INFO)
funnel_handler = RotatingFileHandler(cmd_log_path, maxBytes=2000, backupCount=5)
funnel_handler.setFormatter(logging_format)
funnel_logger.addHandler(funnel_handler)

creds_logger = logging.getLogger('CredsLogger')
creds_logger.setLevel(logging.INFO)
creds_handler = RotatingFileHandler(creds_log_path, maxBytes=2000, backupCount=5)
creds_handler.setFormatter(logging_format)
creds_logger.addHandler(creds_handler)