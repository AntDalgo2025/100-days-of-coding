# import modules needed for the script

import logging
from logging.handlers import RotatingFileHandler

# Define log file name
log_filename = "system_info_log.txt"

# Create a rotating file handler
handler = RotatingFileHandler(log_filename, maxBytes=1_000_000, backupCount=5)


# Set up the logger
logger = ;oggin.getLogger("SystemLogger")
logger.setLevel(logging.INFO)
logger.addHandler(handler))

# Example function to log CPU and Memory Usage
def log_system_info()
	cpu_usage = psutil.cpu_percent(interval=1)
	mem_usage = psutil.virtual_memory().percent
	logger.info(f"CPU: {cpu_usage}%, Memory: {mem_usage}%")

# Example log entries
for _ in range(100): # Simulate multiple log entries
	log_system_info()
