import psutil
import logging
from logging.handlers import RotatingFileHandler
import time
import datetime
import os

# Set the number of cycles (e.g., 3 cycles)
max_cycle = 3
cycle_count = 0

# Inform the user about the cycle limit
print(f"This script will collect system information for a total of {max_cycle} cycles.")

# Open the log file to write the system stat
with open("system_info_log.txt", "a") as log_file:
    # Configure rotating file handler
    log_filename = "system_info_log.txt"
    handler = RotatingFileHandler(log_filename, maxBytes=1_000_000, backupCount=5)

    # Set up the logger
    logger = logging.getLogger("SystemLogger")
    logger.setLevel(logging.INFO)
    logger.addHandler(handler)

    while cycle_count < max_cycle:
        # Get timestamp for log entry
        timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        # CPU Usage
        cpu = psutil.cpu_percent(interval=1)  # Monitor CPU usage for 1 second

        # Memory Usage
        mem = psutil.virtual_memory()

        # Disk usage
        disk = psutil.disk_usage('/')

        # Network usage
        net_io = psutil.net_io_counters()

        # Process details: PID, name, status, and CPU time
        process_info = ""
        for process in psutil.process_iter(['pid', 'name', 'status', 'cpu_times']):
            try:
                pid = process.info['pid']
                name = process.info['name']
                status = process.info['status']
                cpu_time = process.info['cpu_times']
                process_info += f"PID: {pid}, Name: {name}, Status {status}, CPU Time: {cpu_time}\n"
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                pass  # Handle process that may have terminated

        # Log Entry with CPU, Memory, Disk, Network, and Process Info
        log_entry = f"{timestamp} - CPU: {cpu}%, Memory: {mem.percent}%, Disk: {disk.percent}%, Network: Sent={net_io.bytes_sent} Bytes, Recv={net_io.bytes_recv} Bytes\nProcess:\n{process_info}\n"
        
        # Write log entry to the log file
        logger.info(log_entry)

        # Increment cycle count
        cycle_count += 1

        # Add a delay before the next cycle
        time.sleep(10)

    print(f"Logging complete after {cycle_count} cycles. Check system_info_log.txt for results.")