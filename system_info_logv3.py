import psutil
import logging
from logging.handlers import RotatingFileHandler
import time
import datetime
import os

# Set the number of cycles (e.g., 10 cycles)
max_cycle = 6
cycle_count= 0

# Inform the user about the six cycle limit
print("This script will collect system information for a total of 6 cycles. After 3 cycles, a prompt to continue will appear.")


# Open the log file to write the system stat
with open("system_info_log.txt", "a") as log_file:
	while True:
		# Get timestamp for log entry
		timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')

		# CPU Usage
		cpu = psutil.cpu_percent(interval=1) # Monitor CPU usage for 1 second

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
				pass # Handle process that may have terminated

		# Log Entry with CPU, Memory, Disk, Network, and Process Info
		log_entry = f"{timestamp} - CPU: {cpu}%, Memory: {mem.percent}%, Disk: {disk.percent}%, Network: Sent={net_io.bytes_sent} Bytes, Recv={net_io.bytes_recv} Bytes\nProcess:\n{process_info}\n"

		# Configure rotating file handler
		log_filename = "system_info_log.txt"
		handler = RotatingFileHandler(log_filename, maxBytes = 1_000_000, backupCount=5)

		# Set up the logger
		logger = logging.getLogger("SystemLogger")
		logger.setLevel(logging.INFO)
		logger.addHandler(handler)

		def log_system_info():
			cpu_usage = psutil.cpu_percent(interval=1)
			mem_usage = psutil.virtual_memory().percent
			active_process = sorted(psutil.process_iter(attrs=['pid', 'name']), key=lambda p: p.info['name'])

			log_entry = f"CPU: {cpu_usage}%, Memory: {mem_usage}%, Active Process: {len(active_process)}"
			logger.info(log_entry)

		# Logging Loop
		max_cycles = 6
		cycle_counter = 0

		while cycle_counter < max_cycles:
			log_system_info()
			cycle_counter += 1
			if cycle_counter == 3:
				user_input = input("Do you want to continue logging? (y/n): ").strip().lower()
				if user_input != ' y':
					break

		# After 6 cycles, stop automatically
		if cycle_count == max_cycle:
		 log_file.write(f"Logging complete after {cycle_count} cycles.\n")
		 print("Logging completed after 6 cycles.")
		 break # Stop after 6 cycles


		# Wait for the next log cycle (every 10 seconds)
		time.sleep(10)

		print("Logging complete. Check system_info_log.txt for results.")
