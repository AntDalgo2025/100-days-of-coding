import psutil
import time
import datetime

# Open the log file to write the system stat
with open("system_info_log.txt", "a") as log_file:
	while True:
		# Get timestamp for log entry
		timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')

		# CPU Usage
		cpu = psutil.cpu_percent(interval=1) # Monitor CPU usage for 1 second

		# Memory Usage
		mem = psutil.virtual_memory()

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

		# Log Entry with CPU, Memory, and process info
		log_entry = f"{timestamp} - CPU: {cpu}%, Memory: {mem.percent}%, Process:\n{process_info}\n"

		# Write to the log file
		log_file.write(log_entry)

		# Print to console (optional)
		print(log_entry)

		# Wait for the next log cycle (every 10 seconds)
		time.sleep(10)
