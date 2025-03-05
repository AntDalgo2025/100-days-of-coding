import psutil
import time
import datetime

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

		# Write to the log file
		log_file.write(log_entry)

		# Increment the cycle counter
		cycle_count += 1

		# Check if cycle count has reached 3
		if cycle_count == 3:
			# Prompt user for input to continue or stop
			user_input = input("3 Cycles complete. Do you want to continue logging? (y/n): ").strip().lower()
			if  user_input != 'y':
				log_file.write(f"Logging stopped by user after {cycle_count} cycles.\n")
				print("Logging Stopped.")
				break # Exit the loop if user chooses not to continue

		# After 6 cycles, stop automatically
		if cycle_count == max_cycle:
			log_file.write(f"Logging complete after {cycle_count} cycles.\n")
			print("Logging completed after 6 cycles.")
			break # Stop after 6 cycles

		# Wait for the next log cycle (every 10 seconds)
		time.sleep(10)
