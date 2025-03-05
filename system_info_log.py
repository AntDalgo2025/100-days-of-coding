# Import the modules needed
import psutil
import datetime

# Get system stats
cpu = psutil.cpu_percent(interval=1)
mem = psutil.virtual_memory()
timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

# Get top 5 memory-consuming processes
process = sorted(psutil.process_iter(['pid', 'name', 'memory_info']), key=lambda p: p.info['memory_info'].rss, reverse=True)[:5]
process_info = ""
for proc in process:
	try:
		process_info += f"PID: {proc.info['pid']}, Name: {proc.info['name']}, Memory: {proc.info['memory_info'].rss / (1024** 2):.2f} MB\n"
	except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
		pass

# Log Entry
log_entry = f"{timestamp} - CPU: {cpu}%, Memory: {mem.percent}%, Top Processes:\n{process_info} \n"

# Save to file
with open("system_log.txt", "a") as log:
	log.write(log_entry)

print("Logged system stats.")
