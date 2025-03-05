
#CPU Info don't forget to import the module
import psutil

print(f"CPU Usage: {psutil.cpu_percent(interval=1)}%")

# Memory Info
mem = psutil.virtual_memory()
print(f"Memory Usage: {mem.percent}% ({mem.used / (1024 ** 3):.2f}GB used)")

print("\n Active Processes:")
for proc in psutil.process_iter(['pid', 'name']):
	try:
		print(f"PID: {proc.info['pid']}, Name {proc.info['name']}")
	except:
		(psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess);
		pass #Skip inaccessible process


