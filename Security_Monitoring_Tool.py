#!/usr/bin/env python3
"""
Security Monitoring Tool - Day 4 of 100 Days of Coding
This script monitors and reports on security-relevant system information.
"""

import psutil
import logging
from logging.handlers import RotatingFileHandler
import time
import datetime
import os
import socket
import platform
import subprocess
import json
import argparse


class SecurityMonitor:
    """Class for monitoring system security metrics"""

    def __init__(self, log_dir="log"):
        # Create logs directory if it doesn't exist
        self.log_dir = log_dir
        os.makedirs(self.log_dir, exist_ok=True)

        # Configure logger
        self.logger = self._setup_logger()

        # Initialize data dictionary
        self.data = {}
    
    def _setup_logger(self):
        """Set up rotating file logger"""
        logger = logging.getLogger("SecurityMonitor")
        logger.setLevel(logging.INFO)

        # Create rotating file handler
        log_path = os.path.join(self.log_dir, "security_monitor.log")
        handler = RotatingFileHandler(log_path, maxBytes=5_000_000, backupCount=3)
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        handler.setFormatter(formatter)

        # Add handler to logger
        logger.addHandler(handler)

        return logger
    
    def collect_system_info(self):
        """Collect basic system information"""
        self.data['system'] = {
            'hostname': socket.gethostname(),
            'ip_address': self._get_ip_address(),
            'platform': platform.system(),
            'platform_version': platform.version(),
            'architecture': platform.architecture()[0],
            'processor': platform.processor(),
            'boot_time': datetime.datetime.fromtimestamp(psutil.boot_time()).strftime('%Y-%m-%d %H:%M:%S')
        }

        # For Linux systems, get more detailed distribution information
        if platform.system() == 'Linux':
            self.data['system']['distribution'] = self._get_linux_distribution()

    def collect_network_info(self):
        """Collect network information with security focus"""
        # Get network interfaces and their addresses
        interfaces = {}
        for iface, addrs in psutil.net_if_addrs().items():
            interfaces[iface] = {
                'mac': '',
                'ipv4': [],
                'ipv6': []
            }
            for addr in addrs:
                if addr.family == socket.AF_INET: # IPv4
                    interfaces[iface]['ipv4'].append(addr.address)
                elif addr.family == socket.AF_INET6: # IPv6
                    interfaces[iface]['ipv6'].append(addr.address)
                elif addr.family == psutil.AF_LINK: # MAC address
                    interfaces[iface]['mac'] = addr.address

        # Get network connections
        connections = []
        try:
            for conn in psutil.net_connections(kind='inlet'):
                if conn.laddr and conn.laddr.port:
                    connection_info = {
                        'protocol': 'TCP' if conn.type == socket.SOCK_STREAM else 'UDP',
                        'local_address': f"{conn.laddr.ip}:{conn.laddr.port}",
                        'remote_address': f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else 'None',
                        'status': conn.status,
                        'pid': conn.pid
                    }

                    # Try to get process name
                    if conn.pid:
                        try:
                            connection_info['process'] = psutil.Process(conn.pid).name()
                        except (psutil.NoSuchProcess, psutil.AccessDenied):
                            connection_info['process'] = 'Unknown'

                        connections.append(connection_info)

        except (psutil.AccessDenied, AttributeError):
            self.logger.warning("Could not access network connections (requires root/admin privileges)")

        self.data['network'] = {
            'interfaces': interfaces,
            'connections': connections,
            'stats': {
                'bytes_sent': psutil.net_io_counters().bytes_sent,
                'bytes_received': psutil.net_io_counters().bytes_recv,
                'packets_sent': psutil.net_io_counters().packets_sent,
                'packets_received': psutil.net_io_counters().packets_recv
            }
        }
    def collect_security_info(self):
        """Collect security-specific information"""
        security_data = {}

        # Check for listening services (ports)
        listening_ports = []
        try:
            for conn in psutil.net_connections():
                if conn.status == 'LISTEN':
                    port_info = {
                        'port': conn.laddr.port,
                        'address': conn.laddr.ip,
                        'pid': conn.pid,
                        'process': 'Unknown'
                    }

                    # Get process name
                    if conn.pid:
                        try:
                            port_info['process'] = psutil.Process(conn.pid).name()
                        except (psutil.NoSuchProcess, psutil.AccessDenied):
                            pass
                
                listening_ports.append(port_info)
        except (psutil.AccessDenied, AttributeError):
            self.logger.warning("Could not access network connections (requires root/admin privileges)")

        security_data['listening_ports'] = listening_ports

        # Check for suspicious processes (high CPU or memory usage)
        suspicious_processes = []
        for proc in psutil.process_iter(['pid', 'name', 'cppu_percent', 'memory_percent']):
            try:

                # Get process information
                proc_info = proc.info

                # Skip processes with 0 CPU and low memory usage
                if proc_info['cpu_percent'] < 0.1 and proc_info['memory_percent'] < 1.0:
                    continue

                # Check for potentially suspicous processes
                # (This is simplified - in a real security tool, you'd have better heuristics)
                if proc_info['cpu_percent'] >80 or proc_info['memory_percent'] > 80:
                    suspicious_processes.append({
                        'pid': proc_info['pid'],
                        'name': proc_info['name'],
                        'username': proc_info['username'],
                        'cpu_percent': proc_info['cpu_percent'],
                        'memory_percent': proc_info['memory_percent'],
                        'reason': 'High resource usuage'
                    })
            except (psutil.NoSuchProcess, psutil.AccssDenied, psutil.ZombieProcess):
                pass
        
        security_data['suspicious_processes'] = suspicious_processes

        # Check for unusual users with processes (Linux only)
        if platform.system() == 'Linux':
            users_with_processes = {}
            for proc in psutil.process_iter(['pid', 'name', 'username']):
                try:
                    username = proc.info['username']
                    if username not in users_with_processes:
                        users_with_processes[username] = []
                    users_with_processes[username].append(proc.info['pid'])
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    pass
            
            security_data['users_with_processes'] = {
                user :len(pids) for user, pids in users_with_processes.items()
            }

        # Check for recently modified system files (Linux only)
        if platform.system() == 'Linux':
            try:
                # This would need root in many cases
                find_command = "find /etc -type f -mtime -1 -ls"
                result = subprocess.run(find_command, shell=True, capture_output=True, text=True)
                if result.returncode == 0:
                    modified_files = [line.split()[-1] for line in result.stdout.strip().split('\n') if line]
                    security_data['recently_modified_system_files'] = modified_files
            except subprocess.SubprocessError:
                self.logger.warning("Could not check for modified system files")

            self.data['security'] = security_data

    def collect_resource_usage(self):
        """Collect system resource usage"""
        # CPU info
        cpu_info = {
            'percent': psutil.cpu_percent(interval=1),
            'count': {
                'physical': psutil.cpu_count(logical=False),
                'logical': psutil.cpu_count(logical=True)
            },
            'per_cpu': psutil.cpu_percent(interval=1, percpu=True)
        }
        
        # Memory info
        mem = psutil.virtual_memory()
        memory_info = {
            'total': mem.total,
            'available': mem.available,
            'used': mem.used,
            'percent': mem.percent
        }
        
        # Disk info
        disk_info = {}
        for part in psutil.disk_partitions(all=False):
            try:
                usage = psutil.disk_usage(part.mountpoint)
                disk_info[part.mountpoint] = {
                    'device': part.device,
                    'total': usage.total,
                    'used': usage.used,
                    'free': usage.free,
                    'percent': usage.percent
                }
            except (PermissionError, OSError):
                continue
                
        self.data['resources'] = {
            'cpu': cpu_info,
            'memory': memory_info,
            'disk': disk_info
        }
    
    def collect_process_info(self, top_n=10):
        """Collect information about top processes"""
        top_cpu_processes = []
        top_memory_processes = []
        
        # Get processes sorted by CPU usage
        for proc in sorted(psutil.process_iter(['pid', 'name', 'username', 'cpu_percent']), 
                           key=lambda p: p.info['cpu_percent'], 
                           reverse=True)[:top_n]:
            try:
                top_cpu_processes.append({
                    'pid': proc.info['pid'],
                    'name': proc.info['name'],
                    'username': proc.info['username'],
                    'cpu_percent': proc.info['cpu_percent']
                })
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                pass
                
        # Get processes sorted by memory usage
        for proc in sorted(psutil.process_iter(['pid', 'name', 'username', 'memory_percent']), 
                           key=lambda p: p.info['memory_percent'], 
                           reverse=True)[:top_n]:
            try:
                top_memory_processes.append({
                    'pid': proc.info['pid'],
                    'name': proc.info['name'],
                    'username': proc.info['username'],
                    'memory_percent': proc.info['memory_percent']
                })
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                pass
                
        self.data['processes'] = {
            'top_cpu': top_cpu_processes,
            'top_memory': top_memory_processes
        }
    
    def collect_all(self, top_n=10):
        """Collect all information"""
        try:
            self.collect_system_info()
            self.collect_network_info()
            self.collect_security_info()
            self.collect_resource_usage()
            self.collect_process_info(top_n)
            
            # Log that data collection was successful
            self.logger.info("Successfully collected system security data")
            
            return True
        except Exception as e:
            self.logger.error(f"Error collecting data: {str(e)}")
            return False
    
    def print_report(self):
        """Print a security-focused report to the console"""
        print("\n==== SECURITY MONITORING REPORT ====")
        print(f"Time: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"Host: {self.data['system']['hostname']} ({self.data['system']['ip_address']})")
        print(f"Platform: {self.data['system']['platform']} {self.data['system']['platform_version']}")
        
        # Print resource usage
        print("\n-- Resource Usage --")
        print(f"CPU: {self.data['resources']['cpu']['percent']}% used")
        print(f"Memory: {self.data['resources']['memory']['percent']}% used")
        
        # Print listening ports (security-critical)
        print("\n-- Listening Ports --")
        if self.data['security']['listening_ports']:
            for port in self.data['security']['listening_ports']:
                print(f"Port {port['port']} ({port['address']}): {port['process']} (PID: {port['pid']})")
        else:
            print("No listening ports found or insufficient permissions")
        
        # Print suspicious processes
        print("\n-- Suspicious Processes --")
        if self.data['security']['suspicious_processes']:
            for proc in self.data['security']['suspicious_processes']:
                print(f"PID {proc['pid']} ({proc['name']}): CPU {proc['cpu_percent']}%, Memory {proc['memory_percent']}%")
                print(f"  Reason: {proc['reason']}")
        else:
            print("No suspicious processes detected")
            
        # Print top CPU processes
        print("\n-- Top CPU Processes --")
        for proc in self.data['processes']['top_cpu'][:5]:  # Show top 5
            print(f"PID {proc['pid']} ({proc['name']}): {proc['cpu_percent']}% CPU")
            
        # Print network connections summary
        print("\n-- Network Connections Summary --")
        conn_count = len(self.data['network']['connections'])
        print(f"Total connections: {conn_count}")
        
        # Add timestamp to the log
        print(f"\nData logged to: {self.log_dir}/security_monitor.log")
    
    def export_to_json(self, filepath):
        """Export collected data to JSON file"""
        try:
            with open(filepath, 'w') as f:
                json.dump(self.data, f, indent=4)
            self.logger.info(f"Data exported to {filepath}")
            print(f"Data exported to {filepath}")
            return True
        except Exception as e:
            self.logger.error(f"Error exporting data: {str(e)}")
            print(f"Error exporting data: {str(e)}")
            return False
    
    def monitor_loop(self, cycles=3, interval=10):
        """Run monitoring in a loop for specified number of cycles"""
        print(f"Starting security monitoring for {cycles} cycles with {interval} second intervals...")
        
        for cycle in range(1, cycles + 1):
            print(f"\nCycle {cycle}/{cycles}:")
            start_time = time.time()
            
            # Collect data
            success = self.collect_all()
            if success:
                # Print report
                self.print_report()
                
                # Export data to JSON (with timestamp in filename)
                timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
                json_path = os.path.join(self.log_dir, f"security_data_{timestamp}.json")
                self.export_to_json(json_path)
                
            # Wait for next cycle, accounting for collection time
            elapsed = time.time() - start_time
            if elapsed < interval and cycle < cycles:
                print(f"\nWaiting {interval - elapsed:.1f} seconds until next cycle...")
                time.sleep(max(0, interval - elapsed))
        
        print(f"\nMonitoring complete. {cycles} cycles finished.")
    
    def _get_ip_address(self):
        """Get primary IP address"""
        try:
            # This doesn't actually make a connection
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except:
            return "127.0.0.1"  # Fallback to localhost
    
    def _get_linux_distribution(self):
        """Get Linux distribution name"""
        try:
            # Try to get distribution from /etc/os-release
            if os.path.exists('/etc/os-release'):
                with open('/etc/os-release', 'r') as f:
                    for line in f:
                        if line.startswith('PRETTY_NAME='):
                            return line.split('=')[1].strip().strip('"')
            # Fallback to platform module
            return platform.platform()
        except:
            return "Unknown Linux Distribution"


def parse_arguments():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(description="Security Monitoring Tool")
    parser.add_argument("--cycles", type=int, default=3, help="Number of monitoring cycles to run")
    parser.add_argument("--interval", type=int, default=10, help="Interval between cycles (seconds)")
    parser.add_argument("--log-dir", default="logs", help="Directory to store logs and data")
    parser.add_argument("--json-only", action="store_true", help="Output JSON only, no console report")
    
    return parser.parse_args()


def main():
    """Main function"""
    args = parse_arguments()
    
    try:
        # Create security monitor
        monitor = SecurityMonitor(log_dir=args.log_dir)
        
        if args.json_only:
            # Single cycle with JSON output
            if monitor.collect_all():
                timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
                json_path = os.path.join(args.log_dir, f"security_data_{timestamp}.json")
                monitor.export_to_json(json_path)
        else:
            # Run monitoring loop
            monitor.monitor_loop(cycles=args.cycles, interval=args.interval)
    
    except KeyboardInterrupt:
        print("\nMonitoring interrupted by user")
    except Exception as e:
        print(f"Error: {e}")


if __name__ == "__main__":
    main()