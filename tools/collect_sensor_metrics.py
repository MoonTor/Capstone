import psutil
import sqlite3
import csv
import time
import argparse

from datetime import datetime, timezone
from pathlib import Path
from contextlib import closing


#Retrieve the number of alerts waiting for delivery
def get_queue_depth(db_path):

	database_uri = db_path.resolve().as_uri() + "?mode=ro"

	with closing(sqlite3.connect(
	        database_uri, uri=True, timeout=0.2
	)) as conn:

		row = conn.execute(
			"SELECT COUNT(*) FROM pending_alerts"
		).fetchone()

	return row[0]


#Initialize monitoring for a specific process
def initialize_process(pid):

	if pid is None:
		return None

	process = psutil.Process(pid)
	process.cpu_percent()

	return process


#Retrieve resource utilization for a process
def get_process_metrics(process):

	if process is None:
		return None, None, "not_monitored"

	try:

		if not process.is_running():
			return None, None, "stopped"

		cpu = process.cpu_percent()

		memory = (
			process.memory_info().rss
			/ (1024 ** 2)
		)

		return cpu, round(memory, 2), "running"

	except psutil.NoSuchProcess:
		return None, None, "stopped"

	except psutil.AccessDenied:
		return None, None, "access_denied"


#Main metrics collection function
def collect_metrics(sensor_id, agent_pid, suricata_pid,
	db_path, output_path, interval):

	#Verify the queue database exists
	if not db_path.is_file():
		raise FileNotFoundError(db_path)

	# Initialize process monitoring
	agent_process = initialize_process(agent_pid)
	suricata_process = initialize_process(suricata_pid)

	#Initialize system CPU measurement
	psutil.cpu_percent()

	output_path.parent.mkdir(parents=True, exist_ok=True)

	#Create CSV without overwriting previous results
	with open(output_path, "x", newline="") as file:

		writer = csv.writer(file)

		writer.writerow([
			"timestamp",
			"sensor_id",
			"system_cpu_percent",
			"system_memory_percent",
			"agent_cpu_percent",
			"agent_memory_mib",
			"agent_status",
			"suricata_cpu_percent",
			"suricata_memory_mib",
			"suricata_status",
			"queue_depth",
			"interval_seconds"
		])

		file.flush()

		print(f"Monitoring sensor: {sensor_id}")
		print(f"Agent PID: {agent_pid}")
		print(f"Suricata PID: {suricata_pid}")
		print(f"Saving measurements to: {output_path}")
		print("Press Ctrl+C to stop collection.")

		previous_time = time.monotonic()

		try:

			while True:

				time.sleep(interval)

				#System-wide resource measurements
				system_cpu = psutil.cpu_percent()
				system_memory = psutil.virtual_memory().percent

				#Agent resource measurements
				agent_cpu, agent_memory, agent_status = (
					get_process_metrics(agent_process)
				)

				#Suricata resource measurements
				suricata_cpu, suricata_memory, suricata_status = (
					get_process_metrics(suricata_process)
				)

				#Retrieve the current queue depth
				try:
					queue_depth = get_queue_depth(db_path)

				except sqlite3.Error as error:
					print(f"Queue measurement failed: {error}")
					queue_depth = None

				#Calculate actual elapsed time
				current_time = time.monotonic()
				elapsed = current_time - previous_time

				timestamp = datetime.now(timezone.utc).isoformat(
					timespec="milliseconds"
				)

				#Save measurements
				writer.writerow([
					timestamp,
					sensor_id,
					system_cpu,
					system_memory,
					agent_cpu,
					agent_memory,
					agent_status,
					suricata_cpu,
					suricata_memory,
					suricata_status,
					queue_depth,
					round(elapsed, 3)
				])

				file.flush()

				previous_time = current_time

		except KeyboardInterrupt:

			print("\nMetrics collection stopped.")


#Command-line configuration
if __name__ == "__main__":

	parser = argparse.ArgumentParser(
		description="Collect NIDS sensor performance metrics"
	)

	parser.add_argument("--sensor-id", required=True)
	parser.add_argument("--agent-pid", type=int, required=True)
	parser.add_argument("--suricata-pid", type=int, default=None)
	parser.add_argument("--db", type=Path, required=True)
	parser.add_argument("--output", type=Path, required=True)
	parser.add_argument("--interval", type=float, default=1)

	args = parser.parse_args()

	if args.interval <= 0:
		parser.error("Interval must be greater than zero")

	collect_metrics(
		args.sensor_id,
		args.agent_pid,
		args.suricata_pid,
		args.db,
		args.output,
		args.interval
	)
