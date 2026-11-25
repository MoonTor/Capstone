import psutil
import sqlite3
import csv
import time
import argparse

from datetime import datetime, timezone
from pathlib import Path
from contextlib import closing


# Read the number of unique alerts stored in the server database
def get_alert_count(db_path):

	#open the database in read only mode
	database_uri = db_path.resolve().as_uri() + "?mode=ro"

	with closing(sqlite3.connect(database_uri, uri=True)) as conn:
		row = conn.execute(
			"SELECT COUNT(*) FROM alerts"
		).fetchone()

	return row[0]


#Main metrics collection function
def collect_metrics(pid, db_path, output_path, interval):
	
	#Identify the running server process
	server_process = psutil.Process(pid)

	#Initialize the CPU measurements
	psutil.cpu_percent()
	server_process.cpu_percent()
	
	#Record initial alert count and time
	previous_count = get_alert_count(db_path)
	previous_time = time.monotonic()

	#Create output directory if needed
	output_path.parent.mkdir(parents=True, exist_ok=True)

	#Create a new CSV file without overwriting previous results
	with open(output_path, "x", newline="") as file:

		writer = csv.writer(file)

		#CSV column headers
		writer.writerow([
			"timestamp",
			"system_cpu_percent",
			"system_memory_percent",
			"server_cpu_percent",
			"server_memory_mib",
			"total_alerts",
			"new_alerts",
			"interval_seconds",
			"alerts_per_second"
		])

		print(f"Monitoring server process: {pid}")
		print(f"Saving measurements to: {output_path}")
		print("Press Ctrl+C to stop collection")

		try:

			while True:
				time.sleep(interval)

				#Collect system resource measurements
				system_cpu = psutil.cpu_percent()
				system_memory = psutil.virtual_memory().percent

				#Collect server resource measurements
				server_cpu = server_process.cpu_percent()
				
				server_memory = (
					server_process.memory_info().rss
					/ (1024 ** 2)
				)

				#Calculate alert throughput
				total_alerts = get_alert_count(db_path)
				current_time = time.monotonic()

				elapsed = current_time - previous_time
				new_alerts = total_alerts - previous_count

				if new_alerts < 0:
					raise RuntimeError("Alert count decreased during collection")

				throughput = new_alerts / elapsed

				#Record current UTC timestamp
				timestamp = datetime.now(timezone.utc).isoformat(
					timespec="milliseconds"
				)

				#Write measurements to CSV
				writer.writerow([
					timestamp,
					system_cpu,
					system_memory,
					server_cpu,
					round(server_memory, 2),
					total_alerts,
					new_alerts,
					round(elapsed, 3),
					round(throughput, 3)
				])

				#Immediately save measurements to disk
				file.flush()

				#Update values for the next measurement
				previous_count = total_alerts
				previous_time = current_time

		except KeyboardInterrupt:

			print("\nMetrics collection stopped.")

#Command-line configuration
if __name__ == "__main__":

	parser = argparse.ArgumentParser(
		description="Collect NIDS server performance metrics"
	)

	parser.add_argument("--pid", type=int, required=True)
	parser.add_argument("--db", type=Path, required=True)
	parser.add_argument("--output", type=Path, required=True)
	parser.add_argument("--interval", type=float, default=1)

	args = parser.parse_args()

	if args.interval <= 0:
		parser.error("Interval must be greater than zero")

	collect_metrics(
		args.pid,
		args.db,
		args.output,
		args.interval
	)
