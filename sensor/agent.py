import json	#suricata writes JSON text and pythons json module converts that text into normal python dictionary
import time	#needed to let cpu rest between alerts
import uuid 	#needed for id's for each alert
import requests
import sqlite3
import threading #Needed for background thread HTTPS sending
from pathlib import Path 
from alert_queue import (
	initialize_queue,
	get_reader_state,
	save_reader_state,
	enqueue_alert_and_checkpoint,
	get_pending_alerts,
	remove_alert
)
import os

#Load sensor specific setting from the local JSON congifuration file
CONFIG_PATH = Path(__file__).resolve().parent / "config.json"

with open(CONFIG_PATH, "r", encoding="utf-8") as config_file:
	config = json.load(config_file)

#Sensor ID and Suricata log file
SENSOR_ID = config["sensor_id"]
EVE_FILE = config["eve_file"]	

#Central server endpoints
SERVER_BASE_URL = config["server_base_url"].rstrip("/")
SERVER_URL = f"{SERVER_BASE_URL}/alerts"
HEARTBEAT_URL = f"{SERVER_BASE_URL}/heartbeat"

#TLS and Authentication
CA_CERT = config["ca_cert"]
TOKEN_PATH = Path(config["token_path"]).expanduser()

SENSOR_TOKEN = TOKEN_PATH.read_text(encoding="utf-8").strip()

#Check if sensor token exists
if not SENSOR_TOKEN:
	raise RuntimeError("Sensor authentication token is empty")

#Timing and queue settings
HEARTBEAT_INTERVAL = config["heartbeat_interval"]

RETRY_INTERVAL = config["retry_interval"]
MAX_RETRY_BATCH = config["max_retry_batch"] #Max amount of queued alerts

CHECKPOINT_INTERVAL = config["checkpoint_interval"] #Interval between reader checkpoint attempts on non-alert records

#------------------------------------------------------------------

#Function to send periodic "heartbeats" to the server
def send_heartbeat():
	try:
		response = requests.post(
			HEARTBEAT_URL,
			json={"sensor_id": SENSOR_ID},
			headers={"Authorization": f"Bearer {SENSOR_TOKEN}"},
			verify=CA_CERT,
			timeout=5
		)

		response.raise_for_status()

		print(f"Heartbeat acknowledged: HTTP {response.status_code}")

	except requests.RequestException as error:
		print(f"Heartbeat failed: {error}")

#Function to schedule outgoing heatbeats that is used by a background thread
def heartbeat_loop():
	while True:
		send_heartbeat()
		time.sleep(HEARTBEAT_INTERVAL)

retry_event = threading.Event()


#Function that tried to enqueue a newly read alert into local storage and reader position
#	If unsuccessful due to SQLite3 error it retries
def store_alert_safely(alert_data, file):
	while True:
		try:
			
			info = os.fstat(file.fileno())


			inserted = enqueue_alert_and_checkpoint(
				alert_data,
				EVE_FILE,
				info.st_dev,
				info.st_ino,
				file.tell()
			)

			
			if inserted:
				print(f"Alert queued: {alert_data['alert_id']}")
			else:
				print(f"Alert already queued: {alert_data['alert_id']}")

			#Notify sender an alert is ready
			retry_event.set()

			return

		except sqlite3.Error as error:
			print(f"SQLite queue write failed: {error}")
			print(f"Retrying in {RETRY_INTERVAL} seconds...")

			time.sleep(RETRY_INTERVAL)


def retry_pending_alerts():
	while True:
		retry_event.clear()

		try:
			pending = get_pending_alerts(limit=MAX_RETRY_BATCH)

			if not pending:
				retry_event.wait(RETRY_INTERVAL)
				continue
		
			failed = False

			for alert in pending:
				try:

					response = requests.post(
						SERVER_URL, 
						json=alert,
						headers={
							"Authorization": f"Bearer {SENSOR_TOKEN}"
						},
						verify=CA_CERT,
						timeout=5
					)

					if 200 <= response.status_code < 300:
						remove_alert(alert["alert_id"])
						print(f"Alert delivered: {alert['alert_id']}")
					else:
						print(
							f"Alert delivery failed: "
							f"HTTP {response.status_code}"
						)
						failed = True
						break

				except requests.RequestException as e:
					print(f"Server connection error: {e}")
					failed = True
					break
			if failed:
				time.sleep(RETRY_INTERVAL)

		except sqlite3.Error as e:
			print(f"Local SQLite queue error: {e}")
			time.sleep(RETRY_INTERVAL)


#Initialize queue and start the background sender
initialize_queue()

sender_thread = threading.Thread(
	target=retry_pending_alerts,
	daemon=True
)

sender_thread.start()

#Background thread handling outgoing heartbeats
heartbeat_thread = threading.Thread(
	target=heartbeat_loop,
	daemon=True
)

heartbeat_thread.start()


#Persist the current reader position
def save_position_safely(file):
	while True:
		try:
			info = os.fstat(file.fileno())

			save_reader_state(
				EVE_FILE,
				info.st_dev,
				info.st_ino,
				file.tell()
			)
			return

		except sqlite3.Error as error:
			print(f"Checkpoint save failed: {error}")
			time.sleep(RETRY_INTERVAL)


#Periodically checkpoint non-alert events
def checkpoint_if_due(file, last_checkpoint):
	now = time.monotonic()

	if ((now - last_checkpoint) < CHECKPOINT_INTERVAL):
		return last_checkpoint

	try:
		info = os.fstat(file.fileno())

		save_reader_state(
			EVE_FILE,
			info.st_dev,
			info.st_ino,
			file.tell()
		)

		return now

	except sqlite3.Error as error:
		print(f"Periodic checkpoint failed: {error}")
		return last_checkpoint


#opens and reads the eve file, to parse it for specific event types
with open(EVE_FILE, "rb") as file:

	info = os.fstat(file.fileno())
	state = get_reader_state(EVE_FILE)

	if state is None:
	
		#First startup begin at end of file
		file.seek(0, os.SEEK_END)
		save_position_safely(file)
		print("No checkpoint found. Starting at end of log")

	elif (
		state[0] == info.st_dev
		and state[1] == info.st_ino
		and state[2] <= info.st_size
	):
		#Same file and valid checkpoint
		file.seek(state[2])
		print(f"Resuming from saved position: {state[2]}")

	else:
		#File changed identity or was truncated
		file.seek(0)
		save_position_safely(file)
		print("Log changed or truncated. Starting at beginning.")


	print("Watching for new Suricata events...")
	
	last_checkpoint = time.monotonic()


	#keep the agent reading for new events
	while True:

		#Remember where JSON left off
		line_start = file.tell()

		#Read the next line
		line = file.readline()

		
		if not line:
			
			#Get current size of open EVE file
			current_size = os.fstat(file.fileno()).st_size

			#Detect if the file was truncated
			if current_size < file.tell():
				print("Warning: EVE JSON log was truncated.")
				print("Restarting reader from beginning of file.")
				file.seek(0)
				save_position_safely(file)
				last_checkpoint = time.monotonic()

			time.sleep(0.1) #save CPU by sleeping 100ms inbetween checks
			continue

		#Check to have the agent wait in case suricata is not done writing the line to the EVEJSON
		if not line.endswith(b"\n"):
			file.seek(line_start)
			time.sleep(0.1)
			continue

		#Try to convert the JSON line into a python object
		try:
			event = json.loads(line) #converts json into python

		except (json.JSONDecodeError, UnicodeDecodeError) as error:
			print(f"Warning: Invalid or malformed EVEJSON skipped: {error}")
			last_checkpoint = checkpoint_if_due(file, last_checkpoint)
			continue

		#Check to make sure the python object is a dictionary
		if not isinstance(event, dict):
			print("Warning: EVE JSON event is not a dictionary")
			last_checkpoint = checkpoint_if_due(file, last_checkpoint)
			continue

		event_type = event.get("event_type", "unkown") #prevent crash if unkown event exists
		
		#Print only alerts and relevant information
		if event_type == "alert":
			alert_info = event.get("alert")
			
			#Safety check to prevent crashing on a malformed event
			if not isinstance(alert_info, dict):
				print("Warning: Invalid event object skipped")
				last_checkpoint = checkpoint_if_due(file, last_checkpoint)
				continue

			timestamp = event.get("timestamp", "unkown")
			src_ip = event.get("src_ip")
			src_port = event.get("src_port")
			dest_ip = event.get("dest_ip")
			dest_port = event.get("dest_port")
			proto = event.get("proto")

			signature = alert_info.get("signature", "unkown")
			category = alert_info.get("category")
			severity = alert_info.get("severity")
			
			alert_id = str(uuid.uuid4())	#Assign uuid

			#Package the alert as a python dictionary
			alert_data = {
				"alert_id": alert_id,
				"sensor_id": SENSOR_ID,
				"timestamp": timestamp,
				"src_ip": src_ip,
				"src_port": src_port,
				"dest_ip": dest_ip,
				"dest_port": dest_port,
				"proto": proto,
				"signature": signature,
				"category": category,
				"severity": severity
			}

			print("\nALERT DETECTED")
			print(json.dumps(alert_data, indent=4))

			#Store alert in the queue
			store_alert_safely(alert_data, file)
			last_checkpoint = time.monotonic()
		
		else: 
			#Periodically save progress for non-alert events
			last_checkpoint = checkpoint_if_due(file, last_checkpoint)
