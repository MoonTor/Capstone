import json	#suricata writes JSON text and pythons json module converts that text into normal python dictionary
import time	#needed to let cpu rest between alerts
import uuid 	#needed for id's for each alert
import requests
import sqlite3
import threading #Needed for background thread HTTPS sending
from pathlib import Path 
from alert_queue import (
	initialize_queue,
	enqueue_alert,
	get_pending_alerts,
	remove_alert
)

SENSOR_ID = "sensor2-laptop"		#name of the sensor
EVE_FILE = "/var/log/suricata/eve.json"	#store the path to the eve file

SERVER_URL = "https://YOURURLHERE:8443/alerts"	#url for the server
CA_CERT = "/home/USER/nids-certs/ca.crt"	#Store path to certs

TOKEN_PATH = Path("/home/USER/nids-secrets/sensor2.token")
SENSOR_TOKEN = TOKEN_PATH.read_text(encoding="utf-8").strip()

HEARTBEAT_URL = "https://YOURURLHERE:8443/heartbeat" #URL for heatbeat endpoint
HEARTBEAT_INTERVAL = 30	

RETRY_INTERVAL = 5 #How long in between message retry
MAX_RETRY_BATCH = 20 #Max amount of queued alerts


#Check if token exists
if not SENSOR_TOKEN:
	raise RuntimeError("Sensor authentication token is empty")

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

retry_event = threading.Event()

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

#opens and reads the eve file, to parse it for specific event types
with open(EVE_FILE, "r") as file:

	file.seek(0, 2) #move to end of file

	print("Watching for new Suricata events...")
	
	#Start the clock for heartbeat timings
	next_heartbeat = time.monotonic()

	#keep the agent reading for new events
	while True:

		#Check if it is time to send a heartbeat
		if time.monotonic() >= next_heartbeat:
			send_heartbeat()

			#Schedule next heartbeat
			next_heartbeat = (time.monotonic() + HEARTBEAT_INTERVAL)

		#Begin reading
		line = file.readline()

		if not line:
			time.sleep(0.1) #save CPU by sleeping 100ms inbetween checks
			continue

		event = json.loads(line) #converts json into python dictionary

		event_type = event.get("event_type", "unkown") #prevent crash if unkown event exists
		
		#Print only alerts and relevant information
		if event_type == "alert":
			alert_info = event.get("alert", {})
			
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
			enqueue_alert(alert_data)
			print(f"Alert queued: {alert_data['alert_id']}")

			#Notify background sender that a new alert is ready
			retry_event.set()
