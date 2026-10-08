import json	#suricata writes JSON text and pythons json module converts that text into normal python dictionary
import time	#needed to let cpu rest between alerts
import uuid 	#needed for id's for each alert
import requests 

SENSOR_ID = "sensor2-laptop"		#name of the sensor
EVE_FILE = "/var/log/suricata/eve.json"	#store the path to the eve file
SERVER_URL = "http://SERVER_IP/alerts"	#put your server ip here

#opens and reads the eve file, to parse it for specific event types
with open(EVE_FILE, "r") as file:

	file.seek(0, 2) #move to end of file

	print("Watching for new Suricata events...")
	
	#keep the agent reading for new events
	while True:
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

			#Try to send alert as JSON with proper HTTP header
			try:
				response = requests.post(
					SERVER_URL,
					json=alert_data,
					timeout=5
				)
				
				print(f"Server response: {response.status_code}")

			except requests.RequestException as error:
				print(f"Failed to send alert: {error}")
