from fastapi import FastAPI	#main api framework
from pydantic import BaseModel	#used for data structure
from typing import Optional	#used for optional alert fields
from database import save_alert #import the save_alert function from database.py
from fastapi import Header, HTTPException
from pathlib import Path
import secrets #Pythons library for authentication token use

#Load authentication token for sensor2
TOKEN_PATH = Path.home() / "nids-secrets" / "sensor2.token"

SENSOR_TOKENS = {
	"sensor2-laptop": TOKEN_PATH.read_text(encoding="utf-8").strip()
}

if not SENSOR_TOKENS["sensor2-laptop"]:
	raise RuntimeError("Sensor 2 authentication token is empty")



app = FastAPI()

#Defines base data structure for receiving alerts
class Alert(BaseModel):
	alert_id: str
	sensor_id: str
	timestamp: str

	src_ip: Optional[str] = None
	src_port: Optional[int] = None
	dest_ip: Optional[str] = None
	dest_port: Optional[int] = None
	proto: Optional[str] = None

	signature: str
	category: Optional[str] = None
	severity: Optional[int] = None

@app.get("/")
def root():
	return {"status": "NIDS server running"}


#Alerts endpoint
@app.post("/alerts")
def receive_alert(alert: Alert, authorization: str | None = Header(default=None)):

	#Find the expected token
	expected_token = SENSOR_TOKENS.get(alert.sensor_id)

	#Extract the Bearer token from Header
	scheme, separator, received_token = (authorization or "").partition(" ")

	#Verify the credentials
	if (
		expected_token is None
		or scheme.lower() != "bearer"
		or not received_token
		or not secrets.compare_digest(received_token, expected_token)
	):
		raise HTTPException(
			status_code=401,
			detail="Invalid or missing sensor credentials",
			headers={"WWW-Authenticate": "Bearer"}
		)


	#If authentication successfull begin save-alert process
	alert_data = alert.model_dump()
	
	# Save the alert into the SQLite database
	stored = save_alert(alert_data)

	if stored:
		print(f"Alert stored: {alert.alert_id}")
	else:
		print(f"Duplicate alert skipped: {alert.alert_id}")
	
	return {
		"status": "received",
		"alert_id": alert.alert_id,
		"stored": stored
	}

