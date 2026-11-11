from fastapi import FastAPI, Depends	#main api framework
from pydantic import BaseModel	#used for data structure
from typing import Optional	#used for optional alert fields
from database import (
	save_alert, 
	save_heartbeat, 
	get_sensor_status, 
	get_alert_statistics,
	get_recent_alerts)    #import the save functions from database.py
from fastapi import Header, HTTPException, Request
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles 
from fastapi.templating import Jinja2Templates
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from pathlib import Path
import secrets #Pythons library for authentication token use


#Load authentication for monitoring
MONITOR_TOKEN_PATH = Path.home() / "nids-secrets" / "monitor.token"


MONITOR_TOKEN = MONITOR_TOKEN_PATH.read_text(encoding="utf-8").strip()

if not MONITOR_TOKEN: 
	raise RuntimeError("Monitoring token is empty")

#Load authentication tokens for sensors
SENSOR1_TOKEN_PATH = Path.home() / "nids-secrets" / "sensor1.token"
SENSOR2_TOKEN_PATH = Path.home() / "nids-secrets" / "sensor2.token"

SENSOR_TOKENS = {
	"sensor1-pi": SENSOR1_TOKEN_PATH.read_text(encoding="utf-8").strip(),
	"sensor2-laptop": SENSOR2_TOKEN_PATH.read_text(encoding="utf-8").strip()
}

if not all (SENSOR_TOKENS.values()):
	raise RuntimeError("Sensor 2 authentication token is empty")


#Initialize app
app = FastAPI()

#Security
dashboard_security = HTTPBasic()

#Ensure monitoring is secure and can only be accessed through the monitoring token
def authenticate_dashboard(credentials: HTTPBasicCredentials = Depends(dashboard_security)):

	#Uses "monitor" for username and the monitoring token for the password
	valid_username = secrets.compare_digest(credentials.username.encode("utf-8"),b"monitor")
	valid_password = secrets.compare_digest(credentials.password.encode("utf-8"), MONITOR_TOKEN.encode("utf-8"))

	if not (valid_username and valid_password):
		raise HTTPException(
			status_code=401,
			detail="Invalid monitoring credentials",
			headers={"WWW-Authenticate": "Basic"}
		)


#Configures where FastAPI looks for html and css files
BASE_DIR = Path(__file__).resolve().parent

templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))

app.mount(
	"/static",
	StaticFiles(directory=str(BASE_DIR / "static")),
	name="static"
)

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

#Defines base data structure for receiving heartbeats
class Heartbeat(BaseModel):
	sensor_id: str


#Function to authenticate sensors
def authenticate_sensor(sensor_id: str, authorization: str | None):
	
	#Find the expectedtoken
	expected_token = SENSOR_TOKENS.get(sensor_id)

	#Extract the bearer token from header
	scheme, separator, received_token = (
		authorization or ""
	).partition(" ")

	#Verify the token
	if (
		expected_token is None
		or scheme.lower() != "bearer"
		or not received_token
		or not secrets.compare_digest(
			received_token, expected_token
		)
	):
		raise HTTPException(
			status_code=401,
			detail="Invalid or missing sensor credentials",
			headers={"WWW-Authenticate": "Bearer"}
		)

#Base endpoint
@app.get("/")
def root():
	return {"status": "NIDS server running"}

#Alerts endpoint
@app.post("/alerts")
def receive_alert(alert: Alert, authorization: str | None = Header(default=None)):

	#Authenticate the sensor
	authenticate_sensor(alert.sensor_id, authorization)


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

#Heartbeat Endpoint
@app.post("/heartbeat")
def receive_heartbeat(
	heartbeat: Heartbeat,
	authorization: str | None = Header(default=None)
):

	#Authenticate the sensor
	authenticate_sensor(heartbeat.sensor_id, authorization)

	# Store latest heartbeat
	received_at = save_heartbeat(heartbeat.sensor_id)

	print(f"Heartbeat received from {heartbeat.sensor_id}")

	return {
		"status": "received",
		"sensor_id": heartbeat.sensor_id,
		"received_at": received_at
	}

#Endpoint for sensor status
@app.get("/sensors/{sensor_id}/status")
def sensor_status(
	sensor_id: str,
	authorization: str | None = Header(default=None)
):
	#Validate Monitoring Credentials
	scheme, separator, received_token = (
		authorization or "").partition(" ")

	if (
		scheme.lower() != "bearer"
		or not received_token
		or not secrets.compare_digest(
			received_token, MONITOR_TOKEN
		)
	):
		raise HTTPException(
			status_code=401,
			detail="Invalid or missing monitoring credentials",
			headers={"WWW-Authenticate": "Bearer"}
		)

	#Calculate sensor status
	return get_sensor_status(sensor_id)


#Endpoint for monitoring dashboard
@app.get("/dashboard", response_class=HTMLResponse)
def dashboard(request: Request, _: None = Depends(authenticate_dashboard)):

	return templates.TemplateResponse(
		request=request,
		name="dashboard.html"
	)


@app.get("/dashboard/data")
def dashboard_data(_: None = Depends(authenticate_dashboard)):
	sensors = []
	available_count = 0

	#Retrieve the status of each sensor
	for sensor_id in SENSOR_TOKENS:
		status = get_sensor_status(sensor_id)

		sensors.append({
			"sensor_id": sensor_id,
			"details": status
		})

		if status["status"] == "online":
			available_count += 1

	#Retrieve alert statistics
	statistics = get_alert_statistics()

	#Retrieve recent alerts
	recent_alerts = get_recent_alerts(limit=10)

	return {
		"sensors": sensors,
		"statistics": {
			"total_alerts": statistics["total_alerts"],
			"high_severity_alerts": statistics["high_severity_alerts"],
			"available_sensors": available_count,
			"total_sensors": len(SENSOR_TOKENS)
		},
		"recent_alerts": recent_alerts
	}
