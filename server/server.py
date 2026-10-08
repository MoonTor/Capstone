from fastapi import FastAPI	#main api framework
from pydantic import BaseModel	#used for data structure
from typing import Optional	#used for optional alert fields

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

@app.post("/alerts")
def receive_alert(alert: Alert):
	print("\nALERT RECEIVED")
	print(alert.model_dump())

	return {
		"status": "received",
		"alert_id": alert.alert_id
	}
