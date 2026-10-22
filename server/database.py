import sqlite3
from pathlib import Path
from contextlib import closing
from datetime import datetime, timezone

#Store the database next to the server code inside /data
DB_PATH = Path(__file__).resolve().parent / "data" / "alerts.db"

def initialize_database():
	# Create the data directory if it doesn't exist
	DB_PATH.parent.mkdir(parents=True, exist_ok=True)

	# Connect to SQLite to make the alerts table
	with closing(sqlite3.connect(DB_PATH)) as conn:
		with conn:
			conn.execute("""
				CREATE TABLE IF NOT EXISTS alerts (
					alert_id TEXT PRIMARY KEY NOT NULL,
					sensor_id TEXT NOT NULL,
					timestamp TEXT NOT NULL,
					src_ip TEXT,
					src_port INTEGER,
					dest_ip TEXT,
					dest_port INTEGER,
					proto TEXT,
					signature TEXT NOT NULL,
					category TEXT,
					severity INTEGER,
					received_at TEXT NOT NULL DEFAULT (
						strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
					)
				)
			""")
			
			# Create an index for filtering
			conn.execute("""
				CREATE INDEX IF NOT EXISTS idx_alerts_sensor_timestamp
				ON alerts (sensor_id, timestamp)
			""")

			# Create heartbeats table
			conn.execute("""
				CREATE TABLE IF NOT EXISTS sensor_heartbeats (
					sensor_id TEXT PRIMARY KEY,
					last_seen_at TEXT NOT NULL,
					heartbeat_count INTEGER NOT NULL DEFAULT 0
				)
			""")

# This function saves the incoming alert in the alerts table
#	ON CONFLICT prevents duplicates from being inserted
def save_alert(alert:dict):
	with closing(sqlite3.connect(DB_PATH)) as conn:
		with conn:
			cursor = conn.execute("""
				INSERT INTO alerts (
					alert_id, sensor_id, timestamp,
					src_ip, src_port, dest_ip, dest_port,
					proto, signature, category, severity
				)
				VALUES (
					:alert_id, :sensor_id, :timestamp,
					:src_ip, :src_port, :dest_ip, :dest_port,
					:proto, :signature, :category, :severity
				)
				ON CONFLICT(alert_id) DO NOTHING
			""", alert)

			# Return boolean for if alert was successfully inserted
			return cursor.rowcount == 1

#This function saves incoming heartbeat pulses from the sensors
def save_heartbeat(sensor_id: str) -> str:
	#Record the time the server received heartbeat
	received_at = datetime.now(timezone.utc).isoformat(
		timespec="milliseconds"
	).replace("+00:00", "Z")

	with closing(sqlite3.connect(DB_PATH)) as conn:
		with conn:
			conn.execute("""
				INSERT INTO sensor_heartbeats (
					sensor_id, last_seen_at, heartbeat_count
				)
				VALUES (?, ?, 1)
				ON CONFLICT(sensor_id) DO UPDATE SET
					last_seen_at = excluded.last_seen_at,
					heartbeat_count = heartbeat_count + 1
			""", (sensor_id, received_at))

	return received_at


#This function gets the sensor status by querying the last known heartbeat
#Based of the assigned time interval the sensor status may be deemed "offline"
def get_sensor_status(sensor_id: str):
	with closing(sqlite3.connect(DB_PATH)) as conn:
		row = conn.execute("""
			SELECT last_seen_at, heartbeat_count
			FROM sensor_heartbeats
			WHERE sensor_id = ?
		""", (sensor_id,)).fetchone()

	if row is None:
		return {
			"sensor_id": sensor_id,
			"status": "unkown",
			"last_seen_at": None
		}

	last_seen_at, heartbeat_count = row

	#Convert stored timestamp into datetime object
	last_seen = datetime.fromisoformat(
		last_seen_at.replace("Z", "+00:00")
	)

	#Calculate time from last heartbeat
	now = datetime.now(timezone.utc)
	elapsed = (now - last_seen).total_seconds()

	#Determine status (currently 90 seconds to be considered offline)
	status = "online" if elapsed <= 90 else "offline"

	return {
		"sensor_id": sensor_id,
		"status": status,
		"last_seen_at": last_seen_at,
		"seconds_since_heartbeat": round(elapsed, 2),
		"heartbeat_count": heartbeat_count
	}
# Main
if __name__ == "__main__":
	initialize_database()
	print(f"Database initialized at: {DB_PATH}")
