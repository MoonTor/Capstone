import sqlite3
from pathlib import Path
from contextlib import closing

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

if __name__ == "__main__":
	initialize_database()
	print(f"Database initialized at: {DB_PATH}")
