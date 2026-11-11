import sqlite3
import json
from pathlib import Path
from contextlib import closing

DB_PATH = Path(__file__).resolve().parent / "alert_queue.db"

#Function to initialize the queue system
def initialize_queue():
	with sqlite3.connect(DB_PATH) as conn:
		conn.execute("""
			CREATE TABLE IF NOT EXISTS pending_alerts (
				alert_id TEXT PRIMARY KEY,
				payload_json TEXT NOT NULL,
				queued_at TEXT DEFAULT CURRENT_TIMESTAMP
			)
		""")

#Function to enqueue alerts into the buffer
def enqueue_alert(alert):
	alert_id = alert["alert_id"]
	payload = json.dumps(alert)

	with closing(sqlite3.connect(DB_PATH)) as conn:
		with conn:
			cursor = conn.execute("""
				INSERT OR IGNORE INTO pending_alerts
				(alert_id, payload_json)
				VALUES (?, ?)
			""", (alert_id, payload))
			
			return cursor.rowcount == 1

#Function to query the alerts in the queue
def get_pending_alerts(limit=None):
	with closing(sqlite3.connect(DB_PATH)) as conn:

		if limit is None:
			rows = conn.execute("""
				SELECT payload_json
				FROM pending_alerts
				ORDER BY queued_at ASC, rowid ASC
			""").fetchall()

		else:
			rows = conn.execute("""
				SELECT payload_json
				FROM pending_alerts
				ORDER BY queued_at ASC, rowid ASC
				LIMIT ?
			""", (limit,)).fetchall()

	return [json.loads(row[0]) for row in rows]

#Function to dequeue alerts
def remove_alert(alert_id):
	with closing(sqlite3.connect(DB_PATH)) as conn:
		with conn:
			cursor = conn.execute("""
				DELETE FROM pending_alerts
				WHERE alert_id = ?
			""", (alert_id,))
			
			return cursor.rowcount == 1


if __name__ == "__main__":
	initialize_queue()
	print("Local alert queue initialized.")
