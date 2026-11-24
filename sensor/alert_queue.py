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

		#Store the last processed position in the EVE JSON file
		conn.execute("""
			CREATE TABLE IF NOT EXISTS reader_state (
				source_path TEXT PRIMARY KEY,
				device INTEGER NOT NULL,
				inode INTEGER NOT NULL,
				offset INTEGER NOT NULL
			)
		""")

# Retrieve the last saved EVE JSON reader position
def get_reader_state(source_path):
	with closing(sqlite3.connect(DB_PATH)) as conn:
		row = conn.execute("""
			SELECT device, inode, offset
			FROM reader_state
			WHERE source_path = ?
		""", (str(source_path),)).fetchone()

	return row

# Update the reader last saved position into a checkpoint
def _update_reader_state(conn, source_path, device, inode, offset):
	conn.execute("""
		INSERT INTO reader_state (source_path, device, inode, offset)
		VALUES (?, ?, ?, ?)
		ON CONFLICT(source_path) DO UPDATE SET
			device = excluded.device,
			inode = excluded.inode,
			offset = excluded.offset
	""", (str(source_path), device, inode, offset))

#Save a reader checkpoint
def save_reader_state(source_path, device, inode, offset):
	with closing(sqlite3.connect(DB_PATH, timeout=10)) as conn:
		with conn:
			_update_reader_state(
				conn, source_path, device, inode, offset
			)


#New function that stores an alert and checkpoint in the same transaction
def enqueue_alert_and_checkpoint(alert, source_path, device, inode, offset):
	alert_id = alert["alert_id"]
	payload = json.dumps(alert)

	with closing(sqlite3.connect(DB_PATH, timeout=10)) as conn:
		with conn:
		
			#Insert the alert into the local queue
			cursor = conn.execute("""
				INSERT OR IGNORE INTO pending_alerts
				(alert_id, payload_json)
				VALUES (?, ?)
			""", (alert_id, payload))

			#Update the reader position in the same process
			_update_reader_state(conn, source_path, device, inode, offset)

			inserted = cursor.rowcount == 1

		return inserted


#Function to enqueue alerts into the buffer (old)
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
