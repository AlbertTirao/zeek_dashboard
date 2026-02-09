# import os
# import json
# from pathlib import Path
# from datetime import datetime
# from config.client import FOLDER_ID, CLIENT_SECRET_FILE, PARQUET_DIR
# from services.drive_services import authenticate_drive, stream_zeek_log_to_parquet

# # Use your existing config paths
# MANIFEST_PATH = PARQUET_DIR / "sync_manifest.json"

# def load_manifest():
#     if MANIFEST_PATH.exists():
#         return json.loads(MANIFEST_PATH.read_text())
#     return {}

# def save_manifest(manifest):
#     MANIFEST_PATH.parent.mkdir(parents=True, exist_ok=True)
#     MANIFEST_PATH.write_text(json.dumps(manifest, indent=2))

# def run_sync():
#     print(f"Starting Sync: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
#     drive = authenticate_drive(CLIENT_SECRET_FILE)
#     manifest = load_manifest()

#     # Query: find all .log files not in trash
#     query = f"'{FOLDER_ID}' in parents and trashed=false"
#     files = drive.ListFile({'q': query}).GetList()

#     for f in files:
#         file_id = f['id']
#         file_name = f['title']
#         remote_version = f.get('version')

#         if not file_name.endswith(".log") or "conn-summary" in file_name:
#             continue

#         # Skip if we already have this exact version
#         if manifest.get(file_id) == remote_version:
#             continue

#         # data/parquet/YYYY-MM-DD/type.parquet
#         log_date = datetime.fromisoformat(f["modifiedDate"].replace("Z", "+00:00")).strftime("%Y-%m-%d")
#         log_type = file_name.replace(".log", "")
#         save_path = PARQUET_DIR / log_date / f"{log_type}.parquet"

#         print(f"Syncing {file_name} (New version: {remote_version})...")
#         try:
#             stream_zeek_log_to_parquet(drive, f, save_path)
#             manifest[file_id] = remote_version
#             save_manifest(manifest)
#         except Exception as e:
#             print(f"Failed to sync {file_name}: {e}")

# if __name__ == "__main__":
#     run_sync()