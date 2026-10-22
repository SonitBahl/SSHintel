import tempfile
import os
from pathlib import Path
import sys

# Add parent directory to path
sys.path.insert(0, '/home/light/Desktop/Coding/SSHintel')

# Import the module
from honeypot import telemetry_store

# Create a temporary database manually
tmp_db = tempfile.mktemp(suffix='.db')
print(f'Testing with db: {tmp_db}')

# Check if parent directory exists
parent = Path(tmp_db).parent
print(f'Parent exists: {parent.exists()}')

# Create store and open
store = telemetry_store.TelemetryStore(tmp_db)
try:
    store.open()
    print('Store opened successfully')
except Exception as e:
    print(f'Error opening store: {e}')
    import traceback
    traceback.print_exc()

store.close()
os.unlink(tmp_db)
print('Test complete')