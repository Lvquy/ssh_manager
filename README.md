
Build to app MacOs

B1: terminal
pip install pyinstaller

B2: terminal
pyinstaller --windowed --onefile --add-data "servers.json:."  --icon icon.icns ssh_manager.py

B3: 
In the 'dist' folder, run ssh_manager app