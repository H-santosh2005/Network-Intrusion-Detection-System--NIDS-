# Using real Snort (optional)
1. Install Snort (Ubuntu: `sudo apt install snort`; Windows: installer from snort.org + Npcap).
2. Run Snort on your own machine/network with the project rules, writing a fast alert file:
   `sudo snort -i <interface> -c /etc/snort/snort.conf -R backend/rules/local.rules -A fast -l snort/logs`
   (Snort 3: `snort -c snort.lua -R backend/rules/local.rules -i <iface> -A alert_fast -l snort/logs`)
3. Start the dashboard pointing at the alert file:
   - Linux/macOS: `SNORT_ALERT_FILE=snort/logs/alert_fast.txt python backend/app.py` (Snort 2 names it `alert`)
   - Windows PowerShell: `$env:SNORT_ALERT_FILE="snort\logs\alert"; python backend\app.py`
Only monitor networks you own or have permission to monitor.
