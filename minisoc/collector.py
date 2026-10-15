import os
import time
from minisoc.detector import detect_event
from minisoc.storage import save_alert


LOG_FILE = os.path.join(
    os.path.dirname(__file__),
    "..",
    "eduportal",
    "security.log"
)
def parse_log(line):
    parts = line.split(" - ", 2)

    if len(parts) < 3:
        return

    message = parts[2]

    if " | " not in message:
        return

    data = message.split(" | ")

    timestamp = parts[0]
    level = parts[1]
    event = data[0]

    event_data = {
        "timestamp": timestamp,
        "level": level,
        "event": event
    }

    for item in data[1:]:
        key, value = item.split("=", 1)
        event_data[key] = value

    print(event_data)

    result = detect_event(event_data)

    if result:
        result["timestamp"] =  event_data["timestamp"]
        result["ip"] = event_data.get("ip")
        print("alert:", result)

        save_alert(result)

if os.path.exists(LOG_FILE):
    print("security log found,")
    print("Waiting for new events...")

    with open(LOG_FILE, "r") as log_file:
        log_file.seek(0, 2)

        while True:
            line = log_file.readline()

            if not line:
                
                time.sleep(0.5)
                continue

            parse_log(line.strip())

else:
    print("security log not found,")
