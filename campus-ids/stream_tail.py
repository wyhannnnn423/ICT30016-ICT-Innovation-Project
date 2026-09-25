import time
import json
import os

def tail_eve_json(file_path):
    """
    Continuously listen to the Suricata eve.json log file in real-time.
    This acts like the 'tail -f' command in Linux.
    """
    if not os.path.exists(file_path):
        print(f"[!] Error: Target log file not found at {file_path}")
        return

    print(f"[*] Initializing real-time monitoring on {file_path}...")
    print("[*] Waiting for new network traffic...\n")
    
    with open(file_path, "r", encoding="utf-8") as f:
        # Move the file pointer to the very end of the file.
        # We do this to ignore historical logs and only catch NEW traffic.
        f.seek(0, os.SEEK_END)

        while True:
            line = f.readline()
            
            if not line:
                # No new data has been written yet.
                # Sleep for 100ms to prevent 100% CPU usage, then check again.
                time.sleep(0.1)
                continue

            # We captured a new line. Let's parse it as JSON.
            try:
                event = json.loads(line.strip())
                
                # For our IDS model, we only care about 'flow' events.
                if event.get("event_type") == "flow":
                    src_ip = event.get("src_ip", "Unknown")
                    dest_ip = event.get("dest_ip", "Unknown")
                    proto = event.get("proto", "Unknown")
                    
                    # Print the core flow details instantly
                    print(f"[LIVE FLOW] Proto: {proto} | {src_ip} -> {dest_ip}")
                    
            except json.JSONDecodeError:
                # Suricata might be in the middle of writing a line.
                # If the JSON is incomplete, we safely ignore it.
                pass

if __name__ == "__main__":
    # Point this to your actual Suricata eve.json location.
    # Depending on your OS, it might be /var/log/suricata/eve.json 
    # or C:\\Program Files\\Suricata\\log\\eve.json
    TARGET_LOG = "C:\Program Files\Suricata\log\eve.json" 
    
    tail_eve_json(TARGET_LOG)