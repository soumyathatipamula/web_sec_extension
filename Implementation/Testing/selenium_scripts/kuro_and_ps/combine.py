import csv
import pandas as pd

def fetch_payloads_from_local_files(file1="payloads1.txt", file2="payloads2.txt"):
    payloads = []
    for file_name in [file1, file2]:
        try:
            with open(file_name, 'r', encoding='utf-8') as f:
                lines = f.read().splitlines()
                for line in lines:
                    line = line.strip()
                    if line:  # Only add non-empty lines
                        payloads.append(line)
        except FileNotFoundError:
            print(f"Warning: Could not find {file_name}. Skipping...")
        except Exception as e:
            print(f"Error reading {file_name}: {e}")
    return payloads if payloads else []


local_payloads = fetch_payloads_from_local_files("../../../Cheatsheet/portswigger_cheatsheet.txt", "../../Cheatsheet/xss_vectors_kurobeats.txt")


print(f"Collected {len(local_payloads)} base payloads")
# Save the payloads to a CSV file
with open("base_xss_payloads.csv", "w", newline="", encoding="utf-8") as file:
    writer = csv.writer(file)
    writer.writerow(["payload"])
    for payload in local_payloads:
        writer.writerow([payload])