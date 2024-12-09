import socket
import scapy.all as scapy
import requests
import time
import subprocess


def print_hi(name):
    print(f'Hi, {name}')


def scan_ports(target_ip, ports, timeout):
    open_ports = []
    for port in ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((target_ip, port))
        if result == 0:
            open_ports.append(port)
        sock.close()
    return open_ports


def grab_banner(ip, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((ip, port))
        sock.settimeout(1)
        if port == 80 or port == 443:  # HTTP/HTTPS
            sock.sendall(b"HEAD / HTTP/1.1\r\nHost: %s\r\n\r\n" % ip.encode('utf-8'))
        elif port == 21:  # FTP
            sock.sendall(b"USER anonymous\r\n")
        elif port == 22:  # SSH
            sock.sendall(b"SSH-2.0-OpenSSH_7.9p1 Debian-10+deb10u2\r\n")
        elif port == 25:  # SMTP
            sock.sendall(b"EHLO example.com\r\n")
        banner = sock.recv(1024).decode('utf-8', errors='ignore')
        sock.close()
        return banner
    except Exception:
        return None


def search_cve(service_name, version):
    url = f"https://services.nvd.nist.gov/rest/json/cves/1.0?keyword={service_name}%20{version}"
    try:
        response = requests.get(url)
        if response.status_code == 200:
            cve_data = response.json()
            if cve_data.get("result") and cve_data['result'].get("CVE_Items"):
                return cve_data['result']["CVE_Items"]
        return []
    except Exception as e:
        print(f"Error fetching CVE data: {e}")
        return []


def check_vulnerabilities(service_name, version):
    cve_list = search_cve(service_name, version)
    if cve_list:
        print(f"\nVulnerabilities found for {service_name} {version}:")
        for cve in cve_list:
            cve_id = cve.get('cve', {}).get('CVE_data_meta', {}).get('ID', 'Unknown')
            description = cve.get('cve', {}).get('description', {}).get('description_data', [{}])[0].get('value',
                                                                                                         'No description')
            print(f"- {cve_id}: {description}")
    else:
        print(f"No known vulnerabilities for {service_name} {version}.")


def scan_target(target, port_range, timeout, delay_between_scans, max_scan_time):
    print(f"Scanning target: {target}")

    start_time = time.time()  # זמן התחלה של הסריקה

    # בדיקת אם זהו URL או IP
    if "http" in target:
        target_ip = socket.gethostbyname(target.replace("http://", "").replace("https://", ""))
    else:
        target_ip = target

    # סריקת פורטים פתוחים
    ports = range(port_range[0], port_range[1] + 1)
    open_ports = scan_ports(target_ip, ports, timeout)

    print(f"Open ports: {open_ports}")

    for port in open_ports:
        # בדיקה אם עבר הזמן הכולל
        if time.time() - start_time > max_scan_time:
            print(f"Maximum scan time of {max_scan_time} seconds reached. Stopping the scan.")
            break

        banner = grab_banner(target_ip, port)
        if banner:
            print(f"Port {port} banner: {banner.splitlines()[0]}")
            if port == 80 or port == 443:
                service_name = "HTTP"
                version = banner.split(" ")[1] if "Server" in banner else "Unknown"
                check_vulnerabilities(service_name, version)
            elif port == 21:
                service_name = "FTP"
                version = banner.splitlines()[0] if "FTP" in banner else "Unknown"
                check_vulnerabilities(service_name, version)
            elif port == 22:
                service_name = "SSH"
                version = banner.splitlines()[0].split(" ")[1] if "SSH" in banner else "Unknown"
                check_vulnerabilities(service_name, version)
            elif port == 25:
                service_name = "SMTP"
                version = banner.splitlines()[0] if "SMTP" in banner else "Unknown"
                check_vulnerabilities(service_name, version)
        else:
            print(f"No banner found on port {port}.")

        # זמן המתנה בין סריקות
        time.sleep(delay_between_scans)

        # בדיקת הזמן שוב לאחר כל סריקה
        if time.time() - start_time > max_scan_time:
            print(f"Maximum scan time of {max_scan_time} seconds reached. Stopping the scan.")
            break

    # הרצת כלים SQLMap ו-XSSer על היעד
    run_sqlmap(target)
    run_xsser(target)


def run_sqlmap(target):
    print(f"\nRunning sqlmap on target: {target}")
    try:
        # הפעלת sqlmap
        result = subprocess.run(["sqlmap", "-u", target, "--batch", "--crawl=1"], capture_output=True, text=True)
        if result.returncode == 0:
            print(f"sqlmap output:\n{result.stdout}")
        else:
            print(f"sqlmap error:\n{result.stderr}")
    except Exception as e:
        print(f"Error running sqlmap: {e}")


def run_xsser(target):
    print(f"\nRunning XSSer on target: {target}")
    try:
        # הפעלת XSSer
        result = subprocess.run(["python3", "XSSer.py", "-u", target, "--crawl", "--output", "results.txt"],
                                capture_output=True, text=True)
        if result.returncode == 0:
            print(f"XSSer output:\n{result.stdout}")
        else:
            print(f"XSSer error:\n{result.stderr}")
    except Exception as e:
        print(f"Error running XSSer: {e}")


# הסבר למשתמש לגבי כל פרמטר
def explain_options():
    print("\nExplanation of each option:")
    print("1. Target (IP or URL): This is the address (either IP or URL) you want to scan.")
    print("2. Start and End Port: These define the range of ports you want to scan, inclusive.")
    print(
        "3. Timeout (seconds): This is the maximum time to wait for a response from each port. If the port does not respond within this time, it is considered closed.")
    print(
        "4. Delay Between Scans (seconds): This is the wait time between scanning each port. It's used to avoid overwhelming the server or the network.")
    print(
        "5. Max Scan Time (seconds): This is the maximum total time allowed for the scan. If the scan exceeds this time, it will stop.\n")


# בקשה מהמשתמש להכניס זמן המתנה בין סריקות (ב-שניות)
def explain_delay_input():
    print("\nExplanation for Delay Between Scans:")
    print("This parameter controls how long the scanner will wait before moving to the next port.")
    print("You can set this value based on your preference, keeping in mind the following options:")
    print(
        "1. **Low Delay (e.g., 0.1-0.5 seconds)**: This will make the scan faster, but it may put more load on the network and the target.")
    print("2. **Medium Delay (e.g., 1.0-2.0 seconds)**: A good balance between speed and network load.")
    print(
        "3. **High Delay (e.g., 5.0-10.0 seconds)**: This will slow down the scan but reduce network load and minimize the risk of detection.")
    print(
        "Choose the delay based on your network speed, the target's load, and how quickly you want the scan to complete.")


# פונקציה ראשית לקרוא את הקוד
def main():
    target = input("Enter IP or URL to scan: ")
    start_port = int(input("Enter start port: "))
    end_port = int(input("Enter end port: "))

    # הצגת הסבר למשתמש
    explain_options()

    # בקשה מהמשתמש להכניס את זמן ה-timeout (ב-שניות) לכל סריקה
    timeout = float(input("Enter timeout for each scan (in seconds, e.g., 1.0): "))

    # הצגת הסבר על זמן המתנה בין סריקות
    explain_delay_input()

    # בקשה מהמשתמש להכניס זמן המתנה בין סריקות (ב-שניות)
    delay_between_scans = float(input("Enter delay between scans (in seconds, e.g., 0.1): "))
    print("For small port range scans: A total scan time of 5-10 minutes will be effective.")
    print("For scanning large networks or many ports: A total scan time of 30 minutes to 1 hour may be suitable.")
    # בקשה מהמשתמש להכניס את הזמן הכולל לסריקה
    max_scan_time = float(input("Enter maximum scan time (in seconds, e.g., 10.0): "))

    scan_target(target, (start_port, end_port), timeout, delay_between_scans, max_scan_time)


if __name__ == "__main__":
    main()
