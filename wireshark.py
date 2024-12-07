import subprocess
import time
import os

# הדפסת הנתיב המלא לקובץ
output_file = 'scan_output.csv'
print("נתיב הקובץ:", os.path.abspath(output_file))

# הגדרת זמן הסריקה בדקות
duration = 1  # זמן הסריקה בדקה


# פונקציה לעיבוד הזמן
def process_time(time_string):
    # חיתוך רק את החלק של הזמן (למשל: "Dec 6, 2024 02:50:08.436843")
    time_parts = time_string.split(' ')
    return ' '.join(time_parts[:2])  # מחזיר את החלק הראשון והשלישי של הזמן


# הפעלת סריקה כל 60 שניות
while True:
    try:
        # פקודה להריץ את tshark ולשמור את הנתונים בקובץ CSV
        command = [
            "tshark", "-i", r"\Device\NPF_{E0FB1C49-3B7E-4E7E-8FF8-E5E8C3BDFEB5}",  # ודא שהממשק שלך נכון
            "-a", f"duration:{duration * 60}",  # זמן הסריקה בדקות
            "-T", "fields",  # הפלט יהיה רק שדות
            "-e", "frame.time",  # זמן
            "-e", "ip.src",  # כתובת ה-IP של השולח
            "-e", "ip.dst",  # כתובת ה-IP של היעד
            "-e", "ip.proto",  # פרוטוקול IP
            "-e", "frame.len",  # אורך המנות
            "-E", "separator=,",  # מפריד בין הערכים בפלט
            "-E", "quote=d",  # להוסיף גרשיים מסביב לערכים
            "-E", "header=y"  # כולל כותרת
        ]

        # הפעלת הפקודה וקריאת הפלט בקידוד UTF-8
        result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, encoding='utf-8')

        # אם יש פלט, עיבודו
        if result.stdout:
            with open(output_file, 'a', newline='', encoding='utf-8') as f:
                # עיבוד כל שורה בפלט
                for line in result.stdout.splitlines():
                    # פיצול השורה לפי פסיקים
                    columns = line.split(',')

                    if columns:
                        # עיבוד הזמן (חיתוך החלק שלא רצוי אחרי הזמן)
                        columns[0] = process_time(columns[0])  # עיבוד הזמן ישירות בעמודה

                        # כתיבה לקובץ
                        f.write(','.join(columns) + '\n')

            print(f"סיום סריקה ב-{output_file}")
        else:
            print("לא התקבל פלט מהפקודה tshark.")

    except Exception as e:
        print(f"בעיה: {e}")

    # המתנה 60 שניות לפני הסריקה הבאה
    time.sleep(60)  # המתנה של 60 שניות לפני הפעלת הסריקה הבאה
