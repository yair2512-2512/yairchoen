import time
import pandas as pd
from sklearn.ensemble import IsolationForest
import ipaddress
import logging
import re
import pickle
from datetime import datetime
import json
from termcolor import colored

# הגדרת מערכת רישום לוגים
logging.basicConfig(filename="model_output.log", level=logging.INFO, format="%(asctime)s - %(message)s")

# פונקציה לבדוק אם כתובת IP תקינה
def is_valid_ip(ip):
    try:
        ipaddress.IPv4Address(ip)
        return True
    except ipaddress.AddressValueError:
        return False

# פונקציה להאט את הפלט
def slow_print(text, delay=5):
    print(text)  # הדפסת הפלט למסך
    logging.info(text)  # שמירה על הפלט בקובץ הלוג
    time.sleep(delay)  # המתנה של 5 שניות לפני הדפסת הודעה נוספת

# פונקציה לנקות את הנתונים ולהסיר תאריכים וערכים לא תקינים
def clean_data(data):
    data['frame.time'] = data['frame.time'].apply(
        lambda x: re.sub(r'[^a-zA-Z0-9\s:,.]', '', str(x)))  # שומר רק אותיות, מספרים, רווחים, נקודות ופסיקים

    def parse_time(time_str):
        try:
            return pd.to_datetime(time_str, errors='coerce')
        except Exception:
            return None

    data['frame.time'] = data['frame.time'].apply(parse_time)
    data = data[data['frame.time'].notnull()]
    data['frame.time'] = data['frame.time'].apply(lambda x: x.timestamp() if pd.notnull(x) else None)
    data = data[data['ip.src'].apply(is_valid_ip) & data['ip.dst'].apply(is_valid_ip)]
    data['ip.src'] = data['ip.src'].apply(lambda x: int(ipaddress.IPv4Address(x)) if is_valid_ip(x) else None)
    data['ip.dst'] = data['ip.dst'].apply(lambda x: int(ipaddress.IPv4Address(x)) if is_valid_ip(x) else None)
    data = data.dropna(subset=['ip.src', 'ip.dst'])
    return data

# שמירה וטעינה של המיקום האחרון
def save_last_row(last_row, filename="last_row.json"):
    with open(filename, 'w') as f:
        json.dump({"last_row": last_row}, f)

def load_last_row(filename="last_row.json"):
    try:
        with open(filename, 'r') as f:
            data = json.load(f)
        return data.get("last_row", 0)
    except FileNotFoundError:
        return 0  # אם אין מיקום קודם, נתחיל מההתחלה

# פונקציה לקרוא את הנתונים החדשים אחרי המיקום האחרון
def get_new_data(file_path, last_row):
    data = pd.read_csv(file_path, encoding='utf-8', on_bad_lines='skip')
    return data.iloc[last_row:]

# אימון המודל בהתחלה על נתונים קיימים (אם יש)
def train_model(data):
    model = IsolationForest(contamination=0.00000000001)
    features = ['ip.src', 'ip.dst', 'frame.len', 'frame.time']
    model.fit(data[features])
    return model

# שמירה וטעינה של המודל
def save_model(model, filename="model.pkl"):
    with open(filename, 'wb') as file:
        pickle.dump(model, file)

def load_model(filename="model.pkl"):
    try:
        with open(filename, 'rb') as file:
            model = pickle.load(file)
        return model
    except FileNotFoundError:
        return None

# טעינת מודל קיים אם קיים
model = load_model()

if model is None:
    print("No pre-trained model found. Starting with new model.")
else:
    print("Pre-trained model loaded.")

# הפעלת הקוד בזמן אמת
while True:
    try:
        # טעינת המיקום האחרון של הסריקה
        last_row = load_last_row()

        # קריאה לנתונים חדשים אחרי המיקום האחרון
        data = get_new_data('scan_output.csv', last_row)

        # ניקוי הנתונים
        data = clean_data(data)

        if data.empty:
            print("No valid data to predict or update the model")
        else:
            # אם אין מודל קודם, נתחיל לאמן
            if model is None:
                model = train_model(data)
                save_model(model)  # שמירת המודל החדש
                print("Model trained and saved.")
            else:
                # חישוב ציוני החריגה
                features = ['ip.src', 'ip.dst', 'frame.len', 'frame.time']
                scores = model.decision_function(data[features])  # חישוב ציוני החריגה

                # קביעת סף לפי אחוז (למשל, 1% הנמוכים ביותר)
                # קביעת סף מוחלט (למשל -0.1 או כל ציון שמעניין אותך)
                threshold = -0.5

                # הדפסת חריגות חזקות
                for idx, score in enumerate(scores):
                    if score < threshold:  # הציון קטן מהסף המוחלט
                        anomaly_message = f"Anomalous packet detected with score {score}: {data.iloc[idx]}"
                        print(colored(anomaly_message, 'red', attrs=['bold']))  # הדפסה אדומה ובולטת

                # עדכון המיקום האחרון
                last_row += len(data)
                save_last_row(last_row)  # שמירת המיקום האחרון של הסריקה

                # אימון מחדש של המודל עם הנתונים החדשים (אם יש צורך)
                model = train_model(data)  # אימון מחדש על הנתונים החדשים
                save_model(model)  # שמירת המודל המעודכן
                print("Model re-trained with new data.")

    except Exception as e:
        print(f"Error: {e}")

