from scapy.all import sniff, TCP
import requests
import time
import threading
from functools import wraps
from datetime import datetime


packetCounter = 1
function_in_progress = False

def rate_limited(interval):
    def decorator(func):
        @wraps(func)
        def wrapped(*args, **kwargs):
            if not hasattr(wrapped, '_last_call_time'):
                wrapped._last_call_time = 0
            elapsed = time.time() - wrapped._last_call_time
            wait_time = interval - elapsed
            if wait_time > 0:
                time.sleep(wait_time)
            result = func(*args, **kwargs)
            wrapped._last_call_time = time.time()
            return result
        return wrapped
    return decorator

def send_telegram_message(chat_id, text, bot_token):
    send_text = 'https://api.telegram.org/bot' + bot_token + '/sendMessage?chat_id=' + chat_id + '&parse_mode=Markdown&text=' + text
    response = requests.get(send_text)
    return response.json()
    

def packet_callback(packet):
    if packet[TCP].dport == 50017:
        print(f"Перехвачен пакет: {packet.summary()}")
        global packetCounter
        dt_string = datetime.now().strftime("%d/%m/%Y %H:%M:%S")
        if packetCounter == 1:
            send_telegram_message("****** chat", "Пришло уведомление Remedy. \nДата: " + dt_string, "****** token")
            packetCounter = 0
            thread = threading.Thread(target=change_variable)
            thread.start()


def change_variable():
    global function_in_progress, packetCounter
    
    if function_in_progress:
        print("Функция уже запущена.")
        return

    function_in_progress = True
    print("Функция запущена.")
    
    # Имитация длительной работы
    time.sleep(5)
    
    packetCounter = 1
    print("Значение переменной изменено.")
    
    function_in_progress = False

# Запуск функции в отдельном потоке



sniff(filter="tcp and port 50017", prn=packet_callback, store=False)