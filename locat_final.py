import socket
import time
import threading
import pandas as pd
from queue import Queue
import requests
import sys
from datetime import datetime
import subprocess

print("_"*100)

print(""" 
 ___________                   _  ______          _   
|_   _| ___ \                 | | | ___ \        | |  
  | | | |_/ /   __ _ _ __   __| | | |_/ /__  _ __| |_ 
  | | |  __/   / _` | '_ \ / _` | |  __/ _ \| '__| __|
 _| |_| |     | (_| | | | | (_| | | | | (_) | |  | |_ 
 \___/\_|      \__,_|_| |_|\__,_| \_|  \___/|_|   \__|
                                                      
                                                      
 _____                                                
/  ___|                                               
\ `--.  ___ __ _ _ __  _ __   ___ _ __                
 `--. \/ __/ _` | '_ \| '_ \ / _ \ '__|               
/\__/ / (_| (_| | | | | | | |  __/ |                  
\____/ \___\__,_|_| |_|_| |_|\___|_|                  
                                                      
                                                      
""")
print("_"*100)
print("Author : K.Azazel")
print("Usage : Python3")
print("/!\ Attention Usage Personnel Only")
print("_"*100)


res = requests.get("https://ipinfo.io/")

data = res.json()
print("#"*200)
print("data  : ",data)
print("#"*200)
print("Type of data : ",type(data))
print("#"*100)
location = data['loc']
latitude = float(location[0])
longitude = float(location[1])

print("-"*100)
print("GPS Loc   : ",location)
print("Latitude  : ",latitude)
print("Longitude : ", longitude)
print("-"*100)
##################################

df = pd.DataFrame(list(data.items()), columns=['Key_Name', 'info'])

socket.setdefaulttimeout(0.25)
print_lock = threading.Lock()


target_ip = df['info'][0]


target = target_ip
t_IP = socket.gethostbyname(target)
print ('Starting scan on host: ', t_IP)

def portscan(port):
   s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
   try:
      con = s.connect((t_IP, port))
      with print_lock:
         print(port, 'is open')
      con.close()
   except:
      pass

def threader():
   while True:
      worker = q.get()
      portscan(worker)
      q.task_done()
      
q = Queue()
startTime = time.time()
   
for x in range(100):
   t = threading.Thread(target = threader)
   t.daemon = True
   t.start()
   
for worker in range(1, 500):
   q.put(worker)
   
q.join()
print('Time taken:', time.time() - startTime)