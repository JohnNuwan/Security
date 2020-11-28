#!/usr/bin/env Python3
#!-*- conding:utf-8 -*-
# Usage  : Pÿthon3
# Coding : K.Azazel
#-----------------------------
#___________________________________ DocString  ___________________________________________________
"""
	DocString: 
		ProtoScript Pour Information de La Machine avec:
														* Info Système
														* Info User
														* Info Process
														* Info NetConnection
		
		je rajouterais pas la suite la Localisation de L'ip Ainsi que le Scan De Port

		[ /!\  A But purement personnel Ne pas le faire tourné sur un pc autre que le sien 
			 sans L'accord du Propriétaire ]
"""

#___________________________________ Import Lib  ___________________________________________________
import os
import psutil
import pandas as pd 
import datetime
import sys
import platform
import whois
from datetime import datetime
import keyboard
import requests
import socket
import threading
from queue import Queue

#___________________________________Entete Programme_________________________________________________

print("#"*100)
print("""
			_ _  _ ____ ____    ___  ____ ____ ____ ____ ____ ____    _  _ ____ ____ _  _ _ _  _ ____ 
			| |\ | |___ |  |    |__] |__/ |  | |    |___ [__  [__     |\/| |__| |    |__| | |\ | |___ 
			| | \| |    |__|    |    |  \ |__| |___ |___ ___] ___]    |  | |  | |___ |  | | | \| |___ 
			                                                                                          
	""")
print("~"*30)
print("Coding By : K.Azazel")
print("Usage     : Python 3.7")
print("Version   : Protype V02")
print("~"*30)

############################################################
###################### Variable ############################

path ='./data/'
if not os.path.exists(path):
    os.makedirs(path)
############################################################
###################### Debut Programme #####################
def display(message, arg):
	print("_"*26)
	print(message, arg)
	

def info_system():
	print("#"*100)
	print("""
			 _     ___                    _             
			|_|___|  _|___    ___ _ _ ___| |_ ___ _____ 
			| |   |  _| . |  |_ -| | |_ -|  _| -_|     |
			|_|_|_|_| |___|  |___|_  |___|_| |___|_|_|_|
			                     |___|                  
				""")
	display("Os PlatForme              : ",platform.platform())
	display("Os Release                : ",platform.release())
	display("Os Version                : ",platform.version())
	display("affichage temp            : ",psutil.cpu_times()) 
	display("affichage pourcentage CPU : ",psutil.cpu_percent(1)) 
	display("Nombre cores system       : ", psutil.cpu_count()) 
	display("CPU Statistics            : ", psutil.cpu_stats())
	display("Frequance cpu             : ",psutil.cpu_freq()) 
	display("Memoire Virutel Utilisez  : ",psutil.virtual_memory())
	display("Memoire Swap              : ",psutil.swap_memory())
	display("Utilisation du disk       : ",psutil.disk_usage('/'))
	boot_time = psutil.boot_time()
	display("Boot Time                 : ",datetime.fromtimestamp(psutil.boot_time()).strftime("%Y-%m-%d %H:%M:%S"))

def inf_user():
	print("#"*100)
	print("""                   
			 _     ___                        
			|_|___|  _|___    _ _ ___ ___ ___ 
			| |   |  _| . |  | | |_ -| -_|  _|
			|_|_|_|_| |___|  |___|___|___|_|  
			""")
	display("Info User                : ",psutil.users()) 

def inf_process():
	print("#"*100)
	print("""
                                               
			 _     ___                                    
			|_|___|  _|___    ___ ___ ___ ___ ___ ___ ___ 
			| |   |  _| . |  | . |  _| . |  _| -_|_ -|_ -|
			|_|_|_|_| |___|  |  _|_| |___|___|___|___|___|
			                 |_|                          
		""")
	PID_list =[]
	display("Liste PID : \n ",psutil.pids())
	get_pid = psutil.pids()
	for i in get_pid:
		PID_list.append(i)
	df_pid = pd.DataFrame(PID_list, columns=["pid"])
	df_pid.to_csv(path+"PID_info.csv")
	print(df_pid)
	#return df_pid

def inf_NetConnection():
	print("#"*100)
	print("""
                                                                        
		 _     ___        _____     _   _____                     _   _         
		|_|___|  _|___   |   | |___| |_|     |___ ___ ___ ___ ___| |_|_|___ ___ 
		| |   |  _| . |  | | | | -_|  _|   --| . |   |   | -_|  _|  _| | . |   |
		|_|_|_|_| |___|  |_|___|___|_| |_____|___|_|_|_|_|___|___|_| |_|___|_|_|
		                                                                        
		""")
	start_time_netConnection = datetime.now()
	print("Script Start at : ",start_time_netConnection)
	display("Info NetConnection",psutil.net_connections())
	
	a = psutil.net_connections()
	NetConnection_List = []
	for i in a:
		NetConnection_List.append(list(i))
	df = pd.DataFrame(NetConnection_List, columns=["fd","family", "type", "laddr", "raddr", "status", "pid" ])
	df.to_csv(path+"Bing_info.csv")
	#print(df['raddr'])
	for i in df["raddr"]:
		for a in i:
			#print(a)
			liste_tupl_a =[]
			for a in i:
				liste_tupl_a.append(a)
				C = (list(liste_tupl_a))
				cr = C[0]
				#print(cr)
				try:
					w = whois.whois(cr)
					d = w.domain_name
					list_ip = {}
					if d != None:
						#print(d)
						with open(path+'whois_domaine_IP_name.csv', 'a') as file: 
							file.write(f"{a}, {d}\n")

				except Exception as e:
					pass
	df_whois = pd.read_csv(path + 'whois_domaine_IP_name.csv', sep=",")	
	print("Header : \n", df_whois.head())		
	end_time_netConnection = datetime.now()
	print("Script Stop At Time : ",end_time_netConnection - start_time_netConnection )


def loc_Ip():
	print("#"*100)
	print("""
		  _____         _                     _ _          _   _             
		 |_   _|       | |                   | (_)        | | (_)            
		   | |  _ __   | |     ___   ___ __ _| |_ ______ _| |_ _  ___  _ __  
		   | | | '_ \  | |    / _ \ / __/ _` | | |_  / _` | __| |/ _ \| '_ \ 
		  _| |_| |_) | | |___| (_) | (_| (_| | | |/ / (_| | |_| | (_) | | | |
		 |_____| .__/  |______\___/ \___\__,_|_|_/___\__,_|\__|_|\___/|_| |_|
		       | |                                                           
		       |_|                                                           
		""")
	res = requests.get("https://ipinfo.io/")

	data = res.json()
	location = data['loc']
	latitude = float(location[0])
	longitude = float(location[1])

	df_ip_loc = pd.DataFrame(list(data.items()), columns=['Key', 'info'])
	df_ip_loc.to_csv(path+"ip_loc.csv", sep=',')
	print("_"*26)
	print(df_ip_loc.head())
	


def Port_scan():

	print("""
			  _____           _      _____                 
			 |  __ \         | |    / ____|                
			 | |__) |__  _ __| |_  | (___   ___ __ _ _ __  
			 |  ___/ _ \| '__| __|  \___ \ / __/ _` | '_ \ 
			 | |  | (_) | |  | |_   ____) | (_| (_| | | | |
			 |_|   \___/|_|   \__| |_____/ \___\__,_|_| |_|
			                                               
		""")
	start_time_netConnection = datetime.now()
	print("Script Start at : ",start_time_netConnection)

	res = requests.get("https://ipinfo.io/")
	data = res.json()
	df_ip_loc = pd.DataFrame(list(data.items()), columns=['Key', 'info'])
	ip_target = df_ip_loc["info"][0]
	print("#"*60)
	print("Local IP Scan : ",ip_target)
	print("#"*60)
	target = ip_target

	queue = Queue()
	open_ports = []

	def port_scan(port):
	    try:
	        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	        sock.connect((target, port))
	        return True
	    except Exception as e:
	        return False

	def fill_queue(port_list):
	    for port in port_list:
	        queue.put(port)


	def worker():
	    while not queue.empty():
	        port = queue.get()
	        if port_scan(port):
	            print(f"Port {port} is open")
	            open_ports.append(port)

	port_list = range (1, 1024)
	fill_queue(port_list)
	thread_list = []

	for t in range(100):
	    thread = threading.Thread(target=worker)
	    thread_list.append(thread)

	for thread in thread_list:
	    thread.start()

	for thread in thread_list:
	    thread.join()
	end_time_netConnection = datetime.now()
	print("Script Stop At Time : ",end_time_netConnection - start_time_netConnection )

############################################################
######################  Boucle Main  #######################
def main():
	try:
		print("#"*100)
		print("1 / Info system \n2 / Info User\n3 / Info Process\n4 / Info NetConnection \n5 / Localisation IP\n6 / Port Scan \nPress q to quit")
		print("~"*30)
		n = input("Enter Number : ")
		

		if n =='1':
			info_system()
			return main()

		if n =='2':
			inf_user()
			return main()

		if n =='3':
			print(inf_process())
			return main()

		if n =='4':
			inf_NetConnection()
			return main()

		if n =='5':
			loc_Ip()
			return main()

		if n =='6':
			Port_scan()
			return main()

		if keyboard.is_pressed('q'):  # if key 'q' is pressed 
			print('You Pressed A Key!')
			sys.exit()
	except Exception as e:
		display("Error info_system", e)

if __name__ == '__main__':
	main()