#!/bin/python3
import requests
import argparse
import os
import json
import yaml

RED = "\033[31m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
RESET = "\033[0m"

config_path = "$HOME/.config/virustotal" #default config path
#config_path = ".env" #test environment path
config_file = "config.yaml"
api_key = []

detected_urls = []
ip_addresses = []
subdomains = []
undetected_urls = []

def init():
    print(f"{GREEN}[!] creating config file{RESET}")

    if os.path.isdir(config_path):
        print(f"{GREEN}[*]config path: {config_path} exist {RESET}")
    else:
        os.makedirs(config_path)
        
    try:
        with open(f"{config_path}/{config_file}", 'w') as file:
            file.writelines('api-key:')
            
    except FileExistsError as e:
        print(e)

    print(f"{GREEN}[+] config file created on {config_path}/{config_file} {RESET}")

    api_key = input(f"{YELLOW}[!] Enter your virus total API Key: {RESET}")

    try:
        with open(f"{config_path}/{config_file}", 'w') as file:
            file.writelines(f"api-key: {api_key}")

        print(f"{GREEN}[*] Done! {RESET}")
        exit(0)

    except FileNotFoundError as e:
        print(f"{RED}{e}{RESET}")

def read_yaml(): #read yaml config to get api key
    try:
        with open(f"{config_path}/{config_file}", 'r') as file:
            data = yaml.safe_load(file)
            api_key.append(data.get('api-key'))
    except yaml.YAMLError as e:
        print(e)
    except FileNotFoundError:
        print(f"{RED}[!] Error: The config.yaml file was not found.\n[*] Use: -init to setup config file {RESET}")
        exit(0)


def req_data(domain, save=None): #fetching data from virus total
    read_yaml()
    #check existence of api key
    if not api_key: 
        print(f"{RED}[!] No api key found!\n[*] Use: -init to setup config file{RESET}")
        exit(0)
    else:
        pass
    #making request
    headers = {"Accept": "application/json"}
    url = f'https://www.virustotal.com/vtapi/v2/domain/report?apikey={api_key[0]}&domain={domain}'
    
    r = requests.get(url, headers=headers, timeout=10) #fetching response
    data = r.json() #response in json
    #filtering data
    det_urls = [
        {"url": u["url"]}
        for u in data.get("detected_urls", [])
    ]

    res = [
        {"ip": i["ip_address"]}
        for i in data.get("resolutions", [])
    ]

    subs = data.get("subdomains", [])

    undet_urls = data.get("undetected_urls", [])
    urls = [item[0] for item in undet_urls]

    #stdout
    print(f"{GREEN}[+] Detected Urls: \n{RESET}")
    for i in det_urls:
        print(f"{i.get("url")}")
        if save:
            detected_urls.append(i.get("url"))

    print(f"{GREEN}\n[+] IP Addresses:\n{RESET}")
    for i in res:
        print(f"{i.get("ip")}")
        if save:
            ip_addresses.append(i.get("ip"))

    print(f"{GREEN}\n[+] Subdomains:\n{RESET}")
    for i in subs:
        print(i)
        if save:
            subdomains.append(i)

    print(f"{GREEN}\n[+] Undetected Urls:\n{RESET}")
    for url in urls:
        print(url)
        if save:
            undetected_urls.append(url)


def save_file(file_name):
    with open(f"{file_name}", 'w') as file:
        file.write("[+] Detected Urls: \n")
        for i in detected_urls:
            file.writelines(i + "\n")
        file.write("[+] IP Addresses:\n")
        for i in ip_addresses:
            file.writelines(i + "\n")
        file.write("[+] Subdomains:\n")
        for i in subdomains:
            file.writelines(i + "\n")
        file.write("[+] Undetected Urls:\n")
        for i in undetected_urls:
            file.writelines(i + "\n")

def main():
    parser = argparse.ArgumentParser(prog="virusTotal", description="it fetch report data from virustotal")
    parser.add_argument('-init', help="setup config files", action='store_true')
    parser.add_argument('-d', type=str, help="target domain", metavar="domain name")
    parser.add_argument('-o', help="store output into a file", type=str, metavar="file name")
    args = parser.parse_args()

    domain = args.d #domain name

    save = args.o #save file name

    if args.init: 
        init()
    
    req_data(domain,save) #main

    if save: #save file if -o chosen
        save_file(save)

if __name__ == '__main__':
    main()