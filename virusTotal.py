#!/bin/python3
import requests
import argparse
import os
import json
import yaml

#config_path = "$HOME/.config/virustotal"
test_env_path = ".env"
config_file = "config.yaml"
api_key = []

def init():
    print("[!] creating config file")

    if os.path.isdir(test_env_path):
        print(f"config path: {test_env_path} exist")
    else:
        os.makedirs(test_env_path)
        
    try:
        with open(f"{test_env_path}/{config_file}", 'w') as file:
            file.writelines('api-key:')
            
    except FileExistsError as e:
        print(e)

    print(f"[+] config file created on {test_env_path}/{config_file}")

    api_key = input("[!] Enter your virus total API Key: ")

    try:
        with open(f"{test_env_path}/{config_file}", 'w') as file:
            file.writelines(f"api-key: {api_key}")

        print("[*] Done!")
        exit(0)

    except FileNotFoundError as e:
        print(e)

def read_yaml(): #read yaml config to get api key
    try:
        with open(f"{test_env_path}/{config_file}", 'r') as file:
            data = yaml.safe_load(file)
            api_key.append(data.get('api-key'))
    except yaml.YAMLError as e:
        print(e)
    except FileNotFoundError:
        print("[!] Error: The config.yaml file was not found.")

def req_data(domain, save=None): #fetching data from virus total
    read_yaml()
    headers = {"Accept": "application/json"}
    url = f'https://www.virustotal.com/vtapi/v2/domain/report?apikey={api_key[0]}&domain={domain}'
    
    r = requests.get(url, headers=headers, timeout=10)
    data = r.json()
    print(json.dumps(data, indent=4))

def main():
    parser = argparse.ArgumentParser(prog="virusTotal", description="it fetch report data from virustotal")
    parser.add_argument('-init', help="setup config files", action='store_true')
    parser.add_argument('-d', type=str, help="target domain", metavar="domain name")
    parser.add_argument('-o', help="store output into a file", type=str, metavar="file name")
    args = parser.parse_args()

    domain = args.d
    if args.init:
        init()
    req_data(domain)

if __name__ == '__main__':
    main()