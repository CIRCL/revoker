import os
import argparse
import configparser
import requests
import json
import datetime

path_conf = os.path.join(os.getcwd(), 'config', 'config.cfg')

if os.path.isfile(path_conf):
    config = configparser.ConfigParser()
    config.read(path_conf)
else:
    print("[-] No conf file found")
    exit(-1)

if 'mm_revoker' in config:
    login = config["mm_revoker"]["login"]
    password = config["mm_revoker"]["password"]
    bearer = config["mm_revoker"]["bearer"]
    url_general = config["mm_revoker"]["url"]
else:
    print("[-] mm_revoker not in config")
    exit(-1)

parser = argparse.ArgumentParser()
parser.add_argument("-ue", "--useremail", help="Email for the user you want to revoke sessions", required=True)
parser.add_argument("-a", "--all", help="Revoke all sessions for the user. If not selected a list of sessions will be show later.", action="store_true")
args = parser.parse_args()


# If no session already create
if not bearer:
    # Login
    print("[+] Please enter your mfa (leave empty if not needed): ")
    mfa = input(">> ")
    url = f"{url_general}/login"
    data = {"login_id": login, "password": password, "token": mfa}

    r = requests.post(url, data=json.dumps(data))
    if r.status_code != 200:
        print(f"[-] Login error: {r.json()['message']}")
        exit(-1)

    bearer = str(r.headers["Token"])

    # Write the new token to config to keep the same session
    config["general"]["bearer"] = bearer
    with open(path_conf, "w") as write_conf:
        config.write(write_conf)


headers = {"Authorization": f"Bearer {bearer}"}

# Get user id by email
url = f"{url_general}/email/{args.useremail}"
r = requests.get(url, headers=headers)
if r.status_code == 404:
    print(f"[-] Email: {args.useremail}, is wrong")
    exit(-1)
elif r.status_code == 401:
    print("[-] Your bearer seems to be bad. If the bearer have been added by hand consider to remove \" around the value.")
    exit(-1)
else:
    usr_id = r.json()['id']


# List all alive sessions for the user
url = f"{url_general}/{usr_id}/sessions"
sessions_list = list()

r = requests.get(url, headers=headers)
if r.status_code == 200:
    for session in r.json():
        sessions_list.append(session["id"])
        ts = datetime.datetime.fromtimestamp(int(session["last_activity_at"])/1000).strftime('%Y-%m-%d %H:%M:%S')
        print(f"{session['id']}:  last_activity - {ts}, browser - {session['props']['browser']}, os - {session['props']['os']}")

print("\n[+] Enter a session id (multiple seperate by space): ")
res = input(">> ")

while not res.rstrip():
    print("\n[+] Enter a session id (multiple seperate by space): ")
    res = input(">> ")

sessions_to_revoke = res.split(" ")
print()

# Revoke sessions
for session_id in sessions_to_revoke:
    if not session_id in sessions_list:
        print(f"[-] {session_id} not in the sessions list. Skip...")
    else:
        url = f"{url_general}/{usr_id}/sessions/revoke"
        data = {"session_id": session_id}

        r = requests.post(url, headers=headers, data=json.dumps(data))
        if r.status_code == 403:
            print("[-] You don't have the good permissions to perform this action.")
            exit(-1)
        elif r.status_code == 200:
            print(f"{session_id}... done")


# Show remain sessions
url = f"{url_general}/{usr_id}/sessions"

r = requests.get(url, headers=headers)
if r.status_code == 200:
    print("\n[+] Remain sessions: ")
    for session in r.json():
        ts = datetime.datetime.fromtimestamp(int(session["last_activity_at"])/1000).strftime('%Y-%m-%d %H:%M:%S')
        print(f"{session['id']}:  last_activity - {ts}, browser - {session['props']['browser']}, os - {session['props']['os']}")
        