#!/usr/bin/python3

import urllib3
import requests
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def get_token(host: str, port: int, username: str, password: str):
    '''
    Get the C2 token to interact with the REST API
    '''
    try:
        url_empire_token = 'https://{0}:{1}/api/admin/login'.format(host, port)
        headers = {"Content-Type": "application/json"}
        param = {"username":"{0}".format(username), "password":"{0}".format(password)}
        request_token = requests.post(url_empire_token, headers=headers, json=param, verify=False)
        return request_token.json()['token']
    except Exception as e:
        print(e)
        return False

def restart_api(host: str, port: int, token: str):
    '''
    Restart the API server
    '''
    try:
        url_empire_restart_api = 'https://{0}:{1}/api/admin/restart?token={2}'.format(host, port, token)
        request_restart = requests.get(url_empire_restart_api, verify=False)
        return request_restart.json()['success']
    except Exception as e:
        print(e)
        return False

def shutdown_api(host: str, port: int, token: str):
    '''
    Shutdown the API server
    '''
    try:
        url_empire_shutdown_api = 'https://{0}:{1}/api/admin/shutdown?token={2}'.format(host, port, token)
        request_shutdown = requests.get(url_empire_shutdown_api, verify=False)
        return request_shutdown.json()['success']
    except Exception as e:
        print(e)
        return False

def get_listeners(host: str, port: int, token: str):
    '''
    Get all listeners
    '''
    try:
        url_empire_listeners = 'https://{0}:{1}/api/listeners?token={2}'.format(host, port, token)
        request_listeners = requests.get(url_empire_listeners, verify=False)
        return request_listeners.json()['listeners']
    except Exception as e:
        print(e)
        return False

def get_listener_by_name(host: str, port: int, token: str, name: str):
    '''
    Get all listeners
    '''
    try:
        url_empire_listener_name = 'https://{0}:{1}/api/listeners/{3}?token={2}'.format(host, port, token, name)
        request_listener_name = requests.get(url_empire_listener_name, verify=False)
        return request_listener_name.json()['listeners']
    except Exception as e:
        print(e)
        return False

def get_listener_option(host: str, port: int, token: str, module: str):
    '''
    Get all listeners
    '''
    try:
        url_empire_listener_name_options = 'https://{0}:{1}/api/listeners/options/{3}?token={2}'.format(host, port, token, module)
        request_name_options = requests.get(url_empire_listener_name_options, verify=False)
        return request_name_options.json()['listeneroptions']
    except Exception as e:
        print(e)
        return False

def create_listener(host: str, port: int, token: str, name: str, port_listener: int, listener_ip: str):
    '''
    Create a listener
    '''
    try:
        url_new_listener = 'https://{0}:{1}/api/listeners/http?token={2}'.format(host, port, token)
        param_new_listener = {'Name': name, 'Port': port_listener, 'Host': listener_ip}
        headers = {'Content-Type': 'application/json'}
        request_new_listener = requests.post(url_new_listener, headers=headers, json=param_new_listener, verify=False)
        return request_new_listener.json()['success']
    except Exception as e:
        print(e)
        return False
    
def delete_listener(host: str, port: int, token: str, name: str): # BUG in the Empire API => https://github.com/BC-SECURITY/Empire/issues/642
    '''
    Create a listener
    '''
    try:
        url_del_listener = 'https://{0}:{1}/api/listeners/{3}?token={2}'.format(host, port, token, name)
        request_new_listener = requests.delete(url_del_listener, verify=False)
        return request_new_listener.text
    except Exception as e:
        print(e)
        return False
