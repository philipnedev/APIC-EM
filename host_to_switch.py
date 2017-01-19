#!/usr/bin/env python
'''
Show the switch IP address and hostname to which the device with give MAC address is connected .
'''
# import requests library to do the REST API Calls
import requests

#import json library. APIC-EM answers in
import json

#Removes non-secure communication wornings
requests.packages.urllib3.disable_warnings()


#put the ip address or dns of your apic-em controller
controller='sandboxapic.cisco.com'

#the username and password to access the APIC-EM Controller
user_pass = {"username": "devnetuser", "password": "Cisco123!"}

#Constructs the full APIC-EM REST API URL
def url_constructor(call):
    return "https://" + controller + "/api/v1/" + call

def ask_for_macaddress():
    return raw_input("Which MAC address:")

mac_address = ask_for_macaddress()

def get_ticket():

    url = url_constructor("ticket")

    #Content type must be included in the header
    header = {"content-type": "application/json"}

    #Performs a POST on the specified url to get the service ticket
    response= requests.post(url, data=json.dumps(user_pass), headers=header, verify=False)

    #convert response to json format
    r_json=response.json()

    #parse the json to get the service ticket
    return r_json["response"]["serviceTicket"]

ticket = get_ticket()

def get_hosts(ticket):

    # URL for Host REST API call to get list of exisitng hosts on the network.
    url = url_constructor("host")
    ticket = get_ticket()

    #Content type must be included in the header as well as the ticket
    header = {"content-type": "application/json", "X-Auth-Token":ticket}

    # this statement performs a GET on the specified host url
    response = requests.get(url, headers=header, verify=False)

    return response.json()



def find_host_with_mac(ticket, mac_add):

    hosts = get_hosts(ticket)
    for host in hosts["response"]:
        if host["hostMac"] == mac_add:
            print "IP Address: " + host["connectedNetworkDeviceIpAddress"]
            ip_address = host["connectedNetworkDeviceIpAddress"]
            interface = host["connectedInterfaceName"]
            return ip_address,interface

def device_ip_to_hostname(ticket, ip_add):

    # URL for Host REST API call to get list of exisitng hosts on the network.
    url = url_constructor("network-device/ip-address/" + ip_add)

    #Content type must be included in the header as well as the ticket
    header = {"content-type": "application/json", "X-Auth-Token":ticket}

    # this statement performs a GET on the specified host url
    response = requests.get(url, headers=header, verify=False)


    return response.json()

ip_address, interface = find_host_with_mac(ticket,mac_address)
device = device_ip_to_hostname(ticket, ip_address
                               )
print "Hostname: " + device["response"]["hostname"]
print "Interface: " + interface


