#!/usr/bin/env python
'''
Show the switch IP address and hostname to which the device with give MAC address is connected .
'''
# import requests library to do the REST API Calls
import requests
from prettytable import PrettyTable


#import json library. APIC-EM answers in
import json

#import sys module
import sys

#Removes non-secure communication wornings
requests.packages.urllib3.disable_warnings()


#put the ip address or dns of your apic-em controller
controller='sandboxapic.cisco.com'

#the username and password to access the APIC-EM Controller
user_pass = {"username": "devnetuser", "password": "Cisco123!"}

#Constructs the full APIC-EM REST API URL
def url_constructor(call):
    '''Constructs the full URL for the specific APIC-EM call

    Args:
        call - URL for the call from the APIC-EM REST API documentation

    Returns:
        string: Fully constructed URL
    '''
    return "https://" + controller + "/api/v1/" + call

def get_ticket():
    '''Gets the ticket needed for everything else

    Args:
        None

    Returns:
        string: APIC-EM controller ticket
    '''
    url = url_constructor("ticket")

    #Content type must be included in the header
    header = {"content-type": "application/json"}

    #Performs a POST on the specified url to get the service ticket
    response= requests.post(url, data=json.dumps(user_pass), headers=header, verify=False)

    #convert response to json format
    r_json=response.json()

    #parse the json to get the service ticket
    return r_json["response"]["serviceTicket"]

def get_hosts(ticket):
    '''Gets all the hosts connected to the APIC-EM managed network

    Args:
        ticket - Valid APIC-EM ticket

    Returns:
        Dictionary with all the hosts
    '''
    # URL for Host REST API call to get list of exisitng hosts on the network.
    url = url_constructor("host")

    #Content type must be included in the header as well as the ticket
    header = {"content-type": "application/json", "X-Auth-Token":ticket}

    # this statement performs a GET on the specified host url
    response = requests.get(url, headers=header, verify=False)

    return response.json()

def get_sn(ticket,type):
    '''Gets all the network device part hostname , part number, serial number

        Args:
            ticket - Valid APIC-EM ticket

        Returns:
            Dictionary with all the hosts
        '''
    # URL for Host REST API call to get list of exisitng hosts on the network.
    url = url_constructor("network-device")

    # Content type must be included in the header as well as the ticket
    header = {"content-type": "application/json", "X-Auth-Token": ticket}

    # this statement performs a GET on the specified host url
    response = requests.get(url, headers=header, verify=False)

    devices = response.json()['response']
    if type == 'pretty':
        x = PrettyTable(["Hostname", "Part Number", "Serial Number"])
        x.align["IP Address"] = "c"
        x.padding_width = 1

        for i in devices:
            x.add_row([i['hostname'], i['platformId'], i['serialNumber']])

        print x
    else:
        for i in devices:
            print i['serialNumber']


def main(type='ugly'):
    ticket = get_ticket()
    get_sn(ticket,type)

if __name__ == "__main__":
    try:
        if sys.argv[1] == "pretty":
            main(sys.argv[1])
        elif sys.argv[1] == "ugly":
            main(sys.argv[1])
        else:
            print "Incorrect argument"
    except:
        main("ugly")







