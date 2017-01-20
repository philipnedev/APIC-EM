#!/usr/bin/env python
'''
Show the switch IP address and hostname to which the device with give MAC address is connected .
'''
# import requests library to do the REST API Calls
import requests

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



def find_host_with_mac(ticket, mac_add):
    '''Finds the IP address and interface of the device to which the given MAC address is connected

    Args:
        ticket - string - Valid APIC-EM ticket
        mac_add - string - MAC address of the host we are looking for

    Returns:
        ip_address - string - network device IP address
        interface - string - netwrk device interface
    '''

    hosts = get_hosts(ticket)
    for host in hosts["response"]:
        if host["hostMac"] == mac_add:
            ip_address = host["connectedNetworkDeviceIpAddress"]
            if host["hostType"] == "wired":
                interface = host["connectedInterfaceName"]
            else:
                interface = "wireless"
            return ip_address,interface

def device_ip_to_hostname(ticket, ip_add):
    '''Finds the hostname of network divice with the given IP address

     Args:
         ticket - Valid APIC-EM ticket
         ip_add - string - Network device IP address

     Returns:
         string - hostname of the network device
     '''

    # URL for Host REST API call to get list of exisitng hosts on the network.
    url = url_constructor("network-device/ip-address/" + ip_add)

    #Content type must be included in the header as well as the ticket
    header = {"content-type": "application/json", "X-Auth-Token":ticket}

    # this statement performs a GET on the specified host url
    response = requests.get(url, headers=header, verify=False)
    device = response.json()
    return device["response"]["hostname"]


def main(mac_address):
    ticket = get_ticket()
    ip_address, interface = find_host_with_mac(ticket,mac_address)
    hostname = device_ip_to_hostname(ticket, ip_address)
    print "IP Address:" + ip_address
    print "Hostname: " + hostname
    print "Interface: " + interface

if __name__ == "__main__":
    main(sys.argv[1])







