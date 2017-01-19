

# import requests library
import requests

#import json library
import json

#import logging
requests.packages.urllib3.disable_warnings()

mac_address = raw_input("Which MAC address:")

controller='sandboxapic.cisco.com'


# put the ip address or dns of your apic-em controller in this url
url = "https://" + controller + "/api/v1/ticket"

#the username and password to access the APIC-EM Controller
payload = {"username":"devnetuser","password":"Cisco123!"}

#Content type must be included in the header
header = {"content-type": "application/json"}

#Performs a POST on the specified url to get the service ticket
response= requests.post(url,data=json.dumps(payload), headers=header, verify=False)

#convert response to json format
r_json=response.json()

#print(r_json)
#parse the json to get the service ticket
ticket = r_json["response"]["serviceTicket"]

# URL for Host REST API call to get list of exisitng hosts on the network.
url = "https://" + controller + "/api/v1/host"

#Content type must be included in the header as well as the ticket
header = {"content-type": "application/json", "X-Auth-Token":ticket}

# this statement performs a GET on the specified host url
response = requests.get(url, headers=header, verify=False)

# json.dumps serializes the json into a string and allows us to
# print the response in a 'pretty' format with indentation etc.
#print ("Hosts = ")
#print (json.dumps(response.json(), indent=4, separators=(',', ': ')))

hosts = response.json()
for host in hosts["response"]:
    if host["hostMac"] == mac_address:
        print "IP Address: " + host["connectedNetworkDeviceIpAddress"]
        ip_address = host["connectedNetworkDeviceIpAddress"]
        interface = host["connectedInterfaceName"]



# URL for Host REST API call to get list of exisitng hosts on the network.
url = "https://" + controller + "/api/v1/network-device/ip-address/" + ip_address

#Content type must be included in the header as well as the ticket
header = {"content-type": "application/json", "X-Auth-Token":ticket}

# this statement performs a GET on the specified host url
response = requests.get(url, headers=header, verify=False)

#json.dumps serializes the json into a string and allows us to#
#print the response in a 'pretty' format with indentation etc.
#print ("Device = ")
#print (json.dumps(response.json(), indent=4, separators=(',', ': ')))

device = response.json()

print "Hostname: " + device["response"]["hostname"]
print "Interface: " + interface


