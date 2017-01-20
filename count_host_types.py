#!/usr/bin/env python
'''
Returns or displays the number of wired and wireless hosts
'''
# import requests library to do the REST API Calls
import requests

#import json library. APIC-EM answers in
import json

#import sys module
import sys

#For pretty tables
from prettytable import PrettyTable


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

def count_host_types(ticket, type):
    '''Gets the number of hosts connected with the given type

    Args:
        ticket - string - Valid APIC-EM ticket
        type - string - type of connectivity - "wired", "wireless"

    Returns:
        number of devices - int
    '''


    url = url_constructor("host/count?hostType=" + type)

    header = {"content-type": "application/json", "X-Auth-Token": ticket}

    response = requests.get(url, headers=header, verify=False)

    answer = response.json()
    return answer["response"]


def main(output=""):
    '''Displays the result or returns it as tuple

    Args:
        output - desired output
            None - will return a tuple (wired,wireless) with the two numbers
            prrety - will use PrretyTables module to display the results in table
            ugly - will print simple two lines with the result

    Returns:
        (wired, wireless) - tuple (int,int)

    '''
    ticket = get_ticket()
    wired = count_host_types(ticket, "wired")
    wireless = count_host_types(ticket, "wireless")
    if output == "prrety":
        x = PrettyTable(["Type", "Wired", "Wireless"])
        x.align["IP Address"] = "c"
        x.padding_width = 1
        x.add_row(["Count", wired, wireless])
        print x
    elif output == "ugly":
        print "Wired: " + str(wired)
        print "Wireless: " + str(wireless)
    else:
        return wired, wireless

if __name__ == "__main__":
    try:
        if sys.argv[1] == "prrety":
            main(sys.argv[1])
        else:
            print "Incorrect argument"
    except:
        main("ugly")







