import timeit
import socket
import xlrd
import requests
from scapy.all import *

#loads a pcap file and returns a object containing the pcap
def loadfile(filename):
    start = timeit.default_timer()
    print("start loading")
    packets = rdpcap(filename)
    stop = timeit.default_timer()
    print("loading finished after: ",stop - start)
    return packets

#returns json file with location data
def lookupIP(ip):
    url = 'http://api.ipstack.com/' + ip + '?access_key=75ae5d89ba88b940232c4e8f26d6f7e8'.format(ip)
    res = requests.get(url)
    return res.json()

#takes an existing list of ips and looksup the ips and fills a dictionary with the ips and their location information
def fillDictWithLocation(ipList):
    storrage= {}
    for ip in ipList:
        if ((ip != '255.255.255.255') and not (re.search('^192.168.', ip)) and not (ip != '0.0.0.0')):  #checks if the data goes to the broadcasting address or stays in the local network
            jsonCashed = lookupIP(ip)
            storrage[ip] = {'country': jsonCashed['country_name'],
                            'region_name': jsonCashed['region_name'],
                            'longitude': jsonCashed['longitude'],
                            'latitude': jsonCashed['latitude'],
                            'continent': jsonCashed['continent_code'],
                            'city': jsonCashed['city']}
        else:
            storrage[ip] = {'location': "local IP address"}
    return storrage

#creates a set with all ips within a given dictionary returns a set with ip adresses
def buildLocationSet(locationSet, ip_dictionary):
    for k, v in ip_dictionary.items():
        if((k != "secure packages") and (k != "unsecure packages")):                                                    #to prevent that this two keys dont get parsed
            locationSet.add(k)
            for k1, v1 in v.items():
                for k2, v2 in v1.items():
                    if ((k2 != "secure packages") and (k2 != "unsecure packages")):                                     #to prevent that this two keys dont get parsed
                        locationSet.add(k2)
    return locationSet

#creates a dictionary based on origin ips and a dictionary with their destinations
def buildDictWithBothIp(storrage, oriIp, destiIp):
    if(oriIp in storrage.keys()):
        if(destiIp in storrage[oriIp]["targetIp"].keys()):
            storrage[oriIp]["targetIp"][destiIp] +=1
        else:
            storrage[oriIp]["targetIp"][destiIp] = 1
    else:
        storrage[oriIp] = {"targetIp": {destiIp: 1}}
    return storrage

#takes json input and prints location
def printLocationJson(jsonData):
    ip_address = jsonData['ip']
    continent = jsonData['continent_code']
    latitude = jsonData['latitude']
    longitude = jsonData['longitude']
    capital = jsonData['city']

    print('Latitude : {}'.format(latitude))
    print('Longitude : {}'.format(longitude))
    print('IP adress : {}'.format(ip_address))
    print('Continent : {}'.format(continent))
    print('City : {}'.format(capital))

def getProtocolName(number):
    table = {num: name[8:] for name, num in vars(socket).items() if name.startswith("IPPROTO")}
    return table[number]

#creates a dictionary with all ports
def createPortDict(incDict, package):
    outgoingDict = incDict
    #print(package.show())
    if(package.getlayer("TCP").sport in outgoingDict.keys()):
        outgoingDict[package.getlayer("TCP").sport] +=1
    else:
        outgoingDict[package.getlayer("TCP").sport] = 1

    if(package.getlayer("TCP").dport in outgoingDict.keys()):
        outgoingDict[package.getlayer("TCP").dport] +=1
    else:
        outgoingDict[package.getlayer("TCP").dport] = 1

    return outgoingDict

#reades an external excel file which contains the port whitelist and returns an array with all whitelisted ports
def initializePortWhitelist():
    portWhiteList = list()
    loc = ("portWhiteList.xlsx")
    wb = xlrd.open_workbook(loc)
    sheet = wb.sheet_by_index(0)
    sheet.cell_value(0, 0)
    for i in range(sheet.nrows):
        portWhiteList.append(int(sheet.cell_value(i, 0)))
    return portWhiteList

#checks if port is in the whitelist
def checkPortSecurity(port, portWhiteList):
    if(port in portWhiteList):
        return True
    return False

#adds if the connection was secure or unsecure to the ip dictionary
def addPorts(dictionary, package, portWhiteList, oriIp):
    if((package.getlayer("TCP").sport in portWhiteList) or (package.getlayer("TCP").dport in portWhiteList)):
        if("secure packages" in dictionary[oriIp]["targetIp"].keys()):
            dictionary[oriIp]["targetIp"]["secure packages"] +=1
        else:
            dictionary[oriIp]["targetIp"]["secure packages"] = 1
    else:
        if ("unsecure packages" in dictionary[oriIp]["targetIp"].keys()):
            dictionary[oriIp]["targetIp"]["unsecure packages"] +=1
        else:
            dictionary[oriIp]["targetIp"]["unsecure packages"] = 1
    return dictionary



def stepZeroDictBuildBothIps(packets, portWhiteList):
    print("start building dictionary")
    dictionary = {}
    portDictionary = {}
    #protocolList = set()
    for p in packets:
        if (p.getlayer("IP")):  # checks if the packet uses the IP layer
            # if ((p.getlayer("IP").dst != '255.255.255.255') and not (re.search('^192.168.', p.getlayer("IP").dst))):  #checks if the data goes to the broadcasting
                                                                                                                        # address or stays in the local network
            destIp = p.getlayer("IP").dst  # retrieves the destination ip of the packet from the IP layer
            oriIp = p.getlayer("IP").src  # retrieves the ip from the packet is sent
            dictionary = buildDictWithBothIp(dictionary, oriIp, destIp)


            if (p.getlayer("TCP")):  # checks if the packet uses the TCP layer
                dictionary = addPorts(dictionary,p, portWhiteList, oriIp)
                portDictionary = createPortDict(portDictionary, p)
            #protocolList.add(p.getlayer("IP").proto)


    print("finished building the dictionary")
    """    print(protocolList)
    for t in protocolList:
        print(getProtocolName(t))"""
    for i in sorted(portDictionary):                                            #sorts the dictionary based on the keys
        print((i, portDictionary[i]), end=" ")
    print(portDictionary.keys())
    return dictionary

start = timeit.default_timer()
print("program start")
# filename = input("Please enter the name of the pcap file: ")
filename = 'withings_monitor_merge.pcap'
packets = loadfile(filename)
ip_dictionary = {}
locationSet = set()

portWhiteList = initializePortWhitelist()
ip_dictionary = stepZeroDictBuildBothIps(packets, portWhiteList)
locationSet = buildLocationSet(locationSet,ip_dictionary)
locationDictionary = fillDictWithLocation(locationSet)

print(ip_dictionary)
print(locationDictionary)

stop = timeit.default_timer()
print("program finished after: ", stop - start)