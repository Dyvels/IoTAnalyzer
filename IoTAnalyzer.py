#************************************** Import area *************************************************
import timeit
import xlrd
import requests
import multiprocessing
from scapy.all import *


class ResearchFile():
    def __init__(self, filename):
        self.packets = self.loadfile(filename)
        self.allIps = set()                 # contains all used IP adresses (origin and destionations)
        self.connectionSet = set()          # holds a list with all established connections (destination IP, origin IP, call amounts, secure port usage)
        self.clearTextDictionary = dict()   # holds a dictionary with all with all IP who sent cleartext with the corresponding destination address and the cleartext
        self.portDictionary = dict()        # holds a dictionary used Ports and call amounts
        self.locationDict = dict()          # holds a dictionaries with all IPs and their geolocation informations
        self.entropyDict = dict()           # holds a dictionary with all IPs and their destinations and the average entropy of the exchanged packets


    def loadfile(self, filename):
        '''loads a pcap file and returns a object containing the pcap'''
        start = MyTimer()
        print("start loading '" +filename +"', this may take a while depending on the size of the file")
        packets = rdpcap(filename)

        print("loading finished after: ", start.end())
        return packets

    def buildLocationDict(self):
        flag = True
        '''takes an existing list of ips and looksup the ips and fills a dictionary with the ips and their location information'''
        for ip in self.allIps:
            if not ((ip.getAddress() == '255.255.255.255') or             #checks if the data goes to the broadcasting address
                    (re.search('^192\.168\.', ip.getAddress())) or          #stays in the local network
                    (re.search('^172\.16\.', ip.getAddress())) or           #stays in the local network
                    (re.search('^172\.17\.', ip.getAddress())) or           #stays in the local network
                    (re.search('^172\.18\.', ip.getAddress())) or           #stays in the local network
                    (re.search('^172\.19\.', ip.getAddress())) or           #stays in the local network
                    (re.search('^172\.20\.', ip.getAddress())) or           #stays in the local network
                    (re.search('^172\.21\.', ip.getAddress())) or           #stays in the local network
                    (re.search('^172\.22\.', ip.getAddress())) or           #stays in the local network
                    (re.search('^172\.23\.', ip.getAddress())) or           #stays in the local network
                    (re.search('^172\.24\.', ip.getAddress())) or           #stays in the local network
                    (re.search('^172\.25\.', ip.getAddress())) or           #stays in the local network
                    (re.search('^172\.26\.', ip.getAddress())) or           #stays in the local network
                    (re.search('^172\.27\.', ip.getAddress())) or           #stays in the local network
                    (re.search('^172\.28\.', ip.getAddress())) or           #stays in the local network
                    (re.search('^172\.29\.', ip.getAddress())) or           #stays in the local network
                    (re.search('^172\.30\.', ip.getAddress())) or           #stays in the local network
                    (re.search('^172\.31\.', ip.getAddress())) or           #stays in the local network
                    (re.search('^10\.', ip.getAddress())) or               #stays in the local network
                    (ip.getAddress() == '0.0.0.0')):  # checks if the data goes to the broadcasting address
                ip.lookupIP()
                jsonCashed = ip.getJson()
                self.locationDict[ip.getAddress()] = {'country': jsonCashed['country_name'],
                                'region_name': jsonCashed['region_name'],
                                'longitude': jsonCashed['longitude'],
                                'latitude': jsonCashed['latitude'],
                                'continent': jsonCashed['continent_code'],
                                'city': jsonCashed['city']}
                for c in self.connectionSet:
                    if (c.oriIp.getAddress() == ip.getAddress()):
                        c.oriIp.setJson(jsonCashed)
                    elif(c.dstIp.getAddress() == ip.getAddress()):
                        c.dstIp.setJson(jsonCashed)
                    else:
                        pass
            else:
                self.locationDict[ip.getAddress()] = {'location': "local IP address"}

    def buildConnectionSet(self, portWhiteList):
        '''takes the packets and the portWhiteList to create the IP dicitonary and the port dictionary'''
        print("start building connection set")
        counter  = 0
        multicast  = 0
        countdown = Countdown(self.packets.__len__())                                                                   #to visualize how much of the data is already processed
        for p in self.packets:
            countdown.runCountdown()                                                                                    #increases counter in the counter and prints if 10%,20%... is done
            jump = False                    #prevents that an packet without TCP or UDP layer is processed in the portDict creation -> True meens packet will be avoided -> false meens packet will be analyzed
            if (((p.haslayer("IP")) & ( not p.haslayer("DNS")) & (not p.haslayer("DHCP options")) & (not p.haslayer("NTPHeader")) & (not p.haslayer("ICMP")))):  # checks if the packet uses the IP layer
                # analyzation area start: (purpose:) to find specific packages
                """ for p in packets:
                    if (p.getlayer("TCP")):
                        if(p.getlayer("TCP").chksum == 0x343b):
                            print(p.getlayer("TCP").show())
                            print(p.getlayer("TCP").chksum)
                            """
                # if ((p.getlayer("IP").dst != '255.255.255.255') and not (re.search('^192.168.', p.getlayer("IP").dst))):  # checks if the data goes to the broadcasting
                # address or stays in the local network
                destIp = IpAddress(p.getlayer("IP").dst)  # retrieves the destination ip of the packet from the IP layer
                oriIp = IpAddress(p.getlayer("IP").src)  # retrieves the ip from the packet is sent

                if not (any(x.getAddress() == destIp.getAddress() for x in self.allIps)):                   #checks if IP is already listed
                    self.allIps.add(destIp)    #adds IP to the list for all IP adresses

                if not (any(x.getAddress() == oriIp.getAddress() for x in self.allIps)):                    #checks if IP is already listed
                    self.allIps.add(oriIp)    #adds IP to the list for all IP adresses
                """if(self.connectionSet.__len__()==0):
                    if (p.getlayer("TCP")):  # checks if the packet uses the TCP layer
                        new = Connection(oriIp, destIp)  # create new Connection object if not existing in the list
                        if ((p.getlayer("TCP").sport in portWhiteList.getList()) or (
                                p.getlayer("TCP").dport in portWhiteList.getList())):
                            new.secureConnection += 1  # increase secureConnection if used port is whitelisted
                        else:
                            new.unsecureConnection += 0  # increase unsecureConnection if used port is not whitelisted
                        self.__createPortDict(p)
                    self.connectionSet.add(Connection(oriIp, destIp))"""
                if (p.haslayer("TCP")):
                    layer = "TCP"
                elif (p.haslayer("UDP")):
                    layer = "UDP"
                elif (p.haslayer("IP")):                                    #this avoids that multicast addresses will be considered
                    if((re.search('^224\.', p.getlayer("IP").src) or
                        (re.search('^225\.', p.getlayer("IP").src))or
                        (re.search('^226\.', p.getlayer("IP").src))or
                        (re.search('^227\.', p.getlayer("IP").src))or
                        (re.search('^228\.', p.getlayer("IP").src))or
                        (re.search('^229\.', p.getlayer("IP").src))or
                        (re.search('^230\.', p.getlayer("IP").src))or
                        (re.search('^231\.', p.getlayer("IP").src))or
                        (re.search('^232\.', p.getlayer("IP").src))or
                        (re.search('^233\.', p.getlayer("IP").src))or
                        (re.search('^234\.', p.getlayer("IP").src))or
                        (re.search('^235\.', p.getlayer("IP").src))or
                        (re.search('^236\.', p.getlayer("IP").src))or
                        (re.search('^237\.', p.getlayer("IP").src))or
                        (re.search('^238\.', p.getlayer("IP").src))or
                        (re.search('^239\.', p.getlayer("IP").src))or
                        (re.search('^224\.', p.getlayer("IP").dst)) or
                        (re.search('^225\.', p.getlayer("IP").dst))or
                        (re.search('^226\.', p.getlayer("IP").dst))or
                        (re.search('^227\.', p.getlayer("IP").dst))or
                        (re.search('^228\.', p.getlayer("IP").dst))or
                        (re.search('^229\.', p.getlayer("IP").dst))or
                        (re.search('^230\.', p.getlayer("IP").dst))or
                        (re.search('^231\.', p.getlayer("IP").dst))or
                        (re.search('^232\.', p.getlayer("IP").dst))or
                        (re.search('^233\.', p.getlayer("IP").dst))or
                        (re.search('^234\.', p.getlayer("IP").dst))or
                        (re.search('^235\.', p.getlayer("IP").dst))or
                        (re.search('^236\.', p.getlayer("IP").dst))or
                        (re.search('^237\.', p.getlayer("IP").dst))or
                        (re.search('^238\.', p.getlayer("IP").dst))or
                        (re.search('^239\.', p.getlayer("IP").dst)))):
                            multicast +=1
                            jump = True                             #prevents that an packet without TCP or UDP layer is processed in the portDict creation
                else:
                    print("LAYER IS NOT LISTED:")
                    p.show()
                flag = True     #if the connection doesn´t exist yet in the connectionSet
                for c in self.connectionSet:
                    if((c.oriIp.getAddress() == oriIp.getAddress())&(c.dstIp.getAddress() == destIp.getAddress())):
                        flag = False
                        c.callAmount +=1                                                                                #increase callAmount if found
                        if(not(jump)):
                            if (p.getlayer(layer)):  # checks if the packet uses the TCP layer
                                if ((p.getlayer(layer).sport in portWhiteList.getList()) or
                                    (p.getlayer(layer).dport in portWhiteList.getList())):
                                    c.secureConnection += 1                                                                 #increase secureConnection if used port is whitelisted
                                else:
                                    c.unsecureConnection += 1                                                               #increase unsecureConnection if used port is not whitelisted
                                self.__createPortDict(p, layer)
                            break
                if(flag):   #if the connection doesn´t exist yet in the connectionSet
                    new = Connection(oriIp, destIp, 1)                                                                  #create new Connection object if not existing in the list
                    try:
                        if (not (jump)):
                            if (p.haslayer(layer)):  # checks if the packet uses the TCP or UDP layer
                                if ((p.getlayer(layer).sport in portWhiteList.getList()) or (
                                        p.getlayer(layer).dport in portWhiteList.getList())):
                                    new.secureConnection += 1                                                                   #increase secureConnection if used port is whitelisted
                                else:
                                    new.unsecureConnection += 1                                                                 #increase unsecureConnection if used port is not whitelisted
                                self.__createPortDict(p, layer)
                        self.connectionSet.add(new)
                        flag = True
                    except:
                        print("following packet has a layer which is not considered yet")
                        print(p.show())
            else:
                counter +=1
        print(counter, "packets are not analyzed because they are DNS, NTP, ICMP or DHCP packets or didn´t have a IP Layer")
        print(multicast, "IP packets are not analyzed because because they contact multicast addresses")
        for i in sorted(self.portDictionary):  # sorts the dictionary based on the keys
            self.portDictionary.update({i: self.portDictionary[i]})
        print("finished building connectionSet and portDicionary")

    def __createPortDict(self, p, layer):
        '''creates a dictionary with all ports'''
        if (p.getlayer(layer).sport in self.portDictionary.keys()):
            self.portDictionary[p.getlayer(layer).sport] += 1
        else:
            self.portDictionary[p.getlayer(layer).sport] = 1

        if (p.getlayer(layer).dport in self.portDictionary.keys()):
            self.portDictionary[p.getlayer(layer).dport] += 1
        else:
            self.portDictionary[p.getlayer(layer).dport] = 1

    def buildCleartextDict(self):
        ''' clearTextFinder tackets a list of packages
        the function will then write the cleartext if, it was byte enconded, into a dictionary which will be returned afterwards '''
        print("start building cleartext dictionary")
        countdown = Countdown(self.packets.__len__())                                                                   #to visualize how much of the data is already processed
        for packet in self.packets:
            countdown.runCountdown()                                                                                    #increases counter in the counter and prints if 10%,20%... is done
            if ((packet.haslayer("Raw") & (not packet.haslayer("EAPOL")))):
                try:
                    result = packet.getlayer('Raw').load.decode().strip()
                    # result = re.sub(r'[\W+|_]', '', result)                                                            # \W+ deletes all special characters, \d+ deletes all numbers, |_ deletes all underscores
                    destIp = packet.getlayer("IP").dst  # retrieves the destination ip of the packet from the IP layer
                    oriIp = packet.getlayer("IP").src  # retrieves the ip from the packet is sent
                    if (oriIp in self.clearTextDictionary.keys()):
                        if (destIp in self.clearTextDictionary[oriIp]["targetIp"].keys()):
                            self.clearTextDictionary[oriIp]["targetIp"][destIp] += ("; " + result)
                        else:
                            self.clearTextDictionary[oriIp]["targetIp"][destIp] = result
                    else:
                        self.clearTextDictionary[oriIp] = {"targetIp": {destIp: result}}
                except:
                    pass

    def buildEntropyDict(self, upperLimit = 9, lowerLimit = 0):
        '''start for entropy calculation
        prints an overview how many packets are used of ARP, DHCP, DNS, ACK, SYN, SYN/ACK, FA
        iterates over incoming packets and calculates the average entropy which will be given back in a dictionary
        upperLimit and lowerLimit allow to define the span of entropy which should be saved'''
        amountRaw = 0                                                                                                       #for the amount of packets which have a RAW layer
        amountdone = 0                                                                                                      #for the amount of packets which have utf8 based payload
        amountdonesemi = 0                                                                                                  #for the amount of packets which have byte which is not utf8 based payload
        amountdoneExcluded = 0                                                                                              #for the amount of packets outside the given span
        amount = 0                                                                                                          #for the amount packets total
        ackCounter = 0                                                                                                      #for the amount of packets used for ACK, SYN, SYN/ACK, RA
        arpCounter = 0                                                                                                      #for the amount of packets used for ARP, DHCP or DNS

        for packet in self.packets:
                amount += 1                                                                                                 #total amount packets counter

                #counting for the layers start
                if(packet.haslayer("TCP")):
                    if((packet.getlayer("TCP").flags ==  "A") or (packet.getlayer("TCP").flags == "S") or (packet.getlayer("TCP").flags == "FA") or (packet.getlayer("TCP").flags == "SA") or (packet.getlayer("TCP").flags == "RA")):
                        ackCounter+=1
                if(packet.haslayer("ARP") or (packet.haslayer("DNS")) or (packet.haslayer("DHCP"))):
                    arpCounter +=1
                #counting for the layers end

                if ((packet.haslayer("Raw") & (not packet.haslayer("EAPOL")) & (not packet.haslayer("LLC")))):
                    """try:"""
                    if(packet.haslayer("IP")):
                        destIp = packet.getlayer("IP").dst                                                              # retrieves the destination ip of the packet from the IP layer
                        oriIp = packet.getlayer("IP").src                                                               # retrieves the ip from the packet is sent
                    elif(packet.haslayer("IPv6")):
                        destIp = packet.getlayer("IPv6").dst                                                            # retrieves the destination ip of the packet from the IP layer
                        oriIp = packet.getlayer("IPv6").src                                                             # retrieves the ip from the packet is sent
                    else:
                        print("buildEntropyDict: packet as wether IP nor IPv6 address:")
                        packet.show()

                    if (entropy(packet.getlayer('Raw').load) > lowerLimit and entropy(packet.getlayer('Raw').load) < upperLimit):
                        try:
                            impText = packet.getlayer('Raw').load.decode().strip()
                            payload = re.sub(r'[\W+|_]', '',impText)                                                        # \W+ deletes all special characters, \d+ deletes all numbers, |_ deletes all underscores
                            ent = entropy(payload)                                                                          #entropy UTF-8 based without special character
                            # print(entropy(packet.getlayer('Raw').load))                                                   #entropy based on rawdata
                            amountdone += 1
                            #entropyDic = prepareEntropyDic(self.entropyDict, ent, oriIp, destIp)
                            prepareEntropyDic(self.entropyDict, ent, oriIp, destIp)
                        except:
                            try:
                                amountdonesemi += 1
                                payload = packet.getlayer('Raw').load
                                ent = entropy(payload)
                                # print(e)
                                #entropyDic = prepareEntropyDic(self.entropyDict, ent, oriIp, destIp)
                                prepareEntropyDic(self.entropyDict, ent, oriIp, destIp)
                            except:
                                print("something went wrong")
                                print("NEXT FILE")
                    else:
                        amountdoneExcluded += 1
                    """except:
                        print("couldn´t extract the payload from the following packet")
                        packet.show()"""
                else:
                    amountRaw += 1
                    #analyzation area start: (purpose of the area) to find packets where the payload couldn´t be extracted
                    if (packet.haslayer("TCP")):
                        if not ((packet.getlayer("TCP").flags ==  "A") or (packet.getlayer("TCP").flags == "S")
                            or (packet.getlayer("TCP").flags == "FA") or (packet.getlayer("TCP").flags == "SA")
                            or (packet.getlayer("TCP").flags == "RA")):
                            #packet.show()
                            pass
                    else:
                        if (packet.haslayer("ARP") or packet.haslayer("DNS") or packet.haslayer("DHCP")):
                            pass
                        else:
                            #packet.show()
                            pass
                    #analyzation area ends

        finishEntropyDic(self.entropyDict)                                                                                        #to start the "average" calculation within the entropyDictionary
        print("amount packets total:", amount)
        print("amount no Raw level:", amountRaw)
        print("amount done byte based:", amountdonesemi)
        print("amount done utf8 based:", amountdone)
        print("amount done utf8 based but the entropy is higher or lower then the given boundaries:", amountdoneExcluded)
        print("packets used for ACK, SYN, SYN/ACK, FA:", ackCounter)
        print("packets used for ARP, DHCP or DNS:", arpCounter)
        print("total processed packets: ", amountdone + amountdonesemi + amountRaw + amountdoneExcluded)

class Countdown():
    '''consist a countdown to visualize the progress of a current running operation'''
    def __init__(self, total):
        self.count = 1
        self.stage = 10
        self.total = total

    def runCountdown(self):
        self.count += 1
        if (((100 / self.total) * self.count) > self.stage):                                                            #if the amount done is over the value of stage it will print, stage starts with 10 and will increase by 10 every time
            print(self.stage, "% is done")
            self.stage += 10

def entropy(data):
    '''calculates the entropy of the incoming string'''
    e = 0
    counter = collections.Counter(data)
    #print("counter ", counter)
    l = len(data)
    for count in counter.values():
        # count is always > 0
        p_x = count / l
        e += - p_x * math.log2(p_x)
    return e

def finishEntropyDic(dict):
    '''calculates the average entropy based on the data of the incomming dictionary'''
    for o in dict:
        for d in (dict[o].keys()):
            dict[o][d]["averageEntropy"] /= dict[o][d]["amount"]                                                        # calculates the averrage entropy between the two IPs

def prepareEntropyDic(dict, entropy, oriIp, destIp):
    '''responsible for the creation of the entropy dictionary '''
    if (oriIp in dict.keys()):
        if (destIp in dict[oriIp].keys()):
            dict[oriIp][destIp]["amount"] += 1
            dict[oriIp][destIp]["averageEntropy"] += entropy                                                            # adds up the entropy which will be further calculated to the average within "finishEntropy" method
        else:
            dict[oriIp][destIp] = {"averageEntropy": entropy, "amount": 1}                                              #creates new dictionary entry if destination with corresponding origin IP is not in yet
    else:
        dict[oriIp] = {destIp: {"averageEntropy": entropy, "amount": 1}}                                                #creates new dictionary entry if origin IP is not in yet

class MyTimer():
    def __init__(self):
        self.runningTimer = self.startTimer()

    def startTimer(self):
        '''starts an initial timer'''
        return timeit.default_timer()

    def end(self):
        '''ends the initial timer and prints elapsed time'''
        stop = timeit.default_timer()
        return(stop - self.runningTimer)

    def getTimer(self):
        return self.runningTimer

class Connection():
    def __init__(self, ori, dst, cAmount = 0):
        self.oriIp = ori
        self.dstIp = dst
        self.callAmount = cAmount
        self.secureConnection = 0
        self.unsecureConnection = 0

    def getOriIpObject(self):
        return self.oriIp

    def getDestIpObject(self):
        return self.dstIp

    def setOriIpObject(self, new):
        self.oriIp = new

    def setDestIpObject(self, new):
        self.dst = new

    def printAll(self):
        print("oirigin IP address:",self.oriIp.getAddress(),
              " destination IP address:", self.dstIp.getAddress(),
              " callAmount:", self.callAmount,
              " used whitelisted ports:", self.secureConnection,
              " used not whitelisted ports:", self.unsecureConnection)

class Protocol():
    def __init__(self, id):
        self.id = id
        self.name = self.initProtocolName()
        self.protCallAmount = 0

    def initProtocolName(self):
        '''looksup the name of the protocol based on its number'''
        table = {num: name[8:] for name, num in vars(socket).items() if name.startswith("IPPROTO")}
        return table[self.id]

class IpAddress():
    def __init__(self, ip):
        self.address = ip
        self.locationJson = ""

    def getAddress(self):
        return self.address

    def getJson(self):
        return self.locationJson

    def setJson(self, jsn):
        self.locationJson = jsn

    def printLocationJson(self):
        '''takes json input and prints location'''
        if(self.locationJson != ""):
            ip_address = self.locationJson['ip']
            continent = self.locationJson['continent_code']
            latitude = self.locationJson['latitude']
            longitude = self.locationJson['longitude']
            capital = self.locationJson['city']

            print('Latitude : {}'.format(latitude))
            print('Longitude : {}'.format(longitude))
            print('IP adress : {}'.format(ip_address))
            print('Continent : {}'.format(continent))
            print('City : {}'.format(capital))
        elif ((self.getAddress() == '255.255.255.255') or (re.search('^192.168.', self.getAddress())) or (
                    self.getAddress() == '0.0.0.0')):  # checks if the data goes to the broadcasting address or stays in the local network
            print("Its a local or Broadcast IP address, no loopup needed")
        else:
            print("no location loaded yet")

    def lookupIP(self):
        '''returns json file with location data'''
        url = 'http://api.ipstack.com/' + self.address + '?access_key=75ae5d89ba88b940232c4e8f26d6f7e8'.format(self.address)
        self.locationJson = requests.get(url).json()

class PortWhiteList():
    def __init__(self):
        self.pList = self.initializePortWhitelist()

    def initializePortWhitelist(self):
        '''reades an external excel file which contains the port whitelist and returns an array with all whitelisted ports'''
        portWhiteList = list()
        loc = ("portWhiteList.xlsx")
        wb = xlrd.open_workbook(loc)
        sheet = wb.sheet_by_index(0)
        sheet.cell_value(0, 0)
        for i in range(sheet.nrows):
            portWhiteList.append(int(sheet.cell_value(i, 0)))
        return portWhiteList

    def getList(self):
        return self.pList

def main():
    print("program start")
    duration = MyTimer()                                                                                                  #creates a timestamp for the startingtime
    # filename = input("Please enter the name of the pcap file: ")                                                      #to enter the filename during runtime
    #filename = 'withings_monitor_merge.pcap'
    #filename = 'camera.pcap'

    filename = 'Samsung_cam.pcap'

    researchedPcap = ResearchFile(filename)                                                                              #holds a object with all information for a research
    portWhiteList = PortWhiteList()                                                                                     #holds an object with a list with all "safe" ports

    researchedPcap.buildConnectionSet(portWhiteList)
    print("Overview of all used Ports and call amounts: \n", researchedPcap.portDictionary)                             #holds a dictionary used Ports and call amounts

    print("Overview of all established connections ")
    for c in researchedPcap.connectionSet:                                                                              #holds a list with all established connections (destination IP, origin IP, call amounts, secure port usage)
        print(c.printAll())

    print("Overview of all recoreded IPs (origin & destination): ")
    for i in researchedPcap.allIps:                                                                                     #holds a list with all IP-Addresses used
        print(i.getAddress())

    print("Overview of IPs and their geolocation: ")
    researchedPcap.buildLocationDict()                  # holds a dictionaries with all IPs and their geolocation informations
    print(researchedPcap.locationDict)

    #researchedPcap.buildEntropyDict()                   # holds a dictionary with all IPs and their destinations and the average entropy of the exchanged packets

    researchedPcap.buildCleartextDict()                 # holds a dictionary with all with all IP who sent cleartext with the corresponding destination address and the cleartext
    print("Overview of IPs their send utf-8 cleartext and the destination IP: \n", researchedPcap.clearTextDictionary)

    researchedPcap.buildEntropyDict()
    print("Overview of IPs their destination and the average entropy: \n", researchedPcap.entropyDict)

    print("program finished after:",duration.end())

if __name__ == '__main__':
    main()
