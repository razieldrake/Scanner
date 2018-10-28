#coding UTF-8

from kamene.all import *
import sys
import random
import netaddr


def pingsweep():
    # definit la plage ip
    network = input('Entrer une plage d adresse type x.x.x.x /yy')

    # construit une liste d adresse du reseau, initialise le counter hote
    addresses = netaddr.IPNetwork(network)
    liveCounter = 0

    # envoi une requete ICMP et attend une réponse
    for host in addresses:
        if (host == addresses.network or host == addresses.broadcast):
            # passe le réseau et le broadcast
            continue

        resp = sr1(IP(dst=str(host)) / ICMP(), timeout=0.5, verbose=0)

        if resp is None:
            print(host, 'ne répond pas')
        elif (
                int(resp.getlayer(ICMP).type) == 3 and
                int(resp.getlayer(ICMP).code) in [1, 2, 3, 9, 10, 13]
        ):
            print(host, 'bloque ICMP')
        else:
            print(host, ' est en ligne ')
            liveCounter += 1

    print('{}/{} hotes sont en ligne.'.format(liveCounter, addresses.size))
    menu()
def tcpPortRangeScanner():
    portrange = []
    print('Test les ports ouverts sur une hote unique')
    print('Randomize des port source pour passer les parefeu basique')
    print('Ne fonctionne pas sur les parefeu actuels')
    host=  input('Entrer l ip de l hote cible')
    getinput = input('Entrer un port, entrer stop pour finir l ajout de port')
    while (getinput != "stop"):
        portrange.append(int(getinput))
        getinput = input('Entrez un port, entrez stop pour terminer l ajout de port')
    print('Envoi de SYN avec un port source aleatoire pour passer l anti flood parefeu')
    for dstPort in portrange:
        srcPort = random.randint(1025, 65534)
        resp = sr1(IP(dst=host) / TCP(sport=srcPort, dport=dstPort, flags="S"), timeout=0.5)
        if resp is None:
            print('{}:{} est filtré (silently dropped).'.format(host, str(dstPort)))
        elif (resp.haslayer(TCP)):
            if (resp.getlayer(TCP).flags == 0x12):
                # Envoi d'un flag reset pour fermer la connection
                send_rst = sr(IP(dst=host) / TCP(sport=srcPort, dport=dstPort, flags='R'), timeout=0.5)
                print('{}:{} est ouvert.'.format(host, str(dstPort)))
            elif (resp.getlayer(TCP).flags == 0x14):
                print('{}:{} est fermé.'.format(host, str(dstPort)))

        elif (resp.haslayer(ICMP)):
            if (int(resp.getlayer(ICMP).type) == 3 and int(resp.getlayer(ICMP).code) in [1, 2, 3, 9, 10, 13]):
                print('{}:{} est filtré (silently dropped).'.format(host, str(dstPort)))

    menu()

def runsniffing():
    print('Lancement du sniffing')
    print('les filtres sont en language Berkeley Packet Filter aka BSD')
    rep = input('Indiquez vos filtres')
    reptime = int(input('indiquez le temps de sniff'))
    result = sniff(filter=rep,count=0,timeout=reptime)
    print('voulez vous sauvegarder le résulatt du sniff ? ')
    repsave = input('o/n ?')
    if repsave == 'o':
        print('Visionnage des reultat pre sauvegarde')
        hexdump(result)
        print ('sauvegarde pcap')
        wrpcap('sniff.pcap',result)
        print('sauvegarde pcap terminée')
        print('sauvegarde pdf dump')
        result.pdfdump('sniff.pdf')
        print('les sauvegarde sont terminées')
        menu()


def BFT():
    host=[]
    port = []
    print('Un traceroute qui n attend pas les reponse')
    print('precedentes pour lancer les autre trace')
    print('Veuillez noter la liste des nom de dommaine ')
    print ('entrer stop pour arreter d ajouter des hote')
    getinput = input('entrer les hotes a tracer')
    while (getinput != "stop"):
        host.append(getinput)
        getinput = input('Entrer les hotes a tracer et entrer stop pour arreter')
    print ('Veuillez entrer les port sur lesquel faire le BFT')
    print('Entrer stop pour arreter d enregistrer des ports')
    getinput = input('Entrer les ports sur lesquels tracer')
    while(getinput != "stop"):
        port.append(int(getinput))
        getinput = input('Entrer les ports  a tracer et entrer stop pour arreter')
    res,unres = traceroute(host,dport=port,maxttl=50,retry=-2)
    res.nsummary()
    res.graph()
    res.graph(type="ps", target="lp")
    res.graph(target="> graph.svg")
    menu()

def tracrt():
    print('Mode traceroute')
    rep = input('Indiquez la destination finale')
    rep2 = int(input('Inqiuez le nombre de saut maximum'))
    result,nores = sr(IP(dst=rep,ttl=(1,rep2) )/ TCP(),timeout=0.5)
    for emis,recu in result:
        print(emis.ttl, recu.src)

    menu()

def monoping():
    print('Demarrage du ping mono cible')
    destinataire = input('Indiquer l ip cible')
    result = sr1(IP(dst=destinataire)/ICMP(),timeout=0.5)
    result[0][0].show()
    if result.type ==0: #0 === echo-reply
       print (result.src + ' existe')
       discovedred_host.append(result.src)
    menu()


def discoverping():

    print('demarrage du discover ping')
    range = input('Indiquer la plage d adresse ')
    result,nores=sr(IP(dst=range)/ICMP(),timeout=0.5)
    for elem in result:
        if elem[1].type==0:
            print (elem[1].src + ' existe')
            discovedred_host.append(elem[1].src)
    menu()

def sendSynOnPort():
    print('Demarrage de SynACk')
    print('--------------------')
    print('1) pour un scan sur un seul port')
    print('2) Poiur un scan sur 2 ports')
    print('3) Pour un scan sur une lioste de ports')
    rep = int( input('Entrer votre choix : '))
    if rep == 1 :
        port = int(input('Sur quel port voulez envoyer le SYN ? '))
        destination = input('Sur quel adresse ou plage d adresse voulez envoyé ?')
        pq =  IP(dst=destination)/ TCP(sport=12345,dport=port,flags='S')
        result,nores = sr(pq)
        if result[0][1][TCP].flags== 18: #18<==>SYn/ACK
            print(result[0][1].src + ' a le port ' + str(port) + ' ouvert ')
    if rep == 2 :
        port = []
        port.append(int(input('Entrer le premier port ')))
        port.append(int(input('Entrer le second port')))
        destination = input('Entrer l adresse ou la plage d adresse ')
        pq = IP(dst=destination)/TCP(sport=12345,dport=port,flags='S')
        result,nores = sr(pq)
        for ele in port:
            if result[0][1][TCP].flags== 18: #18<==>Syn/ack
                print(result[0][1].src + ' a le port ' + str(ele) + ' ouvert')
    if rep ==3 :
        portD = int(input('Entrez le port intervalle de depart'))
        portF = int(input('Entrez le port final'))
        destination = input('Entrer l ip de la cible')
        pq = IP(dst=destination)/TCP(sport=12345,dport=(portD,portF),flags='S')
        result,nores = sr(pq)
        for emis,recu in result:
            if recu[1].flags == 18 : #18<==> SYN/ACk
                print(recu.src + ' a le port ' + str(recu.sport) + ' ouvert ')
    menu()
def scan() :
    print('------------------------------------------------')
    print('------------------------------------------------')
    print('------------------------------------------------')
    print('1) Attaque ICMP Sweep ')
    print('2) ICMP redirect -- a implémenter')
    print('3) ICMP Close TCP --a implementer')
    print('4) Ping adresse distante')
    print('5) Découverte réseau sans ICMP sweep')
    print('----------------------------------------')
    print('------------------------------------------------')
    print('------------------------------------------------')
    print('6) Envoi TCP SYN-ACK sur une liste de port')
    print('7) Traceroute')
    print('8) sniffinf')
    print('9) Big Fuckinig Traceroute')
    print('------------------------------------------')
    print('------------------------------------------------')
    print('------------------------------------------------')
    print('10) Scanner port ouvert TCP hote unique en port source aleatoire')
    repscan = input('Selectionner vvotre choix')
    repscan=int(repscan)
    if repscan == 1:
        pingsweep()
    if repscan == 4 :
        monoping()
    if repscan == 5:
        discoverping()
    if repscan == 6:
        sendSynOnPort()
    if repscan == 7:
        tracrt()
    if repscan == 8:
        runsniffing()
    if repscan == 9:
        BFT()
    if repscan == 10:
        tcpPortRangeScanner()

def savesess():
    dir()
    save_session("session.scapy")
    menu()

def loadsess():
    load_session("session.scapy")
    dir()
    menu()

def menu():
    print('_____________________________________________________')
    print('-----------------------------------------------------')
    print('-----------------GODLIKE SCANNER---------------------')
    print('-----------------------------------------------------')
    print('*************réalisé par mes soins*******************')
    print('************Raziel Asurean Drake ********************')
    print('_____________________________________________________')
    print('Demarrage du programme')
    print('1 :   demarage du scan')
    print('-----------------------------------------------------')
    print('-----------------------------------------------------')
    print('99:   pas encore implémenté')
    print('109:  save sessions')
    print('110:  load sessions')
    print('-----------------------------------------------------')
    print('-----------------------------------------------------')
    print('111 : sortie du programme')
    rep = input('Selectionner votre choix')
    rep2int = int(rep)
    if rep2int == 1:
        scan()
        for elem in discovedred_host:
            print(elem)
    if rep2int == 99:
        menu()
    if rep2int == 109:
        savesess()
    if rep2int == 110:
        loadsess()
    if rep2int == 111:
        sys.exit(0)


discovedred_host = []
menu()
