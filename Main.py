#coding UTF-8

from kamene.all import *
import sys



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
    print('1) Attaque ICMP Sweep -- a implémenter')
    print('2) ICMP redirect -- a implémenter')
    print('3) ICMP Close TCP --a implementer')
    print('4) Ping adresse distante')
    print('5) Découverte réseau')
    print('----------------------------------------')
    print('6) Envoi TCP SYN-ACK sur une liste de port')
    print('7) Traceroute')
    print('8) sniffinf')
    repscan = input('Selectionner vvotre choix')
    repscan=int(repscan)
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

def savesess():
    dir()
    save_session("session.scapy")
    menu()

def loadsess():
    load_session("session.scapy")
    dir()
    menu()

def menu():
    print('Demarrage du programme')
    print('1 :   demarage du scan')
    print('99:   is not yet implemented')
    print('109:  save sessions')
    print('110:  load sessions')
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
