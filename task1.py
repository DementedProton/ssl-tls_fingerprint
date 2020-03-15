from scapy.all import *
f = rdpcap('handshake_packets.pcap')

dict_of_handshakes = {}

handshake_record_table = {0: '0x00', 1: '0x01', 2: '0x02', 11: '0x0b',
                          12: '0x0c', 13: '0x0d', 14: '0x0e', 15: '0x0f',
                          16: '0x10', 20: '0x14'}

matrix_handshake_table = {0: 0, 1: 1, 2: 2, 11: 3,
                          12: 4, 13: 5, 14: 6, 15: 7,
                          16: 8, 20: 9, 4: 12}
ports = {}
class Handshake:

    def __init__(self, packet):
        self.src = packet[IP].src
        self.dst = packet[IP].dst
        self.dport = str(packet[TCP].dport)
        self.sport = str(packet[TCP].sport)
        #self.hash_val = self.src + '-' + self.sport + '-' + self.dst + '-' + self.dport
        self.hash_val = self.dport if self.sport == '443' else self.sport # FIX THIS TOMORROW
        # if self.dport == '443':
        #     self.hash_val = self.sport
        # elif self.sport == '443':
        #     self.hash_val = self.dport
        self.previous_state = None
        self.current_state = None
        self.matrix = [[0]*14]*14
        self.counter = 0

# 0- hello request  1 - client hello   2- server hello   3-certificate
# 4-server_KE    5-cert_req    6-server_done   7-cert_verif  8-clientKE
# 9-finish   10-Change Cipher spec   11- Application Data    12- Alert
# 13- New session ticket

count = 0

for packet in f:
    count+=1
    if packet.haslayer(SSL):
        handshake_packet = Handshake(packet)
        if handshake_packet.sport not in list(ports.keys()):
            ports[handshake_packet.sport] = 1
        else:
            ports[handshake_packet.sport] += 1
        if handshake_packet.hash_val in list(dict_of_handshakes.keys()):
            handshake_packet = dict_of_handshakes[handshake_packet.hash_val]
        else:
            dict_of_handshakes[handshake_packet.hash_val] = handshake_packet
        handshake_packet.counter += 1
        for record in packet.records:
            if record.content_type == 22: # handshake protocol
                if not record.haslayer(TLSCiphertext) and record[TLSHandshake].type != 22 and record[TLSHandshake].type != 4: # not Certificate Status
                    handshake_packet.current_state = matrix_handshake_table[record[TLSHandshake].type]
            elif record.content_type == 20: # change cipher spec
                handshake_packet.current_state = 10
            elif record.content_type == 21: # alert
                handshake_packet.current_state = 12
            elif record.content_type == 23: # data
                handshake_packet.current_state = 11
            if handshake_packet.previous_state is not None:
                handshake_packet.matrix[handshake_packet.previous_state][handshake_packet.current_state] += 1
                if handshake_packet.matrix[0][handshake_packet.current_state] > 1:
                    print(handshake_packet.matrix)
            else:
                handshake_packet.matrix[0][handshake_packet.current_state] += 1
            handshake_packet.previous_state = handshake_packet.current_state
            dict_of_handshakes[handshake_packet.hash_val] = handshake_packet

print(dict_of_handshakes.keys())
print(ports)
#print(dict_of_handshakes['47378'].matrix)
#print(dict_of_handshakes['51026'].matrix)