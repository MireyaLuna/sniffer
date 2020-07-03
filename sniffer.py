import socket
import sys
import struct
#esta funcion nos ayuda a definir que flags son las que estan activas en la cabecera TCP
def eth_addr (a) :
    b = ("%.2x:%.2x:%.2x:%.2x:%.2x:%.2x" % ((a[0]) , (a[1]) ,(a[2]), (a[3]), (a[4]) , (a[5])))
    return b

def udp_seg(data):
    src_port, dest_port, size = struct.unpack('!HH2xH', data[:8])
    return src_port, dest_port, size, data[8:]

def definirFlagsTCP(flag):
    #guardamos todos los valores posibles de los flags en una tupla
    Flag_URG = {0:'',1: '\t32 - URG (Urgente)\n'}
    Flag_ACK = {0:'',1: '\t16 - ACK (Acuse de recibo)\n'}
    Flag_PSH = {0:'',1: '\t8 - PSH (Push)\n'}
    Flag_RST = {0:'',1: '\t4 - RST (Reset)\n'}
    Flag_SYN = {0:'',1: '\t2 - SYN (Sincronizacion)\n'}
    Flag_FIN = {0:'',1: '\t1 - FIN (Finalizar)\n'}
    #mediante operaciones en hexadecimales definimos los valores comenzando a verificar por URG
    #obtenemos el primer bit
    URG = flag & 0x20 #0x20 equivale a 32 en decimal
    URG >>= 5
    print('   |-Urgent Flag\t: '+str(URG))
    #obtenemos el segundo bit
    ACK = flag & 0x10 #0x10 equivale a 16 en decimal
    ACK >>= 4 
    print('   |-Ackenowledgement Flag : '+str(ACK))
    #obtenemos el tercer bit
    PSH = flag & 0x8 #0x8 equivale a 8 en decimal
    PSH >>= 3
    print('   |-Push Flag\t\t: '+str(PSH))
    #obtenemos el cuarto bit
    RST = flag & 0x4 #0x4 equivale a 4 en decimal
    RST >>= 2 
    print('   |-Reset Flag\t\t: '+str(RST))
    #obtenemos el quinto bit
    SYN = flag & 0x2 #0x2 equivale a 2 en decimal
    SYN >>= 1 
    print('   |-Synchronise Flag\t: '+str(SYN))
    #obtenemos el sexto bit
    FIN = flag & 0x1 #0x1 equivale a 1 en decimal
    FIN >>= 0
    print('   |-Finish Flag\t: '+str(FIN))
    #una vez verificado todo esto para saber cuales bits estan prendidos, concatenamos los datos de cada posicion
    Flags = Flag_URG[URG] + Flag_ACK[ACK] + Flag_PSH[PSH] + Flag_RST[RST] + Flag_SYN[SYN] +  Flag_FIN[FIN]
    #finalmente retornamos el valor de la cadena concatenada
    return Flags
def icmp_packet(data):
    icmp_type, code, checksum = struct.unpack('!BBH', data[:4])
    return icmp_type, code, checksum, data[4:]
#Instanciamos un socket con un try catch para la excepsion de errores
try:
    s = socket.socket( socket.AF_PACKET , socket.SOCK_RAW , socket.ntohs(0x0003))
except:
    print ('Ha ocurrido un error...')
    sys.exit()

#Recibe paquetes
while True:
    datos = s.recvfrom(65565)
    #instanciamos al paquete como una tupla de datos
    datos = datos[0]
	#parse ethernet header
    eth_header = datos[:14]
    eth = struct.unpack('!6s6sH' , eth_header)
    eth_protocol = socket.ntohs(eth[2])
    print('\n------------ LUNA ARUQUIPA MIREYA ADRIANA ------------')
    print('-------------------- C.I.: 9875648 -------------------')
    print('\nEthernet Header\n   |-Destination Address: ' + eth_addr(datos[0:6]) + '\n   |-Source Address \t: ' + eth_addr(datos[6:12])+ '\n   |-Protocol \t\t: ' + str(eth_protocol))

    ip_header = datos[14:20+14]
    iph = struct.unpack('!BBHHHBBH4s4s' , ip_header)

    print('\nIP Header ')
    #guardamos el valor de la primera parte de la cabecera
    version_ihl = iph[0]
    #recorremos cuatro bits para solo obtener la version
    version = version_ihl >> 4
    #guardamos el Internet Header Length realizando un AND con la version de la primera parte de la cabecera
    ihl = version_ihl & 0xF
    #multiplicamos el dato obtenido anteriormente por 4 para luego obtener el tamaño en bytes.
    iph_length = ihl * 4
    ihlbytes = ihl*4
    #obtenemos los datos de la cabecera para poder imprimirlos despues
    ip_tos = iph[1] # (Type Of Service) char
    ip_len = iph[2] # (IP Total Length) short int
    #obtenemos el tamaño en bytes
    ipbytes = ip_len*(32/8)
    ip_id = iph[3]  # (ID) short int
    #ip_flg = definirFlagsIP(iph[4]) # (Flags) short int
    ip_ttl = iph[5] # (Tiempo de vida) char
    ip_p = iph[6]   # (Protocolo)char
    ip_sum = iph[7] # (Cheksum)shor int
    s_addr = socket.inet_ntoa(iph[8]) # source addrees (IP Origen)
    d_addr = socket.inet_ntoa(iph[9]) #destination addrees (IP Destino)
    #imprimos los datos guardadas en las variables anteriores
    
    print('   |-IP Version\t\t: ' + str(version))
    print('   |-IP Header Length\t: ' ,ihl, 'DWORDS ',str(ihlbytes) ,'bytes')
    print('   |-Type Of Service \t: ',str(ip_tos))
    print('   |-IP Total Length \t: ',ip_len, ' Bytes(Size of Packet)')
    print('   |-Identificacion\t: ',ip_id)
    #print('Flags: ',iph[4],'\n',ip_flg)
    print('   |-TTL\t: ' + str(ip_ttl))
    print('   |-Protocol\t: ' + str(ip_p))
    print('   |-Checksum\t: ',ip_sum)
    print('   |-Source IP\t: ' + str(s_addr) )
    print('   |-Destination IP\t: ' + str(d_addr))
    protocolo = int(ip_p)
    if(protocolo == 6):
        t = iph_length + 14
        tcp_header = datos[t:t+20]
        print('\nTCP Header')
        tcph = struct.unpack('!HHLLBBHHH' , tcp_header)
        
        #guardamos en variables los valores para poder imprimirlos luego
        s_port = tcph[0]   # (Puerto de origen) uint16_t
        d_port = tcph[1]   # (Puerto de destino) uint16_t
        seq = tcph[2]   # (Numero de secuencia) uint32_t
        ack = tcph[3]   # (Acuse de recibo) uint32_t
        reservado = tcph[4]   # (espacio reservado para uso futuro) uint8_t
        tcph_length = reservado >> 4   # (Tamaño de la cabecera)
        tcplengthbytes = tcph_length*4 # Tamaño de la cabecera en bytes
        tcph_flags = definirFlagsTCP(tcph[5])  # (Flags TCP) uint8_t
        tcph_windowsize = tcph[6]      # (Tamaño de la ventana) uint16_t
        tcph_checksum = tcph[7]         # (Cheksum) uint16_t
        tcph_up = tcph[8]   # (Puntero urgente) uint16_t
        #imprimimos los datos guardados en las variables anteriores

        print('   |-Source Port\t: ',s_port)
        print('   |.Destination Port\t:',d_port)
        print('   |-Sequence Number\t:',seq)
        print('   |-Acknowledge Number\t:',ack)
        print('   |-Header Length\t:',tcph_length,'DWORDS ',str(tcplengthbytes) ,'bytes')
        tcph_flags = definirFlagsTCP(tcph[5])
        print('   |-Window\t: ',tcph_windowsize)
        print('   |-Checksum\t: ',tcph_checksum)
        print('   |-Urgent Pointer\t:',tcph_up)
    else:
        if(protocolo==1):
            icmp_type, code, checksum, data = icmp_packet(datos)
            print('\nICMP Header')
            print('   |-Type\t: {}\n   |-Code\t: {}\n   |-Checksum\t: {}'.format(icmp_type, code, checksum))
        else:
            if(protocolo==17):
                src_port, dest_port, length, data = udp_seg(datos)
                print('\nUDP Header')
                print('   |-Source Port\t: {}\n   |-Destination Port\t: {}\n   |-Length\t: {}'.format(src_port, dest_port, length))

