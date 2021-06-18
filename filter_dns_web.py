from sys import stdin, argv, exit

arguments = argv[1:]
filename_in = None
if len(arguments) == 1:
    filename_out = arguments[0]
elif len(arguments) == 2:
    filename_in, filename_out = arguments
else:
    exit(1)

data = []
# data positions
D_DATA = 0
D_HORA = 1
D_TTL = 2
D_PROTO = 3
D_IP_ID = 4
D_SIP= 5
D_SPORT = 6
D_DIP= 7
D_DPORT = 8
D_IDC = 9
D_QUERY = 10
D_HOST = 11
D_US_AG = 12
D_DIST = 13
D_IDD = 14


count = 0

DNS_REQ = 0
DNS_RESP = 1
WEB_REQ = 2
WEB_RESP = 3
lines = ''
type = None

INTERNA = 0
EXTERNA = 1
interfaces = { "cc4e 2442 550c": EXTERNA, "cc4e 2442 550d": INTERNA }

if filename_in != None:
    fin = open(filename_in, "r")
else:
    fin = stdin
fout = open(filename_out, "w")

for line in fin:

    ident = 0
    altura = 0
    if len(line) == 0: continue

    # verifica se eh a linha de header
    line_aux = line
    while line[0] == ' ' or line[0] == '\t':
        if line[0] == '\t': ident += 8
        else: ident+=1
        line = line[1:]

    altura = ident/4
    #print (altura)

    if altura == 0:
        lines = ""
        type = None
        data = ["0" for x in range(15)]

        # inicia o processamento do novo hash
        clean_line = line.strip()
        items = clean_line.split(" ")

        if len(items) < 6: continue
        if items[2] != "IP": continue

        val_proto = items[15][1:-2]
        data[D_PROTO] = val_proto

        lines += line_aux

    # linha do corpo
    elif altura == 1:
        items = line.strip().split(" ")
        if len(items) == 0 or len(items[0]) == 0: continue

        # testa para ver se eh o sub-header
        if len(items) > 6:
            c = items[0][0]
            if c >= '0' and c <= '9':
                ip_src_a = items[0].split(".")

                ip_src = ip_src_a[0] + "." + ip_src_a[1] + "." + ip_src_a[2] + "." + ip_src_a[3]
                data[D_SIP] = ip_src
                data[D_SPORT] = ip_src_a[4]


                ip_dst_a = items[2].split(".")
                ip_len = len(ip_dst_a)

                # remove o ":" do final dos campos do ip_dst
                ip_dst_a[ip_len-1] = ip_dst_a[ip_len-1] [:-1]

                # reconstitui o ip
                ip_dst = ip_dst_a[0] + "." + ip_dst_a[1] + "." + ip_dst_a[2] + "." + ip_dst_a[3]
                data[D_DIP] = ip_dst

                if ip_len == 4:
                    #port_dst = "0"
                    data[D_DPORT] = "0"
                else:
                    #port_dst = ip_dst_a[4]
                    data[D_DPORT] = ip_dst_a[4]

                    # concentra portas sem interesse na porta "0"
                    #proto_port = data[D_PROTO] + ":" + port_dst
                
                proto_dport = (data[D_PROTO] + ":" + data[D_DPORT])
                proto_sport = (data[D_PROTO] + ":" + data[D_SPORT])
                
                # dns request
                if proto_dport == "17:53": type = DNS_REQ

                # dns response
                elif proto_sport == "17:53": type = DNS_RESP

                # web request
                elif proto_dport == "6:80" or proto_dport == "6:443": type = WEB_REQ

                # web response
                elif proto_sport == "6:80" or proto_sport == "6:443": type = WEB_RESP
            
                lines += line_aux
    
    # verifica qual eh a interface
    elif altura == 2 and len(line) > 6 and line[:6] == "0x0000":
        pos = line.find("cc4e 2442 550")

        if pos != -1:
            interface = line[pos:pos+14]

            if interface in interfaces:
                if interfaces[interface] == INTERNA: # saindo da rede
                    if type == DNS_REQ or type == WEB_REQ:
                        fout.write("-------->> " + lines)
                
                else: # entrando na rede
                    if type == DNS_RESP or type == WEB_RESP:
                        fout.write("<<-------- " + lines)
            

if filename_in != None: fin.close()
fout.close()
