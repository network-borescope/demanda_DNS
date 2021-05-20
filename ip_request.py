from sys import argv, exit
from ip_to_nome_lat_lon import site_from_ip_addr

arguments = argv[1:]

if len(arguments) == 1:
    filename = arguments[0]
else:
    exit(1)

dns_ip_src = {} # { ip_src dist: 0 } # conta quantas perguntas determinado par ip_src distancia fez
dns_req_count = {} # conta quantos requests sao feitos antes de receber uma resposta

dns_server_resp = {} # { ip_server: [count resp *, count resp non *] }
TOTAL_ANSWERS = 0
AUTHORITATIVE_ANSWERS = 1
AUTHORITATIVE_REFUSED = 2
AUTHORITATIVE_NXDOMAIN = 3
NON_AUTHORITATIVE_ANSWERS = 4
NON_AUTHORITATIVE_REFUSED = 5
NON_AUTHORITATIVE_NXDOMAIN = 6
#RESPONSE_CLIENT_INFO = 7 # [Client Id, Client Name]
REQUEST_MADE_BY_CLIENT = 7
REQUEST_MADE_BY_NON_CLIENT = 8
SERVER_INFO = 9

fin = open(filename, "r")

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
D_IDC = 8
D_QUERY = 9
D_HOST = 10
D_US_AG = 11
D_DIST = 12
D_IDD = 13


for line in fin:

    ident = 0
    altura = 0
    if len(line) == 0: continue

    # verifica se eh a linha de header
    while line[0] == ' ' or line[0] == '\t':
        if line[0] == '\t': ident += 8
        else: ident+=1
        line =line[1:]

    altura = ident/4
    #print (altura)

    if altura == 0:
        # reinicia as variaveis de memoria
        key = ""
        data = []

        # inicia o processamento do novo hash
        clean_line = line.strip()
        items = clean_line.split(" ")

        if len(items) < 6: continue
        if items[2] != "IP": continue

        n = len(items)

        # [data, hora, val_ttl, val_proto, val_ip_id ]
        val_proto = items[15][1:-2]
        data = [ items[0], items[1], items[6].strip(","), val_proto, items[8].strip(","), "0", "0", "0", "0", "0", "0", "0", "0", "0" ]
        #print("Data> ", data)
        if data[D_TTL] == "oui":
             data = []
             continue

        dist = int(data[D_TTL])
        if dist < 64: dist = 64 - dist
        elif dist < 128: dist = 128 - dist
        else: dist = 255 - dist
        data[D_DIST] = str(dist)

    # linha do corpo
    elif altura == 1:

        items = line.strip().split(" ")
        if len(items) == 0 or len(items[0]) == 0: continue

        # testa para ver se eh o sub-header
        if altura == 1 and len(items) > 6:
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
                    port_dst = "0"
                else:
                    port_dst = ip_dst_a[4]

                    # concentra portas sem interesse na porta "0"
                    proto_port = data[D_PROTO] + ":" + port_dst

                if proto_port == "17:53": # se for dns request
                    if len(items) < 10 or (items[7] != 'A?' and items[8] != 'A?'):
                        continue

                    key = f"{data[D_SIP]} {data[D_DIST]}"
                    if key not in dns_ip_src:
                        dns_ip_src[key] = 1
                    
                    else:
                        dns_ip_src[key] += 1


                elif (data[D_PROTO] + ":" + data[D_SPORT]) == "17:53": # dns response
                    key = data[D_SIP]
                    if key not in dns_server_resp:
                        dns_server_resp[key] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]

                        s = site_from_ip_addr(ip_src_a)
                        dns_server_resp[key][SERVER_INFO] = (int(s[6]), s[0])

                    s = site_from_ip_addr(ip_dst_a)
                    if int(s[6]) != 1: dns_server_resp[key][REQUEST_MADE_BY_CLIENT] += 1
                    else: dns_server_resp[key][REQUEST_MADE_BY_NON_CLIENT] += 1
                    
                    dns_server_resp[key][TOTAL_ANSWERS] += 1

                    if "*" in items[6] or "*" in items[7]:
                        dns_server_resp[key][AUTHORITATIVE_ANSWERS] += 1

                        if "Refused" in items[7]:
                            dns_server_resp[key][AUTHORITATIVE_REFUSED] += 1 # resposta com erro
                        
                        elif "NXDomain" in items[7]:
                            dns_server_resp[key][AUTHORITATIVE_NXDOMAIN] += 1 # resposta com erro

                    else:
                        dns_server_resp[key][NON_AUTHORITATIVE_ANSWERS] += 1
                        
                        if "Refused" in items[7]:
                            dns_server_resp[key][NON_AUTHORITATIVE_REFUSED] += 1 # resposta com erro
                        
                        elif "NXDomain" in items[7]:
                            dns_server_resp[key][NON_AUTHORITATIVE_NXDOMAIN] += 1 # resposta com erro

fin.close()

ip_name = {}
max_len_name = 0
with open("req_src_name.txt", "r") as f:
    for line in f:
        line = line.strip()
        ip, name = line.split(" ")

        if len(name) > max_len_name: max_len_name = len(name)

        ip_name[ip] = name

with open("dns_request.txt", "w") as f, open("dns_request.csv", "w") as csv_f:
    # ordena dicionario em ordem decrescente
    sorted_dns_ip_src = {key: val for key, val in sorted(dns_ip_src.items(), key = lambda item: item[1], reverse=True)}

    for key in sorted_dns_ip_src:
        splited_key = key.split(" ")

        ip_src_a = splited_key[0].split(".")
        s = site_from_ip_addr(ip_src_a)
        client_id = int(s[6])
        client_name = s[0]

        #if client_id != 1:
        max_len_name = 30

        padding_ip = " " * (15 - len(splited_key[0]))
        padding_dist = " " * (2 - len(splited_key[1]))
        padding_id = ""
        if client_id < 10: padding_id = " "

        name = None
        if splited_key[0] in ip_name: name = ip_name[splited_key[0]]
        else: name = "NotOnList"

        if len(name) > max_len_name:
            name = name[:26] + "..."
            padding_name = " "
        else:
            padding_name = " " * (max_len_name - len(name))
        
        if dns_ip_src[key] < 10:
            padding_count = " " * 4
        elif dns_ip_src[key] < 100:
            padding_count = " " * 3
        elif dns_ip_src[key] < 1000:
            padding_count = " " * 2
        elif dns_ip_src[key] < 10000:
            padding_count = " "
        

        f.write(f"CLIENT ID: {client_id}{padding_id}| ")
        f.write(f"NAME: {name}{padding_name}| ")
        f.write(f"IP SRC: {splited_key[0]}{padding_ip}| ")
        f.write(f"DIST: {splited_key[1]}{padding_dist}| ")
        f.write(f"COUNT: {dns_ip_src[key]}{padding_count}| ")
        f.write(f"CLIENT NAME: {client_name}\n")
        print(f"{client_id};{name};{splited_key[0]};{splited_key[1]};{dns_ip_src[key]}", file=csv_f)


open_dns = {}
with open("open_dns_list.txt", "r") as f:
    for line in f:
        line = line.strip()
        name, ip1, ip2 = line.split("|")

        open_dns[ip1] = name
        open_dns[ip2] = name

with open("dns_response.txt", "w") as f:
    sorted_dns_server_resp = {key: val for key, val in sorted(dns_server_resp.items(), key = lambda item: item[1][0], reverse=True)}
    f.write(f"RESPOSTAS DE SERVIDORES DNS\n\n")
    for key in sorted_dns_server_resp:
        if key in open_dns:
            print(f"{key} ({open_dns[key]}) *OPEN DNS", file=f)
        else:
            print(f"{key} ({sorted_dns_server_resp[key][SERVER_INFO][1]})", file=f)

        f.write(f"\tTOTAL ANSWERS: {sorted_dns_server_resp[key][TOTAL_ANSWERS]}\n")

        percent = (sorted_dns_server_resp[key][REQUEST_MADE_BY_CLIENT]/sorted_dns_server_resp[key][TOTAL_ANSWERS])*100
        f.write(f"\t\tTOTAL ANSWERS TO POP CLIENTS: {sorted_dns_server_resp[key][REQUEST_MADE_BY_CLIENT]} ({percent:.2f}%)\n")
        
        non_pop_clients = sorted_dns_server_resp[key][TOTAL_ANSWERS] - sorted_dns_server_resp[key][REQUEST_MADE_BY_CLIENT]
        percent = (non_pop_clients/sorted_dns_server_resp[key][TOTAL_ANSWERS])*100
        f.write(f"\t\tTOTAL ANSWERS TO NON POP CLIENTS: {non_pop_clients} ({percent:.2f}%)\n")
        f.write("\t\t-----------------------------------------------------------------\n")

        percent = (sorted_dns_server_resp[key][AUTHORITATIVE_ANSWERS]/sorted_dns_server_resp[key][TOTAL_ANSWERS])*100
        f.write(f"\t\tAUTHORITATIVE ANSWERS: {sorted_dns_server_resp[key][AUTHORITATIVE_ANSWERS]} ({percent:.2f}%)\n")

        if sorted_dns_server_resp[key][AUTHORITATIVE_ANSWERS] != 0:
            percent_refused = (sorted_dns_server_resp[key][AUTHORITATIVE_REFUSED]/sorted_dns_server_resp[key][AUTHORITATIVE_ANSWERS])*100
            percent_nxdomain = (sorted_dns_server_resp[key][AUTHORITATIVE_NXDOMAIN]/sorted_dns_server_resp[key][AUTHORITATIVE_ANSWERS])*100
            
            no_error = sorted_dns_server_resp[key][AUTHORITATIVE_ANSWERS] - sorted_dns_server_resp[key][AUTHORITATIVE_REFUSED] - sorted_dns_server_resp[key][AUTHORITATIVE_NXDOMAIN]
            percent_no_error = (no_error/sorted_dns_server_resp[key][AUTHORITATIVE_ANSWERS])*100

        else:
            percent_refused = 0.0
            percent_nxdomain = 0.0
            no_error = 0
            percent_no_error = 0.0
        
        f.write(f"\t\t\tREFUSED: {sorted_dns_server_resp[key][AUTHORITATIVE_REFUSED]} ({percent_refused:.2f}%)\n")
        f.write(f"\t\t\tNXDOMAIN: {sorted_dns_server_resp[key][AUTHORITATIVE_NXDOMAIN]} ({percent_nxdomain:.2f}%)\n")
        f.write(f"\t\t\tOTHERS: {no_error} ({percent_no_error:.2f}%)\n")


        percent = (sorted_dns_server_resp[key][NON_AUTHORITATIVE_ANSWERS]/sorted_dns_server_resp[key][TOTAL_ANSWERS])*100
        f.write(f"\t\tNON AUTHORITATIVE ANSWERS: {sorted_dns_server_resp[key][NON_AUTHORITATIVE_ANSWERS]} ({percent:.2f}%)\n")

        if sorted_dns_server_resp[key][NON_AUTHORITATIVE_ANSWERS] != 0:
            percent_refused = (sorted_dns_server_resp[key][NON_AUTHORITATIVE_REFUSED]/sorted_dns_server_resp[key][NON_AUTHORITATIVE_ANSWERS])*100
            percent_nxdomain = (sorted_dns_server_resp[key][NON_AUTHORITATIVE_NXDOMAIN]/sorted_dns_server_resp[key][NON_AUTHORITATIVE_ANSWERS])*100

            no_error = sorted_dns_server_resp[key][NON_AUTHORITATIVE_ANSWERS] - sorted_dns_server_resp[key][NON_AUTHORITATIVE_REFUSED] - sorted_dns_server_resp[key][NON_AUTHORITATIVE_NXDOMAIN]
            percent_no_error = (no_error/sorted_dns_server_resp[key][NON_AUTHORITATIVE_ANSWERS])*100
        else:
            percent_refused = 0.0
            percent_nxdomain = 0.0
            no_error = 0
            percent_no_error = 0.0
        
        f.write(f"\t\t\tREFUSED: {sorted_dns_server_resp[key][NON_AUTHORITATIVE_REFUSED]} ({percent_refused:.2f}%)\n")
        f.write(f"\t\t\tNXDOMAIN: {sorted_dns_server_resp[key][NON_AUTHORITATIVE_NXDOMAIN]} ({percent_nxdomain:.2f}%)\n")
        f.write(f"\t\t\tOTHERS: {no_error} ({percent_no_error:.2f}%)\n")
