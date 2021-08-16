from sys import argv, exit
from ip_to_nome_lat_lon import site_from_ip
import datetime

arguments = argv[1:]

if len(arguments) == 1:
    filename = arguments[0]
else:
    exit(1)
    
def hour_to_timedelta(d_hora):
    hour, min, sec = d_hora.split(":")
    
    return datetime.timedelta(hours=int(hour), minutes=int(min), seconds=float(sec))

def dns_req_eof(last_timedelta, current_timedelta, delta_seconds=30):
    delta = datetime.timedelta(seconds=delta_seconds)
    
    if current_timedelta <= last_timedelta - delta: return False
    
    return True

open_dns = {}
with open("open_dns_list.txt", "r") as f:
    for line in f:
        line = line.strip()
        name, ip1, ip2 = line.split("|")

        open_dns[ip1] = name
        open_dns[ip2] = name

dns_match = {} # { f"{ip_src} {ip_dst} {query_id}": [dns_req, dns_resp], "web": primeiro acesso Web da mask} }

REQUEST = 0
RESPONSE = 1
REQUEST_TIME = 2
REQ_INTERFACE = 3
RESP_INTERFACE = 4
REQ_DIST_TTL = 5
REQ_CLIENT = 6
RESP_CLIENT = 7

INTERNA = 0
EXTERNA = 1
interfaces = { "cc4e 2442 550c": EXTERNA, "cc4e 2442 550d": INTERNA }

dns_count = { EXTERNA: [0, 0, 0, 0, 0, 0, 0, 0], INTERNA: [0, 0, 0, 0, 0, 0, 0, 0] }
TOTAL_REQ = 0
TOTAL_PAIRS = 1
REQ_WITHOUT_PAIR = 2
REQ_EOF = 3
TOTAL_RESP = 4
PAIRS_RESP_INTERNA = 5
PAIRS_RESP_EXTERNA = 6
RESP_WITHOUT_PAIR = 7

know_ips = {}

fin = open(filename, "r")
f_resp = open("resp_sem_req.txt", "w")

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
D_DPORT = 14
D_QUERY_ID = 15


count = 0

for line in fin:
    count+=1
    if count % 100000 == 0: print(count)

    ident = 0
    altura = 0
    if len(line) == 0: continue

    # verifica se eh a linha de header
    while line[0] == ' ' or line[0] == '\t':
        if line[0] == '\t': ident += 8
        else: ident+=1
        line =line[1:]

    altura = ident/4

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

        data = [ items[0], items[1], items[6].strip(","), val_proto, items[8].strip(","), "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0" ]
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
                ip_len = len(ip_src_a)
                if ip_len < 5: continue
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
                    data[D_DPORT] = port_dst

                    # concentra portas sem interesse na porta "0"
                    proto_port = data[D_PROTO] + ":" + port_dst

                if proto_port == "17:53": # se for dns request
                    if len(items) < 10 or (items[7] != 'A?' and items[8] != 'A?'):
                        data = []
                        continue

                    pos = 7
                    flags = items[pos]
                    if flags[0] != '[':
                        flags = ""
                        pos -= 1
                    query = items[pos+2][:-1]
                    data[D_QUERY] = query

                    if items[6][0] >= '0' and items[6][0] <= '9':
                        query_id = items[6].replace("+", "")
                        query_id = query_id.replace("%", "")
                        data[D_QUERY_ID] = query_id
                        
                        key = f"{data[D_SIP]} {data[D_SPORT]} {data[D_DIP]} {data[D_QUERY_ID]} {data[D_QUERY]}"

                        if key not in dns_match:
                            dns_match[key] = [f"{data[D_HORA]} {line.strip()}", None, None, None, None, None, None, None]
                            
                            dns_match[key][REQ_CLIENT] = site_from_ip(data[D_SIP])[0]
                            dns_match[key][REQ_DIST_TTL] = f"{data[D_DIST]}({data[D_TTL]})"
                            dns_match[key][REQUEST_TIME] = hour_to_timedelta(data[D_HORA])
                                                    
                        # query repetida
                        else:
                            print("REQ REPETIDA")

                elif (data[D_PROTO] + ":" + data[D_SPORT]) == "17:53": # dns response
                    try:
                        query_pos = items.index("A?") + 1
                        query = items[query_pos][:-1] # remove o ponto

                        data[D_QUERY] = query

                    except ValueError:
                        data = []
                        continue

                    if items[6][0] >= '0' and items[6][0] <= '9':
                        query_id = items[6].replace("*", "")
                        query_id = query_id.replace("-", "")
                        query_id = query_id.replace("|", "")
                        query_id = query_id.replace("$", "")
                        
                        data[D_QUERY_ID] = query_id

                        key = f"{data[D_DIP]} {data[D_DPORT]} {data[D_SIP]} {data[D_QUERY_ID]} {data[D_QUERY]}"

                        if key in dns_match:
                            if dns_match[key][RESPONSE] == None:

                                dns_match[key][RESPONSE] = f"{data[D_HORA]} {line.strip()}"

                                if data[D_SIP] in open_dns: dns_server_provider = f"{open_dns[data[D_SIP]]} (OPEN DNS)"
                                else: dns_server_provider = site_from_ip(data[D_SIP])[0]

                                dns_match[key][RESP_CLIENT] = dns_server_provider

                                # pega ip's da resposta
                                items = items[query_pos+1:]
                                
                                try:
                                    pos = items.index("A") + 1

                                except ValueError: # not on list
                                    pos = -1

                                while pos != -1:
                                    query_response_ip = items[pos]

                                    if query_response_ip[len(query_response_ip)-1] == ",":
                                        query_response_ip = query_response_ip[:-1] # remove a virgula
                                    
                                    #if mascara not in know_ips:
                                        #know_ips[mascara] = {}
                                    #know_ips[mascara][query_response_ip] = query
                                    know_ips[query_response_ip] = query

                                    items = items[pos+1:]

                                    try:
                                        pos = items.index("A")
                                    except ValueError: # not on list
                                        pos = -1
                        else:
                            print(f"{data[D_HORA]} {line.strip()}", file=f_resp)

    # verifica qual eh a interface
    elif altura == 2 and len(data) > 0 and len(line) > 6 and line[:6] == "0x0000":
        pos = line.find("cc4e 2442 550")

        if pos != -1:
            interface = line[pos:pos+14]

            if interface in interfaces:
                if f"{data[D_PROTO]}:{data[D_DPORT]}" == "17:53": # request
                    key = f"{data[D_SIP]} {data[D_SPORT]} {data[D_DIP]} {data[D_QUERY_ID]} {data[D_QUERY]}"
                    if key in dns_match:
                        dns_match[key][REQ_INTERFACE] = interfaces[interface]
                    else:
                        print("key error:", key)

                elif f"{data[D_PROTO]}:{data[D_SPORT]}" == "17:53": # response
                    #dns_count[interfaces[interface]][TOTAL_RESP] += 1
                    
                    key = f"{data[D_DIP]} {data[D_DPORT]} {data[D_SIP]} {data[D_QUERY_ID]} {data[D_QUERY]}"

                    if key in dns_match:
                        dns_match[key][RESP_INTERFACE] = interfaces[interface]
                    else:
                        dns_count[interfaces[interface]][TOTAL_RESP] += 1 # resposta sem par contabilizada no total
                        dns_count[interfaces[interface]][RESP_WITHOUT_PAIR] += 1 # resposta sem par

fin.close()
f_resp.close()

last_hour = hour_to_timedelta(data[D_HORA])

dns_query_pair = {} # { query: { ip_src port_src ip_dst query_id :[req, resp] } }

with open("req_sem_resp.txt", "w") as f:
    for key in dns_match:
        dns = dns_match[key]
        
        if dns[REQ_INTERFACE] == None: continue # nao eh de nennhuma das duas interfaces
        
        dns_count[dns[REQ_INTERFACE]][TOTAL_REQ] += 1
        
        if not dns_req_eof(last_hour, dns[REQUEST_TIME], delta_seconds=2): #delta-seconds = segundos restantes no arquivo
            if dns[RESPONSE] != None:
                dns_count[dns[REQ_INTERFACE]][TOTAL_PAIRS] += 1
                dns_count[dns[RESP_INTERFACE]][TOTAL_RESP] += 1 # resposta com par

                if dns[RESP_INTERFACE] == INTERNA:
                    dns_count[dns[REQ_INTERFACE]][PAIRS_RESP_INTERNA] += 1
                elif dns[RESP_INTERFACE] == EXTERNA:
                    dns_count[dns[REQ_INTERFACE]][PAIRS_RESP_EXTERNA] += 1

                    if dns[REQ_INTERFACE] == INTERNA: # req interna, resp externa
                        splited_key = key.split(" ") # key = f"{data[D_DIP]} {data[D_DPORT]} {data[D_SIP]} {data[D_QUERY_ID]} {data[D_QUERY]}"

                        query = splited_key[len(splited_key)-1]
                        key_dns_query_pair = f"{splited_key[0]} {splited_key[1]} {splited_key[2]} {splited_key[3]}"
                        
                        if query not in dns_query_pair:
                            dns_query_pair[query] = { key_dns_query_pair: (dns[REQUEST], dns[REQ_DIST_TTL], dns[REQ_CLIENT], dns[RESPONSE], dns[RESP_CLIENT]) }
                        else:
                            dns_query_pair[query][key_dns_query_pair] = (dns[REQUEST], dns[REQ_DIST_TTL], dns[REQ_CLIENT], dns[RESPONSE], dns[RESP_CLIENT])

            else:
                print(dns[REQUEST], file=f)
                dns_count[dns[REQ_INTERFACE]][REQ_WITHOUT_PAIR] += 1
        else:
            dns_count[dns[REQ_INTERFACE]][REQ_EOF] += 1

with open("pares_de_interesse.txt", "w") as f:
    req, req_dist_ttl, req_client, resp, resp_client = [x for x in range(5)]
    print("PARES DNS (REQUEST 'A' INTERFACE INTERNA, RESPONSE INTERFACE EXTERNA)\n\n", file=f)
    for query in dns_query_pair:
        print(query, file=f)

        for dns_key in dns_query_pair[query]:
            dns = dns_query_pair[query][dns_key]
            print(f"\tDNS REQUEST SRC: {dns[req_client]}| REQ DISTANCIA(TTL): {dns[req_dist_ttl]}| DNS SERVER: {dns[resp_client]}", file=f)

            print(f"\t{dns[req]}", file=f)
            print(f"\t{dns[resp]}\n", file=f)
        
        print(file=f)

with open("capture_check.txt", "w") as fout:
    #print("INTERNA", file=fout)
    print(f"QTD DE REQUEST  'A' INTERFACE INTERNA: {dns_count[INTERNA][TOTAL_REQ]}", file=fout)
    print(f"QTD DE RESPONSE 'A' INTERFACE INTERNA: {dns_count[INTERNA][TOTAL_RESP]}", file=fout)
    print(f"QTD DE REQUEST  'A' INTERFACE EXTERNA: {dns_count[EXTERNA][TOTAL_REQ]}", file=fout)
    print(f"QTD DE RESPONSE 'A' INTERFACE EXTERNA: {dns_count[EXTERNA][TOTAL_RESP]}\n\n", file=fout)

    percent = (dns_count[INTERNA][TOTAL_PAIRS]/dns_count[INTERNA][TOTAL_REQ]) * 100
    print(f"QTD DE PARES(REQUEST 'A' INTERFACE INTERNA, RESPONSE QUALQUER): {dns_count[INTERNA][TOTAL_PAIRS]} ({percent:.2f}%)", file=fout)
    percent = (dns_count[INTERNA][PAIRS_RESP_INTERNA]/dns_count[INTERNA][TOTAL_PAIRS]) * 100
    print(f"\tQTD DE PARES(REQUEST 'A' INTERFACE INTERNA, RESPONSE INTERFACE INTERNA): {dns_count[INTERNA][PAIRS_RESP_INTERNA]} ({percent:.2f}%)", file=fout)
    percent = (dns_count[INTERNA][PAIRS_RESP_EXTERNA]/dns_count[INTERNA][TOTAL_PAIRS]) * 100
    print(f"\tQTD DE PARES(REQUEST 'A' INTERFACE INTERNA, RESPONSE INTERFACE EXTERNA): {dns_count[INTERNA][PAIRS_RESP_EXTERNA]} ({percent:.2f}%)", file=fout)
    
    percent = (dns_count[INTERNA][REQ_WITHOUT_PAIR]/dns_count[INTERNA][TOTAL_REQ]) * 100
    print(f"QTD DE REQUEST 'A' INTERFACE INTERNA SEM RESPOSTA QUALQUER: {dns_count[INTERNA][REQ_WITHOUT_PAIR]} ({percent:.2f}%)", file=fout)
    
    percent = (dns_count[INTERNA][REQ_EOF]/dns_count[INTERNA][TOTAL_REQ]) * 100
    print(f"QTD DE REQUEST 'A' INTERFACE INTERNA NO FIM DO ARQUIVO: {dns_count[INTERNA][REQ_EOF]} ({percent:.2f}%)", file=fout)

    print(file=fout)

    percent = (dns_count[EXTERNA][TOTAL_PAIRS]/dns_count[EXTERNA][TOTAL_REQ]) * 100
    print(f"QTD DE PARES(REQUEST 'A' INTERFACE EXTERNA, RESPONSE QUALQUER): {dns_count[EXTERNA][TOTAL_PAIRS]} ({percent:.2f}%)", file=fout)
    percent = (dns_count[EXTERNA][PAIRS_RESP_INTERNA]/dns_count[EXTERNA][TOTAL_PAIRS]) * 100
    print(f"\tQTD DE PARES(REQUEST 'A' INTERFACE EXTERNA, RESPONSE INTERFACE INTERNA): {dns_count[EXTERNA][PAIRS_RESP_INTERNA]} ({percent:.2f}%)", file=fout)
    percent = (dns_count[EXTERNA][PAIRS_RESP_EXTERNA]/dns_count[EXTERNA][TOTAL_PAIRS]) * 100
    print(f"\tQTD DE PARES(REQUEST 'A' INTERFACE EXTERNA, RESPONSE INTERFACE EXTERNA): {dns_count[EXTERNA][PAIRS_RESP_EXTERNA]} ({percent:.2f}%)", file=fout)
    
    percent = (dns_count[EXTERNA][REQ_WITHOUT_PAIR]/dns_count[EXTERNA][TOTAL_REQ]) * 100
    print(f"QTD DE REQUEST 'A' INTERFACE EXTERNA SEM RESPOSTA QUALQUER: {dns_count[EXTERNA][REQ_WITHOUT_PAIR]} ({percent:.2f}%)", file=fout)
    
    percent = (dns_count[EXTERNA][REQ_EOF]/dns_count[EXTERNA][TOTAL_REQ]) * 100
    print(f"QTD DE REQUEST 'A' INTERFACE EXTERNA NO FIM DO ARQUIVO: {dns_count[EXTERNA][REQ_EOF]} ({percent:.2f}%)", file=fout)

    print("\n", file=fout)

    percent = (dns_count[INTERNA][RESP_WITHOUT_PAIR]/dns_count[INTERNA][TOTAL_RESP]) * 100
    print(f"QTD DE RESPONSE 'A' INTERFACE INTERNA SEM REQUEST QUALQUER: {dns_count[INTERNA][RESP_WITHOUT_PAIR]} ({percent:.2f}%)", file=fout)
    percent = (dns_count[EXTERNA][RESP_WITHOUT_PAIR]/dns_count[EXTERNA][TOTAL_RESP]) * 100
    print(f"QTD DE RESPONSE 'A' INTERFACE EXTERNA SEM REQUEST QUALQUER: {dns_count[EXTERNA][RESP_WITHOUT_PAIR]} ({percent:.2f}%)", file=fout)
    percent = ((dns_count[INTERNA][RESP_WITHOUT_PAIR] + dns_count[EXTERNA][RESP_WITHOUT_PAIR])/(dns_count[INTERNA][TOTAL_RESP] + dns_count[EXTERNA][TOTAL_RESP])) * 100
    print(f"QTD DE RESPONSE 'A' QUALQUER SEM REQUEST QUALQUER: {dns_count[INTERNA][RESP_WITHOUT_PAIR] + dns_count[EXTERNA][RESP_WITHOUT_PAIR]} ({percent:.2f}%)", file=fout)
