from sys import argv, exit
import datetime
from ip_to_nome_lat_lon import site_from_ip

def hour_to_timedelta(d_hora):
    hour, min, sec = d_hora.split(":")
    
    return datetime.timedelta(hours=int(hour), minutes=int(min), seconds=float(sec))

def get_response_ips(items, know_ips, query):
    # pega ip's da resposta
    #items = items[query_pos+1:]

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
            pos = items.index("A") + 1
        except ValueError: # not on list
            pos = -1


duplicated = None
arguments = argv[1:]

if len(arguments) == 2:
    filename, output_n = arguments
elif len(arguments) == 3:
    if arguments[1] == "-d":
        filename, duplicated, output_n = arguments
    else:
        exit(1)
else:
    exit(1)

open_dns = {}
with open("open_dns_list.txt", "r") as f:
    for line in f:
        line = line.strip()
        name, ip1, ip2 = line.split("|")

        open_dns[ip1] = name
        open_dns[ip2] = name

INTERNA = 0
EXTERNA = 1
interfaces = { "cc4e 2442 550c": EXTERNA, "cc4e 2442 550d": INTERNA }

dns_match = {} # { f"{mask} {distancia} {query}": { "dst": conj dst perguntas,  f"{ip_src} {ip_dst} {query_id}": [dns_req, dns_resp], "web": primeiro acesso Web da mask} }

know_ips = {} # {f"{mascara}": { f"ip dst": host } }

REQUEST = 0
DUPLICATED_REQUEST = 1
REQUEST_CLIENT = 2 # cliente Name
RESPONSE = 3
RESPONSE_ERROR = 4
RESPONSE_CLIENT = 5
DNS_REQUEST_DIST_TTL = 6
DNS_RESPONSE_DIST_TTL = 7
REQ_INTERFACE = 8
RESP_INTERFACE = 9

WEB_REQ = 0
WEB_REQ_CLIENT = 1
WEB_DIST_TTL = 2
WEB_REQ_INTERFACE = 3

dns_statistic = [0, 0, 0, 0, 0, 0]
### Estatistica Geral ###
TOTAL_PAIRS = 0
TOTAL_PAIRS_WITH_ERROR = 1
TOTAL_PAIRS_DUPLICATED = 2

### Estatistica Burst ###
QUERY_SEQUENCE = 3
QUERY_NON_SEQUENCE = 4
QUERY_ERROR_PAIRS = 5 # Refused, NXDomain

ip_dns_req_web = set() # conjunto de ips que fazem req DNS e acesso Web
ip_dns_req = set() # lista de ips que fazem req DNS
ip_web = set() # lista de ips que fazem acesso web

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
D_DPORT = 14
D_QUERY_ID = 15


count = 0
#f_dns = open("dns_responses.txt", "w")
for line in fin:
    count+=1
    if count % 1000000 == 0: print(count)

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

                        #mascara = f"{ip_src_a[0]}.{ip_src_a[1]}.0.0/16"
                        mascara = f"{ip_src_a[0]}.0.0.0/8"

                        key = f"{data[D_QUERY]}"
                        key2 = f"{data[D_SIP]} {data[D_SPORT]} {data[D_DIP]} {data[D_QUERY_ID]}"

                        # { f"{query}": {
                        #   "dst": conj dst perguntas,
                        #   f"{ip_src} {ip_dst} {query_id}": [dns_req, dns_resp],
                        #   "web": {f"{ip_src}{ip_dst}{port_dst}": web_access},
                        #   "last_dns_response_time": hour_to_timedelta(data[D_HORA])
                        # }

                        ip_dns_req.add(data[D_SIP])
                        client_name = site_from_ip(data[D_SIP])[0]

                        if key not in dns_match:
                            dns_match[key] = {
                                "dst": set(),
                                "web": {},
                                "last_dns_response_time": None,
                                key2: [f"{data[D_HORA]} {line.strip()}", False, client_name, None, False, None, f"{data[D_DIST]}({data[D_TTL]})", None, None, None] }
                            
                            dns_match[key]["dst"].add(data[D_DIP])
                        
                        # query repetida
                        elif len(dns_match[key]["web"]) == 0:
                            
                            # mesma query para outro servidor DNS
                            if key2 not in dns_match[key] and data[D_DIP] not in dns_match[key]["dst"]:
                                dns_match[key][key2] = [f"{data[D_HORA]} {line.strip()}", False, client_name, None, False, None, f"{data[D_DIST]}({data[D_TTL]})", None, None, None]

                                dns_match[key]["dst"].add(data[D_DIP])

                            # mesma query sendo feita a um servidor DNS repetido
                            elif data[D_DIP] in dns_match[key]["dst"]:
                                dns_match[key][key2] = [f"{data[D_HORA]} {line.strip()}", True, client_name, None, False, None, f"{data[D_DIST]}({data[D_TTL]})", None, None, None] # req, duplicated_request?, req_src, response, response_error?, resp_src

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

                        #mascara = f"{ip_dst_a[0]}.{ip_dst_a[1]}.0.0/16" # mascara de quem fez a requisicao
                        mascara = f"{ip_dst_a[0]}.0.0.0/8"

                        key = f"{data[D_QUERY]}"
                        key2 = f"{data[D_DIP]} {data[D_DPORT]} {data[D_SIP]} {data[D_QUERY_ID]}"

                        if key in dns_match:
                            # response == None para pegar apenas a primeira resposta
                            # len(web) == 0 para pegar apenas iteracoes antes do primeiro acesso

                            if key2 in dns_match[key]:
                                if dns_match[key][key2][RESPONSE] == None:

                                    if data[D_SIP] in open_dns: client_name = f"{open_dns[data[D_SIP]]} (OPEN DNS)"
                                    else: client_name = site_from_ip(data[D_SIP])[0]

                                    dns_match[key][key2][RESPONSE] = f"{data[D_HORA]} {line.strip()}"
                                    dns_match[key][key2][RESPONSE_CLIENT] = client_name
                                    dns_match[key][key2][DNS_RESPONSE_DIST_TTL] = f"{data[D_DIST]}({data[D_TTL]})"

                                    dns_statistic[TOTAL_PAIRS] += 1 # total de pares pergunta e resposta

                                    for error in ["NXDomain", "Refused"]:
                                        if error in items[7]:
                                            dns_match[key][key2][RESPONSE_ERROR] = True

                                            dns_statistic[TOTAL_PAIRS_WITH_ERROR] += 1 # total de pares pergunta e resposta com erro

                                    items = items[query_pos+1:]

                                    if dns_match[key][key2][DUPLICATED_REQUEST]: # eh duplicado

                                        dns_statistic[TOTAL_PAIRS_DUPLICATED] += 1 # total de pares pergunta e resposta que sao duplicados
                                        dns_statistic[QUERY_NON_SEQUENCE] += 1 # total de pares pergunta e resposta que nao fazem parte de um Burst
                                        
                                        if duplicated != None:
                                            dns_match[key]["last_dns_response_time"] = hour_to_timedelta(data[D_HORA])
                                            get_response_ips(items, know_ips, data[D_QUERY])
                                    else:
                                        dns_match[key]["last_dns_response_time"] = hour_to_timedelta(data[D_HORA])
                                        get_response_ips(items, know_ips, data[D_QUERY])
                                    
                                    # pega ip's da resposta
                                    '''
                                    items = items[query_pos+1:]
                                    #print(f"{data[D_HORA]} {line.strip()}\n\t{data[D_QUERY]}", file=f_dns)
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
                                        #print(f"\t{query_response_ip}", file=f_dns)


                                        items = items[pos+1:]

                                        try:
                                            pos = items.index("A") + 1
                                        except ValueError: # not on list
                                            pos = -1
                                    '''

                elif proto_port == "6:80" or proto_port == "6:443": # http ou https
                    #mascara = f"{ip_src_a[0]}.{ip_src_a[1]}.0.0/16"
                    mascara = f"{ip_src_a[0]}.0.0.0/8"

                    query = None
                    #if mascara in know_ips and data[D_DIP] in know_ips[mascara]:
                        #query = know_ips[mascara][data[D_DIP]]
                    if data[D_DIP] in know_ips:
                        query = know_ips[data[D_DIP]]
                        data[D_QUERY] = query
                    else:
                        data = []
                        continue

                    key = f"{data[D_QUERY]}"
                    web_key = f"{data[D_SIP]} {data[D_DIP]} {data[D_DPORT]}"

                    if key in dns_match:
                        client_name = site_from_ip(data[D_SIP])[0]
                        delta_time = hour_to_timedelta(data[D_HORA]) - dns_match[key]["last_dns_response_time"]

                        if len(dns_match[key]["web"]) == 0:
                            # antes de aceitar verifica se ha uma resposta
                            accept_web = False
                            for key2 in dns_match[key]:
                                item = dns_match[key][key2]

                                if isinstance(item, list):
                                    if item[RESPONSE] != None:
                                        accept_web = True
                                        break
                            
                            if accept_web:
                                # WEB_REQ = 0 WEB_REQ_CLIENT = 1 WEB_DIST_TTL = 2 WEB_REQ_INTERFACE = 3
                                #dns_match[key]["web"] = { web_key: [f"{data[D_HORA]} {line.strip()}", client_name, f"{data[D_DIST]}({data[D_TTL]})", None] }
                                dns_match[key]["web"] = { web_key: [f"{delta_time} {line.strip()}", client_name, f"{data[D_DIST]}({data[D_TTL]})", None] }
                                
                        
                        elif web_key not in dns_match[key]["web"]:
                            #dns_match[key]["web"][web_key] = [f"{data[D_HORA]} {line.strip()}", client_name, f"{data[D_DIST]}({data[D_TTL]})", None]
                            dns_match[key]["web"][web_key] = [f"{delta_time} {line.strip()}", client_name, f"{data[D_DIST]}({data[D_TTL]})", None]

    elif altura == 2 and len(data) > 0 and len(line) > 6 and line[:6] == "0x0000":
        pos = line.find("cc4e 2442 550")

        if pos != -1:
            interface = line[pos:pos+14]

            if interface in interfaces:
                key1 = data[D_QUERY]
                
                if f"{data[D_PROTO]}:{data[D_DPORT]}" == "17:53": # request
                    key2 = f"{data[D_SIP]} {data[D_SPORT]} {data[D_DIP]} {data[D_QUERY_ID]}"

                    if key1 in dns_match and key2 in dns_match[key1]:
                        dns_match[key1][key2][REQ_INTERFACE] = interfaces[interface]
                    else:
                        #print("key error:", f"Query: {key} key2: {key2}")
                        continue

                elif f"{data[D_PROTO]}:{data[D_SPORT]}" == "17:53": # response
                    key2 = f"{data[D_DIP]} {data[D_DPORT]} {data[D_SIP]} {data[D_QUERY_ID]}"

                    if key1 in dns_match and key2 in dns_match[key1]:
                        dns_match[key1][key2][RESP_INTERFACE] = interfaces[interface]

                elif f"{data[D_PROTO]}:{data[D_DPORT]}" in ["6:80", "6:443"]:
                    web_key = f"{data[D_SIP]} {data[D_DIP]} {data[D_DPORT]}"

                    if key1 in dns_match and web_key in dns_match[key1]["web"]:
                        dns_match[key1]["web"][web_key][WEB_REQ_INTERFACE] = interfaces[interface]

fin.close()
#f_dns.close()

def get_ip_dst(line):
    items = line.split(" ")

    pos_port = items[3].rfind(".")
    return items[3][:pos_port]


# { f"{mask} {distancia} {query}": {
#   "dst": conj dst perguntas,
#   f"{ip_src} {ip_dst} {query_id}": [dns_req, dns_resp],
#   "web": primeiro acesso Web da mask
#   "last_dns_response_time": hour_to_timedelta(data[D_HORA])
# }

with open(f"output{output_n}.txt", "w") as fout:
    print("AGRUPADO POR HOST PERGUNTADO NO DNS REQUEST E ACESSADO PELO WEB", file=fout)
    print("PARES DNS(REQUEST 'A' INTERFACE INTERNA, RESPONSE INTERFACE EXTERNA) antes do primeiro acesso web", file=fout)
    print("Primeiros REQUESTS WEB\n\n", file=fout)

    for key in dns_match:
        del dns_match[key]["dst"]
        del dns_match[key]["last_dns_response_time"]

        web = dns_match[key]["web"]
        del dns_match[key]["web"]

        web_to_be_removed = []
        for k, web_access in web.items():
            if web_access[WEB_REQ_INTERFACE] != INTERNA:
                web_to_be_removed.append(k)
        
        for k in web_to_be_removed:
            del web[k]

        if len(web) > 0: # houve acesso web(REQ INTERFACE INTERNA)
            match = []

            for key2 in dns_match[key]:
                dns_pair = dns_match[key][key2]

                if dns_pair[RESPONSE] != None and (duplicated != None or not dns_pair[DUPLICATED_REQUEST]):
                    if dns_pair[REQ_INTERFACE] == INTERNA and dns_pair[RESP_INTERFACE] == EXTERNA: # req interna, resp externa
                        match.append(dns_pair)
            
            if len(match) > 0:
                fout.write(f"HOST: {key}\n")
                for dns in match:
                    fout.write(f"\tDNS REQUEST SRC: {dns[REQUEST_CLIENT]}| REQ DISTANCIA(TTL): {dns[DNS_REQUEST_DIST_TTL]}| DNS SERVER: {dns[RESPONSE_CLIENT]}\n")
                    fout.write(f"\t{dns[REQUEST]}\n")
                    fout.write(f"\t{dns[RESPONSE]}\n\n")
                
                for k, web_access in web.items():
                    fout.write(f"\tWEB REQUEST SRC: {web_access[WEB_REQ_CLIENT]}| DISTANCIA(TTL): {web_access[WEB_DIST_TTL]}\n")
                    fout.write(f"\t{web_access[WEB_REQ]}\n\n")
                fout.write(f"\n\n")
