from sys import argv, exit
import datetime
from ip_to_nome_lat_lon import site_from_ip

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

dns_match = {} # { f"{mask} {distancia} {query}": { "dst": conj dst perguntas,  f"{ip_src} {ip_dst} {query_id}": [dns_req, dns_resp], "web": primeiro acesso Web da mask} }

know_ips = {} # {f"{mascara}": { f"ip dst": host } }

REQUEST = 0
DUPLICATED_REQUEST = 1
REQUEST_CLIENT = 2 # cliente Name
RESPONSE = 3
RESPONSE_ERROR = 4
RESPONSE_CLIENT = 5

ip_query = {} # f"{ip src}{ip dst}" -> query

ip_query_only_dst = {} # f"{ip dst}" -> query

dns_duplicated = {} # {"ip_src query": { f"{query_id}{ip_dst}": resp } }

### Estatistica Geral ###
TOTAL_PAIRS = 0
TOTAL_PAIRS_WITH_ERROR = 1
TOTAL_PAIRS_DUPLICATED = 2

### Estatistica Burst ###
QUERY_SEQUENCE = 3
QUERY_NON_SEQUENCE = 4
QUERY_ERROR_PAIRS = 5 # Refused, NXDomain
dns_statistic = [0, 0, 0, 0, 0, 0]

total_web = {} # {f"{ip src}{ip dst}{dst}{host}": host;line}

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

                    pos = 7
                    flags = items[pos]
                    if flags[0] != '[':
                        flags = ""
                        pos -= 1
                    query = items[pos+2][:-1]

                    if items[6][0] >= '0' and items[6][0] <= '9':
                        query_id = items[6].replace("+", "")
                        query_id = query_id.replace("%", "")

                        #mascara = f"{ip_src_a[0]}.{ip_src_a[1]}.0.0/16"
                        mascara = f"{ip_src_a[0]}.0.0.0/8"

                        #key = f"{mascara} {data[D_DIST]} {query}"
                        #key = f"{mascara} {query}"
                        key = f"{query}"
                        key2 = f"{data[D_SIP]} {data[D_DIP]} {query_id}"

                        # { f"{mask} {distancia} {query}": {
                        #   "dst": conj dst perguntas,
                        #   f"{ip_src} {ip_dst} {query_id}": [dns_req, dns_resp],
                        #   "web": primeiro acesso Web da mask
                        # }

                        ip_dns_req.add(data[D_SIP])
                        client_name = site_from_ip(data[D_SIP])[0]

                        if key not in dns_match:
                            dns_match[key] = { "dst": set(), "web": None, key2: [f"{data[D_HORA]} {line.strip()}", False, client_name, None, False, None] }
                            
                            dns_match[key]["dst"].add(data[D_DIP])
                        
                        # query repetida
                        elif dns_match[key]["web"] == None:
                            
                            # mesma query para outro servidor DNS
                            if key2 not in dns_match[key] and data[D_DIP] not in dns_match[key]["dst"]:
                                dns_match[key][key2] = [f"{data[D_HORA]} {line.strip()}", False, client_name, None, False, None]

                                dns_match[key]["dst"].add(data[D_DIP])

                            # mesma query sendo feita a um servidor DNS repetido
                            elif data[D_DIP] in dns_match[key]["dst"]:
                                dns_match[key][key2] = [f"{data[D_HORA]} {line.strip()}", True, client_name, None, False, None] # req, duplicated_request?, req_src, response, response_error?, resp_src

                elif (data[D_PROTO] + ":" + data[D_SPORT]) == "17:53": # dns response
                    try:
                        query_pos = items.index("A?") + 1
                        query = items[query_pos][:-1] # remove o ponto

                    except ValueError:
                            continue

                    if items[6][0] >= '0' and items[6][0] <= '9':
                        query_id = items[6].replace("*", "")
                        query_id = query_id.replace("-", "")
                        query_id = query_id.replace("|", "")
                        query_id = query_id.replace("$", "")

                        #mascara = f"{ip_dst_a[0]}.{ip_dst_a[1]}.0.0/16" # mascara de quem fez a requisicao
                        mascara = f"{ip_dst_a[0]}.0.0.0/8"

                        #key = f"{mascara} {data[D_DIST]} {query}"
                        #key = f"{mascara} {query}"
                        key = f"{query}"
                        key2 = f"{data[D_DIP]} {data[D_SIP]} {query_id}"

                        if key in dns_match:
                            # response == None para pegar apenas a primeira resposta
                            # web == None para pegar apenas iteracoes antes do primeiro acesso

                            if key2 in dns_match[key]:
                                if dns_match[key][key2][RESPONSE] == None:

                                    if data[D_SIP] in open_dns: client_name = f"{open_dns[data[D_SIP]]} (OPEN DNS)"
                                    else: client_name = site_from_ip(data[D_SIP])[0]

                                    dns_match[key][key2][RESPONSE] = f"{data[D_HORA]} {line.strip()}"
                                    dns_match[key][key2][RESPONSE_CLIENT] = client_name

                                    dns_statistic[TOTAL_PAIRS] += 1 # total de pares pergunta e resposta

                                    for error in ["NXDomain", "Refused"]:
                                        if error in items[7]:
                                            dns_match[key][key2][RESPONSE_ERROR] = True

                                            dns_statistic[TOTAL_PAIRS_WITH_ERROR] += 1 # total de pares pergunta e resposta com erro

                                    if dns_match[key][key2][DUPLICATED_REQUEST]: # eh duplicado

                                        dns_statistic[TOTAL_PAIRS_DUPLICATED] += 1 # total de pares pergunta e resposta que sao duplicados
                                        dns_statistic[QUERY_NON_SEQUENCE] += 1 # total de pares pergunta e resposta que nao fazem parte de um Burst
                                    

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

                elif proto_port == "6:80" or proto_port == "6:443": # http ou https
                    #mascara = f"{ip_src_a[0]}.{ip_src_a[1]}.0.0/16"
                    mascara = f"{ip_src_a[0]}.0.0.0/8"

                    query = None
                    #if mascara in know_ips and data[D_DIP] in know_ips[mascara]:
                        #query = know_ips[mascara][data[D_DIP]]
                    if data[D_DIP] in know_ips:
                        query = know_ips[data[D_DIP]]
                    else: continue

                    #key = f"{mascara} {data[D_DIST]} {query}"
                    #key = f"{mascara} {query}"
                    key = f"{query}"
                    #key2 = f"{data[D_SIP]} {data[D_DIP]} {query_id}"

                    if key in dns_match:
                        if dns_match[key]["web"] == None:

                            # antes de aceitar verifica se ha uma resposta
                            accept_web = False
                            for key2 in dns_match[key]:
                                item = dns_match[key][key2]

                                if isinstance(item, list):
                                    if item[RESPONSE] != None:
                                        accept_web = True
                                        break
                            
                            if accept_web:
                                dns_match[key]["web"] = f"{data[D_HORA]} {line.strip()}"

'''
                elif proto_port == "6:443": # https
                    #ip_web.add(data[D_SIP]) # ip fez acesso web

                    key = f"{data[D_SIP]} {data[D_DIST]}"

                    #if key in dns_match and data[D_DIP] in ip_query:
                    if key in dns_match and f"{data[D_SIP]}{data[D_DIP]}" in ip_query:
                        #key2 = ip_query[data[D_DIP]]
                        key2 = ip_query[f"{data[D_SIP]}{data[D_DIP]}"] # pega a query

                        if key2 in dns_match[key]:
                            ip_dns_req_web.add(data[D_SIP]) # o ip fez req DNS e acesso Web

                            # antes de aceitar verifica se ha uma resposta
                            accept_web = False
                            for item in dns_match[key][key2]:

                                if isinstance(dns_match[key][key2][item], list):
                                    if item[RESPONSE] != None:
                                        accept_web = True
                                        break

                            if accept_web and dns_match[key][key2]["web"] == None:
                                dns_match[key][key2]["web"] = f"{data[D_HORA]} {line.strip()}"
                    
                    # total web
                    if data[D_DIP] in ip_query_only_dst:
                        #print("aqui")
                        query = ip_query_only_dst[data[D_DIP]]

                        if f"{data[D_SIP]}{data[D_DIP]}{data[D_DIST]}{query}" not in total_web:
                                total_web[f"{data[D_SIP]}{data[D_DIP]}{data[D_DIST]}{query}"] = f" {query};{line.strip()}"


    elif altura == 2: # corpo do http
        if len(data) == 0: continue

        items = line.strip().split(" ")
        if len(items) < 2: continue

        if items[0] == "Host:": data[D_HOST] = items[1]
        elif items[0] == "User-Agent:": data[D_US_AG] = items[1]

        if data[D_HOST] != "0" and data[D_US_AG] != "0":
            ip_web.add(data[D_SIP]) # ip fez acesso web

            key = f"{data[D_SIP]} {data[D_DIST]}"
            #key2 = f"{data[D_HOST]}" # query

            line = "ip src:"+data[D_SIP]+"|ip dst:"+data[D_DIP]+"|ttl:"+data[D_TTL]+"("+ data[D_DIST] +")"+"|porta src:"+data[D_SPORT]+"|ip-id:"+data[D_IP_ID]+"|user-agent:"+data[D_US_AG]

            if f"{data[D_SIP]}{data[D_DIP]}" in ip_query:
                key2 = ip_query[f"{data[D_SIP]}{data[D_DIP]}"] # pega a query
            else:
                continue

            if f"{data[D_SIP]}{data[D_DIP]}{data[D_DIST]}{data[D_HOST]}" not in total_web:
                total_web[f"{data[D_SIP]}{data[D_DIP]}{data[D_DIST]}{data[D_HOST]}"] = f"{data[D_HOST]};{line}"

            if key in dns_match and key2 in dns_match[key]:
                ip_dns_req_web.add(data[D_SIP]) # o ip fez req DNS e acesso Web

                # antes de aceitar verifica se ha uma resposta
                accept_web = False
                for item in dns_match[key][key2]:

                    if isinstance(dns_match[key][key2][item], list):
                        if item[RESPONSE] != None:
                            accept_web = True
                            break

                if accept_web and dns_match[key][key2]["web"] == None:
                    dns_match[key][key2]["web"] = f"{data[D_HORA]} {line.strip()}"
'''

fin.close()

def get_ip_dst(line):
    items = line.split(" ")

    pos_port = items[3].rfind(".")
    return items[3][:pos_port]


# { f"{mask} {distancia} {query}": {
#   "dst": conj dst perguntas,
#   f"{ip_src} {ip_dst} {query_id}": [dns_req, dns_resp],
#   "web": primeiro acesso Web da mask
# }

with open(f"output{output_n}.txt", "w") as fout:
    for key in dns_match:
        del dns_match[key]["dst"]

        web = dns_match[key]["web"]

        if web != None:
            match = []

            for key2 in dns_match[key]:
                dns_pair = dns_match[key][key2]

                if dns_pair[RESPONSE] != None and not dns_pair[DUPLICATED_REQUEST]:
                    match.append(dns_pair)
            
            if len(match) > 1:
                #splited_key = key.split(" ")
                #fout.write(f"IP RANGE:{splited_key[0]}| DIST: {splited_key[1]}| HOST: {splited_key[2]}\n")
                #fout.write(f"IP RANGE:{splited_key[0]}| HOST: {splited_key[1]}\n")
                fout.write(f"HOST: {key}\n")
                for dns in match:
                    fout.write(f"\tREQUEST SRC: {dns[REQUEST_CLIENT]}| DNS SERVER: {dns[RESPONSE_CLIENT]}\n")
                    fout.write(f"\t{dns[REQUEST]}\n")
                    fout.write(f"\t{dns[RESPONSE]}\n\n")
                
                fout.write(f"\tWEB: {web}\n\n")
