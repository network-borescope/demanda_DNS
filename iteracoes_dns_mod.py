from sys import argv, exit
import datetime
from ip_to_nome_lat_lon import site_from_ip

# GLOBALS

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
D_QUERY_POS = 16

# dns data positions
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

# web data positions
WEB_REQ = 0
WEB_REQ_CLIENT = 1
WEB_DIST_TTL = 2
WEB_REQ_INTERFACE = 3
WEB_REQ_DELAY = 4
WEB_DELAY_SAME_CLIENT = 5

def hour_to_timedelta(d_hora):
    hour, min, sec = d_hora.split(":")
    
    return datetime.timedelta(hours=int(hour), minutes=int(min), seconds=float(sec))

# pega query e query id do request
def request_parser(items, data):
    if len(items) < 10 or (items[7] != 'A?' and items[8] != 'A?'):
        data.clear()
        return False

    # verifica se tem flags
    pos = 7
    flags = items[pos]
    if flags[0] != '[':
        flags = ""
        pos -= 1
    query = items[pos+2][:-1] # remove o ponto do final da query
    data[D_QUERY] = query

    if items[6][0] >= '0' and items[6][0] <= '9': # assume que items[6] eh o query id
        query_id = items[6].replace("+", "")
        query_id = query_id.replace("%", "")
        data[D_QUERY_ID] = query_id
    else:
        print("#######################################", items[6])
        data.clear()
        return False
    
    return True

# pega query e query id do response
def response_parser(items, data, cnames):
    if items[6][0] >= '0' and items[6][0] <= '9':
        query_id = items[6].replace("*", "")
        query_id = query_id.replace("-", "")
        query_id = query_id.replace("|", "")
        query_id = query_id.replace("$", "")
        data[D_QUERY_ID] = query_id
    else:
        data.clear()
        return False

    n = len(items)
    i = 0
    while i < n:
        if items[i] == 'q:':
            i += 1
            if not (i < n and items[i] == "A?"):
                data.clear()
                return False

            i += 1
            data[D_QUERY] = items[i][:-1] # remove o ponto


            i += 1
            if not (i < n and items[i][0] != "0"):
                data.clear()
                return False

            i += 1
            if not (i < n): data.clear(); return False
            s = items[i][:-1] # remove o ponto
            if s != data[D_QUERY]: data.clear(); return False
            data[D_QUERY_POS] = i

            i += 1
            if not (i < n and items[i][0] == '['): data.clear(); return False

            i += 1
            if not (i < n): data.clear(); return False

            if items[i] == "A":
                return True

            data.clear()
            if items[i] == "CNAME":
                while i < n:
                    # name validade CNAME name
                    i += 1
                    if not i < n: return "CNAME"

                    cname = items[i]
                    if cname[len(cname)-1] == ",":
                        cname = cname[:-2] # remove a virgula e o ponto
                        cnames.add(cname)
                    else:
                        cname = cname[:-1] # remove o ponto
                        cnames.add(cname)
                        return "CNAME"
                    
                    i += 1 # name
                    if not i < n: return "CNAME"

                    i += 1 # validade
                    if not i < n: return "CNAME"

                    i += 1 # CNAME
                    if not (i < n and items[i] == "CNAME"): return "CNAME"
                
                return "CNAME"

            return False
        
        i += 1
    
    data.clear()
    return False

def get_response_ips(items, know_ips, data):
    # query validade A ip
    n = len(items)
    i = data[D_QUERY_POS]

 
    continua = True
    while i < n and continua:
        ignora = False
        # pega a query
        #s = items[i][:-1] # remove o ponto da query
        if i >= n: break
        if items[i][:-1] != data[D_QUERY]: ignora = True

        i += 1
        # ignora validade da resposta

        i += 1
        if i >= n: break
        if not (items[i] == 'A'): ignora = True
        
        i += 1 # posicao do ip
        if i >= n: break
        if not (items[i] >= '0' and items[i] <= '9'): ignora = True
    
        ip = items[i]
        continua = False
        if ip[-1] == ',':
            ip = ip[:-1]
            continua = True

        if not ignora: know_ips[ip] = data[D_QUERY]

        i += 1

def init_dns_data(request, duplicated_request, client_name, dns_request_dist_ttl):
    dns = [None for x in range(10)]

    dns[REQUEST] = request
    dns[DUPLICATED_REQUEST] = duplicated_request
    dns[REQUEST_CLIENT] = client_name
    dns[DNS_REQUEST_DIST_TTL] = dns_request_dist_ttl

    return dns

def init_web_data(request, duplicated_request, client_name, dns_request_dist_ttl):
    web = [None for x in range(6)]

    web[REQUEST] = request
    web[DUPLICATED_REQUEST] = duplicated_request
    web[REQUEST_CLIENT] = client_name
    web[DNS_REQUEST_DIST_TTL] = dns_request_dist_ttl

    return web

def get_response_ips0(items, know_ips, query):
    
    # verifica o contador de respostas
    if "A?" in items:
        pos = items.index("A?") + 2
        response_count = items[pos][0]
    else:
        return
    
    if response_count == "0": return

    items = items[pos:]

    # pega ip's da resposta
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

def get_interface(items):
    if len(items) < 8: return None

    if items[0] != "0x0000:": return None

    interface = f"{items[5]} {items[6]} {items[7]}"
    return interface

def main():
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
            #name, ip1, ip2 = line.split("|")
            #open_dns[ip1] = name
            #open_dns[ip2] = name

            items = line.split("|")
            name = items[0]

            for ip in items[1:]:
                open_dns[ip] = name


    INTERNA = 0
    EXTERNA = 1
    interfaces = { "cc4e 2442 550c": EXTERNA, "cc4e 2442 550d": INTERNA }

    dns_a_count = 0
    dns_a_cname_count = 0
    
    cnames = set() # cname list
    dns_match = {} # { f"{mask} {distancia} {query}": { "dst": conj dst perguntas,  f"{ip_src} {ip_dst} {query_id}": [dns_req, dns_resp], "web": primeiro acesso Web da mask} }

    know_ips = {} # {f"{mascara}": { f"ip dst": host } }

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
            data = [ items[0], items[1], items[6].strip(","), val_proto, items[8].strip(","), "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0" ]
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
                        if not request_parser(items, data): continue

                        #mascara = f"{ip_src_a[0]}.{ip_src_a[1]}.0.0/16"
                        mascara = f"{ip_src_a[0]}.0.0.0/8"

                        key = f"{data[D_QUERY]}"
                        key2 = f"{data[D_SIP]} {data[D_SPORT]} {data[D_DIP]} {data[D_QUERY_ID]}"

                        # { f"{query}": {
                        #   "dst": conj dst perguntas,
                        #   f"{ip_src} {ip_dst} {query_id}": [dns_req, dns_resp],
                        #   "web": {f"{ip_src} {ip_dst} {port_dst}": web_access},
                        #   "last_dns_response_time": hour_to_timedelta(data[D_HORA]),
                        #   "dns_response_time_per_client": {client_name: response_timedelta}
                        # }

                        ip_dns_req.add(data[D_SIP])
                        client_name = site_from_ip(data[D_SIP])[0]

                        if key not in dns_match:
                            cname = key in cnames
                            dns_match[key] = {
                                "cname": cname,
                                "dst": set(),
                                "src": set(),
                                "web": {},
                                "last_dns_response_time": None,
                                "dns_response_time_per_client": {client_name: None}, # usado para calcular o delay do acesso web daquele cliente
                                key2: init_dns_data(f"{data[D_HORA]} {line.strip()}", False, client_name, f"{data[D_DIST]}({data[D_TTL]})") }
                            # [f"{data[D_HORA]} {line.strip()}", False, client_name, None, False, None, f"{data[D_DIST]}({data[D_TTL]})", None, None, None]
                            dns_match[key]["src"].add(data[D_SIP])
                            dns_match[key]["dst"].add(data[D_DIP])
                        
                        # query repetida
                        elif len(dns_match[key]["web"]) == 0:
                            # mesma query sendo feita para outro servidor dns
                            if key2 not in dns_match[key] and data[D_DIP] not in dns_match[key]["dst"]:

                                dns_match[key][key2] = init_dns_data(f"{data[D_HORA]} {line.strip()}", False, client_name, f"{data[D_DIST]}({data[D_TTL]})")
                                dns_match[key]["src"].add(data[D_SIP])
                                dns_match[key]["dst"].add(data[D_DIP])

                            # mesma query sendo feita a um servidor DNS repetido
                            elif data[D_DIP] in dns_match[key]["dst"] and duplicated:

                                dns_match[key][key2] = init_dns_data(f"{data[D_HORA]} {line.strip()}", True, client_name, f"{data[D_DIST]}({data[D_TTL]})")

                    elif (data[D_PROTO] + ":" + data[D_SPORT]) == "17:53": # dns response
                        if response_parser(items, data, cnames) == "CNAME":
                            dns_a_count += 1
                            dns_a_cname_count += 1

                        elif len(data) > 0:
                            dns_a_count += 1

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
                                        
                                        response_timedelta = hour_to_timedelta(data[D_HORA])
                                        req_client_name = dns_match[key][key2][REQUEST_CLIENT]
                                        dns_match[key]["dns_response_time_per_client"][req_client_name] = response_timedelta

                                        dns_statistic[TOTAL_PAIRS] += 1 # total de pares pergunta e resposta

                                        for error in ["NXDomain", "Refused"]:
                                            if error in items[7]:
                                                dns_match[key][key2][RESPONSE_ERROR] = True

                                                dns_statistic[TOTAL_PAIRS_WITH_ERROR] += 1 # total de pares pergunta e resposta com erro

                                        if dns_match[key][key2][DUPLICATED_REQUEST]: # eh duplicado

                                            dns_statistic[TOTAL_PAIRS_DUPLICATED] += 1 # total de pares pergunta e resposta que sao duplicados
                                            
                                            if duplicated != None:
                                                dns_match[key]["last_dns_response_time"] = response_timedelta

                                                get_response_ips(items, know_ips, data)
                                        else:
                                            dns_match[key]["last_dns_response_time"] = response_timedelta

                                            get_response_ips(items, know_ips, data)

                    elif proto_port == "6:80" or proto_port == "6:443": # http ou https
                        query = None

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
                            web_access_time = hour_to_timedelta(data[D_HORA])
                            delta_time = web_access_time - dns_match[key]["last_dns_response_time"]
                            delay = None
                            delay_same_client = None

                            line = line.strip()
                            pos = line.find(":") + 1

                            formated_line = f"{line[:pos]} Delta {delta_time} {line[pos:]}"

                            # calcula delay
                            if client_name in dns_match[key]["dns_response_time_per_client"] and dns_match[key]["dns_response_time_per_client"][client_name]:
                                response_timedelta = dns_match[key]["dns_response_time_per_client"][client_name]
                                delay = web_access_time - response_timedelta

                                delay_same_client = True
                            else:
                                delay = delta_time
                            
                            timedelta_sec = datetime.timedelta(seconds=0.1)
                            if delay < timedelta_sec: delay = "0"
                            else: delay = delay.total_seconds()

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
                                    # WEB_REQ = 0 WEB_REQ_CLIENT = 1 WEB_DIST_TTL = 2 WEB_REQ_INTERFACE = 3 WEB_REQ_DELAY = 4
                                    dns_match[key]["web"] = { web_key: [f"{formated_line}", client_name, f"{data[D_DIST]}({data[D_TTL]})", None, delay, delay_same_client] }
                                    
                            
                            elif web_key not in dns_match[key]["web"]:
                                dns_match[key]["web"][web_key] = [f"{formated_line}", client_name, f"{data[D_DIST]}({data[D_TTL]})", None, delay, delay_same_client]

        elif altura == 2 and len(data) > 0:
            items = line.strip().split(" ")
            interface = get_interface(items)

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

    # { f"{query}": {
    #   "dst": conj dst perguntas,
    #   f"{ip_src} {ip_dst} {query_id}": [dns_req, dns_resp],
    #   "web": {f"{ip_src} {ip_dst} {port_dst}": web_access},
    #   "last_dns_response_time": hour_to_timedelta(data[D_HORA]),
    #   "dns_response_time_per_client": {client_name: response_timedelta}
    # }

    with open(f"output{output_n}.txt", "w") as fout:
        print("AGRUPADO POR HOST PERGUNTADO NO DNS REQUEST E ACESSADO PELO WEB", file=fout)
        print("PARES DNS(REQUEST 'A' INTERFACE INTERNA, RESPONSE INTERFACE EXTERNA) antes do primeiro acesso web", file=fout)
        print("Primeiros REQUESTS WEB\n\n", file=fout)
        
        print(f"QTD RESPOSTAS DNS PARA REQUESTS 'A': {dns_a_count}", file=fout)
        print(f"QTD RESPOSTAS DNS CNAME PARA REQUESTS 'A': {dns_a_cname_count}\n\n", file=fout)

        for key in dns_match:
            cname = dns_match[key]["cname"]
            del dns_match[key]["cname"]
            del dns_match[key]["src"]
            del dns_match[key]["dst"]
            del dns_match[key]["last_dns_response_time"]
            del dns_match[key]["dns_response_time_per_client"]

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
                    if cname: fout.write(f"HOST: {key}(CNAME)\n")
                    else: fout.write(f"HOST: {key}\n")

                    for dns in match:
                        fout.write(f"\tDNS REQUEST SRC: {dns[REQUEST_CLIENT]}| REQ DISTANCIA(TTL): {dns[DNS_REQUEST_DIST_TTL]}| DNS SERVER: {dns[RESPONSE_CLIENT]}\n")
                        fout.write(f"\t{dns[REQUEST]}\n")
                        fout.write(f"\t{dns[RESPONSE]}\n\n")
                    
                    for k, web_access in web.items():
                        if web_access[WEB_DELAY_SAME_CLIENT] is None:
                            fout.write(f"\tWEB REQUEST SRC: {web_access[WEB_REQ_CLIENT]}| DISTANCIA(TTL): {web_access[WEB_DIST_TTL]}| DELAY: \"{web_access[WEB_REQ_DELAY]}s\"\n")
                        else:
                            fout.write(f"\tWEB REQUEST SRC: {web_access[WEB_REQ_CLIENT]}| DISTANCIA(TTL): {web_access[WEB_DIST_TTL]}| DELAY: {web_access[WEB_REQ_DELAY]}s\n")
                        fout.write(f"\t{web_access[WEB_REQ]}\n\n")
                    fout.write(f"\n\n")

if __name__ == '__main__':
    main()