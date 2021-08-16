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
DNS_DIGEST = 8
DNS_FLAGS = 9

# web data positions
WEB_REQ = 0
WEB_REQ_CLIENT = 1
WEB_DIST_TTL = 2
WEB_NEW_FORMAT = 3

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
            #if items[i] == "CNAME": return "CNAME"
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


def init_dns_data(data, is_open_dns, query_id, client_id):
    dns = [None for x in range(10)]

    dns[REQUEST] = True
    dns[DNS_FLAGS] = ["0" for x in range(6)]

    if ('+' in query_id): dns[DNS_FLAGS][0] = "1"
    if ('%' in query_id): dns[DNS_FLAGS][1] = "1"

    ip_dst = "0"
    if is_open_dns: ip_dst = data[D_DIP]

    hour = data[D_HORA].split(":")[0]
    dns[DNS_DIGEST] = f"{data[D_DATA]},{date_to_day(data[D_DATA])},{hour},{client_id},{data[D_SIP]},{data[D_DIST]},{data[D_TTL]},{ip_dst},{data[D_IP_ID]}"

    return dns

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

def get_client_name_and_id(ip):
    result = site_from_ip(ip)
    client_name = result[0]
    client_id = result[6]

    return client_name, client_id

def date_to_day(d_data):
    year, month, day = d_data.split("-")
    day = datetime.datetime(year=int(year), month=int(month), day=int(day)).weekday()

    #day_of_week = {0: "Segunda", 1: "Terca", 2: "Quarta", 3: "Quinta", 4: "Sexta", 5: "Sabado", 6: "Domingo"}

    return str((day+1 % 7)+1)

def main():
    duplicated = None
    arguments = argv[1:]

    if len(arguments) == 2:
        filename, output_n = arguments
    else:
        exit(1)

    open_dns = {}
    with open("open_dns_list.txt", "r") as f:
        for line in f:
            line = line.strip()

            items = line.split("|")
            name = items[0]

            for ip in items[1:]:
                open_dns[ip] = name

    services = {"53": "DNS", "80": "HTTP", "443": "HTTP", "25": "SMTP", "587": "SMTP", "465": "SMTP", "110": "POP3", "995": "POP3", "143": "IMAP", "20": "FTP", "21": "FTP", "22": "SSH"}

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

    ip_dns_req = set() # lista de ips que fazem req DNS

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

                        ip_dns_req.add(data[D_SIP])
                        client_name, client_id = get_client_name_and_id(data[D_SIP])

                        key = f"{client_name} {data[D_QUERY]}"
                        key2 = f"{data[D_SIP]} {data[D_SPORT]} {data[D_DIP]} {data[D_QUERY_ID]}"

                        # { f"{client_id} {data[D_QUERY]}": {
                        #   "dst": conj dst perguntas,
                        #   f"{data[D_SIP]} {data[D_SPORT]} {data[D_DIP]} {data[D_QUERY_ID]}": [dns_req, dns_resp],
                        #   "web": { f"{ip_src} {ip_dst} {port_dst}": web_access},
                        #   "last_dns_response_time": hour_to_timedelta(data[D_HORA])
                        # }


                        if key not in dns_match:
                            cname = data[D_QUERY] in cnames
                            dns_match[key] = {
                                "cname": cname,
                                "dst": set(),
                                "src": set(),
                                "web": {},
                                "last_dns_response_time": None,
                                key2: init_dns_data(data, data[D_DIP] in open_dns, items[6], client_id) }
                            

                            dns_match[key]["src"].add(data[D_SIP])
                            dns_match[key]["dst"].add(data[D_DIP])
                        
                        # cliente e query repetidos
                        elif len(dns_match[key]["web"]) == 0:
                            # mesma query sendo feita pelo mesmo cliente para outro servidor dns
                            if key2 not in dns_match[key] and data[D_DIP] not in dns_match[key]["dst"]:

                                dns_match[key][key2] = init_dns_data(data, data[D_DIP] in open_dns, items[6], client_id)
                                dns_match[key]["src"].add(data[D_SIP])
                                dns_match[key]["dst"].add(data[D_DIP])

                    elif (data[D_PROTO] + ":" + data[D_SPORT]) == "17:53": # dns response
                        if response_parser(items, data, cnames) == "CNAME":
                            dns_a_count += 1
                            dns_a_cname_count += 1

                        elif len(data) > 0:
                            dns_a_count += 1

                            client_name, client_id = get_client_name_and_id(data[D_DIP])

                            key = f"{client_name} {data[D_QUERY]}"
                            key2 = f"{data[D_DIP]} {data[D_DPORT]} {data[D_SIP]} {data[D_QUERY_ID]}"

                            if key in dns_match:
                                # response == None para pegar apenas a primeira resposta
                                # len(web) == 0 para pegar apenas iteracoes antes do primeiro acesso

                                if key2 in dns_match[key]:
                                    if dns_match[key][key2][RESPONSE] == None:

                                        dns_match[key][key2][RESPONSE] = True
                                        dns_match[key][key2][DNS_RESPONSE_DIST_TTL] = f"{data[D_DIST]}({data[D_TTL]})"

                                        if '*' in items[6]: dns_match[key][key2][DNS_FLAGS][2] = "1"
                                        if '-' in items[6]: dns_match[key][key2][DNS_FLAGS][3] = "1"
                                        if '|' in items[6]: dns_match[key][key2][DNS_FLAGS][4] = "1"
                                        if '$' in items[6]: dns_match[key][key2][DNS_FLAGS][5] = "1"

                                        #if items[6]: dns_match[key][key2]
                                        
                                        response_timedelta = hour_to_timedelta(data[D_HORA])

                                        dns_statistic[TOTAL_PAIRS] += 1 # total de pares pergunta e resposta

                                        for error in ["NXDomain", "Refused"]:
                                            if error in items[7]:
                                                dns_match[key][key2][RESPONSE_ERROR] = True

                                                dns_statistic[TOTAL_PAIRS_WITH_ERROR] += 1 # total de pares pergunta e resposta com erro
                                        
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

                        client_name, client_id = get_client_name_and_id(data[D_SIP])

                        key = f"{client_name} {data[D_QUERY]}"
                        web_key = f"{data[D_SIP]} {data[D_DIP]} {data[D_DPORT]}"

                        if key in dns_match:

                            web_access_time = hour_to_timedelta(data[D_HORA])
                            if dns_match[key]["last_dns_response_time"] is None: continue
                            delta_time = web_access_time - dns_match[key]["last_dns_response_time"]

                            service = data[D_DPORT]
                            if data[D_DPORT] in services: service = services[data[D_DPORT]]

                            # data, dia_semana, hora, id_cliente, ..., dist, ttl, ..., ip_src, dist, ttl, port_dst, servico, ip_dst, query, delta
                            web_info = f"{data[D_SIP]},{data[D_DIST]},{data[D_TTL]},{data[D_DPORT]},{service},{data[D_DIP]},{query},{delta_time}"

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
                                    # WEB_REQ = 0 WEB_REQ_CLIENT = 1 WEB_DIST_TTL = 2 WEB_NEW_FORMAT = 3
                                    dns_match[key]["web"] = { web_key: web_info }
                                    
                            
                            elif web_key not in dns_match[key]["web"]:
                                dns_match[key]["web"][web_key] = web_info


    fin.close()
    #f_dns.close()

    def get_ip_dst(line):
        items = line.split(" ")

        pos_port = items[3].rfind(".")
        return items[3][:pos_port]


    # { f"{client_id} {data[D_QUERY]}": {
    #   "dst": conj dst perguntas,
    #   f"{data[D_SIP]} {data[D_SPORT]} {data[D_DIP]} {data[D_QUERY_ID]}": [dns_req, dns_resp],
    #   "web": { f"{ip_src} {ip_dst} {port_dst}": web_access},
    #   "last_dns_response_time": hour_to_timedelta(data[D_HORA])
    # }
    
    with open(f"output{output_n}.txt", "w") as fout, open(f"pre_processed{output_n}.txt", "w") as fout2:
        print("AGRUPADO POR Cliente e HOST PERGUNTADO NO DNS REQUEST E ACESSADO PELO WEB", file=fout)
        
        print(f"QTD RESPOSTAS DNS PARA REQUESTS 'A': {dns_a_count}", file=fout)
        print(f"QTD RESPOSTAS DNS CNAME PARA REQUESTS 'A': {dns_a_cname_count}\n\n", file=fout)

        for key in dns_match:
            cname = dns_match[key]["cname"]
            del dns_match[key]["cname"]
            del dns_match[key]["src"]
            del dns_match[key]["dst"]
            del dns_match[key]["last_dns_response_time"]

            web = dns_match[key]["web"]
            del dns_match[key]["web"]

            if len(web) > 0: # houve acesso web(REQ INTERFACE INTERNA)
                match = []

                for key2 in dns_match[key]:
                    dns_pair = dns_match[key][key2]

                    if dns_pair[RESPONSE] != None and (duplicated != None or not dns_pair[DUPLICATED_REQUEST]):
                        match.append(dns_pair)
                
                if len(match) > 0:
                    if cname: fout.write(f"{key}(CNAME)\n")
                    else: fout.write(f"{key}\n")

                    for dns in match:
                        fout.write(f"\t{dns[DNS_DIGEST]},{dns[DNS_FLAGS][0]},{dns[DNS_FLAGS][1]},{dns[DNS_FLAGS][2]},{dns[DNS_FLAGS][3]},{dns[DNS_FLAGS][4]},{dns[DNS_FLAGS][5]}\n\n")
                    
                    last_dns = match[len(match)-1]
                    for k, web_access in web.items():
                        fout.write(f"\t{last_dns[DNS_DIGEST]},{last_dns[DNS_FLAGS][0]},{last_dns[DNS_FLAGS][1]},{last_dns[DNS_FLAGS][2]},{last_dns[DNS_FLAGS][3]},{last_dns[DNS_FLAGS][4]},{last_dns[DNS_FLAGS][5]},{web_access}\n\n")
                        fout2.write(f"{last_dns[DNS_DIGEST]},{last_dns[DNS_FLAGS][0]},{last_dns[DNS_FLAGS][1]},{last_dns[DNS_FLAGS][2]},{last_dns[DNS_FLAGS][3]},{last_dns[DNS_FLAGS][4]},{last_dns[DNS_FLAGS][5]},{web_access}\n")
                    fout.write(f"\n\n")

if __name__ == '__main__':
    main()