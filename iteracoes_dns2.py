from sys import argv, exit
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

dns_match = {} # { f"{ip_src} {distancia} {query}": { "dst": conj dst perguntas,  f"{query_id}{ip_dst}": [dns_req, dns_resp], "web": primeiro acesso Web } }

REQUEST = 0
DUPLICATED_REQUEST = 1
RESPONSE = 2
RESPONSE_ERROR = 3

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


count =0

for line in fin:
    count+=1
    if count% 100000 ==0: print(count)

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

                        #key = f"{data[D_SIP]} {data[D_DIST]} {query}"
                        #key2 = f"{query_id} {data[D_DIP]}"
                        key = f"{data[D_SIP]} {data[D_DIST]}"
                        key2 = f"{query}"
                        key3 = f"{query_id} {data[D_DIP]}"

                        # { f"{ip_src} {distancia}": {
                        #   "query": {
                        #       "dst": conj dst perguntas,
                        #       f"{query_id} {ip_dst}": [dns_req,duplicated_request,dns_resp,response_erro],
                        #       "web": acesso}
                        #   }
                        # }
                        ip_dns_req.add(data[D_SIP])
                        if key not in dns_match:
                            # key3: [req, duplicated_request?, response, response_erro]
                            dns_match[key] = { key2: { "dst": set(), "web": None, key3: [f"{data[D_HORA]} {line.strip()}", False, None, False] } }
                            dns_match[key][key2]["dst"].add(data[D_DIP])

                        elif key2 not in dns_match[key]: # mesmo ip de origem perguntando por outro dominio
                            dns_match[key][key2] = { "dst": set(), "web": None, key3: [f"{data[D_HORA]} {line.strip()}", False, None, False] }

                            dns_match[key][key2]["dst"].add(data[D_DIP])
                        # pergunta repetida sendo feita a um servidor DNS diferente
                        elif data[D_DIP] not in dns_match[key][key2]["dst"] and dns_match[key][key2]["web"] == None:
                            if key3 in dns_match[key][key2]: print(f"{data[D_HORA]} {line.strip()}") # colisao?

                            dns_match[key][key2]["dst"].add(data[D_DIP])

                            dns_match[key][key2][key3] = [f"{data[D_HORA]} {line.strip()}", False, None, False] # req, duplicated_request?, response, response_error?

                        elif dns_match[key][key2]["web"] == None: # pergunta repetida para um servidor dns repetido
                            if key2 not in dns_match[key]:
                                dns_match[key][key2][key3] = [f"{data[D_HORA]} {line.strip()}", True, None, False] # req, duplicated_request?, response, response_error?

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

                        #key = f"{data[D_DIP]} {data[D_DIST]} {query}"
                        #key2 = f"{query_id} {data[D_SIP]}"

                        key = f"{data[D_DIP]} {data[D_DIST]}"
                        key2 = f"{query}"
                        key3 = f"{query_id} {data[D_SIP]}"

                        if key in dns_match:
                            # response == None para pegar apenas a primeira resposta
                            # web == None para pegar apenas iteracoes antes do primeiro acesso
                            #if key2 in dns_match[key] and dns_match[key][key2]["web"] == None and key3 in dns_match[key][key2]:
                            if key2 in dns_match[key] and key3 in dns_match[key][key2]:
                                if dns_match[key][key2][key3][RESPONSE] == None:
                                    dns_match[key][key2][key3][RESPONSE] = f"{data[D_HORA]} {line.strip()}"

                                    dns_statistic[TOTAL_PAIRS] += 1 # total de pares pergunta e resposta

                                    for error in ["NXDomain", "Refused"]:
                                        if error in items[7]:
                                            dns_match[key][key2][key3][RESPONSE_ERROR] = True

                                            dns_statistic[TOTAL_PAIRS_WITH_ERROR] += 1 # total de pares pergunta e resposta com erro

                                    if dns_match[key][key2][key3][DUPLICATED_REQUEST]: # eh duplicado

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

                                        ip_query[f"{data[D_DIP]}{query_response_ip}"] = query

                                        # only dst
                                        ip_query_only_dst[query_response_ip] = query

                                        items = items[pos+1:]

                                        try:
                                            pos = items.index("A")
                                        except ValueError: # not on list
                                            pos = -1

                elif proto_port == "6:80": # http
                    continue

                elif proto_port == "6:443": # https
                    ip_web.add(data[D_SIP]) # ip fez acesso web

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


fin.close()

def get_ip_dst(line):
    items = line.split(" ")

    pos_port = items[3].rfind(".")
    return items[3][:pos_port]

with open(f"output{output_n}.txt", "w") as fout, open(f"output_dns_web{output_n}.txt", "w") as fout_dns_web:
    fout.write("Dada a dupla ip de origem, distancia, para cada query feita por ele lista as Iteracoes dns antes do primeiro acesso web\n\n")
    fout_dns_web.write("Lista de acessos web que foram feitos por um IP que fez pelo menos um request DNS(nao necessariamente possui response)\n\n")
    for key in dns_match: # ip de origem, distancia
        matches = {}
        write_key = False # garante que sera escrito apenas aqueles que tem iteracoes

        for key2 in dns_match[key]: # dominios
            matches[key2] = []

            del dns_match[key][key2]["dst"]

            web = dns_match[key][key2]["web"]
            del dns_match[key][key2]["web"]
            if web != None:

                fout_dns_web.write(f"Host: {key2}\nAcesso: {web}\n\n")

                for key3 in dns_match[key][key2]:
                    #for dns_pair in dns_match[key][key2][key3]:
                    dns_pair = dns_match[key][key2][key3]
                    if dns_pair[RESPONSE] != None and not dns_pair[DUPLICATED_REQUEST]: # possui resposta
                        matches[key2].append(dns_pair)

                        write_key = True

                matches[key2].append(web)

        if write_key:
            splited_key = key.split(" ")

            client = site_from_ip(splited_key[0])[0]
            fout.write(f"IP SRC: {splited_key[0]}({client})| DIST: {splited_key[1]}\n")

            for query in matches: # query = key2
                if len(matches[query]) > 1:
                    fout.write(f"\t{query}\n")
                    for match in matches[query]:
                        if isinstance(match, list): # dns
                            fout.write(f"\t\t{match[REQUEST]}\n") # request
                            fout.write(f"\t\t{match[RESPONSE]}\n\n") # response
                        else: # web
                            fout.write(f"\t\t{match}\n\n")
'''
with open(f"Resumo{output_n}.txt", "w") as fout_resumo:
    fout_resumo.write("LISTA DE IP'S QUE FAZEM REQ DNS E ACESSO WEB\n")
    for ip in ip_dns_req_web:
        fout_resumo.write(f"\t{ip}\n")
    
    fout_resumo.write("---------------------------------------------------------------------\n")
'''
with open(f"Resumo{output_n}.txt", "w") as fout_resumo:
    fout_resumo.write(f"QUANTIDADE DE IP'S QUE FAZEM REQ DNS: {len(ip_dns_req)}\n")
    percent = (len(ip_dns_req_web)/len(ip_dns_req)) * 100
    fout_resumo.write(f"\tQUANTIDADE DE IP'S QUE FAZEM REQ DNS E ACESSO WEB: {len(ip_dns_req_web)}({percent:.2f}%)\n\n")

    fout_resumo.write(f"QUANTIDADE DE IP'S QUE FAZEM ACESSO WEB: {len(ip_web)}\n")

with open(f"output_dns_list{output_n}.txt", "w") as fout_dns_list:
    fout_dns_list.write("Lista de pares request, response DNS encontrados(nao necessariamente possui um acesso web em seguida)\n\n")
    for key in dns_match:
        for key2 in dns_match[key]:
            for key3 in dns_match[key][key2]:
                dns_pair = dns_match[key][key2][key3]

                if dns_pair[RESPONSE] != None and not dns_pair[DUPLICATED_REQUEST]:
                    items = dns_pair[RESPONSE].split(" ")

                    if "*" in items[7] or "*" in items[8]:
                        fout_dns_list.write(f"AUTHORITATIVE\n")
                        fout_dns_list.write(f"{dns_pair[REQUEST]}\n")
                        fout_dns_list.write(f"{dns_pair[RESPONSE]}\n\n")
                    
                    else:
                        fout_dns_list.write(f"{dns_pair[REQUEST]}\n")
                        fout_dns_list.write(f"{dns_pair[RESPONSE]}\n\n")
'''
with open(f"Resumo{output_n}.txt", "a") as fout_resumo:
    fout_resumo.write("LISTA DE IP'S QUE FAZEM REQ\n")
    for ip in ip_dns_req:
        fout_resumo.write(f"{ip}\n")
'''
with open(f"output_total_web{output_n}.txt", "w") as fout_total_web:
    fout_total_web.write("todos os acessos web(sem repeticao)\n\n")
    for key in total_web:
        #fout_total_web.write(f"{total_web[key]}\n")
        splited = total_web[key].split(";")
        fout_total_web.write(f"Host: {splited[0]}\n")
        fout_total_web.write(f"Acesso: {splited[1]}\n\n")
        

#for ip in ip_query:
    #print(f"{ip} -> {ip_query[ip]}")
'''
for key in dns_match:
    del dns_match[key]["dst"]

    matches = []
    error_count = 0
    for key2 in dns_match[key]:
        # se tem resposta? e (nao eh duplicado ou duplicado permitido)
        if dns_match[key][key2][RESPONSE] != None: # tem resposta?
            #matches.append((dns_match[key][key2][REQUEST], dns_match[key][key2][RESPONSE], dns_match[key][key2][2])) # (pergunta, resposta)

            if not dns_match[key][key2][DUPLICATED_REQUEST]: # nao eh duplicado
                matches.append(dns_match[key][key2])


    if len(matches) > 1:
        fout.write(f"{key}\n")

        duplicated_error_count = 0
        for match in matches:
            if not match[DUPLICATED_REQUEST] and not match[RESPONSE_ERROR]: # NAO eh duplicado e NAO TEM erro
                fout.write(f"\t{match[REQUEST]}\n") # pergunta
                fout.write(f"\t{match[RESPONSE]}\n\n") # resposta

                dns_statistic[QUERY_SEQUENCE] += 1 # total de pares pergunta e resposta que fazem parte de um burst

            elif not match[DUPLICATED_REQUEST] and match[RESPONSE_ERROR]: # NAO eh duplicado e TEM erro
                fout.write(f"\t{match[REQUEST]}\n") # pergunta
                fout.write(f"\t{match[RESPONSE]}\n\n") # resposta

                dns_statistic[QUERY_SEQUENCE] += 1 # total de pares pergunta e resposta que fazem parte de um burst
                dns_statistic[QUERY_ERROR_PAIRS] += 1 # total de pares pergunta e resposta com erro, que fazem parte de um burst

            # Executados apenas quando temos duplicated != None
            elif match[DUPLICATED_REQUEST] and not match[RESPONSE_ERROR]: # EH duplicado e NAO TEM erro
                fout.write(f"\t{match[REQUEST]}\n") # pergunta
                fout.write(f"\t{match[RESPONSE]}\n\n") # resposta

            else: # EH duplicado e TEM erro
                duplicated_error_count += 1

        if duplicated != None:
            fout.write(f"\tTotal de pares duplicados com respostas Refused ou NxDomain: {duplicated_error_count} omitidos\n\n")

    elif len(matches) == 1:
        dns_statistic[QUERY_NON_SEQUENCE] += 1 # total de pares pergunta e resposta que nao fazem parte de um burst

fout.close()

# PRINT ESTATISTICA
with open(f"output_statistic{output_n}.txt", "w") as f:
    f.write(f"Total de request-reply: {dns_statistic[TOTAL_PAIRS]}\n")
    #f.write(f"Total de query-answer duplicados: {dns_statistic[TOTAL_PAIRS_DUPLICATED]}\n")
    #f.write(f"Total de query-answer que sao Refused ou NXDomain: {dns_statistic[TOTAL_PAIRS_WITH_ERROR]}\n\n")
    f.write(f"\tTotal de request-reply que nao fazem parte de um burst(Apenas um par request-reply ou queries repetidas para o mesmo servidor DNS): {dns_statistic[QUERY_NON_SEQUENCE]} ({((dns_statistic[QUERY_NON_SEQUENCE]/dns_statistic[TOTAL_PAIRS])*100):.2f}%)\n")
    f.write(f"\tTotal de request-reply que fazem parte de um burst: {dns_statistic[QUERY_SEQUENCE]} ({((dns_statistic[QUERY_SEQUENCE]/dns_statistic[TOTAL_PAIRS])*100):.2f}%)\n")
    f.write(f"\tTotal de request-reply que fazem parte de um burst e sao Refused ou NXDomain: {dns_statistic[QUERY_ERROR_PAIRS]} ({((dns_statistic[QUERY_ERROR_PAIRS]/dns_statistic[TOTAL_PAIRS])*100):.2f}%)\n")
    query_pairs_without_errors = dns_statistic[QUERY_SEQUENCE] - dns_statistic[QUERY_ERROR_PAIRS]
    f.write(f"\tTotal de request-reply que fazem parte de um burst e nao sao Refused ou NXDomain: {query_pairs_without_errors} ({((query_pairs_without_errors/dns_statistic[TOTAL_PAIRS])*100):.2f}%)\n\n")
    f.write(f"Burst: Dado um ip de origem e um hostname que deseja-se saber o ip, termos pares request-reply em sequencia, onde o request eh feito para servidores DNS diferentes\n")
'''
