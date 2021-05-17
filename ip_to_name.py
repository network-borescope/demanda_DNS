# Importing socket function
import socket
# open file containing ip addresses
with open("ip_to_name_entrada.txt", "r") as f:
    ip_list = f.read().splitlines()

# for loop to take list of ip addresses and resolve to a hostname
count = 0
with open("req_src_name.txt", "w") as f:
    for ip in ip_list:
        count += 1
        try:
            output = socket.gethostbyaddr(ip)[0]
        except socket.herror:
            output = "NotFound"
        
        result = (ip, output)

        if count % 1000 == 0: print(count)

        print(f"{result[0]} {result[1]}", file=f)
