import unittest
import iteracoes_dns_mod

class IteracoesDnsTest(unittest.TestCase):

    #######################################
	#         REQUEST PARSER TESTS        #
	#######################################
    def test_request_parser_0(self):
        data = ["0" for x in range(17)]

        line = "3.236.66.171.52426 > 200.192.233.10.53: [udp sum ok] 38378% [1au] A? fOFuxoSmodaPET.COM.br. ar: . OPT UDPsize=1232 DO (50)"
        items = line.split(" ")

        expected = ["0","0","0","0","0","0","0","0","0","fOFuxoSmodaPET.COM.br","0","0","0","0","0","38378", "0"]

        iteracoes_dns_mod.request_parser(items, data)

        self.assertEqual(data, expected)
    
    def test_request_parser_1(self):
        data = ["0" for x in range(17)]

        line = "200.130.148.253.56807 > 8.8.8.8.53: [udp sum ok] 36029+ [1au] AAAA? fds1.fortinet.com. ar: . OPT UDPsize=4000 DO (46)"
        items = line.split(" ")

        expected = [] # nao eh IPV4, por isso n processa

        iteracoes_dns_mod.request_parser(items, data)

        self.assertEqual(data, expected)
    
    def test_request_parser_2(self):
        data = ["0" for x in range(17)]

        line = "200.130.1.38.43816 > 8.8.8.8.53: [udp sum ok] 34566+ A? mqtt-mini.facebook.com. (40)"
        items = line.split(" ")

        expected = ["0","0","0","0","0","0","0","0","0","mqtt-mini.facebook.com","0","0","0","0","0","34566", "0"]

        iteracoes_dns_mod.request_parser(items, data)

        self.assertEqual(data, expected)
    
    def test_request_parser_3(self):
        data = ["0" for x in range(17)]

        line = "163.178.88.10.45196 > 200.192.233.10.53: [no cksum] 52379% [1au] A? newgrouptelecom.com.br. ar: . OPT UDPsize=4096 DO (51)"
        items = line.split(" ")

        expected = [] # vazio por causa do no cksum

        iteracoes_dns_mod.request_parser(items, data)

        self.assertEqual(data, expected)

    def test_request_parser_4(self):
        data = ["0" for x in range(17)]

        line = "152.255.15.70.56137 > 200.192.233.10.53: [udp sum ok] 40829 [1au] A? www.xvideosnovinha.com.br. ar: . OPT UDPsize=1232 (54)"
        items = line.split(" ")

        expected = ["0","0","0","0","0","0","0","0","0","www.xvideosnovinha.com.br","0","0","0","0","0","40829", "0"]

        iteracoes_dns_mod.request_parser(items, data)

        self.assertEqual(data, expected)
    
    def test_request_parser_5(self):
        data = ["0" for x in range(17)]

        line = "177.126.159.254.45830 > 200.192.233.10.53: [udp sum ok] 33031% [1au] A? www.redtube.com.br. ar: . OPT UDPsize=4096 DO (47)"
        items = line.split(" ")

        expected = ["0","0","0","0","0","0","0","0","0","www.redtube.com.br","0","0","0","0","0","33031", "0"]

        iteracoes_dns_mod.request_parser(items, data)

        self.assertEqual(data, expected)
    
    def test_request_parser_6(self):
        data = ["0" for x in range(17)]

        line = "200.168.137.69.21399 > 200.192.233.10.53: [udp sum ok] 21600 A? megaporno.com.br. (34)"
        items = line.split(" ")

        expected = ["0","0","0","0","0","0","0","0","0","megaporno.com.br","0","0","0","0","0","21600", "0"]

        iteracoes_dns_mod.request_parser(items, data)

        self.assertEqual(data, expected)
    
    # nao eh tipo A

    def test_request_parser_7(self):
        data = ["0" for x in range(17)]

        line = "208.69.34.73.24771 > 200.192.233.10.53: [udp sum ok] 45104% [1au] DS? pornogratis.vlog.br. ar: . OPT UDPsize=1410 DO (48)"
        items = line.split(" ")

        expected = []

        iteracoes_dns_mod.request_parser(items, data)

        self.assertEqual(data, expected)


    #######################################
	#       RESPONSE PARSER TESTS         #
	#######################################


    # Podem ser "parseados"

    def test_response_parser_0(self):
        data = ["0" for x in range(17)]

        line = "172.17.61.159.53 > 10.31.0.88.61259: [udp sum ok] 60436 q: A? e7808.dscg.akamaiedge.net. 1/0/1 e7808.dscg.akamaiedge.net. [20s] A 104.104.131.24 ar: . OPT UDPsize=4000 DO (70)"
        items = line.split(" ")

        expected = ["0","0","0","0","0","0","0","0","0","e7808.dscg.akamaiedge.net","0","0","0","0","0","60436", 11]

        iteracoes_dns_mod.response_parser(items, data)

        self.assertEqual(data, expected)


    def test_response_parser_1(self):
        data = ["0" for x in range(17)]

        line = "200.192.232.14.53 > 66.249.64.41.57394: [udp sum ok] 59321*- q: A? pornobom.com.br. 1/0/0 pornobom.com.br. [1h] A 104.238.138.197 (49)"
        items = line.split(" ")

        expected = ["0","0","0","0","0","0","0","0","0","pornobom.com.br","0","0","0","0","0","59321", 11]

        iteracoes_dns_mod.response_parser(items, data)

        self.assertEqual(data, expected)


    # resposta com CNAME

    def test_response_parser_2(self):
        data = ["0" for x in range(17)]

        line = "200.192.232.14.53 > 152.255.15.248.60562: [udp sum ok] 29985*- q: A? www.pornozinhoosgrate.com.br. 1/0/1 www.pornozinhoosgrate.com.br. [1h] CNAME ghs.google.com. ar: . OPT UDPsize=1232 (85)"
        items = line.split(" ")

        expected = []

        iteracoes_dns_mod.response_parser(items, data)

        self.assertEqual(data, expected)


    def test_response_parser_3(self):
        data = ["0" for x in range(17)]

        line = "1.1.1.1.53 > 200.130.19.88.21703: [udp sum ok] 48263 q: A? id.elsevier.com. 7/0/0 id.elsevier.com. [59m14s] CNAME id.elsevier-ae.com., id.elsevier-ae.com. [14s] CNAME id.elsevier-ae.com.cdn.cloudflare.net., id.elsevier-ae.com.cdn.cloudflare.net. [4m14s] A 104.18.235.170, id.elsevier-ae.com.cdn.cloudflare.net. [4m14s] A 104.18.232.170, id.elsevier-ae.com.cdn.cloudflare.net. [4m14s] A 104.18.234.170, id.elsevier-ae.com.cdn.cloudflare.net. [4m14s] A 104.18.233.170, id.elsevier-ae.com.cdn.cloudflare.net. [4m14s] A 104.18.231.170 (193)"
        items = line.split(" ")

        expected = []

        iteracoes_dns_mod.response_parser(items, data)

        self.assertEqual(data, expected)


    # resposta nao eh tipo A?

    def test_response_parser_4(self):
        data = ["0" for x in range(17)]

        line = "200.192.233.10.53 > 177.74.136.243.5931: [udp sum ok] 27561- q: NS? pornogratis.vlog.br. 0/4/1 ns: pornogratis.vlog.br. [1h] NS heather.ns.cloudflare.com., pornogratis.vlog.br. [1h] NS josh.ns.cloudflare.com., pornogratis.vlog.br. [15m] NSEC, pornogratis.vlog.br. [15m] RRSIG ar: . OPT UDPsize=1232 DO (250)"
        items = line.split(" ")

        expected = []

        iteracoes_dns_mod.response_parser(items, data)
        
        self.assertEqual(data, expected)


    # Testes 0 respostas

    def test_response_parser_5(self):
        data = ["0" for x in range(17)]

        line = "200.192.233.10.53 > 170.245.92.44.56419: [udp sum ok] 27637- q: A? gocache.com.br. 0/6/3 ns: gocache.com.br. [1h] NS deck.ns.gocache.com.br., gocache.com.br. [1h] NS jet.ns.gocache.com.br., jo3n607b2fdr7ddp7a60r4l79v44qi03.com.br. [15m] Type50, jo3n607b2fdr7ddp7a60r4l79v44qi03.com.br. [15m] RRSIG, psmr5dmsutr298to01htp1pi0ast0rkl.com.br. [15m] Type50, psmr5dmsutr298to01htp1pi0ast0rkl.com.br. [15m] RRSIG ar: deck.ns.gocache.com.br. [1h] A 170.82.172.2, jet.ns.gocache.com.br. [1h] A 35.247.207.5, . OPT UDPsize=1232 DO (498)"
        items = line.split(" ")

        expected = []

        iteracoes_dns_mod.response_parser(items, data)
        
        self.assertEqual(data, expected)


    def test_response_parser_6(self):
        data = ["0" for x in range(17)]

        line = "200.192.233.10.53 > 177.126.159.254.45830: [udp sum ok] 33031- q: A? www.redtube.com.br. 0/8/1 ns: redtube.com.br. [1h] NS sdns3.ultradns.com., redtube.com.br. [1h] NS sdns3.ultradns.org., redtube.com.br. [1h] NS sdns3.ultradns.biz., redtube.com.br. [1h] NS sdns3.ultradns.net., jo3n607b2fdr7ddp7a60r4l79v44qi03.com.br. [15m] Type50, jo3n607b2fdr7ddp7a60r4l79v44qi03.com.br. [15m] RRSIG, rdfrc3c30u859q7p2udjakd92e1p0tsa.com.br. [15m] Type50, rdfrc3c30u859q7p2udjakd92e1p0tsa.com.br. [15m] RRSIG ar: . OPT UDPsize=1232 DO (558)"
        items = line.split(" ")

        expected = []

        iteracoes_dns_mod.response_parser(items, data)
        
        self.assertEqual(data, expected)


    def test_response_parser_7(self):
        data = ["0" for x in range(17)]

        line = "200.192.233.10.53 > 177.155.208.38.6545: [udp sum ok] 35097- q: A? pornocaseiro.vlog.br. 0/2/1 ns: pornocaseiro.vlog.br. [1h] NS chan.ns.cloudflare.com., pornocaseiro.vlog.br. [1h] NS clyde.ns.cloudflare.com. ar: . OPT UDPsize=1232 (105)"
        items = line.split(" ")

        expected = []

        iteracoes_dns_mod.response_parser(items, data)
        
        self.assertEqual(data, expected)


    # Com error(Refused, NXDomain)

    def test_response_parser_8(self):
        data = ["0" for x in range(17)]

        line = "200.130.5.250.53 > 189.6.0.174.14463: [udp sum ok] 11099 NXDomain*-| q: A? pornhub.fnde.gov.br. 0/4/1 ns: fnde.gov.br. [2h] SOA parana01.fnde.gov.br. cgeti_csup.fnde.gov.br. 2021032002 43200 7200 1209600 72000, fnde.gov.br. [2h] RRSIG, fnde.gov.br. [20h] NSEC, fnde.gov.br. [20h] RRSIG ar: . OPT UDPsize=4096 DO (499)"
        items = line.split(" ")

        expected = []

        iteracoes_dns_mod.response_parser(items, data)
        
        self.assertEqual(data, expected)


    # No Checksum
    def test_response_parser_9(self):
        data = ["0" for x in range(17)]

        line = "186.250.92.126.53 > 200.130.5.3.13583: [no cksum] 6306*- q: A? mx1.antispam.fecam.sc.gov.br. 1/3/3 mx1.antispam.fecam.sc.gov.br. [12m] A 69.55.49.140 ns: fecam.sc.gov.br. [12m] NS ns3.fecamsc.org.br., fecam.sc.gov.br. [12m] NS ns1.fecamsc.org.br., fecam.sc.gov.br. [12m] NS ns2.fecamsc.org.br. ar: ns1.fecamsc.org.br. [1h] A 186.250.92.126, ns2.fecamsc.org.br. [1h] A 54.39.107.183, ns3.fecamsc.org.br. [1h] A 54.39.107.183 (176)"
        items = line.split(" ")

        expected = []

        iteracoes_dns_mod.response_parser(items, data)
        
        self.assertEqual(data, expected)


    #######################################
	#     RESPONSE iP's PARSER TESTS      #
	#######################################

    def test_response_ips_parser_0(self):
        query = "ptr01.novaportonet.net.br"

        line = "200.192.232.11.53 > 74.125.112.8.59383: [udp sum ok] 31834*- q: A? ptr01.novaportonet.net.br. 1/2/1 ptr01.novaportonet.net.br. [1h] A 177.190.72.124 ns: novaportonet.net.br. [1h] NS b.sec.dns.br., novaportonet.net.br. [1h] NS a.sec.dns.br. ar: . OPT UDPsize=1232 (112)"
        items = line.split(" ")
        know_ips = {}
        data = ["0","0","0","0","0","0","0","0","0","ptr01.novaportonet.net.br","0","0","0","0","0","31834", 11]

        expected = {"177.190.72.124": query}

        iteracoes_dns_mod.get_response_ips(items, know_ips, data)
        self.assertEqual(know_ips, expected)


    def test_response_ips_parser_1(self):
        query = "e7808.dscg.akamaiedge.net"

        line = "172.17.61.159.53 > 10.31.0.88.61259: [udp sum ok] 60436 q: A? e7808.dscg.akamaiedge.net. 1/0/1 e7808.dscg.akamaiedge.net. [20s] A 104.104.131.24 ar: . OPT UDPsize=4000 DO (70)"
        items = line.split(" ")
        know_ips = {}
        data = ["0","0","0","0","0","0","0","0","0","e7808.dscg.akamaiedge.net","0","0","0","0","0","60436", 11]

        expected = {"104.104.131.24": query}

        iteracoes_dns_mod.get_response_ips(items, know_ips, data)
        self.assertEqual(know_ips, expected)


    def test_response_ips_parser_2(self):
        query = "www.reunidaspaulista.com.br"

        line = "200.192.232.11.53 > 138.186.1.195.33776: [udp sum ok] 50614*- q: A? www.reunidaspaulista.com.br. 3/3/1 www.reunidaspaulista.com.br. [1h] A 201.63.46.194, www.reunidaspaulista.com.br. [1h] A 201.49.66.122, www.reunidaspaulista.com.br. [1h] RRSIG ns: reunidaspaulista.com.br. [1h] NS b.sec.dns.br., reunidaspaulista.com.br. [1h] NS c.sec.dns.br., reunidaspaulista.com.br. [1h] RRSIG ar: . OPT UDPsize=1232 DO (368)"
        items = line.split(" ")
        know_ips = {}
        data = ["0","0","0","0","0","0","0","0","0","www.reunidaspaulista.com.br","0","0","0","0","0","50614", 11]

        iteracoes_dns_mod.get_response_ips(items, know_ips, data)
        
        expected = {"201.63.46.194": query, "201.49.66.122": query}
        self.assertEqual(know_ips, expected)


    def test_response_ips_parser_3(self):
        query = "noticiasconcursos.com.br"

        line = "8.8.8.8.53 > 200.130.148.253.58269: [udp sum ok] 55223 q: A? noticiasconcursos.com.br. 2/0/1 noticiasconcursos.com.br. [4m59s] A 104.18.12.95, noticiasconcursos.com.br. [4m59s] A 104.18.13.95 ar: . OPT UDPsize=512 DO (85)"
        items = line.split(" ")
        know_ips = {}
        data = ["0","0","0","0","0","0","0","0","0","noticiasconcursos.com.br","0","0","0","0","0","55223", 11]

        expected = {"104.18.12.95": query, "104.18.13.95": query}

        iteracoes_dns_mod.get_response_ips(items, know_ips, data)
        self.assertEqual(know_ips, expected)  


    def test_response_ips_parser_4(self):
        query = "d3a965827bqypm.cloudfront.net"

        line = "8.8.8.8.53 > 200.130.1.38.45799: [udp sum ok] 54000 q: A? d3a965827bqypm.cloudfront.net. 4/0/0 d3a965827bqypm.cloudfront.net. [59s] A 52.84.154.85, d3a965827bqypm.cloudfront.net. [59s] A 52.84.154.98, d3a965827bqypm.cloudfront.net. [59s] A 52.84.154.27, d3a965827bqypm.cloudfront.net. [59s] A 52.84.154.107 (111)"
        items = line.split(" ")
        know_ips = {}
        data = ["0","0","0","0","0","0","0","0","0","d3a965827bqypm.cloudfront.net","0","0","0","0","0","54000", 11]

        expected = {"52.84.154.85": query, "52.84.154.98": query, "52.84.154.27": query, "52.84.154.107": query}

        iteracoes_dns_mod.get_response_ips(items, know_ips, data)
        self.assertEqual(know_ips, expected)


    def test_response_ips_parser_5(self):
        query = "youtube-ui.l.google.com"

        line = "208.67.222.222.53 > 200.130.103.162.1872: [udp sum ok] 34980 q: A? youtube-ui.l.google.com. 16/0/1 youtube-ui.l.google.com. [5m] A 142.250.79.206, youtube-ui.l.google.com. [5m] A 142.250.218.14, youtube-ui.l.google.com. [5m] A 142.250.218.78, youtube-ui.l.google.com. [5m] A 142.250.218.174, youtube-ui.l.google.com. [5m] A 142.250.218.206, youtube-ui.l.google.com. [5m] A 142.250.218.238, youtube-ui.l.google.com. [5m] A 142.250.219.14, youtube-ui.l.google.com. [5m] A 142.250.219.46, youtube-ui.l.google.com. [5m] A 172.217.28.14, youtube-ui.l.google.com. [5m] A 172.217.28.238, youtube-ui.l.google.com. [5m] A 172.217.29.14, youtube-ui.l.google.com. [5m] A 172.217.162.110, youtube-ui.l.google.com. [5m] A 172.217.173.78, youtube-ui.l.google.com. [5m] A 172.217.173.110, youtube-ui.l.google.com. [5m] A 216.58.202.142, youtube-ui.l.google.com. [5m] A 216.58.202.206 ar: . OPT UDPsize=4096 DO (308)"
        items = line.split(" ")
        know_ips = {}
        data = ["0","0","0","0","0","0","0","0","0","youtube-ui.l.google.com","0","0","0","0","0","34980", 11]

        expected = {"142.250.79.206": query, "142.250.218.14": query, "142.250.218.78": query, "142.250.218.174": query, "142.250.218.206": query, "142.250.218.238": query,
                    "142.250.219.14": query, "142.250.219.46": query, "172.217.28.14": query, "172.217.28.238": query, "172.217.29.14": query, "172.217.162.110": query,
                    "172.217.173.78": query, "172.217.173.110": query, "216.58.202.142": query, "216.58.202.206": query}

        iteracoes_dns_mod.get_response_ips(items, know_ips, data)
        self.assertEqual(know_ips, expected)   
    
    
    def test_response_ips_parser_6(self):
        query = "pornobom.com.br"

        line = "200.192.232.14.53 > 66.249.64.41.57394: [udp sum ok] 59321*- q: A? pornobom.com.br. 1/0/0 pornobom.com.br. [1h] A 104.238.138.197 (49)"
        items = line.split(" ")
        know_ips = {}
        data = ["0","0","0","0","0","0","0","0","0","pornobom.com.br","0","0","0","0","0","59321", 11]

        expected = {"104.238.138.197": query}

        iteracoes_dns_mod.get_response_ips(items, know_ips, data)
        self.assertEqual(know_ips, expected)

    #######################################
	#       INTERFACE PARSER TESTS        #
	#######################################

    def test_interface_parser_0(self):
        line = "0x0000:  8071 1ff6 62e7 cc4e 2442 550d 0800 4500"
        items = line.split(" ")
        print(items)
        expected = "cc4e 2442 550d"

        self.assertEqual(iteracoes_dns_mod.get_interface(items), expected)
    
    def test_interface_parser_1(self):
        line = "0x0000:  f8c0 01d8 8782 cc4e 2442 550c 0800 4500"
        items = line.split(" ")

        expected = "cc4e 2442 550c"

        self.assertEqual(iteracoes_dns_mod.get_interface(items), expected)

    def test_interface_parser_2(self):
        line = "0x0000:  0012 f29f 7d00 ecbd 1db5 8f93 0800 4500"
        items = line.split(" ")

        expected = "ecbd 1db5 8f93"

        self.assertEqual(iteracoes_dns_mod.get_interface(items), expected)
    
    def test_interface_parser_3(self):
        line = "0x0060:  295e 7a17 b85c 8003 6808 b130 320f f53c"
        items = line.split(" ")

        expected = None

        self.assertEqual(iteracoes_dns_mod.get_interface(items), expected)
    
    def test_interface_parser_4(self):
        line = ""
        items = line.split(" ")

        expected = None

        self.assertEqual(iteracoes_dns_mod.get_interface(items), expected)

if __name__ == '__main__':
    unittest.main()