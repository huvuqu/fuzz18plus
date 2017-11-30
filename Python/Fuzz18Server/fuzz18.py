#!/usr/bin/env python
from BaseHTTPServer import BaseHTTPRequestHandler, HTTPServer
import SocketServer
import threading
import urlparse
import requests
import json
import base64
import detect
import copy
import sys
from termcolor import cprint
from bs4 import BeautifulSoup
try:
    from http_parser.parser import HttpParser
except ImportError:
    from http_parser.pyparser import HttpParser

LABEL = """

___________                      ____  ______              
\_   _____/_ __________________ /_   |/  __  \     .__     
 |    __)|  |  \___   /\___   /  |   |>      <   __|  |___ 
 |     \ |  |  //    /  /    /   |   /   --   \ /__    __/ 
 \___  / |____//_____ \/_____ \  |___\______  /    |__|    
     \/              \/      \/             \/             
----------------------------------------------------------------
[*] Say oh yeah
"""
num_of_threads = 5
FILE = {
    "SQLi": "sqlinjection.txt"
}
REDIRECTS = True
TIMEOUT = None
DBMS = None
results = {}
class Server(BaseHTTPRequestHandler):
    def _set_headers(self):
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()

    def do_GET(self):
        self._set_headers()
        self.wfile.write("<html><body><h1>hi!</h1></body></html>")

    def do_POST(self):
        # Doesn't do anything with posted data
        # <--- Gets the size of data
        content_length = int(self.headers['Content-Length'])
        # <--- Gets the data itself
        post_data = self.rfile.read(content_length)
        dataDict = dict(urlparse.parse_qsl(post_data))
        burp_request = base64.b64decode(dataDict["data"])
        mode = dataDict["mode"]
        httptype = dataDict["type"]
        protocol = dataDict["protocol"]
        host = dataDict["host"]
        port = dataDict["port"]
        cprint("[+] Receive HTTP " + httptype + " from Burp", 'green')
        cprint("[+] Host: " + host, 'green')
        cprint("[+] Mode: " + mode, 'green')
        if httptype == "request":
            cprint("------------------------------[BEGIN]--------------------------------", 'green')
            cprint(burp_request , 'green')
            cprint("------------------------------[END]--------------------------------", 'green')
            if mode == "fuzzer":
                cprint("[+] Fuzzing")
                threads = gen_thread_list(burp_request, protocol, host, port)
                fuzzflag = 1
                for thread in threads:
                    thread.join()
                    cprint("[-] Thread " + str(thread.thread_id) + " is finished", "green")
                print_out()
        else:
            # TODO: respone
            if mode == "analyzer":
                pass

        self._set_headers()
        self.wfile.write("<html><body><h1>POST!</h1></body></html>")


def run(server_class=HTTPServer, handler_class=Server, port=9981):
    server_address = ('', port)
    httpd = server_class(server_address, handler_class)
    print 'Starting httpd...'
    httpd.serve_forever()


def parse_request(http_request, protocol, host, port):
    """
    Parse HTTP request form Burp Suite to dict
    TODO cookie parse
    """
    httpParser = HttpParser()
    httpParser.execute(http_request, len(http_request))

    header = dict(httpParser.get_headers())
    header.pop("Content-Length")  # remove Content-Length
    # cookie = header["Cookie"]
    body = httpParser.recv_body()
    method = httpParser.get_method()
    url = protocol + "://" + host + httpParser.get_path()
    query = httpParser.get_query_string()

    params = dict(urlparse.parse_qsl(query))
    data = dict(urlparse.parse_qsl(body)) if method == "POST" else {}
    try:
        jsondata = json.loads(
            body) if method == "POST" and header["Content-Type"] == "application/json" else {}
    except Exception as e:
        print "[!] " + e
        jsondata = {}
    return method, url, header, params, data, jsondata


def gen_thread_list(http_request, protocol, host, port):
    """
    generate a list of thread's name
    """
    method, url, header, params, data, jsondata = parse_request(
        http_request, protocol, host, port)
    threadList = []
    for thread_id in xrange(0, num_of_threads):
        thread = Fuzzer(thread_id, method, url, header, params, data, jsondata)
        thread.start()
        cprint("[+] Thread " + str(thread_id) + " is started", "green")
        threadList.append(thread)
    return threadList

def get_payloads(thread_id, filename):
    """
    Devide payload to each thread
    """
    with open(filename) as f:
        payloads = f.readlines()
        if thread_id >= 0 and thread_id < num_of_threads:
            num_of_payloads_each_thread = len(payloads) / num_of_threads
            if num_of_payloads_each_thread % 2 != 0:
                num_of_payloads_each_thread -= 1
            start_point = thread_id * num_of_payloads_each_thread
            is_not_last_thread = thread_id != (num_of_threads - 1)
            end_point = (thread_id + 1) * \
                num_of_payloads_each_thread if is_not_last_thread else len(
                    payloads)
        else: #get all
            start_point = 0
            end_point = len(payloads)
        payloads = payloads[start_point:end_point]
        payloads = [x.strip() for x in payloads]
    return payloads

def print_out():
    # merge result
    for thread_id, result in results.iteritems():
        if thread_id == 0:
            continue
        for datatype, keylist in result.iteritems():
            for key, payload_and_info in keylist.iteritems():
                results[0][datatype][key].update(payload_and_info)
    payloads = get_payloads(-1, FILE["SQLi"])
    for datatype, keylist in results[0].iteritems():
        cprint("[*] Datatype: " + datatype, "green", "on_white")
        for key, info in keylist.iteritems():
            cprint("\n\t[+] Key: " + key, "blue", "on_white")
            for x in xrange(0,len(payloads),2):
                color = "green"
                payload_pair = [payloads[x],payloads[x+1]]
                status_pair = [info[payloads[x]]["status"],info[payloads[x+1]]["status"]]
                length_pair = [info[payloads[x]]["length"],info[payloads[x+1]]["length"]]
                tag_pair = [info[payloads[x]]["tag"],info[payloads[x+1]]["tag"]]
                error_pair = [info[payloads[x]]["error"],info[payloads[x+1]]["error"]]
                if error_pair != [[],[]] or tag_pair[0] != tag_pair[1] or status_pair[0] != status_pair[1]:
                    color = "red"
                elif length_pair[0]!= length_pair[1]:
                    color = "yellow" 
                else:
                    continue
                cprint(str(payload_pair)+"\t"+str(status_pair)+"\t"+str(length_pair)+"\t"+str(tag_pair)+"\n"+str(error_pair), color)
class Fuzzer (threading.Thread):

    def __init__(self, thread_id, method, url, header, params, data, jsondata):
        threading.Thread.__init__(self)
        self.thread_id = thread_id
        self.method = method
        self.url = url
        self.header = header
        self.params = params if params !={} else None
        self.data = data if data !={} else None
        self.jsondata = jsondata if jsondata !={} else None
        self.result = {}
        self.analyzer = Analyzer()

    def run(self):

        if self.params != None:
            self.result["params"] = {}
            for key, value in self.params.iteritems():
                self.result["params"][key] = {}
                injected_values = self.inject(value, FILE["SQLi"])
                newparam = copy.deepcopy(self.data)
                for payload, injected_value in injected_values.iteritems():
                    newparam[key] = injected_value
                    self.analyzer.response = self.make_a_request(newparam, self.data, self.jsondata)
                    self.result["params"][key][payload] = self.analyzer.get_basic_info()

        if self.data != None:
            self.result["data"] = {}
            for key, value in self.data.iteritems():
                self.result["data"][key] = {}
                injected_values = self.inject(value, FILE["SQLi"])
                newdata = copy.deepcopy(self.data)
                for payload, injected_value in injected_values.iteritems():
                    newdata[key] = injected_value
                    self.analyzer.response = self.make_a_request(self.params, newdata, self.jsondata)
                    self.result["data"][key][payload] = self.analyzer.get_basic_info()

        if self.jsondata != None:
            for key, value in self.jsondata.iteritems():
                print "[json] " + key

        results[self.thread_id] = self.result

    def inject(self, value, filename):
        injected_values = {}
        payloads = get_payloads(self.thread_id, filename)
        for payload in payloads:
            injected_values[str(payload)] = str(value) + str(payload)
        return injected_values

    def make_a_request(self, params, data, jsondata):
        try:
            # , cookies=None, files=None, auth=None, timeout=None, allow_redirects=True, proxies=None, hooks=None, stream=None, verify=None, cert=None, json=None)
            response = requests.request(
                method=self.method, url=self.url, params=params, data=data, json=jsondata, headers=self.header, timeout=TIMEOUT, allow_redirects=REDIRECTS)
            response.raise_for_status()
            return response
        except requests.exceptions.HTTPError as err:
            print "[!http] " + err

class Analyzer(object):
    """docstring for Analyzer"""
    def __init__(self):
        self.response = None
    def get_basic_info(self):
        status = self.response.status_code
        length = len(self.response.content)
        tag = self.count_tag()
        error = detect.check_sqlinjecttion_error(dbms=DBMS, html=self.response.text)
        return {"status": status, "length": length, "tag":tag, "error":error}
    def count_tag(self):
        # No feature lxml? pip install lxml
        soup = BeautifulSoup(self.response.text, 'lxml')
        return len(soup.find_all())        
if __name__ == "__main__":
    from sys import argv
    cprint(LABEL, "red")
    if len(argv) == 2:
        run(port=int(argv[1]))
    else:
        run()
