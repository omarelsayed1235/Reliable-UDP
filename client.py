import struct
import socket
import datetime
import os
import time


class TCPtoUDP:
    def __init__(self, server_address):
        # create UDP socket
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.server_address = server_address
        # set sequence number
        self.seq_num = 0
        self.timeout = True
        self.sock.bind(self.server_address)

    def receive_packet(self):
        # receive packet from server
        self.sock.settimeout(12)
        while True:
            try:
                data, address = self.sock.recvfrom(4096)
                seq_num, checksum = struct.unpack('!II', data[:8])
                packet_data = data[8:]
                if packet_data.decode() == 'FIN':
                    print("***Connection has been closed***\n")
                    self.sock.close()
                    self.timeout = False
                    break
                # check packet checksum
                if self._verify_checksum(packet_data, checksum):
                    # send ACK to server
                    print("Check sum is correct")
                    ack_packet = struct.pack('!I', seq_num)
                    self.sock.sendto(ack_packet, address)
                    self.seq_num = 1 - self.seq_num
                    if packet_data.decode().startswith('GET') or packet_data.decode().startswith('POST'):
                        req = HTTPRequest(packet_data.decode())
                        req.parse_request(packet_data.decode())
                        if req.method == "GET":
                            if os.path.exists(req.uri):
                                with open(req.uri, "r") as file:
                                    line = file.read()
                                    last_modified = time.ctime(os.path.getmtime(req.uri))
                                length = len(line)
                                res = HTTPResponse(req.version, req.headers, "GET", length, last_modified, line)
                                if req.headers['Keep-Alive']:
                                    self.sock.settimeout(int(req.headers['Keep-Alive']))
                                self.sock.sendto(res.response.encode(), address)

                            else:
                                self.sock.sendto("404 error".encode('utf-8'), address)

                        elif req.method == "POST":
                            with open(req.uri, "a") as f:
                                f.write(req.body)
                                last_modified = time.ctime(os.path.getmtime(req.uri))
                            res = HTTPResponse(req.version, req.headers, "POST", 0, last_modified, None)
                            if req.headers['Keep-Alive']:
                                self.sock.settimeout(int(req.headers['Keep-Alive']))
                            self.sock.sendto(res.response.encode(), address)
                    # return packet data
                        return packet_data
                    else:
                        print(packet_data.decode())
                        self.sock.sendto(packet_data, address)
                        return packet_data
            except socket.timeout:
                print('***Connection has been closed due to timeout***\n')
                self.sock.close()
                self.timeout = False
                return None

    def _calculate_checksum(self, data):
        if len(data) % 2 != 0:
            data += bytes('\0', 'utf-8')  # pad with null byte if necessary
        sum = 0
        for i in range(0, len(data), 2):
            word = (data[i] << 8) + data[i + 1]  # convert two bytes to a word
            sum += word
        sum = (sum >> 16) + (sum & 0xffff)  # add carry if necessary
        sum = sum + (sum >> 16)  # add carry again if necessary
        checksum = ~sum & 0xffff  # bitwise NOT and mask to 16 bits
        return checksum

    def _verify_checksum(self, data, checksum):
        # calculate checksum of data
        calculated_checksum = self._calculate_checksum(data)
        # compare calculated checksum with received checksum
        return calculated_checksum == checksum

    def three_way_handshake(self):
        while True:
            syn_packet, address = self.sock.recvfrom(1024)
            print(syn_packet.decode(), " has been received\n")
            time.sleep(2)
            if syn_packet.decode() == "SYN":
                # send SYN-ACK packet to client
                server_packet = "SYN-ACK"
                self.sock.sendto(server_packet.encode(), address)
            # receive ACK packet from client
            ack_packet, address2 = self.sock.recvfrom(1024)
            print(ack_packet.decode(), " has been received\n")
            time.sleep(2)
            if syn_packet.decode() == "SYN" and ack_packet.decode() == "ACK":
                print("***Connection Established***\n")
                break


class HTTPRequest:
    def __init__(self, request_string, headers=None):
        self.method = None
        self.uri = None
        self.version = None
        self.headers = headers if headers is not None else {}
        self.body = ''

    def parse_request(self, request_string):
        lines = request_string.split("\r\n")
        request_line = lines[0].split(' ')
        self.method = request_line[0]
        self.uri = request_line[1]
        self.version = request_line[2]
        for i in range(1, len(lines)-1):
            if lines[i] == "":
                self.body = lines[i+1]
                break

            else:
                header_name, header_value = lines[i].split(': ')
                self.headers[header_name] = header_value


class HTTPResponse:
    def __init__(self, status_code, headers, method, contentlength, last_modified, body, version='HTTP/1.1', keep_alive=True):
        self.status_code = status_code
        self.body = body
        self.headers = headers if headers is not None else {}
        self.version = version
        self.keep_alive = keep_alive
        self.method=method
        header_name = {}
        header_value = {}
        for key, value in self.headers.items():
            header_name[key], header_value[key] = key, value

        self.status_code += " 200 OK"
        if self.method == "GET":
            self.headers['Content-length'] = contentlength

        if 'Content-Type' not in header_name:
            self.headers['Content-Type'] = 'text/plain'

        if 'Last_modified' not in header_name:
            self.headers['Last_modified'] = 'today'

        if 'Server' not in header_name:
            self.headers['Server'] = 'Custom HTTP Server'

        if 'Host' not in header_name:
            self.headers['Host'] = 'PC'

        if 'Date' not in self.headers:
            self.headers['Date'] = datetime.datetime.utcnow().strftime('%a, %d %b %Y %H:%M:%S GMT')

        self.headers['Last_modified'] = last_modified

        self.response = self.status_code + "\r\n"
        for key, value in self.headers.items():
            self.response += str(key) + ": " + str(value) + "\r\n"
        if self.method == "GET":
            self.response += "\r\n" + body
        print(self.response)


if __name__ == '__main__':
    server_address = ('localhost', 9999)
    server = TCPtoUDP(server_address)
    server.three_way_handshake()
    while server.timeout:
        server.receive_packet()

