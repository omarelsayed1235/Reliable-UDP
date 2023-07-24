import struct
import socket
import time


class TCPtoUDP:
    def __init__(self, server_address):
        # create UDP socket
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.settimeout(100.0)

        # set server address
        self.server_address = server_address

        # set sequence number
        self.seq_num = 0

    def receive_response(self):
        data, address = self.sock.recvfrom(4096)
        print(data.decode())

    def send_packet(self, data):
        # calculate checksum
        checksum = self._calculate_checksum(data)
        # pack data and checksum into a struct
        packet = struct.pack('!I', self.seq_num) + struct.pack('!I', checksum) + data
        # send packet to server
        self.sock.sendto(packet, self.server_address)
        # wait for ACK
        while True:
            try:
                if data.decode() == 'FIN':
                    return None
                # receive ACK from server
                data, _ = self.sock.recvfrom(4096)
                # unpack ACK data
                ack_num, = struct.unpack('!I', data)
                # check if ACK matches sequence number
                if ack_num == self.seq_num:
                    self.seq_num = 1 - self.seq_num
                    self.receive_response()
                    break
            except socket.error:
                self.sock.close()
                break
            except socket.timeout:
                print('Connection has been closed due to timeout')
                self.sock.sendto(packet, self.server_address)

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
            client_packet = "SYN"
            self.sock.sendto(client_packet.encode(), self.server_address)

            # receive SYN-ACK packet from server
            syn_ack_packet, address = self.sock.recvfrom(1024)
            print(syn_ack_packet.decode(), " has been received\n")
            time.sleep(2)
            if syn_ack_packet.decode() == "SYN-ACK":
                # send ACK packet to server
                ack_packet = "ACK"
                self.sock.sendto(ack_packet.encode(), address)
                print("***Connection Established***\n")
                break

    def Close(self):
        self.send_packet('FIN'.encode('utf-8'))
        print('***Connection has been closed.***\n')
        self.sock.close()


if __name__ == '__main__':
    address = ('localhost', 9999)
    client = TCPtoUDP(address)
    client.three_way_handshake()
    mess = 'GET C:/Users/w/Desktop/test.txt HTTP/1.1\r\nHost: www.example.com\r\nKeep-Alive: 3\r\nConnection: Keep-Alive\r\n'
    client.send_packet(mess.encode('utf-8'))
    # time.sleep(4)

    # mess = 'GET C:/Users/w/Desktop/test.txt HTTP/1.1\r\nHost: www.example.com\r\nKeep-Alive: 100\r\nConnection: Keep-Alive\r\n'
    # client.send_packet(mess.encode('utf-8'))
    # time.sleep(2)
    # mess = 'POST C:/Users/w/Desktop/test.txt HTTP/1.1\r\nHost: www.example.com\r\nKeep-Alive: 100\r\nConnection: Keep-Alive\r\n\r\nnoureen'
    # client.send_packet(mess.encode('utf-8'))
    # time.sleep(2)
    # mess = 'fady'
    # client.send_packet(mess.encode('utf-8'))
    # time.sleep(2)
    client.Close()

