#!/usr/bin/env python

from sociopatterns import Contact
import time
import random
import socket
import spparser


def simulate():

    ids = [1210 + i for i in range(10)]

    UDP_IP = "10.254.0.1"
    UDP_PORT = 2342

    sock = socket.socket(socket.AF_INET,
                         socket.SOCK_DGRAM)

    parser = spparser.PacketParserOBG()

    seq = 0
    while(True):
        time.sleep(1)
        random.shuffle(ids)
        tstamp = int(time.time())
        pwr = random.randint(1, 3)
        cnt = random.randint(1, 5)

        contact = Contact(tstamp=tstamp, ip=3, id=ids[0], seq=seq,
                          seen_id=[ids[1]], seen_pwr=[pwr],
                          seen_cnt=[cnt], flags=0, boot_count=1)

        packet = parser.pack(contact)
        sock.sendto((bytes(0)*16 + bytes(packet)), (UDP_IP, UDP_PORT))

        print parser.parse_packet(tstamp, 3, bytes(packet))
        seq += 1


if __name__ == '__main__':
    simulate()
