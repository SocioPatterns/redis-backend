#!/usr/bin/env python

import rediscontactadder
import argparse

import socket
from threading import Thread, Event
from Queue import Queue
from sociopatterns import Sighting, Contact
from sociopatterns import xxtea
import spparser
import struct
import time
import os

parser = argparse.ArgumentParser(description='Start a contact capture into a REDIS database.')

parser.add_argument('name', metavar='<run name>',
                    help='name to identify the RUN inside the REDIS database')

parser.add_argument('tstart', metavar='<start time>', nargs='?',
                    default=time.time(), type=int,
                    help='start time for the capture data')

parser.add_argument('delta', metavar='<frame duration>', nargs='?',
                    default='20', type=int,
                    help='duration in seconds of time frames')

parser.add_argument('url', metavar='<Redis server URL>', nargs='?',
                    default="localhost", help='URL of Redis server')

parser.add_argument('port', metavar='<port>', nargs='?',
                    default=6379, type=int, help='port of Redis server')

parser.add_argument('password', metavar='<password>', nargs='?',
                    default=None, help='password to access the database')

args = parser.parse_args()

RUN_NAME = args.name
DELTAT = args.delta
REDIS_URL = args.url
PORT = args.port
PASSWD = args.password

TEA_CRYPTO_KEY = (0xf6e103d4, 0x77a739f6, 0x65eecead, 0xa40543a9)
PROTO_CONTACTREPORT = 69
UDP_IP = "10.254.0.1"
UDP_PORT = 2342


class UDPLoader:
    """
    The UDP Loader class collects UDP packets,
    performs basic selection and filtering operations,
    and provides an iterator over a stream of SocioPatterns events
    that are instances of the Contact and Sighting classes.
    """

    def __init__(self, UDP_IP, UDP_PORT, decode=True, xxtea_crypto_key=None,
                 load_sightings=0, unique_sightings=0, sighting_time_delta=10,
                 load_contacts=1, unique_contacts=1, contact_time_delta=10,
                 packet_parser=spparser.PacketParser()):
        """
        UDP Loader class constructor.

        required arguments:

        UDP_IP -- the address of the computer that is receiving packets
        (where ContactReceiver.py is executed).

        UDP_PORT -- the port to which the UDP packets are sent (default 2342).

        keyword arguments:

        decode -- Boolean flag. If set, the Loader decodes packets
        before processing them, using the crypto key specified
        with the xxtea_crypto keyword argument.
        Otherwise,the packets are assumed to be unencrypted.

        xxtea_crypto_key -- XXTEA 128-bit key, represented
        as a sequence of four unsigned 32-bit integers.

        load_sightings -- Boolean flag. If set, process sighting packets,
        otherwise ignore them.

        load_contacts -- Boolean flag. If set, process contact packets,
        otherwise ignore them.

        unique_sightings -- Boolean flag. If set, multiple copies
        of the sighting packets received by different readers
        over a sliding window of fixed duration (specified by
        the keyword argument sighting_time_delta)
        are detected and only distinct sightings are processed.

        unique_contacts -- Boolean flag. If set, multiple copies
        of the contact packets received by different readers
        over a sliding window of fixed duration (specified by
        the keyword argument contact_time_delta)
        are detected and only distinct contacts are processed.

        sighting_time_delta -- integers representing the length,
        in seconds, of the sliding window over which duplicate
        sightings are detected and dropped.
        Unless the data collection infrastructure implements
        store and forward techniques, or otherwise introduces
        large delays (several seconds), any value above
        a few seconds will work well.

        contact_time_delta -- integers representing the length,
        in seconds, of the sliding window over which duplicate
        sightings are detected and dropped.
        Unless the data collection infrastructure implements
        store and forward techniques, or otherwise introduces
        large delays (several seconds), any value above
        a few seconds will work well.

        packet_parser -- parser for a specific experiment.
        This can be used by subclasses to activate experiment-specific
        packet processing.
        """

        self.UDP_IP, self.UDP_PORT = UDP_IP, UDP_PORT

        self.load_sightings = load_sightings
        self.unique_sightings = unique_sightings

        self.load_contacts = load_contacts
        self.unique_contacts = unique_contacts

        self.decode = decode
        if self.decode:
            xxtea.set_key(*xxtea_crypto_key)

        self.sighting_hash_dict = {}
        self.sighting_time_delta = sighting_time_delta

        self.contact_hash_dict = {}
        self.contact_time_delta = contact_time_delta

        self.time_delta = max(sighting_time_delta, contact_time_delta)
        self.tcleanup = -1

        self.parser = packet_parser

    def unpack_packet(self, packet):
        data, addr = packet
        station_id = struct.unpack('>L', socket.inet_aton(addr[0]))[0]
        return station_id, data[16:]

    def process_packet(self, pktlen, data, timestamp):
        (station_id, payload) = self.unpack_packet(data)

        if self.decode:
            decrypted_data = xxtea.decode(payload)
        else:
            decrypted_data = payload

        return self.parser.parse_packet(timestamp, station_id, decrypted_data)

    def hash_cleanup(self):
        self.contact_hash_dict = dict(filter(lambda (h, t): t > self.tcleanup
                                             - self.contact_time_delta, self.contact_hash_dict.items()))
        self.sighting_hash_dict = dict(filter(lambda (h, t): t > self.tcleanup
                                              - self.sighting_time_delta, self.sighting_hash_dict.items()))

    def open(self):
        self.sock = socket.socket(socket.AF_INET,  # Internet
                                  socket.SOCK_DGRAM)  # UDP
        self.sock.bind((UDP_IP, UDP_PORT))

    def close(self):
        self.sock.close()

    def __iter__(self):
        """
        Returns an iterator that runs over a stream of SocioPatterns object
        """

        while 1:
            tstamp = int(time.time())
            pktlen = 32
            packet = self.sock.recvfrom(pktlen)

            obj = self.process_packet(pktlen, packet, tstamp)
            if obj is None:
                continue

            if obj.t >= self.tcleanup:
                self.hash_cleanup()
                self.tcleanup = obj.t + self.time_delta

            if (obj.__class__ == Sighting) and self.load_sightings:
                if self.unique_sightings:
                    h = obj.get_hash()
                    if h in self.sighting_hash_dict:
                        if obj.t - self.sighting_hash_dict[h] > self.sighting_time_delta:
                            self.sighting_hash_dict[h] = obj.t
                            yield obj
                    else:
                        self.sighting_hash_dict[h] = obj.t
                        yield obj
                else:
                    yield obj

            elif (obj.__class__ == Contact) and self.load_contacts:
                if self.unique_contacts:
                    h = obj.get_hash()
                    if h in self.contact_hash_dict:
                        if obj.t - self.contact_hash_dict[h] > self.contact_time_delta:
                            self.contact_hash_dict[h] = obj.t
                            yield obj
                    else:
                        self.contact_hash_dict[h] = obj.t
                        yield obj
                else:
                    yield obj


adder = rediscontactadder.RedisContactAdder(RUN_NAME, '', DELTAT, REDIS_URL, PORT, PASSWD)

queue = Queue()
loader = UDPLoader(UDP_IP, UDP_PORT, xxtea_crypto_key=TEA_CRYPTO_KEY, decode=True)


class ProducerThread(Thread):
    def run(self):
        try:
            print "ProducerThread created."

            loader.open()

            for contact in loader:
                queue.put(contact)
                if not run_event.is_set():
                    break

        except ValueError:
            print "Producer: Error %s" % ValueError
            loader.close()
            raise


class ConsumerThread(Thread):
    def run(self):
        try:
            print "ConsumerThread created."
            global queue
            # global sock

            while run_event.is_set():
                contact = queue.get()
                try:
                    adder.store_contact(contact)
                    print "Contact stored", contact
                except Exception, e:
                    print e
                    print "Contact: ", contact
                finally:
                    queue.task_done()

        except ValueError:
            print "Consumer: Error %s" % ValueError
            loader.close()
            raise

if __name__ == '__main__':
    run_event = Event()
    run_event.set()
    prod = ProducerThread()
    prod.start()
    cons = ConsumerThread()
    cons.start()

    try:
        while 1:
            time.sleep(1)
    except KeyboardInterrupt:
        print "Attempting to close threads"
        run_event.clear()
        prod.join(2)
        print "Producer closed."
        cons.join(2)
        print "Consumer closed."
        loader.close()
        print "Socket closed."
        os._exit(0)

