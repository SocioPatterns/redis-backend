#!/usr/bin/env python

import rediscontactadder
import argparse
import socket
from threading import Thread, Event
import Queue
from sociopatterns import Sighting, Contact
from sociopatterns import xxtea
import spparser
import struct
import time
import os


class UDPLoader(object):

    def __init__(self, address, port=2342, processor=None):
        """
        UDP Loader class constructor.

        Arguments:

        address -- the address of the computer that is receiving packets
        (where ContactReceiver.py is executed).

        port -- the port to which the UDP packets are sent (default 2342).

        processor -- the processor object that is used to
        process the packets received.
        """
        self.address = address
        self.port = port
        self.processor = processor

    def open(self):
        self.sock = socket.socket(socket.AF_INET,  # Internet
                                  socket.SOCK_DGRAM)  # UDP
        self.sock.bind((self.address, self.port))

    def close(self):
        self.sock.close()

    def __iter__(self):
        """
        Returns an iterator that runs over a stream of objects
        """

        while 1:
            pktlen = 32
            packet = self.sock.recvfrom(pktlen)

            data, addr = packet
            station_id = struct.unpack('>L', socket.inet_aton(addr[0]))[0]
            payload = data[16:]

            obj = self.processor.process(station_id, payload)
            if obj is not None:
                yield obj


class SPProcessor(object):

    def __init__(self, decode=False, xxtea_crypto_key=None,
                 load_sightings=0, unique_sightings=0, sighting_time_delta=10,
                 load_contacts=1, unique_contacts=1, contact_time_delta=10,
                 packet_parser=spparser.PacketParser()):
        """
        SocioPatterns packet processor

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

    def hash_cleanup(self):
        self.contact_hash_dict = dict(filter(lambda (h, t): t > self.tcleanup
                                             - self.contact_time_delta, self.contact_hash_dict.items()))
        self.sighting_hash_dict = dict(filter(lambda (h, t): t > self.tcleanup
                                              - self.sighting_time_delta, self.sighting_hash_dict.items()))

    def process(self, station_id, payload):

        if self.decode:
            payload = xxtea.decode(payload)

        timestamp = int(time.time())
        obj = self.parser.parse_packet(timestamp, station_id, payload)
        if obj is None:
            return

        if obj.t >= self.tcleanup:
            self.hash_cleanup()
            self.tcleanup = obj.t + self.time_delta

        if (obj.__class__ == Sighting) and self.load_sightings:
            if self.unique_sightings:
                h = obj.get_hash()
                if h in self.sighting_hash_dict:
                    if obj.t - self.sighting_hash_dict[h] > self.sighting_time_delta:
                        self.sighting_hash_dict[h] = obj.t
                        return obj
                else:
                    self.sighting_hash_dict[h] = obj.t
                    return obj
            else:
                return obj

        elif (obj.__class__ == Contact) and self.load_contacts:
            if self.unique_contacts:
                h = obj.get_hash()
                if h in self.contact_hash_dict:
                    if obj.t - self.contact_hash_dict[h] > self.contact_time_delta:
                        self.contact_hash_dict[h] = obj.t
                        return obj
                else:
                    self.contact_hash_dict[h] = obj.t
                    return obj
            else:
                return obj


class ProducerThread(Thread):

    def __init__(self, loader, queue, run_event):
        self.run_event = run_event
        self.loader = loader
        self.queue = queue
        super(ProducerThread, self).__init__()

    def run(self):
        try:
            print "ProducerThread created."

            self.loader.open()

            for contact in self.loader:
                self.queue.put(contact)
                if not self.run_event.is_set():
                    break

        except ValueError:
            print "Producer: Error %s" % ValueError
            self.loader.close()
            raise


def main():

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

    UDP_IP = "10.254.0.1"
    UDP_PORT = 2342

    adder = rediscontactadder.RedisContactAdder(RUN_NAME, '', DELTAT, REDIS_URL, PORT, PASSWD)

    queue = Queue.Queue()
    loader = UDPLoader(UDP_IP, UDP_PORT,
                       SPProcessor(packet_parser=spparser.PacketParserOBG()))

    run_event = Event()
    run_event.set()
    prod = ProducerThread(loader, queue, run_event)
    prod.daemon = True
    prod.start()

    try:
        while 1:
            try:
                contact = queue.get(True, 1)
                if contact is not None:
                    adder.store_contact(contact)
                    print "Contact stored", contact
                queue.task_done()

            except KeyboardInterrupt:
                break
            except Queue.Empty:
                pass
    finally:
        print "Attempting to close threads"
        run_event.clear()
        prod.join(2)
        print "Producer closed."
        loader.close()
        print "Socket closed."

if __name__ == '__main__':
    main()
