#!/usr/bin/env python

import rediscontactadder
import argparse

import socket
from threading import Thread, Event
from Queue import Queue
from sociopatterns import Sighting, Contact
from sociopatterns import xxtea
import struct
import time
import os

parser = argparse.ArgumentParser(description='Start a contact capture into a REDIS database.')

parser.add_argument('name', metavar='<run name>',
                   help='name to identify the RUN inside the REDIS database')

parser.add_argument('tstart', metavar='<start time>', nargs='?',
                   default=time.time(), type=int, help='start time for the capture data')

parser.add_argument('delta', metavar='<frame duration>', nargs='?',
                   default='20', type=int, help='duration in seconds of time frames')

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
    The Loader class reads one or multiple network dump files in pcap format,
    performs basic selection and filtering operations,
    and provides an iterator over a stream of SocioPatterns events
    that are instances of the Contact and Sighting classes.
    """

    def __init__(self, UDP_IP, UDP_PORT, start_time=None, stop_time=None,
                 readers=None, decode=True, xxtea_crypto_key=None,
                 load_sightings=0, unique_sightings=0, sighting_time_delta=10,
                 load_contacts=1, unique_contacts=1, contact_time_delta=10,
                 experiment=None, mapping=None):
        """
        Loader class constructor.

        required arguments:

        pcap_filenames -- a filename or a list of filenames
        indicating the pcap files to be processed

        keyword arguments:

        pcap_filter -- a TCPDUMP filter string, as described in
        http://manpages.ubuntu.com/manpages/karmic/man7/pcap-filter.7.html

        files_assume_continuity -- Boolean flag. If set, it makes the Loader
        assume that there are no temporal gaps between consecutive pcap files.
        This affects only the disambiguation of multiple contacts reported
        by different readers across the file boundary. It should be set to
        False only if it is known that the different pcap files correspond
        to separate data-taking sessions.

        files_time_order -- Boolean flag. If set, the Loader instance looks up
        the timestamp of the first packet of each file, and processes the file
        in increasing order of those timestamps. If not set, the Loader reads
        the files in the order they appear in the pcap_filenames list.

        start_time -- unix ctime integer. If specified, all packets
        with timestamp earlier than start_time are ignored.

        stop_time -- unix ctime integer. If specified, all packets
        with timestamp later than stop_time are ignored.

        readers -- sequence of reader IDs. If specified, only packets
        received from the specified readers are considered,
        and the others are ignored.

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

        experiment -- string specifying the name of a specific experiment.
        This can be used by subclasses to activate experiment-specific
        packet processing. The Loader class currently recognizes
        the "25c3" experiment only. When specified, this activates
        alternate parsing of the OpenBeacon packets, as used at 25C3.
        """

        self.UDP_IP, self.UDP_PORT = UDP_IP, UDP_PORT

        self.start_time = start_time
        self.stop_time = stop_time

        self.readers = readers

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

        self.experiment = experiment
        if experiment == '25c3':
            self.parse_packet_contact = self.parse_packet_contact_25C3
            self.parse_packet_sighting = self.parse_packet_sighting_25C3
        elif experiment == 'OBG':
            self.parse_packet_contact = self.parse_packet_contact_OBG
            self.parse_packet_sighting = self.parse_packet_sighting_OBG

        self.mapping = mapping

    def unpack_packet(self, packet):
        data, addr = packet
        station_id = struct.unpack('>L', socket.inet_aton(addr[0]))[0]
        return station_id, data[16:]

    def parse_packet_contact_25C3(self, timestamp, station_id, data):
        (proto, id, id1, id2, id3, count, seq, crc) = struct.unpack("!BHHHHBLH", data)
        if crc != xxtea.crc16(data[:14]):
            #print 'rejecting packet from 0x%08x on CRC' % station_id
            return

        seen_id = []
        seen_pwr = []
        seen_cnt = []

        for id2 in [id1, id2, id3]:
            if not id2:
                break

            cnt = count & 3
            if not cnt:
                cnt = 4

            seen_id.append(id2)
            seen_cnt.append(cnt)
            seen_pwr.append(0)

            count = count >> 2

        contact = Contact(int(timestamp), station_id, id, seq, seen_id, seen_pwr, seen_cnt, flags=0)
        return contact

    def parse_packet_sighting_25C3(self, timestamp, station_id, data):
        (proto, id, size, flags, strength, id_last_seen, reserved, seq, crc) = struct.unpack("!BHBBBHHLH", data)
        if crc != xxtea.crc16(data[:14]):
            #print 'rejecting packet from 0x%08x on CRC' % station_id
            return

        sighting = Sighting(int(timestamp), station_id, id, seq, strength, flags, last_seen=id_last_seen)
        return sighting

    def parse_packet_contact_OBG(self, timestamp, station_id, data):
        (proto, id, boot_count, flags, seen1, seen2, seen3, seq, crc) = struct.unpack("!BHHBHHHHH", data)
        if crc != xxtea.crc16(data[:14]):
            #print 'rejecting packet from 0x%08x on CRC' % station_id
            return

        seen_id = []
        seen_pwr = []
        seen_cnt = []

        for id2 in [seen1, seen2, seen3]:
            if not id2:
                break

            seen_id.append(id2 & 0x07FF)
            seen_pwr.append(id2 >> 14)
            seen_cnt.append((id2 >> 11) & 0x07)

        contact = Contact(int(timestamp), station_id, id, seq, seen_id, seen_pwr, seen_cnt, flags=flags, boot_count=boot_count)
        return contact

    def parse_packet_sighting_OBG(self, timestamp, station_id, data):
        (proto, id, boot_count, flags, strength, id_last_seen, reserved, seq, crc) = struct.unpack("!BHHBBHBLH", data)
        if crc != xxtea.crc16(data[:14]):
            #print 'rejecting packet from 0x%08x on CRC' % station_id
            return

        sighting = Sighting(int(timestamp), station_id, id, seq, strength, flags, last_seen=id_last_seen, boot_count=boot_count)
        return sighting

    def parse_packet_contact(self, timestamp, station_id, data):
        (proto, id, flags, seen1, seen2, seen3, seen4, seq, crc) = struct.unpack("!BHBHHHHHH", data)
        if crc != xxtea.crc16(data[:14]):
            #print 'rejecting packet from 0x%08x on CRC' % station_id
            return

        seen_id = []
        seen_pwr = []
        seen_cnt = []

        for id2 in [seen1, seen2, seen3, seen4]:
            if not id2:
                break

            seen_id.append(id2 & 0x07FF)
            seen_pwr.append(id2 >> 14)
            seen_cnt.append((id2 >> 11) & 0x07)

        contact = Contact(int(timestamp), station_id, id, seq, seen_id, seen_pwr, seen_cnt, flags=flags)
        return contact

    def parse_packet_sighting(self, timestamp, station_id, data):
        (proto, id, flags, strength, id_last_seen, boot_count, reserved, seq, crc) = struct.unpack("!BHBBHHBLH", data)
        if crc != xxtea.crc16(data[:14]):
            #print 'rejecting packet from 0x%08x on CRC' % station_id
            return

        sighting = Sighting(int(timestamp), station_id, id, seq, strength, flags, last_seen=id_last_seen, boot_count=boot_count)
        return sighting

    def process_packet(self, pktlen, data, timestamp):
        (station_id, payload) = self.unpack_packet(data)

        if self.decode:
            decrypted_data = xxtea.decode(payload)
        else:
            decrypted_data = payload

        proto = struct.unpack("!B", decrypted_data[0])[0]

        if proto == Contact.protocol:
            return self.parse_packet_contact(timestamp, station_id, decrypted_data)

        elif proto == Sighting.protocol:
            return self.parse_packet_sighting(timestamp, station_id, decrypted_data)

    def process_mapping(self, obj):
        if obj.__class__ == Contact:
            obj.id = self.mapping.get(obj.t, obj.id)
            if not obj.id:
                return None

            seen_id = []
            seen_pwr = []
            seen_cnt = []

            for (tag_id, pwr, cnt) in zip(obj.seen_id, obj.seen_pwr, obj.seen_cnt):
                mapped_id = self.mapping.get(obj.t, tag_id)
                if not mapped_id:
                    continue
                seen_id.append(mapped_id)
                seen_pwr.append(pwr)
                seen_cnt.append(cnt)

            obj.seen_id = seen_id
            obj.seen_pwr = seen_pwr
            obj.seen_cnt = seen_cnt

            return obj

        elif obj.__class__ == Sighting:
            obj.id = self.mapping.get(obj.t, obj.id)
            if not obj.id:
                return None

            obj.last_seen = self.mapping.get(obj.t, obj.last_seen)

            return obj

    def hash_cleanup(self):
        self.contact_hash_dict = dict( filter( lambda (h, t): t > self.tcleanup - self.contact_time_delta, self.contact_hash_dict.items() ) )
        self.sighting_hash_dict = dict( filter( lambda (h, t): t > self.tcleanup - self.sighting_time_delta, self.sighting_hash_dict.items() ) )

    def open(self):
        self.sock = socket.socket(socket.AF_INET, # Internet
                     socket.SOCK_DGRAM) # UDP
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

            if self.mapping:
                obj = self.process_mapping(obj)
                if obj is None:
                    continue

            if self.readers and not (obj.ip in self.readers):
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
loader = UDPLoader(UDP_IP, UDP_PORT, xxtea_crypto_key=TEA_CRYPTO_KEY, experiment="OBG", decode=False)


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

