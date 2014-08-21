from sociopatterns import Sighting, Contact
from sociopatterns import xxtea
import struct


class PacketParser(object):

    @classmethod
    def parse_packet(cls, timestamp, station_id, data):
        crc = struct.unpack("!H", data[-2:])[0]
        if crc != xxtea.crc16(data[:14]):
            # print 'rejecting packet from 0x%08x on CRC' % station_id
            return

        proto = struct.unpack("!B", data[0])[0]
        if proto == Contact.protocol:
            return cls.parse_packet_contact(timestamp, station_id, data)

        elif proto == Sighting.protocol:
            return cls.parse_packet_sighting(timestamp, station_id, data)

    @classmethod
    def parse_packet_contact(cls, timestamp, station_id, data):
        unpacked_data = struct.unpack("!BHBHHHHHH", data)

        id, flags = unpacked_data[1:3]
        seq = unpacked_data[-2]
        seen = unpacked_data[3:-2]

        seen_id = []
        seen_pwr = []
        seen_cnt = []

        for id2 in seen:
            if not id2:
                break

            seen_id.append(id2 & 0x07FF)
            seen_pwr.append(id2 >> 14)
            seen_cnt.append((id2 >> 11) & 0x07)

        return Contact(int(timestamp), station_id, id, seq,
                       seen_id, seen_pwr, seen_cnt, flags=flags)

    @classmethod
    def parse_packet_sighting(cls, timestamp, station_id, data):
        unpacked_data = struct.unpack("!BHBBHHBLH", data)
        id, flags, strength, id_last_seen, boot_count, reserved, seq = unpacked_data[1:-1]

        return Sighting(int(timestamp), station_id, id, seq,
                        strength, flags, last_seen=id_last_seen,
                        boot_count=boot_count)

    @classmethod
    def pack(cls, contact):
        if (contact.__class__ == Contact):
            return cls.pack_contact(contact)

    @classmethod
    def pack_contact(cls, contact):
        seen = [0, 0, 0, 0]
        for i in range(len(contact.seen_id)):
            seen[i] = contact.seen_id[i] | (contact.seen_cnt[i] << 11) | (contact.seen_pwr[i] << 14)

        data = [Contact.protocol, contact.id, contact.flags,
                seen[0], seen[1], seen[2], seen[3], contact.seq, 0]
        packed = struct.pack("!BHBHHHHHH", *data)
        data[-1] = xxtea.crc16(packed[:14])
        return struct.pack("!BHBHHHHHH", *data)


class PacketParserOBG(PacketParser):

    @classmethod
    def parse_packet_contact(cls, timestamp, station_id, data):
        (proto, id, boot_count, flags, seen1, seen2, seen3, seq, crc) = struct.unpack("!BHHBHHHHH", data)

        seen_id = []
        seen_pwr = []
        seen_cnt = []

        for id2 in [seen1, seen2, seen3]:
            if not id2:
                break

            seen_id.append(id2 & 0x07FF)
            seen_pwr.append(id2 >> 14)
            seen_cnt.append((id2 >> 11) & 0x07)

        return Contact(int(timestamp), station_id, id, seq,
                       seen_id, seen_pwr, seen_cnt,
                       flags=flags, boot_count=boot_count)

    @classmethod
    def parse_packet_sighting(cls, timestamp, station_id, data):
        (proto, id, boot_count, flags, strength, id_last_seen, reserved, seq, crc) = struct.unpack("!BHHBBHBLH", data)

        return Sighting(int(timestamp), station_id, id, seq,
                        strength, flags, last_seen=id_last_seen,
                        boot_count=boot_count)

    @classmethod
    def pack_contact(cls, contact):
        seen = [0, 0, 0]
        for i in range(len(contact.seen_id)):
            seen[i] = contact.seen_id[i] | (contact.seen_cnt[i] << 11) | (contact.seen_pwr[i] << 14)

        data = [Contact.protocol, contact.id, contact.boot_count, contact.flags,
                seen[0], seen[1], seen[2], contact.seq, 0]
        packed = struct.pack("!BHHBHHHHH", *data)
        data[-1] = xxtea.crc16(packed[:14])
        return struct.pack("!BHHBHHHHH", *data)

class PacketParser25C3(PacketParser):

    @classmethod
    def parse_packet_contact(cls, timestamp, station_id, data):
        unpacked_data = struct.unpack("!BHHHHBLH", data)

        id = unpacked_data[1]
        count, seq = unpacked_data[-3:-1]
        seen = unpacked_data[2:-3]

        seen_id = []
        seen_pwr = []
        seen_cnt = []

        for id2 in seen:
            if not id2:
                break

            cnt = count & 3
            if not cnt:
                cnt = 4

            seen_id.append(id2)
            seen_cnt.append(cnt)
            seen_pwr.append(0)

            count = count >> 2

        return Contact(int(timestamp), station_id, id, seq,
                       seen_id, seen_pwr, seen_cnt, flags=0)

    @classmethod
    def parse_packet_sighting(cls, timestamp, station_id, data):
        unpacked_data = struct.unpack("!BHBBBHHLH", data)[1:-1]
        id, size, flags, strength, id_last_seen, reserved, seq = unpacked_data[1:-1]

        return Sighting(int(timestamp), station_id, id, seq,
                        strength, flags, last_seen=id_last_seen)
