import socket, json, time, os


PORT = 53
IP = '127.0.0.1'


class DNSServer:
    def __init__(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind((IP, PORT))
        self.pointer = 0
        self.cache = {}

    def resolve_dns_record(self, data):
        offset = 0

        transaction_id = data[offset:offset + 2]
        offset += 2

        flags = self.resolve_flags(data[offset:offset + 2])
        offset += 2

        qd_count = int.from_bytes(data[offset:offset + 2], byteorder='big')
        offset += 2

        an_count = int.from_bytes(data[offset:offset + 2], byteorder='big')
        offset += 2

        ns_count = int.from_bytes(data[offset:offset + 2], byteorder='big')
        offset += 2

        ar_count = int.from_bytes(data[offset:offset + 2], byteorder='big')
        offset += 2

        queries, off = self.resolve_queries(data, qd_count, offset)
        offset += off

        answers, off = self.resolve_resource_records(data, an_count,
                                                     offset, flags[2])
        offset += off

        authority_rrs, off = self.resolve_resource_records(data, ns_count,
                                                           offset, True)
        offset += off

        additional_rrs, off = self.resolve_resource_records(data, ar_count,
                                                            offset, False)
        offset += off

        return transaction_id, flags, queries, answers, authority_rrs, additional_rrs

    def resolve_flags(self, flag_bytes):
        bits_string = bin(flag_bytes[0])[2:].zfill(8) + bin(flag_bytes[1])[2:].zfill(8)

        qr = bits_string[0]
        opcode = int(bits_string[1:5], base=2)
        aa = bits_string[5]
        tc = bits_string[6]
        rd = bits_string[7]
        ra = bits_string[8]
        z = bits_string[9:12]
        rcode = int(bits_string[12:16], base=2)

        return qr, opcode, aa, tc, rd, ra, z, rcode

    def resolve_name(self, data, offset):
        name = ''
        pointer = offset

        while data[pointer] != 0:
            bits = bin(data[pointer])[2:].zfill(8)
            if bits.startswith('11'):
                label_offset = int.from_bytes(bytes([int('00' + bits[2:], base=2), data[pointer + 1]]), byteorder='big')
                name += self.resolve_name(data, label_offset)[0]
                pointer += 1
                break

            else:
                label_length = data[pointer]
                name += data[pointer + 1: pointer + 1 + label_length].decode('cp866') + '.'
                pointer += label_length + 1

        return name, pointer - offset + 1

    def resolve_queries(self, data, qd_count, offset):
        this_offset = offset
        queries = []

        for i in range(qd_count):
            length = 0

            name, additional = self.resolve_name(data, this_offset)
            this_offset += additional
            length += additional

            type = int.from_bytes(data[this_offset: this_offset + 2], byteorder='big')
            this_offset += 2
            length += 2

            cls = int.from_bytes(data[this_offset: this_offset + 2], byteorder='big')
            this_offset += 2
            length += 2

            queries.append({'name':name, 'type':type, 'class':cls,
                            'query':data[this_offset - length:this_offset + 1]})

        return queries, this_offset - offset

    def resolve_resource_records(self, data, an_count, offset, is_authoritative):
        this_offset = offset
        answers = []

        for i in range(an_count):
            length = 0
            name, additional = self.resolve_name(data, this_offset)
            this_offset += additional
            length += additional

            type = int.from_bytes(data[this_offset: this_offset + 2], byteorder='big')
            this_offset += 2
            length += 2

            cls = int.from_bytes(data[this_offset: this_offset + 2], byteorder='big')
            this_offset += 2
            length += 2

            ttl = int.from_bytes(data[this_offset: this_offset + 4], byteorder='big')
            this_offset += 4
            length += 4

            rd_length = int.from_bytes(data[this_offset: this_offset + 2], byteorder='big')
            this_offset += 2
            length += 2

            r_data = data[this_offset: this_offset + rd_length]

            r_containing = ''

            if type == 1:
                for byte in r_data:
                    r_containing += str(byte) + '.'

                r_containing = r_containing[:-1]

            elif type == 28:
                for i in range(rd_length):
                    if i % 3 == 2:
                        r_containing += ':'

                    r_containing += hex(r_data[i])[2:]

            elif type == 2 or type == 12:
                r_containing, _ = self.resolve_name(data, this_offset)

            this_offset += rd_length
            length += rd_length

            answers.append({'name':name, 'type':type, 'place time':time.time(),
                            'ttl' : ttl, 'r_data':r_containing,
                            'auth': is_authoritative,
                            'answer':data[this_offset - length:this_offset]})

        return answers, this_offset - offset

    def create_responce_from_cache(self, query, answers, auth, id, flags):
        responce = bytearray()

        responce.extend(id)

        responce.append(int('1' + str(flags[1]).zfill(4) + str(auth) + '01', base=2))
        responce.append(int('10000000', base=2))

        responce.extend([0, 1, 0, len(answers), 0, 0, 0, 0])

        responce.extend(query)

        for answer in answers:
            responce.extend(answer)

        print(responce)
        return bytes(responce)

    def run(self):
        with(open('config.txt', 'r')) as file:
            forward = file.readline()

        with(open('cache.json', 'w')) as file:
            if os.stat('cache.json').st_size != 0:
                self.cache = json.load(file)

        while True:
            in_cache = False
            data, addr = self.sock.recvfrom(512)
            transaction_id, flags, queries, _, _, _ = self.resolve_dns_record(data)

            for query in queries:
                try:
                    print(query)
                    record = self.cache[(query['type'], query['name'])]
                    if record['ttl'] > time.time() - record['place time']:
                        print(record)
                        responce = self.create_responce_from_cache(query['query'], record['answers'], flags[2], transaction_id, flags)
                        self.sock.sendto(responce, addr)
                        in_cache = True

                    else:
                        self.cache.pop((query['type'], query['name']))

                    with(open('cache.json', 'w')) as file:
                        json.dump(self.cache, file)

                except KeyError:
                    break

            if not in_cache:
                requester = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                requester.bind(('', PORT))

                requester.sendto(data, (forward, 53))
                nd, na = requester.recvfrom(512)

                self.sock.sendto(nd, addr)
                _, _, _, answers, authority_rrs, additional = self.resolve_dns_record(nd)

                for records in (answers, authority_rrs, additional):
                    for answer in records:
                        try:
                            self.cache[(answer['type'], answer['name'])]['answers'].append(answer['answer'])

                        except KeyError:
                            self.cache[(answer['type'], answer['name'])] = {
                                'ttl': answer['ttl'],
                                'place time': answer['place time'],
                                'auth': answer['auth'],
                                'answers': [answer['answer']]}


if __name__ == "__main__":
    server = DNSServer()
    server.run()
