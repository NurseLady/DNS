import socket
import sys
import pickle
from datetime import timedelta, datetime
from dnslib import DNSError, DNSRecord
from threading import Thread
from time import sleep


class Packet:
    def __init__(self, rr, create_time):
        self.resource_record = rr
        self.create_time = create_time


class DNSserver:
    def __init__(self, forward_server="8.8.8.8"):
        self.forward_server = forward_server
        print("Forward server: " + forward_server)
        self.database = self.load_cache()
        self.set_socket()

    def set_socket(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("", 53))

    @staticmethod
    def load_cache():
        try:
            with open('db.pickle', 'rb') as f:
                database = pickle.load(f)
            print('Cache loaded successfully!')

        except Exception as err:
            print('Сannot load db.pickle:\n' + str(err))
            return

        return database

    def send_response(self, response, addr):
        self.sock.connect(addr)
        self.sock.sendall(response)
        self.sock.close()

    @staticmethod
    def save_cache(database):
        try:
            with open('db.pickle', 'wb') as f:
                pickle.dump(database, f)

            print('Сache was saved.\n')

        except Exception as err:
            print('Cache saving error:\n' + str(err) + "\n")

    def get_cache_response(self, dns_record):
        print("Getting cache reply...")
        key = (str(dns_record.q.qname).lower(), dns_record.q.qtype)

        if key in self.database and self.database[key]:
            responce = dns_record.reply()
            responce.rr = [p.resource_record for p in self.database[key]]
            print("Success\n")
            return responce

        print("Cannot get\n")

    def add_record(self, rr, date_time):
        k = (str(rr.rname).lower(), rr.rtype)

        if k in self.database:
            self.database[k].add(Packet(rr, date_time))
        else:
            self.database[k] = {Packet(rr, date_time)}

        print("New record:")
        print(rr)

    def add_records(self, dns_record):
        for r in dns_record.rr + dns_record.auth + dns_record.ar:
            date_time = datetime.now()
            self.add_record(r, date_time)
        print()

    def check_cache(self, pack):
        return datetime.now() - pack.create_time > timedelta(seconds=pack.resource_record.ttl)

    def clean_cache(self):
        delta = 0

        for key, value in self.database.items():
            last_length = len(value)
            self.database[key] = set(pack for pack in value if not self.check_cache(pack))
            delta += last_length - len(self.database[key])

        if delta > 0:
            print(str(datetime.now()) + " — " + str(delta) + " resource records removed\n")

    def loop(self):
        try:
            while True:
                data, addr = self.sock.recvfrom(2048)

                if self.database:
                    self.clean_cache()

                try:
                    dns_record = DNSRecord.parse(data)
                    self.add_records(dns_record)

                except DNSError as err:
                    print('DNS record parse error:\n' + str(err) + "\n")
                    continue

                if not dns_record.header.qr:
                    response = self.get_cache_response(dns_record)

                    try:
                        if response:
                            self.send_response(response.pack(), addr)

                            if self.database:
                                self.save_cache(self.database)
                        else:
                            resp = dns_record.send(self.forward_server)
                            self.add_records(DNSRecord.parse(resp))
                            self.send_response(resp, addr)

                        self.set_socket()

                        if self.database:
                            self.save_cache(self.database)

                    except Exception as err:

                        print(str(datetime.now()) + " — cannot ask server" +
                              self.forward_server + ":\n" + str(err) + "\n")
        except Exception as err:
            print('Server error: ' + str(err) + "\n")

    def run(self):
        print('Running server...\n')

        try:
            self.loop()
        finally:
            if self.database:
                self.save_cache(self.database)

            print('Server is stopped.')


if __name__ == '__main__':
        if len(sys.argv) > 1:
            input = sys.argv[-1]
            s = DNSserver(input)
        else:
            s = DNSserver()

        thread = Thread(target=s.run)
        thread.daemon = True
        thread.start()

        while (True):
            try:
                sleep(1)
            except KeyboardInterrupt:
                sys.stdout.write("Running was interrupt.")
                exit(0)
