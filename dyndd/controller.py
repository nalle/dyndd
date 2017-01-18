from twisted.internet import reactor, defer
from twisted.python import failure
from twisted.names import client, dns, error, server
import ConfigParser
import logging
import os
import time
import datetime
import socket
import signal
from twisted.internet.address import IPv4Address

import MySQLdb


class DynDDServerFactory(server.DNSServerFactory):
    def handleQuery(self, message, protocol, address):
        if protocol.transport.socket.type == socket.SOCK_STREAM:
            self.peer_address = protocol.transport.getPeer()
        elif protocol.transport.socket.type == socket.SOCK_DGRAM:
            self.peer_address = IPv4Address('UDP', *address)
        else:
            print "Unexpected socket type %r" % protocol.transport.socket.type

        for resolver in self.resolver.resolvers:
            if hasattr(resolver, 'peer_address'):
                resolver.peer_address = self.peer_address

        return server.DNSServerFactory.handleQuery(self, message
                                                   protocol, address)


class DynDDController(object):
    def __init__(self):
        self.config = ConfigParser.ConfigParser()
        self.config.read("/etc/dyndd/dyndd.conf")

        if self.config.get("global", "LogLevel").lower() == "fatal":
            level = logging.FATAL
        elif self.config.get("global", "LogLevel").lower() == "info":
            level = logging.INFO
        elif self.config.get("global", "LogLevel").lower() == "warn":
            level = logging.WARN
        elif self.config.get("global", "LogLevel").lower() == "error":
            level = logging.ERROR
        elif self.config.get("global", "LogLevel").lower() == "debug":
            level = logging.DEBUG
        else:
            level = logging.INFO

        logging.basicConfig(format='[%(asctime)s] %(levelname)s: %(message)s',
                            level=logging.DEBUG,
                            filename=self.config.get("global",
                                                     "ApplicationLog"))
        self.connect_mysql()
        signal.signal(1, self._reload)
        self._peer_address = None

    @property
    def peer_address(self):
        return self._peer_address

    @peer_address.setter
    def peer_address(self, value):
        self._peer_address = value

    def _reload(self, signum, handler):
        self.config.read("/etc/dyndd/dyndd.conf")

    def connect_mysql(self):
        try:
            self.db = MySQLdb.connect(host=self.config.get("global",
                                                           "DBHost"),
                                      user=self.config.get("global",
                                                           "DBUser"),
                                      passwd=self.config.get("global",
                                                             "DBPass"),
                                      db=self.config.get("global",
                                                         "DBSchema"))
            self.cursor = self.db.cursor(MySQLdb.cursors.DictCursor)
            logging.info("MySQL connection successfully established to %s"
                         % self.config.get("global", "DBHost"))
        except Exception, e:
            logging.error("MySQL connection failed to %s, retrying (%s)"
                          % (self.config.get('global', 'DBHost'), str(e)))
            self.connect_mysql()

        return True

    def ping_mysql(self):
        try:
            self.db.ping()
        except Exception, e:
            logging.error("Connection to MySQL %s lost, retrying (%s)"
                          % (self.config.get('global', 'DBHost'), (str(e))))
            self.connect_mysql()

        return True

    def _type(self, record_type):
        if record_type == dns.A:
            return "A"
        if record_type == dns.AAAA:
            return "AAAA"
        if record_type == dns.NS:
            return "NS"
        if record_type == dns.SOA:
            return "SOA"
        if record_type == dns.MX:
            return "MX"
        else:
            return ""

    def _dynamicResponseRequired(self, query):
        if query.type == dns.NS or query.type == dns.SOA:
            self.cursor.execute("SELECT domain, nameservers, contact
                                FROM domains WHERE domain='%s'"
                                % query.name.name)
            self.db.commit()
        else:
            self.cursor.execute("SELECT hostname, ip, recordtype
                                FROM dnsrecords WHERE hostname='%s'
                                AND recordtype='%s'"
                                % (str(query.name.name),
                                   self._type(query.type)))
            self.db.commit()

        self.lookup_result = self.cursor.fetchall()
        if self.cursor.rowcount > 0:
            self.lookup_result = self.lookup_result[0]
            return self.lookup_result
        else:
            return ""

    def _Record_A(self, query):
        answers = [dns.RRHeader(
                name=query.name.name, type=query.type,
                payload=dns.Record_A(address=self.lookup_result['ip'],
                                     ttl=5), auth=True)]

        return answers, [], []

    def _Record_AAAA(self, query):
        answers = [dns.RRHeader(
                name=query.name.name, type=query.type,
                payload=dns.Record_AAAA(address=self.lookup_result['ip'],
                                        ttl=5), auth=True)]

        return answers, [], []

    def _Record_NS(self, query):
        answers = []
        for nameserver in self.lookup_result['nameservers'].split(','):
            answers.append(dns.RRHeader(
                name=query.name.name, type=query.type,
                payload=dns.Record_NS(name=nameserver,
                                      ttl=5), auth=True))

        return answers, [], []

    def _Record_MX(self, query):
        answers = [dns.RRHeader(
                name=query.name.name, type=query.type,
                payload=dns.Record_MX(10, self.lookup_result['ip'],
                                      ttl=5), auth=True)]

        return answers, [], []

    def _Record_SOA(self, query):
        d = self.lookup_result['domain']
        answers = [dns.RRHeader(
                name=query.name.name, type=dns.SOA,
                payload=dns.Record_SOA(mname=self.lookup_result['domain'],
                                       rname="hostmaster." % d,
                                       serial=int(time.time()),
                                       refresh=3600,
                                       ttl=5), auth=True)]

        return answers, [], []

    def _Record_Unknown(self, query):
        answers = [dns.RRHeader(
                name=query.name.name, type=query.type,
                payload=dns.UnknownRecord(query.name.name, ttl=5), auth=True)]

        return answers, [], []

    def _Record_NXDOMAIN(self, query):
        return [], [], []

    def _FigureOutSOAForQuery(self, query):
        tmp = query.name.name.split('.')
        domain = tmp[-2]+"."+tmp[-1]
        self.cursor.execute("SELECT domain, nameservers, contact
                            FROM domains WHERE domain='%s'" % domain)
        self.db.commit()
        self.lookup_result = self.cursor.fetchall()
        if self.cursor.rowcount > 0:
            self.lookup_result = self.lookup_result[0]
        else:
            self.lookup_result = ""

    def _doDynamicResponse(self, query):
        if query.type == dns.SOA:
            return self._Record_SOA(query)
        elif query.type == dns.NS:
            return self._Record_NS(query)
        elif query.type == dns.A:
            return self._Record_A(query)
        elif query.type == dns.AAAA:
            return self._Record_AAAA(query)
        elif query.type == dns.MX:
            return self._Record_MX(query)
        elif query.type == dns.CNAME:
            return self._Record_CNAME(query)
        else:
            return self._Record_Unknown(query)

    def query(self, query, timeout=None):
        self.ping_mysql()
        try:
            logging.info(query)
            if len(self._dynamicResponseRequired(query)) > 0:
                return defer.succeed(self._doDynamicResponse(query))
            else:
                if query.type == dns.MX:
                    return defer.succeed(self._Record_NXDOMAIN(query))

                return defer.succeed(([], [], []))
        except Exception, e:
            logging.error(e)
            return defer.fail(error.DomainError())

    def _src(self, query):
        return {'type': query.type,
                'src': self.peer_address.host.replace("::ffff:", ""),
                'name': query.name.name}

    def main(self):
        factory = DynDDServerFactory(
                  clients=[DynDDController(),
                           client.Resolver(resolv='/etc/resolv.conf')]
        )

        protocol = dns.DNSDatagramProtocol(controller=factory)

        reactor.listenUDP(53, protocol, interface="::0")
        reactor.listenTCP(53, factory)

        reactor.run()
