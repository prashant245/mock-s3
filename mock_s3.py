#!/usr/bin/env python
import argparse
import logging
import os
import socket
import urlparse
from BaseHTTPServer import BaseHTTPRequestHandler, HTTPServer
from SocketServer import ThreadingMixIn

from jinja2 import Environment, PackageLoader
from redis import StrictRedis

from actions import get_acl, get_item, list_buckets, ls_bucket
from file_store import FileStore


logging.basicConfig(level=logging.INFO)

if os.name != "nt":
    import fcntl
    import struct

    def get_interface_ip(ifname):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        return socket.inet_ntoa(fcntl.ioctl(s.fileno(), 0x8915, struct.pack('256s',
                                ifname[:15]))[20:24])
def get_lan_ip():
    ip = socket.gethostbyname(socket.gethostname())
    if ip.startswith("127.") and os.name != "nt":
        interfaces = [
            "eth0",
            "eth1",
            "eth2",
            "wlan0",
            "wlan1",
            "wifi0",
            "ath0",
            "ath1",
            "ppp0",
            ]
        for ifname in interfaces:
            try:
                ip = get_interface_ip(ifname)
                break
            except IOError:
                pass
    return ip        

class S3Handler(BaseHTTPRequestHandler):
    def do_GET(self):

        parsed_path = urlparse.urlparse(self.path)
        qs = urlparse.parse_qs(parsed_path.query, True)
        host = self.headers['host'].split(':')[0]
        path = parsed_path.path
        bucket_name = None
        item_name = None
        req_type = None

        mock_hostname = self.server.mock_hostname
        print host + "asdf" + path + "asfad" + mock_hostname

        if host != mock_hostname and mock_hostname in host:
            idx = host.index(mock_hostname)
            bucket_name = host[:idx-1]

        if path == '/' and not bucket_name:
            req_type = 'list_buckets'

        else:
            if not bucket_name:
                bucket_name, sep, item_name = path.strip('/').partition('/')
            else:
               item_name = path.strip('/')

            if not bucket_name:
                req_type = 'list_buckets'
            elif not item_name:
                req_type = 'ls_bucket'
            else:
                if 'acl' in qs and qs['acl'] == '':
                    req_type = 'get_acl'
                else:
                    req_type = 'get'

        if req_type == 'list_buckets':
            list_buckets(self)

        elif req_type == 'ls_bucket':
            ls_bucket(self, bucket_name, qs)

        elif req_type == 'get_acl':
            get_acl(self)

        elif req_type == 'get':
            get_item(self, bucket_name, item_name)

        else:
            self.wfile.write('%s: [%s] %s' % (req_type, bucket_name, item_name))

    def do_HEAD(self):
        return self.do_GET()

    def do_PUT(self):
        parsed_path = urlparse.urlparse(self.path)
        qs = urlparse.parse_qs(parsed_path.query, True)
        host = self.headers['host'].split(':')[0]
        path = parsed_path.path
        bucket_name = None
        item_name = None
        req_type = None

        mock_hostname = self.server.mock_hostname
        if host != mock_hostname and mock_hostname in host:
            idx = host.index(mock_hostname)
            bucket_name = host[:idx-1]

        if path == '/' and bucket_name:
            req_type = 'create_bucket'
        else:
            if not bucket_name:
                bucket_name, sep, item_name = path.strip('/').partition('/')
            else:
               item_name = path.strip('/')

            if not item_name:
                req_type = 'create_bucket'
            else:
                if 'acl' in qs and qs['acl'] == '':
                    req_type = 'set_acl'
                else:
                    req_type = 'store'

        if 'x-amz-copy-source' in self.headers:
            copy_source = self.headers['x-amz-copy-source']
            src_bucket, sep, src_key = copy_source.partition('/')
            req_type = 'copy'

        if req_type == 'create_bucket':
            self.server.file_store.create_bucket(bucket_name)
            self.send_response(200)

        elif req_type == 'store':
            bucket = self.server.file_store.get_bucket(bucket_name)
            if not bucket:
                # TODO: creating bucket for now, probably should return error
                bucket = self.server.file_store.create_bucket(bucket_name)
            item = self.server.file_store.store_item(bucket, item_name, self)
            self.send_response(200)
            self.send_header('ETag', '"%s"' % item.md5)

        elif req_type == 'copy':
            self.server.file_store.copy_item(src_bucket, src_key, bucket_name, item_name, self)
            self.send_response(200)

        self.send_header('Content-Type', 'text/xml')
        self.end_headers()


class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    def set_file_store(self, file_store):
        self.file_store = file_store

    def set_mock_hostname(self, mock_hostname):
        self.mock_hostname = mock_hostname

    def set_pull_from_aws(self, pull_from_aws):
        self.pull_from_aws = pull_from_aws

    def set_template_env(self, env):
        self.env = env


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='A Mock-S3 server.')
    parser.add_argument('--hostname', dest='hostname', action='store',
                        help='Hostname to listen on.')
    parser.add_argument('--port', dest='port', action='store',
                        default=10001, type=int,
                        help='Port to run server on.')
    parser.add_argument('--root', dest='root', action='store',
                        default='%s/s3store' % os.environ['HOME'],
                        help='Defaults to $HOME/s3store.')
    parser.add_argument('--pull-from-aws', dest='pull_from_aws', action='store_true',
                        default=False,
                        help='Pull non-existent keys from aws.')
    args = parser.parse_args()

    redis_client = StrictRedis()

    hostname = None;

    if args.hostname is None :
        hostname=get_lan_ip();
        print "Binding to lan ip-" + hostname;
    else :
        hostname=args.hostname;
        print "Binding to provided ip-" + hostname;

    server = ThreadedHTTPServer((hostname, args.port), S3Handler)
    server.set_file_store(FileStore(args.root, redis_client))
    server.set_mock_hostname(args.hostname)
    server.set_pull_from_aws(args.pull_from_aws)
    server.set_template_env(Environment(loader=PackageLoader('mock_s3', 'templates')))

    print 'Starting server, use <Ctrl-C> to stop'
    server.serve_forever()
