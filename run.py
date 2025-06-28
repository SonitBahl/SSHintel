from honeypot.main import honeypot
import argparse

parser = argparse.ArgumentParser(description="SSH Honeypot CLI")
parser.add_argument('--host', default='0.0.0.0')
parser.add_argument('--port', type=int, default=2222)
parser.add_argument('--username')
parser.add_argument('--password')
parser.add_argument('--tarpit', action='store_true')

args = parser.parse_args()

honeypot(args.host, args.port, args.username, args.password, args.tarpit)