import subprocess
import requests
import sys
import os
import shlex
import re
import argparse


LAST_IP_FILE = '.last-ipv4'
DOCEAN_API_URL = 'https://api.digitalocean.com/v2/domains/{domain}/records'


def save_ip(ipv4):
    with open(LAST_IP_FILE, 'w+') as f:
        f.write(ipv4)


def update_dns(args, ipv4):
    res = requests.get(
        DOCEAN_API_URL.format(domain=args.domain),
        headers=dict(Authorization='Bearer {}'.format(args.api_token))
    )
    for record in res.json()['domain_records']:
        if record['type'] == 'A' and record['name'] == args.subdomain:
            print('Updating DigitalOcean DNS Record {}'.format(record['id']))
            res = requests.put(
                '{}/{}'.format(
                    DOCEAN_API_URL.format(domain=args.domain),
                    record['id']
                ),
                headers=dict(Authorization='Bearer {}'.format(args.api_token)),
                json=dict(data=ipv4)
            )
            if res.status_code != 200:
                print('An error occurred while updating the DNS record.')


def main():
    parser = argparse.ArgumentParser(description='Updates DigitalOcean DNS Record with current IP.')
    parser.add_argument('--api-token', help='DigitalOcean API Token', required=True)
    parser.add_argument('--domain', help='Domain Name', required=True)
    parser.add_argument('--subdomain', help='Subdomain Name', required=True)
    parser.add_argument('--force', help='Force update even if ip is unchanged.', action='store_true')

    args = parser.parse_args()

    cmd = 'dig @resolver1.opendns.com ANY -4 myip.opendns.com +short'
    stdout, stderr = subprocess.Popen(shlex.split(cmd), stdout=subprocess.PIPE).communicate()

    if stderr is not None:
        print('An error occurred while fetching current ip')
        print(stderr)
        sys.exit(1)

    ipv4 = stdout.decode('UTF-8').strip('\n')

    if not re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', ipv4):
        print('An invalid ip address was returned. {}'.format(ipv4))
        sys.exit(1)

    print('Current IP is {}'.format(ipv4))

    if not os.path.exists(LAST_IP_FILE):
        save_ip(ipv4)
        update_dns(args, ipv4)
    else:
        with open(LAST_IP_FILE, 'r') as f:
            if ipv4 not in f.readlines() or args.force:
                update_dns(args, ipv4)


if __name__ == '__main__':
    main()

