#!/usr/bin/env python
from __future__ import division
from __future__ import print_function
import argparse
import logging
import sys
from binascii import unhexlify

from impacket import version
from impacket.examples import logger
from impacket.examples.utils import parse_credentials
from impacket.krb5 import constants
from impacket.krb5.kerberosv5 import getKerberosTGT
from impacket.krb5.types import Principal
import ldapdomaindump
import ldap3
from getpass import getpass

def TGT_size(options):
    domain, username, password = parse_credentials(options.credentials)
    userName = Principal(username, type=constants.PrincipalNameType.NT_PRINCIPAL.value)
    lmhash = ''
    nthash = ''
    tgt, cipher, oldSessionKey, sessionKey = getKerberosTGT(userName, password, domain, unhexlify(lmhash), unhexlify(nthash),requestPAC=True)
    tgt_2, cipher_2, oldSessionKey_2, sessionKey_2 = getKerberosTGT(userName, password, domain, unhexlify(lmhash), unhexlify(nthash),requestPAC=False)

    # # Print TGT
    # print (tgt)
    # print("_"*50)
    # print(tgt_2)

    TGT_size, TGT_size_2 = len(tgt),len(tgt_2)
    
    print("<"*2+"-"*22+" TGT Size"+"-"*22+'>'*2)
    print(f"[+] Length of TGT size with PAC: {TGT_size} \n")
    
    print(f"[+] Length of TGT size without PAC: {TGT_size_2} \n")
    
    if TGT_size == TGT_size_2:
        print( "[-] Not Vulnerable, PAC validated\n")
    else:
        print("[!] Possbily vulnerable to CVE-2021-42287. \n\n[+] Apply Patches")
    print("<"*3+"-"*51+'>'*3)

# helper functions ldap connection
def init_ldap_connection(target, tls_version, args, domain, username, password):
    user = '%s\\%s' % (domain, username)
    if tls_version is not None:
        use_ssl = True
        port = 636
        tls = ldap3.Tls(validate=ssl.CERT_NONE, version=tls_version)
    else:
        use_ssl = False
        port = 389
        tls = None
    ldap_server = ldap3.Server(target, get_info=ldap3.ALL, port=port, use_ssl=use_ssl, tls=tls)
    ldap_session = ldap3.Connection(ldap_server, user=user, password=password, authentication=ldap3.NTLM, auto_bind=True)

    return ldap_server, ldap_session

def init_ldap_session(args, domain, username, password):

    # if args.k:
    #     target = get_machine_name(args, domain)
    if args.dc_ip is not None:
        target = args.dc_ip
    else:
        target = domain
    return init_ldap_connection(target, None, args, domain, username, password)

## checking MachineAccountQuota
def Check_quota(options):
    domain, username, password = parse_credentials(options.credentials)
    dc_ip = options.dc_ip
    ldap_server, ldap_session = init_ldap_session(options, domain, username, password )
    cnf = ldapdomaindump.domainDumpConfig()
    cnf.basepath = None
    domain_dumper = ldapdomaindump.domainDumper(ldap_server, ldap_session, cnf)
    MachineAccountQuota = None

    # Get domain policy
    dd = domain_dumper.getDomainPolicy()
    for i in dd:
        MachineAccountQuota = int(str(i['ms-DS-MachineAccountQuota']))

    # print("<"*3+"-"*13+"Machine Account Quota "+"-"*13+'>'*3)
    print("<"+"-"*16+" Machine Account Quota "+"-"*16+">")
    # print(f'[-] Machine Account Quota  ')
    print(f'[+] MachineAccountQuota = {MachineAccountQuota} \n')

    #Conditional check
    if MachineAccountQuota < 0:
        print("[#] Not vulnerable  cannot proceed with Machine creation. \n")
    else:
        print("[!] Possible Attack Vector, can be exploited further. \n")

# Process command-line arguments.
if __name__ == '__main__':
    logger.init()
    print(version.BANNER)

    parser = argparse.ArgumentParser()

    
    parser.add_argument
    parser.add_argument('-debug', action='store_true', help='Turn DEBUG output ON')
    
    group = parser.add_argument_group('mandatory')
    ## hashes are currently not supported
    # group.add_argument('-hashes', action="store", metavar = "LMHASH:NTHASH", help='NTLM hashes, format is LMHASH:NTHASH')
    
    group.add_argument('-dc-ip', action='store',required=True, metavar="<IP address>",
                   help='IP of the domain controller to use. Useful if you can\'t translate the FQDN.'
                   'specified in the account parameter will be used')
    group.add_argument('-targetUser', action='store', required=True,metavar="<Target Username>", help='The target user to retrieve the PAC of')
    group.add_argument('credentials', action='store', help='domain/username[:password]. Valid domain credentials to use '
                                                       'for grabbing targetUser\'s PAC \n ')

    if len(sys.argv)==1:
        parser.print_help()
        sys.exit(1)

    options = parser.parse_args()

    domain, username, password = parse_credentials(options.credentials)
    target_user = options.targetUser
    dc_IP = options.dc_ip
    # print("<"*3+"-"*20+" Input Values "+"-"*20+'>'*3)
    print(f"[#] Input Values")
    print(f"domain : {domain} \nusername : {username} \npassword: {password} \ntarget_user: {target_user} \ndc_ip : {dc_IP}")

    if domain is None:
        domain = ''

    if password == '' and username != '' and options.hashes is None:
        password = getpass("Password:")

    if options.debug is True:
        logging.getLogger().setLevel(logging.DEBUG)
        # Print the Library's installation path
        logging.debug(version.getInstallationPath())
    else:
        logging.getLogger().setLevel(logging.INFO)

    try:
        print(f"\n[#] Initiating validations... \n")
        Check_quota(options)
        TGT_size(options)

    except Exception as e:
        if logging.getLogger().level == logging.DEBUG:
            import traceback
            traceback.print_exc()
        logging.error(str(e))
