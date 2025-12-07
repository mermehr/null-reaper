#!/usr/bin/env python3

"""
null-reaper.py: A specialized Active Directory enumeration tool.

This tool is designed for quick, multi-protocol enumeration of Active Directory
environments, specifically targeting low-hanging fruit and misconfigurations
like anonymous null sessions. It combines LDAP, SAMR, and SMB enumeration
with active vulnerability testing (e.g., AS-REP Roasting) to provide a fast,
high-signal overview of a target Domain Controller.

mermehr...
"""

import sys
import argparse
import ipaddress
from impacket.krb5 import constants
from impacket.krb5.kerberosv5 import getKerberosTGT
from impacket.krb5.types import Principal
from impacket.dcerpc.v5.samr import UF_ACCOUNTDISABLE, DCERPCException
from impacket.dcerpc.v5 import transport, samr
from ldap3 import Server, Connection, ANONYMOUS, SUBTREE, BASE, ALL_ATTRIBUTES
from ldap3.core.exceptions import LDAPInvalidCredentialsResult
from impacket.smbconnection import SMBConnection, SessionError
from impacket.nmb import NetBIOSError
from impacket.smb3 import FILE_ATTRIBUTE_DIRECTORY
import datetime
import random
from impacket.krb5.asn1 import AS_REQ, KERB_PA_PAC_REQUEST, AS_REP, seq_set
from impacket.krb5.kerberosv5 import sendReceive, getKerberosTGT
from impacket.krb5 import types
from pyasn1.codec.der import decoder, encoder

# Windows error codes for session status.
STATUS_LOGON_FAILURE = 0xC000006D
STATUS_ACCESS_DENIED = 0xc0000022

# ANSI color codes for console output.
class Style:
    """ANSI color codes for console output."""
    RESET = '\033[0m'
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    CYAN = '\033[96m'

# Helper functions for standardized console output.
def print_info(message): print(f"[*] {message}")
def print_success(message): print(f"[+] {Style.GREEN}{message}{Style.RESET}")
def print_vulnerable(message): print(f"[+] {Style.RED}{message}{Style.RESET}")
def print_error(message): print(f"[!] {Style.YELLOW}{message}{Style.RESET}")
def print_fail(message): print(f"[-] {Style.RED}{message}{Style.RESET}") 
def print_secure(message): print(f"[-] {Style.GREEN}{message}{Style.RESET}") 

def check_smb_null_session(target_ip):
    """
    Checks for SMB null session, lists shares, and enumerates files.
    """
    SHARES_TO_SKIP = ('IPC$', 'PRINT$')
    SENSITIVE_EXTS = ('.xml', '.txt', '.ini', '.config', '.kdbx', '.toml')

    def list_smb_path(conn, share, path):
        r"""
        Recursively lists files and directories in a given path.
        'path' should be a directory, e.g., r'\' or r'\dir1\'
        """
        query_path = f"{path}*"
        try:
            files = conn.listPath(share, query_path)
            for f in files:
                filename = f.get_longname()
                is_dir = f.get_attributes() & FILE_ATTRIBUTE_DIRECTORY
                full_print_path = f"{path}{filename}"

                if filename in ('.', '..'):
                    continue

                if is_dir:
                    print(f"  > {Style.CYAN}{full_print_path}/{Style.RESET}")
                    list_smb_path(conn, share, f"{path}{filename}\\")
                else:
                    # Check for sensitive file extensions or keywords in the filename.
                    if filename.lower().endswith(SENSITIVE_EXTS) or 'password' in filename.lower():
                        print_vulnerable(f"  > {full_print_path}  (SENSITIVE FILE)")
                    else:
                        print(f"  > {full_print_path}")
        except SessionError as e:
            if e.getErrorCode() == STATUS_ACCESS_DENIED:
                print_error(f"  > {query_path} (Access Denied)")
            else:
                print_error(f"  > Error listing {query_path}: {e}")

    print_info("Checking for anonymous SMB login and share listing (port 445)...")
    for user in ['', '.']:
        conn = None
        try:
            conn = SMBConnection(target_ip, target_ip, timeout=5)
            conn.login(user, '')
            print_success(f"SUCCESS: Anonymous SMB login (user: '{user}') is ALLOWED!")

            # Immediately try to list shares to confirm permissions.
            shares = conn.listShares()
            print_info("Enumerating accessible shares...")
            
            for share in shares:
                share_name = share['shi1_netname'][:-1]
                if share_name in SHARES_TO_SKIP:
                    continue
                    
                print(f"\n--- Scanning Share: {Style.CYAN}{share_name}{Style.RESET} ---")
                list_smb_path(conn, share_name, "\\")
            
            return # Success, we listed shares and are done.

        except SessionError as e:
            if e.getErrorCode() == STATUS_ACCESS_DENIED:
                print_error(f"Login with user '{user}' OK, but share listing is DENIED. Trying next user...")
            elif e.getErrorCode() == STATUS_LOGON_FAILURE:
                pass # This user failed to log in, loop will try the next.
            else:
                print_error(f"SMB Error with user '{user}': {e}")
                break # A non-login/access error occurred, stop trying.
        except (ConnectionRefusedError, NetBIOSError):
            print_error(f"Error connecting to SMB on {target_ip} (Connection refused or host not found)")
            return # Can't connect at all, no point in trying other users.
        except Exception as e:
            print_error(f"An unexpected error occurred with SMB on {target_ip}: {e}")
            return
        finally:
            if conn:
                try:
                    conn.logoff()
                except SessionError as e:
                    # Ignore error if the session was already deleted by the server
                    if e.getErrorCode() != 0xc0000203: # STATUS_USER_SESSION_DELETED
                        raise
    
    print_fail("FAILED: Anonymous SMB login is NOT allowed or no user could list shares.")

def query_ldap_info(target_ip):
    """
    Checks for anonymous LDAP bind and queries for domain info, active users,
    and potential Kerberoasting targets (users with SPNs).
    """
    print_info("Checking for anonymous LDAP bind (port 389)...")
    server = Server(target_ip, get_info=ALL_ATTRIBUTES)
    conn = None
    domain_dn = None
    user_list = []

    try:
        conn = Connection(server, authentication=ANONYMOUS, auto_bind=True)
        print_success("SUCCESS: Anonymous LDAP bind is ALLOWED!")
        print_info("Querying Domain Controller information...")

        try:
            domain_attrs = [
                'defaultNamingContext',
                'dnsHostName',
                'serverName',
                'domainControllerFunctionality',
                'forestFunctionality',
                'domainFunctionality',
                'namingContexts'
            ]
            
            conn.search(search_base='', 
                        search_filter='(objectClass=*)', 
                        search_scope=BASE, 
                        attributes=domain_attrs)
            
            if not conn.entries:
                print_error("Could not retrieve domain info from RootDSE.")
                return None, []
            
            domain_info = conn.entries[0]
            
            if 'defaultNamingContext' in domain_info:
                domain_dn = domain_info.defaultNamingContext.value
                print(f"  - {Style.CYAN}Domain DN:{Style.RESET} {domain_dn}")
            else:
                print_error("Could not retrieve defaultNamingContext. Aborting LDAP enum.")
                return None, []

            for attr in domain_attrs:
                if attr == 'defaultNamingContext': continue # Already printed  # noqa: E701
                if attr in domain_info:
                    value = domain_info[attr].value
                    attr_formatted = ' '.join(word.capitalize() for word in attr.replace('Functionality', ' Func Level').split())
                    if isinstance(value, list):
                        print(f"  - {Style.CYAN}{attr_formatted}:{Style.RESET}")
                        for item in value:
                            print(f"    - {item}")
                    else:
                        print(f"  - {Style.CYAN}{attr_formatted}:{Style.RESET} {value}")

            # --- 1. Filter for active, non-system user accounts ---
            print_info("Querying for active, non-system user accounts...")
            real_users_filter = f'(& (objectClass=person) (!(objectClass=computer)) (!(userAccountControl:1.2.840.113556.1.4.803:={UF_ACCOUNTDISABLE})) (!(sAMAccountName=HealthMailbox*)) )'

            conn.search(search_base=domain_dn,
                        search_filter=real_users_filter,
                        search_scope=SUBTREE,
                        attributes=['sAMAccountName', 'description'],
                        size_limit=0) # No limit on results

            print_success("Found active users via LDAP:")
            if conn.entries:
                for entry in conn.entries:
                    username = entry.sAMAccountName.value
                    desc = entry.description.value or 'N/A'
                    if username:
                        user_list.append(username)
                        print(f"{Style.YELLOW}{username:<25}{Style.RESET} Description: {desc}")
            else:
                print("  No active users found with this filter.")

            # --- 2. Filter for SPN Targets (Kerberoasting) ---
            print_info("Querying for users with Service Principal Names (SPNs)...")
            # We use sAMAccountName=krbtgt because krbtgt is a user, not an objectClass
            spn_filter = '(&(objectClass=user)(servicePrincipalName=*)(!(sAMAccountName=krbtgt)))'

            conn.search(search_base=domain_dn,
                        search_filter=spn_filter,
                        search_scope=SUBTREE,
                        attributes=['sAMAccountName', 'servicePrincipalName'],
                        size_limit=0)

            if conn.entries:
                print_vulnerable("Found users with SPNs (Potential Kerberoast Targets):")
                for entry in conn.entries:
                    username = entry.sAMAccountName.value
                    # SPNs are usually a list, we just grab the first one for display
                    spns = entry.servicePrincipalName.value
                    spn_display = spns[0] if isinstance(spns, list) else spns
                    
                    print(f"  > {Style.RED}{username:<25}{Style.RESET} SPN: {spn_display}...")
            else:
                print_secure("No users with SPNs found via anonymous LDAP.")

            # --- 3. Filter for High-Value Servers (DCs, Exchange, etc) ---
            print_info("Querying for high-value Server objects...")
            
            # Find computers running a "Server" OS (filters out workstations)
            server_filter = '(&(objectClass=computer)(operatingSystem=*Server*))'

            conn.search(search_base=domain_dn,
                        search_filter=server_filter,
                        search_scope=SUBTREE,
                        attributes=['sAMAccountName', 'operatingSystem', 'dNSHostName'],
                        size_limit=0)

            if conn.entries:
                print_success("Found Server Objects:")
                for entry in conn.entries:
                    name = entry.sAMAccountName.value
                    os = entry.operatingSystem.value or 'N/A'
                    dns = entry.dNSHostName.value or 'N/A'
                    print(f"  > {Style.CYAN}{name:<20}{Style.RESET} OS: {os} ({dns})")
            else:
                print_info("No Server objects found via anonymous LDAP.")

            return domain_dn, user_list

        except Exception as e:
            print_error(f"Error during LDAP enumeration: {e}")
            return domain_dn, user_list # Return what we have so far

    except LDAPInvalidCredentialsResult:
        print_fail("FAILED: Anonymous LDAP bind is NOT allowed. (Invalid Credentials)")
    except ConnectionRefusedError:
        print_error(f"Error connecting to LDAP on {target_ip} (Connection refused)")
    except Exception as e:
        print_error(f"An unexpected error occurred with LDAP on {target_ip}")
        print(f"    Details: {e}")
    finally:
        if conn:
            conn.unbind()

    return domain_dn, user_list

def enumerate_users_samr(target_ip):
    """
    Enumerate all domain users via the SAMR RPC interface.
    Tries both '' and '.' as usernames for anonymous auth.
    """
    print_info("Enumerating all domain users via SAMR...")
    
    for user in ['', '.']:
        try:
            string_binding = r'ncacn_np:%s[\pipe\samr]' % target_ip
            rpc_transport = transport.DCERPCTransportFactory(string_binding)
            rpc_transport.set_dport(445)
            rpc_transport.set_credentials(user, '')
            rpc_transport.set_connect_timeout(5.0)
            
            print_info(f"Attempting SAMR enum with user: '{user}'")
            user_list = perform_samr_dance(rpc_transport, target_ip)
            if user_list:
                return user_list # Success, return the found users.
        except (DCERPCException, SessionError) as e:
            # Catch both RPC and SMB session errors that indicate access denied.
            if 'STATUS_ACCESS_DENIED' in str(e):
                print_error(f"Login with user '{user}' OK, but SAMR access is DENIED. Trying next user...")
                continue # Try the next user.
            elif e.getErrorCode() != STATUS_LOGON_FAILURE:
                print_error(f"SMB Error during SAMR enum: {e}")
                return [] # A non-login error occurred.
        except (ConnectionRefusedError, NetBIOSError):
            print_error(f"Error connecting to RPC/SAMR on {target_ip} (Connection refused or host not found)")
            return []
        except Exception as e:
            print_error(f"An unexpected error occured with SAMR enumeration: {e}")
            return []
    
    print_fail("FAILED: Anonymous SAMR enumeration is NOT allowed or no user had permissions.")
    return []

def perform_samr_dance(rpc_transport, target_ip):
    """
    A helper function to perform the SAMR enumeration steps.
    """
    user_list = []
    JUNK_PREFIXES = ('$', 'SM_', 'HealthMailbox', 'DefaultAccount', 'Guest', 'Administrator', 'krbtgt')
    
    rpc_transport.connect()
    dce = rpc_transport.get_dce_rpc()
    dce.bind(samr.MSRPC_UUID_SAMR)

    # Connect to the SAMR service and get a server handle.
    resp = samr.hSamrConnect(dce, serverName=f'\\\\{target_ip}', desiredAccess=samr.MAXIMUM_ALLOWED) 
    server_handle = resp['ServerHandle']
    
    resp = samr.hSamrEnumerateDomainsInSamServer(dce, server_handle)
    domain_name = None
    for domain in resp['Buffer']['Buffer']:
        if domain['Name'] != 'Builtin':
            domain_name = domain['Name']
            break
    
    if not domain_name:
        print_error("Could not find a non-Builtin domain via SAMR.")
        dce.disconnect()
        return []
    
    # Open the domain and get a handle.
    resp = samr.hSamrLookupDomainInSamServer(dce, server_handle, domain_name)
    domain_sid = resp['DomainId']
    resp = samr.hSamrOpenDomain(dce, server_handle, desiredAccess=samr.MAXIMUM_ALLOWED, domainId=domain_sid)
    domain_handle = resp['DomainHandle']
    
    # Enumerate the users in the domain.
    resp = samr.hSamrEnumerateUsersInDomain(dce, domain_handle)

    print_success("Found users via SAMR:")
    for user in resp['Buffer']['Buffer']:
        username = user['Name']
        rid = user['RelativeId']

        # Filter out common junk/system accounts.
        if not username.startswith(JUNK_PREFIXES):
            print(f"{Style.YELLOW}{username:<25}{Style.RESET} (RID: {hex(rid)})")
            user_list.append(username)
    
    dce.disconnect()
    if user_list:
        print_info(f"SAMR enumeration complete. Found {len(user_list)} non-junk users.")
        
    return user_list

def check_asrep_roastable_users(target_ip, domain_dn, user_list):
    """
    Checks for the AS-REP Roasting vulnerability. This occurs when a user account
    does not require Kerberos pre-authentication, allowing an attacker to request
    an encrypted portion of the user's credentials and crack it offline.
    """
    print_info("Checking for AS-REP Roastable users...")
    domain_name = domain_dn.replace("DC=", "").replace(",", ".")
    found_roastable = False

    for username in user_list:
        try:
            princ = Principal(username, type=constants.PrincipalNameType.NT_PRINCIPAL.value)
            # Attempt to get a TGT without providing a password.
            getKerberosTGT(princ,
                           '',                # Empty password
                           domain_name,       # Domain (e.g., example.local)
                           '',                # Empty lm_hash
                           '',                # Empty nt_hash
                           None,              # No AES key
                           kdcHost=target_ip)  # The DC's IP

            # If getKerberosTGT succeeds with an empty password, the account has a blank password.
            print_vulnerable(f"VULNERABLE: '{username}' has an EMPTY password!")
            found_roastable = True

        except Exception as e:
            error_string = str(e)

            # This error indicates pre-authentication is disabled (AS-REP Roastable).
            if "SessionKeyDecryptionError" in error_string or "ciphertext integrity failure" in error_string:
                print_vulnerable(f"VULNERABLE: User '{username}' is AS-REP Roastable! (Ticket available)")
                found_roastable = True
            elif "KDC_ERR_PREAUTH_REQUIRED" in error_string:
                pass # This is the expected, secure case.
            elif "KDC_ERR_PREAUTH_FAILED" in error_string:
                # This means pre-auth is required, and our attempt with an empty password failed. Secure.
                print_error(f"User '{username}' requires pre-authentication (PREAUTH_FAILED). Not roastable.")
            elif "KDC_ERR_C_PRINCIPAL_UNKNOWN" in error_string:
                pass # User from SAMR might not be in KDC.
            else:
                print_error(f"Kerberos error for '{username}': {e}")
    
    if not found_roastable:
        print_secure("No AS-REP roastable users found.")

def main():
    """
    Main function to parse arguments and run scans.
    """
    parser = argparse.ArgumentParser(
        description="A specialized, multi-protocol AD Enumeration Tool for null sessions.",
        epilog=f"""
    Examples:
      Scan all modules (default):
        {Style.CYAN}python %(prog)s target{Style.RESET}

      Scan only for open SMB shares and files:
        {Style.CYAN}python %(prog)s target smb{Style.RESET}

      Get DC info and enumerate users (LDAP + SAMR):
        {Style.CYAN}python %(prog)s target dcinfo{Style.RESET}

      Enumerate users and actively test for AS-REP Roasting:
        {Style.CYAN}python %(prog)s target roast{Style.RESET}
    """,
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    parser.add_argument("target", help="The target IP address.")
    parser.add_argument("module", 
                        help="The module to run (smb, dcinfo, roast). Scans all if omitted.", 
                        nargs='?', # Makes it optional
                        default='all') # Default value if not provided
    
    args = parser.parse_args()

    try:
        # Use the ipaddress library to validate the input.
        ipaddress.ip_address(args.target)
    except ValueError:
        print_error(f"Invalid target IP address: {args.target}")
        parser.print_help(sys.stderr)
        sys.exit(1)
        
    module_to_run = args.module.lower()
    target_ip = args.target
    KNOWN_MODULES = ['all', 'smb', 'dcinfo', 'roast']

    if module_to_run not in KNOWN_MODULES:
        print_error(f"Unknown module '{module_to_run}'. Valid modules: {', '.join(KNOWN_MODULES)}")
        parser.print_help(sys.stderr)
        sys.exit(1)

    def print_section_header(title):
        print("\n" + "=" * 60)
        print(f" {title.upper()} ".center(60, "="))
        print("=" * 60 + "\n")

    print_section_header(f"Starting Scan on {target_ip} (Module: {module_to_run.upper()})")

    # --- Module Execution ---

    if module_to_run in ['all', 'smb']:
        print_section_header("SMB Enumeration")
        check_smb_null_session(target_ip)

    # The 'dc' and 'roast' modules both need to enumerate users first.
    if module_to_run in ['all', 'dcinfo', 'roast']:
        print_section_header("LDAP User & Domain Enumeration")
        found_domain_dn, ldap_users = query_ldap_info(target_ip)

        print_section_header("SAMR User Enumeration")
        samr_users = enumerate_users_samr(target_ip)

        master_user_set = set(ldap_users) | set(samr_users)

        # The 'roast' module continues to the AS-REP check.
        if module_to_run in ['all', 'roast']:
            print_section_header("AS-REP Roasting Check")
            if not master_user_set:
                print_info("No users found via LDAP or SAMR. Skipping AS-REP check.")
            elif not found_domain_dn:
                print_error("Cannot run AS-REP roast check: Domain DN not found (LDAP check failed).")
            else:
                check_asrep_roastable_users(target_ip, found_domain_dn, list(master_user_set))

    print_section_header("Scan Complete")

if __name__ == "__main__":
    main()