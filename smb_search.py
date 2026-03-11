import argparse
import multiprocessing
import os
import re
from collections import defaultdict
from impacket.smbconnection import SMBConnection, SessionError
from impacket.smb3structs import FILE_READ_DATA

# Fixed configs
keywords = ['password', 'login', 'username']
ad_accounts = ['admin', 'enterpriseadmin', 'domainadmin']
false_positive_exts = ['.js', '.html', '.css', '.json']
max_depth = 5
pool_size = 4

def search_share(args):
    ip, shares, username, password, domain, verbose = args
    hits = []
    conn = None
    try:
        # Pre-auth check: Try login and list root once for the IP
        conn = SMBConnection(ip, ip, sess_port=445)
        conn.login(username, password, domain)
        if verbose:
            hits.append(f"VERBOSE: Auth success on {ip}")
        
        for share in shares:
            try:
                tree = conn.connectTree(share)
                if verbose:
                    hits.append(f"VERBOSE: Connected to {ip}:{share}")

                def recurse(path, depth=0):
                    if depth > max_depth:
                        return
                    try:
                        files = conn.listPath(share, path, password='')
                        for f in files:
                            if f.is_directory():
                                if f.get_longname() not in ['.', '..']:
                                    recurse(os.path.join(path, f.get_longname() + '\\'), depth + 1)
                            else:
                                fname = f.get_longname().lower()
                                full_path = os.path.join(path, fname).replace('\\', '/')
                                # Filename check
                                for kw in keywords + ad_accounts:
                                    if kw in fname:
                                        hits.append(f"FILENAME HIT: {full_path} (keyword: {kw})")
                                        break
                                # Content check
                                ext = os.path.splitext(fname)[1].lower()
                                if ext not in false_positive_exts:
                                    try:
                                        with conn.openFile(share, full_path, FILE_READ_DATA) as fd:
                                            content = fd.read().decode('utf-8', errors='ignore').lower()
                                            for kw in keywords + ad_accounts:
                                                pattern = re.compile(rf'{re.escape(kw)}\s*[:=]\s*[^ \t\n\r\f\v]+')
                                                matches = pattern.findall(content)
                                                if matches:
                                                    snippet = matches[0][:50]
                                                    hits.append(f"CONTENT HIT: {full_path} (keyword: {kw}, snippet: {snippet})")
                                                    break
                                    except SessionError as se:
                                        if verbose:
                                            hits.append(f"VERBOSE: Skip unreadable file {full_path} on {ip}:{share}: {str(se)}")
                    except SessionError as se:
                        hits.append(f"ERROR on {ip}:{share} (dir access): {str(se)}")

                recurse('')
            except SessionError as se:
                hits.append(f"ERROR on {ip}:{share} (connect tree): {str(se)}")
            except Exception as e:
                hits.append(f"ERROR on {ip}:{share}: {str(e)}")
    except SessionError as se:
        # Early auth fail: Skip all shares on this IP
        hits.append(f"AUTH FAIL on {ip}: {str(se)} - SKIPPING all shares on this IP")
    except Exception as e:
        hits.append(f"ERROR on {ip}: {str(e)} - SKIPPING")
    finally:
        if conn:
            conn.logoff()
    return hits

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='SMB Share Searcher')
    parser.add_argument('--username', required=True)
    parser.add_argument('--password', required=True)
    parser.add_argument('--domain', required=True)
    parser.add_argument('--targets_file', required=True)
    parser.add_argument('--verbose', action='store_true', help='Enable verbose logging')
    args = parser.parse_args()

    # Read and group by IP
    ip_to_shares = defaultdict(list)
    with open(args.targets_file, 'r') as f:
        for line in f:
            if line.strip():
                ip, share = line.strip().split(':')
                ip_to_shares[ip].append(share)

    # Prepare args: One per IP group
    pool_args = [(ip, shares, args.username, args.password, args.domain, args.verbose) for ip, shares in ip_to_shares.items()]

    with multiprocessing.Pool(pool_size) as pool:
        results = pool.map(search_share, pool_args)
    for result in results:
        for hit in result:
            print(hit)
