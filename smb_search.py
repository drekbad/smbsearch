import argparse
import multiprocessing
import os
import re
from impacket.smbconnection import SMBConnection, SessionError
from impacket.smb3structs import FILE_READ_DATA

# Fixed configs (customize if needed)
keywords = ['password', 'login', 'username']
ad_accounts = ['admin', 'enterpriseadmin', 'domainadmin']  # Add your key AD names
false_positive_exts = ['.js', '.html', '.css', '.json']  # Skip likely FP files
max_depth = 5  # Limit recursion
pool_size = 4  # Adjust based on CPU/network

def search_share(args):
    ip, share, username, password, domain = args
    hits = []
    conn = None
    try:
        conn = SMBConnection(ip, ip, sess_port=445)
        conn.login(username, password, domain)
        tree = conn.connectTree(share)

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
                            except SessionError:
                                pass
            except SessionError:
                pass

        recurse('')
    except Exception as e:
        hits.append(f"ERROR on {ip}:{share}: {str(e)}")
    finally:
        if conn:
            conn.logoff()
    return hits

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='SMB Share Searcher')
    parser.add_argument('--username', required=True, help='Username for SMB login')
    parser.add_argument('--password', required=True, help='Password for SMB login')
    parser.add_argument('--domain', required=True, help='Domain for SMB login')
    parser.add_argument('--targets_file', required=True, help='File with IP:share lines')
    args = parser.parse_args()

    # Read targets from file
    with open(args.targets_file, 'r') as f:
        targets = [line.strip() for line in f if line.strip()]

    # Prepare args for each target
    pool_args = [(target.split(':')[0], target.split(':')[1], args.username, args.password, args.domain) for target in targets]

    with multiprocessing.Pool(pool_size) as pool:
        results = pool.map(search_share, pool_args)
    for result in results:
        for hit in result:
            print(hit)
