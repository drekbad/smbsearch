import multiprocessing
import os
import re
from impacket.smbconnection import SMBConnection, SessionError
from impacket.smb3structs import FILE_READ_DATA

# Customize these
targets = ['IP1:share1', 'IP2:share2']  # e.g., ['192.168.1.10:Data', '192.168.1.20:Files']
keywords = ['password', 'login', 'username']
ad_accounts = ['admin', 'enterpriseadmin', 'domainadmin']  # Add your key AD names
false_positive_exts = ['.js', '.html', '.css', '.json']  # Skip likely FP files
username = 'your_provisioned_username'  # Or '' for anon if applicable
password = 'your_provisioned_password'
domain = 'domain.local'
max_depth = 5  # Limit recursion to avoid infinite loops
pool_size = 4  # Adjust based on your CPU/network

def search_share(target):
    ip, share = target.split(':')
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
                                break  # Early break if hit
                        # Content check (only if not FP ext and read access)
                        ext = os.path.splitext(fname)[1].lower()
                        if ext not in false_positive_exts:
                            try:
                                with conn.openFile(share, full_path, FILE_READ_DATA) as fd:
                                    content = fd.read().decode('utf-8', errors='ignore').lower()
                                    for kw in keywords + ad_accounts:
                                        # Smart filter: kw followed by : or = with value (not just isolated word)
                                        pattern = re.compile(rf'{re.escape(kw)}\s*[:=]\s*[^ \t\n\r\f\v]+')
                                        matches = pattern.findall(content)
                                        if matches:
                                            snippet = matches[0][:50]  # Truncate for log
                                            hits.append(f"CONTENT HIT: {full_path} (keyword: {kw}, snippet: {snippet})")
                                            break
                            except SessionError:
                                pass  # Skip unreadable files
            except SessionError:
                pass  # Skip inaccessible dirs

        recurse('')
    except Exception as e:
        hits.append(f"ERROR on {target}: {str(e)}")
    finally:
        if conn:
            conn.logoff()
    return hits

if __name__ == '__main__':
    with multiprocessing.Pool(pool_size) as pool:
        results = pool.map(search_share, targets)
    for result in results:
        for hit in result:
            print(hit)
