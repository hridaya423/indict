"""Planted vulns for smoke tests: sqli + pickle deser + traversal."""
import os, pickle, sqlite3, yaml

def get_user(name):
    conn = sqlite3.connect(":memory:")
    return conn.execute("SELECT * FROM u WHERE n = '%s'" % name).fetchall()

def load_blob(data):
    return pickle.loads(data)  # RCE on attacker bytes

def load_conf(text):
    return yaml.load(text, Loader=yaml.Loader)  # unsafe loader

def read_upload(fname):
    return open("/uploads/" + fname).read()  # path traversal

def run_tool(cmd):
    os.system("tool " + cmd)  # cmd injection
