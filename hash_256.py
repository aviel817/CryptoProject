import hashlib


def hash_256(string):
 return hashlib.sha256(string.encode('utf-8')).hexdigest()