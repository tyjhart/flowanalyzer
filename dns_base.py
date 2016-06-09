import time

def init():
	global dns_cache
	dns_cache = {}
	dns_cache["Records"] = {}
	dns_cache["Prune"] = int(time.time() + 1800)