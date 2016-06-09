# Copyright 2016, Manito Networks, LLC. All rights reserved
#
# Last modified 6/9/2016

import time

def init():
	global dns_cache
	dns_cache = {}
	dns_cache["Records"] = {}
	dns_cache["Prune"] = int(time.time() + 1800)