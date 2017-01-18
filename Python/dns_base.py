# Copyright (c) 2017, Manito Networks, LLC
# All rights reserved.

import time

def init():
	global dns_cache
	dns_cache = {}
	dns_cache["Records"] = {}
	dns_cache["Prune"] = int(time.time() + 1800)

	global second_level_domains
	second_level_domains = {
	"co.id",
	"co.in",
	"co.jp",
	"co.nz",
	"co.uk",
	"co.za",
	"com.ar",
	"com.au",
	"com.bn",
	"com.br",
	"com.cn",
	"com.gh",
	"com.hk",
	"com.mx",
	"com.sg",
	"edu.au",
	"net.au",
	"net.il",
	"org.au"
	}