# Copyright (c) 2016, Manito Networks, LLC
# All rights reserved.

import sys, struct
from xdrlib import Unpacker
from sflow_parsers import * # Functions to parse headers and format numbers

# Flow Sample [0,1] 
def flow_sample(unparsed_data:"XDR Data"):
	sample_cache = {}
	sample_cache["Sequence"] = unparsed_data.unpack_uint() # Sequence number
	source_id_type_index = source_type_index_parser(unparsed_data.unpack_uint()) # Parse Source and Index types
	sample_cache["Source Type"] = source_id_type_index[0] # Source type
	sample_cache["Source Index"] = source_id_type_index[1] # Source index
	sample_cache["Sampling Rate"] = unparsed_data.unpack_uint() # Sample rate * n packets
	sample_cache["Sample Pool"] = unparsed_data.unpack_uint() # Sample pool of total sampled packets
	sample_cache["Drops"] = unparsed_data.unpack_uint() # Unsampled
	sample_cache["Input SNMP Index"] = unparsed_data.unpack_uint() # Input SNMP interface index number
	sample_cache["Output SNMP Index"] = unparsed_data.unpack_uint() # Output SNMP interface index number
	sample_cache["Record Count"] = unparsed_data.unpack_uint() # Records in the sample
	return sample_cache

# Counter Sample [0,2] 
def counter_sample(unparsed_data:"XDR Data"):
	sample_cache = {}
	sample_cache["Sequence"] = unparsed_data.unpack_uint() # Sequence number
	source_id_type_index = source_type_index_parser(unparsed_data.unpack_uint()) # Parse Source and Index types
	sample_cache["Source ID Type"] = source_id_type_index[0] # Source ID Type
	sample_cache["Source ID Index"] = source_id_type_index[1] # Source ID Index
	sample_cache["Record Count"] = unparsed_data.unpack_uint() # Counter Records (num)
	return sample_cache

# Expanded Flow Sample [0,3] 
def expanded_flow_sample(unparsed_data:"XDR Data"):
	sample_cache = {}
	sample_cache["Sequence"] = unparsed_data.unpack_uint() # Sequence number
	sample_cache["Source Type"] = unparsed_data.unpack_uint() # Source type
	sample_cache["Source Index"] = unparsed_data.unpack_uint() # Source index
	sample_cache["Sampling Rate"] = unparsed_data.unpack_uint() # Sample rate * n packets
	sample_cache["Sample Pool"] = unparsed_data.unpack_uint() # Sample pool of total sampled packets
	sample_cache["Drops"] = unparsed_data.unpack_uint() # Unsampled
	sample_cache["Input Interface Format"] = unparsed_data.unpack_uint() # Input interface format
	sample_cache["Input Interface Value"] = unparsed_data.unpack_uint() # Input interface value
	sample_cache["Output Interface Format"] = unparsed_data.unpack_uint() # Output interface format
	sample_cache["Output Interface Value"] = unparsed_data.unpack_uint() # Output interface value
	sample_cache["Record Count"] = unparsed_data.unpack_uint() # Records in the sample
	return sample_cache

# Expanded Flow Sample [0,4] 
def expanded_counter_sample(unparsed_data:"XDR Data"):
	sample_cache = {}
	sample_cache["Sequence"] = unparsed_data.unpack_uint() # Sequence number
	sample_cache["Source ID Type"] = unparsed_data.unpack_uint() # Source ID Type
	sample_cache["Source ID Index"] = unparsed_data.unpack_uint() # Source ID Index
	sample_cache["Record Count"] = unparsed_data.unpack_uint() # Counter Records (num)
	return sample_cache

# Pick Flow, Expanded Flow, Counter, Expanded Counter types to unpack
def sample_picker(enterprise_format:list,unpacked_sample_data:"XDR Data"):
	if enterprise_format == [0,1]:
		return flow_sample(unpacked_sample_data) # Parse the sample header
	elif enterprise_format == [0,2]:
		return counter_sample(unpacked_sample_data) # Parse the sample header
	elif enterprise_format == [0,3]:
		return expanded_flow_sample(unpacked_sample_data) # Parse the sample header
	elif enterprise_format == [0,4]:
		return expanded_counter_sample(unpacked_sample_data) # Parse the sample header
	else:
		return False