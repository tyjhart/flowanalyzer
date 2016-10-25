import sys
from xdrlib import Unpacker

# Generic Interface Counter (Enterprise 0, Format 1)
def gen_int_counter(data):
	sample_data = {}
	sample_data["ifIndex"] = int(data.unpack_uint())
	sample_data["ifType"] = int(data.unpack_uint())
	sample_data["ifSpeed"] = data.unpack_hyper()
	sample_data["ifDirection"] = int(data.unpack_uint())
	sample_data["ifStatus"] = int(data.unpack_uint())
	sample_data["ifInOctets"] = data.unpack_hyper()
	sample_data["ifInUcastPkts"] = int(data.unpack_uint())
	sample_data["ifInMulticastPkts"] = int(data.unpack_uint())
	sample_data["ifInBroadcastPkts"] = int(data.unpack_uint())
	sample_data["ifInDiscards"] = int(data.unpack_uint())
	sample_data["ifInErrors"] = int(data.unpack_uint())
	sample_data["ifInUnknownProtos"] = int(data.unpack_uint())
	sample_data["ifOutOctets"] = data.unpack_hyper()
	sample_data["ifOutUcastPkts"] = int(data.unpack_uint())
	sample_data["ifOutMulticastPkts"] = int(data.unpack_uint())
	sample_data["ifOutBroadcastPkts"] = int(data.unpack_uint())
	sample_data["ifOutDiscards"] = int(data.unpack_uint())
	sample_data["ifOutErrors"] = int(data.unpack_uint())
	sample_data["ifPromiscuousMode"] = int(data.unpack_uint()) 
	return sample_data

# Ethernet Interface Counters (Enterprise 0, Format 2)
def eth_int_counter(data):
	sample_data = {}
	sample_data["dot3StatsAlignmentErrors"] = int(data.unpack_uint())
	sample_data["dot3StatsFCSErrors"] = int(data.unpack_uint())
	sample_data["dot3StatsSingleCollisionFrames"] = int(data.unpack_uint())
	sample_data["dot3StatsMultipleCollisionFrames"] = int(data.unpack_uint())
	sample_data["dot3StatsSQETestErrors"] = int(data.unpack_uint())
	sample_data["dot3StatsDeferredTransmissions"] = int(data.unpack_uint())
	sample_data["dot3StatsLateCollisions"] = int(data.unpack_uint())
	sample_data["dot3StatsExcessiveCollisions"] = int(data.unpack_uint())
	sample_data["dot3StatsInternalMacTransmitErrors"] = int(data.unpack_uint())
	sample_data["dot3StatsCarrierSenseErrors"] = int(data.unpack_uint())
	sample_data["dot3StatsFrameTooLongs"] = int(data.unpack_uint())
	sample_data["dot3StatsInternalMacReceiveErrors"] = int(data.unpack_uint())
	sample_data["dot3StatsSymbolErrors"] = int(data.unpack_uint())
	return sample_data

# Token Ring Counters (Enterprise 0, Format 3)
def token_ring_counter(data):
	sample_data = {}
	sample_data["dot5StatsLineErrors"] = int(data.unpack_uint())
	sample_data["dot5StatsACErrors"] = int(data.unpack_uint())
	sample_data["dot5StatsAbortTransErrors"] = int(data.unpack_uint())
	sample_data["dot5StatsInternalErrors"] = int(data.unpack_uint())
	sample_data["dot5StatsLostFrameErrors"] = int(data.unpack_uint())
	sample_data["dot5StatsReceiveCongestions"] = int(data.unpack_uint())
	sample_data["dot5StatsFrameCopiedErrors"] = int(data.unpack_uint())
	sample_data["dot5StatsTokenErrors"] = int(data.unpack_uint())
	sample_data["dot5StatsSoftErrors"] = int(data.unpack_uint())
	sample_data["dot5StatsHardErrors"] = int(data.unpack_uint())
	sample_data["dot5StatsSignalLoss"] = int(data.unpack_uint())
	sample_data["dot5StatsTransmitBeacons"] = int(data.unpack_uint())
	sample_data["dot5StatsRecoverys"] = int(data.unpack_uint())
	sample_data["dot5StatsLobeWires"] = int(data.unpack_uint())
	sample_data["dot5StatsBurstErrors"] = int(data.unpack_uint())
	sample_data["dot5StatsRemoves"] = int(data.unpack_uint())
	sample_data["dot5StatsSingles"] = int(data.unpack_uint())
	sample_data["dot5StatsFreqErrors"] = int(data.unpack_uint())
	return sample_data

# 100 BaseVG Interface Counters (Enterprise 0, Format 4)
def basevg_int_counter(data):
	sample_data = {}
	sample_data["dot12InHighPriorityFrames"] = int(data.unpack_uint())
	sample_data["dot12InHighPriorityOctets"] = data.unpack_hyper()
	sample_data["dot12InNormPriorityFrames"] = int(data.unpack_uint())
	sample_data["dot12InNormPriorityOctets"] = data.unpack_hyper()
	sample_data["dot12InIPMErrors"] = int(data.unpack_uint())
	sample_data["dot12InOversizeFrameErrors"] = int(data.unpack_uint())
	sample_data["dot12InDataErrors"] = int(data.unpack_uint())
	sample_data["dot12InNullAddressedFrames"] = int(data.unpack_uint())
	sample_data["dot12OutHighPriorityFrames"] = int(data.unpack_uint())
	sample_data["dot12OutHighPriorityOctets"] = data.unpack_hyper()
	sample_data["dot12TransitionIntoTrainings"] = int(data.unpack_uint())
	sample_data["dot12HCInHighPriorityOctets"] = data.unpack_hyper()
	sample_data["dot12HCInNormPriorityOctets"] = data.unpack_hyper()
	sample_data["dot12HCOutHighPriorityOctets"] = data.unpack_hyper()
	return sample_data

# VLAN Counters (Enterprise 0, Format 5)
def vlan_counter(data):
	sample_data = {}
	sample_data["vlan_id"] = int(data.unpack_uint())
	sample_data["octets"] = data.unpack_hyper()
	sample_data["ucastPkts"] = int(data.unpack_uint())
	sample_data["multicastPkts"] = int(data.unpack_uint())
	sample_data["broadcastPkts"] = int(data.unpack_uint())
	sample_data["discards"] = int(data.unpack_uint())
	return sample_data

# Processor Information (Enterprise 0, Format 1001)
def proc_info(data):
	sample_data = {}
	sample_data["5s cpu percentage"] = int(data.unpack_uint())
	sample_data["1m cpu percentage"] = int(data.unpack_uint())
	sample_data["5m cpu percentage"] = int(data.unpack_uint())
	sample_data["total memory"] = data.unpack_hyper()
	sample_data["free memory"] = data.unpack_hyper()
	return sample_data