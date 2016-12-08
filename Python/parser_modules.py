# Copyright (c) 2016, Manito Networks, LLC
# All rights reserved.

class mac_address(object):
    import struct
    
    def __init__(self):
        
        # See the following for MAC OUI information:
        # http://www.iana.org/assignments/ethernet-numbers/ethernet-numbers.xhtml
        # https://tools.ietf.org/html/rfc7042
        mac_oui = {
        "005056": {"Vendor":"VMware",               "Type":"Virtualization"},
        "00005E": {"Vendor":"IANA",                 "Type":"Unicast"},
        "01000C": {"Vendor":"Cisco",                "Type":"Logical"},
        "01005E": {"Vendor":"IANA",                 "Type":"Multicast"},
        "0180C2": {"Vendor":"IEEE",                 "Type":"Logical"},
        "0A0027": {"Vendor":"Oracle",               "Type":"Virtualization"},
        "2C0E3D": {"Vendor":"Samsung",              "Type":"Physical"},
        "333300": {"Vendor":"IPv6",                 "Type":"Virtualization"},
        "48F8B3": {"Vendor":"Linksys",              "Type":"Physical"},
        "5855CA": {"Vendor":"Apple",                "Type":"Physical"},
        "74C63B": {"Vendor":"AzureWave Technology", "Type":"Physical"},
        "74D435": {"Vendor":"Giga-Byte Technology", "Type":"Physical"},
        "FFFFFF": {"Vendor":"Broadcast",            "Type":"Logical"}
        }

    # MAC passed as Python list, 6 elements
    def mac_parse(self,mac:list):
        """Parse MAC addresses passed as Python list(6) that has already been unpacked"""
        mac_list = []
        for mac_item in mac:
            mac_item_hex = hex(mac_item).replace('0x','') # Strip leading characters
            if len(mac_item_hex) == 1:
                mac_item_hex = str("0" + mac_item_hex) # Handle leading zeros and double-0's
            mac_list.append(mac_item_hex)
        parsed_mac = (':'.join(mac_list)).upper() # Format MAC as 00:11:22:33:44:AA
        parsed_mac_oui = (''.join(mac_list[0:3])).upper() # MAC OUI as 001122
        return (parsed_mac,parsed_mac_oui)

    # MAC passed as packed bytes
    def mac_packed_parse(self,packed_data:"Packed Data",pointer:int,field_size:int):
        """Parse MAC addresses passed as packed bytes that first need to be unpacked"""
        mac_list = []
        mac_objects = self.struct.unpack('!%dB' % field_size,packed_data[pointer:pointer+field_size])
        for mac_item in mac_objects:
            mac_item_hex = hex(mac_item).replace('0x','') # Strip leading characters
            if len(mac_item_hex) == 1:
                mac_item_hex = str("0" + mac_item_hex) # Handle leading zeros and double-0's
            mac_list.append(mac_item_hex)
        parsed_mac = (':'.join(mac_list)).upper() # Format MAC as 00:11:22:33:44:AA
        parsed_mac_oui = (''.join(mac_list[0:3])).upper() # MAC OUI as 001122
        return (parsed_mac,parsed_mac_oui)
    
    # MAC OUI formatted "001122"
    def mac_oui(self,mac_oui_num:str):
        """Get MAC OUI (vendor,type) based on an OUI number formatted as '0011AA'"""
        try:
            return (self.mac_oui[mac_oui_num]["Vendor"],self.mac_oui[mac_oui_num]["Type"])
        except NameError,KeyError:
            return False


# Class for parsing ICMP attributes like Type and Code
class icmp_parse(object):

    def __init__(self):

        # ICMP Types and corresponding Codes
        self.icmp_table = {
        0: {"Type":"Echo Reply","Codes": {0: "No Code"}}, 
        1: {"Type":"Unassigned"},
        2: {"Type":"Unassigned"},
        3: {
            "Type":"Destination Unreachable",
            "Codes": {
                0: "Net Unreachable",
                1: "Host Unreachable",
                2: "Protocol Unreachable",
                3: "Port Unreachable",
                4: "Fragmentation Needed and Don't Fragment was Set",
                5: "Source Route Failed",
                6: "Destination Network Unknown",
                7: "Destination Host Unknown",
                8: "Source Host Isolated",
                9: "Communication with Destination Network is Administratively Prohibited",
                10: "Communication with Destination Host is Administratively Prohibited",
                11: "Destination Network Unreachable for Type of Service",
                12: "Destination Host Unreachable for Type of Service",
                13: "Communication Administratively Prohibited ",
                14: "Host Precedence Violation",
                15: "Precedence cutoff in effect"
            }
        },
        4: {"Type":"Source Quench","Codes": {0: "No Code"}},
        5: {
            "Type":"Redirect",
            "Codes": {
                0: "Redirect Datagram for the Network",
                0: "Redirect Datagram for the Host",
                0: "Redirect Datagram for the Type of Service and Network",
                0: "Redirect Datagram for the Type of Service and Host"
            }
        },
        6: {
            "Type":"Alternate Host Address",
            "Codes": {
                0: "Alternate Address for Host"
            }
        }, 
        7: {"Type":"Unassigned"},
        8: {"Type":"Echo","Codes": {0: "No Code"}},
        9: {"Type":"Router Advertisement","Codes": {0: "No Code"}},
        10: {"Type":"Router Selection","Codes": {0: "No Code"}},
        11: {
            "Type":"Time Exceeded",
            "Codes": {
                0: "Time to Live exceeded in Transit",
                1: "Fragment Reassembly Time Exceeded"
            }
        }, 
        12: {
            "Type":"Parameter Problem",
            "Codes": {
                0: "Pointer indicates the error",
                1: "Missing a Required Option",
                2: "Bad Length"
            }
        },
        13: {"Type":"Timestamp","Codes": {0: "No Code"}},
        14: {"Type":"Timestamp Reply","Codes": {0: "No Code"}},
        15: {"Type":"Information Request","Codes": {0: "No Code"}},
        16: {"Type":"Information Reply","Codes": {0: "No Code"}},
        17: {"Type":"Address Mask Request","Codes": {0: "No Code"}},
        18: {"Type":"Address Mask Reply","Codes": {0: "No Code"}},
        19: {"Type":"Reserved"},
        20: {"Type":"Reserved"},
        21: {"Type":"Reserved"},
        22: {"Type":"Reserved"},
        23: {"Type":"Reserved"},
        24: {"Type":"Reserved"},
        25: {"Type":"Reserved"},
        26: {"Type":"Reserved"},
        27: {"Type":"Reserved"},
        28: {"Type":"Reserved"},
        29: {"Type":"Reserved"},
        30: {"Type":"Traceroute"},
        31: {"Type":"Datagram Conversion Error"},
        32: {"Type":"Mobile Host Redirect"},
        33: {"Type":"IPv6 Where-Are-You"},
        34: {"Type":"IPv6 I-Am-Here"},
        35: {"Type":"Mobile Registration Request"},
        36: {"Type":"Mobile Registration Reply"},
        37: {"Type":"Domain Name Request"},
        38: {"Type":"Domain Name Reply"},
        39: {"Type":"SKIP"},
        40: {"Type":"Photuris"}
        }

    # Parse human ICMP Type and Code from integers
    def icmp_human_type_code(self,icmp_reported:int):
        """Parse ICMP integer to get the human ICMP Type and Code"""
        icmp_num_type = icmp_reported//256 # ICMP Type
        icmp_num_code = icmp_reported%256 # ICMP Code

        try:
            icmp_parsed_type = self.icmp_table[icmp_num_type]["Type"]

            try:
                icmp_parsed_code = self.icmp_table[icmp_num_type]["Codes"][icmp_num_code]
            except (NameError,KeyError):
                icmp_parsed_code = "No Code"

            return (icmp_parsed_type,icmp_parsed_code) # Return human ICMP Type and Code
        
        # Failed to parse ICMP Type / Code, just return original Type and Code numbers
        except (NameError,KeyError):
            return (icmp_num_type,icmp_num_code)

    def icmp_num_type_code(self,icmp_reported:int):
        """Parse ICMP integer to get the numeric ICMP Type and Code"""
        icmp_num_type = icmp_reported//256 # ICMP Type
        icmp_num_code = icmp_reported%256 # ICMP Code
        
        return (icmp_num_type,icmp_num_code)