# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

from .EthernetII import *
from .Arp import *
from .Dot3 import *
from .LLC import *
from .Snap import *
from .Raw import *
from .Layers.IS_LLC import *
from .Interfaces.LinuxInterfaces import *
from .Layers.L2SocketL import *
from .Interfaces.LibpcapInterfacesLin import *
from .BaseLayer import *
from .Layers.Mac import *
from .Layers.IPtoa import *
from .Version import *
from .BaseLayer import *
from .Detect_layer import *
from .Logger.LightLogger import *
from .Logger.Errors import *
from .Consts import *

def Ethernet(src: Union[str, bytes] = None, dst: Union[str, bytes] = BROADCAST_MAC,
          ethertype: Union[str, bytes] = None) -> EthernetLayer:

    if src is None:
        src = get_default_interface_mac_linux()
    return EthernetLayer(dst=dst, src=src, ethertype=ethertype)

def Arp(hwtype: int = None, ptype: int = None, maclen: int = None,
        plen: int = None, opcode: int = None, macsrc: Union[str, bytes] = None,
        ipsrc: str = None, macdst: Union[str, bytes] = None, ipdst: str = None) -> ArpLayer:

    if macsrc is None:
        macsrc = get_default_interface_mac_linux()
    if macdst is None:
        macdst = BROADCAST_MAC
    if hwtype is None:
        hwtype = 1
    if ptype is None:
        ptype = IPv4
    if maclen is None:
        maclen = 6
    if plen is None:
        plen = 4
    if opcode is None:
        opcode = 1
    if ipsrc is None:
        ipsrc = get_default_interface_ip_linux()
    if ipdst is None:
        ipdst = get_default_gateway_ipv4_linux()

    return ArpLayer(hwtype=hwtype, ptype=ptype, maclen=maclen,plen=plen, opcode=opcode,
                    macsrc=macsrc, ipsrc=ipsrc, ipdst=ipdst, macdst=macdst)

def Dot3(dst: Union[str, bytes] = BROADCAST_MAC,
         src: Union[str, bytes] = None, length: int = 0) -> Dot3Layer:
    if src is None:
        src = get_default_interface_mac_linux()
    return Dot3Layer(dst=dst, src=src, length=length)

def LLC(dsap: Union[str, bytes] = SAP_LLC_SNAP,ssap: Union[str, bytes] = SAP_LLC_SNAP,
        control: Union[str, bytes] = LLC_UI):
    return LLCLayer(dsap=dsap, ssap=ssap, control=control)

def SNAP(oui: Union[str, bytes] = 0x000000,pid: Union[str, bytes] = ARP):
    return SNAPLayer(oui=oui, pid=pid)

def Raw(payload: bytes = b'Test LightPacket Raw Layer') -> RawLayer:
    return RawLayer(payload=payload)
