# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

"""
Standalone LightPacket L2pcapSocket for Linux (libpcap) – used for layer 2 packets socket.
"""
import ctypes
from ctypes import (
    create_string_buffer, c_ubyte, c_int, c_char_p, c_uint,
    c_void_p, byref, POINTER, c_ulong, c_ushort, c_uint32, Structure
)
import sys
import time
from typing import Optional
from ..Interfaces.LibpcapInterfacesLin import get_default_interface_name_linux

if sys.platform != "linux":
    raise RuntimeError("This module is designed for Linux with libpcap.")

try:
    pcap_lib = ctypes.CDLL("libpcap.so.1")
except OSError:
    try:
        pcap_lib = ctypes.CDLL("libpcap.so")
    except OSError:
        raise RuntimeError("libpcap not found. Install with: sudo apt-get install libpcap-dev")


class pcap_pkthdr(ctypes.Structure):
    _fields_ = [
        ('ts_sec', c_ulong),
        ('ts_usec', c_ulong),
        ('caplen', c_uint),
        ('len', c_uint),
    ]


class bpf_program(ctypes.Structure):
    _fields_ = [
        ('bf_len', c_uint),
        ('bf_insns', c_void_p),
    ]

class pcap_if(Structure):
    pass

class pcap_addr(Structure):
    pass


pcap_addr._fields_ = [
        ('next', POINTER('pcap_addr')),
        ('addr', c_void_p),
        ('netmask', c_void_p),
        ('broadaddr', c_void_p),
        ('dstaddr', c_void_p),
    ]



pcap_if._fields_ = [
        ('next', POINTER('pcap_if')),
        ('name', c_char_p),
        ('description', c_char_p),
        ('addresses', POINTER(pcap_addr)),
        ('flags', c_uint),
    ]


class sockaddr_in(ctypes.Structure):
    _fields_ = [
        ('sin_family', c_ushort),
        ('sin_port', c_ushort),
        ('sin_addr', c_uint32),
        ('sin_zero', ctypes.c_char * 8)
    ]


PCAP_ERRBUF_SIZE = 256
PCAP_ERROR = -1

BROADCAST_MAC = 'ff:ff:ff:ff:ff:ff'
NULL_MAC = '00:00:00:00:00:00'
BROADCAST_MAC_RAW = 'ffffffffffff'
NULL_MAC_RAW = '000000000000'

pcap_lib.pcap_create.argtypes = [c_char_p, c_char_p]
pcap_lib.pcap_create.restype = c_void_p

pcap_lib.pcap_set_snaplen.argtypes = [c_void_p, c_int]
pcap_lib.pcap_set_snaplen.restype = c_int

pcap_lib.pcap_set_promisc.argtypes = [c_void_p, c_int]
pcap_lib.pcap_set_promisc.restype = c_int

pcap_lib.pcap_set_timeout.argtypes = [c_void_p, c_int]
pcap_lib.pcap_set_timeout.restype = c_int

pcap_lib.pcap_set_rfmon.argtypes = [c_void_p, c_int]
pcap_lib.pcap_set_rfmon.restype = c_int

pcap_lib.pcap_activate.argtypes = [c_void_p]
pcap_lib.pcap_activate.restype = c_int

pcap_lib.pcap_inject.argtypes = [c_void_p, c_void_p, ctypes.c_size_t]
pcap_lib.pcap_inject.restype = c_int

pcap_lib.pcap_sendpacket.argtypes = [c_void_p, c_void_p, c_int]
pcap_lib.pcap_sendpacket.restype = c_int

pcap_lib.pcap_next_ex.argtypes = [
    c_void_p,
    POINTER(POINTER(pcap_pkthdr)),
    POINTER(POINTER(c_ubyte))
]
pcap_lib.pcap_next_ex.restype = c_int

pcap_lib.pcap_compile.argtypes = [c_void_p, c_void_p, c_char_p, c_int, c_uint]
pcap_lib.pcap_compile.restype = c_int

pcap_lib.pcap_setfilter.argtypes = [c_void_p, c_void_p]
pcap_lib.pcap_setfilter.restype = c_int

pcap_lib.pcap_close.argtypes = [c_void_p]
pcap_lib.pcap_close.restype = None

pcap_lib.pcap_freecode.argtypes = [c_void_p]
pcap_lib.pcap_freecode.restype = None

pcap_lib.pcap_geterr.argtypes = [c_void_p]
pcap_lib.pcap_geterr.restype = c_char_p

pcap_lib.pcap_findalldevs.argtypes = [POINTER(POINTER(pcap_if)), c_char_p]
pcap_lib.pcap_findalldevs.restype = c_int

pcap_lib.pcap_freealldevs.argtypes = [POINTER(pcap_if)]
pcap_lib.pcap_freealldevs.restype = None

pcap_lib.pcap_lookupdev.argtypes = [c_char_p]
pcap_lib.pcap_lookupdev.restype = c_char_p

class L2Socket:

    def __init__(self, iface=None, snaplen=65535, promisc=True, to_ms=100, monitor=False):
        if iface is None:
            iface = get_default_interface_name_linux()
            if iface is None:
                raise RuntimeError("No network interface found")
        
        self.iface = iface
        self.pcap = None
        self._filter = None
        errbuf = create_string_buffer(PCAP_ERRBUF_SIZE)

        self.pcap = pcap_lib.pcap_create(iface.encode("utf8"), errbuf)
        if not self.pcap:
            raise OSError(self._err(errbuf))

        if pcap_lib.pcap_set_snaplen(self.pcap, snaplen) != 0:
            raise OSError(self._err(errbuf) or "Could not set snaplen")
        if pcap_lib.pcap_set_promisc(self.pcap, 1 if promisc else 0) != 0:
            raise OSError(self._err(errbuf) or "Could not set promisc")
        if pcap_lib.pcap_set_timeout(self.pcap, to_ms) != 0:
            raise OSError(self._err(errbuf) or "Could not set timeout")
        if monitor:
            if pcap_lib.pcap_set_rfmon(self.pcap, 1) != 0:
                raise OSError(self._err(errbuf) or "Could not set monitor mode")

        status = pcap_lib.pcap_activate(self.pcap)
        if status < 0:
            raise OSError(self._err(errbuf) or f"pcap_activate failed with status {status}")

        self._errbuf = errbuf
        self.closed = False

    def _err(self, errbuf):
        """Extract error message from errbuf."""
        return errbuf.value.decode("utf-8", errors="ignore").strip("\x00") or None

    def sendl2(self, packet):
        """Send a Layer 2 packet."""
        if self.closed or not self.pcap:
            raise RuntimeError("Socket closed")

        if hasattr(packet, 'build') and callable(packet.build):
            packet = packet.build()

        data = (c_ubyte * len(packet)).from_buffer_copy(packet)
        return pcap_lib.pcap_inject(self.pcap, data, len(packet))

    def set_filter(self, filter_str: str) -> bool:
        """Set a BPF filter."""
        if not self.pcap:
            return False

        fp = bpf_program()
        filter_bytes = filter_str.encode('utf-8')

        result = pcap_lib.pcap_compile(self.pcap, byref(fp), filter_bytes, 1, 0)
        if result != 0:
            return False

        result = pcap_lib.pcap_setfilter(self.pcap, byref(fp))
        pcap_lib.pcap_freecode(byref(fp))

        if result == 0:
            self._filter = filter_str
            return True
        return False

    def recvl2(self, count: int = 1, timeout: float = 1.0) -> list:
        """Receive Layer 2 packets."""
        if self.closed or not self.pcap:
            raise RuntimeError("Socket closed")

        packets = []
        start_time = time.time()
        received = 0

        while True:
            if timeout > 0 and (time.time() - start_time) > timeout:
                break

            header_ptr = POINTER(pcap_pkthdr)()
            data_ptr = POINTER(c_ubyte)()

            ret = pcap_lib.pcap_next_ex(self.pcap, byref(header_ptr), byref(data_ptr))

            if ret == 1:
                if header_ptr and data_ptr:
                    length = header_ptr.contents.len
                    data = bytearray(length)
                    for i in range(length):
                        data[i] = data_ptr[i]
                    packets.append(bytes(data))
                    received += 1

                    if count > 0 and received >= count:
                        break

            elif ret == -1:
                err = self.geterr()
                raise RuntimeError(f"pcap_next_ex error: {err}")
            elif ret == -2:
                continue

        return packets

    def srp1(self, packet, timeout: float = 3.0, filter_str: str = None) -> Optional[bytes]:
        """Send and receive one Layer 2 packet."""
        if self.closed or not self.pcap:
            raise RuntimeError("Socket closed")

        if hasattr(packet, 'build') and callable(packet.build):
            send_data = packet.build()
        else:
            send_data = packet

        data = (c_ubyte * len(send_data)).from_buffer_copy(send_data)
        sent = pcap_lib.pcap_inject(self.pcap, data, len(send_data))

        original_filter = self._filter
        if filter_str:
            self.set_filter(filter_str)

        response = None
        start_time = time.time()

        while (time.time() - start_time) < timeout:
            header_ptr = POINTER(pcap_pkthdr)()
            data_ptr = POINTER(c_ubyte)()

            ret = pcap_lib.pcap_next_ex(self.pcap, byref(header_ptr), byref(data_ptr))

            if ret == 1:
                if header_ptr and data_ptr:
                    length = header_ptr.contents.len
                    data = bytearray(length)
                    for i in range(length):
                        data[i] = data_ptr[i]
                    response = bytes(data)
                    break
            elif ret == -1:
                err = self.geterr()
                raise RuntimeError(f"pcap_next_ex error: {err}")
            elif ret == -2:
                continue

        if original_filter:
            self.set_filter(original_filter)
        elif filter_str:
            self.set_filter("")

        return response

    def srp(self, packet, timeout: float = 3.0, count: int = 1, filter_str: str = None) -> list:
        """Send and receive multiple Layer 2 packets."""
        responses = []

        if hasattr(packet, 'build') and callable(packet.build):
            send_data = packet.build()
        else:
            send_data = packet

        data = (c_ubyte * len(send_data)).from_buffer_copy(send_data)
        sent = pcap_lib.pcap_inject(self.pcap, data, len(send_data))

        original_filter = self._filter
        if filter_str:
            self.set_filter(filter_str)

        start_time = time.time()
        received = 0

        while (time.time() - start_time) < timeout and (count == 0 or received < count):
            header_ptr = POINTER(pcap_pkthdr)()
            data_ptr = POINTER(c_ubyte)()

            ret = pcap_lib.pcap_next_ex(self.pcap, byref(header_ptr), byref(data_ptr))

            if ret == 1:
                if header_ptr and data_ptr:
                    length = header_ptr.contents.len
                    data = bytearray(length)
                    for i in range(length):
                        data[i] = data_ptr[i]
                    responses.append(bytes(data))
                    received += 1
            elif ret == -1:
                err = self.geterr()
                raise RuntimeError(f"pcap_next_ex error: {err}")
            elif ret == -2:
                continue

        if original_filter:
            self.set_filter(original_filter)
        elif filter_str:
            self.set_filter("")

        return responses

    def geterr(self) -> str:
        """Get the last error message."""
        if not self.pcap:
            return ""
        err = pcap_lib.pcap_geterr(self.pcap)
        return err.decode("utf-8", errors="ignore") if err else ""

    def close(self):
        """Close the socket."""
        if self.pcap:
            pcap_lib.pcap_close(self.pcap)
            self.pcap = None
            self.closed = True

    def __del__(self):
        self.close()
