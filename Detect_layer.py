# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

import struct
from .Layers.IS_LLC import is_llc
from .BaseLayer import Packet


class DetectLayer:
    def start(self, packet, Alr=0, previous_layer=None, verbose=False):
        if hasattr(packet, 'build') and callable(packet.build) and Alr == 0:
            packet = packet.build()

        Lenght = len(packet)

        if previous_layer is None:
            Packet['_raw'] = packet

        if previous_layer in ["Ethernet", "Dot3", "SNAP", "LLC"]:
            from .Raw import RawParser
            RawParser.load_as_Raw_layer(packet,verbose=verbose)
            return Packet

        try:
            if Lenght >= 14:
                HHH = packet[12:14]
                eth_type = struct.unpack('>H', HHH)[0]

                if eth_type >= 0x0600:
                    from .EthernetII import EthernetParser
                    EthernetParser.load_as_ethernet_layer(packet,verbose=verbose)
                elif eth_type <= 0x05DC:
                    from .Dot3 import Dot3Parser
                    Dot3Parser.load_as_dot3_layer(packet,verbose=verbose)
                else:
                    from .Raw import RawParser
                    RawParser.load_as_Raw_layer(packet,verbose=verbose)

            elif is_llc(packet):
                from .LLC import LLCParser
                LLCParser.load_as_llc_layer(packet,verbose=verbose)
            else:
                from .Raw import RawParser
                RawParser.load_as_Raw_layer(packet,verbose=verbose)

        except Exception:
            from .Raw import RawParser
            RawParser.load_as_Raw_layer(packet,verbose=verbose)

        return Packet
