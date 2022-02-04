import time

from scapy.data import EPOCH
from scapy.layers.dhcp6 import (
    DHCP6_Solicit,
    DHCP6_Request,
    DHCP6OptClientId,
    DHCP6OptServerId,
    DUID_LLT,
    DHCP6OptIA_NA,
    DHCP6OptIA_TA,
    DHCP6OptIAAddress,
    DHCP6OptDNSServers)
from scapy.layers.inet import UDP
from scapy.layers.inet6 import ICMPv6ND_RS, IPv6, ICMPv6ND_RA

from Automation.PacketEngine.PacketProcessing.PacketProcessor import PacketProcessor

from Automation.PacketEngine.Processors.PPP.Ipv6cp import (
    PPP_IPv6CP,
    PPP_IPv6CP_Interface_Identifier_Option,
)
from Automation.PacketEngine.Utilities.EthernetUtilities import macToIpv6
from Automation.Utilities.Logging import selflogged


class Ipv6Handler(PacketProcessor):
    """Handles IPv6CP, DHCPv6 and ICMPv6 during NCP phase of DS-lite PPP session."""

    def __init__(self,
        pppServer=None,
        dhcp6Address=None,
        dhcp6Dns1=None,
        dhcp6Dns2=None,
        t1=None,
        t2=None,
        temporary=False,
        *args,
        **kwargs
    ):
        super(Ipv6cpHandler, self).__init__(*args, **kwargs)
        self.pppServer = pppServer
        self._ipv6Address = ""
        self._dhcp6Address = dhcp6Address
        self._dhcp6Dns1 = dhcp6Dns1
        self._dhcp6Dns2 = dhcp6Dns2
        self._t1 = t1
        self._t2 = t2
        self._temporary = temporary
        self._duid = None

    def start(self):
        self.interface = self.pppServer.session.pppInterface
        self._ipv6Address = macToIpv6(self.interface.ethSrc)
        self._setupDuid()
        super(Ipv6cpHandler, self).start()

    def processPacket(self, packet):
        if PPP_IPv6CP in packet and packet[PPP_IPv6CP].code == 1:
            self.processConfRequest(packet)
        elif ICMPv6ND_RS in packet:
            self.processIcmpv6RouterSolicitation(packet)
        elif DHCP6_Solicit in packet:
            self.processDhcpv6Solicit(packet)
        elif DHCP6_Request in packet:
            self.processDhcpv6Request(packet)

    @selflogged
    def processConfRequest(self, packet):
        if PPP_IPv6CP_Interface_Identifier_Option in packet:
            packet[PPP_IPv6CP].code = 2
            self.send(packet[PPP_IPv6CP])
            self.sendConfRequest()

    @selflogged
    def sendConfRequest(self):
        packet = PPP_IPv6CP(
            code=1,
            options=[
                PPP_IPv6CP_Interface_Identifier_Option(data=self._getInterfaceId())
            ],
        )
        return self.send(packet)

    @selflogged
    def processIcmpv6RouterSolicitation(self, packet):
        response = IPv6(src=self._ipv6Address, dst="ff02::1", tc=0xC0) / ICMPv6ND_RA(
            chlim=64, M=True, O=True, H=False, prf=0, P=0, routerlifetime=900
        )
        self.send(response)

    def _getInterfaceId(self):
        macAddress = self.interface.ethSrc
        parts = macAddress.split(":")
        parts[0] = "%x" % (int(parts[0], 16) ^ 2)
        parts.insert(3, "ff")
        parts.insert(4, "fe")
        hexId = "".join(parts)
        return bytes.fromhex(hexId)

    @selflogged
    def processDhcpv6Solicit(self, packet):
        self.sendDhcpResponseWithCode(2, packet)

    @selflogged
    def processDhcpv6Request(self, packet):
        self.sendDhcpResponseWithCode(7, packet)

    def sendDhcpResponseWithCode(self, code, packet):
        ipv6Layer = packet[IPv6]
        ipv6Layer.dst = ipv6Layer.src
        ipv6Layer.src = self._ipv6Address
        ipv6Layer.plen = None

        udpLayer = packet[UDP]
        udpLayer.sport, udpLayer.dport = udpLayer.dport, udpLayer.sport
        udpLayer.len = None
        udpLayer.chksum = None

        dhcpv6Layer = udpLayer.payload
        dhcpv6Layer.msgtype = code

        options = []
        options.append(packet[DHCP6OptClientId])
        options.append(DHCP6OptServerId(duid=self._duid))
        """ For stateful autoconfiguration
        if self._dhcp6Address && self._temporary:
            options.append(
                DHCP6OptIA_TA(
                    iataopt=[
                        DHCP6OptIAAddress(
                            addr=self._dhcp6Address,
                        )
                    ],
                )
            )
        elif self._dhcp6Address:
            options.append(
                DHCP6OptIA_NA(
                    T1=self._t1,
                    T2=self._t2,
                    ianaopt=[
                        DHCP6OptIAAddress(
                            addr=self._dhcp6Address,
                            preflft=86400,
                            validlft=86400,
                        )
                    ],
                )
            )
        """
        options.append(
            DHCP6OptIA_PD(
                T1=43200,
                T2=69120,
                iapdopt=[
                    DHCP6OptIAPrefix(
                        preflft=86400,
                        validlft=86400,
                        plen=56,
                        prefix="2a01:1101:1:9000::",
                    )
                ],
            )
        )
        options.append(
            DHCP6OptDNSServers(
                dnsservers=[
                    self._dhcp6Dns1,
                    self._dhcp6Dns2,
                ]
            )
        )
        """ For DS-lite
        options.append(DHCP6OptUnknown(
            optcode=64,
            data=bytes.fromhex("") # Replace with tunnel-endpoint-name as HEX
        ))
        """
        dhcpv6Layer.remove_payload()

        for option in options:
            option.remove_payload()
            dhcpv6Layer.add_payload(option)

        self.send(ipv6Layer)

    def _setupDuid(self):
        epoch = (2000, 1, 1, 0, 0, 0, 5, 1, 0)

        delta = time.mktime(epoch) - EPOCH
        timeval = time.time() - delta

        self._duid = DUID_LLT(timeval=timeval, lladdr=self.interface.ethSrc)
