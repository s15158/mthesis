from Automation.PacketEngine.Processors.PPP.BasicHandlersFactory import (
    BasicHandlersFactory,
)
from Automation.PacketEngine.Processors.PPP.Ipv6Handler import Ipv6Handler
from Automation.PacketEngine.Processors.PPP.LcpHandler import LcpHandler


class Ipv6HandlersFactory(BasicHandlersFactory):
    def createLcpHandler(self):
        return LcpHandler(
            pppServer=self.pppServer,
            acceptedProtocols=[
                0xC021,  # LCP
                0xC223,  # CHAP
                0x8057,  # IPv6CP
                0x0057,  # IPv6
            ],
        )

    def createNcpHandler(self):
        return Ipv6Handler(
            pppServer=self.pppServer,
            dhcp6Address="2a01::1101::1::7000::ae84::c9ff::fe10::8460",
            dhcp6Dns1="2a01:1101:1:8001:206:5bff:fef0:5ff5",
            dhcp6Dns2="2a01:1101:1:8000:20c:29ff:fef8:fce9",
            t1=43200,
            t2=69120,
            temporary=True,
        )
