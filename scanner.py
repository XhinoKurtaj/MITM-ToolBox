from scapy.all import Ether, ARP, srp
import platform
from rich.console import Console
from rich.table import Column, Table


class ARPScanner:

    __nic: str
    __ipRange: str
    __broadcast: str = "ff:ff:ff:ff:ff:ff"
    __saveToFile: bool
    __filename: str
    console: Console = Console()

    def __init__(
        self,
        nic=None,
        nRange=None,
        saveToFile=False,
        filename=None
    ):
        self.__nic = nic
        self.__ipRange = nRange
        self.__saveToFile = saveToFile
        self.__filename = filename

    def __oSystemNic__(self) -> str:
        match platform.system():
            case "Windows":
                return "Intel(R) Dual Band Wireless-N 7260"
            case "Linux":
                return "eth0"

    def __interface__(self) -> str:
        network_interface: str = self.__nic
        if self.__nic is None:
            network_interface = self.__oSystemNic__()
        return network_interface

    def __ip_range__(self) -> str:
        ip_range = "192.168.1.1/24"
        if self.__ipRange is not None:
            ip_range = self.__ipRange
        return ip_range

    def format_response(self, **kwargs) -> str:
        beautify = f"Ip = {kwargs['ip']}, MAC = {kwargs['mac']}"
        return beautify

    def handle_scanning(self) -> None:
        ether_layer: Ether = Ether(dst=self.__broadcast)
        arp_layer: ARP = ARP(pdst=self.__ip_range__())
        packet = ether_layer / arp_layer

        interface: str = self.__interface__()

        ans, unans = srp(packet, iface=interface, timeout=2)

        if not self.__saveToFile:
            table = self.create_print_table()

        for snd, rcv in ans:
            ip: str = rcv[ARP].psrc
            mac: str = rcv[Ether].src
            response = self.format_response(ip=ip, mac=mac)
            if self.__saveToFile:
                self.write_to_file(response)
            else:
                self.print_response_in_console(ip, mac, table)

    def write_to_file(self, response: str):
        file = open(self.__filename, "w")
        file.write(f"{response} \n")

    def print_response_in_console(self, ip, mac, table):
        table.add_row(ip, mac)
        self.console.print(table)
    
    def create_print_table(self) -> Table:
        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("IP", style="dim")
        table.add_column("Mac", justify="right")
        return table
