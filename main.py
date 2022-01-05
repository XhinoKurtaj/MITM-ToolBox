from scanner import ARPScanner
from spoof import ARPSpoof
import re


def banner() -> None:
    print("\n***************************************")
    print("* ARP Toolkit  1.0                      *")
    print("***************************************")

def perform_scan():
    scanner = ARPScanner()
    scanner.handle_scanning()
    print("[+] Scanning completed successfully ")
    choice()


def mac_regex(item) -> bool:
    return re.search(r'([0-9A-F]{2}[:-]){5}([0-9A-F]{2})', item, re.I)


def ip_regex(item) -> bool:
    return re.search(r'((2[0-5]|1[0-9]|[0-9])?[0-9]\.){3}((2[0-5]|1[0-9]|[0-9])?[0-9])', item, re.I)


def validate_entered_data(data: str) -> dict:
    splitData = data.split()

    hasError: bool = False
    errorMsg: str = ""

    for item in splitData:
        ip: str = ""
        mac: str = ""
        if mac_regex(item):
            mac = item
        elif ip_regex(item):
            ip = item
        else:
            hasError = True
            errorMsg = f"{item} is not valid"

    return dict(ip=ip, mac=mac, hasError=hasError, errorMsg=errorMsg)


def perform_mitm():
    print("[+] 1: Continue ")
    print("[+] 99: Go back")

    t1Err = True
    while t1Err:
        fTarget: str = input(
            "[+] Insert first target IP and Mac ex:(192.168.9.53, ff:ff:ff:ff:ff:ff) : ")
        t1 = validate_entered_data(fTarget)
        if not t1["hasError"]:
            t1Err = False
        print(t1["errorMsg"])

    t2Err = True
    while t2Err:
        sTarget: str = input(
            "[+] Insert second target IP and Mac ex:(192.168.9.53, ff:ff:ff:ff:ff:ff) : ")
        t2 = validate_entered_data(sTarget)

        if not t1["hasError"]:
            t2Err = False
        print(t1["errorMsg"])

    # TODO: Params not getting passed to the class
    mitm = ARPSpoof(tOneIp=t1["ip"], tOneMac=t1["mac"],
                    tTwoIp=t2["ip"], tTwoMac=t2["mac"])
    mitm.MITMAttack()


def choice():
    print("[+] 1: Scan network for ARP connections")
    print("[+] 2: Perform man in the middle between two selected targets")
    print("[+] 99: Exit system")

    choice: int = int(input("choose: > "))

    match choice:
        case 1:
            perform_scan()
        case 2:
            perform_mitm()
        case _:
            return


def start():
    banner()
    choice()


if __name__ == '__main__':
    start()
