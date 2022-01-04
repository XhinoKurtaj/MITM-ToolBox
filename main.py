from scanner import ARPScanner
from spoof import ARPSpoof
import argparse


def banner() -> None:
    print("\n***************************************")
    print("* ARP Toolkit  1.0                      *")
    print("***************************************")

def usage():
    print("Usage:")
    print("         -w: url (http://somesite.com/FUZZ)")
    print("         -t: threads")
    print("         -f: dictionary file\n")
    print("example: forzabruta.py -w http://www.targetsite.com/FUZZ -t 5 -f common.txt\n")

def perform_scan():
    scanner = ARPScanner()
    scanner.handle_scanning()

def perform_mitm():
    mitm = ARPSpoof()
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
