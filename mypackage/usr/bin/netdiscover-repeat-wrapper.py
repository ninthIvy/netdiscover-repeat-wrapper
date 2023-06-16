#!/usr/bin/env -S sudo -E python3
'''
6/15/2023 V1
This script scans the network to check for disconnections and connections. 
It writes these to a log file in ./ along with the time of the (dis)connection.
The user specifies how often the script should scan, how long the script should run for, and an ip range to scan through.
This can reveal devices not supposed to be on the network at the current time as well as devices that are leaving too early/late.
'''
from netdiscover import Discover     #used to scan the network
import sys                    #used to terminate script early
import time                   #used to keep track how often the script should run and when it should terminate
import argparse               #used to allow user to specify options on how the script should run
import socket                 #used to get host ip
from datetime import datetime #used to get current hour and second
import logging                #used to cut down trees in the amazon rainforest
import os

def convertToSeconds(time):
    #convert hours and minutes into seconds
    hours   = time[0:2]
    minutes = time[3:5]
    seconds = time[6:8]

    try:
        hours   = int(hours)
        minutes = int(minutes)
        seconds = int(seconds)
    except:
        print("Improper timestamp specified. Correct format: HH:MM:SS")
        sys.exit(0)

    #convert time input to seconds for use in the time module
    seconds += hours*3600
    seconds += minutes*60

    return seconds

def get_ip():

    '''
    get primary IP on host
    courtesy of fatal_error at https://stackoverflow.com/questions/166506/finding-local-ip-addresses-using-pythons-stdlib
    using the supplied method instead of socket.gethostbyname(socket.gethostname()) as that returns the loopback address 
    on unix like hosts that have /etc/hosts
    '''
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        #try to connect to arbitrary IP to read source (host) IP
        s.connect(('10.255.255.255', 1))
        IP = s.getsockname()[0]
    logging.info(f"Using IP: {IP}")
    return IP

def scan(waitTime, ipRange, duration):
    #This function controls how often the script runs, how long it will run for, 
    #as well as scanning the network and logging (dis)connections.

    #duration is set to a string if the script is supposed to run indefinitely
    if isinstance(duration,str):
        infinite = True

        #now and end are set to these values such that (now < end) returns False.
        #this is so the xor operator can determine when the script has reached it end, if it has one
        now = 2
        end = 1
    else:

        #because the script wont run indefinitely, the time to stop needs to be calculated.
        now = time.time()
        start = now
        end = now + duration
        infinite = False
    
    '''
    If the script exits with an error saying "netdiscover not found" and the python-netdiscover package is installed, 
    this means the python package can not find the netdiscover binary which is different from python-netdiscover
    netdiscover can be installed using apt. netdiscover is also available on the AUR. consult your distribution's
    packages if you don't run an arch or ubuntu based system.
    if the binary is not located in one of the locations noted here: https://pypi.org/project/python-netdiscover/      
    uncomment line 85 and specify the path inside the quotation marks. it may be best to use the absolute path
    '''
    


    disc = Discover()
    #disc = Discover(netdiscover_path="")
    with open("log","w+") as log:
        pass
    numberOfScans = 0
    devices = []

    '''
    there are 4 possibilities for this while statement but only 3 can be used
    1) time has not run out (True) XOR the script is supposed to run indefinitely (False) | True
    2) time has not run out (False) XOR the script is supposed to run indefinitely (False)| False
    3) time has not run out (False) XOR the script is supposed to run indefinitely (True) | True
    '''
    while (now < end) ^ infinite:
        
        '''
        The way the script determines if a device has (dis)connected is by comparing two scans together.
        if there are no scans to compare to, one must be created. the scan is stored as scan0 and its contents
        will be stored to the devices list for comparing against scan1, the current scan.
        after scan1 is compared to devices, the contents of scan1 are saved to the devices list to compare the next scan
        '''            
        if len(devices) == 0:
            logging.info("Starting Initial Scan")
            try:
                scan0 = disc.scan(ip_range = ipRange)
            except KeyboardInterrupt:
                logging.info("KeyboardInterrupt")
                sys.exit(0)
            numberOfScans += 1
            logging.info("Initial Scan finished")
            devices = scan0
        else:
            logging.info(f"Scan {numberOfScans} started")
            try:
                scan1 = disc.scan(ip_range = ipRange)
            except KeyboardInterrupt:
                logging.info("KeyboardInterrupt")
                sys.exit(0)
            numberOfScans += 1
            logging.info(f"Scan {numberOfScans-1} completed")

            #Check for new devices
            for device in scan1:
                #if there is a device in the new scan not in the earlier one, then it is a new device
                if device not in devices:
                    '''
                    python-netdiscover returns a list of dictionaries which are encoded. 
                    device refers to a dictionary with "mac" and "ip" fields.
                    the contents of the dictionary must be decoded before writing to a file
                    '''
                    mac = device["mac"].decode("utf-8")    
                    ip  = device["ip"].decode("utf-8")      
                    current_time = datetime.now().strftime("%H:%M:%S")

                    with open("log","a+") as log:
                        log.write(f"{current_time} {ip} | {mac} has connected\n")
                    

            #Check for devices no longer connected
            for device in devices:
                #if there is a device detected earlier but not in the new scan, then that device has disconnected
                if device not in scan1:
                    mac = device["mac"].decode("utf-8")
                    ip  = device["ip"].decode("utf-8")
                    current_time = datetime.now().strftime("%H:%M:%S")

                    with open("log","a+") as log:
                        log.write(f"{current_time} {ip} | {mac} has connected\n")                   
                   
            devices = scan1
        print("waiting...")
        time.sleep(waitTime)

        #update now if it's in use
        if type(duration) == str:
            pass
        else:
            now = time.time()
    print("script ended successfully")
    if numberOfScans == 1:
        print("Only scanned once, nothing to compare. Please allow the script to run for longer.")
        print("\n 5 minutes is a good starting point or leave duration blank to run indefinitely. Use ctrl+c to terminate.")


if __name__ == "__main__":

    level = logging.DEBUG
    fmt = '[%(levelname)s] %(asctime)s - %(message)s'
    logging.basicConfig(level=level, format=fmt)
        
    parser = argparse.ArgumentParser(prog="final")

    parser.add_argument("-t", "--time", help="The script will wait this much time to scan again. Should be in HH:MM:SS format.", type = str)
    parser.add_argument("-r", "--range",    help="The ip range to be scanned. Leave blank to scan entire network.", type = str)
    parser.add_argument("-d", "--duration", help="How long the program should run for. Leave blank to run indefinitely. should be in HH:MM:SS format.", type = str)

    args = parser.parse_args()

    if not(args.time):
        waitTime = "00:00:00"
    else:
        waitTime = convertToSeconds(args.time)

    if args.duration:
        duration = convertToSeconds(args.duration)
    else:
        #duration is not supplied and its type is set to a string to signal that the program should run indefinitely
        duration = "string"

    if args.range:
        ipRange = args.range

    else:
        '''
        examine host ip to determine the ip range of the network
        depending on the first 3 characters of the ip address, the bitblock of the network's local
        ip can be determined so the whole network can be scanned
        '''
        hostIP = get_ip()
        hostIP = str(hostIP)
        
        determiner = hostIP[0:3]
        if determiner == "192":
            ipRange="192.168.0.0/16"
            logging.info("ipRange = 192.168.0.0/16")
        elif determiner == "172":
            ipRange="172.16.0.0/12"
            logging.info("ipRange = 172.16.0.0/12")
        elif determiner == "10.":
            ipRange="10.0.0.0/8"
            logging.info("ipRange = 10.0.0.0/8")
        else:
            print("Could not determine ip range")
            sys.exit(1)
    
    
    scan(waitTime,ipRange,duration)
