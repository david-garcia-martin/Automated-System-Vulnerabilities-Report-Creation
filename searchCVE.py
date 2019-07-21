# -*- coding: utf-8 -*-
#!/usr/bin/env python
from __future__ import print_function
import sys, os
import time
from optparse import OptionParser
from optparse import BadOptionError
from optparse import AmbiguousOptionError
import subprocess
import ast
from pandas.compat import FileNotFoundError
from createReport import create_report

timestamp = time.strftime("%d_%m_%Y")

def update():
    print("Updating MongoDB from cve_search...\n")
    subprocess.run(["./cve-search.git/trunk/sbin/db_updater.py", "-v"])
    print("Database succesfully updated :)")

def process_inventory(inventory):
    counter = 0
    timestamp = time.strftime("%d_%m_%Y")
    try:
        with open("report_" + timestamp + ".csv", "r") as f:
            x = f.readlines()
            if len(x) > 0:
                sys.stdout.write("THIS SEARCH HAS ALREADY BEEN DONE!!")
                return str ("report_" + timestamp)
    except FileNotFoundError:
        pass

    with open(str(inventory), "r") as f:
        x = f.readlines()
        n=0
        for cpe in x:
            if cpe=="Windows\n":
                operating_system = cpe[:-1]
                continue
            elif cpe=="Ubuntu\n":
                operating_system = cpe[:-1]
                continue
            elif cpe=="MacOS\n":
                operating_system=cpe[:-1]
                continue
            if counter == 0:
                sys.stdout.write("\nGENERATING CSV FILE...")
                counter += 1
            sys.stdout.write("GETTING CVE FROM: " + cpe + "...\n")
            command = "python3 /Users/davidgarcia/PycharmProjects/TFM/cve-search.git/trunk/bin/search.py -p " + cpe.rstrip() + " -o json"
            b = os.popen(command).read()
            c = b.split("\n")
            c = c[:-1]
            for i in range(0, len(c)):
                aux = c[i].rstrip()
                t = ast.literal_eval(aux)
                generate_csv(t, n, operating_system)
                n+=1

    sys.stdout.write("\nOK!")

    create_report(str("report_" + timestamp + ".csv"), timestamp)
    return str("report_" + timestamp)

def generate_csv(dict,n, operating_system):

    with open("report_" + timestamp + ".csv", "a+") as f:
        x = f.readlines()
        if len(x) == 0 and n==0:
            f.write("OS; CVE; PUBLIC_DATE; AUTHENTICATION; COMPLEXITY; VECTOR; CVSS; CWE; AVAILABILITY; CONFIDENTIALITY; INTEGRITY; SUMMARY;")
        cwe, references ="",""
        for key, value in dict.items():
            if key == "id":
                key_csv = value
            elif key == "Published":
                published = value
            elif key =="access":
                access = value["authentication"] + "; " + value["complexity"] +"; "+ value["vector"]
            elif key == "cvss":
                cvss = value
            elif key=="impact":
                impact = value["availability"] + ";" + value["confidentiality"] +";"+ value["integrity"]
            elif key=="summary":
                summary = value
            elif key == "cwe":
                cwe = value
        if cwe:
            f.write("\n" + str(operating_system) +"; "+ str(key_csv) + "; " + str(published) + "; " + str(access)+"; " + str(cvss) + ";" + str(cwe) + ";" + str(impact) + ";"  + str(summary) + ";")
        else:
            f.write("\n" + str(operating_system) +"; "+ str(key_csv) + "; " + str(published) + "; " +  str(access) + "; " + str(cvss) + ";" + "NONE" + ";" + str(impact) +  ";" + str(summary) + ";")

class PassThroughOptionParser(OptionParser):
    def _process_args(self, largs, rargs, values):
        while rargs:
            try:
                OptionParser._process_args(self,largs,rargs,values)
            except (BadOptionError,AmbiguousOptionError) as e:
                largs.append(e.opt_str)

def get_parser():
    parser = PassThroughOptionParser(add_help_option=False)
    parser.add_option('-h', '--help', help='Show help message', action='store_true')
    parser.add_option('-u', '--update', help='Update database', action='store_true', default=False)
    parser.add_option('-f', '--file', help='Inventory file: inventory.csv', action='store', default=False)

    return parser

def main():
    parser = get_parser()
    args = parser.parse_args()

    if args[0].update:
        update()
    elif args[0].file:
        inventory = args[0].file

        process_inventory(inventory)
    elif args[0].help:
        print("This is a script to obtain vulnearabilities from cpe, i.e: python3 searchCVE.py -f inventory.csv", file=sys.stderr)
        print("In case you want to update the MongoDB: python3 searchCVE.py -u", file=sys.stderr)
        exit(0)
    elif (not args[0].help or not args[0].file) or not args[0].update:
        print("Error",file=sys.stderr)
        print("This is a script to obtain vulnearabilities from cpe, i.e: python3 searchCVE.py -f inventory.csv",file=sys.stderr)
        print("In case you want to update the MongoDB: python3 searchCVE.py -u",file=sys.stderr)
        exit(0)

    sys.stdout.write("\n")
    sys.stdout.write("\nDONE!")

if __name__ == "__main__":
	main()

