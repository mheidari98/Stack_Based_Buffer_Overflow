#!/usr/bin/env python3

import argparse
import os
import sys
from subprocess import PIPE, check_output, run
import pandas as pd


files = { 
        "memcpy":{"cnt":17, "extra":True} ,
        "memcpy_int":{"cnt":10, "extra":False} ,
        "memmove":{"cnt":17, "extra":True} ,
        "memmove_int":{"cnt":10, "extra":False} ,
        "strcpy":{"cnt":17, "extra":True} ,
        }


def plot_data_Extractor(folder, cnt):
    '''
    calculate shellphuzz runtime to found firstcrash with "plot_data" file
    '''
    print(f"{folder} : ")
    for i in range(1, cnt+1):
        print(f"\t[{i}] ", end="")
        p =f"{folder}/workdir/shellphuzz/{i}/sync/fuzzer-master/plot_data"
        try :
            df = pd.read_csv( p , sep = ',')
        except :
            print("does not exist.")
            continue

        start_time = df.loc[0, '# unix_time']
        first_crash = df[ df[' unique_crashes']!=0]['# unix_time'].min() - 1 
        time = first_crash - start_time
        print(f"time to Found first crash = {time} sec")
    
    print("-"*40)


def fuzzer_stats_Extractor(folder, cnt):
    '''
    calculate shellphuzz runtime based on "fuzzer_stats" file
    '''
    print(f"{folder} : ")
    for i in range(1, cnt+1):
        print(f"\t[{i}] ", end="")
        p =f"{folder}/workdir/shellphuzz/{i}/sync/fuzzer-master/fuzzer_stats"
        try :
            fp = open( p, "r+")  #"fuzzer_stats"
            lines = fp.readlines()
            fp.close()
        except :
            print("does not exist.")
            continue

        MyDict = {}
        for line in lines :
            MyDict[ line.split(':')[0].split()[0] ] = line.split(':')[1][1:-1]
            
        start = int(MyDict['start_time'])
        if MyDict['last_crash']!='0' :
            end = int(MyDict['last_crash'])
            print(f"last_crash = {end-start}")
        elif MyDict['last_hang']!='0' :
            end = int(MyDict['last_hang'])
            print(f"last_hang = {end-start}")
        else :
            end = int(MyDict['last_update'])
            print(f"last_update = {end-start}")
    
    print("-"*40)


def main():
    parser = argparse.ArgumentParser(description="My Driller Tester")
    parser.add_argument('-t', '--test'      , action='store_true', default=False, help="test err")
    parser.add_argument('-c', '--compile'   , action='store_true', default=False, help="compile files")
    parser.add_argument('-r', '--remove'    , action='store_true', default=False, help="remove files")
    parser.add_argument('-d', '--run_driller'       , action='store_true', default=False, help="run driller")
    parser.add_argument('-e', '--time_extractor'    , action='store_true', default=False, help="extract time")
    
    args = parser.parse_args()
    
    CurDir = os.path.dirname(__file__)    # os.getcwd()

    if args.run_driller :
        os.system("echo core | sudo tee /proc/sys/kernel/core_pattern")
        os.system("echo 1 | sudo tee /proc/sys/kernel/sched_child_runs_first")
    
    for folder, status in files.items():
        os.chdir(folder)
        os.system("mkdir -p workdir/input")
        os.system("echo 'init' > workdir/input/seed1")
        
        for i in range(1, status["cnt"]+1 ) :

            if args.compile :
                if i==status["cnt"] and status["extra"] :
                    if os.path.isfile(f"{i}a.c") and os.path.isfile(f"{i}b.c") : 
                        os.system(f"gcc {i}a.c {i}b.c io.c -o {i}")
                        #run(["gcc", f"{i}a.c", f"{i}b.c", "io.c", "-o", f"{i}"])
                        print(f"[!] ({folder}) {i}a.c & {i}b.c exist and compiled")
                elif os.path.isfile(f"{i}.c") :
                    os.system(f"gcc {i}.c io.c -o {i}")
                    #run(["gcc", f"{i}.c", "io.c", "-o", f"{i}"])
                    print(f"[!] ({folder}) {i}.c exist and compiled")
                else :
                    print(f"[X] ({folder}) {i}.c not exist")
                
            if os.path.isfile(f"{i}") :
                if args.test :
                    p = run([f"./{i}"], stdout=PIPE, stderr=PIPE, input="7/42a8"+"a"*170, encoding="ascii")
                    print(f"[#] ({folder}) test {i} with returncode= {p.returncode} \t stderr= {p.stderr}")
                if args.run_driller :
                    print(f"[*] ({folder}) {i} running driller")
                    os.system(f"shellphuzz -d 1 -c 1 -w workdir/shellphuzz/ -s workdir/input/ -C -t 900 --length-extension 200 ./{i}")
                if args.remove :
                    os.remove(f'{i}')
                    print(f"[!] ({folder}) remove {i}")
            else :
                print(f"[X] ({folder}) {i} not exist")

        print("#"*40)
        os.chdir("..")
        
        if args.time_extractor :
            fuzzer_stats_Extractor(folder, status["cnt"])  


if __name__ == "__main__":
    main()
