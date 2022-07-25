# Stack Based Buffer Overflow test case

## Requirements
- python3
- use virtual environments & install requirements packages ([gist](https://gist.github.com/mheidari98/8ae29b88bd98f8f59828b0ec112811e7)) 
- driller
 ---

## Usage
for compile testcase and test valid input
```bash
./DrillerTester.py --compile --test
```
for run driller
```bash
./DrillerTester.py --compile --run_driller
```
for extract driller runtime
```bash
./DrillerTester.py --time_extractor > result.txt
```
for more options :
```bash
python Wuzzer.py -h
```
