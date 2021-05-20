# capshow
Prints out info about capabilities
## Building
You need libcap-dev
```sh
$ sudo apt-get install libcap-dev
```
Then compile using gcc
```sh
$ gcc capShow.c -o capshow -lcap
```
## Usage
Show every capability of all threads
```sh
$ ./capshow
```
Show capabilities of particular process
```sh
$ ./capshow -p pid
```
Show readable version of capabilities
```sh
$ ./capshow -r
```
# capenv
An application locks itself, and all of its descendants, into an environment where the only way of gaining capabilities is by executing a program with associated file capabilities

## Building
You need libcap-ng-dev
```sh
$ sudo apt-get install libcap-ng-dev
```
Then compile using gcc
```sh
$ gcc capEnviron.c -o capenv -lcap-ng
```
## Usage

Run program with some capabilities
```sh
$ sudo ./capenv [capabilities_to_add] -p program_path program_args
```
Run programm without any capabilities

## services

Services were used for testing ways of manipulating capabilities of a program
