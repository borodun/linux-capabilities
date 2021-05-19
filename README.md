## capshow
Show every capability of all threads
```sh
capshow
```
Show capabilities of particular process
```sh
capshow -p pid
```
Show readable version of capabilities
```sh
capshow -r
```
## capenv
An application locks itself, and all of its descendants, into an environment where the only way of gaining capabilities is by executing a program with associated file capabilities

Run program with some capabilities
```sh
sudo capenv [capabilities_to_add] -p program program args
```
Run programm without any capabilities

## services

Services were used for testing ways of manipulating capabilities of a program