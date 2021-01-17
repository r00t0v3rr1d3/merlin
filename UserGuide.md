# Gandalf User Guide 

## New Commands
* `ifconfig`/`ipconfig`: Prints host network adapter information. Windows hosts use API calls to get extra info (e.g. DHCP)


## Changes from stock Merlin
* Baby-proofed the server - Ctrl-C and DEL key won't exit the server without a confirmation prompt
* JWT verification tweaked to allow for clock skew between agent and server
* Removed ability to run arbitrary commands from the server
* Agent `info` command will now list the executable name