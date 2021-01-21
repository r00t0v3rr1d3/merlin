# Gandalf User Guide 

## New Commands
* `ifconfig`/`ipconfig`: Prints host network adapter information. Windows hosts use API calls to get extra info (e.g. DHCP)
* `kill`: Kill a process by pid using Native Go. This stomps over Merlin's `kill`, which tells your agent to honorable sudoku
    * Usage: `kill <pid>`

## Configurable settings
* `sleep` has been modified. Just `sleep 30 60` instead of `set sleep 30s` and `set skew 30000`. In seconds.

## Changes from stock Merlin
* Baby-proofed the server - Ctrl-C and DEL key won't exit the server without a confirmation prompt
* JWT verification tweaked to allow for clock skew between agent and server
* Removed ability to run arbitrary commands from the server
* Agent `info` command will now list the executable name
* Added `kill` command
* Renamed `kill` to `exit`
* A sweet banner
* Removed help menu from agent
* Changed listener default from 127.0.0.1 to 0.0.0.0
* Changed agent `sleep` command and agent behavior
* Updated `sessions` to include a column for last checkin
