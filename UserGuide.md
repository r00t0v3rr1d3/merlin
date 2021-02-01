# Gandalf User Guide 

## New Commands
* `ifconfig`/`ipconfig`: Prints host network adapter information. Windows hosts use API calls to get extra info (e.g. DHCP)
* `kill`: Kill a process by pid using Native Go. This stomps over Merlin's `kill`, which tells your agent to honorable sudoku
    * Usage: `kill <pid>`

## Configurable settings
* `sleep` has been modified. Just `sleep 30 60` instead of `set sleep 30s` and `set skew 30000`. In seconds.
* `ja3`
* `killdate`
* `maxretry`
* `padding`

## Agent Command Line Options (For something quick if you don't want to use gandalf_generate.py)
* `-v`           := Enable verbose output
* `-version`     := Print the agent version and exit
* `-debug`       := Enable debug output
* `-url`         := Full URL for agent to connect to
* `-psk`         := Pre-Shared Key used to encrypt initial communications
* `-proto`       := Protocol for the agent to connect with [https (HTTP/1.1), http (HTTP/1.1 Clear-Text), h2 (HTTP/2), h2c (HTTP/2 Clear-Text), http3 (QUIC or HTTP/3.0)]
* `-proxy`       := Hardcoded proxy to use for http/1.1 traffic only that will override host configuration
* `-host`        := HTTP Host header
* `-ja3`         := JA3 signature string (not the MD5 hash). Overrides -proto flag
* `-waittimemin` := Minimum time for agent to sleep
* `-waittimemax` := Maximum time for agent to sleep
* `-killdate`    := The date, as a Unix EPOCH timestamp, that the agent will quit running
* `-maxretry`    := The maximum amount of failed checkins before the agent will quit running
* `-padding`     := The maximum amount of data that will be randomly selected and appended to every message
* `-useragent`   := The HTTP User-Agent header string that the Agent will use while sending traffic

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
* Updated `sessions` and agent `info` output for more useful information
* Ability to run `sessions` command from any menu
* Ability to `interact` with agents from any menu
* Command `quit` is now the only way to close the server. `exit` is reserved for telling an agent to die.
* Added `create` command in listener menu since `use` wasn't super intuitive
* Renamed `interact` command to `configure` in listener menu because interact is reserved for interacting with agents.
* `?` now displays the help menus in addition to `help`
* `set` commands are no longer. `sleep`, `ja3`, `killdate`, `maxretry`, `padding` are all individual commands now
* The list of available commands (and tab complete) will now have different options for windows/non-windows hosts.
* You may now enter a comma-separated list of URLs for Gandalf to rotate through for callbacks
* Custom agent builder menu-driven python script: gandalf_generate.py
