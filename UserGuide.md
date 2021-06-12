# Gandalf User Guide 

## New Commands
* `ifconfig`/`ipconfig`: Prints host network adapter information. Windows hosts use API calls to get extra info (e.g. DHCP)
* `kill`: Kill a process by pid using Native Go. This stomps over Merlin's `kill`, which tells your agent to honorable sudoku
    * Usage: `kill <pid>`
* `jobs`: List created (but unsent) jobs across all agents from the main menu
* `queue`: Queue up a command for agents (or groups) from the main menu, even if they haven't come in yet!
    * Usage: `queue <agentID> sleep 300 600`
    * Usage: `queue all ifconfig`
* `note`: Sets a (server-side) note to keep track of agents.
* `group`: Add agents to groups for bulk command processing.
    * Usage: `group add <agentID> <groupName>`
    * Usage: `group remove <agentID> <groupName>`
    * Usage: `group list`
    * Usage (from an agent's menu): `group add <groupName>`
* `sdelete`: Securely delete a given file.
* `touch`: Match destination file's timestamps with source file
    * Usage: `touch <source_file> <destination_file>`
* `ps`: Process listing for Windows agents
* `netstat`: Display network connection for Windows agents (tcp, tcp6, udp, udp6)
    * Usage `netstat [-p tcp|udp]`
* `pipes`: List Windows named pipes
* `uptime`: Print the target system's uptime for Windows agents
* `hibernate`: A one-off immediate sleep in seconds that will survive agent restart
    * Usage `hibernate 86400`
* `env` : View and modify environment variables. "set" will create a new variable if it didn't exist
    * Usage: `env showall`
    * Usage: `env get PATH`
    * Usage: `env set CUSTOM "my desired value"`
    * Usage: `env unset HISTFILE`

## Configurable settings
* `sleep` has been modified. Just `sleep 30 60` instead of `set sleep 30s` and `set skew 30000`. In seconds.
* `ja3`
* `killdate`
* `maxretry`
* `padding`
* `inactivethreshold`: When this many checkins are missed, multiplies sleep times by `inactivemultiplier`
* `inactivemultiplier`: The scaling factor for sleep backoff functionality

## Agent Command Line Options (For something quick if you don't want to use gandalf_generate.py)
* `-dbg`         := Enable verbose output
* `-debug`       := Enable debug output
* `-url`         := Full URL for agent to connect to
* `-psk`         := Pre-Shared Key used to encrypt initial communications
* `-proto`       := Protocol for the agent to connect with [https (HTTP/1.1), http (HTTP/1.1 Clear-Text), h2 (HTTP/2), h2c (HTTP/2 Clear-Text), http3 (QUIC or HTTP/3.0)]
* `-proxy`       := Hardcoded proxy to use for http/1.1 (only http/https) traffic only that will override host configuration
* `-host`        := HTTP Host header
* `-ja3`         := JA3 signature string (not the MD5 hash). Overrides -proto flag
* `-waittimemin` := Minimum time for agent to sleep (in seconds)
* `-waittimemax` := Maximum time for agent to sleep (in seconds)
* `-killdate`    := The date, as a Unix EPOCH timestamp, that the agent will quit running
* `-maxretry`    := The maximum amount of failed checkins before the agent will quit running
* `-padding`     := The maximum amount of data that will be randomly selected and appended to every message
* `-useragent`   := The HTTP User-Agent header string that the Agent will use while sending traffic
* `-inactivethreshold` := Number of checkins with no tasking before agent goes inactive
* `-inactivemultiplier` := Number to multiply waittimemin and waittimemax by every `-inactivethreshold` times an agent checks in with no tasking

## Changes from stock Merlin
* Baby-proofed the server - Ctrl-C and DEL key won't exit the server without a confirmation prompt
* JWT verification tweaked to allow for clock skew between agent and server
* Removed ability to run arbitrary commands from the server
* Agent `info` command will now list the executable name
* Added `kill` command
* Added `sdelete` command
* Added `touch` command
* Added `env` command
* Added `ps` command for Windows agents
* Added `netstat` command for Windows agents
* Added `pipes` command for Windows agents
* Added `uptime` command for Windows agents
* Renamed `kill` to `exit`
* A sweet banner
* Removed help menu from agent
* Changed agent `-v` argument for verbose to `-dbg` to be less guessable
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
* Custom agent builder menu-driven python2 script: gandalf_generate.py; python3 script: py3_gandalf_generate.py
* Adjustment to `jobs` agent output
* Inclusion of global jobs via `queue` and `jobs` from the main menu
* `note`s to keep track of your agents
* `group` to send bulk commands to agents
* pwnboard integration for events such as CCDC using -pwn <address_of_pwnboard>
* When using http or https protocol, the connection only appears in netstat for one second or less
* Added in retrieval of MachineID for AgentInfo to identify unique hosts (eventually will remove external dependency)
* Commands are now executed in the order entered. Results return in order of command completion time
* Sleep backoff functionality: If agents miss several checkins, they will automatically increase their sleep times. Sleep times will also be increased if no commands are issued after several checkins.
* Added `hibernate` command that allows you to sleep an agent for a one-off long period of time, such as between operational days. It utilizes a covert config file to keep track of the sleep amount, so even if the agent restarts due to system restart, new persistence kick-off, etc. - it will still sleep the specified time. Note: after a hibernation, the agent's inactive count will reset to 0 so it will take the full `-inactivethreshold` to begin going inactive again. Also note: if an agent is inactive and the `hibernate` command is issued, once hibernation is complete, the agent will return to the active sleep interval. Another note: the first time the covert config is created, it will attempt to touch itself to the same modified date / time as the agent - if some other time is desired, you will need to touch it once it exists.
* Note regarding shell: if you plan to pipe or redirect output to a file, you must put your entire command in quotes after the `shell` keyword:
 -- shell "last | grep root"
 -- shell "uptime > uptime.txt"