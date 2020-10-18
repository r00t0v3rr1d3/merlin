# Gandalf User Guide

## Commands
### Executing processes
* `exec`: Start a process using Native Go. Renamed from `cmd` and `shell`
* `shinject`: Inject raw shellcode into a process. Renamed from `execute-shellcode`
* `winexec`: Start a process using Windows API calls. Optional ppid spoofing available
	* Usage: `winexec -ppid 500 c:\\notepad.exe`
* `kill`: Kill a process by pid
	* Usage: `kill 500`
### Situational Awareness
* `ps`: Process listing for Windows agents
* `touch`, `timestomp`: Modify a file's timestamps.
	* Usage: `touch "source file" "dest file"
* `note`: Set an agent note to help you keep track of agents.
* `sdelete`: securely delete a file.
	* Usage: `sdelete <filepath>`
* `ipconfig`, `ifconfig`: Get more detailed information on a host's network adapters.
* `nslookup`: Perform lookup of hostname or IP address according to target system default resolver.
### Agent information
* `jobs`: List an agent's currently queued jobs
* `clear`, `c`: Clear queued jobs for an agent
* `queue`: From the main menu, queue up a command for an agent. If the agent doesn't exist yet, it will hold on and send the job along once that agent checks in. Use shortcut `all` uuid `_FFFFFFFF_-FFFF-FFFF-FFFF-FFFFFFFFFFFF`, which sends a command to all agents.
	* Usage: `queue 2b112337-3476-4776-86fa-250b50ac8cfc ipconfig`
	* Usage: `queue all ps`
* `listqueue`: View globally queued jobs that have not been assigned to an agent
* `clearqueue`: Clear globally queued jobs that have not been assigned to an agent.

## Configurable settings
* `sleep` has been modified. Just `sleep 30 60` instead of `set sleep 30s` and `set skew 30000`
* `batchcommands` will tell an agent to keep pulling down jobs until its queue is empty. Default Merlin gets one job per checkin
* `inactivethreshold`: When this many checkins are missed, multiplies sleep times by `inactivemultiplier`
* `inactivemultiplier`: The scaling factor for sleep backoff functionality

## Changelog from stock Merlin
* Baby-proofed the server - mashing keys shouldn't kill your server and you should get an exit confirm prompt
* Commands no longer run asynchronously in agents; settings changes (e.g. sleep time) now take effect immediately
* Agents will now (by default) pull down commands from the server until there are none left, instead of one per checkin.
* Sleep backoff functionality: If agents miss several checkins, they will automatically increase their sleep times.
* Unified syntax for updating agent settings to something rational
* Removed ability to run arbitrary commands from the server
* Implemented `jobs` command to list queued commands that haven't yet been sent to the agent, and `clear` to clear them
* Implemented agent notes, stored server-side only
* Implemented`execute` functionality using Windows API calls. Spoof ppid!
* Implemented `ps` functionality
* Implemented `touch/timestomp` functionality
* Implemented `ipconfig/ifconfig` functionality
* Implemented `nslookup` functionality
* Implemented process killing functionality with `kill`
* Replaced original `kill` with `exit` to cause an agent to kill itself
* Replaced `cmd` and `shell` with `exec`
* Replaced `execute-shellcode` with `shinject`
* A sweet banner
* The list of available commands will now have different options for windows/non-windows hosts. 