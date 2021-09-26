package main

import "C"

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"

	ps "github.com/mitchellh/go-ps"
	sec "github.com/seccomp/libseccomp-golang"
)

type syscallCounter []int

const maxSyscalls = 303

func main() {
	c := make(chan os.Signal)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-c
		os.Exit(1)
	}()
	for {
		findproc()
	}
}

func findproc() {
	procs, err := ps.Processes()
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	for _, proc := range procs {
		exec := proc.Executable()

		if exec == "go" {
			fmt.Printf("Process Name: go")
			fmt.Printf("Process PID: %d\n", proc.Pid())

			eh, _ := os.FindProcess(proc.Pid())
			exploit(eh.Pid)

		}
	}
}

func exploit(pid int) {
	var regs syscall.PtraceRegs
	var err error
	exit := true

	err = syscall.PtraceAttach(pid)
	if err != nil {
		fmt.Printf(err.Error())
	}

	for {
		if exit {
			err = syscall.PtraceGetRegs(pid, &regs)
			if err != nil {
				break
			}

			// Uncomment to show each syscall as it's called
			name, _ := sec.ScmpSyscall(regs.Orig_rax).GetName()
			if name == "openat" {
				fmt.Printf("Name: %s\n", name)

				path, err := getOpenAtPath(pid, regs)
				if err != nil {
					fmt.Println(err)
				}
				fmt.Printf("Path: %s", path)

			}

		}

		err = syscall.PtraceSyscall(pid, 0)
		if err != nil {
			fmt.Printf(err.Error())
			break
		}

		_, err = syscall.Wait4(pid, nil, 0, nil)
		if err != nil {
			fmt.Printf(err.Error())
			break
		}

		exit = !exit
	}

}

func getOpenAtPath(pid int, regs syscall.PtraceRegs) (string, error) {
	path, err := readString(pid, uintptr(regs.Rsi))
	if err != nil {
		return "", err
	}
	return path, nil
}

func readString(pid int, addr uintptr) (string, error) {
	data := make([]byte, 4096)
	bytes_copied, _ := syscall.PtracePeekData(pid, addr, data)
	if bytes_copied == 0 {
		return "", fmt.Errorf("0-byte string returned")
	}
	str := C.GoString((*C.char)(C.CBytes(data)))
	return str, nil
}
