package main

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
				fmt.Printf("here: %s\n", err.Error())
				break
			}

			// Uncomment to show each syscall as it's called
			name, _ := sec.ScmpSyscall(regs.Orig_rax).GetName()
			fmt.Printf("Name: %s\n", name)
		}

		err = syscall.PtraceSyscall(pid, 0)
		if err != nil {
			fmt.Printf(err.Error())
			panic(err)
		}

		_, err = syscall.Wait4(pid, nil, 0, nil)
		if err != nil {
			fmt.Printf(err.Error())
			panic(err)
		}

		exit = !exit
	}

}
