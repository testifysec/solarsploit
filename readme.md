# SolarSploit

Sample malicious program that emulates the SolarWinds attack vector.

1. Listen for processes that use the go compiler
2. Wait for a syscall to open a main.go file
3. Pause compiler process.
4. Modify contents of main.go, cache legitimate copy.
5. Start compiler
6. Replace contents of trojanized file with the original.

## How to use

**Warning** this software will modify files in your system.  Use in a non-production environment only.  This does not work 100% of the time.  I think there are some issues with the way Go handles threading, which occasionally causes the tracing to fail.  If you have a fix please submit a PR.


1.  compile program
`go build .`
2.  Run `solarsploit` as root
3.  In another terminal compile a Go program that includes a file name of `main.go`
4.  `Solarsploit` will inject the following `init function`
```
func init() {
	fmt.Println("Your code is hacked")
}
```
