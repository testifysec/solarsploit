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

## How to mitigate

Set the IMA policy to `tcb`
```GRUB_CMDLINE_LINUX="ima_policy=tcb ima_hash=sha256 ima=on"```

Inspect the IMA log and compare the SHASUM has of the input files to the value in the logs.  Verify the log by calculating the aggrigate of all of the IMA checksums to the value in PCR rgister 10 of the TPM device, they should match. 

![Screenshot from 2021-09-28 23-18-24](https://user-images.githubusercontent.com/6634325/135206145-da183619-2911-48a5-a458-4f7fa3756a56.png)
