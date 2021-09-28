# SolarSploit

Sample malicious program that emulates the SolarWinds attack vector.

1. Listen for processes that use the go compiler
2. Wait for a syscall to open a main.go file
3. Pause compiler process.
4. Modify contents of main.go, cache legitimate copy.
5. Start compiler
6. Replace contents of trojanized file with original.
