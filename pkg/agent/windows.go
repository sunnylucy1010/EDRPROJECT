/**
 * File:    windows.go
 *
 * Summary of File:
 *
 * 	This files containing client function to perform some action with
 *	the Windows operating system, such as:
 *	Kill process, suspend process, resume process.
 *	Delete file, download file.
 *	Block, Unblock firewall windows.
 *	Disable, Enable network adapter windows.
 *	Delete registry key, value.
 */

package agent

import (
	"errors"
	"os/exec"
	"regexp"
	"strings"

	"github.com/shirou/gopsutil/process"
	"golang.org/x/sys/windows/registry"
)

// This function kills the Process Tree
// This is recursive function, call itselt util it reaches the case of
// no children, them kill backward process
func KillTreeProcess(pid32 int32) error {

	// create a new Process instance
	p, err := process.NewProcess(pid32)
	if err != nil {
		return err
	}

	// get a slice pointer of the children of the process
	if children, err := p.Children(); err == nil {

		// If the slice has a length of 0, skip the for loop.
		// Otherwise, call itself for each element in the slice.
		for _, v := range children {
			KillTreeProcess(v.Pid)
		}
	}

	// kill process. If process kills successfully, return nil.
	// otherwise, return error
	return p.Kill()
}

// This function kills the Process
func KillProcess(pid32 int32) error {

	// create a new Process instance
	p, err := process.NewProcess(pid32)
	if err != nil {
		return err
	}

	// kill process. If process kills successfully, return nil.
	// otherwise, return error
	return p.Kill()
}

// This function suppends the Process
func SuspendProcess(pid32 int32) error {

	// create a new Process instance
	if p, err := process.NewProcess(pid32); err != nil {
		return err
	} else {

		// suspend process. If process suspends successfully, return nil.
		// otherwise, return error
		return p.Suspend()
	}
}

// This function resumes the Process
func ResumeProcess(pid32 int32) error {

	// create a new Process instance
	if p, err := process.NewProcess(pid32); err != nil {
		return err
	} else {

		// resume process. If process resumes successfully, return nil.
		// otherwise, return error
		return p.Resume()
	}
}

// This function blocks traffic initiated from external ip to local ip.
// It executes netsh command of Windows OS.
// Example: netsh advfirewall firewall add rule name="BLOCKED IP"
// interface=any dir=in action=block remoteip=192.xxx.xxx.x/xx
func BlockInboundIp(ip string) error {

	name := "name=BLOCK IP " + ip + " INBOUND" // name of firewall rule
	remoteIp := "remoteip=" + ip               // blocked Ip

	// Cmd struct to execute the netsh program with the given arguments
	cmd := exec.Command("netsh", "advfirewall", "firewall", "add", "rule",
		name, "interface=any", "dir=in", "action=block", remoteIp)

	// runs the cmd struct and returns its combined output and error
	if output, err := cmd.CombinedOutput(); err != nil {

		// output is removed special character (\n and \r)
		// and return new error message equal output
		output = output[2 : len(output)-4]
		return errors.New(string(output))
	} else {
		return nil
	}
}

// This function blocks traffic initiated from the local ip to external ip.
// It executes netsh command of Windows OS.
// Example: netsh advfirewall firewall add rule name="BLOCKED IP"
// interface=any dir=out action=block remoteip=192.xxx.xxx.x/xx
func BlockOutboundIp(ip string) error {

	name := "name=BLOCK IP " + ip + " OUTBOUND" // name of firewall rule
	remoteIp := "remoteip=" + ip                // blocked Ip

	// Cmd struct to execute the netsh program with the given arguments
	cmd := exec.Command("netsh", "advfirewall", "firewall", "add", "rule",
		name, "interface=any", "dir=out", "action=block", remoteIp)

	// runs the cmd struct and returns its combined output and error
	if output, err := cmd.CombinedOutput(); err != nil {

		// output is removed special character (\n and \r)
		// and return new error message equal output
		output = output[2 : len(output)-4]
		return errors.New(string(output))
	} else {
		return nil
	}
}

// This function unblocks traffic initiated from external ip to local ip.
// It executes netsh command of Windows OS.
// Example: netsh advfirewall firewall delete rule name="BLOCKED IP"
// remoteip=192.xxx.xxx.x/xx
func UnblockInboundIp(ip string) error {

	name := "name=BLOCK IP " + ip + " INBOUND" // name of firewall rule
	remoteIp := "remoteip=" + ip               // unblocked Ip

	// Cmd struct to execute the netsh program with the given arguments
	cmd := exec.Command("netsh", "advfirewall", "firewall", "delete", "rule",
		name, remoteIp)

	// runs the cmd struct and returns its combined output and error
	if output, err := cmd.CombinedOutput(); err != nil {

		// output is removed special character (\n and \r)
		// and return new error message equal output
		output = output[2 : len(output)-4]
		return errors.New(string(output))
	} else {
		return nil
	}
}

// This function unblocks traffic initiated from the local ip to external ip.
// It executes netsh command of Windows OS.
// Example: netsh advfirewall firewall delete rule name="BLOCKED IP"
// remoteip=192.xxx.xxx.x/xx
func UnblockOutboundIp(ip string) error {

	name := "name=BLOCK IP " + ip + " OUTBOUND" // name of firewall rule
	remoteIp := "remoteip=" + ip                // unblocked Ip

	// Cmd struct to execute the netsh program with the given arguments
	cmd := exec.Command("netsh", "advfirewall", "firewall", "delete", "rule",
		name, remoteIp)

	// runs the cmd struct and returns its combined output and error
	if output, err := cmd.CombinedOutput(); err != nil {

		// output is removed special character (\n and \r)
		// and return new error message equal outputs
		output = output[2 : len(output)-4]
		return errors.New(string(output))
	} else {
		return nil
	}
}

// This function blocks inbound port
// It executes netsh command of Windows OS.
// Example: netsh advfirewall firewall add rule name="BLOCKED PORT"
// interface=any dir=in action=block remoteport=xxxxx
func BlockInboundPort(port string) error {

	name := "name=BLOCK PORT " + port + " INBOUND" // name of firewall rule
	remotePort := "remoteip=" + port               // blocked port

	// Cmd struct to execute the netsh program with the given arguments
	cmd := exec.Command("netsh", "advfirewall", "firewall", "add", "rule",
		name, "interface=any", "dir=in", "action=block", remotePort)

	// runs the cmd struct and returns its combined output and error
	if output, err := cmd.CombinedOutput(); err != nil {

		// output is removed special character (\n and \r)
		// and return new error message equal outputs
		output = output[2 : len(output)-4]
		return errors.New(string(output))
	} else {
		return nil
	}
}

// This function blocks outbound port
// It executes netsh command of Windows OS.
// Example: netsh advfirewall firewall add rule name="BLOCKED PORT"
// interface=any dir=out action=block remoteport=xxxxx
func BlockOutboundPort(port string) error {
	name := "name=BLOCK PORT " + port + " INBOUND" // name of firewall rule
	remotePort := "remoteip=" + port               // blocked port

	// Cmd struct to execute the netsh program with the given arguments
	cmd := exec.Command("netsh", "advfirewall", "firewall", "add", "rule",
		name, "interface=any", "dir=in", "action=block", remotePort)

	// runs the cmd struct and returns its combined output and error
	if output, err := cmd.CombinedOutput(); err != nil {

		// output is removed special character (\n and \r)
		// and return new error message equal outputs
		output = output[2 : len(output)-4]
		return errors.New(string(output))
	} else {
		return nil
	}
}

// This function unblocks inbound port
// It executes netsh command of Windows OS.
// Example: netsh advfirewall firewall delete rule name="BLOCKED PORT"
// remoteport=xxxxx
func UnblockInboundPort(port string) error {
	name := "name=BLOCK PORT " + port + " INBOUND" // name of firewall rule
	remotePort := "remoteip=" + port               // unblocked port

	// Cmd struct to execute the netsh program with the given arguments
	cmd := exec.Command("netsh", "advfirewall", "firewall", "delete", "rule",
		name, remotePort)

	// runs the cmd struct and returns its combined output and error
	if output, err := cmd.CombinedOutput(); err != nil {

		// output is removed special character (\n and \r)
		// and return new error message equal outputs
		output = output[2 : len(output)-4]
		return errors.New(string(output))
	} else {
		return nil
	}
}

// This function unblocks outbound port
// It executes netsh command of Windows OS.
// Example: netsh advfirewall firewall delete rule name="BLOCKED PORT"
// remoteport=xxxxx
func UnblockOutboundPort(port string) error {
	name := "name=BLOCK PORT " + port + " OUTBOUND" // name of firewall rule
	remotePort := "remoteip=" + port                // unblocked port

	// Cmd struct to execute the netsh program with the given arguments
	cmd := exec.Command("netsh", "advfirewall", "firewall", "delete", "rule",
		name, remotePort)

	// runs the cmd struct and returns its combined output and error
	if output, err := cmd.CombinedOutput(); err != nil {

		// output is removed special character (\n and \r)
		// and return new error message equal outputs
		output = output[2 : len(output)-4]
		return errors.New(string(output))
	} else {
		return nil
	}
}

// This function disables Network adapter.
// It executes netsh command of Windows OS.
// Example: netsh interface set interface Ethernet disable
func DisableNetworkAdapter(adapterName string) error {

	// Cmd struct to execute the netsh program with the given arguments
	cmd := exec.Command("netsh", "interface", "set", "interface",
		adapterName, "disable")

	// runs the cmd struct and returns its combined output and error
	if output, err := cmd.CombinedOutput(); err != nil {

		// output is removed special character (\n and \r)
		// and return new error message equal outputs
		output = output[2 : len(output)-4]
		return errors.New(string(output))
	} else {
		return nil
	}
}

// This function enable Network adapter.
// It executes netsh command of Windows OS.
// Example: netsh interface set interface Ethernet enable
func EnableNetworkAdapter(adapterName string) error {

	// Cmd struct to execute the netsh program with the given arguments
	cmd := exec.Command("netsh", "interface", "set", "interface",
		adapterName, "enable")

	// runs the cmd struct and returns its combined output and error
	if output, err := cmd.CombinedOutput(); err != nil {

		// output is removed special character (\n and \r)
		// and return new error message equal outputs
		output = output[2 : len(output)-4]
		return errors.New(string(output))
	} else {
		return nil
	}
}

// Convert key string to Windows Registry Key
func ConvertKey(keyStr string) registry.Key {
	switch keyStr {
	case "HKCR":
		return registry.CLASSES_ROOT
	case "HKCU":
		return registry.CURRENT_USER
	case "HKLM":
		return registry.LOCAL_MACHINE
	case "HKU":
		return registry.USERS
	default:
		return registry.CURRENT_CONFIG
	}
}

// DeleteValue removes a named value from the key k
func DeleteValue(key registry.Key, path string, name string) error {

	// OpenKey opens a new key with path, name
	if k, err := registry.OpenKey(key, path, registry.ALL_ACCESS); err != nil {
		return err
	} else {
		return k.DeleteValue(name) // remove value
	}
}

// This function splits target object (Registry Path) to key string, path, name
func SplitKeyPathName(targetObject string) (string, string, string) {

	// Regex catches character Backslash
	re := regexp.MustCompile(`(?m)\\`)

	// a slice of the substrings after separated the regex matches
	split := re.Split(targetObject, -1)
	keyStr := split[0]
	name := split[len(split)-1]

	// Path of key is string after concatenate the remaining elements of
	// the slice after removing the first and last elements
	path := strings.Join(split[1:len(split)-1], "\\")
	return keyStr, path, name
}

// This function splits target object (Registry Path) to key string, path
func SplitKeyPath(targetObject string) (string, string) {

	// Regex catches character Backslash
	re := regexp.MustCompile(`(?m)\\`)

	// a slice of the substrings after separated the regex matches
	split := re.Split(targetObject, -1)
	keyStr := split[0]

	// Path of key is string after concatenate the remaining elements of
	// the slice after removing the first elements
	path := strings.Join(split[1:], "\\")
	return keyStr, path
}
