/**
 * File:    agent.go
 *
 * Summary of File:
 *
 * 	This file contains the code executed by the agent.
 * 	Functions:
 * 	Allowing the user to send information to the EDR server.
 * 	Waiting for requests from the EDR server.
 * 	Executing the request, and returning the execution result.
 */

package agent

import (
	"bkedr/pkg/rpc"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"os"
	"strconv"
	"time"

	"golang.org/x/sys/windows/registry"
)

const CONFIG_PATH = "C:\\Windows\\System32\\BSkedrAgent\\windowsagent.conf"

// Variables use for multiple func

var (
	//Network adapter name is connected to internet
	adapterInternet string
	serverHost      string
	serverPort      string
	AgentHost       string
	AgentPort       string
)

// AgentConfig struct which contains an array of AgentConfigObj
type AgentConfig struct {
	AgentConfig []AgentConfigObj `json:"AgentConfig"`
}

// AgentConfigObj struct is used to decode json of AgentConfig object
type AgentConfigObj struct {
	AdapterInternet string `json:"AdapterInternet"`
	ServerHost      string `json:"ServerHost"`
	ServerPort      string `json:"ServerPort"`
	AgentHost       string `json:"AgentHost"`
	AgentPort       string `json:"AgentPort"`
}

func init() {

	// Get all values of variables from config file
	agentConfig := GetAgentConfig()
	adapterInternet = agentConfig.AgentConfig[0].AdapterInternet
	serverHost = agentConfig.AgentConfig[0].ServerHost
	serverPort = agentConfig.AgentConfig[0].ServerPort
	AgentHost = agentConfig.AgentConfig[0].AgentHost
	AgentPort = agentConfig.AgentConfig[0].AgentPort
	fmt.Println(serverHost, serverPort, AgentHost, AgentPort, adapterInternet)
}

// This function returns the pointer of ServerConfig
func GetAgentConfig() *AgentConfig {

	// read opened config file as a byte array.
	byteValue, err := ioutil.ReadFile(CONFIG_PATH)

	// If the config cannot be loaded, exit the program
	if err != nil {
		fmt.Println("Load bkedr agent config error: ", err)
		os.Exit(1)
	}

	agentConfig := AgentConfig{}
	json.Unmarshal(byteValue, &agentConfig) // Json decoding
	return &agentConfig
}

// AgentGRPCService is a implementation of ManagerServer Grpc Service
type AgentGRPCService struct{}

// NewAgentGRPCService returns the pointer to the implementation
func NewAgentGRPCService() *AgentGRPCService {
	return &AgentGRPCService{}
}

// Struct computer name and a agent host and port
type AgentInfo struct {
	ComputerName string
	AgentHost    string
	AgentPort    string
}

// This function is used to send Computername to the EDR server
// Function returns null if no error occurs, and returns an error otherwise
func RunSocketDial() error {

	// Create a dial connection using host and port that pass to this function
	con, err := net.Dial("tcp", serverHost+":"+serverPort)
	if err != nil {
		return err
	}
	defer con.Close()

	// Initializing the struct with computername equals the hostname that
	// OS returns, host and port agent listening
	computerName, _ := os.Hostname()
	AgentInfo := &AgentInfo{
		ComputerName: computerName,
		AgentHost:    AgentHost,
		AgentPort:    AgentPort,
	}

	data, err := json.Marshal(AgentInfo) // Json Encoding of agentInfo
	if err != nil {
		return err
	}

	// Send Computername to the EDR server with a timeout of 30 seconds
	con.SetWriteDeadline(time.Now().Add(30 * time.Second))
	if _, err = con.Write([]byte(string(data) + "\n")); err != nil {
		return err
	}
	return nil
}

// ManagerEventCode1 function implementation of gRPC Service.
// This function handles a request  with Event Code 1 (Process creation)
// sent by the EDR Server and returns a  ResponseResult. Action support:
//   - kill: processId
//   - kill tree: processId
//   - suspend: processId
//   - getfile: Image (Func ManagerGetFile())
func (*AgentGRPCService) ManagerEventCode1(
	ctx context.Context, in *rpc.EventCode1) (*rpc.ResponseResult, error) {

	var resultInfo string
	var result = true

	action := in.GetAction()
	pid := in.GetProcessId()
	pid32 := ConvertStringToInt32(pid)

	// Handle the EventCode 1 based on action variable
	switch action {
	// In this case, the agent kills the Process Tree.
	case "killtree":
		if err := KillTreeProcess(pid32); err != nil {
			resultInfo = "Error kills tree ProcessId " + pid + ": " + err.Error()
			result = false
		} else {
			resultInfo = "Success kills tree ProcessId " + pid
		}
	// In this case, the agent kills the Process
	case "kill":
		if err := KillProcess(pid32); err != nil {
			resultInfo = "Error kills ProcessId " + pid + ": " + err.Error()
			result = false
		} else {
			resultInfo = "Success kills ProcessId " + pid
		}
	// In this case, the agent suspends the Process
	case "suspend":
		if err := SuspendProcess(pid32); err != nil {
			resultInfo = "Error suppeds ProcessId " + pid + ": " + err.Error()
			result = false
		} else {
			resultInfo = "Success suspends ProcessId " + pid
		}
	default:
		resultInfo = "Error: Action " + action +
			" is not supported for EventCode 1"
		result = false
	}

	return &rpc.ResponseResult{
		ResultInfo: resultInfo,
		Result:     result,
	}, nil
}

// ManagerEventCode3 function implementation of gRPC Service.
// This function handles a request with Event Code 3 (Network connection) sent
// by the EDR Server and returns a ResponseResult. Action support:
//   - kill: ProcessId
//   - kill tree: ProcessId
//   - block inbound ip: SourceIp
//   - block outbound ip: DestinationIp
func (*AgentGRPCService) ManagerEventCode3(
	ctx context.Context, in *rpc.EventCode3) (*rpc.ResponseResult, error) {

	var resultInfo string
	var result = true

	action := in.GetAction()
	pid := in.GetProcessId()
	pid32 := ConvertStringToInt32(pid)
	sIp := in.GetSourceIp()
	dIp := in.GetDestinationIp()

	// Handle the EventCode 3 based on action variable
	switch action {
	// In this case, the agent kills the Process Tree.
	case "killtree":
		if err := KillTreeProcess(pid32); err != nil {
			resultInfo = "Error kills tree ProcessId " + pid + ": " + err.Error()
			result = false
		} else {
			resultInfo = "Success kills tree ProcessId " + pid
		}
	// In this case, the agent kills the Process
	case "kill":
		if err := KillProcess(pid32); err != nil {
			resultInfo = "Error kills ProcessId " + pid + ": " + err.Error()
			result = false
		} else {
			resultInfo = "Success kills ProcessId " + pid
		}
	// In this case, the agent blocks traffic initiated from external ip
	// to local ip.
	case "block_src_ip":
		if err := BlockInboundIp(sIp); err != nil {
			resultInfo = "Error blocks inbound ip " + sIp + ": " + err.Error()
			result = false
		} else {
			resultInfo = "Success blocks inbound ip " + sIp
		}
	// In this case, the agent blocks traffic initiated from the local ip
	// to external ip.
	case "block_dst_ip":
		if err := BlockOutboundIp(dIp); err != nil {
			resultInfo = "Error blocks outbound ip " + dIp + ": " + err.Error()
			result = false
		} else {
			resultInfo = "Success blocks outbound ip " + dIp
		}
	default:
		resultInfo = "Error: Action " + action +
			" is not supported for EventCode 3"
		result = false
	}

	return &rpc.ResponseResult{
		ResultInfo: resultInfo,
		Result:     result,
	}, nil
}

// ManagerEventCode7 function implementation of gRPC Service.
// This function handles a request with Event Code 7 (Image load) sent by
// the EDR Server and returns a ResponseResult. Action support:
//   - kill: processId
//   - kill tree: processId
//   - delete: ImageLoaded
//   - get file: ImageLoaded (Func ManagerGetFile())
func (*AgentGRPCService) ManagerEventCode7(
	ctx context.Context, in *rpc.EventCode7) (*rpc.ResponseResult, error) {

	var resultInfo string
	var result = true

	action := in.GetAction()
	pid := in.GetProcessId()
	pid32 := ConvertStringToInt32(pid)
	filePath := in.GetImageLoaded()

	// Handle the EventCode 7 based on action variable
	switch action {
	// In this case, the agent kills the Process Tree.
	case "killtree":
		if err := KillTreeProcess(pid32); err != nil {
			resultInfo = "Error kills tree ProcessId " + pid + ": " + err.Error()
			result = false
		} else {
			resultInfo = "Success kills tree ProcessId " + pid
		}
	// In this case, the agent kills the Process
	case "kill":
		if err := KillProcess(pid32); err != nil {
			resultInfo = "Error kills ProcessId " + pid + ": " + err.Error()
			result = false
		} else {
			resultInfo = "Success kills ProcessId " + pid
		}
	// In this case, the agent deletes the created file
	case "delete":
		if err := os.Remove(filePath); err != nil {
			resultInfo = "Error deletes file " + filePath + ": " + err.Error()
			result = false
		} else {
			resultInfo = "Success deletes file " + filePath
		}
	default:
		resultInfo = "Error: Action " + action +
			" is not supported for EventCode 7"
		result = false
	}

	return &rpc.ResponseResult{
		ResultInfo: resultInfo,
		Result:     result,
	}, nil
}

// ManagerEventCode8 function implementation of gRPC Service.
// This function handles a request with Event Code 8 (CreateRemoteThread)
// sent by the EDR Server and returns a ResponseResult. Action support:
//   - kill: SourceProcessId
//   - kill tree: SourceProcessId
func (*AgentGRPCService) ManagerEventCode8(
	ctx context.Context, in *rpc.EventCode8) (*rpc.ResponseResult, error) {

	var resultInfo string
	var result = true

	action := in.GetAction()
	pid := in.GetSourceProcessId()
	pid32 := ConvertStringToInt32(pid)

	// Handle the EventCode 8 based on action variable
	switch action {
	// In this case, the agent kills the Source Process Tree.
	case "killtree":
		if err := KillTreeProcess(pid32); err != nil {
			resultInfo = "Error kills tree ProcessId " + pid + ": " + err.Error()
			result = false
		} else {
			resultInfo = "Success kills tree ProcessId " + pid
		}
	// In this case, the agent kills the Source Process
	case "kill":
		if err := KillProcess(pid32); err != nil {
			resultInfo = "Error kills ProcessId " + pid + ": " + err.Error()
			result = false
		} else {
			resultInfo = "Success kills ProcessId " + pid
		}
	default:
		resultInfo = "Error: Action " + action +
			" is not supported for EventCode 8"
		result = false
	}

	return &rpc.ResponseResult{
		ResultInfo: resultInfo,
		Result:     result,
	}, nil
}

// ManagerEventCode9 function implementation of gRPC Service.
// This function handles a request with EventCode 9 (RawAccessRead)
// sent by the EDR Server and returns a ResponseResult. Action support:
//   - kill: ProcessId
//   - kill tree: ProcessId
func (*AgentGRPCService) ManagerEventCode9(
	ctx context.Context, in *rpc.EventCode9) (*rpc.ResponseResult, error) {

	var resultInfo string
	var result = true

	action := in.GetAction()
	pid := in.GetProcessId()
	pid32 := ConvertStringToInt32(pid)

	// Handle the EventCode 9 based on action variable
	switch action {
	// In this case, the agent kills the Process Tree.
	case "killtree":
		if err := KillTreeProcess(pid32); err != nil {
			resultInfo = "Error kills tree ProcessId " + pid + ": " + err.Error()
			result = false
		} else {
			resultInfo = "Success kills tree ProcessId " + pid
		}
	// In this case, the agent kills the Process
	case "kill":
		if err := KillProcess(pid32); err != nil {
			resultInfo = "Error kills ProcessId " + pid + ": " + err.Error()
			result = false
		} else {
			resultInfo = "Success kills ProcessId " + pid
		}
	default:
		resultInfo = "Error: Action " + action +
			" is not supported for EventCode 9"
		result = false
	}

	return &rpc.ResponseResult{
		ResultInfo: resultInfo,
		Result:     result,
	}, nil
}

// ManagerEventCode10 function implementation of gRPC Service.
// This function handles a request with EventCode 10 (ProcessAccess)
// sent by the EDR Server and returns a ResponseResult. Action support:
//   - kill: ProcessId
//   - kill tree: ProcessId
func (*AgentGRPCService) ManagerEventCode10(
	ctx context.Context, in *rpc.EventCode10) (*rpc.ResponseResult, error) {

	var resultInfo string
	var result = true

	action := in.GetAction()
	pid := in.GetProcessId()
	pid32 := ConvertStringToInt32(pid)

	// Handle the EventCode 10 based on action variable
	switch action {
	// In this case, the agent kills the Process Tree.
	case "killtree":
		if err := KillTreeProcess(pid32); err != nil {
			resultInfo = "Error kills tree ProcessId " + pid + ": " + err.Error()
			result = false
		} else {
			resultInfo = "Success kills tree ProcessId " + pid
		}
	// In this case, the agent kills the Process
	case "kill":
		if err := KillProcess(pid32); err != nil {
			resultInfo = "Error kills ProcessId " + pid + ": " + err.Error()
			result = false
		} else {
			resultInfo = "Success kills ProcessId " + pid
		}
	default:
		resultInfo = "Error: Action " + action +
			" is not supported for EventCode 10"
		result = false
	}

	return &rpc.ResponseResult{
		ResultInfo: resultInfo,
		Result:     result,
	}, nil
}

// ManagerEventCode11 function implementation of gRPC Service.
// This function handles a request with EventCode 11 (FileCreate)
// sent by the EDR Server and returns a ResponseResult. Action support:
//   - delete: TargetFilename
//   - get file: TargetFilename
func (*AgentGRPCService) ManagerEventCode11(
	ctx context.Context, in *rpc.EventCode11) (*rpc.ResponseResult, error) {

	var resultInfo string
	var result = true

	action := in.GetAction()
	filePath := in.GetTargetFilename()

	// Handle the EventCode 11 based on action variable
	switch action {
	// In this case, the agent deletes the newly created file
	case "delete":
		if err := os.Remove(filePath); err != nil {
			resultInfo = "Error deletes file " + filePath + ": " + err.Error()
			result = false
		} else {
			resultInfo = "Success deletes file " + filePath
		}
	default:
		resultInfo = "Error: Action " + action +
			" is not supported for EventCode 11"
		result = false
	}

	return &rpc.ResponseResult{
		ResultInfo: resultInfo,
		Result:     result,
	}, nil
}

// ManagerEventCode12 function implementation of gRPC Service.
// This function handles a request with EventCode 12 (RegistryEvent Object
// create and delete) sent by the EDR Server and returns a ResponseResult.
// Action support:
//   - delete: TargetObject (key)
func (*AgentGRPCService) ManagerEventCode12(
	ctx context.Context, in *rpc.EventCode12) (*rpc.ResponseResult, error) {

	var resultInfo string
	var result = true

	// Get key, path of Registry Key
	targetObject := in.GetTargetObject()
	keyStr, path := SplitKeyPath(targetObject)
	key := ConvertKey(keyStr)

	action := in.GetAction()
	// Handle the EventCode 12 based on action variable
	switch action {
	// In this case, the agent delete the Registry Key
	case "delete":
		if err := registry.DeleteKey(key, path); err != nil {
			resultInfo = "Error deletes Registry Key " + targetObject + ": " + err.Error()
			result = false
		} else {
			resultInfo = "Success deletes Registry Key " + targetObject
		}
	default:
		resultInfo = "Error: Action " + action +
			" is not supported for EventCode 12"
		result = false
	}

	return &rpc.ResponseResult{
		ResultInfo: resultInfo,
		Result:     result,
	}, nil
}

// ManagerEventCode13 function implementation of gRPC Service.
// This function handles a request with EventCode 13 (RegistryEvent Value Set)
// sent by the EDR Server and returns a ResponseResult. Action support:
//   - delete: TargetObject (value)
func (*AgentGRPCService) ManagerEventCode13(
	ctx context.Context, in *rpc.EventCode13) (*rpc.ResponseResult, error) {

	var resultInfo string
	var result = true

	// Get key, path of Registry Key
	targetObject := in.GetTargetObject()
	keyStr, path, name := SplitKeyPathName(targetObject)
	key := ConvertKey(keyStr)

	action := in.GetAction()
	// Handle the EventCode 13 based on action variable
	switch action {
	// In this case, the agent delete the Registry Value
	case "delete":
		if err := DeleteValue(key, path, name); err != nil {
			resultInfo = "Error deletes Registry Value " + targetObject + ": " + err.Error()
			result = false
		} else {
			resultInfo = "Success deletes Registry Value " + targetObject
		}
	default:
		resultInfo = "Error: Action " + action +
			" is not supported for EventCode 13"
		result = false
	}

	return &rpc.ResponseResult{
		ResultInfo: resultInfo,
		Result:     result,
	}, nil
}

// ManagerEventCode14 function implementation of gRPC Service.
// This function handles a request with EventCode 14 (RegistryEvent Registry
// object renamed) sent by the EDR Server and returns a ResponseResult.
// Action support:
//   - delete: TargetObject (key)
func (*AgentGRPCService) ManagerEventCode14(
	ctx context.Context, in *rpc.EventCode14) (*rpc.ResponseResult, error) {

	var resultInfo string
	var result = true

	// Get key, path of Registry Key
	newName := in.GetNewName()
	keyStr, path := SplitKeyPath(newName)
	key := ConvertKey(keyStr)

	action := in.GetAction()
	// Handle the EventCode 14 based on action variable
	switch action {
	// In this case, the agent delete the Registry Key
	case "delete":
		if err := registry.DeleteKey(key, path); err != nil {
			resultInfo = "Error deletes Registry Key " + newName + ": " + err.Error()
			result = false
		} else {
			resultInfo = "Success deletes Registry Key " + newName
		}
	default:
		resultInfo = "Error: Action " + action +
			" is not supported for EventCode 14"
		result = false
	}

	return &rpc.ResponseResult{
		ResultInfo: resultInfo,
		Result:     result,
	}, nil
}

// ManagerNetworkAdapter function implementation of gRPC Service.
// This function handles a request with Network Adapter sent
// by the EDR Server and returns a ResponseResult.
// Action support:
//   - Disable: adapterInternet
func (*AgentGRPCService) ManagerNetworkAdapter(
	ctx context.Context, in *rpc.NetworkAdapter) (*rpc.ResponseResult, error) {

	var resultInfo string
	var result = true

	action := in.GetAction()
	switch action {
	// Disable adapter network that connect to internet
	case "disable":
		if err := DisableNetworkAdapter(adapterInternet); err != nil {
			resultInfo = "Error disable Network Adapter " + adapterInternet +
				": " + err.Error()
			result = false
		} else {
			resultInfo = "Success disable Network Adapter " + adapterInternet
		}
	// Enable adapter network that connect to internet
	case "enable":
		if err := EnableNetworkAdapter(adapterInternet); err != nil {
			resultInfo = "Error enable Network Adapter " + adapterInternet +
				": " + err.Error()
			result = false
		} else {
			resultInfo = "Success enable Network Adapter " + adapterInternet
		}
	default:
		resultInfo = "Error: Action " + action +
			" is not supported for Network Adapter"
		result = false
	}

	return &rpc.ResponseResult{
		ResultInfo: resultInfo,
		Result:     result,
	}, nil
}

// ManagerGetFile function implementation of gRPC Service.
// This function handles a Download File request sent by the EDR Server
func (*AgentGRPCService) ManagerGetFile(FileInfoObj *rpc.FileInfo,
	ResultFileStream rpc.Manager_ManagerGetFileServer) error {

	// 64KiB, buffer length
	bufferSize := 64 * 1024

	file, err := os.Open(FileInfoObj.GetFilePath())
	if err != nil {
		return err
	}
	defer file.Close()

	// Create a slice buff that stores bytes read in buffer
	buff := make([]byte, bufferSize)

	// Read the file multiple times, each time read up to buffer Size bytes,
	// Save them in slice buff and send the changed slice buff to the
	// EDR Server. Keep doing this until the file is finished reading.
	for {

		// Read up to bufferSize bytes, and stores them to slice buff
		bytesRead, err := file.Read(buff)

		// If the error is equal to io.EOF, read file is done,
		// exits the loop and ends the file sending.
		// If an error occurs when the file is not finished reading,
		// stop the reading process and return an error.
		if err != nil {
			if err != io.EOF {
				return err
			}
			break
		}

		// Initializing FileData with FileChunk equals as changed
		// slice buff, length is the number of bytes read
		resp := &rpc.FileData{
			FileChunk: buff[:bytesRead],
		}

		// Send resp to EDR server
		if err = ResultFileStream.Send(resp); err != nil {
			return err
		}
	}
	return nil
}

// This function converts string number to int32 number
func ConvertStringToInt32(numberString string) int32 {
	number, _ := strconv.Atoi(numberString)
	return int32(number)
}
