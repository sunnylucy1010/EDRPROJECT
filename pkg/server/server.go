/**
 * File:    server.go
 * Summary of File:
 *
 * 	This file contains code that is executed by the bkedr server.
 * 	Functions:
 * 	Allowing the server to read the rule, add the rule from the splunk server.
 * 	Getting log from Splunk server.
 * 	Checking that the log matches the rule with an automatic response mechanism.
 * 	Downloading the file from the agent machine.
 * 	Sending the request to the agent and writing the response to a log file.
 */

package server

import (
	"bkedr/pkg/rpc"
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"os"
	"regexp"
	"strings"

	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"
)

const CONFIG_PATH = "./configs/server.conf"

// Variables use for multiple func
var (
	// Parent directory of downloaded agent directory
	parentDirPath string
	// File save result log after done request agent
	resultLogPath string
	// File saves rules that be used to automatically respond
	ruleFilePath string
	// File save app log message
	appLogPath string
	// File save agent info to create grpc connection
	agentsConfPath string
	// Host of splunk server
	splunkHost string
	// Host for bkedr Server
	serverHost string
	// Port for bkedr Server
	serverPort string
	// Rules are used to automatically respond
	rules []map[string]interface{}
	// map computerName with agent Connection
	mapClientConns   = make(map[string]*grpc.ClientConn)
	sliceAgentConfig = make([]map[string]string, 0)
)

// ServerConfig struct which contains an array of ServerConfigObj
type ServerConfig struct {
	ServerConfig []ServerConfigObj `json:"ServerConfig"`
}

// ServerConfigObj struct is used to decode json of ServerConfig object
type ServerConfigObj struct {
	ParentDirPath  string `json:"ParentDirPath"`
	ResultLogPath  string `json:"ResultLogPath"`
	RuleFilePath   string `json:"RuleFilePath"`
	AppLogPath     string `json:"AppLogPath"`
	AgentsConfPath string `json:"AgentsConfPath"`
	SplunkHost     string `json:"SplunkHost"`
	ServerHost     string `json:"ServerHost"`
	ServerPort     string `json:"ServerPort"`
}

func init() {

	// Get all values of variables from config file
	serverConfig := GetServerConfig()
	parentDirPath = serverConfig.ServerConfig[0].ParentDirPath
	resultLogPath = serverConfig.ServerConfig[0].ResultLogPath
	ruleFilePath = serverConfig.ServerConfig[0].RuleFilePath
	appLogPath = serverConfig.ServerConfig[0].AppLogPath
	agentsConfPath = serverConfig.ServerConfig[0].AgentsConfPath
	splunkHost = serverConfig.ServerConfig[0].SplunkHost
	serverHost = serverConfig.ServerConfig[0].ServerHost
	serverPort = serverConfig.ServerConfig[0].ServerPort
	sliceAgentConfig = ReadSliceMapString(agentsConfPath)

	// Get all rules from rule file
	rules = ReadSliceMapInterface(ruleFilePath)

	// Log as JSON instead of the default ASCII formatter.
	log.SetFormatter(&log.JSONFormatter{})

	// Open file/create file is used to store app log message
	f, err := os.OpenFile(appLogPath, os.O_APPEND|os.O_CREATE|os.O_RDWR, 0666)
	if err != nil {
		fmt.Printf("error opening file: %v", err)
		os.Exit(1)
	}
	log.SetOutput(f)             // SetOutput sets the standard logger output
	log.SetLevel(log.DebugLevel) // Only log the debud severity or above.

	// Create all GRPC dial connection from agent config file
	CreateGrpcDial()
}

// This function returns the pointer of ServerConfig
func GetServerConfig() *ServerConfig {

	// read opened config file as a byte array.
	byteValue, err := ioutil.ReadFile(CONFIG_PATH)

	// If the config cannot be loaded, exit the program
	if err != nil {
		fmt.Println("Load Server Config error: ", err)
		os.Exit(1)
	}

	serverConfig := ServerConfig{}
	json.Unmarshal(byteValue, &serverConfig) // Json decoding
	return &serverConfig
}

// This function is used to write app log message to AppLogPath
func WriteAppLogInfo(args ...interface{}) {

	hostname, err := os.Hostname()

	// If get hostname is error, set default hostname: bkedrServer
	if err != nil {
		fmt.Println("Get Hostname Error. Default hostname: bkedrServer")
		hostname = "bkedrServer"
	}

	// creates an entry from the standard logger and adds hostname
	// field and message is errApp
	log.WithFields(log.Fields{
		"Hostname": hostname,
	}).Info(args...)
}

// This function is used to write app log message to AppLogPath
func WriteAppLogError(args ...interface{}) {

	hostname, err := os.Hostname()

	// If get hostname is error, set default hostname: bkedrServer
	if err != nil {
		fmt.Println("Get Hostname Error. Default hostname: bkedrServer")
		hostname = "bkedrServer"
	}

	// creates an entry from the standard logger and adds hostname
	// field and message is errApp
	log.WithFields(log.Fields{
		"Hostname": hostname,
	}).Error(args...)
}

// Create all GRPC dial connection from sliceAgentConfig
func CreateGrpcDial() {

	// try create all grpc client connection from sliceAgentConfig
	for _, agentConfig := range sliceAgentConfig {
		agentAddress := agentConfig["AgentHost"] + ":" + agentConfig["AgentPort"]
		computerName := agentConfig["ComputerName"]

		// Dial creates a client connection to the given target
		agentConn, err := grpc.Dial(agentAddress, grpc.WithInsecure())
		if err != nil {
			WriteAppLogError(err)
		} else {
			// save grpc client connection to mapClientConns
			mapClientConns[computerName] = agentConn
			WriteAppLogInfo("Success creates dial client connection to " + agentAddress)
		}
	}
}

// This function starts bkedr Service's server
func StartServer() {

	serverAdress := serverHost + ":" + serverPort

	// Open TCP server using host and port that pass to this function
	l, err := net.Listen("tcp", serverAdress)

	// If the TCP server can not be started, print the message,
	// store app log and exit the program
	if err != nil {
		fmt.Println("Error listening:", err)
		WriteAppLogError(err)
		os.Exit(1)
	} else {
		fmt.Println("Starting TCP server on " + serverAdress)
		WriteAppLogInfo("Starting TCP server on " + serverAdress)
	}
	defer l.Close()

	// Loop is used to listen for incoming connection.
	for {
		// Accept waits for and returns the next connection to the listener
		conn, err := l.Accept()

		// If connection is error,  exit the program
		if err != nil {
			fmt.Println("Error connecting:", err.Error())
			WriteAppLogError(err)
			os.Exit(1)
		}

		host, _, _ := net.SplitHostPort(conn.RemoteAddr().String())

		// check if host equal splunk host, pass conn to HandleSplunkConn
		// Otherwise, pass conn to Windows
		if host == splunkHost {
			go HandleSplunkConn(conn) // Handle connections in a new goroutine.
		} else {
			go HandleWindowsConn(conn) // Handle connections in a new goroutine.
		}
	}
}

// This function is used to handles incoming request from Windows agent.
// After receiving agent's config, bkedr server creates connection that used
// remote and send request to agent server.
// If the agent's ComputerName already exists in the Config file, we check
// to see if the agent's host and port have been changed. If it changes, we
// delete the old config and add the changed config to the slice.
// Then record the changes to the Config file
// If the agent's ComputerName is not in the config file, we add a new
// config to the slice and to the config file.
func HandleWindowsConn(conn net.Conn) {

	// receive a message from Windows agent
	netData, _ := bufio.NewReader(conn).ReadString('\n')

	// convert string json to map String
	agentInterface := ConvertJsonToInterface(netData)
	agentConfig := ConvertInterfaceToString(agentInterface)

	computerName := agentConfig["ComputerName"]
	agentHost := agentConfig["AgentHost"]
	agentPort := agentConfig["AgentPort"]
	agentAddress := agentHost + ":" + agentPort

	agentExist := false // variable check agent is exist

	// Loop is used to check agent is exist in sliceAgentConfig
	for index, agent := range sliceAgentConfig {
		if agent["ComputerName"] == computerName {

			// If ComputerName already exists, but host or port is change, update old config
			if agent["AgentHost"] != agentHost || agent["AgentPort"] != agentPort {
				sliceAgentConfig[index]["AgentHost"] = agentHost
				sliceAgentConfig[index]["AgentPort"] = agentPort
				if err := WriteSliceMapString(agentsConfPath, sliceAgentConfig); err != nil {
					WriteAppLogError(err)
				} else {
					WriteAppLogInfo("Success changes agent config " + computerName + " to file")
				}
			}
			agentExist = true
			break
		}
	}

	// if agent is new, add config to the slice and add config to the config files
	if !agentExist {
		sliceAgentConfig = append(sliceAgentConfig, agentConfig)
		if err := WriteMapString(agentsConfPath, agentConfig); err != nil {
			WriteAppLogError(err)
		} else {
			WriteAppLogInfo("Success adds agent config " + computerName + " to file")
		}
	}

	// Dial creates a client connection to the given target
	agentConn, err := grpc.Dial(agentAddress, grpc.WithInsecure())
	if err != nil {
		WriteAppLogError(err)
	} else {
		// save grpc client connection to mapClientConns
		mapClientConns[computerName] = agentConn
		WriteAppLogInfo("Success creates dial client connection to " + agentAddress)
	}

	conn.Close()
}

// This function is used to handles incoming request from splunk server
// If the log is sent by the administrator, the log has assigned "action"
// and executes the response. If not, compare the rule. If the rule
// matches, assign the action and execute the response
func HandleSplunkConn(conn net.Conn) {

	// loop is used to recieve messages from splunk server
	for {
		// receive a message from Windows agent
		jsonString, _ := bufio.NewReader(conn).ReadString('\n')
		if jsonString == "" {
			break
		}

		// convert string json to map interface
		logMapInterface := ConvertJsonToInterface(jsonString)

		// if the key "Rule Action" exists, this log is sent to update rules.
		if _, ok := logMapInterface["Action Rule"]; ok {
			if err := HandleRule(jsonString); err != nil {
				WriteAppLogError(err)
			}
			break
		}

		// convert string json to map string
		logMapString := ConvertInterfaceToString(logMapInterface)
		computerName := logMapString["ComputerName"]
		connRequest := mapClientConns[computerName]

		// if the key "action" exists, this log is sent by the administrator.
		if _, ok := logMapString["Action"]; ok {

			// GRPC Connection has a key in the Map equal to the
			// ComputerName of the received message
			connRequest := mapClientConns[computerName]
			HandleRespone(connRequest, logMapString)
			break
			//If not, compare the rule
		} else {

			//the slice log after filtering rules
			objRequests := FilterRulesLog(logMapString)

			// check length of the slice log, if it not empty, call response
			// function for each log
			if len(objRequests) != 0 {
				for _, objRequest := range objRequests {
					HandleRespone(connRequest, objRequest)
				}
			}
		}
	}
}

// This function handle rules base on "Rule Action".
// In case "Rule Action" equal "delete", We will delete a rule in the rules file
// and update the current slice rules.
// In case "Rule Action" equal "add", We will add a new rule in the rules file
// and update the current slice rules.
func HandleRule(ruleString string) error {

	// format,
	ruleString = strings.Replace(ruleString, "\"{", "{", -1)
	ruleString = strings.Replace(ruleString, "}\"", "}", -1)
	ruleString = strings.Replace(ruleString, "\\\"", "\"", -1)

	ruleInterface := ConvertJsonToInterface(ruleString)
	ruleAction := fmt.Sprintf("%v", ruleInterface["Action Rule"])
	delete(ruleInterface, "Action Rule") // delete the key "Rule action"

	switch ruleAction {
	case "delete":

		for index, rule := range rules {

			// map[string]string of data of rule is used to compare field of two data
			data1 := ConvertInterfaceToString(rule["Data"].(map[string]interface{}))
			data2 := ConvertInterfaceToString(ruleInterface["Data"].(map[string]interface{}))

			// If all fields of rulesent and rule are equal, we delete the rule at the
			// index position and update the changes to the rules file and rules slice.
			if rule["Type"] == ruleInterface["Type"] && rule["Message"] == ruleInterface["Message"] &&
				rule["Action"] == ruleInterface["Action"] && CheckMapEqual(data1, data2) {

				// // Remove the element at index from slice.
				copy(rules[index:], rules[index+1:]) // Shift rules[index+1:] left one index
				rules[len(rules)-1] = nil            //Erase last element (write nil value)
				rules = rules[:len(rules)-1]         //Truncate slice.

				// delete a rule in the rules file
				if err := WriteSliceMapInterface(ruleFilePath, rules); err != nil {
					return err
				}
				break
			}
		}

	case "add":

		// add a new rule in the rules file and slice rule

		rules = append(rules, ruleInterface)
		if err := WriteMapInterface(ruleFilePath, ruleInterface); err != nil {
			return err
		}
	}
	WriteAppLogInfo("Success " + ruleAction + " rule")
	return nil
}

// This function handle response for each of "Action" or "EventCode"
// In case "Action" equal "get file" or "disable", we have only one function
// that send request to agent. Other case, we send request base on EventCode.
// After receiving ResponseResult, write it to result log file.
func HandleRespone(clientConn *grpc.ClientConn, objRequest map[string]string) {

	// send request base on "Action" value
	if objRequest["Action"] == "getfile" { // download file from agent
		resultFile := RequestGetFile(objRequest, clientConn)
		HandleResult(resultFile, objRequest)

		// disable network adapter
	} else if objRequest["Action"] == "disable" || objRequest["Action"] == "enable" {
		resultNetAdapt := RequestNetworkAdapter(objRequest, clientConn)
		HandleResult(resultNetAdapt, objRequest)

	} else {

		// send request base on "EventCode" value, then call the HandleResult
		// function to handle the result
		switch objRequest["EventCode"] {
		case "1":
			resultEvent1 := RequestEventCode1(objRequest, clientConn)
			HandleResult(resultEvent1, objRequest)
		case "3":
			resultEvent3 := RequestEventCode3(objRequest, clientConn)
			HandleResult(resultEvent3, objRequest)
		case "7":
			resultEvent7 := RequestEventCode7(objRequest, clientConn)
			HandleResult(resultEvent7, objRequest)
		case "8":
			resultEvent8 := RequestEventCode8(objRequest, clientConn)
			HandleResult(resultEvent8, objRequest)
		case "9":
			resultEvent9 := RequestEventCode9(objRequest, clientConn)
			HandleResult(resultEvent9, objRequest)
		case "10":
			resultEvent10 := RequestEventCode10(objRequest, clientConn)
			HandleResult(resultEvent10, objRequest)
		case "11":
			resultEvent11 := RequestEventCode11(objRequest, clientConn)
			HandleResult(resultEvent11, objRequest)
		case "12":
			resultEvent12 := RequestEventCode12(objRequest, clientConn)
			HandleResult(resultEvent12, objRequest)
		case "13":
			resultEvent13 := RequestEventCode13(objRequest, clientConn)
			HandleResult(resultEvent13, objRequest)
		case "14":
			resultEvent14 := RequestEventCode14(objRequest, clientConn)
			HandleResult(resultEvent14, objRequest)
		default:
			resultDefault := &rpc.ResponseResult{
				ResultInfo: "Error: Not support for EventCode" + objRequest["EventCode"],
				Result:     false,
			}
			HandleResult(resultDefault, objRequest)
		}
	}
}

// This function is used to filter the log with the slice of available rules.
// Function returns a slice of objectRequest that matched rules.
func FilterRulesLog(log map[string]string) []map[string]string {

	// The pointer of slice is used to add objectRequest when rule capture log
	objRequests := make([]map[string]string, 0)

	// The for loop is used to retrieve all the rules, then adds an Object
	// to the slice if the rule matches a log.
	for _, rule := range rules {

		// slice of fields used to match fields in log.
		ruleRegex := ConvertInterfaceToString(rule["Data"].(map[string]interface{}))

		// If the event code is not equal, it means that the log is not
		// related to this rule, continue.
		if log["EventCode"] != ruleRegex["EventCode"] {
			continue
		}

		// check all fields of the rule with fields of log. If the result is true,
		// we add 1 Object to the Slice
		if CheckRule(log, ruleRegex) {
			log["Type"] = fmt.Sprintf("%v", rule["Type"])
			log["Message"] = fmt.Sprintf("%v", rule["Message"])
			log["Action"] = fmt.Sprintf("%v", rule["Action"])
			objRequests = append(objRequests, log)
		}
	}
	return objRequests
}

// This function is used to check all fields of the rule with fields of log.
// Each value of fields of rule is regex. We use regex to catch the fields of log.
func CheckRule(log map[string]string, ruleRegex map[string]string) bool {

	// regex match the string begin and end by $ character. This is how we
	// mark the content between the two $ as the key of a log.
	// We use this method when we want to check in the log if the value whose
	// key is the key of the regex with the value whose key is the content
	// between two $ characters are equal.
	reSimilar := regexp.MustCompile(`(?m)^\$[a-zA-Z]+\$$`)

	// regex matches strings that start with two $ characters and end with
	// one $ character. This is how we highlight the content between the $
	// characters as the key of a log.
	// We use this method when we want to check in the log if the value whose
	// key is the key of the regex with the value whose key is the content
	// between the $ characters are different.
	reDifferent := regexp.MustCompile(`(?m)^\$\$[a-zA-Z]+\$$`)

	// loop for all key of map ruleRegex
	for key := range ruleRegex {

		// check if reSimilar is matched in value of ruleRegex
		if reSimilar.FindString(ruleRegex[key]) != "" {

			// content between the two $ characters as the key of a log
			keyLogSimilar := strings.Replace(ruleRegex[key], "$", "", -1)

			// check if two values of log[key] and log[keyLogSimilar] are equal.
			// If not equal, log is not catched by ruleRegex, return false.
			// Otherwise, continue checking to another ruleRegex.
			if log[key] != log[keyLogSimilar] {
				return false
			} else {
				continue
			}
		}

		// check if reDifferent is matched in value of ruleRegex
		if reDifferent.FindString((ruleRegex[key])) != "" {

			// content between the $ characters as the key of a log
			keyLogDifferent := strings.Replace(ruleRegex[key], "$", "", -1)

			// check if two values of log[key] and log[keyLogDifferent]
			// are different. If equal, log is not captured by ruleRegex, return
			// false. Otherwise, continue checking to another ruleRegex.
			if log[key] == log[keyLogDifferent] {
				return false
			} else {
				continue
			}
		}

		// if reSimilar and reDifferent is not matched value of ruleRegex,
		// We check if ruleRegex[key] captures log[key]. If not matched,
		// log is not captured by ruleRegex, return false.
		re := regexp.MustCompile(ruleRegex[key])
		if re.FindString(log[key]) == "" {
			return false
		}
	}

	// return true if all ruleRegex match log.
	return true
}

// This function sends the request through function client.ManagerEventCode1()
// to AgentGRPC Server side and obtains the ResponseResult at a given EventCode1
func RequestEventCode1(objRequest map[string]string, conn *grpc.ClientConn) *rpc.ResponseResult {

	event1 := &rpc.EventCode1{
		ProcessId: objRequest["ProcessId"],
		Action:    objRequest["Action"],
	}
	client := rpc.NewManagerClient(conn)
	event1Result, err := client.ManagerEventCode1(context.Background(), event1)

	// If error occurs, ResultInfo is error message and request is failure
	if err != nil {
		return &rpc.ResponseResult{
			ResultInfo: "Error occurs: " + err.Error(),
			Result:     false,
		}
	}
	return event1Result
}

// This function sends the request through function client.ManagerEventCode3()
// to AgentGRPC Server side and obtains the ResponseResult at a given EventCode3
func RequestEventCode3(objRequest map[string]string, conn *grpc.ClientConn) *rpc.ResponseResult {

	event3 := &rpc.EventCode3{
		ProcessId:       objRequest["ProcessId"],
		SourceIp:        objRequest["SourceIp"],
		SourcePort:      objRequest["SourcePort"],
		DestinationIp:   objRequest["DestinationIp"],
		DestinationPort: objRequest["DestinationPort"],
		Action:          objRequest["Action"],
	}
	client := rpc.NewManagerClient(conn)
	event3Result, err := client.ManagerEventCode3(context.Background(), event3)

	// If error occurs, ResultInfo is error message and request is failure
	if err != nil {
		return &rpc.ResponseResult{
			ResultInfo: "Error occurs: " + err.Error(),
			Result:     false,
		}
	}
	return event3Result
}

// This function sends the request through function client.ManagerEventCode7()
// to AgentGRPC Server side and obtains the ResponseResult at a given EventCode7
func RequestEventCode7(objRequest map[string]string, conn *grpc.ClientConn) *rpc.ResponseResult {

	event7 := &rpc.EventCode7{
		ProcessId:   objRequest["ProcessId"],
		ImageLoaded: objRequest["ImageLoaded"],
		Action:      objRequest["Action"],
	}
	client := rpc.NewManagerClient(conn)
	event7Result, err := client.ManagerEventCode7(context.Background(), event7)

	// If error occurs, ResultInfo is error message and request is failure
	if err != nil {
		return &rpc.ResponseResult{
			ResultInfo: "Error occurs: " + err.Error(),
			Result:     false,
		}
	}
	return event7Result
}

// This function sends the request through function client.ManagerEventCode8()
// to AgentGRPC Server side and obtains the ResponseResult at a given EventCode8
func RequestEventCode8(objRequest map[string]string, conn *grpc.ClientConn) *rpc.ResponseResult {

	event8 := &rpc.EventCode8{
		SourceProcessId: objRequest["SourceProcessId"],
		Action:          objRequest["Action"],
	}
	client := rpc.NewManagerClient(conn)
	event8Result, err := client.ManagerEventCode8(context.Background(), event8)

	// If error occurs, ResultInfo is error message and request is failure
	if err != nil {
		return &rpc.ResponseResult{
			ResultInfo: "Error occurs: " + err.Error(),
			Result:     false,
		}
	}
	return event8Result
}

// This function sends the request through function client.ManagerEventCode9()
// to AgentGRPC Server side and obtains the ResponseResult at a given EventCode9
func RequestEventCode9(objRequest map[string]string, conn *grpc.ClientConn) *rpc.ResponseResult {

	event9 := &rpc.EventCode9{
		ProcessId: objRequest["ProcessId"],
		Action:    objRequest["Action"],
	}
	client := rpc.NewManagerClient(conn)
	event9Result, err := client.ManagerEventCode9(context.Background(), event9)

	// If error occurs, ResultInfo is error message and request is failure
	if err != nil {
		return &rpc.ResponseResult{
			ResultInfo: "Error occurs: " + err.Error(),
			Result:     false,
		}
	}
	return event9Result
}

// This function sends the request through function client.ManagerEventCode10()
// to AgentGRPC Server side and obtains the ResponseResult at a given EventCode10
func RequestEventCode10(objRequest map[string]string, conn *grpc.ClientConn) *rpc.ResponseResult {

	event10 := &rpc.EventCode10{
		ProcessId: objRequest["ProcessId"],
		Action:    objRequest["Action"],
	}
	client := rpc.NewManagerClient(conn)
	event10Result, err := client.ManagerEventCode10(context.Background(), event10)

	// If error occurs, ResultInfo is error message and request is failure
	if err != nil {
		return &rpc.ResponseResult{
			ResultInfo: "Error occurs: " + err.Error(),
			Result:     false,
		}
	}
	return event10Result
}

// This function sends the request through function client.ManagerEventCode11()
// to AgentGRPC Server side and obtains the ResponseResult at a given EventCode11
func RequestEventCode11(objRequest map[string]string, conn *grpc.ClientConn) *rpc.ResponseResult {

	event11 := &rpc.EventCode11{
		TargetFilename: objRequest["TargetFilename"],
		Action:         objRequest["Action"],
	}
	client := rpc.NewManagerClient(conn)
	event11Result, err := client.ManagerEventCode11(context.Background(), event11)

	// If error occurs, ResultInfo is error message and request is failure
	if err != nil {
		return &rpc.ResponseResult{
			ResultInfo: "Error occurs: " + err.Error(),
			Result:     false,
		}
	}
	return event11Result
}

// This function sends the request through function client.ManagerEventCode12()
// to AgentGRPC Server side and obtains the ResponseResult at a given EventCode12
func RequestEventCode12(objRequest map[string]string, conn *grpc.ClientConn) *rpc.ResponseResult {

	event12 := &rpc.EventCode12{
		TargetObject: objRequest["TargetObject"],
		Action:       objRequest["Action"],
	}
	client := rpc.NewManagerClient(conn)
	event12Result, err := client.ManagerEventCode12(context.Background(), event12)

	// If error occurs, ResultInfo is error message and request is failure
	if err != nil {
		return &rpc.ResponseResult{
			ResultInfo: "Error occurs: " + err.Error(),
			Result:     false,
		}
	}
	return event12Result
}

// This function sends the request through function client.ManagerEventCode13()
// to AgentGRPC Server side and obtains the ResponseResult at a given EventCode13
func RequestEventCode13(objRequest map[string]string, conn *grpc.ClientConn) *rpc.ResponseResult {

	event13 := &rpc.EventCode13{
		TargetObject: objRequest["TargetObject"],
		Action:       objRequest["Action"],
	}
	client := rpc.NewManagerClient(conn)
	event13Result, err := client.ManagerEventCode13(context.Background(), event13)

	// If error occurs, ResultInfo is error message and request is failure
	if err != nil {
		return &rpc.ResponseResult{
			ResultInfo: "Error occurs: " + err.Error(),
			Result:     false,
		}
	}
	return event13Result
}

// This function sends the request through function client.ManagerEventCode14()
// to AgentGRPC Server side and obtains the ResponseResult at a given EventCode14
func RequestEventCode14(objRequest map[string]string, conn *grpc.ClientConn) *rpc.ResponseResult {

	event14 := &rpc.EventCode14{
		EventType:    objRequest["EventType"],
		TargetObject: objRequest["TargetObject"],
		NewName:      objRequest["NewName"],
		Action:       objRequest["Action"],
	}
	client := rpc.NewManagerClient(conn)
	event14Result, err := client.ManagerEventCode14(context.Background(), event14)

	// If error occurs, ResultInfo is error message and request is failure
	if err != nil {
		return &rpc.ResponseResult{
			ResultInfo: "Error occurs: " + err.Error(),
			Result:     false,
		}
	}
	return event14Result
}

// This function sends the request through function client.ManagerNetworkAdapter()
// to AgentGRPC Server side and obtains the ResponseResult at a given NetworkAdapter
func RequestNetworkAdapter(objRequest map[string]string, conn *grpc.ClientConn) *rpc.ResponseResult {

	netAdapter := &rpc.NetworkAdapter{
		Action: objRequest["Action"],
	}
	client := rpc.NewManagerClient(conn)
	netAdapterResult, err := client.ManagerNetworkAdapter(context.Background(), netAdapter)

	// If error occurs, ResultInfo is error message and request is failure
	if err != nil {
		return &rpc.ResponseResult{
			ResultInfo: "Error occurs: " + err.Error(),
			Result:     false,
		}
	}
	return netAdapterResult
}

// This function sends the request through function client.ManagerGetFile()
// to AgentGRPC Server side and obtains the FileDatas available within the
// given FileInfo. Results are streamed rather than returned at once.
func RequestGetFile(objRequest map[string]string, grpcClient *grpc.ClientConn) *rpc.ResponseResult {

	var filePath string
	eventCode := objRequest["EventCode"]

	// Value of filePath is based on eventCode variable
	switch eventCode {
	case "1":
		filePath = objRequest["Image"]
	case "7":
		filePath = objRequest["ImageLoaded"]
	case "11":
		filePath = objRequest["TargetFilename"]
	default: // Other eventcodes are not support
		return &rpc.ResponseResult{
			ResultInfo: "Error: Action get file is not support for EventCode" + eventCode,
			Result:     false,
		}
	}
	fileInfo := &rpc.FileInfo{
		FilePath: filePath,
	}
	client := rpc.NewManagerClient(grpcClient)

	// call the function ManagerGetFile() on AgentGRPC Server side and receive
	// a client stream object. Results are streamed rather than returned at once
	stream, err := client.ManagerGetFile(context.Background(), fileInfo)
	if err != nil {
		return &rpc.ResponseResult{
			ResultInfo: "Error: " + err.Error(),
			Result:     false,
		}
	}

	// Get name of file
	fileName := SplitName(filePath)

	// Check directory to save file. If directory is not exist, create dir
	dirPath, err := CreateDir(parentDirPath, objRequest["ComputerName"])
	if err != nil {
		return &rpc.ResponseResult{
			ResultInfo: "Error: " + err.Error(),
			Result:     false,
		}
	}

	// File path to write data from client stream.
	fileSave := dirPath + "/" + FormatCurrentDate() + fileName
	f, err := os.Create(fileSave)
	if err != nil {
		return &rpc.ResponseResult{
			ResultInfo: "Error: " + err.Error(),
			Result:     false,
		}
	}
	defer f.Close()

	// this loop receives and writes message into filesave util the stream is done.
	// It returns io.EOF when the stream completes successfully. On any other
	// error, the stream is aborted and the error contains the RPC status.
	for {
		chunkData, err := stream.Recv()
		if err == io.EOF { // the stream is done, break
			break
		}
		if err != nil { // return error
			return &rpc.ResponseResult{
				ResultInfo: "Error: " + err.Error(),
				Result:     false,
			}
		}
		_, err = f.Write(chunkData.FileChunk)
		if err != nil {
			return &rpc.ResponseResult{
				ResultInfo: "Error: " + err.Error(),
				Result:     false,
			}
		}
	}

	return &rpc.ResponseResult{
		ResultInfo: "Download file " + fileName + " successfully",
		Result:     true,
	}
}

// This function combines result and writes result log to log file
func HandleResult(responseResult *rpc.ResponseResult, objRequest map[string]string) {

	objRequest["ResultInfo"] = responseResult.GetResultInfo()

	// if result vaule is true, set log result is success,
	// otherwise set log result is failure
	if responseResult.GetResult() {
		objRequest["Result"] = "Success"
	} else {
		objRequest["Result"] = "Failure"
	}
	objRequest["ResultTime"] = FormatCurrentDateMilisecond()

	// write result log to log file
	err := WriteMapString(resultLogPath, objRequest)
	if err != nil {
		WriteAppLogError(err)
	}
}
