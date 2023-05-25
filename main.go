package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
)

func ReadSliceMapInterface(filePath string) []map[string]interface{} {

	file, _ := os.Open(filePath)

	// create slice to add map[string]interface{}
	sliceMapInterface := make([]map[string]interface{}, 0)

	// read from file and split file to line by line
	scanner := bufio.NewScanner(file)
	scanner.Split(bufio.ScanLines)

	// Add to slice each MAP after converting string to map[string]interface{}
	for scanner.Scan() {
		sliceMapInterface = append(sliceMapInterface, ConvertJsonToInterface(scanner.Text()))
	}
	defer file.Close()
	return sliceMapInterface
}

// The function converts json string to map[string]interface{}
func ConvertJsonToInterface(jsonString string) map[string]interface{} {
	mapInterface := make(map[string]interface{})
	json.Unmarshal([]byte(jsonString), &mapInterface)
	return mapInterface
}

// The function converts map[string]interface{} to map[string]string
func ConvertInterfaceToString(mapInterface map[string]interface{}) map[string]string {
	mapString := make(map[string]string)

	// convert interface{} to string
	for key, value := range mapInterface {
		strValue := fmt.Sprintf("%v", value)
		mapString[key] = strValue
	}
	return mapString
}

func main() {
	demo := ReadSliceMapInterface(`.\rules\responserules.txt`)

	for _, i := range demo {
		ruleRegex := ConvertInterfaceToString(i["Data"].(map[string]interface{}))
		fmt.Println(ruleRegex["TargetObject"])
	}
}
