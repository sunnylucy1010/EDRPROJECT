/**
 * File:    file.go
 *
 *
 * Summary of File:
 *
 * 	This file contains the code related to the file handling of the EDR server.
 * 	Functions:
 * 	Read file and return all data.
 * 	Write file, add new line to file.
 */

package server

import (
	"bufio"
	"encoding/json"
	"os"
)

// The function reads all the data from the file line by line,
// converting it to a slice of map[string]interface{}
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

// The function reads all the data from the file line by line,
// converting it to a slice of map[string]string
func ReadSliceMapString(filePath string) []map[string]string {

	file, _ := os.Open(filePath)

	// create slice to add map[string]string
	sliceMapString := make([]map[string]string, 0)

	// read from file and split file to line by line
	scanner := bufio.NewScanner(file)
	scanner.Split(bufio.ScanLines)

	// Add to slice each MAP after converting string to map[string]string
	for scanner.Scan() {
		mapInterface := ConvertJsonToInterface(scanner.Text())
		sliceMapString = append(sliceMapString, ConvertInterfaceToString(mapInterface))
	}
	defer file.Close()
	return sliceMapString
}

// The function converts all elements in the sliceMapString into bytes and stores them
// in the file line by line. Here will delete the old data and replace it with new data.
func WriteSliceMapString(filePath string, sliceMapString []map[string]string) error {

	// slice data to store all json byte
	data := make([]byte, 0)

	file, _ := os.OpenFile(filePath, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0644)

	// converts all elements in the slice into bytes and them to slice data
	for _, mapString := range sliceMapString {
		jsonBytes, err := json.Marshal(mapString) // encode map to json bytes
		if err != nil {
			return err
		}
		jsonBytes = append(jsonBytes, 10)
		data = append(data, jsonBytes...)
	}

	file.Write(data)
	file.Close()
	return nil
}

// The function converts all elements in the sliceMapInterface{} into bytes and stores them
// in the file. Here will delete the old data and replace it with new data.
func WriteSliceMapInterface(filePath string, sliceMapInterface []map[string]interface{}) error {

	// slice data to store all json byte
	data := make([]byte, 0)

	file, _ := os.OpenFile(filePath, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0644)

	// converts all elements in the slice into bytes and them to slice data
	for _, mapInterface := range sliceMapInterface {
		jsonBytes, err := json.Marshal(mapInterface) // encode map to json bytes
		if err != nil {
			return err
		}
		jsonBytes = append(jsonBytes, 10)
		data = append(data, jsonBytes...)
	}

	file.Write(data)
	file.Close()
	return nil
}

// The function converts a map[string]string into bytes and adds a new line to file.
func WriteMapString(filePath string, mapString map[string]string) error {

	// open file to add a new line
	file, err := os.OpenFile(filePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}

	// encode map[string]string to json bytes
	jsonBytes, err := json.Marshal(mapString)
	if err != nil {
		return err
	}

	file.Write(append(jsonBytes, 10))
	file.Close()
	return nil
}

// The function converts a map[string]interface{} into bytes and adds a new line to file.
func WriteMapInterface(filePath string, mapInterface map[string]interface{}) error {

	// open file to add a new line
	file, err := os.OpenFile(filePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}

	// encode map[string]interface{} to json bytes
	jsonBytes, err := json.Marshal(mapInterface)
	if err != nil {
		return err
	}

	file.Write(append(jsonBytes, 10))
	file.Close()
	return nil
}
