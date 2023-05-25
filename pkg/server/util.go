/**
 * File:    util.go
 *
 * Summary of File:
 *
 * 	This file contains code that help file server.go.
 * 	Functions:
 * 	Format date, time, convert Json string, Check equal, get file name,
 *	create directory, ...
 */

package server

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"time"
)

// The function returns the time formatted in milliseconds
func FormatCurrentDateMilisecond() string {
	return time.Now().Format("2006-01-02 15:04:05.000")
}

// The function returns the formatted time used for the file name
func FormatCurrentDate() string {
	return time.Now().Format("20060102_150405_")
}

// The function checks if two map strings are equal
func CheckMapEqual(data1 map[string]string, data2 map[string]string) bool {

	// Compare the lengths of two map
	if len(data1) != len(data2) {
		return false
	}

	// Compare each (key, value) pair of two MAPs.
	// If there is a different pair, return false
	for key := range data1 {
		if data1[key] != data2[key] {
			return false
		}
	}

	return true
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

// The function gets the file name from file path
func SplitName(targetObject string) string {
	re := regexp.MustCompile(`(?m)\\`)
	split := re.Split(targetObject, -1)
	name := split[len(split)-1]
	return name
}

// This function create directory for each windows agent
func CreateDir(parrentDirPath string, dirName string) (string, error) {

	dirPath := parrentDirPath + "/" + dirName
	_, err := os.Stat(dirPath)

	// if error is "Directory is not exist", create directory
	if os.IsNotExist(err) {
		err := os.MkdirAll(dirPath, 0755)
		if err != nil {
			return "", err
		}
	}
	return dirPath, nil
}
