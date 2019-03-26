package policyengine

import (
	"bytes"
	"encoding/json"
	"io/ioutil"
	"log"
	"net/http"
	"time"
)

type Input struct {
	Input *AttributeTuple `json:"input"`
}

type authorized struct {
	Result bool `json:"result"`
}

func ValidateOPAPolicy(opaUrl string, attr *AttributeTuple) int {
	log.Println("checking opa policy")

	client := &http.Client{
		Timeout: time.Second * 5,
	}

	input := &Input{Input: attr}
	inputBytes, err := json.Marshal(input)
	if err != nil {
		log.Println("input marshal error: ", err)
	}
	log.Println("query input: ", string(inputBytes))
	request, err := http.NewRequest("POST", opaUrl, bytes.NewBuffer(inputBytes))
	if err != nil {
		log.Println("error making opa client: ", err)
		return http.StatusInternalServerError
	}

	request.Header.Set("Content-Type", "application/json")

	response, err := client.Do(request)
	if err != nil {
		log.Println("opa client request error: ", err)
		return http.StatusInternalServerError
	}

	log.Println("response: ", response)
	bodyString, err := ioutil.ReadAll(response.Body)
	if err != nil {
		log.Println("no opa body")
	} else {
		log.Println("opa body: ", string(bodyString))
	}

	auth := &authorized{}
	err = json.Unmarshal(bodyString, &auth)

	if err != nil {
		log.Println("error unmarshallign auth: ", err)
	}

	log.Println("opa response: ", auth)

	if auth.Result {
		return http.StatusOK
	}

	return http.StatusUnauthorized
}
