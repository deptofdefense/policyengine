package policyengine

import (
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"time"
)

func ValidateVouchTokens(validateEndpoint, enrollEndpoint, requestUri string, header http.Header) (int, http.Header) {
	log.Println("checking vouch sesssion and cookie")

	//client to make vouch validate request
	client := &http.Client{
		Timeout: time.Second * 5,
	}

	log.Println("Vouch Pre-Request Headers:")
	if len(header) > 0 {
		for k, v := range header {
			log.Printf("key: %v; value: %v\n", k, v)
		}
	} else {
		log.Println("No headers")
	}

	request, err := http.NewRequest("GET", validateEndpoint, nil)
	if err != nil {
		log.Println("error making vouch client: ", err)
		return http.StatusInternalServerError, make(http.Header, 0)
	}

	request.Header = header
	originLocation := fmt.Sprintf("https://%s%s", header["X-Forwarded-Host"][0], header["X-Forwarded-Uri"][0])
	log.Println("Include header for ", originLocation)
	request.Header.Set("X-Original-URI", originLocation)
	request.Header.Set("Content-Type", "application/json")

	response, err := client.Do(request)
	if err != nil {
		log.Println("vouch client request error: ", err)
		return http.StatusInternalServerError, make(http.Header, 0)
	}

	log.Println("response: ", response)
	bodyString, err := ioutil.ReadAll(response.Body)
	if err != nil {
		log.Println("vouch body: ", string(bodyString))
	} else {
		log.Println("no vouch body")
	}

	if response.StatusCode >= 300 && response.StatusCode < 400 {
		log.Println("vouch redirection needed")
		log.Println("request does not contain valid vouch session/cookie")
		log.Printf("%d", response.StatusCode)
		host := header["X-Forwarded-Host"][0]
		enrollLocation := GenerateRedirect(enrollEndpoint, host, requestUri)
		response.Header.Add("Location", enrollLocation)
		return http.StatusTemporaryRedirect, response.Header
	}

	if response.StatusCode != 200 {
		log.Println("vouch returned invalid status")
		return http.StatusUnauthorized, response.Header
	}

	log.Printf("Vouch session cookie check GOOD (status,user): (%v,%v)\n", response.StatusCode, response.Header["X-Vouch-User"][0])
	return http.StatusOK, response.Header
}

func GenerateRedirect(enrollmentEndpoint, host, uri string) string {
	redirloc := fmt.Sprintf("%s/login?url=https://%s%s&X-Vouch-Token=&vouch-failcount=1", enrollmentEndpoint, host, uri)
	log.Println("Redirecting to: ", redirloc)
	return redirloc
}
