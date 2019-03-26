package policyengine

import (
	"log"
	"net/http"
	"time"
)

// needs work; using webauthn.io demo

func ValidateWebauthnToken(enrollmentEndpoint string, validateEndpoint string, requestUri string, header http.Header) (int, http.Header) {
	client := &http.Client{
		Timeout: time.Second * 5,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	request, err := http.NewRequest("GET", validateEndpoint, nil)
	if err != nil {
		log.Println("webauthn error: ", err)
		return 500, make(http.Header, 0)
	}

	request.Header = header

	response, err := client.Do(request)
	if err != nil {
		log.Println("webauthn error: ", err)
		return 500, response.Header
	}

	log.Println("response: ", response)

	switch response.StatusCode {
	case http.StatusOK:
		return http.StatusOK, response.Header
	case http.StatusTemporaryRedirect:
		return http.StatusTemporaryRedirect, response.Header
	default:
		return http.StatusForbidden, response.Header
	}
}
