package policyengine

import (
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strings"

	"pault.ag/go/piv"
)

type AttributeTuple struct {
	CommonName   string `json:"CommonName`
	SerialNumber string `json:"SerialNumber"`
	Uri          string `json:"Uri"`
	Host         string `json:"Host"`
}

func (a *AttributeTuple) FromJSON(jsonObj []byte) {
	err := json.Unmarshal(jsonObj, a)
	if err != nil {
		log.Printf("error unmarshalling: %v\n", string(jsonObj))
		log.Fatal(err)
	}
}

func (a *AttributeTuple) ToJSON() []byte {
	jsonObj, err := json.Marshal(a)
	if err != nil {
		log.Printf("error marshalling: %v\n", a)
		log.Fatal(err)
	}

	return jsonObj
}

func (a *AttributeTuple) FromHeader(header http.Header) {
	possiblePems := strings.Split(header.Get("X-Forwarded-Tls-Client-Cert"), ",")

	clientDerString := ""
	for _, possiblePem := range possiblePems {
		pemString, err := url.QueryUnescape(possiblePem)
		if err != nil {
			log.Println("error getting pem: ", err)
		}

		derString := fmt.Sprintf("-----BEGIN CERTIFICATE-----\n%s\n-----END CERTIFICATE-----\n", pemString)
		clientDerString = fmt.Sprintf("%s%s", clientDerString, derString)
	}

	clientDer, rest := pem.Decode([]byte(clientDerString))

	if len(rest) > 0 {
		log.Println("left over der bytes")
		log.Printf("der bytes left over: %v\n", rest)
	}

	log.Println("der: ", clientDer)

	if clientDer != nil {

		clientPiv, err := piv.ParseCertificate(clientDer.Bytes)
		if err != nil {
			log.Println("error parsing piv: ", err)
		}

		log.Println("parsed piv: ", clientPiv)

		log.Println("subject: ", clientPiv.Subject)

		a.CommonName = clientPiv.Subject.CommonName
		a.SerialNumber = clientPiv.Certificate.SerialNumber.String()
		a.Uri = header.Get("X-Forwarded-Uri")
		a.Host = header.Get("X-Forwarded-Host")
	} else {
		log.Println("unable to parse der")
		log.Println(clientDerString)
	}
}
