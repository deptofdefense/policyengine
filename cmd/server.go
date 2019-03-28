package main

import (
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/deptofdefense/policyengine"
	"github.com/spf13/cobra"
)

var SSO bool
var U2F bool

var addr string
var port string

var vouchSsoEndpoint string
var vouchValidateEndpoint string

var u2fEnrollmentEndpoint string
var u2fValidateEndpoint string

var opaurl string

func init() {
	if os.Getenv("SSOOFF") != "1" {
		SSO = true
	} else {
		SSO = false
	}

	if os.Getenv("U2FOFF") != "1" {
		U2F = true
	} else {
		U2F = false
	}

	OpaCmd.AddCommand(serve)

	serve.Flags().StringVarP(&vouchSsoEndpoint, "vouch-sso-endpoint", "", "", "vouch sso url (ex https://sso.local:8444)")
	serve.Flags().StringVarP(&vouchValidateEndpoint, "vouch-validation-endpoint", "", "", "vouch proxy path to validate against (ex https://sso.local:8444/validate)")

	serve.Flags().StringVarP(&u2fEnrollmentEndpoint, "u2f-enrollment-endpoint", "", "", "u2f enrollment endpoint")
	serve.Flags().StringVarP(&u2fValidateEndpoint, "u2f-validation-endpoint", "", "", "u2f validation endpoint")

	serve.Flags().StringVarP(&opaurl, "opa-endpoint", "", "", "opa url to use")

	serve.Flags().StringVarP(&addr, "addr", "a", "", "address to run rules engine on (default public)")
	serve.Flags().StringVarP(&port, "port", "p", "8080", "port to run rules engine on")

	serve.MarkFlagRequired("opa-endpoint")

	if SSO {
		serve.MarkFlagRequired("vouch-sso-endpoint")
		serve.MarkFlagRequired("vouch-validation-endpoint")
	}
	if U2F {
		serve.MarkFlagRequired("u2f-enrollment-endpoint")
		serve.MarkFlagRequired("u2f-validation-endpoint")
	}
}

var serve = &cobra.Command{
	Use:   "serve",
	Short: "start engine",
	Run: func(c *cobra.Command, args []string) {
		server()
	},
}

func server() {

	//initialize opa engine

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		log.Println("Request:")
		log.Println("method: ", r.Method)
		log.Println("host: ", r.Host)
		log.Println("uri: ", r.RequestURI)

		log.Println("Headers:")
		for k, v := range r.Header {
			log.Printf("key: %v; value: %v\n", k, v)
		}
		// check vouch proxy
		if SSO {
			switch status, headers := policyengine.ValidateVouchTokens(vouchValidateEndpoint, vouchSsoEndpoint, r.RequestURI, r.Header); status {
			case http.StatusOK:
				log.Printf("Vouch session cookie check GOOD (status,user): (%v,%v)\n", status, headers["X-Vouch-User"][0])
				log.Println("Passing through to further checks")

			case http.StatusTemporaryRedirect:
				w.Header().Add("Location", headers.Get("Location"))
				w.WriteHeader(http.StatusTemporaryRedirect)
				return

			case http.StatusUnauthorized:
				log.Println("unauthorized by vouch")
				w.Header().Add("Location", policyengine.GenerateRedirect(vouchSsoEndpoint, r.Header["X-Forwarded-Host"][0], r.RequestURI))
				w.WriteHeader(http.StatusTemporaryRedirect)
				return

			default:
				log.Println("error doing vouch validation request")
				log.Println(headers)
				w.WriteHeader(http.StatusNotImplemented)
				return
			}
		}

		if U2F {
			switch webauthnCode, webauthnHeader := policyengine.ValidateWebauthnToken(u2fEnrollmentEndpoint, u2fValidateEndpoint, r.RequestURI, r.Header); webauthnCode {
			case http.StatusOK:
				log.Println("Webauthn statusOK")
			case http.StatusTemporaryRedirect:
				w.Header().Add("Location", u2fEnrollmentEndpoint)
				w.WriteHeader(http.StatusTemporaryRedirect)
				return
			case http.StatusForbidden:
				w.Header().Add("Location", u2fEnrollmentEndpoint)
				w.WriteHeader(http.StatusTemporaryRedirect)
				return
			default:
				log.Println("Unknown webauthn:", webauthnCode)
				log.Println("Headers:", webauthnHeader)
				w.WriteHeader(http.StatusNotImplemented)
				return
			}
		}

		attributes := &policyengine.AttributeTuple{}
		attributes.FromHeader(r.Header)

		opaResult := policyengine.ValidateOPAPolicy(opaurl, attributes)

		w.WriteHeader(opaResult)

	})

	serverAddr := fmt.Sprintf("%v:%v", addr, port)
	log.Println("starting server on: ", serverAddr)
	http.ListenAndServe(serverAddr, nil)
}
