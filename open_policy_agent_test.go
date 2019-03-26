package policyengine

import (
	"encoding/json"
	"testing"
)

func TestResult(t *testing.T) {
	jsonresult := `{"result":true}`

	auth := authorized{}
	err := json.Unmarshal([]byte(jsonresult), &auth)

	if err != nil {
		t.Fatal(err)
	}

	t.Log(auth)

	if auth.Result != true {
		t.Fatal("should be true")
	}
}
