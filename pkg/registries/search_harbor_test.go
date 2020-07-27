package registries

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/tidwall/pretty"
	"testing"
)

func TestSearchHarbor(t *testing.T) {

	q := "rancher"
	domain := "r.addops.soft.360.cn"
	//testImage := Image{Domain: "r.addops.soft.360.cn", Path: "rancher/rancher", Tag: "dev"}
	//testImage := Image{Domain: "docker.io", Path: "library/alpine", Tag: "latest"}
	r, err := CreateRegistryClient("rancher", "Nn2Gp0Fm", domain, true)
	//r, err := CreateRegistryClient("", "", "docker.io", true)
	if err != nil {
		t.Fatalf("Could not get client: %s", err)
	}

	// Get token.
	token := base64.StdEncoding.EncodeToString([]byte(r.Username + ":" + r.Password))

	d, err := r.ImageSearchHarbor(q, token)
	if err != nil {
		t.Fatalf("Could not get digest: %s", err)
	}

	if d == nil {
		t.Error("Empty digest received")
	}

	bytes,_ := json.Marshal(d)
	fmt.Println(string(pretty.Color(pretty.PrettyOptions(bytes, pretty.DefaultOptions), nil)))
}
