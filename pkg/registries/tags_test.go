package registries

import (
	"encoding/json"
	"fmt"
	"github.com/sirupsen/logrus"
	"github.com/tidwall/pretty"
	"testing"
)

func TestTagsFromDockerHub(t *testing.T) {

	testImage := Image{Domain: "docker.io", Path: "heroku/cedar", Tag: "latest"}
	r, err := CreateRegistryClient("", "", testImage.Domain, true)
	if err != nil {
		t.Fatalf("Could not get client: %s", err)
	}

	digestUrl := r.GetTagsUrl(testImage)

	// Get token.
	token, err := r.Token(digestUrl)
	if err != nil || token == "" {
		t.Fatalf("Could not get token: %s", err)
	}

	d, err := r.ImageTags(testImage, token)
	if err != nil {
		t.Fatalf("Could not get tags: %s", err)
	}

	if d == nil {
		t.Error("Empty digest received")
	}
	bytes,_ := json.Marshal(d)
	fmt.Println(string(pretty.Color(pretty.PrettyOptions(bytes, pretty.DefaultOptions), nil)))
}

func TestVerifyFromDockerHub(t *testing.T) {
	credential := RegistryCredential{
		Username: "360container",
		Password: "Password!@#",
		ServerHost: "https://hub.docker.com",
	}
	// 这里取巧了一下，直接创建客户端获取token，如果成功，说明账号密码域名 都是正确的
	cli, err := CreateRegistryClient(credential.Username, credential.Password, credential.ServerHost, true)
	if err != nil {
		t.Error(err)
	}

	loginUrl := cli.GetLoginUrl()
	logrus.Debugln("token:", loginUrl)

	// Get token.
	token, err := cli.TokenWithLogin(loginUrl)
	if err != nil || token == "" {
		t.Error(err)
	}
	fmt.Println(token)
}
