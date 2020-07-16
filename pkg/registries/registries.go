package registries

import (
	"encoding/json"
	"fmt"
	"github.com/emicklei/go-restful"
	"github.com/rancher/types/config"
	"github.com/sirupsen/logrus"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"strings"
)

const (
	loginSuccess  = "Login Succeeded"
	StatusFailed  = "failed"
	StatusSuccess = "succeeded"
)

type DockerConfigJson struct {
	Auths DockerConfigMap `json:"auths"`
}

type RegistryCredential struct {
	Username   string `json:"username" description:"username"`
	Password   string `json:"password" description:"password"`
	ServerHost string `json:"serverhost" description:"registry server host"`
}

// DockerConfig represents the config file used by the docker CLI.
// This config that represents the credentials that should be used
// when pulling images from specific image repositories.
type DockerConfigMap map[string]DockerConfigEntry

type DockerConfigEntry struct {
	Username      string `json:"username"`
	Password      string `json:"password"`
	Email         string `json:"email"`
	ServerAddress string `json:"serverAddress,omitempty"`
}

type RegistryGetter interface {
	VerifyRegistryCredential(credential RegistryCredential) error
	GetEntry(namespace, secretName, imageName string) (ImageDetails, error)
	GetEntryTags(namespace, secretName, imageName string) ([]string, error)
}

type registryGetter struct {
	//informers informers.SharedInformerFactory
	sc *config.ScaledContext
}

func NewRegistryGetter(sc *config.ScaledContext) RegistryGetter {
	return &registryGetter{sc: sc}
}

func (c *registryGetter) VerifyRegistryCredential(credential RegistryCredential) error {
	// 这里取巧了一下，直接创建客户端获取token，如果成功，说明账号密码域名 都是正确的
	// 只能验证 官方docker api的接口， 私有harbor的接口  不同，这里不能认证
	cli, err := CreateRegistryClient(credential.Username, credential.Password, credential.ServerHost, true)
	if err != nil {
		return err
	}

	loginUrl := cli.GetLoginUrl()
	logrus.Debugln("token:", loginUrl)

	// Get token.
	token, err := cli.TokenWithLogin(loginUrl)
	if err != nil || token == "" {
		return err
	}
	return nil
	//auth := base64.StdEncoding.EncodeToString([]byte(credential.Username + ":" + credential.Password))
	//ctx := context.Background()
	//cli, err := client.NewClientWithOpts(client.WithAPIVersionNegotiation())
	//logrus.Infof("cxx_docker_cli: %+v", cli)
	//if err != nil {
	//	klog.Error(err)
	//}
	//
	//config := types.AuthConfig{
	//	Username:      credential.Username,
	//	Password:      credential.Password,
	//	Auth:          auth,
	//	ServerAddress: credential.ServerHost,
	//}
	//
	//resp, err := cli.RegistryLogin(ctx, config)
	//logrus.Infof("cxx_docker_cli: %+v", resp)
	//cli.Close()
	//
	//if err != nil {
	//	return err
	//}
	//
	//if resp.Status == loginSuccess {
	//	return nil
	//} else {
	//	return fmt.Errorf(resp.Status)
	//}
}

func (c *registryGetter) GetEntry(namespace, secretName, imageName string) (ImageDetails, error) {
	imageDetails, err := c.getEntryBySecret(namespace, secretName, imageName)
	if imageDetails.Status == StatusFailed {
		imageDetails.Message = err.Error()
	}

	return imageDetails, err
}

func  (c *registryGetter) getEntryBySecret(namespace, secretName, imageName string) (ImageDetails, error) {
	failedImageDetails := ImageDetails{
		Status:  StatusFailed,
		Message: "",
	}

	var config *DockerConfigEntry

	if namespace == "" || secretName == "" {
		config = &DockerConfigEntry{}
	} else {
		secret, err := c.sc.Core.Secrets(namespace).Get(secretName, metav1.GetOptions{})
		//secret, err := c.informers.Core().V1().Secrets().Lister().Secrets(namespace).Get(secretName)
		if err != nil {
			return failedImageDetails, err
		}
		config, err = getDockerEntryFromDockerSecret(secret)
		logrus.Infof("docker_config: %+v", config)
		if err != nil {
			return failedImageDetails, err
		}
	}

	// default use ssl
	checkSSl := func(serverAddress string) bool {
		if strings.HasPrefix(serverAddress, "http://") {
			return false
		} else {
			return true
		}
	}

	if strings.HasPrefix(imageName, "http") {
		dockerurl, err := ParseDockerURL(imageName)
		if err != nil {
			return failedImageDetails, err
		}
		imageName = dockerurl.StringWithoutScheme()
	}

	// parse image
	image, err := ParseImage(imageName)
	if err != nil {
		logrus.Error("parse_image: ", err)
		return failedImageDetails, err
	}

	useSSL := checkSSl(config.ServerAddress)

	// Create the registry client.
	r, err := CreateRegistryClient(config.Username, config.Password, image.Domain, useSSL)
	if err != nil {
		logrus.Error("create registry cline err: ", err)
		return failedImageDetails, err
	}

	digestUrl := r.GetDigestUrl(image)

	// Get token.
	token, err := r.Token(digestUrl)
	if err != nil {
		logrus.Error("get token err: ", err)
		return failedImageDetails, err
	}

	// Get digest.
	imageManifest, err := r.ImageManifest(image, token)
	if err != nil {
		if serviceError, ok := err.(restful.ServiceError); ok {
			logrus.Error("get image manifest restful err: ", err)
			return failedImageDetails, serviceError
		}
		logrus.Error("get image manifest err: ", err)
		return failedImageDetails, err
	}

	image.Digest = imageManifest.ManifestConfig.Digest

	// Get blob.
	// some blob get failed, it's normal
	imageBlob, err := r.ImageBlob(image, token)
	if err != nil {
		logrus.Error("get image blob err: ", err)

		// get blob failed
		imageBlob = nil
	}

	return ImageDetails{
		Status:        StatusSuccess,
		ImageManifest: imageManifest,
		ImageBlob:     imageBlob,
		ImageTag:      image.Tag,
		Registry:      image.Domain,
	}, nil
}

func getDockerEntryFromDockerSecret(instance *corev1.Secret) (dockerConfigEntry *DockerConfigEntry, err error) {

	if instance.Type != corev1.SecretTypeDockerConfigJson {
		return nil, fmt.Errorf("secret %s in ns %s type should be %s",
			instance.Name, instance.Namespace, corev1.SecretTypeDockerConfigJson)
	}
	dockerConfigBytes, ok := instance.Data[corev1.DockerConfigJsonKey]
	if !ok {
		return nil, fmt.Errorf("could not get data %s", corev1.DockerConfigJsonKey)
	}
	dockerConfig := &DockerConfigJson{}
	err = json.Unmarshal(dockerConfigBytes, dockerConfig)
	if err != nil {
		return nil, err
	}
	if len(dockerConfig.Auths) == 0 {
		return nil, fmt.Errorf("docker config auth len should not be 0")
	}
	for registryAddress, dce := range dockerConfig.Auths {
		dce.ServerAddress = registryAddress
		return &dce, nil
	}
	return nil, nil
}

func  (c *registryGetter) GetEntryTags(namespace, secretName, imageName string) ([]string, error) {
	var config *DockerConfigEntry

	if namespace == "" || secretName == "" {
		config = &DockerConfigEntry{}
	} else {
		secret, err := c.sc.Core.Secrets(namespace).Get(secretName, metav1.GetOptions{})
		if err != nil {
			return nil, err
		}
		config, err = getDockerEntryFromDockerSecret(secret)
		logrus.Infof("docker_config: %+v", config)
		if err != nil {
			return nil, err
		}
	}

	// default use ssl
	checkSSl := func(serverAddress string) bool {
		if strings.HasPrefix(serverAddress, "http://") {
			return false
		} else {
			return true
		}
	}

	if strings.HasPrefix(imageName, "http") {
		dockerurl, err := ParseDockerURL(imageName)
		if err != nil {
			return nil, err
		}
		imageName = dockerurl.StringWithoutScheme()
	}

	// parse image
	image, err := ParseImage(imageName)
	if err != nil {
		return nil, err
	}

	useSSL := checkSSl(config.ServerAddress)

	// Create the registry client.
	r, err := CreateRegistryClient(config.Username, config.Password, image.Domain, useSSL)
	if err != nil {
		return nil, err
	}

	tagsUrl := r.GetTagsUrl(image)

	// Get token.
	token, err := r.Token(tagsUrl)
	if err != nil {
		return nil, err
	}

	tags, err := r.ImageTags(image, token)
	if err != nil {
		return nil, err
	}
	return tags, nil
}

