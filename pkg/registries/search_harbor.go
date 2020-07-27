package registries

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/emicklei/go-restful"
	log "k8s.io/klog"
)


// Digest returns the digest for an image.
func (r *Registry) ImageSearchHarbor(q string, token string) (*ImageHarbor, error) {
	url := r.GetSearchHarborUrl(q)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}

	if token != "" {
		req.Header.Set("Authorization", fmt.Sprintf("Basic %s", token))
	}

	resp, err := r.Client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	respBody, _ := GetRespBody(resp)

	if resp.StatusCode != http.StatusOK {
		if resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusUnauthorized {
			log.Error(statusUnauthorized)
			return nil, restful.NewError(resp.StatusCode, statusUnauthorized)
		}
		log.Error("got response: " + string(resp.StatusCode) + string(respBody))
		return nil, restful.NewError(resp.StatusCode, "got image manifest failed")
	}

	imageList := &ImageHarbor{}
	err = json.Unmarshal(respBody, imageList)

	return imageList, err
}

func (r *Registry) GetSearchHarborUrl(q string) string {
	url := r.url("/api/search?q=%s", q)
	return url
}
