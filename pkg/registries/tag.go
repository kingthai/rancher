package registries

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/emicklei/go-restful"
	"net/http"
	"regexp"

	log "k8s.io/klog"
)

var (
	ErrNoMorePages = errors.New("no more pages")
)

type tagsResponse struct {
	Tags []string `json:"tags"`
}

func (r *Registry) ImageTags(image Image, token string) (tags []string, err error) {
	url := r.GetTagsUrl(image)
	var (
		response tagsResponse
	)
	for {
		log.Infof("registry.tags url=%s repository=%s", url, image.Path)
		url, err = r.getPaginatedJSON(url, token, &response)

		switch err {
		case ErrNoMorePages:
			tags = append(tags, response.Tags...)
			return tags, nil
		case nil:
			tags = append(tags, response.Tags...)
			continue
		default:
			return nil, err
		}
	}
}

func (r *Registry) GetTagsUrl(image Image) string {
	url := r.url("/v2/%s/tags/list", image.Path)
	return url
}

func (r *Registry) getPaginatedJSON(url, token string, response interface{}) (string, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return "", err
	}
	if token != "" {
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))
	}
	resp, err := r.Client.Do(req)
	//resp, err := r.Client.Get(url)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		if resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusUnauthorized {
			log.Error(statusUnauthorized)
			return "", restful.NewError(resp.StatusCode, statusUnauthorized)
		}
		log.Errorf("got response: %s, %+v", string(resp.StatusCode), resp.Body)
		return "", restful.NewError(resp.StatusCode, "got image tags failed")
	}

	decoder := json.NewDecoder(resp.Body)
	err = decoder.Decode(response)
	if err != nil {
		return "", err
	}
	return getNextLink(resp)
}

// 获取下一页的链接
var nextLinkRE = regexp.MustCompile(`^ *<?([^;>]+)>? *(?:;[^;]*)*; *rel="?next"?(?:;.*)?`)

func getNextLink(resp *http.Response) (string, error) {
	for _, link := range resp.Header[http.CanonicalHeaderKey("Link")] {
		parts := nextLinkRE.FindStringSubmatch(link)
		if parts != nil {
			return parts[1], nil
		}
	}
	return "", ErrNoMorePages
}
