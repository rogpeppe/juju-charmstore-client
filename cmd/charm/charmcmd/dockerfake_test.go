package charmcmd_test

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"

	"github.com/docker/docker/pkg/jsonmessage"
	"github.com/juju/loggo"
)

func newDockerHandler() *dockerHandler {
	return &dockerHandler{}
}

type pushRequest struct {
	imageID string
	tag     string
}

type tagRequest struct {
	imageID string
	tag     string
	repo    string
}

type dockerHandler struct {
	mu   sync.Mutex
	reqs []interface{}
}

func (srv *dockerHandler) imageDigest(imageName string) string {
	return fmt.Sprintf("sha256:%x", sha256.Sum256([]byte(imageName)))
}

var logger = loggo.GetLogger("charm.cmd.charmtest")

func (srv *dockerHandler) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	logger.Infof("dockerHandler.ServeHTTP %v", req.URL)
	req.ParseForm()
	if !strings.HasPrefix(req.URL.Path, "/v1.38/images/") {
		http.NotFound(w, req)
		return
	}
	switch {
	case strings.HasSuffix(req.URL.Path, "/push"):
		srv.servePush(w, req)
	case strings.HasSuffix(req.URL.Path, "/tag"):
		srv.serveTag(w, req)
	default:
		logger.Errorf("docker server page %q not found", req.URL)
		http.NotFound(w, req)
	}
}

func (srv *dockerHandler) serveTag(w http.ResponseWriter, req *http.Request) {
	path := strings.TrimPrefix(req.URL.Path, "/v1.38/images/")
	path = strings.TrimSuffix(path, "/tag")
	srv.addRequest(tagRequest{
		tag:     req.Form.Get("tag"),
		repo:    req.Form.Get("repo"),
		imageID: path,
	})
}

func (srv *dockerHandler) servePush(w http.ResponseWriter, req *http.Request) {
	path := strings.TrimPrefix(req.URL.Path, "/v1.38/images/")
	path = strings.TrimSuffix(path, "/push")
	// TODO include authentication creds in pushRequest?
	srv.addRequest(pushRequest{
		imageID: path,
		tag:     req.Form.Get("tag"),
	})

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(200)
	type finalStatus struct {
		Tag    string
		Digest string
		Size   int64
	}
	aux, _ := json.Marshal(finalStatus{
		Tag:    "latest",
		Digest: srv.imageDigest(path),
		Size:   10000,
	})
	auxMsg := json.RawMessage(aux)
	enc := json.NewEncoder(w)
	enc.Encode(jsonmessage.JSONMessage{
		Aux: &auxMsg,
	})
}

func (srv *dockerHandler) addRequest(req interface{}) {
	srv.mu.Lock()
	defer srv.mu.Unlock()
	srv.reqs = append(srv.reqs, req)
}

func newDockerRegistryHandler() *dockerHandler {
	return &dockerRegistryHandler{}
}

type dockerRegistryHandler struct {
	contents map[string] struct {
		version int
		digest string
	}
}

serve /v2/
	look for token
	if not there, return 401 response with realm, service, etc

serve /v2/..../manifests/:tag
	return header:
	Docker-Distribution-Api-Version: "registry/2.0"
	Docker-Content-Digest: "sha256:xxxxx"


type dockerAuthHandler struct {
}

serve /token
	return token
