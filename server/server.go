package server

import (
	"context"
	"fmt"
	"github.com/coreos/pkg/httputil"
	"github.com/rancher/rancher/pkg/registries"
	"github.com/sirupsen/logrus"
	"io"
	"io/ioutil"
	"k8s.io/client-go/rest"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/rancher/rancher/pkg/api/customization/clusterregistrationtokens"
	"github.com/rancher/rancher/pkg/api/customization/vsphere"
	managementapi "github.com/rancher/rancher/pkg/api/server"
	"github.com/rancher/rancher/pkg/audit"
	"github.com/rancher/rancher/pkg/auth/providers/publicapi"
	"github.com/rancher/rancher/pkg/auth/providers/saml"
	"github.com/rancher/rancher/pkg/auth/requests"
	"github.com/rancher/rancher/pkg/auth/requests/sar"
	"github.com/rancher/rancher/pkg/auth/tokens"
	webhook2 "github.com/rancher/rancher/pkg/auth/webhook"
	"github.com/rancher/rancher/pkg/channelserver"
	"github.com/rancher/rancher/pkg/clustermanager"
	rancherdialer "github.com/rancher/rancher/pkg/dialer"
	"github.com/rancher/rancher/pkg/httpproxy"
	k8sProxyPkg "github.com/rancher/rancher/pkg/k8sproxy"
	"github.com/rancher/rancher/pkg/metrics"
	"github.com/rancher/rancher/pkg/pipeline/hooks"
	"github.com/rancher/rancher/pkg/rkenodeconfigserver"
	"github.com/rancher/rancher/pkg/telemetry"
	"github.com/rancher/rancher/pkg/websocket"
	"github.com/rancher/rancher/server/capabilities"
	"github.com/rancher/rancher/server/ui"
	"github.com/rancher/rancher/server/whitelist"
	"github.com/rancher/steve/pkg/auth"
	"github.com/rancher/steve/pkg/responsewriter"
	managementSchema "github.com/rancher/types/apis/management.cattle.io/v3/schema"
	"github.com/rancher/types/config"
)

var restConfig *rest.Config
var sc *config.ScaledContext

func Start(ctx context.Context, localClusterEnabled bool, scaledContext *config.ScaledContext, clusterManager *clustermanager.Manager, auditLogWriter *audit.LogWriter, authz auth.Middleware) (auth.Middleware, http.Handler, error) {
	tokenAPI, err := tokens.NewAPIHandler(ctx, scaledContext)
	if err != nil {
		return nil, nil, err
	}

	publicAPI, err := publicapi.NewHandler(ctx, scaledContext)
	if err != nil {
		return nil, nil, err
	}

	k8sProxy := k8sProxyPkg.New(scaledContext, scaledContext.Dialer)

	managementAPI, err := managementapi.New(ctx, scaledContext, clusterManager, k8sProxy, localClusterEnabled)
	if err != nil {
		return nil, nil, err
	}

	root := mux.NewRouter()
	root.UseEncodedPath()
	root.Use(responsewriter.ContentTypeOptions)

	rawAuthedAPIs := newAuthed(tokenAPI, managementAPI, k8sProxy, scaledContext)

	auth := requests.NewAuthenticator(ctx, scaledContext)
	auth = requests.NewImpersonatingAuth(auth, sar.NewSubjectAccessReview(clusterManager))
	if f, ok := scaledContext.Dialer.(*rancherdialer.Factory); ok {
		auth = requests.Chain(auth, f.TunnelAuthorizer)
	}

	authMiddleware := requests.ToAuthMiddleware(auth)
	tokenReview := &webhook2.TokenReviewer{
		Authenticator: auth,
	}

	authedHandler, err := requests.NewAuthenticationFilter(ctx, auth, scaledContext, rawAuthedAPIs)
	if err != nil {
		return nil, nil, err
	}
	authedHandler = authz.Wrap(authedHandler)

	metricsHandler, err := requests.NewAuthenticationFilter(ctx, auth, scaledContext, metrics.NewMetricsHandler(scaledContext, promhttp.Handler()))
	if err != nil {
		return nil, nil, err
	}

	websocketHandler := websocket.NewWebsocketHandler(authedHandler)

	auditHandler := audit.NewAuditLogFilter(ctx, auditLogWriter, websocketHandler)

	webhookHandler := hooks.New(scaledContext)

	connectHandler, connectConfigHandler := connectHandlers(scaledContext)

	samlRoot := saml.AuthHandler()
	chain := responsewriter.NewMiddlewareChain(responsewriter.Gzip, responsewriter.NoCache, responsewriter.DenyFrameOptions, responsewriter.ContentType, ui.UI)
	chainGzip := responsewriter.NewMiddlewareChain(responsewriter.Gzip, responsewriter.ContentType)

	restConfig = &scaledContext.RESTConfig
	sc = scaledContext

	root.HandleFunc("/search/docker/image", searchDockersHandler)
	root.HandleFunc("/search/dockerhub/products", searchDockerhubImagesHandler)
	root.HandleFunc("/registry/credential/verify", verifyRegistryCredentialHandler)
	root.HandleFunc("/search/docker/tags", searchDockerTagsHandler)

	root.Handle("/", chain.Handler(managementAPI))
	root.PathPrefix("/v3-public").Handler(publicAPI)
	root.Handle("/v3/import/{token}.yaml", http.HandlerFunc(clusterregistrationtokens.ClusterImportHandler))
	root.Handle("/v3/connect", connectHandler)
	root.Handle("/v3/connect/register", connectHandler)
	root.Handle("/v3/connect/config", connectConfigHandler)
	root.Handle("/v3/settings/cacerts", rawAuthedAPIs).Methods(http.MethodGet)
	root.Handle("/v3/settings/first-login", rawAuthedAPIs).Methods(http.MethodGet)
	root.Handle("/v3/settings/ui-pl", rawAuthedAPIs).Methods(http.MethodGet)
	root.Handle("/v3/settings/ui-banners", rawAuthedAPIs).Methods(http.MethodGet)
	root.Handle("/v3/tokenreview", tokenReview).Methods(http.MethodPost)
	root.PathPrefix("/metrics").Handler(metricsHandler)
	root.PathPrefix("/v3").Handler(chainGzip.Handler(auditHandler))
	root.PathPrefix("/hooks").Handler(webhookHandler)
	root.PathPrefix("/k8s/clusters/").Handler(auditHandler)
	root.PathPrefix("/meta").Handler(auditHandler)
	root.PathPrefix("/v1-telemetry").Handler(auditHandler)
	root.PathPrefix("/v1-release/release").Handler(channelserver.NewProxy(ctx))
	root.NotFoundHandler = ui.UI(http.NotFoundHandler())
	root.PathPrefix("/v1-saml").Handler(samlRoot)

	// UI
	uiContent := responsewriter.NewMiddlewareChain(responsewriter.Gzip, responsewriter.DenyFrameOptions, responsewriter.CacheMiddleware("json", "js", "css")).Handler(ui.Content())
	root.PathPrefix("/assets").Handler(uiContent)
	root.PathPrefix("/translations").Handler(uiContent)
	root.PathPrefix("/ember-fetch").Handler(uiContent)
	root.PathPrefix("/engines-dist").Handler(uiContent)
	root.Handle("/asset-manifest.json", uiContent)
	root.Handle("/crossdomain.xml", uiContent)
	root.Handle("/humans.txt", uiContent)
	root.Handle("/index.html", uiContent)
	root.Handle("/robots.txt", uiContent)
	root.Handle("/VERSION.txt", uiContent)

	//API UI
	root.PathPrefix("/api-ui").Handler(uiContent)

	registerHealth(root)

	return authMiddleware, root, err
}

func newAuthed(tokenAPI http.Handler, managementAPI http.Handler, k8sproxy http.Handler, scaledContext *config.ScaledContext) *mux.Router {
	authed := mux.NewRouter()
	authed.UseEncodedPath()
	authed.Use(responsewriter.ContentTypeOptions)
	authed.Path("/meta/gkeMachineTypes").Handler(capabilities.NewGKEMachineTypesHandler())
	authed.Path("/meta/gkeVersions").Handler(capabilities.NewGKEVersionsHandler())
	authed.Path("/meta/gkeZones").Handler(capabilities.NewGKEZonesHandler())
	authed.Path("/meta/gkeNetworks").Handler(capabilities.NewGKENetworksHandler())
	authed.Path("/meta/gkeSubnetworks").Handler(capabilities.NewGKESubnetworksHandler())
	authed.Path("/meta/gkeServiceAccounts").Handler(capabilities.NewGKEServiceAccountsHandler())
	authed.Path("/meta/aksVersions").Handler(capabilities.NewAKSVersionsHandler())
	authed.Path("/meta/aksVirtualNetworks").Handler(capabilities.NewAKSVirtualNetworksHandler())
	authed.Path("/meta/vsphere/{field}").Handler(vsphere.NewVsphereHandler(scaledContext))
	authed.PathPrefix("/meta/proxy").Handler(newProxy(scaledContext))
	authed.PathPrefix("/meta").Handler(managementAPI)
	authed.PathPrefix("/v3/identit").Handler(tokenAPI)
	authed.PathPrefix("/v3/token").Handler(tokenAPI)
	authed.PathPrefix("/k8s/clusters/").Handler(k8sproxy)
	authed.PathPrefix("/v1-telemetry").Handler(telemetry.NewProxy())
	authed.PathPrefix(managementSchema.Version.Path).Handler(managementAPI)

	return authed
}

func connectHandlers(scaledContext *config.ScaledContext) (http.Handler, http.Handler) {
	if f, ok := scaledContext.Dialer.(*rancherdialer.Factory); ok {
		return f.TunnelServer, rkenodeconfigserver.Handler(f.TunnelAuthorizer, scaledContext)
	}

	return http.NotFoundHandler(), http.NotFoundHandler()
}

func newProxy(scaledContext *config.ScaledContext) http.Handler {
	return httpproxy.NewProxy("/proxy/", whitelist.Proxy.Get, scaledContext)
}

func searchHarborImages(w http.ResponseWriter, r *http.Request) {
	logrus.Infof("cxx-req search harbor: %+v", r)
	params := r.URL.Query()
	namespace := params.Get("namespace")
	secretName := params.Get("secret_name")
	imageDomain := params.Get("image_domain")
	imageName := params.Get("image_name")

	// get entry
	registryGetter := registries.NewRegistryGetter(sc)

	list, err := registryGetter.SearchHarborImages(namespace, secretName, imageDomain, imageName)
	if err != nil {
		logrus.Errorf("%+v", err)
		httputil.WriteJSONResponse(w, http.StatusBadRequest, &registries.ImageDetails{Status: registries.StatusFailed, Message: err.Error()})
		return
	}

	httputil.WriteJSONResponse(w, http.StatusOK, list)
}

func searchDockerhubImagesHandler(w http.ResponseWriter, r *http.Request) {
	params := r.URL.Query()
	q := params.Get("q")
	pagesize := params.Get("page_size")
	searchType := params.Get("type")
	imageFilter := params.Get("image_filter")
	label := params.Get("label")

	// harbor 搜索单独处理
	if label == "harbor" {
		searchHarborImages(w, r)
		return
	}

	// dockerhub 搜索
	url := fmt.Sprintf("https://store.docker.com/api/content/v1/products/search/?&type=%s&page=1&page_size=%s", searchType, pagesize)

	if q != "" {
		url += "&q=" + q
	}
	if imageFilter != "" {
		url += "&image_filter=" + imageFilter
	}

	// new request
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		logrus.Error(err)
		httputil.WriteJSONResponse(w, http.StatusBadRequest, &registries.ImageDetails{Status: registries.StatusFailed, Message: err.Error()})
		return
	}
	//add header
	req.Header.Add("Search-Version", "v3")
	//http client
	client := &http.Client{}
	logrus.Debugf("Go %s URL : %s \n", http.MethodGet, req.URL.String())
	res, err := client.Do(req)
	if err != nil {
		logrus.Error(err)
		httputil.WriteJSONResponse(w, http.StatusBadRequest, &registries.ImageDetails{Status: registries.StatusFailed, Message: err.Error()})
		return
	}
	resp, _ := ioutil.ReadAll(res.Body)
	fmt.Printf("%s", resp)
	io.WriteString(w, string(resp))
}

func searchDockersHandler(w http.ResponseWriter, r *http.Request) {
	logrus.Infof("cxx-req docker: %+v", r)
	//params := mux.Vars(r)
	params := r.URL.Query()
	imageName := params.Get("image")
	namespace := params.Get("namespace")
	secretName := params.Get("secret")

	// get entry
	registryGetter := registries.NewRegistryGetter(sc)

	entry, err := registryGetter.GetEntry(namespace, secretName, imageName)
	logrus.Infof("image_entry: %+v", entry)
	if err != nil {
		logrus.Errorf("%+v", err)
		httputil.WriteJSONResponse(w, http.StatusBadRequest, &registries.ImageDetails{Status: registries.StatusFailed, Message: err.Error()})
		return
	}

	httputil.WriteJSONResponse(w, http.StatusOK, entry)
}

func verifyRegistryCredentialHandler(w http.ResponseWriter, r *http.Request) {
	params := r.URL.Query()
	username := params.Get("username")
	password := params.Get("password")
	serverHost := params.Get("serverhost")

	registryGetter := registries.NewRegistryGetter(sc)

	err := registryGetter.VerifyRegistryCredential(registries.RegistryCredential{Username: username, Password: password, ServerHost: serverHost})
	if err != nil {
		logrus.Errorf("%+v", err)
		httputil.WriteJSONResponse(w, http.StatusBadRequest, err)
		return
	}

	w.WriteHeader(http.StatusOK)
}

func searchDockerTagsHandler(w http.ResponseWriter, r *http.Request) {
	logrus.Infof("cxx-req docker: %+v", r)
	//params := mux.Vars(r)
	params := r.URL.Query()
	imageName := params.Get("image")
	namespace := params.Get("namespace")
	secretName := params.Get("secret")

	// get entry
	registryGetter := registries.NewRegistryGetter(sc)

	tags, err := registryGetter.GetEntryTags(namespace, secretName, imageName)
	logrus.Infof("image_tags: %+v", tags)
	if err != nil {
		logrus.Errorf("%+v", err)
		httputil.WriteJSONResponse(w, http.StatusBadRequest, &registries.ImageDetails{Status: registries.StatusFailed, Message: err.Error()})
		return
	}

	httputil.WriteJSONResponse(w, http.StatusOK, tags)
}
