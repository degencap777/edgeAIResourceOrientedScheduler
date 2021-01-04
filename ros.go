package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"github.com/julienschmidt/httprouter"
	"io"
	"k8s.io/api/core/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	schedulerapi "k8s.io/kube-scheduler/extender/v1"
	"log"
	"net/http"
	"strconv"
	"errors"
	"crypto/tls"
	"crypto/x509"
	"io/ioutil"

)

type DescribedObject struct {
	Kind       string `json:"kind"`
	Name       string `json:"name"`
	APIVersion string `json:"apiVersion"`
}

type MetricItem struct {
	DescribedObject DescribedObject `json:"describedObject"`
	MetricName      string          `json:"metricName"`
	Timestamp       string          `json:"timestamp"`
	Value           string          `json:"value"`
}

type MetricResponse struct {
	Kind  string       `json:"kind"`
	Items []MetricItem `json:"items"`
}

func contains(s []string, e string) bool {
	for _, a := range s {
		if a == e {
			return true
		}
	}
	return false
}

var clientset *kubernetes.Clientset

func GetMetrics(name string) (MetricResponse, error) {
	resp := MetricResponse{}
	out, err := clientset.RESTClient().Get().AbsPath("apis/custom.metrics.k8s.io/v1beta1/nodes/*/" + name).DoRaw(context.TODO())
    if err != nil {
		return resp, errors.New("Fail to query metrics")
	}
	fmt.Printf("metrics [%s]: %s\n", name, string(out))
	if err := json.Unmarshal(out, &resp); err != nil {
		return resp, errors.New("Fail to query metrics")
	}
	return resp, nil
}

func getValue(node string, metric MetricResponse) (int, error) {
	for _, item := range metric.Items {
		if node == item.DescribedObject.Name {
			fmt.Printf("node: %s, metric: %s, value: %s\n", node, item.MetricName, item.Value)
			value, err := strconv.Atoi(item.Value)
			if err != nil {
				return 100, errors.New("Fail to get value")
			}
			if (value >= 0) && (value <= 100) {
				return value, nil
			}
			return 100, errors.New("Metrics value out of range")
		}
	}

	return 100, errors.New("Can't find node in metrics")
}

func FilterByResourceMetric(vpuRequest int, codecRequest int, nodes *v1.NodeList, AllowedNodes []string) ([]string, error) {
	vpuMetrics, err := GetMetrics("collectd_kmb_vpu")
	if (err != nil) {
		return AllowedNodes, err
	}

	codecMetrics, err := GetMetrics("collectd_kmb_codec")
	if (err != nil) {
		return AllowedNodes, err
	}

	for _, node := range nodes.Items {
		vpuUsage, err := getValue(node.Name, vpuMetrics)
		if err == nil && (vpuUsage + vpuRequest <= 100) {
			codecUsage, err := getValue(node.Name, codecMetrics)
			if err == nil && (codecUsage + codecRequest <= 100) {
				AllowedNodes = append(AllowedNodes, node.Name)
			}
		}
	}

	return AllowedNodes, nil
}

func PredicateHandler(args schedulerapi.ExtenderArgs) *schedulerapi.ExtenderFilterResult {
	pod := args.Pod

	log.Print("==================================================================")
	log.Print(pod.Spec.Containers[0].Name)

	vpuQuantity   := pod.Spec.Containers[0].Resources.Limits["kmb.intel.com/vpu"]
	codecQuantity := pod.Spec.Containers[0].Resources.Limits["kmb.intel.com/codec"]
	vpuRequest, _   := vpuQuantity.AsInt64()
	codecRequest, _ := codecQuantity.AsInt64()

	if vpuRequest >= 0 && vpuRequest <= 3 {
		vpuRequest = vpuRequest * 30
	} else {
		vpuRequest = 100
	}

	if codecRequest >= 0 && codecRequest <= 3 {
		codecRequest = codecRequest * 30
	} else {
		codecRequest = 100
	}

	fmt.Printf("vpu requested: %d, codec requested: %d\n", vpuRequest, codecRequest)

	AllowedNodes := []string{}

	AllowedNodes, err := FilterByResourceMetric(int(vpuRequest), int(codecRequest), args.Nodes, AllowedNodes)

	if err != nil {
		result := schedulerapi.ExtenderFilterResult{
			Nodes: nil,
			FailedNodes: nil,
			Error:       err.Error(),
		}
		return &result
	}

	canSchedule := make([]v1.Node, 0, len(args.Nodes.Items))
	canNotSchedule := make(map[string]string)

	for _, node := range args.Nodes.Items {
		if contains(AllowedNodes, node.Name) {
			canSchedule = append(canSchedule, node)
			fmt.Printf("allowed node: %s\n", node.Name)
		}
	}

	result := schedulerapi.ExtenderFilterResult{
		Nodes: &v1.NodeList{
			Items: canSchedule,
		},
		FailedNodes: canNotSchedule,
		Error:       "",
	}

	return &result
}

const (
	basePath       = "/scheduler"
	predicatesPath = basePath + "/predicates"
)

func PredicateRoute() httprouter.Handle {
	return func(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
		if r.Body == nil {
			http.Error(w, "empty body", 400)
			return
		}

		var buf bytes.Buffer
		body := io.TeeReader(r.Body, &buf)

		var extenderArgs schedulerapi.ExtenderArgs
		var extenderFilterResult *schedulerapi.ExtenderFilterResult

		if err := json.NewDecoder(body).Decode(&extenderArgs); err != nil {
			extenderFilterResult = &schedulerapi.ExtenderFilterResult{
				Nodes:       nil,
				FailedNodes: nil,
				Error:       err.Error(),
			}
		} else {
			extenderFilterResult = PredicateHandler(extenderArgs)
		}

		if resultBody, err := json.Marshal(extenderFilterResult); err != nil {
			panic(err)
		} else {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			w.Write(resultBody)
		}
	}
}

func main() {
	config, err := rest.InClusterConfig()
	if err != nil {
		panic(err.Error())
	}

	clientset, err = kubernetes.NewForConfig(config)
	if err != nil {
		panic(err.Error())
	}

	router := httprouter.New()
	router.POST(predicatesPath, PredicateRoute())

        caCert, err := ioutil.ReadFile("/var/run/serving-cert/ca.crt")
        if err != nil {
                log.Fatal(err)
        }
        caCertPool := x509.NewCertPool()
        ok := caCertPool.AppendCertsFromPEM(caCert)
        if !ok {
                log.Fatal(ok)
        }

	cfg := &tls.Config{
		MinVersion:               tls.VersionTLS12,
		MaxVersion:               tls.VersionTLS12,
		CurvePreferences:         []tls.CurveID{tls.CurveP521, tls.CurveP384, tls.CurveP256},
		PreferServerCipherSuites: true,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		},
		ClientCAs: caCertPool,
		ClientAuth: tls.RequireAndVerifyClientCert,
	}

	server := &http.Server{
		Addr:         ":443",
		Handler:      router,
		TLSConfig:    cfg,
		TLSNextProto: make(map[string]func(*http.Server, *tls.Conn, http.Handler), 0),
	}

	log.Print("ROS starting on port :443")
	log.Fatal(server.ListenAndServeTLS("/var/run/serving-cert/server.crt", "/var/run/serving-cert/server.key"))

}
