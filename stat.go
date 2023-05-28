package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/mux"
	"github.com/rs/cors"
)

const (
	hoursToDeleteFromCluster = 1
)

var (
	stats       statType
	servicePort string    = "8880"
	startTime   time.Time = time.Now()
	cert        certType
	cluster     clusterType

	// certPool  *x509.CertPool
)

type statType struct {
	Uptime           string `json:"uptime"`
	RawTraps         uint64 `json:"received"`
	FilteredTrapsV2  uint64 `json:"passedv2"`
	FilteredTrapsV3  uint64 `json:"passedv3"`
	TestTrap         uint64 `json:"testtrap"`
	DeliveredTraps   uint64 `json:"delivered"`
	UndeliveredTraps uint64 `json:"undelivered"`
	LostTraps        uint64 `json:"lost"`
	Master           bool   `json:"master"`

	sync.RWMutex
}

type certType struct {
	pem  string
	key  string
	root string
}

type messageType struct {
	HostName  string    `json:"host"`
	LastCheck time.Time `json:"lastcheck"`
	StartTime time.Time `json:"uptime"`
	Status    bool      `json:"status"`
}

type clusterType struct {
	me             messageType
	c              map[string]messageType
	isMaster       bool
	httpClient     *http.Client
	lastFileChange time.Time

	sync.RWMutex
}

func stat() {
	for cert.key == "" || cert.pem == "" || cert.root == "" { // Ждём заполнения значений файлов ключей при старте программы
		credCond.L.Lock()
		credCond.Wait()
		credCond.L.Unlock()
	}

	cluster.init()

	r := mux.NewRouter()
	r.HandleFunc("/off", off).Methods(http.MethodGet)
	r.HandleFunc("/status", status).Methods(http.MethodGet)
	r.HandleFunc("/setmaster", cluster.setMasterFromHttp).Methods(http.MethodGet)
	r.HandleFunc("/healthcheck", pong).Methods(http.MethodPost)
	r.HandleFunc("/rereadb", rereadDb).Methods(http.MethodGet)
	r.HandleFunc("/proxy/{instance}/{host}/{proxy}", newProxy).Methods(http.MethodPut)
	r.HandleFunc("/proxyfromcluster/{instance}/{host}/{proxy}", newProxyLocal).Methods(http.MethodPut)
	handler := cors.Default().Handler(r)

	certs, err := tls.LoadX509KeyPair(cert.pem, cert.key)
	if err != nil {
		log.Println("Stat: certs:", cert.pem, cert.key, "error:", err.Error())

		httpServer := &http.Server{
			Addr:              ":" + servicePort,
			Handler:           handler,
			ReadHeaderTimeout: 2 * time.Second,
			ReadTimeout:       2 * time.Second,
			WriteTimeout:      5 * time.Second,
			TLSConfig:         &tls.Config{},
		}

		log.Fatal(httpServer.ListenAndServe())
	}

	httpServer := &http.Server{
		Addr:              ":" + servicePort,
		Handler:           handler,
		ReadHeaderTimeout: 2 * time.Second,
		ReadTimeout:       2 * time.Second,
		WriteTimeout:      5 * time.Second,
		TLSConfig: &tls.Config{
			MinVersion:               tls.VersionTLS12,
			MaxVersion:               tls.VersionTLS13,
			PreferServerCipherSuites: true,
			ClientAuth:               tls.VerifyClientCertIfGiven, // tls.RequireAndVerifyClientCert, tls.RequestClientCert, tls.VerifyClientCertIfGiven
			Certificates:             []tls.Certificate{certs},
		},
	}

	log.Fatal(httpServer.ListenAndServeTLS(cert.pem, cert.key))
	// log.Fatal(http.ListenAndServeTLS(":"+servicePort, cert_pem, cert_key, handler))
}

func ping() {
	var wg sync.WaitGroup

	for {
		for _, i := range cluster.list() {
			wg.Add(1)
			go cluster.healthcheck(&wg, i)
			time.Sleep(50 * time.Millisecond)
		}
		wg.Wait()
		cluster.checkMaster()
		time.Sleep(500 * time.Millisecond)
	}
}

func pong(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
	// vars := mux.Vars(r)

	// certOk := false

	// for _, z := range r.TLS.PeerCertificates {
	// 	if cluster.have(z.Subject.CommonName) {
	// 		certOk = true
	// 	}
	// }

	// if !certOk { // вопрос - надо ли это вообще?
	// 	log.Println("Pong: cluster config file don't have record for",)
	// }

	var messages []messageType

	reqBody, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		log.Println("Pong: error ReadAll:", err.Error())
		return
	}

	if err := json.Unmarshal(reqBody, &messages); err != nil {
		log.Println("Pong: error Unmarshal:", err.Error())
		// return
	} else {
		cluster.update(messages)
	}

	cluster.checkMaster()

	json.NewEncoder(w).Encode(cluster.response())
}

func (c *clusterType) init() {
	c.Lock()
	defer c.Unlock()

	// Trusted server certificate.
	var certPool *x509.CertPool

	certRoot, err := os.ReadFile(cert.root)
	if err != nil {
		log.Println("Cluster Init: can't read", cert.root, "error:", err.Error())
	} else {
		certPool = x509.NewCertPool()
		if ok := certPool.AppendCertsFromPEM(certRoot); !ok {
			log.Println("Cluster Init: unable to parse cert from", cert.root)
		}
	}

	certKeys, err := tls.LoadX509KeyPair(cert.pem, cert.key)
	if err != nil {
		log.Printf("Cluster Init: can't load from PEM & KEY files %s,%s error: %+v\n", cert.pem, cert.key, err)
		return
	}

	c.httpClient = &http.Client{
		Timeout: time.Duration(400 * time.Millisecond),
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs:      certPool,
				Certificates: []tls.Certificate{certKeys},
			},
		},
	}

	cc, err := x509.ParseCertificate(certKeys.Certificate[0])
	if err != nil {
		log.Println("Cluster Init: Error in parse certificate:", err.Error())
	} else {
		if debug {
			log.Printf("Cert Hostname: %+v\n\n", cc.Subject.CommonName)
		}
		c.me.HostName = cc.Subject.CommonName
	}

	if c.c == nil {
		c.c = make(map[string]messageType)
	}

	c.me.StartTime = time.Now()
	c.me.LastCheck = c.me.StartTime
	c.me.Status = true
	c.isMaster = false // пока не проверили статусы всех участников кластера трапы не обрабатываем

	go ping()
}

func (c *clusterType) healthcheck(wg *sync.WaitGroup, name string) {
	defer wg.Done()
	defer cluster.checkMaster()

	bytesRepr, err := json.Marshal(cluster.response())
	if err != nil {
		log.Println("Healthcheck: error in Marshal:", err.Error())
	}

	// log.Println("healthcheck: healthcheck:", string(bytesRepr))

	c.RLock()
	client := c.httpClient
	c.RUnlock()

	resp, err := client.Post("https://"+name+":"+servicePort+"/healthcheck", "application/json", bytes.NewBuffer(bytesRepr))
	if err != nil {
		c.setStatus(name, false)
		return
	}
	defer resp.Body.Close()

	resBody, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Println("Healthcheck: error ReadAll:", err.Error())
		c.setStatus(name, false)
		return
	}

	var messages []messageType

	// log.Println("healthcheck: response:", string(resBody))

	if err := json.Unmarshal(resBody, &messages); err != nil {
		log.Println("healthcheck: error Unmarshal:", err.Error())
		c.setStatus(name, false)
		// return
	} else {
		cluster.update(messages)
	}
}

// func (c *clusterType) have(s string) bool {
// 	c.RLock()
// 	defer c.RUnlock()

// 	_, have := c.c[s]
// 	return have
// }

func (c *clusterType) list() []string {
	c.RLock()
	defer c.RUnlock()

	result := make([]string, 0, len(c.c))

	for i := range c.c {
		result = append(result, i)
	}

	return result
}

func (c *clusterType) update(messages []messageType) {
	c.Lock()
	defer c.Unlock()

	for _, i := range messages {
		if i.HostName != c.me.HostName && i.LastCheck.After(c.c[i.HostName].LastCheck) {
			if i.Status != c.c[i.HostName].Status {
				log.Printf("Cluster: status of member %s switched to %v\n", i.HostName, i.Status)
			}
			c.c[i.HostName] = i
		}
	}
}

func (c *clusterType) response() (res []messageType) {
	c.RLock()
	defer c.RUnlock()

	res = make([]messageType, 1, len(c.c)+1)
	res[0].HostName = c.me.HostName
	res[0].LastCheck = time.Now()
	res[0].StartTime = c.me.StartTime
	res[0].Status = true

	for _, i := range c.c {
		res = append(res, i)
	}

	return
}

func (c *clusterType) master() bool {
	c.RLock()
	defer c.RUnlock()

	return c.isMaster
}

func (c *clusterType) checkMaster() {
	c.RLock()

	for _, i := range c.c {
		if i.Status && c.me.StartTime.After(i.StartTime) {
			if c.isMaster {
				c.RUnlock()
				c.setMaster(false)
				return
			} else {
				c.RUnlock()
				return
			}
		}
	}

	if !c.isMaster {
		c.RUnlock()
		c.setMaster(true)
		return
	}

	c.RUnlock()
}

func (c *clusterType) setMaster(status bool) {
	c.Lock()
	defer c.Unlock()

	if c.isMaster != status {
		c.isMaster = status
		log.Printf("Cluster: status master switched to %v\n", status)
	}
}

func (c *clusterType) setMasterFromHttp(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()

	w.WriteHeader(http.StatusAccepted)

	if len(r.TLS.PeerCertificates) > 0 {
		log.Printf("Cluster: Certs: %d, %+v\n\n", len(r.TLS.PeerCertificates), r.TLS.PeerCertificates)
	}

	fromCert := ""
	if r.TLS.PeerCertificates != nil && len(r.TLS.PeerCertificates) > 0 {
		fromCert = ", " + r.TLS.PeerCertificates[0].Subject.CommonName
	}

	if c.master() {
		log.Printf("Cluster: HTTP command from %s%s - master is already TRUE\n", r.RemoteAddr, fromCert)
		return // Уже мастер
	}

	log.Printf("Cluster: master switched to TRUE by HTTP command from %s%s\n", r.RemoteAddr, fromCert)

	c.Lock()
	defer c.Unlock()

	for _, i := range c.c {
		if i.StartTime.Before(c.me.StartTime) {
			c.me.StartTime = i.StartTime.Add(-time.Microsecond)
		}
	}

}

func (c *clusterType) setStatus(name string, status bool) {
	c.Lock()
	defer c.Unlock()

	// Если член кластера протух - удаляем
	if !status && time.Since(c.c[name].LastCheck).Hours() > hoursToDeleteFromCluster && !c.c[name].LastCheck.IsZero() {
		delete(c.c, name)
		// Не логируем т.к. выполняется много раз
		log.Printf("Cluster: member %s deleted\n", name)
	} else {
		t := c.c[name]
		// Не логируем т.к. выполняется много раз
		if t.Status != status {
			log.Printf("Cluster: status of member %s switched to %v\n", name, status)
		}
		t.Status = status
		c.c[name] = t
	}
}

func (c *clusterType) status(name string) bool {
	c.RLock()
	defer c.RUnlock()

	return c.c[name].Status
}

func (c *clusterType) newProxy(clusterName, host, proxy, instance string) {
	c.RLock()
	client := c.httpClient
	c.RUnlock()

	host = strings.ReplaceAll(host, " ", "%20")

	req, err := http.NewRequest(http.MethodPut, "https://"+clusterName+":"+servicePort+"/proxyfromcluster/"+instance+"/"+host+"/"+proxy, nil)
	if err != nil {
		log.Printf("Cluster.NewProxy NewRequest: error %+v\n\n", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		log.Printf("Cluster.NewProxy Do: error %+v\n\n", err)
		return
	}

	defer resp.Body.Close()

	resBody, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Println("Ping request: error ReadAll:", err.Error())
		return
	}

	if resp.StatusCode != 201 {
		log.Printf("Cluster.NewProxy resBody: clusterName: %s, Code: %s, error: %+v\n\n", clusterName, resp.Status, string(resBody))
	}
}

func status(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()

	w.WriteHeader(http.StatusOK)

	workTime := time.Since(startTime).String()
	stats.RLock()
	defer stats.RUnlock()

	// for _, z := range r.TLS.PeerCertificates {
	// 	log.Println("Status: Subject:", z.DNSNames, z.Subject.String(), z.Subject.CommonName)
	// 	for _, i := range z.IPAddresses {
	// 		log.Println("status: IP:", i.String())
	// 	}
	// }

	_ = json.NewEncoder(w).Encode(statType{
		Uptime:           workTime,
		RawTraps:         stats.RawTraps,
		FilteredTrapsV2:  stats.FilteredTrapsV2,
		FilteredTrapsV3:  stats.FilteredTrapsV3,
		TestTrap:         stats.TestTrap,
		LostTraps:        stats.LostTraps,
		DeliveredTraps:   stats.DeliveredTraps,
		UndeliveredTraps: stats.UndeliveredTraps,
		Master:           cluster.master(),
	})
}

func newProxy(w http.ResponseWriter, r *http.Request) {
	newProxyLocal(w, r)

	vars := mux.Vars(r)

	for _, clusterName := range cluster.list() {
		if cluster.status(clusterName) {
			go cluster.newProxy(clusterName, vars["host"], vars["proxy"], vars["instance"])
		}
	}
}

func newProxyLocal(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()

	vars := mux.Vars(r)

	_, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	err = hosts.newProxy(vars["host"], vars["proxy"], vars["instance"])
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		log.Printf("NewProxyLocal: error: %s\n", err.Error())
		return
	}

	w.WriteHeader(http.StatusCreated)

	fromCert := ""
	if r.TLS.PeerCertificates != nil && len(r.TLS.PeerCertificates) > 0 {
		fromCert = ", " + r.TLS.PeerCertificates[0].Subject.CommonName
	}

	log.Printf("Host %s moved to proxy %s on instance %s by REST command from %s%s\n", vars["host"], vars["proxy"], vars["instance"], r.RemoteAddr, fromCert)

}

func off(w http.ResponseWriter, r *http.Request) {

	w.WriteHeader(http.StatusOK)

	time.Sleep(time.Second)

	os.Exit(0)
}

func rereadDb(w http.ResponseWriter, r *http.Request) {
	chReloadDB <- struct{}{}

	fromCert := ""
	if r.TLS.PeerCertificates != nil && len(r.TLS.PeerCertificates) > 0 {
		fromCert = ", " + r.TLS.PeerCertificates[0].Subject.CommonName
	}

	log.Printf("Reread database by REST command from %s%s\n", r.RemoteAddr, fromCert)
}

func (s *statType) newRawTrap() {
	s.Lock()
	defer s.Unlock()

	s.RawTraps++
}

func (s *statType) newFilteredTrap(version int) {
	s.Lock()
	defer s.Unlock()

	if version == 2 {
		s.FilteredTrapsV2++
	} else if version == 3 {
		s.FilteredTrapsV3++
	} else if version == 0 {
		s.TestTrap++
	}
}

func (s *statType) newDeliveredTrap(i int) {
	s.Lock()
	defer s.Unlock()

	s.DeliveredTraps = s.DeliveredTraps + uint64(i)
}

func (s *statType) newUndeliveredTrap(i int) {
	s.Lock()
	defer s.Unlock()

	s.UndeliveredTraps = s.UndeliveredTraps + uint64(i)
}

func (s *statType) newLostTrap() {
	s.Lock()
	defer s.Unlock()

	s.LostTraps++
}
