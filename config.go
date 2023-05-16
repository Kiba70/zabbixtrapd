package main

import (
	"bufio"
	"encoding/json"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	snmp "github.com/gosnmp/gosnmp"
)

const (
	chBuffer        = 2048
	configTimeSleep = 2
)

var (
	chTrapRaw       chan trapRaw       = make(chan trapRaw, chBuffer)
	chTrapFiltered  chan trapType      = make(chan trapType, chBuffer)
	chTrapConverted chan trapConverted = make(chan trapConverted, chBuffer)
	chReloadDB      chan struct{}      = make(chan struct{}, 10) // Триггер для перечитки списка хостов из БД
	chTrapLost      chan trapConverted = make(chan trapConverted, chBuffer)
	trapOids        trapOidType
	varOids         varOidType
	credCond        *sync.Cond = sync.NewCond(&sync.Mutex{})
)

type trapRaw struct {
	time   time.Time
	addr   net.UDPAddr
	packet snmp.SnmpPacket
}

type snmpPacket struct {
	oid     string
	value   string
	name    string
	asn1BER snmp.Asn1BER
}

type trapType struct {
	time   time.Time
	addr   net.UDPAddr
	packet []snmpPacket
}

type oidType struct {
	name         string
	unknownValue string
	wait         int
}

type trapOidType struct {
	oid            map[string]oidType
	lastFileChange time.Time

	sync.RWMutex
}

type varOidType struct {
	oid            map[string]string
	lastFileChange time.Time

	sync.RWMutex
}

type trapConverted struct {
	time      time.Time
	addr      net.UDPAddr
	name      string
	lastDigit string
	oid       string
	ifIndex   string
	packet    []snmpPacket
}

type trapToSend struct {
	proxy string

	trapConverted
}

// Struct for creditionals file
type configCreditionals struct {
	PSQLuser        string              `json:"psql_user"`
	PSQLpassword    string              `json:"psql_password"`
	PSQLport        string              `json:"psql_port"`
	ServicePort     string              `json:"service_port"`
	CertPEM         string              `json:"cert_pem"`
	CertKEY         string              `json:"cert_key"`
	CertROOT        string              `json:"cert_root"`
	Community       map[string]struct{} `json:"community"`
	SNMPv3_user     string              `json:"snmpv3_user"`
	SNMPv3_password string              `json:"snmpv3_password"`
	SNMPv3_authtype string              `json:"snmpv3_authtype"`
}

// Struct for database PGSQL
type configPSQL struct {
	DBhost     string `json:"dbhost"`
	DBport     string `json:"dbport"`
	DBname     string `json:"dbname"`
	DBuser     string `json:"dbuser"`
	DBpassword string `json:"dbpassword"`
}

type instanceZabbix struct {
	// Name string       `json:"zabbix"`
	PSQL []configPSQL `json:"config_psql"`
}

type instancesZabbix struct {
	i                  map[string]instanceZabbix
	lastFileChangeCred time.Time // Время последнего изменения файла cred.json
	lastFileChangeInst time.Time // Время последнего изменения файла instance.json
	lastCheckDB        time.Time // Время последней загрузки информации из БД

	sync.RWMutex
}

// Gorutine поддержки конфигурации в актуальном состоянии
func loadConfigs() {
	for {
		loadOids()
		loadVars()
		dbs.loadConfig()
		cluster.loadCluster()

		time.Sleep(configTimeSleep * time.Second)
	}
}

func (d *instancesZabbix) loadConfig() {
	fstCred, err := os.Stat(fileCred)
	if err != nil {
		log.Printf("Can't Stat info of file %s\n", fileCred)
		return
	}

	fstInst, err := os.Stat(fileInstance)
	if err != nil {
		log.Printf("Can't Stat info of file %s\n", fileInstance)
		return
	}

	if d.lastFileChangeCred != fstCred.ModTime() || d.lastFileChangeInst != fstInst.ModTime() { // Дата модификации файла отличается от последней прочитанной
		// Читаем параметры creditionals
		var crd configCreditionals

		dbs.lastFileChangeCred = fstCred.ModTime()
		dbs.lastFileChangeInst = fstInst.ModTime()

		crdJson, err := os.ReadFile(fileCred)
		if err != nil {
			log.Println("getConfig: creditionals file not found:", err)
		} else if err := json.Unmarshal(crdJson, &crd); err != nil {
			log.Println("getConfig: can't Unmarshal creditionals file:", err)
			return
		}

		credCond.L.Lock()
		cert.pem = crd.CertPEM
		cert.key = crd.CertKEY
		cert.root = crd.CertROOT
		servicePort = crd.ServicePort
		snmpv3_user = crd.SNMPv3_user
		snmpv3_password = crd.SNMPv3_password
		snmpv3_authtype = crd.SNMPv3_authtype
		credCond.L.Unlock()
		credCond.Broadcast()

		community.Lock()
		community.c = crd.Community
		community.Unlock()

		// Заполняем отсутствующие значения параметров creditionals на значения по умолчанию
		if crd.PSQLport == "" {
			crd.PSQLport = dbPort
		}

		// Читаем конфигурацию
		cnfJson, err := os.ReadFile(fileInstance)
		if err != nil {
			log.Println("Can't Read file:", fileInstance)
			return
		}

		inst := make(map[string]instanceZabbix)

		if err := json.Unmarshal(cnfJson, &inst); err != nil {
			log.Println("Can't Unmarshal:", string(cnfJson))
			return
		}

		dd := make(map[string]bool) // Для удаления из мапы

		for z, i := range inst {
			// PostgreSQL Zabbix
			for v := range i.PSQL {
				if i.PSQL[v].DBuser == "" {
					i.PSQL[v].DBuser = crd.PSQLuser
				}
				if i.PSQL[v].DBpassword == "" {
					i.PSQL[v].DBpassword = crd.PSQLpassword
				}
				if i.PSQL[v].DBport == "" {
					i.PSQL[v].DBport = crd.PSQLport
				}
			}
			dd[z] = true
			dbs.Lock()
			dbs.i[z] = i
			dbs.Unlock()
		}
		if len(dd) < len(dbs.i) { // Из файла удалены какие-то instance
			dbs.Lock()
			for i := range dbs.i {
				if _, have := dd[i]; !have {
					delete(dbs.i, i)
				}
			}
			dbs.Unlock()
		}

		chReloadDB <- struct{}{} // Сигналим перечитать все БД
	}
}

// Загрузка переменных Trap
func loadVars() {
	if varOids.oid == nil {
		varOids.oid = make(map[string]string)
	}

	fst, err := os.Stat(fileVars)
	if err != nil {
		log.Printf("Can't Stat info of file %s\n", fileVars)
		return
	}

	if varOids.lastFileChange != fst.ModTime() { // Дата модификации файла отличается от последней прочитанной
		var s []string

		fr, err := os.Open(fileVars)
		if err != nil {
			log.Printf("Can't Read file %s", fileVars)
			return
		}
		defer fr.Close()

		sd := make(map[string]bool) // Для удаления из мапы
		varOids.lastFileChange = fst.ModTime()
		sc := bufio.NewScanner(fr)
		varOids.Lock()
		for sc.Scan() {
			s = strings.Split(sc.Text(), ";")
			if s[0][0] != '.' { // Исправляем ошибку когда OID в файле не начинается с "."
				s[0] = "." + s[0]
			}
			varOids.oid[s[0]] = s[1]
			sd[s[0]] = true
		}
		if len(sd) < len(varOids.oid) { // Из файла удалены какие-то OID
			for i := range varOids.oid {
				if _, have := sd[i]; !have {
					delete(varOids.oid, i)
				}
			}
		}
		varOids.Unlock()

		if debug {
			log.Printf("%v\n", varOids.oid)
		}
	}
}

// Загрузка OID Trap которые должны обрабатываться
func loadOids() {
	if trapOids.oid == nil {
		trapOids.oid = make(map[string]oidType)
	}

	fst, err := os.Stat(fileOids)
	if err != nil {
		log.Printf("Can't Stat info of file %s\n", fileOids)
		return
	}

	if trapOids.lastFileChange != fst.ModTime() { // Дата модификации файла отличается от последней прочитанной
		var s []string
		var oid oidType

		fr, err := os.Open(fileOids)
		if err != nil {
			log.Printf("Can't Read file %s", fileOids)
			return
		}
		defer fr.Close()

		sd := make(map[string]bool) // Для удаления из мапы
		trapOids.lastFileChange = fst.ModTime()
		sc := bufio.NewScanner(fr)
		trapOids.Lock()
		for sc.Scan() {
			s = strings.Split(sc.Text(), ";")
			if s[0][0] == '#' {
				continue
			}
			if s[0][0] != '.' { // Исправляем ошибку когда OID в файле не начинается с "."
				s[0] = "." + s[0]
			}
			oid.name = s[1]
			if len(s) == 4 {
				oid.unknownValue = s[2]
				if oid.wait, err = strconv.Atoi(s[3]); err != nil {
					log.Printf("ERROR: LoadOIDs strconv.Atoi: %s, %+v\n", s[3], err)
				}
			} else {
				oid.unknownValue = ""
				oid.wait = 0
			}
			trapOids.oid[s[0]] = oid
			sd[s[0]] = true
		}
		if len(sd) < len(trapOids.oid) { // Из файла удалены какие-то OID
			for i := range trapOids.oid {
				if _, have := sd[i]; !have {
					delete(trapOids.oid, i)
				}
			}
		}
		trapOids.Unlock()

		if debug {
			log.Printf("%v\n", trapOids.oid)
		}
	}
}

func (c *clusterType) loadCluster() {
	// clusterCond.L.Lock()
	// defer clusterCond.Broadcast()
	// defer clusterCond.L.Unlock()

	fst, err := os.Stat(fileCluster)
	if err != nil {
		log.Printf("Can't Stat info of file %s\n", fileCluster)
		return
	}

	if c.lastFileChange != fst.ModTime() { // Дата модификации файла отличается от последней прочитанной
		fr, err := os.Open(fileCluster)
		if err != nil {
			log.Printf("Can't Read file %s", fileCluster)
			return
		}
		defer fr.Close()

		sc := bufio.NewScanner(fr)
		var s string
		var mt messageType

		c.Lock()
		defer c.Unlock()

		if c.c == nil {
			c.c = make(map[string]messageType)
		}

		for sc.Scan() {
			s = sc.Text()
			if s[0] == '#' {
				continue
			}
			mt = c.c[s]
			mt.HostName = s
			c.c[s] = mt
		}
	}
}
