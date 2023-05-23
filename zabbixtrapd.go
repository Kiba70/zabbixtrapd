package main

import (
	"fmt"
	"log"
	"net"
	"os"
	"time"

	"github.com/akamensky/argparse"
	snmp "github.com/gosnmp/gosnmp"
)

const (
	instanceFile    = "/usr/local/etc/zabbixtrapd/instance.json"
	credFile        = "/usr/local/etc/zabbixtrapd/cred.json"
	logFile         = "/var/log/zabbixtrapd/zabbixtrapd.log"
	fileNameOids    = "/usr/local/etc/zabbixtrapd/traps.txt"
	fileNameVars    = "/usr/local/etc/zabbixtrapd/vars.txt"
	fileNameCluster = "/usr/local/etc/zabbixtrapd/cluster.txt"
)

var (
	debug           bool
	fileCred        string
	fileOids        string
	fileVars        string
	fileCluster     string
	fileInstance    string
	snmpv3_user     string
	snmpv3_password string
	snmpv3_authtype string
)

func main() {
	parser := argparse.NewParser("print", "example run: systemctl start zabbixtrapd")
	lf := parser.String("l", "logfile", &argparse.Options{Required: false, Default: logFile, Help: "log file"})
	fo := parser.String("o", "oids", &argparse.Options{Required: false, Default: fileNameOids, Help: "OIDs file"})
	fcls := parser.String("c", "cluster", &argparse.Options{Required: false, Default: fileNameCluster, Help: "Cluster file"})
	fc := parser.String("u", "creditionals", &argparse.Options{Required: false, Default: credFile, Help: "creditionals file"})
	fv := parser.String("v", "vars", &argparse.Options{Required: false, Default: fileNameVars, Help: "Vars file"})
	fi := parser.String("i", "instance", &argparse.Options{Required: false, Default: instanceFile, Help: "Instance file"})
	dbg := parser.Flag("d", "debug", &argparse.Options{Required: false, Default: false, Help: "debug"})

	err := parser.Parse(os.Args)
	if err != nil {
		fmt.Println(parser.Usage(err))
		os.Exit(0)
	}

	logfile := *lf
	fileOids = *fo
	fileCred = *fc
	fileCluster = *fcls
	fileVars = *fv
	fileInstance = *fi
	debug = *dbg
	// test := *tst

	// init logger
	file, err := os.OpenFile(logfile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0666)
	if err != nil {
		fmt.Printf("Logfile: %s Error: %+v\n", logfile, err)
		os.Exit(0)
	}

	log.SetOutput(file)

	if debug {
		log.SetFlags(log.Ldate | log.Ltime | log.Lshortfile)
	}

	go loadConfigs()   // В 1 поток
	go dbs.loadHosts() // В 1 поток

	go stat() // В 1 поток
	for i := 0; i < 1; i++ {
		go trapRawFilter()
		go trapConverter()
		go trapProxy()
	}
	go trapLost() // В 1 поток

	tl := snmp.NewTrapListener()
	defer tl.Close()

	credCond.L.Lock()
	credCond.Wait()

	tl.OnNewTrap = myTrapHandler
	tl.Params = snmp.Default
	tl.Params.Version = snmp.Version3
	tl.Params.SecurityModel = snmp.UserSecurityModel

	switch snmpv3_authtype { // Обязательно поставить AuthNoPriv и указать логин/пароль !!!!
	case "NoAuthNoPriv":
		tl.Params.MsgFlags = snmp.NoAuthNoPriv
	case "AuthNoPriv":
		tl.Params.MsgFlags = snmp.AuthNoPriv
	default:
		tl.Params.MsgFlags = snmp.AuthNoPriv
	}

	tl.Params.SecurityParameters = &snmp.UsmSecurityParameters{
		UserName:                 snmpv3_user,
		AuthoritativeEngineID:    "1234",
		AuthenticationProtocol:   snmp.SHA,
		AuthenticationPassphrase: snmpv3_password,
		PrivacyProtocol:          snmp.AES,
		PrivacyPassphrase:        "password",
		Logger:                   snmp.NewLogger(log.Default()), // (log.New(os.Stdout, "", 0)),
	}
	// tl.Params.Logger = snmp.NewLogger(log.New(os.Stdout, "", 0))

	credCond.L.Unlock()

	// fmt.Printf("tl: %+v\n\n%+v\n\n%+v\n\n\n", tl, tl.Params, tl.Params.SecurityParameters)

	log.Fatal(tl.Listen("0.0.0.0:162"))
}

func myTrapHandler(packet *snmp.SnmpPacket, addr *net.UDPAddr) {
	var trap trapRaw

	trap.time = time.Now()
	trap.addr = *addr
	trap.packet = *packet

	chTrapRaw <- trap

	stats.newRawTrap()

	// trap.packet.SecurityParameters.Log()

	if debug {
		trap.packet.SecurityParameters.Log()
		fmt.Printf("\nTRAP: %+v\n\nSecParam: %+v\n\n", trap, trap.packet.SecurityParameters)
	}
}

// func myTrapHandler(packet *snmp.SnmpPacket, addr *net.UDPAddr) {
// 	fmt.Printf("got trapdata from %s\n", addr.IP)
// 	for _, v := range packet.Variables {
// 		switch v.Type {
// 		case snmp.OctetString:
// 			b := v.Value.([]byte)
// 			fmt.Printf("Type: %v, OID: %s, string: %s\n", v.Type.String(), v.Name, b)
// 		case snmp.Integer:
// 			fmt.Printf("Type: %v, OID: %s, value: %d\n", v.Type.String(), v.Name, v.Value)
// 		case snmp.TimeTicks:
// 			a := snmp.ToBigInt(v.Value)
// 			// val := fmt.Sprintf("%d", (*a).Int64())
// 			fmt.Printf("Type: %v, value: %v\n", v.Type.String(), (*a).Int64())
// 		default:
// 			fmt.Printf("trap: %+v\n", v)
// 		}
// 	}
// 	fmt.Printf("RAW: %+v\n", packet)
// }
