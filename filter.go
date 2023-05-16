package main

import (
	"fmt"
	"math/rand"
	"net"
	"sync"
	"time"

	snmp "github.com/gosnmp/gosnmp"
)

var (
	community communityType
	r         *rand.Rand
)

type communityType struct {
	c map[string]struct{}

	sync.RWMutex
}

func init() {
	community.c = make(map[string]struct{})
	r = rand.New(rand.NewSource(time.Now().UnixNano()))
}

// Запускаем в 1 поток
func trapRawFilter() {
	var filteredTrap trapType

	for trap := range chTrapRaw {
		// if debug {
		// 	fmt.Printf("TrapRawFilter: Before\ntime %+v\naddr %+v\npacket %+v\n\n", trap.time, trap.addr.IP, trap.packet)
		// }

		if trap.addr.IP.IsLoopback() && trap.packet.Version == snmp.Version3 { // Тестовый трап
			trap.addr = randomHostSource()
			// fmt.Println("Test trap:", trap.addr.IP.IsLoopback(), trap.addr.IP.String())
			stats.newFilteredTrap(0)
		}

		if !cluster.master() || !checkIP(trap.addr) || !checkOid(trap.packet.Variables[1]) || !hosts.have(trap.addr) || !community.check(trap.packet) { // Проверяем на валидный IP и OID + имеется ли host в zabbix + community
			continue
		}

		// fmt.Printf("\nTRAP: %+v\n\nSecParam: %+v\n\nDescription: %+v\n\n", trap, trap.packet.SecurityParameters, trap.packet.SecurityParameters.Description())

		filteredTrap.time = trap.time
		filteredTrap.addr = trap.addr
		filteredTrap.packet = convertPacket(trap.packet.Variables)

		chTrapFiltered <- filteredTrap

		if trap.packet.Version == snmp.Version3 {
			stats.newFilteredTrap(3)
		} else {
			stats.newFilteredTrap(2)
		}
	}
}

func convertPacket(packet []snmp.SnmpPDU) []snmpPacket {
	var p snmpPacket

	result := make([]snmpPacket, 0, len(packet)+1)

	for _, v := range packet {
		switch v.Type {
		case snmp.OctetString:
			p.value = string(v.Value.([]byte))
		// case snmp.Integer:
		// 	p.value = fmt.Sprintf("%d", v.Value)
		default:
			p.value = fmt.Sprintf("%v", v.Value)
		}
		p.oid = v.Name
		if p.oid == ".1.3.6.1.6.3.1.1.4.1.0" {
			p.oid, p.value = p.value, p.oid // Меняем OID на значение самого трапа (стандартно индекс в слайсе [1])
		}
		trapOids.RLock()
		p.name = trapOids.oid[p.oid].name
		trapOids.RUnlock()
		p.asn1BER = v.Type
		result = append(result, p)
	}

	return result
}

func checkIP(addr net.UDPAddr) bool {
	return true
}

func checkOid(packet snmp.SnmpPDU) bool {
	trapOids.RLock()
	defer trapOids.RUnlock()
	_, have := trapOids.oid[packet.Value.(string)]
	// have = true // For DEBUG !!!
	return have
}

func (c *communityType) check(packet snmp.SnmpPacket) bool {
	c.RLock()
	defer c.RUnlock()

	if packet.Version == snmp.Version1 || packet.Version == snmp.Version2c {
		if len(community.c) == 0 {
			return true // Нет списка community на проверку - разрешаем всё
		}
		_, have := community.c[packet.Community]
		return have
	}

	return true
}

func randomHostSource() net.UDPAddr {
	hosts.RLock()
	defer hosts.RUnlock()

	return hosts.h[r.Intn(hosts.len())].hostIP
}
