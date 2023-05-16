package main

import (
	"log"
	"net"
	"strconv"
	"strings"
	"sync"
)

var (
	proxies proxiesType
)

type proxiesType struct {
	p map[string]proxyType
	sync.RWMutex
}

type proxyType struct {
	addr net.TCPAddr
	ch   chan trapToSend
}

func init() {
	proxies.p = make(map[string]proxyType)

}

func trapProxy() {
	var trap trapConverted

	for trap = range chTrapConverted {
		toSender(trap)
	}
}

func toSender(trap trapConverted) {

	var trapForSend trapToSend

	for _, i := range hosts.idsByIP(trap.addr) {
		trapForSend.time = trap.time
		trapForSend.addr = trap.addr
		trapForSend.name = trap.name
		trapForSend.lastDigit = trap.lastDigit
		trapForSend.ifIndex = trap.ifIndex
		trapForSend.packet = trap.packet
		trapForSend.proxy = hosts.proxyName(i)
		proxies.chSend(hosts.proxyName(i), trapForSend)
		// if debug {
		// 	fmt.Printf("toSender: ids %d, proxy %s, addr %s\n", i, trapForSend.proxy, trapForSend.addr.IP.String())
		// }
	}
}

func (p *proxiesType) chSend(proxyName string, trapForSend trapToSend) {
	p.RLock()
	defer p.RUnlock()

	p.p[proxyName].ch <- trapForSend
}

func (p *proxiesType) add(proxyName string) {
	if proxyName == "" {
		return // пока не знаю что с этим делать
	}

	p.RLock()
	if _, have := p.p[proxyName]; have {
		p.RUnlock()
		return // Уже есть
	}
	p.RUnlock()

	var proxy proxyType
	var err error

	ps := strings.Split(proxyName, "_")
	if len(ps) > 1 { // Есть '_'
		proxy.addr.Port, err = strconv.Atoi(ps[len(ps)-1])
		if err != nil {
			proxy.addr.Port = 10051
		}
	} else {
		proxy.addr.Port = 10051
	}

	pn := proxyName
	if len(ps) > 1 {
		pn = ""
		for i, z := range ps[:len(ps)-1] {
			if i > 0 {
				pn = pn + "_"
			}
			pn = pn + z
		}
	}

	if debug {
		log.Printf("proxyAdd: proxyName - %s, pn - %s\n", proxyName, pn)
	}

	s, err := net.LookupHost(pn)
	if err != nil {
		if len(s) == 0 {
			s = append(s, "127.0.0.1")
		} else {
			s[0] = "127.0.0.1"
		}
	}
	proxy.addr.IP = net.ParseIP(s[0])
	proxy.ch = make(chan trapToSend, chBuffer)

	p.Lock()
	p.p[proxyName] = proxy
	p.Unlock()

	go trapSender(proxy.ch)
}

func (p *proxiesType) addr(name string) net.TCPAddr {
	(*p).RLock()
	defer (*p).RUnlock()

	return proxies.p[name].addr
}

func (p *proxiesType) deleteUnused() {
	var index []string = make([]string, 0) // Список прокси на удаление

	(*p).RLock() // Здесь бы более грамотно расписать по блокировкам на чтение/запись (закрытие канала)
	for i := range (*p).p {
		if !hosts.haveProxy(i) {
			close((*p).p[i].ch)
			index = append(index, i)
		}
	}
	(*p).RUnlock()

	if len(index) > 0 {
		(*p).Lock()
		for _, i := range index {
			delete((*p).p, i)
			if debug {
				log.Printf("Proxy: remove id %s,\n", i)
			}

		}
		(*p).Unlock()
	}
}
