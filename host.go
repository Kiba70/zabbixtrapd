package main

import (
	"fmt"
	"log"
	"net"
	"sync"
	"time"
)

var (
	hosts hostsType
)

type hostsType struct {
	h []hostType
	sync.RWMutex
}

type hostType struct {
	hostName  string
	hostIP    net.UDPAddr
	proxyName string
	instance  string
	lastCheck time.Time
}

func init() {
	hosts.h = make([]hostType, 0)
}

func (h *hostsType) proxyName(i int) string {
	h.RLock()
	defer h.RUnlock()

	return h.h[i].proxyName
}

func (h *hostsType) idsByIP(addr net.UDPAddr) (ids []int) {
	h.RLock()
	defer h.RUnlock()

	for i, z := range (*h).h {
		if z.hostIP.IP.Equal(addr.IP) {
			ids = append(ids, i)
		}
	}

	// if debug {
	// 	fmt.Printf("idsByIP: addr: %v, id: %+v\n", addr.IP.String(), ids)
	// }

	return ids
}

func (h *hostsType) have(ip net.UDPAddr) bool {
	h.RLock()
	defer h.RUnlock()

	// if debug {
	// 	return true // Тестирование
	// }

	for _, v := range (*h).h {
		if v.hostIP.IP.Equal(ip.IP) {
			return true
		}
	}
	return false
}

func (h *hostsType) add(hostName string, hostIP net.UDPAddr, proxyName string, instance string) {
	// Ключ по совокупности: hostName + hostIP + instance

	proxies.add(proxyName)

	h.RLock()
	for i := range (*h).h {
		if (*h).h[i].hostName == hostName && (*h).h[i].hostIP.IP.Equal(hostIP.IP) && (*h).h[i].instance == instance {
			h.RUnlock()
			h.Lock()
			(*h).h[i].proxyName = proxyName
			(*h).h[i].lastCheck = time.Now()
			h.Unlock()
			return
		}
	}
	h.RUnlock()

	// Запись не найдена = добавляем
	v := hostType{
		hostName:  hostName,
		hostIP:    hostIP,
		proxyName: proxyName,
		instance:  instance,
		lastCheck: time.Now(),
	}

	h.Lock()
	(*h).h = append((*h).h, v)
	h.Unlock()

	// if debug {
	// 	log.Printf("hostAdd: %+v\n", v)
	// }
}

func (h *hostsType) newProxy(hostName string, proxyName string, instance string) error {

	proxies.add(proxyName)
	have := false

	h.RLock()
	for i := range (*h).h {
		if (*h).h[i].hostName == hostName && (*h).h[i].instance == instance {
			h.RUnlock()
			h.Lock()
			(*h).h[i].proxyName = proxyName
			(*h).h[i].lastCheck = time.Now()
			h.Unlock()
			have = true
			h.RLock()
			// if debug {
			// fmt.Printf("Proxy change: %s, %s, %s\n", instance, hostName, proxyName)
			// }
		}
	}
	h.RUnlock()

	if !have {
		// fmt.Printf("Proxy NOT change: %s, %s, %s\n", instance, hostName, proxyName)
		return fmt.Errorf("host %s on instance %s not found", hostName, instance)
	}

	return nil
}

func (h *hostsType) deleteTimedOut(timeToDelete time.Time) {

	for i := 0; i < h.len(); i++ { // range нельзя !!!!
		if h.h[i].lastCheckBefore(timeToDelete) {
			hosts.remove(i)
			i-- // для восстановления индекса
		}
	}

}

func (h *hostType) lastCheckBefore(time time.Time) bool {
	hosts.RLock()
	defer hosts.RUnlock()

	return h.lastCheck.Before(time)
}

func (h *hostsType) remove(i int) {
	h.Lock()
	defer h.Unlock()

	if debug {
		log.Printf("Host: remove id %d, host, %s\n", i, h.h[i].hostName)
	}

	h.h[i] = h.h[len(h.h)-1]
	h.h = h.h[:len(h.h)-1]
}

func (h *hostsType) len() int {
	h.RLock()
	defer h.RUnlock()

	return len(h.h)
}

func (h *hostsType) haveProxy(proxy string) bool {
	h.RLock()
	defer h.RUnlock()

	for _, i := range (*h).h {
		if i.proxyName == proxy {
			return true
		}
	}

	return false
}

func (h *hostsType) hostNames(addr net.UDPAddr, proxy string) (result []string) {
	h.RLock()
	defer h.RUnlock()

	for _, i := range (*h).h {
		if i.proxyName == proxy && i.hostIP.IP.Equal(addr.IP) {
			result = append(result, i.hostName)
		}
	}

	return
}
