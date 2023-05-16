package main

import (
	"sync"
	"time"
)

var (
	waitQueue queueToWait
)

type queueToWait struct {
	t []trapConverted
	sync.RWMutex
}

func init() {
	waitQueue.t = make([]trapConverted, 0)
}

// Запускать в 1 поток
func trapLost() {
	var trap trapConverted
	var ok bool

	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	for {
		select {
		case trap, ok = <-chTrapLost:
			if !ok {
				return
			}

			waitQueue.checkAndPush(trap)
			waitQueue.checkAndPull()
		case <-ticker.C:
			waitQueue.checkAndPull()
		}
	}

}

func (t *queueToWait) push(unknownValue string, waitTime int, trap trapConverted) {
	t.Lock()
	defer t.Unlock()

	trap.time = time.Now().Add(time.Duration(waitTime) * time.Second)
	trap.lastDigit = unknownValue
	t.t = append(t.t, trap)
}

func (t *queueToWait) have(trap trapConverted) (int, bool) {
	t.RLock()
	defer t.RUnlock()

	for i, z := range t.t {
		if z.addr.IP.Equal(trap.addr.IP) && z.name == trap.name && z.ifIndex == trap.ifIndex {
			return i, true
		}
	}

	return 0, false
}

func (t *queueToWait) checkAndPush(trap trapConverted) {
	if i, have := t.have(trap); have {
		if unknownValue, waitTime, have := trapOids.haveWait(trap.oid); !have {
			t.remove(i)
		} else {
			t.Lock()
			t.t[i].time = time.Now().Add(time.Duration(waitTime) * time.Second) // обновляем время
			t.t[i].lastDigit = unknownValue
			t.Unlock()
		}
	} else {
		if unknownValue, waitTime, have := trapOids.haveWait(trap.oid); have {
			t.push(unknownValue, waitTime, trap)
		}
	}
}

func (t *queueToWait) checkAndPull() {

	for i := 0; i < t.len(); i++ { // range нельзя!!!
		if t.checkBefore(i) {
			t.setTimeNow(i)
			t.sendToChan(i)
			t.remove(i)
			i--
		}
	}
}

func (t *queueToWait) sendToChan(i int) {
	t.RLock()
	defer t.RUnlock()

	// if len(t.t) == 0 {
	// 	return
	// }

	chTrapConverted <- t.t[i]

	stats.newLostTrap()
}

func (t *queueToWait) setTimeNow(i int) {
	t.Lock()
	defer t.Unlock()

	// if len(t.t) == 0 {
	// 	return
	// }

	t.t[i].time = time.Now()
}

func (t *queueToWait) len() int {
	t.RLock()
	defer t.RUnlock()

	return len(t.t)
}

func (t *queueToWait) checkBefore(i int) bool {
	t.RLock()
	defer t.RUnlock()

	// if len(t.t) == 0 {
	// 	return false
	// }

	return t.t[i].time.Before(time.Now())
}

func (t *queueToWait) remove(i int) {
	t.Lock()
	defer t.Unlock()

	// if len(t.t) == 0 {
	// 	return
	// }

	(*t).t[i] = (*t).t[len(t.t)-1]
	t.t = (*t).t[:len(t.t)-1]
}

func (o *trapOidType) haveWait(oid string) (string, int, bool) {
	o.RLock()
	defer o.RUnlock()

	if o.oid[oid].unknownValue != "" {
		return o.oid[oid].unknownValue, o.oid[oid].wait, true
	}

	return "", 0, false
}
