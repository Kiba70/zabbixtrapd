package main

import (
	"strings"
)

func trapConverter() {
	var converted trapConverted

	for trap := range chTrapFiltered {
		converted.time = trap.time
		converted.addr = trap.addr
		converted.name = trap.packet[1].name
		converted.oid = trap.packet[1].oid
		converted.lastDigit = lastDigit(trap.packet[1].oid)
		converted.ifIndex = ifIndex(trap.packet[2:])
		converted.packet = fillVarName(trap.packet[2:])

		chTrapConverted <- converted
		chTrapLost <- converted
	}
}

func fillVarName(p []snmpPacket) (result []snmpPacket) { // Интересно, можно такую конструкцию делать?
	for _, i := range p {
		if varOids.name(i.oid) != "ifIndex" {
			i.name = varOids.name(i.oid)
		} else {
			i.name = ""
		}
		if i.name != "" {
			result = append(result, i)
		}
	}
	return
}

func ifIndex(p []snmpPacket) string {
	for _, i := range p {
		if varOids.name(i.oid) == "ifIndex" {
			return i.value
		}
	}
	return ""
}

func lastDigit(s string) string {
	v := strings.Split(s, ".")
	return v[len(v)-1]
}

func (v *varOidType) name(oid string) string {
	v.RLock()
	defer v.RUnlock()

	for i, z := range v.oid {
		if strings.HasPrefix(oid, i) {
			return z
		}
	}

	return ""
}
