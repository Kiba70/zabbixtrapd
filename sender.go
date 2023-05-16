package main

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"regexp"
	"strconv"
	"time"
)

var (
	header = []byte("ZBXD\x01")
)

// Single Zabbix data item.
type DataItem struct {
	Hostname    string `json:"host"`
	Key         string `json:"key"`
	Timestamp   int64  `json:"clock,omitempty"` // UNIX timestamp, 0 is ignored
	Nanoseconds int    `json:"ns,omitempty"`
	Value       string `json:"value"` // Use ConvertValue() to fill
}

type DataItems []DataItem

// Unexpected header of Zabbix's response.
var ErrBadHeader = errors.New("bad header")

type Response struct {
	Response  string  `json:"response"` // "success" on success
	Info      string  `json:"info"`     // String like "Processed 2 Failed 1 Total 3 Seconds spent 0.000034"
	Processed int     // Filled by parsing Info
	Failed    int     // Filled by parsing Info
	Spent     float64 // Filled by parsing Info
}

var infoRE = regexp.MustCompile(`processed: (\d+); failed: (\d+); total: .*; seconds spent: (\d+\.\d+)`)

func trapSender(ch <-chan trapToSend) {
	var di DataItems = make(DataItems, 0)
	var diNew DataItems = make(DataItems, 0)
	var trap trapToSend
	var res *Response
	var err error
	var ok bool

	di = nil

	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	// if debug {
	// 	log.Printf("Started sender channel %+v\n", ch)
	// }

	for {
		select { // К сожалению нет возможности указать 2 условия на одни и те же действия - просто скопировал
		case trap, ok = <-ch:
			if !ok {
				return
			}

			diNew = makeDataItems(trap)
			if len(di)+len(diNew) > 128 {
				res, err = send(proxies.addr(trap.proxy), di)
				di = nil

				if debug {
					fmt.Printf("Send response: %+v\nErr: %+v\n", res, err)
				}
			}
			di = append(di, diNew...)

			if debug {
				fmt.Printf("\nAdd trap\nproxy %+v\ntime %+v\naddr %+v\ntrapName %+v\nlastDigit %v\nifIndex %v",
					trap.proxy, trap.time, trap.addr.IP, trap.name, trap.lastDigit, trap.ifIndex)
				for _, p := range trap.packet {
					// fmt.Printf("var oid %+v name %+v value %+v\n", p.oid, p.name, p.value)
					if p.name == "ifDesc" {
						fmt.Printf(" %+v\n", p.value)
					}
				}
			}

		case <-ticker.C:
			// if debug {
			// 	log.Println("Ticker", trap.proxy)
			// }
			if di != nil && trap.proxy != "" {
				res, err = send(proxies.addr(trap.proxy), di)

				if debug {
					fmt.Printf("\nTime out for send!!!\n")
					for _, d := range di {
						fmt.Printf("proxy %+v\ntime %+v\naddr %+v\ntrapName %+v\nValue %+v\n",
							trap.proxy, d.Timestamp, d.Hostname, d.Key, d.Value)
					}
					fmt.Printf("Send response: %+v\nErr: %+v\n", res, err)
				}

				if err == nil {
					di = nil
				}

				// if debug {
				// fmt.Printf("\nTime out for send!!!\nproxy %+v\ntime %+v\naddr %+v\ntrapName %+v\nlastDigit %v\nifIndex %v",
				// 	trap.proxy, trap.time, trap.addr.IP, trap.trapName, trap.trapLastDigit, trap.ifIndex)
				// for _, p := range trap.packet {
				// 	// fmt.Printf("var oid %+v name %+v value %+v\n", p.oid, p.name, p.value)
				// 	if p.name == "ifDesc" {
				// 		fmt.Printf(" %+v\n", p.value)
				// 	}
				// }
				// fmt.Printf("Send response: %+v\nErr: %+v\n", res, err)
				// }
			}
		}
	}
}

func makeValues(trap trapToSend) string {
	var kv map[string]string = make(map[string]string)

	kv["lastdigit"] = trap.lastDigit
	for _, i := range trap.packet {
		kv[i.name] = i.value
	}

	b, err := json.Marshal(kv)
	if err != nil {
		log.Printf("JSON Error: %+v\nTried encoding: %+v\n", err, kv)
		return ""
	}

	return string(b)
}

func makeDataItems(trap trapToSend) DataItems {
	var d DataItem

	di := make(DataItems, 0) // Потом увеличить в зависимости от количества сообщений. Пока 1

	for _, hostname := range hosts.hostNames(trap.addr, trap.proxy) {
		d.Hostname = hostname
		if trap.ifIndex != "" {
			d.Key = trap.name + "[" + trap.ifIndex + "]"
		} else {
			d.Key = trap.name
		}
		d.Timestamp = trap.time.Unix()
		d.Nanoseconds = trap.time.Nanosecond()
		d.Value = makeValues(trap)
		di = append(di, d)
	}

	// for k, v := range kv {
	// 	di[i] = DataItem{hostname, k, 0, ConvertValue(v)}
	// 	i++
	// }

	return di
}

func (di DataItems) marshal() (b []byte, err error) {
	d, err := json.Marshal(di)
	if err == nil {
		// the order of fields in this "JSON" is important - request should be before data
		t := time.Now()
		nowt := fmt.Sprint(t.Unix())
		nows := fmt.Sprint(t.Nanosecond())
		datalen := uint64(len(d) + len(nowt) + len(nows) + 48) // 32 + d + 9 + nowt + 6 + nows + 1
		b = make([]byte, 0, datalen+13)                        // datalen + 5 + 8
		buf := bytes.NewBuffer(b)
		buf.Write(header)                                     // 5
		err = binary.Write(buf, binary.LittleEndian, datalen) // 8
		buf.WriteString(`{"request":"sender data","data":`)   // 32
		buf.Write(d)                                          // d
		buf.WriteString(`,"clock":`)                          // 9
		buf.WriteString(nowt)                                 // now
		buf.WriteString(`,"ns":`)                             // 6
		buf.WriteString(nows)                                 // nanoseconds
		buf.WriteByte('}')                                    // 1
		b = buf.Bytes()
	}
	return
}

func send(addr net.TCPAddr, di DataItems) (res *Response, err error) {

	b, err := di.marshal()
	if err != nil {
		return
	}

	// Zabbix doesn't support persistent connections, so open/close it every time.
	conn, err := net.DialTCP(addr.Network(), nil, &addr)
	if err != nil {
		return
	}
	defer conn.Close()

	_, err = conn.Write(b)
	if err != nil {
		return
	}

	buf := make([]byte, 8)
	_, err = io.ReadFull(conn, buf[:5])
	if err != nil {
		return
	}
	if !bytes.Equal(buf[:5], header) {
		err = ErrBadHeader
		return
	}

	_, err = io.ReadFull(conn, buf)
	if err != nil {
		return
	}
	var datalen uint64
	err = binary.Read(bytes.NewBuffer(buf), binary.LittleEndian, &datalen)
	if err != nil {
		err = ErrBadHeader
		return
	}

	buf = make([]byte, datalen)
	_, err = io.ReadFull(conn, buf)
	if err != nil {
		return
	}

	res = new(Response)
	err = json.Unmarshal(buf, res)
	if err == nil {
		m := infoRE.FindStringSubmatch(res.Info)
		if len(m) == 4 {
			p, _ := strconv.Atoi(m[1])
			f, _ := strconv.Atoi(m[2])
			s, _ := strconv.ParseFloat(m[3], 64)
			res.Processed = p
			stats.newDeliveredTrap(p)
			res.Failed = f
			stats.newUndeliveredTrap(f)
			res.Spent = s
		}
	}

	return
}

// Converts value to format accepted by Zabbix server.
// It uses "%.6f" format for floats,
// and fmt.Sprint() (which will try String() and Error() methods) for other types.
// Keep in mind that Zabbix doesn't support negative integers, use floats instead.
// func ConvertValue(i interface{}) string {
// 	switch v := i.(type) {
// 	case float32:
// 		return fmt.Sprintf("%.6f", v)
// 	case float64:
// 		return fmt.Sprintf("%.6f", v)
// 	default:
// 		return fmt.Sprint(v)
// 	}
// 	// panic("not reached")
// }
