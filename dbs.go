package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
)

const (
	dbCheckPeriod = 60 * time.Minute // Период опроса БД с целью обновления хостов
	dbPort        = "5432"

	SQL = "select h.host as host,p.host as proxy,i.ip as ip from hosts h left join interface i using(hostid), hosts p where h.proxy_hostid = p.hostid and h.status = 0 and i.ip is not null"
)

var (
	dbs instancesZabbix
)

func init() {
	dbs.i = make(map[string]instanceZabbix)
}

func (d *instancesZabbix) loadHosts() {
	var wg sync.WaitGroup
	var ok bool

	ticker := time.NewTicker(dbCheckPeriod)
	defer ticker.Stop()

	for {
		select {
		case _, ok = <-chReloadDB: // Внеочередное перечитывание БД
			if !ok {
				return
			}

			if len(chReloadDB) > 0 { // Удаляем "дребезг"
				break
			}

			d.lastCheckSet(time.Now())

			for i := range d.i {
				wg.Add(1)
				go dbs.loadHostsFromDB(i, &wg)
			}

			wg.Wait()

			hosts.deleteTimedOut(d.lastCheck())
			proxies.deleteUnused()

		case <-ticker.C:
			d.lastCheckSet(time.Now())

			for i := range d.i {
				wg.Add(1)
				go dbs.loadHostsFromDB(i, &wg)
			}

			wg.Wait()

			hosts.deleteTimedOut(d.lastCheck())
			proxies.deleteUnused()
		}
	}
}

func (d *instancesZabbix) lastCheck() time.Time {
	d.RLock()
	defer d.RUnlock()

	return d.lastCheckDB
}

func (d *instancesZabbix) lastCheckSet(time time.Time) {
	d.Lock()
	defer d.Unlock()

	d.lastCheckDB = time
}

func (d *instancesZabbix) loadHostsFromDB(inst string, wg *sync.WaitGroup) {
	defer wg.Done()
	d.RLock()
	defer d.RUnlock()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	db, err := d.i[inst].openPSQL(ctx, inst)
	if err != nil {
		log.Printf("%+v\n", err)
		return
	}
	defer db.Close(ctx) // Закрываем соединение с БД

	row, err := db.Query(ctx, SQL)
	if err != nil {
		log.Println("ERROR:", inst, "getFromPSQL: error in db.Query() SQL:", SQL)
		return
	}
	defer row.Close()

	var host, proxy, ip string
	var addr net.UDPAddr

	for row.Next() {
		row.Scan(&host, &proxy, &ip)
		addr.IP = net.ParseIP(ip)
		hosts.add(host, addr, proxy, inst)
	}
}

// Создать connection to СУБД PSQL
func (d instanceZabbix) openPSQL(ctx context.Context, inst string) (*pgx.Conn, error) {

	var err error
	var db *pgx.Conn

	for _, i := range d.PSQL {
		db, err = pgx.Connect(ctx,
			fmt.Sprintf("host=%s user=%s password=%s dbname=%s port=%s sslmode=disable", i.DBhost, i.DBuser, i.DBpassword, i.DBname, i.DBport))
		if err == nil {
			return db, err
		}
		log.Println("WARNING:", inst, "openPSQL: Can't connect to PostgreSQL", err)
	}

	return nil, fmt.Errorf("instance: %s, err: %v", inst, err)
}

// func (d *instancesZabbix) len() int {
// 	d.RLock()
// 	defer d.RUnlock()

// 	return len(d.i)
// }
