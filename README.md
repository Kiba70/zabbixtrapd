zabbixtrapd
===========

Программа - ловушка трапов для системы мониторинга Zabbix. (аналог snmptrapd)

Принимаются трапы версий:
* **SNMPv2c**   - возможны несколько разных _Community_
* **SNMPv3**    - только *AuthNoPriv* с одним _creditionals_  

Принимаемые OID трапов ограничены списком OID прописанным в конфигурационном файле.


# Usage  

* systemctl _start_ zabbixtrapd
* systemctl _stop_ zabbixtrapd


## Параметры командной строки:  

* __--logfile__         - файл логов [-l /var/log/zabbixtrapd/zabbixtrapd.log]
* __--oids__            - список обрабатываемых OID трапов (Traps) [-o /usr/local/etc/hwdb/traps.txt]
* __--vars__            - список обрабатываемых OID переменных трапов (Vars) [-v /usr/local/etc/hwdb/vars.txt]
* __--instance__        - описание _instance_ zabbix, на которые распределяются принимаемые трапы. Формат JSON [-i /usr/local/etc/hwdb/instance.json]
* __--creditionals__    - файл с информацией _creditionals_. Формат JSON [-u /usr/local/etc/hwdb/cred.json]
* __--cluster__         - список серверов, участвующих в кластере [-c /usr/local/etc/hwdb/cluster.txt]


## Формат конфигурационных файлов

* Файл **instance.json**   
Содержит наименование инстанс,
настройки СУБД zabbix
```json
{
    "zabbix_dc": {
        "config_psql": [
            {
                "dbname": "database of zabbix_1",
                "dbhost": "server1",
                "dbport": "5432"
            },
            {
                "dbname": "database of zabbix_1",
                "dbhost": "server2",
                "dbport": "5432"
            }
        ]
    },
    "zabbix_mc": {
        "config_psql": [
            {
                "dbname": "database of zabbix_2",
                "dbhost": "server1",
                "dbport": "5432"
            },
            {
                "dbname": "database of zabbix_2",
                "dbhost": "server2",
                "dbport": "5432"
            }
        ]
    }
}
```
* Файл **cred.json**   
Содержит аккаунты доступа к СУБД,
SNMPv3 пользователя,
SNMPv2c community,
ссылки на файлы сертификатов сервера и клиента
```json
{
    "psql_user": "user of psql",
    "psql_password": "password of psql",
    "cert_root": "/etc/pki/tls/cert.pem",
    "cert_pem": "/etc/pki/nginx/pem/server1.sigma.server.pem",
    "cert_key": "/etc/pki/nginx/keys/server1.sigma.server.key",
    "snmpv3_user": "SNMPv3 user",
    "snmpv3_password": "SNMPv3 password",
    "snmpv3_authtype": "AuthNoPriv",
    "community": {
        "SNMPv2c community1": {},
        "SNMPv2c community2": {},
        "SNMPv2c community3": {}
    }
}
```
* Файл **traps.txt**
