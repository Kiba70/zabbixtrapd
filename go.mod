module zabbixtrapd

go 1.17

require (
	github.com/akamensky/argparse v1.3.1
	github.com/gorilla/mux v1.8.0
	github.com/gosnmp/gosnmp v1.35.0
	github.com/jackc/pgx/v5 v5.3.1
	github.com/rs/cors v1.8.2
)

require (
	github.com/jackc/pgpassfile v1.0.0 // indirect
	github.com/jackc/pgservicefile v0.0.0-20221227161230-091c0ba34f0a // indirect
	golang.org/x/crypto v0.6.0 // indirect
	golang.org/x/text v0.7.0 // indirect
)

replace github.com/gosnmp/gosnmp => ../gosnmp
