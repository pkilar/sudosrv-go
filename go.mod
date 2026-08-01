// Filename: go.mod
module sudosrv

go 1.26.5

require (
	github.com/google/uuid v1.6.0
	google.golang.org/protobuf v1.36.11
	gopkg.in/yaml.v3 v3.0.1
)

require (
	github.com/kr/text v0.2.0 // indirect
	go.uber.org/goleak v1.3.0
)

tool google.golang.org/protobuf/cmd/protoc-gen-go
