// Filename: go.mod
module sudosrv

go 1.27

require (
	go.uber.org/goleak v1.3.0
	google.golang.org/protobuf v1.36.12
	gopkg.in/yaml.v3 v3.0.1
)

require github.com/kr/text v0.2.0 // indirect

tool google.golang.org/protobuf/cmd/protoc-gen-go
