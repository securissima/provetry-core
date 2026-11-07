module example.com/svc

go 1.22

require (
	github.com/gin-gonic/gin v1.9.0
	golang.org/x/net v0.17.0 // indirect
)

require github.com/old/pkg v1.0.0

replace github.com/old/pkg => github.com/new/pkg v1.2.0
