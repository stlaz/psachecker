
build:
	go build -o kubectl-psachecker ./cmd/main.go

install:
	cp kubectl-psachecker ${GOBIN}

uninstall:
	rm ${GOBIN}/kubectl-psachecker
