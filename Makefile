
build:
	go build -o kubectl-psachecker ./cmd/main.go

install: build
	cp kubectl-psachecker ${GOBIN}

uninstall:
	rm ${GOBIN}/kubectl-psachecker
