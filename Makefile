
wlftracer: wl-file-activity-tracer.go go.mod
	go build -o wlftracer wl-file-activity-tracer.go
	# CGO_ENABLED=0 go build -tags osusergo,netgo -ldflags="-extldflags=-static" -o wlftracer wl-file-activity-tracer.go

install: wlftracer
	./scripts/install-in-pod.sh wlftracer

open-shell:
	./scripts/open-shell-in-pod.sh

deploy-dev-pod:
	kubectl apply -f dev/devpod.yaml

clean:
	rm -f wlftracer

all: wlftracer

.PHONY: clean all install deploy-dev-pod