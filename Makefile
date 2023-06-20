
wlftracer: wl-file-activity-tracer.go
	CGO_ENABLED=0 go build -tags osusergo,netgo -ldflags="-extldflags=-static" -o wlftracer wl-file-activity-tracer.go

install: wlftracer
	./scripts/install-in-pod.sh wlftracer

clean:
	rm -f wlftracer

all: wlftracer

.PHONY: clean all install