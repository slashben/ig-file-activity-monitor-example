package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf/rlimit"
	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"

	tracerexec "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/exec/tracer"
	tracerexectype "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/exec/types"

	traceropen "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/open/tracer"
	traceropentype "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/open/types"

	tracertcp "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/tcp/tracer"
	tracertcptype "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/tcp/types"

	tracersyscall "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/advise/seccomp/tracer"

	tracercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/tracer-collection"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

// Global constants
const execTraceName = "trace_exec"
const openTraceName = "trace_open"
const tcpTraceName = "trace_tcp"
const syscallTraceName = "trace_syscall"

var traceSystemCall *tracersyscall.Tracer

// Global variables
var NodeName string
var containerMap = make(map[ContainerKey]*os.File)

// Global types
type ContainerKey struct {
	Namespace     string
	Podname       string
	ContainerName string
}

func checkKubernetesConnection() error {
	// Check if the Kubernetes cluster is reachable
	// Load the Kubernetes configuration from the default location
	config, err := clientcmd.BuildConfigFromFlags("", clientcmd.RecommendedHomeFile)
	if err != nil {
		config, err = rest.InClusterConfig()
		if err != nil {
			return err
		}
	}

	// Create a Kubernetes client
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		log.Printf("Failed to create Kubernetes client: %v\n", err)
		return err
	}

	// Send a request to the API server to check if it's reachable
	_, err = clientset.CoreV1().Pods("default").List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		log.Printf("Failed to communicate with Kubernetes API server: %v\n", err)
		return err
	}

	return nil
}

func serviceInitNChecks() error {
	// Raise the rlimit for memlock to the maximum allowed (eBPF needs it)
	if err := rlimit.RemoveMemlock(); err != nil {
		return err
	}

	// Check Kubernetes cluster connection
	if err := checkKubernetesConnection(); err != nil {
		return err
	}

	// Get Node name from environment variable
	if nodeName := os.Getenv("NODE_NAME"); nodeName == "" {
		return fmt.Errorf("NODE_NAME environment variable not set")
	} else {
		NodeName = nodeName
	}

	return nil
}

func main() {
	// Define --all flag
	allPtr := flag.Bool("all", false, "Trace all containers")
	// Use flags package to parse command line arguments
	flag.Parse()

	// Initialize the service
	if err := serviceInitNChecks(); err != nil {
		log.Fatalf("Failed to initialize service: %v\n", err)
	}

	// Use container collection to get notified for new containers
	containerCollection := &containercollection.ContainerCollection{}

	// Create a tracer collection instance
	tracerCollection, err := tracercollection.NewTracerCollection(containerCollection)
	if err != nil {
		log.Printf("failed to create trace-collection: %s\n", err)
		return
	}
	defer tracerCollection.Close()

	containerEventFuncs := []containercollection.FuncNotify{callback}

	// Load the Kubernetes configuration from the default location (if it is not there, it will assume in-cluster)
	k8sConfig, _ := clientcmd.BuildConfigFromFlags("", clientcmd.RecommendedHomeFile)

	// Define the different options for the container collection instance
	opts := []containercollection.ContainerCollectionOption{
		containercollection.WithTracerCollection(tracerCollection),

		// Get containers created with runc
		containercollection.WithRuncFanotify(),

		// Get containers created with docker
		containercollection.WithCgroupEnrichment(),

		// Enrich events with Linux namespaces information, it is needed for per container filtering
		containercollection.WithLinuxNamespaceEnrichment(),

		// Enrich those containers with data from the Kubernetes API
		containercollection.WithKubernetesEnrichment(NodeName, k8sConfig),

		// Get Notifications from the container collection
		containercollection.WithPubSub(containerEventFuncs...),
	}

	// Initialize the container collection
	if err := containerCollection.Initialize(opts...); err != nil {
		log.Printf("failed to initialize container collection: %s\n", err)
		return
	}
	defer containerCollection.Close()

	// Define a callback to handle exec events
	execEventCallback := func(event *tracerexectype.Event) {
		if event.Retval > -1 {
			procImageName := event.Comm
			if len(event.Args) > 0 {
				procImageName = event.Args[0]
			}
			reportFileAccessInPod(event.Namespace, event.Pod, event.Container, procImageName, "exec")
		}
	}

	// Define a callback to handle open events
	openEventCallback := func(event *traceropentype.Event) {
		if event.Ret > -1 {
			reportFileAccessInPod(event.Namespace, event.Pod, event.Container, event.Path, "open")
		}
	}

	// Define a callback to handle tcp events
	tcpEventCallback := func(event *tracertcptype.Event) {
		log.Printf("TCP event: %v\n", event)
		reportTCPActivityInPod(event.Namespace, event.Pod, event.Container, event.Operation, event.Saddr, event.Daddr)
	}

	var containerSelector containercollection.ContainerSelector
	if !*allPtr {
		// Selecting the container to trace, we are choosing all Pod containers with the label "ig-trace=file-access"
		containerSelector = containercollection.ContainerSelector{
			Labels: map[string]string{
				"ig-trace": "file-access",
			},
		}
	} else {
		// Selecting all containers
		containerSelector = containercollection.ContainerSelector{}
	}

	// Setting up all the tracers

	// Add exec tracer
	if err := tracerCollection.AddTracer(execTraceName, containerSelector); err != nil {
		log.Printf("error adding tracer: %s\n", err)
		return
	}
	defer tracerCollection.RemoveTracer(execTraceName)

	// Add open tracer
	if err := tracerCollection.AddTracer(openTraceName, containerSelector); err != nil {
		log.Printf("error adding tracer: %s\n", err)
		return
	}
	defer tracerCollection.RemoveTracer(openTraceName)

	// Add tcp tracer
	if err := tracerCollection.AddTracer(tcpTraceName, containerSelector); err != nil {
		log.Printf("error adding tracer: %s\n", err)
		return
	}
	defer tracerCollection.RemoveTracer(tcpTraceName)

	// Add syscall tracer
	if err := tracerCollection.AddTracer(syscallTraceName, containerSelector); err != nil {
		log.Printf("error adding tracer: %s\n", err)
		return
	}

	// Get mount namespace map to filter by containers
	execMountnsmap, err := tracerCollection.TracerMountNsMap(execTraceName)
	if err != nil {
		fmt.Printf("failed to get execMountnsmap: %s\n", err)
		return
	}

	// Get mount namespace map to filter by containers
	openMountnsmap, err := tracerCollection.TracerMountNsMap(openTraceName)
	if err != nil {
		fmt.Printf("failed to get openMountnsmap: %s\n", err)
		return
	}

	// Get mount namespace map to filter by containers
	tcpMountnsmap, err := tracerCollection.TracerMountNsMap(tcpTraceName)
	if err != nil {
		fmt.Printf("failed to get tcpMountnsmap: %s\n", err)
		return
	}

	// Create the exec tracer
	tracerExec, err := tracerexec.NewTracer(&tracerexec.Config{MountnsMap: execMountnsmap}, containerCollection, execEventCallback)
	if err != nil {
		fmt.Printf("error creating tracer: %s\n", err)
		return
	}
	defer tracerExec.Stop()

	// Create the open tracer
	tracerOpen, err := traceropen.NewTracer(&traceropen.Config{MountnsMap: openMountnsmap}, containerCollection, openEventCallback)
	if err != nil {
		fmt.Printf("error creating tracer: %s\n", err)
		return
	}
	defer tracerOpen.Stop()

	// Create the tcp tracer
	tracerTCP, err := tracertcp.NewTracer(&tracertcp.Config{MountnsMap: tcpMountnsmap}, containerCollection, tcpEventCallback)
	if err != nil {
		fmt.Printf("error creating tracer: %s\n", err)
		return
	}
	defer tracerTCP.Stop()

	// Create the syscall tracer
	tracerSyscall, err := tracersyscall.NewTracer()
	if err != nil {
		fmt.Printf("error creating tracer: %s\n", err)
		return
	}
	traceSystemCall = tracerSyscall
	defer tracerSyscall.Close()

	// Wait for shutdown signal
	shutdown := make(chan os.Signal, 1)
	signal.Notify(shutdown, os.Interrupt, syscall.SIGTERM)
	<-shutdown
	log.Println("Shutting down...")

	// Exit with success
	os.Exit(0)
}

func callback(notif containercollection.PubSubEvent) {
	if notif.Type == containercollection.EventTypeAddContainer {
		log.Printf("Container in Pod %s added: %v pid %d\n", notif.Container.Podname, notif.Container.ID, notif.Container.Pid)
		// Create a file to store events for the container
		f, err := os.Create(fmt.Sprintf("/tmp/%s-%s-%s.log", notif.Container.Namespace, notif.Container.Podname, notif.Container.Name))
		if err != nil {
			log.Printf("Error creating file: %v\n", err)
			return
		}
		containerMap[ContainerKey{notif.Container.Namespace, notif.Container.Podname, notif.Container.Name}] = f
	} else if notif.Type == containercollection.EventTypeRemoveContainer {
		log.Printf("Container removed: %v pid %d\n", notif.Container.ID, notif.Container.Pid)

		// Close the file
		f, ok := containerMap[ContainerKey{notif.Container.Namespace, notif.Container.Podname, notif.Container.Name}]
		if !ok {
			log.Printf("Container not found: %v pid %d\n", notif.Container.ID, notif.Container.Pid)
			return
		}

		syscalls, err := traceSystemCall.Peek(notif.Container.Mntns)
		if err != nil {
			log.Printf("Error peeking syscalls: %v\n", err)
		} else {
			for _, syscall := range syscalls {
				f.WriteString(fmt.Sprintf("syscall: %s\n", syscall))
			}
		}

		f.Close()
	}
}

func reportFileAccessInPod(namespaceName string, podName string, containerName string, file string, action string) {
	// Not printing so we don't flood the logs and CPU
	//log.Printf("File %s was accessed in Pod %s/%s container %s\n", file, namespaceName, podName, containerName)

	// Write the event to the file
	f, ok := containerMap[ContainerKey{namespaceName, podName, containerName}]
	if !ok {
		log.Printf("Container not found: %s/%s/%s\n", namespaceName, podName, containerName)
		return
	}
	f.WriteString(fmt.Sprintf("%s: %s\n", action, file))
}

func reportTCPActivityInPod(namespaceName string, podName string, containerName string, operation string, src string, dst string) {
	// Write the event to the file
	f, ok := containerMap[ContainerKey{namespaceName, podName, containerName}]
	if !ok {
		log.Printf("Container not found: %s/%s/%s\n", namespaceName, podName, containerName)
		return
	}
	f.WriteString(fmt.Sprintf("%s: %s->%s\n", operation, src, dst))
}

func reportSyscallInPod(namespaceName string, podName string, containerName string, syscall string) {
	// Write the event to the file
	f, ok := containerMap[ContainerKey{namespaceName, podName, containerName}]
	if !ok {
		log.Printf("Container not found: %s/%s/%s\n", namespaceName, podName, containerName)
		return
	}
	f.WriteString(fmt.Sprintf("syscall: %s\n", syscall))
}
