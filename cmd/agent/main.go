package main

import (
	"bkedr/pkg/agent"
	"bkedr/pkg/rpc"
	"flag"
	"fmt"
	"log"
	"net"

	"github.com/kardianos/service"
	"google.golang.org/grpc"
)

// Logger writes to the system log.
var logger service.Logger

// Program structures.
// Define Start and Stop methods.
type program struct {
	exit chan struct{}
}

// This function defind start method
func (p *program) Start(s service.Service) error {

	// Interactive returns false if running under
	// the windows OS service manager and true otherwise.
	if service.Interactive() {
		logger.Info("bkedr agent runs in terminal.")
	} else {
		logger.Info("bkedr agent runs under service manager.")
	}
	p.exit = make(chan struct{})

	// Start should not block. Do the actual work async.
	go p.run()
	return nil
}

// Execute kind of main function for the program
func (p *program) run() error {

	logger.Infof("bkedr agent is running %v.", service.Platform())

	// Connect to EDR server
	if err := agent.RunSocketDial(); err != nil {
		log.Fatal(err)
	}

	// Create new gRPC server and initialize a gRPC service object
	grpcServer := grpc.NewServer()

	// Register the service with gRPC Server (of the gRPC plugin)
	agentGRPCSvc := agent.NewAgentGRPCService()
	rpc.RegisterManagerServer(grpcServer, agentGRPCSvc)

	// Provide gRPC service using host and port from config file
	agentAddress := agent.AgentHost + ":" + agent.AgentPort
	lis, err := net.Listen("tcp", agentAddress)
	if err != nil {
		fmt.Println("success")
		log.Fatal(err)
	}

	// Serve accepts incoming connections on the listener lis, creating a new
	// ServerTransport and service goroutine for each
	grpcServer.Serve(lis)
	return nil
}

// this function defind stop method
func (p *program) Stop(s service.Service) error {
	// Any work in Stop should be quick, usually a few seconds at most.
	logger.Info("bkedr agent is stop")
	close(p.exit)
	return nil
}

//		 Service setup.
//	  Define service config.
//	  Create the service.
//	  Setup the logger.
//	  Handle service controls (optional).
//	  Run the service.
func main() {
	svcFlag := flag.String("service", "", "Control the system service.")
	flag.Parse()

	options := make(service.KeyValue)
	options["Restart"] = "on-success"
	options["SuccessExitStatus"] = "1 2 8 SIGKILL"
	svcConfig := &service.Config{
		Name:         "bkedragent",
		DisplayName:  "Bkedr Agent",
		Description:  "The EDR agent for Windows.",
		Dependencies: []string{},
		Option:       options,
	}

	prg := &program{}
	s, err := service.New(prg, svcConfig)
	if err != nil {
		log.Fatal(err)
	}
	errs := make(chan error, 5)
	logger, err = s.Logger(errs)
	if err != nil {
		log.Fatal(err)
	}

	go func() {
		for {
			err := <-errs
			if err != nil {
				log.Print(err)
			}
		}
	}()

	if len(*svcFlag) != 0 {
		err := service.Control(s, *svcFlag)
		if err != nil {
			log.Printf("Valid actions: %q\n", service.ControlAction)
			log.Fatal(err)
		}

		return
	}

	err = s.Run()
	if err != nil {
		logger.Error(err)
	}
}
