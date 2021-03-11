package proxy

import (
	"fmt"
	"io"
	"net"
	"sync"

	log "github.com/sirupsen/logrus"
	"golang.org/x/sync/syncmap"
)

//TunnelClientMap device ip and tunnel key map
var TunnelClientMap = new(syncmap.Map)

// DeviceIPMap device ip and tunnel key map
var DeviceIPMap = new(syncmap.Map)

// ContextMap device ip and tunnel key map
var ContextMap = new(syncmap.Map)

// Proxy structure
type Proxy struct {
	from string
	to   string
	done chan struct{}
	log  *log.Entry
}

//NewProxy get a new proxy
func NewProxy(from, to string) *Proxy {
	return &Proxy{
		from: from,
		to:   to,
		done: make(chan struct{}),
		log: log.WithFields(log.Fields{
			"from": from,
			"to":   to,
		}),
	}
}

//Start start a new proxy
func (p *Proxy) Start() error {
	p.log.Infoln("Starting proxy")
	listener, err := net.Listen("tcp", p.from)
	if err != nil {
		return err
	}
	p.run(listener)
	return nil
}

// Stop stop proxy
func (p *Proxy) Stop() {
	p.log.Debug("Stopping proxy")
	if p.done == nil {
		return
	}
	close(p.done)
	p.done = nil
}

func (p *Proxy) run(listener net.Listener) {
	for {
		select {
		case <-p.done:
			return
		default:
			connection, err := listener.Accept()
			if err == nil {
				go p.handle(connection)
			} else {
				p.log.WithField("err", err).Errorln("Error accepting conn")
			}
		}
	}
}

func (p *Proxy) handle(connection net.Conn) {
	p.log.Debugln("Handling", connection)
	defer p.log.Debugln("Done handling", connection)
	defer connection.Close()
	deviceIP := connection.RemoteAddr().(*net.TCPAddr).IP.String()

	toAddress := p.to
	if temp, ok := DeviceIPMap.Load(deviceIP); ok {
		// fmt.Printf("\nmap found for ip '%s' and key '%v'\n", deviceIP, temp)
		if temp, ok := TunnelClientMap.Load(temp); ok {
			port := temp.(string)
			toAddress = fmt.Sprintf("0.0.0.0:%s", port)
			// fmt.Printf("\nmap found for key '%s' and client '%v'\n", toAddress, temp)
		}
	}
	log.Infof("Request coming from '%s' and going to '%s'", deviceIP, toAddress)

	remote, err := net.Dial("tcp", toAddress)
	if err != nil {
		p.log.WithField("err", err).Errorln("Error dialing remote host")
		return
	}
	defer remote.Close()
	wg := &sync.WaitGroup{}
	wg.Add(2)
	go p.copy(remote, connection, wg)
	go p.copy(connection, remote, wg)
	wg.Wait()
}

func (p *Proxy) copy(from, to net.Conn, wg *sync.WaitGroup) {
	defer wg.Done()
	select {
	case <-p.done:
		return
	default:
		if _, err := io.Copy(to, from); err != nil {
			p.log.WithField("err", err).Errorln("Error from copy")
			p.Stop()
			return
		}
	}
}

func TestFun() {
	proxy := NewProxy("0.0.0.0:5000", "0.0.0.0:3000")
	proxy.Start()
}
