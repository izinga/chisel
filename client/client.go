package chclient

import (
	"context"
	"crypto/md5"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/denisbrodbeck/machineid"
	"github.com/go-resty/resty/v2"
	"github.com/gorilla/websocket"
	chshare "github.com/jpillora/chisel/share"
	"github.com/jpillora/chisel/share/ccrypto"
	"github.com/jpillora/chisel/share/cio"
	"github.com/jpillora/chisel/share/cnet"
	"github.com/jpillora/chisel/share/settings"
	"github.com/jpillora/chisel/share/tunnel"
	"github.com/sirupsen/logrus"

	"golang.org/x/crypto/ssh"
	"golang.org/x/net/proxy"
	"golang.org/x/sync/errgroup"
)

//Config represents a client configuration
type Config struct {
	Fingerprint      string
	Auth             string
	KeepAlive        time.Duration
	MaxRetryCount    int
	MaxRetryInterval time.Duration
	Server           string
	Proxy            string
	NerveServer      string
	AccessKey        string
	MachineID        string
	TunnelKey        string
	Remotes          []string
	Headers          http.Header
	TLS              TLSConfig
	DialContext      func(ctx context.Context, network, addr string) (net.Conn, error)
}

// ConfigFromNerve config from nerve
type ConfigFromNerve struct {
	Name          string `json:"name" bson:"name" validate:"required"`
	Desc          string `json:"desc" bson:"desc"`
	IP            string `json:"ip" bson:"ip" validate:"required"`
	Port          int    `json:"port" bson:"port" validate:"required"`
	MachineID     string `json:"machineID" bson:"machineID" validate:"required"`
	ServerAddress string `json:"serverAddress" bson:"serverAddress"`
	ServerID      string `json:"serverID" bson:"serverID" validate:"required"`
	Key           string `json:"key" bson:"key" validate:"required"`
}

//TLSConfig for a Client
type TLSConfig struct {
	SkipVerify bool
	CA         string
	Cert       string
	Key        string
}

//Client represents a client instance
type Client struct {
	*cio.Logger
	config    *Config
	computed  settings.Config
	sshConfig *ssh.ClientConfig
	tlsConfig *tls.Config
	proxyURL  *url.URL
	server    string
	connCount cnet.ConnCount
	stop      func()
	eg        *errgroup.Group
	tunnel    *tunnel.Tunnel
}

var restyClient *resty.Client

func init() {
	restyClient = resty.New()
	restyClient.SetHeader("Accept", "application/json")
	restyClient.SetTimeout(5 * time.Second)
}

//NewClient creates a new client instance
func NewClient(c *Config) (*Client, error) {
	//apply default scheme
	if !strings.HasPrefix(c.Server, "http") {
		c.Server = "http://" + c.Server
	}
	if c.MaxRetryInterval < time.Second {
		c.MaxRetryInterval = 5 * time.Minute
	}
	u, err := url.Parse(c.Server)
	if err != nil {
		return nil, err
	}
	//swap to websockets scheme
	u.Scheme = strings.Replace(u.Scheme, "http", "ws", 1)
	//apply default port
	if !regexp.MustCompile(`:\d+$`).MatchString(u.Host) {
		if u.Scheme == "wss" {
			u.Host = u.Host + ":443"
		} else {
			u.Host = u.Host + ":80"
		}
	}
	hasReverse := false
	hasSocks := false
	hasStdio := false
	client := &Client{
		Logger: cio.NewLogger("client"),
		config: c,
		computed: settings.Config{
			Version: chshare.BuildVersion,
		},
		server:    u.String(),
		tlsConfig: nil,
	}
	//set default log level
	client.Logger.Info = true
	//configure tls
	if u.Scheme == "wss" {
		tc := &tls.Config{}
		//certificate verification config
		if c.TLS.SkipVerify {
			client.Infof("TLS verification disabled")
			tc.InsecureSkipVerify = true
		} else if c.TLS.CA != "" {
			rootCAs := x509.NewCertPool()
			if b, err := ioutil.ReadFile(c.TLS.CA); err != nil {
				return nil, fmt.Errorf("Failed to load file: %s", c.TLS.CA)
			} else if ok := rootCAs.AppendCertsFromPEM(b); !ok {
				return nil, fmt.Errorf("Failed to decode PEM: %s", c.TLS.CA)
			} else {
				client.Infof("TLS verification using CA %s", c.TLS.CA)
				tc.RootCAs = rootCAs
			}
		}
		//provide client cert and key pair for mtls
		if c.TLS.Cert != "" && c.TLS.Key != "" {
			c, err := tls.LoadX509KeyPair(c.TLS.Cert, c.TLS.Key)
			if err != nil {
				return nil, fmt.Errorf("Error loading client cert and key pair: %v", err)
			}
			tc.Certificates = []tls.Certificate{c}
		} else if c.TLS.Cert != "" || c.TLS.Key != "" {
			return nil, fmt.Errorf("Please specify client BOTH cert and key")
		}
		client.tlsConfig = tc
	}
	//validate remotes
	for _, s := range c.Remotes {
		r, err := settings.DecodeRemote(s)
		if err != nil {
			return nil, fmt.Errorf("Failed to decode remote '%s': %s", s, err)
		}
		if r.Socks {
			hasSocks = true
		}
		if r.Reverse {
			hasReverse = true
		}
		if r.Stdio {
			if hasStdio {
				return nil, errors.New("Only one stdio is allowed")
			}
			hasStdio = true
		}
		//confirm non-reverse tunnel is available
		if !r.Reverse && !r.Stdio && !r.CanListen() {
			return nil, fmt.Errorf("Client cannot listen on %s", r.String())
		}
		client.computed.Remotes = append(client.computed.Remotes, r)
	}
	client.computed.MachineID = client.config.MachineID
	client.computed.TunnelKey = client.config.TunnelKey
	//outbound proxy
	if p := c.Proxy; p != "" {
		client.proxyURL, err = url.Parse(p)
		if err != nil {
			return nil, fmt.Errorf("Invalid proxy URL (%s)", err)
		}
	}

	//ssh auth and config
	user, pass := settings.ParseAuth(c.Auth)
	client.sshConfig = &ssh.ClientConfig{
		User:            user,
		Auth:            []ssh.AuthMethod{ssh.Password(pass)},
		ClientVersion:   "SSH-" + chshare.ProtocolVersion + "-client",
		HostKeyCallback: client.verifyServer,
		Timeout:         settings.EnvDuration("SSH_TIMEOUT", 30*time.Second),
	}
	//prepare client tunnel
	client.tunnel = tunnel.New(tunnel.Config{
		Logger:   client.Logger,
		Inbound:  true, //client always accepts inbound
		Outbound: hasReverse,
		Socks:    hasReverse && hasSocks,
	})
	return client, nil
}

//Run starts client and blocks while connected
func (c *Client) Run() error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := c.Start(ctx); err != nil {
		return err
	}
	return c.Wait()
}

func (c *Client) verifyServer(hostname string, remote net.Addr, key ssh.PublicKey) error {
	// log.Infof("hostname '%s' key '%+v'", hostname, key)
	expect := c.config.Fingerprint
	if expect == "" {
		return nil
	}
	got := ccrypto.FingerprintKey(key)
	_, err := base64.StdEncoding.DecodeString(expect)
	if _, ok := err.(base64.CorruptInputError); ok {
		c.Logger.Infof("Specified deprecated MD5 fingerprint (%s), please update to the new SHA256 fingerprint: %s", expect, got)
		return c.verifyLegacyFingerprint(key)
	} else if err != nil {
		return fmt.Errorf("Error decoding fingerprint: %w", err)
	}
	// if got != expect {
	// 	return fmt.Errorf("Invalid fingerprint (%s)", got)
	// }
	//overwrite with complete fingerprint
	// c.Infof("Fingerprint %s", got)
	return nil
}

//verifyLegacyFingerprint calculates and compares legacy MD5 fingerprints
func (c *Client) verifyLegacyFingerprint(key ssh.PublicKey) error {
	bytes := md5.Sum(key.Marshal())
	strbytes := make([]string, len(bytes))
	for i, b := range bytes {
		strbytes[i] = fmt.Sprintf("%02x", b)
	}
	got := strings.Join(strbytes, ":")
	expect := c.config.Fingerprint
	if !strings.HasPrefix(got, expect) {
		return fmt.Errorf("Invalid fingerprint (%s)", got)
	}
	return nil
}

//Start client and does not block
func (c *Client) Start(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	c.stop = cancel
	eg, ctx := errgroup.WithContext(ctx)
	c.eg = eg
	via := ""
	if c.proxyURL != nil {
		via = " via " + c.proxyURL.String()
	}
	c.Infof("Connecting to %s%s\n", c.server, via)
	//connect to chisel server
	eg.Go(func() error {
		return c.connectionLoop(ctx)
	})
	//listen sockets
	eg.Go(func() error {
		clientInbound := c.computed.Remotes.Reversed(false)
		if len(clientInbound) == 0 {
			return nil
		}
		return c.tunnel.BindRemotes(ctx, clientInbound)
	})
	return nil
}

func (c *Client) setProxy(u *url.URL, d *websocket.Dialer) error {
	// CONNECT proxy
	if !strings.HasPrefix(u.Scheme, "socks") {
		d.Proxy = func(*http.Request) (*url.URL, error) {
			return u, nil
		}
		return nil
	}
	// SOCKS5 proxy
	if u.Scheme != "socks" && u.Scheme != "socks5h" {
		return fmt.Errorf(
			"unsupported socks proxy type: %s:// (only socks5h:// or socks:// is supported)",
			u.Scheme,
		)
	}
	var auth *proxy.Auth
	if u.User != nil {
		pass, _ := u.User.Password()
		auth = &proxy.Auth{
			User:     u.User.Username(),
			Password: pass,
		}
	}
	socksDialer, err := proxy.SOCKS5("tcp", u.Host, auth, proxy.Direct)
	if err != nil {
		return err
	}
	d.NetDial = socksDialer.Dial
	return nil
}

//Wait blocks while the client is running.
func (c *Client) Wait() error {
	return c.eg.Wait()
}

//Close manually stops the client
func (c *Client) Close() error {
	if c.stop != nil {
		c.stop()
	}
	return nil
}

// markClientOffline mark client offline
func markClientOffline(config *Config, machineID string) {
	url := fmt.Sprintf("%s/v3/tunnel/client/%s?accessKey=%s", config.NerveServer, machineID, config.AccessKey)

	request := restyClient.R()
	resp, err := request.Delete(url)
	if err != nil {
		logrus.Error("unable to mark client offline", err)
	}
	if resp.StatusCode() != 200 {
		logrus.Error("unable to mark client offline, status Code ", resp.StatusCode(), resp.String())
	}
}

// Register register client to nerve
func Register(config *Config) ConfigFromNerve {
	var err error
	clientConf := ConfigFromNerve{}
	config.MachineID, err = machineid.ProtectedID("QphGAb3M6G3XDxivjbIanYJywkw")
	if err != nil {
		logrus.Error("Unable to get machine ID for tunnel server.", err.Error())
		os.Exit(0)
	}

	url := fmt.Sprintf("%s/v3/tunnel/client/register?accessKey=%s&machineID=%s&key=%s", config.NerveServer, config.AccessKey, config.MachineID, config.TunnelKey)
	request := restyClient.R()
	for {
		resp, _ := request.Get(url)

		if resp.StatusCode() >= 400 {

			logrus.Error("Your tunnel server is either not authorized or your auth is expire.\n\n ")
			logrus.Error(resp.String(), "\n\n")
			os.Exit(0)
		} else if resp.StatusCode() != 200 {
			logrus.Error("Unable to register tunnel ", url, " Status Code : ", resp.StatusCode(), " response : ", resp.String())
			logrus.Warn("Going to retry after 5 seconds")
			time.Sleep(5 * time.Second)
			continue
		} else {
			// logrus.Infof("Client config %d %s ", resp.StatusCode(), string(resp.Body()))

			err = json.Unmarshal(resp.Body(), &clientConf)
			if err != nil {
				logrus.Error("Unable to parse tunnel client response")
				logrus.Error(resp.String(), "\n\n")
				os.Exit(0)
			}
			return clientConf
		}
	}
}

// ping  client ping nevre
func ping(config *Config) {
	url := fmt.Sprintf("%s/v3/tunnel/client/ping?accessKey=%s&machineID=%s&key=%s", config.NerveServer, config.AccessKey, config.MachineID, config.TunnelKey)
	request := restyClient.R()
	resp, err := request.Get(url)
	if err != nil {
		logrus.Error("tunnel server unable to ping nerve server", err)
	}
	if resp.StatusCode() != 200 {
		logrus.Error("tunnel server unable to ping nerve server, status Code ", resp.StatusCode())
	}
}

// NotifyNerve notify nerve
func NotifyNerve(config *Config) {
	ticker := time.NewTicker(10 * time.Second)
	for {
		select {
		case <-ticker.C:
			ping(config)
		}
	}
}
