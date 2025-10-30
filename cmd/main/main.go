package main

import (
	"errors"
	"flag"
	"fmt"
	"log"
	"net/netip"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/go-gost/go-shadowsocks2/core"
	"github.com/go-gost/go-shadowsocks2/socks"
	"github.com/go-gost/go-shadowsocks2/utils"
)

type Users []core.UserConfig

func (u *Users) String() string {
	return ""
}

func (u *Users) Set(value string) error {
	r := strings.Split(value, ":")
	if len(r) != 2 {
		return errors.New("parse user config failed")
	}

	*u = append(*u, core.NewUserConfig(r[0], r[1]))
	return nil
}

var config struct {
	Verbose    bool
	UDPTimeout time.Duration
	TCPCork    bool
}

func main() {

	var flags struct {
		Client   string
		Server   string
		Cipher   string
		Password string
		Socks    string
		UDP      bool
		TCP      bool
		users    Users
	}

	flag.Var(&flags.users, "user", "user and password for SIP023")
	flag.BoolVar(&config.Verbose, "verbose", false, "verbose mode")
	flag.StringVar(&flags.Cipher, "cipher", "AEAD_CHACHA20_POLY1305", "available ciphers: "+strings.Join(utils.ListCipher(), " "))
	flag.StringVar(&flags.Socks, "socks", "", "(client-only) SOCKS listen address")
	flag.StringVar(&flags.Password, "password", "", "password")
	flag.StringVar(&flags.Server, "s", "", "server listen address or url")
	flag.StringVar(&flags.Client, "c", "", "client connect address or url")
	flag.BoolVar(&flags.UDP, "udp", false, "enable UDP support")
	flag.BoolVar(&flags.TCP, "tcp", true, "enable TCP support")
	flag.BoolVar(&config.TCPCork, "tcpcork", false, "coalesce writing first few packets")
	flag.DurationVar(&config.UDPTimeout, "udptimeout", 5*time.Minute, "UDP tunnel timeout")
	flag.Parse()

	core.SetLogger(logf)

	if flags.Client == "" && flags.Server == "" {
		flag.Usage()
		return
	}

	if flags.Client != "" { // client mode
		addr := flags.Client
		cipher := flags.Cipher
		password := flags.Password

		if flags.Password == "" {
			password = os.Getenv("SS_PASSWORD")
		}
		var err error

		if strings.HasPrefix(addr, "ss://") {
			addr, cipher, password, err = parseURL(addr)
			if err != nil {
				log.Fatal(err)
			}
		}

		socks.UDPEnabled = flags.UDP

		serverAddr, err := netip.ParseAddrPort(addr)
		if err != nil {
			log.Fatal(err)
		}
		clientConfig, err := utils.NewClientConfig(cipher, password, serverAddr)
		if err != nil {
			log.Fatal(err)
		}

		go socksLocal(flags.Socks, clientConfig)
		if flags.UDP {
			go udpSocksLocal(flags.Socks, clientConfig)
		}
	}

	if flags.Server != "" { // server mode
		addr := flags.Server
		cipher := flags.Cipher
		password := flags.Password
		if flags.Password == "" {
			password = os.Getenv("SS_PASSWORD")
		}
		var err error

		if strings.HasPrefix(addr, "ss://") {
			addr, cipher, password, err = parseURL(addr)
			if err != nil {
				log.Fatal(err)
			}
		}

		serverAddr, err := netip.ParseAddrPort(addr)
		log.Println("addr: ", addr)
		if err != nil {
			log.Fatal(err)
		}

		serverConfig, err := utils.NewServerConfig(cipher, password, serverAddr, flags.users)
		if err != nil {
			log.Fatal(err)
		}
		if flags.UDP {
			go udpRemote(serverConfig)
		}
		if flags.TCP {
			go tcpRemote(serverConfig)
		}
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh
}

func parseURL(s string) (addr, cipher, password string, err error) {
	u, err := url.Parse(s)
	if err != nil {
		return
	}

	if len(u.Hostname()) == 0 {
		u.Host = fmt.Sprintf("0.0.0.0:%s", u.Port())
	}
	addr = u.Host
	if u.User != nil {
		cipher = u.User.Username()
		password, _ = u.User.Password()
	}
	return
}
