// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build linux
// +build linux

package dns

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"tailscale.com/logtail/backoff"

	"github.com/godbus/dbus/v5"
	"golang.org/x/sys/unix"
	"inet.af/netaddr"
	"tailscale.com/health"
	"tailscale.com/types/logger"
	"tailscale.com/util/dnsname"
)

// resolvedListenAddr is the listen address of the resolved stub resolver.
//
// We only consider resolved to be the system resolver if the stub resolver is;
// that is, if this address is the sole nameserver in /etc/resolved.conf.
// In other cases, resolved may be managing the system DNS configuration directly.
// Then the nameserver list will be a concatenation of those for all
// the interfaces that register their interest in being a default resolver with
//   SetLinkDomains([]{{"~.", true}, ...})
// which includes at least the interface with the default route, i.e. not us.
// This does not work for us: there is a possibility of getting NXDOMAIN
// from the other nameservers before we are asked or get a chance to respond.
// We consider this case as lacking resolved support and fall through to dnsDirect.
//
// While it may seem that we need to read a config option to get at this,
// this address is, in fact, hard-coded into resolved.
var resolvedListenAddr = netaddr.IPv4(127, 0, 0, 53)

var errNotReady = errors.New("interface not ready")

// DBus entities we talk to.
//
// DBus is an RPC bus. In particular, the bus we're talking to is the
// system-wide bus (there is also a per-user session bus for
// user-specific applications).
//
// Daemons connect to the bus, and advertise themselves under a
// well-known object name. That object exposes paths, and each path
// implements one or more interfaces that contain methods, properties,
// and signals.
//
// Clients connect to the bus and walk that same hierarchy to invoke
// RPCs, get/set properties, or listen for signals.
const (
	dbusResolvedObject                    = "org.freedesktop.resolve1"
	dbusResolvedPath      dbus.ObjectPath = "/org/freedesktop/resolve1"
	dbusResolvedInterface                 = "org.freedesktop.resolve1.Manager"
	dbusPath              dbus.ObjectPath = "/org/freedesktop/DBus"
	dbusInterface                         = "org.freedesktop.DBus"
	dbusOwnerSignal                       = "NameOwnerChanged" // broadcast when a well-known name's owning process changes.
)

type resolvedLinkNameserver struct {
	Family  int32
	Address []byte
}

type resolvedLinkDomain struct {
	Domain      string
	RoutingOnly bool
}

// resolvedManager is an OSConfigurator which uses the systemd-resolved DBus API.
type resolvedManager struct {
	ctx    context.Context
	cancel func() // terminate the context, for close

	logf  logger.Logf
	ifidx int

	configs chan OSConfig // configs is a channel of OSConfigs, one per each SetDNS call
}

func newResolvedManager(logf logger.Logf, interfaceName string) (*resolvedManager, error) {
	iface, err := net.InterfaceByName(interfaceName)
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithCancel(context.Background())

	mgr := &resolvedManager{
		ctx:    ctx,
		cancel: cancel,

		logf:    logf,
		ifidx:   iface.Index,
		configs: make(chan OSConfig),
	}

	go mgr.run(ctx)

	return mgr, nil
}

func (m *resolvedManager) SetDNS(config OSConfig) error {
	// TODO(raggi|warrick): add error channel output from goroutine
	m.configs <- config

	return nil
}

func (m *resolvedManager) run(ctx context.Context) {
	var (
		conn      *dbus.Conn
		signals   chan *dbus.Signal
		r1Manager dbus.BusObject
	)

	bo := backoff.NewBackoff("resolvedSetDNS", m.logf, 30*time.Second)

	defer func() {
		if conn != nil {
			conn.Close()
		}
	}()

	reconnect := func() error {
		signals = make(chan *dbus.Signal, 16)
		var err error
		conn, err = dbus.SystemBus()
		if err != nil {
			bo.BackOff(ctx, err)
			return err
		}

		r1Manager = conn.Object(dbusResolvedObject, dbus.ObjectPath(dbusResolvedPath))

		// Only receive the DBus signals we need to resync our config on
		// resolved restart. Failure to set filters isn't a fatal error,
		// we'll just receive all broadcast signals and have to ignore
		// them on our end.
		if err := conn.AddMatchSignal(dbus.WithMatchObjectPath(dbusPath), dbus.WithMatchInterface(dbusInterface), dbus.WithMatchMember(dbusOwnerSignal), dbus.WithMatchArg(0, dbusResolvedObject)); err != nil {
			m.logf("[v1] Setting DBus signal filter failed: %v", err)
		}
		conn.Signal(signals)
		return err
	}
	reconnect()

	lastConfig := OSConfig{}

	for {
		select {
		case <-ctx.Done():
			if r1Manager == nil {
				return
			}

			// RevertLink on connection if signals are interrupted in order to create a new connection.
			if call := r1Manager.CallWithContext(ctx, dbusResolvedInterface+".RevertLink", 0, m.ifidx); call.Err != nil {
				// TODO(raggi): return fmt.Errorf("RevertLink: %w", call.Err)
				return
			}

			return

		case config := <-m.configs:
			lastConfig = config

			if r1Manager == nil {
				continue
			}

			m.sync(ctx, r1Manager, config)

		case signal, ok := <-signals:
			if !ok {
				if err := reconnect(); err != nil {
					m.logf("Reconnect error %T", err)
				}
				continue
			}
			// In theory the signal was filtered by DBus, but if
			// AddMatchSignal in the constructor failed, we may be
			// getting other spam.
			if signal.Path != dbusPath || signal.Name != dbusInterface+"."+dbusOwnerSignal {
				continue
			}

			if lastConfig.IsZero() {
				continue
			}

			// signal.Body is a []any of 3 strings: bus name, previous owner, new owner.
			if len(signal.Body) != 3 {
				m.logf("[unexpectected] DBus NameOwnerChanged len(Body) = %d, want 3")
			}
			if name, ok := signal.Body[0].(string); !ok || name != dbusResolvedObject {
				continue
			}
			newOwner, ok := signal.Body[2].(string)
			if !ok {
				m.logf("[unexpected] DBus NameOwnerChanged.new_owner is a %T, not a string", signal.Body[2])
			}
			if newOwner == "" {
				// systemd-resolved left the bus, no current owner,
				// nothing to do.
				continue
			}
			// The resolved bus name has a new owner, meaning resolved
			// restarted. Reprogram current config.
			m.logf("systemd-resolved restarted, syncing DNS config")
			err := m.sync(ctx, r1Manager, lastConfig)
			// Set health while holding the lock, because this will
			// graciously serialize the resync's health outcome with a
			// concurrent SetDNS call.
			health.SetDNSOSHealth(err)
			if err != nil {
				m.logf("failed to configure systemd-resolved: %v", err)
			}

		}

	}
}

// sync is only called from the run goroutine
func (m *resolvedManager) sync(ctx context.Context, r1Manager dbus.BusObject, config OSConfig) error {
	ctx, cancel := context.WithTimeout(ctx, reconfigTimeout)
	defer cancel()

	var linkNameservers = make([]resolvedLinkNameserver, len(config.Nameservers))
	for i, server := range config.Nameservers {
		ip := server.As16()
		if server.Is4() {
			linkNameservers[i] = resolvedLinkNameserver{
				Family:  unix.AF_INET,
				Address: ip[12:],
			}
		} else {
			linkNameservers[i] = resolvedLinkNameserver{
				Family:  unix.AF_INET6,
				Address: ip[:],
			}
		}
	}

	err := r1Manager.CallWithContext(
		ctx, dbusResolvedInterface+".SetLinkDNS", 0,
		m.ifidx, linkNameservers,
	).Store()
	if err != nil {
		return fmt.Errorf("setLinkDNS: %w", err)
	}

	linkDomains := make([]resolvedLinkDomain, 0, len(config.SearchDomains)+len(config.MatchDomains))
	seenDomains := map[dnsname.FQDN]bool{}
	for _, domain := range config.SearchDomains {
		if seenDomains[domain] {
			continue
		}
		seenDomains[domain] = true
		linkDomains = append(linkDomains, resolvedLinkDomain{
			Domain:      domain.WithTrailingDot(),
			RoutingOnly: false,
		})
	}
	for _, domain := range config.MatchDomains {
		if seenDomains[domain] {
			// Search domains act as both search and match in
			// resolved, so it's correct to skip.
			continue
		}
		seenDomains[domain] = true
		linkDomains = append(linkDomains, resolvedLinkDomain{
			Domain:      domain.WithTrailingDot(),
			RoutingOnly: true,
		})
	}
	if len(config.MatchDomains) == 0 && len(config.Nameservers) > 0 {
		// Caller requested full DNS interception, install a
		// routing-only root domain.
		linkDomains = append(linkDomains, resolvedLinkDomain{
			Domain:      ".",
			RoutingOnly: true,
		})
	}

	err = r1Manager.CallWithContext(
		ctx, dbusResolvedInterface+".SetLinkDomains", 0,
		m.ifidx, linkDomains,
	).Store()
	if err != nil && err.Error() == "Argument list too long" { // TODO: better error match
		// Issue 3188: older systemd-resolved had argument length limits.
		// Trim out the *.arpa. entries and try again.
		err = r1Manager.CallWithContext(
			ctx, dbusResolvedInterface+".SetLinkDomains", 0,
			m.ifidx, linkDomainsWithoutReverseDNS(linkDomains),
		).Store()
	}
	if err != nil {
		return fmt.Errorf("setLinkDomains: %w", err)
	}

	if call := r1Manager.CallWithContext(ctx, dbusResolvedInterface+".SetLinkDefaultRoute", 0, m.ifidx, len(config.MatchDomains) == 0); call.Err != nil {
		if dbusErr, ok := call.Err.(dbus.Error); ok && dbusErr.Name == dbus.ErrMsgUnknownMethod.Name {
			// on some older systems like Kubuntu 18.04.6 with systemd 237 method SetLinkDefaultRoute is absent,
			// but otherwise it's working good
			m.logf("[v1] failed to set SetLinkDefaultRoute: %v", call.Err)
		} else {
			return fmt.Errorf("setLinkDefaultRoute: %w", call.Err)
		}
	}

	// Some best-effort setting of things, but resolved should do the
	// right thing if these fail (e.g. a really old resolved version
	// or something).

	// Disable LLMNR, we don't do multicast.
	if call := r1Manager.CallWithContext(ctx, dbusResolvedInterface+".SetLinkLLMNR", 0, m.ifidx, "no"); call.Err != nil {
		m.logf("[v1] failed to disable LLMNR: %v", call.Err)
	}

	// Disable mdns.
	if call := r1Manager.CallWithContext(ctx, dbusResolvedInterface+".SetLinkMulticastDNS", 0, m.ifidx, "no"); call.Err != nil {
		m.logf("[v1] failed to disable mdns: %v", call.Err)
	}

	// We don't support dnssec consistently right now, force it off to
	// avoid partial failures when we split DNS internally.
	if call := r1Manager.CallWithContext(ctx, dbusResolvedInterface+".SetLinkDNSSEC", 0, m.ifidx, "no"); call.Err != nil {
		m.logf("[v1] failed to disable DNSSEC: %v", call.Err)
	}

	if call := r1Manager.CallWithContext(ctx, dbusResolvedInterface+".SetLinkDNSOverTLS", 0, m.ifidx, "no"); call.Err != nil {
		m.logf("[v1] failed to disable DoT: %v", call.Err)
	}

	if call := r1Manager.CallWithContext(ctx, dbusResolvedInterface+".FlushCaches", 0); call.Err != nil {
		m.logf("failed to flush resolved DNS cache: %v", call.Err)
	}

	return nil
}

func (m *resolvedManager) SupportsSplitDNS() bool {
	return true
}

func (m *resolvedManager) GetBaseConfig() (OSConfig, error) {
	return OSConfig{}, ErrGetBaseConfigNotSupported
}

func (m *resolvedManager) Close() error {
	m.cancel()

	// No need to do anything on close which is handled in trySet
	return nil
}

// linkDomainsWithoutReverseDNS returns a copy of v without
// *.arpa. entries.
func linkDomainsWithoutReverseDNS(v []resolvedLinkDomain) (ret []resolvedLinkDomain) {
	for _, d := range v {
		if strings.HasSuffix(d.Domain, ".arpa.") {
			// Oh well. At least the rest will work.
			continue
		}
		ret = append(ret, d)
	}
	return ret
}
