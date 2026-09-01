package runtime

import (
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat-tunnel/internal/control"
	"github.com/pinksaucepasta/paperboat-tunnel/internal/datacarrier"
	"github.com/pinksaucepasta/paperboat-tunnel/internal/route"
)

func TestCanonicalManagedAssignmentStagesFromControlProjection(t *testing.T) {
	assignment := control.RouteAssignment{
		Canonical: true, RouteID: "rte_tun_chMH6AnTd3wz_HPD0rRdFg_default", Revision: 1,
		AccountID: "usr_aa550b50991ce221923c6dd46250e075", HostID: "mch_3426305b8923ea607db673051eb4fb6d",
		MachineIdentityPublicKey: "V_3IRrjtfIdR7AKoJETXXYreyuCy0BbJfHOVqmJZXwA", MachineIdentityThumbprint: "R24c_xC8ZK_RmfUYQWNX0ChS7-BMa30Sjo_JfPERE4s",
		TunnelID: "tun_chMH6AnTd3wz_HPD0rRdFg", ConnectorID: "con_Nl0Ee8yKzvYpMHfzAQkVWQ", Generation: 1,
		ConnectorSessionID: "sess_af79d13ac2ccaf3f31051e29b4e79bfe4b16", ConnectorProcessGeneration: 15,
		ConfigGeneration: 1, ConfigContentHash: "sha256:53d45d01a7b2fd79b5cbdbd0693347856f38ec4ac7d86d2448599ff3fa7b47d7",
		AssignmentID: "asn_faa83010e700246bc5ce93448ae2532f68f809e74019c36f", AssignmentGeneration: 7,
		EdgeFailureDomain: "default", EdgeProcessEpoch: "XgDXW6wyhRsNUnYoo8xKhMyg5g_5DvKb", NodeID: "pprbt-helsinki",
		Kind: string(route.TunnelHTTPSWSS), PublicHost: "1d22bc42-1290-440b-9dbc-bcaa2e1f2357.tunnels.pprbt.dev",
		MatchType: route.MatchManagedExact, MatchHostname: "1d22bc42-1290-440b-9dbc-bcaa2e1f2357.tunnels.pprbt.dev",
		Priority: 100, Protocol: "http", OriginScheme: "http", AccessMode: "public", PreserveHost: true,
		DesiredState: "active", ObservedState: "pending", State: "staged",
		TargetRouteID: "rte_tun_chMH6AnTd3wz_HPD0rRdFg_default", TargetConnectorSessionID: "sess_af79d13ac2ccaf3f31051e29b4e79bfe4b16",
		TargetConnectorProcessGen: 15, TargetConfigGeneration: 1,
	}
	if err := validateCanonicalAssignment(assignment, assignment.NodeID, assignment.EdgeProcessEpoch); err != nil {
		t.Fatalf("validate: %v", err)
	}
	rules := canonicalRouteRules([]control.RouteAssignment{assignment})
	registry := route.NewGenerationRegistry(4)
	if err := registry.StageGeneration(1, rules); err != nil {
		t.Fatalf("stage: %v; rules=%+v", err, rules)
	}
	admissions, err := canonicalDurableAdmissions([]control.RouteAssignment{assignment})
	if err != nil {
		t.Fatalf("admissions: %v", err)
	}
	durable, err := datacarrier.NewDurableAdmissionRegistry(datacarrier.DurableAdmissionRegistryConfig{NodeID: assignment.NodeID, ProcessEpoch: assignment.EdgeProcessEpoch})
	if err != nil {
		t.Fatal(err)
	}
	if err := durable.Replace(admissions, time.Now().UTC()); err != nil {
		t.Fatalf("replace admissions: %v", err)
	}
}
