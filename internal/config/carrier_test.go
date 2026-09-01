package config

import (
	"strings"
	"testing"
)

func TestDeploymentCarrierListenerValidation(t *testing.T) {
	valid := validDeploymentJSON()
	cases := []struct {
		name   string
		mutate func(string) string
	}{
		{
			name: "listeners missing",
			mutate: func(value string) string {
				value = strings.Replace(value, `"carrier_tcp_listen_address":"0.0.0.0:27443"`, `"carrier_tcp_listen_address":""`, 1)
				return strings.Replace(value, `"carrier_quic_listen_address":"0.0.0.0:27444"`, `"carrier_quic_listen_address":""`, 1)
			},
		},
		{
			name: "missing TCP listener",
			mutate: func(value string) string {
				return strings.Replace(value, `"carrier_tcp_listen_address":"0.0.0.0:27443"`, `"carrier_tcp_listen_address":""`, 1)
			},
		},
		{
			name: "missing QUIC listener",
			mutate: func(value string) string {
				return strings.Replace(value, `"carrier_quic_listen_address":"0.0.0.0:27444"`, `"carrier_quic_listen_address":""`, 1)
			},
		},
		{
			name: "same listeners",
			mutate: func(value string) string {
				return strings.Replace(value, `"carrier_quic_listen_address":"0.0.0.0:27444"`, `"carrier_quic_listen_address":"0.0.0.0:27443"`, 1)
			},
		},
		{
			name: "hostname listener",
			mutate: func(value string) string {
				return strings.Replace(value, `"carrier_tcp_listen_address":"0.0.0.0:27443"`, `"carrier_tcp_listen_address":"edge.example.test:27443"`, 1)
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := LoadDeployment(writeDeployment(t, tc.mutate(valid))); err == nil {
				t.Fatal("invalid carrier configuration accepted")
			}
		})
	}
}

func TestDeploymentCarrierMintsProcessTrustWithoutStaticFiles(t *testing.T) {
	if _, err := LoadDeployment(writeDeployment(t, validDeploymentJSON())); err != nil {
		t.Fatalf("process-bound carrier trust profile rejected: %v", err)
	}
}

func TestLoadDeploymentRequiresCanonicalCarrier(t *testing.T) {
	for _, field := range []string{
		`"carrier_tcp_listen_address":"0.0.0.0:27443",`,
		`"carrier_quic_listen_address":"0.0.0.0:27444",`,
	} {
		value := strings.Replace(validDeploymentJSON(), field, "", 1)
		if _, err := LoadDeployment(writeDeployment(t, value)); err == nil {
			t.Fatalf("deployment without %s accepted", field)
		}
	}
}
