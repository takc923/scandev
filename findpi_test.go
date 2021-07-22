package main

import (
	"net"
	"reflect"
	"testing"
)

func TestGetRPiMACAddress(t *testing.T) {
	type args struct {
		ip net.IP
	}
	tests := []struct {
		name    string
		args    args
		want    string
		wantErr bool
	}{
		{
			name:    "success",
			args:    args{net.IPv4(192, 168, 1, 4)},
			want:    "b8:27:eb:a3:ee:bb",
			wantErr: false,
		},
		{
			name:    "failure",
			args:    args{net.IPv4(192, 168, 1, 5)},
			want:    "",
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := GetRPiMACAddress(tt.args.ip)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetRPiMACAddress() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("GetRPiMACAddress() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestAllIPAddrInNetwork(t *testing.T) {
	type args struct {
		ip   [4]byte
		mask [4]byte
	}
	var want1 []net.IP
	for i := byte(1); i < 255; i++ {
		if i == 3 {
			continue
		}
		want1 = append(want1, net.IPv4(192, 168, 1, i))
	}

	tests := []struct {
		name string
		args args
		want []net.IP
	}{
		{
			"normal",
			args{
				[4]byte{192, 168, 1, 3},
				[4]byte{255, 255, 255, 0},
			},
			want1,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := AllIPAddrInNetwork(tt.args.ip, tt.args.mask); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("AllIPAddrInNetwork() = %v, want %v", got, tt.want)
			}
		})
	}
}
