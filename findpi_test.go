package main

import (
	"net"
	"reflect"
	"testing"
)

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
