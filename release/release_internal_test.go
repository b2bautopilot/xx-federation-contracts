package release

import (
	"runtime/debug"
	"testing"
)

func TestPublicReplacement(t *testing.T) {
	tests := []struct {
		name        string
		replacement *debug.Module
		want        string
	}{
		{
			name:        "nil replacement",
			replacement: nil,
			want:        "",
		},
		{
			name:        "versioned module replacement",
			replacement: &debug.Module{Path: "github.com/example/fork", Version: "v1.2.3"},
			want:        "github.com/example/fork@v1.2.3",
		},
		{
			name:        "unversioned module replacement",
			replacement: &debug.Module{Path: "github.com/example/fork"},
			want:        "",
		},
		{
			name:        "devel version replacement",
			replacement: &debug.Module{Path: "github.com/example/fork", Version: "(devel)"},
			want:        "",
		},
		{
			name:        "relative dot slash path",
			replacement: &debug.Module{Path: "../dep", Version: "v1.2.3"},
			want:        "",
		},
		{
			name:        "relative current dir path",
			replacement: &debug.Module{Path: "./dep", Version: "v1.2.3"},
			want:        "",
		},
		{
			name:        "absolute path",
			replacement: &debug.Module{Path: "/home/builder/work/dep", Version: "v1.2.3"},
			want:        "",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := publicReplacement(tc.replacement); got != tc.want {
				t.Fatalf("publicReplacement(%+v) = %q, want %q", tc.replacement, got, tc.want)
			}
		})
	}
}
