package alpine

import (
	apko "chainguard.dev/apko/pkg/build/types"
	ocispecs "github.com/opencontainers/image-spec/specs-go/v1"
)

var platformMapping = map[string]string{
	"amd64": "x86_64",
	"arm64": "aarch64",
	"386":   "x86",
	"arm":   "armv7l",
}

func alpinePlatform(p ocispecs.Platform) string {
	v, ok := platformMapping[p.Architecture]
	if !ok {
		return p.Architecture
	}
	return v
}

func fromAlpinePlatforms(ps []apko.Architecture) []ocispecs.Platform {
	out := make([]ocispecs.Platform, len(ps))
	for i, p := range ps {
		pp := p.ToOCIPlatform()
		out[i] = ocispecs.Platform{
			Architecture: pp.Architecture,
			OS:           pp.OS,
			Variant:      pp.Variant,
		}
	}
	return out
}
