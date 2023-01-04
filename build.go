package alpine

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"strings"

	apko "chainguard.dev/apko/pkg/build/types"
	"github.com/containerd/containerd/platforms"
	"github.com/moby/buildkit/client/llb"
	"github.com/moby/buildkit/exporter/containerimage/exptypes"
	"github.com/moby/buildkit/frontend/gateway/client"
	ocispecs "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/pkg/errors"
	"golang.org/x/sync/errgroup"
	"gopkg.in/yaml.v3"
)

const (
	defaultFilename = "Dockerfile"

	keyFilename      = "filename"
	keyPlatform      = "platform"
	localContextName = "context"
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

func parsePlatforms(v string) ([]ocispecs.Platform, error) {
	pl := []ocispecs.Platform{}
	for _, s := range strings.Split(v, ",") {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		p, err := platforms.Parse(s)
		if err != nil {
			return nil, err
		}
		p = platforms.Normalize(p)
		pl = append(pl, p)
	}
	return pl, nil
}

type cf interface {
	CurrentFrontend() (*llb.State, error)
}

func Build(ctx context.Context, c client.Client) (*client.Result, error) {
	opts := c.BuildOpts()

	fn := defaultFilename
	if f, ok := opts.Opts[keyFilename]; ok {
		fn = f
	}

	var pl []ocispecs.Platform
	if v, ok := opts.Opts[keyPlatform]; ok {
		var err error
		pl, err = parsePlatforms(v)
		if err != nil {
			return nil, errors.Wrapf(err, "failed to parse platforms: %s", v)
		}
	}
	if len(pl) == 0 {
		pl = append(pl, platforms.Normalize(platforms.DefaultSpec()))
	}

	var self llb.State
	if cc, ok := c.(cf); !ok {
		return nil, errors.Errorf("no support for frontend reexec, buildkit v0.10+ required")
	} else {
		st, err := cc.CurrentFrontend()
		if err != nil {
			return nil, err
		}
		self = *st
	}

	// TODO: git/http contexts
	src := llb.Local(localContextName, llb.SessionID(c.BuildOpts().SessionID), llb.SharedKeyHint("alpine-filename"), llb.FollowPaths([]string{fn}))
	def, err := src.Marshal(ctx)
	if err != nil {
		return nil, err
	}

	res, err := c.Solve(ctx, client.SolveRequest{
		Definition: def.ToPB(),
	})
	if err != nil {
		return nil, err
	}
	dt, err := res.Ref.ReadFile(ctx, client.ReadRequest{
		Filename: fn,
	})
	if err != nil {
		return nil, err
	}

	ic, err := parse(dt)
	if err != nil {
		return nil, err
	}

	res = client.NewResult()
	expPlatforms := &exptypes.Platforms{
		Platforms: make([]exptypes.Platform, len(pl)),
	}

	eg, ctx := errgroup.WithContext(ctx)
	for k, p := range pl {
		k, p := k, p
		eg.Go(func() error {
			r, err := buildPlatform(ctx, c, self, p, ic)
			if err != nil {
				return err
			}
			pkey := platforms.Format(p)
			res.AddRef(pkey, r.Ref)
			expPlatforms.Platforms[k] = exptypes.Platform{
				ID:       pkey,
				Platform: p,
			}
			return nil
		})
	}
	if err := eg.Wait(); err != nil {
		return nil, err
	}

	dt, err = json.Marshal(expPlatforms)
	if err != nil {
		return nil, err
	}
	res.AddMeta(exptypes.ExporterPlatformsKey, dt)

	return res, err
}

func isIgnoreCache(c client.Client) bool {
	if _, ok := c.BuildOpts().Opts["no-cache"]; ok {
		return true
	}
	return false
}

func buildPlatform(ctx context.Context, c client.Client, self llb.State, p ocispecs.Platform, ic *apko.ImageConfiguration) (*client.Result, error) {
	cmd := fmt.Sprintf(`sh -c "apk add --initdb --arch %s --root /out"`, alpinePlatform(p))

	ro := []llb.RunOption{llb.Shlex(cmd), llb.Network(llb.NetModeNone)}
	if isIgnoreCache(c) {
		ro = append(ro, llb.IgnoreCache)
	}
	rootfs := self.Run(ro...).AddMount("/out", llb.Scratch())

	rootfs = rootfs.File(
		llb.Mkfile("/etc/apk/repositories", 0644, []byte(strings.Join(ic.Contents.Repositories, "\n"))).
			Copy(self, "/usr/share/apk/keys/"+alpinePlatform(p)+"/*", "/etc/apk/keys/", &llb.CopyInfo{
				AllowWildcard:      true,
				AllowEmptyWildcard: true,
				FollowSymlinks:     true,
			}),
	)

	cmd = fmt.Sprintf(`sh -c "ls -l /out/etc/apk/keys && apk update --root /out && apk fetch -R --simulate --root /out --update --url %s > /urls"`, strings.Join(ic.Contents.Packages, " "))

	ro = []llb.RunOption{llb.Shlex(cmd)}
	if isIgnoreCache(c) {
		ro = append(ro, llb.IgnoreCache)
	}
	run := self.Run(ro...)
	run.AddMount("/out", rootfs)

	def, err := run.Marshal(ctx)
	if err != nil {
		return nil, err
	}
	res, err := c.Solve(ctx, client.SolveRequest{
		Definition: def.ToPB(),
	})
	if err != nil {
		return nil, err
	}
	dt, err := res.Ref.ReadFile(ctx, client.ReadRequest{
		Filename: "/urls",
	})
	if err != nil {
		return nil, err
	}
	log.Printf("urls: %s", string(dt))
	return res, nil
}

func parse(dt []byte) (*apko.ImageConfiguration, error) {
	// TODO: apko doesn't have a clean types pkg. Upstream changes or copy/paste only the definitions
	var ic apko.ImageConfiguration
	if err := yaml.Unmarshal(dt, &ic); err != nil {
		return nil, errors.Errorf("failed to parse image configuration: %w", err)
	}
	if err := ic.Validate(); err != nil {
		return nil, err
	}
	return &ic, nil
}
