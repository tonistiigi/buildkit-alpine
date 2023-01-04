package alpine

import (
	"context"

	"github.com/moby/buildkit/client/llb"
	"github.com/moby/buildkit/frontend/gateway/client"
)

func Build(ctx context.Context, c client.Client) (*client.Result, error) {
	def, err := llb.Image("alpine:latest").Marshal(ctx)
	if err != nil {
		return nil, err
	}
	res, err := c.Solve(ctx, client.SolveRequest{
		Definition: def.ToPB(),
	})
	return res, err
}
