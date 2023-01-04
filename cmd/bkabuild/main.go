package main

import (
	"github.com/moby/buildkit/frontend/gateway/grpcclient"
	"github.com/moby/buildkit/util/appcontext"
	"github.com/sirupsen/logrus"
	alpine "github.com/tonistiigi/buildkit-alpine"
)

func main() {
	if err := grpcclient.RunFromEnvironment(appcontext.Context(), alpine.Build); err != nil {
		logrus.Errorf("fatal error: %+v", err)
		panic(err)
	}
}
