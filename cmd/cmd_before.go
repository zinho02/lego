package cmd

import (
	"github.com/urfave/cli"
	"github.com/zinho02/lego/v4/log"
)

func Before(ctx *cli.Context) error {
	if ctx.GlobalString("path") == "" {
		log.Fatal("Could not determine current working directory. Please pass --path.")
	}

	err := createNonExistingFolder(ctx.GlobalString("path"))
	if err != nil {
		log.Fatalf("Could not check/create path: %v", err)
	}

	if ctx.GlobalString("server") == "" {
		log.Fatal("Could not determine current working server. Please pass --server.")
	}

	return nil
}
