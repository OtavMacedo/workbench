package main

import (
	"github.com/pedroloch/workbench/internal/app"
	"os"
)

func main() { os.Exit(app.New().Run(os.Args[1:])) }
