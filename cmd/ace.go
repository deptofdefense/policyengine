package main

import (
	"fmt"

	"github.com/spf13/cobra"
)

var OpaCmd = &cobra.Command{
	Use:   "policyengine",
	Short: "ACE engine",
}

func main() {
	if err := OpaCmd.Execute(); err != nil {
		fmt.Println(err)
	}
}
