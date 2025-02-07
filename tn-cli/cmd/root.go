package cmd

import (
	pb "github.com/tinode/chat/pbx"
	"github.com/tinode/chat/server/logs"
	"os"
	"strings"

	"github.com/spf13/cobra"
)

// global variables those used in more than one command, e.g. in login and acc.
var (
	scheme, secret, uname, password, authToken string
	cookieFile                                 = ".tn-cli-cookie"
)

var (
	logFlags   string
	host       string
	loginBasic string
	verbose    bool
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "tn-cli",
	Short: "Tinode cli implemented with Go",
	Long:  "Tinode cli is a Go implementation of tn-cli, a command-line interface program that interacts with the Tinode gRPC server.",
	Run: func(cmd *cobra.Command, args []string) {
		if loginBasic != "" {
			if !strings.Contains(loginBasic, ":") {
				logs.Err.Println("Invalid format for --login-basic, expected username:password.")
			}
			handleLogin(&pb.ClientLogin{
				Scheme: "basic",
				Secret: []byte(loginBasic),
			})
		}
	},
}

// Execute adds all child commands to the root command and sets flags appropriately.
func Execute() {
	if len(os.Args) == 1 {
		_ = rootCmd.Help()
		return
	}
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func init() {
	// define persistent flags e.g. host.
	rootCmd.PersistentFlags().StringVar(&logFlags, "log_flags", "stdFlags", "comma-separated list of log flags")
	rootCmd.PersistentFlags().StringVar(&host, "host", "localhost:16060", "address of Tinode gRPC server")
	rootCmd.PersistentFlags().StringVar(&loginBasic, "login-basic", "", "login using basic authentication username:password")
	rootCmd.PersistentFlags().BoolVar(&verbose, "verbose", false, "log full JSON representation of all messages")

	// add all other sub-commands to the rootCmd.
	rootCmd.AddCommand(newAccCmd(), loginCmd())
}
