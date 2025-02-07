package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/tinode/chat/server/logs"
	"os"
	"time"

	"github.com/spf13/cobra"
	pb "github.com/tinode/chat/pbx"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// loginCmd command to login.
func loginCmd() *cobra.Command {
	loginCmd := &cobra.Command{
		Use:   "login",
		Short: "Authenticate current session",
		Run: func(cmd *cobra.Command, args []string) {
			if scheme == "basic" {
				secret = uname + ":" + password
				logs.Info.Printf("logging in with login:password: %v\n", secret)
			} else {
				logs.Info.Printf("logging in with token: %v\n", secret)
			}

			loginMsg := &pb.ClientLogin{
				Scheme: scheme,
				Secret: []byte(secret),
			}
			handleLogin(loginMsg)
		},
	}
	loginCmd.Flags().StringVar(&scheme, "scheme", "basic", "Authentication schema")
	loginCmd.Flags().StringVar(&secret, "secret", "", "Secret for authentication")
	loginCmd.Flags().StringVar(&uname, "uname", "", "User name for authentication")
	loginCmd.Flags().StringVar(&password, "password", "", "Password for authentication")
	return loginCmd
}

// handleLogin receive login payload from cli and send to Tinode server.
func handleLogin(loginMsg *pb.ClientLogin) {
	conn, err := grpc.NewClient(host, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		logs.Err.Printf("failed to connect to server: %v", err)
		os.Exit(1)
	}
	defer conn.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	client := pb.NewNodeClient(conn)
	stream, err := client.MessageLoop(ctx)
	if err != nil {
		logs.Err.Printf("failed to initiate message loop: %v", err)
		os.Exit(1)
	}
	handleHiMsg(stream)

	if verbose {
		logs.Info.Printf("sending login message: %v\n", loginMsg)
	}

	err = stream.Send(&pb.ClientMsg{
		Message: &pb.ClientMsg_Login{
			Login: loginMsg,
		},
	})
	if err != nil {
		logs.Err.Printf("failed to send login message: %v", err)
		return
	}

	response, err := stream.Recv()
	if err != nil {
		logs.Err.Printf("failed to receive response: %v", err)
		return
	}

	switch msg := response.Message.(type) {
	case *pb.ServerMsg_Ctrl:
		if msg.Ctrl.Code == 200 {
			authToken = string(msg.Ctrl.Params["token"])
			usr := string(msg.Ctrl.Params["user"])
			logs.Info.Printf("logged in as %s\n", usr)
			if err := saveCookie(map[string]string{"token": authToken, "user": usr}); err != nil {
				logs.Err.Printf("failed to save cookie: %v", err)
				return
			} else {
				logs.Info.Printf("cookie saved to %s\n", cookieFile)
			}
		} else {
			logs.Err.Printf("login failed: %s\n", msg.Ctrl.Text)
			return
		}
	default:
		logs.Err.Println("unexpected response from server.")
	}
}

// handleHiMsg sends handshake message and read the response on the stream.
func handleHiMsg(stream grpc.BidiStreamingClient[pb.ClientMsg, pb.ServerMsg]) {
	err := stream.Send(&pb.ClientMsg{
		Message: &pb.ClientMsg_Hi{
			Hi: &pb.ClientHi{
				Ver: "1.69.2",
			},
		},
	})
	if err != nil {
		logs.Err.Printf("failed to send hi message: %v", err)
		return
	}

	_, err = stream.Recv()
	if err != nil {
		logs.Err.Printf("failed to receive response: %v", err)
		return
	}
}

// saveCookie store session data on a file.
func saveCookie(params map[string]string) error {
	file, err := os.Create(cookieFile)
	if err != nil {
		return err
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	if err := encoder.Encode(params); err != nil {
		return err
	}
	return nil
}

// readCookie read session data from a cookie file.
func readCookie() (string, error) {
	file, err := os.Open(cookieFile)
	if err != nil {
		return "", fmt.Errorf("missing or invalid cookie file: %v", err)
	}
	defer file.Close()

	var params map[string]string
	if err := json.NewDecoder(file).Decode(&params); err != nil {
		return "", fmt.Errorf("failed to decode cookie file: %v", err)
	}
	authToken, _ = params["token"]
	return authToken, nil
}
