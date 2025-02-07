package cmd

import (
	"context"
	"encoding/json"
	"github.com/spf13/cobra"
	pb "github.com/tinode/chat/pbx"
	"github.com/tinode/chat/server/logs"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"log"
	"os"
	"time"
)

var user, tags, fn, photo string
var doLogin bool

// newAccCmd command to create new account.
func newAccCmd() *cobra.Command {
	accCmd := &cobra.Command{
		Use:   "acc",
		Short: "Create or alter an account",
		Run: func(cmd *cobra.Command, args []string) {
			if scheme == "basic" {
				secret = uname + ":" + password
			}

			publicData := map[string]any{
				"fn":    fn,
				"photo": map[string]string{"ref": photo},
			}
			public, err := json.Marshal(publicData)
			if err != nil {
				logs.Err.Printf("failed to encode JSON: %v", err)
				return
			}

			if user == "new" {
				logs.Info.Printf("creating new user account: %s\n", user)
			} else {
				logs.Info.Printf("updating user account: %s\n", user)
			}

			handleAcc(&pb.ClientAcc{
				UserId: user,
				Scheme: scheme,
				Secret: []byte(secret),
				Login:  doLogin,
				Tags:   []string{tags},
				Desc:   &pb.SetDesc{Public: public},
			})
		},
	}

	accCmd.Flags().StringVar(&user, "user", "new", "ID of the account to update")
	accCmd.Flags().StringVar(&scheme, "scheme", "basic", "authentication scheme")
	accCmd.Flags().StringVar(&secret, "secret", "", "secret for authentication")
	accCmd.Flags().StringVar(&uname, "uname", "", "user name for basic authentication")
	accCmd.Flags().StringVar(&password, "password", "", "password for basic authentication")
	accCmd.Flags().BoolVar(&doLogin, "do-login", false, "login with the newly created account")
	accCmd.Flags().StringVar(&tags, "tags", "", "tags for user discovery")
	accCmd.Flags().StringVar(&fn, "fn", "", "user's human name")
	accCmd.Flags().StringVar(&photo, "photo", "", "avatar file name")
	return accCmd
}

// handleAcc receive acc payload from cli and send to Tinode server.
// handleAcc expect as credential such as email or tel validation is not required.
func handleAcc(accMsg *pb.ClientAcc) {
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
		logs.Info.Printf("sending acc message: %v\n", accMsg)
	}

	err = stream.Send(&pb.ClientMsg{
		Message: &pb.ClientMsg_Acc{
			Acc: accMsg,
		}})

	response, err := stream.Recv()
	if err != nil {
		logs.Err.Printf("failed to receive response: %v", err)
		return
	}

	switch msg := response.Message.(type) {
	case *pb.ServerMsg_Ctrl:
		if msg.Ctrl.Code == 201 {
			usr := string(msg.Ctrl.Params["user"])
			logs.Info.Printf("\nuser %s updated successfully\n", usr)

			// save session data into cookie.
			if doLogin {
				authToken = string(msg.Ctrl.Params["token"])
				if err := saveCookie(map[string]string{"token": authToken, "user": usr}); err != nil {
					logs.Info.Printf("failed to save cookie: %v", err)
				} else {
					log.Printf("cookie saved to %s\n", cookieFile)
				}
			}
		} else {
			log.Printf("acc updated failed: %s\n", msg.Ctrl.Text)
		}
	default:
		log.Println("unexpected response from server.")
	}
}
