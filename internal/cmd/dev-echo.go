package cmd

import (
	"context"
	"fmt"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/spf13/cobra"
)

func newDevEchoCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "dev-echo",
		Short: "Run a tiny stdio MCP echo server (fake upstream for tests and demos)",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runDevEcho(cmd.Context())
		},
	}
}

// echoInput is the dev-echo tool schema.
type echoInput struct {
	Text string `json:"text" jsonschema:"Echo this text back"`
}

// echoOutput is the dev-echo tool output.
type echoOutput struct {
	Echo string `json:"echo"`
}

func runDevEcho(ctx context.Context) error {
	srv := mcp.NewServer(&mcp.Implementation{Name: "dev-echo", Version: "dev"}, nil)
	mcp.AddTool(srv, &mcp.Tool{
		Name:        "echo",
		Description: "Echo the given text back. A fake upstream for tests and demos.",
	}, func(_ context.Context, _ *mcp.CallToolRequest, in echoInput) (*mcp.CallToolResult, echoOutput, error) {
		out := echoOutput{Echo: in.Text}
		return &mcp.CallToolResult{
			Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("echo: %s", in.Text)}},
		}, out, nil
	})
	return srv.Run(ctx, &mcp.StdioTransport{})
}
