package main

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"os"

	"github.com/spf13/cobra"
)

const BASE_URL = "http://localhost:8080"

func main() {
	var rootCmd = &cobra.Command{Use: "cli"}

	rootCmd.AddCommand(&cobra.Command{
		Use:   "summary-time [start] [end]",
		Short: "Get error summary in a time range",
		Args:  cobra.ExactArgs(2),
		Run: func(cmd *cobra.Command, args []string) {
			url := fmt.Sprintf("%s/errors/summary-time?start=%s&end=%s", BASE_URL, args[0], args[1])
			resp, err := http.Get(url)
			if err != nil {
				fmt.Println("error", err)
				return
			}
			defer resp.Body.Close()
			body, err := ioutil.ReadAll(resp.Body)
			if err != nil {
				fmt.Println("error", err)
				return
			}
			fmt.Println(string(body))
		},
	})

	rootCmd.AddCommand(&cobra.Command{
		Use:   "top-errors-limit [limit]",
		Short: "Get top errors by limit",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			url := fmt.Sprintf("%s/errors/top-limit?limit=%s", BASE_URL, args[0])
			resp, err := http.Get(url)
			if err != nil {
				fmt.Println("error", err)
				return
			}
			defer resp.Body.Close()
			body, err := ioutil.ReadAll(resp.Body)
			if err != nil {
				fmt.Println("error", err)
				return
			}
			fmt.Println(string(body))
		},
	})

	rootCmd.AddCommand(&cobra.Command{
		Use:   "error-details [fingerprint]",
		Short: "Get all logs for a fingerprint",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			url := fmt.Sprintf("%s/errors/details-fp?fingerprint=%s", BASE_URL, args[0])
			resp, err := http.Get(url)
			if err != nil {
				fmt.Println("error", err)
				return
			}
			defer resp.Body.Close()
			body, err := ioutil.ReadAll(resp.Body)
			if err != nil {
				fmt.Println("error", err)
				return
			}
			fmt.Println(string(body))
		},
	})

	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}