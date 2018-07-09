/*
Copyright (c) 2016-2017 Bitnami

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package nats

import (
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/nats-io/go-nats"
)

var publishCmd = &cobra.Command{
	Use:   "publish FLAG",
	Short: "publish message to a topic",
	Long:  `publish message to a topic`,
	Run: func(cmd *cobra.Command, args []string) {
		data, err := cmd.Flags().GetString("message")
		if err != nil {
			logrus.Fatal(err)
		}

		topic, err := cmd.Flags().GetString("topic")
		if err != nil {
			logrus.Fatal(err)
		}

		url, err := cmd.Flags().GetString("url")
		if err != nil {
			logrus.Fatal(err)
		}

		nopts, err := newNatsOpts(cmd)
		if err != nil {
			logrus.Fatal(err)
		}

		err = publishTopic(topic, data, url, nopts.Options()...)
		if err != nil {
			logrus.Fatal("Failed to publish message to topic: ", err)
		}
	},
}

func publishTopic(topic, message, url string, opts ...nats.Option) error {
	nc, err := nats.Connect(url, opts...)
	if err != nil {
		logrus.Fatal(err)
	}
	defer nc.Close()
	nc.Publish(topic, []byte(message))
	nc.Flush()
	if err := nc.LastError(); err != nil {
		return err
	}
	logrus.Infof("Published [%s] : '%s'\n", topic, message)
	return nil
}

func newNatsOpts(cmd *cobra.Command) (*natsOpts, error) {
	fls := cmd.Flags()
	n := &natsOpts{}
	if fls.Lookup("tls-key") != nil && fls.Lookup("tls-cert") != nil {
		key, err := fls.GetString("tls-key")
		if err != nil {
			return nil, err
		}
		cert, err := fls.GetString("tls-cert")
		if err != nil {
			return nil, err
		}
		n.TLSKey = key
		n.TLSCert = cert
	}
	if fls.Lookup("ca-cert") != nil {
		caCerts, err := fls.GetStringSlice("ca-cert")
		if err != nil {
			return nil, err
		}
		n.CACerts = caCerts
	}
	return n, nil
}

type natsOpts struct {
	TLSCert string
	TLSKey  string
	CACerts []string
}

func (n *natsOpts) Options() []nats.Option {
	var opts []nats.Option
	if len(n.CACerts) > 0 {
		opts = append(opts, nats.RootCAs(n.CACerts...))
	}
	if n.TLSCert != "" && n.TLSKey != "" {
		opts = append(opts, nats.ClientCert(n.TLSCert, n.TLSKey))
	}
	return opts
}

func init() {
	fls := publishCmd.Flags()
	fls.StringP("message", "", "", "Specify message to be published")
	fls.StringP("topic", "", "kubeless", "Specify topic name")
	fls.StringP("url", "", "", "Specify NATS server details for e.g nats://localhost:4222)")
	fls.StringP("tls-cert", "", "", "Specify NATS client TLS public key")
	fls.StringP("tls-key", "", "", "Specify NATS client TLS private key")
	fls.StringSliceP("ca-cert", "", nil, "Specify NATS client trusted CA public keys")
	publishCmd.MarkFlagRequired("url")
	publishCmd.MarkFlagRequired("topic")
	publishCmd.MarkFlagRequired("message")
}
