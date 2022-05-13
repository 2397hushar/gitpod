// Copyright (c) 2022 Gitpod GmbH. All rights reserved.
// Licensed under the GNU Affero General Public License (AGPL).
// See License-AGPL.txt in the project root for license information.

package config

import "github.com/gitpod-io/gitpod/common-go/baseserver"

type Configuration struct {
	GitpodServiceURL string `json:"gitpodServiceUrl"`

	Server *baseserver.Configuration `json:"server,omitempty"`
}
