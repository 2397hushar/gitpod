/**
 * Copyright (c) 2022 Gitpod GmbH. All rights reserved.
 * Licensed under the GNU Affero General Public License (AGPL).
 * See License-AGPL.txt in the project root for license information.
 */

export type Connections = TailscaleConnection;

export interface Connection {
    id: string;
}

export interface TailscaleConnection extends Connection {
    authKey: string;
}

export interface GCloudAdcConnection extends Connection {
    serviceAccount: string;
}
export interface ConnectionType {
    name: string;
    attributes: string[];
    envVars: { name: string; value: string }[];
    tasks: { name: string; command: string }[];
}
