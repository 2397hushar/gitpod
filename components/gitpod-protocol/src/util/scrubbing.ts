/**
 * Copyright (c) 2023 Gitpod GmbH. All rights reserved.
 * Licensed under the GNU Affero General Public License (AGPL).
 * See License.AGPL.txt in the project root for license information.
 */

import { createHash } from "crypto";

const redactedFields = ["auth_", "password", "token", "key", "jwt", "secret", "email"];
const hashedFields = ["contextURL", "workspaceID", "username"];

const hashedValues = new Map<string, RegExp>([]);
const redactedValues = new Map<string, RegExp>([
    // https://html.spec.whatwg.org/multipage/input.html#email-state-(type=email)
    [
        "email",
        new RegExp(
            /[a-zA-Z0-9.!#$%&'*+/=?^_\`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*/,
            "g",
        ),
    ],
]);

interface SanitizeOptions {
    key?: string;
}
type Sanitisatiser = (value: string, options?: SanitizeOptions) => string;

const SanitiseRedact: Sanitisatiser = (_: string, options?: SanitizeOptions) => {
    if (options?.key) {
        return `[redacted:${options?.key}]`;
    }
    return "[redacted]";
};
const SanitiseHash: Sanitisatiser = (value: string, options?: SanitizeOptions) => {
    const hash = createHash("md5");
    hash.update(value);

    let res = `[redacted:md5:${hash.digest("hex")}`;
    if (options?.key) {
        res += `:${options?.key}`;
    }
    res += `]`;
    return res;
};

const regexes = new Map<RegExp, Sanitisatiser>([
    [new RegExp(redactedFields.join("|"), "i"), SanitiseRedact],
    [new RegExp(hashedFields.join("|"), "i"), SanitiseHash],
]);

export function scrubKeyValue(key: string, value: string): string {
    for (const [regex, sanitisatiser] of regexes) {
        if (regex.test(key)) {
            return sanitisatiser(value);
        }
    }
    return value;
}

export function scrubValue(value: string): string {
    for (const [key, expr] of hashedValues.entries()) {
        value = value.replace(expr, (s) => SanitiseHash(s, { key }));
    }
    for (const [key, expr] of redactedValues.entries()) {
        value = value.replace(expr, (s) => SanitiseRedact(s, { key }));
    }
    return value;
}
