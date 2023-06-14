/**
 * Copyright (c) 2023 Gitpod GmbH. All rights reserved.
 * Licensed under the GNU Affero General Public License (AGPL).
 * See License.AGPL.txt in the project root for license information.
 */

import { createHash } from "crypto";

/**
 * `scrub` function is used to redact sensitive information from the given object.
 * It traverses through the properties of the object and replaces sensitive values
 * with a placeholder "[redacted]" or a more specific placeholder based on the context.
 * It also handles arrays and nested objects.
 *
 * If an instance of `ScrubbedValue` is encountered,
 * it calls the `scrub` method on it, allowing for custom scrubbing logic on a per-value basis.
 * `ScrubbedValue` instances can be created using `createScrubbedValue` function.
 *
 * The function does not mutate the original data structures. Instead, it creates new data structures
 * that mirror the originals but with sensitive information redacted.
 *
 * @param obj - The object to be scrubbed.
 * @param nested - A boolean to determine whether to scrub nested objects or arrays.
 *                 Default is `true`, which means the function will scrub nested objects or arrays.
 *
 * @returns - The scrubbed object with redacted sensitive information.
 */
export function scrub(obj: any, nested: boolean = true): any {
    return doScrub(obj, 0, nested);
}

/**
 * `Scrubber` interface is used to define the structure for the scrubbing utility.
 * An object of this type is used to redact sensitive information from a string or a key-value pair.
 */
export interface Scrubber {
    /**
     * `scrubKeyValue` method is used to redact sensitive information from a key-value pair.
     * @param key - The key of the key-value pair.
     * @param value - The value of the key-value pair.
     * @returns - The redacted value for the key-value pair.
     */
    scrubKeyValue(key: string, value: string): string;
    /**
     * `scrubValue` method is used to redact sensitive information from a string.
     * @param value - The string to be redacted.
     * @returns - The redacted string.
     */
    scrubValue(value: string): string;
}

export function createScrubbedValue(scrub: (scrubber: Scrubber) => any): any {
    return new ScrubbedValue(scrub);
}

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

const scrubber: Scrubber = {
    scrubKeyValue: function (key: string, value: string): string {
        for (const [regex, sanitisatiser] of regexes) {
            if (regex.test(key)) {
                return sanitisatiser(value);
            }
        }
        return value;
    },
    scrubValue: function (value: string): string {
        for (const [key, expr] of hashedValues.entries()) {
            value = value.replace(expr, (s) => SanitiseHash(s, { key }));
        }
        for (const [key, expr] of redactedValues.entries()) {
            value = value.replace(expr, (s) => SanitiseRedact(s, { key }));
        }
        return value;
    },
};

class ScrubbedValue {
    constructor(readonly scrub: (scrubber: Scrubber) => any) {}
}

function doScrub(obj: any, depth: number, nested: boolean): any {
    if (obj === undefined || obj === null) {
        return undefined;
    }
    if (obj instanceof ScrubbedValue) {
        return obj.scrub(scrubber);
    }
    const objType = typeof obj;
    if (objType === "string") {
        return scrubber.scrubValue(obj);
    }
    if (objType === "boolean" || objType === "number") {
        return obj;
    }
    if (Array.isArray(obj)) {
        if (!nested && depth > 0) {
            return "[redacted:nested:array]";
        }
        return obj.map((v) => doScrub(v, depth + 1, nested));
    }
    if (!nested && depth > 0) {
        return `[redacted:nested:${objType}}]`;
    }
    if (objType === "object") {
        const result: any = {};
        for (const [key, value] of Object.entries(obj)) {
            if (typeof value === "string") {
                result[key] = scrubber.scrubKeyValue(key, value);
            } else {
                result[key] = doScrub(value, depth + 1, nested);
            }
        }
        return result;
    }
    return obj;
}
