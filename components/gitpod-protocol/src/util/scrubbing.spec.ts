/**
 * Copyright (c) 2023 Gitpod GmbH. All rights reserved.
 * Licensed under the GNU Affero General Public License (AGPL).
 * See License.AGPL.txt in the project root for license information.
 */

import * as chai from "chai";
import { suite, test } from "mocha-typescript";
import { createScrubbedValue, scrub } from "./scrubbing";
const expect = chai.expect;

@suite
export class ScrubbingTest {
    @test public testValue_EmptyString() {
        expect(scrub("")).to.equal("");
    }
    @test public testValue_Email() {
        expect(scrub("foo@bar.com")).to.equal("[redacted:email]");
    }
    @test public testValue_EmailInText() {
        expect(scrub("The email is foo@bar.com or bar@foo.com")).to.equal(
            "The email is [redacted:email] or [redacted:email]",
        );
    }

    @test public testKeyValue_Email() {
        expect(scrub({ email: "testvalue" })).to.deep.equal({ email: "[redacted]" });
    }
    @test public testKeyValue_AuthorEmail() {
        expect(scrub({ author_email: "testvalue" })).to.deep.equal({ author_email: "[redacted]" });
    }
    @test public testKeyValue_Token() {
        expect(scrub({ token: "testvalue" })).to.deep.equal({ token: "[redacted]" });
    }
    @test public testKeyValue_OwnerToken() {
        expect(scrub({ owner_token: "testvalue" })).to.deep.equal({ owner_token: "[redacted]" });
    }

    @test public testKeyValue_NestedObject() {
        expect(scrub({ key: { owner_token: "testvalue" } }, true)).to.deep.equal({
            key: { owner_token: "[redacted]" },
        });
    }
    @test public testKeyValue_NoNestedObject() {
        expect(scrub({ key: { owner_token: "testvalue" } }, false)).to.deep.equal({
            key: "[redacted:nested:object}]",
        });
    }

    @test public testKeyValue_NestedArray() {
        expect(scrub([["foo@bar.com"]])).to.deep.equal([["[redacted:email]"]]);
    }

    @test public testKeyValue_NoNestedArray() {
        expect(scrub([["foo@bar.com"]], false)).to.deep.equal(["[redacted:nested:array]"]);
    }

    @test public testKeyValue_Scrubbable() {
        const scrubbedValue = createScrubbedValue((scrubber) => scrubber.scrubValue("foo@bar.com"));
        expect(scrub({ key: scrubbedValue })).to.deep.equal({ key: "[redacted:email]" });
    }
}
module.exports = new ScrubbingTest();
