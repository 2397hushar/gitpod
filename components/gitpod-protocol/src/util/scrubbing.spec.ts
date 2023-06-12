/**
 * Copyright (c) 2023 Gitpod GmbH. All rights reserved.
 * Licensed under the GNU Affero General Public License (AGPL).
 * See License.AGPL.txt in the project root for license information.
 */

import * as chai from "chai";
import { suite, test } from "mocha-typescript";
import { scrubKeyValue, scrubValue } from "./scrubbing";
const expect = chai.expect;

@suite
export class ScrubbingTest {
    @test public testValue_EmptyString() {
        expect(scrubValue("")).to.equal("");
    }
    @test public testValue_Email() {
        expect(scrubValue("foo@bar.com")).to.equal("[redacted:email]");
    }
    @test public testValue_EmailInText() {
        expect(scrubValue("The email is foo@bar.com or bar@foo.com")).to.equal(
            "The email is [redacted:email] or [redacted:email]",
        );
    }

    @test public testKeyValue_Email() {
        expect(scrubKeyValue("email", "testvalue")).to.equal("[redacted]");
    }
    @test public testKeyValue_AuthorEmail() {
        expect(scrubKeyValue("author_email", "testvalue")).to.equal("[redacted]");
    }
    @test public testKeyValue_Token() {
        expect(scrubKeyValue("token", "testvalue")).to.equal("[redacted]");
    }
    @test public testKeyValue_OwnerToken() {
        expect(scrubKeyValue("owner_token", "testvalue")).to.equal("[redacted]");
    }
}
module.exports = new ScrubbingTest();
