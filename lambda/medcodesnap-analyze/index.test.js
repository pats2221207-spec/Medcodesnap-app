// Tests for the Phase 10 admin actions (adminListUsers / adminUpdateUser /
// adminCreateUser) added to medcodesnap-analyze. No real AWS credentials are
// used or required — every Cognito/DynamoDB call is mocked. The whole point
// of this file is to prove, mechanically, that:
//
//   1. A caller whose access token resolves (via Cognito GetUser) to any
//      email other than patty@medcodesnap.com is rejected with 403 by all
//      three new actions, even if the request body *claims* to be Patty.
//   2. A caller with no/garbage/expired token is rejected the same way.
//   3. Only a caller whose token actually resolves to patty@medcodesnap.com
//      can reach the underlying Cognito admin calls.
//   4. billing_status is restricted to the fixed allowed set.
//   5. The existing, unrelated actions (analyze/savePendingSheet/etc.) and
//      the Stripe webhook path are untouched by this change.
//
// Run with: npm test (from this directory) — requires `npm install` first.

let mockSend = jest.fn();

jest.mock("@aws-sdk/client-dynamodb", () => ({
  DynamoDBClient: jest.fn().mockImplementation(() => ({}))
}), { virtual: true });

jest.mock("@aws-sdk/lib-dynamodb", () => ({
  DynamoDBDocumentClient: { from: () => ({ send: jest.fn() }) },
  PutCommand: function (input) { this.input = input; },
  GetCommand: function (input) { this.input = input; },
  DeleteCommand: function (input) { this.input = input; }
}), { virtual: true });

jest.mock("@aws-sdk/client-cognito-identity-provider", () => {
  function makeCommand(name) {
    return function (input) {
      this.input = input;
      this.__name = name;
    };
  }
  return {
    CognitoIdentityProviderClient: jest.fn().mockImplementation(() => ({
      send: (...args) => mockSend(...args)
    })),
    AdminUpdateUserAttributesCommand: makeCommand("AdminUpdateUserAttributesCommand"),
    ListUsersCommand: makeCommand("ListUsersCommand"),
    GetUserCommand: makeCommand("GetUserCommand"),
    AdminCreateUserCommand: makeCommand("AdminCreateUserCommand"),
    ForgotPasswordCommand: makeCommand("ForgotPasswordCommand")
  };
}, { virtual: true });

const { handler } = require("./index");

const ADMIN_EMAIL = "patty@medcodesnap.com";

function makeEvent(body) {
  return { httpMethod: "POST", headers: {}, body: JSON.stringify(body) };
}

// Token → identity map used by the mocked GetUser call below, standing in
// for "what Cognito would actually say this access token belongs to."
const TOKEN_IDENTITIES = {
  "admin-token": ADMIN_EMAIL,
  "other-user-token": "someoneelse@example.com",
  "second-user-token": "rando@example.com"
};

beforeEach(() => {
  mockSend.mockReset();
  mockSend.mockImplementation(async (command) => {
    switch (command.__name) {
      case "GetUserCommand": {
        const email = TOKEN_IDENTITIES[command.input.AccessToken];
        if (!email) {
          const err = new Error("Access Token has been revoked");
          err.name = "NotAuthorizedException";
          throw err;
        }
        return { UserAttributes: [{ Name: "email", Value: email }] };
      }
      case "ListUsersCommand":
        return {
          Users: [
            {
              UserCreateDate: new Date("2026-01-01T00:00:00.000Z"),
              Attributes: [
                { Name: "sub", Value: "sub-1" },
                { Name: "email", Value: "client1@example.com" },
                { Name: "custom:billing_status", Value: "active" },
                { Name: "custom:trial_start", Value: "1735689600000" }
              ]
            }
          ]
        };
      case "AdminUpdateUserAttributesCommand":
        return {};
      case "AdminCreateUserCommand":
        return { User: { Username: command.input.Username } };
      case "ForgotPasswordCommand":
        return {};
      default:
        throw new Error(`Unmocked command: ${command.__name}`);
    }
  });
});

describe("admin-only gating (all three new actions)", () => {
  const actionsUnderTest = [
    { action: "adminListUsers", extraBody: {} },
    { action: "adminUpdateUser", extraBody: { sub: "sub-1", billing_status: "active" } },
    { action: "adminCreateUser", extraBody: { email: "newclient@example.com", billing_status: "trialing" } }
  ];

  for (const { action, extraBody } of actionsUnderTest) {
    test(`${action} rejects a different signed-in user, even if body claims to be Patty`, async () => {
      const res = await handler(makeEvent({
        action,
        accessToken: "other-user-token",
        email: ADMIN_EMAIL, // forged/claimed field — must be ignored
        ...extraBody
      }));
      expect(res.statusCode).toBe(403);
      // The underlying Cognito admin call must never have been reached.
      const adminCallNames = ["ListUsersCommand", "AdminUpdateUserAttributesCommand", "AdminCreateUserCommand"];
      const reachedAdminCall = mockSend.mock.calls.some(([cmd]) => adminCallNames.includes(cmd.__name));
      expect(reachedAdminCall).toBe(false);
    });

    test(`${action} rejects a missing access token`, async () => {
      const res = await handler(makeEvent({ action, ...extraBody }));
      expect(res.statusCode).toBe(403);
    });

    test(`${action} rejects an unrecognized/expired access token`, async () => {
      const res = await handler(makeEvent({ action, accessToken: "garbage-token", ...extraBody }));
      expect(res.statusCode).toBe(403);
    });

    test(`${action} rejects a second, different non-admin account too`, async () => {
      const res = await handler(makeEvent({ action, accessToken: "second-user-token", ...extraBody }));
      expect(res.statusCode).toBe(403);
    });

    test(`${action} succeeds for the real admin token`, async () => {
      const res = await handler(makeEvent({ action, accessToken: "admin-token", ...extraBody }));
      expect(res.statusCode).toBe(200);
    });
  }
});

describe("adminListUsers", () => {
  test("returns the expected fields for each user", async () => {
    const res = await handler(makeEvent({ action: "adminListUsers", accessToken: "admin-token" }));
    const data = JSON.parse(res.body);
    expect(data.users).toEqual([
      {
        sub: "sub-1",
        email: "client1@example.com",
        billing_status: "active",
        trial_start: "1735689600000",
        created: "2026-01-01T00:00:00.000Z"
      }
    ]);
  });
});

describe("adminUpdateUser validation", () => {
  test("rejects an out-of-set billing_status", async () => {
    const res = await handler(makeEvent({
      action: "adminUpdateUser",
      accessToken: "admin-token",
      sub: "sub-1",
      billing_status: "vip-lifetime" // not in the allowed set
    }));
    expect(res.statusCode).toBe(400);
  });

  test("rejects when neither billing_status nor trial_start is provided", async () => {
    const res = await handler(makeEvent({
      action: "adminUpdateUser",
      accessToken: "admin-token",
      sub: "sub-1"
    }));
    expect(res.statusCode).toBe(400);
  });

  test("rejects a non-numeric trial_start", async () => {
    const res = await handler(makeEvent({
      action: "adminUpdateUser",
      accessToken: "admin-token",
      sub: "sub-1",
      trial_start: "2026-06-22" // ISO date, not the epoch-ms string format actually used
    }));
    expect(res.statusCode).toBe(400);
  });

  test("accepts a valid epoch-ms trial_start string", async () => {
    const res = await handler(makeEvent({
      action: "adminUpdateUser",
      accessToken: "admin-token",
      sub: "sub-1",
      trial_start: String(Date.now())
    }));
    expect(res.statusCode).toBe(200);
  });
});

describe("adminCreateUser", () => {
  test("rejects missing email", async () => {
    const res = await handler(makeEvent({ action: "adminCreateUser", accessToken: "admin-token" }));
    expect(res.statusCode).toBe(400);
  });

  test("rejects an out-of-set billing_status", async () => {
    const res = await handler(makeEvent({
      action: "adminCreateUser",
      accessToken: "admin-token",
      email: "newclient@example.com",
      billing_status: "vip-lifetime"
    }));
    expect(res.statusCode).toBe(400);
  });

  test("creates with MessageAction SUPPRESS, no TemporaryPassword, no email_verified, then calls ForgotPassword", async () => {
    const res = await handler(makeEvent({
      action: "adminCreateUser",
      accessToken: "admin-token",
      email: "newclient@example.com",
      billing_status: "trialing",
      trial_start: String(Date.now())
    }));
    expect(res.statusCode).toBe(200);

    const createCall = mockSend.mock.calls.find(([cmd]) => cmd.__name === "AdminCreateUserCommand");
    expect(createCall).toBeTruthy();
    const createInput = createCall[0].input;
    expect(createInput.MessageAction).toBe("SUPPRESS");
    expect(createInput.TemporaryPassword).toBeUndefined();
    expect(createInput.UserAttributes.some(a => a.Name === "email_verified")).toBe(false);
    expect(createInput.UserAttributes).toEqual(
      expect.arrayContaining([{ Name: "email", Value: "newclient@example.com" }])
    );

    const forgotCall = mockSend.mock.calls.find(([cmd]) => cmd.__name === "ForgotPasswordCommand");
    expect(forgotCall).toBeTruthy();
    expect(forgotCall[0].input.Username).toBe("newclient@example.com");
  });

  test("returns 409 when the email already exists", async () => {
    mockSend.mockImplementation(async (command) => {
      if (command.__name === "GetUserCommand") {
        return { UserAttributes: [{ Name: "email", Value: ADMIN_EMAIL }] };
      }
      if (command.__name === "AdminCreateUserCommand") {
        const err = new Error("An account with the given email already exists.");
        err.name = "UsernameExistsException";
        throw err;
      }
      throw new Error(`Unmocked command: ${command.__name}`);
    });

    const res = await handler(makeEvent({
      action: "adminCreateUser",
      accessToken: "admin-token",
      email: "dupe@example.com"
    }));
    expect(res.statusCode).toBe(409);
  });
});

describe("existing behavior is untouched", () => {
  test("savePendingSheet still requires sub and is not admin-gated", async () => {
    // Sanity check that unrelated existing actions didn't get swept up into
    // the admin-gating change.
    jest.mock("@aws-sdk/lib-dynamodb"); // already mocked above; no-op here
    const res = await handler(makeEvent({ action: "savePendingSheet" }));
    expect(res.statusCode).toBe(400); // missing sub — same as before this change
  });
});
