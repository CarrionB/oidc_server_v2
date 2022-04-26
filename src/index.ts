import "dotenv/config";
import { Provider } from "oidc-provider";
import express, { Express } from "express";
import path from "path";
import bodyParser from "body-parser";
import assert from "assert";
import MongoAdapter from "./adapters/mongodb";

const app: Express = express();
const parse = bodyParser.urlencoded({ extended: false });
MongoAdapter.connect();
const oidc = new Provider("http://localhost:3000", {
  adapter: MongoAdapter,
  clientBasedCORS(ctx, origin, client) {
    return true;
  },
  clients: [
    {
      client_id: "foo",
      client_secret: "bar",
      redirect_uris: [
        "https://jwt.io",
        "https://openidconnect.net/callback",
        "https://oauth.pstmn.io/v1/callback",
        "https://oauthdebugger.com/debug"
      ], // using jwt.io as redirect_uri to show the ID Token contents
      // response_types: ["id_token", "code", "code id_token"],
      // grant_types: ["implicit", "authorization_code", "refresh_token"],
      grant_types: ["authorization_code", "refresh_token"],
      scope: "openid email profile phone address offline_access",
      application_type: "web",
    },
  ],
  claims: {
    address: ["address"],
    email: ["email", "email_verified"],
    phone: ["phone_number", "phone_number_verified"],
    profile: [
      "birthdate",
      "family_name",
      "gender",
      "given_name",
      "locale",
      "middle_name",
      "name",
      "nickname",
      "picture",
      "preferred_username",
      "profile",
      "updated_at",
      "website",
      "zoneinfo",
    ],
  },
  cookies: {
    keys: "SuperSecret".split(","),
  },
  interactions: {
    url(ctx, interaction) {
      return `/interaction/${interaction.uid}`;
    },
  },
  features: {
    // disable the packaged interactions
    devInteractions: { enabled: false },
    introspection: {
      enabled: true,
      allowedPolicy(ctx, client, token) {
        if (
          client.introspectionEndpointAuthMethod === "none" &&
          token.clientId !== ctx.oidc.client?.clientId
        ) {
          return false;
        }
        return true;
      },
    },
    resourceIndicators: {
      defaultResource(ctx) {
        console.log("ctx.oidc.params => ",ctx.oidc.params)
        return Array.isArray(ctx.oidc.params?.resource)
          ? ctx.oidc.params?.resource[0]
          : ctx.oidc.params?.resource;
      },
      getResourceServerInfo(ctx, resourceIndicator, client) {
        return {
          scope: "api:read offline_access",
        };
      },
    },
  },
  pkce: {
    methods: ["S256", "plain"],
    required: function pkceRequired(ctx, client) {
      return false;
    },
  },
  jwks: {
    keys: [
      {
        kty: "RSA",
        n: "jw3bixcae4ktBdXYcKeK5J7pmsXvQdvuOB8yv_q426tsMDlTZ1jj9CgYEZF_SCfzwQ5pcogLD-WY-LYJtt8zfjU_mWZZWcbR1QcMIWhLsSdi2OSlksIewMiv5CzvDBzs6h9sU0yr6yY6SYmT89jXU-D0MqSakDR0x0tyVUonGAWiVGJYINCCEbonoqFYAXjKdrNCCIliXiWQS6rajkEEXj0I2uQr4L1S80mSWWvDfFmFw4yC7V9nOGf1OPotscLCpT7vzlhHCuh3rY12bTEceZeARQ9G9aWQMBhQZPIPBvLdTRl5smFByFJ_FWs2yXXdHXFRo2L8UgwV2D4qVlgUXw",
        e: "AQAB",
        d: "PodKHUPd-X1-RnywfJ1fIosrhNFbwSfGupU4c529y5bkVTfZcuTxzrjvvE4imoGMFCiegsdgPnSXJq87E8oAEfxobj7Ec29qLHlGHhweabLTjAZ1MO7UzmNqLoxNeLfz_mn5yXdL9h7hf185Ym63wBwl4TT9smabXLlnokwlRmQXL-FWN5P50X60XgPG9hbv5BGPCrfbNNkLzae3fVeTfAZUYw-rwfrKN_HVUz78lo3cNhE2AVMnIF2CeZeH1xrUC81MWGJi7W1R1MtMTUObdqCpqLMtoWSojF3UT0pOMCiMeEt25EGpMiRVNy8HQD-z92uBEh8n2DYWb8Fou1Wa0Q",
        p: "23oJTOlWauw_fQJxBmwkfzPL_j9p_Fjtf_ThESn4ZpCkl2Y5cKSqc70bBP3SkgKRWWIt8QunkmkSHDmVzu0_UQu7YgCxqwwR8TvK8uCgNw8umtE_2w2fvf8l_863TEg4btz87kMtk01vWRUcqQxlBvd-bTmL8FDm0iblkskSpbs",
        q: "ptwhZzh1TkXFiglDz04_dC6s-Ek_qRxTtUSdhaRr7UDzpa_mEEd41m3kgmjgIlK-FgDpf66N4OWHQow76PVtRUAQSZDSPo4k8TNs5AY_oyzIBAWBnakfs8L368Vo4O3RZJ4wiMqnphTRGiM6rLOev74uTILcVnPgDZLbAm2Gb60",
        dp: "QDjIienpcKYqucDCI_f3AgW9Fmul7sJy1LNqPGSEnDaNAwRVoIF-oxld06sWN8VqlLYm7VbUtQHr27h5_q_rjCKbtUSwuHVytp0heMqD9ziJEaJTRh0JdkY370-k0Tx8zuv5UxrzNhw9jdqgpVLMKSq4outo6Gwz7qCVIsuVmks",
        dq: "FHPNAFryPfrdYLMMBcAAlRwXhYNs8yyOshxL9pKVzAn3E2sBFyO7kwT7SmTSfEKKHCZWeJkLuPJJZwXLXh2fHCrjFDFVI-fGbW4xPa3qZPTbO2r1XT7arO0L-HFFDrT3wo6FQm8cp4XLr5l72qlVnwkPob80hMBFSUSj5aNJJC0",
        qi: "MJJ6KTrCdq1gEgH-MpDF4DeXhE_dlB1P2am3juUR8ieZmohWbruBo6vmA_9Fm_lUs6V3qZ7gjbszguQZwcIFnvXceOBMH35_8TQLM3IrnNTJJTyWslrH3rdLAsIPk_x0cgIJ_gC0BHiQ9TfW8mKjGAK0JRv-V8XXnT4ZFQrlmQI",
      },
    ],
  },
  ttl: {
    AccessToken: function AccessTokenTTL(ctx, token, client) {
      if (token.resourceServer) {
        return token.resourceServer.accessTokenTTL || 60 * 60; // 1 hour in seconds
      }
      return 60 * 60; // 1 hour in seconds
    },
    AuthorizationCode: 600 /* 10 minutes in seconds */,
    BackchannelAuthenticationRequest:
      function BackchannelAuthenticationRequestTTL(ctx, request, client) {
        if (ctx.oidc.params) {
          if (ctx && ctx.oidc && ctx.oidc.params.requested_expiry) {
            return Math.min(
              10 * 60,
              +(ctx.oidc.params.requested_expiry as Number)
            ); // 10 minutes in seconds or requested_expiry, whichever is shorter
          }
        }

        return 10 * 60; // 10 minutes in seconds
      },
    ClientCredentials: function ClientCredentialsTTL(ctx, token, client) {
      if (token.resourceServer) {
        return token.resourceServer.accessTokenTTL || 10 * 60; // 10 minutes in seconds
      }
      return 10 * 60; // 10 minutes in seconds
    },
    DeviceCode: 600 /* 10 minutes in seconds */,
    Grant: 1209600 /* 14 days in seconds */,
    IdToken: 3600 /* 1 hour in seconds */,
    Interaction: 3600 /* 1 hour in seconds */,
    RefreshToken: function RefreshTokenTTL(ctx, token, client) {
      if (
        ctx &&
        ctx.oidc.entities.RotatedRefreshToken &&
        client.applicationType === "web" &&
        client.tokenEndpointAuthMethod === "none" &&
        !token.isSenderConstrained()
      ) {
        // Non-Sender Constrained SPA RefreshTokens do not have infinite expiration through rotation
        return ctx.oidc.entities.RotatedRefreshToken.remainingTTL;
      }

      return 14 * 24 * 60 * 60; // 14 days in seconds
    },
    Session: 1209600,
  },
  async findAccount(ctx: any, id: string, token: any) {
    console.log(token);
    console.log("findAccount => ", id);
    return {
      accountId: id,
      async claims(use, scope) {
        return { sub: id, scope };
      },
    };
  },
  // async issueRefreshToken(ctx, client, code) {
  //   console.log("issueRefreshToken")
  //   console.log("code => ", code.scopes)
  //   return client.grantTypeAllowed('refresh_token') && code.scopes.has('offline_access');
  // },
  async issueRefreshToken(ctx, client, code) {
    console.log("issueRefreshToken");
    console.log("code => ", code)
    console.log("scope => ", code.scopes)
    console.log("client.tokenEndpointAuthMethod => ", client.tokenEndpointAuthMethod)
    console.log("client.applicationType => ", client.applicationType)
    if (!client.grantTypeAllowed("refresh_token")) {
      return false;
    }
    console.log(code.scopes.has("offline_access") ||
    (client.applicationType === "web" &&
      client.tokenEndpointAuthMethod === "none"))
    return (
      code.scopes.has("offline_access") ||
      (client.applicationType === "web")
    );
  },
  tokenEndpointAuthMethods: [
    "client_secret_basic",
    "client_secret_jwt",
    "client_secret_post",
    "private_key_jwt",
    "none"
  ],
});

// http://localhost:3000/auth?response_type=id_token&client_id=foo&redirect_uri=https%3A%2F%2Fjwt.io&nonce=test&scope=openid
// http://localhost:3000/auth?response_type=id_token&client_id=foa&redirect_uri=https%3A%2F%2Fjwt.io&nonce=test&scope=openid

app.set("view engine", "ejs");
app.set("views", path.resolve(__dirname, "views"));

function setNoCache(req: any, res: any, next: any) {
  res.set("Pragma", "no-cache");
  res.set("Cache-Control", "no-cache, no-store");
  next();
}

app.get("/interaction/:uid", setNoCache, async (req, res, next) => {
  try {
    const details = await oidc.interactionDetails(req, res);
    console.log(
      "see what else is available to you for interaction views",
      details
    );
    const { uid, prompt, params } = details;
    const client = await oidc.Client.find(params.client_id as string);
    console.log("params before login => ",params);

    if (prompt.name === "login") {
      return res.render("login", {
        client,
        uid,
        details: prompt.details,
        params,
        title: "Sign-in",
        flash: undefined,
      });
    }
    console.log(prompt.name, " => ");
    console.log(params);
    return res.render("interaction", {
      client,
      uid,
      details: prompt.details,
      params,
      title: "Authorize",
    });
  } catch (err) {
    return next(err);
  }
});

app.post(
  "/interaction/:uid/login",
  setNoCache,
  parse,
  async (req, res, next) => {
    try {
      const { uid, prompt, params } = await oidc.interactionDetails(req, res);
      assert.strictEqual(prompt.name, "login");
      const client = await oidc.Client.find(params.client_id as string);
      let accountId;
      let loginResult = await MongoAdapter.login(
        req.body.email,
        req.body.password
      );
      if (loginResult) {
        accountId = loginResult._id.toString();
      }

      if (!accountId) {
        res.render("login", {
          client,
          uid,
          details: prompt.details,
          params: {
            ...params,
            login_hint: req.body.email,
          },
          title: "Sign-in",
          flash: "Invalid email or password.",
        });
        return;
      }

      const result = {
        login: { accountId },
      };

      await oidc.interactionFinished(req, res, result, {
        mergeWithLastSubmission: false,
      });
    } catch (err) {
      next(err);
    }
  }
);

app.post(
  "/interaction/:uid/confirm",
  setNoCache,
  parse,
  async (req, res, next) => {
    try {
      const interactionDetails = await oidc.interactionDetails(req, res);
      const {
        prompt: { name, details },
        params,
        session,
      } = interactionDetails;

      const accountId = session?.accountId;
      assert.strictEqual(name, "consent");

      let { grantId } = interactionDetails;
      let grant;

      if (grantId) {
        // we'll be modifying existing grant in existing session
        grant = await oidc.Grant.find(grantId);
      } else {
        // we're establishing a new grant
        grant = new oidc.Grant({
          accountId,
          clientId: params.client_id as string,
        });
      }

      const missingOIDCScope = details.missingOIDCScope as string[];
      if (missingOIDCScope) {
        grant?.addOIDCScope(missingOIDCScope.join(" "));
        // use grant.rejectOIDCScope to reject a subset or the whole thing
      }
      if (details.missingOIDCClaims) {
        grant?.addOIDCClaims(details.missingOIDCClaims as string[]);
        // use grant.rejectOIDCClaims to reject a subset or the whole thing
      }
      if (details.missingResourceScopes) {
        // eslint-disable-next-line no-restricted-syntax
        for (const [indicator, scopes] of Object.entries(
          details.missingResourceScopes as any
        )) {
          grant?.addResourceScope(indicator, (scopes as string[]).join(" "));
          // use grant.rejectResourceScope to reject a subset or the whole thing
        }
      }

      grantId = await grant?.save();

      const consent: any = {};
      if (!interactionDetails.grantId) {
        // we don't have to pass grantId to consent, we're just modifying existing one
        consent.grantId = grantId;
      }

      const result = { consent };
      await oidc.interactionFinished(req, res, result, {
        mergeWithLastSubmission: true,
      });
    } catch (err) {
      next(err);
    }
  }
);

app.get("/interaction/:uid/abort", setNoCache, async (req, res, next) => {
  try {
    const result = {
      error: "access_denied",
      error_description: "End-User aborted interaction",
    };
    await oidc.interactionFinished(req, res, result, {
      mergeWithLastSubmission: false,
    });
  } catch (err) {
    next(err);
  }
});

app.use(oidc.callback());

app.listen("3000", () => {
  console.log(
    "oidc-provider listening on port 3000, check http://localhost:3000/.well-known/openid-configuration"
  );
});
