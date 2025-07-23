import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import bodyParser from "body-parser";
import OAuthClient from "intuit-oauth";
import axios from "axios";

const app = express();
dotenv.config();

const allowedOrigins = [
  "https://expensetraker-5cfea.web.app", // ✅ Your deployed Flutter web app
  "http://localhost:53371",              // ✅ Local dev environment (optional)
];

const corsOptions = {
  origin: function (origin, callback) {
    // Allow requests with no origin (like curl or Postman) or valid domains
    if (!origin || allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error("Not allowed by CORS"));
    }
  },
  credentials: true,
};

app.use(cors(corsOptions));
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: false }));

let oauthClient = null;
let oauth2_token_json = null;

const getOAuthClient = () =>
  new OAuthClient({
    clientId: process.env.QUICKBOOKS_CLIENT_ID,
    clientSecret: process.env.QUICKBOOKS_CLIENT_SECRET,
    environment: "sandbox", // or "sandbox"
    redirectUri: process.env.QUICKBOOKS_REDIRECT_URI,
  });

app.get("/authUri", (req, res) => {
  try {
    oauthClient = new OAuthClient({
      clientId: process.env.QUICKBOOKS_CLIENT_ID,
      clientSecret: process.env.QUICKBOOKS_CLIENT_SECRET,
      environment: "sandbox",
      redirectUri: process.env.QUICKBOOKS_REDIRECT_URI,
    });

    const authUri = oauthClient.authorizeUri({
      scope: [
        OAuthClient.scopes.Accounting,
        OAuthClient.scopes.OpenId,
        OAuthClient.scopes.Profile,
        OAuthClient.scopes.Email,
      ],
      state: "intuit-test",
    });

    console.log("Auth URI:", authUri);
    res.send(authUri);
  } catch (err) {
    console.error("Auth URI Error:", err);
    res.status(500).send("Error generating authUri");
  }
});


app.get("/callback", async (req, res) => {
  try {
    oauthClient = getOAuthClient();
    const authResponse = await oauthClient.createToken(req.url);
    oauth2_token_json = authResponse.getJson();

    // ✅ Ensure realmId is included
    oauth2_token_json.realmId = oauthClient.getToken().realmId;

    res.send(`<script>window.close();</script>`);
  } catch (e) {
    console.error("Callback error", e);
    res.status(400).send("Callback error");
  }
});

app.get("/retrieveToken", (req, res) => {
  if (!oauth2_token_json) {
    return res.status(404).json({ error: "Token not found" });
  }
  res.json({ token: oauth2_token_json });
});

app.post("/refreshAccessToken", async (req, res) => {
  try {
    const refresh_token = req.body.token?.refresh_token;
    const client = getOAuthClient();
    const response = await client.refreshUsingToken(refresh_token);
    oauth2_token_json = response.getJson();
    res.json({ token: oauth2_token_json });
  } catch (error) {
    console.error("Refresh error", error);
    res.status(400).json({ error: "Unable to refresh token" });
  }
});

app.post("/disconnect", async (req, res) => {
  try {
    const access_token = req.body.token?.access_token;
    const client = getOAuthClient();
    await client.revoke({ access_token });
    oauthClient = null;
    oauth2_token_json = null;
    res.json({ result: "Disconnected" });
  } catch (error) {
    console.error("Disconnect error", error);
    res.status(400).json({ error: "Unable to disconnect" });
  }
});

app.post("/create-customer", async (req, res) => {
  try {
    const accessToken = oauth2_token_json.access_token;
    const realmId = oauth2_token_json.realmId;

    const customerPayload = {
      DisplayName: req.body.name || "Test Customer",
      PrimaryEmailAddr: {
        Address: req.body.email || "test@example.com",
      },
    };

    const response = await axios.post(
      `https://sandbox-quickbooks.api.intuit.com/v3/company/${realmId}/customer`,
      customerPayload,
      {
        headers: {
          Authorization: `Bearer ${accessToken}`,
          Accept: "application/json",
          "Content-Type": "application/json",
        },
      }
    );

    res.json(response.data);
  } catch (err) {
    console.error("Error creating customer", err.response?.data || err);
    res.status(500).json({ error: "Failed to create customer" });
  }
});

app.get("/get-customers", async (req, res) => {
  try {
    const accessToken = oauth2_token_json.access_token;
    const realmId = oauth2_token_json.realmId;

    const response = await axios.get(
      `https://sandbox-quickbooks.api.intuit.com/v3/company/${realmId}/query?query=SELECT * FROM Customer`,
      {
        headers: {
          Authorization: `Bearer ${accessToken}`,
          Accept: "application/json",
        },
      }
    );

    res.json(response.data);
  } catch (err) {
    console.error("Error fetching customers", err.response?.data || err);
    res.status(500).json({ error: "Failed to fetch customers" });
  }
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`QuickBooks OAuth server running on port ${PORT}`);
});