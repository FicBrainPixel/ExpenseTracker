import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import bodyParser from "body-parser";
import OAuthClient from "intuit-oauth";

const app = express();
dotenv.config();

app.use(cors());
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
  oauthClient = getOAuthClient();
  const authUri = oauthClient.authorizeUri({
    scope: [
      OAuthClient.scopes.Accounting,
      OAuthClient.scopes.OpenId,
      OAuthClient.scopes.Profile,
      OAuthClient.scopes.Email,
    ],
    state: "intuit-test",
  });
  res.send(authUri);
});

app.get("/callback", async (req, res) => {
  try {
    oauthClient = getOAuthClient();
    const authResponse = await oauthClient.createToken(req.url);
    oauth2_token_json = authResponse.getJson();
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

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`QuickBooks OAuth server running on port ${PORT}`);
});