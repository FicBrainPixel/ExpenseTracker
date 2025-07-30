import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import bodyParser from "body-parser";
import OAuthClient from "intuit-oauth";
import axios from "axios";
import { v4 as uuidv4 } from "uuid";
import admin from "firebase-admin";

dotenv.config();

// Initialize Firebase Admin SDK

try {
  if (process.env.GOOGLE_APPLICATION_CREDENTIALS_JSON) {
    admin.initializeApp({
      credential: admin.credential.cert(
        JSON.parse(process.env.GOOGLE_APPLICATION_CREDENTIALS_JSON)
      ),
    });
  } else {
    throw new Error("GOOGLE_APPLICATION_CREDENTIALS_JSON not set");
  }
} catch (error) {
  console.error("Firebase Admin initialization failed:", error);
  throw new Error("Firebase Admin SDK initialization failed");
}

const db = admin.firestore();

const app = express();

const allowedOrigins = [
  "https://expensetraker-5cfea.web.app",
  "http://localhost:53371",
];

const corsOptions = {
  origin: function (origin, callback) {
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
    environment: "sandbox",
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

const entityMapping = {
  "categories": "Account",
  "clients": "Customer",
  "employees": "Employee",
  "expenses": "Purchase",
  "merchants": "Item",
  "payment-methods": "PaymentMethod",
  "projects": "Customer",
  "tasks": "TimeActivity",
  "vendors": "Vendor",
  "customers": "Customer"
};

async function fetchEntity(entityName, accessToken, realmId) {
  const response = await axios.get(
    `https://sandbox-quickbooks.api.intuit.com/v3/company/${realmId}/query?query=SELECT * FROM ${entityName}`,
    {
      headers: {
        Authorization: `Bearer ${accessToken}`,
        Accept: "application/json",
      },
    }
  );
  return response.data;
}

app.get("/get-:item", async (req, res) => {
  const item = req.params.item;
  const entityName = entityMapping[item];
  if (!entityName) {
    return res.status(400).json({ error: "Invalid item" });
  }
  try {
    const accessToken = oauth2_token_json.access_token;
    const realmId = oauth2_token_json.realmId;
    const data = await fetchEntity(entityName, accessToken, realmId);
    res.json(data);
  } catch (err) {
    console.error(`Error fetching ${item}`, err.response?.data || err);
    res.status(500).json({ error: `Failed to fetch ${item}` });
  }
});

app.post("/send-invitation", async (req, res) => {
  try {
    const { toEmail, workspaceId, workspaceName, inviterId } = req.body;

    // Validate request body
    if (!toEmail || !workspaceId || !workspaceName || !inviterId) {
      return res.status(400).json({ error: "Missing required fields" });
    }

    // Verify Firebase ID token for authentication
    const idToken = req.headers.authorization?.split("Bearer ")[1];
    if (!idToken) {
      return res
        .status(401)
        .json({ error: "Unauthorized: No ID token provided" });
    }
    await admin.auth().verifyIdToken(idToken);

    // Generate a unique token
    const token = uuidv4();
    const expirationTime = new Date(Date.now() + 24 * 60 * 60 * 1000); // 24 hours

    // Store invitation in Firestore
    await db.collection("invitations").add({
      token,
      workspaceId,
      inviterId,
      inviteeEmail: toEmail,
      expirationTime,
    });

    // Create invitation link
    const invitationLink = `https://expensetraker-5cfea.web.app/invite?token=${token}`;

    // Send email via Resend
    const response = await axios.post(
      "https://api.resend.com/emails",
      {
        from: process.env.RESEND_SENDER_EMAIL,
        to: toEmail,
        subject: "Invitation to Join Workspace",
        text: `You have been invited to join the workspace "${workspaceName}" on the Expense Tracker app.\nClick the link below to accept the invitation:\n${invitationLink}\nThis invitation will expire in 24 hours.`,
      },
      {
        headers: {
          Authorization: `Bearer ${process.env.RESEND_API_KEY}`,
          "Content-Type": "application/json",
        },
      }
    );

    res.json({ success: true, message: "Invitation sent successfully" });
  } catch (error) {
    console.error("Error sending invitation:", error.response?.data || error);
    res.status(500).json({ error: "Failed to send invitation" });
  }
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
