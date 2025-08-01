import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import bodyParser from "body-parser";
import OAuthClient from "intuit-oauth";
import axios from "axios";
import { v4 as uuidv4 } from "uuid";
import admin from "firebase-admin";

dotenv.config();

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

// Initialize Firebase Admin SDK
const db = admin.firestore();

const app = express();

const allowedOrigins = [
  "https://corpexpense.flashcubeit.com",
  "https://expensetraker-5cfea.web.app",
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

app.get("/oauthClient-null", function (req, res) {
  try {
    oauthClient = getOAuthClient();

    res.status(200).json({
      message: "done",
    });
  } catch (err) {
    console.error("Error:", err);
    res.status(500).send("Error setting OAuth");
  }
});

app.get("/authUri", (req, res) => {
  try {
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
  try {
    res.send(oauthClient);
  } catch (err) {
    res.status(500).json({ error: "Unable to retrive token" });
  }
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

const entityMapping = {
  categories: "Account",
  employees: "Employee",
  "payment-methods": "PaymentMethod",
  vendors: "Vendor",
  customers: "Customer",
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
    const {
      workspaceId,
      workspaceName,
      inviterId,
      inviteeName,
      inviteeEmail,
      inviteeRole,
    } = req.body;

    // Validate request body
    if (
      !workspaceId ||
      !workspaceName ||
      !inviterId ||
      !inviteeName ||
      !inviteeEmail ||
      !inviteeRole
    ) {
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
      token: token,
      used: false,
      workspaceId: workspaceId,
      workspaceName: workspaceName,
      inviterId: inviterId,
      inviteeName: inviteeName,
      inviteeEmail: inviteeEmail,
      inviteeRole: inviteeRole,
      expirationTime: expirationTime,
    });

    // Create invitation link
    const invitationLink = `${process.env.WEB_URL}/invite?token=${token}`;

    // Send email via Resend
    const response = await axios.post(
      "https://api.resend.com/emails",
      {
        from: process.env.RESEND_SENDER_EMAIL,
        to: inviteeEmail,
        subject: "Invitation to Join Workspace",
        text: `You have been invited to join the workspace "${workspaceName}" on the CorpExpense.\nClick the link below to accept the invitation:\n${invitationLink}\nThis invitation will expire in 24 hours.`,
      },
      {
        headers: {
          Authorization: `Bearer ${process.env.RESEND_API_KEY}`,
          "Content-Type": "application/json",
        },
      }
    );

    res.json({
      success: true,
      message: "Invitation sent successfully",
      response: response.data,
    });
  } catch (error) {
    console.error("Error sending invitation:", error.response?.data || error);
    res.status(500).json({ error: "Failed to send invitation" });
  }
});

app.post("/validate-invite", async (req, res) => {
  try {
    const { token } = req.body;

    // Check if token is provided
    if (!token) {
      return res
        .status(400)
        .json({ valid: false, message: "Token is required" });
    }

    // Query Firestore for the token
    const snapshot = await db
      .collection("invitations")
      .where("token", "==", token)
      .limit(1)
      .get();

    if (snapshot.empty) {
      return res.status(404).json({ valid: false, message: "Invalid token" });
    }

    const doc = snapshot.docs[0];
    const data = doc.data();

    // Check expiration
    const now = new Date();
    const expires =
      data.expirationTime?.toDate?.() || new Date(data.expirationTime);
    if (expires < now) {
      return res.status(410).json({ valid: false, message: "Token expired" });
    }

    if (data.used) {
      return res
        .status(409)
        .json({ valid: false, message: "Token already used" });
    }

    // Success — return invite details for registration
    return res.json({
      valid: true,
      workspaceId: data.workspaceId,
      workspaceName: data.workspaceName,
      inviterId: data.inviterId,
      inviteeName: data.inviteeName,
      inviteeEmail: data.inviteeEmail,
      inviteeRole: data.inviteeRole,
    });
  } catch (error) {
    console.error("Error validating invitation:", error);
    return res.status(500).json({ valid: false, message: "Server error" });
  }
});

app.post("/sync-to-qb", async (req, res) => {
  const idToken = req.headers.authorization?.split('Bearer ')[1];

  try {
    const decoded = await admin.auth().verifyIdToken(idToken);
    const userId = decoded.uid;

    // Optional: Check if user is admin of workspace, etc.
    if (!userIsAuthorized(userId)) {
      return res.status(403).json({ error: "Forbidden" });
    }

    await syncExpensesToQuickBooks(userId);
    res.json({ success: true });
  } catch (err) {
    return res.status(401).json({ error: "Unauthorized" });
  }
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
