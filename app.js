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

// Sign-in endpoint
app.post('/signin', async (req, res) => {
  const { idToken } = req.body;

  // Input validation
  if (!idToken) {
    return res.status(400).json({ error: 'ID token required' });
  }

  try {
    // Verify ID token
    const decodedToken = await admin.auth().verifyIdToken(idToken);
    const uid = decodedToken.uid;

    // Fetch user data
    const user = await admin.auth().getUser(uid);

    // Update user document in Firestore
    await admin.firestore().collection('users').doc(uid).set(
      {
        email: user.email,
        lastLogin: admin.firestore.FieldValue.serverTimestamp(),
      },
      { merge: true }
    );

    // Return minimal user data
    res.status(200).json({
      uid: user.uid,
      email: user.email,
      displayName: user.displayName || null,
    });
  } catch (error) {
    console.error('Sign-in error:', error);
    res.status(401).json({ error: 'Invalid credentials or unauthorized' });
  }
});

const getOAuthClient = () =>
  new OAuthClient({
    clientId: process.env.QUICKBOOKS_CLIENT_ID,
    clientSecret: process.env.QUICKBOOKS_CLIENT_SECRET,
    environment: "sandbox",
    redirectUri: process.env.QUICKBOOKS_REDIRECT_URI,
  });

// Generate and store a temporary state token
app.post("/authUri", async (req, res) => {
  try {
    const { idToken, workspaceId } = req.body;
    if (!idToken || !workspaceId) {
      return res.status(400).json({ error: "Missing idToken or workspaceId" });
    }

    const decodedToken = await admin.auth().verifyIdToken(idToken);
    const userId = decodedToken.uid;

    const stateToken = uuidv4();
    await db
      .collection("oauthStates")
      .doc(stateToken)
      .set({
        userId,
        workspaceId,
        createdAt: admin.firestore.FieldValue.serverTimestamp(),
        expiresAt: new Date(Date.now() + 10 * 60 * 1000), // 10 minutes
      });

    const oauthClient = getOAuthClient();
    const authUri = oauthClient.authorizeUri({
      scope: [
        OAuthClient.scopes.Accounting,
        OAuthClient.scopes.OpenId,
        OAuthClient.scopes.Profile,
        OAuthClient.scopes.Email,
      ],
      state: stateToken,
    });

    res.json({ authUri });
  } catch (err) {
    console.error("Auth URI Error:", err);
    res.status(500).send("Error generating authUri");
  }
});

app.get("/callback", async (req, res) => {
  try {
    const oauthClient = getOAuthClient();
    const authResponse = await oauthClient.createToken(req.url);
    const tokenJson = authResponse.getJson();
    tokenJson.realmId = oauthClient.getToken().realmId;

    const stateToken = oauthClient.getToken().state;
    const stateDoc = await db.collection("oauthStates").doc(stateToken).get();
    if (!stateDoc.exists) {
      throw new Error("Invalid state token");
    }
    const { workspaceId } = stateDoc.data();

    await db.collection("quickbooksTokens").doc(workspaceId).set({
      workspaceId,
      accessToken: tokenJson.access_token,
      refreshToken: tokenJson.refresh_token,
      expiresIn: tokenJson.expires_in,
      tokenType: tokenJson.token_type,
      realmId: tokenJson.realmId,
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
      updatedAt: admin.firestore.FieldValue.serverTimestamp(),
    });

    await db.collection("oauthStates").doc(stateToken).delete();
    res.send(`<script>window.close();</script>`);
  } catch (e) {
    console.error("Callback error", e);
    res.status(400).send("Callback error");
  }
});

app.post("/checkConnection", async (req, res) => {
  try {
    const { idToken, workspaceId } = req.body;
    if (!idToken || !workspaceId) {
      return res.status(400).json({ error: "Missing idToken or workspaceId" });
    }

    await admin.auth().verifyIdToken(idToken);
    const tokenDoc = await db
      .collection("quickbooksTokens")
      .doc(workspaceId)
      .get();
    if (!tokenDoc.exists) {
      return res.json({ connected: false });
    }

    const tokenData = tokenDoc.data();
    const now = Date.now() / 1000;
    const expiresAt =
      tokenData.createdAt.toDate().getTime() / 1000 + tokenData.expiresIn;

    if (now > expiresAt) {
      const oauthClient = getOAuthClient();
      const response = await oauthClient.refreshUsingToken(
        tokenData.refreshToken
      );
      const newToken = response.getJson();
      await db.collection("quickbooksTokens").doc(workspaceId).update({
        accessToken: newToken.access_token,
        refreshToken: newToken.refresh_token,
        expiresIn: newToken.expires_in,
        updatedAt: admin.firestore.FieldValue.serverTimestamp(),
      });
    }

    res.json({ connected: true });
  } catch (error) {
    console.error("Check connection error", error);
    res.status(500).json({ error: "Failed to check connection" });
  }
});

app.post("/disconnect", async (req, res) => {
  try {
    const { idToken, workspaceId } = req.body;
    if (!idToken || !workspaceId) {
      return res.status(400).json({ error: "Missing idToken or workspaceId" });
    }

    await admin.auth().verifyIdToken(idToken);
    const tokenDoc = await db
      .collection("quickbooksTokens")
      .doc(workspaceId)
      .get();
    if (tokenDoc.exists) {
      const { accessToken } = tokenDoc.data();
      const oauthClient = getOAuthClient();
      await oauthClient.revoke({ access_token: accessToken });
      await db.collection("quickbooksTokens").doc(workspaceId).delete();
    }

    res.json({ result: "Disconnected" });
  } catch (error) {
    console.error("Disconnect error", error);
    res.status(400).json({ error: "Unable to disconnect" });
  }
});

// const entityMapping = {
//   "bank-accounts": "Account",
//   categories: "Account",
//   employees: "Employee",
//   "credit-cards": "Account",
//   vendors: "Vendor",
//   customers: "Customer",
// };

// async function fetchEntity(entityName, accessToken, realmId) {
//   const response = await axios.get(
//     `https://sandbox-quickbooks.api.intuit.com/v3/company/${realmId}/query?query=SELECT * FROM ${entityName}`,
//     {
//       headers: {
//         Authorization: `Bearer ${accessToken}`,
//         Accept: "application/json",
//       },
//     }
//   );
//   return response.data;
// }

const entityMapping = {
  "bank-accounts": { entity: "Account", filter: "WHERE AccountType = 'Bank'" },
  categories: { entity: "Account", filter: "WHERE AccountType = 'Expense'" },
  "credit-cards": {
    entity: "Account",
    filter: "WHERE AccountType = 'Credit Card'",
  },
  employees: { entity: "Employee", filter: "" },
  vendors: { entity: "Vendor", filter: "" },
  customers: { entity: "Customer", filter: "" },
};

async function fetchEntity(entityName, accessToken, realmId) {
  const { entity, filter } = entityMapping[entityName];
  const query = `SELECT * FROM ${entity} ${filter}`.trim();

  try {
    const response = await axios.get(
      `https://sandbox-quickbooks.api.intuit.com/v3/company/${realmId}/query?query=${encodeURIComponent(
        query
      )}`,
      {
        headers: {
          Authorization: `Bearer ${accessToken}`,
          Accept: "application/json",
        },
      }
    );
    return response.data;
  } catch (error) {
    console.error(
      `Error fetching ${entityName}:`,
      error.response?.data || error.message
    );
    throw error;
  }
}

app.post("/get-entity", async (req, res) => {
  const { idToken, workspaceId, entity } = req.body;
  // Check for missing fields and validate entity
  if (!idToken || !workspaceId || !entity) {
    return res.status(400).json({ error: "Missing required fields" });
  }
  if (!entityMapping[entity]) {
    return res.status(400).json({ error: "Invalid entity" });
  }

  try {
    await admin.auth().verifyIdToken(idToken);
    const tokenDoc = await db
      .collection("quickbooksTokens")
      .doc(workspaceId)
      .get();
    if (!tokenDoc.exists) {
      return res.status(401).json({ error: "Not connected to QuickBooks" });
    }

    let { accessToken, refreshToken, expiresIn, createdAt, realmId } =
      tokenDoc.data();
    const now = Date.now() / 1000;
    const expiresAt = createdAt.toDate().getTime() / 1000 + expiresIn;

    if (now > expiresAt) {
      const oauthClient = getOAuthClient();
      const response = await oauthClient.refreshUsingToken(refreshToken);
      const newToken = response.getJson();
      accessToken = newToken.access_token;
      await db.collection("quickbooksTokens").doc(workspaceId).update({
        accessToken: newToken.access_token,
        refreshToken: newToken.refresh_token,
        expiresIn: newToken.expires_in,
        updatedAt: admin.firestore.FieldValue.serverTimestamp(),
      });
    }

    // Pass entity directly to fetchEntity
    const data = await fetchEntity(entity, accessToken, realmId);
    res.json(data);
  } catch (err) {
    console.error(`Error fetching ${entity}`, err.response?.data || err);
    res.status(500).json({ error: `Failed to fetch ${entity}` });
  }
});

// app.post("/create-bills", async (req, res) => {
//   const { idToken, workspaceId, bills } = req.body;
//   if (!idToken || !workspaceId || !Array.isArray(bills) || bills.length === 0) {
//     return res
//       .status(400)
//       .json({ error: "Missing required fields or invalid bills" });
//   }

//   try {
//     await admin.auth().verifyIdToken(idToken);
//     const tokenDoc = await db
//       .collection("quickbooksTokens")
//       .doc(workspaceId)
//       .get();
//     if (!tokenDoc.exists) {
//       return res.status(401).json({ error: "Not connected to QuickBooks" });
//     }

//     let { accessToken, refreshToken, expiresIn, createdAt, realmId } =
//       tokenDoc.data();
//     const now = Date.now() / 1000;
//     const expiresAt = createdAt.toDate().getTime() / 1000 + expiresIn;

//     if (now > expiresAt) {
//       const oauthClient = getOAuthClient();
//       const response = await oauthClient.refreshUsingToken(refreshToken);
//       const newToken = response.getJson();
//       accessToken = newToken.access_token;
//       await db.collection("quickbooksTokens").doc(workspaceId).update({
//         accessToken: newToken.access_token,
//         refreshToken: newToken.refresh_token,
//         expiresIn: newToken.expires_in,
//         updatedAt: admin.firestore.FieldValue.serverTimestamp(),
//       });
//     }

//     const batchRequests = bills.map((bill, idx) => ({
//       bId: `bill${idx + 1}`,
//       operation: "create",
//       Bill: bill,
//     }));

//     const batchPayload = { BatchItemRequest: batchRequests };
//     const url = `https://sandbox-quickbooks.api.intuit.com/v3/company/${realmId}/batch`;
//     const qbResp = await axios.post(url, batchPayload, {
//       headers: {
//         Authorization: `Bearer ${accessToken}`,
//         Accept: "application/json",
//       },
//     });

//     res.json(qbResp.data);
//   } catch (err) {
//     console.error("Error creating bills", err.response?.data || err.message);
//     res.status(500).json({
//       error: err.response?.data || "Failed to create bills in QuickBooks",
//     });
//   }
// });

app.post("/create-bills", async (req, res) => {
  const {
    idToken,
    workspaceId,
    bills = [],
    checks = [],
    expenses = [],
    ccCharges = [],
  } = req.body;

  if (
    !idToken ||
    !workspaceId ||
    ((!Array.isArray(bills) || bills.length === 0) &&
      (!Array.isArray(checks) || checks.length === 0) &&
      (!Array.isArray(expenses) || expenses.length === 0) &&
      (!Array.isArray(ccCharges) || ccCharges.length === 0))
  ) {
    return res
      .status(400)
      .json({ error: "Missing required fields or empty payload" });
  }

  try {
    await admin.auth().verifyIdToken(idToken);
    const tokenDoc = await db
      .collection("quickbooksTokens")
      .doc(workspaceId)
      .get();
    if (!tokenDoc.exists)
      return res.status(401).json({ error: "Not connected to QuickBooks" });

    let { accessToken, refreshToken, expiresIn, createdAt, realmId } =
      tokenDoc.data();
    const now = Date.now() / 1000;
    const expiresAt = createdAt.toDate().getTime() / 1000 + expiresIn;

    if (now > expiresAt) {
      const oauthClient = getOAuthClient();
      const newToken = (
        await oauthClient.refreshUsingToken(refreshToken)
      ).getJson();
      accessToken = newToken.access_token;
      await db.collection("quickbooksTokens").doc(workspaceId).update({
        accessToken,
        refreshToken: newToken.refresh_token,
        expiresIn: newToken.expires_in,
        updatedAt: admin.firestore.FieldValue.serverTimestamp(),
      });
    }

    const batchRequests = [];

    bills.forEach((bill, idx) => {
      batchRequests.push({
        bId: `bill${idx + 1}`,
        operation: "create",
        Bill: bill,
      });
    });

    checks.forEach((check, idx) => {
      batchRequests.push({
        bId: `purchase${idx + 1}`,
        operation: "create",
        Purchase: check,
      });
    });

    expenses.forEach((expense, idx) => {
      if (Object.keys(expense).length > 0) {
        batchRequests.push({
          bId: `expense${idx + 1}`,
          operation: "create",
          Purchase: expense,
        });
      }
    });

    ccCharges.forEach((ccCharge, idx) => {
      if (Object.keys(ccCharge).length > 0) {
        batchRequests.push({
          bId: `ccCharge${idx + 1}`,
          operation: "create",
          Purchase: ccCharge,
        });
      }
    });

    const batchPayload = { BatchItemRequest: batchRequests };
    console.log(JSON.stringify(batchPayload, null, 2));
    const url = `https://sandbox-quickbooks.api.intuit.com/v3/company/${realmId}/batch`;

    const qbResp = await axios.post(url, batchPayload, {
      headers: {
        Authorization: `Bearer ${accessToken}`,
        Accept: "application/json",
        "Content-Type": "application/json",
      },
    });

    res.json(qbResp.data);
  } catch (err) {
    console.error(
      "Error creating bills/checks",
      err.response?.data || err.message
    );
    res
      .status(500)
      .json({ error: err.response?.data || "Failed to create bills/checks" });
  }
});

// Existing /send-invitation and /validate-invite endpoints remain unchanged
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

    const idToken = req.headers.authorization?.split("Bearer ")[1];
    if (!idToken) {
      return res
        .status(401)
        .json({ error: "Unauthorized: No ID token provided" });
    }
    await admin.auth().verifyIdToken(idToken);

    const token = uuidv4();
    const expirationTime = new Date(Date.now() + 24 * 60 * 60 * 1000);

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

    const invitationLink = `${process.env.WEB_URL}/invite?token=${token}`;
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
    if (!token) {
      return res
        .status(400)
        .json({ valid: false, message: "Token is required" });
    }

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

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
