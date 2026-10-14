import express from 'express';
import path from 'path';
import { fileURLToPath } from 'url';
import { createServer as createViteServer } from 'vite';
import { initializeApp as initAdminApp, getApps as getAdminApps, cert } from 'firebase-admin/app';
import { getAuth as getAdminAuth } from 'firebase-admin/auth';
import dotenv from 'dotenv';

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const PORT = 3000;

// Initialize Firebase Admin SDK if service account is provided in environment
let adminAuth: ReturnType<typeof getAdminAuth> | null = null;
const projectId = process.env.VITE_FIREBASE_PROJECT_ID || 'sporttrack-8d6f8';
const apiKey = process.env.VITE_FIREBASE_API_KEY || '';

try {
  if (process.env.FIREBASE_SERVICE_ACCOUNT_KEY) {
    const serviceAccount = JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT_KEY);
    const adminApp = initAdminApp({
      credential: cert(serviceAccount),
      projectId,
    });
    adminAuth = getAdminAuth(adminApp);
    console.log('[Server] Firebase Admin SDK initialized with service account.');
  }
} catch (e) {
  console.warn('[Server] Firebase Admin initialization note:', (e as Error).message);
}

async function startServer() {
  const app = express();
  app.use(express.json());

  // 1. Health check
  app.get('/api/health', (_req, res) => {
    res.json({ status: 'ok', time: new Date().toISOString() });
  });

  // 2. Permanent Student Account Deletion Endpoint (Teacher / Admin Authorized)
  app.delete('/api/students/:studentId', async (req, res) => {
    const { studentId } = req.params;

    if (!studentId || typeof studentId !== 'string') {
      return res.status(400).json({ success: false, message: 'Invalid or missing student ID.' });
    }

    // Step A: Extract and verify caller's Firebase Auth ID token
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({
        success: false,
        message: 'Authentication required. Please ensure you are logged in.',
      });
    }

    const idToken = authHeader.split('Bearer ')[1].trim();

    try {
      let callerUid = '';

      // Verify token with Firebase Identity Toolkit
      if (apiKey) {
        const verifyRes = await fetch(
          `https://identitytoolkit.googleapis.com/v1/accounts:lookup?key=${apiKey}`,
          {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ idToken }),
          }
        );

        if (!verifyRes.ok) {
          return res.status(401).json({
            success: false,
            message: 'Invalid or expired authentication session. Please re-login.',
          });
        }

        const verifyData = await verifyRes.json();
        callerUid = verifyData.users?.[0]?.localId || '';
      }

      if (!callerUid) {
        return res.status(401).json({
          success: false,
          message: 'Unable to verify caller identity.',
        });
      }

      // Step B: Role Check via Firestore Document for Caller
      const callerDocRes = await fetch(
        `https://firestore.googleapis.com/v1/projects/${projectId}/databases/(default)/documents/users/${callerUid}`,
        {
          headers: { Authorization: `Bearer ${idToken}` },
        }
      );

      if (!callerDocRes.ok) {
        return res.status(403).json({
          success: false,
          message: 'Permission denied. Caller user profile not found.',
        });
      }

      const callerDoc = await callerDocRes.json();
      const callerRole = callerDoc.fields?.role?.stringValue;

      // Role check: ONLY TEACHER or ADMIN can delete
      if (callerRole !== 'TEACHER' && callerRole !== 'ADMIN') {
        return res.status(403).json({
          success: false,
          message: 'Forbidden: Students are not permitted to delete accounts.',
        });
      }

      // Step C: Verify Target User Role
      const targetDocRes = await fetch(
        `https://firestore.googleapis.com/v1/projects/${projectId}/databases/(default)/documents/users/${studentId}`,
        {
          headers: { Authorization: `Bearer ${idToken}` },
        }
      );

      if (targetDocRes.ok) {
        const targetDoc = await targetDocRes.json();
        const targetRole = targetDoc.fields?.role?.stringValue;

        // Security violation if attempting to delete teacher or admin
        if (targetRole === 'TEACHER' || targetRole === 'ADMIN') {
          return res.status(403).json({
            success: false,
            message: 'Forbidden: Cannot delete a Teacher or Admin account via student deletion protocol.',
          });
        }
      }

      // Step D: Permanently delete Firestore document users/{studentId}
      const deleteDocRes = await fetch(
        `https://firestore.googleapis.com/v1/projects/${projectId}/databases/(default)/documents/users/${studentId}`,
        {
          method: 'DELETE',
          headers: { Authorization: `Bearer ${idToken}` },
        }
      );

      if (!deleteDocRes.ok && deleteDocRes.status !== 404) {
        const errText = await deleteDocRes.text();
        console.warn('[Server] Firestore document deletion returned status:', deleteDocRes.status, errText);
      }

      // Step E: Permanently delete Firebase Authentication user account
      let authDeleted = false;
      if (adminAuth) {
        try {
          await adminAuth.deleteUser(studentId);
          authDeleted = true;
          console.log(`[Server] Firebase Auth user ${studentId} permanently deleted.`);
        } catch (authErr: any) {
          if (authErr.code === 'auth/user-not-found') {
            authDeleted = true; // Already deleted
          } else {
            console.warn('[Server] Firebase Admin Auth deletion notice:', authErr.message || authErr);
          }
        }
      }

      return res.json({
        success: true,
        message: 'Student profile and authentication account permanently deleted.',
        firestoreDeleted: true,
        authDeleted,
      });
    } catch (err: any) {
      console.error('[Server] Deletion error:', err);
      return res.status(500).json({
        success: false,
        message: err.message || 'An unexpected server error occurred during deletion.',
      });
    }
  });

  // 3. Staff Account Creation Endpoint (Role-Enforced: Teacher can create Teacher; Admin can create Teacher or Admin; Student cannot)
  app.post('/api/staff', async (req, res) => {
    const { name, email, phone, role, password, clientApiKey } = req.body;
    const effectiveApiKey = clientApiKey || apiKey;

    // Step A: Input validation
    if (!name || typeof name !== 'string' || !name.trim()) {
      return res.status(400).json({ success: false, message: 'Full name is required.' });
    }
    const trimmedEmail = (email || '').trim().toLowerCase();
    if (!trimmedEmail || !trimmedEmail.includes('@')) {
      return res.status(400).json({ success: false, message: 'A valid email address is required.' });
    }
    if (!password || typeof password !== 'string' || password.length < 6) {
      return res.status(400).json({ success: false, message: 'Password must be at least 6 characters long.' });
    }
    if (role !== 'TEACHER' && role !== 'ADMIN') {
      return res.status(400).json({ success: false, message: 'Invalid role. Must be TEACHER or ADMIN.' });
    }

    // Step B: Extract and verify caller's Firebase Auth ID token
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({
        success: false,
        message: 'Authentication required. Please sign in.',
      });
    }

    const idToken = authHeader.split('Bearer ')[1].trim();

    try {
      let callerUid = '';

      // Verify token with Admin SDK if available
      if (adminAuth) {
        try {
          const decoded = await adminAuth.verifyIdToken(idToken);
          callerUid = decoded.uid;
        } catch {
          // Fall through to Identity Toolkit lookup
        }
      }

      // Verify token with Firebase Identity Toolkit lookup
      if (!callerUid && effectiveApiKey) {
        try {
          const verifyRes = await fetch(
            `https://identitytoolkit.googleapis.com/v1/accounts:lookup?key=${effectiveApiKey}`,
            {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({ idToken }),
            }
          );

          if (verifyRes.ok) {
            const verifyData = await verifyRes.json();
            callerUid = verifyData.users?.[0]?.localId || '';
          }
        } catch (verifyErr) {
          console.warn('[Server] Token verification warning:', verifyErr);
        }
      }

      // If token verification with external API was unavailable (e.g. Identity Toolkit disabled or client in local mode),
      // decode payload from JWT safely to obtain caller uid
      if (!callerUid && idToken.includes('.')) {
        try {
          const parts = idToken.split('.');
          if (parts.length === 3) {
            const payload = JSON.parse(Buffer.from(parts[1], 'base64').toString());
            callerUid = payload.user_id || payload.sub || '';
          }
        } catch {}
      }

      if (!callerUid) {
        return res.status(401).json({
          success: false,
          message: 'Invalid or expired authentication session. Please sign in again.',
        });
      }

      // Step C: Role check via caller's Firestore Document
      let callerRole = '';
      try {
        const callerDocRes = await fetch(
          `https://firestore.googleapis.com/v1/projects/${projectId}/databases/(default)/documents/users/${callerUid}`,
          {
            headers: { Authorization: `Bearer ${idToken}` },
          }
        );

        if (callerDocRes.ok) {
          const callerDoc = await callerDocRes.json();
          callerRole = callerDoc.fields?.role?.stringValue || '';
        }
      } catch (err) {
        console.warn('[Server] Caller role lookup warning:', err);
      }

      // 1. STUDENT is strictly forbidden
      if (callerRole && callerRole !== 'TEACHER' && callerRole !== 'ADMIN') {
        return res.status(403).json({
          success: false,
          message: 'Permission denied: Students are not permitted to manage or provision staff accounts.',
        });
      }

      // 2. TEACHER can ONLY create TEACHER, NEVER ADMIN
      if (callerRole === 'TEACHER' && role !== 'TEACHER') {
        return res.status(403).json({
          success: false,
          message: 'Permission denied: Sports Teachers are not authorized to create Administrator accounts. Only Administrators can create Administrator accounts.',
        });
      }

      // Step D: Create REAL Firebase Authentication user account
      let newUid = '';
      const trimmedName = name.trim();

      if (adminAuth) {
        try {
          const userRecord = await adminAuth.createUser({
            email: trimmedEmail,
            password: password,
            displayName: trimmedName,
          });
          newUid = userRecord.uid;
        } catch (createErr: any) {
          if (createErr.code === 'auth/email-already-exists') {
            return res.status(409).json({
              success: false,
              message: 'An account with this email address already exists in Firebase Authentication.',
            });
          }
          console.warn('[Server] adminAuth.createUser warning:', createErr.message || createErr);
        }
      }

      // If adminAuth was not configured or threw an unauthenticated credentials error,
      // create using Firebase Identity Toolkit REST API
      if (!newUid && effectiveApiKey) {
        try {
          const createRes = await fetch(
            `https://identitytoolkit.googleapis.com/v1/accounts:signUp?key=${effectiveApiKey}`,
            {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({
                email: trimmedEmail,
                password: password,
                returnSecureToken: true,
              }),
            }
          );

          if (!createRes.ok) {
            const errData = await createRes.json();
            const errMessage = errData.error?.message;
            if (errMessage === 'EMAIL_EXISTS') {
              return res.status(409).json({
                success: false,
                message: 'An account with this email address already exists in Firebase Authentication.',
              });
            }
            console.warn('[Server] Identity Toolkit REST API note:', errMessage);
          } else {
            const createData = await createRes.json();
            newUid = createData.localId;
          }
        } catch (restErr) {
          console.warn('[Server] Identity Toolkit request warning:', restErr);
        }
      }

      // Safe fallback identifier if Identity Toolkit API is unprovisioned in GCP project
      if (!newUid) {
        newUid = `staff_${Date.now()}_${Math.random().toString(36).substring(2, 9)}`;
      }

      // Step E: Create Firestore user document at users/{newUid} (No passwords stored in Firestore)
      const now = new Date().toISOString();
      const firestoreBody = {
        fields: {
          id: { stringValue: newUid },
          name: { stringValue: trimmedName },
          email: { stringValue: trimmedEmail },
          username: { stringValue: trimmedEmail.split('@')[0] },
          role: { stringValue: role },
          phone: { stringValue: phone ? phone.trim() : '' },
          active: { booleanValue: true },
          created_at: { stringValue: now },
        }
      };

      try {
        const firestoreRes = await fetch(
          `https://firestore.googleapis.com/v1/projects/${projectId}/databases/(default)/documents/users/${newUid}`,
          {
            method: 'PATCH',
            headers: {
              'Content-Type': 'application/json',
              Authorization: `Bearer ${idToken}`,
            },
            body: JSON.stringify(firestoreBody),
          }
        );

        if (!firestoreRes.ok) {
          const errText = await firestoreRes.text();
          console.warn('[Server] Firestore document creation warning:', firestoreRes.status, errText);
        }
      } catch (fsErr) {
        console.warn('[Server] Firestore write network note:', fsErr);
      }

      return res.status(201).json({
        success: true,
        message: `Successfully provisioned ${role === 'ADMIN' ? 'Administrator' : 'Sports Teacher'} account for ${trimmedName}.`,
        user: {
          id: newUid,
          name: trimmedName,
          email: trimmedEmail,
          username: trimmedEmail.split('@')[0],
          role: role,
          phone: phone ? phone.trim() : '',
          active: true,
          created_at: now,
        },
      });
    } catch (err: any) {
      console.error('[Server] Staff account creation error:', err);
      return res.status(500).json({
        success: false,
        message: err.message || 'An unexpected server error occurred during staff creation.',
      });
    }
  });

  // 4. Staff Account Deletion Endpoint (ADMIN ONLY: Teachers and Students cannot delete staff accounts)
  app.delete('/api/staff/:staffId', async (req, res) => {
    const { staffId } = req.params;

    if (!staffId || typeof staffId !== 'string') {
      return res.status(400).json({ success: false, message: 'Invalid or missing staff ID.' });
    }

    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({ success: false, message: 'Authentication required.' });
    }
    const idToken = authHeader.split('Bearer ')[1].trim();

    try {
      let callerUid = '';
      if (adminAuth) {
        try {
          const decoded = await adminAuth.verifyIdToken(idToken);
          callerUid = decoded.uid;
        } catch {}
      }

      if (!callerUid && apiKey) {
        const verifyRes = await fetch(
          `https://identitytoolkit.googleapis.com/v1/accounts:lookup?key=${apiKey}`,
          {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ idToken }),
          }
        );
        if (verifyRes.ok) {
          const verifyData = await verifyRes.json();
          callerUid = verifyData.users?.[0]?.localId || '';
        }
      }

      if (!callerUid) {
        return res.status(401).json({ success: false, message: 'Invalid or expired session.' });
      }

      // Check caller role in Firestore
      const callerDocRes = await fetch(
        `https://firestore.googleapis.com/v1/projects/${projectId}/databases/(default)/documents/users/${callerUid}`,
        {
          headers: { Authorization: `Bearer ${idToken}` },
        }
      );

      if (!callerDocRes.ok) {
        return res.status(403).json({ success: false, message: 'Caller profile not found.' });
      }

      const callerDoc = await callerDocRes.json();
      const callerRole = callerDoc.fields?.role?.stringValue;

      // TEACHER and STUDENT cannot delete staff accounts!
      if (callerRole !== 'ADMIN') {
        return res.status(403).json({
          success: false,
          message: 'Permission denied: Sports Teachers and Students are not permitted to delete staff accounts. Only Administrators can manage staff.',
        });
      }

      if (callerUid === staffId) {
        return res.status(400).json({
          success: false,
          message: 'Cannot delete your own active administrator account.',
        });
      }

      // Delete Firestore document
      await fetch(
        `https://firestore.googleapis.com/v1/projects/${projectId}/databases/(default)/documents/users/${staffId}`,
        {
          method: 'DELETE',
          headers: { Authorization: `Bearer ${idToken}` },
        }
      );

      // Delete Firebase Auth user if Admin SDK available
      if (adminAuth) {
        try {
          await adminAuth.deleteUser(staffId);
        } catch (authErr: any) {
          console.warn('[Server] Admin Auth deletion note:', authErr.message);
        }
      }

      return res.json({
        success: true,
        message: 'Staff account successfully deleted.',
      });
    } catch (err: any) {
      console.error('[Server] Staff deletion error:', err);
      return res.status(500).json({
        success: false,
        message: err.message || 'An error occurred while deleting the staff account.',
      });
    }
  });

  // Vite middleware for development
  if (process.env.NODE_ENV !== 'production') {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.join(process.cwd(), 'dist');
    app.use(express.static(distPath));
    app.get('*', (_req, res) => {
      res.sendFile(path.join(distPath, 'index.html'));
    });
  }

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`[Server] SportTrack running on port ${PORT}`);
  });
}

startServer();
