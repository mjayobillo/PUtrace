// =============================================
// PUTrace - Campus Lost & Found QR System
// Built with: Node.js, Express, EJS, Supabase
// =============================================

const path = require("path");
const crypto = require("crypto");
const express = require("express");
const session = require("express-session");
const bcrypt = require("bcryptjs");
const QRCode = require("qrcode");
const multer = require("multer");
const sharp = require("sharp");
const { createClient } = require("@supabase/supabase-js");
require("dotenv").config();

// ── Setup ──

const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 5 * 1024 * 1024 } }); // 5MB max
const app = express();
const PORT = process.env.PORT || 5000;
const BASE_URL = process.env.BASE_URL || `http://localhost:${PORT}`;

// Connect to Supabase database
const supabase = createClient(process.env.SUPABASE_URL || "", process.env.SUPABASE_SERVICE_ROLE_KEY || "");

// Item categories for dropdowns
const CATEGORIES = ["Electronics", "ID / Cards", "Clothing", "Bags", "Bottles", "Books", "Accessories", "Keys", "Other"];
const ITEM_STATUS = { ACTIVE: "active", LOST: "lost", RECOVERED: "recovered" };
const ITEM_STATUS_VALUES = Object.values(ITEM_STATUS);
const REPORT_STATUS = { OPEN: "open", RESOLVED: "resolved" };
const ALLOWED_EMAIL_DOMAIN = "panpacificu.edu.ph";

// ── Helper Functions ──

// Remove extra spaces from user input
function sanitize(str) {
  return (str || "").trim();
}

// Check if email format is valid
function isValidEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

// Restrict emails to school domain
function isSchoolEmail(email) {
  const normalized = String(email || "").toLowerCase();
  return isValidEmail(normalized) && normalized.endsWith(`@${ALLOWED_EMAIL_DOMAIN}`);
}

// Generate a random token for QR codes
function generateToken() {
  return crypto.randomBytes(16).toString("hex");
}

// Hash tokens before storing in DB
function hashToken(token) {
  return crypto.createHash("sha256").update(String(token || "")).digest("hex");
}

function buildResetLink(token) {
  return `${BASE_URL}/reset-password/${token}`;
}

// Send password reset email (uses Gmail via nodemailer when configured, otherwise logs link)
async function sendPasswordResetEmail(email, resetLink) {
  const gmailUser = process.env.GMAIL_USER || "";
  const gmailPass = process.env.GMAIL_PASS || "";

  if (!gmailUser || !gmailPass) {
    console.log(`[PUTrace password reset link] ${email}: ${resetLink}`);
    return false;
  }

  try {
    const nodemailer = require("nodemailer");
    const transporter = nodemailer.createTransport({
      service: "gmail",
      auth: { user: gmailUser, pass: gmailPass }
    });
    await transporter.sendMail({
      from: `"PUTrace" <${gmailUser}>`,
      to: email,
      subject: "PUTrace Password Reset",
      html: `<p>You requested a password reset for PUTrace.</p>
             <p><a href="${resetLink}">Reset your password</a></p>
             <p>This link expires in 30 minutes.</p>
             <p>If you did not request this, you can ignore this email.</p>`
    });
    return true;
  } catch (err) {
    console.error("Password reset email error:", err);
    return false;
  }
}

async function getValidResetTokenRecord(rawToken) {
  const tokenHash = hashToken(rawToken);
  const nowIso = new Date().toISOString();
  const { data } = await supabase
    .from("password_reset_tokens")
    .select("id, user_id, expires_at, used_at, created_at")
    .eq("token_hash", tokenHash)
    .is("used_at", null)
    .gt("expires_at", nowIso)
    .order("created_at", { ascending: false })
    .limit(1)
    .maybeSingle();
  return data || null;
}

// Make filenames safe for downloads
function safeFileName(value) {
  return (value || "item").replace(/[^a-z0-9-_]/gi, "-").toLowerCase();
}

// Upload an image to Supabase Storage (compress first)
async function uploadImage(fileBuffer, prefix) {
  const compressed = await sharp(fileBuffer)
    .resize(800, 800, { fit: "inside", withoutEnlargement: true })
    .jpeg({ quality: 75 })
    .toBuffer();

  const fileName = `${prefix}-${generateToken()}.jpg`;
  const { error } = await supabase.storage
    .from("item-images")
    .upload(fileName, compressed, { contentType: "image/jpeg", upsert: false });

  if (error) return null;

  const { data } = supabase.storage.from("item-images").getPublicUrl(fileName);
  return data.publicUrl;
}

// ── Express Config ──

app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, "static")));
app.use(
  session({
    secret: process.env.SESSION_SECRET || "dev-secret-change-me",
    resave: false,
    saveUninitialized: false,
    cookie: { maxAge: 1000 * 60 * 60 * 24 } // 24 hours
  })
);

// ── Middleware ──

// Load current user and flash messages for every page
app.use(async (req, res, next) => {
  res.locals.currentUser = null;
  res.locals.flash = req.session.flash || null;
  res.locals.currentPath = req.path || "/";
  delete req.session.flash;

  if (req.session.userId) {
    const { data } = await supabase
      .from("users")
      .select("id, full_name, email")
      .eq("id", req.session.userId)
      .single();
    res.locals.currentUser = data || null;

    // Count open finder reports for the Messages nav badge
    const { data: userItems } = await supabase
      .from("items")
      .select("id")
      .eq("user_id", req.session.userId);
    const ownedIds = (userItems || []).map((i) => i.id);
    let unread = 0;
    if (ownedIds.length > 0) {
      // Get IDs of open reports on owned items
      const { data: openReports } = await supabase
        .from("finder_reports")
        .select("id")
        .in("item_id", ownedIds)
        .eq("status", "open");
      const openReportIds = (openReports || []).map((r) => r.id);
      if (openReportIds.length > 0) {
        // Count messages in those threads sent by finders (not by the owner)
        const { count } = await supabase
          .from("report_messages")
          .select("id", { count: "exact", head: true })
          .in("report_id", openReportIds)
          .neq("sender_user_id", req.session.userId);
        unread = count || 0;
      }
    }
    res.locals.unreadMessagesCount = unread;
  }
  next();
});

// Show a one-time message (success or error)
function setFlash(req, type, message) {
  req.session.flash = { type, message };
}

// Set flash and redirect in one line
function flashRedirect(req, res, path, type, message) {
  setFlash(req, type, message);
  return res.redirect(path);
}

// Keep category values consistent
function normalizeCategory(category) {
  return CATEGORIES.includes(category) ? category : "Other";
}

// Shared search helper for simple text filtering
function filterBySearch(rows, search, fields) {
  const list = rows || [];
  const query = sanitize(search).toLowerCase();
  if (!query) return list;

  return list.filter((row) =>
    fields.some((field) => String(row[field] || "").toLowerCase().includes(query))
  );
}

// Shared validation for finder/sighting reports
function getReportValidationError(name, email, message) {
  if (name.length < 2) return "Name is too short.";
  if (!isValidEmail(email)) return "Invalid email.";
  if (message.length < 3) return "Message is too short.";
  return null;
}

// Load an item only if it belongs to the logged-in user
async function getOwnedItem(req, itemId, columns = "id, user_id") {
  const { data: item } = await supabase.from("items").select(columns).eq("id", itemId).maybeSingle();
  if (!item || item.user_id !== req.session.userId) return null;
  return item;
}

// Ensure logged-in user can access the report thread (item owner or finder email match)
async function getAccessibleReportContext(req, res, reportId) {
  const id = Number(reportId);
  if (!Number.isFinite(id)) return { error: "not_found" };

  const { data: report } = await supabase
    .from("finder_reports")
    .select("id, item_id, finder_name, finder_email, message, status, created_at")
    .eq("id", id)
    .maybeSingle();
  if (!report) return { error: "not_found" };

  const { data: item } = await supabase.from("items").select("id, user_id, item_name").eq("id", report.item_id).maybeSingle();
  if (!item) return { error: "not_found" };

  const { data: owner } = await supabase.from("users").select("id, full_name, email").eq("id", item.user_id).maybeSingle();
  if (!owner) return { error: "not_found" };

  const currentUser = res.locals.currentUser || null;
  if (!currentUser) return { error: "forbidden" };

  const currentEmail = String(currentUser.email || "").toLowerCase();
  const finderEmail = String(report.finder_email || "").toLowerCase();
  const isOwner = currentUser.id === item.user_id;
  const isFinder = currentEmail === finderEmail;

  if (!isOwner && !isFinder) return { error: "forbidden" };
  return { report, item, owner, currentUser, isOwner, isFinder };
}

// Block access if not logged in
function requireAuth(req, res, next) {
  if (!req.session.userId) {
    setFlash(req, "error", "Please login first.");
    return res.redirect("/login");
  }
  next();
}

// ── Home Page ──

app.get("/", (req, res) => res.render("home"));

// ── Sign Up ──

app.get("/signup", (req, res) => res.render("signup"));

app.post("/signup", async (req, res) => {
  try {
    const full_name = sanitize(req.body.full_name);
    const email = sanitize(req.body.email).toLowerCase();
    const password = req.body.password || "";
    const confirm_password = req.body.confirm_password || "";

    // Validate inputs
    if (full_name.length < 2 || full_name.length > 100) {
      setFlash(req, "error", "Full name must be 2–100 characters.");
      return res.redirect("/signup");
    }
    if (!isValidEmail(email)) {
      setFlash(req, "error", "Please enter a valid email address.");
      return res.redirect("/signup");
    }
    if (!isSchoolEmail(email)) {
      setFlash(req, "error", `Use your school email (@${ALLOWED_EMAIL_DOMAIN}).`);
      return res.redirect("/signup");
    }
    if (password.length < 8) {
      setFlash(req, "error", "Password must be at least 8 characters.");
      return res.redirect("/signup");
    }
    if (password !== confirm_password) {
      setFlash(req, "error", "Passwords do not match.");
      return res.redirect("/signup");
    }

    // Check if email already exists
    const { data: exists } = await supabase.from("users").select("id").eq("email", email).maybeSingle();
    if (exists) {
      setFlash(req, "error", "Email already registered.");
      return res.redirect("/signup");
    }

    // Hash password and create account
    const password_hash = await bcrypt.hash(password, 10);
    const { error } = await supabase.from("users").insert({ full_name, email, password_hash });

    if (error) {
      setFlash(req, "error", "Signup failed. Please try again.");
      return res.redirect("/signup");
    }

    setFlash(req, "success", "Account created. Please login.");
    return res.redirect("/login");
  } catch (err) {
    console.error("Signup error:", err);
    setFlash(req, "error", "Something went wrong.");
    return res.redirect("/signup");
  }
});

// ── Login / Logout ──

app.get("/login", (req, res) => res.render("login", { loginConfirmed: false, redirectTo: "" }));

app.post("/login", async (req, res) => {
  try {
    const email = (req.body.email || "").toLowerCase().trim();
    const password = req.body.password || "";
    if (!isSchoolEmail(email)) {
      setFlash(req, "error", `Use your school email (@${ALLOWED_EMAIL_DOMAIN}).`);
      return res.redirect("/login");
    }

    // Find user by email
    const { data: user } = await supabase.from("users").select("*").eq("email", email).maybeSingle();
    if (!user) {
      setFlash(req, "error", "Invalid email or password.");
      return res.redirect("/login");
    }

    // Check password
    const ok = await bcrypt.compare(password, user.password_hash);
    if (!ok) {
      setFlash(req, "error", "Invalid email or password.");
      return res.redirect("/login");
    }

    // Save user session
    req.session.userId = user.id;
    return res.render("login", { loginConfirmed: true, redirectTo: "/dashboard" });
  } catch (err) {
    console.error("Login error:", err);
    setFlash(req, "error", "Something went wrong.");
    return res.redirect("/login");
  }
});

app.get("/forgot-password", (req, res) => res.render("forgot_password"));

app.post("/forgot-password", async (req, res) => {
  try {
    const email = sanitize(req.body.email).toLowerCase();
    if (!isSchoolEmail(email)) {
      return flashRedirect(req, res, "/forgot-password", "error", `Use your school email (@${ALLOWED_EMAIL_DOMAIN}).`);
    }

    const { data: user } = await supabase.from("users").select("id, email").eq("email", email).maybeSingle();
    if (user) {
      const rawToken = crypto.randomBytes(32).toString("hex");
      const tokenHash = hashToken(rawToken);
      const expiresAt = new Date(Date.now() + 30 * 60 * 1000).toISOString();

      await supabase.from("password_reset_tokens").insert({
        user_id: user.id,
        token_hash: tokenHash,
        expires_at: expiresAt
      });

      const resetLink = buildResetLink(rawToken);
      await sendPasswordResetEmail(email, resetLink);
    }

    return flashRedirect(req, res, "/login", "success", "If your account exists, a password reset link has been sent.");
  } catch (err) {
    console.error("Forgot password error:", err);
    return flashRedirect(req, res, "/forgot-password", "error", "Something went wrong.");
  }
});

app.get("/reset-password/:token", async (req, res) => {
  try {
    const record = await getValidResetTokenRecord(req.params.token);
    if (!record) return flashRedirect(req, res, "/forgot-password", "error", "This reset link is invalid or expired.");
    return res.render("reset_password", { token: req.params.token });
  } catch (err) {
    console.error("Reset password page error:", err);
    return flashRedirect(req, res, "/forgot-password", "error", "Something went wrong.");
  }
});

app.post("/reset-password/:token", async (req, res) => {
  try {
    const { new_password, confirm_new_password } = req.body;
    if (!new_password || new_password.length < 8) {
      return flashRedirect(req, res, `/reset-password/${req.params.token}`, "error", "New password must be at least 8 characters.");
    }
    if (new_password !== (confirm_new_password || "")) {
      return flashRedirect(req, res, `/reset-password/${req.params.token}`, "error", "New passwords do not match.");
    }

    const record = await getValidResetTokenRecord(req.params.token);
    if (!record) return flashRedirect(req, res, "/forgot-password", "error", "This reset link is invalid or expired.");

    const hash = await bcrypt.hash(new_password, 10);
    await supabase.from("users").update({ password_hash: hash }).eq("id", record.user_id);
    await supabase.from("password_reset_tokens").update({ used_at: new Date().toISOString() }).eq("id", record.id);

    return flashRedirect(req, res, "/login", "success", "Password reset complete. You can now sign in.");
  } catch (err) {
    console.error("Reset password submit error:", err);
    return flashRedirect(req, res, `/reset-password/${req.params.token}`, "error", "Something went wrong.");
  }
});

app.get("/logout", (req, res) => {
  req.session.destroy(() => {
    res.redirect("/");
  });
});

// ── Dashboard (view items + reports) ──

app.get("/dashboard", requireAuth, async (req, res) => {
  try {
    const search = (req.query.search || "").trim();
    const filterCategory = req.query.category || "";
    const filterStatus = req.query.status || "";

    // Get all items belonging to this user
    let query = supabase.from("items").select("*").eq("user_id", req.session.userId).order("created_at", { ascending: false });
    if (filterCategory) query = query.eq("category", filterCategory);
    if (filterStatus) query = query.eq("item_status", filterStatus);
    const { data: items } = await query;

    // Filter by search text
    const filteredItems = filterBySearch(items, search, ["item_name", "item_description", "category"]);

    // Get finder reports for these items
    const itemIds = filteredItems.map((i) => i.id);
    let reports = [];
    if (itemIds.length > 0) {
      const { data } = await supabase
        .from("finder_reports")
        .select("id, item_id, finder_name, finder_email, location_hint, message, status, created_at")
        .in("item_id", itemIds)
        .order("created_at", { ascending: false });
      reports = data || [];
    }

    // Count open reports per item
    const itemNameMap = Object.fromEntries(filteredItems.map((i) => [i.id, i.item_name]));
    const openCounts = {};
    for (const r of reports) {
      if (r.status === REPORT_STATUS.OPEN) openCounts[r.item_id] = (openCounts[r.item_id] || 0) + 1;
    }

    res.render("dashboard", {
      items: filteredItems.map((i) => ({ ...i, open_reports: openCounts[i.id] || 0 })),
      reports: reports.map((r) => ({ ...r, item_name: itemNameMap[r.item_id] || "Unknown item" })),
      baseUrl: BASE_URL,
      categories: CATEGORIES,
      search, filterCategory, filterStatus
    });
  } catch (err) {
    console.error("Dashboard error:", err);
    setFlash(req, "error", "Failed to load dashboard.");
    return res.redirect("/");
  }
});

// ── Register Item ──

app.get("/items/new", requireAuth, (req, res) => {
  res.render("new_item", { categories: CATEGORIES });
});

// Shared handler so old and new form actions both work
async function handleRegisterItem(req, res) {
  try {
    const item_name = sanitize(req.body.item_name);
    const item_description = sanitize(req.body.item_description);
    const category = req.body.category || "Other";

    if (!item_name || item_name.length > 150) {
      return flashRedirect(req, res, "/items/new", "error", "Item name is required (max 150 characters).");
    }
    if (item_description && item_description.length > 1000) {
      return flashRedirect(req, res, "/items/new", "error", "Description is too long (max 1000 characters).");
    }

    // Generate unique token and QR code
    const token = generateToken();
    const qrUrl = `${BASE_URL}/found/${token}`;
    const qr_data_url = await QRCode.toDataURL(qrUrl);

    // Upload image if provided
    let image_url = null;
    if (req.file) {
      image_url = await uploadImage(req.file.buffer, token);
    }

    // Save item to database
    const { error } = await supabase.from("items").insert({
      user_id: req.session.userId,
      item_name,
      item_description: item_description || null,
      category: normalizeCategory(category),
      item_status: ITEM_STATUS.ACTIVE,
      image_url, token, qr_data_url
    });

    if (error) {
      return flashRedirect(req, res, "/items/new", "error", "Failed to register item.");
    }

    return flashRedirect(req, res, "/dashboard", "success", "Item registered and QR generated.");
  } catch (err) {
    console.error("Register item error:", err);
    return flashRedirect(req, res, "/items/new", "error", "Something went wrong.");
  }
}

app.post("/items/new", requireAuth, upload.single("image"), handleRegisterItem);
app.post("/dashboard", requireAuth, upload.single("image"), handleRegisterItem);

// ── Lost Board (login required) ──

app.get("/lost", requireAuth, async (req, res) => {
  try {
    const search = (req.query.search || "").trim();
    const filterCategory = req.query.category || "";

    // Get all items marked as "lost"
    let query = supabase
      .from("items")
      .select("id, item_name, item_description, category, image_url, created_at, user_id")
      .eq("item_status", ITEM_STATUS.LOST)
      .order("created_at", { ascending: false });
    if (filterCategory) query = query.eq("category", filterCategory);

    const { data: items } = await query;
    const filteredItems = filterBySearch(items, search, ["item_name", "item_description", "category"]);

    // Get owner first names only (for privacy)
    const userIds = [...new Set(filteredItems.map((i) => i.user_id))];
    let ownerMap = {};
    if (userIds.length > 0) {
      const { data: users } = await supabase.from("users").select("id, full_name").in("id", userIds);
      for (const u of users || []) {
        ownerMap[u.id] = u.full_name.split(" ")[0]; // first name only
      }
    }

    res.render("lost", {
      items: filteredItems.map((i) => ({ ...i, owner_first_name: ownerMap[i.user_id] || "Someone" })),
      categories: CATEGORIES,
      search, filterCategory
    });
  } catch (err) {
    console.error("Lost board error:", err);
    setFlash(req, "error", "Failed to load lost board.");
    return res.redirect("/");
  }
});

// Submit a sighting report for a lost item
app.post("/lost/:id/sighting", requireAuth, async (req, res) => {
  try {
    const reporter_name = sanitize(req.body.reporter_name);
    const reporter_email = sanitize(req.body.reporter_email);
    const location = sanitize(req.body.location);
    const message = sanitize(req.body.message);

    // Find the lost item
    const { data: item } = await supabase.from("items").select("id, item_name").eq("id", req.params.id).eq("item_status", "lost").maybeSingle();
    if (!item) {
      setFlash(req, "error", "Item not found.");
      return res.redirect("/lost");
    }

    // Validate inputs
    const validationError = getReportValidationError(reporter_name, reporter_email, message);
    if (validationError) return flashRedirect(req, res, "/lost", "error", validationError);
    if (!isSchoolEmail(reporter_email)) {
      return flashRedirect(req, res, "/lost", "error", `Use a school email (@${ALLOWED_EMAIL_DOMAIN}).`);
    }

    // Save report
    const { error } = await supabase.from("finder_reports").insert({
      item_id: item.id,
      finder_name: reporter_name,
      finder_email: reporter_email,
      location_hint: location || null,
      message: `[Sighting] ${message}`,
      status: REPORT_STATUS.OPEN
    });

    if (error) {
      return flashRedirect(req, res, "/lost", "error", "Failed to submit sighting.");
    }
    return flashRedirect(req, res, "/lost", "success", `Sighting reported for "${item.item_name}". The owner has been notified!`);
  } catch (err) {
    console.error("Sighting error:", err);
    return flashRedirect(req, res, "/lost", "error", "Something went wrong.");
  }
});

// ── QR Code Scan Page (shown when someone scans a QR sticker) ──

app.get("/found/:token", async (req, res) => {
  try {
    const { data: item } = await supabase.from("items").select("*").eq("token", req.params.token).maybeSingle();
    if (!item) return res.status(404).render("not_found");

    const { data: owner } = await supabase.from("users").select("full_name, email").eq("id", item.user_id).single();
    return res.render("found_qr", { item, owner });
  } catch (err) {
    console.error("QR page error:", err);
    return res.status(500).send("Something went wrong.");
  }
});

// Handle the finder's report form from the QR page
app.post("/found/:token", async (req, res) => {
  try {
    const finder_name = sanitize(req.body.finder_name);
    const finder_email = sanitize(req.body.finder_email);
    const location_hint = sanitize(req.body.location_hint);
    const message = sanitize(req.body.message);

    const { data: item } = await supabase.from("items").select("id, item_name").eq("token", req.params.token).maybeSingle();
    if (!item) return res.status(404).render("not_found");

    // Basic validation
    const validationError = getReportValidationError(finder_name, finder_email, message);
    if (validationError) return flashRedirect(req, res, `/found/${req.params.token}`, "error", validationError);
    if (!isSchoolEmail(finder_email)) {
      return flashRedirect(req, res, `/found/${req.params.token}`, "error", `Use a school email (@${ALLOWED_EMAIL_DOMAIN}).`);
    }

    // Save report to database
    const { error } = await supabase.from("finder_reports").insert({
      item_id: item.id,
      finder_name,
      finder_email,
      location_hint: location_hint || null,
      message,
      status: REPORT_STATUS.OPEN
    });

    if (error) {
      return flashRedirect(req, res, `/found/${req.params.token}`, "error", "Failed to submit report.");
    }
    return flashRedirect(req, res, `/found/${req.params.token}`, "success", "Report submitted to owner!");
  } catch (err) {
    console.error("QR report error:", err);
    return flashRedirect(req, res, `/found/${req.params.token}`, "error", "Something went wrong.");
  }
});

// ── Found Items Board (login required) ──

app.get("/found-items", requireAuth, async (req, res) => {
  try {
    const search = (req.query.search || "").trim();
    const filterCategory = req.query.category || "";

    let query = supabase
      .from("found_posts")
      .select("*")
      .eq("status", "unclaimed")
      .order("created_at", { ascending: false });
    if (filterCategory) query = query.eq("category", filterCategory);

    const { data: posts } = await query;
    const filtered = filterBySearch(posts, search, ["item_name", "item_description", "category", "location_found"]);

    res.render("found_items", { posts: filtered, categories: CATEGORIES, search, filterCategory });
  } catch (err) {
    console.error("Found board error:", err);
    setFlash(req, "error", "Failed to load found items.");
    return res.redirect("/");
  }
});

// Post a found item to the board
app.post("/found-items", requireAuth, upload.single("image"), async (req, res) => {
  try {
    const finder_name = sanitize(req.body.finder_name);
    const finder_email = sanitize(req.body.finder_email);
    const item_name = sanitize(req.body.item_name);
    const item_description = sanitize(req.body.item_description);
    const category = req.body.category || "Other";
    const location_found = sanitize(req.body.location_found);

    // Validate
    if (finder_name.length < 2) return flashRedirect(req, res, "/found-items", "error", "Name is too short.");
    if (!isValidEmail(finder_email)) return flashRedirect(req, res, "/found-items", "error", "Invalid email.");
    if (!isSchoolEmail(finder_email)) return flashRedirect(req, res, "/found-items", "error", `Use a school email (@${ALLOWED_EMAIL_DOMAIN}).`);
    if (!item_name || item_name.length > 150) return flashRedirect(req, res, "/found-items", "error", "Item name is required (max 150 chars).");

    // Upload image if provided (reuse helper)
    const image_url = req.file ? await uploadImage(req.file.buffer, "found") : null;

    // Save to database
    const { error } = await supabase.from("found_posts").insert({
      finder_name, finder_email, item_name,
      item_description: item_description || null,
      category: normalizeCategory(category),
      location_found: location_found || null,
      image_url,
      status: "unclaimed"
    });

    if (error) {
      return flashRedirect(req, res, "/found-items", "error", "Failed to post item.");
    }
    return flashRedirect(req, res, "/found-items", "success", "Found item posted! The owner can now find it here.");
  } catch (err) {
    console.error("Post found item error:", err);
    return flashRedirect(req, res, "/found-items", "error", "Something went wrong.");
  }
});

// Claim a found item (must be logged in)
app.post("/found-items/:id/claim", requireAuth, async (req, res) => {
  try {
    const { data: post } = await supabase
      .from("found_posts")
      .select("*")
      .eq("id", Number(req.params.id))
      .eq("status", "unclaimed")
      .maybeSingle();

    if (!post) {
      setFlash(req, "error", "Post not found or already claimed.");
      return res.redirect("/found-items");
    }

    await supabase.from("found_posts").update({ status: "claimed" }).eq("id", post.id);
    setFlash(req, "success", `You claimed "${post.item_name}". Contact the finder at ${post.finder_email} to arrange pickup.`);
    return res.redirect("/found-items");
  } catch (err) {
    console.error("Claim error:", err);
    setFlash(req, "error", "Something went wrong.");
    return res.redirect("/found-items");
  }
});

// ── Messages (owner <-> finder chat per report) ──

app.get("/messages", requireAuth, async (req, res) => {
  try {
    const currentEmail = String(res.locals.currentUser?.email || "").toLowerCase();

    const { data: ownerItems } = await supabase.from("items").select("id, item_name, user_id").eq("user_id", req.session.userId);
    const ownerItemIds = (ownerItems || []).map((i) => i.id);
    const ownerItemIdSet = new Set(ownerItemIds);

    let ownerReports = [];
    if (ownerItemIds.length > 0) {
      const { data } = await supabase
        .from("finder_reports")
        .select("id, item_id, finder_name, finder_email, message, status, created_at")
        .in("item_id", ownerItemIds)
        .order("created_at", { ascending: false });
      ownerReports = data || [];
    }

    const { data: finderReportsData } = await supabase
      .from("finder_reports")
      .select("id, item_id, finder_name, finder_email, message, status, created_at")
      .eq("finder_email", currentEmail)
      .order("created_at", { ascending: false });
    const finderReports = finderReportsData || [];

    const mergedMap = new Map();
    for (const r of [...ownerReports, ...finderReports]) {
      if (!mergedMap.has(r.id)) mergedMap.set(r.id, r);
    }
    const reports = [...mergedMap.values()];

    // Fetch latest chat message per report to use as conversation preview
    const reportIds = reports.map((r) => r.id);
    let latestMsgMap = {};
    if (reportIds.length > 0) {
      const { data: latestMsgs } = await supabase
        .from("report_messages")
        .select("report_id, message, created_at")
        .in("report_id", reportIds)
        .order("created_at", { ascending: false });
      for (const m of latestMsgs || []) {
        if (!latestMsgMap[m.report_id]) latestMsgMap[m.report_id] = m;
      }
    }

    const allItemIds = [...new Set(reports.map((r) => r.item_id))];
    let itemsById = {};
    if (allItemIds.length > 0) {
      const { data: items } = await supabase.from("items").select("id, item_name, user_id").in("id", allItemIds);
      itemsById = Object.fromEntries((items || []).map((i) => [i.id, i]));
    }

    const ownerUserIds = [...new Set(Object.values(itemsById).map((i) => i.user_id))];
    let usersById = {};
    if (ownerUserIds.length > 0) {
      const { data: users } = await supabase.from("users").select("id, full_name").in("id", ownerUserIds);
      usersById = Object.fromEntries((users || []).map((u) => [u.id, u]));
    }

    const conversations = reports
      .map((r) => {
        const item = itemsById[r.item_id];
        if (!item) return null;

        const role = ownerItemIdSet.has(r.item_id) ? "owner" : "finder";
        const counterpartName = role === "owner"
          ? (r.finder_name || r.finder_email || "Finder")
          : (usersById[item.user_id]?.full_name || "Owner");

        return {
          id: r.id,
          item_name: item.item_name,
          preview: latestMsgMap[r.id]?.message || r.message,
          status: r.status,
          role,
          counterpart_name: counterpartName,
          created_at: latestMsgMap[r.id]?.created_at || r.created_at
        };
      })
      .filter(Boolean)
      .sort((a, b) => new Date(b.created_at) - new Date(a.created_at));

    res.render("messages", { conversations });
  } catch (err) {
    console.error("Messages list error:", err);
    return flashRedirect(req, res, "/dashboard", "error", "Failed to load messages.");
  }
});

app.get("/messages/:reportId", requireAuth, async (req, res) => {
  try {
    const ctx = await getAccessibleReportContext(req, res, req.params.reportId);
    if (ctx.error === "not_found") return res.status(404).render("not_found");
    if (ctx.error === "forbidden") return res.status(403).send("Forbidden");

    const { report, item, owner, currentUser, isOwner } = ctx;

    const { data: rows } = await supabase
      .from("report_messages")
      .select("id, report_id, sender_user_id, message, created_at")
      .eq("report_id", report.id)
      .order("created_at", { ascending: true });
    const messages = rows || [];

    const senderIds = [...new Set(messages.map((m) => m.sender_user_id).filter(Boolean))];
    let senderMap = {};
    if (senderIds.length > 0) {
      const { data: users } = await supabase.from("users").select("id, full_name").in("id", senderIds);
      senderMap = Object.fromEntries((users || []).map((u) => [u.id, u.full_name]));
    }

    const counterpartName = isOwner ? (report.finder_name || report.finder_email || "Finder") : owner.full_name;

    res.render("message_thread", {
      report,
      item,
      messages: messages.map((m) => ({
        ...m,
        is_me: m.sender_user_id === currentUser.id,
        sender_name: senderMap[m.sender_user_id] || "User"
      })),
      counterpartName
    });
  } catch (err) {
    console.error("Message thread error:", err);
    return flashRedirect(req, res, "/messages", "error", "Failed to load conversation.");
  }
});

app.post("/messages/:reportId", requireAuth, async (req, res) => {
  try {
    const ctx = await getAccessibleReportContext(req, res, req.params.reportId);
    if (ctx.error === "not_found") return res.status(404).render("not_found");
    if (ctx.error === "forbidden") return res.status(403).send("Forbidden");

    const text = sanitize(req.body.message);
    if (!text) return flashRedirect(req, res, `/messages/${ctx.report.id}`, "error", "Message cannot be empty.");
    if (text.length > 1000) return flashRedirect(req, res, `/messages/${ctx.report.id}`, "error", "Message is too long (max 1000 chars).");

    const { error } = await supabase.from("report_messages").insert({
      report_id: ctx.report.id,
      sender_user_id: req.session.userId,
      message: text
    });
    if (error) return flashRedirect(req, res, `/messages/${ctx.report.id}`, "error", "Failed to send message.");

    return flashRedirect(req, res, `/messages/${ctx.report.id}`, "success", "Message sent.");
  } catch (err) {
    console.error("Send message error:", err);
    return flashRedirect(req, res, `/messages/${req.params.reportId}`, "error", "Something went wrong.");
  }
});

// ── Resolve a finder report ──

app.post("/report/:id/resolve", requireAuth, async (req, res) => {
  try {
    const { data: report } = await supabase.from("finder_reports").select("id, item_id").eq("id", Number(req.params.id)).maybeSingle();
    if (!report) return res.status(404).render("not_found");

    // Make sure the logged-in user owns the item
    const item = await getOwnedItem(req, report.item_id);
    if (!item) return res.status(403).send("Forbidden");

    await supabase.from("finder_reports").update({ status: REPORT_STATUS.RESOLVED }).eq("id", report.id);
    setFlash(req, "success", "Report marked as resolved.");
    return res.redirect("/dashboard");
  } catch (err) {
    console.error("Resolve report error:", err);
    setFlash(req, "error", "Something went wrong.");
    return res.redirect("/dashboard");
  }
});

// ── Account Page ──

app.get("/account", requireAuth, async (req, res) => {
  try {
    // Get user info and item stats for the account page
    const { data: user } = await supabase.from("users").select("created_at").eq("id", req.session.userId).single();
    const { data: items } = await supabase.from("items").select("id").eq("user_id", req.session.userId);
    const itemIds = (items || []).map((i) => i.id);

    let openReports = 0;
    let resolvedReports = 0;
    if (itemIds.length > 0) {
      const { data: reports } = await supabase.from("finder_reports").select("status").in("item_id", itemIds);
      for (const r of reports || []) {
        if (r.status === REPORT_STATUS.OPEN) openReports++;
        else resolvedReports++;
      }
    }

    res.render("account", {
      createdAt: user?.created_at || new Date().toISOString(),
      itemCount: (items || []).length,
      openReports, resolvedReports
    });
  } catch (err) {
    console.error("Account page error:", err);
    setFlash(req, "error", "Failed to load account.");
    return res.redirect("/dashboard");
  }
});

// Update display name
app.post("/account", requireAuth, async (req, res) => {
  try {
    const full_name = sanitize(req.body.full_name);
    if (full_name.length < 2) { setFlash(req, "error", "Name is too short."); return res.redirect("/account"); }

    const { error } = await supabase.from("users").update({ full_name }).eq("id", req.session.userId);
    setFlash(req, error ? "error" : "success", error ? "Update failed." : "Profile updated.");
    return res.redirect("/account");
  } catch (err) {
    console.error("Update name error:", err);
    setFlash(req, "error", "Something went wrong.");
    return res.redirect("/account");
  }
});

// Change password
app.post("/account/password", requireAuth, async (req, res) => {
  try {
    const { current_password, new_password, confirm_new_password } = req.body;
    if (!new_password || new_password.length < 8) {
      setFlash(req, "error", "New password must be at least 8 characters.");
      return res.redirect("/account");
    }
    if (new_password !== (confirm_new_password || "")) {
      setFlash(req, "error", "New passwords do not match.");
      return res.redirect("/account");
    }

    const { data: user } = await supabase.from("users").select("password_hash").eq("id", req.session.userId).single();
    const ok = await bcrypt.compare(current_password || "", user.password_hash);
    if (!ok) { setFlash(req, "error", "Current password is incorrect."); return res.redirect("/account"); }

    const hash = await bcrypt.hash(new_password, 10);
    await supabase.from("users").update({ password_hash: hash }).eq("id", req.session.userId);
    setFlash(req, "success", "Password updated.");
    return res.redirect("/account");
  } catch (err) {
    console.error("Password change error:", err);
    setFlash(req, "error", "Something went wrong.");
    return res.redirect("/account");
  }
});

app.post("/account/password/reset-link", requireAuth, async (req, res) => {
  try {
    const email = String(res.locals.currentUser?.email || "").toLowerCase();
    if (!email) return flashRedirect(req, res, "/account", "error", "Unable to find your account email.");

    const rawToken = crypto.randomBytes(32).toString("hex");
    const tokenHash = hashToken(rawToken);
    const expiresAt = new Date(Date.now() + 30 * 60 * 1000).toISOString();

    await supabase.from("password_reset_tokens").insert({
      user_id: req.session.userId,
      token_hash: tokenHash,
      expires_at: expiresAt
    });

    await sendPasswordResetEmail(email, buildResetLink(rawToken));
    return flashRedirect(req, res, "/account", "success", "Password reset link sent to your email.");
  } catch (err) {
    console.error("Account reset link error:", err);
    return flashRedirect(req, res, "/account", "error", "Something went wrong.");
  }
});

// ── Change Item Status (active / lost / recovered) ──

app.post("/item/:id/status", requireAuth, async (req, res) => {
  const { item_status } = req.body;

  const item = await getOwnedItem(req, req.params.id);
  if (!item) { setFlash(req, "error", "Item not found."); return res.redirect("/dashboard"); }
  if (!ITEM_STATUS_VALUES.includes(item_status)) { setFlash(req, "error", "Invalid status."); return res.redirect("/dashboard"); }

  await supabase.from("items").update({ item_status }).eq("id", item.id);
  setFlash(req, "success", `Item marked as ${item_status}.`);
  return res.redirect("/dashboard");
});

// ── Delete Item ──

app.post("/item/:id/delete", requireAuth, async (req, res) => {
  const item = await getOwnedItem(req, req.params.id, "id, user_id, image_url");
  if (!item) { setFlash(req, "error", "Item not found."); return res.redirect("/dashboard"); }

  // Remove item image from storage if one was uploaded
  if (item.image_url) {
    const fileName = item.image_url.split("/").pop().split("?")[0];
    await supabase.storage.from("item-images").remove([fileName]);
  }

  // Cascade on finder_reports and report_messages is handled by the schema
  await supabase.from("items").delete().eq("id", item.id);
  setFlash(req, "success", "Item deleted.");
  return res.redirect("/dashboard");
});

// ── Download QR Code as PNG ──

app.get("/download/:token", requireAuth, async (req, res) => {
  const { data: item } = await supabase.from("items").select("*").eq("token", req.params.token).eq("user_id", req.session.userId).maybeSingle();
  if (!item) return res.status(404).render("not_found");

  const base64 = (item.qr_data_url || "").split(",")[1];
  if (!base64) return res.status(500).send("QR unavailable");

  const imgBuffer = Buffer.from(base64, "base64");
  res.setHeader("Content-Type", "image/png");
  res.setHeader("Content-Disposition", `attachment; filename="${safeFileName(item.item_name)}-qr.png"`);
  res.send(imgBuffer);
});

// ── Start the server ──

app.listen(PORT, () => {
  console.log(`PUTrace running on port ${PORT}`);
});
