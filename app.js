// Secret key — must match the key in generate-url.js
// NOTE: This key is visible in browser DevTools. It prevents casual tampering but not a
// determined attacker who reads the source. For this use case that is acceptable.
const SECRET_KEY = "qr-aktivera-secret-2024-xK9mP3nL";

// Formspree endpoint
const FORMSPREE_ENDPOINT = "https://formspree.io/f/xojplvgn";

// ── Helpers ────────────────────────────────────────────────────────────────

async function importKey(secret) {
  const enc = new TextEncoder();
  return crypto.subtle.importKey(
    "raw",
    enc.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign", "verify"]
  );
}

async function computeHmac(secret, message) {
  const enc = new TextEncoder();
  const key = await importKey(secret);
  const sig = await crypto.subtle.sign("HMAC", key, enc.encode(message));
  return Array.from(new Uint8Array(sig))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

function safeEqual(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return diff === 0;
}

// ── Button state ───────────────────────────────────────────────────────────

function updateSubmitButton() {
  const email = document.getElementById("email").value.trim();
  const password = document.getElementById("password").value;
  const terms = document.getElementById("terms").checked;
  const btn = document.getElementById("submit-btn");

  const valid = email.length > 0 && password.length >= 8 && terms;
  btn.disabled = !valid;
  btn.classList.toggle("active", valid);
}

["email", "password"].forEach((id) => {
  document.getElementById(id).addEventListener("input", updateSubmitButton);
});
document.getElementById("terms").addEventListener("change", updateSubmitButton);

// ── Signature verification ─────────────────────────────────────────────────

async function init() {
  const params = new URLSearchParams(window.location.search);
  const cn = params.get("cn");
  const addr = params.get("addr");
  const sig = params.get("sig");

  const errorEl = document.getElementById("error-msg");
  const formEl = document.getElementById("account-form");

  if (!cn || !addr || !sig) {
    errorEl.style.display = "block";
    errorEl.textContent = "Ogiltig QR-kod. Kontakta kundtjänst.";
    formEl.style.display = "none";
    return;
  }

  // Recompute expected signature — must use URL-encoded values to match generate-url.js
  const message = `cn=${encodeURIComponent(cn)}&addr=${encodeURIComponent(addr)}`;
  const expected = await computeHmac(SECRET_KEY, message);

  if (!safeEqual(expected, sig)) {
    errorEl.style.display = "block";
    errorEl.innerHTML = `
      <strong>Ogiltig signatur.</strong><br><br>
      <small>
        <b>Received sig:</b> ${sig}<br>
        <b>Expected sig:</b> ${expected}<br>
        <b>Message signed:</b> ${message}<br>
        <b>cn:</b> ${cn}<br>
        <b>addr:</b> ${addr}
      </small>`;
    formEl.style.display = "none";
    return;
  }

  // Valid — populate read-only customer number field
  document.getElementById("customer-number").value = cn;
}

// ── Form submission ────────────────────────────────────────────────────────

document.getElementById("account-form").addEventListener("submit", async (e) => {
  e.preventDefault();

  const email = document.getElementById("email").value.trim();
  const password = document.getElementById("password").value;
  if (!email || password.length < 8) return;

  const submitBtn = document.getElementById("submit-btn");
  submitBtn.disabled = true;
  submitBtn.classList.remove("active");
  submitBtn.textContent = "Skickar...";

  const data = {
    customerNumber: document.getElementById("customer-number").value,
    email,
  };

  try {
    const res = await fetch(FORMSPREE_ENDPOINT, {
      method: "POST",
      headers: { "Content-Type": "application/json", Accept: "application/json" },
      body: JSON.stringify(data),
    });

    if (res.ok) {
      document.getElementById("account-form").style.display = "none";
      document.getElementById("success-msg").style.display = "block";
    } else {
      submitBtn.disabled = false;
      submitBtn.classList.add("active");
      submitBtn.textContent = "Skapa konto";
      alert("Något gick fel. Försök igen.");
    }
  } catch {
    submitBtn.disabled = false;
    submitBtn.classList.add("active");
    submitBtn.textContent = "Skapa konto";
    alert("Nätverksfel. Kontrollera din internetanslutning.");
  }
});

// Run on page load
init();
