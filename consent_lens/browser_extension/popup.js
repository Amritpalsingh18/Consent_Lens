const $ = id => document.getElementById(id);

let currentDomain = null;
let currentUrl = null;
let dashboard = null;

const LABELS = {
  camera: "Camera",
  microphone: "Microphone",
  location: "Location",
  notifications: "Notifications",
  popups: "Pop-ups",
  automaticDownloads: "Automatic downloads"
};

function escapeHtml(value) {
  return String(value ?? "").replace(/[&<>"']/g, char => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#39;"
  })[char]);
}

function showStatus(message) {
  $("status").textContent = message;
}

function send(message) {
  return new Promise((resolve, reject) => {
    chrome.runtime.sendMessage(message, response => {
      const error = chrome.runtime.lastError;

      if (error) {
        reject(new Error(error.message));
      } else if (!response) {
        reject(new Error("No response from the extension."));
      } else if (response.ok === false) {
        reject(new Error(response.error || "Request failed."));
      } else {
        resolve(response);
      }
    });
  });
}

function humanDate(timestamp) {
  if (!timestamp) return "Not recorded";

  return new Date(timestamp).toLocaleString([], {
    dateStyle: "medium",
    timeStyle: "short"
  });
}

function humanAgo(timestamp) {
  if (!timestamp) return "No visit recorded";

  const days = Math.floor((Date.now() - timestamp) / 86400000);

  if (days <= 0) return "Visited today";
  if (days === 1) return "Last visited yesterday";

  return `Last visited ${days} days ago`;
}

function getRisk(permissions, domain) {
  let score = 0;
  const reasons = [];
  const host = (domain || "").toLowerCase();

  const highRisk = [
    ["camera", 25, "Camera access can expose video from your device."],
    ["microphone", 25, "Microphone access can expose audio."],
    ["location", 25, "Location access can reveal where you are."]
  ];

  for (const [type, points, explanation] of highRisk) {
    if (permissions[type] === "allow") {
      score += points;
      reasons.push(explanation);
    }
  }

  if (permissions.notifications === "allow") {
    score += 10;
    reasons.push("Notifications can be used for persistent prompts or spam.");
  }

  if (permissions.popups === "allow") {
    score += 10;
    reasons.push("Pop-ups are allowed for this website.");
  }

  if (permissions.automaticDownloads === "allow") {
    score += 15;
    reasons.push("Automatic downloads are allowed.");
  }

  // A simple purpose heuristic. This is not proof of legitimacy.
  const communicationSite =
    /(meet|zoom|teams|webex|video|call|conference)/i.test(host);

  const mappingSite =
    /(maps|navigation|weather|delivery|ride|travel)/i.test(host);

  if (communicationSite && permissions.camera === "allow") {
    score -= 10;
    reasons.push("Camera access may fit a communication site's purpose.");
  }

  if (mappingSite && permissions.location === "allow") {
    score -= 10;
    reasons.push("Location access may fit a mapping or travel site's purpose.");
  }

  score = Math.max(0, Math.min(100, score));

  let level = "Low";
  if (score >= 50) level = "High";
  else if (score >= 25) level = "Moderate";

  if (reasons.length === 0) {
    reasons.push(
      "No reviewed sensitive permissions are currently marked as allowed."
    );
  }

  return { score, level, reasons };
}

function renderPermissions(permissions) {
  const entries = Object.entries(LABELS);

  $("permission-list").innerHTML = entries.map(([type, label]) => {
    const setting = permissions[type] || "unavailable";

    const statusClass = {
      allow: "status-allow",
      block: "status-block",
      ask: "status-ask"
    }[setting] || "status-unknown";

    const safeLabel = escapeHtml(label);
    const safeSetting = escapeHtml(setting);

    const button = setting === "allow"
      ? `<button class="revoke" data-block="${escapeHtml(type)}">
           Block
         </button>`
      : "";

    return `
      <div class="permission-row">
        <div class="permission-info">
          <strong>${safeLabel}</strong>
          <small class="${statusClass}">${safeSetting.toUpperCase()}</small>
        </div>
        ${button}
      </div>
    `;
  }).join("");

  document.querySelectorAll("[data-block]").forEach(button => {
    button.addEventListener("click", async () => {
      const type = button.dataset.block;

      const confirmed = window.confirm(
        `Block ${LABELS[type]} access for ${currentDomain}?\n\n` +
        "This changes Chrome's site permission setting."
      );

      if (!confirmed) return;

      try {
        await send({
          type: "REVOKE_PERMISSION",
          domain: currentDomain,
          permission: type
        });

        showStatus(`${LABELS[type]} access blocked.`);
        await loadDashboard();
      } catch (error) {
        showStatus(error.message);
      }
    });
  });
}

function renderRisk(permissions, domain) {
  const result = getRisk(permissions, domain);

  const levelClass = result.level.toLowerCase();

  $("risk-summary").innerHTML = `
    <div class="risk-card risk-${levelClass}">
      <div class="risk-heading">
        <strong>${result.level} estimated risk</strong>
        <strong>${result.score}/100</strong>
      </div>
      <div class="risk-track">
        <div class="risk-fill" style="width:${result.score}%"></div>
      </div>
      <p class="note">
        This score measures permission exposure, not whether the website
        is malicious.
      </p>
      <ul>
        ${result.reasons.map(reason =>
          `<li>${escapeHtml(reason)}</li>`
        ).join("")}
      </ul>
    </div>
  `;
}

function describeEvent(event) {
  const details = event.details || {};

  switch (event.type) {
    case "first_visit":
      return "First visit recorded";
    case "visit":
      return "Website visited";
    case "permission_change":
      return `${LABELS[details.permission] || details.permission}: ` +
        `${details.from} → ${details.to}`;
    case "inactivity_reminder":
      return `Permission review reminder: inactive ${details.inactiveDays} days`;
    case "reviewed":
      return "Permissions marked as reviewed";
    case "trusted_site_changed":
      return details.trusted ? "Added to trusted websites" :
        "Removed from trusted websites";
    case "permission_blocked_by_user":
      return `${LABELS[details.permission] || details.permission} blocked by you`;
    default:
      return event.type.replaceAll("_", " ");
  }
}

function renderTimeline(activities) {
  if (!activities.length) {
    $("timeline").innerHTML =
      '<p class="muted">No activity recorded yet.</p>';
    return;
  }

  $("timeline").innerHTML = activities.slice(0, 25).map(event => `
    <div class="timeline-item">
      <span class="timeline-dot"></span>
      <div class="timeline-content">
        <strong>${escapeHtml(event.domain || "Browser")}</strong>
        <p>${escapeHtml(describeEvent(event))}</p>
        <small>${escapeHtml(humanDate(event.timestamp))}</small>
      </div>
    </div>
  `).join("");
}

async function loadDashboard() {
  const tabs = await chrome.tabs.query({
    active: true,
    currentWindow: true
  });

  const tab = tabs[0];
  currentUrl = tab?.url || null;

  const response = await send({
    type: "GET_DASHBOARD",
    url: currentUrl
  });

  dashboard = response;
  currentDomain = response.domain;

  $("current-domain").textContent =
    currentDomain || "This page cannot be inspected";

  $("site-summary").textContent = response.site
    ? humanAgo(response.site.lastVisit)
    : "No activity record yet for this website.";

  renderPermissions(response.permissions || {});
  renderRisk(response.permissions || {}, currentDomain);
  renderTimeline(response.activities || []);

  $("tracking-toggle").checked =
    response.settings.trackingEnabled;

  $("reminders-toggle").checked =
    response.settings.remindersEnabled;

  $("reminder-days").value =
    String(response.settings.reminderDays || 30);

  const trusted = (
    response.settings.trustedSites || []
  ).includes(currentDomain);

  $("trust-site").textContent = trusted
    ? "Remove from trusted websites"
    : "Trust this website";

  $("trust-site").disabled = !currentDomain;
  $("mark-reviewed").disabled = !currentDomain;
  $("open-settings").disabled = !currentDomain;
}

$("save-settings").addEventListener("click", async () => {
  try {
    await send({
      type: "SAVE_SETTINGS",
      settings: {
        trackingEnabled: $("tracking-toggle").checked,
        remindersEnabled: $("reminders-toggle").checked,
        reminderDays: Number($("reminder-days").value)
      }
    });

    showStatus("Preferences saved.");
    await loadDashboard();
  } catch (error) {
    showStatus(error.message);
  }
});

$("mark-reviewed").addEventListener("click", async () => {
  if (!currentDomain) return;

  try {
    await send({
      type: "REVIEW_SITE",
      domain: currentDomain
    });

    showStatus("Website marked as reviewed.");
    await loadDashboard();
  } catch (error) {
    showStatus(error.message);
  }
});

$("trust-site").addEventListener("click", async () => {
  if (!currentDomain || !dashboard) return;

  const trustedSites = dashboard.settings.trustedSites || [];
  const isTrusted = trustedSites.includes(currentDomain);

  try {
    await send({
      type: "TRUST_SITE",
      domain: currentDomain,
      trusted: !isTrusted
    });

    showStatus(
      !isTrusted
        ? "Website added to trusted list."
        : "Website removed from trusted list."
    );

    await loadDashboard();
  } catch (error) {
    showStatus(error.message);
  }
});

$("open-settings").addEventListener("click", async () => {
  if (!currentDomain) return;

  const url = "chrome://settings/content/siteDetails?site=" +
    encodeURIComponent("https://" + currentDomain);

  await chrome.tabs.create({ url });
});

$("export-data").addEventListener("click", async () => {
  try {
    const data = await send({ type: "EXPORT_DATA" });
    const blob = new Blob(
      [JSON.stringify(data, null, 2)],
      { type: "application/json" }
    );

    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");

    link.href = url;
    link.download = "consent-lens-privacy-report.json";
    link.click();

    URL.revokeObjectURL(url);
    showStatus("Privacy report exported.");
  } catch (error) {
    showStatus(error.message);
  }
});

$("clear-activity").addEventListener("click", async () => {
  const confirmed = window.confirm(
    "Delete the locally stored activity timeline? " +
    "Site records used for inactivity reminders will remain."
  );

  if (!confirmed) return;

  try {
    await send({ type: "CLEAR_ACTIVITY" });
    showStatus("Activity timeline cleared.");
    await loadDashboard();
  } catch (error) {
    showStatus(error.message);
  }
});

loadDashboard().catch(error => {
  showStatus("Could not load privacy information: " + error.message);
});