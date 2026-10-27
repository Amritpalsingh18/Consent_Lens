const DEFAULT_SETTINGS = {
  trackingEnabled: true,
  remindersEnabled: true,
  reminderDays: 30,
  trustedSites: []
};

const MAX_EVENTS = 500;
const DAY_MS = 24 * 60 * 60 * 1000;

const PERMISSION_TYPES = [
  "camera",
  "microphone",
  "location",
  "notifications",
  "popups",
  "automaticDownloads"
];

function getDomain(url) {
  try {
    const parsed = new URL(url);

    if (!["http:", "https:"].includes(parsed.protocol)) {
      return null;
    }

    return parsed.hostname.toLowerCase();
  } catch {
    return null;
  }
}

async function getSettings() {
  const result = await chrome.storage.local.get("settings");

  return {
    ...DEFAULT_SETTINGS,
    ...(result.settings || {})
  };
}

async function getState() {
  const result = await chrome.storage.local.get([
    "settings",
    "activities",
    "sites"
  ]);

  return {
    settings: {
      ...DEFAULT_SETTINGS,
      ...(result.settings || {})
    },
    activities: result.activities || [],
    sites: result.sites || {}
  };
}

await chrome.storage.local.set({
  lastSync: new Date().toISOString(),
  siteCount: sites.length,
  lastSnapshot: sites
});

async function logEvent(state, domain, type, details = {}) {
  state.activities.push({
    id: crypto.randomUUID(),
    domain,
    type,
    details,
    timestamp: Date.now()
  });

  state.activities = state.activities.slice(-MAX_EVENTS);
}

async function getPermissions(url) {
  const permissions = {};

  for (const type of PERMISSION_TYPES) {
    try {
      const api = chrome.contentSettings[type];

      if (!api) continue;

      const result = await api.get({
        primaryUrl: url
      });

      permissions[type] = result.setting || "unknown";
    } catch {
      permissions[type] = "unavailable";
    }
  }

  return permissions;
}

async function recordVisit(url, title = "") {
  const domain = getDomain(url);

  if (!domain) return;

  const state = await getState();

  if (!state.settings.trackingEnabled) return;

  const now = Date.now();
  const permissions = await getPermissions(url);

  const previous = state.sites[domain] || {
    domain,
    firstSeen: now,
    lastVisit: null,
    permissions: {},
    reviewedAt: null,
    lastReminderForVisit: null,
    trusted: false
  };

  if (previous.permissions) {
    for (const type of PERMISSION_TYPES) {
      const oldValue = previous.permissions[type];
      const newValue = permissions[type];

      if (
        oldValue &&
        newValue &&
        oldValue !== newValue &&
        oldValue !== "unavailable" &&
        newValue !== "unavailable"
      ) {
        await logEvent(state, domain, "permission_change", {
          permission: type,
          from: oldValue,
          to: newValue
        });
      }
    }
  }

  const isFirstVisit = !previous.lastVisit;

  previous.domain = domain;
  previous.title = title || previous.title || domain;
  previous.lastVisit = now;
  previous.permissions = permissions;
  previous.lastReminderForVisit = null;

  const trustedSites = state.settings.trustedSites || [];
  previous.trusted = trustedSites.includes(domain);

  state.sites[domain] = previous;

  await logEvent(
    state,
    domain,
    isFirstVisit ? "first_visit" : "visit",
    {
      title: previous.title
    }
  );

  await saveState(state);
}

async function checkInactivity() {
  const state = await getState();

  if (!state.settings.remindersEnabled) return;

  const reminderDays = Math.max(
    1,
    Number(state.settings.reminderDays) || 30
  );

  const threshold = reminderDays * DAY_MS;
  const now = Date.now();
  const trustedSites = state.settings.trustedSites || [];

  for (const [domain, site] of Object.entries(state.sites)) {
    if (!site.lastVisit) continue;
    if (trustedSites.includes(domain)) continue;

    const hasAllowedPermission = Object.values(
      site.permissions || {}
    ).some(value => value === "allow");

    if (!hasAllowedPermission) continue;

    const inactiveFor = now - site.lastVisit;

    if (inactiveFor < threshold) continue;

    // Notify at most once per last-visit period.
    if (site.lastReminderForVisit === site.lastVisit) continue;

    site.lastReminderForVisit = site.lastVisit;

    await logEvent(state, domain, "inactivity_reminder", {
      inactiveDays: Math.floor(inactiveFor / DAY_MS),
      message: "Review this site's permissions."
    });

    try {
      await chrome.notifications.create({
        type: "basic",
        iconUrl: "icon.png",
        title: "CONSENT LENS: Permission review",
        message:
          `${domain} has not been visited for ` +
          `${Math.floor(inactiveFor / DAY_MS)} days. ` +
          "Consider reviewing its permissions.",
        priority: 1
      });
    } catch {
      // Notifications may be unavailable if icon.png is absent.
      // The reminder remains visible in the activity timeline.
    }
  }

  await saveState(state);
}

async function ensureDefaults() {
  const state = await getState();

  await chrome.storage.local.set({
    settings: state.settings,
    activities: state.activities,
    sites: state.sites
  });

  await chrome.alarms.create("consent-lens-daily-check", {
    periodInMinutes: 60 * 24
  });
}

chrome.runtime.onInstalled.addListener(() => {
  ensureDefaults();
});

chrome.runtime.onStartup.addListener(() => {
  ensureDefaults();
});

chrome.alarms.onAlarm.addListener(alarm => {
  if (alarm.name === "consent-lens-daily-check") {
    checkInactivity();
  }
});

chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status === "complete" && tab.url) {
    recordVisit(tab.url, tab.title || "");
  }
});

chrome.tabs.onActivated.addListener(async ({ tabId }) => {
  try {
    const tab = await chrome.tabs.get(tabId);

    if (tab.url) {
      recordVisit(tab.url, tab.title || "");
    }
  } catch {
    // The tab may have closed before it could be inspected.
  }
});

chrome.notifications.onClicked.addListener(() => {
  chrome.tabs.create({
    url: chrome.runtime.getURL("popup.html")
  });
});

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  (async () => {
    const state = await getState();

    if (message.type === "GET_DASHBOARD") {
      const domain = getDomain(message.url);
      let permissions = {};
      let site = null;

      if (domain && message.url) {
        permissions = await getPermissions(message.url);
        site = state.sites[domain] || null;
      }

      return {
        settings: state.settings,
        activities: [...state.activities].reverse().slice(0, 40),
        site,
        domain,
        permissions,
        sites: state.sites
      };
    }

    if (message.type === "SAVE_SETTINGS") {
      state.settings = {
        ...state.settings,
        ...message.settings
      };

      state.settings.reminderDays = Math.max(
        1,
        Number(state.settings.reminderDays) || 30
      );

      state.settings.trustedSites = [
        ...new Set(state.settings.trustedSites || [])
      ];

      await saveState(state);
      await checkInactivity();

      return { ok: true };
    }

    if (message.type === "REVIEW_SITE") {
      const domain = message.domain;
      const site = state.sites[domain];

      if (site) {
        site.reviewedAt = Date.now();
        site.lastReminderForVisit = site.lastVisit;

        await logEvent(state, domain, "reviewed", {
          message: "User reviewed this site's permissions."
        });

        await saveState(state);
      }

      return { ok: true };
    }

    if (message.type === "TRUST_SITE") {
      const domain = message.domain;
      const trustedSites = new Set(state.settings.trustedSites || []);

      if (message.trusted) {
        trustedSites.add(domain);
      } else {
        trustedSites.delete(domain);
      }

      state.settings.trustedSites = [...trustedSites];

      if (state.sites[domain]) {
        state.sites[domain].trusted = message.trusted;
      }

      await logEvent(state, domain, "trusted_site_changed", {
        trusted: message.trusted
      });

      await saveState(state);

      return { ok: true };
    }

    if (message.type === "REVOKE_PERMISSION") {
      const { domain, permission } = message;

      if (!PERMISSION_TYPES.includes(permission)) {
        throw new Error("Unsupported permission type.");
      }

      if (!domain || domain.includes("/") || domain.includes(":")) {
        throw new Error("Invalid website domain.");
      }

      const api = chrome.contentSettings[permission];

      if (!api || typeof api.set !== "function") {
        throw new Error("This permission cannot be changed here.");
      }

      await api.set({
        primaryPattern: `*://[*.]${domain}/*`,
        setting: "block",
        scope: "regular"
      });

      await logEvent(state, domain, "permission_blocked_by_user", {
        permission
      });

      const site = state.sites[domain];

      if (site) {
        site.permissions[permission] = "block";
      }

      await saveState(state);

      return { ok: true };
    }

    if (message.type === "CLEAR_ACTIVITY") {
      state.activities = [];
      await saveState(state);
      return { ok: true };
    }

    if (message.type === "EXPORT_DATA") {
      return {
        exportedAt: new Date().toISOString(),
        settings: state.settings,
        sites: state.sites,
        activities: state.activities
      };
    }

    throw new Error("Unknown request.");
  })()
    .then(sendResponse)
    .catch(error => {
      sendResponse({
        ok: false,
        error: error.message || "Something went wrong."
      });
    });

  return true;
});