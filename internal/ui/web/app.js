"use strict";
const $ = (id) => document.getElementById(id);
let csrf = "",
  entries = [],
  receivingKey = "",
  editing = false,
  inspectedPacket = "",
  page = 1;
const pageSize = 25;
const revealTimers = new Map();
function objectOf(path) {
  return path.match(/^\.([^.[\]]+)/)?.[1] || path;
}
function renderObjects() {
  const select = $("group-filter");
  const selected = select.value;
  const counts = new Map();
  for (const entry of entries) {
    const object = objectOf(entry.path);
    counts.set(object, (counts.get(object) || 0) + 1);
  }
  select.replaceChildren(new Option(`All objects (${entries.length})`, ""));
  for (const object of [...counts.keys()].sort()) {
    select.append(new Option(`${object} (${counts.get(object)})`, object));
  }
  select.value = counts.has(selected) ? selected : "";
}
function message(text, error = false) {
  $("message").textContent = text;
  $("message").classList.toggle("error", error);
}
function dialogError(id, text) {
  $(id).querySelector(".dialog-error").textContent = text;
}
async function api(path, data) {
  const response = await fetch(`/api/${path}`, {
    method: data === undefined ? "GET" : "POST",
    headers: { "Content-Type": "application/json", "X-Workbench-CSRF": csrf },
    credentials: "same-origin",
    body: data === undefined ? undefined : JSON.stringify(data),
    cache: "no-store",
  });
  const result = await response.json();
  if (!response.ok) throw new Error(result.error || "Request failed");
  return result;
}
function close(id) {
  $(id).close();
  if (id === "editor") $("edit-value").value = "";
  if (id === "import-dialog") {
    $("import-packet").value = "";
    inspectedPacket = "";
  }
  if (id === "share-dialog") $("share-packet").value = "";
}
document
  .querySelectorAll("[data-close]")
  .forEach((button) =>
    button.addEventListener("click", () => close(button.dataset.close)),
  );
document.querySelectorAll("dialog").forEach((dialog) =>
  dialog.addEventListener("cancel", (event) => {
    event.preventDefault();
    close(dialog.id);
  }),
);
function button(label, action, className = "") {
  const b = document.createElement("button");
  b.textContent = label;
  b.className = className;
  b.addEventListener("click", async () => {
    b.disabled = true;
    try {
      await action();
    } catch (error) {
      message(error.message, true);
    } finally {
      b.disabled = false;
    }
  });
  return b;
}
function render() {
  for (const timer of revealTimers.values()) clearTimeout(timer);
  revealTimers.clear();
  const root = $("entries");
  root.replaceChildren();
  const query = $("search").value.toLowerCase();
  const object = $("group-filter").value;
  const filtered = entries.filter(
    (entry) =>
      (!object || objectOf(entry.path) === object) &&
      entry.path.toLowerCase().includes(query),
  );
  const pages = Math.max(1, Math.ceil(filtered.length / pageSize));
  page = Math.min(page, pages);
  const start = (page - 1) * pageSize;
  $("pagination").hidden = filtered.length <= pageSize;
  $("page-summary").textContent =
    `${start + 1}-${Math.min(start + pageSize, filtered.length)} of ${filtered.length} values`;
  $("page-number").textContent = `${page} / ${pages}`;
  $("page-previous").disabled = page === 1;
  $("page-next").disabled = page === pages;
  if (!filtered.length) {
    const empty = document.createElement("div");
    empty.className = "empty";
    const title = document.createElement("strong");
    title.textContent = query ? "No matching paths" : "Your vault is ready";
    const detail = document.createElement("span");
    detail.textContent = query
      ? "Try another search."
      : "Add your first value or import an encrypted share.";
    empty.append(title, detail);
    root.append(empty);
    return;
  }
  let previousObject = "";
  for (const entry of filtered.slice(start, start + pageSize)) {
    const object = objectOf(entry.path);
    if (object !== previousObject) {
      const heading = document.createElement("h2");
      heading.className = "object-heading";
      heading.textContent = `.${object}`;
      root.append(heading);
      previousObject = object;
    }
    const row = document.createElement("div");
    row.className = "entry";
    const name = document.createElement("div");
    const path = document.createElement("span");
    path.className = "path";
    path.textContent = entry.path;
    const value = document.createElement("span");
    value.className = "value";
    value.textContent = "••••••••";
    name.append(path, value);
    const classification = document.createElement("div");
    const badge = button(entry.secret ? "Secret" : "Public", async () => {
      const secret = !entry.secret;
      const prompt = secret
        ? `Mark ${entry.path} as secret?`
        : `Make ${entry.path} public? CLI get will be allowed to display it. The value stays encrypted on disk.`;
      if (!confirm(prompt)) return;
      await api("classify", { path: entry.path, secret });
      await load();
      message("Classification updated.");
    });
    badge.className = `badge${entry.secret ? "" : " public"}`;
    badge.title = "Change classification";
    const type = document.createElement("span");
    type.className = "type";
    type.textContent = entry.type;
    classification.append(badge, type);
    const actions = document.createElement("div");
    actions.className = "actions";
    const reveal = button("Reveal", async () => {
      if (reveal.textContent === "Hide") {
        value.textContent = "••••••••";
        reveal.textContent = "Reveal";
        clearTimeout(revealTimers.get(entry.path));
        return;
      }
      if (!confirm(`Reveal ${entry.path} on this screen?`)) return;
      const result = await api("reveal", { path: entry.path });
      value.textContent = result.value;
      reveal.textContent = "Hide";
      revealTimers.set(
        entry.path,
        setTimeout(() => {
          value.textContent = "••••••••";
          reveal.textContent = "Reveal";
        }, 10000),
      );
    });
    actions.append(
      reveal,
      button("Copy", async () => {
        await api("copy", { path: entry.path });
        message(`Copied ${entry.path} to this device's clipboard.`);
      }),
      button("Edit", () => edit(entry)),
      button("Share", () => share(entry)),
      button(
        "Delete",
        async () => {
          if (!confirm(`Delete ${entry.path}?`)) return;
          await api("unset", { path: entry.path });
          await load();
          message("Value removed.");
        },
        "delete",
      ),
    );
    row.append(name, classification, actions);
    root.append(row);
  }
}
async function load() {
  const data = await api("list");
  entries = data.entries;
  receivingKey = data.identity;
  renderObjects();
  render();
  message(
    `${entries.length} ${entries.length === 1 ? "value" : "values"} in your encrypted vault.`,
  );
}
$("search").addEventListener("input", () => {
  page = 1;
  render();
});
$("group-filter").addEventListener("change", () => {
  page = 1;
  render();
});
$("page-previous").addEventListener("click", () => {
  if (page > 1) page--;
  render();
});
$("page-next").addEventListener("click", () => {
  page++;
  render();
});
function normalizePath(value) {
  const parts = value.trim().replace(/^\./, "").split(".");
  return (
    "." +
    parts
      .map((part) =>
        part
          .normalize("NFKD")
          .replace(/[\u0300-\u036f]/g, "")
          .replace(/([A-Z]+)([A-Z][a-z])/g, "$1_$2")
          .replace(/([a-z0-9])([A-Z])/g, "$1_$2")
          .toLowerCase()
          .replace(/\s+/g, "_"),
      )
      .join(".")
  );
}
const newPathPattern =
  /^\.[a-z0-9]+(?:(?:_|-)[a-z0-9]+)*(?:\[(?:0|[1-9][0-9]*)\])*(?:\.[a-z0-9]+(?:(?:_|-)[a-z0-9]+)*(?:\[(?:0|[1-9][0-9]*)\])*)*$/;
function preparePath(id) {
  const input = $(id);
  if (input.readOnly) return true;
  input.value = normalizePath(input.value);
  input.setCustomValidity(
    newPathPattern.test(input.value)
      ? ""
      : "Use lowercase names separated by _ or -, dots for objects, and numeric array indices.",
  );
  return input.reportValidity();
}
for (const id of ["edit-path", "import-path"]) {
  const input = $(id);
  input.addEventListener("input", () => input.setCustomValidity(""));
  input.addEventListener("blur", () => {
    if (input.readOnly || !input.value.trim()) return;
    input.value = normalizePath(input.value);
    input.setCustomValidity(
      newPathPattern.test(input.value)
        ? ""
        : "Use lowercase names separated by _ or -, dots for objects, and numeric array indices.",
    );
  });
}
function edit(entry) {
  editing = !!entry;
  $("editor-title").textContent = editing ? "Replace value" : "Add value";
  $("edit-path").value = entry?.path || "";
  $("edit-path").readOnly = editing;
  $("edit-path").setCustomValidity("");
  $("edit-value").value = "";
  $("edit-secret").value = entry && !entry.secret ? "public" : "secret";
  $("edit-type").value = entry && entry.type !== "string" ? "json" : "string";
  dialogError("editor", "");
  $("editor").showModal();
}
$("add").addEventListener("click", () => edit());
$("edit-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  if (!preparePath("edit-path")) return;
  const b = event.submitter;
  b.disabled = true;
  try {
    if (editing && !confirm(`Replace ${$("edit-path").value}?`)) return;
    await api("set", {
      path: $("edit-path").value,
      value: $("edit-value").value,
      secret: $("edit-secret").value === "secret",
      replace: editing,
      type: $("edit-type").value,
    });
    close("editor");
    await load();
    message("Value saved.");
  } catch (error) {
    dialogError("editor", error.message);
  } finally {
    b.disabled = false;
  }
});
function share(entry) {
  $("share-path").textContent = entry.path;
  $("share-to").value = "";
  $("share-packet").value = "";
  $("share-result").hidden = true;
  dialogError("share-dialog", "");
  $("share-dialog").showModal();
}
$("share-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  event.submitter.disabled = true;
  try {
    const result = await api("share", {
      path: $("share-path").textContent,
      to: $("share-to").value.trim(),
    });
    $("share-packet").value = result.packet;
    $("share-result").hidden = false;
    dialogError("share-dialog", "");
  } catch (error) {
    dialogError("share-dialog", error.message);
  } finally {
    event.submitter.disabled = false;
  }
});
$("share-copy").addEventListener("click", async () => {
  try {
    await navigator.clipboard.writeText($("share-packet").value);
    dialogError("share-dialog", "");
    message("Encrypted packet copied.");
  } catch {
    dialogError(
      "share-dialog",
      "Clipboard unavailable. Download the packet or select and copy it manually.",
    );
  }
});
$("share-download").addEventListener("click", () => {
  const url = URL.createObjectURL(
    new Blob([$("share-packet").value], { type: "text/plain" }),
  );
  const a = document.createElement("a");
  a.href = url;
  a.download = "workbench-share.wb";
  a.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
});
$("identity").addEventListener("click", () => {
  $("public-key").value = receivingKey;
  dialogError("identity-dialog", "");
  $("identity-dialog").showModal();
});
$("identity-copy").addEventListener("click", async () => {
  try {
    await navigator.clipboard.writeText(receivingKey);
    message("Public receiving key copied.");
  } catch {
    dialogError("identity-dialog", "Select and copy the public key manually.");
  }
});
function invalidateImport() {
  inspectedPacket = "";
  $("import-details").hidden = true;
  $("import-submit").disabled = true;
  $("import-path").required = false;
}
$("import").addEventListener("click", () => {
  $("import-form").reset();
  invalidateImport();
  dialogError("import-dialog", "");
  $("import-dialog").showModal();
});
$("import-packet").addEventListener("input", invalidateImport);
$("import-file").addEventListener("change", async () => {
  invalidateImport();
  const file = $("import-file").files[0];
  if (!file) return;
  if (file.size > 8 * 1024 * 1024) {
    dialogError("import-dialog", "Packet exceeds 8 MiB.");
    return;
  }
  $("import-packet").value = await file.text();
});
$("inspect").addEventListener("click", async () => {
  try {
    const packet = $("import-packet").value;
    const result = await api("inspect", { packet });
    inspectedPacket = packet;
    $("import-path").value = result.path;
    $("import-path").required = true;
    $("import-classification").textContent =
      `${result.secret ? "Secret" : "Public configuration"} · ${result.type}`;
    $("import-details").hidden = false;
    $("import-submit").disabled = false;
    dialogError("import-dialog", "");
  } catch (error) {
    invalidateImport();
    dialogError("import-dialog", error.message);
  }
});
$("import-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  if (!inspectedPacket || inspectedPacket !== $("import-packet").value) return;
  if (!preparePath("import-path")) return;
  event.submitter.disabled = true;
  try {
    const path = $("import-path").value;
    const replace = $("import-replace").checked;
    if (
      replace &&
      !confirm(`Import into ${path}, replacing an existing value if present?`)
    )
      return;
    await api("import", { packet: inspectedPacket, path, replace });
    close("import-dialog");
    await load();
    message("Shared value imported.");
  } catch (error) {
    dialogError("import-dialog", error.message);
  } finally {
    event.submitter.disabled = false;
  }
});
document.addEventListener("visibilitychange", () => {
  if (document.hidden) render();
});
(async () => {
  try {
    const token = location.hash.slice(1);
    history.replaceState(null, "", "/");
    const session = await api("session", { token });
    csrf = session.csrf;
    await load();
    for (const id of ["add", "search", "group-filter", "import", "identity"])
      $(id).disabled = false;
  } catch (error) {
    message(error.message, true);
  }
})();
