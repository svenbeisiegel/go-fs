// The page is generated from the schema the server sends, which it in turn
// generates from the configuration struct. Nothing here knows the name of a
// single setting, so a key added to the configuration file shows up with no
// change to this file.
//
// The endpoints are asked for relative to the page, as values of the file
// server's go-fs marker, so the interface works under whatever folder it was
// opened in and reserves no name in the served one.

let schema = null;
let values = null;
// what each stored certificate or key actually is, keyed "ftps.cert", since
// base64 on its own tells the reader nothing
let summaries = {};
// the tab that is open, kept across a reload so that Apply does not send the
// reader back to the first one
let selected = 0;
// the subtab open in each section that has a row of them, by section key,
// kept across a reload the same way
const selectedSub = {};
// the records that are unfolded, remembered by the record object itself: the
// list is redrawn on every add and remove, and the objects survive that, while
// a fresh read of the file replaces them all and so folds everything up again
const openRecords = new WeakSet();
// the bearer tokens created on this page, keyed by their record. A token is
// shown only here and only until the file is read again: the record, and so
// the file, holds nothing but its hash
const newTokens = new WeakMap();
// the name each remote server has in the file, keyed by its record: the name
// can be changed on the page before Apply, and the dialog that edits the
// server has to tell the server which entry of the file it was
const storedServers = new WeakMap();
// the protocols a remote server may be reached with
let protocols = [];
// what the update endpoint says about the running binary, or null where it
// does not answer this session: switched off, or not an admin. It is the one
// tab the schema does not describe, since it edits no key of the file
let update = null;
// what the update endpoint says about the latest release: null until it has
// been asked, then { checking: true }, { info } or { error }. It is asked once
// per page, in the background, since the answer comes from GitHub
let release = null;

const banner = document.getElementById("banner");
// beside the banner rather than in it, so that no other message hides it
const releaseNotice = document.getElementById("release-notice");
const tabs = document.getElementById("tabs");
const panels = document.getElementById("panels");
const footer = document.getElementById("footer");
const status = document.getElementById("status");
const applyButton = document.getElementById("apply");

function say(text, good) {
  banner.textContent = text;
  banner.classList.toggle("good", good === true);
  banner.hidden = text === "";
}

async function load() {
  const answer = await fetch("?go-fs=admin-config", { headers: { Accept: "application/json" } });
  if (!answer.ok) {
    say("The configuration could not be read: " + (await answer.text()));
    return;
  }
  const state = await answer.json();
  schema = state.schema;
  values = state.values;
  summaries = state.summaries || {};
  protocols = state.protocols || [];
  schema.sections.forEach((section) => {
    if (section.direct && section.tables[0].create === "server") {
      (values[section.key] || []).forEach((record) => storedServers.set(record, record.name));
    }
  });

  document.getElementById("path").textContent = state.path;
  if (!state.writable) {
    say("This file cannot be written, so Apply will fail: " + state.writeError);
  } else if (!state.reload) {
    say("general.reloadConfig is off, so a change is written to the file but only "
      + "takes effect when go-fs is restarted.", true);
  } else {
    say("");
  }
  applyButton.disabled = !state.writable;
  update = await updateInfo();

  render();
  footer.hidden = false;
  if (update && release === null) {
    checkRelease(false);
  }
}

// checkRelease asks the update endpoint about the latest release and shows
// the answer on the update tab, and above the tabs when it is newer.
async function checkRelease(refresh) {
  release = { checking: true };
  showRelease();
  try {
    const answer = await fetch("?go-fs=update&release=latest" + (refresh ? "&refresh=1" : ""),
      { headers: { Accept: "application/json" } });
    const text = await answer.text();
    if (!answer.ok) {
      throw new Error(text.trim() || answer.statusText);
    }
    release = { info: JSON.parse(text) };
  } catch (error) {
    release = { error: error.message };
  }
  showRelease();
}

// updateInfo asks the update endpoint what is running. Anything but an answer
// means there is no update tab to show.
async function updateInfo() {
  try {
    const answer = await fetch("?go-fs=update", { headers: { Accept: "application/json" } });
    return answer.ok ? await answer.json() : null;
  } catch (error) {
    return null;
  }
}

function render() {
  tabs.replaceChildren();
  panels.replaceChildren();
  schema.sections.forEach((section, index) => {
    tabs.append(tab(section, index));
    panels.append(panel(section, index));
  });
  if (update) {
    const index = schema.sections.length;
    const button = tab({ label: "UPDATE" }, index);
    button.id = "update-tab";
    tabs.append(button);
    panels.append(updatePanel(index));
    showRelease();
  }
  select(Math.min(selected, tabs.children.length - 1));
}

function tab(section, index) {
  return tabButton(section.label, () => select(index));
}

function tabButton(label, open) {
  const button = document.createElement("button");
  button.type = "button";
  button.textContent = label;
  button.setAttribute("role", "tab");
  button.addEventListener("click", open);
  return button;
}

function select(index) {
  selected = index;
  Array.from(tabs.children).forEach((button, i) =>
    button.setAttribute("aria-selected", String(i === index)));
  Array.from(panels.children).forEach((section, i) => (section.hidden = i !== index));
}

function panel(section, index) {
  const element = document.createElement("section");
  element.hidden = index !== selected;
  if (!section.subsections || section.subsections.length === 0) {
    element.append(...sectionBody(section, values[section.key], section.key));
    return element;
  }

  // a section with tables nested in it, [general.ssh] and the like, gets a
  // row of tabs of its own: main for the keys of the section itself, then
  // one per nested table, each with its own description, and one per list
  // that repeats in it, [[general.cleanup]] and the like
  const own = Object.assign({}, section, { tables: [] });
  const parts = [{ key: "main", body: sectionBody(own, values[section.key], section.key) }]
    .concat(section.subsections.map((sub) => ({
      key: sub.key,
      body: sectionBody(sub, values[section.key][sub.key], section.key + "." + sub.key),
    })))
    .concat((section.tables || []).map((table) => ({
      key: table.key,
      body: [tableBlock(values[section.key], table.key, table, section.key + "." + table.key)],
    })));
  const row = document.createElement("nav");
  row.className = "subtabs";
  row.setAttribute("role", "tablist");
  row.setAttribute("aria-label", section.label);
  const bodies = parts.map((part) => {
    const body = document.createElement("div");
    body.append(...part.body);
    return body;
  });
  const show = (i) => {
    selectedSub[section.key] = parts[i].key;
    Array.from(row.children).forEach((button, j) =>
      button.setAttribute("aria-selected", String(j === i)));
    bodies.forEach((body, j) => (body.hidden = j !== i));
  };
  parts.forEach((part, i) => row.append(tabButton(part.key, () => show(i))));
  element.append(row, ...bodies);
  show(Math.max(0, parts.findIndex((part) => part.key === selectedSub[section.key])));
  return element;
}

// sectionBody is what one table of the file is shown as: its description,
// its keys, and the lists that repeat in it. path is its name in the file,
// "ftp" or "general.ssh", which the lists and the key material are found by.
function sectionBody(section, holder, path) {
  const parts = [];
  if (section.help) {
    parts.push(paragraph(section.help, "section-help"));
  }
  if (section.direct) {
    // the section is the list itself, [[users]] at the top of the file
    parts.push(tableBlock(values, section.key, section.tables[0], ""));
    return parts;
  }
  parts.push(fieldGrid(section.fields, holder, path));
  (section.tables || []).forEach((table) => {
    parts.push(tableBlock(holder, table.key, table, path + "." + table.key));
  });
  return parts;
}

// updatePanel is the tab that installs a new go-fs binary: the latest release,
// which the server downloads itself, or an update file uploaded here. Either
// way the server checks its signature, its platform and that it runs, and
// answers before it restarts into it.
function updatePanel(index) {
  const element = document.createElement("section");
  element.hidden = index !== selected;
  element.className = "update";
  const latest = document.createElement("div");
  latest.id = "release";
  latest.className = "release";
  element.append(
    paragraph("Running go-fs " + update.version + " for " + update.os + "/" + update.arch
      + " from " + update.executable + ".", "update-current"),
    latest,
    paragraph("Or upload the go-fs_<version>_" + update.os + "_" + update.arch + ".update file "
      + "of a release yourself, for a server that cannot reach GitHub. Either way the file is "
      + "accepted only when it is signed with a key built into the running binary ("
      + (update.keys.length ? update.keys.join(", ") : "this build has none")
      + ") and is built for this platform. go-fs then replaces its executable, keeping the "
      + "previous one beside it as .old, and restarts. You stay logged in, unless "
      + "http.httpSessionTokenSecret could not be stored in the configuration file.",
      "section-help"));

  const input = document.createElement("input");
  input.type = "file";
  input.accept = ".update";
  const button = document.createElement("button");
  button.type = "button";
  button.className = "plain";
  button.textContent = "Upload and restart";
  button.disabled = true;
  input.addEventListener("change", () => (button.disabled = input.files.length === 0));
  button.addEventListener("click", async () => {
    const file = input.files[0];
    if (!file) return;
    say("Uploading " + file.name + "...", true);
    await install(() => fetch("?go-fs=update", {
      method: "PUT",
      headers: { "Content-Type": "application/octet-stream" },
      body: file,
    }));
  });

  const row = document.createElement("div");
  row.className = "update-upload update-file";
  row.append(input, button);
  element.append(row);
  return element;
}

// showRelease draws what is known about the latest release: a mark on the
// update tab when it is newer, and on the tab itself what it is and the
// button that installs it.
function showRelease() {
  const button = document.getElementById("update-tab");
  const holder = document.getElementById("release");
  if (!button || !holder) return;
  const info = release && release.info;
  button.textContent = "UPDATE";
  button.classList.toggle("has-update", Boolean(info && info.newer));
  releaseNotice.hidden = !(info && info.newer);
  if (info && info.newer) {
    button.append(span(info.version, "badge"));
    const open = document.createElement("button");
    open.type = "button";
    open.className = "link";
    open.textContent = "Open the UPDATE tab";
    open.addEventListener("click", () => select(schema.sections.length));
    releaseNotice.replaceChildren("go-fs " + info.version + " is available, this server runs "
      + info.current + ". ", open);
  }

  const again = plainButton("Check again", () => checkRelease(true));
  if (!release || release.checking) {
    holder.replaceChildren(paragraph("Checking GitHub for the latest release...", "release-status"));
    return;
  }
  if (release.error) {
    holder.replaceChildren(
      paragraph("The latest release could not be looked up: " + release.error, "release-status"),
      again);
    return;
  }

  const notes = document.createElement("a");
  notes.href = info.url;
  notes.target = "_blank";
  notes.rel = "noopener noreferrer";
  notes.textContent = "release notes";
  const published = info.published ? new Date(info.published) : null;
  const when = published && !isNaN(published) ? ", published " + published.toLocaleDateString() : "";

  if (!info.newer) {
    const text = info.version === info.current
      ? "This is the latest release, go-fs " + info.version + when + " ("
      : "The latest release is go-fs " + info.version + when + ", which is not newer (";
    const status = paragraph(text, "release-status");
    status.append(notes, ").");
    holder.replaceChildren(status, again);
    return;
  }

  const status = paragraph("go-fs " + info.version + " is available" + when + " (", "release-status release-new");
  status.append(notes, ").");
  if (!info.asset) {
    status.append(" It has no update file for " + update.os + "/" + update.arch
      + ", so it cannot be installed from here.");
    holder.replaceChildren(status, again);
    return;
  }
  const install = document.createElement("button");
  install.type = "button";
  install.className = "primary";
  install.textContent = "Update to " + info.version + " and restart";
  install.addEventListener("click", () => installRelease(info));
  const row = document.createElement("div");
  row.className = "update-upload";
  row.append(install, again);
  holder.replaceChildren(status, row);
}

// installRelease has go-fs download and install the latest release.
async function installRelease(info) {
  if (!confirm("Download go-fs " + info.version + " from GitHub, install it and restart go-fs?")) {
    return;
  }
  say("Downloading and checking go-fs " + info.version + "...", true);
  await install(() => fetch("?go-fs=update&release=latest", { method: "POST" }));
}

// install sends an update with send and waits for the restart it leads to.
// Every control on the update tab is off meanwhile, and on again when the
// update was not accepted.
async function install(send) {
  const controls = Array.from(panels.querySelectorAll(".update button, .update input"));
  controls.forEach((control) => (control.disabled = true));
  try {
    const answer = await send();
    const text = await answer.text();
    if (!answer.ok) {
      throw new Error(text.trim() || answer.statusText);
    }
    const result = JSON.parse(text);
    say("go-fs " + result.version + " was accepted, restarting...", true);
    await awaitRestart(result.previous);
  } catch (error) {
    say("The update was not accepted: " + error.message);
    controls.forEach((control) => (control.disabled = false));
    // the upload button stays off until a file is chosen
    const input = panels.querySelector(".update-file input");
    const upload = panels.querySelector(".update-file button");
    if (input && upload) upload.disabled = input.files.length === 0;
  }
}

// awaitRestart waits for go-fs to come back and then reloads the page. It is
// back once it answers as another version, or answers at all after it was
// seen to be down, which also covers an upload of the same version. A 401 is
// the session that did not survive the restart; the reload leads to the login.
async function awaitRestart(previous) {
  let wentDown = false;
  for (let attempt = 0; attempt < 60; attempt++) {
    await new Promise((resolve) => setTimeout(resolve, 1000));
    try {
      const answer = await fetch("?go-fs=update", { headers: { Accept: "application/json" } });
      if (answer.status === 401) break;
      if (answer.ok) {
        const info = await answer.json();
        if (info.version !== previous || wentDown) break;
      }
    } catch (error) {
      wentDown = true;
    }
  }
  location.reload();
}

// fieldGrid lays out the plain keys of a section or of one record: one row
// per key, holding its name, its input, a help icon and the cell the help
// opens into. Every row has all four cells, so that a key with nothing to say
// keeps the rows below it aligned.
function fieldGrid(fields, holder, section) {
  const grid = document.createElement("div");
  grid.className = "fields";
  fields.forEach((field) => {
    const label = document.createElement("label");
    label.textContent = field.label;
    const input = field.upload
      ? materialEditor(field, holder, section)
      : editor(field, holder);
    label.htmlFor = input.id;
    grid.append(label, input.element, ...helpCells(field));
  });
  return grid;
}

// helpCells is the icon that opens a key's description and the cell to its
// right that it opens into. Each icon toggles its own row, so as many as the
// reader wants can be open at once, and the text lives only in the cell while
// it is open, so what is not shown is not read out either.
function helpCells(field) {
  const text = document.createElement("div");
  text.className = "help-text";
  if (!field.help) {
    return [span("", "help-toggle none"), text];
  }
  const toggle = document.createElement("button");
  toggle.type = "button";
  toggle.className = "help-toggle";
  toggle.setAttribute("aria-label", "help for " + field.label);
  toggle.append(span("?", "ring"));
  const show = (open) => {
    toggle.setAttribute("aria-expanded", String(open));
    text.textContent = open ? field.help : "";
  };
  toggle.addEventListener("click", () =>
    show(toggle.getAttribute("aria-expanded") !== "true"));
  show(false);
  return [toggle, text];
}

// A table that repeats in the file, [[users]] and the like, is shown as a list
// with one record per entry, each of which can be removed, and an Add button
// that appends an empty one. The records live in holder[key]; heading is what
// the list is titled with, empty for a list that is a tab of its own.
//
// Each record folds up to one line, and starts folded: a long account list
// reads as a list of names, and one of them opens to be edited.
function tableBlock(holder, key, table, heading) {
  const block = document.createElement("div");
  block.className = "table";

  if (heading) {
    const title = document.createElement("h3");
    title.textContent = heading;
    block.append(title);
  }
  if (table.help) {
    block.append(paragraph(table.help, "help"));
  }

  const list = document.createElement("div");
  block.append(list);

  const draw = () => {
    list.replaceChildren();
    const records = holder[key] || [];
    if (records.length === 0) {
      list.append(paragraph("No entries.", "empty"));
    }
    records.forEach((record, i) => {
      const card = document.createElement("details");
      card.className = "record";
      card.open = openRecords.has(record);
      card.addEventListener("toggle", () => {
        if (card.open) openRecords.add(record);
        else openRecords.delete(record);
      });

      const summary = document.createElement("summary");
      summary.append(span(table.key + " " + (i + 1), "ordinal"));
      const title = span(describe(table, record), "title");
      summary.append(title);

      if (table.create === "server") {
        // the login of a server is changed in the dialog, which logs in
        // with it before storing it
        const edit = document.createElement("button");
        edit.type = "button";
        edit.className = "plain edit";
        edit.textContent = "Edit…";
        edit.addEventListener("click", (event) => {
          event.preventDefault();
          event.stopPropagation();
          serverDialog.open(table, record, () => draw());
        });
        summary.append(edit);
      }

      const remove = document.createElement("button");
      remove.type = "button";
      remove.className = "plain remove";
      remove.textContent = "Remove";
      remove.addEventListener("click", (event) => {
        // a button inside the summary would otherwise fold it too
        event.preventDefault();
        event.stopPropagation();
        records.splice(i, 1);
        draw();
      });
      summary.append(remove);
      card.append(summary);

      if (newTokens.has(record)) {
        card.append(tokenNotice(newTokens.get(record)));
      }
      card.append(fieldGrid(table.fields, record, ""));
      // the line the record folds up to follows what is typed into it
      const refresh = () => (title.textContent = describe(table, record));
      card.addEventListener("input", refresh);
      card.addEventListener("change", refresh);
      list.append(card);
    });
  };

  const append = (record) => {
    if (!holder[key]) {
      holder[key] = [];
    }
    holder[key].push(record);
    // a new record is there to be filled in, so it starts open
    openRecords.add(record);
    draw();
  };

  draw();
  if (table.create === "token") {
    block.append(tokenCreator(table, (record) => {
      append(record);
      list.lastElementChild.scrollIntoView({ block: "nearest" });
    }));
    return block;
  }

  if (table.create === "server") {
    block.append(plainButton("Add server…", () =>
      serverDialog.open(table, null, (record) => {
        append(record);
        list.lastElementChild.scrollIntoView({ block: "nearest" });
      })));
    return block;
  }

  const add = document.createElement("button");
  add.type = "button";
  add.className = "plain";
  add.textContent = "Add " + table.key;
  add.addEventListener("click", () => {
    append(blank(table.fields));
    const first = list.lastElementChild.querySelector("input, textarea");
    if (first) first.focus();
  });
  block.append(add);
  return block;
}

// tokenCreator is the Add button of a list whose records the server makes: a
// bearer token is random, and the file keeps only its hash, so a new one is
// asked for with a name and a lifetime rather than typed in. done is handed
// the new record.
function tokenCreator(table, done) {
  const form = document.createElement("div");
  form.className = "create";

  const name = document.createElement("input");
  name.type = "text";
  name.id = "field-" + ++sequence;
  name.spellcheck = false;
  name.placeholder = "what uses it, e.g. backup-job";
  const nameLabel = document.createElement("label");
  nameLabel.textContent = "name";
  nameLabel.htmlFor = name.id;

  const days = document.createElement("input");
  days.type = "number";
  days.id = "field-" + ++sequence;
  days.min = "0";
  days.step = "1";
  days.value = "0";
  const daysLabel = document.createElement("label");
  daysLabel.textContent = "lifetime in days (0 = never expires)";
  daysLabel.htmlFor = days.id;

  const problem = paragraph("", "problem");
  problem.hidden = true;
  const report = (text) => {
    problem.textContent = text;
    problem.hidden = text === "";
  };

  const create = plainButton("Create " + table.key.replace(/s$/, ""), async () => {
    report("");
    const label = name.value.trim();
    if (label === "") {
      report("A token needs a name.");
      name.focus();
      return;
    }
    const lifetime = Number(days.value || "0");
    if (!Number.isInteger(lifetime) || lifetime < 0) {
      report("The lifetime is a whole number of days, 0 for a token that never expires.");
      days.focus();
      return;
    }
    try {
      const result = await post("?go-fs=admin-generate",
        { kind: "token", name: label, days: lifetime });
      const record = blank(table.fields);
      record.name = label;
      record.hash = result.hash;
      record.expires = result.expires;
      newTokens.set(record, result.value);
      name.value = "";
      days.value = "0";
      done(record);
    } catch (error) {
      report(String(error.message || error));
    }
  });

  const row = document.createElement("div");
  row.className = "inputs";
  row.append(nameLabel, name, daysLabel, days, create);
  form.append(row, problem);
  return form;
}

// serverDialog adds and edits a remote server. It asks the server for the key
// the host shows, the admin accepts it, and the server logs in with the login
// and that key before it writes the entry into the file, at once and with
// nothing else of the page. The record on the page is then what the file
// holds. A protocol reached by an address and a token, Artifactory, asks for
// those in place of the host and the login, and shows no key.
const serverDialog = (() => {
  const dialog = document.getElementById("server-dialog");
  const form = dialog.querySelector("form");
  const title = dialog.querySelector("#server-title");
  const keyBox = dialog.querySelector(".hostkey");
  const note = keyBox.querySelector(".note");
  const keyHost = keyBox.querySelector(".host");
  const keyType = keyBox.querySelector(".fingerprint .type");
  const keyPrint = keyBox.querySelector(".fingerprint code");
  const progress = dialog.querySelector(".progress");
  const connect = form.querySelector("button[value='connect']");
  const save = form.querySelector("button[value='save']");
  const field = (name) => form.elements[name];

  // record is the server edited, null for a new one; done is told the
  // record once it is stored; key is the fingerprint the host showed
  let record = null;
  let done = null;
  let key = "";
  let step = "connect";
  // asked counts the questions put to the server, so that the answer to one
  // that was overtaken is dropped
  let asked = 0;

  const protocol = () => protocols.find((p) => p.id === field("type").value) || null;

  function tell(text, bad) {
    progress.textContent = text;
    progress.classList.toggle("bad", bad === true);
    progress.hidden = text === "";
  }

  function show(next) {
    step = next;
    keyBox.hidden = next !== "hostkey";
    connect.hidden = next !== "connect";
    save.hidden = next !== "hostkey";
  }

  // a field of the login the protocol does not use is hidden, and disabled
  // so that the form does not ask for it
  function working(on) {
    Array.from(form.elements).forEach((element) => {
      if (element.value !== "cancel") element.disabled = on || element.hidden;
    });
  }

  // fields shows the fields of the login the protocol chosen asks for
  function fields() {
    const byToken = protocol() !== null && protocol().token === true;
    form.querySelectorAll("[data-login]").forEach((element) => {
      element.hidden = (element.dataset.login === "token") !== byToken;
      if (element.tagName !== "LABEL") element.disabled = element.hidden;
    });
  }

  // what the dialog knows of the host is forgotten once the login changes
  function forget() {
    asked++;
    key = "";
    tell("");
    show("connect");
  }

  function login() {
    return {
      name: field("name").value.trim(),
      type: field("type").value,
      host: field("host").value.trim(),
      port: Number(field("port").value) || 0,
      username: field("username").value.trim(),
      password: field("password").value,
      url: field("url").value.trim(),
      token: field("token").value.trim(),
    };
  }

  // a host the key of which is accepted as stored is the one the record has
  function sameHost() {
    const now = login();
    const port = (p) => Number(p) || (protocol() ? protocol().defaultPort : 0);
    return record !== null && now.type === record.type && now.host === record.host &&
      port(now.port) === port(record.port);
  }

  async function connectHost() {
    const ticket = ++asked;
    working(true);
    tell("Connecting…");
    try {
      if (protocol() && !protocol().hostKey) {
        // a host that shows no key is logged in to at once
        await store(ticket);
        return;
      }
      const view = await post("?go-fs=admin-server-hostkey", { server: login() });
      if (ticket !== asked) return;
      working(false);
      tell("");
      key = view.fingerprint;
      const before = sameHost() ? record.hostKeyFingerprint : "";
      if (before && before === key) {
        note.textContent = "This is the key the server is stored with.";
        note.classList.remove("bad");
      } else if (before) {
        note.textContent = "This is not the key the server is stored with. That happens when the host "
          + "was set up anew, and when someone stands between it and go-fs. Do not accept it unless you "
          + "know why it changed.";
        note.classList.add("bad");
      } else {
        note.textContent = "";
      }
      note.hidden = note.textContent === "";
      keyHost.textContent = view.host;
      keyType.textContent = view.keyType;
      keyPrint.textContent = view.fingerprint;
      show("hostkey");
      save.focus();
    } catch (error) {
      if (ticket !== asked) return;
      working(false);
      tell(String(error.message || error), true);
      show("connect");
    }
  }

  async function store(ticket) {
    working(true);
    tell("Logging in…");
    try {
      const result = await post("?go-fs=admin-server-save", {
        was: record ? storedServers.get(record) || "" : "",
        server: login(),
        hostKey: key,
      });
      if (ticket !== asked) return;
      working(false);
      const stored = record || {};
      Object.assign(stored, result.record);
      storedServers.set(stored, stored.name);
      dialog.close();
      say("The server " + stored.name + " was logged in to and written to " + result.path
        + (result.reload ? ", and is offered from the next reload of the file on." : "; it is offered once go-fs is restarted."), true);
      done(stored);
    } catch (error) {
      if (ticket !== asked) return;
      working(false);
      tell(String(error.message || error), true);
      show(key ? "hostkey" : "connect");
    }
  }

  form.addEventListener("input", (event) => {
    // the name is not the login: the key that was shown still holds
    if (event.target !== field("name") && (step !== "connect" || key)) {
      forget();
    }
  });

  field("type").addEventListener("change", () => {
    const chosen = protocol();
    if (chosen && chosen.defaultPort) field("port").value = String(chosen.defaultPort);
    fields();
  });

  // Enter presses whichever button acts first in the form, so what is done
  // is decided by the step rather than by the button.
  form.addEventListener("submit", (event) => {
    const pressed = event.submitter ? event.submitter.value : "";
    if (pressed === "cancel") {
      return;
    }
    event.preventDefault();
    if (step === "connect") {
      connectHost();
    } else {
      store(++asked);
    }
  });

  dialog.addEventListener("close", () => {
    asked++;
    working(false);
  });

  function open(table, edited, then) {
    record = edited;
    done = then;
    title.textContent = edited ? "Edit server " + edited.name : "Add server";
    const select = field("type");
    select.replaceChildren(...protocols.map((p) => {
      const option = document.createElement("option");
      option.value = p.id;
      option.textContent = p.label;
      return option;
    }));
    const from = edited || {};
    select.value = from.type || (protocols[0] ? protocols[0].id : "");
    field("name").value = from.name || "";
    field("host").value = from.host || "";
    field("port").value = String(from.port || (protocol() ? protocol().defaultPort : ""));
    field("username").value = from.username || "";
    field("password").value = "";
    field("url").value = from.url || "";
    field("token").value = "";
    // an edit keeps the password and the token stored unless another is
    // typed in
    field("password").placeholder = edited ? "unchanged unless typed in" : "";
    field("token").placeholder = edited ? "unchanged unless typed in" : "sent as Authorization: Bearer";
    fields();
    forget();
    working(false);
    dialog.showModal();
    const first = protocol() && protocol().token ? "url" : "host";
    field(edited ? first : "name").focus();
  }

  return { open };
})();

// tokenNotice shows a token that was just created, the one time it is shown.
function tokenNotice(token) {
  const notice = document.createElement("div");
  notice.className = "token-notice";
  notice.append(paragraph("Copy this token now: it is shown only until the page "
    + "is read again, and it is accepted once Apply has written it. Send it as "
    + "\"Authorization: Bearer <token>\".", ""));
  const row = document.createElement("div");
  row.className = "secret";
  const value = document.createElement("input");
  value.type = "text";
  value.readOnly = true;
  value.value = token;
  value.addEventListener("focus", () => value.select());
  const copy = document.createElement("button");
  copy.type = "button";
  copy.textContent = "copy";
  copy.addEventListener("click", async () => {
    try {
      await navigator.clipboard.writeText(token);
      copy.textContent = "copied";
    } catch {
      value.select();
    }
  });
  row.append(value, copy);
  notice.append(row);
  return notice;
}

// describe is the line a folded record is named by: the fields the schema
// marks for it, which are its first text and its switches. A switch reads as
// its name when it is on and as nothing when it is off.
function describe(table, record) {
  const parts = [];
  const on = [];
  table.fields.forEach((field) => {
    if (!field.summary) return;
    if (field.kind === "bool") {
      if (record[field.key]) on.push(field.label);
    } else if (record[field.key]) {
      parts.push(record[field.key]);
    }
  });
  if (on.length > 0) parts.push(on.join(", "));
  return parts.join(" \u00b7 ");
}

function span(text, className) {
  const element = document.createElement("span");
  element.className = className;
  element.textContent = text;
  return element;
}

// blank is a new record with every key at its zero value, which is what an
// unset key means in the file.
function blank(fields) {
  const record = {};
  fields.forEach((field) => {
    if (field.kind === "bool") record[field.key] = false;
    else if (field.kind === "int") record[field.key] = 0;
    else if (field.kind === "lines") record[field.key] = [];
    else record[field.key] = "";
  });
  return record;
}

let sequence = 0;

// editor builds the input for one key and wires it straight into the value it
// edits, so that Apply posts what is on the screen with nothing to collect.
function editor(field, holder) {
  const id = "field-" + ++sequence;
  const set = (value) => (holder[field.key] = value);

  if (field.kind === "bool") {
    const input = document.createElement("input");
    input.type = "checkbox";
    input.id = id;
    input.checked = holder[field.key] === true;
    input.addEventListener("change", () => set(input.checked));
    return { element: input, id };
  }

  if (field.kind === "lines") {
    const input = document.createElement("textarea");
    input.id = id;
    input.spellcheck = false;
    input.placeholder = "one entry per line";
    input.value = (holder[field.key] || []).join("\n");
    input.addEventListener("input", () =>
      set(input.value.split("\n").map((line) => line.trim()).filter((line) => line !== "")));
    return { element: input, id };
  }

  const input = document.createElement("input");
  input.id = id;
  input.spellcheck = false;

  if (field.kind === "int") {
    input.type = "number";
    input.step = "1";
    input.value = String(holder[field.key] ?? 0);
    // kept as text: an empty box is not a number, and the server reads "" as 0
    input.addEventListener("input", () => set(input.value));
    if (field.readOnly) {
      input.readOnly = true;
      input.className = "readonly";
    }
    return { element: input, id };
  }

  input.type = field.kind === "secret" ? "password" : "text";
  input.value = holder[field.key] ?? "";
  input.addEventListener("input", () => set(input.value));
  if (field.readOnly) {
    // made by the server and sent back as it came
    input.readOnly = true;
    input.className = "readonly";
    return { element: input, id };
  }
  if (field.kind !== "secret") {
    return { element: input, id };
  }

  const wrapper = document.createElement("div");
  wrapper.className = "secret";
  const reveal = document.createElement("button");
  reveal.type = "button";
  reveal.textContent = "show";
  reveal.addEventListener("click", () => {
    const hidden = input.type === "password";
    input.type = hidden ? "text" : "password";
    reveal.textContent = hidden ? "hide" : "show";
  });
  wrapper.append(input, reveal);
  return { element: wrapper, id };
}

// A certificate or a key is not typed in: it is the content of a file, held in
// the configuration as base64. So the box comes with an Upload button that
// posts the file for the server to validate, and a Generate button that makes
// a real one instead of the throwaway the server makes at every start when the
// key is empty. Both only put a value on the page; Apply writes it.
function materialEditor(field, holder, section) {
  const id = "field-" + ++sequence;
  const path = section ? section + "." + field.key : field.key;

  const wrapper = document.createElement("div");
  wrapper.className = "material";

  const input = document.createElement("textarea");
  input.id = id;
  input.className = "blob";
  input.rows = 3;
  input.spellcheck = false;
  input.placeholder = "empty: generated at every start";
  input.value = holder[field.key] ?? "";

  const summary = paragraph(summaries[path] || "", "summary");
  const problem = paragraph("", "problem");
  const report = (text) => {
    problem.textContent = text;
    problem.hidden = text === "";
  };
  report("");

  // a value typed or pasted in is not the one the server described
  input.addEventListener("input", () => {
    holder[field.key] = input.value.trim();
    summary.textContent = "";
    report("");
  });

  const buttons = document.createElement("div");
  buttons.className = "buttons";

  const picker = document.createElement("input");
  picker.type = "file";
  picker.hidden = true;
  picker.accept = accepts(field.upload);
  picker.addEventListener("change", async () => {
    const file = picker.files[0];
    picker.value = "";
    if (!file) return;
    report("");
    try {
      const result = await post("?go-fs=admin-upload", {
        kind: field.upload,
        filename: file.name,
        content: await base64Of(file),
      });
      holder[field.key] = result.value;
      summaries[path] = result.summary;
      render();
    } catch (error) {
      report(String(error.message || error));
    }
  });

  // a signing key is random bytes rather than something that arrives as a
  // file, so it is generated or pasted, never uploaded
  if (field.upload !== "sessionsecret") {
    buttons.append(picker, plainButton("Upload\u2026", () => picker.click()));
  }

  // only a certificate and a host key can be generated: a private key on its
  // own would not match any certificate
  if (field.upload !== "tlskey") {
    buttons.append(plainButton("Generate", async () => {
      report("");
      try {
        const result = await post("?go-fs=admin-generate", { kind: field.upload });
        holder[field.key] = result.value;
        summaries[path] = result.summary;
        if (field.pair) {
          holder[field.pair] = result.pairValue;
          summaries[section + "." + field.pair] = result.pairSummary;
        }
        render();
      } catch (error) {
        report(String(error.message || error));
      }
    }));
  }

  buttons.append(plainButton("Clear", () => {
    holder[field.key] = "";
    summaries[path] = "";
    render();
  }));

  // a private key is not shown until it is asked for, the way the one line
  // secrets are masked
  if (field.kind === "secret" && input.value !== "") {
    input.hidden = true;
    buttons.append(plainButton("show", (event) => {
      input.hidden = !input.hidden;
      event.target.textContent = input.hidden ? "show" : "hide";
    }));
  }

  wrapper.append(input, buttons, summary, problem);
  return { element: wrapper, id };
}

function plainButton(text, onClick) {
  const button = document.createElement("button");
  button.type = "button";
  button.className = "plain";
  button.textContent = text;
  button.addEventListener("click", onClick);
  return button;
}

// accepts is a hint for the file dialog only. What a file may be is decided by
// the server, which parses it.
function accepts(kind) {
  if (kind === "certificate") return ".pem,.crt,.cer,.cert";
  if (kind === "sessionsecret") return ".txt,.key";
  return ".pem,.key,.p8";
}

// base64Of reads a file the way it is posted. A data URL is the one reader
// result that is already base64, so the prefix is all there is to strip.
function base64Of(file) {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onerror = () => reject(new Error("the file could not be read"));
    reader.onload = () => resolve(String(reader.result).split(",")[1] || "");
    reader.readAsDataURL(file);
  });
}

async function post(url, body) {
  const answer = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  const text = await answer.text();
  if (!answer.ok) {
    throw new Error(text.trim());
  }
  return JSON.parse(text);
}

function paragraph(text, className) {
  const element = document.createElement("p");
  element.className = className;
  element.textContent = text;
  return element;
}

applyButton.addEventListener("click", async () => {
  applyButton.disabled = true;
  status.textContent = "writing...";
  try {
    const answer = await fetch("?go-fs=admin-config", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(values),
    });
    const text = await answer.text();
    if (!answer.ok) {
      say(text.trim());
      status.textContent = "not written";
      return;
    }
    const result = JSON.parse(text);
    const note = "Written to " + result.path + ". The previous file is " + result.backup
      + (result.reload
        ? ". go-fs applies it within the next few seconds."
        : ". general.reloadConfig is off, so it applies at the next restart.");
    status.textContent = "written";
    // reading the file back is what the page then shows, so the message about
    // the write is set after it rather than being cleared by it
    await load();
    say(note, true);
  } catch (error) {
    say(String(error));
    status.textContent = "not written";
  } finally {
    applyButton.disabled = false;
  }
});

// The menu in the corner of the header is a details element and opens and
// closes on its own; what is added is closing it on a click beside it and on
// Escape, as a menu is expected to.
const nav = document.querySelector("details.nav");
if (nav) {
  document.addEventListener("click", (event) => {
    if (nav.open && !nav.contains(event.target)) {
      nav.open = false;
    }
  }, true);
  nav.addEventListener("keydown", (event) => {
    if (event.key === "Escape" && nav.open) {
      event.preventDefault();
      nav.open = false;
      nav.querySelector("summary").focus();
    }
  });
}

load();
