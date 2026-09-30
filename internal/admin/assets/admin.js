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
// the records that are unfolded, remembered by the record object itself: the
// list is redrawn on every add and remove, and the objects survive that, while
// a fresh read of the file replaces them all and so folds everything up again
const openRecords = new WeakSet();
// the bearer tokens created on this page, keyed by their record. A token is
// shown only here and only until the file is read again: the record, and so
// the file, holds nothing but its hash
const newTokens = new WeakMap();
// what the update endpoint says about the running binary, or null where it
// does not answer this session: switched off, or not an admin. It is the one
// tab the schema does not describe, since it edits no key of the file
let update = null;

const banner = document.getElementById("banner");
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
    tabs.append(tab({ label: "UPDATE" }, index));
    panels.append(updatePanel(index));
  }
  select(Math.min(selected, tabs.children.length - 1));
}

function tab(section, index) {
  const button = document.createElement("button");
  button.type = "button";
  button.textContent = section.label;
  button.setAttribute("role", "tab");
  button.addEventListener("click", () => select(index));
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
  if (section.help) {
    element.append(paragraph(section.help, "section-help"));
  }
  if (section.direct) {
    // the section is the list itself, [[users]] at the top of the file
    element.append(tableBlock(values, section.key, section.tables[0], ""));
    return element;
  }
  element.append(fieldGrid(section.fields, values[section.key], section.key));

  (section.tables || []).forEach((table) => {
    element.append(tableBlock(values[section.key], table.key, table, section.key + "." + table.key));
  });
  return element;
}

// updatePanel is the tab that uploads a new go-fs binary. The file is sent as
// it is, as octet-stream: the server checks its signature, its platform and
// that it runs, and answers before it restarts into it.
function updatePanel(index) {
  const element = document.createElement("section");
  element.hidden = index !== selected;
  element.className = "update";
  element.append(
    paragraph("Running go-fs " + update.version + " for " + update.os + "/" + update.arch
      + " from " + update.executable + ".", "update-current"),
    paragraph("Upload the go-fs_<version>_" + update.os + "_" + update.arch + ".update file of a "
      + "release. It is accepted only when it is signed with a key built into the running "
      + "binary (" + (update.keys.length ? update.keys.join(", ") : "this build has none")
      + ") and is built for this platform. go-fs then replaces its executable, keeping the "
      + "previous one beside it as .old, and restarts. Without http.httpSessionTokenSecret "
      + "the restart logs this page out.", "section-help"));

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
    button.disabled = true;
    input.disabled = true;
    say("Uploading " + file.name + "...", true);
    try {
      const answer = await fetch("?go-fs=update", {
        method: "PUT",
        headers: { "Content-Type": "application/octet-stream" },
        body: file,
      });
      const text = await answer.text();
      if (!answer.ok) {
        throw new Error(text.trim());
      }
      const result = JSON.parse(text);
      say("go-fs " + result.version + " was accepted, restarting...", true);
      await awaitRestart(result.previous);
    } catch (error) {
      say("The update was not accepted: " + error.message);
      button.disabled = false;
      input.disabled = false;
    }
  });

  const row = document.createElement("div");
  row.className = "update-upload";
  row.append(input, button);
  element.append(row);
  return element;
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
