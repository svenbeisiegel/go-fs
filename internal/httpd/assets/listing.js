// The page is complete without this script: the listing is rendered by the
// server and the sort headers are ordinary links. What is added here is the
// part a link cannot do — sorting without a round trip, filtering, and the
// requests that create, rename, remove and upload.
(function () {
  "use strict";

  // #/admin is the address the admin interface is remembered by, but a
  // fragment never reaches the server, so the page turns it into the marker
  // the server answers under. Typing it into the address bar of a listing
  // that is already open changes only the fragment, which is what the
  // second hook is for.
  function toAdmin() {
    if (window.location.hash === "#/admin") {
      window.location.replace(window.location.pathname + "?go-fs=admin");
      return true;
    }
    return false;
  }
  window.addEventListener("hashchange", toAdmin);
  if (toAdmin()) {
    return;
  }

  var table = document.getElementById("listing");
  if (!table) {
    return;
  }
  var body = table.tBodies[0];
  // folder is the path this page lists, always with a trailing slash and
  // already escaped: every request below appends one escaped segment to it.
  var folder = table.dataset.folder;
  var banner = document.getElementById("banner");
  // maxChunkSize is the largest piece an upload is split into; 0 means
  // chunked upload is off and a large file is sent as one request, as before.
  var maxChunkSize = parseInt(table.dataset.maxChunkSize, 10) || 0;

  function rows() {
    return Array.prototype.slice.call(body.rows).filter(function (row) {
      return row.dataset.name !== undefined;
    });
  }

  function segment(name) {
    return folder + encodeURIComponent(name);
  }

  function say(message, good) {
    banner.textContent = message;
    banner.classList.toggle("good", good === true);
    banner.hidden = false;
  }

  function clear() {
    banner.hidden = true;
  }

  // A refused write is answered with a bare status, so what it meant depends on
  // what was asked for: the same 404 is a folder with something still in it,
  // a name already taken, or a file somebody else removed first.
  var refusals = {
    create: {
      404: "That name is taken, or the folder above it is gone.",
      405: "There is already something with that name."
    },
    rename: {
      404: "The file is gone, or the name you typed is not allowed here.",
      412: "There is already something with that name."
    },
    file: { 404: "That file is already gone." },
    folder: { 404: "The folder still has something in it, or it is already gone." },
    upload: {
      403: "You may not upload here, or there is already a file with that name and you may not replace it.",
      404: "There is already a file with that name.",
      416: "This upload lost sync with the server — try uploading it again."
    }
  };

  function reason(what, status, text) {
    // a session can now run out while the page is open, which is a different
    // thing from never having been allowed
    if (status === 401) {
      return "Your session has ended \u2014 reload the page to log in again.";
    }
    var known = refusals[what] || {};
    if (known[status]) {
      return known[status];
    }
    if (status === 403) {
      return "You are not allowed to do that here.";
    }
    if (status === 409) {
      return "The folder above it does not exist.";
    }
    if (status === 413) {
      return text || "The file is larger than this server accepts.";
    }
    return text || ("The server answered " + status + ".");
  }

  function send(what, method, url, headers) {
    return fetch(url, {
      method: method,
      headers: headers || {},
      credentials: "same-origin"
    }).then(function (res) {
      if (res.ok) {
        return null;
      }
      return res.text().then(function (text) {
        throw new Error(reason(what, res.status, text.trim()));
      });
    });
  }

  function done() {
    window.location.reload();
  }

  function failed(err) {
    say(err.message);
  }

  // --- sorting ---------------------------------------------------------
  //
  // The default order — folders first, then files, both by name — is the one
  // the server rendered, so the header cycles back to it after descending
  // rather than leaving no way to return to it.

  var order = { key: table.dataset.sort || "", dir: table.dataset.dir || "asc" };
  // the columns the server rendered, so that a remembered order naming one it
  // no longer has is thrown away rather than applied to nothing
  var columns = Array.prototype.map.call(table.querySelectorAll("th[data-key]"), function (cell) {
    return cell.dataset.key;
  });
  var remembered = "go-fs.listing.order";

  function value(row, key) {
    if (key === "size") {
      return Number(row.dataset.size);
    }
    if (key === "date") {
      return Number(row.dataset.time);
    }
    if (key === "type") {
      return row.dataset.kind.toLowerCase();
    }
    return row.dataset.name.toLowerCase();
  }

  function compare(a, b, key, sign) {
    var x = value(a, key);
    var y = value(b, key);
    if (x < y) {
      return -sign;
    }
    if (x > y) {
      return sign;
    }
    // a stable tie break, so two files of the same size never swap places
    return a.dataset.name.toLowerCase() < b.dataset.name.toLowerCase() ? -1 : 1;
  }

  function arrange() {
    var list = rows();
    var sign = order.dir === "desc" ? -1 : 1;
    if (order.key === "") {
      list.sort(function (a, b) {
        var group = Number(b.dataset.dir) - Number(a.dataset.dir);
        return group !== 0 ? group : compare(a, b, "name", 1);
      });
    } else {
      var key = order.key;
      list.sort(function (a, b) {
        return compare(a, b, key, sign);
      });
    }
    list.forEach(function (row) {
      body.appendChild(row);
    });

    Array.prototype.forEach.call(table.tHead.rows[0].cells, function (cell) {
      var key = cell.dataset.key;
      if (key === undefined) {
        return;
      }
      if (key === order.key && order.key !== "") {
        cell.setAttribute("aria-sort", order.dir === "desc" ? "descending" : "ascending");
        cell.querySelector(".caret").textContent = order.dir === "desc" ? "▼" : "▲";
      } else {
        cell.removeAttribute("aria-sort");
        cell.querySelector(".caret").textContent = "";
      }
    });
  }

  // next is the state a click on a column moves to: ascending, descending, then
  // no order at all, which is the grouped default the page was rendered in.
  function next(key) {
    if (order.key !== key) {
      return { key: key, dir: "asc" };
    }
    if (order.dir === "asc") {
      return { key: key, dir: "desc" };
    }
    return { key: "", dir: "asc" };
  }

  function retarget() {
    Array.prototype.forEach.call(table.querySelectorAll("th[data-key] a"), function (link) {
      var state = next(link.parentNode.dataset.key);
      link.setAttribute("href", query(state));
    });
  }

  function query(state) {
    if (state.key === "") {
      return "?";
    }
    return "?sort=" + state.key + "&dir=" + state.dir;
  }

  // show writes the order into the address bar, so that a reload, a copied link
  // and what is on screen all say the same thing.
  function show() {
    var url = window.location.pathname;
    if (order.key !== "") {
      url += query(order);
    }
    window.history.replaceState(null, "", url);
  }

  // The order is remembered for the server rather than for one folder: somebody
  // who sorted by size wants the folder they open next sorted by size too.
  // Storage can be switched off or full, which costs the preference and nothing
  // else, so every use of it is allowed to fail quietly.
  function keep(state) {
    try {
      if (state.key === "") {
        window.localStorage.removeItem(remembered);
      } else {
        window.localStorage.setItem(remembered, state.key + ":" + state.dir);
      }
    } catch (ignored) {
      return;
    }
  }

  function recall() {
    var stored = null;
    try {
      stored = window.localStorage.getItem(remembered);
    } catch (ignored) {
      return null;
    }
    if (!stored) {
      return null;
    }
    var parts = stored.split(":");
    if (columns.indexOf(parts[0]) === -1 || (parts[1] !== "asc" && parts[1] !== "desc")) {
      // written by an older version, or by hand
      keep({ key: "" });
      return null;
    }
    return { key: parts[0], dir: parts[1] };
  }

  Array.prototype.forEach.call(table.querySelectorAll("th[data-key] a"), function (link) {
    link.addEventListener("click", function (event) {
      event.preventDefault();
      order = next(link.parentNode.dataset.key);
      arrange();
      retarget();
      keep(order);
      show();
    });
  });

  // A query string is somebody asking for an order outright — a link they were
  // sent, or a reload — so it wins and becomes the preference. With none, the
  // preference is what decides, which is how an order survives walking into
  // another folder: the links between folders are relative and carry nothing.
  if (new URLSearchParams(window.location.search).has("sort")) {
    keep(order);
  } else {
    var restored = recall();
    if (restored) {
      order = restored;
      arrange();
      retarget();
      show();
    }
  }

  // --- filtering -------------------------------------------------------

  var filter = document.getElementById("filter");
  if (filter) {
    filter.addEventListener("input", function () {
      var needle = filter.value.trim().toLowerCase();
      rows().forEach(function (row) {
        row.classList.toggle("gone",
          needle !== "" && row.dataset.name.toLowerCase().indexOf(needle) === -1);
      });
    });
  }

  // --- dialogs ---------------------------------------------------------

  var asking = document.getElementById("prompt");
  var checking = document.getElementById("confirm");
  var onAccept = null;
  var onAgree = null;

  function ask(title, detail, current, label, then) {
    asking.querySelector("h2").textContent = title;
    asking.querySelector("p").textContent = detail;
    asking.querySelector(".go").textContent = label;
    var field = asking.querySelector("input");
    field.value = current;
    onAccept = function () {
      var typed = field.value.trim();
      if (typed === "" || typed === current) {
        return;
      }
      then(typed);
    };
    asking.showModal();
    field.focus();
    var stem = current.lastIndexOf(".");
    field.setSelectionRange(0, stem > 0 ? stem : current.length);
  }

  // The submit event rather than close: a dialog closed by its own form does
  // not reliably report a close, and submit says which button was pressed
  // while the answer is still in front of it. An implicit submit — Enter in the
  // field — names no button, and the markup puts the acting one first so that
  // it is the one the browser would have picked anyway.
  function answered(dialog, taken) {
    dialog.querySelector("form").addEventListener("submit", function (event) {
      var pending = taken();
      if (event.submitter && event.submitter.value === "cancel") {
        return;
      }
      if (pending) {
        pending();
      }
    });
  }

  answered(asking, function () {
    var pending = onAccept;
    onAccept = null;
    return pending;
  });

  answered(checking, function () {
    var pending = onAgree;
    onAgree = null;
    return pending;
  });

  // --- actions ---------------------------------------------------------

  var makeFolder = document.getElementById("new-folder");
  if (makeFolder) {
    makeFolder.addEventListener("click", function () {
      clear();
      ask("New folder", "It is created in " + decodeURI(folder) + ".", "", "Create", function (name) {
        send("create", "MKCOL", segment(name) + "/").then(done).catch(failed);
      });
    });
  }

  body.addEventListener("click", function (event) {
    var button = event.target.closest("button[data-do]");
    if (!button) {
      return;
    }
    clear();
    var row = button.closest("tr");
    var name = row.dataset.name;
    var isFolder = row.dataset.dir === "1";
    if (button.dataset.do === "rename") {
      ask("Rename", decodeURI(folder) + name, name, "Rename", function (typed) {
        send("rename", "MOVE", segment(name), { Destination: segment(typed) }).then(done).catch(failed);
      });
      return;
    }
    checking.querySelector("h2").textContent = isFolder ? "Delete folder" : "Delete file";
    checking.querySelector("p").textContent = isFolder
      ? "Delete " + decodeURI(folder) + name + "? Only an empty folder can be removed."
      : "Delete " + decodeURI(folder) + name + "? This cannot be undone.";
    onAgree = function () {
      send(isFolder ? "folder" : "file", "DELETE", segment(name)).then(done).catch(failed);
    };
    checking.showModal();
  });

  // --- uploading -------------------------------------------------------
  //
  // XMLHttpRequest rather than fetch, because only it reports how far an
  // upload has got.

  var drop = document.getElementById("drop");
  if (!drop) {
    return;
  }
  var picker = document.getElementById("picker");
  var queue = document.getElementById("queue");

  document.getElementById("upload").addEventListener("click", function () {
    picker.click();
  });
  picker.addEventListener("change", function () {
    accept(picker.files);
    picker.value = "";
  });

  ["dragenter", "dragover"].forEach(function (name) {
    document.addEventListener(name, function (event) {
      event.preventDefault();
      drop.classList.add("over");
    });
  });
  document.addEventListener("dragleave", function (event) {
    if (event.target === drop || event.relatedTarget === null) {
      drop.classList.remove("over");
    }
  });
  document.addEventListener("drop", function (event) {
    event.preventDefault();
    drop.classList.remove("over");
    if (event.dataTransfer && event.dataTransfer.files.length) {
      accept(event.dataTransfer.files);
    }
  });

  function accept(files) {
    clear();
    var pending = Array.prototype.slice.call(files);
    if (!pending.length) {
      return;
    }
    queue.hidden = false;
    // every file gets its own reason: dropping ten at once and being told only
    // why the last one failed says nothing about the other nine
    var problems = [];
    function step() {
      if (!pending.length) {
        if (problems.length === 0) {
          done();
          return;
        }
        // no reload, because it would take the reasons with it
        say(problems.join("\n"));
        return;
      }
      put(pending.shift(), function (problem) {
        if (problem) {
          problems.push(problem);
        }
        step();
      });
    }
    step();
  }

  function put(file, then) {
    var line = document.createElement("li");
    var label = document.createElement("span");
    label.className = "what";
    label.textContent = file.name;
    var track = document.createElement("span");
    track.className = "track";
    var fill = document.createElement("span");
    fill.className = "fill";
    track.appendChild(fill);
    var state = document.createElement("span");
    state.className = "state";
    state.textContent = "0%";
    line.appendChild(label);
    line.appendChild(track);
    line.appendChild(state);
    queue.appendChild(line);

    function progress(fraction) {
      var percent = Math.round(fraction * 100);
      fill.style.width = percent + "%";
      state.textContent = percent + "%";
    }
    function succeed() {
      fill.style.width = "100%";
      state.textContent = "done";
      then(null);
    }
    function fail(problem) {
      line.classList.add("failed");
      fill.style.width = "100%";
      state.textContent = "failed";
      line.title = problem;
      then(problem);
    }

    if (!maxChunkSize || file.size <= maxChunkSize) {
      putWhole(file, progress, succeed, fail);
      return;
    }
    putChunked(file, progress, succeed, fail);
  }

  // putWhole sends a file as a single request, exactly as every upload was
  // sent before chunking existed: still the path for anything at or under
  // maxChunkSize, and for every upload when chunking is off.
  function putWhole(file, progress, succeed, fail) {
    var request = new XMLHttpRequest();
    request.open("PUT", segment(file.name));
    request.setRequestHeader("Content-Type", "application/octet-stream");
    request.withCredentials = true;
    request.upload.addEventListener("progress", function (event) {
      if (event.lengthComputable) {
        progress(event.loaded / event.total);
      }
    });
    request.addEventListener("load", function () {
      if (request.status >= 200 && request.status < 300) {
        succeed();
        return;
      }
      fail(file.name + ": " + reason("upload", request.status, request.responseText.trim()));
    });
    request.addEventListener("error", function () {
      fail(file.name + ": the upload could not be sent.");
    });
    request.send(file);
  }

  // chunkRetries is how many times the current chunk of a chunked upload is
  // retried before the whole file is reported as failed. A chunk that lands
  // stays landed on the server (its staging file only grows, never shrinks
  // below a completed chunk's end), so retrying is always safe: it never
  // restarts the file from the beginning.
  var chunkRetries = 3;

  // putChunked sends a file as consecutive Content-Range PUTs of at most
  // maxChunkSize each, to the same URL a whole-file PUT uses. The server's
  // staging file is the only record of how far the upload has gotten; a 416
  // means the server's idea of that offset differs from this one (an earlier
  // attempt's chunk landing after this page stopped waiting for it, most
  // likely), and is answered by resuming from the offset the response names,
  // once, rather than treating a resync as a failed upload.
  function putChunked(file, progress, succeed, fail) {
    var sent = 0;
    var retries = 0;
    var resynced = false;

    function sendFrom(start) {
      var end = Math.min(start + maxChunkSize, file.size);

      function retry(problem) {
        if (retries < chunkRetries) {
          retries++;
          sendFrom(start);
          return;
        }
        fail(problem);
      }

      var request = new XMLHttpRequest();
      request.open("PUT", segment(file.name));
      request.setRequestHeader("Content-Type", "application/octet-stream");
      request.setRequestHeader("Content-Range",
        "bytes " + start + "-" + (end - 1) + "/" + file.size);
      request.withCredentials = true;
      request.upload.addEventListener("progress", function (event) {
        if (event.lengthComputable) {
          progress((sent + event.loaded) / file.size);
        }
      });
      request.addEventListener("load", function () {
        if (request.status >= 200 && request.status < 300) {
          sent = end;
          retries = 0;
          progress(sent / file.size);
          if (sent >= file.size) {
            succeed();
          } else {
            sendFrom(sent);
          }
          return;
        }
        if (request.status === 416 && !resynced) {
          var have = resumeOffset(request.getResponseHeader("Content-Range"));
          if (have !== null && have <= file.size) {
            resynced = true;
            sent = have;
            sendFrom(have);
            return;
          }
        }
        retry(file.name + ": " + reason("upload", request.status, request.responseText.trim()));
      });
      request.addEventListener("error", function () {
        retry(file.name + ": the upload could not be sent.");
      });
      request.send(file.slice(start, end));
    }

    sendFrom(0);
  }

  // resumeOffset reads the size a 416 names in its own Content-Range, the
  // "bytes */<size>" form the server answers an out-of-sync chunk with.
  function resumeOffset(header) {
    var match = /^bytes \*\/(\d+)$/.exec(header || "");
    return match ? parseInt(match[1], 10) : null;
  }
})();
