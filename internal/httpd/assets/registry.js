// The registry page is complete without this script: the rows are rendered by
// the server and the views and the sort headers are ordinary links. What is
// added here is what a link cannot do — filtering, the options of a tag, its
// details, copying its pull command and deleting it, and pulling an image
// from another registry or pushing a tag to one.
(function () {
  "use strict";

  // The menu in the corner of the header is a details element and opens and
  // closes on its own; what is added is closing it on a click beside it and
  // on Escape, as a menu is expected to.
  (function () {
    var nav = document.querySelector("details.nav");
    if (!nav) {
      return;
    }
    document.addEventListener("click", function (event) {
      if (nav.open && !nav.contains(event.target)) {
        nav.open = false;
      }
    }, true);
    nav.addEventListener("keydown", function (event) {
      if (event.key === "Escape" && nav.open) {
        event.preventDefault();
        nav.open = false;
        nav.querySelector("summary").focus();
      }
    });
  })();

  var table = document.getElementById("registry");
  if (!table) {
    return;
  }
  var body = table.tBodies[0];
  // base is the path the page was opened on, already escaped: every request
  // below puts the marker and the tag on it as a query.
  var base = table.dataset.base;
  var banner = document.getElementById("banner");

  function rows() {
    return Array.prototype.slice.call(body.rows).filter(function (row) {
      return row.dataset.name !== undefined;
    });
  }

  function say(message, good) {
    banner.textContent = message;
    banner.classList.toggle("good", good === true);
    banner.hidden = false;
  }

  function clear() {
    banner.hidden = true;
  }

  // A message that has to survive the reload after a pull is kept for the
  // next page of this tab. Storage may be off; the reload then says nothing.
  var carried = "go-fs-registry-banner";
  try {
    var kept = window.sessionStorage.getItem(carried);
    if (kept) {
      window.sessionStorage.removeItem(carried);
      say(kept, true);
    }
  } catch (err) {
    // nothing carried
  }

  function sayAfterReload(message) {
    try {
      window.sessionStorage.setItem(carried, message);
    } catch (err) {
      // the reload will show the new tag, which says it as well
    }
    window.location.reload();
  }

  function tagURL(action, row) {
    return base + "?go-fs=" + action +
      "&repository=" + encodeURIComponent(row.dataset.repository) +
      "&tag=" + encodeURIComponent(row.dataset.tag);
  }

  function reason(status, text) {
    if (status === 401) {
      return "Your session has ended — reload the page to log in again.";
    }
    if (status === 403) {
      return "You are not allowed to do that here.";
    }
    return text || ("The server answered " + status + ".");
  }

  function request(method, url, body) {
    var options = {
      method: method,
      headers: { Accept: "application/json" },
      credentials: "same-origin"
    };
    if (body !== undefined) {
      options.headers["Content-Type"] = "application/json";
      options.body = JSON.stringify(body);
    }
    return fetch(url, options).then(function (res) {
      if (res.ok) {
        return res;
      }
      return res.text().then(function (text) {
        throw new Error(reason(res.status, text.trim()));
      });
    });
  }

  function failed(err) {
    say(err.message);
  }

  // the same units the server writes into the Size column
  function readableSize(size) {
    function tenth(value) {
      return Math.round(value * 10) / 10;
    }
    if (size > 1000000000) {
      return tenth(size / 1024 / 1024 / 1024) + " GB";
    }
    if (size > 1000000) {
      return tenth(size / 1024 / 1024) + " MB";
    }
    return tenth(size / 1024) + " KB";
  }

  function when(value) {
    if (!value) {
      return "—";
    }
    var date = new Date(value);
    return isNaN(date.getTime()) ? value : date.toLocaleString();
  }

  // el builds an element with text in it, never markup: every value here comes
  // from what somebody pushed.
  function el(tag, className, text) {
    var node = document.createElement(tag);
    if (className) {
      node.className = className;
    }
    if (text !== undefined) {
      node.textContent = text;
    }
    return node;
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

  // --- the options menu ------------------------------------------------
  //
  // One menu serves every row. It is placed below the button that opened it
  // and remembers the row, which is what the items act on.

  var menu = document.getElementById("menu");
  var opener = null;

  function items() {
    return Array.prototype.slice.call(menu.querySelectorAll("button"));
  }

  function openMenu(button) {
    opener = button;
    button.setAttribute("aria-expanded", "true");
    menu.hidden = false;
    var box = button.getBoundingClientRect();
    var left = box.right + window.scrollX - menu.offsetWidth;
    menu.style.left = Math.max(window.scrollX + 8, left) + "px";
    var top = box.bottom + window.scrollY + 4;
    // a menu that would run off the bottom opens above its button instead
    if (box.bottom + menu.offsetHeight + 8 > window.innerHeight) {
      top = box.top + window.scrollY - menu.offsetHeight - 4;
    }
    menu.style.top = top + "px";
    items()[0].focus();
  }

  function closeMenu(refocus) {
    if (!opener) {
      return;
    }
    menu.hidden = true;
    opener.setAttribute("aria-expanded", "false");
    if (refocus) {
      opener.focus();
    }
    opener = null;
  }

  body.addEventListener("click", function (event) {
    var button = event.target.closest("button[data-do='menu']");
    if (!button) {
      return;
    }
    event.stopPropagation();
    clear();
    if (opener === button) {
      closeMenu(true);
      return;
    }
    closeMenu(false);
    openMenu(button);
  });

  document.addEventListener("click", function (event) {
    if (opener && !menu.contains(event.target)) {
      closeMenu(false);
    }
  });

  window.addEventListener("resize", function () {
    closeMenu(false);
  });

  menu.addEventListener("keydown", function (event) {
    var list = items();
    var at = list.indexOf(document.activeElement);
    switch (event.key) {
      case "Escape":
        event.preventDefault();
        closeMenu(true);
        break;
      case "Tab":
        closeMenu(false);
        break;
      case "ArrowDown":
        event.preventDefault();
        list[(at + 1) % list.length].focus();
        break;
      case "ArrowUp":
        event.preventDefault();
        list[(at - 1 + list.length) % list.length].focus();
        break;
      case "Home":
        event.preventDefault();
        list[0].focus();
        break;
      case "End":
        event.preventDefault();
        list[list.length - 1].focus();
        break;
    }
  });

  menu.addEventListener("click", function (event) {
    var item = event.target.closest("button[data-do]");
    if (!item || !opener) {
      return;
    }
    var row = opener.closest("tr");
    closeMenu(item.dataset.do === "copy");
    if (item.dataset.do === "details") {
      showDetails(row);
    } else if (item.dataset.do === "copy") {
      copyPull(row);
    } else if (item.dataset.do === "push") {
      openPush(row);
    } else if (item.dataset.do === "delete") {
      deleteTag(row);
    }
  });

  // --- details ---------------------------------------------------------

  var details = document.getElementById("details");

  function facts(pairs) {
    var list = el("dl", "facts");
    pairs.forEach(function (pair) {
      if (pair[1] === undefined || pair[1] === null || pair[1] === "") {
        return;
      }
      list.appendChild(el("dt", "", pair[0]));
      list.appendChild(el("dd", pair[2] ? "mono" : "", pair[1]));
    });
    return list;
  }

  // Each platform is folded away, so the facts of the tag stay in view and
  // the admin opens only the platform they want to look at.
  function platformSection(platform) {
    var section = el("details", "platform");
    var heading = el("summary");
    heading.appendChild(el("span", "badge", platform.label || "artifact"));
    if (platform.platform && platform.platform !== platform.label) {
      heading.appendChild(el("span", "meta", platform.platform));
    }
    section.appendChild(heading);
    section.appendChild(facts([
      ["Manifest", platform.digest, true],
      ["Media type", platform.mediaType, true],
      ["Config", platform.config, true],
      ["Created", platform.created ? when(platform.created) : ""],
      ["Size", readableSize(platform.size)]
    ]));
    if (platform.layers.length > 0) {
      var fold = el("details", "layers");
      fold.appendChild(el("summary", "",
        platform.layers.length === 1 ? "1 layer" : platform.layers.length + " layers"));
      var list = el("ol");
      platform.layers.forEach(function (layer) {
        var item = el("li");
        item.appendChild(el("span", "mono", layer.digest));
        item.appendChild(el("span", "meta", readableSize(layer.size)));
        list.appendChild(item);
      });
      fold.appendChild(list);
      section.appendChild(fold);
    }
    return section;
  }

  function showDetails(row) {
    request("GET", tagURL("registry-image", row)).then(function (res) {
      return res.json();
    }).then(function (image) {
      var title = details.querySelector("h2");
      title.textContent = image.repository + ":" + image.tag;
      var badges = el("span", "badges");
      image.platforms.forEach(function (platform) {
        if (platform.platform) {
          var badge = el("span", "badge", platform.label);
          badge.title = platform.platform;
          badges.appendChild(badge);
        }
      });
      if (badges.childNodes.length > 0) {
        title.appendChild(badges);
      }
      var holder = details.querySelector(".facts");
      holder.textContent = "";
      holder.appendChild(facts([
        ["Digest", image.digest, true],
        ["Media type", image.mediaType, true],
        ["Pushed", when(image.pushed)],
        ["Size", readableSize(image.size)],
        ["Pull", image.pull, true],
        ["Also tagged", image.tags.join(", ")],
        ["Index", image.merged ? "Built by the registry from images pushed one platform at a time" : ""]
      ]));
      image.platforms.forEach(function (platform) {
        holder.appendChild(platformSection(platform));
      });
      details.showModal();
    }).catch(failed);
  }

  // --- copying the pull command ----------------------------------------

  var pull = document.getElementById("pull");

  function showPull(command) {
    var field = pull.querySelector("input");
    field.value = command;
    pull.showModal();
    field.focus();
    field.select();
  }

  function copyPull(row) {
    var command = row.dataset.pull;
    // the clipboard is only there on https and on localhost; anywhere else
    // the command is shown for copying by hand
    if (!navigator.clipboard || !window.isSecureContext) {
      showPull(command);
      return;
    }
    navigator.clipboard.writeText(command).then(function () {
      say("Copied: " + command, true);
    }, function () {
      showPull(command);
    });
  }

  // --- pulling from and pushing to another registry --------------------
  //
  // A transfer is checked before it may start: Validate asks the server to
  // reach the other registry with the login given, and answers the
  // architectures there are to copy, which the admin then picks from. Editing
  // the image or the login undoes the check. The server does the copying, as
  // a job of its own: the dialog starts it, then asks every second how far it
  // has got. Closing the dialog leaves the job running, and the banner says
  // how it ended.

  function transfer(dialog, calls) {
    var form = dialog.querySelector("form");
    var progress = dialog.querySelector(".progress");
    var bar = progress.querySelector("progress");
    var status = progress.querySelector(".status");
    var platforms = dialog.querySelector(".platforms");
    var choices = platforms.querySelector(".choices");
    var check = form.querySelector("button[value='check']");
    var go = form.querySelector("button[value='start']");
    var stop = form.querySelector("button[value='stop']");
    var close = form.querySelector("button[value='cancel']");
    var job = null;
    // checked is what the last Validate answered, null until it succeeded
    var checked = null;

    function boxes() {
      return Array.prototype.slice.call(choices.querySelectorAll("input[type='checkbox']"));
    }

    function ready() {
      go.disabled = !checked || (boxes().length > 0 && !boxes().some(function (box) {
        return box.checked;
      }));
    }

    function busy(on) {
      Array.prototype.forEach.call(form.querySelectorAll("input"), function (input) {
        input.disabled = on;
      });
      check.hidden = on;
      go.hidden = on;
      stop.hidden = !on;
      close.textContent = on ? "Close" : "Cancel";
      check.disabled = on;
      if (!on) {
        ready();
      }
    }

    function tell(message, bad) {
      progress.hidden = false;
      status.textContent = message;
      status.classList.toggle("bad", bad === true);
    }

    function quiet() {
      progress.hidden = true;
      status.textContent = "";
      status.classList.remove("bad");
    }

    function invalidate() {
      if (checked === null) {
        return;
      }
      checked = null;
      platforms.hidden = true;
      choices.textContent = "";
      quiet();
      ready();
      if (calls.changed) {
        calls.changed(null);
      }
    }

    function offer(answer) {
      checked = answer;
      choices.textContent = "";
      answer.platforms.forEach(function (platform) {
        var label = el("label");
        label.title = platform.platform;
        var box = el("input");
        box.type = "checkbox";
        box.value = platform.platform;
        box.checked = true;
        label.appendChild(box);
        label.appendChild(el("span", "badge", platform.label));
        if (platform.label !== platform.platform) {
          label.appendChild(el("span", "meta", platform.platform));
        }
        choices.appendChild(label);
      });
      if (answer.platforms.length === 0) {
        choices.appendChild(el("span", "meta", "It names no architecture, so it is copied as it is."));
      }
      platforms.hidden = false;
      ready();
      if (calls.changed) {
        calls.changed(answer);
      }
    }

    // chosen is what the transfer is limited to: nothing while every box is
    // ticked, so that the image is copied as it is, under its own digest.
    function chosen() {
      var ticked = boxes().filter(function (box) {
        return box.checked;
      });
      if (ticked.length === boxes().length) {
        return "";
      }
      return ticked.map(function (box) {
        return box.value;
      }).join(", ");
    }

    function show(view) {
      if (view.bytesTotal > 0) {
        bar.max = view.bytesTotal;
        bar.value = Math.min(view.bytesDone, view.bytesTotal);
      } else {
        // not known yet: the bar runs without a value
        bar.removeAttribute("value");
      }
      if (view.blobsTotal > 0) {
        tell(view.blobsDone + " of " + view.blobsTotal + " blobs · " +
          readableSize(view.bytesDone) + " of " + readableSize(view.bytesTotal));
      } else {
        tell("Reading the manifests…");
      }
    }

    function reset() {
      form.reset();
      invalidate();
      quiet();
    }

    function end(view) {
      job = null;
      busy(false);
      if (view.state === "done") {
        reset();
        if (dialog.open) {
          dialog.close();
        }
        calls.finished(view);
        return;
      }
      var message = view.state === "cancelled" ? "Stopped." : (view.message || "The transfer failed.");
      bar.value = 0;
      tell(message, view.state !== "cancelled");
      if (!dialog.open) {
        say(view.what ? view.what + ": " + message : message);
      }
    }

    function poll() {
      if (!job) {
        return;
      }
      request("GET", base + "?go-fs=registry-job&id=" + encodeURIComponent(job)).then(function (res) {
        return res.json();
      }).then(function (view) {
        if (view.state === "running") {
          show(view);
          window.setTimeout(poll, 1000);
          return;
        }
        end(view);
      }).catch(function (err) {
        end({ state: "failed", message: err.message, what: "" });
      });
    }

    function validate() {
      var call = calls.check();
      invalidate();
      Array.prototype.forEach.call(form.querySelectorAll("input"), function (input) {
        input.disabled = true;
      });
      check.disabled = true;
      bar.removeAttribute("value");
      tell("Checking…");
      request("POST", call.url, call.body).then(function (res) {
        return res.json();
      }).then(function (answer) {
        busy(false);
        quiet();
        offer(answer);
      }).catch(function (err) {
        busy(false);
        bar.value = 0;
        tell(err.message, true);
      });
    }

    form.addEventListener("input", function (event) {
      if (event.target.closest(".fields")) {
        invalidate();
      }
    });
    choices.addEventListener("change", ready);

    // The submit event rather than close, for the reason the listing gives:
    // which button was pressed is only known there.
    form.addEventListener("submit", function (event) {
      var pressed = event.submitter ? event.submitter.value : "check";
      if (pressed === "cancel") {
        return;
      }
      event.preventDefault();
      if (pressed === "stop") {
        if (job) {
          request("DELETE", base + "?go-fs=registry-job&id=" + encodeURIComponent(job)).catch(failed);
        }
        return;
      }
      if (pressed === "check" || !checked) {
        validate();
        return;
      }
      if (go.disabled) {
        return;
      }
      var call = calls.start(checked, chosen());
      busy(true);
      bar.removeAttribute("value");
      tell("Starting…");
      request("POST", call.url, call.body).then(function (res) {
        return res.json();
      }).then(function (view) {
        job = view.id;
        show(view);
        window.setTimeout(poll, 1000);
      }).catch(function (err) {
        busy(false);
        tell(err.message, true);
      });
    });

    return {
      // open shows the dialog: as it was left while a job runs, fresh
      // otherwise. It reports whether the dialog was fresh.
      open: function () {
        var fresh = !job;
        if (fresh) {
          reset();
        }
        dialog.showModal();
        return fresh;
      }
    };
  }

  // localName is where a pull stores an image, worked out the way the server
  // does: the registry is dropped, and an official image of Docker Hub is
  // under library/. It is only shown; the server decides.
  function isHost(component) {
    return /[.:]/.test(component) || component === "localhost";
  }

  function localName(value) {
    var rest = value.trim().replace(/^https?:\/\//, "");
    var byDigest = false;
    var at = rest.indexOf("@");
    if (at >= 0) {
      rest = rest.slice(0, at);
      byDigest = true;
    }
    var tag = "";
    var colon = rest.lastIndexOf(":");
    if (colon > rest.lastIndexOf("/")) {
      tag = rest.slice(colon + 1);
      rest = rest.slice(0, colon);
    }
    var hub = true;
    var slash = rest.indexOf("/");
    if (slash >= 0 && isHost(rest.slice(0, slash))) {
      var host = rest.slice(0, slash).toLowerCase();
      hub = host === "docker.io" || host === "index.docker.io";
      rest = rest.slice(slash + 1);
    }
    if (rest === "") {
      return "";
    }
    if (hub && rest.indexOf("/") < 0) {
      rest = "library/" + rest;
    }
    if (tag === "") {
      if (byDigest) {
        return null;
      }
      tag = "latest";
    }
    return rest + ":" + tag;
  }

  // remoteName is a reference written in full, the way the server reads it:
  // Docker Hub where no registry is named, and its official images under
  // library/. It is only shown; the server decides.
  function remoteName(value) {
    var rest = value.trim().replace(/^https?:\/\//, "");
    if (rest === "" || rest.indexOf("@") >= 0) {
      return "";
    }
    var tag = "latest";
    var colon = rest.lastIndexOf(":");
    if (colon > rest.lastIndexOf("/")) {
      tag = rest.slice(colon + 1);
      rest = rest.slice(0, colon);
    }
    var host = "docker.io";
    var slash = rest.indexOf("/");
    if (slash >= 0 && isHost(rest.slice(0, slash))) {
      host = rest.slice(0, slash).toLowerCase();
      rest = rest.slice(slash + 1);
    }
    if (host === "index.docker.io") {
      host = "docker.io";
    }
    if (rest === "") {
      return "";
    }
    if (host === "docker.io" && rest.indexOf("/") < 0) {
      rest = "library/" + rest;
    }
    return host + "/" + rest + ":" + tag;
  }

  function fieldOf(dialog) {
    return function (name) {
      return dialog.querySelector("input[name='" + name + "']");
    };
  }

  var pullDialog = document.getElementById("remote-pull");
  var pullButton = document.getElementById("pull-image");
  if (pullDialog && pullButton) {
    var pullField = fieldOf(pullDialog);
    var pullWhere = pullDialog.querySelector(".where");
    var showLocal = function () {
      var name = localName(pullField("reference").value);
      if (name === null) {
        pullWhere.textContent = "Name a tag along with the digest: the image is stored under it.";
      } else {
        pullWhere.textContent = name ? "Stored here as " + name : "";
      }
    };
    pullField("reference").addEventListener("input", showLocal);
    var pullLogin = function () {
      return {
        reference: pullField("reference").value.trim(),
        username: pullField("username").value.trim(),
        password: pullField("password").value,
        skipVerify: !pullField("verify").checked
      };
    };
    var pulling = transfer(pullDialog, {
      check: function () {
        return { url: base + "?go-fs=registry-pull-check", body: pullLogin() };
      },
      start: function (checked, platforms) {
        var body = pullLogin();
        body.digest = checked.digest;
        body.platforms = platforms;
        return { url: base + "?go-fs=registry-pull", body: body };
      },
      changed: function (checked) {
        if (checked) {
          pullWhere.textContent = "Pulls " + checked.reference + " · stored here as " + checked.local;
        } else {
          showLocal();
        }
      },
      finished: function (view) {
        sayAfterReload(view.message);
      }
    });
    pullButton.addEventListener("click", function () {
      clear();
      if (pulling.open()) {
        showLocal();
        pullField("reference").focus();
      }
    });
  }

  var pushDialog = document.getElementById("remote-push");
  var pushing = null;
  var pushRow = null;
  var showTarget = null;
  if (pushDialog) {
    var pushField = fieldOf(pushDialog);
    var pushWhere = pushDialog.querySelector(".where");
    showTarget = function () {
      var target = remoteName(pushField("reference").value);
      pushWhere.textContent = target ? "Pushes to " + target : "";
    };
    pushField("reference").addEventListener("input", showTarget);
    var pushLogin = function () {
      return {
        reference: pushField("reference").value.trim(),
        username: pushField("username").value.trim(),
        password: pushField("password").value,
        skipVerify: !pushField("verify").checked
      };
    };
    pushing = transfer(pushDialog, {
      check: function () {
        return { url: tagURL("registry-push-check", pushRow), body: pushLogin() };
      },
      start: function (checked, platforms) {
        var body = pushLogin();
        body.platforms = platforms;
        return { url: tagURL("registry-push", pushRow), body: body };
      },
      changed: function (checked) {
        if (checked) {
          pushWhere.textContent = "Pushes to " + checked.reference +
            (checked.exists ? " · replaces the tag there" : "");
        } else {
          showTarget();
        }
      },
      finished: function (view) {
        say(view.message, true);
      }
    });
  }

  function openPush(row) {
    if (!pushing) {
      return;
    }
    // while a push runs the dialog shows that one, whichever row asked
    var previous = pushRow;
    pushRow = row;
    if (!pushing.open()) {
      pushRow = previous;
      return;
    }
    pushDialog.querySelector(".what").textContent = row.dataset.repository + ":" + row.dataset.tag;
    var field = pushDialog.querySelector("input[name='reference']");
    field.value = row.dataset.repository + ":" + row.dataset.tag;
    showTarget();
    field.focus();
    // the registry goes in front of what is there
    field.setSelectionRange(0, 0);
  }

  // --- deleting a tag --------------------------------------------------

  var checking = document.getElementById("confirm");
  var onAgree = null;

  // The submit event rather than close, for the reason the listing gives.
  checking.querySelector("form").addEventListener("submit", function (event) {
    var pending = onAgree;
    onAgree = null;
    if (event.submitter && event.submitter.value === "cancel") {
      return;
    }
    if (pending) {
      pending();
    }
  });

  function deleteTag(row) {
    var name = row.dataset.repository + ":" + row.dataset.tag;
    checking.querySelector("h2").textContent = "Delete tag";
    checking.querySelector("p").textContent = "Delete " + name +
      "? Pulling it will stop working. The image itself stays while another tag points to it.";
    onAgree = function () {
      request("DELETE", tagURL("registry", row)).then(function () {
        window.location.reload();
      }).catch(failed);
    };
    checking.showModal();
  }
})();
