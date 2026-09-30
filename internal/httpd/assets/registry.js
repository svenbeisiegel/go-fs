// The registry page is complete without this script: the rows are rendered by
// the server and the views and the sort headers are ordinary links. What is
// added here is what a link cannot do — filtering, the options of a tag, its
// details, copying its pull command and deleting it.
(function () {
  "use strict";

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

  function request(method, url) {
    return fetch(url, {
      method: method,
      headers: { Accept: "application/json" },
      credentials: "same-origin"
    }).then(function (res) {
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

  function platformSection(platform) {
    var section = el("section", "platform");
    var heading = el("h3");
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
      details.querySelector("h2").textContent = image.repository + ":" + image.tag;
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
