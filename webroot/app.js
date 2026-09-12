const stats = [
  ["packets_in", "Packets In"],
  ["packets_out", "Packets Out"],
  ["packets_dropped", "Dropped"],
  ["pid0_packets_dropped", "PID 0 Dropped"],
  ["pid_packets_dropped", "PID Dropped"],
  ["tei_packets_flipped", "TEI Flipped"],
  ["sync_bytes_replaced", "Sync Replaced"],
  ["adaptation_lengths_faulted", "AF Lengths"],
  ["udp_reorders_completed", "UDP Reorders"],
  ["pusi_packets_faulted", "PUSI Packets"],
  ["pusi_frames_faulted", "PUSI Frames"],
  ["bytes_corrupted", "Corrupted Bytes"],
];

const controls = [
  {
    title: "Drop Packets",
    command: "/api/drop",
    button: "Drop",
    fields: [["packets", "Packets", 1, 20]],
  },
  {
    title: "Drop Duration",
    command: "/api/drop_for",
    button: "Drop For",
    fields: [["ms", "Milliseconds", 1, 1000]],
  },
  {
    title: "Drop PID 0",
    command: "/api/drop_pid0_for",
    button: "Drop PAT",
    fields: [["ms", "Milliseconds", 1, 1000]],
  },
  {
    title: "Drop PID",
    command: "/api/drop_pid_for",
    button: "Drop PID",
    fields: [
      ["ms", "Milliseconds", 1, 1000],
      ["pid", "PID decimal", 0, 49],
    ],
  },
  {
    title: "Drop Pattern",
    command: "/api/drop_every",
    button: "Set Pattern",
    fields: [["n", "Drop 1 in N packets, 0 disables", 0, 10]],
  },
  {
    title: "Jitter",
    command: "/api/jitter",
    button: "Inject",
    fields: [
      ["ms", "Milliseconds", 1, 250],
      ["count", "Count", 1, 5],
    ],
  },
  {
    title: "Corrupt Bytes",
    command: "/api/corrupt",
    button: "Corrupt",
    fields: [["bytes", "Bytes", 1, 16]],
  },
  {
    title: "Flip TEI Bit",
    command: "/api/flip_tei",
    button: "Flip TEI",
    fields: [["packets", "Packets", 1, 20]],
  },
  {
    title: "Replace Sync Byte",
    command: "/api/replace_sync_for",
    button: "Replace Sync",
    fields: [["seconds", "Seconds", 1, 5]],
  },
  {
    title: "Fault Adaptation Length",
    command: "/api/fault_adaptation_length",
    button: "Set Length 191",
    fields: [
      ["packets", "Packets", 1, 20],
      ["pid", "PID decimal", 0, 49],
    ],
  },
  {
    title: "UDP Packet Reorder",
    command: "/api/udp_packet_reorder",
    button: "Reorder Once",
    fields: [],
  },
  {
    title: "Enable PUSI",
    command: "/api/enable_pusi_for",
    button: "Enable PUSI",
    fields: [
      ["frames", "UDP frames", 1, 3],
      ["pid", "PID decimal", 0, 49],
    ],
  },
];

const faultState = [
  ["drop_next_packets", "Drop queue"],
  ["drop_ms_remaining", "Drop ms"],
  ["drop_pid0_ms_remaining", "PID 0 ms"],
  ["drop_pid_ms_remaining", "PID drop ms"],
  ["drop_pid", "Drop PID"],
  ["drop_every_n", "Drop every"],
  ["jitter_remaining", "Jitter left"],
  ["corrupt_next_bytes", "Corrupt queue"],
  ["flip_tei_next_packets", "TEI flip queue"],
  ["replace_sync_ms_remaining", "Sync replace ms"],
  ["adaptation_length_next_packets", "AF length queue"],
  ["adaptation_length_pid", "AF length PID"],
  ["udp_reorder_pending", "UDP reorder queue"],
  ["pusi_frames_remaining", "PUSI frames left"],
  ["pusi_pid", "PUSI PID"],
  ["pusi_waiting", "PUSI waiting"],
];

function fmt(value) {
  return Number(value || 0).toLocaleString();
}

function initialControlValues() {
  return Object.fromEntries(controls.map((control) => [
    control.command,
    Object.fromEntries(control.fields.map(([name, , , value]) => [name, String(value)])),
  ]));
}

class SaboteurApp extends HTMLElement {
  connectedCallback() {
    this.status = {};
    this.health = { ok: false, text: "Connecting" };
    this.error = "";
    this.statusExpanded = false;
    this.controlValues = initialControlValues();
    this.render();
    this.refreshStatus();
    this.timer = setInterval(() => this.refreshStatus(), 1000);
  }

  disconnectedCallback() {
    clearInterval(this.timer);
  }

  async refreshStatus() {
    try {
      const response = await fetch("/api/status", { cache: "no-store" });
      if (!response.ok) {
        throw new Error(`status ${response.status}`);
      }
      this.status = await response.json();
      this.health = { ok: true, text: "Running" };
      this.error = "";
    } catch (error) {
      this.health = { ok: false, text: "Not running" };
      this.error = String(error);
    }
    this.updateLiveValues();
  }

  async postCommand(path) {
    try {
      const response = await fetch(path, { method: "POST" });
      if (!response.ok) {
        throw new Error(`command failed: ${response.status}`);
      }
      this.status = await response.json();
      this.health = { ok: true, text: "Running" };
      this.error = "";
    } catch (error) {
      this.health = { ok: false, text: "Command failed" };
      this.error = String(error);
    }
    this.updateLiveValues();
  }

  updateLiveValues() {
    const health = this.querySelector(".health");
    if (health) {
      health.classList.toggle("is-ok", this.health.ok);
      health.classList.toggle("is-error", !this.health.ok);
      health.querySelector("[data-health-text]").textContent = this.health.text;
    }

    this.querySelectorAll("[data-status-key]").forEach((element) => {
      element.textContent = fmt(this.status[element.dataset.statusKey]);
    });

    const statusJson = this.querySelector("[data-status-json]");
    if (statusJson) {
      statusJson.textContent = this.error || JSON.stringify(this.status, null, 2);
    }
  }

  captureFocus() {
    const active = document.activeElement;
    const form = active ? active.closest("form[data-command]") : null;

    if (!form || !active.name) {
      return null;
    }

    return {
      command: form.dataset.command,
      name: active.name,
      start: active.selectionStart,
      end: active.selectionEnd,
    };
  }

  restoreFocus(focus) {
    if (!focus) {
      return;
    }

    const input = this.querySelector(
      `form[data-command="${focus.command}"] input[name="${focus.name}"]`,
    );
    if (!input) {
      return;
    }

    input.focus();
    if (focus.start !== null && focus.end !== null) {
      try {
        input.setSelectionRange(focus.start, focus.end);
      } catch {
        // Number inputs may not support selection ranges in every browser.
      }
    }
  }

  render() {
    const focus = this.captureFocus();

    this.innerHTML = `
      <main class="shell">
        <header class="topbar">
          <div class="brand">
            <span class="brand-logo-wrap">
              <img class="brand-logo" src="/logo.png" alt="" aria-hidden="true">
              <span class="logo-popover" role="presentation">
                <img src="/logo.png" alt="">
              </span>
            </span>
            <div>
              <h1>Saboteur</h1>
              <p>MPEG-TS stream fault injection</p>
            </div>
          </div>
          <div class="health ${this.health.ok ? "is-ok" : "is-error"}">
            <span class="health-dot" aria-hidden="true"></span>
            <span data-health-text>${this.health.text}</span>
          </div>
        </header>

        <section class="stats" aria-label="Stream status">
          ${stats.map(([key, label]) => `
            <article class="stat-card">
              <span>${label}</span>
              <strong data-status-key="${key}">${fmt(this.status[key])}</strong>
            </article>
          `).join("")}
        </section>

        <section class="controls" aria-label="Fault controls">
          ${controls.map((control, index) => this.renderControl(control, index)).join("")}
          <section class="panel">
            <h2>Fault State</h2>
            <dl class="active-state">
              ${faultState.map(([key, label]) => `
                <div><dt>${label}</dt><dd data-status-key="${key}">${fmt(this.status[key])}</dd></div>
              `).join("")}
            </dl>
            <button class="secondary" type="button" data-action="reset">Clear Faults</button>
          </section>
        </section>

        <section class="status-panel">
          <div class="section-title">
            <h2>Status JSON</h2>
            <div class="status-actions">
              <button class="secondary compact" type="button" data-action="toggle-status">
                ${this.statusExpanded ? "Collapse" : "Expand"}
              </button>
            </div>
          </div>
          ${this.statusExpanded ? `<pre data-status-json>${this.error || JSON.stringify(this.status, null, 2)}</pre>` : ""}
        </section>
      </main>
    `;

    this.querySelectorAll("form[data-command]").forEach((form) => {
      form.addEventListener("submit", (event) => this.submitControl(event));
      form.querySelectorAll("input[name]").forEach((input) => {
        input.addEventListener("input", (event) => this.updateControlValue(event));
      });
    });
    this.querySelector("[data-action='reset']").addEventListener("click", () => this.postCommand("/api/reset"));
    this.querySelector("[data-action='toggle-status']").addEventListener("click", () => {
      this.statusExpanded = !this.statusExpanded;
      this.render();
      this.updateLiveValues();
    });

    this.restoreFocus(focus);
  }

  renderControl(control, index) {
    const values = this.controlValues[control.command] || {};
    return `
      <form class="panel control-card" data-command="${control.command}">
        <h2>${control.title}</h2>
        ${control.fields.map(([name, label, min, value]) => `
          <label for="control-${index}-${name}">${label}</label>
          <input id="control-${index}-${name}" name="${name}" type="number" min="${min}" value="${values[name] ?? value}">
        `).join("")}
        <button type="submit">${control.button}</button>
      </form>
    `;
  }

  updateControlValue(event) {
    const form = event.currentTarget.closest("form[data-command]");
    this.controlValues[form.dataset.command] = {
      ...this.controlValues[form.dataset.command],
      [event.currentTarget.name]: event.currentTarget.value,
    };
  }

  submitControl(event) {
    event.preventDefault();
    const form = event.currentTarget;
    const params = new URLSearchParams();
    new FormData(form).forEach((value, key) => params.set(key, value));
    this.postCommand(`${form.dataset.command}?${params.toString()}`);
  }
}

customElements.define("saboteur-app", SaboteurApp);
document.getElementById("app").innerHTML = "<saboteur-app></saboteur-app>";
