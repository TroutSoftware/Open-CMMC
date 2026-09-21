<template>
  <div class="row">
    <div class="column shopfloor">
      <div class="card">
        <div class="card-title">
          <h2>Shop floor</h2>
        </div>

        <p class="cmmc-identity-notice">
          <strong>Your machines, by cell.</strong>
          A cell is a group of machines that share the same programs. Each
          machine gets its own network share, reachable only from the address
          you list here. Changes are applied to the server within a few seconds
          of saving.
        </p>

        <div class="card-content full">
          <div v-if="loading" class="small">Loading…</div>
          <div v-else-if="disabled" class="small">
            Shop-floor delivery isn't set up on this server yet. An
            administrator enables it with
            <code
              >sudo config/install.sh deploy --with-smb --ot-ip
              &lt;address&gt;</code
            >.
          </div>

          <template v-else>
            <p class="small status">
              Server address for the machines:
              <code>{{ status.ot_address || "—" }}</code>
              <span v-if="status.up_to_date" class="ok">· applied</span>
              <span v-else class="pending">· applying changes…</span>
              <span v-if="dirty" class="pending">· unsaved edits</span>
            </p>

            <p v-if="!cells.length" class="small">
              No machines yet. Click <b>+ Add cell</b>, name the cell (for
              example <i>milling</i>), list its machines with their addresses,
              tick the protected-cable box, then <b>Save changes</b>. Machines
              can connect a few seconds later.
            </p>

            <div v-for="(cell, ci) in cells" :key="ci" class="cell">
              <div class="cell-head">
                <label>
                  Cell
                  <input
                    v-model.trim="cell.name"
                    class="input"
                    placeholder="e.g. milling-1"
                    @input="dirty = true"
                  />
                </label>
                <label>
                  Programs marked
                  <select
                    v-model="cell.mark"
                    class="input"
                    @change="dirty = true"
                  >
                    <option v-for="m in marks" :key="m" :value="m">
                      {{ m || "not CUI" }}
                    </option>
                  </select>
                </label>
                <label>
                  Files from machines go to
                  <input
                    v-model.trim="cell.return_path"
                    class="input"
                    placeholder="/Engineering_CUI/NC/milling-1/return"
                    @input="dirty = true"
                  />
                </label>
                <label class="check">
                  <input
                    type="checkbox"
                    v-model="cell.pds_attested"
                    @change="dirty = true"
                  />
                  The cable to these machines is protected (conduit or locked
                  cabinets, own switch, no Wi-Fi)
                </label>
                <button
                  class="button button--flat button--grey"
                  @click="removeCell(ci)"
                >
                  Remove cell
                </button>
              </div>

              <table>
                <tr>
                  <th>Machine</th>
                  <th>Address</th>
                  <th>Talks</th>
                  <th>Password</th>
                  <th>Model (for the inventory)</th>
                  <th></th>
                </tr>
                <tr v-for="(m, mi) in cell.machines" :key="mi">
                  <td>
                    <input
                      v-model.trim="m.name"
                      class="input"
                      placeholder="haas-vf2"
                      @input="dirty = true"
                    />
                  </td>
                  <td>
                    <input
                      v-model.trim="m.ip"
                      class="input"
                      placeholder="10.20.1.11"
                      @input="dirty = true"
                    />
                  </td>
                  <td>
                    <select
                      v-model="m.dialect"
                      class="input"
                      @change="dirty = true"
                    >
                      <option value="smb3">SMB3 (recent)</option>
                      <option value="smb2">SMB2 (older)</option>
                      <option value="smb1">SMB1 (legacy)</option>
                    </select>
                  </td>
                  <td>
                    <select
                      v-model="m.auth"
                      class="input"
                      @change="dirty = true"
                    >
                      <option value="none">no password</option>
                      <option value="password">password</option>
                    </select>
                  </td>
                  <td>
                    <input
                      v-model.trim="m.model"
                      class="input"
                      placeholder="Haas VF-2 NGC"
                      @input="dirty = true"
                    />
                  </td>
                  <td class="small">
                    <button
                      class="action"
                      title="Connection details"
                      @click="showCard(cell, m)"
                    >
                      <i class="material-icons">info</i>
                    </button>
                    <button
                      class="action"
                      :title="`Remove ${m.name}`"
                      @click="removeMachine(cell, mi)"
                    >
                      <i class="material-icons">delete</i>
                    </button>
                  </td>
                </tr>
              </table>
              <button class="button button--flat" @click="addMachine(cell)">
                + Add machine
              </button>

              <div
                v-if="released[cell.name] && released[cell.name].length"
                class="released"
              >
                <h3>On this cell's share right now</h3>
                <table class="released-table">
                  <tr>
                    <th>File</th>
                    <th>From folder</th>
                    <th>Sent by</th>
                    <th>Available until</th>
                    <th></th>
                  </tr>
                  <tr v-for="f in released[cell.name]" :key="f.name">
                    <td>
                      <code>{{ f.name }}</code>
                    </td>
                    <td class="small">{{ folderOf(f.path) }}</td>
                    <td class="small">{{ f.released_by }}</td>
                    <td class="small">
                      {{ f.pinned ? "until taken back" : fmt(f.expires_at) }}
                    </td>
                    <td class="small">
                      <button
                        v-if="f.can_revoke"
                        class="button button--flat button--grey"
                        @click="takeBack(cell.name, f.name)"
                      >
                        Take back
                      </button>
                    </td>
                  </tr>
                </table>
              </div>
            </div>

            <p>
              <button class="button button--flat" @click="addCell">
                + Add cell
              </button>
            </p>

            <p v-if="error" class="small" style="color: #c62828">{{ error }}</p>

            <p>
              <button
                class="button button--flat"
                :disabled="!dirty || saving"
                @click="save"
              >
                {{ saving ? "Saving…" : "Save changes" }}
              </button>
              <button
                class="button button--flat button--grey"
                :disabled="!dirty || saving"
                @click="load"
              >
                Discard
              </button>
            </p>

            <div v-if="card" class="cmmc-identity-notice card-box">
              <strong>Connection details for {{ card.machine }}</strong>
              <table>
                <tr>
                  <td>Server</td>
                  <td>
                    <code>{{ card.server }}</code>
                  </td>
                </tr>
                <tr>
                  <td>Programs (read)</td>
                  <td>
                    <code>\\{{ card.server }}\{{ card.out }}</code>
                  </td>
                </tr>
                <tr>
                  <td>Send back (write)</td>
                  <td>
                    <code>\\{{ card.server }}\{{ card.ret }}</code>
                  </td>
                </tr>
                <tr>
                  <td>User name</td>
                  <td>
                    <code>{{ card.machine }}</code>
                  </td>
                </tr>
                <tr>
                  <td>Password</td>
                  <td>
                    <span v-if="card.auth === 'password'">
                      set on the server with
                      <code>sudo cmmc-smb useradd {{ card.machine }}</code>
                      (shown once there)
                    </span>
                    <span v-else>none — leave blank</span>
                  </td>
                </tr>
              </table>
              <button
                class="button button--flat button--grey"
                @click="card = null"
              >
                Close
              </button>
            </div>
          </template>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { inject, onMounted, ref } from "vue";
import { useAuthStore } from "@/stores/auth";
import { baseURL } from "@/utils/constants";

interface Machine {
  name: string;
  ip: string;
  dialect: "smb3" | "smb2" | "smb1";
  auth: "none" | "password";
  model?: string;
}
interface Cell {
  name: string;
  mark: string;
  return_path: string;
  pds_attested: boolean;
  ttl_days?: number;
  machines: Machine[];
}
interface Status {
  modified: string;
  applied: string;
  up_to_date: boolean;
  ot_address: string;
  legacy_ip?: string;
}
interface Released {
  name: string;
  path: string;
  released_by: string;
  expires_at: string;
  pinned: boolean;
  can_revoke: boolean;
}

const authStore = useAuthStore();
const $showError = inject<IToastError>("$showError")!;
const $showSuccess = inject<IToastSuccess>("$showSuccess")!;

const loading = ref(true);
const disabled = ref(false);
const saving = ref(false);
const dirty = ref(false);
const error = ref("");
const cells = ref<Cell[]>([]);
const status = ref<Status>({
  modified: "",
  applied: "",
  up_to_date: true,
  ot_address: "",
});
const released = ref<Record<string, Released[]>>({});
const marks = ref<string[]>(["", "CUI//BASIC", "CUI//SP-ITAR"]);
const card = ref<{
  machine: string;
  server: string;
  out: string;
  ret: string;
  auth: string;
} | null>(null);

const headers = (): HeadersInit => {
  const h: Record<string, string> = { "Content-Type": "application/json" };
  if (authStore.jwt) h["X-Auth"] = authStore.jwt;
  return h;
};

const fmt = (iso: string) => new Date(iso).toLocaleDateString();
const folderOf = (p: string) => p.substring(0, p.lastIndexOf("/")) || "/";

const load = async () => {
  loading.value = true;
  error.value = "";
  try {
    const res = await fetch(`${baseURL}/api/cmmc/ot/inventory`, {
      headers: headers(),
      credentials: "include",
    });
    if (res.status === 503) {
      disabled.value = true;
      return;
    }
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const body = (await res.json()) as { cells: Cell[]; status: Status };
    cells.value = (body.cells || []).map((c) => ({
      ...c,
      machines: (c.machines || []).map((m) => ({
        ...m,
        auth: m.auth || "none",
      })),
    }));
    status.value = body.status;
    dirty.value = false;
    await loadReleased();
    try {
      const cat = await fetch(`${baseURL}/api/cmmc/marking/catalog`, {
        headers: headers(),
        credentials: "include",
      });
      if (cat.ok) {
        const c = (await cat.json()) as { marks: string[] };
        marks.value = ["", ...(c.marks || []).filter((m) => m !== "")];
      }
    } catch {
      /* keep the default list */
    }
  } catch (err) {
    error.value = `Could not load: ${(err as Error).message}`;
  } finally {
    loading.value = false;
  }
};

const loadReleased = async () => {
  const out: Record<string, Released[]> = {};
  for (const c of cells.value) {
    if (!c.name) continue;
    try {
      const res = await fetch(
        `${baseURL}/api/cmmc/ot/released?cell=${encodeURIComponent(c.name)}`,
        { headers: headers(), credentials: "include" }
      );
      if (res.ok) out[c.name] = (await res.json()) as Released[];
    } catch {
      /* cell not applied yet */
    }
  }
  released.value = out;
};

const addCell = () => {
  cells.value.push({
    name: "",
    mark: "CUI//BASIC",
    return_path: "",
    pds_attested: false,
    machines: [{ name: "", ip: "", dialect: "smb3", auth: "none", model: "" }],
  });
  dirty.value = true;
};
const removeCell = (i: number) => {
  cells.value.splice(i, 1);
  dirty.value = true;
};
const addMachine = (c: Cell) => {
  c.machines.push({
    name: "",
    ip: "",
    dialect: "smb3",
    auth: "none",
    model: "",
  });
  dirty.value = true;
};
const removeMachine = (c: Cell, i: number) => {
  c.machines.splice(i, 1);
  dirty.value = true;
};

const showCard = (c: Cell, m: Machine) => {
  const server =
    m.dialect === "smb1" && status.value.legacy_ip
      ? status.value.legacy_ip
      : status.value.ot_address || "<server address>";
  // Share names mirror smb/render: no-password machines get their own
  // pair; SMB2 password machines in a cell with SMB3 ones get -signed.
  let suffix = "";
  if (m.auth !== "password") suffix = `-${m.name}`;
  else if (
    m.dialect === "smb2" &&
    c.machines.some((o) => o.dialect === "smb3" && o.auth === "password")
  )
    suffix = "-signed";
  card.value = {
    machine: m.name,
    server,
    out: `${c.name}-out${suffix}`,
    ret: `${c.name}-return${suffix}`,
    auth: m.auth,
  };
};

// The server validates in cells.yaml terms; say it in the page's words.
const plainValidation = (raw: string): string =>
  raw
    .replace(/^.*invalid cells config: /, "")
    .replace(/\)?\s*$/, "")
    .replace(
      /set pds_attested: true on the cell/g,
      "tick “The cable to these machines is protected”"
    )
    .replace(
      /requires pds_attested: true \(plaintext SMB wire\)/g,
      "needs “The cable to these machines is protected” ticked (older SMB is not encrypted)"
    )
    .replace(
      /give the machine auth: password/g,
      "set its Password column to “password”"
    )
    .replace(/has no password \(auth: none\)/g, "has no password")
    .replace(
      /name must match \S+/g,
      "name may only use lowercase letters, digits and dashes"
    )
    .replace(
      /return_path must be a clean absolute path/g,
      "“Files from machines go to” must be a folder path starting with /"
    )
    .replace(
      /ip "([^"]*)" is not an IPv4 address/g,
      "address “$1” is not a valid IP address"
    );

const save = async () => {
  saving.value = true;
  error.value = "";
  try {
    // Default the return path so a cell needs only a name to be valid.
    for (const c of cells.value) {
      if (!c.return_path && c.name)
        c.return_path = `/Engineering_CUI/NC/${c.name}/return`;
      for (const m of c.machines) if (!m.model) delete m.model;
    }
    const res = await fetch(`${baseURL}/api/cmmc/ot/inventory`, {
      method: "PUT",
      headers: headers(),
      credentials: "include",
      body: JSON.stringify({
        cells: cells.value,
        modified: status.value.modified,
      }),
    });
    if (res.status === 409) {
      error.value =
        "Someone else changed the inventory in the meantime. Reload and try again.";
      return;
    }
    if (res.status === 422) {
      error.value = `Can't save: ${plainValidation(await res.text())}`;
      return;
    }
    if (res.status === 401 || res.status === 403) {
      error.value =
        "Saving needs a recent sign-in with your code. Sign out, sign in again, then save.";
      return;
    }
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const body = (await res.json()) as { cells: Cell[]; status: Status };
    cells.value = body.cells.map((c) => ({
      ...c,
      machines: (c.machines || []).map((m) => ({
        ...m,
        auth: m.auth || "none",
      })),
    }));
    status.value = body.status;
    dirty.value = false;
    $showSuccess(
      "Saved. The server is applying the change to the machine shares."
    );
    await loadReleased();
    // Poll the apply status a few times so the banner flips on its own.
    for (let i = 0; i < 12 && !status.value.up_to_date; i++) {
      await new Promise((r) => setTimeout(r, 5000));
      const s = await fetch(`${baseURL}/api/cmmc/ot/inventory`, {
        headers: headers(),
        credentials: "include",
      });
      if (s.ok) status.value = ((await s.json()) as { status: Status }).status;
    }
  } catch (err) {
    $showError(err as Error);
  } finally {
    saving.value = false;
  }
};

const takeBack = async (cell: string, name: string) => {
  try {
    const res = await fetch(`${baseURL}/api/cmmc/ot/release`, {
      method: "DELETE",
      headers: headers(),
      credentials: "include",
      body: JSON.stringify({ cell, name, reason: "taken back from Settings" }),
    });
    if (res.status === 401 || res.status === 403) {
      error.value =
        "Taking a file back needs a recent sign-in with your code. Sign out, sign in again, then retry.";
      return;
    }
    if (!res.ok && res.status !== 204) throw new Error(`HTTP ${res.status}`);
    $showSuccess(`${name} is no longer on the ${cell} share`);
    await loadReleased();
  } catch (err) {
    $showError(err as Error);
  }
};

onMounted(load);
</script>

<style scoped>
/* One wide column: the machine table needs the room. */
.shopfloor {
  flex: 1 1 100%;
  max-width: 100%;
}
.cell {
  border: 1px solid var(--borderPrimary, #e0e0e0);
  border-radius: 4px;
  padding: 0.75em 1em;
  margin: 1em 0;
}
.cell-head {
  display: flex;
  flex-wrap: wrap;
  gap: 0.75em 1.5em;
  align-items: flex-end;
  margin-bottom: 0.5em;
}
.cell-head label {
  display: flex;
  flex-direction: column;
  font-size: 0.85em;
}
.cell-head label.check {
  flex-direction: row;
  align-items: center;
  gap: 0.4em;
  max-width: 28em;
}
.cell table {
  width: 100%;
}
.cell td .input {
  width: 100%;
  min-width: 7em;
}
.cell td:nth-child(3) .input,
.cell td:nth-child(4) .input {
  min-width: 9em;
}
.released {
  margin-top: 0.75em;
}
.released h3 {
  font-size: 0.95em;
  margin: 0.5em 0;
}
.released-table th,
.released-table td {
  white-space: nowrap;
  padding-right: 1.5em;
}
.released-table td:first-child {
  white-space: normal;
  width: 40%;
}
.status .ok {
  color: #2e7d32;
}
.status .pending {
  color: #8a4d00;
}
.card-box table td {
  padding: 0.15em 0.6em 0.15em 0;
}
code {
  font-family: ui-monospace, monospace;
  background: var(--surfaceSecondary, #f3f3f3);
  padding: 0.1em 0.35em;
  border-radius: 2px;
}
</style>
