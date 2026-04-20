<template>
  <div class="card floating card-wide">
    <div class="card-title">
      <h2>Folder permissions</h2>
    </div>

    <div class="card-content">
      <p class="small">
        Per-folder access control for <code>{{ targetPath }}</code>.
        Entries here override the starter cabinet defaults and
        apply to this folder + every subfolder under it. Admin +
        fresh MFA required. CMMC 3.1.1 / 3.1.5.
      </p>

      <p v-if="loading" class="small">Loading…</p>
      <p v-if="error" class="small acl-error">{{ error }}</p>

      <div v-if="!loading && defaults.length > 0" class="acl-section">
        <h4 class="acl-section-title">In force now (starter defaults)</h4>
        <table class="acl-table">
          <thead>
            <tr>
              <th class="col-type">Type</th>
              <th class="col-principal">Principal</th>
              <th class="col-perm">R</th>
              <th class="col-perm">W</th>
              <th class="col-perm">S</th>
              <th class="col-source">Source</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="(def, i) in defaults" :key="'default-' + i" class="row-default">
              <td>{{ def.kind }}</td>
              <td><code>{{ def.id }}</code></td>
              <td>{{ def.perms.read ? "✓" : "" }}</td>
              <td>{{ def.perms.write ? "✓" : "" }}</td>
              <td>{{ def.perms.share ? "✓" : "" }}</td>
              <td class="small">{{ def.source }}</td>
            </tr>
          </tbody>
        </table>
        <p class="small">
          Explicit entries below override the defaults for this
          folder and its subfolders.
        </p>
      </div>

      <div v-if="!loading" class="acl-section">
        <h4 class="acl-section-title">Explicit permissions</h4>
        <table class="acl-table">
          <thead>
            <tr>
              <th class="col-type">Type</th>
              <th class="col-principal">Principal</th>
              <th class="col-perm">R</th>
              <th class="col-perm">W</th>
              <th class="col-perm">S</th>
              <th class="col-action"></th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="(entry, i) in entries" :key="i">
              <td>
                <select v-model="entry.kind" class="compact-select">
                  <option value="group">Group</option>
                  <option value="user">User</option>
                </select>
              </td>
              <td>
                <input
                  class="input compact-input"
                  v-model="entry.id"
                  :placeholder="entry.kind === 'user' ? 'alice' : 'engineering'"
                />
              </td>
              <td><input type="checkbox" v-model="entry.perms.read" /></td>
              <td><input type="checkbox" v-model="entry.perms.write" /></td>
              <td><input type="checkbox" v-model="entry.perms.share" /></td>
              <td>
                <button
                  class="icon-button"
                  @click="removeRow(i)"
                  type="button"
                  title="Remove"
                  aria-label="Remove row"
                >
                  ✕
                </button>
              </td>
            </tr>
            <tr v-if="entries.length === 0">
              <td colspan="6" class="small empty">
                No explicit entries. Defaults above are in force.
              </td>
            </tr>
          </tbody>
        </table>
      </div>

      <p>
        <button
          class="button button--flat"
          @click="addRow"
          type="button"
          :disabled="loading || submitting"
        >
          + Add permission
        </button>
      </p>
    </div>

    <div class="card-action">
      <button
        class="button button--flat button--grey"
        @click="closeHovers"
      >
        Cancel
      </button>
      <button
        v-if="hasExisting && entries.length === 0"
        class="button button--flat button--red"
        @click="deleteAcl"
        :disabled="loading || submitting"
      >
        {{ submitting ? "Removing…" : "Remove ACL" }}
      </button>
      <button
        @click="save"
        class="button button--flat"
        :disabled="loading || submitting"
      >
        {{ submitting ? "Saving…" : "Save" }}
      </button>
    </div>
  </div>
</template>

<script setup lang="ts">
import { computed, inject, onMounted, ref } from "vue";
import { useLayoutStore } from "@/stores/layout";
import { useFileStore } from "@/stores/file";
import { useAuthStore } from "@/stores/auth";
import { baseURL } from "@/utils/constants";

interface Perms {
  read: boolean;
  write: boolean;
  share: boolean;
}
interface Entry {
  kind: "group" | "user";
  id: string;
  perms: Perms;
}

const layoutStore = useLayoutStore();
const fileStore = useFileStore();
const authStore = useAuthStore();

interface DefaultEntry {
  kind: "group" | "user";
  id: string;
  perms: Perms;
  source: string;
}

const loading = ref(true);
const submitting = ref(false);
const error = ref("");
const entries = ref<Entry[]>([]);
const defaults = ref<DefaultEntry[]>([]);
const hasExisting = ref(false);

const $showSuccess = inject<IToastSuccess>("$showSuccess")!;
const $showError = inject<IToastError>("$showError")!;

const closeHovers = () => layoutStore.closeHovers();

// Same target-path semantics as ClassifyCUI: if a single directory
// is selected, target it; otherwise target the currently-browsed
// folder.
const targetPath = computed<string>(() => {
  const req: any = fileStore.req;
  if (!req) return "/";
  const sel = fileStore.selected;
  if (req.items && sel && sel.length === 1) {
    return decodeURI(req.items[sel[0]].path);
  }
  return decodeURI(req.path || "/");
});

const authHeaders = (): HeadersInit => {
  const h: Record<string, string> = { "Content-Type": "application/json" };
  if (authStore.jwt) h["X-Auth"] = authStore.jwt;
  return h;
};

onMounted(async () => {
  try {
    const url = `${baseURL}/api/cmmc/acl?path=${encodeURIComponent(
      targetPath.value
    )}`;
    const res = await fetch(url, {
      headers: authHeaders(),
      credentials: "include",
    });
    if (!res.ok) throw new Error(`GET /api/cmmc/acl HTTP ${res.status}`);
    const body = (await res.json()) as {
      path: string;
      entries: Entry[];
      defaults?: DefaultEntry[];
    };
    entries.value = body.entries ?? [];
    defaults.value = body.defaults ?? [];
    hasExisting.value = (body.entries ?? []).length > 0;
  } catch (err) {
    error.value = `Could not load ACL: ${(err as Error).message}`;
  } finally {
    loading.value = false;
  }
});

const addRow = () => {
  entries.value.push({
    kind: "group",
    id: "",
    perms: { read: true, write: false, share: false },
  });
};

const removeRow = (i: number) => {
  entries.value.splice(i, 1);
};

const save = async () => {
  submitting.value = true;
  error.value = "";
  try {
    // Reject empty ids before the round trip — backend validates
    // too, but a quick UX check saves a failed request.
    for (const e of entries.value) {
      if (!e.id.trim()) {
        error.value =
          "Every row needs a principal (group name or username).";
        submitting.value = false;
        return;
      }
    }
    const res = await fetch(`${baseURL}/api/cmmc/acl`, {
      method: "PUT",
      headers: authHeaders(),
      credentials: "include",
      body: JSON.stringify({
        path: targetPath.value,
        entries: entries.value,
      }),
    });
    if (!res.ok) {
      const txt = await res.text();
      throw new Error(txt || `HTTP ${res.status}`);
    }
    $showSuccess(`Permissions saved for ${targetPath.value}`);
    fileStore.reload = true;
    closeHovers();
  } catch (err) {
    $showError(err as Error);
  } finally {
    submitting.value = false;
  }
};

const deleteAcl = async () => {
  submitting.value = true;
  error.value = "";
  try {
    const url = `${baseURL}/api/cmmc/acl?path=${encodeURIComponent(
      targetPath.value
    )}`;
    const res = await fetch(url, {
      method: "DELETE",
      headers: authHeaders(),
      credentials: "include",
    });
    if (!res.ok && res.status !== 204) {
      const txt = await res.text();
      throw new Error(txt || `HTTP ${res.status}`);
    }
    $showSuccess(`Permissions cleared for ${targetPath.value}`);
    fileStore.reload = true;
    closeHovers();
  } catch (err) {
    $showError(err as Error);
  } finally {
    submitting.value = false;
  }
};
</script>

<style scoped>
.card-wide {
  max-width: 820px;
  width: min(90vw, 820px);
}
.card-content code {
  font-family: ui-monospace, monospace;
  background: var(--surfaceSecondary, #f3f3f3);
  padding: 0.1em 0.35em;
  border-radius: 2px;
  font-size: 0.9em;
}
.acl-error {
  color: #c62828;
}
.acl-section {
  margin: 1rem 0 0.5rem;
}
.acl-section-title {
  font-size: 0.78rem;
  text-transform: uppercase;
  letter-spacing: 0.05em;
  color: var(--textSecondary);
  margin: 0 0 0.4rem;
  font-weight: 600;
}
.acl-table {
  width: 100%;
  border-collapse: collapse;
  font-size: 0.9em;
  table-layout: fixed;
}
.acl-table th,
.acl-table td {
  padding: 0.4rem 0.35rem;
  border-bottom: 1px solid var(--divider, #eee);
  text-align: left;
  vertical-align: middle;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.acl-table th {
  font-weight: 600;
  color: var(--textPrimary);
}
.col-type {
  width: 5.5rem;
}
.col-principal {
  width: auto;
}
.col-perm {
  width: 2.2rem;
  text-align: center;
}
.col-source {
  width: 42%;
  color: var(--textSecondary);
}
.col-action {
  width: 2rem;
}
.acl-table .col-perm {
  text-align: center;
}
.acl-table td.col-perm input[type="checkbox"] {
  transform: scale(1.1);
}
.row-default td {
  background: var(--surfaceSecondary, #fafafa);
  color: var(--textPrimary);
  font-size: 0.85em;
}
.row-default code {
  background: transparent;
  padding: 0;
}
.compact-select {
  height: 2rem;
  padding: 0 0.4rem;
  width: 100%;
}
.compact-input {
  height: 2rem;
  padding: 0 0.5rem;
  width: 100%;
  box-sizing: border-box;
}
.icon-button {
  background: transparent;
  border: none;
  color: #c62828;
  cursor: pointer;
  font-size: 1rem;
  padding: 0.25rem 0.4rem;
  line-height: 1;
}
.icon-button:hover {
  color: #d32f2f;
}
.empty {
  text-align: center;
  color: var(--textSecondary);
  font-style: italic;
}
</style>
