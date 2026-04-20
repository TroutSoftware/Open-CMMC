<template>
  <div class="dashboard">
    <header-bar showMenu showLogo />

    <div class="row me-grid">
      <!-- ─── top: profile card (spans both columns) ───────────── -->
      <div class="column col-wide">
        <div class="card">
          <div class="card-title">
            <h2>{{ me?.fullName || me?.username || "…" }}</h2>
          </div>
          <div class="card-content">
            <div v-if="loading" class="small">Loading…</div>
            <div v-else-if="me" class="profile-grid">
              <div class="profile-item">
                <label>Username</label>
                <div>{{ me.username }}</div>
              </div>
              <div class="profile-item" v-if="me.email">
                <label>Email</label>
                <div><a :href="'mailto:' + me.email">{{ me.email }}</a></div>
              </div>
              <div class="profile-item">
                <label>Scope</label>
                <div><code>{{ me.scope }}</code></div>
              </div>
              <div class="profile-item profile-item--full" v-if="me.groups && me.groups.length">
                <label>Groups &amp; roles</label>
                <div>
                  <span
                    v-for="g in me.groups"
                    :key="g"
                    class="group-pill"
                  >
                    <code>{{ g }}</code>
                    <span class="role">→ {{ me.roleLabels?.[g] || "No access" }}</span>
                  </span>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>

    <div class="row me-grid">
      <!-- Recent activity, full width (Favorites placeholder removed). -->
      <div class="column">
        <div class="card">
          <div class="card-title">
            <h2>Recent activity</h2>
          </div>
          <div class="card-content full">
            <div v-if="loading" class="small">Loading…</div>
            <p v-else-if="!me?.activity?.length" class="small empty">
              No activity yet. Actions you take (downloads, uploads,
              logins) appear here with their timestamp.
            </p>
            <table v-else class="activity-table">
              <tr v-for="(e, i) in me.activity" :key="i">
                <td class="time">
                  <time :datetime="e.ts" :title="e.ts">{{ shortTime(e.ts) }}</time>
                </td>
                <td class="action-cell">
                  <span :class="['action-pill', actionClass(e.action)]">{{ humanAction(e.action) }}</span>
                </td>
                <td class="resource">
                  <code v-if="e.resource">{{ truncate(e.resource, 48) }}</code>
                </td>
                <td class="outcome">
                  <span v-if="e.outcome !== 'success'" :class="['outcome-' + e.outcome]">
                    {{ e.outcome }}
                  </span>
                </td>
              </tr>
            </table>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { onMounted, ref, inject } from "vue";
import dayjs from "dayjs";
import HeaderBar from "@/components/header/HeaderBar.vue";
import { baseURL } from "@/utils/constants";
import { useAuthStore } from "@/stores/auth";

interface AuditEvent {
  ts: string;
  action: string;
  resource?: string;
  outcome: string;
  status?: number;
}
interface MePayload {
  username: string;
  email?: string;
  fullName?: string;
  groups?: string[];
  roleLabels?: Record<string, string>;
  scope: string;
  perm: Record<string, boolean>;
  activity: AuditEvent[];
}

const me = ref<MePayload | null>(null);
const loading = ref<boolean>(true);

const authStore = useAuthStore();
const $showError = inject<IToastError>("$showError")!;

onMounted(async () => {
  loading.value = true;
  try {
    const res = await fetch(`${baseURL}/api/cmmc/me`, {
      headers: authStore.jwt ? { "X-Auth": authStore.jwt } : {},
      credentials: "include",
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    me.value = await res.json();
  } catch (err) {
    $showError(err as Error);
  } finally {
    loading.value = false;
  }
});

const shortTime = (iso: string): string => {
  if (!iso) return "";
  const d = dayjs(iso);
  if (Date.now() - d.valueOf() < 24 * 3600 * 1000) return d.format("HH:mm:ss");
  return d.format("MMM D HH:mm");
};

const truncate = (s: string, n: number): string =>
  s.length > n ? s.slice(0, n - 1) + "…" : s;

// Humanize the namespaced action into something a shop-floor user
// recognizes. Unknown actions fall through unchanged.
const humanAction = (a: string): string => {
  const m: Record<string, string> = {
    "auth.login.ok": "Login",
    "auth.login.fail": "Login failed",
    "auth.logout": "Logout",
    "file.read": "Open folder",
    "file.download": "Download",
    "file.upload": "Upload",
    "file.delete": "Delete",
    "file.rename": "Rename",
    "file.modify": "Modify",
    "file.preview": "Preview",
    "file.search": "Search",
    "cui.mark.set": "Set CUI mark",
    "cui.mark.get": "Read CUI mark",
    "cui.access.reject": "Blocked (CUI)",
    "share.create": "Create share",
    "share.delete": "Delete share",
    "authz.priv.reject": "Denied (MFA)",
  };
  return m[a] || a;
};

const actionClass = (a: string): string => {
  if (a.startsWith("auth.login.fail") || a.endsWith(".reject")) return "bad";
  if (a.startsWith("cui.")) return "cui";
  if (a === "file.download" || a === "file.upload") return "warn";
  return "ok";
};
</script>

<style scoped>
.me-grid .column {
  flex: 1 1 22em;
  min-width: 18em;
}
.me-grid .col-wide {
  flex: 1 1 100%;
}
.profile-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(14em, 1fr));
  gap: 0.8em 1.5em;
}
.profile-item label {
  display: block;
  font-size: 0.75rem;
  text-transform: uppercase;
  letter-spacing: 0.04em;
  color: var(--textSecondary, #666);
  margin-bottom: 0.2em;
}
.profile-item--full {
  grid-column: 1 / -1;
}
.profile-item div {
  font-size: 0.95rem;
}
.profile-item code {
  font-family: ui-monospace, monospace;
  background: var(--surfaceSecondary, #f3f3f3);
  padding: 0.1em 0.35em;
  border-radius: 2px;
  font-size: 0.85em;
}
.group-pill {
  display: inline-flex;
  align-items: center;
  gap: 0.4em;
  margin: 0.25em 0.5em 0.25em 0;
  padding: 0.2em 0.55em;
  background: #e8f4fd;
  border: 1px solid #1976d2;
  border-radius: 3px;
  font-size: 0.85em;
}
.group-pill code {
  background: transparent;
  padding: 0;
  font-weight: 500;
}
.group-pill .role {
  color: #0d3c6e;
  font-weight: 500;
}

.activity-table {
  width: 100%;
  border-collapse: collapse;
  font-size: 0.85rem;
}
.activity-table td {
  padding: 0.4em 0.6em;
  border-bottom: 1px solid var(--borderPrimary, #eee);
  vertical-align: middle;
}
.activity-table tr:last-child td {
  border-bottom: 0;
}
.activity-table .time {
  white-space: nowrap;
  color: var(--textSecondary, #666);
  font-variant-numeric: tabular-nums;
  width: 9em;
}
.activity-table .action-cell {
  white-space: nowrap;
  width: 11em;
}
.activity-table .resource code {
  font-family: ui-monospace, monospace;
  font-size: 0.82em;
  color: var(--textSecondary, #555);
}
.activity-table .outcome {
  width: 6em;
  text-align: right;
  font-size: 0.8em;
}
.activity-table .outcome-reject,
.activity-table .outcome-failure {
  color: #c62828;
  font-weight: 600;
}
.action-pill {
  display: inline-block;
  padding: 0.1em 0.5em;
  border-radius: 3px;
  font-size: 0.75em;
  font-weight: 500;
  background: #eef4f9;
  color: #375a7f;
}
.action-pill.cui {
  background: #fde7e7;
  color: #8c1f1f;
}
.action-pill.warn {
  background: #fff4e5;
  color: #8a4d00;
}
.action-pill.bad {
  background: #c62828;
  color: white;
}

.empty {
  color: var(--textSecondary, #777);
  padding: 0.5em 0;
}
</style>
