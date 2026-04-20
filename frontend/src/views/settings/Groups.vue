<template>
  <div class="row">
    <div class="column">
      <div class="card">
        <div class="card-title">
          <h2>Groups &amp; Permissions</h2>
        </div>

        <p class="cmmc-identity-notice">
          <strong>Group-based authorization.</strong>
          Each Keycloak group maps to one role. Users inherit the
          <em>union</em> of their groups' permissions on every login.
          Group membership is managed in Keycloak; the mapping from
          group to role is managed here.
        </p>

        <div class="card-content full">
          <div v-if="loading" class="small">Loading…</div>
          <div v-else-if="rows.length === 0" class="small">
            No groups configured yet. Add the first one below to grant
            access to a Keycloak group.
          </div>
          <table v-else>
            <tr>
              <th>Keycloak group</th>
              <th>Role</th>
              <th>Source</th>
              <th></th>
            </tr>
            <tr v-for="row in rows" :key="row.group">
              <td>
                <code>{{ row.group }}</code>
              </td>
              <td>
                <select
                  class="input"
                  v-model="row.role"
                  @change="saveRow(row)"
                >
                  <option
                    v-for="r in roles"
                    :key="r"
                    :value="r"
                  >
                    {{ roleLabel(r) }}
                  </option>
                </select>
              </td>
              <td class="small">
                {{ row.source || "—" }}
              </td>
              <td class="small">
                <button
                  class="action"
                  :aria-label="`Remove ${row.group}`"
                  :title="`Remove ${row.group}`"
                  @click="removeRow(row)"
                >
                  <i class="material-icons">delete</i>
                </button>
              </td>
            </tr>
          </table>
        </div>

        <div class="card-action">
          <form
            class="add-row"
            @submit.prevent="addRow"
            autocomplete="off"
          >
            <input
              class="input"
              type="text"
              v-model="newGroup"
              placeholder="Keycloak group name (e.g., engineering)"
            />
            <select class="input" v-model="newRole">
              <option
                v-for="r in rolesNonEmpty"
                :key="r"
                :value="r"
              >
                {{ roleLabel(r) }}
              </option>
            </select>
            <button
              class="button button--flat"
              type="submit"
              :disabled="!newGroup.trim()"
            >
              Add group
            </button>
          </form>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { inject, onMounted, ref, computed } from "vue";
import { baseURL } from "@/utils/constants";
import { useAuthStore } from "@/stores/auth";

interface GroupRow {
  group: string;
  role: string;
  source?: string;
}

const rows = ref<GroupRow[]>([]);
const roles = ref<string[]>([]);
const loading = ref<boolean>(true);
const newGroup = ref<string>("");
const newRole = ref<string>("viewer");

const authStore = useAuthStore();
const $showError = inject<IToastError>("$showError")!;
const $showSuccess = inject<IToastSuccess>("$showSuccess")!;

const rolesNonEmpty = computed(() => roles.value.filter((r) => r !== ""));

const roleLabel = (r: string): string => {
  switch (r) {
    case "viewer":
      return "Viewer";
    case "contributor":
      return "Contributor";
    case "collaborator":
      return "Collaborator";
    case "admin":
      return "Admin (ISSO)";
    case "":
      return "No access";
  }
  return r;
};

const authHeaders = (): HeadersInit => {
  const h: Record<string, string> = { "Content-Type": "application/json" };
  if (authStore.jwt) h["X-Auth"] = authStore.jwt;
  return h;
};

const load = async (): Promise<void> => {
  loading.value = true;
  try {
    const res = await fetch(`${baseURL}/api/cmmc/groups`, {
      headers: authHeaders(),
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const body = (await res.json()) as { groups: GroupRow[]; roles: string[] };
    rows.value = body.groups ?? [];
    roles.value = body.roles ?? [];
  } catch (err) {
    $showError(err as Error);
  } finally {
    loading.value = false;
  }
};

const saveRow = async (row: GroupRow): Promise<void> => {
  try {
    const res = await fetch(`${baseURL}/api/cmmc/groups`, {
      method: "PUT",
      headers: authHeaders(),
      body: JSON.stringify({ group: row.group, role: row.role }),
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    $showSuccess(`Updated ${row.group} → ${roleLabel(row.role)}`);
    // Reload to pick up Source update.
    await load();
  } catch (err) {
    $showError(err as Error);
    await load(); // revert local edit
  }
};

const addRow = async (): Promise<void> => {
  const g = newGroup.value.trim();
  if (!g) return;
  try {
    const res = await fetch(`${baseURL}/api/cmmc/groups`, {
      method: "PUT",
      headers: authHeaders(),
      body: JSON.stringify({ group: g, role: newRole.value }),
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    $showSuccess(`Added ${g} → ${roleLabel(newRole.value)}`);
    newGroup.value = "";
    await load();
  } catch (err) {
    $showError(err as Error);
  }
};

const removeRow = async (row: GroupRow): Promise<void> => {
  if (!confirm(`Remove the ${row.group} group assignment?\n\nUsers whose only group is ${row.group} will lose access on next login.`)) {
    return;
  }
  try {
    const res = await fetch(
      `${baseURL}/api/cmmc/groups/${encodeURIComponent(row.group)}`,
      { method: "DELETE", headers: authHeaders() }
    );
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    $showSuccess(`Removed ${row.group}`);
    await load();
  } catch (err) {
    $showError(err as Error);
  }
};

onMounted(load);
</script>

<style scoped>
.card-action form.add-row {
  display: flex;
  gap: 0.5em;
  flex-wrap: wrap;
  align-items: center;
}
.card-action form.add-row input[type="text"] {
  flex: 1 1 14em;
  min-width: 12em;
}
.card-action form.add-row select {
  flex: 0 0 auto;
}
td code {
  font-family: ui-monospace, monospace;
  background: var(--surfaceSecondary, #f3f3f3);
  padding: 0.1em 0.35em;
  border-radius: 2px;
  font-size: 0.85em;
}
</style>
