<template>
  <div class="card floating">
    <div class="card-title">
      <h2>Send to the shop floor</h2>
    </div>

    <div class="card-content">
      <p class="small">
        Make <code>{{ fileName }}</code> available to the machines in a cell. It
        stays on the machines' share until it expires or you take it back; the
        release is logged under your name.
      </p>

      <p v-if="loading" class="small">Loading cells…</p>
      <p v-else-if="disabled" class="small" style="color: #8a4d00">
        Shop-floor delivery isn't set up on this server yet.
      </p>

      <template v-else>
        <p>
          <label for="ot-cell">Which cell</label>
          <select
            id="ot-cell"
            v-model="selectedCell"
            class="input input--block"
          >
            <option v-for="c in cells" :key="c.name" :value="c.name">
              {{ c.name }} · {{ c.machines }} machine{{
                c.machines === 1 ? "" : "s"
              }}
              · available {{ c.ttl_days }} days
            </option>
          </select>
        </p>

        <p>
          <label for="ot-ttl"
            >Keep it available for (days) — leave blank for the cell's
            default</label
          >
          <input
            id="ot-ttl"
            v-model.number="ttlDays"
            type="number"
            min="1"
            max="365"
            class="input input--block"
          />
        </p>

        <p>
          <input id="ot-pinned" v-model="pinned" type="checkbox" />
          <label for="ot-pinned"> Keep until I take it back (no expiry) </label>
        </p>
      </template>

      <p v-if="error" class="small" style="color: #c62828">{{ error }}</p>
    </div>

    <div class="card-action">
      <button class="button button--flat button--grey" @click="closeHovers">
        Cancel
      </button>
      <button
        class="button button--flat"
        :disabled="loading || disabled || submitting || !selectedCell"
        @click="submit"
      >
        {{ submitting ? "Sending…" : "Send" }}
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

interface OTCell {
  name: string;
  mark: string;
  machines: number;
  pds_attested: boolean;
  ttl_days: number;
}

const layoutStore = useLayoutStore();
const fileStore = useFileStore();
const authStore = useAuthStore();

const cells = ref<OTCell[]>([]);
const selectedCell = ref<string>("");
const ttlDays = ref<number | "">("");
const pinned = ref<boolean>(false);
const loading = ref<boolean>(true);
const disabled = ref<boolean>(false);
const submitting = ref<boolean>(false);
const error = ref<string>("");

const $showError = inject<IToastError>("$showError")!;
const $showSuccess = inject<IToastSuccess>("$showSuccess")!;

const closeHovers = () => layoutStore.closeHovers();

// Single selected file in the current listing — the header button is
// only shown in that state (FileListing.vue headerButtons.releaseOt).
const targetPath = computed<string>(() => {
  const req: any = fileStore.req;
  const sel = fileStore.selected;
  if (req?.items && sel && sel.length === 1) {
    return decodeURI(req.items[sel[0]].path);
  }
  return "";
});

const fileName = computed<string>(() => {
  const p = targetPath.value;
  return p.substring(p.lastIndexOf("/") + 1) || p;
});

const authHeaders = (): HeadersInit => {
  const h: Record<string, string> = { "Content-Type": "application/json" };
  if (authStore.jwt) h["X-Auth"] = authStore.jwt;
  return h;
};

onMounted(async () => {
  try {
    const res = await fetch(`${baseURL}/api/cmmc/ot/cells`, {
      headers: authHeaders(),
      credentials: "include",
    });
    if (res.status === 503) {
      disabled.value = true;
      return;
    }
    if (!res.ok) throw new Error(`cells HTTP ${res.status}`);
    cells.value = (await res.json()) as OTCell[];
    if (cells.value.length > 0) selectedCell.value = cells.value[0].name;
  } catch (err) {
    error.value = `Could not load cells: ${(err as Error).message}`;
  } finally {
    loading.value = false;
  }
});

const submit = async () => {
  if (!targetPath.value || !selectedCell.value) return;
  submitting.value = true;
  error.value = "";
  try {
    const body: Record<string, unknown> = {
      path: targetPath.value,
      cell: selectedCell.value,
      pinned: pinned.value,
    };
    if (ttlDays.value !== "" && Number(ttlDays.value) > 0) {
      body.ttl_days = Number(ttlDays.value);
    }
    const res = await fetch(`${baseURL}/api/cmmc/ot/release`, {
      method: "POST",
      headers: authHeaders(),
      credentials: "include",
      body: JSON.stringify(body),
    });
    if (res.status === 409) {
      error.value =
        "This file is marked ITAR and that cell isn't an ITAR cell. Pick an ITAR cell.";
      return;
    }
    if (res.status === 401 || res.status === 403) {
      error.value =
        "You can't send files from this folder. Ask an admin for the Release permission, or sign in again if your MFA step is old.";
      return;
    }
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const m = (await res.json()) as {
      name: string;
      cell: string;
      sha256: string;
    };
    $showSuccess(`${m.name} is now available to the ${m.cell} machines`);
    closeHovers();
  } catch (err) {
    $showError(err as Error);
  } finally {
    submitting.value = false;
  }
};
</script>

<style scoped>
.card-content code {
  font-family: ui-monospace, monospace;
  background: var(--surfaceSecondary, #f3f3f3);
  padding: 0.1em 0.35em;
  border-radius: 2px;
  font-size: 0.9em;
}
</style>
