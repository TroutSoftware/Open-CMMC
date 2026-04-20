<template>
  <div class="card floating">
    <div class="card-title">
      <h2>{{ targetIsDir ? "Classify folder" : "Classify file" }}</h2>
    </div>

    <div class="card-content">
      <p v-if="targetIsDir" class="small">
        Classification for <code>{{ targetPath }}</code>. Files uploaded
        into this folder automatically inherit this mark (CMMC 3.8.4).
        Changes take effect immediately. Admin + fresh MFA required.
      </p>
      <p v-else class="small">
        Classification for <code>{{ targetPath }}</code>. Per-file marks
        override the folder default for this one file (CMMC 3.8.4).
        Changes take effect immediately. Admin + fresh MFA required.
      </p>

      <p>
        <label for="classify-mark">Classification</label>
        <select
          id="classify-mark"
          v-model="selectedMark"
          class="input input--block"
        >
          <option
            v-for="m in catalog"
            :key="m"
            :value="m"
          >
            {{ labelFor(m) }}
          </option>
        </select>
      </p>

      <!-- Reason is mandatory when declassifying (mark -> None). CMMC
           3.8.3 / DoDI 5200.48 require the decontrol decision to be
           documented; this value lands verbatim on the
           cui.mark.declassify audit event. -->
      <p v-if="selectedMark === '' && currentMark !== ''">
        <label for="classify-reason">
          Reason for declassification
          <span class="small" style="color: #8a4d00">(required — recorded in audit log)</span>
        </label>
        <textarea
          id="classify-reason"
          v-model="declassifyReason"
          class="input input--block"
          rows="3"
          maxlength="500"
          placeholder="e.g. marked in error; legal review confirmed decontrol; data aged out"
        ></textarea>
        <span class="small" style="color: var(--textSecondary)">
          {{ declassifyReason.length }} / 500
        </span>
      </p>

      <p v-if="loading" class="small">Loading catalog…</p>
      <p v-if="error" class="small" style="color: #c62828">{{ error }}</p>
    </div>

    <div class="card-action">
      <button
        class="button button--flat button--grey"
        @click="closeHovers"
      >
        Cancel
      </button>
      <button
        @click="submit"
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

const layoutStore = useLayoutStore();
const fileStore = useFileStore();
const authStore = useAuthStore();

const catalog = ref<string[]>([]);
const selectedMark = ref<string>("");
const currentMark = ref<string>(""); // what's stored server-side right now
const declassifyReason = ref<string>("");
const loading = ref<boolean>(true);
const submitting = ref<boolean>(false);
const error = ref<string>("");

const $showError = inject<IToastError>("$showError")!;
const $showSuccess = inject<IToastSuccess>("$showSuccess")!;

const closeHovers = () => layoutStore.closeHovers();

// The path of the item being classified. Two cases:
//   - Modal opened from the listing with a selected file OR folder →
//     operate on the selected item
//   - Modal opened while browsing inside a folder (no selection) →
//     operate on the current req path.
const targetPath = computed<string>(() => {
  const req: any = fileStore.req;
  if (!req) return "";
  const sel = fileStore.selected;
  if (req.items && sel && sel.length === 1) {
    return decodeURI(req.items[sel[0]].path);
  }
  return decodeURI(req.path || "/");
});

// Whether the target is a directory. Drives the copy shown above
// ("Classify folder" vs "Classify file") and whether the save
// handler surfaces the declassify-children-exist message.
const targetIsDir = computed<boolean>(() => {
  const req: any = fileStore.req;
  if (!req) return true;
  const sel = fileStore.selected;
  if (req.items && sel && sel.length === 1) {
    return !!req.items[sel[0]]?.isDir;
  }
  return !!req.isDir;
});

const labelFor = (mark: string): string => {
  if (mark === "") return "— None (uncontrolled)";
  return mark;
};

const authHeaders = (): HeadersInit => {
  const h: Record<string, string> = { "Content-Type": "application/json" };
  if (authStore.jwt) h["X-Auth"] = authStore.jwt;
  return h;
};

onMounted(async () => {
  try {
    const res = await fetch(`${baseURL}/api/cmmc/marking/catalog`, {
      headers: authHeaders(),
      credentials: "include",
    });
    if (!res.ok) throw new Error(`catalog HTTP ${res.status}`);
    const body = (await res.json()) as { marks: string[] };
    // Prepend "None" so admins can clear a classification from the
    // dropdown directly (backend's declassify gate still refuses if
    // the folder has CUI children).
    catalog.value = ["", ...(body.marks || []).filter((m) => m !== "")];
    // Pre-select current classification if possible. Track the
    // server-side value separately so the reason-field shows only
    // when this PUT would actually clear an existing mark (not
    // when an already-uncontrolled path is saved with None again).
    currentMark.value = await fetchCurrentMark(targetPath.value);
    selectedMark.value = currentMark.value;
  } catch (err) {
    error.value = `Could not load classification catalog: ${(err as Error).message}`;
  } finally {
    loading.value = false;
  }
});

const fetchCurrentMark = async (path: string): Promise<string> => {
  if (!path) return "";
  try {
    const res = await fetch(
      `${baseURL}/api/cmmc/marking?path=${encodeURIComponent(path)}`,
      { headers: authHeaders(), credentials: "include" }
    );
    if (!res.ok) return "";
    const body = (await res.json()) as { mark?: string };
    return body.mark || "";
  } catch {
    return "";
  }
};

const submit = async () => {
  if (!targetPath.value) return;

  // Client-side gate: declassify requires a non-empty reason (the
  // backend enforces this too — 400 on empty reason). Showing the
  // error before the round trip saves an API call.
  const isDeclassify = selectedMark.value === "" && currentMark.value !== "";
  if (isDeclassify && declassifyReason.value.trim() === "") {
    error.value = "A reason is required to declassify — recorded in the audit log.";
    return;
  }

  submitting.value = true;
  error.value = "";
  try {
    const body: Record<string, string> = {
      path: targetPath.value,
      mark: selectedMark.value,
    };
    if (isDeclassify) body.reason = declassifyReason.value.trim();
    const res = await fetch(`${baseURL}/api/cmmc/marking`, {
      method: "PUT",
      headers: authHeaders(),
      credentials: "include",
      body: JSON.stringify(body),
    });
    if (res.status === 409) {
      // Declassify refused because CUI descendants exist — only
      // possible for folders; a file has no descendants.
      error.value = targetIsDir.value
        ? "Cannot declassify: this folder contains CUI items. Move or declassify them first."
        : "Cannot declassify: backend refused (409).";
      return;
    }
    if (!res.ok) {
      throw new Error(`HTTP ${res.status}`);
    }
    $showSuccess(
      selectedMark.value === ""
        ? `Declassified ${targetPath.value}`
        : `Classified ${targetPath.value} as ${selectedMark.value}`
    );
    // Reload current listing so the badge refreshes.
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
.card-content code {
  font-family: ui-monospace, monospace;
  background: var(--surfaceSecondary, #f3f3f3);
  padding: 0.1em 0.35em;
  border-radius: 2px;
  font-size: 0.9em;
}
</style>
