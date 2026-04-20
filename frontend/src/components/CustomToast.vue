<template>
  <div class="t-container">
    <span>{{ message }}</span>
    <button v-if="showLogin" class="action" @click.stop="logInAgain">
      Log in again
    </button>
  </div>
</template>

<script setup lang="ts">
import { computed } from "vue";
import { logout } from "@/utils/auth";

const props = defineProps<{
  message: string;
  status?: number;
  // Legacy upstream props — accepted so main.ts can keep passing
  // them while we transition. Ignored beyond compiling.
  reportText?: string;
  isReport?: boolean;
}>();

// Only 401 has an actionable recovery in a CMMC deployment: drop
// the stale session and let Keycloak re-challenge. Other errors
// (404, 422 scan reject, 403 CUI move, 5xx) have no generic
// remediation the user can take from a toast — a "Report issue"
// button pointing at the upstream GitHub repo was worse than
// nothing because it nudged users toward pasting CUI file names
// into a public tracker. Silence the button for those cases.
const showLogin = computed(() => {
  if (props.status === 401) return true;
  const msg = (props.message || "").toString();
  return /\b401\b/.test(msg);
});

const logInAgain = async () => {
  try {
    await logout();
  } catch {
    // logout() navigates on success; on any error just hard-
    // navigate to /login so the user isn't stuck.
    window.location.assign("/login");
  }
};
</script>

<style scoped>
.t-container {
  width: 100%;
  padding: 5px 0;
  display: flex;
  justify-content: space-between;
  align-items: center;
}
.action {
  text-align: center;
  height: 40px;
  padding: 0 10px;
  margin-left: 20px;
  border-radius: 5px;
  color: white;
  cursor: pointer;
  border: thin solid currentColor;
}

html[dir="rtl"] .action {
  margin-left: initial;
  margin-right: 20px;
}
</style>
