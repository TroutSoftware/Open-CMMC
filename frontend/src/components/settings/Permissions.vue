<template>
  <div>
    <h3>{{ $t("settings.permissions") }}</h3>
    <!--
      Under OIDC, per-user permission editing is read-only — the
      source of truth is the user's Keycloak group membership
      unioned through the Groups & Permissions table. Admins who
      want to grant or revoke must either (a) change the user's
      Keycloak groups, or (b) change the role assigned to one of
      those groups on the Groups & Permissions page. Keeping this
      panel read-only prevents the next-login-overwrite surprise.
    -->
    <p v-if="isOIDC" class="cmmc-identity-notice">
      <strong>Derived from group membership.</strong>
      Permissions are computed at login from the user's Keycloak
      groups via
      <router-link to="/settings/groups">Groups &amp; Permissions</router-link>.
      Changes here will be overwritten on next login.
    </p>
    <p class="small" v-else>{{ $t("settings.permissionsHelp") }}</p>

    <p>
      <input type="checkbox" v-model="admin" :disabled="isOIDC" />
      {{ $t("settings.administrator") }}
    </p>

    <p>
      <input type="checkbox" :disabled="admin || isOIDC" v-model="perm.create" />
      {{ $t("settings.perm.create") }}
    </p>
    <p>
      <input type="checkbox" :disabled="admin || isOIDC" v-model="perm.delete" />
      {{ $t("settings.perm.delete") }}
    </p>
    <p>
      <input
        type="checkbox"
        :disabled="admin || perm.share || isOIDC"
        v-model="perm.download"
      />
      {{ $t("settings.perm.download") }}
    </p>
    <p>
      <input type="checkbox" :disabled="admin || isOIDC" v-model="perm.modify" />
      {{ $t("settings.perm.modify") }}
    </p>
    <p v-if="isExecEnabled">
      <input type="checkbox" :disabled="admin || isOIDC" v-model="perm.execute" />
      {{ $t("settings.perm.execute") }}
    </p>
    <p>
      <input type="checkbox" :disabled="admin || isOIDC" v-model="perm.rename" />
      {{ $t("settings.perm.rename") }}
    </p>
    <p>
      <input type="checkbox" :disabled="admin || isOIDC" v-model="perm.share" />
      {{ $t("settings.perm.share") }}
    </p>
  </div>
</template>

<script>
import { enableExec, authMethod } from "@/utils/constants";
export default {
  name: "permissions",
  props: ["perm"],
  computed: {
    admin: {
      get() {
        return this.perm.admin;
      },
      set(value) {
        if (value) {
          for (const key in this.perm) {
            this.perm[key] = true;
          }
        }

        this.perm.admin = value;
      },
    },
    isExecEnabled: () => enableExec,
    isOIDC: () => authMethod === "oidc",
  },
  watch: {
    perm: {
      deep: true,
      handler() {
        if (this.perm.share === true) {
          this.perm.download = true;
        }
      },
    },
  },
};
</script>
