<template>
  <errors v-if="error" :errorCode="error.status" />
  <div class="row" v-else-if="!layoutStore.loading">
    <div class="column">
      <div class="card">
        <div class="card-title">
          <h2>{{ t("settings.users") }}</h2>
          <!--
            CMMC: under OIDC the IdP is the sole source of identity.
            Creating a local user without a matching Keycloak account
            produces an orphan that can never log in; rows are
            provisioned automatically on first successful OIDC login.
          -->
          <router-link v-if="!isOIDC" to="/settings/users/new"
            ><button class="button">
              {{ t("buttons.new") }}
            </button></router-link
          >
        </div>

        <p v-if="isOIDC" class="cmmc-identity-notice">
          <strong>Identity managed in Keycloak.</strong>
          Users are created automatically on first OIDC login. This
          panel shows the per-user authorization state (scope,
          admin status) derived from IdP group membership. To add or
          remove a user, manage them in Keycloak.
        </p>

        <div class="card-content full">
          <table>
            <tr>
              <th>{{ t("settings.username") }}</th>
              <th>{{ t("settings.admin") }}</th>
              <th>{{ t("settings.scope") }}</th>
              <th></th>
            </tr>

            <tr v-for="user in users" :key="user.id">
              <td>{{ user.username }}</td>
              <td>
                <i v-if="user.perm.admin" class="material-icons">done</i
                ><i v-else class="material-icons">close</i>
              </td>
              <td>{{ user.scope }}</td>
              <td class="small">
                <router-link :to="'/settings/users/' + user.id"
                  ><i class="material-icons">mode_edit</i></router-link
                >
              </td>
            </tr>
          </table>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { useLayoutStore } from "@/stores/layout";
import { users as api } from "@/api";
import Errors from "@/views/Errors.vue";
import { onMounted, ref } from "vue";
import { useI18n } from "vue-i18n";
import { StatusError } from "@/api/utils";
import { authMethod } from "@/utils/constants";

const isOIDC = authMethod === "oidc";

const error = ref<StatusError | null>(null);
const users = ref<IUser[]>([]);

const layoutStore = useLayoutStore();
const { t } = useI18n();

onMounted(async () => {
  layoutStore.loading = true;

  try {
    users.value = await api.getAll();
  } catch (err) {
    if (err instanceof Error) {
      error.value = err;
    }
  } finally {
    layoutStore.loading = false;
  }
});
</script>
