<template>
  <errors v-if="error" :errorCode="error.status" />
  <div class="row" v-else-if="!layoutStore.loading && settings !== null">
    <div class="column">
      <!--
        CMMC fork: settings are READ-ONLY in the UI. Security-
        relevant knobs (FIPS posture, encryption, idle timeout,
        rate limit, MFA threshold) are SSP-level decisions baked
        into env + bootstrap at deploy time. Runtime edits would
        turn admin compromise into a silent policy-degradation
        channel. Assessors + operators can still *read* the
        configured posture; writes are blocked server-side too
        (settings_put returns 405 with X-CMMC-Block: settings-readonly).
      -->
      <div class="card cmmc-readonly-banner">
        <div class="card-content">
          <p class="small">
            <strong>Read-only.</strong> Settings visible here are
            SSP-locked. To change any value, edit the deployment
            env file (<code>/etc/cmmc-filebrowser/environment</code>)
            and redeploy — the appliance refuses runtime writes by
            design (CMMC 3.4.1 / 3.4.5 configuration management).
          </p>
        </div>
      </div>
      <form class="card cmmc-readonly" @submit.prevent="() => {}">
        <div class="card-title">
          <h2>{{ t("settings.globalSettings") }}</h2>
        </div>

        <div class="card-content">
          <!--
            CMMC authority separation: identity + credentials live in
            Keycloak; file authorization (scope, perms, access rules)
            lives here. The first three controls below relate to
            identity lifecycle and are irrelevant under OIDC:

              * "Allow signup" — Keycloak decides whether users can
                self-enroll.
              * "Create user home directory on signup" — there is no
                signup path under OIDC; provisioning is per-login.
              * "Minimum password length" — realm password policy in
                Keycloak is authoritative. The setting here only
                affected local JSON-auth password changes that never
                happen under OIDC.

            Keep the underlying values in the backend struct (so a
            deployment that flips AuthMethod back to json still works)
            but hide the controls from the admin UI.
          -->
          <p v-if="!isOIDC">
            <input type="checkbox" v-model="settings.signup" />
            {{ t("settings.allowSignup") }}
          </p>

          <p v-if="!isOIDC">
            <input type="checkbox" v-model="settings.createUserDir" />
            {{ t("settings.createUserDir") }}
          </p>

          <p v-if="isOIDC" class="cmmc-identity-notice">
            <strong>Identity managed in Keycloak.</strong>
            User signup, password policy, and MFA device lifecycle
            are configured in the identity provider, not here.
            Changes to <code>cmmc-admins</code> group membership in
            Keycloak take effect on the user's next login.
          </p>

          <p>
            <input type="checkbox" v-model="settings.hideLoginButton" />
            {{ t("settings.hideLoginButton") }}
          </p>

          <p>
            <label class="small">{{ t("settings.userHomeBasePath") }}</label>
            <input
              class="input input--block"
              type="text"
              v-model="settings.userHomeBasePath"
            />
          </p>

          <p v-if="!isOIDC">
            <label for="minimumPasswordLength">{{
              t("settings.minimumPasswordLength")
            }}</label>
            <vue-number-input
              controls
              v-model.number="settings.minimumPasswordLength"
              id="minimumPasswordLength"
              :min="1"
            />
          </p>

          <h3>{{ t("settings.rules") }}</h3>
          <p class="small">{{ t("settings.globalRules") }}</p>
          <rules v-model:rules="settings.rules" />

          <!--
            CMMC 3.4.6 / 3.14: shell-exec and the command runner are
            incompatible with a sealed CUI cabinet — they widen the
            boundary past anything the audit path covers. Ship disabled;
            the whole "Execute on shell" + "Command runner" card below
            is also gated behind `enableExec` which is now false by
            default in the CMMC build.

            The branding card is hidden too: instance name, logo path,
            and theme are deployment-vendor concerns, not customer-admin
            ones. Letting an admin rebrand creates drift from the CMMC
            package that was assessed. If a customer truly needs to
            rebrand, that's a vendor/MSP configuration.
          -->
          <h3>{{ t("settings.branding") }}</h3>
          <p class="small cmmc-removed-feature">
            Branding controls (instance name, logo, theme, disabling
            external links, disabling disk usage percentage) are
            managed by the deployment vendor, not per-instance. A
            customer admin changing branding here would drift the
            deployment from the CMMC package that was assessed.
          </p>

          <h3>{{ t("settings.tusUploads") }}</h3>

          <p class="small">{{ t("settings.tusUploadsHelp") }}</p>

          <div class="tusConditionalSettings">
            <p>
              <label for="tus-chunkSize">{{
                t("settings.tusUploadsChunkSize")
              }}</label>
              <input
                class="input input--block"
                type="text"
                v-model="formattedChunkSize"
                id="tus-chunkSize"
              />
            </p>

            <p>
              <label for="tus-retryCount">{{
                t("settings.tusUploadsRetryCount")
              }}</label>
              <vue-number-input
                controls
                v-model.number="settings.tus.retryCount"
                id="tus-retryCount"
                :min="0"
              />
            </p>
          </div>
        </div>

        <div class="card-action">
          <input
            class="button button--flat"
            type="submit"
            :value="t('buttons.update')"
          />
        </div>
      </form>
    </div>

    <div class="column">
      <form class="card cmmc-readonly" @submit.prevent="() => {}">
        <div class="card-title">
          <h2>{{ t("settings.userDefaults") }}</h2>
        </div>

        <div class="card-content">
          <p class="small">{{ t("settings.defaultUserDescription") }}</p>

          <user-form
            :isNew="false"
            :isDefault="true"
            v-model:user="settings.defaults"
          />
        </div>

        <div class="card-action">
          <input
            class="button button--flat"
            type="submit"
            :value="t('buttons.update')"
          />
        </div>
      </form>
    </div>

    <div class="column">
      <form v-if="enableExec" class="card cmmc-readonly" @submit.prevent="() => {}">
        <div class="card-title">
          <h2>{{ t("settings.commandRunner") }}</h2>
        </div>

        <div class="card-content">
          <!-- Command runner card is only rendered when enableExec
               is true, which is false by default in the CMMC build
               (see rationale on the execute-on-shell block above).
               Upstream doc link removed: filebrowser.org is a
               wrong-product reference in this fork. -->
          <i18n-t
            keypath="settings.commandRunnerHelp"
            tag="p"
            class="small"
            scope="global"
          >
            <code>FILE</code>
            <code>SCOPE</code>
            <span>{{ t("settings.documentation") }}</span>
          </i18n-t>

          <div
            v-for="(command, key) in settings.commands"
            :key="key"
            class="collapsible"
          >
            <input :id="key" type="checkbox" />
            <label :for="key">
              <p>{{ capitalize(key) }}</p>
              <i class="material-icons">arrow_drop_down</i>
            </label>
            <div class="collapse">
              <textarea
                class="input input--block input--textarea"
                v-model.trim="commandObject[key]"
              ></textarea>
            </div>
          </div>
        </div>

        <div class="card-action">
          <input
            class="button button--flat"
            type="submit"
            :value="t('buttons.update')"
          />
        </div>
      </form>
    </div>
  </div>
</template>

<script setup lang="ts">
import { settings as api } from "@/api";
import { StatusError } from "@/api/utils";
import Rules from "@/components/settings/Rules.vue";
import Themes from "@/components/settings/Themes.vue";
import UserForm from "@/components/settings/UserForm.vue";
import { useLayoutStore } from "@/stores/layout";
import { enableExec, authMethod } from "@/utils/constants";

const isOIDC = authMethod === "oidc";
import { getTheme, setTheme } from "@/utils/theme";
import Errors from "@/views/Errors.vue";
import { computed, inject, onBeforeUnmount, onMounted, ref } from "vue";
import { useI18n } from "vue-i18n";

const error = ref<StatusError | null>(null);
const originalSettings = ref<ISettings | null>(null);
const settings = ref<ISettings | null>(null);
const debounceTimeout = ref<number | null>(null);

const commandObject = ref<{
  [key: string]: string[] | string;
}>({});
const shellValue = ref<string>("");

const $showError = inject<IToastError>("$showError")!;
const $showSuccess = inject<IToastSuccess>("$showSuccess")!;

const { t } = useI18n();

const layoutStore = useLayoutStore();

const formattedChunkSize = computed({
  get() {
    return settings?.value?.tus?.chunkSize
      ? formatBytes(settings?.value?.tus?.chunkSize)
      : "";
  },
  set(value: string) {
    // Use debouncing to allow the user to type freely without
    // interruption by the formatter
    // Clear the previous timeout if it exists
    if (debounceTimeout.value) {
      clearTimeout(debounceTimeout.value);
    }

    // Set a new timeout to apply the format after a short delay
    debounceTimeout.value = window.setTimeout(() => {
      if (settings.value) settings.value.tus.chunkSize = parseBytes(value);
    }, 1500);
  },
});

// Define funcs
const capitalize = (name: string, where: string | RegExp = "_") => {
  if (where === "caps") where = /(?=[A-Z])/;
  const split = name.split(where);
  name = "";

  for (let i = 0; i < split.length; i++) {
    name += split[i].charAt(0).toUpperCase() + split[i].slice(1) + " ";
  }

  return name.slice(0, -1);
};

const save = async () => {
  if (settings.value === null) return false;
  const newSettings: ISettings = {
    ...settings.value,
    shell:
      settings.value?.shell
        .join(" ")
        .trim()
        .split(" ")
        .filter((s: string) => s !== "") ?? [],
    commands: {},
  };

  const keys = Object.keys(settings.value.commands) as Array<
    keyof SettingsCommand
  >;
  for (const key of keys) {
    // not sure if we can safely assume non-null
    const newValue = commandObject.value[key];
    if (!newValue) continue;

    if (Array.isArray(newValue)) {
      newSettings.commands[key] = newValue;
    } else if (key in commandObject.value) {
      newSettings.commands[key] = newValue
        .split("\n")
        .filter((cmd: string) => cmd !== "");
    }
  }
  newSettings.shell = shellValue.value
    .trim()
    .split(" ")
    .filter((s) => s !== "");

  if (newSettings.branding.theme !== getTheme()) {
    setTheme(newSettings.branding.theme);
  }

  try {
    await api.update(newSettings);
    $showSuccess(t("settings.settingsUpdated"));
  } catch (e: any) {
    $showError(e);
  }

  return true;
};
// Parse the user-friendly input (e.g., "20M" or "1T") to bytes
const parseBytes = (input: string) => {
  const regex = /^(\d+)(\.\d+)?(B|K|KB|M|MB|G|GB|T|TB)?$/i;
  const matches = input.match(regex);
  if (matches) {
    const size = parseFloat(matches[1].concat(matches[2] || ""));
    let unit: keyof SettingsUnit =
      matches[3].toUpperCase() as keyof SettingsUnit;
    if (!unit.endsWith("B")) {
      unit += "B";
    }
    const units: SettingsUnit = {
      KB: 1024,
      MB: 1024 ** 2,
      GB: 1024 ** 3,
      TB: 1024 ** 4,
    };
    return size * (units[unit as keyof SettingsUnit] || 1);
  } else {
    return 1024 ** 2;
  }
};
// Format the chunk size in bytes to user-friendly format
const formatBytes = (bytes: number) => {
  const units = ["B", "KB", "MB", "GB", "TB"];
  let size = bytes;
  let unitIndex = 0;
  while (size >= 1024 && unitIndex < units.length - 1) {
    size /= 1024;
    unitIndex++;
  }
  return `${size}${units[unitIndex]}`;
};

// Define Hooks

onMounted(async () => {
  try {
    layoutStore.loading = true;
    const original: ISettings = await api.get();
    const newSettings: ISettings = { ...original, commands: {} };

    const keys = Object.keys(original.commands) as Array<keyof SettingsCommand>;
    for (const key of keys) {
      newSettings.commands[key] = original.commands[key];
      commandObject.value[key] = original.commands[key]!.join("\n");
    }

    originalSettings.value = original;
    settings.value = newSettings;
    shellValue.value = newSettings.shell.join(" ");
  } catch (err) {
    if (err instanceof Error) {
      error.value = err;
    }
  } finally {
    layoutStore.loading = false;
  }
});

// Clear the debounce timeout when the component is destroyed
onBeforeUnmount(() => {
  if (debounceTimeout.value) {
    clearTimeout(debounceTimeout.value);
  }
});
</script>


<style scoped>
.cmmc-readonly-banner {
  background: #fff4e5;
  border: 1px solid #d89a3e;
  border-left: 3px solid #d89a3e;
  color: #4a2e00;
  margin-bottom: 1rem;
}
.cmmc-readonly-banner code {
  font-family: ui-monospace, monospace;
  background: rgba(0,0,0,0.06);
  padding: 0.1em 0.35em;
  border-radius: 2px;
  font-size: 0.9em;
}
.cmmc-readonly :deep(input),
.cmmc-readonly :deep(select),
.cmmc-readonly :deep(textarea),
.cmmc-readonly :deep(button) {
  pointer-events: none;
  opacity: 0.6;
  cursor: not-allowed !important;
}
.cmmc-readonly :deep(input[type="submit"]) {
  display: none;
}
.cmmc-readonly :deep(.card-action) {
  display: none;
}
</style>
