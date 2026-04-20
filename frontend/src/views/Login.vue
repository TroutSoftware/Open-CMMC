<template>
  <div id="login" :class="{ recaptcha: recaptcha }">
    <form @submit="submit">
      <img :src="logoURL" alt="CMMC Filebrowser" />
      <h1>{{ name }}</h1>

      <!--
        CMMC 3.1.9 / NIST SP 800-171 — system use notification. Must
        appear before authentication and describe the terms of use.
        Required content: government system / authorized users only /
        activity monitored / consent to monitoring on continued use.
        The text here is defensible for a private contractor handling
        DoD CUI; a DoD-direct tenancy should substitute the official
        Standard Mandatory DoD Notice and Consent banner.
      -->
      <div class="cmmc-banner" role="note" aria-label="System use notification">
        <strong>Notice:</strong> This system may process, store, or transmit
        Controlled Unclassified Information (CUI). It is restricted to
        authorized users engaged in official work. All activity is logged
        and monitored for security, compliance (NIST SP 800-171 / CMMC L2),
        and lawful purposes. By continuing, you consent to monitoring and
        accept that unauthorized access or misuse may result in civil and
        criminal penalties, including under 18 U.S.C. § 1030.
      </div>

      <p v-if="authMethod === 'oidc'" class="cmmc-sso-note">
        You will be redirected to your company's identity provider to
        sign in. MFA is handled there.
      </p>


      <p v-if="reason != null" class="logout-message">
        {{ t(`login.logout_reasons.${reason}`) }}
      </p>
      <div v-if="error !== ''" class="wrong">{{ error }}</div>

      <input
        autofocus
        class="input input--block"
        type="text"
        autocapitalize="off"
        v-model="username"
        :placeholder="t('login.username')"
      />
      <input
        class="input input--block"
        type="password"
        v-model="password"
        :placeholder="t('login.password')"
      />
      <input
        class="input input--block"
        v-if="createMode"
        type="password"
        v-model="passwordConfirm"
        :placeholder="t('login.passwordConfirm')"
      />

      <div v-if="recaptcha" id="recaptcha"></div>
      <input
        class="button button--block"
        type="submit"
        :value="createMode ? t('login.signup') : t('login.submit')"
      />

      <p @click="toggleMode" v-if="signup">
        {{ createMode ? t("login.loginInstead") : t("login.createAnAccount") }}
      </p>
    </form>
  </div>
</template>

<script setup lang="ts">
import { StatusError } from "@/api/utils";
import * as auth from "@/utils/auth";
import { decideOIDCAction } from "@/utils/oidc";
import {
  name,
  logoURL,
  recaptcha,
  recaptchaKey,
  signup,
  authMethod,
  baseURL,
} from "@/utils/constants";
import { inject, onMounted, ref } from "vue";
import { useI18n } from "vue-i18n";
import { useRoute, useRouter } from "vue-router";

// Define refs
const createMode = ref<boolean>(false);
const error = ref<string>("");
const username = ref<string>("");
const password = ref<string>("");
const passwordConfirm = ref<string>("");

const route = useRoute();
const router = useRouter();
const { t } = useI18n({});
// Define functions
const toggleMode = () => (createMode.value = !createMode.value);

const $showError = inject<IToastError>("$showError")!;

const reason = route.query["logout-reason"] ?? null;

const submit = async (event: Event) => {
  event.preventDefault();
  event.stopPropagation();

  const redirect = (route.query.redirect || "/files/") as string;

  let captcha = "";
  if (recaptcha) {
    captcha = window.grecaptcha.getResponse();

    if (captcha === "") {
      error.value = t("login.wrongCredentials");
      return;
    }
  }

  if (createMode.value) {
    if (password.value !== passwordConfirm.value) {
      error.value = t("login.passwordsDontMatch");
      return;
    }
  }

  try {
    if (createMode.value) {
      await auth.signup(username.value, password.value);
    }

    await auth.login(username.value, password.value, captcha);
    router.push({ path: redirect });
  } catch (e: any) {
    // console.error(e);
    if (e instanceof StatusError) {
      if (e.status === 409) {
        error.value = t("login.usernameTaken");
      } else if (e.status === 403) {
        error.value = t("login.wrongCredentials");
      } else if (e.status === 400) {
        const match = e.message.match(/minimum length is (\d+)/);
        if (match) {
          error.value = t("login.passwordTooShort", { min: match[1] });
        } else {
          error.value = e.message;
        }
      } else {
        $showError(e);
      }
    }
  }
};

// Run hooks
onMounted(async () => {
  // CMMC OIDC flow. Two cases on mount:
  //  1. Backend already completed the IdP round-trip and set the
  //     HttpOnly session cookie on /api/auth/oidc/callback → bridge
  //     the session into the SPA by POSTing /api/renew (cookie auth),
  //     take the returned JWT, and push to /files/.
  //  2. No cookie yet (or expired) → kick off the IdP login by
  //     redirecting to /api/auth/oidc/login which 302s to the IdP.
  if (authMethod === "oidc") {
    const action = await decideOIDCAction(authMethod, baseURL);
    if (action.type === "bridge-session") {
      try {
        auth.parseToken(action.token);
        const redirect = (route.query.redirect as string) || "/files/";
        router.push({ path: redirect });
        return;
      } catch (e) {
        console.warn("OIDC session bridge: malformed JWT from /api/renew, restarting login", e);
      }
    }
    if (action.type === "bridge-session" || action.type === "start-login") {
      const redirect = (route.query.redirect as string) || "/files/";
      const params = new URLSearchParams({ redirect });
      window.location.replace(
        `${baseURL}/api/auth/oidc/login?${params.toString()}`
      );
      return;
    }
  }

  if (!recaptcha) return;

  window.grecaptcha.ready(function () {
    window.grecaptcha.render("recaptcha", {
      sitekey: recaptchaKey,
    });
  });
});
</script>
