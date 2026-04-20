<template>
  <div class="card floating help">
    <div class="card-title">
      <h2>About this cabinet</h2>
    </div>

    <div class="card-content cmmc-help">
      <p class="brand">CMMC Filebrowser <code>{{ version }}</code></p>
      <p class="small">
        A file storage cabinet opinionated for DIB (Defense Industrial
        Base) contractors working toward CMMC Level 2 and NIST SP
        800-171 compliance. Stores and marks CUI, audits every access,
        and gates CUI downloads behind fresh MFA.
      </p>

      <h3>Quick answers</h3>

      <p class="q"><strong>How do I mark a file as CUI?</strong></p>
      <p>
        Admins only. Select a file, open its actions menu, and choose
        "Mark as CUI…" to pick a category from the DoD CUI Registry
        (BASIC, SP-PRVCY, SP-PROPIN, SP-ITAR, SPECIFIED). The badge
        appears next to the filename for every user.
      </p>

      <p class="q"><strong>Why did the system ask for MFA again?</strong></p>
      <p>
        Downloads of CUI require a fresh MFA assertion (CMMC 3.5.3).
        Your regular login cookie is not enough — a recent authenticator
        code is required before CUI bytes leave the system. The same
        applies to previews and archives that contain CUI.
      </p>

      <p class="q"><strong>Who sees my audit trail?</strong></p>
      <p>
        Every action is recorded with a tamper-evident HMAC chain and
        streamed to the SIEM (CMMC 3.3.1/3.3.8). Your ISSO and the
        compliance team can audit your activity; your ordinary
        colleagues cannot. Logins, downloads, shares, and marking
        changes are all captured with correlation IDs.
      </p>

      <p class="q"><strong>Why can I not share a CUI file publicly?</strong></p>
      <p>
        Public shares are blocked for anything marked CUI (CMMC 3.1.22).
        Use a named, authenticated transfer instead — the recipient
        still has to authenticate through the IdP and satisfy MFA.
      </p>

      <p class="q"><strong>Where do I manage users and passwords?</strong></p>
      <p>
        Identity lives in Keycloak — your company's identity provider.
        This cabinet reads who you are and which groups you belong to
        from your ID token on every login. To add or remove users, to
        reset a password, or to re-enroll a token, use the Keycloak
        admin console.
      </p>

      <h3>Keyboard shortcuts</h3>
      <ul class="shortcuts">
        <li><strong>F1</strong> — {{ $t("help.f1") }}</li>
        <li><strong>F2</strong> — {{ $t("help.f2") }}</li>
        <li><strong>DEL</strong> — {{ $t("help.del") }}</li>
        <li><strong>ESC</strong> — {{ $t("help.esc") }}</li>
        <li><strong>CTRL + S</strong> — {{ $t("help.ctrl.s") }}</li>
        <li><strong>CTRL + SHIFT + F</strong> — {{ $t("help.ctrl.f") }}</li>
      </ul>
    </div>

    <div class="card-action">
      <button
        id="focus-prompt"
        type="submit"
        @click="closeHovers"
        class="button button--flat"
        :aria-label="$t('buttons.ok')"
        :title="$t('buttons.ok')"
        tabindex="1"
      >
        {{ $t("buttons.ok") }}
      </button>
    </div>
  </div>
</template>

<script>
import { mapActions } from "pinia";
import { useLayoutStore } from "@/stores/layout";
import { version } from "@/utils/constants";

export default {
  name: "help",
  data() {
    return { version };
  },
  methods: {
    ...mapActions(useLayoutStore, ["closeHovers"]),
  },
};
</script>

<style scoped>
.cmmc-help {
  max-width: 36em;
  font-size: 0.9rem;
  line-height: 1.45;
}
.cmmc-help .brand {
  font-size: 1.1rem;
  font-weight: 600;
  margin: 0 0 0.3em;
}
.cmmc-help .brand code {
  font-size: 0.8rem;
  font-weight: normal;
  font-family: ui-monospace, monospace;
  color: #666;
  background: #f3f3f3;
  padding: 0 0.3em;
  border-radius: 2px;
}
.cmmc-help h3 {
  margin: 1.2em 0 0.5em;
  font-size: 0.95rem;
  color: #444;
}
.cmmc-help .q {
  margin: 0.8em 0 0.2em;
}
.cmmc-help ul.shortcuts {
  list-style: none;
  padding-left: 0;
  font-size: 0.85rem;
}
.cmmc-help ul.shortcuts li {
  margin: 0.25em 0;
}
</style>
