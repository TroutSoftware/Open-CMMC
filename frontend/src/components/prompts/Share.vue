<template>
  <div class="card floating" id="share">
    <div class="card-title">
      <h2>{{ $t("buttons.share") }}</h2>
    </div>

    <!--
      CMMC: for non-CUI items we show a terse "direct link" box at
      the top. For CUI items we replace the preamble with a single
      amber notice explaining that the link requires login (which
      is the whole story — no duplicated "Safe for CUI" paragraph).
      External sharing of CUI is deliberately out of scope for
      this release.
    -->
    <div v-if="!isCUI" class="card-content cmmc-auth-share">
      <p class="small">
        <strong>Direct link (requires login).</strong>
        Audit captures every click.
      </p>
      <div class="input-group input">
        <input
          class="input input--block"
          readonly
          :value="authenticatedLink"
          @click="selectAll"
        />
        <button
          class="action"
          :title="$t('buttons.copyToClipboard')"
          :aria-label="$t('buttons.copyToClipboard')"
          @click="copyToClipboard(authenticatedLink)"
        >
          <i class="material-icons">content_paste</i>
        </button>
      </div>
    </div>

    <div v-if="isCUI" class="card-content cmmc-cui-notice">
      <p class="small">
        <strong>CUI item (<code>{{ cuiMark }}</code>).</strong>
        CUI stays on the filebrowser — recipients must log in to
        access it. External sharing of CUI is out of scope for
        this release.
      </p>
      <div class="input-group input">
        <input
          class="input input--block"
          readonly
          :value="authenticatedLink"
          @click="selectAll"
        />
        <button
          class="action"
          :title="$t('buttons.copyToClipboard')"
          :aria-label="$t('buttons.copyToClipboard')"
          @click="copyToClipboard(authenticatedLink)"
        >
          <i class="material-icons">content_paste</i>
        </button>
      </div>
    </div>

    <template v-if="isCUI">
      <!-- CUI: no public share. Just a Close button — the direct
           link above is the complete flow. External sharing is out
           of scope for this release (server rejects anyway). -->
      <div class="card-action">
        <button
          class="button button--flat"
          @click="closeHovers"
          :aria-label="$t('buttons.close')"
          :title="$t('buttons.close')"
        >
          {{ $t("buttons.close") }}
        </button>
      </div>
    </template>

    <template v-else-if="listing">
      <div class="card-content">
        <table>
          <tr>
            <th>#</th>
            <th>{{ $t("settings.shareDuration") }}</th>
            <th></th>
            <th></th>
            <th></th>
          </tr>

          <tr v-for="link in links" :key="link.hash">
            <td>{{ link.hash }}</td>
            <td>
              <template v-if="link.expire !== 0">{{
                humanTime(link.expire)
              }}</template>
              <template v-else>{{ $t("permanent") }}</template>
            </td>
            <td class="small">
              <button
                class="action"
                :aria-label="$t('buttons.copyToClipboard')"
                :title="$t('buttons.copyToClipboard')"
                @click="copyToClipboard(buildLink(link))"
              >
                <i class="material-icons">content_paste</i>
              </button>
            </td>
            <td class="small">
              <button
                class="action"
                :aria-label="$t('buttons.copyDownloadLinkToClipboard')"
                :title="$t('buttons.copyDownloadLinkToClipboard')"
                :disabled="!!link.password_hash"
                @click="copyToClipboard(buildDownloadLink(link))"
              >
                <i class="material-icons">content_paste_go</i>
              </button>
            </td>
            <td class="small">
              <button
                class="action"
                @click="deleteLink($event, link)"
                :aria-label="$t('buttons.delete')"
                :title="$t('buttons.delete')"
              >
                <i class="material-icons">delete</i>
              </button>
            </td>
          </tr>
        </table>
      </div>

      <div class="card-action">
        <button
          class="button button--flat button--grey"
          @click="closeHovers"
          :aria-label="$t('buttons.close')"
          :title="$t('buttons.close')"
          tabindex="2"
        >
          {{ $t("buttons.close") }}
        </button>
        <button
          id="focus-prompt"
          class="button button--flat button--blue"
          @click="() => switchListing()"
          :aria-label="$t('buttons.new')"
          :title="$t('buttons.new')"
          tabindex="1"
        >
          {{ $t("buttons.new") }}
        </button>
      </div>
    </template>

    <template v-else>
      <div class="card-content">
        <p>{{ $t("settings.shareDuration") }}</p>
        <p class="small" style="margin-top: -0.25rem;">
          0 means the link never expires on its own — revoke it by
          deleting the entry in the list.
        </p>
        <div class="input-group input">
          <vue-number-input
            center
            controls
            size="small"
            :max="2147483647"
            :min="0"
            @keyup.enter="submit"
            v-model="time"
            tabindex="1"
          />
          <select
            class="right"
            v-model="unit"
            :aria-label="$t('time.unit')"
            tabindex="2"
          >
            <option value="seconds">{{ $t("time.seconds") }}</option>
            <option value="minutes">{{ $t("time.minutes") }}</option>
            <option value="hours">{{ $t("time.hours") }}</option>
            <option value="days">{{ $t("time.days") }}</option>
          </select>
        </div>
        <p>{{ $t("prompts.optionalPassword") }}</p>
        <input
          class="input input--block"
          type="password"
          v-model.trim="password"
          tabindex="3"
        />
      </div>

      <div class="card-action">
        <button
          class="button button--flat button--grey"
          @click="() => switchListing()"
          :aria-label="$t('buttons.cancel')"
          :title="$t('buttons.cancel')"
          tabindex="5"
        >
          {{ $t("buttons.cancel") }}
        </button>
        <button
          id="focus-prompt"
          class="button button--flat button--blue"
          @click="submit"
          :aria-label="$t('buttons.share')"
          :title="$t('buttons.share')"
          tabindex="4"
        >
          {{ $t("buttons.share") }}
        </button>
      </div>
    </template>
  </div>
</template>

<script>
import { mapActions, mapState } from "pinia";
import { useFileStore } from "@/stores/file";
import * as api from "@/api/index";
import dayjs from "dayjs";
import { useLayoutStore } from "@/stores/layout";
import { copy } from "@/utils/clipboard";

export default {
  name: "share",
  data: function () {
    return {
      time: 0,
      unit: "hours",
      links: [],
      clip: null,
      password: "",
      listing: true,
    };
  },
  inject: ["$showError", "$showSuccess"],
  computed: {
    ...mapState(useFileStore, [
      "req",
      "selected",
      "selectedCount",
      "isListing",
    ]),
    url() {
      if (!this.isListing) {
        return this.$route.path;
      }

      if (this.selectedCount === 0 || this.selectedCount > 1) {
        // This shouldn't happen.
        return;
      }

      return this.req.items[this.selected[0]].url;
    },
    // targetItem is the selected ResourceItem when a row is picked,
    // or the current req resource when viewing a folder. Used to
    // detect a CUI mark so the public-share flow can be hidden and
    // the "direct link" notice can name the mark.
    targetItem() {
      if (!this.isListing) return this.req;
      if (this.selectedCount === 1 && this.req.items) {
        return this.req.items[this.selected[0]];
      }
      return null;
    },
    // Any non-empty `mark` on the target means CUI. The marking
    // catalog currently emits "CUI//BASIC", "CUI//SP-ITAR", etc.
    cuiMark() {
      return (this.targetItem && this.targetItem.mark) || "";
    },
    isCUI() {
      return !!this.cuiMark;
    },
    // Absolute authenticated URL. Keycloak will intercept
    // unauthenticated requests and bounce through OIDC; after
    // login, cabinet rules + folder ACLs decide whether the
    // recipient sees the content. Works for CUI and non-CUI.
    //
    // NOTE: this.url is already the item's routable URL
    // (e.g. "/files/Operations/") — do NOT prepend "/files" or
    // the browser ends up at /files/files/... (reported as a
    // live bug). Strip a possible leading /files prefix when
    // we're rendering from this.$route.path to be safe.
    authenticatedLink() {
      const origin = typeof window !== "undefined" ? window.location.origin : "";
      let path = this.url || "/files/";
      if (!path.startsWith("/files")) {
        path = "/files" + (path.startsWith("/") ? path : "/" + path);
      }
      return origin + path;
    },
  },
  async beforeMount() {
    try {
      const links = await api.share.get(this.url);
      this.links = links;
      this.sort();

      if (this.links.length == 0) {
        this.listing = false;
      }
    } catch (e) {
      this.$showError(e);
    }
  },
  methods: {
    ...mapActions(useLayoutStore, ["closeHovers"]),
    selectAll(event) {
      if (event && event.target && event.target.select) {
        event.target.select();
      }
    },
    copyToClipboard: function (text) {
      copy({ text }).then(
        () => {
          // clipboard successfully set
          this.$showSuccess(this.$t("success.linkCopied"));
        },
        () => {
          // clipboard write failed
          copy({ text }, { permission: true }).then(
            () => {
              // clipboard successfully set
              this.$showSuccess(this.$t("success.linkCopied"));
            },
            (e) => {
              // clipboard write failed
              this.$showError(e);
            }
          );
        }
      );
    },
    submit: async function () {
      try {
        let res = null;

        if (!this.time) {
          res = await api.share.create(this.url, this.password);
        } else {
          res = await api.share.create(
            this.url,
            this.password,
            this.time,
            this.unit
          );
        }

        this.links.push(res);
        this.sort();

        this.time = 0;
        this.unit = "hours";
        this.password = "";

        this.listing = true;
      } catch (e) {
        this.$showError(e);
      }
    },
    deleteLink: async function (event, link) {
      event.preventDefault();
      try {
        await api.share.remove(link.hash);
        this.links = this.links.filter((item) => item.hash !== link.hash);

        if (this.links.length == 0) {
          this.listing = false;
        }
      } catch (e) {
        this.$showError(e);
      }
    },
    humanTime(time) {
      return dayjs(time * 1000).fromNow();
    },
    buildLink(share) {
      return api.share.getShareURL(share);
    },
    buildDownloadLink(share) {
      return api.pub.getDownloadURL(
        {
          hash: share.hash,
          path: "",
        },
        true
      );
    },
    sort() {
      this.links = this.links.sort((a, b) => {
        if (a.expire === 0) return -1;
        if (b.expire === 0) return 1;
        return new Date(a.expire) - new Date(b.expire);
      });
    },
    switchListing() {
      if (this.links.length == 0 && !this.listing) {
        this.closeHovers();
      }

      this.listing = !this.listing;
    },
  },
};
</script>

<style scoped>
.cmmc-auth-share .input-group {
  margin-top: 0.5rem;
}
.cmmc-auth-share .input-group input {
  font-family: ui-monospace, monospace;
  font-size: 0.85em;
}
.cmmc-cui-notice {
  background: #fff4e5;
  border-left: 3px solid #d89a3e;
  color: #4a2e00;
  margin: 0.5rem 0;
}
.cmmc-cui-notice code {
  font-family: ui-monospace, monospace;
  background: rgba(0, 0, 0, 0.06);
  padding: 0.1em 0.35em;
  border-radius: 2px;
  font-size: 0.9em;
}
.cmmc-cui-notice .input-group {
  margin-top: 0.5rem;
}
.cmmc-cui-notice .input-group input {
  font-family: ui-monospace, monospace;
  font-size: 0.85em;
  background: rgba(255, 255, 255, 0.7);
}
</style>
