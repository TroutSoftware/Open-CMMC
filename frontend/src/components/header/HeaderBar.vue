<template>
  <header>
    <img v-if="showLogo" :src="logoURL" />
    <Action
      v-if="showMenu"
      class="menu-button"
      icon="menu"
      :label="t('buttons.toggleSidebar')"
      @action="layoutStore.showHover('sidebar')"
    />

    <!--
      Product brand shown in the navbar next to the logo/hamburger.
      Visible in both operator and admin views. Uses the configured
      `name` so a deployment vendor can override (e.g., "Acme CMMC
      Cabinet") without a rebuild.
    -->
    <h1 class="brand">{{ brandName }}</h1>

    <slot />

    <div
      id="dropdown"
      :class="{ active: layoutStore.currentPromptName === 'more' }"
    >
      <slot name="actions" />
    </div>

    <Action
      v-if="ifActionsSlot"
      id="more"
      icon="more_vert"
      :label="t('buttons.more')"
      @action="layoutStore.showHover('more')"
    />

    <div
      class="overlay"
      v-show="layoutStore.currentPromptName == 'more'"
      @click="layoutStore.closeHovers"
    />
  </header>
</template>

<script setup lang="ts">
import { useLayoutStore } from "@/stores/layout";

import { logoURL, name as brandName } from "@/utils/constants";

import Action from "@/components/header/Action.vue";
import { computed, useSlots } from "vue";
import { useI18n } from "vue-i18n";

defineProps<{
  showLogo?: boolean;
  showMenu?: boolean;
}>();

const layoutStore = useLayoutStore();
const slots = useSlots();

const { t } = useI18n();

const ifActionsSlot = computed(() => (slots.actions ? true : false));
</script>

<style scoped>
header .brand {
  font-size: 1.05rem;
  font-weight: 600;
  letter-spacing: 0.01em;
  color: var(--textPrimary, #263238);
  margin: 0 0.75em 0 0.25em;
  white-space: nowrap;
  user-select: none;
}
@media (max-width: 600px) {
  header .brand {
    display: none;
  }
}
</style>
