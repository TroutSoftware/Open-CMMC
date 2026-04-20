<template>
  <span v-if="mark" :class="['cui-badge', severityClass]" :title="title">
    {{ displayLabel }}
  </span>
</template>

<script setup lang="ts">
import { computed } from "vue";

// CuiBadge renders the per-file CMMC marking next to a file name.
// The severity class drives color: advisory (amber) for CUI//BASIC,
// elevated (red) for Specified / ITAR / Privacy / Proprietary.
// Missing or empty `mark` renders nothing at all.

const props = defineProps<{ mark?: string }>();

const severityClass = computed(() => {
  if (!props.mark) return "";
  if (props.mark === "CUI//BASIC") return "cui-basic";
  // Anything more restrictive than BASIC is rendered red.
  return "cui-elevated";
});

const displayLabel = computed(() => {
  if (!props.mark) return "";
  // Trim the "CUI//" prefix for a compact inline pill; the full value
  // is in the tooltip for operators auditing the UI.
  return props.mark.replace(/^CUI\/\//, "");
});

const title = computed(() => props.mark ?? "");
</script>

<style scoped>
.cui-badge {
  display: inline-block;
  padding: 0.12em 0.5em;
  margin-left: 0.5em;
  font-size: 0.68rem;
  font-weight: 700;
  letter-spacing: 0.03em;
  line-height: 1.2;
  border-radius: 2px;
  text-transform: uppercase;
  vertical-align: middle;
  font-family: system-ui, sans-serif;
}
.cui-basic {
  background: #fff4e5;
  color: #8a4d00;
  border: 1px solid #d89a3e;
}
.cui-elevated {
  background: #fde7e7;
  color: #8c1f1f;
  border: 1px solid #c62828;
}
</style>
