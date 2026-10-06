<script setup lang="ts">
import { toasts } from '../stores/app'
</script>
<template>
  <div class="toast-wrap">
    <div v-for="t in toasts" :key="t.id" class="toast" :class="t.kind">
      <div class="t-title">{{ t.title }}</div>
      <div v-if="t.desc" class="t-desc">{{ t.desc }}</div>
    </div>
  </div>
</template>
