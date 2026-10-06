<script setup lang="ts">
const props = defineProps<{ title?: string; sub?: string; flush?: boolean; bodyStyle?: string }>()
</script>
<template>
  <section class="panel">
    <header v-if="props.title || $slots.actions" class="panel-head">
      <div class="col" style="gap: 1px; min-width: 0">
        <div class="panel-title">{{ props.title }}</div>
        <div v-if="props.sub" class="panel-sub">{{ props.sub }}</div>
      </div>
      <div class="panel-actions"><slot name="actions" /></div>
    </header>
    <div class="panel-body" :class="{ flush: props.flush }" :style="props.bodyStyle">
      <slot />
    </div>
  </section>
</template>
