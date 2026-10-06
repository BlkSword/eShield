<script setup lang="ts">
const props = defineProps<{ text: string; kind?: string; dot?: boolean }>()
</script>
<template>
  <span class="tag" :class="props.kind || ''"><span v-if="props.dot" class="dot"></span>{{ props.text }}</span>
</template>
