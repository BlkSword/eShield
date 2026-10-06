<script setup lang="ts">
const props = defineProps<{ modelValue: boolean; disabled?: boolean }>()
const emit = defineEmits<{ (e: 'update:modelValue', v: boolean): void }>()
</script>
<template>
  <button
    class="switch"
    :class="{ on: props.modelValue }"
    :disabled="props.disabled"
    :aria-pressed="props.modelValue"
    @click="emit('update:modelValue', !props.modelValue)"
  ></button>
</template>
