<script setup lang="ts">
import { getCurrentWindow } from '@tauri-apps/api/window'
import pkg from '~/../package.json'

onBeforeMount(async () => {
  await getCurrentWindow().setTitle(`LowTier GUI: v${pkg.version}`)
})
</script>

<template>
  <Toast position="bottom-right" />
  <RouterView />
</template>
