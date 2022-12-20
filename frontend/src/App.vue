<template>
  <el-config-provider namespace="ep">
    <el-menu class="el-menu-demo" mode="horizontal" :default-active="route.path">
      <el-menu-item index="/welcome" @click="router.push('/welcome')">证书管理系统 (Certificate Authority)</el-menu-item>
      <el-menu-item h="full" @click="toggleDark()">
        <button class="border-none w-full bg-transparent cursor-pointer" style="height: var(--ep-menu-item-height);">
          <i inline-flex i="dark:ep-moon ep-sunny" />
        </button>
      </el-menu-item>
    </el-menu>
    <div id="main">
      <base-side />
      <div id="page">
        <suspense>
          <router-view></router-view>
        </suspense>
      </div>
    </div>
  </el-config-provider>
</template>

<script lang="ts" setup>
import { toggleDark } from './composables'
import { useRouter, useRoute } from 'vue-router'

const route = useRoute()
const router = useRouter()

</script>

<style>
#app {
  color: var(--ep-text-color-primary);
  top: 0;
  left: 0;
  width: 100vw;
  height: 100vh;
}

#main {
  display: flex;
  height: calc(90vh - var(--ep-menu-item-height));
}

#page {
  width: 100%;
  height: 100%;
  margin-top: 40px;
  margin-left: 40px;
  margin-right: 40px;
}

</style>
