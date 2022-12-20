<template>
  <el-menu
    class="el-menu-vertical-demo"
    :router=true
    :default-active="this.$route.path"
  >
    <el-menu-item index="/sign">
      <el-icon><icon-circle-plus /></el-icon>
      <span>签发证书</span>
    </el-menu-item>
    <el-menu-item index="/revoke">
      <el-icon><icon-delete /></el-icon>
      <span>吊销证书</span>
    </el-menu-item>
    <el-menu-item index="/user_list">
      <el-icon><icon-message-box /></el-icon>
      <span>签发列表</span>
    </el-menu-item>
    <el-menu-item index="/revoke_list">
      <el-icon><icon-moon-night /></el-icon>
      <span>吊销列表</span>
    </el-menu-item>
  </el-menu>
</template>

<script lang="ts" setup>
import {
  CirclePlus as IconCirclePlus,
  Delete as IconDelete,
  MessageBox as IconMessageBox,
  MoonNight as IconMoonNight
} from '@element-plus/icons-vue'

</script>

<style scoped="true">
.el-menu {
  height: 100vh;
}
</style>
