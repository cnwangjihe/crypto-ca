

<template>
  <div id="user-list">
    <el-input v-model="search" placeholder="Type to search UID" />
    <el-table :data="filterTableData" style="width: 100%">
      <el-table-column prop="uid" label="UID" sortable width="180" />
      <el-table-column prop="pubkey_digest" label="Pubkey MD5" />
      <el-table-column prop="cert_digest" label="Cert Fingerprint" />
      <el-table-column prop="timestamp" sortable label="Time" :formatter="formatter" />
    </el-table>
  </div>
</template>

<script lang="ts" setup>
import { computed, ref } from 'vue'

interface User {
  uid: string
  pubkey: string
  pubkey_digest: string
  cert_digest: string
  timestamp: number
}

const formatter = (row: User) => {
  return new Date(row.timestamp).toLocaleString()
}

const search = ref('')
const filterTableData = computed(() =>
  tableData.filter(
    (data) =>
      !search.value ||
      data.uid.toLowerCase().includes(search.value.toLowerCase())
  )
)

const tableData: User[] = (await (await fetch("api/user")).json()).data.users

</script>
