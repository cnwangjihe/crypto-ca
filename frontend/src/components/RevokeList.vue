<template>
  <div id="revoke-list">
    <el-table :data="tableData" style="width: 100%">
      <el-table-column prop="cert_digest" label="Cert Fingerprint" />
      <el-table-column prop="timestamp" sortable label="Time" :formatter="formatter" />
    </el-table>
  </div>
</template>

<script lang="ts" setup>
import type { TableColumnCtx } from 'element-plus'

interface RevokeItem {
  cert_digest: string
  timestamp: number
}

const formatter = (row: RevokeItem, column: TableColumnCtx<RevokeItem>) => {
  console.log(row.timestamp)
  return new Date(row.timestamp).toLocaleString()
}

const tableData: RevokeItem[] = (await (await fetch("api/revoke")).json()).data.revoke

</script>
  