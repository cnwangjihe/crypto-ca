<template>
  <div id="gen-key">
    <p>
      在此处可以生成ECDSA密钥对，整个过程都在您的浏览器上完成，不会发送数据至CA。
    </p>
    <el-input v-model="passwd" size="large" placeholder="请输入私钥密码，用于保护生成的私钥" type="password" show-password />
    <el-input v-model="filename" size="large" maxlength="64" placeholder="文件名" show-word-limit type="text" />
    <div style="float: right; padding-top: 20px;">
      <el-button type="primary" @click="generate">生成</el-button>
    </div>
  </div>
</template>

<script lang="ts" setup>
import { ref } from 'vue'
import { ElMessage } from 'element-plus'
import { generateKeyPair, exportPEMPrivKey, exportPEMPubKey, download } from '~/composables'

const passwd = ref<string>("")
const filename = ref<string>("")

const generate = async () => {
  if (filename.value === "") {
    ElMessage.error("filename cannot be empty")
    return
  }
  if (passwd.value === "") {
    ElMessage.error("passwd cannot be empty")
    return
  }
  const keyPair = await generateKeyPair()
  download(
    `${filename.value}_priv.pem`,
    await exportPEMPrivKey(keyPair.privateKey, passwd.value)
  )
  download(
    `${filename.value}_pub.pem`,
    await exportPEMPubKey(keyPair.publicKey)
  )
  ElMessage({
    type: "success",
    message: "key pair generated."
  })
}

</script>

<style>
#gen-key {
  max-width: 700px;
  margin: 0 auto;
}

#gen-key p {
  text-indent: 2em;
}
</style>
