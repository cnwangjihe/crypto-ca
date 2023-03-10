<template>
  <div id="sign">
    <p>
      在此处可以向CA请求颁发证书，CA会将您的公钥和提供的UID绑定，生成由CA私钥签名的证书，同时会在数据库中记录您的公钥、UID以及生成的证书的指纹。
    </p>
    <p>
      您的私钥会在本地浏览器上用于签署颁发请求，签署完后只有签名会被发送给CA，您的私钥会留在本地，不会泄露给任何人。
    </p>
    <el-row :gutter="20">
      <el-col :span="12">
        <el-upload class="key-upload" drag :auto-upload="false" :on-change="readPubkey" :limit="1">
          <el-icon class="el-icon--upload"><upload-filled /></el-icon>
          <div class="el-upload__text">
            请在此处上传您的公钥
          </div>
        </el-upload>
      </el-col>
      <el-col :span="12">
        <el-upload class="key-upload" drag :auto-upload="false" :on-change="readPrivkey" :limit="1">
          <el-icon class="el-icon--upload"><upload-filled /></el-icon>
          <div class="el-upload__text">
            请在此处上传您的私钥
          </div>
        </el-upload>
      </el-col>
    </el-row>
    <el-input v-model="uid" size="large" maxlength="64" placeholder="请输入证书UID" show-word-limit type="text" />
    <el-input v-model="passwd" size="large" maxlength="64" placeholder="请输入私钥密码" show-word-limit type="password" show-password />
    <div style="float: right; padding-top: 20px;">
      <el-button type="primary" @click="submit">签名</el-button>
    </div>
  </div>
</template>

<script lang="ts" setup>
import type { UploadFile } from 'element-plus'

import { ref } from 'vue'
import { ElMessage } from 'element-plus'
import { generateSignature, importPEMPrivKey, download } from '~/composables'
import { UploadFilled } from '@element-plus/icons-vue'

const uid = ref<string>("")
const passwd = ref<string>("")
let pubkey = ""
let privkey = ""

const readPubkey = async (uploadFile: UploadFile) => {
  let reader = new FileReader()
  if (uploadFile.raw?.size === undefined || uploadFile.raw?.size > 0x1000) {
    ElMessage.error("pubkey too large.")
    return
  }
  if (uploadFile.raw !== undefined) {
    reader.readAsText(uploadFile.raw)
    reader.onload = async (e) => {
      if (typeof e.target?.result === "string") {
        if (!e.target.result.startsWith("-----BEGIN")) {
          ElMessage.error("pubkey must be ascii pem file.")
          return
        }
      } else {
        ElMessage.error("pubkey must be ascii pem file.")
        return
      }
      pubkey = e.target.result
    }
  }
}

const readPrivkey = async (uploadFile: UploadFile) => {
  let reader = new FileReader()
  if (uploadFile.raw?.size === undefined || uploadFile.raw?.size > 0x1000) {
    ElMessage.error("pubkey too large.")
    return
  }
  if (uploadFile.raw !== undefined) {
    reader.readAsText(uploadFile.raw)
    reader.onload = async (e) => {
      if (typeof e.target?.result === "string") {
        if (!e.target.result.startsWith("-----BEGIN")) {
          ElMessage.error("privkey must be ascii pem file.")
          return
        }
      } else {
        ElMessage.error("privkey must be ascii pem file.")
        return
      }
      privkey = e.target.result
    }
  }
}

const submit = async () => {
  if (pubkey === "" || privkey === "" || uid.value === "") {
    ElMessage.error("please complete the form first.")
    return
  }
  if (passwd.value === "") {
    ElMessage.error("passwd cannot be empty")
    return
  }
  const timestamp = Date.now();
  let sig;
  try {
    sig = await generateSignature(
      await importPEMPrivKey(privkey, passwd.value),
      // f"{sig.timestamp}||{user['uid']}||{user['pubkey']}||{msg}"
      `${timestamp.toString()}||${uid.value}||${pubkey}||POST:/user`
    )
  } catch (e) {
    ElMessage.error("privkey load failed.")
    return
  }
  const response = await fetch("api/user?" + new URLSearchParams({ uid: uid.value }), {
    method: "POST",
    mode: "same-origin",
    cache: "no-cache",
    headers: {
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({
      sig: {
        sig: sig,
        timestamp: timestamp,
        ieee_p1363: true
      },
      pubkey: pubkey
    })
  })
  if (response.status !== 200) {
    ElMessage.error("http error: " + response.body)
    return
  }
  const data = await response.json()
  if (data.data.result !== 0) {
    ElMessage.error("error: " + data.data.msg)
    return
  }
  download(uid.value + "-" + timestamp.toString() + ".crt", data.data.cert)
  ElMessage({
    type: "success",
    message: "cert signed."
  })
}

</script>

<style scoped="true">
#sign {
  max-width: 700px;
  margin: 0 auto;
}

#sign p {
  text-indent: 2em;
}
</style>