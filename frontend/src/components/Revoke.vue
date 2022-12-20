
<script lang="ts" setup>
import { UploadFilled } from '@element-plus/icons-vue'
</script>
<template>
  <div id="revoke">
    <p>
      在此处可以向CA请求吊销证书，CA会将您证书的指纹加入吊销列表，需要使用您的私钥签名确认。
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
    <el-input v-model="uid" maxlength="64" placeholder="请输入证书UID" show-word-limit type="text" />
    <div style="float: right; padding-top: 20px;">
      <el-button type="danger" @click="Submit">吊销</el-button>
    </div>
  </div>
</template>

<script lang="ts">
import { defineComponent } from "vue";
import type { UploadFile } from 'element-plus'
import { ElMessage } from 'element-plus'
import { generateSigature } from '~/composables';

export default defineComponent({
  name: "Revoke",
  components: {},
  data() {
    return {
      pubkey: "" as string,
      privkey: "" as string,
      uid: "" as string
    }
  },
  methods: {
    async readPubkey(uploadFile: UploadFile) {
      console.log("pubkey")
      console.dir(uploadFile)
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
          this.pubkey = e.target.result
        }
      }
    },
    async readPrivkey(uploadFile: UploadFile) {
      console.log("privkey")
      console.dir(uploadFile)
      let reader = new FileReader()
      if (uploadFile.raw?.size === undefined || uploadFile.raw?.size > 0x1000) {
        ElMessage.error("privkey too large.")
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
          this.privkey = e.target.result
        }
      }
    },
    async Submit() {
      console.dir(this.pubkey)
      console.dir(this.privkey)
      console.dir(this.uid)
      if (this.pubkey === "" || this.privkey === "" || this.uid === "") {
        ElMessage.error("please complete the form first.")
        return
      }
      const timestamp = Date.now();
      // f"{sig.timestamp}||{user['uid']}||{user['pubkey']}||{msg}"
      const sig = await generateSigature(
        this.privkey,
        timestamp.toString() + "||" + this.uid + "||" + this.pubkey + "||DELETE:/user"
      )
      console.log(sig)
      const response = await fetch("api/user?" + new URLSearchParams({ uid: this.uid }), {
        method: "DELETE",
        mode: "same-origin",
        cache: "no-cache",
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          sig: {
            sig: sig,
            timestamp: timestamp
          }
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
      ElMessage({
        type: "success",
        message: "cert revoked!"
      })
    }
  }
})


</script>

<style scoped="true">
#revoke {
  max-width: 700px;
  margin: 0 auto;
}

#revoke p {
  text-indent: 2em;
}
</style>