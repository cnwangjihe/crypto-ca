import { createApp } from "vue";
import { createRouter, createWebHashHistory } from 'vue-router'
import App from "./App.vue";
import Sign from "./components/Sign.vue"
import Welcome from "./components/Welcome.vue"
import Revoke from "./components/Revoke.vue"
import UserList from "./components/UserList.vue"
import RevokeList from "./components/RevokeList.vue"
import GenKey from "./components/GenKey.vue"

// import "~/styles/element/index.scss";

// import ElementPlus from "element-plus";
// import all element css, uncommented next line
// import "element-plus/dist/index.css";
import "element-plus/es/components/message/style/index";

// or use cdn, uncomment cdn link in `index.html`

import "~/styles/index.scss";
import 'uno.css'


const routes = [{
    path: '/',
    redirect: '/welcome',
  }, {
    path: '/welcome', 
    component: Welcome
  }, {
    path: '/sign',
    component: Sign
  }, {
    path: '/revoke',
    component: Revoke
  }, {
    path: '/user_list',
    component: UserList
  }, {
    path: '/revoke_list',
    component: RevokeList
  }, {
    path: '/gen_key',
    component: GenKey
  }
]
   
const router = createRouter({
  history: createWebHashHistory(),
  routes
})

const app = createApp(App);
app.use(router);
app.mount("#app");