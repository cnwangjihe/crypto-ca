## ca-crypto
一个简易CA，使用ECDSA签名，由fastapi+vue+element-plus编写。  
数据库使用MongoDB。

## build && run
frontend没有使用docker进行构建，需要您在本地先build，再使用docker compose启动整个CA  
```sh
cd frontend
yarn install
yarn build
cd ..
docker compose up --build
```