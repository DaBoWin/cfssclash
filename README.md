# CF SS + YAML Worker

基于老王cfss改造，项目地址：https://github.com/eooce/Cloudflare-proxy
感谢老王。

`worker.js` 是一个 Cloudflare Worker，提供 Shadowsocks 以及基于 YAML 的订阅输出：

- **/sub/<UUID>**：输出经过 Base64 的 SS 订阅，包含默认 CF 优选节点、自定义原生节点以及自定义优选节点。
- **/yaml/<UUID>**：输出带有完整节点列表的 YAML 配置，自动为每个节点生成唯一名称，避免客户端因重复命名报错。
- **/你的UUID**：提供管理界面，可在浏览器里编辑优选入口与自建节点，并复制订阅链接。

  <img width="834" height="850" alt="image" src="https://github.com/user-attachments/assets/8ebea362-d6f3-4f39-951a-d9873a313444" />


## 部署步骤

1. 在 Cloudflare Workers 中创建一个 KV 命名空间，
2. 将 `worker.js` 上传为 Worker项目发布。并在项目的 `绑定`菜单 添加绑定KV，命名为 `CONFIG_KV`。

## 使用说明

- 访问 `https://<你的域名>/<UUID>` 进入管理页面，更新优选入口或自定义节点后点击“保存并生成链接”。
- 客户端订阅 `https://<你的域名>/sub/<UUID>` 或 `https://<你的域名>/yaml/<UUID>` 即可获取最新配置。

> 备注：脚本默认禁止测速站点直连、在 YAML 中会标注未能自动转换的节点，方便手工处理。
