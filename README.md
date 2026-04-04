# Z.AI Coding Plan OpenAI Proxy

一个独立的 Rust 代理服务，把 Z.AI Coding Plan 端点包装成 OpenAI 兼容接口，方便给 OneAPI 一类面板接入。

这个代理只放行基于 `openclaw` 中 Z.AI Coding Plan 相关实现整理出的套餐模型别名：

- `zai-coding-plan/glm-5`
- `zai-coding-plan/glm-5-turbo`
- `zai-coding-plan/glm-4.7`
- `zai-coding-plan/glm-4.7-flash`
- `zai-coding-plan/glm-4.7-flashx`

它们会被精确映射到 Z.AI Coding Plan 上游裸模型名：

- `glm-5`
- `glm-5-turbo`
- `glm-4.7`
- `glm-4.7-flash`
- `glm-4.7-flashx`

未在白名单里的模型会直接返回 `400`，避免误打到错误模型名。

## 环境变量

复制 `.env.example` 后按需设置：

```bash
cp .env.example .env
```

- `ZAI_API_KEY`: 你的 Z.AI Coding Plan key
- `ZAI_CODING_PLAN_ENDPOINT`: `global` 或 `cn`
- `PROXY_API_KEY`: 可选。本地代理自己的 Bearer key，给 OneAPI 填这个
- `HOST`: 监听地址，默认 `0.0.0.0`
- `PORT`: 监听端口，默认 `8787`
- `ALLOW_ANONYMOUS`: 是否允许不带任何认证直接访问，默认 `false`
- `FREE_LOGIN_TOTAL_TOKENS`: 登录用户赠送的累计免费 token，默认 `200000`
- `FREE_USAGE_STORE_PATH`: 登录用户免费额度记账文件，默认 `./data/free-usage.jsonl`
- `PAID_USAGE_STORE_PATH`: 按量购买额度的记账文件，默认 `./data/paid-usage.jsonl`
- `PAID_BALANCE_STORE_PATH`: 按量购买余额文件，默认 `./data/paid-balances.json`
- `PAID_GRANT_STORE_PATH`: 按量充值流水文件，默认 `./data/paid-grants.jsonl`
- `INTERNAL_API_KEY`: 平台服务调用内部充值 / 查询接口时使用的 key
  对应 `webclaw-platform` 里的 `ZAI_CODING_PLAN_PROXY_INTERNAL_KEY`

对应的上游 Coding Plan 端点：

- `global` -> `https://api.z.ai/api/coding/paas/v4`
- `cn` -> `https://open.bigmodel.cn/api/coding/paas/v4`

## 本地运行

```bash
cd /Users/jiayiqiu/智能体/webcode/zai-coding-plan-openai-proxy
export ZAI_API_KEY="your-plan-key"
export ZAI_CODING_PLAN_ENDPOINT="global"
export PROXY_API_KEY="local-proxy-key"
export ALLOW_ANONYMOUS="false"
export FREE_LOGIN_TOTAL_TOKENS="200000"
export PAID_USAGE_STORE_PATH="./data/paid-usage.jsonl"
export PAID_BALANCE_STORE_PATH="./data/paid-balances.json"
cargo run --release
```

## Docker 运行

```bash
docker build -t zai-coding-plan-openai-proxy .
docker run --rm -p 8787:8787 \
  -e ZAI_API_KEY="your-plan-key" \
  -e ZAI_CODING_PLAN_ENDPOINT="global" \
  -e PROXY_API_KEY="local-proxy-key" \
  -e ALLOW_ANONYMOUS="false" \
  -e FREE_LOGIN_TOTAL_TOKENS="200000" \
  -e PAID_USAGE_STORE_PATH="./data/paid-usage.jsonl" \
  -e PAID_BALANCE_STORE_PATH="./data/paid-balances.json" \
  zai-coding-plan-openai-proxy
```

## Docker Compose

先准备 `.env`：

```bash
cp .env.example .env
```

然后至少填这几个变量：

```bash
ZAI_API_KEY=your-plan-key
ZAI_CODING_PLAN_ENDPOINT=global
PROXY_API_KEY=local-proxy-key
PORT=8787
ALLOW_ANONYMOUS=false
FREE_LOGIN_TOTAL_TOKENS=200000
PAID_USAGE_STORE_PATH=./data/paid-usage.jsonl
PAID_BALANCE_STORE_PATH=./data/paid-balances.json
```

启动：

```bash
docker compose up -d --build
```

停止：

```bash
docker compose down
```

## 生产部署到 dub.qhkly.com

只需要这一份 `docker-compose.yml`，生产环境通过 `prod` profile 额外拉起 `caddy`。

最小步骤：

```bash
cp .env.example .env
mkdir -p data caddy_data caddy_config
```

然后至少把这些值改掉：

```bash
DOMAIN=dub.qhkly.com
ACME_EMAIL=you@example.com
ZAI_API_KEY=your-plan-key
PROXY_API_KEY=replace-with-a-long-random-token
```

启动：

```bash
docker compose --profile prod up -d
```

这套配置会：

- 用 `caddy` 自动申请 `dub.qhkly.com` 的 HTTPS 证书
- 把外部 `80/443` 反代到内部代理服务
- 把免费额度记账持久化到 `./data/free-usage.jsonl`
- 保留 `PROXY_API_KEY` 作为 OneAPI 可用的不限量内部 token

## 多平台构建

```bash
docker buildx build \
  --platform linux/amd64,linux/arm64 \
  -t yourname/zai-coding-plan-openai-proxy:latest \
  --push .
```

## OneAPI 配置建议

- Base URL: `http://你的代理地址:8787/v1`
- API Key: `PROXY_API_KEY`
- 模型名填白名单别名，比如 `zai-coding-plan/glm-4.7`

## 已实现接口

- `GET /health`
- `GET /v1/models`
- `GET /v1/models/{id}`
- `GET /v1/usage`
- `POST /v1/chat/completions`
- `GET /internal/user-usage?user_id=123`
- `POST /internal/grant-tokens`

## 说明

- 上游实际转发到 Z.AI Coding Plan 的 `POST /chat/completions`
- 当前实现会在服务端验签 launcher 登录 token，并把免费额度记账保存在本地 JSONL 文件中
- 上游 HTTPS 请求由运行时 `curl` 负责，因此镜像内会安装 `curl`
- 现在支持 `X-WebClaw-License-Token` 请求头。launcher 登录后可把平台登录 token 转发过来，代理会在服务端验签并给免费额度
- 免费额度按 `usage.total_tokens` 累计
- 现在支持 `X-WebClaw-Usage-Mode` 请求头
  - `free_trial`: 扣赠送免费额度
  - `paid_balance`: 扣按量购买余额
- `PAID_BALANCE_STORE_PATH` 是一个简单的 JSON 文件，格式示例：`{"123":500000,"456":1200000}`，键是 `userId`，值是该用户买入的总 token 数
- `PROXY_API_KEY` 仍然是“内部 / 面板用不限量 token”入口，适合给 OneAPI 这类中间层直接配置
- `GET /v1/usage` 会返回免费额度、按量余额以及当前请求模式下的剩余状态
- `GET /internal/user-usage` 和 `POST /internal/grant-tokens` 需要 `Authorization: Bearer ${INTERNAL_API_KEY}`
- `POST /internal/grant-tokens` 按 `order_no` 幂等，同一笔支付重复回调不会重复加额度
