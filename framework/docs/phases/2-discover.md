# Phase 2 — Discover (Attack Surface & Trust Boundaries)

> Vẽ bản đồ *attack surface* và đánh dấu *trust boundaries*. Attacker chỉ vào được qua
> entry point; thiệt hại nghiêm trọng xảy ra khi một trust boundary bị vượt.

## Mục tiêu
Tạo một **Attack Surface Map**: mọi entry point, data store, cơ chế auth, và dịch vụ
ngoài — kèm ranh giới tin cậy giữa chúng.

## Attack Surface Map (mẫu)

```
Application
├── Frontend      (Login, Profile, Admin UI)  ← secrets lộ ở client?
├── API           (/login, /users/:id, /orders/:id, /admin, /upload)
├── Database      (users, orders, payments)
├── Auth          (JWT / session)
└── External      (Storage, AI API, payment provider)
```

Đánh dấu luồng và ranh giới:

```
Internet ──╢ TB1 ╟──> Frontend ──> API ──╢ TB2: AuthN ╟──> ──╢ TB3: AuthZ ╟──> DB
```
- **TB1** Internet → app (input không tin cậy).
- **TB2** chưa xác thực → đã xác thực.
- **TB3** user này → dữ liệu của user/kịch bản khác (authorization).

## Cách phát hiện entry points
- Route/handler, controller, GraphQL resolvers, websocket, cron/webhook.
- Mọi nơi đọc input: query string, path param, header, cookie, body, file upload.
- Config/secret: biến môi trường, file config, key nhúng trong bundle frontend.
- CORS, redirect, SSRF-prone fetch, template render, SQL/ORM raw.

## Output
`attack-surface-map.md` (mẫu: [../../templates/attack-surface-map.md](../../templates/attack-surface-map.md))
liệt kê entry points + trust boundaries + assets phía sau mỗi boundary.

## Done when
- [ ] Mọi entry point của tính năng vừa viết được liệt kê.
- [ ] Mỗi trust boundary được đánh dấu và biết "sau ranh giới là asset gì".
