# Rate Limiter & Logger Service

A Node.js backend project for API rate limiting, abuse word detection, and comprehensive request logging. Built with clean code practices, using Express.js, in-memory storage (Map simulating Redis), and file system for logs.

## Features
- **Rate Limiting**: In-memory Map-based (ready for Redis migration)
- **Abuse Detection**: Detects abusive words/patterns in requests
- **Suspicious Activity Detection**: Tracks repeated failures, traffic spikes, abnormal patterns; flags + auto-blocks user/IP
- **Blocked Users System**: Blocked on suspicious/abuse (403 on access); admin unblock only via /admin/blocked/:key
- **Request Logging**: All traffic logged to file system (access.log, error.log)
- **Authentication/Authorization**: JWT + bcrypt, FS-stored users (data/users.json)
- **Security**: Helmet, body parsing limits, protected routes
- **Environment Config**: dotenv support
- **Best Practices**: Modular services, middleware separation, error handling

## Project Structure
```
rate-limitter/
├── src/
│   ├── config/          # Configuration files
│   ├── controllers/     # Route handlers
│   ├── middleware/      # Custom middlewares (rate limit, abuse detect)
│   ├── services/        # Core services (RateLimiter, Logger, AbuseDetector)
│   ├── utils/           # Utilities
│   ├── models/          # Data models (future)
│   ├── routes/          # Route definitions
│   └── server.js        # Entry point
├── logs/                # Generated log files
├── data/                # File-based data storage
├── .env.example
├── .eslintrc.js
└── package.json
```

## Setup

1. Clone/Setup:
   ```bash
   npm install
   ```

2. Configure environment:
   ```bash
   cp .env.example .env
   # Edit .env as needed
   ```

3. Run development:
   ```bash
   npm run dev
   ```

4. Production:
   ```bash
   npm start
   ```

5. Lint:
   ```bash
   npm run lint
   ```

## API Endpoints
### Auth
- `POST /auth/register` - Register user `{ username, password, role? }` (limited roles: user/admin only; invalid role rejected)
- `POST /auth/login` - Login `{ username, password }` returns JWT

### Protected (require Bearer JWT token)
- `GET /health` - Health check (public)
- `POST /api/submit` - Example (any authenticated user; dynamic IP rate limit: 5/10s demo)
- `GET /logs/:type` - Logs (admin only, e.g., /logs/access)
- `POST /admin/rate-limits` - Set dynamic rule (admin only) e.g. `{ "endpoint": "/health", "maxRequests": 10, "windowMs": 60000 }`
- `DELETE /admin/blocked/:key` - Unblock user/IP (admin only, e.g. /admin/blocked/user123)

### Emergency (for blocked localhost cases)
- `POST /emergency-unblock` - Unblock by secret + key e.g. `{ "secret": "abbbbbbbbbbbbbb", "key": "127.0.0.1" }` (bypasses blocks)

Rate limiter dynamically detects endpoint (req.path) and applies rules from FS-persisted config. Blocked users (from abuse/suspicious) denied access (403). Use Authorization: Bearer <token> header for protected routes.

## Testing
- Integration tests for rate limiter (IP-based fixed window, 429 on exceed) in `tests/rateLimiter.test.js`
- Run: `npm test`

## Rate Limiting
- Default: 100 requests per 15 minutes per IP
- Headers: X-RateLimit-Limit, X-RateLimit-Remaining, etc.
- Uses JS Map (simulates Redis)

## Logging
- All requests logged to `logs/access.log`
- Errors to `logs/error.log`
- JSON format for easy parsing

## Future Enhancements
- Integrate real Redis
- Add database (e.g., MongoDB/Postgres) for persistent storage (replace FS users)
- Advanced abuse detection (NLP/ML)
- Role-based enhancements, refresh tokens

## Best Practices Used
- Modular architecture (services, middleware)
- Environment variables
- Error handling
- Security headers
- Clean code, comments, JSDoc
