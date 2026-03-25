# Shared Files — Web File Manager

Custom Node.js web-based file manager with full CRUD capabilities.

## Features

- 📁 Directory browsing (FTP-style interface)
- 📤 File upload via drag-drop or modal button
- 📥 File download (click or download button)
- ✏️ Rename files and folders
- 🗑️ Delete files and folders (recursive directory delete)
- 📂 Create new folders
- 🔐 Session-based authentication (admin/admin123)
- ⏰ 24-hour session expiry with auto-cleanup
- 🛡️ Path traversal protection
- 🚫 Login rate limiting (5 attempts → 5-min lockout)
- ✅ Filename sanitization and validation

## Quick Start

```bash
cd /home/ubuntu/shared-files
node filemanager.js
```

Server runs at `http://localhost:9000`

### Login Credentials
| Username | Password |
|----------|----------|
| admin    | admin123 |

## Configuration

Environment variables:
- `FILE_MANAGER_ROOT` — Root directory for file operations (default: `/home/ubuntu/shared-files`)

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/auth/login` | POST | Authenticate, returns session token |
| `/api/auth/logout` | POST | Invalidate current session |
| `/?path=/` | GET | Browse directory (requires auth) |
| `/download?path=/file.txt` | GET | Download file (requires auth) |
| `/api/upload?path=/dir/` | POST | Upload file via multipart/form-data |
| `/api/delete` | POST | Delete file/folder (JSON: `{"path":"/item"}`) |
| `/api/rename` | POST | Rename item (JSON: `{"path":"/old","newName":"new"}`) |
| `/api/mkdir` | POST | Create folder (JSON: `{"path":"/parent","name":"child"}`) |
| `/api/files/?path=/` | GET | List directory as JSON array |

## Security Features

- **Path traversal protection:** Normalized paths with strict boundary checking
- **Session management:** 24-hour expiry, automatic cleanup on access
- **Rate limiting:** 5 failed login attempts → 5-minute IP lockout (HTTP 429)
- **Filename sanitization:** Null byte removal, character filtering, length limits
- **Directory traversal blocked:** All `../` sequences resolved and validated

## Architecture

Single-file Node.js application using native `http` module:
- No Express.js — minimal dependencies
- Custom multipart parser for file uploads (native HTTP compatible)
- In-memory session storage with Map
- Synchronous filesystem operations (sufficient for single-user use case)

### Dependencies

```json
{
  "multer": "^1.4.5-lts.1"
}
```

Note: Multer is listed but custom multipart parsing is used for compatibility with native HTTP module.

## Development History

- **March 25, 2026:** Initial build and deployment
- **March 25, 2026 (evening):** Critical bug fixes — upload pipeline repair, endpoint correction, path traversal patch
- **March 25, 2026 (evening):** Reliability hardening — session expiry, validation, error handling, rate limiting

## License

MIT