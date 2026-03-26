#!/usr/bin/env node
/**
 * Simple Web File Manager
 * Features: Directory browsing, upload, download, delete, rename
 */

const http = require('http');
const fs = require('fs');
const path = require('path');
const url = require('url');
const crypto = require('crypto');
const { IncomingMessage } = require('stream');
const Database = require('better-sqlite3');
const Busboy = require('busboy');

// WebDAV Server Setup (v2.x API)
const webdavModule = require('webdav-server');
let WebDAVV2, HTTPDigestAuthentication, SimpleUserManager, SimplePathPrivilegeManager;

try {
  // v2.x uses the .v2 namespace with a completely different architecture
  const v2 = webdavModule.v2;
  if (v2) {
    WebDAVV2 = v2.WebDAVServer;
    HTTPDigestAuthentication = v2.HTTPDigestAuthentication;
    SimpleUserManager = v2.SimpleUserManager;
    SimplePathPrivilegeManager = v2.SimplePathPrivilegeManager;
  }
} catch (e) {
  console.warn('Failed to load WebDAV v2.x API:', e.message);
}

// Configuration
const PORT = 9000;
const ROOT_DIR = process.env.FILE_MANAGER_ROOT || '/home/ubuntu/shared-files';
const USERNAME = 'admin';
const PASSWORD = 'admin123';

// WebDAV configuration
const WEBDAV_PORT = parseInt(process.env.WEBDAV_PORT) || 9001;
const WEBDAV_ENABLED = process.env.WEBDAV_DISABLED !== 'true';

// Session configuration
const SESSION_LIFETIME_MS = 24 * 60 * 60 * 1000; // 24 hours session expiry

// SQLite database for persistent sessions (use absolute path based on script location)
const dbPath = process.env.SESSIONS_DB || path.join(__dirname, 'sessions.db');
const db = new Database(dbPath);

// Initialize sessions table
db.exec(`
  CREATE TABLE IF NOT EXISTS sessions (
    token TEXT PRIMARY KEY,
    user TEXT NOT NULL,
    created INTEGER NOT NULL,
    last_access INTEGER NOT NULL
  );
  CREATE INDEX IF NOT EXISTS idx_sessions_created ON sessions(created);
`);

// Session management functions (database-backed)
function createSession(user) {
  const token = crypto.randomBytes(32).toString('hex');
  const now = Date.now();
  
  try {
    db.prepare('INSERT INTO sessions (token, user, created, last_access) VALUES (?, ?, ?, ?)')
      .run(token, user, now, now);
    return token;
  } catch (e) {
    console.error('Failed to create session:', e);
    return null;
  }
}

function getSession(token) {
  if (!token) return null;
  
  const session = db.prepare('SELECT * FROM sessions WHERE token = ?').get(token);
  if (!session) return null;
  
  // Check expiry
  if (Date.now() - session.created > SESSION_LIFETIME_MS) {
    db.prepare('DELETE FROM sessions WHERE token = ?').run(token);
    return null;
  }
  
  // Update last_access
  db.prepare('UPDATE sessions SET last_access = ? WHERE token = ?').run(Date.now(), token);
  
  return { user: session.user, created: session.created };
}

function deleteSession(token) {
  db.prepare('DELETE FROM sessions WHERE token = ?').run(token);
}

// Periodic cleanup of expired sessions (every hour)
setInterval(() => {
  const expired = Date.now() - SESSION_LIFETIME_MS;
  const result = db.prepare('DELETE FROM sessions WHERE created < ?').run(expired);
  if (result.changes > 0) {
    console.log('Cleaned up ' + result.changes + ' expired session(s)');
  }
}, 60 * 60 * 1000);

// Rate limiting for login attempts
const loginAttempts = new Map();
const MAX_LOGIN_ATTEMPTS = 5;
const LOGIN_LOCKOUT_MS = 5 * 60 * 1000; // 5 minutes lockout

// Request size limit (100MB) to prevent DoS via large uploads
const MAX_REQUEST_SIZE = 100 * 1024 * 1024;

// Helper to parse multipart form data
async function parseMultipart(req) {
  return new Promise((resolve, reject) => {
    // Parse Content-Type header for boundary
    const contentType = req.headers['content-type'] || '';
    const boundaryMatch = contentType.match(/boundary=(.+)/);
    if (!boundaryMatch) {
      reject(new Error('No boundary found in Content-Type'));
      return;
    }
    
    // Read request body with size limit check
    let body = Buffer.alloc(0);
    req.on('data', (chunk) => {
      const newLength = body.length + chunk.length;
      if (newLength > MAX_REQUEST_SIZE) {
        req.destroy();
        return;
      }
      body = Buffer.concat([body, chunk]);
    });
    req.on('end', () => {
      try {
        const boundaryStr = boundaryMatch[1];
        // Split by the boundary delimiter
        const parts = body.toString('binary').split('--' + boundaryStr);
        
        let fileData = null;
        let fieldName = null;
        
        for (let i = 0; i < parts.length; i++) {
          let part = parts[i].trim();
          if (!part) continue;
          
          // Skip CRLF prefix
          if (part.startsWith('\r\n')) part = part.substring(2);
          
          const headersEnd = part.indexOf('\r\n\r\n');
          if (headersEnd === -1) continue;
          
          const headerSection = part.substring(0, headersEnd);
          let bodySection = part.substring(headersEnd + 4);
          
          // Remove trailing -- if present (final boundary)
          bodySection = bodySection.replace(/--\r?\n$/, '');
          
          // Parse Content-Disposition for field name and filename
          const dispMatch = headerSection.match(/name="([^"]+)"(?:;\s*filename="([^"]+)")?/i);
          if (!dispMatch) continue;
          
          fieldName = dispMatch[1];
          const fileName = dispMatch[2] || null;
          
          // Check Content-Type header to determine if it's a file
          const contentTypeHeader = headerSection.match(/Content-Type:\s*([^\r\n]+)/i);
          
          // If has filename or non-text content-type, treat as file
          if (fileName || (contentTypeHeader && !contentTypeHeader[1].includes('text/plain'))) {
            fileData = {
              originalname: fileName,
              buffer: Buffer.from(bodySection.trim(), 'binary'),
              mimetype: contentTypeHeader ? contentTypeHeader[1].trim() : 'application/octet-stream'
            };
          }
        }
        
        resolve({ fieldname: fieldName, file: fileData });
      } catch (e) {
        reject(e);
      }
    });
    req.on('error', reject);
  });
}

// Helper to check request size exceeded
function isRequestTooLarge(bodyLength) {
  return bodyLength > MAX_REQUEST_SIZE;
}

// Generate session token
function generateSessionToken() {
  return crypto.randomBytes(32).toString('hex');
}

// Validate credentials
function validateCredentials(user, pass) {
  return user === USERNAME && pass === PASSWORD;
}

// Rate limiting helper functions
function isLoginRateLimited(ip) {
  const attempts = loginAttempts.get(ip) || { count: 0, lockedUntil: 0 };
  if (attempts.lockedUntil > Date.now()) return true;
  return attempts.count >= MAX_LOGIN_ATTEMPTS;
}

function recordLoginAttempt(ip, success) {
  const existing = loginAttempts.get(ip) || { count: 0, lockedUntil: 0 };
  if (!success) {
    existing.count++;
    if (existing.count >= MAX_LOGIN_ATTEMPTS) {
      existing.lockedUntil = Date.now() + LOGIN_LOCKOUT_MS;
    }
  } else {
    existing.count = 0; // Reset on success
    existing.lockedUntil = 0;
  }
  loginAttempts.set(ip, existing);
}

// Sanitize filename to prevent injection and filesystem issues
function sanitizeFilename(filename) {
  if (!filename || typeof filename !== 'string') return null;
  
  // Remove null bytes (potential buffer overflow attack)
  filename = filename.replace(/\0/g, '');
  
  // Limit to 255 chars (filesystem limit on many systems)
  filename = filename.substring(0, 255);
  
  // Replace dangerous characters with underscores
  // These can cause issues: < > : " | ? * are problematic in Windows/macOS/Unix
  filename = filename.replace(/[<>:"|?*]/g, '_');
  
  // Remove leading/trailing whitespace and dots (hidden files)
  filename = filename.trim().replace(/^\.+/, '');
  
  return filename || null;
}

// Ensure path is within root directory
function safePath(reqPath) {
  const decoded = decodeURIComponent(reqPath || '/');
  // Normalize to resolve ./ ../ sequences BEFORE checking
  let resolved = path.normalize(path.resolve(ROOT_DIR, '.' + decoded));
  // Ensure it's within root (with trailing slash to prevent /home/ubuntu/shared-files-evil)
  if (!resolved.startsWith(ROOT_DIR + '/') && resolved !== ROOT_DIR) {
    return null;
  }
  return resolved;
}

// Read directory listing
function readDir(dir) {
  try {
    const items = fs.readdirSync(dir, { withFileTypes: true });
    return items.map(item => ({
      name: item.name,
      path: '/' + path.relative(ROOT_DIR, path.join(dir, item.name)),
      isDirectory: item.isDirectory(),
      size: item.isFile() ? fs.statSync(path.join(dir, item.name)).size : 0,
      modified: item.isFile() ? new Date(fs.statSync(path.join(dir, item.name)).mtime).toISOString() : null
    })).sort((a, b) => {
      if (a.isDirectory !== b.isDirectory) return a.isDirectory ? -1 : 1;
      return a.name.localeCompare(b.name);
    });
  } catch (err) {
    console.error('Error reading directory:', err);
    return null;
  }
}

// HTML escape helper
function h(text) {
  if (text === null || text === undefined) return '';
  const str = String(text);
  return str.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

// Format size for display (client-side only)
function formatSize(bytes) {
  if (bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
}

// Login page HTML
const LOGIN_HTML = `<!DOCTYPE html>
<html><head>
<title>FileBrowser - Login</title>
<style>
* { margin: 0; padding: 0; box-sizing: border-box; }
body { font-family: Arial, sans-serif; background: #1a1a2e; color: #eee; display: flex; justify-content: center; align-items: center; min-height: 100vh; }
.login-container { background: #16213e; padding: 40px; border-radius: 8px; box-shadow: 0 4px 20px rgba(0,0,0,0.5); width: 350px; }
h1 { text-align: center; margin-bottom: 30px; color: #e94560; }
.form-group { margin-bottom: 20px; }
label { display: block; margin-bottom: 5px; color: #aaa; }
input[type="text"], input[type="password"] { width: 100%; padding: 12px; border: none; border-radius: 4px; background: #0f3460; color: #fff; font-size: 14px; }
input:focus { outline: none; box-shadow: 0 0 0 2px #e94560; }
button { width: 100%; padding: 12px; background: #e94560; color: white; border: none; border-radius: 4px; cursor: pointer; font-size: 16px; margin-top: 10px; }
button:hover { background: #ff6b6b; }
.error { background: #e94560; color: white; padding: 10px; border-radius: 4px; margin-bottom: 20px; text-align: center; display: none; }
</style>
</head><body>
<div class="login-container">
<h1>📁 FileBrowser</h1>
<div id="error" class="error">Invalid username or password</div>
<form id="loginForm">
<div class="form-group"><label>Username</label><input type="text" name="user" required autofocus></div>
<div class="form-group"><label>Password</label><input type="password" name="pass" required></div>
<button type="submit">Login</button>
</form>
</div>
<script>
document.getElementById('loginForm').addEventListener('submit', async (e) => {
e.preventDefault();
const formData = new FormData(e.target);
const response = await fetch('/api/auth/login', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ user: formData.get('user'), pass: formData.get('pass') }) });
const data = await response.json();
if (data.success) { document.cookie = 'session=' + data.session + '; path=/; max-age=86400; SameSite=Strict'; window.location.href = '/?path=/'; }
else { document.getElementById('error').style.display = 'block'; }
});
</script>
</body></html>`;

// Generate breadcrumb HTML
function generateBreadcrumb(currentPath) {
  const parts = currentPath.split('/').filter(p => p);
  let html = '<a href="/?path=/">🏠 Root</a>';
  let pathStr = '';
  for (const part of parts) {
    pathStr += '/' + part;
    html += ' <span>/</span> <a href="/?path=' + encodeURIComponent(pathStr) + '">' + h(part) + '</a>';
  }
  return html;
}

// Generate file browser HTML
function generateFileBrowserHTML(currentPath, items) {
  const parentPath = currentPath === '/' ? null : path.dirname(currentPath);
  
  let rowsHtml = '';
  for (const item of items) {
    const isDir = item.isDirectory;
    const icon = isDir ? '📁' : '📄';
    const link = '/?path=' + encodeURIComponent(item.path);
    const sizeDisplay = isDir ? '-' : String(item.size);
    
    rowsHtml += '<tr data-path="' + h(item.path) + '" data-size="' + (isDir ? 0 : item.size) + '">';
    rowsHtml += '<td><a href="' + link + '" class="file-name"><span class="icon">' + icon + '</span> ' + h(item.name) + '</a></td>';
    rowsHtml += '<td class="size">' + sizeDisplay + '</td>';
    rowsHtml += '<td class="modified">-</td>';
    rowsHtml += '<td class="actions">';
    if (!isDir) {
      rowsHtml += '<button class="btn-sm btn-download" onclick="download(\'' + h(item.path) + '\')">Download</button> ';
    }
    rowsHtml += '<button class="btn-sm btn-rename" onclick="renameItem(\'' + h(item.path) + '\', \'' + h(item.name) + '\')">Rename</button>';
    rowsHtml += '<button class="btn-sm btn-delete" onclick="deleteItem(\'' + h(item.path) + '\')">Delete</button>';
    rowsHtml += '</td></tr>';
  }
  
  const breadcrumb = generateBreadcrumb(currentPath);
  const homeLink = parentPath ? '<a href="/" style="color: #e94560; text-decoration: none;">🏠 Home</a> ' : '';
  
  return `<!DOCTYPE html>
<html><head>
<title>FileBrowser - ${h(currentPath)}</title>
<style>
* { margin: 0; padding: 0; box-sizing: border-box; }
body { font-family: Arial, sans-serif; background: #1a1a2e; color: #eee; min-height: 100vh; }
.header { background: #16213e; padding: 15px 30px; display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid #0f3460; }
.logo { font-size: 24px; color: #e94560; font-weight: bold; }
.nav-controls { display: flex; gap: 10px; align-items: center; }
.breadcrumb { display: flex; gap: 5px; align-items: center; margin-bottom: 20px; padding: 10px; background: #16213e; border-radius: 4px; }
.breadcrumb a { color: #e94560; text-decoration: none; padding: 5px 10px; border-radius: 3px; }
.breadcrumb a:hover { background: #0f3460; }
.breadcrumb span { color: #888; }
button { padding: 8px 16px; background: #e94560; color: white; border: none; border-radius: 4px; cursor: pointer; }
button:hover { background: #ff6b6b; }
.container { padding: 30px; max-width: 1200px; margin: 0 auto; }
.toolbar { display: flex; gap: 15px; margin-bottom: 20px; flex-wrap: wrap; align-items: center; }
.path-input { flex: 1; min-width: 300px; padding: 10px 15px; background: #16213e; border: 1px solid #0f3460; color: #fff; border-radius: 4px; font-size: 14px; }
.table-container {
  overflow-x: auto;
  -webkit-overflow-scrolling: touch;
}

.file-list {
  min-width: 600px;
  border-collapse: collapse;
}
.file-list th, .file-list td { padding: 12px 15px; text-align: left; border-bottom: 1px solid #16213e; }
.file-list th { background: #16213e; color: #888; font-weight: normal; font-size: 12px; text-transform: uppercase; }
.file-list tr:hover { background: #16213e; }
.file-name { display: flex; align-items: center; gap: 10px; color: #fff; text-decoration: none; }
.file-name:hover { color: #e94560; }
.icon { font-size: 20px; }
.size { color: #888; width: 80px; }
.modified { color: #888; width: 180px; }
.actions { display: flex; gap: 5px; }
.btn-sm { padding: 4px 8px; font-size: 12px; margin-right: 5px; }

/* Accessibility focus styles */
button:focus-visible,
input:focus-visible,
a:focus-visible {
  outline: 2px solid #e94560;
  outline-offset: 2px;
}

/* Mobile responsive styles */
@media (max-width: 768px) {
  .container { padding: 15px; }
  
  .toolbar {
    flex-direction: column;
    align-items: stretch;
    gap: 10px;
  }
  
  .path-input {
    min-width: auto;
    order: 3;
    margin-top: 5px;
  }
  
  .breadcrumb {
    font-size: 14px;
    word-break: break-all;
  }
  
  .file-list {
    font-size: 12px;
  }
  
  .file-list th, .file-list td {
    padding: 8px 5px;
  }
  
  .actions {
    flex-direction: column;
    gap: 3px;
  }
  
  .btn-sm {
    padding: 4px 8px;
    font-size: 11px;
  }
}
.btn-download { background: #4CAF50; }
.btn-delete { background: #f44336; }
.btn-rename { background: #ff9800; }
.btn-upload { background: #2196F3; color: white; padding: 10px 18px; border: none; border-radius: 4px; cursor: pointer; font-size: 14px; display: inline-flex; align-items: center; gap: 6px; }
.btn-upload:hover { background: #1976D2; }
.btn-folder { background: #4CAF50; color: white; padding: 10px 18px; border: none; border-radius: 4px; cursor: pointer; font-size: 14px; display: inline-flex; align-items: center; gap: 6px; }
.btn-folder:hover { background: #388E3C; }
.upload-area { border: 2px dashed #0f3460; padding: 30px; text-align: center; margin-bottom: 20px; border-radius: 8px; cursor: pointer; transition: all 0.3s; }
.upload-area:hover, .upload-area.dragover { border-color: #e94560; background: rgba(233, 69, 96, 0.1); }
.upload-area p { margin-bottom: 10px; color: #888; }
.hidden { display: none; }
.modal-overlay { position: fixed; top: 0; left: 0; right: 0; bottom: 0; background: rgba(0,0,0,0.7); display: flex; justify-content: center; align-items: center; z-index: 1000; }
/* Force hide modal when hidden class is applied */
.modal-overlay.hidden { display: none !important; }
.modal { background: #16213e; padding: 30px; border-radius: 8px; width: 400px; max-width: 90%; }
.modal h3 { margin-bottom: 20px; color: #fff; }
.modal input[type="text"] { width: 100%; padding: 10px; background: #0f3460; border: none; color: #fff; border-radius: 4px; margin-bottom: 15px; box-sizing: border-box; }
.modal-buttons { display: flex; gap: 10px; justify-content: flex-end; }
.btn-cancel { background: #666; }
.progress-bar { width: 100%; height: 4px; background: #0f3460; margin-top: 15px; border-radius: 2px; overflow: hidden; display: none; }
.progress-fill { height: 100%; background: #e94560; width: 0%; transition: width 0.3s; }
.status-msg { margin-top: 10px; padding: 10px; border-radius: 4px; display: none; }
.status-success { background: rgba(76, 175, 80, 0.2); color: #4CAF50; }
.status-error { background: rgba(244, 67, 54, 0.2); color: #f44336; }
a { text-decoration: none; }
</style>
</head><body>
<div class="header">
<div class="logo">📁 FileBrowser</div>
<div class="nav-controls">${homeLink}<button onclick="logout()">Logout</button></div>
</div>
<div class="container">
<div class="breadcrumb">${breadcrumb}</div>
<div class="toolbar">
<button onclick="showUploadModal()" class="btn-upload">📤 Upload Files</button>
<button onclick="createFolder()" class="btn-folder">📁 New Folder</button>
<input type="text" class="path-input" id="pathInput" value="${h(currentPath)}" placeholder="/path/to/directory" onkeypress="if(event.key==='Enter') navigate(this.value)">
</div>
<div id="uploadArea" class="upload-area">
<p><strong>Drag and drop files here</strong></p>
<p>or click to select files</p>
<input type="file" id="fileInput" multiple style="display: none;">
</div>
<div id="progressBar" class="progress-bar"><div id="progressFill" class="progress-fill"></div></div>
<div id="statusMsg" class="status-msg"></div>
<div class="table-container">
<table class="file-list">
<thead><tr><th>Name</th><th>Size</th><th>Modified</th><th>Actions</th></tr></thead>
<tbody id="fileListBody">${rowsHtml}</tbody>
</table>
</div></div>
<div id="renameModal" class="modal-overlay hidden"><div class="modal"><h3>Rename</h3><input type="text" id="newNameInput"><div class="modal-buttons"><button class="btn-cancel" onclick="closeRename()">Cancel</button><button onclick="confirmRename()">Rename</button></div></div></div>
<div id="folderModal" class="modal-overlay hidden"><div class="modal"><h3>New Folder Name</h3><input type="text" id="folderNameInput" placeholder="Enter folder name"><div class="modal-buttons"><button class="btn-cancel" onclick="closeFolderModal()">Cancel</button><button onclick="confirmCreateFolder()">Create</button></div></div></div>
<div id="uploadModal" class="modal-overlay hidden"><div class="modal"><h3>Upload Files</h3><p style="color: #888; margin-bottom: 15px;">Select files to upload to current folder</p><input type="file" id="modalFileInput" multiple style="width: 100%; padding: 10px; background: #0f3460; border: none; color: #fff; border-radius: 4px; margin-bottom: 15px;"><div id="uploadProgress" style="color: #888; margin-bottom: 15px;"></div><div class="modal-buttons"><button class="btn-cancel" onclick="closeUploadModal()">Cancel</button><button onclick="startUpload()" id="uploadBtn" disabled>Upload</button></div></div></div>
<script>
const currentPath = '${h(currentPath)}';
let renamingPath = null;

// Determine if file should use streaming upload (>10MB threshold)
function shouldUseStreaming(file) {
  return file.size > 10 * 1024 * 1024; // Use streaming for files > 10MB
}

// User-friendly error message mapping
function userFriendlyError(technicalError) {
  const mappings = {
    'Invalid credentials': 'Wrong username or password',
    'Too many login attempts': 'Too many failed logins. Try again in 5 minutes.',
    'Invalid request': 'Please check your input and try again',
    'File not found': 'The file does not exist',
    'Access Denied': 'You do not have permission to access this resource'
  };
  return mappings[technicalError] || 'An error occurred. Please try again.';
}

function formatSize(bytes) {
if (bytes === 0) return '0 B';
const k = 1024, sizes = ['B', 'KB', 'MB', 'GB'];
const i = Math.floor(Math.log(bytes) / Math.log(k));
return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
}

function navigate(path) { window.location.href = '/?path=' + encodeURIComponent(path); }
function logout() {
  document.cookie = 'session=; path=/; expires=' + new Date(0).toUTCString();
  fetch('/api/auth/logout', { method: 'POST' });
  window.location.href = '/';
}

async function uploadFile(file, index, total) {
const formData = new FormData();
formData.append('file', file);

// Use streaming for large files (>10MB), buffered upload for small files
const useStreaming = shouldUseStreaming(file);
const endpoint = useStreaming ? '/api/upload-stream?path=' + encodeURIComponent(currentPath) : '/api/upload?path=' + encodeURIComponent(currentPath);
const displaySize = formatSize(file.size);

try {
  if (useStreaming && 'XMLHttpRequest' in window) {
    // Use XHR for streaming uploads to get progress events
    return new Promise((resolve, reject) => {
      const xhr = new XMLHttpRequest();
      
      xhr.open('POST', endpoint, true);
      
      // Update progress bar during upload
      xhr.upload.addEventListener('progress', (e) => {
        if (e.lengthComputable) {
          const percentComplete = Math.round((e.loaded / e.total) * 100);
          showStatus('Uploading ' + file.name + ': ' + percentComplete + '% (' + formatSize(e.loaded) + ' of ' + displaySize + ')', false);
        }
      });
      
      xhr.addEventListener('load', () => {
        if (xhr.status >= 200 && xhr.status < 300) {
          try {
            const data = JSON.parse(xhr.responseText);
            updateProgress(index, total);
            if (data.success) {
              showStatus('Uploaded ' + file.name + ' (' + formatSize(data.size || file.size) + ')', false);
              resolve(true);
            } else {
              showStatus('Failed to upload "' + file.name + '": ' + userFriendlyError(data.error || 'Unknown error'), true);
              updateProgress(index, total);
              resolve(false);
            }
          } catch (parseErr) {
            showStatus('Response parse error for "' + file.name + '"', true);
            updateProgress(index, total);
            resolve(false);
          }
        } else {
          showStatus('HTTP ' + xhr.status + ' uploading "' + file.name + '"', true);
          updateProgress(index, total);
          resolve(false);
        }
      });
      
      xhr.addEventListener('error', () => {
        showStatus('Network error uploading "' + file.name + '"', true);
        updateProgress(index, total);
        resolve(false);
      });
      
      xhr.addEventListener('abort', () => {
        showStatus('Upload aborted: "' + file.name + '"', true);
        updateProgress(index, total);
        resolve(false);
      });
      
      xhr.send(formData);
    });
  } else {
    // Use fetch for small files (no progress tracking needed)
    const response = await fetch(endpoint, { method: 'POST', body: formData });
    if (!response.ok) { throw new Error('HTTP ' + response.status + ': ' + response.statusText); }
    const data = await response.json();
    updateProgress(index, total);
    if (!data.success) {
      showStatus('Failed to upload "' + file.name + '": ' + userFriendlyError(data.error || 'Unknown error'), true);
    } else {
      showStatus('Uploaded ' + file.name + ' (' + displaySize + ')', false);
    }
    return data.success;
  }
} catch (e) {
  updateProgress(index, total);
  showStatus('Network error uploading "' + file.name + '"', true);
  return false;
}
}

async function handleFiles(files) {
if (!files.length) return;
document.getElementById('progressBar').style.display = 'block';
for (let i = 0; i < files.length; i++) { await uploadFile(files[i], i, files.length); }
updateProgress(files.length, files.length);
setTimeout(() => { document.getElementById('progressBar').style.display = 'none'; window.location.reload(); }, 500);
}

function updateProgress(current, total) { document.getElementById('progressFill').style.width = ((current / total) * 100) + '%'; }
function showStatus(message, isError) {
const el = document.getElementById('statusMsg');
el.textContent = message;
el.className = 'status-msg ' + (isError ? 'status-error' : 'status-success');
el.style.display = 'block';
setTimeout(() => { el.style.display = 'none'; }, 3000);
}

function download(filePath) { window.location.href = '/download?path=' + encodeURIComponent(filePath); }
async function deleteItem(filePath) {
if (!confirm('Delete "' + filePath.split('/').pop() + '"?')) return;
try {
  const response = await fetch('/api/delete', { method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({ path: filePath })});
  if (!response.ok) { throw new Error('HTTP ' + response.status + ': ' + response.statusText); }
  const data = await response.json();
  if (data.success) window.location.reload(); else showStatus(userFriendlyError(data.error), true);
} catch (e) {
  showStatus('Network error during delete', true);
}
}

function renameItem(filePath, currentName) {
renamingPath = filePath;
document.getElementById('newNameInput').value = currentName;
document.getElementById('renameModal').classList.remove('hidden');
document.getElementById('newNameInput').focus();
}
function closeRename() { document.getElementById('renameModal').classList.add('hidden'); renamingPath = null; }
async function confirmRename() {
const newName = document.getElementById('newNameInput').value.trim();
if (!newName) return;
try {
  const response = await fetch('/api/rename', { method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({ path: renamingPath, newName })});
  if (!response.ok) { throw new Error('HTTP ' + response.status + ': ' + response.statusText); }
  const data = await response.json();
  closeRename();
  if (data.success) window.location.reload(); else showStatus(userFriendlyError(data.error), true);
} catch (e) {
  showStatus('Network error during rename', true);
}
}

// Modal state management
const modals = {
  folder: { elementId: 'folderModal', closeFunc: 'closeFolderModal' },
  rename: { elementId: 'renameModal', closeFunc: 'closeRename' },
  upload: { elementId: 'uploadModal', closeFunc: 'closeUploadModal' }
};

// Upload modal functions
function showUploadModal() {
  document.getElementById('uploadModal').classList.remove('hidden');
}

function closeUploadModal() {
  const modal = document.getElementById('uploadModal');
  if (modal) {
    modal.classList.add('hidden');
    const input = document.getElementById('modalFileInput');
    if (input) input.value = '';
    document.getElementById('uploadProgress').innerHTML = '';
  }
}

async function startUpload() {
  const fileInput = document.getElementById('modalFileInput');
  const files = fileInput.files;
  
  if (!files.length) { showStatus('No files selected', true); return; }
  
  let successCount = 0;
  
  for (let i = 0; i < files.length; i++) {
    const file = files[i];
    const formData = new FormData();
    formData.append('file', file);
    const displaySize = formatSize(file.size);
    
    // Use streaming for large files
    const useStreaming = shouldUseStreaming(file);
    const endpoint = useStreaming ? '/api/upload-stream?path=' + encodeURIComponent(currentPath) : '/api/upload?path=' + encodeURIComponent(currentPath);
    
    document.getElementById('uploadProgress').innerHTML = '<p>Uploading ' + (i+1) + '/' + files.length + ': <strong>' + file.name + '</strong> (' + displaySize + ')' + (useStreaming ? ' [streaming]' : '') + '...</p>';
    
    try {
      if (useStreaming && 'XMLHttpRequest' in window) {
        // Use XHR for streaming uploads with progress
        await new Promise((resolve, reject) => {
          const xhr = new XMLHttpRequest();
          xhr.open('POST', endpoint, true);
          
          xhr.upload.addEventListener('progress', (e) => {
            if (e.lengthComputable) {
              const percentComplete = Math.round((e.loaded / e.total) * 100);
              document.getElementById('uploadProgress').innerHTML = '<p>Uploading ' + (i+1) + '/' + files.length + ': <strong>' + file.name + '</strong>: ' + percentComplete + '% (' + formatSize(e.loaded) + ' of ' + displaySize + ')</p>';
            }
          });
          
          xhr.addEventListener('load', () => {
            if (xhr.status >= 200 && xhr.status < 300) {
              try {
                const data = JSON.parse(xhr.responseText);
                resolve(data.success);
              } catch (parseErr) {
                reject(new Error('Response parse error'));
              }
            } else {
              reject(new Error('HTTP ' + xhr.status));
            }
          });
          
          xhr.addEventListener('error', () => reject(new Error('Network error')));
          xhr.addEventListener('abort', () => reject(new Error('Aborted')));
          
          xhr.send(formData);
        });
      } else {
        // Use fetch for small files
        const response = await fetch(endpoint, { method: 'POST', body: formData });
        if (!response.ok) { throw new Error('HTTP ' + response.status + ': ' + response.statusText); }
        const data = await response.json();
        if (!data.success) throw new Error(data.error || 'Upload failed');
      }
      successCount++;
    } catch (error) {
      showStatus('Failed to upload ' + file.name + ': ' + error.message, true);
      continue;
    }
  }
  
  closeUploadModal();
  if (successCount === files.length) {
    showStatus(files.length + ' file(s) uploaded successfully', false);
  } else if (successCount > 0) {
    showStatus(successCount + '/' + files.length + ' file(s) uploaded successfully', false);
  }
  window.location.reload();
}

// Handle modal file selection
document.getElementById('modalFileInput').addEventListener('change', function() {
  const uploadBtn = document.getElementById('uploadBtn');
  if (uploadBtn) {
    uploadBtn.disabled = this.files.length === 0;
  }
});

function openModal(modalName) {
  const modal = document.getElementById(modals[modalName].elementId);
  if (modal) {
    modal.classList.remove('hidden');
    console.log('Opened ' + modalName + ' modal');
  }
}

function closeModal(modalName) {
  const modal = document.getElementById(modals[modalName].elementId);
  if (modal) {
    modal.classList.add('hidden');
    // Clear any input fields
    const inputs = modal.querySelectorAll('input');
    inputs.forEach(input => input.value = '');
    console.log('Closed ' + modalName + ' modal, display:', window.getComputedStyle(modal).display);
  }
}

function createFolder() { document.getElementById('folderModal').classList.remove('hidden'); document.getElementById('folderNameInput').focus(); }
function closeFolderModal() {
  const modal = document.getElementById('folderModal');
  console.log('[closeFolderModal] Before - hidden class:', modal.classList.contains('hidden'));
  
  modal.classList.add('hidden');
  
  // Force reflow to ensure CSS applies
  void modal.offsetWidth;
  
  console.log('[closeFolderModal] After - hidden class:', modal.classList.contains('hidden'));
  console.log('[closeFolderModal] Computed display:', window.getComputedStyle(modal).display);
  
  // Clear input field
  const input = document.getElementById('folderNameInput');
  if (input) input.value = '';
}
async function confirmCreateFolder() {
const folderName = document.getElementById('folderNameInput').value.trim();
if (!folderName) { showStatus('Please enter a folder name', true); return; }
try {
  const response = await fetch('/api/mkdir', { method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({ path: currentPath, name: folderName })});
  if (!response.ok) { throw new Error('HTTP ' + response.status + ': ' + response.statusText); }
  const data = await response.json();
  closeFolderModal();
  if (data.success) window.location.reload(); else showStatus(userFriendlyError(data.error), true);
} catch (e) {
  showStatus('Network error creating folder', true);
}
}

document.getElementById('uploadArea').addEventListener('click', () => document.getElementById('fileInput').click());
document.getElementById('uploadArea').addEventListener('dragover', (e) => { e.preventDefault(); e.currentTarget.classList.add('dragover'); });
document.getElementById('uploadArea').addEventListener('dragleave', (e) => {
if (e.target === e.currentTarget) {
  document.getElementById('uploadArea').classList.remove('dragover');
}
});
document.getElementById('uploadArea').addEventListener('drop', (e) => {
e.preventDefault(); document.getElementById('uploadArea').classList.remove('dragover'); handleFiles(e.dataTransfer.files);
});
document.getElementById('fileInput').addEventListener('change', (e) => handleFiles(e.target.files));
document.getElementById('newNameInput').addEventListener('keypress', (e) => { if (e.key === 'Enter') confirmRename(); });
document.getElementById('folderNameInput').addEventListener('keypress', (e) => { if (e.key === 'Enter') confirmCreateFolder(); });

// ESC key closes all modals
document.addEventListener('keydown', (e) => {
if (e.key === 'Escape') {
const renameModal = document.getElementById('renameModal');
const folderModal = document.getElementById('folderModal');
const uploadModal = document.getElementById('uploadModal');
if (!renameModal.classList.contains('hidden')) closeRename();
if (!folderModal.classList.contains('hidden')) closeFolderModal();
if (!uploadModal.classList.contains('hidden')) closeUploadModal();
}
});

// Click backdrop to close modals
document.getElementById('renameModal').addEventListener('click', (e) => { if (e.target === e.currentTarget) closeRename(); });
document.getElementById('folderModal').addEventListener('click', (e) => { if (e.target === e.currentTarget) closeFolderModal(); });

// Attach explicit event listener to cancel button
document.addEventListener('DOMContentLoaded', function() {
  const cancelBtn = document.querySelector('.btn-cancel');
  if (cancelBtn && !cancelBtn.hasAttribute('data-handler-attached')) {
    cancelBtn.setAttribute('data-handler-attached', 'true');
    cancelBtn.addEventListener('click', function(e) {
      e.preventDefault();
      e.stopPropagation();
      console.log('[Cancel Button] Click detected, calling closeFolderModal()');
      closeFolderModal();
    });
  }
});
</script>
</body></html>`;
}

// Authentication middleware
function checkAuth(req) {
  const cookie = req.headers.cookie || '';
  const sessionMatch = cookie.match(/session=([^;]+)/);
  if (sessionMatch) {
    const sessionData = getSession(sessionMatch[1]);
    // getSession handles expiry and cleanup internally
    return !!sessionData;
  }
  return false;
}

// Error codes enum for consistent error responses
const ERROR_CODES = {
  UNAUTHORIZED: 'UNAUTHORIZED',
  ACCESS_DENIED: 'ACCESS_DENIED',
  NOT_FOUND: 'NOT_FOUND',
  INVALID_REQUEST: 'INVALID_REQUEST',
  FILE_EXISTS: 'FILE_EXISTS',
  INVALID_FILENAME: 'INVALID_FILENAME',
  PAYLOAD_TOO_LARGE: 'PAYLOAD_TOO_LARGE',
  RATE_LIMITED: 'RATE_LIMITED',
  INTERNAL_ERROR: 'INTERNAL_ERROR'
};

// Response helper
function sendJSON(res, data) {
  res.writeHead(200, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify(data));
}

function sendHTML(res, html) {
  res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
  res.end(html);
}

// V1 API Response helpers with consistent format
function sendV1Success(res, statusCode, data, meta = null) {
  const response = {
    status: 'success',
    data: data
  };
  if (meta !== null) {
    response.meta = meta;
  }
  res.writeHead(statusCode, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify(response));
}

function sendV1Error(res, statusCode, code, message) {
  res.writeHead(statusCode, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify({
    status: 'error',
    code: code,
    message: message
  }));
}

// Session check (legacy)
function checkSession(req, res) {
  const cookie = req.headers.cookie || '';
  const sessionMatch = cookie.match(/session=([^;]+)/);
  if (!sessionMatch || !getSession(sessionMatch[1])) {
    res.writeHead(401, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ success: false, error: 'Unauthorized' }));
    return false;
  }
  return true;
}

// Session check with V1 error response
function checkSessionV1(req, res) {
  const cookie = req.headers.cookie || '';
  const sessionMatch = cookie.match(/session=([^;]+)/);
  if (!sessionMatch || !getSession(sessionMatch[1])) {
    sendV1Error(res, 401, ERROR_CODES.UNAUTHORIZED, 'Authentication required');
    return false;
  }
  return true;
}

// Helper to extract path from V1 file endpoints (returns path with leading /)
function extractPathFromV1Endpoint(pathname, prefixLength) {
  let encodedPath = pathname.substring(prefixLength);
  // Ensure path always starts with /
  if (!encodedPath || encodedPath === '/') {
    return '/';
  }
  if (!encodedPath.startsWith('/')) {
    encodedPath = '/' + encodedPath;
  }
  return decodeURIComponent(encodedPath);
}

// Main server
const server = http.createServer(async (req, res) => {
  const parsedUrl = url.parse(req.url);
  const pathname = parsedUrl.pathname;
  
  // API: Login (deprecated - use /api/v1/auth/login)
  if (pathname === '/api/auth/login' && req.method === 'POST') {
    res.setHeader('Deprecation', 'true');
    res.setHeader('X-Deprecation-Warning', 'Use /api/v1/auth/login instead');
    
    let body = '';
    for await (const chunk of req) body += chunk;
    
    // Get client IP for rate limiting
    const clientIP = req.socket.remoteAddress || 
                     req.headers['x-forwarded-for']?.split(',')[0] || 
                     'unknown';
    
    // Check rate limit first
    if (isLoginRateLimited(clientIP)) {
      res.writeHead(429, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ success: false, error: 'Too many login attempts. Please try again later.' }));
      return;
    }
    
    try {
      const { user, pass } = JSON.parse(body);
      const valid = validateCredentials(user, pass);
      recordLoginAttempt(clientIP, valid); // Record attempt (success or failure)
      
      if (valid) {
        const session = createSession(user);
        if (!session) {
          res.writeHead(500, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ success: false, error: 'Failed to create session' }));
          return;
        }
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ success: true, session }));
      } else {
        res.writeHead(401, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ success: false, error: 'Invalid credentials' }));
      }
    } catch (e) {
      res.writeHead(400).end('Bad Request');
    }
    return;
  }
  
  // API: Logout
  if (pathname === '/api/auth/logout' && req.method === 'POST') {
    const cookie = req.headers.cookie || '';
    const sessionMatch = cookie.match(/session=([^;]+)/);
    if (sessionMatch) deleteSession(sessionMatch[1]);
    res.writeHead(200).end('OK');
    return;
  }

  // ========== V1 API ENDPOINTS ==========

  // V1: Login - POST /api/v1/auth/login
  if (pathname === '/api/v1/auth/login' && req.method === 'POST') {
    let body = '';
    for await (const chunk of req) body += chunk;
    
    const clientIP = req.socket.remoteAddress || 
                     req.headers['x-forwarded-for']?.split(',')[0] || 
                     'unknown';
    
    if (isLoginRateLimited(clientIP)) {
      sendV1Error(res, 429, ERROR_CODES.RATE_LIMITED, 'Too many login attempts. Please try again later.');
      return;
    }
    
    try {
      const { user, pass } = JSON.parse(body);
      const valid = validateCredentials(user, pass);
      recordLoginAttempt(clientIP, valid);
      
      if (valid) {
        const session = createSession(user);
        if (!session) {
          sendV1Error(res, 500, ERROR_CODES.INTERNAL_ERROR, 'Failed to create session');
          return;
        }
        sendV1Success(res, 200, { session });
      } else {
        sendV1Error(res, 401, ERROR_CODES.UNAUTHORIZED, 'Invalid credentials');
      }
    } catch (e) {
      sendV1Error(res, 400, ERROR_CODES.INVALID_REQUEST, 'Malformed request body');
    }
    return;
  }

  // V1: Logout - POST /api/v1/auth/logout
  if (pathname === '/api/v1/auth/logout' && req.method === 'POST') {
    const cookie = req.headers.cookie || '';
    const sessionMatch = cookie.match(/session=([^;]+)/);
    if (sessionMatch) deleteSession(sessionMatch[1]);
    res.writeHead(204); // No Content
    res.end();
    return;
  }

  // V1: Raw file download - GET /api/v1/files/{path*}/raw
  // Must come BEFORE general /api/v1/files handler to avoid being caught first
  if (pathname.startsWith('/api/v1/files') && pathname.endsWith('/raw')) {
    if (!checkSessionV1(req, res)) return;
    
    const pathWithoutRaw = pathname.substring(0, pathname.length - 4); // Remove '/raw'
    const decodedPath = extractPathFromV1Endpoint(pathWithoutRaw, 14);
    const resolvedPath = safePath(decodedPath);
    
    if (!resolvedPath) {
      sendV1Error(res, 403, ERROR_CODES.ACCESS_DENIED, 'Access denied');
      return;
    }
    
    try {
      const stat = fs.statSync(resolvedPath);
      if (!stat.isFile()) {
        sendV1Error(res, 400, ERROR_CODES.INVALID_REQUEST, 'Not a file');
        return;
      }
      
      const filename = path.basename(resolvedPath);
      res.writeHead(200, {
        'Content-Type': 'application/octet-stream',
        'Content-Disposition': 'attachment; filename="' + filename + '"',
        'Content-Length': stat.size
      });
      fs.createReadStream(resolvedPath).pipe(res);
    } catch (e) {
      if (e.code === 'ENOENT') {
        sendV1Error(res, 404, ERROR_CODES.NOT_FOUND, 'File not found');
      } else {
        sendV1Error(res, 500, ERROR_CODES.INTERNAL_ERROR, e.message);
      }
    }
    return;
  }

  // V1: File operations - /api/v1/files/{path*}
  if (pathname.startsWith('/api/v1/files')) {
    if (!checkSessionV1(req, res)) return;
    
    const decodedPath = extractPathFromV1Endpoint(pathname, 14); // 14 = length of '/api/v1/files'
    const resolvedPath = safePath(decodedPath);
    
    if (!resolvedPath) {
      sendV1Error(res, 403, ERROR_CODES.ACCESS_DENIED, 'Access denied');
      return;
    }
    
    // V1: List files - GET /api/v1/files/{path*}
    if (req.method === 'GET') {
      try {
        const entries = fs.readdirSync(resolvedPath, { withFileTypes: true });
        const files = entries.map(entry => {
          const fullPath = path.join(resolvedPath, entry.name);
          let stat;
          try {
            stat = fs.statSync(fullPath);
          } catch (e) {
            return null; // Skip broken symlinks
          }
          
          return {
            name: entry.name,
            path: decodedPath === '/' ? '/' + entry.name : decodedPath + '/' + entry.name,
            isDirectory: entry.isDirectory(),
            size: entry.isDirectory() ? 0 : stat.size,
            modified: stat.mtime.toISOString()
          };
        }).filter(f => f !== null);
        
        sendV1Success(res, 200, files, { path: decodedPath, count: files.length });
      } catch (e) {
        if (e.code === 'ENOENT') {
          sendV1Error(res, 404, ERROR_CODES.NOT_FOUND, 'Path not found');
        } else {
          sendV1Error(res, 500, ERROR_CODES.INTERNAL_ERROR, e.message);
        }
      }
      return;
    }
    
    // V1: Upload file - POST /api/v1/files/{path*}
    if (req.method === 'POST') {
      try {
        const parsed = await parseMultipart(req);
        
        if (!parsed.file) {
          sendV1Error(res, 400, ERROR_CODES.INVALID_REQUEST, 'No file uploaded');
          return;
        }
        
        const sanitizedFilename = sanitizeFilename(parsed.file.originalname);
        if (!sanitizedFilename) {
          sendV1Error(res, 400, ERROR_CODES.INVALID_FILENAME, 'Invalid filename');
          return;
        }
        
        const targetDir = resolvedPath;
        fs.mkdirSync(targetDir, { recursive: true });
        
        const finalPath = path.join(targetDir, sanitizedFilename);
        
        // Check if file already exists
        try {
          fs.accessSync(finalPath);
          sendV1Error(res, 409, ERROR_CODES.FILE_EXISTS, 'File already exists');
          return;
        } catch (e) {
          // File doesn't exist, proceed with upload
        }
        
        fs.writeFileSync(finalPath, parsed.file.buffer);
        const stat = fs.statSync(finalPath);
        
        console.log(`V1 Upload: ${parsed.file.originalname} (${sanitizedFilename}) → ${finalPath}`);
        sendV1Success(res, 201, {
          name: sanitizedFilename,
          originalName: parsed.file.originalname,
          path: decodedPath === '/' ? '/' + sanitizedFilename : decodedPath + '/' + sanitizedFilename,
          size: stat.size,
          created: stat.mtime.toISOString()
        });
      } catch (error) {
        console.error('V1 Upload error:', error);
        sendV1Error(res, 500, ERROR_CODES.INTERNAL_ERROR, error.message);
      }
      return;
    }
    
    // V1: Create folder - PUT /api/v1/files/{path*}
    if (req.method === 'PUT') {
      try {
        fs.mkdirSync(resolvedPath, { recursive: true });
        const stat = fs.statSync(resolvedPath);
        sendV1Success(res, 201, {
          name: path.basename(decodedPath),
          path: decodedPath,
          isDirectory: true,
          created: stat.mtime.toISOString()
        });
      } catch (e) {
        if (e.code === 'EEXIST') {
          sendV1Error(res, 409, ERROR_CODES.FILE_EXISTS, 'Folder already exists');
        } else {
          sendV1Error(res, 500, ERROR_CODES.INTERNAL_ERROR, e.message);
        }
      }
      return;
    }
    
    // V1: Delete - DELETE /api/v1/files/{path*}
    if (req.method === 'DELETE') {
      try {
        const stat = fs.statSync(resolvedPath);
        if (stat.isDirectory()) {
          fs.rmSync(resolvedPath, { recursive: true, force: true });
        } else {
          fs.unlinkSync(resolvedPath);
        }
        res.writeHead(204); // No Content
        res.end();
      } catch (e) {
        if (e.code === 'ENOENT') {
          sendV1Error(res, 404, ERROR_CODES.NOT_FOUND, 'File not found');
        } else {
          sendV1Error(res, 500, ERROR_CODES.INTERNAL_ERROR, e.message);
        }
      }
      return;
    }
    
    // V1: Rename - PATCH /api/v1/files/{path*}
    if (req.method === 'PATCH') {
      let body = '';
      for await (const chunk of req) body += chunk;
      
      try {
        const { newName } = JSON.parse(body);
        
        if (!newName) {
          sendV1Error(res, 400, ERROR_CODES.INVALID_REQUEST, 'Missing newName field');
          return;
        }
        
        const sanitizedNewName = sanitizeFilename(newName);
        if (!sanitizedNewName) {
          sendV1Error(res, 400, ERROR_CODES.INVALID_FILENAME, 'Invalid filename');
          return;
        }
        
        const dir = path.dirname(resolvedPath);
        const newFullPath = path.join(dir, sanitizedNewName);
        
        if (!safePath(newFullPath)) {
          sendV1Error(res, 403, ERROR_CODES.ACCESS_DENIED, 'Access denied');
          return;
        }
        
        fs.renameSync(resolvedPath, newFullPath);
        const stat = fs.statSync(newFullPath);
        
        sendV1Success(res, 200, {
          name: sanitizedNewName,
          path: '/' + path.relative(ROOT_DIR, newFullPath),
          isDirectory: stat.isDirectory(),
          size: stat.isDirectory() ? 0 : stat.size,
          modified: stat.mtime.toISOString()
        });
      } catch (e) {
        if (e.code === 'ENOENT') {
          sendV1Error(res, 404, ERROR_CODES.NOT_FOUND, 'File not found');
        } else {
          sendV1Error(res, 500, ERROR_CODES.INTERNAL_ERROR, e.message);
        }
      }
      return;
    }
    
    // Method not allowed
    sendV1Error(res, 400, ERROR_CODES.INVALID_REQUEST, 'Method not allowed');
    return;
  }

  // V1: Raw file download - GET /api/v1/files/{path*}/raw
  if (pathname.startsWith('/api/v1/files') && pathname.endsWith('/raw')) {
    if (!checkSessionV1(req, res)) return;
    
    const pathWithoutRaw = pathname.substring(0, pathname.length - 4); // Remove '/raw'
    const decodedPath = extractPathFromV1Endpoint(pathWithoutRaw, 14);
    const resolvedPath = safePath(decodedPath);
    
    if (!resolvedPath) {
      sendV1Error(res, 403, ERROR_CODES.ACCESS_DENIED, 'Access denied');
      return;
    }
    
    try {
      const stat = fs.statSync(resolvedPath);
      if (!stat.isFile()) {
        sendV1Error(res, 400, ERROR_CODES.INVALID_REQUEST, 'Not a file');
        return;
      }
      
      const filename = path.basename(resolvedPath);
      res.writeHead(200, {
        'Content-Type': 'application/octet-stream',
        'Content-Disposition': 'attachment; filename="' + filename + '"',
        'Content-Length': stat.size
      });
      fs.createReadStream(resolvedPath).pipe(res);
    } catch (e) {
      if (e.code === 'ENOENT') {
        sendV1Error(res, 404, ERROR_CODES.NOT_FOUND, 'File not found');
      } else {
        sendV1Error(res, 500, ERROR_CODES.INTERNAL_ERROR, e.message);
      }
    }
    return;
  }

  // ========== END V1 API ENDPOINTS ==========
  
  // Check auth for protected routes
  if (!checkAuth(req)) {
    if (pathname.startsWith('/api/')) {
      res.writeHead(401, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Unauthorized' }));
      return;
    }
    sendHTML(res, LOGIN_HTML);
    return;
  }
  
  // File Browser
  if (pathname === '/' || pathname === '/index.html') {
    const query = url.parse(req.url, true).query;
    const reqPath = query.path || '/';
    const resolvedPath = safePath(reqPath);
    
    if (!resolvedPath) {
      res.writeHead(403).end('Access Denied');
      return;
    }
    
    const items = readDir(resolvedPath);
    if (!items) {
      res.writeHead(500).end('Cannot read directory');
      return;
    }
    
    sendHTML(res, generateFileBrowserHTML(reqPath, items));
    return;
  }
  
  // Download (deprecated - use /api/v1/files/{path}/raw)
  if (pathname === '/download') {
    res.setHeader('Deprecation', 'true');
    res.setHeader('X-Deprecation-Warning', 'Use /api/v1/files/{path}/raw instead');
    
    const query = url.parse(req.url, true).query;
    const resolvedPath = safePath(query.path);
    
    if (!resolvedPath) {
      res.writeHead(403).end('Access Denied');
      return;
    }
    
    try {
      const stat = fs.statSync(resolvedPath);
      if (!stat.isFile()) {
        res.writeHead(400).end('Not a file');
        return;
      }
      
      const filename = path.basename(resolvedPath);
      res.writeHead(200, {
        'Content-Type': 'application/octet-stream',
        'Content-Disposition': 'attachment; filename="' + filename + '"',
        'Content-Length': stat.size
      });
      fs.createReadStream(resolvedPath).pipe(res);
    } catch (e) {
      res.writeHead(404).end('File not found');
    }
    return;
  }
  
  // API: Streaming Upload - deprecated (use /api/v1/files/{path} POST)
  if (pathname === '/api/upload-stream' && req.method === 'POST') {
    res.setHeader('Deprecation', 'true');
    res.setHeader('X-Deprecation-Warning', 'Use /api/v1/files/{path} with POST method instead');
    
    if (!checkSession(req, res)) return;
    
    const query = url.parse(req.url, true).query;
    let targetPath = query.path || '/';
    
    // Handle encoded path properly
    if (targetPath.startsWith('%2F')) {
      targetPath = decodeURIComponent(targetPath);
    } else if (targetPath !== '/') {
      targetPath = '/' + targetPath;
    }
    
    const targetDir = safePath(targetPath);
    if (!targetDir) { sendJSON(res, { success: false, error: 'Invalid path' }); return; }
    
    // Ensure directory exists
    try {
      fs.mkdirSync(targetDir, { recursive: true });
    } catch (e) {
      sendJSON(res, { success: false, error: e.message });
      return;
    }
    
    const busboy = new Busboy({ headers: req.headers });
    let writeFileStream = null;
    let bytesWritten = 0;
    let filename = '';
    let originalFilename = '';
    
    busboy.on('file', (fieldname, fileStream, info) => {
      originalFilename = decodeURIComponent(info.filename);
      filename = sanitizeFilename(originalFilename);
      if (!filename) { req.destroy(); return; }
      
      const finalPath = path.join(targetDir, filename);
      
      // Verify path is within bounds
      const resolvedFinalPath = path.resolve(finalPath);
      if (!resolvedFinalPath.startsWith(ROOT_DIR + '/') && resolvedFinalPath !== ROOT_DIR) {
        sendJSON(res, { success: false, error: 'Access Denied' });
        req.destroy();
        return;
      }
      
      try {
        writeFileStream = fs.createWriteStream(finalPath);
        fileStream.pipe(writeFileStream);
        
        // Track bytes written
        fileStream.on('data', (chunk) => {
          bytesWritten += chunk.length;
        });
        
        writeFileStream.on('finish', () => {
          console.log(`Streaming upload: ${originalFilename} (${filename}) → ${finalPath}, size: ${bytesWritten}`);
          sendJSON(res, { success: true, filename, original: originalFilename, size: bytesWritten });
        });
        
        writeFileStream.on('error', (err) => {
          console.error(`Stream write error: ${err.message}`);
          if (!res.headersSent) {
            sendJSON(res, { success: false, error: err.message });
          }
          req.destroy();
        });
      } catch (e) {
        console.error(`Stream setup error: ${e.message}`);
        if (!res.headersSent) {
          sendJSON(res, { success: false, error: e.message });
        }
        req.destroy();
      }
    });
    
    busboy.on('error', (err) => {
      console.error(`Busboy error: ${err.message}`);
      if (!res.headersSent) {
        sendJSON(res, { success: false, error: err.message });
      }
    });
    
    req.pipe(busboy);
    return;
  }
  
  // API: Upload (deprecated - use /api/v1/files/{path} POST)
  if (pathname === '/api/upload' && req.method === 'POST') {
    res.setHeader('Deprecation', 'true');
    res.setHeader('X-Deprecation-Warning', 'Use /api/v1/files/{path} with POST method instead');
    
    try {
      // Parse multipart form data
      const parsed = await parseMultipart(req);
      
      if (!parsed.file) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ success: false, error: 'No file uploaded' }));
        return;
      }
      
      // Sanitize filename to prevent injection attacks
      const sanitizedFilename = sanitizeFilename(parsed.file.originalname);
      if (!sanitizedFilename) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ success: false, error: 'Invalid filename' }));
        return;
      }
      
      // Get target directory from query
      const query = url.parse(req.url, true).query;
      let targetPath = query.path || '/';
      
      // Handle encoded path properly  
      if (targetPath.startsWith('%2F')) {
        targetPath = decodeURIComponent(targetPath);
      } else if (targetPath !== '/') {
        targetPath = '/' + targetPath;
      }
      
      const targetDir = safePath(targetPath);
      
      if (!targetDir) {
        res.writeHead(403, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ success: false, error: 'Access Denied' }));
        return;
      }
      
      // Ensure directory exists
      fs.mkdirSync(targetDir, { recursive: true });
      
      // Write file with sanitized filename (not temp -> move like multer)
      const finalPath = path.join(targetDir, sanitizedFilename);
      fs.writeFileSync(finalPath, parsed.file.buffer);
      
      console.log(`File uploaded: ${parsed.file.originalname} (${sanitizedFilename}) → ${finalPath}`);
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ success: true, filename: sanitizedFilename, original: parsed.file.originalname }));
    } catch (error) {
      console.error('Upload error:', error);
      res.writeHead(500, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ success: false, error: error.message }));
    }
    return;
  }
  
  // API: Delete (deprecated - use /api/v1/files/{path} DELETE)
  if (pathname === '/api/delete' && req.method === 'POST') {
    res.setHeader('Deprecation', 'true');
    res.setHeader('X-Deprecation-Warning', 'Use /api/v1/files/{path} with DELETE method instead');
    
    let body = '';
    for await (const chunk of req) body += chunk;
    const { path: filePath } = JSON.parse(body);
    const resolvedPath = safePath(filePath);
    
    if (!resolvedPath) {
      sendJSON(res, { success: false, error: 'Access Denied' });
      return;
    }
    
    try {
      // Check if directory or file
      const stat = fs.statSync(resolvedPath);
      if (stat.isDirectory()) {
        // Use recursive delete for directories
        fs.rmSync(resolvedPath, { recursive: true, force: true });
      } else {
        fs.unlinkSync(resolvedPath);
      }
      sendJSON(res, { success: true });
    } catch (e) {
      sendJSON(res, { success: false, error: e.message });
    }
    return;
  }
  
  // API: Rename (deprecated - use /api/v1/files/{path} PATCH)
  if (pathname === '/api/rename' && req.method === 'POST') {
    res.setHeader('Deprecation', 'true');
    res.setHeader('X-Deprecation-Warning', 'Use /api/v1/files/{path} with PATCH method instead');
    
    let body = '';
    for await (const chunk of req) body += chunk;
    const { path: oldPath, newName } = JSON.parse(body);
    const resolvedOldPath = safePath(oldPath);
    
    if (!resolvedOldPath || !newName) {
      sendJSON(res, { success: false, error: 'Invalid request' });
      return;
    }
    
    // Sanitize new filename to prevent directory traversal and injection
    const sanitizedNewName = sanitizeFilename(newName);
    if (!sanitizedNewName) {
      res.writeHead(400, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ success: false, error: 'Invalid filename' }));
      return;
    }
    
    try {
      const dir = path.dirname(resolvedOldPath);
      const newFullPath = path.join(dir, sanitizedNewName);
      // Re-validate path after join to ensure still within bounds
      if (!safePath(newFullPath)) {
        res.writeHead(403, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ success: false, error: 'Access Denied' }));
        return;
      }
      fs.renameSync(resolvedOldPath, newFullPath);
      sendJSON(res, { success: true });
    } catch (e) {
      sendJSON(res, { success: false, error: e.message });
    }
    return;
  }
  
  // API: Create directory (deprecated - use /api/v1/files/{path} PUT)
  if (pathname === '/api/mkdir' && req.method === 'POST') {
    res.setHeader('Deprecation', 'true');
    res.setHeader('X-Deprecation-Warning', 'Use /api/v1/files/{path} with PUT method instead');
    
    let body = '';
    for await (const chunk of req) body += chunk;
    const { path: dirPath, name } = JSON.parse(body);
    const resolvedDirPath = safePath(dirPath);
    
    if (!resolvedDirPath || !name) {
      sendJSON(res, { success: false, error: 'Invalid request' });
      return;
    }
    
    // Sanitize folder name to prevent directory traversal and injection
    const sanitizedFolderName = sanitizeFilename(name);
    if (!sanitizedFolderName) {
      res.writeHead(400, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ success: false, error: 'Invalid folder name' }));
      return;
    }
    
    try {
      fs.mkdirSync(path.join(resolvedDirPath, sanitizedFolderName));
      sendJSON(res, { success: true });
    } catch (e) {
      sendJSON(res, { success: false, error: e.message });
    }
    return;
  }
  
  // API: List files (deprecated - use /api/v1/files/{path})
  if (pathname === '/api/files') {
    res.setHeader('Deprecation', 'true');
    res.setHeader('X-Deprecation-Warning', 'Use /api/v1/files/{path} instead');
    
    const query = url.parse(req.url, true).query;
    const reqPath = query.path || '/';
    const resolvedPath = safePath(reqPath);
    
    if (!resolvedPath) {
      res.writeHead(403, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Access Denied' }));
      return;
    }
    
    const items = readDir(resolvedPath);
    if (!items) {
      res.writeHead(500, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Cannot read directory' }));
      return;
    }
    
    sendJSON(res, items);
    return;
  }
  
  // Default
  res.writeHead(404).end('Not Found');
});

// WebDAV Server Configuration
if (WEBDAV_ENABLED) {
  try {
    // Create simple user manager with our credentials
    const SimpleUserManager = webdavModule.SimpleUserManager;
    const userManager = new SimpleUserManager();
    userManager.addUser(USERNAME, PASSWORD, false);
    
    // Create Digest authentication (more secure than Basic)
    const authManager = new webdavModule.HTTPDigestAuthentication(userManager, 'Shared Files');
    
    // Create WebDAV server with root directory
    const webdavServer = new webdavModule.WebDAVServer({
      port: WEBDAV_PORT,
      authManager: authManager,
      root: ROOT_DIR  // This sets the physical root for file operations
    });
    
    // Start the WebDAV server
    webdavServer.start(() => {
      console.log(`WebDAV server started on port ${WEBDAV_PORT}`);
      console.log(`Mount at: http://localhost:${WEBDAV_PORT}/`);
    });
  } catch (err) {
    console.error('Failed to start WebDAV server:', err.message);
  }
}

// Start HTTP server
server.listen(PORT, () => {
  console.log('\n========================================');
  console.log('Shared Files Server Started');
  console.log('========================================');
  console.log(`Web Interface: http://localhost:${PORT}/`);
  if (WEBDAV_ENABLED) {
    console.log(`WebDAV Server:   http://localhost:${WEBDAV_PORT}/`);
  }
  console.log(`Root Directory: ${ROOT_DIR}`);
  console.log('=========================================\n');

  // Mounting instructions
  if (WEBDAV_ENABLED) {
    console.log('\nMounting Instructions:\n');
    console.log('macOS:');
    console.log('  Command + K → smb://localhost:' + WEBDAV_PORT + '/');
    console.log('  Or: mount_webdav http://localhost:' + WEBDAV_PORT + '/ /Volumes/shared-files\n');

    console.log('Windows Explorer:');
    console.log('  This PC → Add a network location');
    console.log('  URL: http://localhost:' + WEBDAV_PORT + '/\n');

    console.log('Linux (Nautilus):');
    console.log('  Connect to Server → smb://localhost:' + WEBDAV_PORT + '/\n');

    console.log('Command Line (any OS):');
    console.log('  mkdir -p ~/mnt/shared-files');
    console.log('  mount -t webdav http://localhost:' + WEBDAV_PORT + '/ ~/mnt/shared-files \\');
    console.log('    -o username=' + USERNAME + ',password=' + PASSWORD + '\n');
  }
});
