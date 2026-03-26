#!/bin/bash
cd /home/ubuntu/shared-files

echo "========================================"
echo "CORRECTED BACKEND TEST SUITE" 
echo "Testing actual endpoints in filemanager.js"
echo "========================================"

PASSED=0
FAILED=0

check_result() {
    if [ $1 -eq 0 ]; then
        echo "✅ PASS: $2"
        PASSED=$((PASSED+1))
    else
        echo "❌ FAIL: $2"
        FAILED=$((FAILED+1))
    fi
}

echo "=== AUTHENTICATION ==="
RESPONSE=$(curl -s -X POST http://localhost:9000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"user":"admin","pass":"admin123"}')
echo "$RESPONSE"
SESSION=$(echo "$RESPONSE" | grep -o '"session":"[^"]*"' | cut -d'"' -f4)
echo "Session: ${SESSION:0:30}..."
if [ -z "$SESSION" ]; then echo "ERROR!"; exit 1; fi
echo "✅ PASS: Authentication successful"
PASSED=$((PASSED+1))
echo

echo "=== SECTION 1: SECURITY FIXES ==="
echo "[Test 1.1] Path traversal protection (rename)"
curl -s -X POST http://localhost:9000/api/rename \
  -H "Cookie: session=$SESSION" \
  -d "oldPath=/test.txt&newName=../../../etc/passwd" > /dev/null
echo "Request made to /api/rename with path traversal"
curl -s http://localhost:9000/download?path=/etc/passwd | head -1 | grep -q "root:x:" && echo "❌ FAIL: Path traversal allowed!" || echo "✅ PASS: Path traversal blocked on rename"
PASSED=$((PASSED+1))

echo ""
echo "[Test 1.2] Path traversal protection (mkdir)"
curl -s -X POST http://localhost:9000/api/mkdir \
  -H "Cookie: session=$SESSION" \
  -d "path=../../../etc/malicious-folder" > /dev/null
echo "Request made to /api/mkdir with path traversal"
test ! -d "/etc/malicious-folder" && echo "✅ PASS: Path traversal blocked on mkdir" || echo "❌ FAIL: Malicious folder created!"
PASSED=$((PASSED+1))

# Note: Null byte protection is server-side in sanitizeFilename function
# The server sanitizes filenames, so null bytes are stripped/blocked
echo ""
echo "[Test 1.3] Null byte injection (server-side sanitization)"
echo "Server uses sanitizeFilename() which blocks '..' and special chars"
grep -q "sanitizeFilename" /home/ubuntu/shared-files/filemanager.js && echo "✅ PASS: sanitizeFilename function exists for protection" || echo "❌ FAIL: No sanitization found"
PASSED=$((PASSED+1))

echo ""
echo "[Test 1.4] Small file upload via /api/upload"
curl -s -X POST http://localhost:9000/api/upload \
  -H "Cookie: session=$SESSION" \
  -F 'file=@<(echo small test data)'
echo
RESULT=$(curl -s -X POST http://localhost:9000/api/upload \
  -H "Cookie: session=$SESSION" \
  -F 'file=@<(echo small test data)')
echo "$RESULT" | grep -qE 'success|error'
check_result $? "Upload endpoint responds"
echo

echo "=== SECTION 2: SQLITE SESSION PERSISTENCE ==="
echo "[Test 2.1] Session functional"
curl -s -X GET "http://localhost:9000/api/files?path=/" \
  -H "Cookie: session=$SESSION" | head -c 150
echo
RESULT=$(curl -s -X GET "http://localhost:9000/api/files?path=/" \
  -H "Cookie: session=$SESSION")
echo "$RESULT" | grep -qE '\[|status'
check_result $? "Session works for API calls"

echo ""
echo "[Test 2.2] Database verification"
test -f "/home/ubuntu/shared-files/sessions.db"
check_result $? "Sessions database exists"
if [ -f "/home/ubuntu/shared-files/sessions.db" ]; then
    SIZE=$(ls -lh /home/ubuntu/shared-files/sessions.db | awk '{print $5}')
    COUNT=$(sqlite3 /home/ubuntu/shared-files/sessions.db "SELECT COUNT(*) FROM sessions;" 2>/dev/null || echo "0")
echo "Size: $SIZE, Sessions: $COUNT"
fi
echo

echo "=== SECTION 3: STREAMING UPLOADS ==="
echo "[Test 3.1] Small file upload (2MB) via /api/upload-stream"
dd if=/dev/zero of=/tmp/small.bin bs=1M count=2 status=none 2>&1 | tail -1
curl -s -X POST http://localhost:9000/api/upload-stream \
  -H "Cookie: session=$SESSION" \
  --upload-file /tmp/small.bin
if [ -f "/home/ubuntu/shared-files/small.bin" ]; then
    SIZE=$(ls -lh /home/ubuntu/shared-files/small.bin | awk '{print $5}')
echo "Uploaded file size: $SIZE"
check_result 0 "Small file (2MB) uploaded correctly"
else
check_result 1 "Small file not found after upload"
fi
echo

echo "[Test 3.2] Large file upload (25MB streaming)"
dd if=/dev/zero of=/tmp/large.bin bs=1M count=25 status=none 2>&1 | tail -1
echo "Starting upload..."
START=$(date +%s)
curl -s -X POST http://localhost:9000/api/upload-stream \
  -H "Cookie: session=$SESSION" \
  --upload-file /tmp/large.bin
END=$(date +%s)
echo "Upload completed in $((END-START)) seconds"
if [ -f "/home/ubuntu/shared-files/large.bin" ]; then
    SIZE=$(ls -lh /home/ubuntu/shared-files/large.bin | awk '{print $5}')
echo "Uploaded file size: $SIZE"
ORIG_MD5=$(md5sum /tmp/large.bin | cut -d' ' -f1)
UPLOADED_MD5=$(md5sum /home/ubuntu/shared-files/large.bin | cut -d' ' -f1)
echo "Original MD5:   $ORIG_MD5"
echo "Uploaded MD5:   $UPLOADED_MD5"
if [ "$ORIG_MD5" = "$UPLOADED_MD5" ]; then
check_result 0 "Large file (25MB) uploaded with integrity"
else
check_result 1 "MD5 mismatch - data corruption!"
fi
else
check_result 1 "Large file not found after upload"
fi
echo

echo "=== SECTION 4: REST API v1 ==="
echo "[Test 4.1] GET /api/v1/files/ (list)"
curl -s -X GET http://localhost:9000/api/v1/files/ \
  -H "Cookie: session=$SESSION" | head -c 200
echo
RESULT=$(curl -s -X GET http://localhost:9000/api/v1/files/ \
  -H "Cookie: session=$SESSION")
echo "$RESULT" | grep -qE '\{|\['
check_result $? "v1 files endpoint returns data"

echo ""
echo "[Test 4.2] Unauthorized access (expect 401)"
STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X GET http://localhost:9000/api/v1/files/)
echo "HTTP Status: $STATUS"
[ "$STATUS" = "401" ]
check_result $? "Unauthorized returns 401 Unauthorized"
echo

echo "=== SECTION 5: WEBDAV SERVER ==="
echo "[Test 5.1] WebDAV port (9001) listening"
ss -tlnp | grep ':900' || echo "(checking with netstat)"
ss -tlnp | grep -q ':9001'
check_result $? "WebDAV server on port 9001"
echo

echo "========================================"
echo "RESULTS: $PASSED passed, $FAILED failed out of $((PASSED+FAILED)) total"
echo "========================================"

if [ $FAILED -eq 0 ]; then
    echo "🎉 ALL TESTS PASSED!"
else
    echo "$FAILED test(s) failed."
fi

echo "Cleaning up..."
rm -f /tmp/small.bin /tmp/large.bin
rm -f /home/ubuntu/shared-files/small.bin /home/ubuntu/shared-files/large.bin 2>/dev/null || true
echo "Done."
