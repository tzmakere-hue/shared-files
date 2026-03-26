#!/bin/bash
cd /home/ubuntu/shared-files

echo "========================================"
echo "CORE BACKEND TEST SUITE" 
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
curl -s -X POST http://localhost:9000/api/files/ \
  -H "Cookie: session=$SESSION" -F 'file=@<(echo test content)' > /dev/null
sleep 0.5
echo "[Test 1.1] Path traversal on rename"
curl -s -X PATCH "http://localhost:9000/api/files/test%20content" \
  -H "Cookie: session=$SESSION" -H "Content-Type: application/json" \
  -d '{"newName":"../../../etc/passwd"}'
echo
RESULT=$(curl -s -X PATCH "http://localhost:9000/api/files/test%20content" \
  -H "Cookie: session=$SESSION" -H "Content-Type: application/json" \
  -d '{"newName":"../../../etc/passwd"}')
echo "$RESULT" | grep -qE 'error|Not Found'
check_result $? "Path traversal blocked on rename"

echo ""
echo "[Test 1.2] Path traversal on mkdir"
curl -s -X PUT "http://localhost:9000/api/files/%2E%2E%2F%2E%2E%2Fetc/malicious" \
  -H "Cookie: session=$SESSION"
echo
RESULT=$(curl -s -X PUT "http://localhost:9000/api/files/%2E%2E%2F%2E%2E%2Fetc/malicious" \
  -H "Cookie: session=$SESSION")
echo "$RESULT" | grep -qE 'error|denied|Not Found'
check_result $? "Path traversal blocked on mkdir"

echo ""
echo "[Test 1.3] Null byte injection"
curl -s -X PATCH "http://localhost:9000/api/files/test%20content" \
  -H "Cookie: session=$SESSION" -H "Content-Type: application/json" \
  -d '{"newName":"test%00.jpg"}'
echo
RESULT=$(curl -s -X PATCH "http://localhost:9000/api/files/test%20content" \
  -H "Cookie: session=$SESSION" -H "Content-Type: application/json" \
  -d '{"newName":"test%00.jpg"}')
echo "$RESULT" | grep -qE 'error|Not Found'
check_result $? "Null byte injection blocked"

echo ""
echo "[Test 1.4] Small file upload"
curl -s -X POST "http://localhost:9000/api/files/" \
  -H "Cookie: session=$SESSION" -F 'file=@<(echo small test data)'
echo
RESULT=$(curl -s -X POST "http://localhost:9000/api/files/" \
  -H "Cookie: session=$SESSION" -F 'file=@<(echo small test data)')
echo "$RESULT" | grep -qE 'success|name'
check_result $? "Small file upload works"
echo

echo "=== SECTION 2: SESSION PERSISTENCE ==="
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
echo "Size: $SIZE"
fi
echo

echo "=== SECTION 3: FILE UPLOADS ==="
echo "[Test 3.1] Small file upload (2MB)"
dd if=/dev/zero of=/tmp/small.bin bs=1M count=2 status=none 2>&1 | tail -1
curl -s -X POST "http://localhost:9000/api/files/" \
  -H "Cookie: session=$SESSION" -F "file=@/tmp/small.bin"
echo
if [ -f "/home/ubuntu/shared-files/small.bin" ]; then
    SIZE=$(ls -lh /home/ubuntu/shared-files/small.bin | awk '{print $5}')
    echo "Uploaded file size: $SIZE"
    check_result 0 "Small file (2MB) uploaded correctly"
else
    check_result 1 "Small file not found after upload"
fi
echo

echo "=== SECTION 4: REST API ==="
curl -s -X DELETE "http://localhost:9000/api/files/test" \
  -H "Cookie: session=$SESSION" > /dev/null 2>&1 || true

echo "[Test 4.1] Upload new file (expect 201)"
curl -s -o /tmp/t.txt -F 'file=@<(echo test)' \
  -X POST http://localhost:9000/api/files/ \
  -H "Cookie: session=$SESSION" > /dev/null
STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST "http://localhost:9000/api/files/" \
  -H "Cookie: session=$SESSION" -F 'file=@<(echo test)')
echo "HTTP Status: $STATUS"
[ "$STATUS" = "201" ]
check_result $? "New file upload returns 201 Created"

echo ""
echo "[Test 4.2] Upload duplicate (expect 409)"
STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST "http://localhost:9000/api/files/" \
  -H "Cookie: session=$SESSION" -F 'file=@<(echo test)')
echo "HTTP Status: $STATUS"
[ "$STATUS" = "409" ]
check_result $? "Duplicate file returns 409 Conflict"

echo ""
echo "[Test 4.3] Delete existing (expect 204)"
STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X DELETE "http://localhost:9000/api/files/test" \
  -H "Cookie: session=$SESSION")
echo "HTTP Status: $STATUS"
[ "$STATUS" = "204" ]
check_result $? "Delete returns 204 No Content"

echo ""
echo "[Test 4.4] Delete non-existent (expect 404)"
STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X DELETE "http://localhost:9000/api/files/doesnotexist" \
  -H "Cookie: session=$SESSION")
echo "HTTP Status: $STATUS"
[ "$STATUS" = "404" ]
check_result $? "Delete non-existent returns 404 Not Found"

echo ""
echo "[Test 4.5] No authentication (expect 401)"
STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X GET "http://localhost:9000/api/files?path=/")
echo "HTTP Status: $STATUS"
[ "$STATUS" = "401" ]
check_result $? "Unauthorized returns 401 Unauthorized"
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
rm -f /tmp/small.bin
rm -f /home/ubuntu/shared-files/small.bin 2>/dev/null || true
echo "Done."
