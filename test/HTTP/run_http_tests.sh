    
#!/bin/bash

# All requests are sent to a local server on port 8000. Use Python http.server module
# sudo python -m netcreds_ng -i lo --no-tui --debug

TARGET_URL="http://127.0.0.1:8000/login"
FAKE_JWT="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"

echo "[*] Testing HTTP Basic Authentication..."
curl -s -o /dev/null --user "testuser:Str0ngP@ssw0rd!" $TARGET_URL
sleep 1

echo "[*] Testing HTTP Bearer Token (JWT)..."
curl -s -o /dev/null -H "Authorization: Bearer $FAKE_JWT" $TARGET_URL
sleep 1

echo "[*] Testing HTTP API Key..."
curl -s -o /dev/null -H "X-Api-Key: da237-b235b-38a3c-b631d-12345" $TARGET_URL
sleep 1

echo "[*] Testing HTTP Session Cookie..."
curl -s -o /dev/null --cookie "sessionid=a8123b; phpsessid=c9876d; user=admin" $TARGET_URL
sleep 1

echo "[*] Testing HTTP Form Submission..."
curl -s -o /dev/null -X POST -H "Content-Type: application/x-www-form-urlencoded" \
  -d "user=form_user&pass=form_password123&login=true" $TARGET_URL
sleep 1

echo "[*] Testing JWT in JSON Body..."
curl -s -o /dev/null -X POST -H "Content-Type: application/json" \
  -d '{"auth_token": "'"$FAKE_JWT"'", "user_id": "99"}' $TARGET_URL
sleep 1

echo "[+] All tests sent."

  