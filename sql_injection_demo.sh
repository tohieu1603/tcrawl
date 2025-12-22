#!/bin/bash

# SQL Injection Demo Script
# Mục đích: Test các lỗ hổng SQL Injection trên backend của bạn
# CHỈ SỬ DỤNG TRÊN HỆ THỐNG CỦA CHÍNH BẠN

API_URL="http://localhost:3001/api"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}   SQL INJECTION DEMO - SECURITY TEST  ${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""

# Test 1: Normal Request (baseline)
echo -e "${YELLOW}[TEST 1] Normal Request - Baseline${NC}"
echo "Request: GET /api/products?sortBy=name&limit=2"
start=$(python3 -c "import time; print(time.time())")
response=$(curl -s "$API_URL/products?sortBy=name&limit=2")
end=$(python3 -c "import time; print(time.time())")
duration=$(python3 -c "print(round($end - $start, 2))")
success=$(echo $response | python3 -c "import sys,json; print(json.load(sys.stdin).get('success', False))" 2>/dev/null || echo "false")
echo -e "Response time: ${duration}s | Success: $success"
echo ""

# Test 2: Time-based SQL Injection với pg_sleep
echo -e "${YELLOW}[TEST 2] Time-based SQL Injection - pg_sleep(3)${NC}"
echo "Payload: sortBy=name'; SELECT pg_sleep(3)--"
echo "Nếu injection thành công, response sẽ mất ~3s"
start=$(python3 -c "import time; print(time.time())")
response=$(curl -s "$API_URL/products?sortBy=name%27%3B%20SELECT%20pg_sleep(3)--&limit=2")
end=$(python3 -c "import time; print(time.time())")
duration=$(python3 -c "print(round($end - $start, 2))")
if (( $(echo "$duration > 2.5" | bc -l) )); then
    echo -e "${RED}⚠️  VULNERABLE! Response took ${duration}s (> 2.5s)${NC}"
else
    echo -e "${GREEN}✓ SAFE - Response took ${duration}s (injection blocked)${NC}"
fi
echo ""

# Test 3: UNION-based SQL Injection
echo -e "${YELLOW}[TEST 3] UNION-based SQL Injection${NC}"
echo "Payload: sortBy=name UNION SELECT table_name FROM information_schema.tables--"
response=$(curl -s "$API_URL/products?sortBy=name%20UNION%20SELECT%20table_name%20FROM%20information_schema.tables--&limit=2")
success=$(echo $response | python3 -c "import sys,json; print(json.load(sys.stdin).get('success', False))" 2>/dev/null || echo "false")
if [ "$success" = "True" ] || [ "$success" = "true" ]; then
    echo -e "${RED}⚠️  POTENTIALLY VULNERABLE - Query executed${NC}"
    echo "Response: $response" | head -c 200
else
    echo -e "${GREEN}✓ SAFE - Injection blocked${NC}"
fi
echo ""

# Test 4: Boolean-based SQL Injection
echo -e "${YELLOW}[TEST 4] Boolean-based SQL Injection${NC}"
echo "Payload: sortBy=name AND 1=1"
response1=$(curl -s "$API_URL/products?sortBy=name%20AND%201%3D1&limit=2")
echo "Payload: sortBy=name AND 1=2"
response2=$(curl -s "$API_URL/products?sortBy=name%20AND%201%3D2&limit=2")
success1=$(echo $response1 | python3 -c "import sys,json; print(json.load(sys.stdin).get('success', False))" 2>/dev/null || echo "false")
success2=$(echo $response2 | python3 -c "import sys,json; print(json.load(sys.stdin).get('success', False))" 2>/dev/null || echo "false")
if [ "$success1" != "$success2" ]; then
    echo -e "${RED}⚠️  POTENTIALLY VULNERABLE - Different responses for 1=1 vs 1=2${NC}"
else
    echo -e "${GREEN}✓ SAFE - Both queries blocked or same response${NC}"
fi
echo ""

# Test 5: Invalid Field Name
echo -e "${YELLOW}[TEST 5] Invalid Field Name${NC}"
echo "Payload: sortBy=nonexistent_column"
response=$(curl -s "$API_URL/products?sortBy=nonexistent_column&limit=2")
success=$(echo $response | python3 -c "import sys,json; print(json.load(sys.stdin).get('success', False))" 2>/dev/null || echo "false")
if [ "$success" = "True" ] || [ "$success" = "true" ]; then
    echo -e "${RED}⚠️  WARNING - Server accepted invalid column (no whitelist)${NC}"
else
    echo -e "${GREEN}✓ GOOD - Server rejected invalid column${NC}"
fi
echo ""

# Test 6: Comment-based bypass
echo -e "${YELLOW}[TEST 6] SQL Comment Bypass${NC}"
echo "Payload: sortBy=name/**/OR/**/1=1"
response=$(curl -s "$API_URL/products?sortBy=name/**/OR/**/1%3D1&limit=2")
success=$(echo $response | python3 -c "import sys,json; print(json.load(sys.stdin).get('success', False))" 2>/dev/null || echo "false")
if [ "$success" = "True" ] || [ "$success" = "true" ]; then
    echo -e "${RED}⚠️  POTENTIALLY VULNERABLE - Comment bypass worked${NC}"
else
    echo -e "${GREEN}✓ SAFE - Comment bypass blocked${NC}"
fi
echo ""

# Test 7: Stacked Queries
echo -e "${YELLOW}[TEST 7] Stacked Queries (Multiple Statements)${NC}"
echo "Payload: sortBy=name; DROP TABLE products;--"
echo "(Đừng lo, PostgreSQL thường không cho phép stacked queries qua parameters)"
response=$(curl -s "$API_URL/products?sortBy=name%3B%20DROP%20TABLE%20products%3B--&limit=2")
success=$(echo $response | python3 -c "import sys,json; print(json.load(sys.stdin).get('success', False))" 2>/dev/null || echo "false")
if [ "$success" = "True" ] || [ "$success" = "true" ]; then
    echo -e "${RED}⚠️  POTENTIALLY VULNERABLE${NC}"
else
    echo -e "${GREEN}✓ SAFE - Stacked query blocked${NC}"
fi
echo ""

# Test 8: XSS trong product name (Stored XSS)
echo -e "${YELLOW}[TEST 8] Stored XSS Test${NC}"
echo "Tạo product với XSS payload trong name..."
xss_response=$(curl -s -X POST "$API_URL/products" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "<script>alert(document.cookie)</script>Test Product",
    "basePrice": 100,
    "status": "draft"
  }')
echo "Response: $xss_response" | head -c 300
product_name=$(echo $xss_response | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('data',{}).get('name',''))" 2>/dev/null || echo "")
if [[ "$product_name" == *"<script>"* ]]; then
    echo -e "\n${RED}⚠️  VULNERABLE - XSS payload stored without sanitization${NC}"
else
    echo -e "\n${GREEN}✓ SAFE - XSS payload was sanitized or blocked${NC}"
fi
echo ""

# Test 9: Mass Assignment
echo -e "${YELLOW}[TEST 9] Mass Assignment Test${NC}"
echo "Trying to set internal fields like id, createdAt..."
mass_response=$(curl -s -X POST "$API_URL/products" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Mass Assignment Test",
    "basePrice": 100,
    "id": "00000000-0000-0000-0000-000000000001",
    "createdAt": "2020-01-01T00:00:00Z",
    "viewCount": 999999
  }')
created_id=$(echo $mass_response | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('data',{}).get('id',''))" 2>/dev/null || echo "")
if [ "$created_id" = "00000000-0000-0000-0000-000000000001" ]; then
    echo -e "${RED}⚠️  VULNERABLE - Attacker can set custom ID${NC}"
else
    echo -e "${GREEN}✓ SAFE - ID was auto-generated: $created_id${NC}"
fi
echo ""

# Summary
echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}           TEST SUMMARY               ${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""
echo "Đây chỉ là demo cơ bản. Để test đầy đủ cần:"
echo "1. SQLMap - automated SQL injection testing"
echo "2. Burp Suite - comprehensive web security testing"
echo "3. OWASP ZAP - free security scanner"
echo ""
echo -e "${YELLOW}Khuyến nghị fix:${NC}"
echo "1. Thêm whitelist validation cho sortBy"
echo "2. Thêm authentication cho tất cả routes"
echo "3. Sanitize input trước khi lưu database"
echo "4. Strip internal fields trong create/update"
