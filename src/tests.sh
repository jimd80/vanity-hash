#!/usr/bin/env bash
set -e

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

BIN="./bin/vanity-hash"
if [ ! -f "$BIN" ]; then
    BIN="./vanity-hash"
fi

if [ ! -f "$BIN" ]; then
    echo "Building project first..."
    make
    BIN="./bin/vanity-hash"
fi

echo "=========================================="
echo "Starting Vanity-Hash Test Suite"
echo "Binary: $BIN"
echo "=========================================="

TMPDIR="/tmp/vanity_test_$$"
mkdir -p "$TMPDIR"

cleanup() {
    rm -rf "$TMPDIR"
}
trap cleanup EXIT

compute_sha256() {
    local file="$1"
    sha256sum "$file" | awk '{print $1}'
}

# Test 1: Help message
echo -n "Test 1: Help message and options display properly... "
output=$($BIN --help)
if echo "$output" | grep -q "Modifies a file with a nonce so its hash contains magic words" && \
   echo "$output" | grep -q -- "-a --alphabet" && \
   echo "$output" | grep -q -- "-m --magic"; then
    echo -e "${GREEN}PASS${NC}"
else
    echo -e "${RED}FAIL${NC}"
    exit 1
fi

# Test 2: Empty file prefix search (-s dead, 16 bits)
echo -n "Test 2: Empty file prefix search (-s dead)... "
touch "$TMPDIR/empty.txt"
$BIN -s dead "$TMPDIR/empty.txt" "$TMPDIR/empty_out.txt" >/dev/null
hash=$(compute_sha256 "$TMPDIR/empty_out.txt")
if [[ "$hash" =~ ^dead ]]; then
    echo -e "${GREEN}PASS ($hash)${NC}"
else
    echo -e "${RED}FAIL ($hash)${NC}"
    exit 1
fi

# Test 3: Small text file suffix search (-e cafe, 16 bits)
echo -n "Test 3: Small text file suffix search (-e cafe)... "
echo "Hello, World!" > "$TMPDIR/hello.txt"
$BIN -e cafe "$TMPDIR/hello.txt" "$TMPDIR/hello_out.txt" >/dev/null
hash=$(compute_sha256 "$TMPDIR/hello_out.txt")
if [[ "$hash" =~ cafe$ ]]; then
    echo -e "${GREEN}PASS ($hash)${NC}"
else
    echo -e "${RED}FAIL ($hash)${NC}"
    exit 1
fi

# Test 4: 4-bit boundaries (odd hex length: -s 123)
echo -n "Test 4: 4-bit boundary prefix search (-s 123)... "
echo "Testing 4-bit boundary" > "$TMPDIR/odd.txt"
$BIN -s 123 "$TMPDIR/odd.txt" "$TMPDIR/odd_out.txt" >/dev/null
hash=$(compute_sha256 "$TMPDIR/odd_out.txt")
if [[ "$hash" =~ ^123 ]]; then
    echo -e "${GREEN}PASS ($hash)${NC}"
else
    echo -e "${RED}FAIL ($hash)${NC}"
    exit 1
fi

# Test 5: 4-bit boundaries suffix search (odd hex length: -e abc)
echo -n "Test 5: 4-bit boundary suffix search (-e abc)... "
echo "Testing suffix 4-bit boundary" > "$TMPDIR/odd_sfx.txt"
$BIN -e abc "$TMPDIR/odd_sfx.txt" "$TMPDIR/odd_sfx_out.txt" >/dev/null
hash=$(compute_sha256 "$TMPDIR/odd_sfx_out.txt")
if [[ "$hash" =~ abc$ ]]; then
    echo -e "${GREEN}PASS ($hash)${NC}"
else
    echo -e "${RED}FAIL ($hash)${NC}"
    exit 1
fi

# Test 6: Both prefix and suffix search (-s a -e b, 8 bits)
echo -n "Test 6: Both prefix and suffix (-s a -e b)... "
echo "Dual boundary test" > "$TMPDIR/dual.txt"
$BIN -s a -e b "$TMPDIR/dual.txt" "$TMPDIR/dual_out.txt" >/dev/null
hash=$(compute_sha256 "$TMPDIR/dual_out.txt")
if [[ "$hash" =~ ^a.*b$ ]]; then
    echo -e "${GREEN}PASS ($hash)${NC}"
else
    echo -e "${RED}FAIL ($hash)${NC}"
    exit 1
fi

# Test 7: Infile overwrite when outfile is omitted
echo -n "Test 7: Infile overwrite (outfile omitted)... "
echo "Original Content" > "$TMPDIR/overwrite.txt"
$BIN -s 77 "$TMPDIR/overwrite.txt" >/dev/null
hash=$(compute_sha256 "$TMPDIR/overwrite.txt")
if [[ "$hash" =~ ^77 ]]; then
    echo -e "${GREEN}PASS ($hash)${NC}"
else
    echo -e "${RED}FAIL ($hash)${NC}"
    exit 1
fi

# Test 8: Nonce offset at exact position (-o 0)
echo -n "Test 8: Nonce offset at exact position (-o 0)... "
head -c 128 </dev/urandom > "$TMPDIR/offset0.bin"
$BIN -o 0 -s 42 "$TMPDIR/offset0.bin" "$TMPDIR/offset0_out.bin" >/dev/null
hash=$(compute_sha256 "$TMPDIR/offset0_out.bin")
if [[ "$hash" =~ ^42 ]]; then
    echo -e "${GREEN}PASS ($hash)${NC}"
else
    echo -e "${RED}FAIL ($hash)${NC}"
    exit 1
fi

# Test 9: Nonce offset 'last' (overwriting end growing backwards)
echo -n "Test 9: Nonce offset 'last' (-o last)... "
head -c 100 </dev/urandom > "$TMPDIR/offset_last.bin"
$BIN -o last -s 88 "$TMPDIR/offset_last.bin" "$TMPDIR/offset_last_out.bin" >/dev/null
orig_sz=$(stat -c%s "$TMPDIR/offset_last.bin")
new_sz=$(stat -c%s "$TMPDIR/offset_last_out.bin")
hash=$(compute_sha256 "$TMPDIR/offset_last_out.bin")
if [[ "$hash" =~ ^88 ]] && [ "$orig_sz" -eq "$new_sz" ]; then
    echo -e "${GREEN}PASS ($hash, size $new_sz)${NC}"
else
    echo -e "${RED}FAIL (hash: $hash, size: $new_sz != $orig_sz)${NC}"
    exit 1
fi

# Test 10: Nonce offset explicit 'append' (-o append)
echo -n "Test 10: Nonce offset explicit 'append' (-o append)... "
head -c 50 </dev/urandom > "$TMPDIR/offset_append.bin"
$BIN -o append -n 4 -s 11 "$TMPDIR/offset_append.bin" "$TMPDIR/offset_append_out.bin" >/dev/null
orig_sz=$(stat -c%s "$TMPDIR/offset_append.bin")
new_sz=$(stat -c%s "$TMPDIR/offset_append_out.bin")
hash=$(compute_sha256 "$TMPDIR/offset_append_out.bin")
if [[ "$hash" =~ ^11 ]] && [ "$new_sz" -eq $((orig_sz + 4)) ]; then
    echo -e "${GREEN}PASS ($hash, size $new_sz)${NC}"
else
    echo -e "${RED}FAIL (hash: $hash, size: $new_sz != $((orig_sz + 4)))${NC}"
    exit 1
fi

# Test 11: Alphabet: num (0-9)
echo -n "Test 11: Alphabet num (0-9)... "
echo -n "data_" > "$TMPDIR/alpha_num.txt"
$BIN -a num -n 4 -s 55 "$TMPDIR/alpha_num.txt" "$TMPDIR/alpha_num_out.txt" >/dev/null
hash=$(compute_sha256 "$TMPDIR/alpha_num_out.txt")
nonce=$(tail -c 4 "$TMPDIR/alpha_num_out.txt")
if [[ "$hash" =~ ^55 ]] && [[ "$nonce" =~ ^[0-9]{4}$ ]]; then
    echo -e "${GREEN}PASS ($hash, nonce: '$nonce')${NC}"
else
    echo -e "${RED}FAIL ($hash, nonce: '$nonce')${NC}"
    exit 1
fi

# Test 12: Alphabet: lower (a-z)
echo -n "Test 12: Alphabet lower (a-z)... "
echo -n "data_" > "$TMPDIR/alpha_lower.txt"
$BIN -a lower -n 4 -s 33 "$TMPDIR/alpha_lower.txt" "$TMPDIR/alpha_lower_out.txt" >/dev/null
hash=$(compute_sha256 "$TMPDIR/alpha_lower_out.txt")
nonce=$(tail -c 4 "$TMPDIR/alpha_lower_out.txt")
if [[ "$hash" =~ ^33 ]] && [[ "$nonce" =~ ^[a-z]{4}$ ]]; then
    echo -e "${GREEN}PASS ($hash, nonce: '$nonce')${NC}"
else
    echo -e "${RED}FAIL ($hash, nonce: '$nonce')${NC}"
    exit 1
fi

# Test 13: Alphabet: upper (A-Z)
echo -n "Test 13: Alphabet upper (A-Z)... "
echo -n "data_" > "$TMPDIR/alpha_upper.txt"
$BIN -a upper -n 4 -s 44 "$TMPDIR/alpha_upper.txt" "$TMPDIR/alpha_upper_out.txt" >/dev/null
hash=$(compute_sha256 "$TMPDIR/alpha_upper_out.txt")
nonce=$(tail -c 4 "$TMPDIR/alpha_upper_out.txt")
if [[ "$hash" =~ ^44 ]] && [[ "$nonce" =~ ^[A-Z]{4}$ ]]; then
    echo -e "${GREEN}PASS ($hash, nonce: '$nonce')${NC}"
else
    echo -e "${RED}FAIL ($hash, nonce: '$nonce')${NC}"
    exit 1
fi

# Test 14: Alphabet: alphanum (a-Z, 0-9)
echo -n "Test 14: Alphabet alphanum (a-Z, 0-9)... "
echo -n "data_" > "$TMPDIR/alpha_an.txt"
$BIN -a alphanum -n 4 -s 66 "$TMPDIR/alpha_an.txt" "$TMPDIR/alpha_an_out.txt" >/dev/null
hash=$(compute_sha256 "$TMPDIR/alpha_an_out.txt")
nonce=$(tail -c 4 "$TMPDIR/alpha_an_out.txt")
if [[ "$hash" =~ ^66 ]] && [[ "$nonce" =~ ^[a-zA-Z0-9]{4}$ ]]; then
    echo -e "${GREEN}PASS ($hash, nonce: '$nonce')${NC}"
else
    echo -e "${RED}FAIL ($hash, nonce: '$nonce')${NC}"
    exit 1
fi

# Test 15: Timeout option (-t 1 with huge search space)
echo -n "Test 15: Timeout handling (-t 1)... "
set +e
$BIN -s 00000000000000 -t 1 "$TMPDIR/hello.txt" "$TMPDIR/timeout_out.txt" >/dev/null 2>&1
exit_code=$?
set -e
if [ $exit_code -ne 0 ]; then
    echo -e "${GREEN}PASS (Timed out as expected with exit code $exit_code)${NC}"
else
    echo -e "${RED}FAIL (Should have timed out and failed)${NC}"
    exit 1
fi

# Test 16: File already matches required hash
echo -n "Test 16: File already matches required hash... "
echo "This is already matching data" > "$TMPDIR/already.txt"
actual_hash=$(compute_sha256 "$TMPDIR/already.txt")
target_prefix=${actual_hash:0:4}
output=$($BIN -s "$target_prefix" "$TMPDIR/already.txt" "$TMPDIR/already_out.txt")
if echo "$output" | grep -q "File already matches the required hash" && \
   ! echo "$output" | grep -q "hashes searched"; then
    echo -e "${GREEN}PASS (Correctly detected without computation stats)${NC}"
else
    echo -e "${RED}FAIL (Unexpected output: $output)${NC}"
    exit 1
fi

# Test 17: Magic string replacement (-m --magic)
echo -n "Test 17: Magic string replacement (-m MAGIC_NONCE)... "
echo "PrefixHeader:MAGIC_NONCE:SuffixFooter" > "$TMPDIR/magic_in.txt"
$BIN -m "MAGIC_NONCE" -a alphanum -s 77 "$TMPDIR/magic_in.txt" "$TMPDIR/magic_out.txt" >/dev/null
hash=$(compute_sha256 "$TMPDIR/magic_out.txt")
orig_sz=$(stat -c%s "$TMPDIR/magic_in.txt")
new_sz=$(stat -c%s "$TMPDIR/magic_out.txt")
content=$(cat "$TMPDIR/magic_out.txt")
if [[ "$hash" =~ ^77 ]] && [ "$orig_sz" -eq "$new_sz" ] && [[ "$content" =~ ^PrefixHeader:[a-zA-Z0-9]{11}:SuffixFooter$ ]]; then
    echo -e "${GREEN}PASS ($hash, replaced magic string)${NC}"
else
    echo -e "${RED}FAIL (hash: $hash, content: '$content')${NC}"
    exit 1
fi

# Test 18: Magic string occurring more than once (error test)
echo -n "Test 18: Magic string occurring more than once... "
echo "First MAGIC and Second MAGIC" > "$TMPDIR/magic_dup.txt"
set +e
dup_out=$($BIN -m "MAGIC" -s 12 "$TMPDIR/magic_dup.txt" 2>&1)
exit_code=$?
set -e
if [ $exit_code -ne 0 ] && echo "$dup_out" | grep -qi "more than once"; then
    echo -e "${GREEN}PASS (Error correctly reported: '$dup_out')${NC}"
else
    echo -e "${RED}FAIL (Exit code $exit_code, output: '$dup_out')${NC}"
    exit 1
fi

# Test 19: Magic string not found (error test)
echo -n "Test 19: Magic string not found in file... "
echo "Some random content without target" > "$TMPDIR/magic_missing.txt"
set +e
missing_out=$($BIN -m "NOT_THERE" -s 12 "$TMPDIR/magic_missing.txt" 2>&1)
exit_code=$?
set -e
if [ $exit_code -ne 0 ] && echo "$missing_out" | grep -qi "not found"; then
    echo -e "${GREEN}PASS (Error correctly reported: '$missing_out')${NC}"
else
    echo -e "${RED}FAIL (Exit code $exit_code, output: '$missing_out')${NC}"
    exit 1
fi

# Test 20: 20-bit vanity search (-s deadb)
echo -n "Test 20: 20-bit vanity search (-s deadb)... "
echo "Performance test for 20-bit search" > "$TMPDIR/perf.txt"
$BIN -s deadb "$TMPDIR/perf.txt" "$TMPDIR/perf_out.txt" >/dev/null
hash=$(compute_sha256 "$TMPDIR/perf_out.txt")
if [[ "$hash" =~ ^deadb ]]; then
    echo -e "${GREEN}PASS ($hash)${NC}"
else
    echo -e "${RED}FAIL ($hash)${NC}"
    exit 1
fi

echo "=========================================="
echo -e "${GREEN}All tests passed successfully!${NC}"
echo "=========================================="