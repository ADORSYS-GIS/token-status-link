#!/bin/bash

# Script to check credential status from status list
# Usage: ./check_status.sh <status_list_uri> <idx>

URI=$1
IDX=$2

if [ -z "$URI" ] || [ -z "$IDX" ]; then
  echo "Usage: $0 <status_list_uri> <idx>"
  exit 1
fi

echo "Fetching status list from $URI"

# Fetch and decompress
curl -s -H "Accept: application/statuslist+jwt" "$URI" | gunzip > statuslist.jwt 2>/dev/null

if [ ! -f statuslist.jwt ]; then
  echo "Failed to fetch or decompress status list"
  exit 1
fi

# Decode payload
python3 -c "
import base64, zlib, json, sys

jwt = open('statuslist.jwt').read().strip()
header, payload, sig = jwt.split('.')

payload_decoded = base64.urlsafe_b64decode(payload + '==')
data = json.loads(payload_decoded)

bits = data['status_list']['bits']
lst = data['status_list']['lst']

idx = int(sys.argv[1])
print(f'Status list: bits={bits}, idx={idx}')

# Decompress
lst_bytes = base64.urlsafe_b64decode(lst + '==')
decompressed = zlib.decompress(lst_bytes)

print(f'Decompressed: {decompressed.hex()}')

# Check bit (LSB first)
byte_idx = idx // 8
bit_in_byte = idx % 8
bit_value = (decompressed[byte_idx] >> bit_in_byte) & 1

print(f'Bit at idx={idx}: {bit_value} (1=revoked, 0=valid)')
" "$IDX"

rm -f statuslist.jwt
