# @TEST-EXEC: zeek -NN ZPO::ZPO |sed -e 's/version.*)/version)/g' >output
# @TEST-EXEC: btest-diff output
