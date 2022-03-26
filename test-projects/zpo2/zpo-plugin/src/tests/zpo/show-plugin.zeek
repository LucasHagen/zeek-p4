# @TEST-EXEC: zeek -NN BR_INF_UFRGS::ZPO |sed -e 's/version.*)/version)/g' >output
# @TEST-EXEC: btest-diff output
