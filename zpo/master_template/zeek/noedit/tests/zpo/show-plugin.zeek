# @TEST-EXEC: zeek -NN BR_UFRGS_INF::ZPO |sed -e 's/version.*)/version)/g' >output
# @TEST-EXEC: btest-diff output
