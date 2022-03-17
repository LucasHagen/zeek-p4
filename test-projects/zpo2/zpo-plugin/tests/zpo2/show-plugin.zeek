# @TEST-EXEC: zeek -NN INF_UFRGS::ZPO2 |sed -e 's/version.*)/version)/g' >output
# @TEST-EXEC: btest-diff output
