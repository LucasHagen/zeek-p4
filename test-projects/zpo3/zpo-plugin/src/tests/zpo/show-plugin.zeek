# @TEST-EXEC: zeek -NN BR_INF_UFRGS::RNA |sed -e 's/version.*)/version)/g' >output
# @TEST-EXEC: btest-diff output
