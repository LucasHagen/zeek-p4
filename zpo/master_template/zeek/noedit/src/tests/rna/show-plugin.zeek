# @TEST-EXEC: zeek -NN BR_UFRGS_INF::RNA |sed -e 's/version.*)/version)/g' >output
# @TEST-EXEC: btest-diff output
