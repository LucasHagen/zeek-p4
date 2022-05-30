# @TEST-EXEC: zeek -NN RNA::RNA |sed -e 's/version.*)/version)/g' >output
# @TEST-EXEC: btest-diff output
