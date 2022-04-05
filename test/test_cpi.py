import sys, pprint, urllib3
import mylib
from src import cpiapi


def test_cpi():
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    cred = mylib.credentials(system='ncs01.case.edu')
    if cred is None: assert False
    myCpi = cpiapi.Cpi(username=sys.argv[1], password=sys.argv[2])
    if len(sys.argv) > 1:
        tableURL = sys.argv[3]          # relative URL of table
    else:
        tableURL = 'v1/op/cliTemplateConfiguration/deviceTypes'
    # tableURL = 'v4/op/rateService/rateLimits'
    reader = cpiapi.Cpi.Reader(myCpi, tableURL, verbose=True)
    pp = pprint.PrettyPrinter(indent=2, width=160)
    rownum = 0
    maxlen = 0
    for row in reader:
        if rownum < 5:
            pp.pprint(row)
        rownum += 1
        maxlen = max(maxlen, len(row))
        if rownum > 10000:
            break
    if rownum >= 10:
        print('...')
    if rownum > 10000:
        print(f"retrieval stopped after {rownum} records")
    print(f"returned {rownum} rows with up to {maxlen} attr:val pairs")
    print(f"reader.recCnt={reader.recCnt}")
    assert True
