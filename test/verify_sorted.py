#
# verify_sorted.py Copyright 2022 Dennis Risen, Case Western Reserve University
#
"""
In a set of csv files, sorted ascending by file name,
verify that the @id field is ascending within each file and between files.
Report ay discrepancies.
"""

from argparse import ArgumentParser
import csv
import glob
from typing import Union

parser = ArgumentParser(description="Verify records in csv files are in ascending order by <fieldname>")
parser.add_argument('--fieldname', action='store', default='@id',
                    help='field name to check. Default=@id')
parser.add_argument('--type', choices=['int', 'str'], default='int',
                    help="type(fieldname), Default=int")
parser.add_argument('filenames', nargs='+',
                    help='one of more file names and/or globs')
args = parser.parse_args()

caster = {'int': int, 'str': str}[args.type]
fileNames = []  # Accumulate all of the file names matching the file names/pattern(s)
for filePat in args.filenames:
    more = glob.glob(filePat)
    print(f"{filePat} --> {more}")
    fileNames += more

previous:Union[int, str, None] = None         # previous key value
fileNames.sort()        # Will process files in ascending order by file name
for fn in fileNames:
    with open(fn, 'rt', newline='') as csv_file:
        print(fn)
        reader = csv.DictReader(csv_file)
        line_num = 1                    # 1st record will be line 2 in the file
        for rec in reader:
            line_num += 1
            val = caster(rec[args.fieldname])
            if previous and val < previous:
                print(f" line {line_num:,} {args.fieldname}={val} < previous={previous}")
            previous = val
