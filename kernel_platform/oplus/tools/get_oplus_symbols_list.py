import os
import subprocess
import time
import shutil
import fnmatch
import pathlib
import sys
import csv
import codecs
import io
import glob
from datetime import datetime

out_put = "out/oplus"


def format_duration(td):
    minutes, seconds = divmod(td.seconds, 60)
    hours, minutes = divmod(minutes, 60)
    return '{:02} Hour {:02} Minute {:02} Second'.format(hours, minutes, seconds)

def main():
    start_time = datetime.now()
    print("Begin time:", start_time.strftime("%Y-%m-%d %H:%M:%S"))
    print("get update symbol start ...")

    end_time = datetime.now()
    print("End time:", end_time.strftime("%Y-%m-%d %H:%M:%S"))
    elapsed_time = end_time - start_time
    print("Total time:", format_duration(elapsed_time))

if __name__ == "__main__":
    main()
