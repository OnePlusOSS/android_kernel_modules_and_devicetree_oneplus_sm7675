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

def extract_second_column_to_new_file(input_filepath, output_filepath):
    """
    Extracts the second column from a file and writes it to another file
    with a space at the beginning of each line.

    :param input_filepath: Path to the input file
    :param output_filepath: Path to the output file
    """
    directory = os.path.dirname(output_filepath)
    if not os.path.exists(directory):
        os.makedirs(directory)
    try:
        with open(input_filepath, 'r') as infile, open(output_filepath, 'w') as outfile:
            for line in infile:
                # Split line into columns based on space
                columns = line.split()
                # Check if there are at least 2 columns
                if len(columns) >= 2:
                    # Write the second column to the output file with a leading space
                    outfile.write('  ' + columns[1] + '\n')
                else:
                    # Handle the case where there are not enough columns
                    print("Warning: Line skipped due to not enough columns: {}".format(line.strip()))
    except IOError as e:
        # Handle IO errors, e.g., file not found or permission issues
        print("IOError: {}".format(str(e)))

def write_unique_lines_from_second_file(file_base, file_upgrade, output_path):
    """
    Compares two files and writes lines that are unique to the second file into a new file.

    :param file_base: Path to the first input file
    :param file_upgrade: Path to the second input file
    :param output_path: Path to the output file
    """
    try:
        # Read all lines from the first file and store them in a set for faster lookup
        with open(file_base, 'r') as file1:
            file1_lines = set(line.strip() for line in file1)

        # Open the second file and the output file
        with open(file_upgrade, 'r') as file2, open(output_path, 'w') as output_file:
            for line in file2:
                # If the line from the second file is not found in the set, write to output file
                if line.strip() not in file1_lines:
                    output_file.write(line)
    except IOError as e:
        # Handle IO errors
        print("IOError: {}".format(str(e)))

def format_duration(td):
    minutes, seconds = divmod(td.seconds, 60)
    hours, minutes = divmod(minutes, 60)
    return '{:02} Hour {:02} Minute {:02} Second'.format(hours, minutes, seconds)

def main():
    start_time = datetime.now()
    print("Begin time:", start_time.strftime("%Y-%m-%d %H:%M:%S"))
    print("get update symbol start ...")

    os.system("cd ../../../")

    # Example usage:
    extract_second_column_to_new_file("kernel_platform/oplus/platform/aosp_gki/vmlinux.symvers", "out/oplus/symbols.txt")

    #write_unique_lines_from_second_file("out/oplus/symbols.txt", "kernel_platform/common/android/abi_gki_aarch64_oplus", "out/oplus/symbols_add.txt")
    write_unique_lines_from_second_file("kernel_platform/oplus/platform/aosp_gki/delete.txt", "kernel_platform/common/android/abi_gki_aarch64_oplus", "out/oplus/symbols_add.txt")

    end_time = datetime.now()
    print("End time:", end_time.strftime("%Y-%m-%d %H:%M:%S"))
    elapsed_time = end_time - start_time
    print("Total time:", format_duration(elapsed_time))

if __name__ == "__main__":
    main()
