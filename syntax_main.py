import argparse
import sys
import os
import time

from pre_process import pre_process
from select_protocol import select_protocol
from main_parsing import main_parsing


sys_dir = os.path.dirname(os.path.abspath(__file__))


def main(args):
    # Two step: Pre_processing and Main_parsing
    parser = argparse.ArgumentParser(description="Command-line argument parser")

    # Pre_processing, dest is the directory of Wireshark protocol dissector files
    parser.add_argument('--pre_process', '-p', type=str, default=None, help="Input the directory path for pre-processing")
    # Main_parsing
    # parser.add_argument('--main_parsing', '-m')
    parser.add_argument('--main_parsing', '-m', action='store_true', help="Enable main parsing")
    args = vars(parser.parse_args(args[1:]))

    time_start = time.time()

    # Pre_processing
    if args['pre_process']:
        source_file_dir = args['pre_process']

        # Check pre_process directory exists
        pre_processing_dir = os.path.abspath(os.path.join(sys_dir, 'pre_processing'))
        if not os.path.exists(pre_processing_dir):
            os.mkdir(pre_processing_dir) 

        pre_process_start = time.time()
        pre_process(source_file_dir)
        pre_process_end = time.time()

        print("Pre_processing time: " + str(pre_process_end - pre_process_start))

    # Main_parsing
    if args['main_parsing']:
        # Check main_parsing directory exists
        main_parsing_dir = os.path.abspath(os.path.join(sys_dir, 'main_parsing'))
        if not os.path.exists(main_parsing_dir):
            os.mkdir(main_parsing_dir)  

        # Select protocol 
        proto_name, dissect_name = select_protocol()    

        main_parsing_start = time.time()
        main_parsing(proto_name, dissect_name)
        main_parsing_end = time.time()
        print("Main_parsing time: " + str(main_parsing_end - main_parsing_start))

    # print("--------------------------------------")
    # print("Process time: " + str(time.time() - time_start))
    # print("--------------------------------------")


if __name__ == "__main__":
        main(sys.argv)
