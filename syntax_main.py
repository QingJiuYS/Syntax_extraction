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
    parser.add_argument('--pre_process', '-p')
    # argp.add_argument('--select_protocol', '-s',action='store_true')
    parser.add_argument('--main_parsing', '-m')
    args = vars(parser.parse_args(args[1:]))

    time_start = time.time()

    # Check pre_process directory exists
    pre_processing_dir = os.path.abspath(os.path.join(sys_dir, 'pre_processing'))
    if not os.path.exists(pre_processing_dir):
        os.mkdir(pre_processing_dir) 
        
    # Check main_parsing directory exists
    main_parsing_dir = os.path.abspath(os.path.join(sys_dir, 'main_parsing'))
    if not os.path.exists(main_parsing_dir):
        os.mkdir(main_parsing_dir) 

    # Pre_processing
    if args['pre_process']:
        pre_process()

    # Main_parsing
    if args['main_parsing']:
        # Select protocol 
        proto_name, dissect_name = select_protocol()    

        main_parsing(proto_name, dissect_name)

    print("--------------------------------------")
    print("Process time: " + str(time.time() - time_start))
    print("--------------------------------------")


if __name__ == "__main__":
        main(sys.argv)
