General Information
-------------------

Extract protocol syntax information by parsing Wireshark protocol dissector files

Requirements
-------------------

This script is written using python 3.9

Run
-------------------

The script consists of the following steps:

Step 1: Pre_process
-------------------

In this step, We preprocess all protocol dissector files and store the processed content under `pre_process/proto_files/`. Extract the names and dissector information for all protocols, and generate the `proto_table` and `dissect_table` under `pre_process/`.

This step can be performed with the following command:

~~~
python syntax_extraction/syntax_main.py - p DIR
~~~

Wherein, `DIR` is the local directory of the Wireshark protocol dissector files, please replace `DIR` with actual directory of the dissector files in order to perform this step correctly.

Wireshark protocol dissector file is officially provided by Wireshark and can be found at:
https://github.com/wireshark/wireshark/tree/master/epan/dissectors

Step 2: Main_parsing
-------------------

In this step, We parsing the target protocol and extract the protocol syntax information.
First, the target protocol is selected through a selector, and then start parsing, 
Output standard file under `main_parsing/standard_files/`, output standard fields under `main_parsing/standard_fields/`, and output syntax infortation under `syntax_info/`

This step can be performed with the following command:

~~~
python syntax_extraction/syntax_main.py - m
~~~

Note that this step requires the preprocessed file of the target protocol under `pre_process/proto_files/`, and `proto_table` and `dissect_table` under `pre_process/`.


