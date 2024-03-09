# syntax_extraction

Extract protocol syntax information by parsing Wireshark protocol dissector files.

# Requirements

This script is written using python 3.9

# Run program

The script consists of the following steps:

# Step 1: Pre_process

In this step, We preprocess all protocol dissector files and store the processed content under `pre_process/proto_files/`. Extract the names and dissector information for all protocols, and generate the `proto_table` and `dissect_table` under `pre_process/`.

This step can be performed with the following command:

```
python syntax_extraction/syntax_main.py - p
```

Note that this step requires that all the protocol dissector files is in the ‘dissector_files’ directory. Please check the files exists. The protocol dissector file is officially provided by Wireshark and can be fund at:
```
https://github.com/wireshark/wireshark/tree/master/epan/dissectors
```

# Step 2: Main_parsing

In this step, we extract the entity types using the hierarchical
structure of the RFCs. The resulting entity types are stored under `system/tmp/ent/`. This step can be run directly by doing:

```
python syntax_extraction/syntax_main.py - m

```

Note that this step requires the preprocessed file of the target protocol under `pre_process/proto_files/`, and `proto_table` and `dissect_table` under `pre_process/`.


