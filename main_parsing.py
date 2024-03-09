import json
import os
import re
import time
import fileinput


# Convert multiple lines to a single line
def merge_code(lines, symbol):
    merged_lines = []
    in_line = False
    current_line = ""

    # Multiple lines ending with "= , & | ?"
    if symbol == "=":
        for line in lines:
            line = line.rstrip()
            if line.endswith("=") and not in_line:
                current_line += line
                in_line = True
                continue
            if in_line:
                line = line.strip()
                current_line += line
                if line.endswith(";"):
                    in_line = False
                else:
                    continue
            if current_line:
                merged_lines.append(current_line)
                current_line = ''
                continue
            merged_lines.append(line)
    
    elif symbol == ",":
        for line in lines:
            line = line.rstrip()
            if line.endswith(",") and not in_line:
                current_line += line
                in_line = True
                continue
            if in_line:
                line = line.strip()
                current_line += line
                if line.endswith(";") or line.endswith("{"):
                    in_line = False
                else:
                    continue
            if current_line:
                merged_lines.append(current_line)
                current_line = ''
                continue
            merged_lines.append(line)
    
    elif symbol == "&":
        for line in lines:
            line = line.strip()
            if line.endswith("&") and not in_line:
                current_line += line
                in_line = True
                continue
            if in_line:
                if ";" in line:
                    in_line = False
                    if current_line:
                        merged_lines.append(current_line)
                        current_line = ''
                else:
                    current_line += line
                    continue
            merged_lines.append(line)

    elif symbol == "|":
        for line in lines:
            line = line.strip()
            if line.endswith("|") and not in_line:
                current_line += line
                in_line = True
                continue
            if in_line:
                if ";" in line:
                    in_line = False
                    if current_line:
                        merged_lines.append(current_line)
                        current_line = ''
                else:
                    current_line += line
                    continue
            merged_lines.append(line)        
    
    elif symbol == "?":
        for line in lines:
            line = line.strip()
            if line.endswith("?") and not in_line:
                current_line += line
                in_line = True
                continue
            if in_line:
                if ";" in line:
                    in_line = False
                    if current_line:
                        merged_lines.append(current_line)
                        current_line = ''
                else:
                    current_line += line
                    continue
            merged_lines.append(line)        
    
    # Multiple lines ending with a number 
    else:
        for line in lines:
            line = line.strip()
            if line.endswith(tuple(str(i) for i in range(10))) and not in_line:
            # if line.endswith("8") and not in_line:
                current_line += line
                in_line = True
                continue
            if in_line:
                if ";" in line:
                    in_line = False
                    if current_line:
                        merged_lines.append(current_line)
                        current_line = ''
                else:
                    current_line += line
                    continue
            merged_lines.append(line) 
    return merged_lines


# convert multiple lines of code into a single line
def convert_to_single_line(source_file_path, symbol):
    try:
        with open(source_file_path, 'r', encoding='utf-8') as file:
            lines = file.readlines()

        merged_lines = merge_code(lines, symbol)
        with open(source_file_path, 'w', encoding='utf-8') as file:
            file.seek(0)

            merged_lines_with_newlines = [line + '\n' for line in merged_lines]
            file.writelines(merged_lines_with_newlines)

    except FileNotFoundError:
        print(f"Error: File '{source_file_path}' not found.")
    except Exception as e:
        print(f"An error occurred: {e}")


# Extract protocol name and associated with file, save to dissect_table
def extract_proto_info(file_name, code, proto_table):
    proto_names = {}
    proto_handle = ''
    proto_handle = code.split('=')[0].strip()

    content = extract_parameter(code)
    long_name = content[0].strip(' "').strip()
    short_name = content[1].strip(' "').strip()
    abbrev_name = content[2].strip(' "').strip()

    # protocol names:long name, short name, abbreviation
    proto_names = {
        "long_name": long_name,
        "short_name": short_name,
        "abbrev_name": abbrev_name
    }

    # associated with file name
    proto_info = {
        "file_name": file_name,
        "proto_handle": proto_handle,
        "proto_name": long_name,
        "short_name": short_name,
        "abbrev_name": abbrev_name
    }

    # save to protocol table
    proto_table.append(proto_info)
    return proto_names, proto_handle


# Extract dissector name and associate with protocol
def extract_dissect_info(proto_table, code, this_dissect, dissect_all, tag):
    dissect_handle = ''

    content = extract_parameter(code)
    if tag:
        if "=" in code:
            dissect_handle = code.split('=')[0].strip()
        else:
            dissect_handle = ''
        dissect_name = content[0].strip(' "')
        dissect_func_name = content[1].strip()
        proto_handle = content[2].strip()
        dissect_info = {
            "dissect_name": dissect_name,
            "type": "global",
            "func_name": dissect_func_name,
            "dissect_handle": dissect_handle,
            "proto_handle": proto_handle,
            "upper": [],
            "lower": ''
        }
        dissect_all.append(dissect_func_name)
    else:
        if "=" in code:
            dissect_handle = code.split('=')[0].strip()
        else:
            dissect_handle = ''
        dissect_func_name = content[0].strip()
        proto_handle = content[1].strip()
        dissect_info = {
            "dissect_name": "",
            "type": "local",
            "func_name": dissect_func_name,
            "dissect_handle": dissect_handle,
            "proto_handle": proto_handle,
            "upper": [],
            "lower": ''
        }
        dissect_all.append(dissect_func_name)
        
    # associate with protocol
    for proto in proto_table:
        if dissect_info["proto_handle"] == proto["proto_handle"]:
            dissect_info["proto_name"] = proto["proto_name"]
            dissect_info["proto_short_name"] = proto["short_name"]
            dissect_info["proto_abbrev_name"] = proto["abbrev_name"]
            dissect_info["file_name"] = proto["file_name"]
            this_dissect.append(dissect_info)
            break
    return dissect_handle


# extract dissector information from target line, associated with protocol name and save to dissector table 
def save_dissect_to_table(dissect_code, this_dissect, dissect_all, proto_table):
    content = extract_parameter(dissect_code)
    lower = content[0].strip().strip('"').strip()
    dissect_func_name = content[1].strip().strip('"').strip()
    proto_description = content[2].strip().strip('"').strip()
    dissect_name = content[3].strip().strip('"').strip()
    proto_handle = content[4].strip().strip('"').strip()
    
    dissect_info = {
            "dissect_name": dissect_name,
            "type": "local",
            "func_name": dissect_func_name,
            "proto_description": proto_description,
            "proto_handle": proto_handle,
            "upper": [],
            "lower": lower
        }
    dissect_all.append(dissect_func_name)

    # assocaited with ptotocol name
    for proto in proto_table:
        if dissect_info["proto_handle"] == proto["proto_handle"]:
            dissect_info["proto_name"] = proto["proto_name"]
            dissect_info["proto_abbrev_name"] = proto["abbrev_name"]
            dissect_info["file_name"] = proto["file_name"]            
            this_dissect.append(dissect_info)
            break


# save dissector with port information to dissector table
def save_port_info_to_dissect_table(dissect_code, this_dissect):
    content = extract_parameter(dissect_code)
    port_type = content[0].strip().strip('"').strip()
    port_num = content[1].strip()
    dissect_handle = content[2].strip()
    for dissector in this_dissect:
        if 'dissect_handle' in dissector and dissector['dissect_handle'] == dissect_handle:
            dissector['port_num'] = port_num
            dissector['port_type'] = port_type


# improve the hierarchical relationship of each dissecor in the dissector table
def improve_relation(dissect_table):
    for dissect in dissect_table:
        if dissect['lower'] not in ['tcp', 'udp', None] and dissect['type'] == 'global':
            if dissect['upper'] != []:
                for dissect_tar in dissect_table:
                    for dissect_name in dissect['upper']:
                        if dissect_tar['dissect_name'] == dissect_name:
                            dissect_tar['lower'] = dissect['proto_abbrev_name']


# split multiple lines of code displayed on a single line into a single line
def convert_to_multi_line(file_path, string):
    new_lines = []
    with open(file_path, 'r', encoding='utf-8') as file:
        lines = file.readlines()
    for line in lines:
        line = line.strip()
        if line.startswith("if ") and line.endswith(";"):
            condition, rest = line.split(")", 1)
            new_lines.append(condition + ')')
            new_lines.append(rest)
        else:
            new_lines.append(line)
    with open(file_path, 'w', encoding='utf-8') as file:
        for line in new_lines:
            file.write(line + '\n')


# delete comments, between "#if" and "#endif"
def remove_conditional_comments(output_file_path):
    in_comment = False
    with fileinput.FileInput(output_file_path, inplace=True, backup='.bak') as file:
        for line in file:
            line_stripped = line.strip()
            if line_stripped.startswith("#if"):
                in_comment = True
            elif in_comment:
                if line_stripped.startswith("#endif"):
                    in_comment = False
            elif line_stripped:
                print(line, end='')

# Select target protocol and dissector by accessing the protocol table and dissector table
def extract_target_proto_info(proto_table, dissect_table, proto_files_dir, proto_name, dissect_name, target_proto_info):
    lower_proto = False
    lower_proto_name = ''
    lower_dissect_name = ''
    func_name = ''
    file_name = ''

    # Traverse dissector table, find lower layer protocol information
    for dissect in dissect_table:
        if dissect["dissect_name"] == dissect_name:
            func_name = dissect['func_name']
            # dissector over tcp and udp
            if dissect['lower'] and (dissect['lower'] not in ('tcp', 'udp')):
                for low_dissect in dissect_table:
                    if ('dissect_handle' not in low_dissect) or ('proto_abbrev_name' not in low_dissect):
                        continue
                    elif low_dissect['proto_abbrev_name'] == dissect['lower']:
                        lower_proto_name = low_dissect['proto_short_name'] 
                        lower_dissect_name = low_dissect['dissect_name'] 
                        lower_proto = True
                        break

    # traverse protocol table, find target file
    for proto in proto_table:
        if proto["short_name"] == proto_name:
            file_name = proto['file_name']
    file_path = os.path.join(proto_files_dir, file_name)

    proto_info = {
        'proto_name': proto_name,
        'dissect_name': dissect_name,
        'file_name': file_name,
        'func_name': func_name,
        'file_path': file_path
    }

    target_proto_info.append(proto_info)

    # if there is a lower-layer protocol, continue traversing
    if lower_proto:
        extract_target_proto_info(proto_table, dissect_table, proto_files_dir, lower_proto_name, lower_dissect_name, target_proto_info)

    return target_proto_info


# extract standard fields from "hf_register_info" sturcture
def extract_fields(lines):
    field_list = []
    fields_all = []
    in_array = False
    in_block = False
    current_line = ''

    # standardize the structure of each field information
    for line in lines:
        line = line.strip()
        if line.startswith("static hf_register_info"):
            in_array = True
            continue
        elif in_array:
            if line.startswith("{") and not line.endswith("},"):
                current_line += line.rstrip()
                in_block = True
            elif in_block:
                current_line += line.rstrip()
                if line.endswith("},"):
                    in_block = False
            elif line.startswith("{") and line.endswith("},"):
                fields_all.append(line)
                continue
        if current_line and not in_block:
            fields_all.append(current_line)
            current_line = ''
        if line.endswith("};"):
            in_array = False
    
    # extract field information from standardized structures
    for field in fields_all:
        field = field.replace('{', '').replace('}', '').replace('"', '').replace('&', '').strip()
        item = field.split(",")
        identifier = item[0].strip()
        name = item[1].strip()
        filter_name = item[2].strip()
        data_type = item[3].strip()
        if data_type == 'FT_NONE':
            field_length = 0
        elif data_type == 'FT_UINT8':
            field_length = 1
        elif data_type == 'FT_UINT16':
            field_length = 2   
        elif data_type == 'FT_UINT32':
            field_length = 4             
        elif data_type == 'FT_UINT64':
            field_length = 8
        elif data_type == 'FT_BOOLEAN':
            field_length = 1  
        elif data_type == 'FT_STRING':
            field_length = 'variable'  
        elif data_type == 'FT_FRAMENUM':
            field_length = 4             
        else:
            field_length = -1  
        base_or_unit = item[4].strip()
        options_value = item[5].strip()
        flags_or_attributes = item[6].strip()
        display_filter = item[7].strip()
        macro_for_structure_filling = item[8].strip()
        field_info = {
            "field_identifier": identifier,
            "field_name": name,
            "field_filter_name": filter_name,
            "field_type": data_type,
            "field_length": field_length,
            "field_base": base_or_unit,
            "field_options_value": options_value,
            "field_flags": flags_or_attributes,
            "field_display_filter": display_filter,
            "field_macro_for_structure_filling": macro_for_structure_filling,
        }
        field_list.append(field_info)
    return field_list


# Extract the function body of the target function name
def extract_func_body(lines, func_name):
    in_body = False
    count = 0
    function_body = []
    for line in lines:
        line = line.strip()
        if (line.startswith(func_name + "(") and  not line.endswith(";")) or\
           (line.startswith("static int " + func_name)) or \
           (line.startswith("static gint " + func_name)) or \
           (line.startswith("static gboolean " + func_name)):
            in_body = True
            function_body.append(line)
            continue
        if in_body:
            function_body.append(line)
            if "{" in line:
                count += 1
            if "}" in line:
                count -= 1
                if count == 0:
                    in_body = False
                    break
    print("last third line:", function_body[-3])
    print("last second line", function_body[-2])
    print("last line:", function_body[-1])                
    return function_body


# Add braces for basic blocks (if/else if/else, for)
def add_brace(file_path, string):
    with open(file_path, 'r') as file:
        code = file.readlines()
    modified_code = []
    in_line = False
    pass_next_line = False

    # if basic block
    if string == "if":
        for i in range(len(code)- 1):
            line = code[i].rstrip('\n')
            next_line = code[i+1].strip()
            if in_line:
                modified_code.append(line + '\n}')
                in_line = False
            elif line.strip().startswith("if") and line.strip().endswith(")"):
                if next_line == '{':
                    modified_code.append(line + ' {')
                    pass_next_line = True
                    continue
                else:
                    modified_code.append(line + ' {')
                    in_line = True
            else:
                if pass_next_line:
                    pass_next_line = False
                    continue
                else:
                    modified_code.append(line)
        modified_code.append(code[-1])

    # else if basic block
    if string == "else if":
        for line in code:
            line = line.rstrip('\n')
            if line.strip().startswith("} else if"):
                modified_code.append("}")
                line = line.replace("} ", '')
            if in_line:
                modified_code.append(line + '\n}')
                in_line = False
            elif "else if" in line and line.strip().endswith(")"):
                modified_code.append(line + ' {')
                in_line = True
            else:
                modified_code.append(line)

    # else basic block
    if string == "else":
        for i in range(len(code)- 1):
            line = code[i].rstrip('\n')
            next_line = code[i+1].strip()            
            if line.strip().startswith("} else"):
                modified_code.append("}")
                line = line.replace("} ", "")
            if in_line:
                modified_code.append(line + '\n}')
                in_line = False
            elif "else" in line and not line.endswith("{"):
                if next_line == '{':
                    modified_code.append(line + ' {')
                    pass_next_line = True
                    continue
                else:
                    modified_code.append(line + ' {')
                    in_line = True
            else:
                if pass_next_line:
                    pass_next_line = False
                    continue
                else:
                    modified_code.append(line)

    # for basic block
    if string == "for":
        for line in code:
            line = line.rstrip('\n')
            if in_line:
                modified_code.append(line + '\n}')
                in_line = False
            elif line.strip().startswith("for ") and line.strip().endswith(")"):
                modified_code.append(line + ' {')
                in_line = True
            else:
                modified_code.append(line)
    
    # elif string == 'else':
    #     for line in code:
    #         line = line.rstrip('\n')
    #         if line.startswith("if") and "{" in line:
    #             in_if = True
    
    with open(file_path, 'w') as file:
        for line in modified_code:
            file.write(line + '\n')


# find main dissector function name
def find_main_dissector(lines, dissect_func_name):
    main_dissector = dissect_func_name
    in_function = False
    num_braces = 0
    for line in lines:
        line = line.strip()
        if (line.startswith(dissect_func_name + "(")) or (line.startswith("static gint " + dissect_func_name + "(")):
            in_function = True
        elif in_function:
            if "{" in line:
                num_braces += 1
            if "}" in line:
                num_braces -= 1            
            if (dissect_func_name in line) or ('dissect_' in line):
                items = re.split(r'[,(\s)]', line)
                for item in items:
                    if "dissect_" in item:
                        main_dissector = find_main_dissector(lines, item)
            elif "offset" in line:
                break

            if num_braces == 0 and in_function:
                in_function = False
                break
    return main_dissector


# add else statement to if/else if/else sturcture 
def add_else_to_if(input_path, output_path):
    with open(input_path, 'r') as file:
        lines = file.readlines()
    modified_lines = []
    inside_if_block = 0
    inside_other_block = 0
    block_stack = []

    for i, line in enumerate(lines):
        line_stripped = line.strip()
        if line_stripped.startswith('if') and "{" in line:
            inside_if_block += 1
            modified_lines.append(line)
            block_stack.append('if')
        elif line_stripped.startswith('else if'):
            inside_if_block += 1
            modified_lines.append(line)
            block_stack.append('else if')
        elif line_stripped.startswith('else'):
            inside_if_block += 1
            modified_lines.append(line)
            block_stack.append('else')
        elif line_stripped == '}':
            if block_stack:
                block_type = block_stack[-1]
                block_stack.pop()
                modified_lines.append(line)
                if block_type == 'if':
                    next_non_empty_line = find_next_non_empty_line(lines, i + 1)
                    if next_non_empty_line and next_non_empty_line.strip().startswith('else if'):
                        continue
                    elif next_non_empty_line and next_non_empty_line.strip().startswith('else'):
                        continue
                    else:
                        modified_lines.append('else {\n')
                        modified_lines.append('}\n')  
                elif block_type == 'else if':
                    next_non_empty_line = find_next_non_empty_line(lines, i + 1)
                    if next_non_empty_line is not None and not next_non_empty_line.strip().startswith('else'):
                        modified_lines.append('else {\n')
                        modified_lines.append('}\n')
                elif block_type == ('switch', 'for', 'while'):
                    inside_other_block -= 1
            else:
                modified_lines.append(line)
        elif line_stripped.startswith('switch'):
            inside_other_block += 1
            modified_lines.append(line)
            block_stack.append('switch')
        elif line_stripped.startswith('while'):
            inside_other_block += 1
            modified_lines.append(line)
            block_stack.append('while')
        elif line_stripped.startswith('for'):
            inside_other_block += 1
            modified_lines.append(line)
            block_stack.append('for')
        else:
            modified_lines.append(line)

    with open(output_path, 'w') as file:
        file.writelines(modified_lines)


# find the next non-blank line
def find_next_non_empty_line(lines, start_index):
    for i in range(start_index, len(lines)):
        if lines[i].strip():
            return lines[i]
    return None


# extract parameter between "(" and ")" 
def extract_parameter(line):
    content = ''
    left_bracket_index = line.find('(')
    if left_bracket_index != -1:
        right_bracket_index = line.rfind(')')
        if right_bracket_index != -1:
            content = line[left_bracket_index + 1:right_bracket_index].split(',')
    return content


# extract codition between "(" and ")" 
def extract_condition(line):
    content = ''
    left_bracket_index = line.find('(')
    if left_bracket_index != -1:
        right_bracket_index = line.rfind(')')
        if right_bracket_index != -1:
            content = line[left_bracket_index + 1:right_bracket_index].strip()
    return content


# extract number 
def extract_number_from_line(line):
    match = re.search(r'\b\d+\b', line)
    if match:
        return int(match.group())
    else:
        return 0


# add the function body under subfunction call statements
def add_sub_func_body(lines, dissect_name, code, dissect_table, subfunction_call_format, dissect_func_name_list):
    curr_dissect_name = dissect_name
    dissect_func_name_list.append(curr_dissect_name)
    func_code = extract_func_body(lines, dissect_name)
    skip_first_line = True  
    for line in func_code:
        if skip_first_line:
            code.append(line)
            skip_first_line = False
            continue

        # several formats of subfuntion call
        elif (line.startswith("dissect_") and ";" in line) or ():
            code.append(line)
            dissect_name = line.split("(")[0].strip()

            if dissect_name in dissect_func_name_list:
                continue
            if "response" in dissect_name:
                continue
            if curr_dissect_name == dissect_name:
                continue
            else:
                for line in lines:
                    if line.startswith(dissect_name + "(") and ";" not in line:
                        add_sub_func_body(lines, dissect_name, code, dissect_table, subfunction_call_format, dissect_func_name_list)

        elif (("= " + subfunction_call_format) in line) and (line.endswith(";")):
            code.append(line)
            dissect_name = line.split("=")[1].split("(")[0].strip()
            if dissect_name in dissect_func_name_list:
                continue
            if "response" in dissect_name:
                continue
            if curr_dissect_name == dissect_name:
                continue
            else:
                for line in lines:
                    if (line.startswith(dissect_name + "(") and ";" not in line) or \
                       line.startswith("static int " + dissect_name + "(") or \
                       line.startswith("static gint " + dissect_name + "(") or \
                       line.startswith("static gboolean " + dissect_name + "(") :
                        add_sub_func_body(lines, dissect_name, code, dissect_table, subfunction_call_format, dissect_func_name_list)
                        print("End of a function call!")
                        dissect_func_name_list.pop()
                        break  

        elif (line.startswith(subfunction_call_format)) and (line.endswith(";")):
            code.append(line)
            dissect_name = line.split("(")[0].strip()
            if dissect_name in dissect_func_name_list:
                continue
            if "response" in dissect_name:
                continue
            if curr_dissect_name == dissect_name:
                continue
            else:
                for line in lines:
                    if (line.startswith(dissect_name + "(") and ";" not in line) or \
                       line.startswith("static int " + dissect_name + "(") or \
                       line.startswith("static gint " + dissect_name + "(") or \
                       line.startswith("static gboolean " + dissect_name + "(") :
                        add_sub_func_body(lines, dissect_name, code, dissect_table, subfunction_call_format, dissect_func_name_list)
                        print("End of a function call!")
                        break 

        elif line.startswith("call_dissector"):
            code.append(line)
            content = extract_parameter(line)
            dissect_handle = content[0].strip()
            for dissect in dissect_table:
                if 'dissect_handle' in dissect and dissect["dissect_handle"] == dissect_handle:
                    print(dissect)
                    dissect_name = dissect["func_name"]
                    if dissect_name in dissect_func_name_list:
                        continue
                    if "response" in dissect_name:
                        continue 
                    if curr_dissect_name == dissect_name:
                        continue
                    else:
                        for line in lines:
                            if line.startswith(dissect_name + "(") and ";" not in line:
                                add_sub_func_body(lines, dissect_name, code, dissect_table, subfunction_call_format, dissect_func_name_list)
        
        else:
            code.append(line)

    return code


# put { into a single line 
def wrap_brace(file_path):
    formatted_lines = []
    with open(file_path, 'r', encoding= 'utf-8') as file:
        lines = file.readlines()
        for line in lines:
            line = line.strip()
            if line.endswith("{"):
                formatted_lines.append(line[:-1]) 
                formatted_lines.append("{")                
            else:
                formatted_lines.append(line)
    with open(file_path, 'w', encoding= 'utf-8') as file:
        for line in formatted_lines:
            if line:
                file.writelines(line+ '\n')


# extract hexadecimal value from line, as the bit-level length of the field
def extract_last_hex_value(line):
    match = re.search(r'0[xX][0-9a-fA-F]+', line)
    if match:
        hex_values = match.group(0)
        last_hex_value = hex_values.split()[-1]
        return last_hex_value
    else:
        return None


# extract field's variable name from line 
def extract_variable_name(line):
    variable_name = ''
    line = line.split('=')[0].strip()
    if ' ' in line:
        variable_name = line.split(' ')[1].strip()
    else:
        variable_name = line
    return variable_name


# extract case value from line 
def extract_case_value(case_line):
    pattern = re.compile(r'\bcase\s+([^:]+):')
    match = pattern.search(case_line)
    if match:
        return match.group(1)
    else:
        return None


# Extract the contents of the switch conditional statement 
def extract_switch_content(switch_statement):
    pattern = re.compile(r'switch\s*\((.*?)\)')
    match = pattern.search(switch_statement)
    if match:
        return match.group(1).strip()
    else:
        return None


# extract packet types based on base path set
def extract_packet_types(input_file_path, output_file_path, truth_field_dir, field_list, file_name, subfunction_call_format):
    packet_types_all_fragments = []

    field_all = []

    offset_stack = []
    packet_stack = []
    tvb_get_field = []
    if_dependence = []

    add_field = False
    case_value_list = []
    first_circle_line = True
    if_stack = []
    type_stack = []

    type_stack.append('function')
    function_list = ['function']
    function_list_end = ['function_end']
    
    packet_stack.append(packet_types_all_fragments)
    packet_stack[-1].append(function_list)
    packet_stack[-1].append(function_list_end)
    packet_stack.append(function_list)

    switch_dependence = []
    if_contion_string = []
    in_circle = False
    first_line_tag = True

    data_type_field_value = ''
    num = 0
    if_condition = ''
    data_field_change_value = []

    with open(input_file_path, 'r') as file:
        lines = file.readlines()
        for i in range(len(lines)):
            line = lines[i].strip()
            if first_line_tag:
                first_line_tag = False
                continue

            if not in_circle:

                # circle basic block
                if line.startswith(("for ", "while ", "do ")):
                    first_circle_line = True
                    in_circle = True
                    if type_stack[-1] == 'ordinary':
                        add_field = True
                        if len(packet_stack[-1]) == 1:
                            packet_stack[-2].pop()                    
                        type_stack.pop()
                        packet_stack.pop()
                    if line.startswith("for "):
                        type_stack.append('for')
                        circular_list = ['for']
                    elif line.startswith("while "):
                        condition = extract_condition(line)
                        if condition.startswith("tvb_"):
                            first_circle_line = False
                            in_circle = False
                        circular_list = ['while']
                        type_stack.append('while')
                    elif line.startswith("do "):
                        type_stack.append('do while')
                        circular_list = ['do while']
                    packet_stack[-1].append(circular_list)                                                      
                    packet_stack.append(circular_list)                                                      
                
                # branch basic block
                elif line.startswith(("if", "switch", "TRY")):
                    if type_stack[-1] == 'ordinary':
                        if len(packet_stack[-1]) == 1:
                            packet_stack[-2].pop()
                        type_stack.pop()
                        packet_stack.pop()
                    if line.startswith("if"):
                        if_condition = extract_condition(line)
                        if_contion_string.append(if_condition)
                        if_stack.append(['condition', 'if', if_condition, 'true'])
                        type_stack.append('if')
                        if_list1 = ['if_else']
                        packet_stack[-1].append(if_list1)
                        packet_stack.append(if_list1)
                        if_list2 = ['if']
                        packet_stack[-1].append(if_list2)
                        packet_stack.append(if_list2)

                    elif line.startswith("switch"):
                        if case_value_list:
                            case_value_list.append('/')
                        type_field = extract_switch_content(line)
                        print('switch_dependence = ', type_field)
                        switch_dependence.append(type_field)
                        type_stack.append('switch')
                        switch_list = ['switch']
                        packet_stack[-1].append(switch_list) 
                        packet_stack.append(switch_list) 

                    elif line.startswith("TRY"):
                        type_stack.append('TRY')
                        TRY_list1 = ['TRY_CATCH']
                        packet_stack[-1].append(TRY_list1)
                        packet_stack.append(TRY_list1)
                        TRY_list2 = ['TRY']
                        packet_stack[-1].append(TRY_list2)
                        packet_stack.append(TRY_list2)

                # function basic block
                elif (line.startswith("dissect_") and line.endswith(")")) or\
                     (line.startswith("static int ") and line.endswith(")")) or\
                     (line.startswith("static gint ") and line.endswith(")")) or\
                     (line.startswith("static gboolean ") and line.endswith(")")) or\
                     (line.startswith(subfunction_call_format) and line.endswith(")")):
                    if type_stack[-1] == 'ordinary':
                        if len(packet_stack[-1]) == 1:
                            packet_stack[-2].pop()
                        type_stack.pop()
                        packet_stack.pop() 
                    type_stack.append('function')
                    function_list = ['function']
                    function_list_end = ['function_end']
                    packet_stack[-1].append(function_list)
                    packet_stack[-1].append(function_list_end)
                    packet_stack.append(function_list) 
                
                # branch item basic block
                elif line.startswith("else if") or line.startswith("CATCH") or line.startswith("else") or line.startswith("case") or line.startswith("default"):
                    if type_stack[-1] == 'ordinary':
                        if len(packet_stack[-1]) == 1:
                            packet_stack[-2].pop()    
                        type_stack.pop()
                        packet_stack.pop()                
                    if line.startswith("else if"):
                        else_if_condition = extract_condition(line)
                        if_stack.append(['condition', 'else if', else_if_condition, 'true'])
                        type_stack.append('else if')
                        else_if_list = ['else if']
                        packet_stack[-1].append(else_if_list) 
                        packet_stack.append(else_if_list) 
                    elif line.startswith("else"):
                        else_condition = if_contion_string[-1]
                        if_stack.append(['condition', 'else', else_condition, 'false'])
                        type_stack.append('else')
                        else_list = ['else']
                        packet_stack[-1].append(else_list) 
                        packet_stack.append(else_list)                    
                    elif line.startswith("CATCH"):
                        type_stack.append('CATCH')
                        CATCH_list = ['CATCH']
                        packet_stack[-1].append(CATCH_list) 
                        packet_stack.append(CATCH_list)                                                
                    elif line.startswith("case"):
                        if (packet_stack[-1][0] == 'case') and (len(packet_stack[-1]) > 1):
                            type_stack.pop()
                            packet_stack.pop()
                            if "/" in case_value_list:
                                for i in range(len(case_value_list)-1,-1, -1):
                                    string = case_value_list[i]
                                    if string == '/':
                                        case_value_list = case_value_list[:i+1]
                                        break
                            else:
                                case_value_list = []
                        add_field = False
                        case_value = extract_case_value(line)
                        case_value_list.append(case_value)
                        next_line_index = i + 1
                        next_line = lines[next_line_index].strip()
                        if next_line.startswith("case"):
                            next_case_value = extract_case_value(line)
                            case_value_list.pop()
                            case_value_list.append(next_case_value)
                            continue
                        elif next_line.startswith("default"):
                            case_value_list.append('') 
                        else:
                            type_stack.append('case')
                            case_list = ['case']
                            packet_stack[-1].append(case_list) 
                            packet_stack.append(case_list)                     
                    elif line.startswith("default"):
                        if case_value_list and case_value_list[-1] != '':
                            case_value_list.append('') 
                        type_stack.append('default')
                        default_list = ['default']
                        packet_stack[-1].append(default_list) 
                        packet_stack.append(default_list)  

                # return basic block   
                elif line.startswith("return"):
                    if type_stack[-1] == 'ordinary':
                        if len(packet_stack[-1]) == 1:
                            packet_stack[-2].pop()    
                        type_stack.pop()
                        packet_stack.pop()                      
                    if type_stack[-1] == 'default':
                        for field in field_all:
                            if ('field_vari_name' in field) and (field['field_vari_name'] == switch_dependence[-1]):
                                if has_dict_element(packet_stack[-1]):
                                    continue
                                else:
                                    null_field_info = {
                                        'field_name':'There is no Field!'
                                    }     
                                    null_field_info["switch_dependence"] = switch_dependence.copy()
                                    null_field_info["switch_dependence_value"] = case_value_list.copy()
                                    new_ordinary = ['ordinary']  
                                    new_ordinary.append(null_field_info)   
                                    packet_stack[-1].append(new_ordinary) 
                                    field_all.append(null_field_info)
                        return_list = ['return']
                        packet_stack[-1].append(return_list)                        
                        type_stack.pop()
                        packet_stack.pop()
                    else:
                        return_list = ['return']
                        packet_stack[-1].append(return_list)

                # break basic block
                elif line.startswith("break"):
                    if type_stack[-1] == 'ordinary':
                        if len(packet_stack[-1]) == 1:
                            packet_stack[-2].pop()    
                        '''
                        # if add_field == False:
                        #     if case_value_list:
                        #         print(case_value_list)
                        #         null_field_info = {
                        #             'field_name':'There is no Field!'
                        #         }                            
                        #         null_field_info["switch_dependence"] = switch_dependence.copy()
                        #         null_field_info["switch_dependence_value"] = case_value_list.copy()
                        #     packet_stack[-1].append(null_field_info)  
                        '''
                        type_stack.pop()
                        packet_stack.pop()                    
                    if type_stack[-1] == 'if':
                        pass
                    elif type_stack[-1] == 'case' or type_stack[-1] == 'default':
                        for field in field_all:
                            if ('field_vari_name' in field) and (field['field_vari_name'] == switch_dependence[-1]):
                                if has_dict_element(packet_stack[-1]):
                                    continue
                                else:
                                    null_field_info = {
                                        'field_name':'There is no Field!'
                                    }     
                                    null_field_info["switch_dependence"] = switch_dependence.copy()
                                    null_field_info["switch_dependence_value"] = case_value_list.copy()
                                    new_ordinary = ['ordinary']  
                                    new_ordinary.append(null_field_info)   
                                    packet_stack[-1].append(new_ordinary)
                                    field_all.append(null_field_info)
                        if "/" in case_value_list:
                            for i in range(len(case_value_list)-1,-1, -1):
                                string = case_value_list[i]
                                if string == '/':
                                    case_value_list = case_value_list[:i+1]
                                    break
                        else:
                            case_value_list = []
                        type_stack.pop()
                        packet_stack.pop()

                # { }
                elif line.startswith(("{", "}")):
                    if type_stack[-1] == 'ordinary':
                        if len(packet_stack[-1]) == 1:
                            packet_stack[-2].pop()
                        type_stack.pop()
                        packet_stack.pop()                
                    if line.startswith("{"):
                        continue
                    elif line.startswith("}"):
                        if type_stack[-1] == 'case' or type_stack[-1] == 'default':
                            if "/" in case_value_list:
                                for i in range(len(case_value_list)-1,-1, -1):
                                    string = case_value_list[i]
                                    if string == '/':
                                        case_value_list = case_value_list[:i+1]
                                        break
                            else:
                                case_value_list = []
                            type_stack.pop()
                            packet_stack.pop()
                        if type_stack[-1] == 'switch':
                            if "/" in case_value_list:
                                for i in range(len(case_value_list)-1,-1, -1):
                                    string = case_value_list[i]
                                    if string == '/':
                                        case_value_list = case_value_list[:i+1]
                                        break
                            else:
                                case_value_list = []
                            if case_value_list and case_value_list[-1] == '/':
                                case_value_list.pop()
                            switch_dependence.pop()
                        if type_stack[-1] == 'else':
                            if_contion_string.pop()
                            if_stack.pop()
                            if_condition = ''
                            else_if_condition = ''
                            type_stack.pop()
                            packet_stack.pop()
                            packet_stack.pop()
                        elif type_stack[-1] == 'CATCH':
                            type_stack.pop()
                            packet_stack.pop()
                            packet_stack.pop() 
                        elif type_stack[-1] == 'if':
                            if_stack.pop()
                            type_stack.pop()
                            packet_stack.pop()
                        elif type_stack[-1] == 'TRY':
                            type_stack.pop()
                            packet_stack.pop()
                        elif type_stack[-1] == 'else if':
                            if_stack.pop()
                            type_stack.pop()
                            packet_stack.pop()
                        elif type_stack[-1] in ('switch', 'function', 'for', 'while', 'do while'):
                            type_stack.pop()
                            packet_stack.pop()
                
                # ordinary basic block
                else:
                    if type_stack[-1] != 'ordinary':
                        type_stack.append('ordinary')
                        ordinary_list = ['ordinary']
                        packet_stack[-1].append(ordinary_list)
                        packet_stack.append(ordinary_list)

                # buffer read function
                if ("= tvb_get_" in line and (line.endswith(";"))):
                    field_info = {}
                    if " = tvb_get_guint8" in line:
                        field_length = 1
                        field_vari_name = extract_variable_name(line)
                        content = extract_parameter(line)[1].strip()
                        field_offset = content
                        hex_value = extract_last_hex_value(line)
                        if hex_value:
                            field_bit_length = hex_value
                        else:
                            field_bit_length = ''
                        field_endian = 'ENC_NA'
                    elif " = tvb_get_ntohs" in line:
                        field_length = 2
                        field_endian = 'ENC_BIG_ENDIAN'
                        field_vari_name = extract_variable_name(line)
                        content = extract_parameter(line)[1]
                        offset_value = extract_number_from_line(content)
                        content = extract_parameter(line)[1].strip()
                        field_offset = content
                        field_bit_length = ''
                    elif " = tvb_get_ntohl" in line:
                        field_length = 4
                        field_endian = 'ENC_BIG_ENDIAN'
                        field_vari_name = extract_variable_name(line)
                        content = extract_parameter(line)[1].strip()
                        field_offset = content
                    elif " = tvb_get_ntoh24" in line:
                        field_length = 3
                        field_endian = 'ENC_BIG_ENDIAN'
                        field_vari_name = extract_variable_name(line)
                        content = extract_parameter(line)[1].strip()
                        field_offset = content      
                    elif " = tvb_get_ntoh48" in line:
                        field_length = 6
                        field_endian = 'ENC_BIG_ENDIAN'
                        field_vari_name = extract_variable_name(line)
                        content = extract_parameter(line)[1].strip()
                        field_offset = content 
                    # invalid
                    else:
                        continue
                    
                    if field_bit_length:
                        field_info = {
                                "field_vari_name": field_vari_name,
                                "field_offset": field_offset,
                                'field_length': field_length,
                                'field_bit_length': field_bit_length,
                                'field_endian': field_endian
                            }                    
                    else:
                        field_info = {
                                "field_vari_name": field_vari_name,
                                "field_offset": field_offset,
                                'field_length': field_length,
                                'field_endian': field_endian
                            }
                    tvb_get_field.append(field_info)
                
                # proto tree function
                elif "proto_tree_add_" in line:
                    field_info = {}
                    field_identifier = ''
                    field_vari_name = ''
                    field_offset = ''
                    field_length = ''
                    field_endian = ''

                    if (line.startswith("proto_tree_add_item(")) or (line.startswith("proto_tree_add_item_ret_uint(")):
                        if 'hf_modbus_functioncode' in line:
                            field_vari_name = 'function_code'
                        content = extract_parameter(line)
                        field_identifier = content[1].strip()
                        field_endian = content[5].strip()
                        length_info = content[4].strip()
                        if length_info == "0" or length_info == "-1":
                            continue
                        try:
                            field_length = int(length_info)
                        except ValueError:
                            field_length = 'value of ' + length_info
                        content = extract_parameter(line)[3].strip()
                        field_offset = content
                        if field_vari_name:
                            field_info = {
                                "field_identifier": field_identifier,
                                "field_vari_name": field_vari_name,
                                "field_offset": field_offset,
                                'field_length': field_length,
                                'field_endian': field_endian,
                            }
                        else:
                            field_info = {
                                "field_identifier": field_identifier,
                                "field_offset": field_offset,
                                'field_length': field_length,
                                'field_endian': field_endian,
                            } 
                    elif "proto_tree_add_bitmask(" in line:
                        content = extract_parameter(line)
                        field_offset = content[2].strip()
                        field_identifier = content[3].strip()
                        field_endian = content[6].strip()
                        field_info = {
                            "field_identifier": field_identifier,
                            "field_offset": field_offset,
                            'field_endian': field_endian,
                        }                      
                    elif "proto_tree_add_uint(" in line:
                        content = extract_parameter(line)
                        field_identifier = content[1].strip()
                        field_vari_name = content[5].strip()
                        if content[4].strip() == '0' or content[4].strip() == '-1':
                            continue
                        try:
                            field_length = int(content[4])
                        except ValueError:
                            field_length = 'value of ' + content[4]
                        content = extract_parameter(line)[3].strip()
                        field_offset = content
                        field_info = {
                                "field_identifier": field_identifier,
                                "field_vari_name": field_vari_name,
                                "field_offset": field_offset,
                                'field_length': field_length,
                            }                    
                    elif line.startswith("proto_tree_add_uint64("):
                        content = extract_parameter(line)
                        field_identifier = content[1].strip()
                        field_vari_name = content[5]
                        length_info = content[4].strip()
                        if length_info == "0" or length_info == "-1":
                            print(line)
                            continue
                        try:
                            field_length = int(length_info)
                        except ValueError:
                            field_length = 'value of ' + length_info
                        content = extract_parameter(line)[3].strip()
                        field_offset = content
                        field_info = {
                                "field_identifier": field_identifier,
                                "field_vari_name": field_vari_name,
                                "field_offset": field_offset,
                                'field_length': field_length,
                            } 
                    elif "proto_tree_add_uint_format_value(" in line:
                        content = extract_parameter(line)
                        field_identifier = content[1].strip()
                        field_vari_name = content[5].strip()
                        if content[4].strip() == '0' or content[4].strip() == '-1':
                            continue
                        try:
                            field_length = int(content[4])
                        except ValueError:
                            field_length = 'value of ' + content[4]
                        content = extract_parameter(line)[3].strip()
                        field_offset = content
                        field_info = {
                                "field_identifier": field_identifier,
                                "field_vari_name": field_vari_name,
                                "field_offset": field_offset,
                                'field_length': field_length,
                            }                          
                    elif line.startswith("proto_tree_add_boolean("):
                        content = extract_parameter(line)
                        field_identifier = content[1].strip()
                        field_vari_name = content[5]
                        length_info = content[4].strip()
                        if length_info == "0" or length_info == "-1":
                            print(line)
                            continue
                        try:
                            field_length = int(length_info)
                        except ValueError:
                            field_length = 'value of ' + length_info
                        content = extract_parameter(line)[3].strip()
                        field_offset = content
                        field_info = {
                                "field_identifier": field_identifier,
                                "field_vari_name": field_vari_name,
                                "field_offset": field_offset,
                                'field_length': field_length,
                            }                                    
                    elif line.startswith("proto_tree_add_checksum"):
                        content = extract_parameter(line)
                        field_identifier = content[3].strip()
                        field_endian = content[-2]
                        content = extract_parameter(line)[2].strip()
                        field_offset = content
                        field_info = {
                                "field_identifier": field_identifier,
                                "field_offset": field_offset,
                                'field_endian': field_endian,
                            }                                     
                    else:
                        continue

                    if case_value_list:
                        field_info["switch_dependence"] = switch_dependence.copy()
                        field_info["switch_dependence_value"] = case_value_list.copy()
                        
                    if if_stack:
                        for condition in if_stack:
                            dependence = condition[-2:]
                            if_dependence.append(dependence)
                        field_info["if_dependence"] = if_dependence.copy()
                        if_dependence = []

                    # improve field information
                    for field in tvb_get_field:
                        if 'field_vari_name' in field_info:
                            if field['field_vari_name'] == field_info['field_vari_name']:
                                for key, value in field.items():
                                    if key not in field_info:
                                        field_info[key] = value
                    # improve field information
                    for field1 in field_list:
                        if field1['field_identifier'] == field_info['field_identifier']:
                            for key, value in field1.items():
                                if key not in field_info:
                                    field_info[key] = value
                    packet_stack[-1].append(field_info)
                    field_all.append(field_info)
                    add_field == True

            # data type field
            if in_circle:
                if "{" in line:
                    num += 1
                elif "}" in line:
                    num -= 1

                # first line in circle
                if first_circle_line:
                    pattern1 = re.compile(r'^\s*while\s*\(\s*(\w+)\s*<\s*(\w+)\s*\)\s*$')
                    match1 = pattern1.match(line)
                    pattern2 = re.compile(r'^\s*while\s*\(\s*(\w+)\s*>\s*(\w+)\s*\)\s*$')
                    match2 = pattern2.match(line)         
                    pattern3 = re.compile(r'^\s*for\s*\(\s*([^;]+)\s*;\s*([^;]+)\s*;\s*([^;]+)\s*\)\s*$')
                    match3 = pattern3.match(line)
                    pattern4 = re.compile(r'^\s*while\s*\(.*?\b(\w+)\b\s*<=\s*\((.*?)\)\s*\)\s*$')
                    match4 = pattern4.match(line)  
                    pattern5 = re.compile(r'^\s*while\s*\(\s*(\w+)\s*!=\s*(\w+)\s*\)\s*$')
                    match5 = pattern5.match(line)  
                    if match1:
                        loop_start_condition = match1.group(1)
                        loop_end_condition = match1.group(2)  
                        first_circle_line = False  
                    elif match2:
                        loop_start_condition = match2.group(1)
                        loop_end_condition = match2.group(2)
                        first_circle_line = False   
                    elif match5:
                        loop_start_condition = match5.group(1)
                        loop_end_condition = match5.group(2)
                        first_circle_line = False 
                    elif match4:
                        loop_start_condition = match4.group(1)
                        loop_end_condition = match4.group(2)
                        print('loop_start_condition = ', loop_start_condition)
                        print('loop_end_condition = ', loop_end_condition)
                        first_circle_line = False                                                  
                    elif match3:
                        first_param = match3.group(1)
                        second_param = match3.group(2)
                        third_param = match3.group(3)
                        first_circle_line = False 
                        if '++' in third_param:
                            data_field_value = 1
                        if '/' in second_param:
                            data_field_value = second_param.split('/')[1].strip()
                            data_field_num = 'value of ' + second_param.split('<')[1].strip()
                        else:
                            data_field_num = second_param

                        field_info = {
                                'field_identifier': 'data_type_field',
                                'field_name': 'data_type_field',
                                'field_type': data_field_value,
                                'field_length': data_field_num
                            } 
                        if case_value_list:
                                field_info["switch_dependence"] = switch_dependence.copy()
                                field_info["switch_dependence_value"] = case_value_list.copy()
                        field_block = ['ordinary', field_info]
                        packet_stack[-1].append(field_block)
                        field_all.append(field_block)
                        field_info = {}
                        loop_start_condition = ''
                        loop_end_condition = ''                        

                    else:
                        first_circle_line = False                      
                        loop_start_condition = ''  
                        loop_end_condition = ''                      

                # other line in circle
                else:
                    if loop_start_condition == '':
                        pass
                    elif line.startswith(loop_start_condition):
                        if '++' in line:
                            change_value = 1
                            data_field_change_value.append(1)
                            data_field_num = 'value of ' + loop_end_condition
                        elif '+=' in line:
                            change_value = line.split('+=')[1].strip('; ')
                            if change_value.isdigit():
                                data_field_change_value.append(change_value)
                                data_field_num = loop_end_condition + '/' + change_value
                            else:
                                change_value = 'value of ' + str(line.split('+=')[1].strip('; ')   )
                                data_field_change_value.append(change_value)
                                data_field_num = 1
                        elif ' = ' in line:
                            change_value = 'value of ' + line.split('=')[1].strip('; ')   
                            data_field_change_value.append(change_value)
                            data_field_num = 1
                        elif '-=' in line:
                            change_value = 'value of ' + line.split('-=')[1].strip('; ')   
                            data_field_change_value.append(change_value)
                            data_field_num = 'value of ' + loop_start_condition + ' / ' + change_value
                        elif '=' in line and '(' in line and ')' in line:
                            change_value = 'value of ' + line.split('=')[0].strip('; ')   
                            data_field_change_value.append(change_value)
                            data_field_num = 'value of ' + loop_end_condition + ' / ' + loop_start_condition
                    if num == 0:
                        if loop_start_condition == '':
                            type_stack.pop()
                            packet_stack.pop()
                            in_circle = False
                        else:
                            data_field_value = data_field_change_value[-1] 
                            field_info = {
                                'field_identifier': 'data_type_field',
                                'field_name': 'data_type_field',
                                'field_type': data_field_value,
                                'field_length': data_field_num
                            }
                            if case_value_list:
                                field_info["switch_dependence"] = switch_dependence.copy()
                                field_info["switch_dependence_value"] = case_value_list.copy()
                            field_block = ['ordinary', field_info]
                            packet_stack[-1].append(field_block)
                            field_all.append(field_block)
                            type_stack.pop()
                            packet_stack.pop()
                            in_circle = False
                            field_info = {}
                            loop_start_condition = ''
                            loop_end_condition = ''

    # write the extracted base path set to json file
    with open(output_file_path, 'w', encoding='utf-8') as file:
        json.dump(packet_types_all_fragments, file, indent=4, default = custom_encoder)

    # write fields extracted from buffer reading function to json file
    truth_field_path = os.path.join(truth_field_dir, f"{os.path.splitext(file_name)[0]}.json")
    with open(truth_field_path, 'w', encoding='utf-8') as file:
        json.dump(tvb_get_field, file, indent=4, default = custom_encoder)

    return packet_types_all_fragments, tvb_get_field


# Checks whether the list contains a dictionary element, returning True if it does, and False if it does not.
def has_dict_element(lst):
    for item in lst:
        if isinstance(item, dict):
            return True
        elif isinstance(item, list):
            if has_dict_element(item):
                return True
    return False


# Checks if obj is a list and all elements in the list are strings.
def custom_encoder(obj):
    if isinstance(obj, list) and all(isinstance(item, str) for item in obj):
        return {'__list_of_strings__': obj}
    return obj


# expand the basic path set to obtain each packet type
def expand_recursion(packet_types_all_fragments):
    sequential_list = ['function', 'if', 'else if', 'else', 'while', 'for', 'do_while', 'case']
    branch_list = ['if_else', 'switch']
    end_list = ['return', 'function_end']
    packets_all = []
    for i in range(len(packet_types_all_fragments)):
        packet_type = packet_types_all_fragments[i]
        packet = []
        new_packets = []
        for j in range(len(packet_type)):

            block = packet_type[j]
            if block[0] == "default":
                if len(block) == 1:
                    continue
                if block[1][0] == 'if_else':
                    for item in block[1][1:]:
                        if len(item) > 1:
                            packet.append(item)
                    continue
                else:
                    packet.extend(block[1:])
            elif block[0] in sequential_list:
                if (block[0] == 'case'):
                    for block_item in block[1:]:
                        if block_item[0] == 'if_else':
                            for block_i in block_item[1:]:
                                if len(block_i) == 1:
                                    block_item.remove(block_i)
                if len(block) == 1:
                    continue
                packet.extend(block[1:])
            elif block[0] in branch_list:
                is_null = False
                if block[0] == 'if_else':
                    if len(block) == 3:
                        if (len(block[1]) == 1) and (len(block[2]) == 1):
                            is_null = True
                    elif len(block) == 4:
                        if (len(block[1]) == 1) and (len(block[2]) == 1) and (len(block[3]) == 1):
                            is_null = True    
                elif block[0] == 'switch':
                    is_null = True
                    for item in block[1:]:
                        if len(item) != 1:
                            is_null = False
                            break
                if is_null:
                    continue
                if (block[0] == 'if_else') and (len(block) == 3):
                    if_field = []
                    else_field = []
                    if_block = block[1]
                    else_block = block[2]
                    for i in if_block[1:]:
                        if i[0] == 'ordinary':
                            if_field.extend(i[1:])
                    for i in else_block[1:]:
                        if i[0] == 'ordinary':
                            else_field.extend(i[1:])
                    if len(if_field) == 1 and len(else_field) == 1:
                        if if_field[0]['field_name'] == else_field[0]['field_name']:
                            block.pop()
                new_packet = []
                for branch_block in block[1:]:
                    if (len(branch_block) == 2) and (branch_block[1][0] == 'return'):
                        continue
                    if len(branch_block) == 1:
                        continue
                    new_packet = packet.copy()
                    new_packet.append(branch_block)
                    new_packet.extend(packet_type[j+1:])
                    new_packets.append(new_packet) 
                if new_packets:
                    break
            elif block[0] == 'ordinary':
                if len(block) == 1:
                    continue
                packet.append(block)
            elif block[0] in end_list:
                packet.append(block)
        if new_packets:
            packets_all.extend(new_packets)
        else:
            packets_all.append(packet)    
    unique_packet_types = unique_packet(packets_all)
    return unique_packet_types


# filter duplicate packet types
def unique_packet(packets_all):
    unique_packet_types = []
    for packet in packets_all:
        if packet in unique_packet_types:
            continue
        else:
            unique_packet_types.append(packet)
    return unique_packet_types


# check if there are duplicate elements in list
def has_duplicates(lst):
    return len(lst) != len(set(lst))


# find the index of duplicate elements.
def find_duplicate_indices(lst):
    seen = {}
    duplicates = []
    for index, element in enumerate(lst):
        if element in seen:
            duplicates.append(seen[element])
            duplicates.append(index)
        else:
            seen[element] = index
    return duplicates


def expand_packet_types(packet_types_all_fragments):
    packet_types_expanded = []
    packet_types_expanded = expand_recursion(packet_types_all_fragments)
    packet_types_expanded = expand_recursion(packet_types_expanded)
    packet_types_expanded = expand_recursion(packet_types_expanded)
    packet_types_expanded = expand_recursion(packet_types_expanded)
    packet_types_expanded = expand_recursion(packet_types_expanded)
    packet_types_expanded = expand_recursion(packet_types_expanded)
    packet_types_expanded = expand_recursion(packet_types_expanded)
    packet_types_expanded = expand_recursion(packet_types_expanded)
    packet_types_expanded = expand_recursion(packet_types_expanded)
    packet_types_expanded = expand_recursion(packet_types_expanded)
    packet_types_expanded = expand_recursion(packet_types_expanded)
    packet_types_expanded = expand_recursion(packet_types_expanded)
    packet_types_expanded = expand_recursion(packet_types_expanded)
    packet_types_expanded = expand_recursion(packet_types_expanded)
    packet_types_expanded = expand_recursion(packet_types_expanded)
    packet_types_expanded = expand_recursion(packet_types_expanded)
    packet_types_expanded = expand_recursion(packet_types_expanded)
    packet_types_expanded = expand_recursion(packet_types_expanded)
    packet_types_expanded = expand_recursion(packet_types_expanded)
    packet_types_expanded = expand_recursion(packet_types_expanded)
    packet_types_expanded = expand_recursion(packet_types_expanded)
    packet_types_expanded = expand_recursion(packet_types_expanded)
    packet_types_expanded = expand_recursion(packet_types_expanded)
    packet_types_expanded = expand_recursion(packet_types_expanded)
    packet_types_expanded = expand_recursion(packet_types_expanded)
    packet_types_expanded = expand_recursion(packet_types_expanded)
    packet_types_expanded = expand_recursion(packet_types_expanded)
    packet_types_expanded = expand_recursion(packet_types_expanded)
    packet_types_expanded = expand_recursion(packet_types_expanded)
    packet_types_expanded = expand_recursion(packet_types_expanded)   
    packet_types_expanded = expand_recursion(packet_types_expanded)   
    packet_types_expanded = expand_recursion(packet_types_expanded)   
    packet_types_expanded = expand_recursion(packet_types_expanded)   
    packet_types_expanded = expand_recursion(packet_types_expanded)   
    packet_types_expanded = expand_recursion(packet_types_expanded)   
    packet_types_expanded = expand_recursion(packet_types_expanded)   
    packet_types_expanded = expand_recursion(packet_types_expanded)   
    packet_types_expanded = expand_recursion(packet_types_expanded)   
    packet_types_expanded = expand_recursion(packet_types_expanded)   
    packet_types_expanded = expand_recursion(packet_types_expanded)   
    packet_types_expanded = expand_recursion(packet_types_expanded)   
    packet_types_expanded = expand_recursion(packet_types_expanded)   
    packet_types_expanded = expand_recursion(packet_types_expanded)   
    packet_types_expanded = expand_recursion(packet_types_expanded)   
    packet_types_expanded = expand_recursion(packet_types_expanded) 
    packet_types_expanded = expand_recursion(packet_types_expanded)   
    packet_types_expanded = expand_recursion(packet_types_expanded)   
    packet_types_expanded = expand_recursion(packet_types_expanded)
    return packet_types_expanded


# merge packet types, retaining only field information
def merge_packet_types(packet_types_expanded_list):
    packet_types_merged = []
    for packet in packet_types_expanded_list:
        new_packet = []
        for block in packet:
            if block[0] == 'ordinary':
                new_packet.extend(block[1:])
        if new_packet:
            packet_types_merged.append(new_packet)
    # ensure each packet type is unique
    packet_types_merged = unique_packet(packet_types_merged)
    return packet_types_merged


# Determine the validity of the packet type based on the swicth dependency of each field
# If there are inconsistent switch dependencie of multiple fields in a packet type, that packet type is invalid.
def correct_switch_type(packet_type):
    valid_packet = True
    for field in packet_type:
        type_value = ''
        if 'switch_dependence' in field:
            field_type = field['switch_dependence']
            field_type_value = field["switch_dependence_value"]
            if has_duplicates(field_type):
                same_index = find_duplicate_indices(field['switch_dependence'])
                if len(same_index) == 2:
                    index_1 = same_index[0]
                    index_2 = same_index[1]
                    type_value = split_list_by_slash(field_type_value)
                    valid_packet = has_common_elements(type_value[index_1], type_value[index_2])  
    return valid_packet


# Determine the validity of the packet type based on the if dependency of each field
def correct_if_type(packet):
    valid = True
    dependence_info = {}
    for field in packet:
        if 'if_dependence' in field:
            for dependence in field['if_dependence']:
                condition = dependence[0]
                condition_value = dependence[1]
                if condition in dependence_info.keys():
                    if (condition_value !=  dependence_info[condition]):
                        valid = False
                else:
                    dependence_info[condition] = condition_value
    return valid


# Check if two lists have common elements
def has_common_elements(list1, list2):
    set1 = set(list1)
    set2 = set(list2)
    common_elements = set1 & set2
    if not common_elements and '' in list2:
        return True
    return bool(common_elements)


# Split list elements based on /, used to compare whether two case values are equal
def split_list_by_slash(input_list):
    result_list = []
    current_sublist = []
    for item in input_list:
        if item == "/":
            result_list.append(current_sublist)
            current_sublist = []
        else:
            current_sublist.append(item)

    if current_sublist:
        result_list.append(current_sublist)
    return result_list


# Filter packet type 
def filter_packet_types(packet_types_merged):
    packet_types_fieltered_switch = []
    packet_types_fieltered_if = []
    packet_types_fieltered_tree = []
    packet_types_fieltered_no_field = []
    packet_types_fieltered_if_and_switch = []
    for packet in packet_types_merged:
        if correct_switch_type(packet):
            packet_types_fieltered_switch.append(packet)
    for packet in packet_types_fieltered_switch:
        if correct_if_type(packet):
            packet_types_fieltered_if.append(packet)
    for packet in packet_types_fieltered_if:
        if correct_tree_type(packet):
            packet_types_fieltered_tree.append(packet)
    for packet in packet_types_fieltered_tree:
        if correct_field_type(packet):
            packet_types_fieltered_no_field.append(packet)
    for packet in packet_types_fieltered_no_field:
        if correct_if_and_switch_type(packet):
            packet_types_fieltered_if_and_switch.append(packet)

    return packet_types_fieltered_if_and_switch


def correct_field_type(packet):
    valid = True
    for i in range(len(packet)- 1):
        field = packet[i]
        if 'field_name' in field and field['field_name'] == "There is no Field!":
            if i != len(packet) - 1:
                pass
                # valid = False
    return valid


# Filter packet types based on the consistency of the field's if dependenc and switch dependency.
def correct_if_and_switch_type(packet):
    valid = True
    switch_dependence = []
    switch_dependence_value = []
    if_dependence_info = {}
    for field in packet:
        if 'switch_dependence' in field:
            switch_dependence.extend(field['switch_dependence'])
            switch_dependence_value.extend(field['switch_dependence_value'])
        if 'if_dependence' in field:
            for dependence in field['if_dependence']:
                dependence = dependence[0]
                dependence_field = ''
                dependence_field_value = ''
                if (dependence[0] != '(') and ('==' in dependence): 
                    split_list = re.split(r'[=<>|&()]+', dependence)
                    dependence_field = split_list[0].strip()
                    dependence_field_value = split_list[1].strip()
                elif (dependence[0] == '(') and ('==' in dependence): 
                    split_list = re.split(r'[=<>|&()]+', dependence)
                    dependence_field = split_list[1].strip()
                    dependence_field_value = split_list[2].strip()
                if dependence_field:
                    if dependence_field in if_dependence_info.keys():
                        if (dependence_field_value != if_dependence_info[dependence_field]):
                            valid = False
                            break
                    else:
                        if_dependence_info[dependence_field] = dependence_field_value
    return valid


# filter packet types base on if(tree)
def correct_tree_type(packet):
    valid = True
    for field in packet:
        if 'if_dependence' in field:
            for dependence in field['if_dependence']:
                if_dependence =  dependence[0]
                if_dependence_value =  dependence[1]
                if if_dependence == 'tree' and if_dependence_value == 'false':
                    valid = False
    return valid


def main_analyse(file_path, file_name, func_name, preprocess_file_path, main_parsing_dir, truth_field_dir, output_dir, dissect_table, dissect_name):
    packet_types = []

    with open(file_path, 'r') as file:
        lines = file.readlines()

        # standard fields dir, used to store standard fields for each protocol
        field_list = extract_fields(lines)
        standard_field_dir = os.path.join(main_parsing_dir,'standard_fields')
        if not os.path.exists(standard_field_dir):
            os.makedirs(standard_field_dir)
        
        # write standard fields to json file, under "main-parsing/standard_fields/"
        standard_field_path = os.path.join(standard_field_dir, f"{os.path.splitext(file_name)[0]}.json")
        with open(standard_field_path, 'w', encoding='utf-8') as file:
            json.dump(field_list, file, indent=4)

        # Normalizing, make code conform to unified standards
        # Convert multiple lines into a single line
        convert_to_single_line(file_path, ",")
        convert_to_single_line(file_path, "&")
        convert_to_single_line(file_path, "|")
        convert_to_single_line(file_path, "?")
        convert_to_single_line(file_path, 1)

        # Add braces to structure
        add_brace(file_path, "if")
        add_brace(file_path, "else if")
        add_brace(file_path, "else")
        add_brace(file_path, "for")

        # Add else statement to if structure
        add_else_to_if(file_path, preprocess_file_path)

        # Put { into a single line
        wrap_brace(preprocess_file_path)

        # Find the main dissector function of the target protocol
        with open(preprocess_file_path, 'r') as file:
            lines = file.readlines()     
        main_dissector = find_main_dissector(lines, func_name)
        print("fuction name:", main_dissector)

        # standardized files directory
        standardize_file_dir = os.path.join(main_parsing_dir, 'standard_files')
        if not os.path.exists(standardize_file_dir):
            os.makedirs(standardize_file_dir)

        # Add the subfunction body under the subfunction call to become a standard code
        final_code = []
        standard_file_path = os.path.join(standardize_file_dir, file_name)
        subfunction_call_format = ''
        with open(preprocess_file_path, 'r') as file:
            lines = file.readlines()
            subfunction_call_format = file_name.split('-')[1].strip('.c') + '_decode_'
            print("subfunction_call_format = ", subfunction_call_format)
            dissect_func_name_list = []
            code = add_sub_func_body(lines, main_dissector, final_code, dissect_table, subfunction_call_format, dissect_func_name_list)
        # Write standard code to standard file
        with open(standard_file_path, 'w', encoding= 'utf-8') as file:
            for line in code:
                if line:
                    file.writelines(line+ '\n')

        # Extract packet types based on Base Path Set
        # Output to XXX-extracted.json file under "main-parsing/PROTOCOL"
        output_file_path = os.path.join(output_dir, (dissect_name.strip('.c')+'-extracted.json'))
        packet_types_all_fragments, tvb_get_field = extract_packet_types(standard_file_path, output_file_path, truth_field_dir, field_list, file_name, subfunction_call_format)

        # Expand the basic path set to obtain each packet type
        packet_types_expanded_path = os.path.join(output_dir, (dissect_name.strip('.c')+'-expanded.json'))
        packet_types_expanded = []
        packet_types_expanded.append(packet_types_all_fragments)
        packet_types_expanded_list = expand_packet_types(packet_types_expanded)

        with open(packet_types_expanded_path, 'w', encoding='utf-8') as file:
            json.dump(packet_types_expanded_list, file, indent=4, default = custom_encoder)
        
        # Merge packet types, retaining only field information
        # Output to XXX-merged.json file under "main-parsing/PROTOCOL"
        packet_types_merged_path = os.path.join(output_dir, (dissect_name.strip('.c')+'-merged.json'))
        packet_types_merged = merge_packet_types(packet_types_expanded_list)
        with open(packet_types_merged_path, 'w', encoding='utf-8') as file:
            json.dump(packet_types_merged, file, indent=4, default = custom_encoder)

        # Filter wrong packet types and output the results to XXX-filtered.json file
        packet_types_fieltered_path = os.path.join(output_dir, (dissect_name.strip('.c')+'-filtered.json'))
        packet_types_fieltered = filter_packet_types(packet_types_merged)
        with open(packet_types_fieltered_path, 'w', encoding='utf-8') as file:
            json.dump(packet_types_fieltered, file, indent=4, default = custom_encoder)   

        # Extract standard fields from the filtered packet type and output the fields to XXX-fields.json
        standard_fields = []
        packet_types_standard_fields_path = os.path.join(output_dir, (dissect_name.strip('.c')+'-fields.json'))
        for packet in packet_types_fieltered:
            for field in packet:
                if 'field_identifier' in field:
                    if field['field_identifier'] not in standard_fields:
                        standard_fields.append(field['field_identifier'])
        with open(packet_types_standard_fields_path, 'w', encoding='utf-8') as file:
            json.dump(standard_fields, file, indent=4, default = custom_encoder)  

        # Print the type of each packet type
        for packet in packet_types_fieltered:
            for field in packet:
                if 'switch_dependence_value' in field:
                    print(field['switch_dependence_value'])
            print("-------------------------")

        # Output all types of the target protocol to XXX-packet.json file
        all_packets = []
        packet_types_all_packets_path = os.path.join(output_dir, (dissect_name.strip('.c')+'-packets.json'))
        for packet in packet_types_fieltered:
            for field in packet:
                if 'switch_dependence_value' in field:
                    for types in field['switch_dependence_value']:
                        if types not in all_packets:
                            all_packets.append(types)
        with open(packet_types_all_packets_path, 'w', encoding='utf-8') as file:
            json.dump(all_packets, file, indent=4, default = custom_encoder)  

        # Extract field information from filtered packet type and only important attributes
        # Output to XXX-packet-types.json file
        output_packets = []
        output_packets_path = os.path.join(output_dir, (dissect_name.strip('.c')+'-packet-types.json'))
        for packet in packet_types_fieltered:
            output_packet = []
            for field in packet:
                if 'field_offset' in field and 'field_endian' in field:
                    field_info = {
                        'field_name': field['field_name'],
                        'field_offset': field['field_offset'],
                        'field_length': field['field_length'],
                        'field_type': field['field_type'],
                        'field_endian': field['field_endian'],
                    }
                    output_packet.append(field_info)
            output_packets.append(output_packet)
        with open(output_packets_path, 'w', encoding='utf-8') as file:
            json.dump(output_packets, file, indent=4, default = custom_encoder) 
        
    return packet_types


def read_json_file(file_path):
    with open(file_path, 'r') as file:
        list = json.load(file)
    return list


def main_parsing(proto_name, dissect_name):

        current_dir = os.path.dirname(os.path.abspath(__file__))

        # Pre-processing directory
        pre_process_dir = os.path.join(current_dir, 'pre_process')
        if not os.path.exists(pre_process_dir):
            os.makedirs(pre_process_dir)

        # Preprocessed protocol files dir
        proto_files_dir = os.path.join(pre_process_dir, 'proto_files')
        if not os.path.exists(proto_files_dir):
            os.makedirs(proto_files_dir)

        proto_table_path = os.path.join(pre_process_dir, "proto_table.json")
        dissect_table_path = os.path.join(pre_process_dir, "dissect_table.json")
        proto_table = read_json_file(proto_table_path)
        dissect_table = read_json_file(dissect_table_path)

        # Extract target protocol information by accessing "protocol table" and "parser table"
        target_proto_info = []
        target_proto_info = extract_target_proto_info(proto_table, dissect_table, proto_files_dir, proto_name, dissect_name, target_proto_info)


        # Main-parsing module directory,
        main_parsing_dir = os.path.join(current_dir, 'main_parsing')
        if not os.path.exists(main_parsing_dir):
            os.makedirs(main_parsing_dir)

        # truth field, extracted from "buffer read", used to complete the field information extracted from "proto tree"
        truth_field_dir = os.path.join(main_parsing_dir,'truth_fields')
        if not os.path.exists(truth_field_dir):
            os.makedirs(truth_field_dir)
        # process files in main-parsing module (without subfunction call), used to check the format
        preprocess_files = os.path.join(main_parsing_dir, 'preprocess_files')
        if not os.path.exists(preprocess_files):
            os.makedirs(preprocess_files)
            
        # Extracted syntax information dir, store output results
        result_dir = os.path.join(current_dir, 'syntax_info')
        if not os.path.exists(result_dir):
            os.makedirs(result_dir) 
        # Generate separate directories for each protocol under the "syntax_info" directory
        output_dir = os.path.join(result_dir, proto_name.replace('/', '_'))
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)  

        # multi-layer protocol
        for target_proto in target_proto_info:
            proto_name = target_proto['proto_name']
            dissect_name = target_proto['dissect_name']
            func_name = target_proto['func_name']
            file_name = target_proto['file_name']
            file_path = target_proto['file_path']

            print("=============================Selected Protocol Information=============================")
            print("Protocol name:", proto_name)
            print("Dissector name:", dissect_name)
            print("Function name:", func_name)
            print("File name:", file_name)
            print("File path:", file_path) 

            # main-parsing process
            preprocess_file_path = os.path.join(preprocess_files, file_name)
            print("=============================Main-parsing Module=============================")
            packet_types = main_analyse(file_path, file_name, func_name, preprocess_file_path, main_parsing_dir, truth_field_dir, output_dir, dissect_table, dissect_name)
