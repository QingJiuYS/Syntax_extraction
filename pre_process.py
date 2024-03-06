import json
import os
import re
import shutil
import time


def custom_encoder(obj):
    if isinstance(obj, list) and all(isinstance(item, str) for item in obj):
        return {'__list_of_strings__': obj}
    return obj


def improve_relation(dissect_list):
    for dissect in dissect_list:
        if dissect['lower'] not in ['tcp', 'udp', None] and dissect['type'] == 'global':
            if dissect['upper'] != []:
                for dissect_tar in dissect_list:
                    for dissect_name in dissect['upper']:
                        if dissect_tar['dissect_name'] == dissect_name:
                            dissect_tar['lower'] = dissect['proto_identifier_name']


def extract_parameter(line):
    content = ''
    left_bracket_index = line.find('(')
    if left_bracket_index != -1:
        right_bracket_index = line.rfind(')')
        if right_bracket_index != -1:
            content = line[left_bracket_index + 1:right_bracket_index].split(',')
    return content
    

def save_port_info_to_dissect_list(dissect_code, this_dissect):
    content = extract_parameter(dissect_code)
    port_type = content[0].strip().strip('"').strip()
    port_num = content[1].strip()
    dissect_handle = content[2].strip()
    print('port_type = ', port_type)
    print('port_num = ', port_num)
    print('dissect_handle = ', dissect_handle)
    for dissector in this_dissect:
        print(dissector)
        if 'dissect_handle' in dissector and dissector['dissect_handle'] == dissect_handle:
            dissector['port_num'] = port_num
            dissector['port_type'] = port_type


def save_dissect_to_list(dissect_code, this_dissect, dissect_all, proto_list):
    content = extract_parameter(dissect_code)
    print(content)
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

    for proto in proto_list:
        if dissect_info["proto_handle"] == proto["proto_handle"]:
            dissect_info["proto_name"] = proto["proto_name"]
            dissect_info["proto_identifier_name"] = proto["identifier_name"]
            dissect_info["file_name"] = proto["file_name"]
            this_dissect.append(dissect_info)
            break


def extract_dissect_info(proto_list, code, this_dissect, dissect_all, tag):
    dissect_handle = ''

    content = extract_param(code)
    # global
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
    # local
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
        
    for proto in proto_list:
        if dissect_info["proto_handle"] == proto["proto_handle"]:
            dissect_info["proto_name"] = proto["proto_name"]
            dissect_info["proto_identifier_name"] = proto["identifier_name"]
            dissect_info["file_name"] = proto["file_name"]
            this_dissect.append(dissect_info)
            break
    return dissect_handle


def extract_param(line):
    content = ''
    left_bracket_index = line.find('(')
    if left_bracket_index != -1:
        right_bracket_index = line.rfind(')')
        if right_bracket_index != -1:
            content = line[left_bracket_index + 1:right_bracket_index].split(',')
    return content


def extract_proto_info(file_name, code, proto_list):
    proto_names = {}
    proto_handle = ''
    proto_handle = code.split('=')[0].strip()

    content = extract_param(code)
    long_name = content[0].strip(' "').strip()
    short_name = content[1].strip(' "').strip()
    identifier_name = content[2].strip(' "').strip()
    print("content = ", content)
    print("content[0] = ", long_name)
    print("content[1] = ", short_name)
    print("content[2] = ", identifier_name)
    proto_names = {
        "long_name": long_name,
        "short_name": short_name,
        "identifier_name": identifier_name
    }
    proto_info = {
        "file_name": file_name,
        "proto_handle": proto_handle,
        "proto_name": long_name,
        "short_name": short_name,
        "identifier_name": identifier_name
    }
    proto_list.append(proto_info)
    return proto_names, proto_handle

def extract_chunck(register_body, code_name):
    body = []
    in_body = False
    for line in register_body:
        line = line.strip()
        old_line = line 
        current_line = line

        if (code_name + "()") in line:
            continue
        elif (code_name + "(") in line and ");" in line:
            body.append(line)
        elif (code_name + " (") in line and ");" not in line:
            body.append(line)
            in_body = True
            continue
        elif (code_name + "(") in line and ");" not in line:
            body.append(line)
            in_body = True
            continue
        if in_body:
            body[-1] = body[-1] + line.split('/*')[0].strip()
            if ");" in line:
                in_body = False
    return body


def merge_code(lines, string):
    merged_lines = []
    in_line = False
    current_line = ""

    if string == "=":
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
    elif string == ",":
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
    
    elif string == "&":
        for line in lines:
            line = line.rstrip()
            if line.endswith("&") and not in_line:
                current_line += line
                in_line = True
                continue
            if in_line:
                line = line.strip()
                current_line += line
                if line.endswith("{"):
                    in_line = False
                else:
                    continue
            if current_line:
                merged_lines.append(current_line)
                current_line = ''
                continue
            merged_lines.append(line)
    elif string == "|":
        for line in lines:
            line = line.rstrip()
            if line.endswith("|") and not in_line:
                current_line += line
                in_line = True
                continue
            if in_line:
                line = line.strip()
                current_line += line
                if line.endswith("{"):
                    in_line = False
                else:
                    continue
            if current_line:
                merged_lines.append(current_line)
                current_line = ''
                continue
            merged_lines.append(line)

    return merged_lines


def convert_to_single_line(source_file_path, string):
    try:
        with open(source_file_path, 'r', encoding='utf-8') as file:
            lines = file.readlines()
        merged_lines = merge_code(lines, string)

        with open(source_file_path, 'w', encoding='utf-8') as file:
            file.seek(0)
            merged_lines_with_newlines = [line + '\n' for line in merged_lines]
            file.writelines(merged_lines_with_newlines)
            file.truncate()
    except FileNotFoundError:
        print(f"Error: File '{source_file_path}' not found.")
    except Exception as e:
        print(f"An error occurred: {e}")


def remove_comments(source_file_path, new_file_path):
    try:
        with open(source_file_path, 'r', encoding='utf-8') as file:
            content = file.read()
        pattern = re.compile(r'/\*.*?\*/|//.*?$', re.DOTALL | re.MULTILINE)
        content = pattern.sub('', content)

        with open(new_file_path, 'w', encoding = 'utf-8') as new_file:
            new_file.writelines(content)

        print(f"Content copied from '{source_file_path}' to '{new_file_path}'.")

    except FileNotFoundError:
        print(f"Error: File '{source_file_path}' not found.")
    except Exception as e:
        print(f"An error occurred: {e}")


def pre_process(directory, current_path, proto_list_path, dissect_list_path):
    
    start_time = time.time()

    proto_list = []
    dissect_list = []
    dissect_all = []
    num = 0
    for root, dirs, files in os.walk(directory):
        for file_name in files:
            if file_name.startswith("packet-") and file_name.endswith(".c") and not file_name.endswith("-template.c"):
            # if file_name == ("packet-mbtcp.c"):
            # if file_name == ("packet-dccp.c"):
            # if file_name == ("packet-dnp.c"):
            # if file_name == ("packet-s7comm.c"):
            # if file_name == ("packet-ositp.c"):
            # if file_name == ("packet-tpkt.c"):
                source_file_path = os.path.join(root, file_name)
                num += 1
                new_file_path = os.path.join(current_path,'pre_process', 'proto_files', file_name)
                os.makedirs(os.path.dirname(new_file_path), exist_ok=True)

                remove_comments(source_file_path, new_file_path) 
                convert_to_single_line(new_file_path, "=")
                with open(new_file_path, 'r', encoding = 'utf-8') as file:
                    this_dissect = []

                    lines = file.readlines()                
                    register_code = extract_chunck(lines, "proto_register_protocol")
                    if register_code:
                        for proto in register_code:
                            proto_names, proto_handle = extract_proto_info(file_name, proto, proto_list)

                    # global
                    dissector_global = extract_chunck(lines, "register_dissector")

                    if dissector_global:


                        for dissect in dissector_global:
                            dissect_handle = extract_dissect_info(proto_list, dissect, this_dissect, dissect_all, True)
                            
                    # local
                    dissector_local = extract_chunck(lines, "create_dissector_handle")

                    if dissector_local:
                        for dissect in dissector_local:
                            pattern = r'create_dissector_handle\([^)]+\)'
                            match = re.search(pattern, dissect)
                            if match:
                                code =  match.group()
                            else:
                                code = None
                            dissect_handle = extract_dissect_info(proto_list, dissect, this_dissect, dissect_all, False)

                    dissector_upper = extract_chunck(lines, "heur_dissector_add")
                    if dissector_upper:
                        for dissect in dissector_upper:
                            save_dissect_to_list(dissect, this_dissect, dissect_all, proto_list)
                        dissector_upper = []

                    dissector_port = extract_chunck(lines, "dissector_add_uint_with_preference")
                    if dissector_port:
                        for dissect in dissector_port:
                            save_port_info_to_dissect_list(dissect, this_dissect)
                        dissector_port = []

                    dissector_lower = extract_chunck(lines, "find_dissector")
                    if dissector_lower:
                        for dissect in dissector_lower:
                            content = extract_parameter(dissect)
                            upper = content[0].strip('"').strip()
                            dissect_handle = dissect.split('=')[0].strip()
                            for dissector in this_dissect:
                                dissector['upper'] = [upper]

                    for dissect in this_dissect:
                        dissect_list.append(dissect)
                    this_dissect = []


    # improve relation
    improve_relation(dissect_list)

    with open(proto_list_path, 'w', encoding='utf-8') as file:
        json.dump(proto_list, file, indent=4, default = custom_encoder)
    with open(dissect_list_path, 'w', encoding='utf-8') as file:
        json.dump(dissect_list, file, indent=4, default = custom_encoder) 

                    
    # end time
    end_time = time.time()
    run_time = end_time - start_time
    print(f"pre-process time:{run_time:.2f} 秒")
    print("protocl number：", num)
    return proto_list, dissect_list, dissect_all


def main():
        directory_path = "C:/Users/lhs/Desktop/wireshark/epan/dissectors"
        current_path = os.path.dirname(os.path.abspath(__file__))
               
        pre_process_dir = os.path.join(current_path,'pre_process')
        if not os.path.exists(pre_process_dir):
            os.makedirs(pre_process_dir)

        proto_list_path = os.path.join(pre_process_dir, 'proto_list.json')
        dissect_list_path = os.path.join(pre_process_dir, 'dissect_list.json')

        proto_list, dissect_list, proto_dissect_map = pre_process(directory_path, current_path, proto_list_path, dissect_list_path)


if __name__ == "__main__":
    main()