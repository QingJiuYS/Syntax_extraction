import json
import os
import re
import shutil
import time
import csv


def convert_to_map(proto_list, dissect_list):

    proto_dissect_map = []

    for proto in proto_list:
        current_map = {}
        # 提取协议名称
        proto_name = proto['proto_name']
        short_name = proto['short_name']
        current_map['proto_name'] = proto_name
        current_map['short_name'] = short_name
        current_map['dissect_name'] = []

        # 判断是否已经存在该协议
        # if proto_name in proto_dissect_map:
            # continue

        # 创建映射，以协议名称为键，以协议拥有的解析器的函数名为值
        # proto_dissect_map[proto_name] = []
        # 遍历解析器表
        for dissect in dissect_list:
            # 查找与当前协议名称匹配的解析器
            if dissect['dissect_name'] and dissect['proto_name'] == proto_name:
                dissect_name = dissect['dissect_name']
                # 将解析器的函数名作为值存储到映射中
                current_map['dissect_name'].append(dissect_name)
                # proto_dissect_map[proto_name].append(dissect['dissect_name'])
        proto_dissect_map.append(current_map)
    
    return proto_dissect_map


# 将列表中的字符串进行处理，使其可以序列化为json
def custom_encoder(obj):
    if isinstance(obj, list) and all(isinstance(item, str) for item in obj):
        return {'__list_of_strings__': obj}
    return obj


# 读取 JSON 文件内容并存储到列表中
def read_json_file(file_path):
    with open(file_path, 'r') as file:
        list = json.load(file)
    return list


def write_to_map(fiel_path, proto_dissect_map):
    with open(fiel_path, 'w', encoding='utf-8') as file:
        json.dump(proto_dissect_map, file, indent=4, default = custom_encoder)
        print("成功写入到proto_dissect_map.json文件！")

    
def write_to_csv(csv_file_path, proto_dissect_map):

    with open(csv_file_path, "w", newline="") as csv_file:

        writer = csv.DictWriter(csv_file, fieldnames=["protocol", "dissector"])
        writer.writeheader()
        for map in proto_dissect_map:
            writer.writerow(map)


def select_proto(proto_dissect_map):
    proto_name = ''
    dissect_name = ''
    protos = []
    for map in proto_dissect_map:
        protos.append(map['proto_name'])
        # print(map['proto_name'])


    print("请选择一个选项:")
    for i, proto in enumerate(protos, 1):
        print(f"{i}. {proto}")
        
    print("Modbus/TCP协议编号为980")
    print("Modbus/UDP协议编号为981")
    print("Modbus RTU协议编号为982")
    print("Modbus协议编号为983")
    print("S7 Communication协议编号为1420")
    proto_choice = int(input("请输入协议的编号："))

    
    # 检查用户输入的编号是否在有效范围内
    if 1 <= proto_choice <= len(protos):
        selected_proto = protos[proto_choice - 1]
        print("你选择的协议为:", selected_proto)

        proto_name = selected_proto

        for map in proto_dissect_map:
            if map['proto_name'] == proto_name:
                dissectors = map['dissect_name']
                break
        print("请选择一个选项:")
        for i, dissector in enumerate(dissectors, 1):
            print(f"{i}. {dissector}")
        dissector_choice = int(input("请输入解析器的编号："))
        if 1 <= dissector_choice <= len(dissectors):
            selected_dissect = dissectors[dissector_choice - 1]
            print("你选择的解析器为:", selected_dissect)
            dissect_name = selected_dissect
        else:
            print("无效的解析器编号!")
            
    else:
        print("无效的协议编号！")

    return proto_name, dissect_name


def main():
        current_path = os.path.dirname(os.path.abspath(__file__))
        
        # 将pre_process文件夹作为输出目录
        pre_process_dir = os.path.join(current_path,'pre_process')

        # 获取协议表文件路径，为当前脚本所在目录的同级目录下的dissect_list.json文件
        proto_list_path = os.path.join(pre_process_dir, "proto_list.json")
        # 获取解析器表文件路径，为当前脚本所在目录的同级目录下的dissect_list.json文件
        dissect_list_path = os.path.join(pre_process_dir, "dissect_list.json")
        # 读取协议表文件
        proto_list = read_json_file(proto_list_path)
        # 读取解析器表文件
        dissect_list = read_json_file(dissect_list_path)
        # print(dissect_list)

        # 选择待解析协议
        proto_dissect_map = convert_to_map(proto_list, dissect_list)

        # csv_file_path = os.path.join(os.path.dirname(__file__), "proto_dissect_map.csv")
        # write_to_csv(csv_file_path, proto_dissect_map)


        map_file_path = os.path.join(pre_process_dir, "proto_dissect_map.json")
        write_to_map(map_file_path, proto_dissect_map)

        # print(proto_dissect_map)

        proto_name, dissect_name = select_proto(proto_dissect_map)
        print('---------------------------------------')
        print('选择的协议为：', proto_name)
        print('选择的解析器为：', dissect_name)
        print('---------------------------------------')

        
if __name__ == "__main__":
    main()