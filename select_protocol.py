import json
import os
import csv


def convert_to_map(proto_list, dissect_list):
    proto_dissect_map = []
    for proto in proto_list:
        current_map = {}
        proto_name = proto['proto_name']
        short_name = proto['short_name']
        current_map['proto_name'] = proto_name
        current_map['short_name'] = short_name
        current_map['dissect_name'] = []
        for dissect in dissect_list:
            if dissect['dissect_name'] and dissect['proto_name'] == proto_name:
                dissect_name = dissect['dissect_name']
                current_map['dissect_name'].append(dissect_name)
        proto_dissect_map.append(current_map)
    return proto_dissect_map


def custom_encoder(obj):
    if isinstance(obj, list) and all(isinstance(item, str) for item in obj):
        return {'__list_of_strings__': obj}
    return obj


def read_json_file(file_path):
    with open(file_path, 'r') as file:
        list = json.load(file)
    return list


def write_to_map(fiel_path, proto_dissect_map):
    with open(fiel_path, 'w', encoding='utf-8') as file:
        json.dump(proto_dissect_map, file, indent=4, default = custom_encoder)
        print("Successfully written to file:proto_dissect_map.json")


def select_proto(proto_dissect_map):
    proto_name = ''
    dissect_name = ''
    protos = []
    for map in proto_dissect_map:
        protos.append(map['proto_name'])


    for i, proto in enumerate(protos, 1):
        print(f"{i}. {proto}")
    print("Modbus/TCP Protocol Number:980")
    print("Modbus/UDP Protocol Number:981")
    print("Modbus RTU Protocol Number:982")
    print("Modbus Protocol Number:983")
    print("S7Comm Protocol Number:1420")
    proto_choice = int(input("Please enter the number:"))

    
    if 1 <= proto_choice <= len(protos):
        selected_proto = protos[proto_choice - 1]
        proto_name = selected_proto
        for map in proto_dissect_map:
            if map['proto_name'] == proto_name:
                dissectors = map['dissect_name']
                break
        for i, dissector in enumerate(dissectors, 1):
            print(f"{i}. {dissector}")
        dissector_choice = int(input("Please select an dissector:"))
        if 1 <= dissector_choice <= len(dissectors):
            selected_dissect = dissectors[dissector_choice - 1]
            dissect_name = selected_dissect
        else:
            print("Invalid Dissector Number!")
    else:
        print("Invalid Protocol Number!")

    return proto_name, dissect_name


def main():
        current_path = os.path.dirname(os.path.abspath(__file__))
        pre_process_dir = os.path.join(current_path,'pre_process')
        proto_list_path = os.path.join(pre_process_dir, "proto_list.json")
        dissect_list_path = os.path.join(pre_process_dir, "dissect_list.json")
        proto_list = read_json_file(proto_list_path)
        dissect_list = read_json_file(dissect_list_path)

        proto_dissect_map = convert_to_map(proto_list, dissect_list)
        map_file_path = os.path.join(pre_process_dir, "proto_dissect_map.json")
        write_to_map(map_file_path, proto_dissect_map)

        proto_name, dissect_name = select_proto(proto_dissect_map)
        print('---------------------------------------')
        print('Selected Protocol:', proto_name)
        print('Selected Dissector:', dissect_name)
        print('---------------------------------------')

        
if __name__ == "__main__":
    main()
