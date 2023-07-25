import os
import sys
import re
import pathlib

from pathlib import Path
from itertools import product

import xml.etree.ElementTree as ET

SCRIPT_DIRECTORY_PATH = pathlib.Path.cwd()
INPUT_FILE_DIRECTORY = Path(SCRIPT_DIRECTORY_PATH, "Data")
REPORT_FILE_DIRECTORY = Path(SCRIPT_DIRECTORY_PATH, "Reports")

TEMPLATE_FILE_PATH = Path(SCRIPT_DIRECTORY_PATH, "Project_templates", "Template.xml")

CVE_PATTERN = r'CVE-\d{4}-\d{4,}'
CVE_NUMBERS_PATTERN = r'\d{4}-\d{4,}'

def file_existence_check() -> None:
    '''Check if file already existe in report directory with such name as input file.
    Code will execute only if report file doesn't existe.
      
    '''
    input_files = os.listdir(INPUT_FILE_DIRECTORY)
    report_files = os.listdir(REPORT_FILE_DIRECTORY)
    for input_file in input_files:
        input_file_path = Path(INPUT_FILE_DIRECTORY, input_file)
        if not report_files or input_file not in report_files:
            execute_code(input_file_path, input_file)

def read_inputfile(file_path: Path) -> ET.ElementTree:
    '''Read any files
    
    Parameters: 
        file_path (Path): full file path
        
    Returns:
        tree (ElementTree): xml-tree structure
        
    '''
    try:
        tree = ET.parse(file_path)
    except FileNotFoundError:
        print(f"Input file {file_path} doesn't exist in such directory")
        sys.exit()
    return tree

def get_cve_by_ports(host_tag: ET.Element) -> list:
    '''Get cve and port information from input nmap report
    
    Parameters:
        host_tag (ET.Element): xml-tag for search
        
    Returns:
        list_cves (list): info port-cves
    '''
    list_cves = []
    for port_tag in host_tag.iter('port'):
        port_id = port_tag.get('portid')
        port_tag_str = ET.tostring(port_tag).decode()
        cve =  re.findall(CVE_PATTERN, port_tag_str)
        cve_list = list(dict.fromkeys(cve))
        if cve_list:
            port_data = {"port":port_id, "cve":cve_list}
            list_cves.append(port_data)
    return list_cves

def get_hostdata(host_tag: ET.Element) -> dict:
    '''Get host information from input nmap report
    
    Parameters:
        host_tag (ET.Element): xml-tag for search
        
    Returns:
        host_data (dict): ip, mac and hostname info
    
    '''
    host_data = {"ipv4": "", "mac": "", "hostname": []}
    for address_tag in host_tag.iter('address'):
        if address_tag.attrib['addrtype'] == 'ipv4':
            host_data["ipv4"] = address_tag.get('addr')
        elif address_tag.attrib['addrtype'] == 'mac':
            host_data["mac"] = address_tag.get('addr')
    for hostnames_tag in host_tag.iter('hostnames'):
        for hostname_tag in hostnames_tag.iter('hostname'):
            host_data['hostname'].append(hostname_tag.get('name'))
    return host_data

def input_data (input_file_path) -> list:
    '''Get final list with requeried data for QRadar:
    
    Returns:
        final_cve_list (list): list of lists by hosts
    
    '''
    unfiltered_data = []
    final_cve_list = []
    tree = read_inputfile(input_file_path)
    for host_tag in tree.iter('host'):
        list_cves = get_cve_by_ports(host_tag)
        host_data = get_hostdata(host_tag)
        list_cves.append(host_data)
        unfiltered_data.append(list_cves)
    for cve_list in unfiltered_data:
        if any("cve" in list for list in cve_list):
            final_cve_list.append(cve_list)
    return final_cve_list

def add_hosts_to_report_template(final_cve_list: list, input_file) -> Path:
    '''Read template data and create report file with required hosts number
    
    Parameters:
        host_count (int): host number from nmap report
    
    '''
    tree_t = read_inputfile(TEMPLATE_FILE_PATH)
    root_t = tree_t.getroot()
    host_tag = root_t.find('host')
    host_count = len(final_cve_list)
    while host_count > 1:
        host_count -= 1
        root_t.append(host_tag)
    tree = ET.ElementTree(root_t)
    report_file = Path(REPORT_FILE_DIRECTORY, input_file)
    tree.write(open(report_file, 'wb'), encoding="UTF-8")
    return report_file

def replace_information_in_template(final_cve_list: list, report_file: Path) -> None:
    '''Fill in qradar xml-file with information from nmap report
    
    Parameters:
        final_cve_list (list): final list with requeried data
        last_seen_time (str): nmap report creation time

    '''
    tree_r = ET.parse(report_file)
    index = 0
    for host_tag in tree_r.iter('host'):
        for _ in final_cve_list:
            current_list = final_cve_list[index]
            
            for ip_tag, mac_tag, item in product(host_tag.iter('ip'), host_tag.iter('macAddress'), current_list):
                if "ipv4" in item:
                    ip_tag.set("value", item["ipv4"])
            
            for mac_tag, item in product(host_tag.iter('macAddress'), current_list):
                if "mac" in item:
                    mac_tag.text = item["mac"]
            
            for hostname_tag in host_tag.iter('hostName'):
                for item in current_list:
                    hostname_tag.text = ''
                    if "hostname" in item:
                        host_names = item['hostname']
                        if len(host_names) > 1:
                            hostname_tag.text = host_names[0]
                            for name in host_names[1:]:
                                new_hostname = ET.SubElement(host_tag, 'hostName')
                                new_hostname.text = name
                        elif len(host_names) == 1:
                            hostname_tag.text = host_names[0]
                break
            
            for port_tag in host_tag.iter('port'):
                for item_index, item in enumerate(current_list):
                    if "port" in item:
                        port = item["port"]
                        if item_index == 0:
                            port_tag.set("value", port)
                        else:
                            new_port_tag = ET.Element("port")
                            host_tag.append(new_port_tag)
                            new_port_tag.set("value", port)
                            new_cve_tag = ET.Element('vulnerability')
                            new_cve_tag.set ("type", "CVE ID")
                            new_port_tag.append(new_cve_tag)
                break
            
            for item_index, item in enumerate(current_list):
                if "cve" in item:
                    cve_numbers =  re.findall(CVE_NUMBERS_PATTERN, str(item["cve"]))
                    for port_index, port_tag in enumerate(host_tag.iter('port')):
                        if port_index == item_index:
                            for vulnerability_tag in port_tag.findall("vulnerability"):
                                for cve_number in cve_numbers:
                                    new_cve = vulnerability_tag if cve_numbers.index(cve_number) == 0 else ET.Element('vulnerability')
                                    new_cve.set("type", "CVE ID")
                                    new_cve.set("id", cve_number)
                                    new_cve.set("risk", '3')
                                    if cve_numbers.index(cve_number) != 0:
                                        port_tag.append(new_cve)
                            break
            break
        index +=1
    tree_r.write(open(report_file, 'wb'),  encoding="UTF-8", xml_declaration=True)

def change_report_format(report_file) -> None:
    '''Change CRLF control character to LF (Qradar read format).'''
    with open(report_file, 'rb') as file:
        content = file.read()
    content = content.replace(b'\r\n', b'\n')
    with open(report_file, 'wb') as file:
        file.write(content)

def execute_code(input_file_path: Path, input_file: str) -> None:
    ''' Create QRadar report based on new nmap report'''
    final_cve_list = input_data(input_file_path)
    report_file = add_hosts_to_report_template(final_cve_list, input_file)
    replace_information_in_template(final_cve_list, report_file)
    change_report_format(report_file)

if __name__ == "__main__":
    file_existence_check()