#!/usr/bin/env python3
import sys
from lxml import etree

def debug_xml_parsing(path):
    try:
        tree = etree.parse(path)
        root = tree.getroot()
        
        # Count different violation types
        stdviol_count = len(root.xpath("//StdViol"))
        flowviol_count = len(root.xpath("//FlowViol"))
        combined_count = len(root.xpath("//StdViol | //FlowViol"))
        
        print(f"StdViol count: {stdviol_count}")
        print(f"FlowViol count: {flowviol_count}")
        print(f"Combined count: {combined_count}")
        print(f"Total expected: {stdviol_count + flowviol_count}")
        
        # Check severity distribution
        sev1_count = len(root.xpath("//StdViol[@sev='1'] | //FlowViol[@sev='1']"))
        sev2_count = len(root.xpath("//StdViol[@sev='2'] | //FlowViol[@sev='2']"))
        sev3_count = len(root.xpath("//StdViol[@sev='3'] | //FlowViol[@sev='3']"))
        
        print(f"Severity 1 (Highest): {sev1_count}")
        print(f"Severity 2 (High): {sev2_count}")
        print(f"Severity 3 (Medium): {sev3_count}")
        
        # Test the XPath expression
        violations = root.xpath("//StdViol | //FlowViol")
        processed_count = 0
        excluded_count = 0
        error_count = 0
        
        excluded_directories = []  # No exclusions for now
        
        for violation in violations:
            try:
                file_path = violation.get("locFile", "")
                if file_path and file_path.startswith('/'):
                    file_path = file_path[1:]
                
                # Check if the file is in an excluded directory
                if any(excluded_dir in file_path for excluded_dir in excluded_directories):
                    excluded_count += 1
                    continue
                
                processed_count += 1
            except Exception as e:
                error_count += 1
        
        print(f"Processed violations: {processed_count}")
        print(f"Excluded violations: {excluded_count}")
        print(f"Error violations: {error_count}")
        
    except Exception as e:
        print(f"Error parsing XML: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    print("=== Checking report.xml ===")
    debug_xml_parsing("C:/Parasoft/NISKO_LATE/final report/report.xml")
    print("\n=== Checking report2857483253601862296.xml ===")
    debug_xml_parsing("C:/Parasoft/NISKO_LATE/final report/report2857483253601862296.xml")
