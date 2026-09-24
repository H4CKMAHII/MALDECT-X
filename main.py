from analyzer.file_identifier import identify_file
from analyzer.hash_analyzer import calculate_hashes
from analyzer.metadata_analyzer import get_metadata
from analyzer.pe_analyzer import analyze_pe
from analyzer.yara_analyzer import scan_with_yara
from analyzer.risk_engine import calculate_risk
from analyzer.string_analyzer import (
    extract_strings,
    find_suspicious_strings
)

from analyzer.entropy_analyzer import calculate_entropy

def analyze_file(file_path):
    print("\n" + "=" * 60)
    print("             MALDETECT-X")
    print("          UNIVERSAL FILE ANALYZER")
    print("=" * 60)

    metadata = get_metadata(file_path)
    file_info = identify_file(file_path)
    hashes = calculate_hashes(file_path)
    strings = extract_strings(file_path)
    suspicious = find_suspicious_strings(strings)
    entropy = calculate_entropy(file_path)
    pe_info = analyze_pe(file_path)
    yara_matches = scan_with_yara(
        file_path,
        "rules/malware_rules.yar"
    )
    risk = calculate_risk(
        suspicious_strings=len(suspicious),
        suspicious_imports=len(
            pe_info.get("suspicious_imports", [])
        ),
        yara_matches=len(yara_matches),
        entropy=entropy
    )
        
    print("\n[FILE INFORMATION]")
    print("-" * 60)
    print(f"File Name : {metadata.get('file_name')}")
    print(f"File Size : {metadata.get('file_size')} bytes")
    print(f"Extension : {file_info.get('extension')}")
    print(f"File Type : {file_info.get('type')}")

    print("\n[HASH INFORMATION]")
    print("-" * 60)
    print(f"MD5      : {hashes.get('md5')}")
    print(f"SHA-1    : {hashes.get('sha1')}")
    print(f"SHA-256  : {hashes.get('sha256')}")
    
    

    print("\n[METADATA]")
    print("-" * 60)
    print(f"Created  : {metadata.get('created')}")
    print(f"Modified : {metadata.get('modified')}")

    print("\n" + "=" * 60)
    
    print("\n[STRING ANALYSIS]")
    print("-" * 60)
    print(f"Total Strings Found : {len(strings)}")
    print(f"Suspicious Matches  : {len(suspicious)}")

    for finding in suspicious[:10]:
        print(
            f"[!] {finding['keyword']} -> "
            f"{finding['string'][:100]}"
        )

    print("\n[ENTROPY ANALYSIS]")
    print("-" * 60)
    print(f"File Entropy : {entropy}")
    
    
    print("\n[PE ANALYSIS]")
    print("-" * 60)

    if pe_info["is_pe"]:
        print(f"Architecture : {pe_info['architecture']}")
        print(f"Entry Point  : {pe_info['entry_point']}")
        print(f"Image Base   : {pe_info['image_base']}")

        print("\nSections:")

        for section in pe_info["sections"]:
            print(
                f"  {section['name']:<10} "
                f"Entropy: {section['entropy']}"
            )

        print("\nSuspicious Imports:")

        if pe_info["suspicious_imports"]:
            for api in pe_info["suspicious_imports"]:
                print(f"  [!] {api}")
        else:
            print("  None detected")

    else:
        print("Not a PE file - PE analysis not applicable.")
        
        print("\n[YARA ANALYSIS]")
    print("-" * 60)

    if yara_matches:
        for match in yara_matches:
            print(f"[!] Rule Match: {match['rule']}")
            print(f"    Tags: {', '.join(match['tags'])}")
    else:
        print("No YARA rule matched.")
        
    
    print("\n[RISK ASSESSMENT]")
    print("-" * 60)
    print(f"Risk Score : {risk['score']}/100")
    print(f"Verdict    : {risk['verdict']}")

    if risk["reasons"]:
        print("\nReasons:")
        for reason in risk["reasons"]:
            print(f"  [!] {reason}")
    else:
        print("No significant suspicious indicators detected.")


if __name__ == "__main__":
    file_path = input("Enter file path: ").strip()

    analyze_file(file_path)
