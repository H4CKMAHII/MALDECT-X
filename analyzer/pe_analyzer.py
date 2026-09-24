import pefile


SUSPICIOUS_APIS = {
    "VirtualAlloc",
    "VirtualAllocEx",
    "WriteProcessMemory",
    "CreateRemoteThread",
    "WinExec",
    "ShellExecuteA",
    "ShellExecuteW",
    "CreateProcessA",
    "CreateProcessW",
    "URLDownloadToFileA",
    "URLDownloadToFileW",
    "InternetOpenA",
    "InternetOpenW",
    "RegSetValueExA",
    "RegSetValueExW",
}


def analyze_pe(file_path):
    try:
        pe = pefile.PE(file_path)

        # Architecture
        if pe.FILE_HEADER.Machine == 0x14C:
            architecture = "x86 (32-bit)"
        elif pe.FILE_HEADER.Machine == 0x8664:
            architecture = "x64 (64-bit)"
        else:
            architecture = "Unknown"

        # Sections
        sections = []

        for section in pe.sections:
            name = section.Name.rstrip(b"\x00").decode(
                errors="ignore"
            )

            entropy = section.get_entropy()

            sections.append({
                "name": name,
                "virtual_size": section.Misc_VirtualSize,
                "raw_size": section.SizeOfRawData,
                "entropy": round(entropy, 4)
            })

        # Imported APIs
        imports = []
        suspicious_imports = []

        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            for dll in pe.DIRECTORY_ENTRY_IMPORT:
                dll_name = dll.dll.decode(
                    errors="ignore"
                )

                for entry in dll.imports:
                    if entry.name:
                        api_name = entry.name.decode(
                            errors="ignore"
                        )

                        imports.append(
                            f"{dll_name}!{api_name}"
                        )

                        if api_name in SUSPICIOUS_APIS:
                            suspicious_imports.append(
                                f"{dll_name}!{api_name}"
                            )

        return {
            "is_pe": True,
            "architecture": architecture,
            "entry_point": hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint),
            "image_base": hex(pe.OPTIONAL_HEADER.ImageBase),
            "sections": sections,
            "imports": imports,
            "suspicious_imports": suspicious_imports,
        }

    except (pefile.PEFormatError, OSError):
        return {
            "is_pe": False
        }
