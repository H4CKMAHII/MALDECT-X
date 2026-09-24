from pathlib import Path


def identify_file(file_path):
    path = Path(file_path)

    extension = path.suffix.lower() if path.suffix else "No Extension"

    file_signatures = {
        b"MZ": "Windows PE Executable",
        b"\x7fELF": "Linux ELF Executable",
        b"%PDF": "PDF Document",
        b"PK\x03\x04": "ZIP / Office / APK / JAR Archive",
        b"\x89PNG": "PNG Image",
        b"\xff\xd8\xff": "JPEG Image",
        b"GIF8": "GIF Image",
        b"Rar!": "RAR Archive",
        b"7z\xbc\xaf'\x1c": "7-Zip Archive",
    }

    detected_type = "Unknown / Generic File"

    try:
        with open(file_path, "rb") as file:
            header = file.read(16)

        for signature, file_type in file_signatures.items():
            if header.startswith(signature):
                detected_type = file_type
                break

    except OSError as error:
        return {
            "extension": extension,
            "type": "Error",
            "error": str(error)
        }

    return {
        "extension": extension,
        "type": detected_type
    }
