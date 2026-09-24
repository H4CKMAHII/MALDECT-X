from pathlib import Path
from datetime import datetime


def get_metadata(file_path):
    path = Path(file_path)

    try:
        stat = path.stat()

        return {
            "file_name": path.name,
            "file_size": stat.st_size,
            "created": datetime.fromtimestamp(stat.st_ctime).isoformat(
                timespec="seconds"
            ),
            "modified": datetime.fromtimestamp(stat.st_mtime).isoformat(
                timespec="seconds"
            )
        }

    except OSError as error:
        return {
            "error": str(error)
        }
