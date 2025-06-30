import os
import datetime
from PIL import Image
import piexif

# Thresholds for timestamp validation
EARLIEST_ALLOWED_YEAR = 1990
LATEST_ALLOWED_YEAR = datetime.datetime.now().year + 1

def load_exif(file_path):
    try:
        img = Image.open(file_path)
        exif_data = piexif.load(img.info.get("exif", b""))
        return exif_data
    except Exception as e:
        print(f"[ERROR] Could not read EXIF data from {file_path}: {e}")
        return None

def parse_exif_timestamp(timestamp):
    try:
        return datetime.datetime.strptime(timestamp.decode(), "%Y:%m:%d %H:%M:%S")
    except Exception:
        return None

def check_exif_integrity(exif_data, file_path):
    flagged = []

    # Extract timestamps
    try:
        dt = parse_exif_timestamp(exif_data['0th'][piexif.ImageIFD.DateTime])
        dto = parse_exif_timestamp(exif_data['Exif'][piexif.ExifIFD.DateTimeOriginal])
        dtd = parse_exif_timestamp(exif_data['Exif'][piexif.ExifIFD.DateTimeDigitized])
    except KeyError:
        dt = dto = dtd = None

    timestamps = [dt, dto, dtd]
    valid_times = [ts for ts in timestamps if ts]

    if valid_times:
        for ts in valid_times:
            if ts.year < EARLIEST_ALLOWED_YEAR or ts.year > LATEST_ALLOWED_YEAR:
                flagged.append("Unusual timestamp: " + ts.strftime("%Y-%m-%d %H:%M:%S"))

        if len(set(valid_times)) > 1:
            flagged.append("Timestamp inconsistency between EXIF fields.")
    else:
        flagged.append("Missing all relevant EXIF timestamps.")

    # Check for GPS data
    if 'GPS' in exif_data and exif_data['GPS']:
        flagged.append("GPS metadata present - possible GPS injection.")

    if flagged:
        print(f"\n[FLAGGED] {file_path}")
        for f in flagged:
            print(f" - {f}")
    else:
        print(f"[OK] {file_path}")

def scan_directory_for_images(directory):
    supported_extensions = ('.jpg', '.jpeg', '.JPG', '.JPEG')
    for root, _, files in os.walk(directory):
        for file in files:
            if file.endswith(supported_extensions):
                full_path = os.path.join(root, file)
                exif_data = load_exif(full_path)
                if exif_data:
                    check_exif_integrity(exif_data, full_path)

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="EXIF Integrity Validator")
    parser.add_argument("path", help="Path to image file or directory")
    args = parser.parse_args()

    if os.path.isdir(args.path):
        scan_directory_for_images(args.path)
    elif os.path.isfile(args.path):
        exif_data = load_exif(args.path)
        if exif_data:
            check_exif_integrity(exif_data, args.path)
    else:
        print("Invalid path.")
