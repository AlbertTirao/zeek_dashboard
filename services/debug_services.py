# services/debug_utils.py
from pathlib import Path
from turtle import st
import pandas as pd

# Utility function to print row counts of all parquet files on disk
def print_parquet_rows_on_disk(parquet_root: Path):
    print("\n=== 📦 PARQUET ROW COUNTS ON DISK ===")

    if not parquet_root.exists():
        print("❌ Parquet root does not exist")
        return

    for date_dir in sorted(parquet_root.iterdir()):
        if not date_dir.is_dir():
            continue

        print(f"\n📁 {date_dir.name}/")

        for pq_file in sorted(date_dir.glob("*.parquet")):
            try:
                df = pd.read_parquet(pq_file, columns=None)
                print(f"  📄 {pq_file.name}: {len(df)} rows")
            except Exception as e:
                print(f"  ❌ {pq_file.name}: FAILED ({e})")

    print("=== END DISK CHECK ===\n")

# call it like this:
# from services.debug_utils import print_parquet_rows_on_disk
# print_parquet_rows_on_disk(PARQUET_DIR)

# Utility function to load all parquet files into a dict and print row counts (with Streamlit caching)
@st.cache_data(show_spinner=False)
def print_all_parquets(parquet_root: Path):
    print("\n=== ⚡ STREAMLIT CACHE LOAD: PARQUETS ===")

    result = {}

    for date_dir in sorted(parquet_root.iterdir()):
        if not date_dir.is_dir():
            continue

        date_key = date_dir.name
        result[date_key] = {}

        print(f"\n📁 {date_key}/")

        for pq_file in sorted(date_dir.glob("*.parquet")):
            df = pd.read_parquet(pq_file)
            result[date_key][pq_file.stem] = df

            print(f"  📄 {pq_file.name}: {len(df)} rows (cached)")

    print("=== END CACHE LOAD ===\n")
    return result

# call it like this:
# from services.debug_utils import print_all_parquets
# parquet_cache = print_all_parquets(PARQUET_DIR)