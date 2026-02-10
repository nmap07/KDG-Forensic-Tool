import Extractor
import Analyser

def main():
    print("[1] Extracting timeline...")
    Extractor.main()

    print("[2] Generating HTML report...")
    Analyser.main()

    print("[✓] Done")

if __name__ == "__main__":
    main()
