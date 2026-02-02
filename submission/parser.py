from src.log_ingestor import LogIngestor
import pandas as pd

def main():
    print("--- Log Parser PoC ---")
    ingestor = LogIngestor()
    
    # Read the sample log file
    log_file = 'auth_logs.txt'
    print(f"Reading logs from {log_file}...")
    
    # Parse logs
    df = ingestor.read_log_file(log_file)
    
    if not df.empty:
        print("\nParsed Log Data (First 5 rows):")
        print(df.head())
        
        print("\nExtracted Fields:")
        print(list(df.columns))
        
        # Save parsed logs for the next step
        output_file = 'parsed_logs.csv'
        df.to_csv(output_file, index=False)
        print(f"\nSaved parsed logs to {output_file}")
    else:
        print("No logs parsed.")

if __name__ == "__main__":
    main()

