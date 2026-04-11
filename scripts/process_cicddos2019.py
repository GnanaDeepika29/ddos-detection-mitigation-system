#!/usr/bin/env python3
"""
Process CICDDoS2019 Dataset in low-memory chunks and map to CloudShield features.
"""

import pandas as pd
import numpy as np
import gc
import os
import argparse
from pathlib import Path

def process_chunk(chunk):
    # Strip whitespace from columns to avoid KeyError
    chunk.columns = chunk.columns.str.strip()
    
    is_attack = chunk['Label'].apply(lambda x: 0 if 'BENIGN' in str(x).upper() else 1)
    
    # Packet counts
    total_packets = chunk['Total Fwd Packets'] + chunk['Total Backward Packets']
    total_bytes = chunk['Total Length of Fwd Packets'] + chunk['Total Length of Bwd Packets']
    
    # We simulate "flow" features for individual rows
    total_flows = np.ones(len(chunk))
    unique_src_ips = np.ones(len(chunk))
    unique_dst_ips = np.ones(len(chunk))
    entropy_src_ip = np.zeros(len(chunk))
    entropy_dst_ip = np.zeros(len(chunk))
    
    # Rates
    # Handle infinite or problematic rates
    packets_per_sec = chunk['Flow Packets/s'].replace([np.inf, -np.inf], np.nan).fillna(0).astype('float32')
    bytes_per_sec = chunk['Flow Bytes/s'].replace([np.inf, -np.inf], np.nan).fillna(0).astype('float32')
    
    duration_s = np.where(chunk['Flow Duration'] > 0, chunk['Flow Duration'] / 1000000.0, 1.0)
    flows_per_sec = np.ones(len(chunk)) / duration_s
    
    # Protocols (TCP=6, UDP=17, ICMP=1)
    protocol = chunk['Protocol']
    tcp_ratio = np.where(protocol == 6, 1.0, 0.0)
    udp_ratio = np.where(protocol == 17, 1.0, 0.0)
    icmp_ratio = np.where(protocol == 1, 1.0, 0.0)
    
    # Average packet size
    avg_packet_size = chunk['Fwd Packet Length Mean'].fillna(0).astype('float32')
    
    # Flags
    syn_ratio = chunk['SYN Flag Count'].fillna(0).astype('float32') if 'SYN Flag Count' in chunk.columns else np.zeros(len(chunk))
    rst_ratio = chunk['RST Flag Count'].fillna(0).astype('float32') if 'RST Flag Count' in chunk.columns else np.zeros(len(chunk))

    out_df = pd.DataFrame({
        'total_packets': total_packets.astype('float32'),
        'total_bytes': total_bytes.astype('float32'),
        'total_flows': total_flows.astype('float32'),
        'packets_per_second': packets_per_sec,
        'bytes_per_second': bytes_per_sec,
        'flows_per_second': flows_per_sec.astype('float32'),
        'unique_src_ips': unique_src_ips.astype('float32'),
        'unique_dst_ips': unique_dst_ips.astype('float32'),
        'entropy_src_ip': entropy_src_ip.astype('float32'),
        'entropy_dst_ip': entropy_dst_ip.astype('float32'),
        'tcp_ratio': tcp_ratio.astype('float32'),
        'udp_ratio': udp_ratio.astype('float32'),
        'icmp_ratio': icmp_ratio.astype('float32'),
        'avg_packet_size': avg_packet_size,
        'syn_ratio': syn_ratio,
        'rst_ratio': rst_ratio,
        'is_attack': is_attack.astype('int8')
    })
    
    return out_df

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--input', '-i', required=True, help='Path to CICDDoS2019 CSV file or directory')
    parser.add_argument('--output', '-o', default='data/processed/training_data.parquet', help='Output paths')
    parser.add_argument('--sample-frac', type=float, default=0.01, help='Fraction of data to sample to save memory')
    args = parser.parse_args()

    input_path = Path(args.input)
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    files_to_process = []
    if input_path.is_file():
        files_to_process.append(input_path)
    else:
        files_to_process.extend(input_path.glob('*.csv'))

    print(f"Found {len(files_to_process)} CSV files.")
    
    processed_chunks = []
    
    for f in files_to_process:
        print(f"Processing {f.name} in chunks...")
        try:
            # Chunking to save active memory
            for chunk in pd.read_csv(f, chunksize=50000, low_memory=False):
                # Ensure we only pick small amount to dodge OOMs
                if args.sample_frac < 1.0:
                    chunk = chunk.sample(frac=args.sample_frac, random_state=42)
                    
                if len(chunk) == 0:
                    continue
                    
                processed_df = process_chunk(chunk)
                processed_chunks.append(processed_df)
                
                # Proactive GC
                del chunk
                del processed_df
                gc.collect()
        except Exception as e:
            print(f"Error processing {f}: {e}")
            
    if not processed_chunks:
        print("No data processed!")
        return
        
    print("Concatenating all processed valid chunks...")
    final_df = pd.concat(processed_chunks, ignore_index=True)
    
    print(f"Final dataset shape: {final_df.shape}")
    print(f"Saving to {output_path}...")
    final_df.to_parquet(output_path, index=False)
    
    print("Optimization complete!")

if __name__ == '__main__':
    main()
