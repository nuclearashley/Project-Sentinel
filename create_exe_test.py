#!/usr/bin/env python3
"""
Create a simple test EXE file for Project Sentinel
"""

import struct
import os

def create_minimal_pe():
    """Create a minimal PE file for testing"""
    # This creates a very basic PE header structure
    # Note: This is for testing purposes only and creates a non-functional PE
    
    # DOS Header
    dos_header = b'MZ'  # DOS signature
    dos_header += b'\x00' * 58  # DOS header padding
    dos_header += struct.pack('<L', 0x80)  # PE header offset
    
    # DOS stub
    dos_stub = b'\x00' * (0x80 - len(dos_header))
    
    # PE Header
    pe_signature = b'PE\x00\x00'
    
    # COFF Header
    machine = struct.pack('<H', 0x014c)  # i386
    number_of_sections = struct.pack('<H', 1)
    time_date_stamp = struct.pack('<L', 0)
    pointer_to_symbol_table = struct.pack('<L', 0)
    number_of_symbols = struct.pack('<L', 0)
    size_of_optional_header = struct.pack('<H', 224)
    characteristics = struct.pack('<H', 0x0102)
    
    coff_header = machine + number_of_sections + time_date_stamp + pointer_to_symbol_table + number_of_symbols + size_of_optional_header + characteristics
    
    # Optional Header (simplified)
    optional_header = b'\x0b\x01'  # Magic (PE32)
    optional_header += b'\x00' * 222  # Rest of optional header (simplified)
    
    # Section Header
    section_name = b'.text\x00\x00\x00'
    virtual_size = struct.pack('<L', 0x1000)
    virtual_address = struct.pack('<L', 0x1000)
    size_of_raw_data = struct.pack('<L', 0x200)
    pointer_to_raw_data = struct.pack('<L', 0x200)
    pointer_to_relocations = struct.pack('<L', 0)
    pointer_to_line_numbers = struct.pack('<L', 0)
    number_of_relocations = struct.pack('<H', 0)
    number_of_line_numbers = struct.pack('<H', 0)
    characteristics = struct.pack('<L', 0x60000020)
    
    section_header = section_name + virtual_size + virtual_address + size_of_raw_data + pointer_to_raw_data + pointer_to_relocations + pointer_to_line_numbers + number_of_relocations + number_of_line_numbers + characteristics
    
    # Section data (minimal)
    section_data = b'\x00' * 0x200
    
    # Combine all parts
    pe_file = dos_header + dos_stub + pe_signature + coff_header + optional_header + section_header + section_data
    
    return pe_file

def create_suspicious_pe():
    """Create a PE with suspicious import names"""
    pe_data = create_minimal_pe()
    
    # Add some suspicious strings that would be detected
    suspicious_strings = b'CreateProcess\x00WriteProcessMemory\x00VirtualAlloc\x00GetProcAddress\x00'
    pe_data += suspicious_strings
    
    return pe_data

def main():
    # Create safe PE
    safe_pe = create_minimal_pe()
    with open('safe_executable.exe', 'wb') as f:
        f.write(safe_pe)
    print("Created: safe_executable.exe")
    
    # Create suspicious PE
    suspicious_pe = create_suspicious_pe()
    with open('suspicious_executable.exe', 'wb') as f:
        f.write(suspicious_pe)
    print("Created: suspicious_executable.exe")

if __name__ == "__main__":
    main()

