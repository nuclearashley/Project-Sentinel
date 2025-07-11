import re
import os
from typing import Dict, List, Any
import pefile
import hashlib

class PEAnalyzer:
    """
    PE (Portable Executable) file analyzer for Windows executables
    """
    
    def __init__(self):
        # Suspicious API imports commonly found in malware
        self.suspicious_apis = [
            'VirtualAlloc', 'VirtualProtect', 'VirtualFree',
            'CreateProcess', 'CreateProcessA', 'CreateProcessW',
            'ShellExecute', 'ShellExecuteA', 'ShellExecuteW',
            'WinExec', 'system',
            'CreateFile', 'WriteFile', 'ReadFile',
            'RegCreateKey', 'RegSetValue', 'RegDeleteKey',
            'GetProcAddress', 'LoadLibrary', 'LoadLibraryA', 'LoadLibraryW',
            'CreateThread', 'CreateRemoteThread',
            'OpenProcess', 'TerminateProcess',
            'SetWindowsHookEx', 'UnhookWindowsHookEx',
            'GetAsyncKeyState', 'GetForegroundWindow',
            'GetWindowText', 'FindWindow',
            'InternetOpen', 'InternetOpenUrl', 'InternetReadFile',
            'HttpSendRequest', 'HttpOpenRequest',
            'URLDownloadToFile', 'URLDownloadToCacheFile',
            'CryptAcquireContext', 'CryptEncrypt', 'CryptDecrypt',
            'GetTickCount', 'GetLocalTime', 'GetSystemTime',
            'IsDebuggerPresent', 'CheckRemoteDebuggerPresent',
            'OutputDebugString', 'SetUnhandledExceptionFilter',
            'RtlCreateUserThread', 'LdrLoadDll',
            'NtCreateFile', 'NtWriteFile', 'NtReadFile',
            'NtCreateProcess', 'NtResumeThread',
            'malloc', 'free', 'memcpy', 'memset'
        ]
        
        # Suspicious DLL imports
        self.suspicious_dlls = [
            'urlmon.dll', 'wininet.dll', 'ws2_32.dll', 'wsock32.dll',
            'ntdll.dll', 'kernel32.dll', 'user32.dll', 'advapi32.dll',
            'shell32.dll', 'ole32.dll', 'oleaut32.dll',
            'crypt32.dll', 'cryptsp.dll', 'wincrypt.dll',
            'psapi.dll', 'imagehlp.dll', 'dbghelp.dll',
            'msvcrt.dll', 'vcruntime140.dll', 'msvcp140.dll'
        ]
        
        # Suspicious section names
        self.suspicious_sections = [
            '.packed', '.upx', '.aspack', '.petite', '.themida',
            '.vmp', '.enigma', '.obsidium', '.epack', '.npack',
            '.mpress', '.pecloak', '.rlpack', '.wwpack', '.ypack',
            '.rsrc', '.data', '.text', '.rdata', '.reloc',
            '.tls', '.debug', '.idata', '.edata', '.pdata',
            '.xdata', '.sdata', '.gfids', '.00cfg', '.didat'
        ]
        
        # Suspicious strings patterns
        self.suspicious_strings = [
            r'cmd\.exe', r'powershell', r'wscript', r'cscript',
            r'regedit', r'taskkill', r'net\.exe', r'sc\.exe',
            r'rundll32', r'regsvr32', r'mshta', r'bitsadmin',
            r'certutil', r'wmic', r'schtasks', r'at\.exe',
            r'bcdedit', r'vssadmin', r'wbem', r'wmiprvse',
            r'Software\\Microsoft\\Windows\\CurrentVersion\\Run',
            r'Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce',
            r'HKEY_LOCAL_MACHINE', r'HKEY_CURRENT_USER',
            r'\\System32\\', r'\\SysWOW64\\', r'\\Temp\\',
            r'\\AppData\\', r'\\ProgramData\\', r'\\Users\\',
            r'http://', r'https://', r'ftp://', r'\\\\',
            r'\.exe', r'\.dll', r'\.bat', r'\.cmd', r'\.vbs',
            r'\.ps1', r'\.scr', r'\.com', r'\.pif'
        ]
    
    def analyze_pe_structure(self, file_path: str) -> Dict[str, Any]:
        """Analyze PE file structure and headers"""
        try:
            pe = pefile.PE(file_path)
            
            # Basic PE information
            pe_info = {
                'machine': pe.FILE_HEADER.Machine,
                'number_of_sections': pe.FILE_HEADER.NumberOfSections,
                'time_date_stamp': pe.FILE_HEADER.TimeDateStamp,
                'characteristics': pe.FILE_HEADER.Characteristics,
                'size_of_optional_header': pe.FILE_HEADER.SizeOfOptionalHeader,
                'entry_point': pe.OPTIONAL_HEADER.AddressOfEntryPoint,
                'image_base': pe.OPTIONAL_HEADER.ImageBase,
                'section_alignment': pe.OPTIONAL_HEADER.SectionAlignment,
                'file_alignment': pe.OPTIONAL_HEADER.FileAlignment,
                'size_of_image': pe.OPTIONAL_HEADER.SizeOfImage,
                'size_of_headers': pe.OPTIONAL_HEADER.SizeOfHeaders,
                'checksum': pe.OPTIONAL_HEADER.CheckSum,
                'subsystem': pe.OPTIONAL_HEADER.Subsystem,
                'dll_characteristics': pe.OPTIONAL_HEADER.DllCharacteristics
            }
            
            # Section information
            sections = []
            for section in pe.sections:
                section_info = {
                    'name': section.Name.decode('utf-8', errors='ignore').rstrip('\x00'),
                    'virtual_address': section.VirtualAddress,
                    'virtual_size': section.Misc_VirtualSize,
                    'raw_size': section.SizeOfRawData,
                    'characteristics': section.Characteristics,
                    'entropy': section.get_entropy()
                }
                sections.append(section_info)
            
            pe_info['sections'] = sections
            
            return pe_info
            
        except Exception as e:
            print(f"PE structure analysis error: {str(e)}")
            return {}
    
    def analyze_imports(self, file_path: str) -> Dict[str, Any]:
        """Analyze imported functions and DLLs"""
        try:
            pe = pefile.PE(file_path)
            
            imported_dlls = []
            imported_functions = []
            suspicious_api_count = 0
            suspicious_dll_count = 0
            
            if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    dll_name = entry.dll.decode('utf-8', errors='ignore').lower()
                    imported_dlls.append(dll_name)
                    
                    # Check if DLL is suspicious
                    if dll_name in [dll.lower() for dll in self.suspicious_dlls]:
                        suspicious_dll_count += 1
                    
                    # Analyze imported functions
                    for imp in entry.imports:
                        if imp.name:
                            func_name = imp.name.decode('utf-8', errors='ignore')
                            imported_functions.append(func_name)
                            
                            # Check if function is suspicious
                            if func_name in self.suspicious_apis:
                                suspicious_api_count += 1
            
            return {
                'imported_dlls': imported_dlls,
                'imported_functions': imported_functions,
                'total_imports': len(imported_functions),
                'suspicious_api_count': suspicious_api_count,
                'suspicious_dll_count': suspicious_dll_count,
                'unique_dlls': len(set(imported_dlls))
            }
            
        except Exception as e:
            print(f"Import analysis error: {str(e)}")
            return {
                'imported_dlls': [],
                'imported_functions': [],
                'total_imports': 0,
                'suspicious_api_count': 0,
                'suspicious_dll_count': 0,
                'unique_dlls': 0
            }
    
    def analyze_strings(self, file_path: str) -> Dict[str, Any]:
        """Analyze strings in the PE file"""
        try:
            with open(file_path, 'rb') as f:
                content = f.read()
            
            # Extract printable strings
            strings = re.findall(rb'[^\x00-\x1F\x7F-\xFF]{4,}', content)
            string_list = [s.decode('utf-8', errors='ignore') for s in strings]
            
            suspicious_string_count = 0
            found_patterns = []
            
            # Check for suspicious string patterns
            for string in string_list:
                for pattern in self.suspicious_strings:
                    if re.search(pattern, string, re.IGNORECASE):
                        suspicious_string_count += 1
                        found_patterns.append(f"Suspicious string: {string[:50]}...")
                        break
            
            return {
                'total_strings': len(string_list),
                'suspicious_string_count': suspicious_string_count,
                'found_patterns': found_patterns[:10],  # Limit to first 10
                'average_string_length': sum(len(s) for s in string_list) / len(string_list) if string_list else 0
            }
            
        except Exception as e:
            print(f"String analysis error: {str(e)}")
            return {
                'total_strings': 0,
                'suspicious_string_count': 0,
                'found_patterns': [],
                'average_string_length': 0
            }
    
    def check_packing(self, pe_info: Dict[str, Any]) -> Dict[str, Any]:
        """Check if the PE file is packed or obfuscated"""
        try:
            packing_indicators = 0
            packing_reasons = []
            
            # Check section names for packing indicators
            if 'sections' in pe_info:
                for section in pe_info['sections']:
                    section_name = section['name'].lower()
                    for suspicious_name in ['.upx', '.packed', '.aspack', '.petite']:
                        if suspicious_name in section_name:
                            packing_indicators += 1
                            packing_reasons.append(f"Suspicious section name: {section_name}")
                    
                    # Check section entropy (high entropy indicates packing/encryption)
                    if section['entropy'] > 7.0:
                        packing_indicators += 1
                        packing_reasons.append(f"High entropy section: {section_name} ({section['entropy']:.2f})")
            
            # Check for unusual entry point
            if pe_info.get('entry_point'):
                # Basic heuristic: entry point should be in .text section typically
                entry_point = pe_info['entry_point']
                if entry_point > 0x100000:  # Very high entry point
                    packing_indicators += 1
                    packing_reasons.append(f"Unusual entry point: 0x{entry_point:X}")
            
            return {
                'is_packed': packing_indicators > 0,
                'packing_score': packing_indicators,
                'packing_reasons': packing_reasons
            }
            
        except Exception as e:
            print(f"Packing check error: {str(e)}")
            return {
                'is_packed': False,
                'packing_score': 0,
                'packing_reasons': []
            }
    
    def analyze_file(self, file_path: str) -> Dict[str, Any]:
        """
        Perform comprehensive PE file analysis
        Returns analysis results with threat score and confidence level
        """
        try:
            # Analyze PE structure
            pe_info = self.analyze_pe_structure(file_path)
            
            # Analyze imports
            import_info = self.analyze_imports(file_path)
            
            # Analyze strings
            string_info = self.analyze_strings(file_path)
            
            # Check for packing
            packing_info = self.check_packing(pe_info)
            
            # Calculate threat score (0.0 = safe, 1.0 = malicious)
            threat_score = 0.0
            reasons = []
            
            # Suspicious API calls (high risk)
            if import_info['suspicious_api_count'] > 5:
                threat_score += 0.4
                reasons.append(f"Multiple suspicious API calls ({import_info['suspicious_api_count']} found)")
            elif import_info['suspicious_api_count'] > 0:
                threat_score += 0.2
                reasons.append(f"Suspicious API calls found ({import_info['suspicious_api_count']} found)")
            
            # Packing indicators (medium-high risk)
            if packing_info['is_packed']:
                threat_score += 0.3
                reasons.append(f"File appears to be packed/obfuscated ({packing_info['packing_score']} indicators)")
            
            # Suspicious strings (medium risk)
            if string_info['suspicious_string_count'] > 10:
                threat_score += 0.25
                reasons.append(f"Many suspicious strings found ({string_info['suspicious_string_count']} found)")
            elif string_info['suspicious_string_count'] > 3:
                threat_score += 0.15
                reasons.append(f"Suspicious strings found ({string_info['suspicious_string_count']} found)")
            
            # Unusual structure (low-medium risk)
            if len(pe_info.get('sections', [])) < 3:
                threat_score += 0.1
                reasons.append(f"Unusual number of sections ({len(pe_info.get('sections', []))} sections)")
            
            # Low import count (possible import obfuscation)
            if import_info['total_imports'] < 5:
                threat_score += 0.1
                reasons.append(f"Very few imports ({import_info['total_imports']} imports)")
            
            # Cap the threat score at 1.0
            threat_score = min(threat_score, 1.0)
            
            # Calculate confidence level (how confident we are in our analysis)
            confidence_factors = []
            base_confidence = 0.8  # Base confidence for PE files (usually have good structure)
            
            # Increase confidence based on analysis completeness
            if pe_info.get('is_valid', False):
                base_confidence += 0.1
                confidence_factors.append("Valid PE structure analyzed")
            
            if import_info['total_imports'] > 0:
                base_confidence += 0.05
                confidence_factors.append("Import table analyzed")
            
            if string_info['total_strings'] > 10:
                base_confidence += 0.05
                confidence_factors.append("String analysis completed")
            
            # Higher confidence if clear indicators found
            if import_info['suspicious_api_count'] > 0 or string_info['suspicious_string_count'] > 0:
                base_confidence += 0.1
                confidence_factors.append("Strong malicious indicators detected")
            
            if packing_info['is_packed']:
                base_confidence += 0.1
                confidence_factors.append("Packing/obfuscation detected")
            
            # Lower confidence for edge cases
            if not pe_info.get('is_valid', False):
                base_confidence -= 0.2
                confidence_factors.append("Invalid or corrupted PE structure")
            
            if import_info['total_imports'] == 0:
                base_confidence -= 0.1
                confidence_factors.append("No imports found")
            
            confidence_level = min(base_confidence, 1.0)
            
            # Generate rationale
            is_malicious = threat_score > 0.5
            if threat_score > 0:
                rationale = f"PE analysis completed. Threat score: {threat_score:.2f}. " + "; ".join(reasons)
            else:
                rationale = "PE analysis completed. No suspicious indicators found"
            
            # Create features dictionary
            features = {
                'sections': len(pe_info.get('sections', [])),
                'imports': import_info['total_imports'],
                'suspicious_apis': import_info['suspicious_api_count'],
                'suspicious_strings': string_info['suspicious_string_count'],
                'is_packed': packing_info['is_packed'],
                'packing_score': packing_info['packing_score'],
                'unique_dlls': import_info['unique_dlls']
            }
            
            return {
                'is_malicious': is_malicious,
                'threat_score': threat_score,
                'confidence_level': confidence_level,
                'confidence_factors': confidence_factors,
                'rationale': rationale,
                'features': features,
                'source': 'AI Analysis',
                'pe_info': pe_info,
                'import_info': import_info,
                'string_info': string_info,
                'packing_info': packing_info
            }
            
        except Exception as e:
            return {
                'is_malicious': False,
                'threat_score': 0.0,
                'confidence_level': 0.3,  # Low confidence due to analysis failure
                'confidence_factors': ["Analysis failed"],
                'rationale': f"PE analysis failed: {str(e)}",
                'features': {},
                'source': 'Error'
            } 