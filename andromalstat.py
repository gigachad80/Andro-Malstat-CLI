#!/usr/bin/env python3
"""
Andro-Malstat (Hybrid Engine)
Full-Featured Static Analysis Tool for APK Files
"""

# 1. STANDARD LIBRARIES
import sys
import os
import hashlib
import json
import zipfile
import math
import logging
import threading
import time
import re
from pathlib import Path
from datetime import datetime
from collections import defaultdict

# 2. CONFIGURATION
logging.getLogger("androguard").setLevel(logging.CRITICAL)
logging.getLogger("androguard.core.api_specific_resources").setLevel(logging.CRITICAL)

# 3. THIRD-PARTY DEPENDENCIES (With Safety Check)
MISSING_DEPS = []

try:
    from androguard.misc import AnalyzeAPK
   
except ImportError:
    MISSING_DEPS.append("androguard")

try:
    import yara  
except ImportError:
    MISSING_DEPS.append("yara-python")

try:
    from colorama import Fore, Style, init
    init(autoreset=True)
except ImportError:
    MISSING_DEPS.append("colorama")
    # Fake Colorama if missing
    class Fore: 
        CYAN = GREEN = RED = YELLOW = MAGENTA = BLUE = RESET = ""
    class Style:
        BRIGHT = RESET_ALL = ""

# 4. STOP IF MISSING CRITICAL LIBS
if MISSING_DEPS:
    print(f"[-] CRITICAL: Missing dependencies: {', '.join(MISSING_DEPS)}")
    print(f"[-] Run: pip install androguard yara-python colorama")
    sys.exit(1)

# 5. MAIN CLASS
class AndroMalstat:
    def __init__(self, apk_path, output_dir="analysis_result"):
        self.apk_path = Path(apk_path)
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)

        # Androguard objects (initialized in step_load_androguard)
        self.a = None   # APK object
        self.d = None   # DalvikVMFormat objects (list)
        self.dx = None  # Analysis object

        # Data storage
        self.data = {
            'file_info': {},
            'permissions': [],
            'components': {},
            'findings': [],
            'risk_score': 0,
            'dangerous_apis': defaultdict(list),
            'secrets': defaultdict(list),
            'native_libs': [],
            'nested_apks': [],
            'yara_matches': [],
            'obfuscation_metrics': {},
            'network_config': {}
        }

        # COMPILE YARA RULES
        self.yara_rules = self._compile_yara()

    def _compile_yara(self):
        """
        Compiles YARA rules from 'yara_rules' directory.
        Falls back to internal rules if directory doesn't exist.
        """
        rules_dir = Path("yara_rules")

        if not rules_dir.exists():
            print(f"{Fore.YELLOW}[!] 'yara_rules/' folder not found. Using internal defaults.")
            return self._compile_internal_rules()

        # Gather all .yar files
        filepaths = {}
        for file_path in rules_dir.glob("*.yar"):
            filepaths[file_path.stem] = str(file_path)

        if not filepaths:
            print(f"{Fore.YELLOW}[!] No .yar files in 'yara_rules/'. Using defaults.")
            return self._compile_internal_rules()

        # Compile
        print(f"{Fore.CYAN}[*] Loading {len(filepaths)} YARA rule file(s)...")
        try:
            return yara.compile(filepaths=filepaths)
        except yara.Error as e:
            print(f"{Fore.RED}[!] YARA Syntax Error: {e}")
            print(f"{Fore.YELLOW}[!] Falling back to internal rules...")
            return self._compile_internal_rules()

    def _compile_internal_rules(self):
        """Fallback YARA rules (minimal but functional)"""
        rules = """
        rule Suspicious_Overlay_Attack {
            meta:
                description = "Detects overlay attack patterns (banking trojans)"
                severity = "high"
            strings:
                $a = "WindowManager$LayoutParams"
                $b = "SYSTEM_ALERT_WINDOW"
                $c = "TYPE_SYSTEM_ALERT"
            condition:
                2 of them
        }

        rule APK_Dropper_Payload {
            meta:
                description = "Nested APK in assets (dropper behavior)"
                severity = "critical"
            strings:
                $a = "assets/" ascii
                $b = ".apk" ascii
                $c = "classes.dex"
            condition:
                all of them
        }

        rule Native_Shell_Execution {
            meta:
                description = "Native code with shell execution capability"
                severity = "high"
            strings:
                $a = "/system/bin/sh" ascii
                $b = "Runtime.exec" ascii
                $c = "ProcessBuilder" ascii
            condition:
                any of them
        }

        rule Crypto_Ransomware_Pattern {
            meta:
                description = "Encryption with file operations (ransomware indicator)"
                severity = "critical"
            strings:
                $a = "Cipher.getInstance"
                $b = "AES/CBC"
                $c = "SecretKeySpec"
                $d = ".encrypt"
            condition:
                3 of them
        }
        """
        try:
            return yara.compile(source=rules)
        except Exception as e:
            print(f"{Fore.RED}[!] Internal YARA rules failed: {e}")
            return None

    def run(self):
        """Main analysis pipeline"""
        print(f"{Fore.CYAN}{Style.BRIGHT}{'='*70}")
        print(f"{Fore.CYAN}{Style.BRIGHT}  Andro-Malstat")
        print(f"{Fore.CYAN}{Style.BRIGHT}{'='*70}")
        print(f"{Fore.GREEN}[*] TARGET: {self.apk_path.name}")
        print(f"{Fore.GREEN}[*] TIME:   {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"{Fore.CYAN}{'='*70}\n")

        # Phase 1: File Profiling
        self.step_file_profiling()

        # Phase 2: Androguard Loading
        if not self.step_load_androguard():
            self._emergency_report()
            return

        # Phase 3: Certificate & Manifest
        self.step_manifest_and_cert()

        # Phase 4: Obfuscation Detection
        self.step_obfuscation_detection()

        # Phase 5: Hybrid Code Analysis
        self.step_hybrid_code_analysis()

        # Phase 6: Native & Nested Check
        self.step_native_and_nested()

        # Phase 7: Network Security Config
        self.step_network_config()

        # Phase 8: Anti-Analysis Detection
        self.step_anti_analysis()

        # Phase 9: YARA Scan
        self.step_yara()

        # Phase 10: Final Report
        self.step_report()

    def step_file_profiling(self):
        """Calculate file hashes and entropy"""
        print(f"{Fore.GREEN}[+] Phase 1: File Profiling")
        try:
            with open(self.apk_path, 'rb') as f:
                raw = f.read()
                md5 = hashlib.md5(raw).hexdigest()
                sha1 = hashlib.sha1(raw).hexdigest()
                sha256 = hashlib.sha256(raw).hexdigest()

                # Entropy calculation (handles empty files)
                entropy = 0
                if len(raw) > 0:
                    counts = [raw.count(bytes([i])) for i in range(256)]
                    probs = [c/len(raw) for c in counts if c > 0]
                    entropy = -sum(p * math.log2(p) for p in probs)

            print(f"    MD5:     {md5}")
            print(f"    SHA256:  {sha256[:64]}")
            print(f"    Size:    {len(raw):,} bytes")
            print(f"    Entropy: {entropy:.4f} (Max: 8.0)")

            self.data['file_info'] = {
                'md5': md5,
                'sha1': sha1,
                'sha256': sha256,
                'entropy': entropy,
                'size': len(raw)
            }

            if entropy > 7.5:
                self._add_finding("HIGH Entropy detected (Likely packed/encrypted)", 20)
            elif entropy > 7.0:
                self._add_finding("Moderate entropy (Possible obfuscation)", 10)

        except Exception as e:
            print(f"{Fore.RED}    Error reading file: {e}")

    def step_load_androguard(self):
        """Load APK with Androguard (with animated spinner)"""
        print(f"{Fore.YELLOW}[*] Phase 2: Loading Androguard Analysis Engine...")

        done = False
        def animate():
            chars = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"
            i = 0
            while not done:
                sys.stdout.write(f'\r    {Fore.CYAN}Processing DEX bytecode... {chars[i % len(chars)]}')
                sys.stdout.flush()
                time.sleep(0.08)
                i += 1

        t = threading.Thread(target=animate, daemon=True)
        t.start()

        try:
            self.a, self.d, self.dx = AnalyzeAPK(str(self.apk_path))
            done = True
            print(f"\r    {Fore.GREEN}✓ Analysis loaded successfully!{' '*30}")
            return True
        except Exception as e:
            done = True
            print(f"\n{Fore.RED}[-] FATAL: Androguard failed to load APK")
            print(f"    Reason: {str(e)[:100]}")
            print(f"    (APK might be corrupted, encrypted, or password-protected)")
            return False

    def step_manifest_and_cert(self):
        """Analyze AndroidManifest.xml and signing certificate"""
        print(f"{Fore.GREEN}[+] Phase 3: Manifest & Certificate Analysis")

        # 3.1 Certificate Analysis
        try:
            if self.a.is_signed():
                for cert in self.a.get_certificates():
                    # Fixed: Direct attribute access (no hasattr check needed)
                    issuer = cert.issuer.human_friendly
                    subject = cert.subject.human_friendly

                    print(f"    {Fore.CYAN}Issuer:  {issuer}")
                    print(f"    {Fore.CYAN}Subject: {subject}")

                    # Check for debug certificates
                    if "Android Debug" in issuer or "CN=Android Debug" in issuer:
                        self._add_finding("Signed with DEBUG certificate (Test/Development key)", 30)

                    # Check for self-signed
                    if issuer == subject:
                        self._add_finding("Self-signed certificate", 5)

            else:
                self._add_finding("APK is NOT SIGNED (Unsigned)", 50)
        except Exception as e:
            print(f"    {Fore.YELLOW}[!] Certificate parsing error: {e}")

        # 3.2 Permission Analysis
        perms = self.a.get_permissions()
        dangerous = [
            'SEND_SMS', 'READ_SMS', 'RECEIVE_SMS', 'RECEIVE_BOOT_COMPLETED',
            'SYSTEM_ALERT_WINDOW', 'READ_CONTACTS', 'WRITE_CONTACTS',
            'INSTALL_PACKAGES', 'DELETE_PACKAGES', 'READ_PHONE_STATE',
            'CALL_PHONE', 'RECORD_AUDIO', 'CAMERA', 'ACCESS_FINE_LOCATION',
            'READ_EXTERNAL_STORAGE', 'WRITE_EXTERNAL_STORAGE'
        ]

        found_danger = [p.split('.')[-1] for p in perms if any(d in p for d in dangerous)]

        if found_danger:
            print(f"    {Fore.RED}⚠ Dangerous Permissions: {', '.join(found_danger[:5])}")
            if len(found_danger) > 5:
                print(f"      ... and {len(found_danger) - 5} more")
            self._add_finding(f"Dangerous Permissions: {', '.join(found_danger)}", len(found_danger) * 8)

        self.data['permissions'] = perms

        # 3.3 Component Analysis
        components = {
            'activities': self.a.get_activities(),
            'services': self.a.get_services(),
            'receivers': self.a.get_receivers(),
            'providers': self.a.get_providers()
        }
        self.data['components'] = components

        print(f"    Activities: {len(components['activities'])}")
        print(f"    Services:   {len(components['services'])}")
        print(f"    Receivers:  {len(components['receivers'])}")

        # 3.4 Persistence Check (Boot receivers)
        try:
            manifest_str = str(self.a.get_android_manifest_axml().get_xml())
            if "BOOT_COMPLETED" in manifest_str:
                self._add_finding("Auto-start on boot (Persistence mechanism)", 25)
            if "QUICKBOOT_POWERON" in manifest_str:
                self._add_finding("Quick boot receiver (Advanced persistence)", 20)
        except Exception:
            pass

    def step_obfuscation_detection(self):
        """Detect ProGuard/R8 obfuscation via class name entropy"""
        print(f"{Fore.GREEN}[+] Phase 4: Obfuscation Detection")

        try:
            all_classes = list(self.dx.get_classes())
            if not all_classes:
                return

            # Sample class names
            class_names = [c.name for c in all_classes[:500]]

            # Calculate average class name length
            avg_length = sum(len(n) for n in class_names) / len(class_names)

            # Check for short, random names (ProGuard signature)
            short_names = [n for n in class_names if len(n.split('/')[-1]) <= 2]
            obfuscation_ratio = len(short_names) / len(class_names)

            print(f"    Total Classes: {len(all_classes)}")
            print(f"    Avg Name Length: {avg_length:.1f} chars")
            print(f"    Obfuscation Ratio: {obfuscation_ratio:.2%}")

            self.data['obfuscation_metrics'] = {
                'total_classes': len(all_classes),
                'avg_name_length': avg_length,
                'obfuscation_ratio': obfuscation_ratio
            }

            if obfuscation_ratio > 0.7:
                self._add_finding("HEAVY obfuscation detected (ProGuard/R8)", 15)
            elif obfuscation_ratio > 0.4:
                self._add_finding("Moderate obfuscation detected", 5)

        except Exception as e:
            print(f"    {Fore.YELLOW}[!] Obfuscation analysis skipped: {e}")

    def step_hybrid_code_analysis(self):
        """Hybrid: Bytecode tracing + raw string fallback"""
        print(f"{Fore.GREEN}[+] Phase 5: Hybrid Code Analysis (Smart + Dumb Scan)")

        # 5.1 Bytecode API Tracing (Accurate but fragile)
        suspicious_apis = {
            'Ljavax/crypto/Cipher;->getInstance': 'Encryption',
            'Ljava/lang/Runtime;->exec': 'Command Execution',
            'Landroid/telephony/SmsManager;->sendTextMessage': 'SMS Sending',
            'Ldalvik/system/DexClassLoader;->loadClass': 'Dynamic Code Loading',
            'Ljava/lang/reflect/Method;->invoke': 'Reflection',
            'Landroid/content/pm/PackageManager;->getInstalledPackages': 'App Enumeration',
            'Landroid/app/admin/DevicePolicyManager;->resetPassword': 'Admin Abuse'
        }

        bytecode_hits = defaultdict(int)
        try:
            print(f"    {Fore.CYAN}[Bytecode] Scanning DEX methods...")
            method_count = 0
            for method in self.dx.get_methods():
                if method.is_external():
                    continue
                method_count += 1
                if method_count > 50000:  # Performance limit
                    break

                try:
                    for instr in method.get_instructions():
                        code = instr.get_output()
                        for api, cat in suspicious_apis.items():
                            if api in code:
                                method_sig = f"{method.class_name}::{method.name}"
                                self.data['dangerous_apis'][cat].append(method_sig)
                                bytecode_hits[cat] += 1
                except:
                    continue

            for cat, count in bytecode_hits.items():
                print(f"    {Fore.YELLOW}  - {cat}: {count} calls")
        except Exception as e:
            print(f"    {Fore.RED}[!] Bytecode scan error: {e}")

        # 5.2 Raw String Fallback (Catches obfuscated APIs)
        print(f"    {Fore.CYAN}[Strings] Scanning for IOCs and hidden APIs...")

        patterns = {
            'URL': r'https?://[a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,}(?:/[^\s]*)?',
            'IP_Address': r'\b(?:\d{1,3}\.){3}\d{1,3}\b',
            'C2_Domain': r'[a-zA-Z0-9\-]+\.(?:xyz|top|ru|cn|ga|tk|cc)\b',
            'Exec_API': r'Runtime\.exec|ProcessBuilder',
            'SMS_API': r'sendTextMessage|SmsManager',
            'Base64': r'[A-Za-z0-9+/]{40,}={0,2}'
        }

        string_hits = defaultdict(set)
        try:
            for i, s in enumerate(self.dx.get_strings()):
                if i > 50000:  # Limit for large APKs
                    break
                val = s.get_value()
                if len(val) > 500 or len(val) < 4:
                    continue

                for key, pat in patterns.items():
                    matches = re.findall(pat, val)
                    if matches:
                        string_hits[key].update(matches[:10])
        except Exception as e:
            print(f"    {Fore.RED}[!] String scan error: {e}")

        # 5.3 Merge Results
        if not bytecode_hits and ('Exec_API' in string_hits or 'SMS_API' in string_hits):
            self._add_finding("Hidden APIs in strings (Obfuscation/reflection detected)", 25)

        for key, vals in string_hits.items():
            if vals:
                clean_vals = list(vals)[:10]
                print(f"    {Fore.MAGENTA}  - {key}: {len(vals)} found")
                self.data['secrets'][key] = clean_vals

                if key == 'C2_Domain':
                    self._add_finding(f"Suspicious C2 domains: {', '.join(clean_vals[:3])}", 40)
                elif key == 'IP_Address' and len(vals) > 5:
                    self._add_finding(f"Multiple hardcoded IPs ({len(vals)} found)", 15)

    def step_native_and_nested(self):
        """Scan for native libraries and nested APKs"""
        print(f"{Fore.GREEN}[+] Phase 6: Native & Nested Analysis")

        try:
            for f in self.a.get_files():
                # 6.1 Native Libraries
                if f.endswith(".so"):
                    self.data['native_libs'].append(f)
                    try:
                        content = self.a.get_file(f)
                        if b"/bin/sh" in content or b"system(" in content:
                            self._add_finding(f"Native shell payload in {f}", 35)
                    except:
                        pass

                # 6.2 Nested APKs/DEX (Dropper behavior)
                if f.endswith(".apk") or (f.endswith(".dex") and "classes" not in f):
                    print(f"    {Fore.RED}⚠ Nested payload: {f}")
                    self.data['nested_apks'].append(f)
                    self._add_finding(f"Dropper behavior: Nested APK/DEX ({f})", 50)

            if self.data['native_libs']:
                print(f"    Native libs: {len(self.data['native_libs'])} found")
                if len(self.data['native_libs']) > 10:
                    self._add_finding(f"Excessive native libraries ({len(self.data['native_libs'])})", 10)
        except Exception as e:
            print(f"    {Fore.YELLOW}[!] Error: {e}")

    def step_network_config(self):
        """Parse network_security_config.xml for cleartext traffic"""
        print(f"{Fore.GREEN}[+] Phase 7: Network Security Config")

        try:
            # Check if file exists
            nsc_path = "res/xml/network_security_config.xml"
            if nsc_path in self.a.get_files():
                content = self.a.get_file(nsc_path).decode('utf-8', errors='ignore')
                self.data['network_config']['has_config'] = True

                if 'cleartextTrafficPermitted="true"' in content:
                    print(f"    {Fore.RED}⚠ Cleartext traffic ALLOWED")
                    self._add_finding("Cleartext HTTP traffic permitted (MITM risk)", 20)
                else:
                    print(f"    {Fore.GREEN}✓ Cleartext traffic blocked")
            else:
                # Check manifest for android:usesCleartextTraffic
                manifest_str = str(self.a.get_android_manifest_axml().get_xml())
                if 'android:usesCleartextTraffic="true"' in manifest_str:
                    print(f"    {Fore.RED}⚠ Cleartext traffic enabled in manifest")
                    self._add_finding("Cleartext traffic enabled (usesCleartextTraffic)", 15)
        except Exception as e:
            print(f"    {Fore.YELLOW}[!] Skipped: {e}")

    def step_anti_analysis(self):
        """Detect anti-debugging and anti-emulator techniques"""
        print(f"{Fore.GREEN}[+] Phase 8: Anti-Analysis Detection")

        anti_patterns = {
            'Debug Detection': ['isDebuggerConnected', 'Debug.isDebuggerConnected'],
            'Emulator Detection': ['Build.FINGERPRINT', 'goldfish', 'generic', 'Build.PRODUCT'],
            'Root Detection': ['su', '/system/xbin/su', 'Superuser.apk'],
            'Frida Detection': ['frida-server', 'frida-agent']
        }

        detected = defaultdict(list)
        try:
            for s in self.dx.get_strings():
                val = s.get_value()
                for category, patterns in anti_patterns.items():
                    for pattern in patterns:
                        if pattern.lower() in val.lower():
                            detected[category].append(pattern)
                            break

            for category, findings in detected.items():
                print(f"    {Fore.YELLOW}⚠ {category}: {', '.join(set(findings)[:3])}")
                self._add_finding(f"Anti-analysis: {category}", 15)

        except Exception as e:
            print(f"    {Fore.YELLOW}[!] Skipped: {e}")

    def step_yara(self):
        """Run YARA malware signatures"""
        print(f"{Fore.GREEN}[+] Phase 9: YARA Malware Signature Scan")

        if not self.yara_rules:
            print(f"    {Fore.YELLOW}[!] No YARA rules loaded - skipping")
            return

        try:
            raw_apk = self.a.get_raw()
            matches = self.yara_rules.match(data=raw_apk)

            if matches:
                for m in matches:
                    print(f"    {Fore.RED}⚠ MATCH: {m.rule}")
                    if hasattr(m, 'meta') and 'severity' in m.meta:
                        severity = m.meta['severity']
                        score = {'critical': 60, 'high': 40, 'medium': 20, 'low': 10}.get(severity, 30)
                    else:
                        score = 30
                    self._add_finding(f"YARA: {m.rule}", score)
                    self.data['yara_matches'].append(m.rule)
            else:
                print(f"    {Fore.GREEN}✓ No YARA matches")
        except Exception as e:
            print(f"    {Fore.RED}[!] YARA scan failed: {e}")

    def step_report(self):
        """Generate final risk assessment report"""
        score = self.data['risk_score']

        # Risk classification
        if score > 100: risk_level, color = "CRITICAL", Fore.RED
        elif score > 60: risk_level, color = "HIGH", Fore.RED
        elif score > 30: risk_level, color = "MEDIUM", Fore.YELLOW
        else: risk_level, color = "LOW", Fore.GREEN

        print(f"\n{Fore.CYAN}{Style.BRIGHT}{'='*70}")
        print(f"{color}{Style.BRIGHT}  RISK ASSESSMENT: {risk_level} (Score: {score})")
        print(f"{Fore.CYAN}{Style.BRIGHT}{'='*70}")

        if self.data['findings']:
            print(f"{Fore.YELLOW}\nFINDINGS:")
            for i, finding in enumerate(self.data['findings'], 1):
                print(f"  {i}. {finding}")
        else:
            print(f"{Fore.GREEN}\n✓ No significant threats detected")

        # Save JSON report
        json_path = self.output_dir / f"report_{self.apk_path.stem}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(json_path, 'w') as f:
            json.dump(self.data, f, indent=2, default=str)

        print(f"\n{Fore.CYAN}[+] Full report saved: {json_path}")
        print(f"{Fore.CYAN}{'='*70}\n")

    def _emergency_report(self):
        """Generate minimal report when Androguard fails"""
        print(f"\n{Fore.RED}[!] Emergency static analysis fallback...")

        try:
            with zipfile.ZipFile(self.apk_path, 'r') as zf:
                files = zf.namelist()
                print(f"    Files in APK: {len(files)}")

                # Check for nested APKs
                nested = [f for f in files if f.endswith('.apk')]
                if nested:
                    print(f"    {Fore.RED}⚠ Nested APKs: {nested}")

                # Check for native libs
                native = [f for f in files if f.endswith('.so')]
                if native:
                    print(f"    Native libs: {len(native)} found")
        except:
            print(f"    {Fore.RED}Cannot read APK as ZIP file")

    def _add_finding(self, desc, points):
        """Add a security finding with risk points"""
        self.data['findings'].append(desc)
        self.data['risk_score'] += points


# 6. MAIN ENTRY POINT
if __name__ == '__main__':
    if len(sys.argv) < 2:
        print(f"{Fore.CYAN}Andro-Malstat")
        print(f"\nUsage: python {sys.argv[0]} <apk_file> [output_dir]")
        print(f"\nExample: python {sys.argv[0]} malware.apk ./analysis")
        sys.exit(1)

    target = sys.argv[1]
    output = sys.argv[2] if len(sys.argv) > 2 else "analysis_result"

    if not os.path.exists(target):
        print(f"{Fore.RED}[-] File not found: {target}")
        sys.exit(1)

    analyzer = AndroMalstat(target, output)
    analyzer.run()
