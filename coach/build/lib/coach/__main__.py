#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import json
import shutil
import logging
import time
import pyfiglet
from rich.console import Console
from rich.prompt import Prompt
from rich.table import Table
import subprocess
import git
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed

# Ensure config and log directory exists
CONFIG_DIR = os.path.expanduser("~/.coach")
CONFIG_FILE = os.path.join(CONFIG_DIR, "config.json")
LOG_FILE = os.path.join(CONFIG_DIR, "coach.log")

if not os.path.exists(CONFIG_DIR):
    os.makedirs(CONFIG_DIR)

# Ensure log file exists
if not os.path.exists(LOG_FILE):
    with open(LOG_FILE, 'a') as f:
        os.utime(LOG_FILE, None)

# Setup logging
logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('coach')

# Default configuration
default_config = {
    'general': {
        'temp_dir': '/tmp/coach',
        'threads': '4',
        'timeout': '300',
        'verbose': 'false',
    },
    'analyzers': {
        'python': 'true',
        'javascript': 'true',
        'java': 'true',
        'php': 'true',
        'ruby': 'true',
        'go': 'true',
        'c': 'true',
        'cpp': 'true',
        'csharp': 'true',
        'semgrep': 'true',
    },
    'dependencies': {
        'check_deps': 'true',
        'auto_install': 'false',
    },
    'tools': {
        # Python tools
        'pylint': 'true',
        'bandit': 'true',
        # JavaScript tools
        'eslint': 'true',
        'jshint': 'true',
        # Java tools
        'pmd': 'true',
        'spotbugs': 'true',
        # PHP tools
        'phpcs': 'true',
        'phpstan': 'true',
        # Ruby tools
        'rubocop': 'true',
        'brakeman': 'true',
        # Go tools
        'golint': 'true',
        'gosec': 'true',
        # C/C++ tools
        'cppcheck': 'true',
        'clang-analyzer': 'true',
        # C# tools
        'sonarscanner': 'true',
    }
}

# Initialize console
console = Console()

# Tool metadata
VERSION = "1.0.0"
TOOL_NAME = "Coach"

class Config:
    """Configuration manager for Coach"""
    
    def __init__(self, stream_or_path=CONFIG_FILE):
        self.stream_or_path = stream_or_path
        self.config = default_config
        
        # Load or create config file
        if os.path.exists(self.stream_or_path):
            self.load_config()
        else:
            self.save_config()
    
    def load_config(self):
        """Load configuration from file"""
        console.print("[yellow]Usage: coach <repository_url> [branch] [options][/yellow]")
        console.print("[yellow]Example: coach https://github.com/username/repo.git main[/yellow]")
        try:
            with open(self.stream_or_path, 'r') as f:
                self.config = json.load(f)
        except Exception as e:
            logger.error(f"Error loading config: {e}")
            self.config = default_config
    
    def save_config(self):
        """Save configuration to file"""
        try:
            with open(self.stream_or_path, 'w') as f:
                json.dump(self.config, f, indent=4)
        except Exception as e:
            logger.error(f"Error saving config: {e}")
    
    def get(self, section, key, fallback=None):
        """Get a configuration value with an optional fallback"""
        return self.config.get(section, {}).get(key, fallback)
    
    def set(self, section, key, value):
        """Set a configuration value"""
        if section not in self.config:
            self.config[section] = {}
        self.config[section][key] = value

class RepoManager:
    """Manage repository cloning and language detection"""
    
    def __init__(self, config):
        self.config = config
    
    def clone_repo(self, repo_url, branch):
        """Clone a repository to a temporary directory"""
        repo_name = os.path.basename(repo_url).replace('.git', '')
        temp_dir = os.path.join(self.config.get('general', 'temp_dir'), f"{repo_name}_{int(os.times().elapsed)}")
        if os.path.exists(temp_dir):
            shutil.rmtree(temp_dir)
        
        os.makedirs(temp_dir, exist_ok=True)
        console.print(f"[cyan]Cloning repository: {repo_url} (branch: {branch})[/cyan]")
        try:
            git.Repo.clone_from(repo_url, temp_dir, branch=branch)
            console.print(f"[green]Repository cloned to: {temp_dir}[/green]")
            return temp_dir
        except Exception as e:
            logger.error(f"Error cloning repository: {e}")
            console.print(f"[red]Error cloning repository: {e}[/red]")
            raise
    
    def detect_languages(self, repo_path):
      """Detect programming languages in the repository"""
      languages = {}
      file_extensions = {
        '.py': 'python',
        '.js': 'javascript',
        '.jsx': 'javascript',
        '.ts': 'javascript',
        '.tsx': 'javascript',
        '.java': 'java',
        '.kt': 'java',  # Kotlin, treated as Java for analysis tools
        '.php': 'php',
        '.rb': 'ruby',
        '.go': 'go',
        '.c': 'c',
        '.cpp': 'cpp',
        '.cc': 'cpp',
        '.cxx': 'cpp',
        '.h': 'c',
        '.hpp': 'cpp',
        '.cs': 'csharp'
        }
    
      for root, _, files in os.walk(repo_path):
        if '/.git' in root:
            continue
            
        for file in files:
            _, ext = os.path.splitext(file)
            if ext in file_extensions:
                lang = file_extensions[ext]
                languages[lang] = True
                logger.info(f"Detected {lang} file: {os.path.join(root, file)}")
    
      if not languages:
        console.print("[yellow]No recognizable source code files detected.[/yellow]")
        logger.warning("No languages detected in repository.")
      else:
        console.print(f"[green]Detected languages: {', '.join(languages.keys())}[/green]")
    
      return languages

class SemgrepAnalyzer:
    """Semgrep security analyzer"""
    
    def __init__(self):
        self.name = "semgrep"
    
    def analyze(self, repo_path):
        """Run Semgrep analysis"""
        console.print("[cyan]Running Semgrep analysis...[/cyan]")
        
        try:
            cmd = [
                "semgrep",
                "--config=p/security-audit",
                "--quiet",
                "--json",
                repo_path
            ]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            if result.returncode != 0:
                logger.error(f"Semgrep failed: {result.stderr}")
                return {"issues": [], "error": result.stderr}
            
            results = json.loads(result.stdout)
            return self._process_results(results)
        except subprocess.TimeoutExpired:
            logger.error("Semgrep analysis timed out")
            return {"issues": [], "error": "Analysis timed out"}
        except Exception as e:
            logger.error(f"Error running Semgrep: {e}")
            return {"issues": [], "error": str(e)}
    
    def _process_results(self, results):
        """Process and structure Semgrep results"""
        processed_results = {
            "issues": [],
            "stats": results.get("stats", {})
        }
        
        for finding in results.get("results", []):
            processed_results["issues"].append({
                "file": finding.get("path"),
                "line": finding.get("start", {}).get("line"),
                "rule_id": finding.get("check_id"),
                "severity": finding.get("severity", "INFO"),
                "message": finding.get("extra", {}).get("message"),
                "snippet": finding.get("extra", {}).get("lines")
            })
        
        return processed_results

class CodeQualityAnalyzer:
    """Code quality analyzer for multiple languages"""
    
    def __init__(self, config):
        self.name = "code_quality"
        self.config = config
    
    def analyze(self, repo_path):
        """Run code quality analysis for detected languages"""
        console.print("[cyan]Running code quality analysis...[/cyan]")
        languages = RepoManager(self.config).detect_languages(repo_path)
        
        results = {"issues": []}
        
        # Run language-specific analyzers
        for language in languages:
            if self.config.get('analyzers', language) == 'true':
                analyzer_method = getattr(self, f"analyze_{language}", None)
                if analyzer_method:
                    language_results = analyzer_method(repo_path)
                    results["issues"].extend(language_results.get("issues", []))
        
        return results
    
    def analyze_python(self, repo_path):
        """Analyze Python code quality"""
        console.print("[cyan]Running Python code quality analysis...[/cyan]")
        results = {"issues": []}
        
        # Run Pylint
        if self.config.get('tools', 'pylint') == 'true':
            python_files = self._get_files_by_extension(repo_path, '.py')
            if not python_files:
                return {"issues": [], "message": "No Python files found"}
            
            for file in python_files:
                try:
                    cmd = ["pylint", "--output-format=json", file]
                    result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
                    if result.returncode != 0 and result.stdout:
                        issues = json.loads(result.stdout)
                        for issue in issues:
                            results["issues"].append({
                                "file": issue.get("path"),
                                "line": issue.get("line"),
                                "severity": issue.get("type", "INFO").upper(),
                                "message": issue.get("message"),
                                "language": "python"
                            })
                except Exception as e:
                    logger.error(f"Pylint error for {file}: {e}")
        
        # Run Bandit
        if self.config.get('tools', 'bandit') == 'true':
            try:
                cmd = ["bandit", "-r", "-f", "json", repo_path]
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
                if result.returncode != 0 and result.stdout:
                    bandit_results = json.loads(result.stdout)
                    for issue in bandit_results.get("results", []):
                        results["issues"].append({
                            "file": issue.get("filename"),
                            "line": issue.get("line_number"),
                            "severity": issue.get("issue_severity", "INFO").upper(),
                            "message": issue.get("issue_text"),
                            "language": "python"
                        })
            except Exception as e:
                logger.error(f"Bandit error: {e}")
        
        return results
    
    def analyze_javascript(self, repo_path):
       """Analyze JavaScript code for security vulnerabilities using Semgrep"""
       console.print("[cyan]Running JavaScript security analysis with Semgrep...[/cyan]")
       results = {"issues": []}
       
       try:
           yaml_path = os.path.join(os.path.dirname(__file__), "react-security.yaml")
           cmd = [
               "semgrep",
               "--config", "auto",
               "--config", "p/javascript",
               "--config", "p/typescript",
               "--config", "r/javascript.react.security",
               "--config", "r/javascript.security",
               "--config", yaml_path,
               "--json",
               "--quiet",
               "--timeout", "60",
               repo_path
           ]
           console.print(f"[cyan]Running: {' '.join(cmd)}[/cyan]")
           result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
           console.print(f"[cyan]Semgrep return code: {result.returncode}[/cyan]")
           console.print(f"[cyan]Semgrep stdout: {result.stdout[:1000] if result.stdout else 'Empty'}[/cyan]")
           console.print(f"[cyan]Semgrep stderr: {result.stderr[:200] if result.stderr else 'Empty'}[/cyan]")
           
           if result.returncode == 0 and result.stdout:
               semgrep_results = json.loads(result.stdout)
               scanned_files = semgrep_results.get("paths", {}).get("scanned", [])
               console.print(f"[cyan]Scanned files: {len(scanned_files)} files[/cyan]")
               for finding in semgrep_results.get("results", []):
                   severity = finding.get("extra", {}).get("severity", "WARNING").upper()
                   if severity in ["INFO"]:
                       severity = "LOW"
                   elif severity in ["ERROR"]:
                       severity = "HIGH"
                   results["issues"].append({
                       "file": finding.get("path"),
                       "line": finding.get("start", {}).get("line", 0),
                       "severity": severity,
                       "message": finding.get("extra", {}).get("message", "No message"),
                       "language": "javascript"
                   })
               if not semgrep_results.get("results"):
                   console.print("[yellow]No security issues found by Semgrep[/yellow]")
           else:
               # Report Semgrep errors as issues
               if result.stdout:
                   semgrep_results = json.loads(result.stdout)
                   for error in semgrep_results.get("errors", []):
                       results["issues"].append({
                           "file": "N/A",
                           "line": 0,
                           "severity": "HIGH",
                           "message": f"Semgrep analysis failed: {error.get('message')}",
                           "language": "javascript"
                       })
               console.print(f"[red]Semgrep failed with code {result.returncode}[/red]")
   
           # Dependency scan with Retire.js
           if os.path.exists(os.path.join(repo_path, "package.json")):
               console.print("[cyan]Scanning JavaScript dependencies with Retire.js...[/cyan]")
               retire_cmd = ["retire", "--path", repo_path, "--outputformat", "json"]
               retire_result = subprocess.run(retire_cmd, capture_output=True, text=True, timeout=300)
               console.print(f"[cyan]Retire.js return code: {retire_result.returncode}[/cyan]")
               console.print(f"[cyan]Retire.js stdout: {retire_result.stdout[:500] if retire_result.stdout else 'Empty'}[/cyan]")
               if retire_result.stdout:
                   try:
                       retire_results = json.loads(retire_result.stdout)
                       for vuln in retire_results.get("data", []):
                           results["issues"].append({
                               "file": vuln.get("file", "package.json"),
                               "line": 0,
                               "severity": "HIGH",
                               "message": f"Vulnerable dependency: {vuln.get('component')} {vuln.get('version')} - {vuln.get('vulnerability')}",
                               "language": "javascript"
                           })
                   except json.JSONDecodeError:
                       console.print("[yellow]Failed to parse Retire.js output[/yellow]")
       
       except Exception as e:
           logger.error(f"Semgrep/Retire error: {e}")
           console.print(f"[red]Analysis exception: {e}[/red]")
       
       return results
    
    def analyze_php(self, repo_path):
        """Analyze PHP code quality"""
        console.print("[cyan]Running PHP code quality analysis...[/cyan]")
        results = {"issues": []}
        
        # Run PHP_CodeSniffer
        if self.config.get('tools', 'phpcs') == 'true':
            try:
                cmd = ["phpcs", "--report=json", "--standard=PSR12", repo_path]
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
                if result.stdout:
                    phpcs_results = json.loads(result.stdout)
                    for file_path, file_issues in phpcs_results.get("files", {}).items():
                        for issue in file_issues.get("messages", []):
                            results["issues"].append({
                                "file": file_path,
                                "line": issue.get("line"),
                                "severity": issue.get("type", "ERROR").upper(),
                                "message": issue.get("message"),
                                "language": "php"
                            })
            except Exception as e:
                logger.error(f"PHP_CodeSniffer error: {e}")
        
        # Run PHPStan
        if self.config.get('tools', 'phpstan') == 'true':
            try:
                cmd = ["phpstan", "analyse", "--error-format=json", repo_path]
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
                if result.stdout:
                    phpstan_results = json.loads(result.stdout)
                    for file_path, file_errors in phpstan_results.get("files", {}).items():
                        for error in file_errors.get("messages", []):
                            results["issues"].append({
                                "file": file_path,
                                "line": error.get("line"),
                                "severity": "ERROR",
                                "message": error.get("message"),
                                "language": "php"
                            })
            except Exception as e:
                logger.error(f"PHPStan error: {e}")
        
        return results
    
    def analyze_ruby(self, repo_path):
        """Analyze Ruby code quality"""
        console.print("[cyan]Running Ruby code quality analysis...[/cyan]")
        results = {"issues": []}
        
        # Run RuboCop
        if self.config.get('tools', 'rubocop') == 'true':
            try:
                cmd = ["rubocop", "--format", "json", repo_path]
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
                if result.stdout:
                    rubocop_results = json.loads(result.stdout)
                    for file_result in rubocop_results.get("files", []):
                        for offense in file_result.get("offenses", []):
                            results["issues"].append({
                                "file": file_result.get("path"),
                                "line": offense.get("location", {}).get("line"),
                                "severity": offense.get("severity", "warning").upper(),
                                "message": offense.get("message"),
                                "language": "ruby"
                            })
            except Exception as e:
                logger.error(f"RuboCop error: {e}")
        
        # Run Brakeman
        if self.config.get('tools', 'brakeman') == 'true':
            try:
                cmd = ["brakeman", "--format", "json", repo_path]
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
                if result.stdout:
                    brakeman_results = json.loads(result.stdout)
                    for warning in brakeman_results.get("warnings", []):
                        results["issues"].append({
                            "file": warning.get("file"),
                            "line": warning.get("line"),
                            "severity": warning.get("confidence", "Medium").upper(),
                            "message": warning.get("message"),
                            "language": "ruby"
                        })
            except Exception as e:
                logger.error(f"Brakeman error: {e}")
        
        return results
    
    def analyze_go(self, repo_path):
        """Analyze Go code quality"""
        console.print("[cyan]Running Go code quality analysis...[/cyan]")
        results = {"issues": []}
        
        # Run golint
        if self.config.get('tools', 'golint') == 'true':
            try:
                cmd = ["golint", repo_path]
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
                if result.stdout:
                    for line in result.stdout.splitlines():
                        parts = line.split(":", 3)
                        if len(parts) >= 3:
                            results["issues"].append({
                                "file": parts[0],
                                "line": parts[1],
                                "severity": "WARNING",
                                "message": parts[2].strip(),
                                "language": "go"
                            })
            except Exception as e:
                logger.error(f"golint error: {e}")
        
        # Run gosec
        if self.config.get('tools', 'gosec') == 'true':
            try:
                cmd = ["gosec", "-fmt=json", repo_path]
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
                if result.stdout:
                    gosec_results = json.loads(result.stdout)
                    for issue in gosec_results.get("Issues", []):
                        results["issues"].append({
                            "file": issue.get("file"),
                            "line": issue.get("line"),
                            "severity": issue.get("severity", "MEDIUM").upper(),
                            "message": issue.get("details"),
                            "language": "go"
                        })
            except Exception as e:
                logger.error(f"gosec error: {e}")
        
        return results
    
    def analyze_c(self, repo_path):
        """Analyze C code quality"""
        console.print("[cyan]Running C code quality analysis...[/cyan]")
        results = {"issues": []}
        
        # Run cppcheck
        if self.config.get('tools', 'cppcheck') == 'true':
            try:
                cmd = ["cppcheck", "--xml", "--enable=all", repo_path]
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
                if result.stderr:
                    import xml.etree.ElementTree as ET
                    root = ET.fromstring(result.stderr)
                    for error in root.findall(".//error"):
                        location = error.find("location")
                        if location is not None:
                            results["issues"].append({
                                "file": location.get("file"),
                                "line": location.get("line"),
                                "severity": error.get("severity", "warning").upper(),
                                "message": error.get("msg"),
                                "language": "c"
                            })
            except Exception as e:
                logger.error(f"cppcheck error: {e}")
        
        # Run clang-analyzer
        if self.config.get('tools', 'clang-analyzer') == 'true':
            try:
                cmd = ["scan-build", "-o", os.path.join(repo_path, "scan-build-results"), "make"]
                subprocess.run(cmd, cwd=repo_path, capture_output=True, timeout=300)
                
                # Parse clang-analyzer results
                # This is a simplified approach, real implementation would need to handle the output format
                result_dirs = os.listdir(os.path.join(repo_path, "scan-build-results"))
                if result_dirs:
                    latest_result = os.path.join(repo_path, "scan-build-results", result_dirs[0])
                    reports = os.listdir(latest_result)
                    for report in reports:
                        with open(os.path.join(latest_result, report), 'r') as f:
                            report_content = f.read()
                            # Simple parsing logic (actual implementation would be more complex)
                            if "warning:" in report_content:
                                results["issues"].append({
                                    "file": "extracted_from_report",
                                    "line": "extracted_from_report",
                                    "severity": "WARNING",
                                    "message": "clang-analyzer warning detected",
                                    "language": "c"
                                })
            except Exception as e:
                logger.error(f"clang-analyzer error: {e}")
        
        return results
    
    def analyze_cpp(self, repo_path):
        """Analyze C++ code quality"""
        # For C++, we can reuse the C analyzer since they use similar tools
        return self.analyze_c(repo_path)
    
    def analyze_csharp(self, repo_path):
        """Analyze C# code quality"""
        console.print("[cyan]Running C# code quality analysis...[/cyan]")
        results = {"issues": []}
        
        # Run SonarScanner
        if self.config.get('tools', 'sonarscanner') == 'true':
            try:
                # Create a temporary sonar-project.properties file
                sonar_props = os.path.join(repo_path, "sonar-project.properties")
                with open(sonar_props, 'w') as f:
                    f.write(f"""
                    sonar.projectKey=coach-csharp
                    sonar.projectName=coach C# Analysis
                    sonar.projectVersion=1.0
                    sonar.sources={repo_path}
                    sonar.cs.file.suffixes=.cs
                    sonar.sourceEncoding=UTF-8
                    """)
                
                # Run SonarScanner
                cmd = ["sonar-scanner"]
                subprocess.run(cmd, cwd=repo_path, capture_output=True, timeout=300)
                
                # Parse results from SonarQube API
                # This is a simplified approach, real implementation would need to handle authentication and API calls
                sonar_url = "http://localhost:9000"
                resp = requests.get(f"{sonar_url}/api/issues/search?projectKeys=coach-csharp&resolved=false")
                if resp.status_code == 200:
                    sonar_results = resp.json()
                    for issue in sonar_results.get("issues", []):
                        results["issues"].append({
                            "file": issue.get("component"),
                            "line": issue.get("line"),
                            "severity": issue.get("severity", "MAJOR").upper(),
                            "message": issue.get("message"),
                            "language": "csharp"
                        })
            except Exception as e:
                logger.error(f"SonarScanner error: {e}")
        
        return results
    
    def _get_files_by_extension(self, directory, extensions):
        """Get files with specified extensions in a directory"""
        if isinstance(extensions, str):
            extensions = [extensions]
        
        files = []
        for root, _, filenames in os.walk(directory):
            for filename in filenames:
                if any(filename.endswith(ext) for ext in extensions):
                    files.append(os.path.join(root, filename))
        return files

class DependencyAnalyzer:
    """Analyze dependencies for security vulnerabilities"""
    
    def __init__(self, config):
        self.name = "dependencies"
        self.config = config
    
    def analyze(self, repo_path):
        """Run dependency analysis"""
        console.print("[cyan]Running dependency analysis...[/cyan]")
        results = {"issues": []}
        
        # Detect languages in the repository
        languages = RepoManager(self.config).detect_languages(repo_path)
        #print(languages)
        
        # Analyze dependencies for each language
        for language in languages:
            analyzer_method = getattr(self, f"analyze_{language}_deps", None)
            if analyzer_method:
                language_results = analyzer_method(repo_path)
                results["issues"].extend(language_results.get("issues", []))
        
        return results
    
    def analyze_python_deps(self, repo_path):
        """Analyze Python dependencies"""
        console.print("[cyan]Analyzing Python dependencies...[/cyan]")
        results = {"issues": []}
        
        # Check for requirements.txt
        req_file = os.path.join(repo_path, "requirements.txt")
        if os.path.exists(req_file):
            try:
                cmd = ["safety", "check", "-r", req_file, "--json"]
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
                if result.stdout:
                    safety_results = json.loads(result.stdout)
                    for issue in safety_results.get("vulnerabilities", []):
                        results["issues"].append({
                                 "file": "requirements.txt",
                                 "line": 0,
                                 "severity": issue.get("severity", "").upper() or "HIGH",
                                 "message": f"Vulnerable dependency: {issue.get('package_name')} {issue.get('vulnerable_spec')}: {issue.get('advisory')}",
                                 "language": "python"
                               })
            except Exception as e:
                logger.error(f"Safety check error: {e}")
        
        return results
    
    def analyze_javascript_deps(self, repo_path):
        """Analyze JavaScript dependencies"""
        console.print("[cyan]Analyzing JavaScript dependencies...[/cyan]")
        results = {"issues": []}
        
        # Check for package.json
        pkg_file = os.path.join(repo_path, "package.json")
        if os.path.exists(pkg_file):
            try:
                cmd = ["npm", "audit", "--json"]
                result = subprocess.run(cmd, cwd=repo_path, capture_output=True, text=True, timeout=300)
                if result.stdout:
                    npm_results = json.loads(result.stdout)
                    for vuln_id, vuln_info in npm_results.get("advisories", {}).items():
                        results["issues"].append({
                            "file": "package.json",
                            "line": 0,
                            "severity": vuln_info.get("severity", "").upper(),
                            "message": f"Vulnerable dependency: {vuln_info.get('module_name')} {vuln_info.get('vulnerable_versions')}: {vuln_info.get('title')}",
                            "language": "javascript"
                        })
            except Exception as e:
                logger.error(f"npm audit error: {e}")
        
        return results
    
    def analyze_java_deps(self, repo_path):
        """Analyze Java dependencies"""
        console.print("[cyan]Analyzing Java dependencies...[/cyan]")
        results = {"issues": []}
        
        # Check for pom.xml (Maven)
        pom_file = os.path.join(repo_path, "pom.xml")
        if os.path.exists(pom_file):
            try:
                cmd = ["mvn", "dependency:check", "-DoutputFormat=JSON", 
                       f"-DoutputDirectory={os.path.join(repo_path, 'dependency-check-output')}"]
                subprocess.run(cmd, cwd=repo_path, capture_output=True, timeout=300)
                
                # Parse OWASP Dependency Check results
                report_file = os.path.join(repo_path, "dependency-check-output", "dependency-check-report.json")
                if os.path.exists(report_file):
                    with open(report_file, 'r') as f:
                        dc_results = json.load(f)
                        for dependency in dc_results.get("dependencies", []):
                            for vuln in dependency.get("vulnerabilities", []):
                                results["issues"].append({
                                    "file": pom_file,
                                    "line": 0,
                                    "severity": vuln.get("severity", "").upper(),
                                    "message": f"Vulnerable dependency: {dependency.get('fileName')}: {vuln.get('name')} - {vuln.get('description')}",
                                    "language": "java"
                                })
            except Exception as e:
                logger.error(f"Dependency check error: {e}")
        
        return results
    
    def analyze_ruby_deps(self, repo_path):
        """Analyze Ruby dependencies"""
        console.print("[cyan]Analyzing Ruby dependencies...[/cyan]")
        results = {"issues": []}
        
        # Check for Gemfile
        gemfile = os.path.join(repo_path, "Gemfile")
        if os.path.exists(gemfile):
            try:
                cmd = ["bundle", "audit", "--format", "json"]
                result = subprocess.run(cmd, cwd=repo_path, capture_output=True, text=True, timeout=300)
                if result.stdout:
                    bundle_results = json.loads(result.stdout)
                    for vuln in bundle_results.get("vulnerabilities", []):
                        results["issues"].append({
                            "file": "Gemfile",
                            "line": 0,
                            "severity": vuln.get("criticality", "").upper() or "HIGH",
                            "message": f"Vulnerable dependency: {vuln.get('gem')}: {vuln.get('advisory')}",
                            "language": "ruby"
                        })
            except Exception as e:
                logger.error(f"Bundle audit error: {e}")
        
        return results
    
    def analyze_php_deps(self, repo_path):
        """Analyze PHP dependencies"""
        console.print("[cyan]Analyzing PHP dependencies...[/cyan]")
        results = {"issues": []}
        
        # Check for composer.json
        composer_file = os.path.join(repo_path, "composer.json")
        if os.path.exists(composer_file):
            try:
                cmd = ["composer", "audit", "--format=json"]
                result = subprocess.run(cmd, cwd=repo_path, capture_output=True, text=True, timeout=300)
                if result.stdout:
                    composer_results = json.loads(result.stdout)
                    for vuln in composer_results.get("advisories", []):
                        results["issues"].append({
                            "file": "composer.json",
                            "line": 0,
                            "severity": vuln.get("severity", "").upper() or "HIGH",
                            "message": f"Vulnerable dependency: {vuln.get('package')}: {vuln.get('title')}",
                            "language": "php"
                        })
            except Exception as e:
                logger.error(f"Composer audit error: {e}")
        
        return results
    
    def analyze_go_deps(self, repo_path):
        """Analyze Go dependencies"""
        console.print("[cyan]Analyzing Go dependencies...[/cyan]")
        results = {"issues": []}
        
        # Check for go.mod
        go_mod = os.path.join(repo_path, "go.mod")
        if os.path.exists(go_mod):
            try:
                cmd = ["nancy", "sleuth", "--output", "json"]
                with open(go_mod, 'r') as f:
                    result = subprocess.run(cmd, input=f.read(), capture_output=True, text=True, timeout=300)
                if result.stdout:
                    nancy_results = json.loads(result.stdout)
                    for vuln in nancy_results.get("vulnerable", []):
                        results["issues"].append({
                            "file": "go.mod",
                            "line": 0,
                            "severity": vuln.get("severity", "").upper() or "HIGH",
                            "message": f"Vulnerable dependency: {vuln.get('coordinates')}: {vuln.get('description')}",
                            "language": "go"
                        })
            except Exception as e:
                logger.error(f"Nancy sleuth error: {e}")
        
        return results

class ReportGenerator:
    """Generate security and quality reports"""
    
    def __init__(self, config):
        self.config = config
    
    def generate_report(self, analysis_results):
        """Generate a comprehensive report from analysis results"""
        console.print("[cyan]Generating report...[/cyan]")
        
        # Create a Rich table for issues
        table = Table(title="Coach Analysis Results")
        table.add_column("File", style="cyan")
        table.add_column("Line", style="blue")
        table.add_column("Severity", style="red")
        table.add_column("Message", style="green")
        table.add_column("Language", style="yellow")
        
        total_issues = 0
        severity_counts = {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}
        all_issues = []  # Collect issues for AI suggestions
        
        # Add issues to table and collect them
        for analyzer_name, results in analysis_results.items():
            for issue in results.get("issues", []):
                severity = issue.get("severity", "").upper()
                if severity in ["INFO", "WARNING"]:
                    severity = "LOW"
                elif severity in ["ERROR"]:
                    severity = "HIGH"
                
                if severity in severity_counts:
                    severity_counts[severity] += 1
                
                total_issues += 1
                table.add_row(
                    str(issue.get("file", "Unknown")),
                    str(issue.get("line", "0")),
                    severity,
                    str(issue.get("message", "No message")),
                    str(issue.get("language", "Unknown"))
                )
                all_issues.append(issue)  # Store issue for later
        
        # Print summary
        console.print(f"\n[bold green]Total issues found: {total_issues}[/bold green]")
        console.print(f"[bold red]Critical: {severity_counts['CRITICAL']}[/bold red]")
        console.print(f"[bold yellow]High: {severity_counts['HIGH']}[/bold yellow]")
        console.print(f"[bold blue]Medium: {severity_counts['MEDIUM']}[/bold blue]")
        console.print(f"[bold cyan]Low: {severity_counts['LOW']}[/bold cyan]")
        
        # Print table
        console.print(table)
        
        # Prompt user for AI fix suggestions if there are issues
        if total_issues > 0:
            ai_prompt = Prompt.ask(
                "\n[cyan]Would you like AI suggestions to fix these issues?[/cyan]",
                choices=["yes", "no"],
                default="no"
            )
            if ai_prompt.lower() == "yes":
                suggestions_file = self.get_fix_suggestions(all_issues)
                if suggestions_file:
                    console.print(f"[green]AI suggestions saved to: {suggestions_file}[/green]")
        
        # Save report to file
        self.save_report_to_file(analysis_results, total_issues, severity_counts)
        
        return {
            "total_issues": total_issues,
            "severity_counts": severity_counts
        }
    
    def get_fix_suggestions(self, issues):
        """Generate AI fix suggestions and save them to an HTML file, removing only the word 'loading'"""
        console.print("[cyan]Fetching fix suggestions from Terminal GPT...Please Wait!![/cyan]")
        
        try:
            # Check if tgpt is installed
            subprocess.run(["which", "tgpt"], check=True, capture_output=True)
        except subprocess.CalledProcessError:
            console.print("[red]Terminal GPT (tgpt) is not installed. Please install it with:[/red]")
            console.print("[yellow]curl -sSL https://raw.githubusercontent.com/aandrew-me/tgpt/main/install | bash -s /usr/local/bin[/yellow]")
            return None
        
        # Prepare HTML content
        timestamp = int(os.times().elapsed)
        report_dir = os.path.expanduser("~/coach_reports")
        os.makedirs(report_dir, exist_ok=True)
        suggestions_file = os.path.join(report_dir, f"suggestions_{timestamp}.html")
        
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Coach AI Fix Suggestions</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; }}
                h1, h2 {{ color: #333; }}
                table {{ width: 100%; border-collapse: collapse; margin-top: 20px; }}
                th, td {{ padding: 10px; text-align: left; border-bottom: 1px solid #ddd; }}
                th {{ background-color: #f2f2f2; }}
                tr:hover {{ background-color: #f5f5f5; }}
                .severity-CRITICAL {{ color: #d9534f; font-weight: bold; }}
                .severity-HIGH {{ color: #f0ad4e; font-weight: bold; }}
                .severity-MEDIUM {{ color: #5bc0de; }}
                .severity-LOW {{ color: #5cb85c; }}
                .suggestion {{ color: #f39c12; font-style: italic; }}
            </style>
        </head>
        <body>
            <h1>Coach AI Fix Suggestions</h1>
            <p>Generated on: {time.ctime(timestamp)}</p>
            <h2>Suggestions ({len(issues)})</h2>
            <table>
                <tr>
                    <th>File</th>
                    <th>Line</th>
                    <th>Severity</th>
                    <th>Issue</th>
                    <th>Language</th>
                    <th>Suggestion</th>
                </tr>
        """
        
        # Fetch suggestions and build HTML rows
        for i, issue in enumerate(issues, 1):
            file = issue.get("file", "Unknown")
            line = issue.get("line", 0)
            severity = issue.get("severity", "Unknown")
            message = issue.get("message", "No message")
            language = issue.get("language", "Unknown")
            
            # Craft prompt for tgpt
            prompt = (
                f"In a {language} file '{file}' at line {line}, "
                f"a {severity} severity issue was found: '{message}'. "
                f"How can I fix this issue? Provide a concise suggestion."
            )
            
            suggestion = "No suggestion available"
            try:
                cmd = ["tgpt", prompt]
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
                if result.returncode == 0 and result.stdout:
                    # Remove only the word "loading" (case-insensitive) while keeping the rest
                    raw_suggestion = result.stdout.strip()
                    suggestion = raw_suggestion.replace("loading", "").replace("Loading", "").strip()
                    # Ensure suggestion isn’t empty after removal; revert to raw if it is
                    if not suggestion:
                        suggestion = raw_suggestion
                elif result.stderr:
                    logger.error(f"tgpt error for issue {i}: {result.stderr}")
            except subprocess.TimeoutExpired:
                suggestion = "AI suggestion timed out"
                logger.warning(f"tgpt timed out for issue {i}")
            except Exception as e:
                suggestion = f"Error fetching suggestion: {e}"
                logger.error(f"Error calling tgpt for issue {i}: {e}")
            
            # Add row to HTML
            html_content += f"""
                <tr>
                    <td>{file}</td>
                    <td>{line}</td>
                    <td class="severity-{severity}">{severity}</td>
                    <td>{message}</td>
                    <td>{language}</td>
                    <td class="suggestion">{suggestion}</td>
                </tr>
            """
        
        # Close HTML
        html_content += """
            </table>
        </body>
        </html>
        """
        
        # Write to file
        try:
            with open(suggestions_file, 'w') as f:
                f.write(html_content)
            return suggestions_file
        except Exception as e:
            logger.error(f"Error saving suggestions HTML: {e}")
            console.print(f"[red]Failed to save AI suggestions: {e}[/red]")
            return None
    
    def save_report_to_file(self, analysis_results, total_issues, severity_counts):
        """Save report to JSON and HTML files"""
        timestamp = int(os.times().elapsed)
        report_dir = os.path.expanduser("~/coach_reports")
        os.makedirs(report_dir, exist_ok=True)
        
        # Save JSON report
        json_file = os.path.join(report_dir, f"report_{timestamp}.json")
        report_data = {
            "timestamp": timestamp,
            "total_issues": total_issues,
            "severity_counts": severity_counts,
            "results": analysis_results
        }
        
        with open(json_file, 'w') as f:
            json.dump(report_data, f, indent=4)
        
        console.print(f"[green]JSON report saved to: {json_file}[/green]")
        
        # Generate HTML report
        html_file = os.path.join(report_dir, f"report_{timestamp}.html")
        with open(html_file, 'w') as f:
            f.write(f"""
            <!DOCTYPE html>
            <html>
            <head>
                <title>Coach Security Report</title>
                <style>
                    body {{ font-family: Arial, sans-serif; margin: 20px; }}
                    h1, h2 {{ color: #333; }}
                    .summary {{ display: flex; justify-content: space-between; margin: 20px 0; }}
                    .summary-item {{ padding: 15px; border-radius: 5px; color: white; text-align: center; flex: 1; margin: 0 10px; }}
                    .critical {{ background-color: #d9534f; }}
                    .high {{ background-color: #f0ad4e; }}
                    .medium {{ background-color: #5bc0de; }}
                    .low {{ background-color: #5cb85c; }}
                    table {{ width: 100%; border-collapse: collapse; }}
                    th, td {{ padding: 8px; text-align: left; border-bottom: 1px solid #ddd; }}
                    th {{ background-color: #f2f2f2; }}
                    tr:hover {{ background-color: #f5f5f5; }}
                    .severity-CRITICAL {{ color: #d9534f; font-weight: bold; }}
                    .severity-HIGH {{ color: #f0ad4e; font-weight: bold; }}
                    .severity-MEDIUM {{ color: #5bc0de; }}
                    .severity-LOW {{ color: #5cb85c; }}
                </style>
            </head>
            <body>
                <h1>Coach Security Analysis Report</h1>
                <p>Generated on: {time.ctime(timestamp)}</p>
                
                <h2>Summary</h2>
                <div class="summary">
                    <div class="summary-item critical">
                        <h3>Critical</h3>
                        <p>{severity_counts['CRITICAL']}</p>
                    </div>
                    <div class="summary-item high">
                        <h3>High</h3>
                        <p>{severity_counts['HIGH']}</p>
                    </div>
                    <div class="summary-item medium">
                        <h3>Medium</h3>
                        <p>{severity_counts['MEDIUM']}</p>
                    </div>
                    <div class="summary-item low">
                        <h3>Low</h3>
                        <p>{severity_counts['LOW']}</p>
                    </div>
                </div>
                
                <h2>Issues ({total_issues})</h2>
                <table>
                    <tr>
                        <th>File</th>
                        <th>Line</th>
                        <th>Severity</th>
                        <th>Message</th>
                        <th>Language</th>
                    </tr>
            """)
            
            # Add issues to HTML table
            for analyzer_name, results in analysis_results.items():
                for issue in results.get("issues", []):
                    severity = issue.get("severity", "").upper()
                    if severity in ["INFO", "WARNING"]:
                        severity = "LOW"
                    elif severity in ["ERROR"]:
                        severity = "HIGH"
                    
                    f.write(f"""
                    <tr>
                        <td>{issue.get("file", "Unknown")}</td>
                        <td>{issue.get("line", "0")}</td>
                        <td class="severity-{severity}">{severity}</td>
                        <td>{issue.get("message", "No message")}</td>
                        <td>{issue.get("language", "Unknown")}</td>
                    </tr>
                    """)
            
            f.write("""
                </table>
            </body>
            </html>
            """)
        
        console.print(f"[green]HTML report saved to: {html_file}[/green]")

def check_dependencies(config):
    """Check if required dependencies are installed"""
    console.print("[cyan]Checking dependencies...[/cyan]")
    
    required_tools = {
        "semgrep": "pip3 install semgrep",
        "pylint": "pip3 install pylint",
        "bandit": "pip3 install bandit",
        "eslint": "npm install -g eslint",
        "jshint": "npm install -g jshint",
        "pmd": "npm install -g pmd-bin",
        "spotbugs": "manual_install_spotbugs",
        "phpcs": "composer global require squizlabs/php_codesniffer",
        "phpstan": "composer global require phpstan/phpstan",
        "rubocop": "gem install rubocop",
        "brakeman": "gem install brakeman",
        "golint": "go install golang.org/x/lint/golint@latest",
        "gosec": "go install github.com/securego/gosec/v2/cmd/gosec@latest",
        "cppcheck": "sudo apt install cppcheck -y",
        "scan-build": "sudo apt install clang-tools -y",
        "sonar-scanner": "npm install -g sonar-scanner",
        "safety": "pip3 install safety",
        "npm": "sudo apt install npm -y",
        "mvn": "sudo apt install maven -y",
        "composer": "curl -sS https://getcomposer.org/installer | php && sudo mv composer.phar /usr/local/bin/composer",
        "bundle": "gem install bundler",
        "nancy": "go install github.com/sonatype-nexus-community/nancy@latest",
        "tgpt": "curl -sSL https://raw.githubusercontent.com/aandrew-me/tgpt/main/install | bash -s /usr/local/bin"  # Added tgpt
    }
    
    # Documentation URLs for manual install tools
    manual_install_docs = {
        "pmd": "https://www.npmjs.com/package/pmd-bin?activeTab=readme",
        "spotbugs": "https://spotbugs.github.io/",
        "sonar-scanner": "https://www.npmjs.com/package/sonar-scanner",
        "rubocop": "gem install rubocop --user-install",
        "brakeman": "gem install brakeman --user-install",
        "bundle": "gem install bundler --user-install",
    }
    
    missing_tools = []
    
    for tool, install_cmd in required_tools.items():
        if config.get('tools', tool, fallback='false') == 'true' or tool in ["semgrep", "npm", "mvn", "composer", "bundle", "nancy"]:
            try:
                subprocess.run(["which", tool], check=True, capture_output=True)
            except subprocess.CalledProcessError:
                missing_tools.append((tool, install_cmd))
    
    if missing_tools:
        console.print("[yellow]Some required tools are missing:[/yellow]")
        for tool, install_cmd in missing_tools:
            console.print(f"  - {tool}: Install with `{install_cmd}`")
        
        if config.get('dependencies', 'auto_install') == 'true':
            console.print("[cyan]Attempting to install missing tools...[/cyan]")
            for tool, install_cmd in missing_tools:
                if "manual_install" in install_cmd:
                    doc_url = manual_install_docs.get(tool, "relevant documentation")
                    console.print(f"[yellow]{tool} requires manual installation. See: {doc_url}[/yellow]")
                    continue
                try:
                    console.print(f"[cyan]Installing {tool}...[/cyan]")
                    subprocess.run(install_cmd, shell=True, check=True)
                    console.print(f"[green]{tool} installed successfully.[/green]")
                except subprocess.CalledProcessError as e:
                    console.print(f"[red]Failed to install {tool}: {e}[/red]")
                    return False
        else:
            console.print("[yellow]Please install the missing dependencies manually.[/yellow]")
            return False
    
    console.print("[green]All required dependencies are installed.[/green]")
    return True

def main():
    console.print(pyfiglet.figlet_format(TOOL_NAME), style="bold blue")
    console.print(f"[bold cyan]Version {VERSION}[/bold cyan]")
    console.print("[bold cyan]A comprehensive code security & quality analysis tool[/bold cyan]")
    console.print()
    
    config = Config()
    
    if len(sys.argv) < 2:
        console.print("[yellow]Usage: coach <repository_url> [branch] [options][/yellow]")
        console.print("[yellow]Example: coach https://github.com/username/repo.git main[/yellow]")
        sys.exit(1)
    
    if config.get('dependencies', 'check_deps') == 'true':
        if not check_dependencies(config):
            if config.get('dependencies', 'auto_install') == 'true':
                console.print("[cyan]Attempting to install missing dependencies...[/cyan]")
            else:
                console.print("[yellow]Please install the missing dependencies manually.[/yellow]")
                sys.exit(1)
    
    repo_url = sys.argv[1]
    branch = sys.argv[2] if len(sys.argv) > 2 else "main"
    
    try:
        repo_manager = RepoManager(config)
        repo_path = repo_manager.clone_repo(repo_url, branch)
        
        semgrep_analyzer = SemgrepAnalyzer()
        code_quality_analyzer = CodeQualityAnalyzer(config)
        dependency_analyzer = DependencyAnalyzer(config)
        
        analysis_results = {}
        
        with ThreadPoolExecutor(max_workers=int(config.get('general', 'threads'))) as executor:
            futures = {}
            
            if config.get('analyzers', 'semgrep') == 'true':
                futures[executor.submit(semgrep_analyzer.analyze, repo_path)] = "semgrep"
            
            futures[executor.submit(code_quality_analyzer.analyze, repo_path)] = "code_quality"
            
            if config.get('dependencies', 'check_deps') == 'true':
                futures[executor.submit(dependency_analyzer.analyze, repo_path)] = "dependencies"
            
            for future in as_completed(futures):
                analyzer_name = futures[future]
                try:
                    result = future.result()
                    analysis_results[analyzer_name] = result
                except Exception as e:
                    logger.error(f"Error in {analyzer_name} analysis: {e}")
                    console.print(f"[red]Error in {analyzer_name} analysis: {e}[/red]")
                    analysis_results[analyzer_name] = {"issues": [], "error": str(e)}
        
        report_generator = ReportGenerator(config)
        report_generator.generate_report(analysis_results)
        
        if os.path.exists(repo_path):
            shutil.rmtree(repo_path)
        
        console.print("[green]Analysis completed successfully![/green]")
    
    except Exception as e:
        logger.error(f"Error during analysis: {e}")
        console.print(f"[red]Error: {e}[/red]")
        sys.exit(1)

if __name__ == "__main__":
    main()