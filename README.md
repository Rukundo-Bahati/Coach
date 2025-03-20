# Coach

<!-- Replace with an actual logo if available -->

## A Comprehensive Code Security & Quality Analysis Tool

**Version:** 1.0.0  
**Built with:** Python 3, Semgrep, Rich, and more

Coach is an advanced, multi-language static analysis tool designed to identify security vulnerabilities, code quality issues, and dependency risks in your repositories. Whether you're a developer, security professional, or DevOps engineer, Coach empowers you to maintain secure and high-quality codebases with ease.

---

## 🚀 Features

✅ **Multi-Language Support**: Analyzes Python, JavaScript, Java, PHP, Ruby, Go, C/C++, and C# codebases.  
✅ **Security Scanning**: Uses Semgrep to detect security vulnerabilities across languages.  
✅ **Code Quality Checks**: Integrates tools like Pylint, ESLint, RuboCop, and more for in-depth quality analysis.  
✅ **Dependency Auditing**: Identifies vulnerable dependencies using tools like Safety, npm audit, and OWASP Dependency-Check.  
✅ **Customizable Configuration**: Fine-tune analysis via a JSON config file.  
✅ **Parallel Execution**: Speeds up scans with multi-threading support.  
✅ **Rich Reporting**: Generates detailed JSON and HTML reports with severity-based summaries.  
✅ **AI-Powered Suggestions**: Optional fix suggestions powered by Terminal GPT (tgpt).  

---

## 🛠 Installation

### **Prerequisites**
- Python 3.6+
- Git
- Language-specific tools (e.g., Node.js for JavaScript, Maven for Java, etc.)
- **Optional:** Terminal GPT (tgpt) for AI suggestions

### **Quick Setup**

Clone the repository:
```bash
git clone https://github.com/Rukundo-Bahati/Coach.git
cd Coach/coach
```

Create a virtual environment:
```bash
python3 -m venv venv_new
source venv_new/bin/activate
```

Install Python dependencies:
```bash
pip3 install .
```
(*Note: Ensure `requirements.txt` includes rich, pyfiglet, gitpython, requests, etc.*)

Check and install required tools:
```bash
python3 coach
```
Coach will check for missing dependencies and provide installation commands. Set `auto_install` to `true` in `config.json` for automatic setup (where supported).

---

## 📌 Usage

### **Basic Command (Example)** 
Analyze a repository by providing its URL and branch:
```bash
coach https://github.com/username/repo.git main
```
//Replace the github repo with the one you want to analyze
### main branch is considered as default for all repositories. If it's not, you have to specify it.
 
### **Example Output**
```
  ____                 _     
 / ___|___   __ _  ___| |__  
| |   / _ \ / _` |/ __| '_ \ 
| |__| (_) | (_| | (__| | | |
 \____\___/ \__,_|\___|_| |_|
                             

Version 1.0.0
A comprehensive code security & quality analysis tool

[cyan]Cloning repository: https://github.com/username/repo.git (branch: main)[/cyan]
[green]Repository cloned to: /tmp/coach/repo_123456[/green]
[cyan]Running Semgrep analysis...[/cyan]
[cyan]Running code quality analysis...[/cyan]
[cyan]Running dependency analysis...[/cyan]
[green]Total issues found: 5[/green]
[bold red]Critical: 1[/bold red]
[bold yellow]High: 2[/bold yellow]
[bold blue]Medium: 1[/bold blue]
[bold cyan]Low: 1[/bold cyan]
```

### **Generated Reports**
- **JSON Report:** `~/coach_reports/report_<timestamp>.json`
- **HTML Report:** `~/coach_reports/report_<timestamp>.html`
- **AI Suggestions (Optional):** `~/coach_reports/suggestions_<timestamp>.html`

---

## ⚙️ Configuration
Coach uses a JSON configuration file located at `~/.coach/config.json`. Customize settings like:

```json
{
    "general": {
        "temp_dir": "/tmp/coach",
        "threads": "4",
        "timeout": "300",
        "verbose": "false"
    },
    "analyzers": {
        "python": "true",
        "javascript": "true",
        "semgrep": "true"
    },
    "dependencies": {
        "check_deps": "true",
        "auto_install": "false"
    },
    "tools": {
        "pylint": "true",
        "bandit": "true",
        "eslint": "true"
    }
}
```

### **Customization Options**
- **Enable/Disable Analyzers**: Set language or tool flags to `"true"` or `"false"`.
- **Threads**: Adjust for performance (default: `4`).
- **Auto-Install**: Set `"auto_install": "true"` to attempt automatic dependency installation.

---

## Logs
Check logs at `~/.coach/coach.log`

## 🛡 Supported Tools

| Language  | Security Tools         | Quality Tools                | Dependency Tools          |
|-----------|------------------------|------------------------------|---------------------------|
| **Python**  | Bandit, Semgrep        | Pylint                        | Safety                    |
| **JavaScript** | Semgrep, Retire.js   | ESLint, JSHint                | npm audit                  |
| **Java**   | SpotBugs, Semgrep      | PMD                          | OWASP Dependency-Check     |
| **PHP**    | Semgrep                | PHP_CodeSniffer, PHPStan     | Composer audit             |
| **Ruby**   | Brakeman, Semgrep      | RuboCop                      | Bundle audit               |
| **Go**     | Gosec, Semgrep         | Golint                        | Nancy                      |
| **C/C++**  | Semgrep                | Cppcheck, Clang-Analyzer     | -                          |
| **C#**     | Semgrep                | SonarScanner                 | -                          |

---

## 🤝 Contributing
We welcome contributions! Here's how to get started:

1. **Fork** the repository.
2. Create a feature branch:
   ```bash
   git checkout -b feature-name
   ```
3. Commit your changes:
   ```bash
   git commit -m "Add feature"
   ```
4. Push to your branch:
   ```bash
   git push origin feature-name
   ```
5. Open a **Pull Request**.

### **Ideas for Contribution**
- Add support for new languages or tools.
- Enhance report formatting or add new output formats.
- Improve error handling and logging.

---

## 📜 License
This project is licensed under the **MIT License** - see the `LICENSE` file for details.

---

## 🙌 Acknowledgments
- Built with by **[Team Coach]**
- Powered by open-source tools like Semgrep, Pylint, and Rich.
- Special thanks to the **Terminal GPT** project for AI suggestion capabilities.

🔒 **Happy coding, and stay secure with Coach!** 🚀

