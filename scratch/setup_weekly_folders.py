import os
import shutil

base_dir = "docs"

weeks_data = [
    {
        "folder": "week-01",
        "title": "Threat-model your project",
        "goal": "Turn the chosen project into a first threat model.",
        "submit": "The Threat Dragon JSON file and a one-page summary.",
        "condition": "Done when every data flow that crosses a boundary has at least one threat recorded against it.",
        "status": "Completed"
    },
    {
        "folder": "week-02",
        "title": "An input-handling kit",
        "goal": "Build the validation and data-access layer the project will reuse.",
        "submit": "The module, the tests and the Semgrep output.",
        "condition": "Done when all tests pass and Semgrep reports nothing.",
        "status": "Completed"
    },
    {
        "folder": "week-03",
        "title": "Sanitizer drill",
        "goal": "Make memory errors loud, then remove them.",
        "submit": "The diffs, the clean build log and the test output.",
        "condition": "Done when the builds are warning-free and the sanitizers stay silent on every test.",
        "status": "Upcoming"
    },
    {
        "folder": "week-04",
        "title": "An authentication module",
        "goal": "Build login the project can drop in.",
        "submit": "The module and the test report.",
        "condition": "Done when the tests prove throttling, cookie flags and session rotation.",
        "status": "Upcoming"
    },
    {
        "folder": "week-05",
        "title": "A file-encryption utility",
        "goal": "Encrypt data correctly with a vetted library.",
        "submit": "The tool, its tests and a short note on nonce handling.",
        "condition": "Done when the tamper test fails closed and Bandit reports no cryptography findings.",
        "status": "Upcoming"
    },
    {
        "folder": "week-06",
        "title": "An integrity toolkit",
        "goal": "Detect changes and prove who released a file.",
        "submit": "The tool, a sample report and the verifier tests.",
        "condition": "Done when every tampering case is detected and the verifier fails closed.",
        "status": "Upcoming"
    },
    {
        "folder": "week-07",
        "title": "TLS and SSH hardening",
        "goal": "Serve the project over correctly configured TLS and lock down its host.",
        "submit": "The configurations and before-and-after scan reports.",
        "condition": "Done when testssl.sh and ssh-audit show no high findings.",
        "status": "Upcoming"
    },
    {
        "folder": "week-08",
        "title": "Firewall and detection",
        "goal": "Allow only what the project needs, and see when something else happens.",
        "submit": "The ruleset, the policy and alert screenshots.",
        "condition": "Done when each rule fires on its test and stays quiet on the baseline.",
        "status": "Upcoming"
    },
    {
        "folder": "week-09",
        "title": "VPN and dependency hygiene",
        "goal": "Protect administrator traffic and clean up the project's dependencies.",
        "submit": "The WireGuard configuration with keys removed, both captures, the SBOM and the scan before and after.",
        "condition": "Done when the tunnel works and no unexplained critical findings remain.",
        "status": "Upcoming"
    },
    {
        "folder": "week-10",
        "title": "Peer security review",
        "goal": "Practise finding and reporting issues the way industry teams do.",
        "submit": "The findings and the response.",
        "condition": "Done when every finding has an agreed status: fixed, accepted risk or disputed with reasons.",
        "status": "Upcoming"
    }
]

for w in weeks_data:
    folder_path = os.path.join(base_dir, w["folder"])
    os.makedirs(folder_path, exist_ok=True)
    
    readme_path = os.path.join(folder_path, "README.md")
    content = f"""# {w['folder'].upper().replace('-', ' ')}: {w['title']}

**Course:** CSSS 441 Software Security I  
**Project:** Project 7 — Private PKI and Certificate Lifecycle Manager  
**Group:** Group 7  
**Status:** {'✅ ' + w['status'] if w['status'] == 'Completed' else '⏳ ' + w['status']}  

---

## 🎯 Goal
{w['goal']}

## 📦 Expected Submission Deliverables
* **Submission Requirements:** {w['submit']}
* **Done Condition:** {w['condition']}

---

"""
    if w["folder"] == "week-01":
        content += """## 📁 Week 1 Included Deliverables

This folder contains the complete, verified submission deliverables for Week 1:

1. **`threat-model.json`**: Official OWASP Threat Dragon v2 model file containing the Level-1 Data Flow Diagram, 3 trust boundaries, 8 components, 7 data flows, and 17 STRIDE threats.
2. **`Threat_Model_Summary_Group7.docx`**: Minimalist, clean academic Word document formatted as a one-page submission deliverable.
3. **`summary.md`**: Markdown companion summary documenting the threat model, STRIDE risk ratings, chosen controls, and boundary flow verification table.
"""
    elif w["folder"] == "week-02":
        content += """## 📁 Week 2 Associated Implementation & Tests
* **Validation Schemas:** `src/pki_lifecycle/validation/schemas.py` (Pydantic request schemas)
* **Parameterized Data Access:** `src/pki_lifecycle/database/repository.py`
* **Auto-Escaping Templates:** `src/pki_lifecycle/rendering/templates.py`
* **OWASP Unit Tests:** `tests/test_validation_negative.py` (20 negative test cases)
* **Static Analysis:** `.semgrep.yml`
"""
    else:
        content += f"""## 📁 Deliverables Checklist
- [ ] Implement {w['title']}
- [ ] Prepare {w['submit']}
- [ ] Verify pass condition: {w['condition']}
"""
    
    with open(readme_path, "w", encoding="utf-8") as f:
        f.write(content)

# Copy Week 1 deliverables into docs/week-01
w1_src = os.path.join("docs", "threat-model")
w1_dest = os.path.join("docs", "week-01")

shutil.copy2(os.path.join(w1_src, "threat-model.json"), os.path.join(w1_dest, "threat-model.json"))
shutil.copy2(os.path.join(w1_src, "Threat_Model_Summary_Group7.docx"), os.path.join(w1_dest, "Threat_Model_Summary_Group7.docx"))
shutil.copy2(os.path.join(w1_src, "summary.md"), os.path.join(w1_dest, "summary.md"))

print("All 10 weekly exercise folders created and Week 1 deliverables populated successfully!")

