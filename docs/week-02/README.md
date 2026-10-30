# WEEK 02: An input-handling kit

**Course:** CSSS 441 Software Security I  
**Project:** Project 7 — Private PKI and Certificate Lifecycle Manager  
**Group:** Group 7  
**Status:** ✅ Completed  

---

## 🎯 Goal
Build the validation and data-access layer the project will reuse.

## 📦 Expected Submission Deliverables
* **Submission Requirements:** The module, the tests and the Semgrep output.
* **Done Condition:** Done when all tests pass and Semgrep reports nothing.

---

## 📁 Week 2 Associated Implementation & Tests
* **Validation Schemas:** `src/pki_lifecycle/validation/schemas.py` (Pydantic request schemas)
* **Parameterized Data Access:** `src/pki_lifecycle/database/repository.py`
* **Auto-Escaping Templates:** `src/pki_lifecycle/rendering/templates.py`
* **OWASP Unit Tests:** `tests/test_validation_negative.py` (20 negative test cases)
* **Static Analysis:** `.semgrep.yml`
