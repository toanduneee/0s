#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Automated Test Runner & Comparison Engine for ATS Configuration Auditor
Author: Senior iOS Security Engineer
Description: Executes batch audits against test samples and remediated samples,
             verifies accuracy against ground_truth.json, and outputs structured
             Markdown and CLI comparison tables.
"""

import os
import sys
import json

# Ensure UTF-8 output encoding across Windows terminals
if sys.stdout.encoding != "utf-8" and hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if sys.stderr.encoding != "utf-8" and hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

from typing import Dict, Any, List
from ats_auditor import ATSAuditor, VERBATIM_WARNING


def load_ground_truth(gt_path: str) -> Dict[str, Any]:
    """Tải dữ liệu đáp án chuẩn (Ground Truth)."""
    with open(gt_path, "r", encoding="utf-8") as f:
        return json.load(f)


def run_baseline_audit(base_dir: str, ground_truth: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Quét toàn bộ 8 tệp kiểm thử gốc và đối chiếu với Ground Truth."""
    results = []
    for rel_path, expected_info in ground_truth.items():
        full_path = os.path.join(base_dir, rel_path)
        audit_res = ATSAuditor.audit_file(full_path)
        
        actual_risk = audit_res["risk_level"]
        expected_risk = expected_info["expected_risk"]
        is_match = (actual_risk == expected_risk)
        
        # Lấy tóm tắt lý do phát hiện
        if audit_res.get("findings"):
            reasons = "; ".join([f["title"] for f in audit_res["findings"]])
        elif audit_res.get("error"):
            reasons = audit_res["error"]
        else:
            reasons = "Không có cảnh báo"

        results.append({
            "rel_path": rel_path,
            "file_name": os.path.basename(full_path),
            "expected_risk": expected_risk,
            "actual_risk": actual_risk,
            "status": "MATCH" if is_match else "MISMATCH",
            "findings_summary": reasons,
            "audit_res": audit_res
        })
    return results


def run_remediation_comparison(base_dir: str) -> List[Dict[str, Any]]:
    """Quét các cặp tệp trước và sau khi khắc phục để đo lường hiệu quả giảm thiểu rủi ro."""
    pairs = [
        ("samples/sample2_global_bypass.plist", "remediated_samples/sample2_fixed.plist", "sample2"),
        ("samples/sample4_weak_tls.plist", "remediated_samples/sample4_fixed.plist", "sample4"),
        ("samples/sample7_wildcard_domain.plist", "remediated_samples/sample7_fixed.plist", "sample7")
    ]

    remediation_results = []
    for before_rel, after_rel, label in pairs:
        before_path = os.path.join(base_dir, before_rel)
        after_path = os.path.join(base_dir, after_rel)

        before_audit = ATSAuditor.audit_file(before_path)
        after_audit = ATSAuditor.audit_file(after_path)

        before_summary = "; ".join([f["title"] for f in before_audit["findings"]]) if before_audit["findings"] else "N/A"
        after_summary = "; ".join([f["title"] for f in after_audit["findings"]]) if after_audit["findings"] else "N/A"

        remediation_results.append({
            "label": label,
            "before_file": os.path.basename(before_path),
            "before_risk": before_audit["risk_level"],
            "before_summary": before_summary,
            "after_file": os.path.basename(after_path),
            "after_risk": after_audit["risk_level"],
            "after_summary": after_summary,
            "status": "REMEDIATED (SECURED)" if after_audit["risk_level"] in ("LOW / SAFE") else "PARTIALLY REMEDIATED"
        })
    return remediation_results


def print_markdown_reports(baseline_results: List[Dict[str, Any]], remediation_results: List[Dict[str, Any]]) -> None:
    """Xuất báo cáo dưới định dạng Markdown chuẩn cho báo cáo nghiệm thu."""
    total_tests = len(baseline_results)
    matched_tests = sum(1 for r in baseline_results if r["status"] == "MATCH")
    accuracy = (matched_tests / total_tests) * 100

    print("\n" + "=" * 90)
    print("### BÁO CÁO KẾT QUẢ NGHIỆM THU KIỂM TRA CẤU HÌNH ATS (APP TRANSPORT SECURITY)")
    print("=" * 90)
    print(f"\n> **{VERBATIM_WARNING}**\n")

    print("#### 1. BẢNG SO SÁNH KẾT QUẢ QUÉT VÀ GROUND TRUTH (ĐỘ CHÍNH XÁC: {:.1f}%)".format(accuracy))
    print("| STT | Tên Tệp Plist | Kỳ Vọng (Ground Truth) | Thực Tế (Auditor) | Trạng Thái | Lý Do / Phát Hiện Chính |")
    print("|---|---|---|---|---|---|")
    for idx, r in enumerate(baseline_results, 1):
        status_badge = "[OK] MATCH" if r["status"] == "MATCH" else "[X] MISMATCH"
        print(f"| {idx} | `{r['file_name']}` | **{r['expected_risk']}** | **{r['actual_risk']}** | `{status_badge}` | {r['findings_summary']} |")

    print("\n#### 2. BẢNG SO SÁNH ĐỐI CHỨNG TRƯỚC VÀ SAU KHI SỬA LỖI (REMEDIATION)")
    print("| STT | Mục Kiểm Thử | Tệp Gốc | Rủi Ro Ban Đầu | Tệp Đã Khắc Phục | Rủi Ro Sau Sửa | Đánh Giá Khắc Phục |")
    print("|---|---|---|---|---|---|---|")
    for idx, rem in enumerate(remediation_results, 1):
        print(f"| {idx} | `{rem['label']}` | `{rem['before_file']}` | **{rem['before_risk']}** | `{rem['after_file']}` | **{rem['after_risk']}** | `{rem['status']}` |")

    print("\n" + "=" * 90)


def main():
    base_dir = os.path.dirname(os.path.abspath(__file__))
    gt_file = os.path.join(base_dir, "ground_truth.json")

    if not os.path.exists(gt_file):
        print(f"[!] Không tìm thấy tệp {gt_file}")
        sys.exit(1)

    ground_truth = load_ground_truth(gt_file)
    baseline_results = run_baseline_audit(base_dir, ground_truth)
    remediation_results = run_remediation_comparison(base_dir)

    print_markdown_reports(baseline_results, remediation_results)


if __name__ == "__main__":
    main()
