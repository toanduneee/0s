#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
App Transport Security (ATS) Configuration Auditor for iOS
Author: Senior iOS Security Engineer
Description: Analyzes iOS Info.plist files (XML and Binary Plist) to evaluate ATS configurations,
             detect security exceptions, assign risk levels, and provide remediation guidance.
"""

import os
import sys
import plistlib

# Ensure UTF-8 output encoding across Windows terminals
if sys.stdout.encoding != "utf-8" and hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if sys.stderr.encoding != "utf-8" and hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

from typing import Dict, Any, List

VERBATIM_WARNING = (
    "CẢNH BÁO: Tệp cấu hình không có ngoại lệ ATS KHÔNG đồng nghĩa ứng dụng an toàn trên thực tế. "
    "Cần kết hợp phân tích lưu lượng mạng động (Runtime Traffic) để phát hiện socket cấp thấp "
    "hoặc thư viện bên thứ ba bỏ qua ATS."
)

# Thang điểm phân cấp độ ưu tiên mức độ rủi ro
RISK_ORDER = {
    "CRITICAL": 4,
    "HIGH": 3,
    "MEDIUM": 2,
    "LOW / SAFE": 1,
    "ERROR / CORRUPT": 0
}

WEAK_TLS_VERSIONS = {"TLSv1.0", "TLSv1.1", "1.0", "1.1"}


class ATSAuditor:
    """Bộ kiểm tra và phân tích cấu hình App Transport Security (ATS) chuyên sâu."""

    @staticmethod
    def audit_file(file_path: str) -> Dict[str, Any]:
        """
        Đọc và phân tích tệp Info.plist (hỗ trợ cả XML và Binary Plist).
        Xử lý an toàn các ngoại lệ hỏng tệp hoặc lỗi đọc/ghi.
        """
        result: Dict[str, Any] = {
            "file_path": file_path,
            "file_name": os.path.basename(file_path),
            "risk_level": "LOW / SAFE",
            "findings": [],
            "ats_present": False,
            "raw_ats": None,
            "error": None
        }

        # 1. Đọc và parse tệp plist với cơ chế bảo vệ ngoại lệ
        try:
            with open(file_path, "rb") as fp:
                # plistlib.load hỗ trợ tự động cả XML plist và Binary plist (bplist00)
                plist_data = plistlib.load(fp)
        except (plistlib.InvalidFileException, ValueError, Exception) as err:
            # Bắt cả ExpatError và InvalidFileException khi XML/bplist hỏng
            error_cls = err.__class__.__name__
            if isinstance(err, (OSError, IOError)) and not isinstance(err, plistlib.InvalidFileException):
                result["risk_level"] = "ERROR / CORRUPT"
                result["error"] = f"Lỗi truy cập tệp tin (I/O Error): {err}"
                result["findings"].append({
                    "severity": "ERROR / CORRUPT",
                    "title": "Lỗi truy cập tệp tin (I/O Error)",
                    "detail": str(err),
                    "remediation": "Kiểm tra đường dẫn và quyền đọc tập tin."
                })
                return result

            result["risk_level"] = "ERROR / CORRUPT"
            result["error"] = f"Tệp Plist hỏng hoặc cú pháp XML/Binary không hợp lệ ({error_cls}): {err}"
            result["findings"].append({
                "severity": "ERROR / CORRUPT",
                "title": f"Tệp Plist hỏng / Lỗi phân tích cú pháp ({error_cls})",
                "detail": str(err),
                "remediation": "Khôi phục tệp Info.plist từ định dạng XML/Binary chuẩn bằng plutil hoặc Xcode."
            })
            return result

        if not isinstance(plist_data, dict):
            result["risk_level"] = "ERROR / CORRUPT"
            result["error"] = "Dữ liệu plist gốc không phải là dictionary hợp lệ."
            return result

        # 2. Kiểm tra sự tồn tại của NSAppTransportSecurity
        ats_config = plist_data.get("NSAppTransportSecurity")
        if ats_config is None:
            result["ats_present"] = False
            result["risk_level"] = "LOW / SAFE"
            result["findings"].append({
                "severity": "LOW / SAFE",
                "title": "Không khai báo NSAppTransportSecurity",
                "detail": "Hệ điều hành iOS mặc định kích hoạt toàn bộ cơ chế bảo vệ ATS nghiêm ngặt (chỉ cho phép HTTPS, TLS 1.2+, Forward Secrecy).",
                "remediation": "Duy trì cấu hình mặc định này nếu không có nhu cầu bắt buộc về ngoại lệ."
            })
            return result

        if not isinstance(ats_config, dict):
            result["risk_level"] = "ERROR / CORRUPT"
            result["error"] = "Khoá NSAppTransportSecurity tồn tại nhưng không chứa dictionary."
            return result

        result["ats_present"] = True
        result["raw_ats"] = ats_config
        findings: List[Dict[str, Any]] = []

        # 3. Phân tích các cờ toàn cục (Global Flags)
        # 3.1. NSAllowsArbitraryLoads
        allows_arbitrary = ats_config.get("NSAllowsArbitraryLoads", False)
        if allows_arbitrary is True:
            findings.append({
                "severity": "CRITICAL",
                "title": "Vô hiệu hóa ATS toàn cục (NSAllowsArbitraryLoads = true)",
                "detail": "Toàn bộ lưu lượng mạng trong ứng dụng có thể truyền tải qua HTTP không mã hóa (Cleartext), đối mặt nguy cơ Man-in-the-Middle (MitM) và đánh cắp dữ liệu.",
                "remediation": "Loại bỏ hoàn toàn NSAllowsArbitraryLoads hoặc đổi thành false. Sử dụng kết nối HTTPS tiêu chuẩn với chứng chỉ số hợp lệ."
            })

        # 3.2. NSAllowsArbitraryLoadsInWebContent
        if ats_config.get("NSAllowsArbitraryLoadsInWebContent", False) is True:
            findings.append({
                "severity": "MEDIUM",
                "title": "Cho phép tải HTTP không an toàn trong Web View (NSAllowsArbitraryLoadsInWebContent = true)",
                "detail": "Các thành phần WKWebView trong ứng dụng có thể tải nội dung trang web qua HTTP thông thường.",
                "remediation": "Chỉ tải các tài nguyên Web bảo mật qua HTTPS. Sử dụng CSP (Content Security Policy) trên máy chủ web."
            })

        # 3.3. NSAllowsArbitraryLoadsForMedia
        if ats_config.get("NSAllowsArbitraryLoadsForMedia", False) is True:
            findings.append({
                "severity": "MEDIUM",
                "title": "Cho phép tải nội dung Media không mã hóa (NSAllowsArbitraryLoadsForMedia = true)",
                "detail": "Ứng dụng cho phép tải video/audio thông qua giao thức HTTP không an toàn bằng AVFoundation.",
                "remediation": "Nâng cấp máy chủ phân phối nội dung (CDN) để phục vụ media qua giao thức HTTPS."
            })

        # 3.4. NSAllowsLocalNetworking
        if ats_config.get("NSAllowsLocalNetworking", False) is True:
            findings.append({
                "severity": "MEDIUM",
                "title": "Cho phép kết nối mạng cục bộ không an toàn (NSAllowsLocalNetworking = true)",
                "detail": "Cho phép kết nối HTTP tới các thiết bị hoặc địa chỉ IP cục bộ (LAN/Localhost).",
                "remediation": "Đảm bảo cờ này chỉ dùng cho mục đích kết nối thiết bị IoT nội bộ hoặc môi trường phát triển (Debug)."
            })

        # 4. Phân tích các ngoại lệ từng tên miền (NSExceptionDomains)
        exception_domains = ats_config.get("NSExceptionDomains", {})
        if isinstance(exception_domains, dict):
            for domain, rules in exception_domains.items():
                if not isinstance(rules, dict):
                    continue

                includes_subdomains = rules.get("NSIncludesSubdomains", False)
                allows_insecure_http = rules.get("NSExceptionAllowsInsecureHTTPLoads", False)
                min_tls_version = rules.get("NSExceptionMinimumTLSVersion", None)
                requires_forward_secrecy = rules.get("NSExceptionRequiresForwardSecrecy", True)

                # Trường hợp: Wildcard subdomain + HTTP không an toàn
                if allows_insecure_http and includes_subdomains:
                    findings.append({
                        "severity": "HIGH",
                        "title": f"Bật HTTP không mã hóa trên toàn bộ Subdomain (*.{domain})",
                        "detail": f"Domain '{domain}' bật đồng thời NSIncludesSubdomains = true và NSExceptionAllowsInsecureHTTPLoads = true, mở rộng bề mặt tấn công sang mọi subdomains.",
                        "remediation": f"Tắt NSIncludesSubdomains cho '{domain}', chuyển sang HTTPS hoặc chỉ định đích danh từng subdomain thực sự cần thiết."
                    })
                elif allows_insecure_http:
                    findings.append({
                        "severity": "MEDIUM",
                        "title": f"Cho phép HTTP không mã hóa trên domain '{domain}'",
                        "detail": f"Domain '{domain}' được cấp phép truyền tải dữ liệu qua HTTP không an toàn.",
                        "remediation": f"Cấu hình chứng chỉ TLS trên máy chủ '{domain}' và loại bỏ ngoại lệ NSExceptionAllowsInsecureHTTPLoads."
                    })

                # Trường hợp: Phiên bản TLS yếu
                if min_tls_version in WEAK_TLS_VERSIONS:
                    findings.append({
                        "severity": "HIGH",
                        "title": f"Hạ cấp phiên bản TLS xuống mức yếu ({min_tls_version}) tại domain '{domain}'",
                        "detail": f"Giao thức {min_tls_version} chứa nhiều lỗ hổng mật mã đã bị khai tử (POODLE, BEAST). Tiêu chuẩn Apple yêu cầu tối thiểu TLSv1.2 hoặc TLSv1.3.",
                        "remediation": f"Nâng cấp máy chủ '{domain}' hỗ trợ tối thiểu TLSv1.2 hoặc TLSv1.3 và cập nhật NSExceptionMinimumTLSVersion."
                    })

                # Trường hợp: Tắt Forward Secrecy
                if requires_forward_secrecy is False:
                    findings.append({
                        "severity": "MEDIUM",
                        "title": f"Tắt cơ chế Forward Secrecy (PFS) tại domain '{domain}'",
                        "detail": f"Domain '{domain}' tắt NSExceptionRequiresForwardSecrecy = false, cho phép các bộ mật mã (cipher suites) không hỗ trợ PFS. Nếu khoá riêng máy chủ bị lộ, toàn bộ dữ liệu ghi lại trong quá khứ có thể bị giải mã.",
                        "remediation": f"Bật NSExceptionRequiresForwardSecrecy = true và kích hoạt ECDHE trên máy chủ '{domain}'."
                    })

        # 5. Tổng hợp và đánh giá mức độ rủi ro chung (Risk Aggregation)
        if not findings:
            result["risk_level"] = "LOW / SAFE"
            result["findings"].append({
                "severity": "LOW / SAFE",
                "title": "Cấu hình ATS tuân thủ chuẩn an toàn",
                "detail": "Không phát hiện ngoại lệ an ninh mạng nguy hiểm nào trong tệp cấu hình.",
                "remediation": "Không cần can thiệp cấu hình tĩnh."
            })
        else:
            # Xác định mức độ cao nhất trong các findings
            highest_risk = "LOW / SAFE"
            for f in findings:
                sev = f["severity"]
                if RISK_ORDER.get(sev, 0) > RISK_ORDER.get(highest_risk, 0):
                    highest_risk = sev
            result["risk_level"] = highest_risk
            result["findings"] = findings

        return result


def print_single_report(result: Dict[str, Any]) -> None:
    """In báo cáo phân tích chi tiết cho một tệp plist đơn lẻ."""
    print("=" * 80)
    print(f"BÁO CÁO KIỂM TRA ATS: {result['file_name']}")
    print(f"Đường dẫn: {result['file_path']}")
    print(f"Mức độ rủi ro: [{result['risk_level']}]")
    print("-" * 80)
    print(f"{VERBATIM_WARNING}\n")
    print("-" * 80)

    if result.get("error"):
        print(f"[!] LỖI PHÂN TÍCH: {result['error']}\n")
        return

    print("DANH SÁCH PHÁT HIỆN:")
    for idx, finding in enumerate(result["findings"], 1):
        print(f"  {idx}. [{finding['severity']}] {finding['title']}")
        print(f"     - Chi tiết: {finding['detail']}")
        print(f"     - Khắc phục: {finding['remediation']}")
        print()
    print("=" * 80)


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Sử dụng: python ats_auditor.py <duong_dan_tep_plist>")
        sys.exit(1)

    target_plist = sys.argv[1]
    audit_res = ATSAuditor.audit_file(target_plist)
    print_single_report(audit_res)
