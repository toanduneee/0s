# BỘ KIỂM TRA & ĐÁNH GIÁ CẤU HÌNH APP TRANSPORT SECURITY (ATS) TRÊN IOS

Dự án thực nghiệm an toàn thông tin chuyên sâu dành cho nền tảng iOS, cung cấp công cụ tự động phân tích tĩnh (Static Analysis) cấu hình **App Transport Security (ATS)** từ tệp `Info.plist`. Toàn bộ giải pháp được xây dựng bằng **Python thuần (chỉ dùng thư viện chuẩn `plistlib`)**, không phụ thuộc thư viện ngoài, hỗ trợ cả định dạng **XML Plist** và **Binary Plist (`bplist00`)**, xử lý an toàn các tệp hỏng hóc và cung cấp các khuyến nghị khắc phục (Remediation) chuẩn theo hướng dẫn của Apple.

---

> [!WARNING]
> **CẢNH BÁO NGUYÊN VĂN BẮT BUỘC TRONG TẤT CẢ BÁO CÁO:**  
> *"CẢNH BÁO: Tệp cấu hình không có ngoại lệ ATS KHÔNG đồng nghĩa ứng dụng an toàn trên thực tế. Cần kết hợp phân tích lưu lượng mạng động (Runtime Traffic) để phát hiện socket cấp thấp hoặc thư viện bên thứ ba bỏ qua ATS."*

---

## 1. TỔNG QUAN VỀ CƠ CHẾ APP TRANSPORT SECURITY (ATS)

Kể từ phiên bản **iOS 9.0+**, Apple đưa ra chuẩn bảo mật mạng **App Transport Security (ATS)** bắt buộc nhằm ép buộc các ứng dụng di động phải kết nối qua giao thức an toàn. 

### Các tiêu chuẩn mặc định của ATS khi không có ngoại lệ:
1. **Giao thức bắt buộc:** Chỉ cho phép **HTTPS** (kết nối HTTP Cleartext bị hệ điều hành chặn ở tầng network framework).
2. **Phiên bản TLS tối thiểu:** **TLSv1.2** trở lên (khuyến nghị **TLSv1.3**).
3. **Mã hóa chuyển tiếp bảo mật (Perfect Forward Secrecy - PFS):** Bắt buộc các bộ mã hóa (cipher suites) sử dụng trao đổi khóa tạm thời (`ECDHE_RSA` hoặc `ECDHE_ECDSA`).
4. **Chứng chỉ số (X.509):** Khóa RSA tối thiểu $2048$-bit hoặc ECC tối thiểu $256$-bit; hàm băm chữ ký số tối thiểu từ SHA-256 trở lên.

Khi nhà phát triển cấu hình các khoá ngoại lệ trong từ điển `NSAppTransportSecurity`, các rào chắn bảo mật này có thể bị vô hiệu hóa hoặc suy giảm nghiêm trọng.

---

## 2. MA TRẬN ĐÁNH GIÁ MỨC ĐỘ RỦI RO (RISK MATRIX)

Bộ engine phân tích [ats_auditor.py](file:///d:/Workspace/report/ATMKD&DV/ats_auditor.py) phân loại mức độ nghiêm trọng theo 5 cấp độ:

| Mức Độ Rủi Ro | Dấu Hiệu Nhận Biết Trong `NSAppTransportSecurity` | Nguy Cơ An Ninh Mạng Thực Tế | Khuyến Nghị Xử Lý |
|---|---|---|---|
| **CRITICAL** | `NSAllowsArbitraryLoads = true` | Toàn bộ lưu lượng mạng của app có thể đi qua HTTP không mã hóa; đối mặt nguy cơ nghe lén, Man-in-the-Middle (MitM) và bị Apple từ chối duyệt ứng dụng (App Store Rejection). | Bỏ hoàn toàn cờ này hoặc đặt thành `false`. Chỉ dùng HTTPS chuẩn. |
| **HIGH** | `NSIncludesSubdomains = true` kết hợp `NSExceptionAllowsInsecureHTTPLoads = true` trên domain | Cho phép HTTP không mã hóa trên toàn bộ tên miền con (`*.example.com`). Khi một subdomain nội bộ hoặc dịch vụ bên thứ ba bị tổn thương, toàn bộ app sẽ bị ảnh hưởng. | Bỏ `NSIncludesSubdomains`, ép buộc HTTPS hoặc chỉ định đích danh đúng 1 FQDN cần thiết. |
| **HIGH** | `NSExceptionMinimumTLSVersion` = `TLSv1.0` hoặc `TLSv1.1` | Chấp nhận giao thức mật mã lỗi thời đã bị khai tử, dễ tổn thương trước các cuộc tấn công BEAST, POODLE, CRIME. | Nâng cấp máy chủ hỗ trợ TLS 1.2 / TLS 1.3 và cập nhật cấu hình plist. |
| **MEDIUM** | `NSExceptionAllowsInsecureHTTPLoads = true` (không dùng wildcard) | Cho phép HTTP không mã hóa trên một tên miền cụ thể xác định. Dữ liệu trao đổi với host này không được bảo vệ. | Cấu hình chứng chỉ TLS trên máy chủ đích và loại bỏ ngoại lệ. |
| **MEDIUM** | `NSExceptionRequiresForwardSecrecy = false` | Cho phép cipher suite không hỗ trợ PFS. Nếu khóa riêng của server bị lộ, toàn bộ dữ liệu ghi lại trong quá khứ có thể bị giải mã hồi tố. | Kích hoạt bộ mã hóa ECDHE trên máy chủ và đặt cờ này thành `true`. |
| **MEDIUM** | `NSAllowsArbitraryLoadsInWebContent = true` / `NSAllowsArbitraryLoadsForMedia = true` | Cho phép `WKWebView` hoặc `AVPlayer` tải nội dung web / video qua giao thức HTTP không an toàn. | Nâng cấp Web/CDN sang HTTPS; triển khai chính sách CSP (Content Security Policy). |
| **LOW / SAFE** | Không khai báo `NSAppTransportSecurity` hoặc cấu hình tuân thủ tuyệt đối chuẩn an toàn | Hệ điều hành kích hoạt bảo vệ ATS toàn diện. | Duy trì cấu hình mặc định này. |
| **ERROR / CORRUPT** | Tệp bị cắt cụt, sai cú pháp XML/Binary Plist, lỗi I/O | Tệp Info.plist hỏng, có thể khiến Xcode không build được hoặc app bị crash khi khởi động. | Dùng công cụ `plutil` hoặc Xcode để khôi phục cấu trúc chuẩn. |

---

## 3. CẤU TRÚC THƯ MỤC VÀ TỆP TIN DỰ ÁN

```text
d:\Workspace\report\ATMKD&DV\
├── samples/                                  # Thư mục chứa 8 tệp kiểm thử tình huống thực tế
│   ├── sample1_default.plist                 # Mặc định, không khai báo ATS (Hệ điều hành ép HTTPS)
│   ├── sample2_global_bypass.plist           # NSAllowsArbitraryLoads = true (Vô hiệu hóa toàn cục)
│   ├── sample3_domain_http.plist             # NSExceptionAllowsInsecureHTTPLoads = true cho 1 domain
│   ├── sample4_weak_tls.plist                # Hạ cấp TLS 1.0, tắt Forward Secrecy
│   ├── sample5_web_media.plist               # Arbitrary loads cho WebContent và Media streaming
│   ├── sample6_combination.plist             # Kết hợp Global bypass cùng Domain rule
│   ├── sample7_wildcard_domain.plist         # Wildcard Subdomain (*.domain) cho phép HTTP
│   └── sample8_corrupted.plist               # Tệp XML bị cắt cụt / hỏng để kiểm tra Exception
├── remediated_samples/                       # Thư mục chứa các tệp đã được khắc phục bảo mật
│   ├── sample2_fixed.plist                   # Bản khắc phục của sample 2 (Loại bỏ global bypass)
│   ├── sample4_fixed.plist                   # Bản khắc phục của sample 4 (Nâng TLS 1.3, bật PFS)
│   └── sample7_fixed.plist                   # Bản khắc phục của sample 7 (Bỏ wildcard, ép HTTPS)
├── ground_truth.json                         # Bộ đáp án chuẩn kỳ vọng lập trước khi chạy kiểm thử
├── ats_auditor.py                            # Engine phân tích tĩnh ATS & đánh giá rủi ro
├── run_audit.py                              # Script runner tự động quét, so sánh và xuất bảng
└── README.md                                 # Tài liệu kỹ thuật chi tiết của dự án
```

---

## 4. CÁC NGUYÊN TẮC KỸ THUẬT & KIẾN TRÚC PHẦN MỀM

### 4.1. Không phụ thuộc thư viện ngoài (Zero External Dependencies)
Chương trình sử dụng hoàn toàn các thư viện chuẩn tích hợp sẵn trong Python:
- `plistlib`: Đọc, ghi và parse dữ liệu Plist. `plistlib.load()` trong Python 3 tự động nhận biết và parse trong suốt cả định dạng **XML Plist** và **Binary Plist (`bplist00`)** mà không cần tham số phụ.
- `os`, `sys`: Quản lý đường dẫn tập tin và mã hóa xuất nhập terminal.
- `json`: Đọc bộ dữ liệu [ground_truth.json](file:///d:/Workspace/report/ATMKD&DV/ground_truth.json).

### 4.2. Khả năng chống sập ứng dụng (Robust Exception Handling)
Khi phân tích các tệp plist trong thực tế từ các gói `.ipa` trôi nổi, tệp `Info.plist` có thể bị hỏng cấu trúc, cắt cụt hoặc mã hóa dị dạng. [ats_auditor.py](file:///d:/Workspace/report/ATMKD&DV/ats_auditor.py) cài đặt bộ bọc `try-except` đa lớp:
- Bắt `plistlib.InvalidFileException` và `xml.parsers.expat.ExpatError` khi cú pháp XML bị lỗi (được kiểm chứng qua tệp [`sample8_corrupted.plist`](file:///d:/Workspace/report/ATMKD&DV/samples/sample8_corrupted.plist)).
- Bắt `OSError` / `IOError` khi gặp vấn đề phân quyền hoặc tệp không tồn tại.
- Phân loại lỗi thành trạng thái **`ERROR / CORRUPT`** một cách có kiểm soát thay vì để lộ traceback ra ngoài màn hình.

### 4.3. Hỗ trợ hiển thị UTF-8 trên Windows
Script chủ động tự động phát hiện và reconfigure luồng xuất dữ liệu (`sys.stdout`, `sys.stderr`) sang `utf-8` để tránh lỗi mã hóa ký tự tiếng Việt (`charmap` / `cp1252`) trên PowerShell / Command Prompt.

---

## 5. HƯỚNG DẪN CÀI ĐẶT VÀ SỬ DỤNG

### Yêu cầu môi trường
- Python 3.8 trở lên (đã được kiểm thử hoàn hảo trên Python 3.12).
- Không cần cài thêm bất kỳ gói `pip` nào.

### 5.1. Chạy kiểm thử tự động toàn diện (Automated Runner)
Lệnh này quét toàn bộ 8 tệp gốc, đối chiếu với đáp án chuẩn trong `ground_truth.json`, quét 3 tệp đã khắc phục và in ra bảng tổng kết Markdown:

```powershell
python run_audit.py
```

### 5.2. Quét một tệp Plist đơn lẻ
Bạn có thể sử dụng công cụ như một tiện ích dòng lệnh độc lập để phân tích bất kỳ tệp `Info.plist` nào của ứng dụng:

```powershell
# Quét tệp có rủi ro nghiêm trọng
python ats_auditor.py samples/sample2_global_bypass.plist

# Quét tệp sử dụng TLS yếu
python ats_auditor.py samples/sample4_weak_tls.plist

# Quét tệp hỏng cú pháp (kiểm tra chống crash)
python ats_auditor.py samples/sample8_corrupted.plist
```

---

## 6. KẾT QUẢ NGHIỆM THU THỰC NGHIỆM

Dưới đây là kết quả thực tế thu được từ engine kiểm thử tự động:

### 6.1. Bảng so sánh kết quả quét và Ground Truth (Độ chính xác: 100%)

| STT | Tên Tệp Plist | Kỳ Vọng (Ground Truth) | Thực Tế (Auditor) | Trạng Thái | Lý Do / Phát Hiện Chính |
|:---:|---|:---:|:---:|:---:|---|
| 1 | [`sample1_default.plist`](file:///d:/Workspace/report/ATMKD&DV/samples/sample1_default.plist) | **LOW / SAFE** | **LOW / SAFE** | `[OK] MATCH` | Không khai báo NSAppTransportSecurity (Hệ điều hành mặc định bảo vệ tối đa) |
| 2 | [`sample2_global_bypass.plist`](file:///d:/Workspace/report/ATMKD&DV/samples/sample2_global_bypass.plist) | **CRITICAL** | **CRITICAL** | `[OK] MATCH` | Vô hiệu hóa ATS toàn cục (NSAllowsArbitraryLoads = true) |
| 3 | [`sample3_domain_http.plist`](file:///d:/Workspace/report/ATMKD&DV/samples/sample3_domain_http.plist) | **MEDIUM** | **MEDIUM** | `[OK] MATCH` | Cho phép HTTP không mã hóa trên domain 'api.legacy-internal.com' |
| 4 | [`sample4_weak_tls.plist`](file:///d:/Workspace/report/ATMKD&DV/samples/sample4_weak_tls.plist) | **HIGH** | **HIGH** | `[OK] MATCH` | Hạ cấp phiên bản TLS xuống mức yếu (TLSv1.0); Tắt cơ chế Forward Secrecy (PFS) |
| 5 | [`sample5_web_media.plist`](file:///d:/Workspace/report/ATMKD&DV/samples/sample5_web_media.plist) | **MEDIUM** | **MEDIUM** | `[OK] MATCH` | Cho phép tải HTTP không an toàn trong Web View và nội dung Media không mã hóa |
| 6 | [`sample6_combination.plist`](file:///d:/Workspace/report/ATMKD&DV/samples/sample6_combination.plist) | **CRITICAL** | **CRITICAL** | `[OK] MATCH` | Vô hiệu hóa ATS toàn cục (NSAllowsArbitraryLoads = true) kết hợp ngoại lệ domain |
| 7 | [`sample7_wildcard_domain.plist`](file:///d:/Workspace/report/ATMKD&DV/samples/sample7_wildcard_domain.plist) | **HIGH** | **HIGH** | `[OK] MATCH` | Bật HTTP không mã hóa trên toàn bộ Subdomain (*.corp-partner.com) |
| 8 | [`sample8_corrupted.plist`](file:///d:/Workspace/report/ATMKD&DV/samples/sample8_corrupted.plist) | **ERROR / CORRUPT** | **ERROR / CORRUPT** | `[OK] MATCH` | Tệp Plist hỏng / Lỗi phân tích cú pháp (ExpatError) - Bắt ngoại lệ an toàn |

### 6.2. Bảng đối chứng hiệu quả khắc phục (Remediation Comparison)

| STT | Mục Kiểm Thử | Tệp Gốc | Rủi Ro Ban Đầu | Tệp Đã Khắc Phục | Rủi Ro Sau Sửa | Đánh Giá Khắc Phục |
|:---:|---|---|:---:|---|:---:|:---:|
| 1 | `sample2` | [`sample2_global_bypass.plist`](file:///d:/Workspace/report/ATMKD&DV/samples/sample2_global_bypass.plist) | **CRITICAL** | [`sample2_fixed.plist`](file:///d:/Workspace/report/ATMKD&DV/remediated_samples/sample2_fixed.plist) | **LOW / SAFE** | `REMEDIATED (SECURED)` |
| 2 | `sample4` | [`sample4_weak_tls.plist`](file:///d:/Workspace/report/ATMKD&DV/samples/sample4_weak_tls.plist) | **HIGH** | [`sample4_fixed.plist`](file:///d:/Workspace/report/ATMKD&DV/remediated_samples/sample4_fixed.plist) | **LOW / SAFE** | `REMEDIATED (SECURED)` |
| 3 | `sample7` | [`sample7_wildcard_domain.plist`](file:///d:/Workspace/report/ATMKD&DV/samples/sample7_wildcard_domain.plist) | **HIGH** | [`sample7_fixed.plist`](file:///d:/Workspace/report/ATMKD&DV/remediated_samples/sample7_fixed.plist) | **LOW / SAFE** | `REMEDIATED (SECURED)` |

---

## 7. HƯỚNG DẪN KHẮC PHỤC CỤ THỂ DÀNH CHO DEVELOPERS

### Tình huống 1: Ứng dụng bật toàn cục `NSAllowsArbitraryLoads`
```xml
<!-- NGUY HIỂM: sample2_global_bypass.plist -->
<key>NSAppTransportSecurity</key>
<dict>
    <key>NSAllowsArbitraryLoads</key>
    <true/>
</dict>
```
*Khắc phục:* Gỡ bỏ hoàn toàn thẻ `NSAppTransportSecurity` hoặc đặt rõ `false`:
```xml
<!-- AN TOÀN: sample2_fixed.plist -->
<key>NSAppTransportSecurity</key>
<dict>
    <key>NSAllowsArbitraryLoads</key>
    <false/>
</dict>
```

### Tình huống 2: Kết nối tới máy chủ cũ hỗ trợ TLS yếu
```xml
<!-- NGUY HIỂM: sample4_weak_tls.plist -->
<key>NSExceptionDomains</key>
<dict>
    <key>old-gateway.example.com</key>
    <dict>
        <key>NSExceptionMinimumTLSVersion</key>
        <string>TLSv1.0</string>
        <key>NSExceptionRequiresForwardSecrecy</key>
        <false/>
    </dict>
</dict>
```
*Khắc phục:* Nâng cấp máy chủ gateway và siết cấu hình:
```xml
<!-- AN TOÀN: sample4_fixed.plist -->
<key>NSExceptionDomains</key>
<dict>
    <key>old-gateway.example.com</key>
    <dict>
        <key>NSExceptionMinimumTLSVersion</key>
        <string>TLSv1.3</string>
        <key>NSExceptionRequiresForwardSecrecy</key>
        <true/>
    </dict>
</dict>
```

### Tình huống 3: Mở HTTP cho toàn bộ Subdomain qua Wildcard
```xml
<!-- NGUY HIỂM: sample7_wildcard_domain.plist -->
<key>NSExceptionDomains</key>
<dict>
    <key>corp-partner.com</key>
    <dict>
        <key>NSIncludesSubdomains</key>
        <true/>
        <key>NSExceptionAllowsInsecureHTTPLoads</key>
        <true/>
    </dict>
</dict>
```
*Khắc phục:* Tắt cờ `NSIncludesSubdomains`, ép buộc HTTPS và xác định rõ endpoint:
```xml
<!-- AN TOÀN: sample7_fixed.plist -->
<key>NSExceptionDomains</key>
<dict>
    <key>api.corp-partner.com</key>
    <dict>
        <key>NSIncludesSubdomains</key>
        <false/>
        <key>NSExceptionAllowsInsecureHTTPLoads</key>
        <false/>
        <key>NSExceptionMinimumTLSVersion</key>
        <string>TLSv1.2</string>
        <key>NSExceptionRequiresForwardSecrecy</key>
        <true/>
    </dict>
</dict>
```

---

## 8. BƯỚC TIẾP THEO: KẾT HỢP PHÂN TÍCH ĐỘNG (RUNTIME TRAFFIC ANALYSIS)

Như cảnh báo an ninh đã nêu rõ, phân tích tĩnh `Info.plist` chỉ kiểm tra được chính sách khai báo ở tầng ứng dụng cấp cao. Để đánh giá an ninh mạng toàn diện cho ứng dụng iOS trong thực tế (Penetration Testing / Security Audit), cần thực hiện tiếp các bước sau:

1. **Kiểm tra lưu lượng mạng qua Proxy (Man-in-the-Middle Inspection):**
   - Thiết lập proxy trung gian (sử dụng **mitmproxy** hoặc **Charles Proxy**).
   - Cài đặt root CA Certificate của proxy vào cấu hình tin cậy (Profile) trên thiết bị thử nghiệm iOS.
   - Theo dõi xem có bất kỳ gói tin HTTP rõ (Cleartext) hoặc dữ liệu nhạy cảm nào lọt ra ngoài mạng hay không.

2. **Phát hiện Socket cấp thấp và thư viện thứ ba:**
   - Sử dụng framework **Frida** hoặc **objection** để hook vào các hàm mạng:
     - Các API Objective-C / Swift: `NSURLSession`, `NSURLConnection`, `WKWebView`.
     - Các API C/C++ cấp thấp: `CFSocketCreate`, `getaddrinfo`, `connect`, `SSLHandshake`.
   - Kiểm tra các thư viện C/C++ nhúng độc lập (chẳng hạn `libcurl`, WebSockets C++, `gRPC`) có tự mở socket TCP riêng mà không đi qua cơ chế bảo vệ ATS của hệ điều hành hay không.

3. **Kiểm tra SSL Pinning:**
   - Thử nghiệm bẻ khóa chứng chỉ số bằng proxy để kiểm tra ứng dụng có cài đặt cơ chế ghim chứng chỉ (Certificate Pinning) nhằm ngăn chặn kẻ tấn công tự sinh chứng chỉ giả mạo hay không.

