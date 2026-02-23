#include <windows.h>
#include <commdlg.h>
#include <bcrypt.h>

#include <cwctype>
#include <sstream>
#include <string>
#include <vector>

#pragma comment(lib, "Comdlg32.lib")
#pragma comment(lib, "Bcrypt.lib")

namespace {
constexpr int ID_EDIT_FILE = 1001;
constexpr int ID_BUTTON_BROWSE = 1002;
constexpr int ID_EDIT_HASH_INPUT = 1003;
constexpr int ID_BUTTON_READ_HASH = 1004;
constexpr int ID_BUTTON_VERIFY = 1005;
constexpr int ID_EDIT_HASH_OUTPUT = 1006;
constexpr size_t kSha256HexLength = 64;
constexpr DWORD kHashReadBufferSize = 8192;
constexpr size_t kMaxUiPathChars = 32767;

HWND g_fileEdit = nullptr;
HWND g_expectedHashEdit = nullptr;
HWND g_calculatedHashEdit = nullptr;
HWND g_readHashButton = nullptr;
HWND g_verifyButton = nullptr;

std::wstring FormatWindowsError(DWORD errorCode);

std::wstring GetControlText(HWND hwnd) {
    int len = GetWindowTextLengthW(hwnd);
    std::wstring text(static_cast<size_t>(len), L'\0');
    if (len > 0) {
        std::vector<wchar_t> buffer(static_cast<size_t>(len) + 1, L'\0');
        GetWindowTextW(hwnd, buffer.data(), len + 1);
        text.assign(buffer.data());
    }
    return text;
}

std::wstring Trim(const std::wstring& input) {
    size_t start = 0;
    while (start < input.size() && iswspace(input[start])) {
        ++start;
    }

    size_t end = input.size();
    while (end > start && iswspace(input[end - 1])) {
        --end;
    }

    return input.substr(start, end - start);
}

std::wstring ToLower(std::wstring input) {
    for (wchar_t& ch : input) {
        ch = static_cast<wchar_t>(towlower(ch));
    }
    return input;
}

bool ConstantTimeEquals(const std::wstring& a, const std::wstring& b) {
    if (a.size() != b.size()) {
        return false;
    }

    unsigned int diff = 0;
    for (size_t i = 0; i < a.size(); ++i) {
        diff |= static_cast<unsigned int>(a[i] ^ b[i]);
    }
    return diff == 0;
}

bool NormalizePath(const std::wstring& rawPath, std::wstring& normalizedPath, std::wstring& errorMessage) {
    if (rawPath.empty()) {
        errorMessage = L"File path is empty.";
        return false;
    }

    DWORD required = GetFullPathNameW(rawPath.c_str(), 0, nullptr, nullptr);
    if (required == 0) {
        errorMessage = L"Invalid file path:\n" + FormatWindowsError(GetLastError());
        return false;
    }

    std::vector<wchar_t> buffer(static_cast<size_t>(required), L'\0');
    DWORD written = GetFullPathNameW(rawPath.c_str(), required, buffer.data(), nullptr);
    if (written == 0 || written >= required) {
        errorMessage = L"Failed to normalize file path:\n" + FormatWindowsError(GetLastError());
        return false;
    }

    normalizedPath.assign(buffer.data(), written);
    return true;
}

bool IsPathBlocked(const std::wstring& pathLower) {
    if (pathLower.rfind(L"\\\\?\\", 0) == 0) {
        return true;
    }

    if (pathLower.rfind(L"\\\\.\\", 0) == 0) {
        return true;
    }

    if (pathLower.rfind(L"\\??\\", 0) == 0) {
        return true;
    }

    if (pathLower.rfind(L"\\\\", 0) == 0) {
        return true;
    }

    return false;
}

bool HasAlternateDataStream(const std::wstring& path) {
    size_t firstColon = path.find(L':');
    if (firstColon == std::wstring::npos) {
        return false;
    }
    if (firstColon != 1) {
        return true;
    }
    return path.find(L':', firstColon + 1) != std::wstring::npos;
}

bool ValidateAndNormalizeSelectedPath(const std::wstring& filePathInput,
                                      std::wstring& normalizedPath,
                                      std::wstring& errorMessage) {
    if (filePathInput.empty()) {
        errorMessage = L"Please select a file first.";
        return false;
    }

    std::wstring normalizeError;
    if (!NormalizePath(filePathInput, normalizedPath, normalizeError)) {
        errorMessage = normalizeError;
        return false;
    }

    if (IsPathBlocked(ToLower(normalizedPath))) {
        errorMessage = L"Device, UNC, and namespace paths are blocked for security.";
        return false;
    }

    if (HasAlternateDataStream(normalizedPath)) {
        errorMessage = L"Alternate data streams are blocked for security.";
        return false;
    }

    if (normalizedPath.size() > kMaxUiPathChars) {
        errorMessage = L"Normalized file path is too long for this application.";
        return false;
    }

    return true;
}

bool IsValidSha256Hex(const std::wstring& hash) {
    if (hash.size() != kSha256HexLength) {
        return false;
    }

    for (wchar_t ch : hash) {
        if (!iswxdigit(ch)) {
            return false;
        }
    }
    return true;
}

std::wstring BytesToHexLower(const std::vector<BYTE>& bytes) {
    static const wchar_t* kHex = L"0123456789abcdef";
    std::wstring out;
    out.reserve(bytes.size() * 2);

    for (BYTE b : bytes) {
        out.push_back(kHex[(b >> 4) & 0x0F]);
        out.push_back(kHex[b & 0x0F]);
    }
    return out;
}

std::wstring FormatNtStatus(NTSTATUS status) {
    std::wstringstream ss;
    ss << L"0x" << std::hex << static_cast<unsigned long>(status);
    return ss.str();
}

std::wstring FormatWindowsError(DWORD errorCode) {
    wchar_t* messageBuffer = nullptr;
    DWORD len = FormatMessageW(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        nullptr,
        errorCode,
        0,
        reinterpret_cast<LPWSTR>(&messageBuffer),
        0,
        nullptr);

    std::wstring message;
    if (len > 0 && messageBuffer != nullptr) {
        message.assign(messageBuffer, len);
        while (!message.empty() && (message.back() == L'\r' || message.back() == L'\n')) {
            message.pop_back();
        }
    } else {
        std::wstringstream ss;
        ss << L"Windows error " << errorCode;
        message = ss.str();
    }

    if (messageBuffer) {
        LocalFree(messageBuffer);
    }

    return message;
}

bool ComputeSha256ForFile(const std::wstring& filePath, std::wstring& hexHash, std::wstring& errorMessage) {
    constexpr DWORD kOpenFlags =
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN | FILE_FLAG_OPEN_REPARSE_POINT;

    HANDLE file = CreateFileW(
        filePath.c_str(),
        GENERIC_READ,
        FILE_SHARE_READ,
        nullptr,
        OPEN_EXISTING,
        kOpenFlags,
        nullptr);

    if (file == INVALID_HANDLE_VALUE) {
        errorMessage = L"Failed to open file:\n" + FormatWindowsError(GetLastError());
        return false;
    }

    DWORD fileType = GetFileType(file);
    if (fileType != FILE_TYPE_DISK) {
        CloseHandle(file);
        errorMessage = L"Only regular disk files are allowed.";
        return false;
    }

    BY_HANDLE_FILE_INFORMATION fileInfo = {};
    if (!GetFileInformationByHandle(file, &fileInfo)) {
        DWORD infoErr = GetLastError();
        CloseHandle(file);
        errorMessage = L"Failed to inspect file:\n" + FormatWindowsError(infoErr);
        return false;
    }

    if ((fileInfo.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0) {
        CloseHandle(file);
        errorMessage = L"Directories are not allowed. Select a regular file.";
        return false;
    }

    if ((fileInfo.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0) {
        CloseHandle(file);
        errorMessage = L"Reparse points (symlinks/junctions) are blocked for security.";
        return false;
    }

    BCRYPT_ALG_HANDLE algHandle = nullptr;
    BCRYPT_HASH_HANDLE hashHandle = nullptr;
    std::vector<BYTE> hashObject;
    std::vector<BYTE> hash;

    NTSTATUS status = BCryptOpenAlgorithmProvider(&algHandle, BCRYPT_SHA256_ALGORITHM, nullptr, 0);
    if (status < 0) {
        CloseHandle(file);
        errorMessage = L"BCryptOpenAlgorithmProvider failed: " + FormatNtStatus(status);
        return false;
    }

    DWORD dataSize = 0;
    DWORD hashObjectSize = 0;
    status = BCryptGetProperty(
        algHandle,
        BCRYPT_OBJECT_LENGTH,
        reinterpret_cast<PUCHAR>(&hashObjectSize),
        sizeof(hashObjectSize),
        &dataSize,
        0);
    if (status < 0) {
        BCryptCloseAlgorithmProvider(algHandle, 0);
        CloseHandle(file);
        errorMessage = L"BCryptGetProperty(BCRYPT_OBJECT_LENGTH) failed: " + FormatNtStatus(status);
        return false;
    }

    DWORD hashLength = 0;
    status = BCryptGetProperty(
        algHandle,
        BCRYPT_HASH_LENGTH,
        reinterpret_cast<PUCHAR>(&hashLength),
        sizeof(hashLength),
        &dataSize,
        0);
    if (status < 0) {
        BCryptCloseAlgorithmProvider(algHandle, 0);
        CloseHandle(file);
        errorMessage = L"BCryptGetProperty(BCRYPT_HASH_LENGTH) failed: " + FormatNtStatus(status);
        return false;
    }

    if (hashLength != 32) {
        BCryptCloseAlgorithmProvider(algHandle, 0);
        CloseHandle(file);
        errorMessage = L"Unexpected SHA-256 hash length from provider.";
        return false;
    }

    hashObject.resize(hashObjectSize);
    hash.resize(hashLength);

    status = BCryptCreateHash(
        algHandle,
        &hashHandle,
        hashObject.data(),
        static_cast<ULONG>(hashObject.size()),
        nullptr,
        0,
        0);
    if (status < 0) {
        BCryptCloseAlgorithmProvider(algHandle, 0);
        CloseHandle(file);
        errorMessage = L"BCryptCreateHash failed: " + FormatNtStatus(status);
        return false;
    }

    std::vector<BYTE> buffer(kHashReadBufferSize);
    while (true) {
        DWORD bytesRead = 0;
        BOOL readOk = ReadFile(file, buffer.data(), static_cast<DWORD>(buffer.size()), &bytesRead, nullptr);
        if (!readOk) {
            DWORD readErr = GetLastError();
            BCryptDestroyHash(hashHandle);
            BCryptCloseAlgorithmProvider(algHandle, 0);
            CloseHandle(file);
            errorMessage = L"Failed while reading file:\n" + FormatWindowsError(readErr);
            return false;
        }

        if (bytesRead == 0) {
            break;
        }

        status = BCryptHashData(hashHandle, buffer.data(), bytesRead, 0);
        if (status < 0) {
            BCryptDestroyHash(hashHandle);
            BCryptCloseAlgorithmProvider(algHandle, 0);
            CloseHandle(file);
            errorMessage = L"BCryptHashData failed: " + FormatNtStatus(status);
            return false;
        }
    }

    status = BCryptFinishHash(hashHandle, hash.data(), static_cast<ULONG>(hash.size()), 0);
    if (status < 0) {
        BCryptDestroyHash(hashHandle);
        BCryptCloseAlgorithmProvider(algHandle, 0);
        CloseHandle(file);
        errorMessage = L"BCryptFinishHash failed: " + FormatNtStatus(status);
        return false;
    }

    BCryptDestroyHash(hashHandle);
    BCryptCloseAlgorithmProvider(algHandle, 0);
    CloseHandle(file);

    hexHash = BytesToHexLower(hash);
    return true;
}

bool TryGetValidatedPathFromUi(HWND owner, std::wstring& normalizedPath) {
    std::wstring filePathInput = Trim(GetControlText(g_fileEdit));
    std::wstring pathError;
    if (!ValidateAndNormalizeSelectedPath(filePathInput, normalizedPath, pathError)) {
        MessageBoxW(owner, pathError.c_str(), L"Invalid Path", MB_OK | MB_ICONERROR);
        return false;
    }

    SetWindowTextW(g_fileEdit, normalizedPath.c_str());
    return true;
}

void OnBrowse(HWND owner) {
    wchar_t fileName[MAX_PATH] = {};

    OPENFILENAMEW ofn = {};
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = owner;
    ofn.lpstrFile = fileName;
    ofn.nMaxFile = MAX_PATH;
    ofn.lpstrFilter = L"All Files\0*.*\0";
    ofn.nFilterIndex = 1;
    ofn.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST | OFN_NOCHANGEDIR | OFN_DONTADDTORECENT;

    if (GetOpenFileNameW(&ofn)) {
        std::wstring normalizedPath;
        std::wstring pathError;
        if (!ValidateAndNormalizeSelectedPath(fileName, normalizedPath, pathError)) {
            MessageBoxW(owner, pathError.c_str(), L"Invalid Path", MB_OK | MB_ICONERROR);
            return;
        }

        SetWindowTextW(g_fileEdit, normalizedPath.c_str());
        SetWindowTextW(g_calculatedHashEdit, L"");
    }
}

void OnReadFileHash(HWND owner) {
    std::wstring normalizedPath;
    if (!TryGetValidatedPathFromUi(owner, normalizedPath)) {
        return;
    }

    EnableWindow(g_readHashButton, FALSE);
    EnableWindow(g_verifyButton, FALSE);

    std::wstring calculatedHash;
    std::wstring error;
    if (!ComputeSha256ForFile(normalizedPath, calculatedHash, error)) {
        EnableWindow(g_readHashButton, TRUE);
        EnableWindow(g_verifyButton, TRUE);
        MessageBoxW(owner, error.c_str(), L"Error", MB_OK | MB_ICONERROR);
        return;
    }

    EnableWindow(g_readHashButton, TRUE);
    EnableWindow(g_verifyButton, TRUE);
    SetWindowTextW(g_calculatedHashEdit, calculatedHash.c_str());

    std::wstring message = L"Calculated SHA-256:\n" + calculatedHash;
    MessageBoxW(owner, message.c_str(), L"File Hash Loaded", MB_OK | MB_ICONINFORMATION);
}

void OnVerify(HWND owner) {
    std::wstring trustedHash = ToLower(Trim(GetControlText(g_expectedHashEdit)));

    if (trustedHash.empty()) {
        MessageBoxW(owner, L"Please enter the expected SHA-256 hash first.", L"Warning", MB_OK | MB_ICONWARNING);
        return;
    }

    if (!IsValidSha256Hex(trustedHash)) {
        MessageBoxW(owner, L"Trusted hash must be 64 hexadecimal characters.", L"Warning", MB_OK | MB_ICONWARNING);
        return;
    }

    std::wstring normalizedPath;
    if (!TryGetValidatedPathFromUi(owner, normalizedPath)) {
        return;
    }

    EnableWindow(g_readHashButton, FALSE);
    EnableWindow(g_verifyButton, FALSE);

    std::wstring calculatedHash;
    std::wstring error;
    if (!ComputeSha256ForFile(normalizedPath, calculatedHash, error)) {
        EnableWindow(g_readHashButton, TRUE);
        EnableWindow(g_verifyButton, TRUE);
        MessageBoxW(owner, error.c_str(), L"Error", MB_OK | MB_ICONERROR);
        return;
    }

    EnableWindow(g_readHashButton, TRUE);
    EnableWindow(g_verifyButton, TRUE);
    SetWindowTextW(g_calculatedHashEdit, calculatedHash.c_str());

    if (ConstantTimeEquals(calculatedHash, trustedHash)) {
        std::wstring message =
            L"SHA-256 matches.\n\nExpected:\n" + trustedHash + L"\n\nCalculated:\n" + calculatedHash;
        MessageBoxW(owner, message.c_str(), L"Verified", MB_OK | MB_ICONINFORMATION);
    } else {
        std::wstring message =
            L"Hash does NOT match.\n\nExpected:\n" + trustedHash + L"\n\nCalculated:\n" + calculatedHash;
        MessageBoxW(owner, message.c_str(), L"Mismatch", MB_OK | MB_ICONERROR);
    }
}

LRESULT CALLBACK WindowProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
        case WM_CREATE: {
            CreateWindowExW(0, L"STATIC", L"File Path:", WS_CHILD | WS_VISIBLE,
                            16, 14, 100, 20, hwnd, nullptr, nullptr, nullptr);

            g_fileEdit = CreateWindowExW(
                WS_EX_CLIENTEDGE,
                L"EDIT",
                L"",
                WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL,
                16,
                36,
                420,
                24,
                hwnd,
                reinterpret_cast<HMENU>(ID_EDIT_FILE),
                nullptr,
                nullptr);

            CreateWindowExW(0, L"BUTTON", L"Browse", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                            444, 36, 92, 24, hwnd,
                            reinterpret_cast<HMENU>(ID_BUTTON_BROWSE), nullptr, nullptr);

            g_readHashButton = CreateWindowExW(0, L"BUTTON", L"Read Hash", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                                               444, 66, 92, 24, hwnd,
                                               reinterpret_cast<HMENU>(ID_BUTTON_READ_HASH), nullptr, nullptr);

            CreateWindowExW(0, L"STATIC", L"Expected SHA-256 Hash (paste here):", WS_CHILD | WS_VISIBLE,
                            16, 98, 320, 20, hwnd, nullptr, nullptr, nullptr);

            g_expectedHashEdit = CreateWindowExW(
                WS_EX_CLIENTEDGE,
                L"EDIT",
                L"",
                WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL,
                16,
                120,
                520,
                24,
                hwnd,
                reinterpret_cast<HMENU>(ID_EDIT_HASH_INPUT),
                nullptr,
                nullptr);

            CreateWindowExW(0, L"STATIC", L"Calculated SHA-256 Hash:", WS_CHILD | WS_VISIBLE,
                            16, 154, 220, 20, hwnd, nullptr, nullptr, nullptr);

            g_calculatedHashEdit = CreateWindowExW(
                WS_EX_CLIENTEDGE,
                L"EDIT",
                L"",
                WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL | ES_READONLY,
                16,
                176,
                520,
                24,
                hwnd,
                reinterpret_cast<HMENU>(ID_EDIT_HASH_OUTPUT),
                nullptr,
                nullptr);

            SendMessageW(g_fileEdit, EM_LIMITTEXT, static_cast<WPARAM>(kMaxUiPathChars), 0);
            SendMessageW(g_expectedHashEdit, EM_LIMITTEXT, static_cast<WPARAM>(kSha256HexLength), 0);
            SendMessageW(g_calculatedHashEdit, EM_LIMITTEXT, static_cast<WPARAM>(kSha256HexLength), 0);

            g_verifyButton = CreateWindowExW(0, L"BUTTON", L"Verify Hash Match",
                                             WS_CHILD | WS_VISIBLE | BS_DEFPUSHBUTTON,
                                             16, 214, 520, 34, hwnd,
                                             reinterpret_cast<HMENU>(ID_BUTTON_VERIFY), nullptr, nullptr);
            return 0;
        }

        case WM_COMMAND: {
            int id = LOWORD(wParam);
            if (id == ID_BUTTON_BROWSE) {
                OnBrowse(hwnd);
                return 0;
            }
            if (id == ID_BUTTON_READ_HASH) {
                OnReadFileHash(hwnd);
                return 0;
            }
            if (id == ID_BUTTON_VERIFY) {
                OnVerify(hwnd);
                return 0;
            }
            break;
        }

        case WM_DESTROY:
            PostQuitMessage(0);
            return 0;
    }

    return DefWindowProcW(hwnd, msg, wParam, lParam);
}

}  // namespace

int WINAPI wWinMain(HINSTANCE hInstance, HINSTANCE, PWSTR, int nCmdShow) {
    const wchar_t kClassName[] = L"Sha256VerifierWindowClass";

    WNDCLASSW wc = {};
    wc.lpfnWndProc = WindowProc;
    wc.hInstance = hInstance;
    wc.lpszClassName = kClassName;
    wc.hCursor = LoadCursor(nullptr, IDC_ARROW);
    wc.hbrBackground = reinterpret_cast<HBRUSH>(COLOR_WINDOW + 1);

    if (!RegisterClassW(&wc)) {
        MessageBoxW(nullptr, L"Failed to register window class.", L"Error", MB_OK | MB_ICONERROR);
        return 1;
    }

    HWND hwnd = CreateWindowExW(
        0,
        kClassName,
        L"SHA-256 File Verifier",
        WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX,
        CW_USEDEFAULT,
        CW_USEDEFAULT,
        570,
        300,
        nullptr,
        nullptr,
        hInstance,
        nullptr);

    if (!hwnd) {
        MessageBoxW(nullptr, L"Failed to create main window.", L"Error", MB_OK | MB_ICONERROR);
        return 1;
    }

    ShowWindow(hwnd, nCmdShow);
    UpdateWindow(hwnd);

    MSG msg;
    while (GetMessageW(&msg, nullptr, 0, 0) > 0) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }

    return static_cast<int>(msg.wParam);
}
