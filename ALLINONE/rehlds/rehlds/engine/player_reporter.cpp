/*
*    Player Reporter Module for ReHLDS
*    增量上报服务器玩家信息到 Web API
*    使用 libcurl 支持 HTTP/2 多路复用和自动连接管理
*/

#include "precompiled.h"
#include "player_reporter.h"
#include <stdarg.h>
#include <atomic>

// libcurl - HTTP 客户端库
#include "curl/curl.h"

// cJSON - JSON 构建库
extern "C" {
#include "cjson/cJSON.h"
}

#ifdef _WIN32
#include <process.h>  // for _beginthreadex
#include <ws2tcpip.h>  // for getaddrinfo, inet_ntop
#pragma comment(lib, "libcurl.lib")
#pragma comment(lib, "ws2_32.lib")
#else
#include <unistd.h>
#include <pthread.h>
#include <semaphore.h>  // for sem_t - 解决 Lost Wakeup 问题
#include <time.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#endif

// HTTP 错误码定义
enum class HttpResult : int {
    OK                  =  0,   // 成功
    ERR_INVALID_PARAMS  = -1,   // 参数错误
    ERR_CURL_INIT       = -2,   // CURL 初始化失败
    ERR_CURL_PERFORM    = -3,   // CURL 执行失败
    ERR_CONNECT         = -4,   // 连接失败
    ERR_TIMEOUT         = -5,   // 超时
    ERR_HTTP_STATUS     = -7,   // HTTP 状态码错误
    ERR_RATE_LIMITED    = -9,   // 429 限流
    ERR_SERVICE_UNAVAIL = -10,  // 503 服务不可用
    ERR_AUTH_FAILED     = -11   // 401/403 认证失败
};

// 配置 cvar
cvar_t sv_reporter_interval = { "sv_reporter_interval", "1", 0, 1.0f, NULL };
cvar_t sv_reporter_full_interval = { "sv_reporter_full_interval", "60", 0, 60.0f, NULL };
cvar_t sv_reporter_debug = { "sv_reporter_debug", "0", 0, 0.0f, NULL };  // 调试日志开关

// 硬编码的 API URL
static const char *g_szReportApiUrl = "https://bllom.fullcone.cn/api/server/report.php";
static const char *g_szAuthApiUrl = "https://bllom.fullcone.cn/api/server/auth.php";

// 玩家状态跟踪
#define MAX_TRACKED_PLAYERS 64

struct TrackedPlayer {
    bool active;
    int userid;
    int ping;      // 玩家延迟（毫秒）
    char name[64]; // Raw name (utf-8 or not)
};

// UTF-8 安全的字符串复制
static void Q_strncpy_utf8safe(char *dst, const char *src, int size)
{
    if (size <= 0) return;
    
    int i = 0;
    while (i < size - 1 && src[i]) {
        dst[i] = src[i];
        i++;
    }
    
    if (i > 0 && src[i]) {
        int backtrack = 0;
        for (int j = i - 1; j >= 0 && j >= i - 4; j--) {
            unsigned char c = (unsigned char)dst[j];
            if ((c & 0xC0) == 0x80) {
                backtrack++;
            } else if ((c & 0x80) == 0) {
                break;
            } else {
                int expectedLen = 0;
                if (c >= 0xC2 && c <= 0xDF) expectedLen = 2;
                else if (c >= 0xE0 && c <= 0xEF) expectedLen = 3;
                else if (c >= 0xF0 && c <= 0xF4) expectedLen = 4;
                
                if (expectedLen > 0 && backtrack + 1 < expectedLen) {
                    i = j;
                }
                break;
            }
        }
    }
    
    dst[i] = '\0';
}

// 安全的 snprintf 封装
static int SafeSnprintf(char *buf, int size, const char *fmt, ...)
{
    if (size <= 0) return 0;
    
    va_list args;
    va_start(args, fmt);
    int ret = Q_vsnprintf(buf, size, fmt, args);
    va_end(args);
    
    if (ret < 0) {
        buf[0] = '\0';
        return 0;
    }
    if (ret >= size) {
        buf[size - 1] = '\0';
        return size - 1;
    }
    return ret;
}

// 单调时钟
static double MonotonicSeconds()
{
#ifdef _WIN32
    static LARGE_INTEGER freq = {0};
    if (freq.QuadPart == 0) {
        QueryPerformanceFrequency(&freq);
    }
    LARGE_INTEGER counter;
    QueryPerformanceCounter(&counter);
    return (double)counter.QuadPart / (double)freq.QuadPart;
#else
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec * 1e-9;
#endif
}

// 全局状态
static TrackedPlayer g_LastPlayers[MAX_TRACKED_PLAYERS];
static char g_szLastMap[64] = "";
static double g_flNextReportTime = 0.0;
static double g_flNextFullReportTime = 0.0;
static float g_flLastFullInterval = 60.0f;
static bool g_bReporterInitialized = false;
static bool g_bReporterDisabled = false;  // 运行时禁用标志（配置错误或认证失败时设置）
static std::atomic<bool> g_bForceFullReport{true};
static std::atomic<bool> g_bIsShuttingDown{false};
static cvar_t *g_pHostnameCvar = NULL;

// 认证状态（启动时认证一次，缓存 server_id）
static bool g_bAuthenticated = false;
static int g_nCachedServerId = 0;

// HTTP 结果队列（Worker -> 主线程）- SPSC 无锁
struct HttpResultEntry {
    int32_t resultCode;  // >0 成功, <0 错误码
    bool isFull;
    char errorMsg[128];  // 错误信息（只在失败时有效）
    char hostname[128];  // 服务器名称（full report 成功时从响应解析）
};
#define MAX_RESULT_QUEUE 32
static HttpResultEntry g_ResultQueue[MAX_RESULT_QUEUE];
// 使用 alignas(64) 避免伪共享：head 和 tail 分别由不同线程频繁写入
alignas(64) static std::atomic<int> g_nResultHead{0};  // 主线程写
alignas(64) static std::atomic<int> g_nResultTail{0};  // Worker 写

static int g_nFullReportRetryCount = 0;
#define MAX_FULL_REPORT_RETRIES 5

// 统计信息
static std::atomic<int> g_nSuccessCount{0};
static std::atomic<int> g_nFailureCount{0};
static std::atomic<int> g_nFullReportCount{0};
static std::atomic<int> g_nDeltaReportCount{0};
static std::atomic<int> g_nJsonTruncateCount{0};
static std::atomic<int64_t> g_nTotalBytesSent{0};
static double g_flLastSuccessTime = 0.0;
static double g_flLastFailureTime = 0.0;
static double g_flModuleStartTime = 0.0;

// 错误码统计
static std::atomic<int> g_nErrConnect{0};
static std::atomic<int> g_nErrTimeout{0};
static std::atomic<int> g_nErrHttpStatus{0};
static std::atomic<int> g_nErrRateLimited{0};
static std::atomic<int> g_nErrAuthFailed{0};

// 日志队列
#define MAX_LOG_QUEUE 64
#define MAX_LOG_MSG_LEN 256
struct LogEntry {
    char msg[MAX_LOG_MSG_LEN];
    bool isDebug;
};
static LogEntry g_LogQueue[MAX_LOG_QUEUE];
// 使用 alignas(64) 避免伪共享：head 和 tail 分别由不同线程频繁写入
alignas(64) static std::atomic<int> g_nLogHead{0};   // 主线程写
alignas(64) static std::atomic<int> g_nLogTail{0};   // Worker 写
static std::atomic<int> g_nLogDropped{0};

// 线程同步
// 所有队列都使用 SPSC 无锁设计，完全无锁！
// 错误信息通过结果队列传递，不需要单独的锁

// libcurl 全局状态（Worker 线程专用）
// WARNING: g_pCurl 仅供单 Worker 线程使用
// 如需多 Worker 线程，请改用 thread_local 或传参
static CURL *g_pCurl = NULL;  // 复用的 CURL easy handle
static struct curl_slist *g_pSharedHeaders = NULL;  // 共享的 HTTP headers（主线程创建，只读）
static std::atomic<int> g_nTotalRequestsSent{0};
static std::atomic<int> g_nConnectionsReused{0};

// 前向声明
static size_t CurlWriteCallback(void *contents, size_t size, size_t nmemb, void *userp);

// 创建共享的 HTTP headers（在 Init 中调用一次，之后只读）
static void CreateSharedHeaders()
{
    if (g_pSharedHeaders) return;  // 已创建
    
    g_pSharedHeaders = curl_slist_append(NULL, "Content-Type: application/json");
    g_pSharedHeaders = curl_slist_append(g_pSharedHeaders, "Accept: application/json");
#ifdef _WIN32
    g_pSharedHeaders = curl_slist_append(g_pSharedHeaders, "User-Agent: ReHLDS-PlayerReporter/3.0 (Windows; libcurl)");
#else
    g_pSharedHeaders = curl_slist_append(g_pSharedHeaders, "User-Agent: ReHLDS-PlayerReporter/3.0 (Linux; libcurl)");
#endif
}

// 清理共享的 HTTP headers（在 Shutdown 中调用）
static void DestroySharedHeaders()
{
    if (g_pSharedHeaders) {
        curl_slist_free_all(g_pSharedHeaders);
        g_pSharedHeaders = NULL;
    }
}

// 设置通用的 CURL 选项（供认证和上报复用）
static void SetupCommonCurlOptions(CURL *pCurl, struct curl_slist *headers)
{
    // HTTP headers
    curl_easy_setopt(pCurl, CURLOPT_HTTPHEADER, headers);
    
    // HTTP/2（HTTPS 连接上尝试 HTTP/2，不支持则自动降级）
    curl_easy_setopt(pCurl, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_2TLS);
    
    // SSL 证书验证
    curl_easy_setopt(pCurl, CURLOPT_SSL_VERIFYPEER, 1L);
    curl_easy_setopt(pCurl, CURLOPT_SSL_VERIFYHOST, 2L);
    
    // 多线程安全
    curl_easy_setopt(pCurl, CURLOPT_NOSIGNAL, 1L);
    
    // 响应回调
    curl_easy_setopt(pCurl, CURLOPT_WRITEFUNCTION, CurlWriteCallback);
}


// 日志队列函数 - SPSC 无锁
// 生产者（Worker）：只写 tail
// 消费者（主线程）：只写 head
static void QueueLog(bool isDebug, const char *fmt, ...)
{
    char buf[MAX_LOG_MSG_LEN];
    va_list args;
    va_start(args, fmt);
    Q_vsnprintf(buf, sizeof(buf), fmt, args);
    va_end(args);
    
    // SPSC 无锁入队
    int tail = g_nLogTail.load(std::memory_order_relaxed);
    int nextTail = (tail + 1) % MAX_LOG_QUEUE;
    int head = g_nLogHead.load(std::memory_order_acquire);
    
    if (nextTail == head) {
        // 队列满，丢弃
        g_nLogDropped.fetch_add(1, std::memory_order_relaxed);
        return;
    }
    
    Q_strncpy(g_LogQueue[tail].msg, buf, MAX_LOG_MSG_LEN);
    g_LogQueue[tail].isDebug = isDebug;
    g_nLogTail.store(nextTail, std::memory_order_release);
}

// SPSC 无锁出队
static void ProcessLogQueue()
{
    // 如果调试模式关闭，直接清空队列不输出
    if (sv_reporter_debug.value == 0.0f) {
        int head = g_nLogHead.load(std::memory_order_relaxed);
        int tail = g_nLogTail.load(std::memory_order_acquire);
        if (head != tail) {
            g_nLogHead.store(tail, std::memory_order_release);
        }
        g_nLogDropped.exchange(0, std::memory_order_relaxed);
        return;
    }
    
    int head = g_nLogHead.load(std::memory_order_relaxed);
    int tail = g_nLogTail.load(std::memory_order_acquire);
    int dropped = g_nLogDropped.exchange(0, std::memory_order_relaxed);
    
    // 处理所有待输出的日志
    while (head != tail) {
        LogEntry entry = g_LogQueue[head];
        head = (head + 1) % MAX_LOG_QUEUE;
        g_nLogHead.store(head, std::memory_order_release);
        
        Con_Printf("%s", entry.msg);
        
        // 重新读取 tail（可能有新日志）
        tail = g_nLogTail.load(std::memory_order_acquire);
    }
    
    if (dropped > 0) {
        Con_Printf("[PlayerReporter] Warning: %d log messages dropped\n", dropped);
    }
}

// 结果队列函数（Worker 线程调用）- SPSC 无锁
static void QueueHttpResult(int32_t resultCode, bool isFull, const char *errorMsg = NULL, const char *hostname = NULL)
{
    int tail = g_nResultTail.load(std::memory_order_relaxed);
    int nextTail = (tail + 1) % MAX_RESULT_QUEUE;
    int head = g_nResultHead.load(std::memory_order_acquire);
    
    if (nextTail == head) {
        // 队列满，丢弃当前结果（不能移动 head，因为 head 只能由主线程写）
        // 这种情况很少发生，因为主线程每帧都会处理结果
        return;
    }
    
    g_ResultQueue[tail].resultCode = resultCode;
    g_ResultQueue[tail].isFull = isFull;
    if (errorMsg && errorMsg[0]) {
        Q_strncpy(g_ResultQueue[tail].errorMsg, errorMsg, sizeof(g_ResultQueue[tail].errorMsg));
    } else {
        g_ResultQueue[tail].errorMsg[0] = '\0';
    }
    if (hostname && hostname[0]) {
        Q_strncpy(g_ResultQueue[tail].hostname, hostname, sizeof(g_ResultQueue[tail].hostname));
    } else {
        g_ResultQueue[tail].hostname[0] = '\0';
    }
    g_nResultTail.store(nextTail, std::memory_order_release);
}

// Worker 线程局部错误信息缓冲区
static char g_WorkerErrorBuf[128];

// libcurl 响应回调
struct CurlResponseData {
    char body[1024];
    int body_len;
    long http_code;
};

static size_t CurlWriteCallback(void *contents, size_t size, size_t nmemb, void *userp)
{
    size_t realsize = size * nmemb;
    CurlResponseData *resp = (CurlResponseData *)userp;
    
    // 只保存前 1023 字节用于错误信息
    int remaining = (int)sizeof(resp->body) - 1 - resp->body_len;
    if (remaining > 0) {
        int to_copy = (int)realsize < remaining ? (int)realsize : remaining;
        memcpy(resp->body + resp->body_len, contents, to_copy);
        resp->body_len += to_copy;
        resp->body[resp->body_len] = '\0';
    }
    
    return realsize;
}

// 检查是否有玩家变化
static bool HasPlayerChanges()
{
    if (Q_strcmp(g_szLastMap, g_psv.name) != 0)
        return true;
    
    for (int i = 0; i < g_psvs.maxclients && i < MAX_TRACKED_PLAYERS; i++) {
        client_t *cl = &g_psvs.clients[i];
        bool curActive = cl->active && !cl->fakeclient;
        if (curActive != g_LastPlayers[i].active)
            return true;
        if (curActive && g_LastPlayers[i].active) {
            if (cl->userid != g_LastPlayers[i].userid)
                return true;
            // 直接比较原始名字，避免每帧进行 UTF-8 处理
            // 这里的比较是安全的，因为 g_LastPlayers[i].name 现在存储的是原始名字
            if (Q_strcmp(cl->name, g_LastPlayers[i].name) != 0)
                return true;
        }
    }
    return false;
}


// 上报任务数据（存储玩家快照，JSON 在 Worker 线程构建）
#define REPORT_JSON_BUFFER_SIZE 32768
struct ReportTask {
    char url[256];
    int serverId;             // 服务器 ID（认证后获取）
    char mapName[64];
    int maxPlayers;
    TrackedPlayer players[MAX_TRACKED_PLAYERS];      // 当前玩家快照
    TrackedPlayer lastPlayers[MAX_TRACKED_PLAYERS];  // 上次玩家快照（用于 delta）
    double queuedMono;
    bool isFull;
};

// 任务队列 - SPSC 无锁设计
// 生产者（主线程）：只写 tail，读 head
// 消费者（Worker）：只写 head，读 tail
// 这是经典的单生产者单消费者无锁队列
#define MAX_TASK_QUEUE 32
#define MAX_TASK_AGE 10.0
static ReportTask g_TaskQueue[MAX_TASK_QUEUE];
// 使用 alignas(64) 避免伪共享：head 和 tail 分别由不同线程频繁写入
alignas(64) static std::atomic<int> g_nTaskHead{0};  // Worker 写，主线程读
alignas(64) static std::atomic<int> g_nTaskTail{0};  // 主线程写，Worker 读
static std::atomic<int> g_nTaskDropped{0};
static std::atomic<int> g_nTaskExpired{0};

// 指数退避
static int g_nHttpRetryCount = 0;
#define MAX_HTTP_RETRY_COUNT 8
#define BASE_RETRY_DELAY 2.0
#define MAX_RETRY_DELAY 120.0

// Worker 线程用的 JSON 缓冲区
static char g_WorkerJsonBuffer[REPORT_JSON_BUFFER_SIZE];

// 在 Worker 线程中从任务构建 JSON
static bool BuildJsonFromTask(const ReportTask *task, char *buf, int bufsize)
{
    cJSON *root = cJSON_CreateObject();
    if (!root) {
        buf[0] = '\0';
        return false;
    }
    
    // Worker 线程本地缓冲区，用于 UTF-8 安全处理
    char safeName[64];
    
    // 计算当前玩家数
    int count = 0;
    for (int i = 0; i < MAX_TRACKED_PLAYERS; i++) {
        if (task->players[i].active) count++;
    }
    
    if (task->isFull) {
        cJSON_AddStringToObject(root, "type", "full");
        cJSON_AddNumberToObject(root, "server_id", task->serverId);
        cJSON_AddStringToObject(root, "map", task->mapName);
        cJSON_AddNumberToObject(root, "max_players", task->maxPlayers);
        cJSON_AddNumberToObject(root, "player_count", count);
        
        cJSON *players = cJSON_AddArrayToObject(root, "players");
        if (players) {
            for (int i = 0; i < MAX_TRACKED_PLAYERS; i++) {
                if (!task->players[i].active) continue;
                cJSON *player = cJSON_CreateObject();
                if (player) {
                    cJSON_AddNumberToObject(player, "userid", task->players[i].userid);
                    // UTF-8 安全处理在 Worker 线程执行，不影响主线程性能
                    Q_strncpy_utf8safe(safeName, task->players[i].name, sizeof(safeName));
                    cJSON_AddStringToObject(player, "name", safeName);
                    cJSON_AddNumberToObject(player, "ping", task->players[i].ping);
                    cJSON_AddItemToArray(players, player);
                }
            }
        }
    } else {
        cJSON_AddStringToObject(root, "type", "delta");
        cJSON_AddNumberToObject(root, "server_id", task->serverId);
        cJSON_AddNumberToObject(root, "player_count", count);
        
        // 先收集 joined 玩家，只有非空才添加到 JSON
        cJSON *joined = cJSON_CreateArray();
        if (joined) {
            for (int i = 0; i < MAX_TRACKED_PLAYERS; i++) {
                if (task->players[i].active && 
                    (!task->lastPlayers[i].active || task->lastPlayers[i].userid != task->players[i].userid)) {
                    cJSON *player = cJSON_CreateObject();
                    if (player) {
                        cJSON_AddNumberToObject(player, "userid", task->players[i].userid);
                        // UTF-8 安全处理在 Worker 线程执行
                        Q_strncpy_utf8safe(safeName, task->players[i].name, sizeof(safeName));
                        cJSON_AddStringToObject(player, "name", safeName);
                        cJSON_AddItemToArray(joined, player);
                    }
                }
            }
            // 只有非空才添加到 root
            if (cJSON_GetArraySize(joined) > 0) {
                cJSON_AddItemToObject(root, "joined", joined);
            } else {
                cJSON_Delete(joined);
            }
        }
        
        // 先收集 left 玩家，只有非空才添加到 JSON
        cJSON *left = cJSON_CreateArray();
        if (left) {
            for (int i = 0; i < MAX_TRACKED_PLAYERS; i++) {
                if (task->lastPlayers[i].active && 
                    (!task->players[i].active || task->players[i].userid != task->lastPlayers[i].userid)) {
                    cJSON *num = cJSON_CreateNumber(task->lastPlayers[i].userid);
                    if (num) {
                        cJSON_AddItemToArray(left, num);
                    }
                }
            }
            // 只有非空才添加到 root
            if (cJSON_GetArraySize(left) > 0) {
                cJSON_AddItemToObject(root, "left", left);
            } else {
                cJSON_Delete(left);
            }
        }
        
        // 先收集 renamed 玩家，只有非空才添加到 JSON
        cJSON *renamed = cJSON_CreateArray();
        if (renamed) {
            for (int i = 0; i < MAX_TRACKED_PLAYERS; i++) {
                if (task->players[i].active && task->lastPlayers[i].active && 
                    task->players[i].userid == task->lastPlayers[i].userid &&
                    Q_strcmp(task->players[i].name, task->lastPlayers[i].name) != 0) {
                    cJSON *player = cJSON_CreateObject();
                    if (player) {
                        cJSON_AddNumberToObject(player, "userid", task->players[i].userid);
                        // UTF-8 安全处理在 Worker 线程执行
                        Q_strncpy_utf8safe(safeName, task->players[i].name, sizeof(safeName));
                        cJSON_AddStringToObject(player, "name", safeName);
                        cJSON_AddItemToArray(renamed, player);
                    }
                }
            }
            // 只有非空才添加到 root
            if (cJSON_GetArraySize(renamed) > 0) {
                cJSON_AddItemToObject(root, "renamed", renamed);
            } else {
                cJSON_Delete(renamed);
            }
        }
    }
    
    int printResult = cJSON_PrintPreallocated(root, buf, bufsize, 0);
    cJSON_Delete(root);
    
    if (!printResult) {
        SafeSnprintf(buf, bufsize, "{\"type\":\"%s\",\"error\":\"truncated\"}",
            task->isFull ? "full" : "delta");
        g_nJsonTruncateCount.fetch_add(1, std::memory_order_relaxed);
        return false;
    }
    
    return true;
}

#ifdef _WIN32
static HANDLE g_hWorkerThread = NULL;
static HANDLE g_hTaskEvent = NULL;
#else
static pthread_t g_workerThread;
static sem_t g_semTask;  // 使用信号量代替条件变量，解决 Lost Wakeup 问题
static std::atomic<bool> g_bWorkerRunning{false};
#endif


// ============================================================================
// libcurl HTTP POST 实现
// ============================================================================

// 初始化 Worker 线程的 CURL handle（只调用一次）
static bool InitCurlHandle()
{
    if (g_pCurl) return true;
    
    g_pCurl = curl_easy_init();
    if (!g_pCurl) {
        QueueLog(false, "[PlayerReporter] ERROR: Failed to init CURL handle\n");
        return false;
    }
    
    // 使用共享的 headers（在 Init 中已创建）
    SetupCommonCurlOptions(g_pCurl, g_pSharedHeaders);
    
    // Worker 线程专用的额外选项
    curl_easy_setopt(g_pCurl, CURLOPT_TIMEOUT, 10L);  // 总超时 10 秒
    curl_easy_setopt(g_pCurl, CURLOPT_CONNECTTIMEOUT, 5L);  // 连接超时 5 秒
    
    // TCP Keep-Alive（长连接优化）
    curl_easy_setopt(g_pCurl, CURLOPT_TCP_KEEPALIVE, 1L);
    curl_easy_setopt(g_pCurl, CURLOPT_TCP_KEEPIDLE, 30L);
    curl_easy_setopt(g_pCurl, CURLOPT_TCP_KEEPINTVL, 10L);
    
    // 禁用 Nagle 算法（减少延迟）
    curl_easy_setopt(g_pCurl, CURLOPT_TCP_NODELAY, 1L);
    
    // 启用连接复用
    curl_easy_setopt(g_pCurl, CURLOPT_FORBID_REUSE, 0L);
    curl_easy_setopt(g_pCurl, CURLOPT_FRESH_CONNECT, 0L);
    
    // DNS 缓存 5 分钟
    curl_easy_setopt(g_pCurl, CURLOPT_DNS_CACHE_TIMEOUT, 300L);
    
    // 启用 gzip/deflate 压缩（服务器不支持则自动降级）
    curl_easy_setopt(g_pCurl, CURLOPT_ACCEPT_ENCODING, "gzip, deflate");
    
    QueueLog(true, "[PlayerReporter] CURL handle initialized\n");
    return true;
}

// 清理 CURL handle（Worker 线程专用资源）
static void CleanupCurlHandle()
{
    if (g_pCurl) {
        curl_easy_cleanup(g_pCurl);
        g_pCurl = NULL;
    }
    // 注意：g_pSharedHeaders 由主线程在 Shutdown 中清理
}

// 发送 HTTP POST 请求（错误信息写入 g_WorkerErrorBuf，成功时响应体写入 respBody）
static HttpResult SendHttpPost(const char *url, const char *json, char *respBody = NULL, int respBodySize = 0)
{
    g_WorkerErrorBuf[0] = '\0';  // 清空错误信息
    if (respBody && respBodySize > 0) {
        respBody[0] = '\0';  // 清空响应体
    }
    
    if (!url || !url[0] || !json || !json[0]) {
        Q_strncpy(g_WorkerErrorBuf, "Invalid parameters", sizeof(g_WorkerErrorBuf));
        return HttpResult::ERR_INVALID_PARAMS;
    }
    
    if (!InitCurlHandle()) {
        Q_strncpy(g_WorkerErrorBuf, "CURL init failed", sizeof(g_WorkerErrorBuf));
        return HttpResult::ERR_CURL_INIT;
    }
    
    // 缓存 JSON 长度（避免多次调用 strlen）
    size_t jsonLen = strlen(json);
    
    // 设置 URL
    curl_easy_setopt(g_pCurl, CURLOPT_URL, url);
    
    // 强制使用 HTTP/2（HTTPS 连接上尝试 HTTP/2，不支持则自动降级到 HTTP/1.1）
    curl_easy_setopt(g_pCurl, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_2TLS);
    
    // 设置 POST 数据
    curl_easy_setopt(g_pCurl, CURLOPT_POST, 1L);
    curl_easy_setopt(g_pCurl, CURLOPT_POSTFIELDS, json);
    curl_easy_setopt(g_pCurl, CURLOPT_POSTFIELDSIZE, (long)jsonLen);
    
    // headers 已在 InitCurlHandle() 中设置，无需每次重新创建
    
    // 响应数据
    CurlResponseData resp;
    memset(&resp, 0, sizeof(resp));
    curl_easy_setopt(g_pCurl, CURLOPT_WRITEDATA, &resp);
    
    // 执行请求
    CURLcode res = curl_easy_perform(g_pCurl);
    
    // 获取统计信息
    long httpCode = 0;
    curl_easy_getinfo(g_pCurl, CURLINFO_RESPONSE_CODE, &httpCode);
    
    double totalTime = 0;
    curl_easy_getinfo(g_pCurl, CURLINFO_TOTAL_TIME, &totalTime);
    
    long numConnects = 0;
    curl_easy_getinfo(g_pCurl, CURLINFO_NUM_CONNECTS, &numConnects);
    
    // 统计（使用缓存的 jsonLen）
    g_nTotalRequestsSent.fetch_add(1, std::memory_order_relaxed);
    g_nTotalBytesSent.fetch_add((int64_t)jsonLen, std::memory_order_relaxed);
    if (numConnects == 0) {
        g_nConnectionsReused.fetch_add(1, std::memory_order_relaxed);
    }
    
    // 检查 CURL 错误
    if (res != CURLE_OK) {
        const char *errStr = curl_easy_strerror(res);
        SafeSnprintf(g_WorkerErrorBuf, sizeof(g_WorkerErrorBuf), "CURL error: %s", errStr);
        
        if (res == CURLE_COULDNT_CONNECT || res == CURLE_COULDNT_RESOLVE_HOST) {
            g_nErrConnect.fetch_add(1, std::memory_order_relaxed);
            return HttpResult::ERR_CONNECT;
        } else if (res == CURLE_OPERATION_TIMEDOUT) {
            g_nErrTimeout.fetch_add(1, std::memory_order_relaxed);
            return HttpResult::ERR_TIMEOUT;
        }
        return HttpResult::ERR_CURL_PERFORM;
    }
    
    // 调试日志
    if (numConnects > 0) {
        QueueLog(true, "[PlayerReporter] New connection (%.2fms)\n", totalTime * 1000);
    } else {
        QueueLog(true, "[PlayerReporter] Connection reused (%.2fms)\n", totalTime * 1000);
    }
    
    // 检查 HTTP 状态码
    if (httpCode >= 200 && httpCode < 300) {
        // 成功时复制响应体
        if (respBody && respBodySize > 0 && resp.body_len > 0) {
            int copyLen = (resp.body_len < respBodySize - 1) ? resp.body_len : (respBodySize - 1);
            memcpy(respBody, resp.body, copyLen);
            respBody[copyLen] = '\0';
        }
        return HttpResult::OK;
    }
    
    // HTTP 错误处理
    g_nErrHttpStatus.fetch_add(1, std::memory_order_relaxed);
    
    if (httpCode == 429) {
        Q_strncpy(g_WorkerErrorBuf, "HTTP 429: Rate limited", sizeof(g_WorkerErrorBuf));
        g_nErrRateLimited.fetch_add(1, std::memory_order_relaxed);
        return HttpResult::ERR_RATE_LIMITED;
    } else if (httpCode == 503) {
        Q_strncpy(g_WorkerErrorBuf, "HTTP 503: Service unavailable", sizeof(g_WorkerErrorBuf));
        return HttpResult::ERR_SERVICE_UNAVAIL;
    } else if (httpCode == 401 || httpCode == 403) {
        SafeSnprintf(g_WorkerErrorBuf, sizeof(g_WorkerErrorBuf), "HTTP %ld: API key error", httpCode);
        g_nErrAuthFailed.fetch_add(1, std::memory_order_relaxed);
        return HttpResult::ERR_AUTH_FAILED;
    }
    
    // 其他错误
    if (resp.body_len > 0) {
        // 清理换行符
        for (int i = 0; i < resp.body_len; i++) {
            if (resp.body[i] == '\r' || resp.body[i] == '\n') {
                resp.body[i] = ' ';
            }
        }
        if (resp.body_len > 79) resp.body[79] = '\0';
        SafeSnprintf(g_WorkerErrorBuf, sizeof(g_WorkerErrorBuf), "HTTP %ld: %s", httpCode, resp.body);
    } else {
        SafeSnprintf(g_WorkerErrorBuf, sizeof(g_WorkerErrorBuf), "HTTP %ld", httpCode);
    }
    
    return HttpResult::ERR_HTTP_STATUS;
}


// ============================================================================
// 认证函数 - 启动时调用一次，获取 session token
// ============================================================================

/**
 * 执行服务器认证
 * 调用 /api/server/auth 接口，发送端口号，服务端根据 IP+端口 自动识别服务器
 * 
 * @return true 认证成功，false 认证失败
 */
static bool PerformAuthentication()
{
    // 获取服务器端口（从 hostport cvar）
    cvar_t *hostportCvar = Cvar_FindVar("hostport");
    int port = 27015;  // 默认端口
    if (hostportCvar && hostportCvar->value > 0) {
        port = (int)hostportCvar->value;
    }
    
    // 使用硬编码的认证 URL
    const char *authUrl = g_szAuthApiUrl;
    
    if (sv_reporter_debug.value != 0.0f) {
        Con_Printf("[PlayerReporter] Authenticating to %s (port=%d)\n", authUrl, port);
    }
    
    // 获取 hostname
    const char *hostname = "Unknown Server";
    if (g_pHostnameCvar && g_pHostnameCvar->string && g_pHostnameCvar->string[0]) {
        hostname = g_pHostnameCvar->string;
    }
    
    // 构建 JSON 请求体（需要转义 hostname 中的特殊字符）
    char jsonBody[256];
    cJSON *authJson = cJSON_CreateObject();
    if (authJson) {
        cJSON_AddNumberToObject(authJson, "port", port);
        cJSON_AddStringToObject(authJson, "hostname", hostname);
        if (!cJSON_PrintPreallocated(authJson, jsonBody, sizeof(jsonBody), 0)) {
            SafeSnprintf(jsonBody, sizeof(jsonBody), "{\"port\":%d}", port);
        }
        cJSON_Delete(authJson);
    } else {
        SafeSnprintf(jsonBody, sizeof(jsonBody), "{\"port\":%d}", port);
    }
    
    // 初始化 CURL
    CURL *pCurl = curl_easy_init();
    if (!pCurl) {
        if (sv_reporter_debug.value != 0.0f) {
            Con_Printf("[PlayerReporter] ERROR: Failed to init CURL for auth\n");
        }
        return false;
    }
    
    // 使用共享的 headers 和公共配置
    SetupCommonCurlOptions(pCurl, g_pSharedHeaders);
    
    // 设置 URL
    curl_easy_setopt(pCurl, CURLOPT_URL, authUrl);
    
    // POST 请求
    curl_easy_setopt(pCurl, CURLOPT_POST, 1L);
    curl_easy_setopt(pCurl, CURLOPT_POSTFIELDS, jsonBody);
    curl_easy_setopt(pCurl, CURLOPT_POSTFIELDSIZE, (long)strlen(jsonBody));
    
    // 认证专用的超时设置（比上报更长，因为是启动时）
    curl_easy_setopt(pCurl, CURLOPT_TIMEOUT, 15L);
    curl_easy_setopt(pCurl, CURLOPT_CONNECTTIMEOUT, 10L);
    
    // 响应数据
    CurlResponseData resp;
    memset(&resp, 0, sizeof(resp));
    curl_easy_setopt(pCurl, CURLOPT_WRITEDATA, &resp);
    
    // 执行请求
    CURLcode res = curl_easy_perform(pCurl);
    
    long httpCode = 0;
    curl_easy_getinfo(pCurl, CURLINFO_RESPONSE_CODE, &httpCode);
    
    // 清理（共享 headers 不需要清理，由 Shutdown 处理）
    curl_easy_cleanup(pCurl);
    
    // 检查 CURL 错误
    if (res != CURLE_OK) {
        if (sv_reporter_debug.value != 0.0f) {
            Con_Printf("[PlayerReporter] Auth failed: %s\n", curl_easy_strerror(res));
        }
        return false;
    }
    
    // 检查 HTTP 状态码
    if (httpCode != 200) {
        if (sv_reporter_debug.value != 0.0f) {
            Con_Printf("[PlayerReporter] Auth failed: HTTP %ld\n", httpCode);
            if (resp.body_len > 0) {
                Con_Printf("[PlayerReporter] Response: %s\n", resp.body);
            }
        }
        return false;
    }
    
    // 解析 JSON 响应
    cJSON *root = cJSON_Parse(resp.body);
    if (!root) {
        if (sv_reporter_debug.value != 0.0f) {
            Con_Printf("[PlayerReporter] Auth failed: Invalid JSON response\n");
        }
        return false;
    }
    
    // 检查 status
    cJSON *status = cJSON_GetObjectItem(root, "status");
    if (!status || !cJSON_IsString(status) || Q_strcmp(status->valuestring, "ok") != 0) {
        cJSON *message = cJSON_GetObjectItem(root, "message");
        const char *errMsg = (message && cJSON_IsString(message)) ? message->valuestring : "Unknown error";
        if (sv_reporter_debug.value != 0.0f) {
            Con_Printf("[PlayerReporter] Auth failed: %s\n", errMsg);
        }
        cJSON_Delete(root);
        return false;
    }
    
    // 获取 server_id
    cJSON *serverId = cJSON_GetObjectItem(root, "server_id");
    if (!serverId || !cJSON_IsNumber(serverId)) {
        if (sv_reporter_debug.value != 0.0f) {
            Con_Printf("[PlayerReporter] Auth failed: Missing server_id\n");
        }
        cJSON_Delete(root);
        return false;
    }
    
    // 检查是否是新注册的服务器
    cJSON *isNew = cJSON_GetObjectItem(root, "is_new");
    bool isNewServer = (isNew && cJSON_IsBool(isNew) && cJSON_IsTrue(isNew));
    
    // 保存认证结果
    g_nCachedServerId = (int)serverId->valuedouble;
    g_bAuthenticated = true;
    
    cJSON_Delete(root);
    
    if (sv_reporter_debug.value != 0.0f) {
        if (isNewServer) {
            Con_Printf("[PlayerReporter] New server registered! (server_id=%d)\n", g_nCachedServerId);
        } else {
            Con_Printf("[PlayerReporter] Authenticated successfully (server_id=%d)\n", g_nCachedServerId);
        }
    }
    
    return true;
}


// ============================================================================
// Worker 线程 - SPSC 无锁消费者
// ============================================================================

#ifdef _WIN32
static unsigned __stdcall WorkerThreadProc(void *p)
{
    // 使用 static 避免每次循环在栈上分配 32KB+
    // 单 Worker 线程模型下 static 是安全的
    static ReportTask taskCopy;
    
    while (!g_bIsShuttingDown.load(std::memory_order_acquire)) {
        // 等待事件或超时（1秒轮询）
        DWORD waitResult = WaitForSingleObject(g_hTaskEvent, 1000);
        
        if (g_bIsShuttingDown.load(std::memory_order_acquire)) break;
        
        // 处理队列中所有任务
        while (!g_bIsShuttingDown.load(std::memory_order_acquire)) {
            // SPSC 无锁读取：Worker 只读 tail，只写 head
            int head = g_nTaskHead.load(std::memory_order_relaxed);
            int tail = g_nTaskTail.load(std::memory_order_acquire);  // acquire 同步生产者的写入
            
            if (head == tail) break;  // 队列空
            
            // 复制任务数据（无锁，因为主线程不会修改已发布的槽位）
            Q_memcpy(&taskCopy, &g_TaskQueue[head], sizeof(ReportTask));
            
            // 更新 head（release 确保复制完成后才可见）
            int nextHead = (head + 1) % MAX_TASK_QUEUE;
            g_nTaskHead.store(nextHead, std::memory_order_release);
            
            // 检查任务是否过期
            double nowMono = MonotonicSeconds();
            double taskAge = nowMono - taskCopy.queuedMono;
            if (!taskCopy.isFull && taskAge > MAX_TASK_AGE) {
                g_nTaskExpired.fetch_add(1, std::memory_order_relaxed);
                g_bForceFullReport.store(true, std::memory_order_release);
                QueueLog(false, "[PlayerReporter] Delta task expired (age: %.1fs)\n", taskAge);
                continue;
            }
            
            // 在 Worker 线程中构建 JSON
            if (!BuildJsonFromTask(&taskCopy, g_WorkerJsonBuffer, sizeof(g_WorkerJsonBuffer))) {
                QueueLog(false, "[PlayerReporter] JSON build failed\n");
                g_bForceFullReport.store(true, std::memory_order_release);
                continue;
            }
            
            // 发送 HTTP 请求（full report 时获取响应体）
            char respBody[512] = "";
            HttpResult ret;
            if (taskCopy.isFull) {
                ret = SendHttpPost(taskCopy.url, g_WorkerJsonBuffer, respBody, sizeof(respBody));
            } else {
                ret = SendHttpPost(taskCopy.url, g_WorkerJsonBuffer);
            }
            
            // 解析响应中的 hostname（仅 full report 成功时）
            char parsedHostname[128] = "";
            if (ret == HttpResult::OK && taskCopy.isFull && respBody[0]) {
                cJSON *respJson = cJSON_Parse(respBody);
                if (respJson) {
                    cJSON *nameItem = cJSON_GetObjectItem(respJson, "name");
                    if (nameItem && cJSON_IsString(nameItem) && nameItem->valuestring && nameItem->valuestring[0]) {
                        Q_strncpy(parsedHostname, nameItem->valuestring, sizeof(parsedHostname));
                    }
                    cJSON_Delete(respJson);
                }
            }
            
            // 统计
            if (ret == HttpResult::OK) {
                if (taskCopy.isFull) g_nFullReportCount.fetch_add(1, std::memory_order_relaxed);
                else g_nDeltaReportCount.fetch_add(1, std::memory_order_relaxed);
            }
            
            if (ret != HttpResult::OK) {
                // 清空队列（SPSC：Worker 可以安全地移动 head 到 tail）
                int curTail = g_nTaskTail.load(std::memory_order_acquire);
                int curHead = g_nTaskHead.load(std::memory_order_relaxed);
                if (curHead != curTail) {
                    int dropped = (curTail - curHead + MAX_TASK_QUEUE) % MAX_TASK_QUEUE;
                    g_nTaskHead.store(curTail, std::memory_order_release);
                    g_nTaskDropped.fetch_add(dropped, std::memory_order_relaxed);
                    QueueLog(true, "[PlayerReporter] HTTP failed, dropped %d pending tasks\n", dropped);
                }
                g_bForceFullReport.store(true, std::memory_order_release);
            }
            
            // 提交结果到队列（包含错误信息和 hostname）
            int32_t resultCode = (ret == HttpResult::OK) ? 1 : static_cast<int32_t>(ret);
            QueueHttpResult(resultCode, taskCopy.isFull, g_WorkerErrorBuf, parsedHostname);
        }
    }
    
    CleanupCurlHandle();
    return 0;
}
#else
static void *WorkerThreadProc(void *p)
{
    // 使用 static 避免每次循环在栈上分配 32KB+
    // 单 Worker 线程模型下 static 是安全的
    static ReportTask taskCopy;
    
    // Linux: 使用信号量等待，解决 Lost Wakeup 问题
    // sem_wait 会阻塞直到信号量 > 0，然后原子减 1
    // sem_post 会原子加 1，即使没有线程在等待也会保留信号
    
    while (!g_bIsShuttingDown.load(std::memory_order_acquire)) {
        // 使用 sem_timedwait 实现 1 秒超时轮询
        struct timespec ts;
        clock_gettime(CLOCK_REALTIME, &ts);
        ts.tv_sec += 1;
        
        // sem_timedwait: 如果信号量 > 0 立即返回，否则等待直到超时
        // 这解决了 Lost Wakeup 问题：即使 sem_post 在我们开始等待之前调用，
        // 信号量计数也会增加，下次 sem_timedwait 会立即返回
        int waitResult = sem_timedwait(&g_semTask, &ts);
        // waitResult: 0 = 收到信号, -1 && errno == ETIMEDOUT = 超时
        (void)waitResult;  // 无论超时还是收到信号，都检查队列
        
        if (g_bIsShuttingDown.load(std::memory_order_acquire)) break;
        
        // 处理队列中所有任务
        while (!g_bIsShuttingDown.load(std::memory_order_acquire)) {
            // SPSC 无锁读取：Worker 只读 tail，只写 head
            int head = g_nTaskHead.load(std::memory_order_relaxed);
            int tail = g_nTaskTail.load(std::memory_order_acquire);  // acquire 同步生产者的写入
            
            if (head == tail) break;  // 队列空
            
            // 复制任务数据（无锁，因为主线程不会修改已发布的槽位）
            Q_memcpy(&taskCopy, &g_TaskQueue[head], sizeof(ReportTask));
            
            // 更新 head（release 确保复制完成后才可见）
            int nextHead = (head + 1) % MAX_TASK_QUEUE;
            g_nTaskHead.store(nextHead, std::memory_order_release);
            
            // 检查任务是否过期
            double nowMono = MonotonicSeconds();
            double taskAge = nowMono - taskCopy.queuedMono;
            if (!taskCopy.isFull && taskAge > MAX_TASK_AGE) {
                g_nTaskExpired.fetch_add(1, std::memory_order_relaxed);
                g_bForceFullReport.store(true, std::memory_order_release);
                QueueLog(false, "[PlayerReporter] Delta task expired (age: %.1fs)\n", taskAge);
                continue;
            }
            
            // 在 Worker 线程中构建 JSON
            if (!BuildJsonFromTask(&taskCopy, g_WorkerJsonBuffer, sizeof(g_WorkerJsonBuffer))) {
                QueueLog(false, "[PlayerReporter] JSON build failed\n");
                g_bForceFullReport.store(true, std::memory_order_release);
                continue;
            }
            
            // 发送 HTTP 请求（full report 时获取响应体）
            char respBody[512] = "";
            HttpResult ret;
            if (taskCopy.isFull) {
                ret = SendHttpPost(taskCopy.url, g_WorkerJsonBuffer, respBody, sizeof(respBody));
            } else {
                ret = SendHttpPost(taskCopy.url, g_WorkerJsonBuffer);
            }
            
            // 解析响应中的 hostname（仅 full report 成功时）
            char parsedHostname[128] = "";
            if (ret == HttpResult::OK && taskCopy.isFull && respBody[0]) {
                cJSON *respJson = cJSON_Parse(respBody);
                if (respJson) {
                    cJSON *nameItem = cJSON_GetObjectItem(respJson, "name");
                    if (nameItem && cJSON_IsString(nameItem) && nameItem->valuestring && nameItem->valuestring[0]) {
                        Q_strncpy(parsedHostname, nameItem->valuestring, sizeof(parsedHostname));
                    }
                    cJSON_Delete(respJson);
                }
            }
            
            // 统计
            if (ret == HttpResult::OK) {
                if (taskCopy.isFull) g_nFullReportCount.fetch_add(1, std::memory_order_relaxed);
                else g_nDeltaReportCount.fetch_add(1, std::memory_order_relaxed);
            }
            
            if (ret != HttpResult::OK) {
                // 清空队列（SPSC：Worker 可以安全地移动 head 到 tail）
                int curTail = g_nTaskTail.load(std::memory_order_acquire);
                int curHead = g_nTaskHead.load(std::memory_order_relaxed);
                if (curHead != curTail) {
                    int dropped = (curTail - curHead + MAX_TASK_QUEUE) % MAX_TASK_QUEUE;
                    g_nTaskHead.store(curTail, std::memory_order_release);
                    g_nTaskDropped.fetch_add(dropped, std::memory_order_relaxed);
                    QueueLog(true, "[PlayerReporter] HTTP failed, dropped %d pending tasks\n", dropped);
                }
                g_bForceFullReport.store(true, std::memory_order_release);
            }
            
            // 提交结果到队列（包含错误信息和 hostname）
            int32_t resultCode = (ret == HttpResult::OK) ? 1 : static_cast<int32_t>(ret);
            QueueHttpResult(resultCode, taskCopy.isFull, g_WorkerErrorBuf, parsedHostname);
        }
    }
    
    CleanupCurlHandle();
    g_bWorkerRunning.store(false, std::memory_order_release);
    return NULL;
}
#endif


// ============================================================================
// 主线程接口 - SPSC 无锁生产者
// ============================================================================

static void TriggerReport(bool full)
{
    double startTime = Sys_FloatTime();
    
    // ========================================================================
    // SPSC 无锁队列：主线程只写 tail，Worker 只写 head
    // 主线程操作只需要几微秒，完全不会造成卡顿
    // ========================================================================
    
    // 1. 读取当前队列状态
    int tail = g_nTaskTail.load(std::memory_order_relaxed);  // 主线程独占写 tail
    int head = g_nTaskHead.load(std::memory_order_acquire);  // acquire 同步 Worker 的更新
    int nextTail = (tail + 1) % MAX_TASK_QUEUE;
    
    // 2. 检查队列是否满
    if (nextTail == head) {
        g_nTaskDropped.fetch_add(1, std::memory_order_relaxed);
        g_bForceFullReport.store(true, std::memory_order_release);
        g_flNextReportTime = realtime + 3.0;
        if (sv_reporter_debug.value != 0.0f) {
            Con_Printf("[PlayerReporter] Task queue full, dropped task\n");
        }
        return;
    }
    
    // 3. 直接在队列槽位上构建任务数据（无锁，因为 Worker 不会访问未发布的槽位）
    ReportTask* pTask = &g_TaskQueue[tail];
    
    // 复制配置（使用硬编码的 URL 和认证后缓存的 serverId）
    Q_strncpy(pTask->url, g_szReportApiUrl, sizeof(pTask->url));
    pTask->serverId = g_nCachedServerId;
    Q_strncpy(pTask->mapName, g_psv.name, sizeof(pTask->mapName));
    pTask->maxPlayers = g_psvs.maxclients;
    pTask->queuedMono = MonotonicSeconds();
    
    // 检查地图是否变化
    bool mapChanged = Q_strcmp(g_szLastMap, g_psv.name) != 0;
    pTask->isFull = full || mapChanged;
    
    // 复制当前玩家快照
    Q_memset(pTask->players, 0, sizeof(pTask->players));
    for (int i = 0; i < g_psvs.maxclients && i < MAX_TRACKED_PLAYERS; i++) {
        client_t *cl = &g_psvs.clients[i];
        if (cl->active && !cl->fakeclient) {
            pTask->players[i].active = true;
            pTask->players[i].userid = cl->userid;
            // 直接读取 latency 字段（单位：秒），转换为毫秒，零开销
            pTask->players[i].ping = (int)(cl->latency * 1000.0f);
            // 存储原始名字，将 UTF-8 处理推迟到 Worker 线程
            Q_strncpy(pTask->players[i].name, cl->name, sizeof(pTask->players[i].name));
        }
    }
    
    // 复制上次玩家快照（用于 delta 计算）
    Q_memcpy(pTask->lastPlayers, g_LastPlayers, sizeof(pTask->lastPlayers));
    
    // 4. 更新全局快照状态（主线程独占）
    Q_memcpy(g_LastPlayers, pTask->players, sizeof(g_LastPlayers));
    if (mapChanged) {
        Q_strncpy(g_szLastMap, g_psv.name, sizeof(g_szLastMap));
    }
    
    // 5. 发布新的 tail（release 确保所有写入对 Worker 可见）
    g_nTaskTail.store(nextTail, std::memory_order_release);
    
    // 6. 通知 Worker 线程（这不是锁，只是唤醒信号）
#ifdef _WIN32
    SetEvent(g_hTaskEvent);
#else
    sem_post(&g_semTask);  // 信号量 +1，即使 Worker 没在等待也会保留
#endif
    
    // 性能日志（主线程操作应该 <1ms）
    double totalTime = (Sys_FloatTime() - startTime) * 1000.0;
    if (totalTime > 1.0 && sv_reporter_debug.value != 0.0f) {
        Con_Printf("[PlayerReporter] PERF: TriggerReport took %.2fms (should be <1ms)\n", totalTime);
    }
    
    if (sv_reporter_debug.value != 0.0f) {
        Con_Printf("[PlayerReporter] Queued %s report (lock-free)\n", pTask->isFull ? "full" : "delta");
    }
}

// 公开接口
void PlayerReporter_Init()
{
    if (g_bReporterInitialized) return;
    
    g_bIsShuttingDown.store(false, std::memory_order_release);
    (void)MonotonicSeconds();
    
    // 初始化 libcurl 全局状态
    curl_global_init(CURL_GLOBAL_ALL);
    
    // 创建共享的 HTTP headers（主线程创建，之后只读，无需加锁）
    CreateSharedHeaders();
    
    // 注册 cvar
    Cvar_RegisterVariable(&sv_reporter_interval);
    Cvar_RegisterVariable(&sv_reporter_full_interval);
    Cvar_RegisterVariable(&sv_reporter_debug);
    
    Cmd_AddCommand("reporter_stats", PlayerReporter_PrintStats);
    Cmd_AddCommand("reporter_reset", PlayerReporter_ResetStats);
    
    g_pHostnameCvar = Cvar_FindVar("hostname");
    
    Q_memset(g_LastPlayers, 0, sizeof(g_LastPlayers));
    g_szLastMap[0] = '\0';
    
    // 初始化任务队列
    Q_memset(g_TaskQueue, 0, sizeof(g_TaskQueue));
    g_nTaskHead.store(0, std::memory_order_release);
    g_nTaskTail.store(0, std::memory_order_release);
    g_nTaskDropped.store(0, std::memory_order_release);
    g_nTaskExpired.store(0, std::memory_order_release);
    g_nHttpRetryCount = 0;
    
    // 初始化结果队列
    Q_memset(g_ResultQueue, 0, sizeof(g_ResultQueue));
    g_nResultHead.store(0, std::memory_order_release);
    g_nResultTail.store(0, std::memory_order_release);
    
    // 重置统计
    g_nSuccessCount.store(0, std::memory_order_release);
    g_nFailureCount.store(0, std::memory_order_release);
    g_nFullReportCount.store(0, std::memory_order_release);
    g_nDeltaReportCount.store(0, std::memory_order_release);
    g_nJsonTruncateCount.store(0, std::memory_order_release);
    g_nTotalBytesSent.store(0, std::memory_order_release);
    g_nTotalRequestsSent.store(0, std::memory_order_release);
    g_nConnectionsReused.store(0, std::memory_order_release);
    g_nErrConnect.store(0, std::memory_order_release);
    g_nErrTimeout.store(0, std::memory_order_release);
    g_nErrHttpStatus.store(0, std::memory_order_release);
    g_nErrRateLimited.store(0, std::memory_order_release);
    g_nErrAuthFailed.store(0, std::memory_order_release);
    g_flLastSuccessTime = 0.0;
    g_flLastFailureTime = 0.0;
    g_flModuleStartTime = realtime;
    
#ifdef _WIN32
    // 完全无锁设计，只需要初始化事件和线程
    g_hTaskEvent = CreateEvent(NULL, FALSE, FALSE, NULL);
    g_hWorkerThread = (HANDLE)_beginthreadex(NULL, 0, WorkerThreadProc, NULL, 0, NULL);
#else
    // 初始化信号量（初始值 0）
    if (sem_init(&g_semTask, 0, 0) != 0) {
        if (sv_reporter_debug.value != 0.0f) {
            Con_Printf("[PlayerReporter] ERROR: Failed to init semaphore\n");
        }
        return;
    }
    g_bWorkerRunning.store(true, std::memory_order_release);
    if (pthread_create(&g_workerThread, NULL, WorkerThreadProc, NULL) != 0) {
        g_bWorkerRunning.store(false, std::memory_order_release);
        sem_destroy(&g_semTask);
    }
#endif
    
    g_bReporterInitialized = true;
    g_bForceFullReport.store(true, std::memory_order_release);
    
    // 获取 libcurl 版本信息
    if (sv_reporter_debug.value != 0.0f) {
        curl_version_info_data *ver = curl_version_info(CURLVERSION_NOW);
        Con_Printf("[PlayerReporter] Initialized with libcurl %s", ver->version);
        if (ver->features & CURL_VERSION_HTTP2) {
            Con_Printf(" (HTTP/2 supported)");
        }
        Con_Printf("\n");
    }
}

void PlayerReporter_Shutdown()
{
    if (!g_bReporterInitialized) return;
    
    // 检查是否是真正的服务器关闭（而不是换图）
    // 如果 g_psv.active 仍然为 true，说明只是换图，不需要完全关闭
    // 注意：这个检查可能不完全准确，但可以避免换图时关闭 Reporter
    
    g_bIsShuttingDown.store(true, std::memory_order_release);
    
#ifdef _WIN32
    if (g_hTaskEvent) SetEvent(g_hTaskEvent);
    
    if (g_hWorkerThread) {
        DWORD waitResult = WaitForSingleObject(g_hWorkerThread, 5000);
        if (waitResult == WAIT_TIMEOUT) {
            if (sv_reporter_debug.value != 0.0f) {
                Con_Printf("[PlayerReporter] WARNING: Worker thread timeout\n");
            }
            TerminateThread(g_hWorkerThread, 1);
        }
        CloseHandle(g_hWorkerThread);
        g_hWorkerThread = NULL;
    }
    if (g_hTaskEvent) {
        CloseHandle(g_hTaskEvent);
        g_hTaskEvent = NULL;
    }
    // 完全无锁设计，无需删除任何锁
#else
    // 唤醒 Worker 线程（信号量 +1 确保 Worker 能退出等待）
    sem_post(&g_semTask);
    
    if (g_bWorkerRunning.load(std::memory_order_acquire)) {
        pthread_join(g_workerThread, NULL);
    }
    
    sem_destroy(&g_semTask);
#endif
    
    // 清理共享的 HTTP headers
    DestroySharedHeaders();
    
    // 清理 libcurl
    curl_global_cleanup();
    
    g_bReporterInitialized = false;
    g_bAuthenticated = false;  // 重置认证状态，下次启动需要重新认证
    if (sv_reporter_debug.value != 0.0f) {
        Con_Printf("[PlayerReporter] Shutdown (SPSC lock-free)\n");
    }
}


void PlayerReporter_Frame()
{
    if (!g_bReporterInitialized) return;
    
    if (g_bReporterDisabled) return;
    
    ProcessLogQueue();
    
    // 处理 HTTP 结果队列 - SPSC 无锁
    while (true) {
        int head = g_nResultHead.load(std::memory_order_relaxed);  // 主线程独占写
        int tail = g_nResultTail.load(std::memory_order_acquire);  // acquire 同步 Worker 的写入
        
        if (head == tail) break;  // 队列空
        
        HttpResultEntry result = g_ResultQueue[head];
        int nextHead = (head + 1) % MAX_RESULT_QUEUE;
        g_nResultHead.store(nextHead, std::memory_order_release);
        
        int32_t httpResult = result.resultCode;
        bool lastWasFull = result.isFull;
        
        if (httpResult > 0) {
            if (sv_reporter_debug.value != 0.0f) {
                Con_Printf("[PlayerReporter] HTTP request succeeded (%s)\n", lastWasFull ? "full" : "delta");
            }
            g_nSuccessCount.fetch_add(1, std::memory_order_relaxed);
            g_flLastSuccessTime = realtime;
            g_nHttpRetryCount = 0;
            if (lastWasFull) g_nFullReportRetryCount = 0;
            
            // full report 成功时，检查并同步 hostname
            if (lastWasFull && result.hostname[0] && g_pHostnameCvar) {
                // 只有当 hostname 不同时才更新（避免不必要的 cvar 设置）
                if (Q_strcmp(g_pHostnameCvar->string, result.hostname) != 0) {
                    Cvar_DirectSet(g_pHostnameCvar, result.hostname);
                    if (sv_reporter_debug.value != 0.0f) {
                        Con_Printf("[PlayerReporter] Hostname synced: %s\n", result.hostname);
                    }
                }
            }
        } else {
            // 错误信息直接从结果队列获取（无锁）
            if (sv_reporter_debug.value != 0.0f) {
                Con_Printf("[PlayerReporter] HTTP failed: %s\n", result.errorMsg[0] ? result.errorMsg : "Unknown error");
            }
            g_nFailureCount.fetch_add(1, std::memory_order_relaxed);
            g_flLastFailureTime = realtime;
            
            g_nHttpRetryCount++;
            if (g_nHttpRetryCount > MAX_HTTP_RETRY_COUNT) {
                g_nHttpRetryCount = MAX_HTTP_RETRY_COUNT;
            }
            double backoffDelay = BASE_RETRY_DELAY * (1 << (g_nHttpRetryCount - 1));
            if (backoffDelay > MAX_RETRY_DELAY) backoffDelay = MAX_RETRY_DELAY;
            
            if (httpResult == static_cast<int>(HttpResult::ERR_RATE_LIMITED)) {
                g_bForceFullReport.store(true, std::memory_order_release);
                double rateBackoff = backoffDelay < 30.0 ? 30.0 : backoffDelay;
                g_flNextReportTime = realtime + rateBackoff;
                if (sv_reporter_debug.value != 0.0f) {
                    Con_Printf("[PlayerReporter] Rate limited, waiting %.0fs\n", rateBackoff);
                }
            } else if (httpResult == static_cast<int>(HttpResult::ERR_AUTH_FAILED)) {
                if (sv_reporter_debug.value != 0.0f) {
                    Con_Printf("[PlayerReporter] API key error! Reporter disabled.\n");
                }
                g_bReporterDisabled = true;
            } else if (!lastWasFull) {
                g_bForceFullReport.store(true, std::memory_order_release);
                g_flNextReportTime = realtime + 1.0;
            } else if (g_nFullReportRetryCount < MAX_FULL_REPORT_RETRIES) {
                g_nFullReportRetryCount++;
                g_bForceFullReport.store(true, std::memory_order_release);
                g_flNextReportTime = realtime + backoffDelay;
            }
        }
    }
    
    if (realtime < g_flNextReportTime) return;
    if (!g_bAuthenticated) return;
    
    float interval = sv_reporter_interval.value;
    if (interval < 0.1f) interval = 0.1f;
    g_flNextReportTime = realtime + interval;
    
    // 检测 cvar 变化
    float fullInterval = sv_reporter_full_interval.value;
    if (fullInterval < 1.0f) fullInterval = 1.0f;
    if (fullInterval != g_flLastFullInterval) {
        g_flNextFullReportTime = realtime + fullInterval;
        g_flLastFullInterval = fullInterval;
        if (sv_reporter_debug.value != 0.0f) {
            Con_Printf("[PlayerReporter] Full interval changed to %.0fs\n", fullInterval);
        }
    }
    
    bool needFull = g_bForceFullReport.load(std::memory_order_acquire) || (realtime >= g_flNextFullReportTime);
    
    if (needFull) {
        g_flNextFullReportTime = realtime + sv_reporter_full_interval.value;
        g_bForceFullReport.store(false, std::memory_order_release);
        TriggerReport(true);
    } else if (HasPlayerChanges()) {
        TriggerReport(false);
    }
}

void PlayerReporter_ServerActivated()
{
    // 执行认证（如果还没认证）
    if (!g_bAuthenticated) {
        if (sv_reporter_debug.value != 0.0f) {
            Con_Printf("[PlayerReporter] Authenticating...\n");
        }
        
        // 重试机制：最多重试 5 次，指数退避（1s, 2s, 4s, 8s, 16s）
        const int maxRetries = 5;
        int retryDelay = 1;  // 初始延迟 1 秒
        
        for (int attempt = 1; attempt <= maxRetries; attempt++) {
            if (PerformAuthentication()) {
                // 认证成功
                break;
            }
            
            if (attempt < maxRetries) {
                if (sv_reporter_debug.value != 0.0f) {
                    Con_Printf("[PlayerReporter] Authentication failed, retrying in %d seconds... (attempt %d/%d)\n", 
                        retryDelay, attempt, maxRetries);
                }
                
                // 阻塞等待（在主线程，但这是启动阶段，可以接受）
#ifdef _WIN32
                Sleep(retryDelay * 1000);
#else
                sleep(retryDelay);
#endif
                retryDelay *= 2;  // 指数退避
            } else {
                // 所有重试都失败，退出
                Sys_Error("[PlayerReporter] FATAL: Authentication failed after %d attempts!", maxRetries);
                return;  // 不会执行到这里
            }
        }
    }
    
    g_bForceFullReport.store(true, std::memory_order_release);
    g_nFullReportRetryCount = 0;
    g_flNextReportTime = realtime + 3.0;
    Q_memset(g_LastPlayers, 0, sizeof(g_LastPlayers));
    
    if (sv_reporter_debug.value != 0.0f) {
        Con_Printf("[PlayerReporter] Server activated (server_id=%d)\n", g_nCachedServerId);
    }
}

void PlayerReporter_ServerDeactivated()
{
    // libcurl 会自动管理连接
    if (sv_reporter_debug.value != 0.0f) {
        Con_Printf("[PlayerReporter] Server deactivated\n");
    }
}

void PlayerReporter_PrintStats()
{
    if (!g_bReporterInitialized) {
        if (sv_reporter_debug.value != 0.0f) {
            Con_Printf("[PlayerReporter] Not initialized\n");
        }
        return;
    }
    
    int queueSize = (g_nTaskTail.load() - g_nTaskHead.load() + MAX_TASK_QUEUE) % MAX_TASK_QUEUE;
    int successCount = g_nSuccessCount.load();
    int failureCount = g_nFailureCount.load();
    int totalRequests = successCount + failureCount;
    double successRate = (totalRequests > 0) ? (100.0 * successCount / totalRequests) : 0.0;
    double uptimeSeconds = realtime - g_flModuleStartTime;
    double lastSuccessAgo = (g_flLastSuccessTime > 0) ? (realtime - g_flLastSuccessTime) : -1.0;
    double lastFailureAgo = (g_flLastFailureTime > 0) ? (realtime - g_flLastFailureTime) : -1.0;
    
    Con_Printf("[PlayerReporter] Statistics (SPSC lock-free, libcurl):\n");
    Con_Printf("  Uptime: %.0f seconds\n", uptimeSeconds);
    Con_Printf("  Requests: %d (success: %d, failed: %d, rate: %.1f%%)\n", 
        g_nTotalRequestsSent.load(), successCount, failureCount, successRate);
    Con_Printf("  Connections reused: %d\n", g_nConnectionsReused.load());
    Con_Printf("  Data sent: %.2f KB\n", g_nTotalBytesSent.load() / 1024.0);
    Con_Printf("  Reports: full=%d, delta=%d\n",
        g_nFullReportCount.load(), g_nDeltaReportCount.load());
    Con_Printf("  Tasks dropped: %d, expired: %d\n", 
        g_nTaskDropped.load(), g_nTaskExpired.load());
    Con_Printf("  Queue size: %d/%d\n", queueSize, MAX_TASK_QUEUE - 1);
    Con_Printf("  HTTP retry count: %d/%d\n", g_nHttpRetryCount, MAX_HTTP_RETRY_COUNT);
    
    int errConnect = g_nErrConnect.load();
    int errTimeout = g_nErrTimeout.load();
    int errHttp = g_nErrHttpStatus.load();
    int errRate = g_nErrRateLimited.load();
    int errAuth = g_nErrAuthFailed.load();
    if (failureCount > 0) {
        Con_Printf("  Errors: connect=%d, timeout=%d, http=%d, rate_limit=%d, auth=%d\n",
            errConnect, errTimeout, errHttp, errRate, errAuth);
    }
    
    if (lastSuccessAgo >= 0) {
        Con_Printf("  Last success: %.1fs ago\n", lastSuccessAgo);
    } else {
        Con_Printf("  Last success: never\n");
    }
    if (lastFailureAgo >= 0) {
        Con_Printf("  Last failure: %.1fs ago\n", lastFailureAgo);
    }
    
    int jsonTruncate = g_nJsonTruncateCount.load();
    if (jsonTruncate > 0) {
        Con_Printf("  JSON truncations: %d (WARNING)\n", jsonTruncate);
    }
}

void PlayerReporter_ResetStats()
{
    if (!g_bReporterInitialized) {
        if (sv_reporter_debug.value != 0.0f) {
            Con_Printf("[PlayerReporter] Not initialized\n");
        }
        return;
    }
    
    g_nSuccessCount.store(0);
    g_nFailureCount.store(0);
    g_nFullReportCount.store(0);
    g_nDeltaReportCount.store(0);
    g_nJsonTruncateCount.store(0);
    g_nTotalBytesSent.store(0);
    g_nTotalRequestsSent.store(0);
    g_nConnectionsReused.store(0);
    g_nTaskDropped.store(0);
    g_nTaskExpired.store(0);
    g_nErrConnect.store(0);
    g_nErrTimeout.store(0);
    g_nErrHttpStatus.store(0);
    g_nErrRateLimited.store(0);
    g_nErrAuthFailed.store(0);
    g_flLastSuccessTime = 0.0;
    g_flLastFailureTime = 0.0;
    g_flModuleStartTime = realtime;
    g_nHttpRetryCount = 0;
    
    if (sv_reporter_debug.value != 0.0f) {
        Con_Printf("[PlayerReporter] Statistics reset\n");
    }
}
