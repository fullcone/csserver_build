/*
 * Remote Agent Loader for ReHLDS
 * 
 * 在 hlds_linux 启动时加载 remote_agent.so 动态库
 * Agent 运行在独立线程中，不阻塞游戏服务器主线程
 */

#include "precompiled.h"
#include <dlfcn.h>
#include <string.h>

// Agent 函数指针类型
typedef void (*RemoteAgent_Init_t)(int argc, char **argv);
typedef void (*RemoteAgent_Shutdown_t)(void);
typedef int (*RemoteAgent_IsRunning_t)(void);

// Agent 状态（静态变量，文件作用域）
static void *g_pRemoteAgentLib = nullptr;
static RemoteAgent_Init_t g_pfnRemoteAgent_Init = nullptr;
static RemoteAgent_Shutdown_t g_pfnRemoteAgent_Shutdown = nullptr;

// 加载 Remote Agent 动态库
// Agent 永远启用，只要 .so 文件存在就加载
bool LoadRemoteAgent(int argc, char **argv)
{
    // 尝试加载 remote_agent.so
    const char *agentPaths[] = {
        "./remote_agent.so",           // 当前目录
        "./addons/remote_agent.so",    // addons 目录
        "../remote_agent.so",          // 上级目录
        nullptr
    };
    
    for (int i = 0; agentPaths[i] != nullptr; i++) {
        g_pRemoteAgentLib = dlopen(agentPaths[i], RTLD_NOW | RTLD_LOCAL);
        if (g_pRemoteAgentLib) {
            printf("[RemoteAgent] Loaded from: %s\n", agentPaths[i]);
            break;
        }
    }
    
    if (!g_pRemoteAgentLib) {
        printf("[RemoteAgent] Warning: Could not load remote_agent.so: %s\n", dlerror());
        printf("[RemoteAgent] Agent feature disabled\n");
        return false;
    }
    
    // 获取函数指针
    g_pfnRemoteAgent_Init = (RemoteAgent_Init_t)dlsym(g_pRemoteAgentLib, "RemoteAgent_Init");
    g_pfnRemoteAgent_Shutdown = (RemoteAgent_Shutdown_t)dlsym(g_pRemoteAgentLib, "RemoteAgent_Shutdown");
    
    if (!g_pfnRemoteAgent_Init) {
        printf("[RemoteAgent] Error: RemoteAgent_Init not found\n");
        dlclose(g_pRemoteAgentLib);
        g_pRemoteAgentLib = nullptr;
        return false;
    }
    
    // 调用初始化函数（非阻塞，立即返回）
    g_pfnRemoteAgent_Init(argc, argv);
    
    return true;
}

// 卸载 Remote Agent
void UnloadRemoteAgent()
{
    if (g_pfnRemoteAgent_Shutdown) {
        g_pfnRemoteAgent_Shutdown();
    }
    
    if (g_pRemoteAgentLib) {
        dlclose(g_pRemoteAgentLib);
        g_pRemoteAgentLib = nullptr;
        printf("[RemoteAgent] Unloaded\n");
    }
}
