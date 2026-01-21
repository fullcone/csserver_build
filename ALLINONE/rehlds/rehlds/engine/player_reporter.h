/*
*    Player Reporter Module for ReHLDS
*    定时上报服务器玩家信息到 Web API
*/

#pragma once

// 初始化上报模块
void PlayerReporter_Init();

// 关闭上报模块
void PlayerReporter_Shutdown();

// 每帧调用，检查是否需要上报
void PlayerReporter_Frame();

// 服务器激活时调用（地图加载完成）
void PlayerReporter_ServerActivated();

// 服务器关闭时调用
void PlayerReporter_ServerDeactivated();

// 打印统计信息（可通过控制台命令调用）
// 控制台命令: reporter_stats
void PlayerReporter_PrintStats();

// 重置统计信息（可通过控制台命令调用）
// 控制台命令: reporter_reset
void PlayerReporter_ResetStats();
