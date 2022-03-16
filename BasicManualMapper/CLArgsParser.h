#pragma once

#include <tchar.h>
#include <map>
#include <string>
#include <vector>
#include <functional>

using ProcessArgFunc = std::function<void(const std::vector<std::string>& args)>;

struct ArgHandler
{
	int m_NumArgs = 0;
	ProcessArgFunc m_Handler = nullptr;
};

struct CLArgsParser
{
	static std::map<std::string, ArgHandler> ArgToHandlerMap;
	static void RegisterArg(const char* arg, ArgHandler handler);
	static void ProcessArgs(char** args, int numArgs);
};