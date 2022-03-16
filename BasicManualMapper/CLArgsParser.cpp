#include "CLArgsParser.h"
#include "logger.h"
#include <iostream>

std::map<std::string, ArgHandler> CLArgsParser::ArgToHandlerMap = {};

void CLArgsParser::RegisterArg(const char* arg, ArgHandler handler)
{
	ArgToHandlerMap[arg] = handler;
}


void CLArgsParser::ProcessArgs(char** args, int numArgs)
{
	for (int argIndex = 1; argIndex < numArgs; argIndex++)
	{
		char* arg = args[argIndex];
		LOG_INFO("Checking for arg handler for '{}'", args[argIndex]);
		std::map<std::string, ArgHandler>::iterator match = ArgToHandlerMap.find(arg);
		if (match == ArgToHandlerMap.end())
		{
			LOG_WARN("Could not find arg handler for '{}'. Skipping.", args[argIndex]);
			continue;
		}

		// collect all of this arg's sub args to pass to its handler
		if ((argIndex + 1 + match->second.m_NumArgs) > numArgs)
		{
			LOG_WARN("Arg handler for '{}' expected '{}' args but not that many are available. Skipping.", arg, match->second.m_NumArgs);
			continue;
		}
		std::vector<std::string> subArgs{};
		int subArgIndex;
		for (subArgIndex = argIndex + 1; subArgIndex < (argIndex + 1 + match->second.m_NumArgs); subArgIndex++)
		{
			subArgs.push_back(args[subArgIndex]);
		}

		// call the handler now
		match->second.m_Handler(subArgs);
		// skip to next real arg
		argIndex = subArgIndex - 1;
	}
}