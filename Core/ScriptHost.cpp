#include "stdafx.h"
#include "ScriptHost.h"
#include "ScriptingContext.h"
#include "EventType.h"

#ifndef LIBRETRO
#include "LuaScriptingContext.h"
#endif

ScriptHost::ScriptHost(int scriptId)
{
	_scriptId = scriptId;
}

int ScriptHost::GetScriptId()
{
	return _scriptId;
}

const char* ScriptHost::GetLog()
{
	shared_ptr<ScriptingContext> context = _context;
	return context ? context->GetLog() : "";
}

void ScriptHost::AttachScript(shared_ptr<ScriptingContext> context)
{
	_context = context;
}

bool ScriptHost::LoadScript(string scriptName, string scriptContent, Debugger* debugger)
{
#ifndef LIBRETRO
	LuaScriptingContext* context = new LuaScriptingContext(debugger);
	_context.reset(context);
	if(!context->LoadScript(scriptName, scriptContent, debugger)) {
		return false;
	}
	return true;
#else
	return false;
#endif
}

void ScriptHost::ProcessMemoryOperation(uint32_t addr, uint8_t &value, MemoryOperationType type, CpuType cpuType)
{
	if(_context) {
		switch(type) {
			case MemoryOperationType::Read: _context->CallMemoryCallback(addr, value, CallbackType::CpuRead, cpuType); break;
			case MemoryOperationType::Write: _context->CallMemoryCallback(addr, value, CallbackType::CpuWrite, cpuType); break;
			case MemoryOperationType::ExecOpCode: _context->CallMemoryCallback(addr, value, CallbackType::CpuExec, cpuType); break;
			default: break;
		}
	}
}

void ScriptHost::ProcessEvent(EventType eventType)
{
	if(_context) {
		_context->CallEventCallback(eventType);
	}
}

bool ScriptHost::ProcessSavestate()
{
	if(_context) {
		return _context->ProcessSavestate();
	}
	return false;
}

bool ScriptHost::CheckStateLoadedFlag()
{
	if(_context) {
		return _context->CheckStateLoadedFlag();
	}
	return false;
}
