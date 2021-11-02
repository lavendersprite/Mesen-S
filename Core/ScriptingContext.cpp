#include "stdafx.h"
#include <algorithm>
#include "ScriptingContext.h"
#include "DebugTypes.h"
#include "Debugger.h"
#include "Console.h"
#include "SaveStateManager.h"
#include "MemoryMappings.h"
#include "MemoryManager.h"
#include <set>

string ScriptingContext::_log = "";

#define DIRECT_ACCESS_VALUE 0xFFFFFFFF

ScriptingContext::ScriptingContext(Debugger *debugger)
{
	_debugger = debugger;
}

void ScriptingContext::Log(string message)
{
	auto lock = _logLock.AcquireSafe();
	_logRows.push_back(message);
	if(_logRows.size() > 500) {
		_logRows.pop_front();
	}
}

const char* ScriptingContext::GetLog()
{
	auto lock = _logLock.AcquireSafe();
	stringstream ss;
	for(string &msg : _logRows) {
		ss << msg << "\n";
	}
	_log = ss.str();
	return _log.c_str();
}

Debugger* ScriptingContext::GetDebugger()
{
	return _debugger;
}

string ScriptingContext::GetScriptName()
{
	return _scriptName;
}

void ScriptingContext::CallMemoryCallback(uint32_t addr, uint8_t &value, CallbackType type, CpuType cpuType)
{
	if (_callbacks[(int)type].empty())
	{
		return;
	}
	
	AddressInfo addrInfo = GetAddressInfo(addr);
	
	// references already visited; we shouldn't invoke multiple times.
	std::set<int> visited;
	
	for (MemoryCallback& callback : _callbacks[(int)type])
	{
		if (callback.Type != cpuType) continue;
		
		bool shouldVisit = false;
		if (callback.RequestedStartAddr <= addr && addr < callback.RequestedEndAddr)
		{
			shouldVisit = true;
		}
		else if (callback.MemoryType == addrInfo.Type && (int)callback.StartAddress <= addrInfo.Address && addrInfo.Address < (int)callback.EndAddress)
		{
			shouldVisit = true;
		}
	
		if (shouldVisit)
		{
			if (!callback.multiReference)
			{
				if (visited.find(callback.Reference) != visited.end())
				{
					// we've already visited this reference.
					continue;
				}
				else
				{
					// make a note not to visit this reference again.
					visited.emplace(callback.Reference);
				}
			}
			
			// run the callback.
			_inExecOpEvent = type == CallbackType::CpuExec;
			InternalCallMemoryCallback(addr, value, type, callback);
		}
	}
	
	_inExecOpEvent = false;
}

int ScriptingContext::CallEventCallback(EventType type)
{
	_inStartFrameEvent = type == EventType::StartFrame;
	int returnValue = InternalCallEventCallback(type);
	_inStartFrameEvent = false;

	return returnValue;
}

bool ScriptingContext::CheckInitDone()
{
	return _initDone;
}

bool ScriptingContext::CheckInStartFrameEvent()
{
	return _inStartFrameEvent;
}

bool ScriptingContext::CheckInExecOpEvent()
{
	return _inExecOpEvent;
}

bool ScriptingContext::CheckStateLoadedFlag()
{
	bool stateLoaded = _stateLoaded;
	_stateLoaded = false;
	return stateLoaded;
}

void ScriptingContext::RegisterMemoryCallback(CallbackType type, int startAddr, int endAddr, CpuType cpuType, int reference, bool directOnly)
{
	if(endAddr < startAddr) {
		return;
	}

	if(startAddr == 0 && endAddr == 0) {
		endAddr = 0xFFFFFF;
	}
	
	// add a direct memory callback; this will always fire if the memory address is accessed directly.
	{
		MemoryCallback callback;
		callback.StartAddress = (uint32_t)startAddr;
		callback.EndAddress = (uint32_t)endAddr;
		callback.RequestedStartAddr = startAddr;
		callback.RequestedEndAddr = endAddr;
		callback.DirectAccess = DIRECT_ACCESS_VALUE;
		callback.Type = cpuType;
		callback.Reference = reference;
		callback.multiReference = directOnly;
		_callbacks[(int)type].push_back(callback);
		
		for (uint32_t addr = callback.StartAddress; addr < callback.EndAddress; ++addr)
		{
			_debugger->WatchMemory(addr);
		}
	}
	
	if (!directOnly)
	{
		// sometimes the memory can be accessed indirectly. So we place watchpoints at the mapped region.
		// Because one memory callback cannot straddle the boundary of a memory region, we have to 
		// split at each boundary point.
		MemoryMappings* const memoryMap = _debugger->GetConsole()->GetMemoryManager()->GetMemoryMappings();
		AddressInfo startAddrInfo = memoryMap->GetAbsoluteAddress(startAddr);
		for (int addr = startAddr + 1; addr <= endAddr; ++addr)
		{
			if (addr == endAddr || memoryMap->GetAbsoluteAddress(addr).Type != startAddrInfo.Type)
			{
				if (startAddrInfo.Address >= 0)
				{
					MemoryCallback callback;
					callback.StartAddress = (uint32_t)startAddrInfo.Address;
					callback.EndAddress = (uint32_t)memoryMap->GetAbsoluteAddress(addr - 1).Address + 1;
					callback.MemoryType = startAddrInfo.Type;
					callback.Reference = reference;
					callback.Type = cpuType;
					callback.RequestedStartAddr = startAddr;
					callback.RequestedEndAddr = endAddr;
					callback.multiReference = directOnly;
					_callbacks[(int)type].push_back(callback);
					
					for (uint32_t addr = callback.StartAddress; addr < callback.EndAddress; ++addr)
					{
						_debugger->WatchMemory(addr);
					}
				}
				
				if (addr != endAddr)
				// set new start-of-region boundary for next iterations.
				{
					startAddrInfo = memoryMap->GetAbsoluteAddress(addr);
				}
			}
		}
	}
}

void ScriptingContext::UnregisterMemoryCallback(CallbackType type, int startAddr, int endAddr, CpuType cpuType, int reference, bool directOnly)
{
	if(endAddr < startAddr) {
		return;
	}

	if(startAddr == 0 && endAddr == 0) {
		endAddr = 0xFFFFFF;
	}

	for(size_t i = 0; i < _callbacks[(int)type].size(); i++) {
		MemoryCallback &callback = _callbacks[(int)type][i];
		
		// remove reference.
		if (callback.Reference == reference && callback.Type == cpuType && (int)callback.RequestedStartAddr == startAddr && (int)callback.RequestedEndAddr == endAddr) {
			
			for (uint32_t addr = callback.StartAddress; addr < callback.EndAddress; ++addr)
			{
				_debugger->UnwatchMemory(addr);
			}
			
			_callbacks[(int)type].erase(_callbacks[(int)type].begin() + i);
			
			if (directOnly) break;
		}
	}
}

void ScriptingContext::RegisterEventCallback(EventType type, int reference)
{
	_eventCallbacks[(int)type].push_back(reference);
}

void ScriptingContext::UnregisterEventCallback(EventType type, int reference)
{
	vector<int> &callbacks = _eventCallbacks[(int)type];
	callbacks.erase(std::remove(callbacks.begin(), callbacks.end(), reference), callbacks.end());
}

void ScriptingContext::RequestSaveState(int slot)
{
	_saveSlot = slot;
	if(_inExecOpEvent) {
		SaveState();
	} else {
		_saveSlotData.erase(slot);
	}
}

bool ScriptingContext::RequestLoadState(int slot)
{
	if(_saveSlotData.find(slot) != _saveSlotData.end()) {
		_loadSlot = slot;
		if(_inExecOpEvent) {
			return LoadState();
		} else {
			return true;
		}
	}
	return false;
}

void ScriptingContext::SaveState()
{
	if(_saveSlot >= 0) {
		stringstream ss;
		_debugger->GetConsole()->GetSaveStateManager()->SaveState(ss);
		_saveSlotData[_saveSlot] = ss.str();
		_saveSlot = -1;
	}
}

bool ScriptingContext::LoadState()
{
	if(_loadSlot >= 0 && _saveSlotData.find(_loadSlot) != _saveSlotData.end()) {
		stringstream ss;
		ss << _saveSlotData[_loadSlot];
		bool result = _debugger->GetConsole()->GetSaveStateManager()->LoadState(ss);
		_loadSlot = -1;
		if(result) {
			_stateLoaded = true;
		}
		return result;
	}
	return false;
}

bool ScriptingContext::LoadState(string stateData)
{
	stringstream ss;
	ss << stateData;
	bool result = _debugger->GetConsole()->GetSaveStateManager()->LoadState(ss);
	if(result) {
		_stateLoaded = true;
	}
	return result;
}

bool ScriptingContext::ProcessSavestate()
{
	SaveState();
	return LoadState();
}

string ScriptingContext::GetSavestateData(int slot)
{
	if(slot >= 0) {
		auto result = _saveSlotData.find(slot);
		if(result != _saveSlotData.end()) {
			return result->second;
		}
	}

	return "";
}

void ScriptingContext::ClearSavestateData(int slot)
{
	if(slot >= 0) {
		_saveSlotData.erase(slot);
	}
}

inline AddressInfo ScriptingContext::GetAddressInfo(uint32_t addr)
{
	return _debugger->GetConsole()->GetMemoryManager()->GetMemoryMappings()->GetAbsoluteAddress(addr);
}