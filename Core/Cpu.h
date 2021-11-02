
#if (defined(DUMMYCPU) && !defined(__DUMMYCPU__H)) || (!defined(DUMMYCPU) && !defined(__CPU__H))
#ifdef DUMMYCPU
#define __DUMMYCPU__H
#else
#define __CPU__H
#endif

#include "stdafx.h"
#include "CpuTypes.h"
#include "../Utilities/ISerializable.h"

class MemoryMappings;
class MemoryManager;
class DmaController;
class Console;

class Cpu : public ISerializable
{
private:
	static constexpr uint32_t NmiVector = 0x00FFEA;
	static constexpr uint32_t ResetVector = 0x00FFFC;
	static constexpr uint32_t IrqVector = 0x00FFEE;
	static constexpr uint32_t AbortVector = 0x00FFE8;
	static constexpr uint32_t BreakVector = 0x00FFE6;
	static constexpr uint32_t CoprocessorVector = 0x00FFE4;

	static constexpr uint16_t LegacyNmiVector = 0xFFFA;
	static constexpr uint32_t LegacyIrqVector = 0xFFFE;
	static constexpr uint32_t LegacyCoprocessorVector = 0x00FFF4;

	typedef void(Cpu::*Func)();
	
	MemoryManager *_memoryManager = nullptr;
	DmaController *_dmaController = nullptr;
	Console *_console = nullptr;

	bool _immediateMode = false;

	CpuState _state = {};
	uint32_t _operand = -1;

	uint32_t GetProgramAddress(uint16_t addr);
	uint32_t GetDataAddress(uint16_t addr);

	uint16_t GetDirectAddress(uint16_t offset, bool allowEmulationMode = true);

	uint16_t GetDirectAddressIndirectWord(uint16_t offset, bool allowEmulationMode = true);
	uint32_t GetDirectAddressIndirectLong(uint16_t offset, bool allowEmulationMode = true);
	
	uint8_t GetOpCode();
	
	uint16_t GetResetVector();

	void UpdateIrqNmiFlags();
	void ProcessCpuCycle();

	void Idle();
	void IdleOrRead();
	void IdleEndJump();
	void IdleTakeBranch();
	
	uint8_t ReadOperandByte();
	uint16_t ReadOperandWord();
	uint32_t ReadOperandLong();

	uint16_t ReadVector(uint16_t vector);

	uint8_t Read(uint32_t addr, MemoryOperationType type);

	void SetSP(uint16_t sp);
	void SetPS(uint8_t ps);

	void SetRegister(uint8_t &reg, uint8_t value);
	void SetRegister(uint16_t &reg, uint16_t value, bool eightBitMode);
	
	void SetZeroNegativeFlags(uint16_t value);
	void SetZeroNegativeFlags(uint8_t value);

	void ClearFlags(uint8_t flags);
	void SetFlags(uint8_t flags);
	bool CheckFlag(uint8_t flag);

	uint8_t ReadCode(uint16_t addr, MemoryOperationType type = MemoryOperationType::Read);
	uint16_t ReadCodeWord(uint16_t addr, MemoryOperationType type = MemoryOperationType::Read);

	uint8_t ReadData(uint32_t addr, MemoryOperationType type = MemoryOperationType::Read);
	uint16_t ReadDataWord(uint32_t addr, MemoryOperationType type = MemoryOperationType::Read);
	uint32_t ReadDataLong(uint32_t addr, MemoryOperationType type = MemoryOperationType::Read);

	void Write(uint32_t addr, uint8_t value, MemoryOperationType type = MemoryOperationType::Write);
	void WriteWord(uint32_t addr, uint16_t value, MemoryOperationType type = MemoryOperationType::Write);

	uint8_t GetByteValue();

	uint16_t GetWordValue();

	void PushByte(uint8_t value);
	uint8_t PopByte();

	void PushWord(uint16_t value);
	uint16_t PopWord();

	//Add/substract instructions
	void Add8(uint8_t value);
	void Add16(uint16_t value);
	void ADC();

	void Sub8(uint8_t value);
	void Sub16(uint16_t value);
	void SBC();
	
	//Branch instructions
	void BCC();
	void BCS();
	void BEQ();
	void BMI();
	void BNE();
	void BPL();
	void BRA();
	void BRL();
	void BVC();
	void BVS();
	void BranchRelative(bool branch);
	
	//Set/clear flag instructions
	void CLC();
	void CLD();
	void CLI();
	void CLV();
	void SEC();
	void SED();
	void SEI();

	void REP();
	void SEP();

	//Increment/decrement instructions
	void DEX();
	void DEY();
	void INX();
	void INY();
	void DEC();
	void INC();

	void DEC_Acc();
	void INC_Acc();

	void IncDecReg(uint16_t & reg, int8_t offset);
	void IncDec(int8_t offset);

	//Compare instructions
	void Compare(uint16_t reg, bool eightBitMode);
	void CMP();
	void CPX();
	void CPY();

	//Jump instructions
	void JML();
	void JMP();
	void JSL();
	void JSR();
	void RTI();
	void RTL();
	void RTS();

	//Interrupts
	void ProcessInterrupt(uint16_t vector, bool forHardwareInterrupt);
	void BRK();
	void COP();

	//Bitwise operations
	void AND();
	void EOR();
	void ORA();

	template<typename T> T ShiftLeft(T value);
	template<typename T> T RollLeft(T value);
	template<typename T> T ShiftRight(T value);
	template<typename T> T RollRight(T value);

	//Shift operations
	void ASL_Acc();
	void ASL();
	void LSR_Acc();
	void LSR();
	void ROL_Acc();
	void ROL();
	void ROR_Acc();
	void ROR();

	//Move operations
	void MVN();
	void MVP();

	//Push/pull instructions
	void PEA();
	void PEI();
	void PER();
	void PHB();
	void PHD();
	void PHK();
	void PHP();
	void PLB();
	void PLD();
	void PLP();

	void PHA();
	void PHX();
	void PHY();
	void PLA();
	void PLX();
	void PLY();

	void PushRegister(uint16_t reg, bool eightBitMode);
	void PullRegister(uint16_t &reg, bool eightBitMode);

	//Store/load instructions
	void LoadRegister(uint16_t &reg, bool eightBitMode);
	void StoreRegister(uint16_t val, bool eightBitMode);

	void LDA();
	void LDX();
	void LDY();

	void STA();
	void STX();
	void STY();
	void STZ();
		
	//Test bits
	template<typename T> void TestBits(T value, bool alterZeroFlagOnly);
	void BIT();

	void TRB();
	void TSB();

	//Transfer registers
	void TAX();
	void TAY();
	void TCD();
	void TCS();
	void TDC();
	void TSC();
	void TSX();
	void TXA();
	void TXS();
	void TXY();
	void TYA();
	void TYX();
	void XBA();
	void XCE();

	//No operation
	void NOP();
	void WDM();

	//Misc.
	void STP();
	void WAI();

	//Addressing modes
	//Absolute: a
	void AddrMode_Abs();
	//Absolute Indexed: a,x
	void AddrMode_AbsIdxX(bool isWrite);
	//Absolute Indexed: a,y
	void AddrMode_AbsIdxY(bool isWrite);
	//Absolute Long: al
	void AddrMode_AbsLng();
	//Absolute Long Indexed: al,x
	void AddrMode_AbsLngIdxX();

	void AddrMode_AbsJmp();
	void AddrMode_AbsLngJmp();
	void AddrMode_AbsIdxXInd(); //JMP/JSR
	void AddrMode_AbsInd(); //JMP only
	void AddrMode_AbsIndLng(); //JML only

	void AddrMode_Acc();

	void AddrMode_BlkMov();

	uint8_t ReadDirectOperandByte();
	
	//Direct: d
	void AddrMode_Dir();
	//Direct Indexed: d,x
	void AddrMode_DirIdxX();
	//Direct Indexed: d,y
	void AddrMode_DirIdxY();
	//Direct Indirect: (d)
	void AddrMode_DirInd();
	
	//Direct Indexed Indirect: (d,x)
	void AddrMode_DirIdxIndX();
	//Direct Indirect Indexed: (d),y
	void AddrMode_DirIndIdxY(bool isWrite);
	//Direct Indirect Long: [d]
	void AddrMode_DirIndLng();
	//Direct Indirect Indexed Long: [d],y
	void AddrMode_DirIndLngIdxY();

	void AddrMode_Imm8();
	void AddrMode_Imm16();
	void AddrMode_ImmX();
	void AddrMode_ImmM();

	void AddrMode_Imp();

	void AddrMode_RelLng();
	void AddrMode_Rel();

	void AddrMode_StkRel();
	void AddrMode_StkRelIndIdxY();
	
	void RunOp();

public:
#ifndef DUMMYCPU
	Cpu(Console *console);
#else
	DummyCpu(Console* console, CpuType type);
#endif

	virtual ~Cpu();

	void PowerOn();

	void Reset();
	void Exec();

	CpuState GetState();
	uint64_t GetCycleCount();
	void SetState(CpuState& state)
	{
		_state = state;
	}

	template<uint64_t value>
	void IncreaseCycleCount();

	void SetNmiFlag(bool nmiFlag);
	void DetectNmiSignalEdge();

	void SetIrqSource(IrqSource source);
	bool CheckIrqSource(IrqSource source);
	void ClearIrqSource(IrqSource source);

	// Inherited via ISerializable
	void Serialize(Serializer &s) override;

#ifdef DUMMYCPU
private:
	MemoryMappings* _memoryMappings;
	uint32_t _writeCounter = 0;
	uint32_t _writeAddresses[10];
	uint8_t _writeValue[10];

	uint32_t _readCounter = 0;
	uint32_t _readAddresses[10];
	uint8_t _readValue[10];

	void LogRead(uint32_t addr, uint8_t value);
	void LogWrite(uint32_t addr, uint8_t value);

public:
	void SetDummyState(CpuState &state);
	int32_t GetLastOperand();

	uint32_t GetWriteCount();
	uint32_t GetReadCount();
	void GetWriteInfo(uint32_t index, uint32_t &addr, uint8_t &value);
	void GetReadInfo(uint32_t index, uint32_t &addr, uint8_t &value);
#endif
};

template<uint64_t count>
void Cpu::IncreaseCycleCount()
{
	_state.CycleCount += count;
}

#endif