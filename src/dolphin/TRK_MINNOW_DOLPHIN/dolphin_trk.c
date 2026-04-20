#include "TRK_MINNOW_DOLPHIN/Os/dolphin/dolphin_trk.h"
#include "TRK_MINNOW_DOLPHIN/MetroTRK/Portable/main_TRK.h"
#include "TRK_MINNOW_DOLPHIN/MetroTRK/Portable/mem_TRK.h"
#include "TRK_MINNOW_DOLPHIN/Os/dolphin/dolphin_trk_glue.h"
#include "TRK_MINNOW_DOLPHIN/ppc/Generic/targimpl.h"
#include "TRK_MINNOW_DOLPHIN/ppc/Generic/flush_cache.h"
#include "dolphin/ar.h"
#include "dolphin/ar/__ar.h"
#include "dolphin/os/OSReset.h"
#include "stddef.h"

#define EXCEPTIONMASK_ADDR 0x80000044

extern u32 lc_base;
extern u32 _db_stack_addr;
extern void* TRK_memcpy(void* dst, const void* src, unsigned int n);

static u32 gTRKExceptionVectorOffsets[15] = { PPC_SystemReset,
	                               PPC_MachineCheck,
	                               PPC_DataStorage,
	                               PPC_InstructionStorage,
	                               PPC_ExternalInterrupt,
	                               PPC_Alignment,
	                               PPC_Program,
	                               PPC_FloatingPointUnavaiable,
	                               PPC_Decrementer,
	                               PPC_SystemCall,
	                               PPC_Trace,
	                               PPC_PerformanceMonitor,
	                               PPC_InstructionAddressBreakpoint,
	                               PPC_SystemManagementInterrupt,
	                               PPC_ThermalManagementInterrupt };

/*
 * --INFO--
 * PAL Address: TODO
 * PAL Size: TODO
 * EN Address: TODO
 * EN Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 */
__declspec(section ".init") void __TRK_reset(void) { OSResetSystem(0, 0, 0); }

asm void InitMetroTRK()
{
#ifdef __MWERKS__ // clang-format off
	nofralloc

	addi r1, r1, -4
	stw r3, 0(r1)
	lis r3, gTRKCPUState@h
	ori r3, r3, gTRKCPUState@l
	stmw r0, ProcessorState_PPC.Default.GPR(r3) //Save the gprs
	lwz r4, 0(r1)
	addi r1, r1, 4
	stw r1, ProcessorState_PPC.Default.GPR[1](r3)
	stw r4, ProcessorState_PPC.Default.GPR[3](r3)
	mflr r4
	stw r4, ProcessorState_PPC.Default.LR(r3)
	stw r4, ProcessorState_PPC.Default.PC(r3)
	mfcr r4
	stw r4, ProcessorState_PPC.Default.CR(r3)
	//???
	mfmsr r4
	ori r3, r4, (1 << (31 - 16))
	xori r3, r3, (1 << (31 - 16))
	mtmsr r3
	mtsrr1 r4 //Copy msr to srr1
	//Save misc registers to gTRKCPUState
	bl TRKSaveExtended1Block
	lis r3, gTRKCPUState@h
	ori r3, r3, gTRKCPUState@l
	lmw r0, ProcessorState_PPC.Default.GPR(r3) //Restore the gprs
	//Reset IABR and DABR
	li r0, 0
	mtspr  0x3f2, r0
	mtspr  0x3f5, r0
	//Restore stack pointer
	lis r1, _db_stack_addr@h
	ori r1, r1, _db_stack_addr@l
	mr r3, r5
	bl InitMetroTRKCommTable //Initialize comm table
	/*
	If InitMetroTRKCommTable returned 1 (failure), an invalid hardware
	id or the id for GDEV was somehow passed. Since only BBA or NDEV
	are supported, we return early. Otherwise, we proceed with
	starting up TRK.
	*/
	cmpwi r3, 1
	bne initCommTableSuccess
	/*
	BUG: The code probably orginally reloaded gTRKCPUState here, but
	as is it will read the returned value of InitMetroTRKCommTable
	as a TRKCPUState struct pointer, causing the CPU to return to
	a garbage code address.
	*/
	lwz r4, ProcessorState_PPC.Default.LR(r3)
	mtlr r4
	lmw r0, ProcessorState_PPC.Default.GPR(r3) //Restore the gprs
	blr
initCommTableSuccess:
	b TRK_main //Jump to TRK_main
#endif // clang-format on
}

/*
 * --INFO--
 * PAL Address: TODO
 * PAL Size: TODO
 * EN Address: TODO
 * EN Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 */
__declspec(weak) void InitMetroTRK_BBA(void);
asm void InitMetroTRK_BBA(void)
{
#ifdef __MWERKS__ // clang-format off
	nofralloc

	addi r1, r1, -4
	stw r3, 0(r1)
	lis r3, gTRKCPUState@h
	ori r3, r3, gTRKCPUState@l
	stmw r0, ProcessorState_PPC.Default.GPR(r3)
	lwz r4, 0(r1)
	addi r1, r1, 4
	stw r1, ProcessorState_PPC.Default.GPR[1](r3)
	stw r4, ProcessorState_PPC.Default.GPR[3](r3)
	mflr r4
	stw r4, ProcessorState_PPC.Default.LR(r3)
	stw r4, ProcessorState_PPC.Default.PC(r3)
	mfcr r4
	stw r4, ProcessorState_PPC.Default.CR(r3)
	mfmsr r4
	ori r3, r4, (1 << (31 - 16))
	mtmsr r3
	mtsrr1 r4
	bl TRKSaveExtended1Block
	lis r3, gTRKCPUState@h
	ori r3, r3, gTRKCPUState@l
	lmw r0, ProcessorState_PPC.Default.GPR(r3)
	li r0, 0
	mtspr  0x3f2, r0
	mtspr  0x3f5, r0
	lis r1, _db_stack_addr@h
	ori r1, r1, _db_stack_addr@l
	li r3, 2
	bl InitMetroTRKCommTable
	cmpwi r3, 1
	bne initCommTableSuccessBBA
	lwz r4, ProcessorState_PPC.Default.LR(r3)
	mtlr r4
	lmw r0, ProcessorState_PPC.Default.GPR(r3)
	blr
initCommTableSuccessBBA:
	b TRK_main
	blr
#endif // clang-format on
}

static inline void dataCacheBlockInvalidate(register void* param_1)
{
#ifdef __MWERKS__
	asm { dcbi 0, param_1 }
#endif
}

static inline void dataCacheBlockInvalidateIndexed(register u32 offset, register void* base)
{
#ifdef __MWERKS__
	asm { dcbi offset, base }
#endif
}

static inline void dataCacheBlockFlush(register void* param_1)
{
#ifdef __MWERKS__
	asm { dcbf 0, param_1 }
#endif
}

static inline void dataCacheBlockFlushIndexed(register u32 offset, register void* base)
{
#ifdef __MWERKS__
	asm { dcbf offset, base }
#endif
}

void EnableMetroTRKInterrupts(void) { EnableEXI2Interrupts(); }

u32 TRKTargetTranslate(u32 param_0)
{
	if (param_0 >= lc_base && param_0 < lc_base + 0x4000) {
		if ((gTRKCPUState.Extended1.DBAT3U & 3) != 0) {
			return param_0;
		}
	}

	return param_0 & 0x3FFFFFFF | 0x80000000;
}

extern u8 gTRKInterruptVectorTable[];

void __TRK_copy_vectors(void)
{
	u32 r3 = lc_base;
	u32* isrOffsetPtr;
	int i;
	u32 r29;

	if (r3 <= 0x44 && r3 + 0x4000 > 0x44 && gTRKCPUState.Extended1.DBAT3U & 3) {
		r3 = 0x44;
	} else {
		r3 = EXCEPTIONMASK_ADDR;
	}

	i            = 0;
	r29          = *(u32*)r3;
	isrOffsetPtr = gTRKExceptionVectorOffsets;

	do {
		if ((r29 & (1 << i)) && i != 4) {
			void* destPtr = (void*)TRKTargetTranslate(isrOffsetPtr[i]);
			TRK_memcpy(destPtr, gTRKInterruptVectorTable + isrOffsetPtr[i], 0x100);
			TRK_flush_cache(destPtr, 0x100);
		}

		i++;
	} while (i <= 14);
}

DSError TRKInitializeTarget()
{
	gTRKState.isStopped     = TRUE;
	gTRKState.msr           = __TRK_get_MSR();
	lc_base   = 0xE0000000;
	return DS_NoError;
}

void TRK__read_aram(register u32 param_1, register u32 param_2, u32* param_3)
{
	u32 alignedAddress;
	u32 uVar1;
	u16 sVar3;
	u16 sVar4;
	u32 i;

	if ((param_2 < 0x4000) || (param_2 + *param_3 > 0x8000000)) {
		return;
	}

	alignedAddress = param_2 & 0xFFFFFFE0;
	uVar1 = *param_3 + (param_2 & 0x1F);
	uVar1 = OSRoundUp32B(uVar1);

	for (i = 0; i < uVar1; i += 0x20) {
		dataCacheBlockInvalidateIndexed(i, (void*)param_1);
	}

	do {
		i = ARGetDMAStatus();
	} while (i != 0);
	sVar3 = __ARGetInterruptStatus();
	__ARClearInterrupt();
	ARStartDMA(1, param_1, alignedAddress, uVar1);
	do {
		sVar4 = __ARGetInterruptStatus();
	} while (sVar4 == 0);
	if (sVar3 == 0) {
		__ARClearInterrupt();
	}
}

void TRK__write_aram(register u32 param_1, register u32 param_2, u32* param_3)
{
	u8 buff[32] ATTRIBUTE_ALIGN(32);
	u32 err;
	register u32 bf;
	u32 uVar1;
	u32 size;
	u16 r;
	register u32 g;
	register int counter;
	u32 i;

	if ((size_t)param_2 < 0x4000 || param_2 + *param_3 > 0x8000000) {
		return;
	}

	uVar1 = param_2 & ~0x1F;
	counter = 0;
	size = *param_3 + (param_2 & 0x1F);
	size = OSRoundUp32B(size);

	for (i = 0; i < size; i += 0x20) {
		dataCacheBlockFlushIndexed(counter, (void*)param_1);
		counter += 0x20;
	}

	do {
		err = ARGetDMAStatus();
	} while (err);

	r = __ARGetInterruptStatus();
	g = 0x8000000;

	counter = param_2 & 0x1F;
	if (counter) {
		g = uVar1;
		bf = (u32)buff;
		dataCacheBlockInvalidate(buff);
		__ARClearInterrupt();
		ARStartDMA(1, bf, uVar1, 0x20);

		while (!__ARGetInterruptStatus()) { }

		TRK_memcpy((void*)param_1, buff, counter);
		dataCacheBlockFlush((void*)param_1);
	}

	param_2 += *param_3;
	counter = param_2 & 0x1F;
	if (counter) {
		u32 val = param_2 & ~0x1F;
		if (val != g) {
			bf = (u32)buff;
			dataCacheBlockInvalidate(buff);
			__ARClearInterrupt();
			ARStartDMA(1, bf, val, 0x20);

			while (!__ARGetInterruptStatus()) { }
		}
		g = param_1 + param_2;
		TRK_memcpy((void*)g, buff + counter, 0x20 - counter);

		dataCacheBlockFlush((void*)g);
	}
	__sync();
	__ARClearInterrupt();
	ARStartDMA(0, param_1, uVar1, size);
	if (!r) {
		while (!__ARGetInterruptStatus()) { }

		__ARClearInterrupt();
	}
}
