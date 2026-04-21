#ifndef __METROTRK_TRK_H__
#define __METROTRK_TRK_H__

#include "dolphin/types.h"
#include "PowerPC_EABI_Support/MetroTRK/dstypes.h"
#include "PowerPC_EABI_Support/MetroTRK/trkenum.h"
#include "PowerPC_EABI_Support/MetroTRK/trktypes.h"
#include "PowerPC_EABI_Support/MetroTRK/ppc_reg.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef MessageBuffer TRKBuffer;

void TRKSaveExtended1Block();

DSError TRKDoConnect(TRKBuffer*);
DSError TRKDoUnsupported(TRKBuffer*);
DSError TRKDoDisconnect(TRKBuffer*);
DSError TRKDoReset(TRKBuffer*);
DSError TRKDoVersions(TRKBuffer*);
DSError TRKDoSupportMask(TRKBuffer*);
DSError TRKDoOverride(TRKBuffer*);
DSError TRKDoCPUType(TRKBuffer*);
DSError TRKDoReadMemory(TRKBuffer*);
DSError TRKDoWriteMemory(TRKBuffer*);
DSError TRKDoReadRegisters(TRKBuffer*);
DSError TRKDoWriteRegisters(TRKBuffer*);
DSError TRKDoFlushCache(TRKBuffer*);
DSError TRKDoSetOption(TRKBuffer*);
DSError TRKDoContinue(TRKBuffer*);
DSError TRKDoStep(TRKBuffer*);
DSError TRKDoStop(TRKBuffer*);

void SetBufferPosition(TRKBuffer*, u32);
void SetTRKConnected(BOOL);
BOOL GetTRKConnected(void);

DSError TRKGetFreeBuffer(int*, TRKBuffer**);
void OutputData(void* data, int length);
void TRKResetBuffer(TRKBuffer* msg, u8 keepData);

DSError TRKReadBuffer1_ui64(TRKBuffer* buffer, u64* data);
DSError TRKAppendBuffer1_ui64(TRKBuffer* buffer, const u64 data);

void InitMetroTRK(void);
void InitMetroTRK_BBA(void);
void EnableMetroTRKInterrupts(void);

void TRKLoadContext(OSContext* ctx, u32);
void TRKRestoreExtended1Block(void);
int InitMetroTRKCommTable(int);
void TRK_board_display(char*);

void TRKConstructEvent(TRKEvent* event, NubEventType eventType);
void TRKDestructEvent(TRKEvent* event);
DSError TRKPostEvent(TRKEvent* event);
BOOL TRKGetNextEvent(TRKEvent* event);
DSError TRKDispatchMessage(TRKBuffer*);
void* TRKGetBuffer(int);
void TRKReleaseBuffer(int);
void TRKGetInput(void);

DSError TRKTargetContinue(void);
DSError TRKTargetInterrupt(TRKEvent*);
BOOL TRKTargetStopped(void);
void TRKTargetSetStopped(uint);
DSError TRKTargetSupportRequest(void);

DSError TRKAppendBuffer_ui8(TRKBuffer*, const u8*, int);
DSError TRKAppendBuffer_ui16(TRKBuffer*, const u16*, int);
DSError TRKAppendBuffer_ui32(TRKBuffer*, const u32*, int);
DSError TRKAppendBuffer_ui64(TRKBuffer*, const u64*, int);
DSError TRKAppendBuffer1_ui8(TRKBuffer*, const u8);
DSError TRKAppendBuffer1_ui16(TRKBuffer*, const u16);
DSError TRKSetBufferPosition(TRKBuffer*, u32);

DSError TRKReadBuffer1_ui8(TRKBuffer*, u8*);
DSError TRKReadBuffer1_ui16(TRKBuffer*, u16*);
DSError TRKReadBuffer1_ui32(TRKBuffer*, u32*);
DSError TRKReadBuffer1_ui64(TRKBuffer*, u64*);
DSError TRKReadBuffer_ui8(TRKBuffer*, u8*, int);
DSError TRKReadBuffer_ui16(TRKBuffer*, u16*, int);
DSError TRKReadBuffer_ui32(TRKBuffer*, u32*, int);
DSError TRKReadBuffer_ui64(TRKBuffer*, u64*, int);

/* TRKMessageSend declared in msg.h as taking TRK_Msg* */
void TRKSwapAndGo(void);
DSError TRKInitializeNub(void);
DSError TRKTerminateNub(void);
void TRKNubWelcome(void);
void TRKNubMainLoop(void);

DSError TRKInitializeMutex(void*);
DSError TRKAcquireMutex(void*);
DSError TRKReleaseMutex(void*);
void* TRK_memcpy(void* dst, const void* src, unsigned int n);

DSError TRKInitializeEventQueue(void);
DSError TRKInitializeMessageBuffers(void);
DSError TRKInitializeDispatcher(void);
void InitializeProgramEndTrap(void);
DSError TRKInitializeSerialHandler(void);
DSError TRKTerminateSerialHandler(void);
void TRKProcessInput(int bufferIdx);
DSError TRKInitializeTarget(void);

void UnreserveEXI2Port(void);
void ReserveEXI2Port(void);

void MWTRACE(u8, char*, ...);

DSError TRKRequestSend(TRKBuffer* msgBuf, int* bufferId, u32 p1, u32 p2, int p3);

DSError TRK_main(void);
UARTError InitializeUART(UARTBaudRate baudRate);
DSError TRKInitializeIntDrivenUART(u32, u32, u32, void*);
int TRKPollUART(void);
UARTError TRKReadUARTPoll(s8*);
UARTError TRKReadUARTN(void*, u32);
UARTError TRKWriteUARTN(const void* bytes, u32 length);
void usr_put_initialize(void);
void TRKTargetSetInputPendingPtr(void*);
void SetUseSerialIO(u8);
u8 GetUseSerialIO(void);

DSError TRKTargetAddStopInfo(TRKBuffer*);
DSError TRKTargetAddExceptionInfo(TRKBuffer*);
void TRKInterruptHandler(void);
BOOL usr_puts_serial(const char* msg);

extern BOOL gTRKBigEndian;
extern void* gTRKInputPendingPtr;
extern ProcessorState_PPC gTRKCPUState;
extern ProcessorRestoreFlags_PPC gTRKRestoreFlags;
extern u8 gTRKInterruptVectorTable[];
extern TRKState gTRKState;
extern TRKBuffer gTRKMessageBuffers[3];

#ifdef __cplusplus
}
#endif

#endif /* __METROTRK_TRK_H__ */
