#include "TRK_MINNOW_DOLPHIN/Os/dolphin/dolphin_trk_glue.h"
#include "TRK_MINNOW_DOLPHIN/ppc/Generic/targimpl.h"
#include "OdemuExi2/odemuexi/DebuggerDriver.h"
#include "amcstubs/AmcExi2Stubs.h"
#include "dolphin/base/PPCArch.h"
#include "PowerPC_EABI_Support/MetroTRK/trk.h"
#include "string.h"

typedef struct UARTInlineBuffer {
    s32 writeLen;
    s32 readPos;
    s32 readLen;
    u32 _0C;
    u8  readData[0x110C];
} UARTInlineBuffer;

static UARTInlineBuffer gUARTBuffer;
static u8 gUARTWriteBuffer[0x110C];

volatile u8 TRK_Use_BBA = 0;
BOOL _MetroTRK_Has_Framing = FALSE;
int ddh_cc_initinterrupts(void);
int ddh_cc_initialize(void*, __OSInterruptHandler);
int ddh_cc_shutdown(void);
int ddh_cc_peek(void);
int ddh_cc_read(u8*, int);
int ddh_cc_write(const u8*, int);
int ddh_cc_open(void);
int ddh_cc_close(void);
int ddh_cc_pre_continue(void);
int ddh_cc_post_stop(void);
int gdev_cc_initinterrupts(void);
int gdev_cc_initialize(void*, __OSInterruptHandler);
int gdev_cc_shutdown(void);
int gdev_cc_peek(void);
int gdev_cc_read(u8*, int);
int gdev_cc_write(const u8*, int);
int gdev_cc_open(void);
int gdev_cc_close(void);
int gdev_cc_pre_continue(void);
int gdev_cc_post_stop(void);
int udp_cc_initialize(void);
int udp_cc_shutdown(void);
int udp_cc_peek(void);
int udp_cc_read(u8*, int);
int udp_cc_write(const u8*, int);
int udp_cc_open(void);
int udp_cc_close(void);
int udp_cc_pre_continue(void);
int udp_cc_post_stop(void);

DBCommTable gDBCommTable = {};

asm void TRKLoadContext(OSContext* ctx, u32)
{
#ifdef __MWERKS__ // clang-format off
    nofralloc
    lwz r0, OSContext.gpr[0](r3)
    lwz r1, OSContext.gpr[1](r3)
    lwz r2, OSContext.gpr[2](r3)
    lhz r5, OSContext.state(r3)
    rlwinm. r6, r5, 0, 0x1e, 0x1e
    beq lbl_80371C1C
    rlwinm r5, r5, 0, 0x1f, 0x1d
    sth r5, OSContext.state(r3)
    lmw r5, OSContext.gpr[5](r3)
    b lbl_80371C20
lbl_80371C1C:
    lmw r13, OSContext.gpr[13](r3)
lbl_80371C20:
    mr r31, r3
    mr r3, r4
    lwz r4, OSContext.cr(r31)
    mtcrf 0xff, r4
    lwz r4, OSContext.lr(r31)
    mtlr r4
    lwz r4, OSContext.ctr(r31)
    mtctr r4
    lwz r4, OSContext.xer(r31)
    mtxer r4
    mfmsr r4
    rlwinm r4, r4, 0, 0x11, 0xf //Turn off external exceptions
    rlwinm r4, r4, 0, 0x1f, 0x1d //Turn off recoverable exception flag
    mtmsr r4
    mtsprg 1, r2
    lwz r4, OSContext.gpr[3](r31)
    mtsprg 2, r4
    lwz r4, OSContext.gpr[4](r31)
    mtsprg 3, r4
    lwz r2, OSContext.srr0(r31)
    lwz r4, OSContext.srr1(r31)
    lwz r31, OSContext.gpr[31](r31)
    b TRKInterruptHandler
#endif // clang-format on
}

void TRKEXICallBack(__OSInterrupt param_0, OSContext* ctx)
{
    OSEnableScheduler();
    TRKLoadContext(ctx, 0x500);
}

int InitMetroTRKCommTable(int hwId)
{
    int result;

    if (hwId == HARDWARE_GDEV) {
        result = Hu_IsStub();

        gDBCommTable.initialize_func      = (DBCommInitFunc)DBInitComm;
        gDBCommTable.init_interrupts_func = (DBCommFunc)DBInitInterrupts;
        gDBCommTable.peek_func            = (DBCommFunc)DBQueryData;
        gDBCommTable.read_func            = (DBCommReadFunc)DBRead;
        gDBCommTable.write_func           = (DBCommWriteFunc)DBWrite;
        gDBCommTable.open_func            = (DBCommFunc)DBOpen;
        gDBCommTable.close_func           = (DBCommFunc)DBClose;
    } else {
        result = AMC_IsStub();

        gDBCommTable.initialize_func      = (DBCommInitFunc)EXI2_Init;
        gDBCommTable.init_interrupts_func = (DBCommFunc)EXI2_EnableInterrupts;
        gDBCommTable.peek_func            = (DBCommFunc)EXI2_Poll;
        gDBCommTable.read_func            = (DBCommReadFunc)EXI2_ReadN;
        gDBCommTable.write_func           = (DBCommWriteFunc)EXI2_WriteN;
        gDBCommTable.open_func            = (DBCommFunc)EXI2_Reserve;
        gDBCommTable.close_func           = (DBCommFunc)EXI2_Unreserve;
    }

    return result;
}

DSError TRKInitializeIntDrivenUART(u32 param_0, u32 param_1, u32 param_2, void* param_3)
{
    gDBCommTable.initialize_func(param_3, TRKEXICallBack);
    return DS_NoError;
}

void EnableEXI2Interrupts(void)
{
    gDBCommTable.init_interrupts_func();
}

int TRKPollUART(void) 
{
    return gDBCommTable.peek_func();
}

UARTError TRKReadUARTN(void* bytes, u32 length)
{
    int readErr = gDBCommTable.read_func(bytes, length);
    return readErr == 0 ? 0 : -1;
}

UARTError TRKWriteUARTN(const void* bytes, u32 length)
{
    int writeErr = gDBCommTable.write_func(bytes, length);
    return writeErr == 0 ? 0 : -1;
}

#pragma dont_inline on
asm UARTError TRKReadUARTPoll(register u8* byte) {
    nofralloc
    stwu r1, -0x20(r1)
    mflr r0
    lis r4, gUARTBuffer@ha
    stw r0, 0x24(r1)
    stw r31, 0x1c(r1)
    mr r31, r3
    stw r30, 0x18(r1)
    addi r30, r4, gUARTBuffer@l
    stw r29, 0x14(r1)
    li r29, 0x4
    lwz r3, 0x4(r30)
    lwz r0, 0x8(r30)
    cmpw r3, r0
    blt lbl_rup_check_buf
    lis r3, gDBCommTable@ha
    li r0, 0
    addi r3, r3, gDBCommTable@l
    stw r0, 0x4(r30)
    lwz r12, 0x8(r3)
    mtctr r12
    bctrl
    cmpwi r3, 0
    stw r3, 0x8(r30)
    ble lbl_rup_check_buf
    cmpwi r3, 0x110a
    ble lbl_rup_after_cap
    li r0, 0x110a
    stw r0, 0x8(r30)
lbl_rup_after_cap:
    lis r4, gDBCommTable@ha
    addi r3, r30, 0x10
    addi r5, r4, gDBCommTable@l
    lwz r4, 0x8(r30)
    lwz r12, 0xc(r5)
    mtctr r12
    bctrl
    neg r0, r3
    or r0, r0, r3
    srawi. r0, r0, 31
    mr r29, r0
    beq lbl_rup_check_buf
    li r0, 0
    stw r0, 0x8(r30)
lbl_rup_check_buf:
    lwz r3, 0x4(r30)
    lwz r0, 0x8(r30)
    cmpw r3, r0
    bge lbl_rup_epilogue
    addi r0, r3, 1
    add r3, r30, r3
    stw r0, 0x4(r30)
    li r29, 0
    lbz r0, 0x10(r3)
    stb r0, 0x0(r31)
lbl_rup_epilogue:
    lwz r0, 0x24(r1)
    mr r3, r29
    lwz r31, 0x1c(r1)
    lwz r30, 0x18(r1)
    lwz r29, 0x14(r1)
    mtlr r0
    addi r1, r1, 0x20
    blr
}
#pragma dont_inline reset

UARTError WriteUART1(s8 byte)
{
    gUARTWriteBuffer[gUARTBuffer.writeLen++] = byte;
    return UART_NoError;
}

#pragma dont_inline on
asm UARTError WriteUARTFlush(void) {
    nofralloc
    stwu r1, -0x10(r1)
    mflr r0
    lis r3, gUARTBuffer@ha
    lis r5, gUARTWriteBuffer@ha
    stw r0, 0x14(r1)
    addi r4, r3, gUARTBuffer@l
    addi r0, r5, gUARTWriteBuffer@l
    li r3, 0
    lwz r4, 0(r4)
    li r7, 0
    cmpwi r4, 0x800
    add r8, r0, r4
    subfic r6, r4, 0x800
    bge lbl_flush_store
    srwi. r5, r6, 3
    mr r0, r6
    mtctr r5
    beq lbl_flush_byte_setup
lbl_flush_block:
    stb r7, 0(r8)
    stb r7, 1(r8)
    stb r7, 2(r8)
    stb r7, 3(r8)
    stb r7, 4(r8)
    stb r7, 5(r8)
    stb r7, 6(r8)
    stb r7, 7(r8)
    addi r8, r8, 8
    bdnz lbl_flush_block
    andi. r6, r6, 7
    beq lbl_flush_after_memset
lbl_flush_byte_setup:
    mtctr r6
lbl_flush_byte:
    stb r7, 0(r8)
    addi r8, r8, 1
    bdnz lbl_flush_byte
lbl_flush_after_memset:
    add r4, r4, r0
lbl_flush_store:
    lis r5, gUARTBuffer@ha
    cmpwi r4, 0
    stw r4, gUARTBuffer@l(r5)
    beq lbl_flush_exit
    lis r3, gDBCommTable@ha
    lis r5, gUARTWriteBuffer@ha
    addi r3, r3, gDBCommTable@l
    lwz r12, 0x10(r3)
    addi r3, r5, gUARTWriteBuffer@l
    mtctr r12
    bctrl
    neg r5, r3
    lis r4, gUARTBuffer@ha
    li r0, 0
    or r3, r5, r3
    stw r0, gUARTBuffer@l(r4)
    srawi r3, r3, 31
lbl_flush_exit:
    lwz r0, 0x14(r1)
    mtlr r0
    addi r1, r1, 0x10
    blr
}
#pragma dont_inline reset

void ReserveEXI2Port(void) { gDBCommTable.open_func(); }

void UnreserveEXI2Port(void) { gDBCommTable.close_func(); }

void TRK_board_display(char* str) { OSReport(str); }

/*
 * --INFO--
 * PAL Address: TODO
 * PAL Size: TODO
 * EN Address: TODO
 * EN Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 */
void InitializeProgramEndTrap(void)
{
    static const u32 EndofProgramInstruction = 0x00454E44;
    register u8* ppcHalt = (u8*)PPCHalt;

    TRK_memcpy(ppcHalt + 4, &EndofProgramInstruction, 4);
    ICInvalidateRange(ppcHalt + 4, 4);
    DCFlushRange(ppcHalt + 4, 4);
}

void TRKUARTInterruptHandler() { }
