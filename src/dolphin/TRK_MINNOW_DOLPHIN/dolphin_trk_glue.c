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

UARTError TRKReadUARTPoll(u8* byte)
{
    UARTError err = UART_NoData;

    if (gUARTBuffer.readPos >= gUARTBuffer.readLen) {
        int peekLen;
        gUARTBuffer.readPos = 0;
        peekLen = gDBCommTable.peek_func();
        gUARTBuffer.readLen = peekLen;
        if (peekLen > 0) {
            int readErr;
            if (gUARTBuffer.readLen > 0x110A) {
                gUARTBuffer.readLen = 0x110A;
            }
            readErr = gDBCommTable.read_func(gUARTBuffer.readData, gUARTBuffer.readLen);
            err = (readErr != 0) ? -1 : 0;
            if (err != 0) {
                gUARTBuffer.readLen = 0;
            }
        }
    }

    if (gUARTBuffer.readPos < gUARTBuffer.readLen) {
        *byte = gUARTBuffer.readData[gUARTBuffer.readPos++];
        err = UART_NoError;
    }

    return err;
}

UARTError WriteUART1(s8 byte)
{
    gUARTWriteBuffer[gUARTBuffer.writeLen++] = byte;
    return UART_NoError;
}

UARTError WriteUARTFlush(void)
{
    UARTError err = UART_NoError;
    s32 len = (s32)gUARTBuffer.writeLen;
    u8* dst = &gUARTWriteBuffer[len];
    u32 remaining = 0x800 - len;
    u8 zero = 0;
    int writeErr;

    if (len < 0x800) {
        u32 blocks = remaining >> 3;
        u32 tail;
        if (blocks != 0) {
            do {
                dst[0] = zero;
                dst[1] = zero;
                dst[2] = zero;
                dst[3] = zero;
                dst[4] = zero;
                dst[5] = zero;
                dst[6] = zero;
                dst[7] = zero;
                dst += 8;
            } while (--blocks);
        }
        tail = remaining & 7;
        if (tail != 0) {
            do {
                *dst++ = zero;
            } while (--tail);
        }
        len += remaining;
    }
    gUARTBuffer.writeLen = len;
    if (len != 0) {
        writeErr = gDBCommTable.write_func(gUARTWriteBuffer, len);
        gUARTBuffer.writeLen = 0;
        err = (writeErr != 0) ? -1 : 0;
    }
    return err;
}

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
