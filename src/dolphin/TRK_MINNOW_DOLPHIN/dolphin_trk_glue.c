#include "TRK_MINNOW_DOLPHIN/Os/dolphin/dolphin_trk_glue.h"
#include "TRK_MINNOW_DOLPHIN/ppc/Generic/targimpl.h"
#include "OdemuExi2/odemuexi/DebuggerDriver.h"
#include "amcstubs/AmcExi2Stubs.h"
#include "dolphin/base/PPCArch.h"
#include "PowerPC_EABI_Support/MetroTRK/trk.h"

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
    int result = 1;

    OSReport("Devkit set to : %ld\n", hwId);
    TRK_Use_BBA = 0;

    if (hwId == HARDWARE_BBA) {
        OSReport("MetroTRK : Set to BBA\n");
        TRK_Use_BBA = 1;

        gDBCommTable.initialize_func      = (DBCommInitFunc)udp_cc_initialize;
        gDBCommTable.open_func            = udp_cc_open;
        gDBCommTable.close_func           = udp_cc_close;
        gDBCommTable.read_func            = udp_cc_read;
        gDBCommTable.write_func           = udp_cc_write;
        gDBCommTable.peek_func            = udp_cc_peek;
        gDBCommTable.init_interrupts_func = NULL;
        return 0;
    }

    if (hwId == HARDWARE_GDEV) {
        OSReport("MetroTRK : Set to GDEV hardware\n");
        result = Hu_IsStub();

        gDBCommTable.initialize_func      = gdev_cc_initialize;
        gDBCommTable.open_func            = gdev_cc_open;
        gDBCommTable.close_func           = gdev_cc_close;
        gDBCommTable.read_func            = gdev_cc_read;
        gDBCommTable.write_func           = gdev_cc_write;
        gDBCommTable.peek_func            = gdev_cc_peek;
        gDBCommTable.init_interrupts_func = gdev_cc_initinterrupts;
    } else if (hwId == HARDWARE_AMC_DDH) {

        OSReport("MetroTRK : Set to AMC DDH hardware\n");
        result = AMC_IsStub();

        gDBCommTable.initialize_func      = ddh_cc_initialize;
        gDBCommTable.open_func            = ddh_cc_open;
        gDBCommTable.close_func           = ddh_cc_close;
        gDBCommTable.read_func            = ddh_cc_read;
        gDBCommTable.write_func           = ddh_cc_write;
        gDBCommTable.peek_func            = ddh_cc_peek;
        gDBCommTable.init_interrupts_func = ddh_cc_initinterrupts;
    } else {
        OSReport("MetroTRK : Set to UNKNOWN hardware. (%ld)\n", hwId);
        OSReport("MetroTRK : Invalid hardware ID passed from OS\n");
        OSReport("MetroTRK : Defaulting to GDEV Hardware\n");
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
    if (TRK_Use_BBA == 0 && gDBCommTable.init_interrupts_func != NULL) {
        gDBCommTable.init_interrupts_func();
    }
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
