#include <dolphin/exi.h>
#include "dolphin/os.h"
#include <dolphin/hw_regs.h>

u8 lbl_803DE3DC;

u8* lbl_803DE3D8;

s32 lbl_803DE3D4;

u32 lbl_803DE3D0;

void (*lbl_803DE3CC)(u32, OSContext*);

__OSInterruptHandler lbl_803DE3C8;

u8 lbl_803DC630[8] = { 0x80 };

#define MTRCallback lbl_803DE3C8
#define DBGCallback lbl_803DE3CC
#define SendMailData lbl_803DE3D0
#define RecvDataLeng lbl_803DE3D4
#define pEXIInputFlag lbl_803DE3D8
#define EXIInputFlag lbl_803DE3DC
#define SendCount lbl_803DC630[0]

#define ROUND_UP(x, align) (((x) + (align)-1) & (-(align)))

inline static void DBGEXIInit() {
    __OSMaskInterrupts(0x18000);
    __EXIRegs[10] = 0;
}

inline static u32 DBGEXISelect(u32 v) {
    u32 regs = __EXIRegs[10];
    regs &= 0x405;
    regs |= 0x80 | (v << 4);
    __EXIRegs[10] = regs;
    return TRUE;
}

inline static BOOL DBGEXIDeselect(void) {
    __EXIRegs[10] &= 0x405;
    return TRUE;
}

inline static BOOL DBGEXISync() {
    while (__EXIRegs[13] & 1)
        ;

    return TRUE;
}

static BOOL DBGEXIImm(void* buffer, s32 bytecounter, u32 write) {
    u8* tempPointer;
    u32 writeOutValue;
    int i;

    if (write) {
        tempPointer = buffer;
        writeOutValue = 0;
        for (i = 0; i < bytecounter; i++) {
            u8* temp = ((u8*)buffer) + i;
            writeOutValue |= *temp << ((3 - i) << 3);
        }
        __EXIRegs[14] = writeOutValue;
    }

    __EXIRegs[13] = 1 | write << 2 | (bytecounter - 1) << 4;
    do {
        writeOutValue = __EXIRegs[13];
    } while (writeOutValue & 1);

    if (!write) {
        writeOutValue = __EXIRegs[14];
        tempPointer = buffer;
        for (i = 0; i < bytecounter; i++) {
            *tempPointer++ = writeOutValue >> ((3 - i) << 3);
        }
    }

    return TRUE;
}

inline static BOOL DBGWriteMailbox(u32 p1) {
    BOOL error = FALSE;
    u32 value;

    if (!DBGEXISelect(4)) {
        return FALSE;
    }

    value = (p1 & 0x1FFFFFFF) | 0xC0000000;
    error |= !DBGEXIImm((u8*)&value, sizeof(value), TRUE);
    error |= !DBGEXISync();
    error |= !DBGEXIDeselect();

    return !error;
}

static BOOL DBGReadMailbox(u32* p1) {
    BOOL error;
    u32 v;

    error = FALSE;
    if (!DBGEXISelect(4)) {
        return FALSE;
    }

    v = 0x60000000;
    error |= !DBGEXIImm((u8*)&v, 2, TRUE);
    error |= !DBGEXISync();
    error |= !DBGEXIImm((u8*)p1, sizeof(*p1), FALSE);
    error |= !DBGEXISync();
    error |= !DBGEXIDeselect();

    return !error;
}

static BOOL DBGRead(u32 count, u32* buffer, s32 param3) {
    BOOL error;
    u32* dataPtr;
    u32 value;
    u32 readValue;

    error = FALSE;
    dataPtr = (u32*)buffer;
    if (!DBGEXISelect(4)) {
        return FALSE;
    }

    value = ((count & 0x1FFFC) << 8) | 0x20000000;
    error |= !DBGEXIImm((u8*)&value, sizeof(value), TRUE);
    error |= !DBGEXISync();

    while (param3 != 0) {
        error |= !DBGEXIImm((u8*)&readValue, sizeof(readValue), FALSE);
        error |= !DBGEXISync();
        *dataPtr++ = readValue;
        param3 -= 4;
        if (param3 < 0) {
            param3 = 0;
        }
    }

    error |= !DBGEXIDeselect();
    return !error;
}

static BOOL DBGWrite(u32 count, void* buffer, s32 param3) {
    BOOL total;
    u32* buf_p;
    u32 v1;
    u32 v;

    total = FALSE;
    buf_p = (u32*)buffer;
    if (!DBGEXISelect(4)) {
        return FALSE;
    }

    v1 = ((count & 0x1FFFC) << 8) | 0xA0000000;
    total |= !DBGEXIImm((u8*)&v1, sizeof(v1), TRUE);
    total |= !DBGEXISync();

    while (param3 != 0) {
        v = *buf_p++;
        total |= !DBGEXIImm((u8*)&v, sizeof(v), TRUE);
        total |= !DBGEXISync();
        param3 -= 4;
        if (param3 < 0) {
            param3 = 0;
        }
    }

    total |= !DBGEXIDeselect();
    return !total;
}

static BOOL _DBGReadStatus(u32* p1) {
    BOOL error;
    u32 cmd;

    error = FALSE;
    if (!DBGEXISelect(4)) {
        return FALSE;
    }

    cmd = 0x40000000;
    error |= !DBGEXIImm((u8*)&cmd, 2, TRUE);
    error |= !DBGEXISync();
    error |= !DBGEXIImm((u8*)p1, sizeof(*p1), FALSE);
    error |= !DBGEXISync();
    error |= !DBGEXIDeselect();

    return !error;
}
inline static BOOL DBGReadStatus(u32* p1) {
    return _DBGReadStatus(p1);
}

static void MWCallback(u32 a, OSContext* b) {
    EXIInputFlag = TRUE;
    if (MTRCallback) {
        MTRCallback(0, b);
    }
}

static void DBGHandler(s16 a, OSContext* b) {
    *__PIRegs = 0x1000;
    if (DBGCallback) {
        DBGCallback(a, b);
    }
}

inline static void CheckMailBox(void) {
    u32 value;

    DBGReadStatus(&value);
    if (value & 1) {
        DBGReadMailbox(&value);
        value &= 0x1fffffff;

        if ((value & 0x1f000000) == 0x1f000000) {
            SendMailData = value;
            RecvDataLeng = value & 0x7fff;
            EXIInputFlag = 1;
        }
    }
}

void DBInitComm(volatile u8** a, __OSInterruptHandler b) {
    BOOL interrupts = OSDisableInterrupts();

    pEXIInputFlag = &EXIInputFlag;
    *a = pEXIInputFlag;
    MTRCallback = b;
    DBGEXIInit();
    OSRestoreInterrupts(interrupts);
}

void DBInitInterrupts(void) {
    __OSMaskInterrupts(0x18000);
    __OSMaskInterrupts(0x40);
    DBGCallback = MWCallback;
    __OSSetInterruptHandler(0x19, DBGHandler);
    __OSUnmaskInterrupts(0x40);
}

u32 DBQueryData(void) {
    BOOL interrupts;

    EXIInputFlag = 0;
    if (RecvDataLeng) goto end;
    interrupts = OSDisableInterrupts();
    CheckMailBox();
end:
    OSRestoreInterrupts(interrupts);
    return RecvDataLeng;
}

int DBRead(void* buffer, u32 count) {
    BOOL interrupts;
    s32 value;

    interrupts = OSDisableInterrupts();
    value = (SendMailData & 0x10000) ? 0x1000 : 0;

    DBGRead(value + 0x1e000, (u32*)buffer, (count + 3U) & 0xfffffffc);

    RecvDataLeng = 0;
    EXIInputFlag = 0;

    OSRestoreInterrupts(interrupts);

    return 0;
}

int DBWrite(const void* src, u32 size) {
    u32 busyFlag;
    u32 v;
    BOOL interrupts = OSDisableInterrupts();

    do {
        _DBGReadStatus(&busyFlag);
    } while (busyFlag & 2);

    SendCount++;
    v = ((SendCount & 1) ? 0x1000 : 0);

    while (!DBGWrite(v | 0x1c000, (u32*)src, ROUND_UP(size, 4)))
        ;

    do {
        _DBGReadStatus(&busyFlag);
    } while (busyFlag & 2);

    v = SendCount;
    while (!DBGWriteMailbox((0x1f000000) | v << 0x10 | size))
        ;

    do {
        while (!_DBGReadStatus(&busyFlag))
            ;
    } while (busyFlag & 2);

    OSRestoreInterrupts(interrupts);

    return 0;
}

void DBOpen(void) {}

void DBClose(void) {}
