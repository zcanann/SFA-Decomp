#include <dolphin/exi.h>
#include <dolphin/os.h>

#include "dolphin/os/__os.h"

static SramControl Scb ATTRIBUTE_ALIGN(DOLPHIN_ALIGNMENT);

static inline int ReadSram(void* buffer);
static void WriteSramCallback(s32, OSContext*);
static int WriteSram(void* buffer, u32 offset, u32 size);
static inline void* LockSram(u32 offset);
static int UnlockSram(int commit, u32 offset);

static inline int ReadSram(void* buffer) {
    int err;
    u32 cmd;

    DCInvalidateRange(buffer, SRAM_SIZE);
    if (!EXILock(0, 1, NULL)) {
        return 0;
    }
    if (!EXISelect(0, 1, 3)) {
        EXIUnlock(0);
        return 0;
    }
    cmd = 0x20000100;
    err = 0;
    err |= !EXIImm(0, &cmd, 4, 1, 0);
    err |= !EXISync(0);
    err |= !EXIDma(0, buffer, SRAM_SIZE, 0, NULL);
    err |= !EXISync(0);
    err |= !EXIDeselect(0);
    EXIUnlock(0);
    return !err;
}

static void WriteSramCallback(s32, OSContext*) {
    ASSERTLINE(258, !Scb.locked);
    Scb.sync = WriteSram(&Scb.sram[Scb.offset], Scb.offset, SRAM_SIZE - Scb.offset);
    if (Scb.sync != 0) {
        Scb.offset = SRAM_SIZE;
    }
    ASSERTLINE(264, Scb.sync);
}

static int WriteSram(void* buffer, u32 offset, u32 size) {
    int err;
    u32 cmd;

    if (!EXILock(0, 1, WriteSramCallback)) {
        return 0;
    }
    if (!EXISelect(0, 1, 3)) {
        EXIUnlock(0);
        return 0;
    }
    offset <<= 6;
    cmd = ((offset + 0x100) | 0xA0000000);
    err = 0;
    err |= !EXIImm(0, &cmd, 4, 1, 0);
    err |= !EXISync(0);
    err |= !EXIImmEx(0, buffer, size, 1);
    err |= !EXIDeselect(0);
    EXIUnlock(0);
    return !err;
}

void __OSInitSram(void) {
    Scb.locked = Scb.enabled = FALSE;
    Scb.sync = ReadSram(Scb.sram);
    ASSERTLINE(318, Scb.sync);
    Scb.offset = SRAM_SIZE;
}

static inline void* LockSram(u32 offset) {
    BOOL enabled;

    enabled = OSDisableInterrupts();
    ASSERTLINE(341, !Scb.locked);
    if (Scb.locked) {
        OSRestoreInterrupts(enabled);
        return NULL;
    }
    Scb.enabled = enabled;
    Scb.locked = TRUE;
    return &Scb.sram[offset];
}

OSSram* __OSLockSram(void) {
    return (OSSram*)LockSram(0);
}

OSSramEx* __OSLockSramEx(void) {
    return (OSSramEx*)LockSram(sizeof(OSSram));
}

static int UnlockSram(int commit, u32 offset) {
    u16* p;

    ASSERTLINE(375, Scb.locked);
    if (commit != 0) {
        if (offset == 0) {
            OSSram* sram  = (OSSram*)Scb.sram;
            if (2u < (sram->flags & 3)) {
                sram->flags &= ~3;
            }

            sram->checkSum = sram->checkSumInv = 0;
            for (p = (u16*)&sram->counterBias; p < ((u16*)&Scb.sram[sizeof(OSSram)]); p++) {
                sram->checkSum += *p;
                sram->checkSumInv += ~(*p);
            }
        }
        if (offset < Scb.offset) {
            Scb.offset = offset;
        }

        Scb.sync = WriteSram(&Scb.sram[Scb.offset], Scb.offset, SRAM_SIZE - Scb.offset);
        if (Scb.sync != 0) {
            Scb.offset = SRAM_SIZE;
        }
    }
    Scb.locked = FALSE;
    OSRestoreInterrupts(Scb.enabled);
    return Scb.sync;
}

int __OSUnlockSram(int commit) {
    return UnlockSram(commit, 0);
}

int __OSUnlockSramEx(int commit) {
    return UnlockSram(commit, sizeof(OSSram));
}

int __OSSyncSram(void) {
    return Scb.sync;
}

int __OSReadROM(void* buffer, s32 length, s32 offset) {
    int err;
    u32 cmd;

    if (!EXILock(0, 1, NULL)) {
        return 0;
    }
    if (!EXISelect(0, 1, 3)) {
        EXIUnlock(0);
        return 0;
    }
    cmd = offset << 6;
    err = 0;
    err |= !EXIImm(0, &cmd, 4, 1, 0);
    err |= !EXISync(0);
    err |= !EXIDma(0, buffer, length, 0, NULL);
    err |= !EXISync(0);
    err |= !EXIDeselect(0);
    EXIUnlock(0);
    return !err;
}

u32 OSGetSoundMode(void) {
    OSSram* sram;
    u32 mode;

    sram = __OSLockSram();
    mode = (sram->flags & 4) ? OS_SOUND_MODE_STEREO : OS_SOUND_MODE_MONO;
    __OSUnlockSram(FALSE);
    return mode;
}

void OSSetSoundMode(u32 mode) {
    OSSram* sram;
    u32 newFlags;

    ASSERTLINE(617, mode == OS_SOUND_MODE_MONO || mode == OS_SOUND_MODE_STEREO);
    newFlags = (mode & 1) << 2;
    sram = __OSLockSram();
    if (newFlags == (sram->flags & 4)) {
        __OSUnlockSram(FALSE);
        return;
    }
    sram->flags &= ~4;
    sram->flags |= newFlags;
    __OSUnlockSram(TRUE);
}

u32 OSGetProgressiveMode(void) {
    OSSram* sram;
    u32 on;

    sram = __OSLockSram();
    on = (sram->flags & 0x80) >> 7;
    __OSUnlockSram(FALSE);
    return on;
}

void OSSetProgressiveMode(u32 on) {
    OSSram* sram;
    u32 newFlags;

    ASSERTLINE(670, on == OS_PROGRESSIVE_MODE_OFF || on == OS_PROGRESSIVE_MODE_ON);
    newFlags = (on & 1) << 7;
    sram = __OSLockSram();
    if (newFlags == (sram->flags & 0x80)) {
        __OSUnlockSram(FALSE);
        return;
    }
    sram->flags &= ~0x80;
    sram->flags |= newFlags;
    __OSUnlockSram(TRUE);
}

u8 OSGetLanguage(void) {
    OSSram* sram;
    u8 language;

    sram = __OSLockSram();
    language = sram->language;
    __OSUnlockSram(FALSE);
    return language;
}

u16 OSGetWirelessID(s32 chan) {
    OSSramEx* sram;
    u16 id;

    sram = __OSLockSramEx();
    id = sram->wirelessPadID[chan];
    __OSUnlockSramEx(FALSE);
    return id;
}

void OSSetWirelessID(s32 chan, u16 id) {
    OSSramEx* sram;

    sram = __OSLockSramEx();
    if (sram->wirelessPadID[chan] != id) {
        sram->wirelessPadID[chan] = id;
        __OSUnlockSramEx(TRUE);
        return;
    }

    __OSUnlockSramEx(FALSE);
}
