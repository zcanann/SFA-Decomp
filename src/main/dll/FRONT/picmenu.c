#include "dolphin/ai.h"
#include "dolphin/dvd.h"
#include "dolphin/os.h"
#include "dolphin/thp/THPPlayer.h"
#include "dolphin/thp/THPVideoDecode.h"
#include "string.h"

/* DVDRead: sync DVD read (distinct from DVDReadPrio) */
extern s32 DVDRead(DVDFileInfo* fileInfo, void* addr, s32 length, s32 offset);

/* External functions */
extern BOOL THPInit(void);
extern void fn_80118018(void);
extern void fn_80118B88(int);

/* BSS objects (lis+addi addressing) */
extern char             lbl_803A57C0[0x50C];
extern THPPlayer        lbl_803A5D60;
extern char             lbl_803A5F08[0x1000];
extern OSThread         lbl_803A6F08;
extern OSMessageQueue   lbl_803A7290;
extern OSMessageQueue   lbl_803A72B0;
extern OSMessageQueue   lbl_803A72D0;
extern char             lbl_803A72F0[0x18];
extern OSMessageQueue   lbl_803A7308;
extern OSMessageQueue   lbl_803A7328;
extern OSThread         lbl_803A8348;
extern char             lbl_803A5D20[0x40];

/* SDATA string (SDA21) */
extern char             lbl_803DB9E8[];

/* Float constant (sdata2) */
extern f32              lbl_803E1D54;

/* SBSS dword flags (SDA21) */
extern u32              lbl_803DD660;
extern AIDCallback      lbl_803DD668;
extern s32              lbl_803DD66C;
extern u32              lbl_803DD670;
extern u32              lbl_803DD674;
extern u32              lbl_803DD678;
extern s32              lbl_803DD688;
extern s32              lbl_803DD690;
extern u32              lbl_803DD694;
extern u32              lbl_803DD698;

/* Forward declarations needed by OSCreateThread */
void  fn_80119520(void);
void  fn_801198E0(void*);
void  fn_80119A1C(void);

/* ------------------------------------------------------------------ */
/* movieLoad (748 bytes)                                                */
/* ------------------------------------------------------------------ */
BOOL movieLoad(const char* fileName, void* param2)
{
    s32 result;
    u32 i;
    char* p = (char*)&lbl_803A5D60;

    if (lbl_803DD660 != 0) {
        return 0;
    }

    if (*(u32*)(p + 0x98) != 0) {
        return 0;
    }

    memset(p + 0x80, 0, 8);
    memset(p + 0x88, 0, 0xC);

    if (!DVDOpen(fileName, &lbl_803A5D60.mFileInfo)) {
        return 0;
    }

    result = DVDRead(&lbl_803A5D60.mFileInfo, lbl_803A5D20, 0x40, 0);
    if (result < 0) {
        DVDClose(&lbl_803A5D60.mFileInfo);
        return 0;
    }

    memcpy(p + 0x3C, lbl_803A5D20, 0x30);

    if (strcmp(p + 0x3C, lbl_803DB9E8) != 0) {
        DVDClose(&lbl_803A5D60.mFileInfo);
        return 0;
    }

    if (*(u32*)(p + 0x40) - 0x10000 != 0) {
        DVDClose(&lbl_803A5D60.mFileInfo);
        return 0;
    }

    {
        u32 compOff = *(u32*)(p + 0x5C);
        u32 readOff;

        result = DVDRead(&lbl_803A5D60.mFileInfo, lbl_803A5D20, 0x20, compOff);
        if (result < 0) {
            DVDClose(&lbl_803A5D60.mFileInfo);
            return 0;
        }

        memcpy(p + 0x6C, lbl_803A5D20, 0x14);
        readOff = compOff + 0x14;
        p[0x9F] = 0;

        for (i = 0; i < *(u32*)(p + 0x6C); i++) {
            u8 compType = (u8)p[0x70 + i];
            if (compType == 1) {
                result = DVDRead(&lbl_803A5D60.mFileInfo, lbl_803A5D20, 0x20, readOff);
                if (result < 0) {
                    DVDClose(&lbl_803A5D60.mFileInfo);
                    return 0;
                }
                memcpy(p + 0x88, lbl_803A5D20, 0xC);
                p[0x9F] = 1;
                readOff += 0xC;
            } else if (compType == 0) {
                result = DVDRead(&lbl_803A5D60.mFileInfo, lbl_803A5D20, 0x20, readOff);
                if (result < 0) {
                    DVDClose(&lbl_803A5D60.mFileInfo);
                    return 0;
                }
                memcpy(p + 0x80, lbl_803A5D20, 8);
                readOff += 8;
            } else {
                return 0;
            }
        }
    }

    {
        char* q = (char*)&lbl_803A5D60;
        q[0x9D] = 0;
        q[0x9C] = 0;
        q[0x9E] = 0;
        *(u32*)(q + 0xA8) = (u32)param2;
        *(u32*)(p + 0x98) = 1;
        *(f32*)(q + 0xD4) = lbl_803E1D54;
        *(f32*)(q + 0xD8) = lbl_803E1D54;
        *(u32*)(q + 0xE0) = 0;
    }

    return 1;
}

/* ------------------------------------------------------------------ */
/* audioFn_801192ec (76 bytes)                                         */
/* ------------------------------------------------------------------ */
#pragma scheduling off
#pragma peephole off
void audioFn_801192ec(void)
{
    u32 saved = OSDisableInterrupts();
    if (lbl_803DD668 != (AIDCallback)0) {
        AIRegisterDMACallback(lbl_803DD668);
    }
    OSRestoreInterrupts(saved);
    lbl_803DD660 = 0;
}
#pragma peephole reset
#pragma scheduling reset

/* ------------------------------------------------------------------ */
/* attractModeAudioFn_80119338 (288 bytes)                             */
/* ------------------------------------------------------------------ */
#pragma scheduling off
#pragma peephole off
BOOL attractModeAudioFn_80119338(int param_1)
{
    char* base = lbl_803A57C0;
    u32 saved;
    AIDCallback oldCb;

    memset(base + 0x5A0, 0, 0x1A8);
    OSInitMessageQueue((OSMessageQueue*)(base + 0x50C), (void*)(base + 0x500), 3);

    if (!THPInit()) {
        return 0;
    }

    saved = OSDisableInterrupts();
    lbl_803DD66C = param_1;
    lbl_803DD678 = 0;
    lbl_803DD674 = 0;
    lbl_803DD670 = 0;
    oldCb = AIRegisterDMACallback((AIDCallback)fn_80118018);
    lbl_803DD668 = oldCb;

    if (oldCb == (AIDCallback)0) {
        if (lbl_803DD66C != 0) {
            AIRegisterDMACallback((AIDCallback)0);
            OSRestoreInterrupts(saved);
            return 0;
        }
    }

    OSRestoreInterrupts(saved);

    if (lbl_803DD66C == 0) {
        memset(base, 0, 0x500);
        DCFlushRange(base, 0x500);
        AIInitDMA((u32)(base + lbl_803DD678 * 0x280), 0x280);
        AIStartDMA();
    }

    lbl_803DD660 = 1;
    return 1;
}
#pragma peephole reset
#pragma scheduling reset

/* ------------------------------------------------------------------ */
/* fn_80119458 (48 bytes)                                              */
/* ------------------------------------------------------------------ */
#pragma scheduling off
#pragma peephole off
void fn_80119458(OSMessage msg)
{
    OSSendMessage(&lbl_803A7290, msg, OS_MESSAGE_BLOCK);
}
#pragma peephole reset
#pragma scheduling reset

/* ------------------------------------------------------------------ */
/* fn_80119488 (52 bytes)                                              */
/* ------------------------------------------------------------------ */
#pragma dont_inline on
#pragma scheduling off
#pragma peephole off
OSMessage fn_80119488(void)
{
    OSMessage msg;
    OSReceiveMessage(&lbl_803A7290, &msg, OS_MESSAGE_BLOCK);
    return msg;
}
#pragma peephole reset
#pragma scheduling reset
#pragma dont_inline reset

/* ------------------------------------------------------------------ */
/* fn_801194BC (48 bytes)                                              */
/* ------------------------------------------------------------------ */
#pragma dont_inline on
#pragma scheduling off
#pragma peephole off
void fn_801194BC(OSMessage msg)
{
    OSSendMessage(&lbl_803A72D0, msg, OS_MESSAGE_BLOCK);
}
#pragma peephole reset
#pragma scheduling reset
#pragma dont_inline reset

/* ------------------------------------------------------------------ */
/* fn_801194EC (52 bytes)                                              */
/* ------------------------------------------------------------------ */
#pragma dont_inline on
#pragma scheduling off
#pragma peephole off
OSMessage fn_801194EC(void)
{
    OSMessage msg;
    OSReceiveMessage(&lbl_803A72B0, &msg, OS_MESSAGE_BLOCK);
    return msg;
}
#pragma peephole reset
#pragma scheduling reset
#pragma dont_inline reset

/* ------------------------------------------------------------------ */
/* fn_80119520 (248 bytes) - DVD-read thread                           */
/* ------------------------------------------------------------------ */
#pragma scheduling off
#pragma peephole off
void fn_80119520(void)
{
    char* base = lbl_803A5F08;
    int i = 0;
    char* pb = (char*)&lbl_803A5D60;
    u32* req;
    u32 readOff = *(u32*)(pb + 0xB0);
    u32 readSize = *(u32*)(pb + 0xB4);

    while (1) {
        OSMessage msgVal;
        s32 res;

        OSReceiveMessage((OSMessageQueue*)(base + 0x13C8), &msgVal, OS_MESSAGE_BLOCK);
        req = (u32*)msgVal;

        res = DVDReadPrio((DVDFileInfo*)pb, (void*)req[0], readSize, readOff, 2);
        if (res != (s32)readSize) {
            if (res == -1) {
                *(s32*)(pb + 0xA0) = -1;
            }
            if (i == 0) {
                fn_80118B88(0);
            }
            OSSuspendThread((OSThread*)(base + 0x1000));
        }

        req[1] = i;
        OSSendMessage((OSMessageQueue*)(base + 0x13A8), (OSMessage)req, OS_MESSAGE_BLOCK);

        readOff += readSize;
        readSize = *(u32*)(req[0]);

        {
            u32 cols = *(u32*)(pb + 0x50);
            u32 bOff = *(u32*)(pb + 0xB8);
            u32 pos  = (i + bOff) % cols;
            if (pos == cols - 1) {
                if (*(u8*)(pb + 0x9E) & 1) {
                    readOff = *(u32*)(pb + 0x64);
                } else {
                    OSSuspendThread((OSThread*)(base + 0x1000));
                }
            }
        }
        i++;
    }
}
#pragma peephole reset
#pragma scheduling reset

/* ------------------------------------------------------------------ */
/* fn_80119618 (60 bytes)                                              */
/* ------------------------------------------------------------------ */
#pragma scheduling off
#pragma peephole off
void fn_80119618(void)
{
    if (lbl_803DD688 != 0) {
        OSCancelThread(&lbl_803A6F08);
        lbl_803DD688 = 0;
    }
}
#pragma peephole reset
#pragma scheduling reset

/* ------------------------------------------------------------------ */
/* fn_80119654 (52 bytes)                                              */
/* ------------------------------------------------------------------ */
#pragma scheduling off
#pragma peephole off
void fn_80119654(void)
{
    if (lbl_803DD688 != 0) {
        OSResumeThread(&lbl_803A6F08);
    }
}
#pragma peephole reset
#pragma scheduling reset

/* ------------------------------------------------------------------ */
/* fn_80119688 (156 bytes)                                             */
/* ------------------------------------------------------------------ */
#pragma scheduling off
#pragma peephole off
BOOL fn_80119688(OSPriority priority)
{
    char* base = lbl_803A5F08;
    char* stack = base + 0x1000;

    if (!OSCreateThread((OSThread*)stack, (void*(*)(void*))fn_80119520, NULL,
                        stack, 0x1000, priority, 1)) {
        return 0;
    }

    OSInitMessageQueue((OSMessageQueue*)(base + 0x13C8), (void*)(base + 0x1360), 10);
    OSInitMessageQueue((OSMessageQueue*)(base + 0x13A8), (void*)(base + 0x1338), 10);
    OSInitMessageQueue((OSMessageQueue*)(base + 0x1388), (void*)(base + 0x1310), 10);
    lbl_803DD688 = 1;
    return 1;
}
#pragma peephole reset
#pragma scheduling reset

/* ------------------------------------------------------------------ */
/* fn_80119724 (68 bytes)                                              */
/* ------------------------------------------------------------------ */
#pragma scheduling off
#pragma peephole off
OSMessage fn_80119724(s32 flags)
{
    OSMessage msg;
    if (OSReceiveMessage(&lbl_803A7308, &msg, flags) == 1) {
        return msg;
    }
    return (OSMessage)0;
}
#pragma peephole reset
#pragma scheduling reset

/* ------------------------------------------------------------------ */
/* fn_80119768 (48 bytes)                                              */
/* ------------------------------------------------------------------ */
#pragma scheduling off
#pragma peephole off
void fn_80119768(OSMessage msg)
{
    OSSendMessage(&lbl_803A7328, msg, OS_MESSAGE_NOBLOCK);
}
#pragma peephole reset
#pragma scheduling reset

/* ------------------------------------------------------------------ */
/* fn_80119798 (328 bytes) - video decode frame                        */
/* ------------------------------------------------------------------ */
void fn_80119798(void* param)
{
    char* pb  = (char*)&lbl_803A5D60;
    char* db  = lbl_803A72F0;
    char* cur = (char*)((void**)param)[0];
    u32* compSizes = (u32*)(cur + 8);
    char* dvdData = cur + *(u32*)(pb + 0x6C) * 4 + 8;
    void** readMsg;
    u32 i;
    char* pb2;
    char* pbwalk;

    OSReceiveMessage((OSMessageQueue*)(db + 0x38), (OSMessage*)&readMsg, OS_MESSAGE_BLOCK);
    i = 0;
    pb2 = (char*)&lbl_803A5D60;
    pbwalk = pb2;

    while (i < *(u32*)(pb + 0x6C)) {
        if (pbwalk[0x70] == 0) {
            s32 dec = THPVideoDecode(dvdData, readMsg[0], readMsg[1], readMsg[2],
                                     (void*)*(u32*)(pb2 + 0x94));
            *(s32*)(pb2 + 0xA4) = dec;
            if (dec != 0) {
                if (lbl_803DD694 != 0) {
                    fn_80118B88(0);
                    lbl_803DD694 = 0;
                }
                OSSuspendThread((OSThread*)(db + 0x1058));
            }
            readMsg[3] = (void*)((u32*)param)[1];
            OSSendMessage((OSMessageQueue*)(db + 0x18), (OSMessage)readMsg, OS_MESSAGE_BLOCK);
            {
                u32 intr = OSDisableInterrupts();
                *(s32*)(pb2 + 0xD0) += 1;
                OSRestoreInterrupts(intr);
            }
            lbl_803DD698 = 0;
        }
        dvdData += *compSizes;
        compSizes++;
        pbwalk++;
        i++;
    }

    if (lbl_803DD694 != 0) {
        fn_80118B88(1);
        lbl_803DD694 = 0;
    }
}

/* ------------------------------------------------------------------ */
/* fn_801198E0 (316 bytes)                                             */
/* ------------------------------------------------------------------ */
#pragma scheduling off
#pragma peephole off
void fn_801198E0(void* param)
{
    char* pb = (char*)&lbl_803A5D60;   /* r31 */
    u32 frameSize = *(u32*)(pb + 0xB4); /* r30 */
    void* cur = param;                  /* at stack[8], address taken by &cur */
    int i = 0;                          /* r29 */

    while (1) {
        if (*(u8*)(pb + 0x9F) != 0) {
            while (*(s32*)(pb + 0xD0) < 0) {
                {
                    u32 intr = OSDisableInterrupts();
                    *(s32*)(pb + 0xD0) += 1;
                    OSRestoreInterrupts(intr);
                }
                {
                    u32 bOff = *(u32*)(pb + 0xB8);
                    u32 sum  = (u32)i + bOff;
                    u32 cols = *(u32*)(pb + 0x50);
                    u32 pos  = sum % cols;
                    if (pos == cols - 1) {
                        if (!(*(u8*)(pb + 0x9E) & 1)) {
                            break; /* pos==cols-1, not looping: go to decode */
                        }
                        /* looping: update cur and frameSize */
                        frameSize = *(u32*)cur;
                        cur = (void*)*(u32*)(pb + 0xAC);
                    } else {
                        u32 nextSize = *(u32*)cur;
                        cur = (char*)cur + frameSize;
                        frameSize = nextSize;
                    }
                }
                i++;
            }
        }

        /* Store i adjacent to cur on stack so fn_80119798 can read it as param[1] */
        *(s32*)(&cur + 1) = i;
        fn_80119798(&cur);

        {
            u32 bOff = *(u32*)(pb + 0xB8);
            u32 sum  = (u32)i + bOff;
            u32 cols = *(u32*)(pb + 0x50);
            u32 pos  = sum % cols;
            if (pos == cols - 1) {
                if (*(u8*)(pb + 0x9E) & 1) {
                    frameSize = *(u32*)cur;
                    cur = (void*)*(u32*)(pb + 0xAC);
                } else {
                    OSSuspendThread(&lbl_803A8348);
                }
            } else {
                u32 nextSize = *(u32*)cur;
                cur = (char*)cur + frameSize;
                frameSize = nextSize;
            }
        }
        i++;
    }
}
#pragma peephole reset
#pragma scheduling reset

/* ------------------------------------------------------------------ */
/* fn_80119A1C (204 bytes)                                             */
/* ------------------------------------------------------------------ */
#pragma scheduling off
#pragma peephole off
void fn_80119A1C(void)
{
    char* pb = (char*)&lbl_803A5D60;  /* r31 */
    void* msg;                         /* r30 */

    while (1) {
        if (*(u8*)(pb + 0x9F) != 0) {
            while (*(s32*)(pb + 0xD0) < 0) {
                msg = fn_80119488();
                {
                    u32 cols = *(u32*)(pb + 0x50);
                    u32 bOff = *(u32*)(pb + 0xB8);
                    u32 pos  = (*(u32*)((char*)msg + 4) + bOff) % cols;
                    if (pos == cols - 1 && !(*(u8*)(pb + 0x9E) & 1)) {
                        fn_80119798(msg);
                    }
                }
                fn_801194BC((OSMessage)msg);
                {
                    u32 intr = OSDisableInterrupts();
                    *(s32*)(pb + 0xD0) += 1;
                    OSRestoreInterrupts(intr);
                }
            }
        }
        if (*(u8*)(pb + 0x9F) != 0) {
            msg = fn_80119488();
        } else {
            msg = (void*)fn_801194EC();
        }
        fn_80119798(msg);
        fn_801194BC((OSMessage)msg);
    }
}
#pragma peephole reset
#pragma scheduling reset

/* ------------------------------------------------------------------ */
/* fn_80119AE8 (60 bytes)                                              */
/* ------------------------------------------------------------------ */
#pragma scheduling off
#pragma peephole off
void fn_80119AE8(void)
{
    if (lbl_803DD690 != 0) {
        OSCancelThread(&lbl_803A8348);
        lbl_803DD690 = 0;
    }
}
#pragma peephole reset
#pragma scheduling reset

/* ------------------------------------------------------------------ */
/* fn_80119B24 (52 bytes)                                              */
/* ------------------------------------------------------------------ */
#pragma scheduling off
#pragma peephole off
void fn_80119B24(void)
{
    if (lbl_803DD690 != 0) {
        OSResumeThread(&lbl_803A8348);
    }
}
#pragma peephole reset
#pragma scheduling reset

/* ------------------------------------------------------------------ */
/* fn_80119B58 (200 bytes)                                             */
/* ------------------------------------------------------------------ */
#pragma scheduling off
BOOL fn_80119B58(OSPriority param_1, u32 param_2)
{
    char* db = lbl_803A72F0;

    if (param_2 != 0) {
        if (!OSCreateThread((OSThread*)(db + 0x1058), (void*(*)(void*))fn_801198E0, (void*)param_2,
                            (void*)(db + 0x1058), 0x1000, param_1, 1)) {
            return 0;
        }
    } else {
        if (!OSCreateThread((OSThread*)(db + 0x1058), (void*(*)(void*))fn_80119A1C, NULL,
                            (void*)(db + 0x1058), 0x1000, param_1, 1)) {
            return 0;
        }
    }

    OSInitMessageQueue((OSMessageQueue*)(db + 0x38), (void*)(db + 0x0C), 3);
    OSInitMessageQueue((OSMessageQueue*)(db + 0x18), (void*)db, 3);
    lbl_803DD690 = 1;
    lbl_803DD694 = 1;
    return 1;
}
#pragma scheduling reset
