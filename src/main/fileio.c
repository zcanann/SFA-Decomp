#include "ghidra_import.h"
#include "main/engine_shared.h"

#pragma scheduling off
void dvdCheckError(void)
{
    int msgId = 0xffff;
    int status;

    if (gAudioStreamPlayAddrCallbackDone) {
        gAudioStreamPlayAddrCallbackDone = 0;
        gAudioStreamPlayAddrCallbackResult = 0;
        DVDGetStreamPlayAddrAsync(lbl_80339950, AudioStream_PlayAddrCallback);
    }

    status = DVDGetDriveStatus();
    lbl_803DC960 = status;
    switch (status) {
    case -1:
        msgId = 0x339;
        stopRumble2();
        if (lbl_803DC950 == 0) {
            lbl_803DC950 = 1;
            setTimeStop(0xff);
            cutsceneFadeInOut(1);
            lbl_803DC951 = 1;
        }
        break;
    case 4:
        msgId = 0x33d;
        stopRumble2();
        if (lbl_803DC950 == 0) {
            lbl_803DC950 = 1;
            setTimeStop(0xff);
            cutsceneFadeInOut(1);
        }
        break;
    case 5:
        msgId = 0x33c;
        stopRumble2();
        if (lbl_803DC950 == 0) {
            lbl_803DC950 = 1;
            setTimeStop(0xff);
            cutsceneFadeInOut(1);
        }
        break;
    case 6:
        msgId = 0x33e;
        stopRumble2();
        if (lbl_803DC950 == 0) {
            lbl_803DC950 = 1;
            setTimeStop(0xff);
            cutsceneFadeInOut(1);
        }
        break;
    case 11:
        msgId = 0x33a;
        stopRumble2();
        if (lbl_803DC950 == 0) {
            lbl_803DC950 = 1;
            setTimeStop(0xff);
            cutsceneFadeInOut(1);
        }
        break;
    default:
        if (lbl_803DC950 != 0) {
            if ((getLoadedFileFlags(0) & ~0x100000) == 0) {
                if (getGameState() != 1 || DVDCheckDisk() != 0) {
                    lbl_803DC950 = 0;
                    cutsceneFadeInOut(0);
                    Sfx_SetObjectSoundsPaused(0);
                }
            }
        }
        break;
    }

    if (msgId != 0xffff) {
        int prevCharset = gameTextFn_80019b14();
        Sfx_SetObjectSoundsPaused(1);
        gameTextSetCharset(2, 2);
        gameTextSetColor(0xff, 0xff, 0xff, 0xff);
        gameTextShow(msgId);
        if (prevCharset != 2) {
            gameTextSetCharset(prevCharset, 2);
        }
    }
}
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void fileReadCb_80015954(void* result)
{
    lbl_803DC958 = (int)result;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void setFileInfo(void* fileInfo)
{
    lbl_803DC954 = fileInfo;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void* loadFileByPath(char* path, int* outSize)
{
    u8 fileInfo[0x3c];
    int size;
    u32 alignedSize;
    void* buf;
    if (outSize != NULL) {
        *outSize = 0;
    }
    DVDSetAutoInvalidation(1);
    if (DVDOpen(path, fileInfo) == 0) {
        return NULL;
    }
    size = *(u32*)(fileInfo + 0x34);
    alignedSize = (size + 0x1f) & ~0x1f;
    buf = mmAlloc(alignedSize, 0x7d7d7d7d, NULL);
    if (buf == NULL) {
        return NULL;
    }
    if (DVDRead(fileInfo, buf, alignedSize, 0) == -1) {
        mm_free(buf);
        return NULL;
    }
    if (DVDClose(fileInfo) == 0) {
        mm_free(buf);
        return NULL;
    }
    DCStoreRange(buf, size);
    if (outSize != NULL) {
        *outSize = size;
    }
    return buf;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
int DVDRead(void* fileInfo, void* buf, int size, int offset)
{
    u8 resetSeen = 0;
    lbl_803DC958 = 0;
    while (lbl_803DC958 == 0 || lbl_803DC958 == -1 || lbl_803DC958 == -3) {
        DVDReadAsyncPrio(fileInfo, buf, size, offset, fileReadCb_80015954, 2);
        while (lbl_803DC958 == 0 || lbl_803DC958 == -1) {
            padUpdate();
            checkReset();
            if (resetSeen) {
                waitNextFrame();
            }
            dvdCheckError();
            if (resetSeen) {
                mmFreeTick(0);
                gameTextRun();
                GXFlush_(1, 0);
            }
            if (lbl_803DC950 != 0) {
                resetSeen = 1;
            }
        }
    }
    return lbl_803DC958;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
#pragma dont_inline on
void* loadFileByPathAsync(char* path, int* outSize, int unused, void (*cb)(void*))
{
    void* fileInfo;
    int size;
    u32 alignedSize;
    void* buf;
    int guard;
    if (outSize != NULL) {
        *outSize = 0;
    }
    DVDSetAutoInvalidation(1);
    if (lbl_803DC954 != NULL) {
        fileInfo = lbl_803DC954;
    } else {
        guard = testAndSet_onlyUseHeap3(0);
        fileInfo = mmAlloc(0x3c, 0xFACEFEED, NULL);
        testAndSet_onlyUseHeap3(guard);
    }
    if (DVDOpen(path, fileInfo) == 0) {
        mm_free(fileInfo);
        return NULL;
    }
    size = *(int*)((u8*)fileInfo + 0x34);
    alignedSize = (size + 0x1f) & ~0x1f;
    guard = testAndSet_onlyUseHeap3(0);
    buf = mmAlloc(alignedSize, 0x7d7d7d7d, NULL);
    testAndSet_onlyUseHeap3(guard);
    if (buf == NULL) {
        mm_free(fileInfo);
        return NULL;
    }
    if (DVDReadAsyncPrio(fileInfo, buf, alignedSize, 0, cb, 2) != 0) {
        if (outSize != NULL) {
            *outSize = size;
        }
        return buf;
    }
    mm_free(buf);
    mm_free(fileInfo);
    return NULL;
}
#pragma dont_inline reset
#pragma peephole reset
#pragma scheduling reset
