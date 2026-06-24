#include "main/engine_shared.h"

// DVDGetDriveStatus() drive-status codes
#define DVD_STATE_FATAL_ERROR -1
#define DVD_STATE_NO_DISK 4
#define DVD_STATE_COVER_OPEN 5
#define DVD_STATE_WRONG_DISK 6
#define DVD_STATE_RETRY 11

void dvdCheckError(void)
{
    int msgId = 0xffff;
    int status;

    if (gAudioStreamPlayAddrCallbackDone)
    {
        gAudioStreamPlayAddrCallbackDone = 0;
        gAudioStreamPlayAddrCallbackResult = 0;
        DVDGetStreamPlayAddrAsync(lbl_80339950, AudioStream_PlayAddrCallback);
    }

    status = DVDGetDriveStatus();
    gDvdLastDriveStatus = status;
    switch (status)
    {
    case DVD_STATE_FATAL_ERROR:
        msgId = 0x339;
        stopRumble2();
        if (gDvdErrorPauseActive == 0)
        {
            gDvdErrorPauseActive = 1;
            setTimeStop(0xff);
            cutsceneFadeInOut(1);
            gDvdCoverOpenErrorActive = 1;
        }
        break;
    case DVD_STATE_NO_DISK:
        msgId = 0x33d;
        stopRumble2();
        if (gDvdErrorPauseActive == 0)
        {
            gDvdErrorPauseActive = 1;
            setTimeStop(0xff);
            cutsceneFadeInOut(1);
        }
        break;
    case DVD_STATE_COVER_OPEN:
        msgId = 0x33c;
        stopRumble2();
        if (gDvdErrorPauseActive == 0)
        {
            gDvdErrorPauseActive = 1;
            setTimeStop(0xff);
            cutsceneFadeInOut(1);
        }
        break;
    case DVD_STATE_WRONG_DISK:
        msgId = 0x33e;
        stopRumble2();
        if (gDvdErrorPauseActive == 0)
        {
            gDvdErrorPauseActive = 1;
            setTimeStop(0xff);
            cutsceneFadeInOut(1);
        }
        break;
    case DVD_STATE_RETRY:
        msgId = 0x33a;
        stopRumble2();
        if (gDvdErrorPauseActive == 0)
        {
            gDvdErrorPauseActive = 1;
            setTimeStop(0xff);
            cutsceneFadeInOut(1);
        }
        break;
    default:
        if (gDvdErrorPauseActive != 0)
        {
            if ((getLoadedFileFlags(0) & ~0x100000) == 0)
            {
                if (getGameState() != 1 || DVDCheckDisk() != 0)
                {
                    gDvdErrorPauseActive = 0;
                    cutsceneFadeInOut(0);
                    Sfx_SetObjectSoundsPaused(0);
                }
            }
        }
        break;
    }

    if (msgId != 0xffff)
    {
        int prevCharset = gameTextGetCharset();
        Sfx_SetObjectSoundsPaused(1);
        gameTextSetCharset(2, 2);
        gameTextSetColor(0xff, 0xff, 0xff, 0xff);
        gameTextShow(msgId);
        if (prevCharset != 2)
        {
            gameTextSetCharset(prevCharset, 2);
        }
    }
}

void fileReadCb_80015954(void* result)
{
    gDvdReadCallbackResult = (int)result;
}

void setFileInfo(void* fileInfo)
{
    gFileInfo = fileInfo;
}

void* loadFileByPath(char* path, int* outSize)
{
    u8 fileInfo[0x3c];
    int size;
    u32 alignedSize;
    void* buf;
    if (outSize != NULL)
    {
        *outSize = 0;
    }
    DVDSetAutoInvalidation(1);
    if (DVDOpen(path, fileInfo) == 0)
    {
        return NULL;
    }
    size = *(u32*)(fileInfo + 0x34);
    alignedSize = (size + 0x1f) & ~0x1f;
    buf = mmAlloc(alignedSize, 0x7d7d7d7d, NULL);
    if (buf == NULL)
    {
        return NULL;
    }
    if (DVDRead(fileInfo, buf, alignedSize, 0) == -1)
    {
        mm_free(buf);
        return NULL;
    }
    if (DVDClose(fileInfo) == 0)
    {
        mm_free(buf);
        return NULL;
    }
    DCStoreRange(buf, size);
    if (outSize != NULL)
    {
        *outSize = size;
    }
    return buf;
}

int DVDRead(void* fileInfo, void* buf, int size, int offset)
{
    u8 resetSeen = 0;
    gDvdReadCallbackResult = 0;
    while (gDvdReadCallbackResult == 0 || gDvdReadCallbackResult == -1 ||
        gDvdReadCallbackResult == -3)
    {
        DVDReadAsyncPrio(fileInfo, buf, size, offset, fileReadCb_80015954, 2);
        while (gDvdReadCallbackResult == 0 || gDvdReadCallbackResult == -1)
        {
            padUpdate();
            checkReset();
            if (resetSeen)
            {
                waitNextFrame();
            }
            dvdCheckError();
            if (resetSeen)
            {
                mmFreeTick(0);
                gameTextRun();
                GXFlush_(1, 0);
            }
            if (gDvdErrorPauseActive != 0)
            {
                resetSeen = 1;
            }
        }
    }
    return gDvdReadCallbackResult;
}

void* loadFileByPathAsync(char* path, int* outSize, int unused, void (*cb)(void*))
{
    void* fileInfo;
    int size;
    u32 alignedSize;
    void* buf;
    int guard;
    if (outSize != NULL)
    {
        *outSize = 0;
    }
    DVDSetAutoInvalidation(1);
    if (gFileInfo != NULL)
    {
        fileInfo = gFileInfo;
    }
    else
    {
        guard = testAndSet_onlyUseHeap3(0);
        fileInfo = mmAlloc(0x3c, 0xFACEFEED, NULL);
        testAndSet_onlyUseHeap3(guard);
    }
    if (DVDOpen(path, fileInfo) == 0)
    {
        mm_free(fileInfo);
        return NULL;
    }
    size = *(int*)((u8*)fileInfo + 0x34);
    alignedSize = (size + 0x1f) & ~0x1f;
    guard = testAndSet_onlyUseHeap3(0);
    buf = mmAlloc(alignedSize, 0x7d7d7d7d, NULL);
    testAndSet_onlyUseHeap3(guard);
    if (buf == NULL)
    {
        mm_free(fileInfo);
        return NULL;
    }
    if (DVDReadAsyncPrio(fileInfo, buf, alignedSize, 0, cb, 2) != 0)
    {
        if (outSize != NULL)
        {
            *outSize = size;
        }
        return buf;
    }
    mm_free(buf);
    mm_free(fileInfo);
    return NULL;
}
