#include "main/audio/stream_api.h"
#include "main/audio/sfx.h"
#include "main/fileio.h"
#include "main/gameloop_api.h"
#include "main/gametext_charset_api.h"
#include "main/gametext_show_api.h"
#include "main/textrender_api.h"
#include "main/loaded_file_flags.h"
#include "main/mm.h"
#include "main/pad.h"
#include "main/pi_dolphin_api.h"
#include "dolphin/dvd.h"
#include "dolphin/gx/GXLegacy.h"
#include "dolphin/os/OSCache.h"

// DVDGetDriveStatus() drive-status codes
#define DVD_STATE_FATAL_ERROR -1
#define DVD_STATE_NO_DISK     4
#define DVD_STATE_COVER_OPEN  5
#define DVD_STATE_WRONG_DISK  6
#define DVD_STATE_RETRY       11

// gameTextShow() message ids for the on-screen disk-error prompts
#define GAMETEXT_MSG_DVD_FATAL_ERROR 0x339
#define GAMETEXT_MSG_DVD_RETRY       0x33a
#define GAMETEXT_MSG_DVD_COVER_OPEN  0x33c
#define GAMETEXT_MSG_DVD_NO_DISK     0x33d
#define GAMETEXT_MSG_DVD_WRONG_DISK  0x33e

DVDCommandBlock lbl_80339950;

void dvdCheckError(void)
{
    int msgId = 0xffff;
    int status;

    if (gAudioStreamPlayAddrCallbackDone)
    {
        gAudioStreamPlayAddrCallbackDone = 0;
        gAudioStreamPlayAddrCallbackResult = 0;
        DVDGetStreamPlayAddrAsync(&lbl_80339950, (DVDCBCallback)AudioStream_PlayAddrCallback);
    }

    status = DVDGetDriveStatus();
    gDvdLastDriveStatus = status;
    switch (status)
    {
    case DVD_STATE_FATAL_ERROR:
        msgId = GAMETEXT_MSG_DVD_FATAL_ERROR;
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
        msgId = GAMETEXT_MSG_DVD_NO_DISK;
        stopRumble2();
        if (gDvdErrorPauseActive == 0)
        {
            gDvdErrorPauseActive = 1;
            setTimeStop(0xff);
            cutsceneFadeInOut(1);
        }
        break;
    case DVD_STATE_COVER_OPEN:
        msgId = GAMETEXT_MSG_DVD_COVER_OPEN;
        stopRumble2();
        if (gDvdErrorPauseActive == 0)
        {
            gDvdErrorPauseActive = 1;
            setTimeStop(0xff);
            cutsceneFadeInOut(1);
        }
        break;
    case DVD_STATE_WRONG_DISK:
        msgId = GAMETEXT_MSG_DVD_WRONG_DISK;
        stopRumble2();
        if (gDvdErrorPauseActive == 0)
        {
            gDvdErrorPauseActive = 1;
            setTimeStop(0xff);
            cutsceneFadeInOut(1);
        }
        break;
    case DVD_STATE_RETRY:
        msgId = GAMETEXT_MSG_DVD_RETRY;
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
        gameTextSetColorInt(0xff, 0xff, 0xff, 0xff);
        gameTextShow(msgId);
        if (prevCharset != 2)
        {
            gameTextSetCharset(prevCharset, 2);
        }
    }
}

#pragma dont_inline on
int DVDRead(DVDFileInfo* fileInfo, void* buf, int size, int offset)
{
    typedef int (*DVDReadAsyncPrioCompatFn)(void*, void*, int, int, void (*)(void*), int);
    u8 resetSeen = 0;
    gDvdReadCallbackResult = 0;
    while (gDvdReadCallbackResult == 0 || gDvdReadCallbackResult == -1 || gDvdReadCallbackResult == -3)
    {
        ((DVDReadAsyncPrioCompatFn)DVDReadAsyncPrio)(fileInfo, buf, size, offset,
                                                     (void (*)(void*))fileReadCb_80015954, 2);
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
#pragma dont_inline reset

void fileReadCb_80015954(s32 result, DVDFileInfo* fileInfo)
{
    (void)fileInfo;
    gDvdReadCallbackResult = result;
}

void setFileInfo(DVDFileInfo* fileInfo)
{
    gFileInfo = fileInfo;
}

void* loadFileByPathAsync(char* path, int* outSize, int unused, DVDCallback cb)
{
    DVDFileInfo* fileInfo;
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
        guard = testAndSetOnlyUseHeap3_u8(0);
        fileInfo = mmAllocTagged(sizeof(DVDFileInfo), 0xFACEFEED, NULL);
        testAndSetOnlyUseHeap3_u8(guard);
    }
    if (DVDOpen(path, fileInfo) == 0)
    {
        mm_free(fileInfo);
        return NULL;
    }
    size = *(int*)((u8*)fileInfo + 0x34);
    alignedSize = (size + 0x1f) & ~0x1f;
    guard = testAndSetOnlyUseHeap3_u8(0);
    buf = mmAllocTagged(alignedSize, 0x7d7d7d7d, NULL);
    testAndSetOnlyUseHeap3_u8(guard);
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

void* loadFileByPath(char* path, int* outSize)
{
    DVDFileInfo fileInfo;
    int size;
    u32 alignedSize;
    void* buf;
    if (outSize != NULL)
    {
        *outSize = 0;
    }
    DVDSetAutoInvalidation(1);
    if (DVDOpen(path, &fileInfo) == 0)
    {
        return NULL;
    }
    size = fileInfo.length;
    alignedSize = (size + 0x1f) & ~0x1f;
    buf = mmAllocTagged(alignedSize, 0x7d7d7d7d, NULL);
    if (buf == NULL)
    {
        return NULL;
    }
    if (DVDRead(&fileInfo, buf, alignedSize, 0) == -1)
    {
        mm_free(buf);
        return NULL;
    }
    if (DVDClose(&fileInfo) == 0)
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
