/*
 * dll_3e - THP attract-mode movie playback (FRONT/attract_movie).
 *
 * Drives the streamed THP attract movie via the VI post-retrace callback:
 * PlayControl() runs each retrace, pops a decoded texture set from the
 * decode pipeline, paces it against the audio track (single-field /
 * even-field / odd-field cadence from playFlags), recycles the previously
 * displayed set back to its message queue, and detects end-of-movie /
 * loop completion.
 *
 * THPPlayerPlay/THPPlayerStop arm and tear down the player (state machine
 * in AttractMoviePlayer.state / internalState, with worker threads for
 * video decode, audio decode and DVD read).
 *
 * prepareAttractMode() seeks to a movie within the attract package
 * (offset table indexed by movieIndex), spins up the decode/read threads,
 * primes the message queues (InitAllMessageQueue) and installs the
 * retrace callback. Operates on the AttractMovieControl block at
 * lbl_803A57C0 and the AttractMoviePlayer at lbl_803A5D60.
 */
#include "global.h"
#include "dolphin/os.h"
#include "dolphin/vi/vifuncs.h"
#include "main/dll/FRONT/attract_movie.h"
#include "main/dll/FRONT/n_options.h"
#include "main/dll/FRONT/dll_3B.h"

void InitAllMessageQueue(void);

extern OSMessage PopDecodedTextureSet(s32 flags);
extern int DVDRead(void* fileInfo, void* buf, int size, int offset);
extern BOOL CreateVideoDecodeThread(int priority, void* param);
extern BOOL CreateAudioDecodeThread(int priority, void* param);
extern BOOL CreateReadThread(int priority);
extern void VideoDecodeThreadStart(void);
extern void ReadThreadStart(void);
extern void VideoDecodeThreadCancel(void);
extern void ReadThreadCancel(void);
extern void PushFreeReadBuffer(OSMessage msg);
extern void PushFreeTextureSet(OSMessage msg);
extern OSMessageQueue lbl_803A5CCC;
extern char lbl_803A57C0[];
extern void (*lbl_803DD664)(void);
extern u8 gAttractMovieLoopCompleted;
extern OSMessageQueue lbl_803A5CEC;
extern OSMessage lbl_803DD67C;

typedef struct AttractMovieControl {
    u8 pad000[0x560];
    u32 readBufBegin;     /* 0x560 */
    u32 readBufEnd;       /* 0x564 */
    u8 pad568[0x5f0 - 0x568];
    u32 movieCount;       /* 0x5f0 */
    u32 firstMovieSize;   /* 0x5f4 */
    s32 initReadSize;     /* 0x5f8 */
    u8 pad5fc[0x600 - 0x5fc];
    u32 offsetTable;      /* 0x600 */
    u32 dataOffset;       /* 0x604 */
    u8 pad608[0x638 - 0x608];
    s32 enabled;          /* 0x638 */
    u8 isPrepared;        /* 0x63c */
    u8 field63d;          /* 0x63d */
    u8 playFlags;         /* 0x63e */
    u8 audioExists;       /* 0x63f */
    u8 pad640[0x648 - 0x640];
    s32 preloaded;        /* 0x648 */
    void* loopFrame;      /* 0x64c */
    u32 frameOffset;      /* 0x650 */
    u32 frameSize;        /* 0x654 */
    u32 movieIndex;       /* 0x658 */
    u8 pad65c[0x670 - 0x65c];
    u32 field670;         /* 0x670 */
    u8 pad674[0x684 - 0x674];
    u32 field684;         /* 0x684 */
    u32 field688;         /* 0x688 */
    u32 field68c;         /* 0x68c */
    u32 field690;         /* 0x690 */
} AttractMovieControl;

STATIC_ASSERT(offsetof(AttractMovieControl, readBufBegin) == 0x560);
STATIC_ASSERT(offsetof(AttractMovieControl, movieCount) == 0x5f0);
STATIC_ASSERT(offsetof(AttractMovieControl, offsetTable) == 0x600);
STATIC_ASSERT(offsetof(AttractMovieControl, enabled) == 0x638);
STATIC_ASSERT(offsetof(AttractMovieControl, isPrepared) == 0x63c);
STATIC_ASSERT(offsetof(AttractMovieControl, preloaded) == 0x648);
STATIC_ASSERT(offsetof(AttractMovieControl, frameOffset) == 0x650);
STATIC_ASSERT(offsetof(AttractMovieControl, field670) == 0x670);
STATIC_ASSERT(offsetof(AttractMovieControl, field684) == 0x684);
STATIC_ASSERT(offsetof(AttractMovieControl, field690) == 0x690);

/* playFlags bits (shared by AttractMoviePlayer and AttractMovieControl) */
enum {
    THP_PLAY_LOOP = 1,
    THP_PLAY_EVEN_FIELD = 2,
    THP_PLAY_ODD_FIELD = 4
};

void PlayControl(void)
{
    AttractMovieTextureSet* decodedTexture;
    s32 frame;
    int allowPop;
    s32 modResult;

    if (lbl_803DD664 != NULL)
    {
        lbl_803DD664();
    }

    decodedTexture = (AttractMovieTextureSet*)-1;
    if (lbl_803A5D60.isOpen == 0)
    {
        return;
    }
    if (lbl_803A5D60.state != 2)
    {
        return;
    }
    if ((lbl_803A5D60.dvdError != 0) || (lbl_803A5D60.videoError != 0))
    {
        lbl_803A5D60.internalState = 5;
        lbl_803A5D60.state = 5;
        return;
    }

    if ((lbl_803A5D60.retraceCount == 0) &&
        ((lbl_803A5D60.internalState == 0) || (lbl_803A5D60.internalState == 4)))
    {
        lbl_803A5D60.internalState = 2;
    }
    lbl_803A5D60.retraceCount++;

    if ((lbl_803A5D60.internalState == 0) || (lbl_803A5D60.internalState == 4))
    {
        if ((lbl_803A5D60.playFlags & THP_PLAY_EVEN_FIELD) != 0)
        {
            if (VIGetNextField() != 0)
            {
                goto deny;
            }
            allowPop = 1;
            goto checked;
        }
        else if ((lbl_803A5D60.playFlags & THP_PLAY_ODD_FIELD) != 0)
        {
            if (VIGetNextField() != 1)
            {
                goto deny;
            }
            allowPop = 1;
            goto checked;
        }
        else
        {
            allowPop = 1;
            goto checked;
        }
    deny:
        allowPop = 0;
    checked:

        if (allowPop != 0)
        {
            if (lbl_803A5D60.audioExists != 0)
            {
                frame = lbl_803A5D60.curAudioTrack - lbl_803A5D60.curVideoNumber;
                if (frame <= 1)
                {
                    decodedTexture = (AttractMovieTextureSet*)PopDecodedTextureSet(0);
                    if (lbl_803A5D60.videoDecodeCount > frame)
                    {
                        lbl_803A5D60.videoDecodeCount--;
                    }
                }
                else
                {
                    lbl_803A5D60.internalState = 2;
                }
            }
            else
            {
                decodedTexture = (AttractMovieTextureSet*)PopDecodedTextureSet(0);
                lbl_803A5D60.internalState = 2;
            }
        }
        else
        {
            lbl_803A5D60.retraceCount = -1;
        }
    }
    else if (ProperTimingForGettingNextFrame() != 0)
    {
        if (lbl_803A5D60.audioExists != 0)
        {
            frame = lbl_803A5D60.curAudioTrack - lbl_803A5D60.curVideoNumber;
            if (frame <= 1)
            {
                decodedTexture = (AttractMovieTextureSet*)PopDecodedTextureSet(0);
                if (lbl_803A5D60.videoDecodeCount > frame)
                {
                    lbl_803A5D60.videoDecodeCount--;
                }
            }
        }
        else
        {
            decodedTexture = (AttractMovieTextureSet*)PopDecodedTextureSet(0);
        }
    }

    if ((decodedTexture != NULL) && (decodedTexture != (AttractMovieTextureSet*)-1))
    {
        lbl_803A5D60.curAudioTrack = decodedTexture->frameNumber;
        if ((void*)lbl_803A5D60.curAudioNumber != NULL)
        {
            OSSendMessage(&lbl_803A5CCC, (OSMessage)lbl_803A5D60.curAudioNumber, OS_MESSAGE_NOBLOCK);
        }
        lbl_803A5D60.curAudioNumber = (s32)decodedTexture;
    }

    if ((lbl_803A5D60.playFlags & THP_PLAY_LOOP) == 0)
    {
        if (lbl_803A5D60.audioExists != 0)
        {
            modResult = (lbl_803A5D60.curVideoNumber + lbl_803A5D60.initReadFrame) %
                lbl_803A5D60.header.mNumFrames;
            if ((modResult == (lbl_803A5D60.header.mNumFrames - 1)) &&
                (lbl_803A5D60.dispTextureSet == NULL))
            {
                modResult = (lbl_803A5D60.curAudioTrack + lbl_803A5D60.initReadFrame) %
                    lbl_803A5D60.header.mNumFrames;
                if ((modResult == (lbl_803A5D60.header.mNumFrames - 1)) &&
                    (decodedTexture == NULL))
                {
                    lbl_803A5D60.internalState = 3;
                    lbl_803A5D60.state = 3;
                }
            }
        }
        else
        {
            u32 numFrames;
            modResult = (lbl_803A5D60.curAudioTrack + lbl_803A5D60.initReadFrame) %
                (numFrames = lbl_803A5D60.header.mNumFrames);
            if ((modResult == (numFrames - 1)) && (decodedTexture == NULL))
            {
                lbl_803A5D60.internalState = 3;
                lbl_803A5D60.state = 3;
            }
        }
    }
    else
    {
        u32 numFrames;
        modResult = (lbl_803A5D60.curAudioTrack + lbl_803A5D60.initReadFrame) %
            (numFrames = lbl_803A5D60.header.mNumFrames);
        if (modResult == (numFrames - 1))
        {
            gAttractMovieLoopCompleted = 1;
        }
    }
}

void THPPlayerStop(void)
{
    OSMessage msg;

    if ((lbl_803A5D60.isOpen != 0) && (lbl_803A5D60.state != 0))
    {
        lbl_803A5D60.internalState = 0;
        lbl_803A5D60.state = 0;
        VISetPostRetraceCallback((void (*)(u32))lbl_803DD664);

        if (lbl_803A5D60.isOnMemory == 0)
        {
            DVDCancel((DVDCommandBlock*)&lbl_803A5D60.fileInfo);
            ReadThreadCancel();
        }

        VideoDecodeThreadCancel();
        if (lbl_803A5D60.audioExists != 0)
        {
            AudioDecodeThreadCancel();
        }

        while (((OSReceiveMessage(&lbl_803A5CCC, &msg, OS_MESSAGE_NOBLOCK) == TRUE) ? msg : NULL) != NULL)
        {
        }

        lbl_803A5D60.curVolume = lbl_803A5D60.targetVolume;
        lbl_803A5D60.rampCount = 0;
        lbl_803A5D60.dvdError = 0;
        lbl_803A5D60.videoError = 0;
    }
}

BOOL THPPlayerPlay(void)
{
    if ((lbl_803A5D60.isOpen != 0) &&
        ((lbl_803A5D60.state == 1) || (lbl_803A5D60.state == 4)))
    {
        lbl_803A5D60.state = 2;
        lbl_803A5D60.prevCount = 0;
        lbl_803A5D60.curCount = 0;
        lbl_803A5D60.retraceCount = -1;
        return TRUE;
    }
    return FALSE;
}

BOOL prepareAttractMode(u32 movieIndex, s32 playFlags)
{
    char* base;
    AttractMovieControl* ctrl;
    s32 readyMsg;
    s32 startOffset;

    base = lbl_803A57C0;
    ctrl = (AttractMovieControl*)base;
    gAttractMovieLoopCompleted = 0;

    if (ctrl->enabled != 0 && ctrl->isPrepared == 0)
    {
    if ((s32)movieIndex > 0)
    {
        u32 offsetTable = ctrl->offsetTable;

        if (offsetTable == 0)
        {
            return FALSE;
        }
        if (ctrl->movieCount > movieIndex)
        {
            if (DVDRead((DVDFileInfo*)(base + 0x5a0), base + 0x560, 0x20,
                        offsetTable + ((movieIndex - 1) * sizeof(u32))) < 0)
            {
                return FALSE;
            }

            ctrl->frameOffset = ctrl->dataOffset + ctrl->readBufBegin;
            ctrl->movieIndex = movieIndex;
            ctrl->frameSize = ctrl->readBufEnd - ctrl->readBufBegin;
        }
        else
        {
            return FALSE;
        }
    }
    else
    {
        ctrl->frameOffset = ctrl->dataOffset;
        ctrl->frameSize = ctrl->firstMovieSize;
        ctrl->movieIndex = movieIndex;
    }

    ctrl->playFlags = playFlags;
    ctrl->field670 = 0;

    if (ctrl->preloaded != 0)
    {
        if (DVDRead((DVDFileInfo*)(base + 0x5a0), ctrl->loopFrame,
                    ctrl->initReadSize, ctrl->dataOffset) < 0)
        {
            return FALSE;
        }
        startOffset = ((s32)ctrl->loopFrame + ctrl->frameOffset) -
            ctrl->dataOffset;
        CreateVideoDecodeThread(0xf, (void*)startOffset);
        if (ctrl->audioExists != 0)
        {
            CreateAudioDecodeThread(0xc, (void*)startOffset);
        }
    }
    else
    {
        CreateVideoDecodeThread(0xf, NULL);
        if (ctrl->audioExists != 0)
        {
            CreateAudioDecodeThread(0xc, NULL);
        }
        CreateReadThread(8);
    }

    InitAllMessageQueue();
    VideoDecodeThreadStart();
    if (ctrl->audioExists != 0)
    {
        AudioDecodeThreadStart();
    }
    if (ctrl->preloaded == 0)
    {
        ReadThreadStart();
    }

    OSReceiveMessage((OSMessageQueue*)(base + 0x52c), (OSMessage*)&readyMsg, OS_MESSAGE_BLOCK);
    if (readyMsg == 0)
    {
        return FALSE;
    }
    ctrl->isPrepared = 1;
    ctrl->field63d = 0;
    ctrl->field68c = 0;
    ctrl->field690 = 0;
    ctrl->field684 = 0;
    ctrl->field688 = 0;
    lbl_803DD664 = (void (*)(void))VISetPostRetraceCallback((void (*)(u32))PlayControl);
    return TRUE;
    }
    return FALSE;
}

void PrepareReady(void* msg)
{
    OSSendMessage(&lbl_803A5CEC, msg, OS_MESSAGE_BLOCK);
}

void InitAllMessageQueue(void)
{
    AttractMoviePlayer* buf;
    s32 i;

    buf = &lbl_803A5D60;
    if (buf->isOnMemory == 0)
    {
        for (i = 0; i < 10; i++)
        {
            PushFreeReadBuffer((OSMessage)&buf->readBuffer[i]);
        }
    }

    i = 0;
    buf = &lbl_803A5D60;
    do
    {
        PushFreeTextureSet((OSMessage)&buf->textureSet[i]);
        i++;
    }
    while (i < 3);

    if (lbl_803A5D60.audioExists != 0)
    {
        i = 0;
        do
        {
            PushFreeAudioBuffer((OSMessage)&buf->audioBuffer[i]);
            i++;
        }
        while (i < 3);
    }

    OSInitMessageQueue(&lbl_803A5CEC, &lbl_803DD67C, 1);
}
