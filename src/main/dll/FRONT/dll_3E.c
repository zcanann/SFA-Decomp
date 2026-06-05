#include "ghidra_import.h"
#include "dolphin/os.h"
#include "dolphin/vi/vifuncs.h"
#include "main/dll/FRONT/attract_movie.h"
#include "main/dll/FRONT/dll_3E.h"

extern int FUN_80006c30();
extern int ProperTimingForGettingNextFrame(void);
extern undefined4 FUN_801177dc();
extern undefined4 FUN_80117818();
extern undefined4 THPPlayerDrawCurrentFrame();
extern int FUN_80118540();
extern undefined4 AttractMovie_AssignBuffers();
extern undefined4 FUN_801197e0();
extern undefined4 FUN_8011981c();
extern undefined4 FUN_80119850();
extern int FUN_801198e8();
extern undefined4 FUN_80119c60();
extern undefined4 FUN_80119c9c();
extern undefined4 FUN_80119cd0();
extern undefined4 FUN_80244758();
extern int FUN_80244820();
extern undefined4 FUN_8024bdfc();
extern undefined4 FUN_8024c910();
extern ushort FUN_8024df24();
extern OSMessage PopDecodedTextureSet(s32 flags);
extern s32 DVDRead(DVDFileInfo *fileInfo, void *addr, s32 length, s32 offset);
extern BOOL CreateVideoDecodeThread(int priority, void *param);
extern BOOL CreateAudioDecodeThread(int priority, void *param);
extern BOOL CreateReadThread(int priority);
extern void InitAllMessageQueue(void);
extern void VideoDecodeThreadStart(void);
extern void AudioDecodeThreadStart(void);
extern void ReadThreadStart(void);
extern void VideoDecodeThreadCancel(void);
extern void AudioDecodeThreadCancel(void);
extern void ReadThreadCancel(void);
extern void PushFreeReadBuffer(OSMessage msg);
extern void PushFreeTextureSet(OSMessage msg);
extern void PushFreeAudioBuffer(void *msg);

extern OSMessageQueue lbl_803A5CCC;
extern char lbl_803A57C0[];
extern undefined4 DAT_803a692c;
extern undefined4 DAT_803a694c;
extern undefined4 DAT_803a6980;
extern undefined4 DAT_803a6984;
extern undefined4 DAT_803a69c0;
extern undefined4 DAT_803a6a10;
extern undefined4 DAT_803a6a14;
extern undefined4 DAT_803a6a18;
extern undefined4 DAT_803a6a20;
extern undefined4 DAT_803a6a24;
extern undefined4 DAT_803a6a58;
extern undefined4 DAT_803a6a5c;
extern undefined4 DAT_803a6a5d;
extern undefined4 DAT_803a6a5e;
extern undefined4 DAT_803a6a5f;
extern undefined4 DAT_803a6a60;
extern undefined4 DAT_803a6a64;
extern undefined4 DAT_803a6a68;
extern undefined4 DAT_803a6a6c;
extern undefined4 DAT_803a6a70;
extern undefined4 DAT_803a6a74;
extern undefined4 DAT_803a6a78;
extern undefined4 DAT_803a6a80;
extern undefined4 DAT_803a6a84;
extern undefined4 DAT_803a6a88;
extern undefined4 DAT_803a6a8c;
extern undefined4 DAT_803a6a90;
extern undefined4 DAT_803a6a94;
extern undefined4 DAT_803a6a98;
extern undefined4 DAT_803a6aa0;
extern undefined4 DAT_803a6aa4;
extern undefined4 DAT_803a6aa8;
extern undefined4 DAT_803a6aac;
extern undefined4 DAT_803a6ab0;
extern undefined4* DAT_803de2e4;
extern undefined4 DAT_803de300;
extern void (*lbl_803DD664)(void);
extern u8 gAttractMovieLoopCompleted;
extern OSMessageQueue lbl_803A5CEC;
extern OSMessage lbl_803DD67C;

/*
 * --INFO--
 *
 * Function: PlayControl
 * EN v1.0 Address: 0x8011846C
 * EN v1.0 Size: 944b
 * EN v1.1 Address: 0x80118714
 * EN v1.1 Size: 944b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off
void PlayControl(void)
{
  AttractMovieTextureSet *decodedTexture;
  s32 frame;
  u32 allowPop;

  if (lbl_803DD664 != NULL) {
    lbl_803DD664();
  }

  decodedTexture = (AttractMovieTextureSet *)-1;
  if (lbl_803A5D60.isOpen == 0) {
    return;
  }
  if (lbl_803A5D60.state != 2) {
    return;
  }
  if ((lbl_803A5D60.dvdError != 0) || (lbl_803A5D60.videoError != 0)) {
    lbl_803A5D60.internalState = 5;
    lbl_803A5D60.state = 5;
    return;
  }

  if ((lbl_803A5D60.retraceCount == 0) &&
      ((lbl_803A5D60.internalState == 0) || (lbl_803A5D60.internalState == 4))) {
    lbl_803A5D60.internalState = 2;
  }
  lbl_803A5D60.retraceCount++;

  if ((lbl_803A5D60.internalState == 0) || (lbl_803A5D60.internalState == 4)) {
    if ((lbl_803A5D60.playFlags & 2) != 0) {
      allowPop = (VIGetNextField() == 0) ? 1 : 0;
    }
    else if ((lbl_803A5D60.playFlags & 4) != 0) {
      allowPop = (VIGetNextField() == 1) ? 1 : 0;
    }
    else {
      allowPop = 1;
    }

    if (allowPop != 0) {
      if (lbl_803A5D60.audioExists != 0) {
        frame = lbl_803A5D60.curAudioTrack - lbl_803A5D60.curVideoNumber;
        if (frame <= 1) {
          decodedTexture = (AttractMovieTextureSet *)PopDecodedTextureSet(0);
          if (lbl_803A5D60.videoDecodeCount > frame) {
            lbl_803A5D60.videoDecodeCount--;
          }
        }
        else {
          lbl_803A5D60.internalState = 2;
        }
      }
      else {
        decodedTexture = (AttractMovieTextureSet *)PopDecodedTextureSet(0);
        lbl_803A5D60.internalState = 2;
      }
    }
    else {
      lbl_803A5D60.retraceCount = -1;
    }
  }
  else if (ProperTimingForGettingNextFrame() != 0) {
    if (lbl_803A5D60.audioExists != 0) {
      frame = lbl_803A5D60.curAudioTrack - lbl_803A5D60.curVideoNumber;
      if (frame <= 1) {
        decodedTexture = (AttractMovieTextureSet *)PopDecodedTextureSet(0);
        if (lbl_803A5D60.videoDecodeCount > frame) {
          lbl_803A5D60.videoDecodeCount--;
        }
      }
    }
    else {
      decodedTexture = (AttractMovieTextureSet *)PopDecodedTextureSet(0);
    }
  }

  if ((decodedTexture != NULL) && ((u32)decodedTexture != 0xffffffff)) {
    lbl_803A5D60.curAudioTrack = decodedTexture->frameNumber;
    if (lbl_803A5D60.curAudioNumber != 0) {
      OSSendMessage(&lbl_803A5CCC, (OSMessage)lbl_803A5D60.curAudioNumber, OS_MESSAGE_NOBLOCK);
    }
    lbl_803A5D60.curAudioNumber = (s32)decodedTexture;
  }

  if ((lbl_803A5D60.playFlags & 1) == 0) {
    if (lbl_803A5D60.audioExists != 0) {
      if ((((lbl_803A5D60.curVideoNumber + lbl_803A5D60.initReadFrame) %
            lbl_803A5D60.header.mNumFrames) == (lbl_803A5D60.header.mNumFrames - 1)) &&
          (lbl_803A5D60.dispTextureSet == NULL) &&
          (((lbl_803A5D60.curAudioTrack + lbl_803A5D60.initReadFrame) %
            lbl_803A5D60.header.mNumFrames) == (lbl_803A5D60.header.mNumFrames - 1)) &&
          (decodedTexture == NULL)) {
        lbl_803A5D60.internalState = 3;
        lbl_803A5D60.state = 3;
      }
    }
    else if ((((lbl_803A5D60.curAudioTrack + lbl_803A5D60.initReadFrame) %
               lbl_803A5D60.header.mNumFrames) == (lbl_803A5D60.header.mNumFrames - 1)) &&
             (decodedTexture == NULL)) {
      lbl_803A5D60.internalState = 3;
      lbl_803A5D60.state = 3;
    }
  }
  else if (((lbl_803A5D60.curAudioTrack + lbl_803A5D60.initReadFrame) %
             lbl_803A5D60.header.mNumFrames) == (lbl_803A5D60.header.mNumFrames - 1)) {
    gAttractMovieLoopCompleted = 1;
  }
}
#pragma peephole reset
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: FUN_80118470
 * EN v1.0 Address: 0x80118470
 * EN v1.0 Size: 180b
 * EN v1.1 Address: 0x80118AC4
 * EN v1.1 Size: 228b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80118470(void)
{
  int iVar1;
  int iVar2;
  int local_18 [5];
  
  if ((DAT_803a6a58 != 0) && (DAT_803a6a5c != '\0')) {
    DAT_803a6a5d = 0;
    DAT_803a6a5c = '\0';
    FUN_8024c910(DAT_803de2e4);
    if (DAT_803a6a68 == 0) {
      FUN_8024bdfc((int *)&DAT_803a69c0);
      FUN_801197e0();
    }
    FUN_80119c60();
    if (DAT_803a6a5f != '\0') {
      FUN_801177dc();
    }
    do {
      iVar2 = FUN_80244820((int *)&DAT_803a692c,local_18,0);
      iVar1 = local_18[0];
      if (iVar2 != 1) {
        iVar1 = 0;
      }
    } while (iVar1 != 0);
    DAT_803a6a94 = DAT_803a6a98;
    DAT_803a6aa0 = 0;
    DAT_803a6a60 = 0;
    DAT_803a6a64 = 0;
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80118524
 * EN v1.0 Address: 0x80118524
 * EN v1.0 Size: 80b
 * EN v1.1 Address: 0x80118BA8
 * EN v1.1 Size: 96b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_80118524(void)
{
  if ((DAT_803a6a58 != 0) && ((DAT_803a6a5c == '\x01' || (DAT_803a6a5c == '\x04')))) {
    DAT_803a6a5c = 2;
    DAT_803a6a88 = 0;
    DAT_803a6a8c = 0;
    DAT_803a6a84 = 0xffffffff;
    DAT_803a6a80 = 0xffffffff;
    return 1;
  }
  return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_80118574
 * EN v1.0 Address: 0x80118574
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x80118C08
 * EN v1.1 Size: 552b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
bool FUN_80118574(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 uint param_9,undefined param_10,undefined4 param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)
{
    return 0;
}

#pragma scheduling off
#pragma peephole off
void THPPlayerStop(void) {
    OSMessage msg;

    if ((lbl_803A5D60.isOpen != 0) && (lbl_803A5D60.state != 0)) {
        lbl_803A5D60.internalState = 0;
        lbl_803A5D60.state = 0;
        VISetPostRetraceCallback((void (*)(u32))lbl_803DD664);

        if (lbl_803A5D60.isOnMemory == 0) {
            DVDCancel((DVDCommandBlock *)&lbl_803A5D60.fileInfo);
            ReadThreadCancel();
        }

        VideoDecodeThreadCancel();
        if (lbl_803A5D60.audioExists != 0) {
            AudioDecodeThreadCancel();
        }

        do {
            if (OSReceiveMessage(&lbl_803A5CCC, &msg, OS_MESSAGE_NOBLOCK) == TRUE) {
                continue;
            }
            msg = NULL;
        } while (msg != NULL);

        lbl_803A5D60.curVolume = lbl_803A5D60.targetVolume;
        lbl_803A5D60.rampCount = 0;
        lbl_803A5D60.dvdError = 0;
        lbl_803A5D60.videoError = 0;
    }
}

#pragma peephole reset
BOOL THPPlayerPlay(void) {
    if ((lbl_803A5D60.isOpen != 0) &&
        ((lbl_803A5D60.state == 1) || (lbl_803A5D60.state == 4))) {
        lbl_803A5D60.state = 2;
        lbl_803A5D60.prevCount = 0;
        lbl_803A5D60.curCount = 0;
        lbl_803A5D60.retraceCount = -1;
        return TRUE;
    }
    return FALSE;
}

#pragma peephole off
BOOL prepareAttractMode(u32 movieIndex, s32 playFlags) {
    char *base;
    void *readyMsg;

    base = lbl_803A57C0;
    gAttractMovieLoopCompleted = 0;

    if (*(s32 *)(base + 0x638) == 0) {
        return FALSE;
    }
    if (*(u8 *)(base + 0x63c) != 0) {
        return FALSE;
    }

    if ((s32)movieIndex > 0) {
        u32 offsetTable = *(u32 *)(base + 0x600);

        if (offsetTable == 0) {
            return FALSE;
        }
        if (*(u32 *)(base + 0x5f0) <= movieIndex) {
            return FALSE;
        }
        if (DVDRead((DVDFileInfo *)(base + 0x5a0), base + 0x560, 0x20,
                    offsetTable + ((movieIndex - 1) * sizeof(u32))) < 0) {
            return FALSE;
        }

        *(u32 *)(base + 0x650) = *(u32 *)(base + 0x604) + *(u32 *)(base + 0x560);
        *(u32 *)(base + 0x658) = movieIndex;
        *(u32 *)(base + 0x654) = *(u32 *)(base + 0x564) - *(u32 *)(base + 0x560);
    } else {
        *(u32 *)(base + 0x650) = *(u32 *)(base + 0x604);
        *(u32 *)(base + 0x654) = *(u32 *)(base + 0x5f4);
        *(u32 *)(base + 0x658) = movieIndex;
    }

    *(u8 *)(base + 0x63e) = (u8)playFlags;
    *(u32 *)(base + 0x670) = 0;

    if (*(s32 *)(base + 0x648) != 0) {
        if (DVDRead((DVDFileInfo *)(base + 0x5a0), *(void **)(base + 0x64c),
                    *(s32 *)(base + 0x5f8), *(s32 *)(base + 0x604)) < 0) {
            return FALSE;
        }
        playFlags = ((s32)*(void **)(base + 0x64c) + *(s32 *)(base + 0x650)) -
                    *(s32 *)(base + 0x604);
        CreateVideoDecodeThread(0xf, (void *)playFlags);
        if (*(u8 *)(base + 0x63f) != 0) {
            CreateAudioDecodeThread(0xc, (void *)playFlags);
        }
    } else {
        CreateVideoDecodeThread(0xf, NULL);
        if (*(u8 *)(base + 0x63f) != 0) {
            CreateAudioDecodeThread(0xc, NULL);
        }
        CreateReadThread(8);
    }

    InitAllMessageQueue();
    VideoDecodeThreadStart();
    if (*(u8 *)(base + 0x63f) != 0) {
        AudioDecodeThreadStart();
    }
    if (*(s32 *)(base + 0x648) == 0) {
        ReadThreadStart();
    }

    OSReceiveMessage((OSMessageQueue *)(base + 0x52c), &readyMsg, OS_MESSAGE_BLOCK);
    if (readyMsg == NULL) {
        return FALSE;
    }

    *(u8 *)(base + 0x63c) = 1;
    *(u8 *)(base + 0x63d) = 0;
    *(u32 *)(base + 0x68c) = 0;
    *(u32 *)(base + 0x690) = 0;
    *(u32 *)(base + 0x684) = 0;
    *(u32 *)(base + 0x688) = 0;
    lbl_803DD664 = (void (*)(void))VISetPostRetraceCallback((void (*)(u32))PlayControl);
    return TRUE;
}
#pragma peephole reset

void PrepareReady(void *msg) {
    OSSendMessage(&lbl_803A5CEC, msg, OS_MESSAGE_BLOCK);
}

#pragma peephole off
void InitAllMessageQueue(void) {
    char *player;
    s32 i;
    char *walk;
    s32 j;

    player = (char *)&lbl_803A5D60;
    if (lbl_803A5D60.isOnMemory == 0) {
        i = 0;
        do {
            PushFreeReadBuffer((OSMessage)(player + 0xf4));
            player += sizeof(AttractMovieReadBuffer);
            i++;
        } while (i < 10);
    }

    i = 0;
    walk = (char *)&lbl_803A5D60;
    player = walk;
    do {
        PushFreeTextureSet((OSMessage)(player + 0x144));
        player += sizeof(AttractMovieTextureSet);
        i++;
    } while (i < 3);

    if (lbl_803A5D60.audioExists != 0) {
        j = 0;
        do {
            PushFreeAudioBuffer(walk + 0x174);
            walk += sizeof(AttractMovieAudioBuffer);
            j++;
        } while (j < 3);
    }

    OSInitMessageQueue(&lbl_803A5CEC, &lbl_803DD67C, 1);
}
#pragma peephole reset
#pragma scheduling reset
