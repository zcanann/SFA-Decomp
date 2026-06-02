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
#pragma peephole off
void PlayControl(void)
{
  AttractMoviePlayer *player;
  AttractMovieTextureSet *textureSet;
  s32 pendingFrames;
  u32 allowPop;
  u32 framesPerGroup;
  u32 frameOffset;

  if (lbl_803DD664 != NULL) {
    lbl_803DD664();
  }

  textureSet = (AttractMovieTextureSet *)-1;
  player = &lbl_803A5D60;
  if (player->isOpen == 0) {
    return;
  }
  if (player->state != 2) {
    return;
  }
  if ((player->dvdError != 0) || (player->videoError != 0)) {
    player->internalState = 5;
    player->state = 5;
    return;
  }

  if ((player->retraceCount == 0) &&
      ((player->internalState == 0) || (player->internalState == 4))) {
    player->internalState = 2;
  }
  player->retraceCount++;

  if ((player->internalState == 0) || (player->internalState == 4)) {
    if ((player->playFlags & 2) != 0) {
      allowPop = VIGetNextField() == 0;
    }
    else if ((player->playFlags & 4) != 0) {
      allowPop = VIGetNextField() == 1;
    }
    else {
      allowPop = 1;
    }

    if (allowPop != 0) {
      if (player->audioExists != 0) {
        pendingFrames = player->curAudioTrack - player->curVideoNumber;
        if (pendingFrames <= 1) {
          textureSet = (AttractMovieTextureSet *)PopDecodedTextureSet(0);
          if (pendingFrames < player->videoDecodeCount) {
            player->videoDecodeCount--;
          }
        }
        else {
          player->internalState = 2;
        }
      }
      else {
        textureSet = (AttractMovieTextureSet *)PopDecodedTextureSet(0);
        player->internalState = 2;
      }
    }
    else {
      player->retraceCount = -1;
    }
  }
  else if (ProperTimingForGettingNextFrame() != 0) {
    if (player->audioExists != 0) {
      pendingFrames = player->curAudioTrack - player->curVideoNumber;
      if (pendingFrames <= 1) {
        textureSet = (AttractMovieTextureSet *)PopDecodedTextureSet(0);
        if (pendingFrames < player->videoDecodeCount) {
          player->videoDecodeCount--;
        }
      }
    }
    else {
      textureSet = (AttractMovieTextureSet *)PopDecodedTextureSet(0);
    }
  }

  if ((textureSet != NULL) && (textureSet != (AttractMovieTextureSet *)-1)) {
    player->curAudioTrack = textureSet->frameNumber;
    if (player->curAudioNumber != 0) {
      OSSendMessage(&lbl_803A5CCC, (OSMessage)player->curAudioNumber, OS_MESSAGE_NOBLOCK);
    }
    player->curAudioNumber = (s32)textureSet;
  }

  framesPerGroup = player->header.mNumFrames;
  frameOffset = player->initReadFrame;
  if ((player->playFlags & 1) == 0) {
    if (player->audioExists != 0) {
      if ((((player->curVideoNumber + frameOffset) % framesPerGroup) !=
           (framesPerGroup - 1)) ||
          (player->dispTextureSet != NULL) ||
          (((player->curAudioTrack + frameOffset) % framesPerGroup) !=
           (framesPerGroup - 1)) ||
          (textureSet != NULL)) {
        return;
      }
      player->internalState = 3;
      player->state = 3;
    }
    else if ((((player->curAudioTrack + frameOffset) % framesPerGroup) ==
              (framesPerGroup - 1)) &&
             (textureSet == NULL)) {
      player->internalState = 3;
      player->state = 3;
    }
  }
  else if (((player->curAudioTrack + frameOffset) % framesPerGroup) ==
           (framesPerGroup - 1)) {
    gAttractMovieLoopCompleted = 1;
  }
}
#pragma peephole reset

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
            if (OSReceiveMessage(&lbl_803A5CCC, &msg, OS_MESSAGE_NOBLOCK) != TRUE) {
                msg = NULL;
            }
        } while (msg != NULL);

        lbl_803A5D60.curVolume = lbl_803A5D60.targetVolume;
        lbl_803A5D60.rampCount = 0;
        lbl_803A5D60.dvdError = 0;
        lbl_803A5D60.videoError = 0;
    }
}

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

void PrepareReady(void *msg) {
    OSSendMessage(&lbl_803A5CEC, msg, OS_MESSAGE_BLOCK);
}
#pragma scheduling reset
