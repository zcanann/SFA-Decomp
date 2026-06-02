#include "ghidra_import.h"
#include "dolphin/ai.h"
#include "dolphin/os.h"
#include "dolphin/os/OSCache.h"
#include "dolphin/vi.h"
#include "dolphin/vi/vifuncs.h"
#include "main/dll/FRONT/attract_movie.h"
#include "main/dll/FRONT/n_options.h"


#pragma peephole off
#pragma scheduling off
extern void *memset(void *dst, int value, uint size);
extern void *memcpy(void *dst, const void *src, uint size);
extern void gxSetPeControl_ZCompLoc_();
extern void gxSetZMode_();
extern undefined4 PopDecodedAudioBuffer(int flags);
extern void PushFreeAudioBuffer(undefined4 message);
extern undefined4 FUN_801175b4();
extern undefined4 FUN_801175b8();
extern undefined4 FUN_80119928();
extern undefined4 FUN_802420b0();
extern undefined4 FUN_802420e0();
extern undefined4 FUN_80243e74();
extern undefined4 FUN_80243e88();
extern undefined4 FUN_80243e9c();
extern undefined4 FUN_802446f8();
extern int FUN_80244820();
extern int FUN_80246a0c();
extern undefined4 FUN_8024fe60();
extern uint FUN_8024ff18();
extern undefined4 FUN_80258674();
extern undefined4 FUN_80258944();
extern undefined4 FUN_80259288();
extern undefined4 FUN_8025aa74();
extern undefined4 FUN_8025ace8();
extern undefined4 FUN_8025b054();
extern undefined4 FUN_8025be54();
extern undefined4 FUN_8025be80();
extern undefined4 FUN_8025c1a4();
extern undefined4 FUN_8025c224();
extern undefined4 FUN_8025c2a8();
extern undefined4 FUN_8025c368();
extern undefined4 FUN_8025c49c();
extern undefined4 FUN_8025c510();
extern undefined4 GXSetBlendMode();
extern undefined4 FUN_8025c5f0();
extern undefined4 FUN_8025c65c();
extern undefined4 FUN_8025c6b4();
extern undefined4 FUN_8025c754();
extern undefined4 FUN_8025c828();
extern undefined4 FUN_8025ca04();
extern undefined4 FUN_8025cce8();
extern undefined4 FUN_8025cdec();
extern undefined4 FUN_8025ce2c();
extern undefined8 FUN_80286840();
extern undefined4 FUN_8028688c();
extern void fn_8004C7AC(void *yTexture, void *uTexture, void *vTexture, int width, int height);
extern u8 *ObjModel_GetRenderOp(undefined4 model, undefined4 idx);
extern void PushFreeTextureSet(OSMessage msg);

extern undefined4 DAT_8031b000;
extern undefined4 DAT_803a50a8;
extern undefined4 DAT_803a50b4;
extern undefined4 DAT_803a50c0;
extern undefined4 DAT_803a50e0;
extern undefined4 DAT_803a6420;
extern undefined4 DAT_803a692c;
extern undefined4 DAT_803a6a58;
extern undefined4 DAT_803a6a5d;
extern undefined4 DAT_803a6a5f;
extern undefined4 DAT_803a6a94;
extern undefined4 DAT_803a6a98;
extern undefined4 DAT_803a6a9c;
extern undefined4 DAT_803a6aa0;
extern undefined4 DAT_803a6aa8;
extern undefined4 DAT_803a6ab0;
extern undefined4 DAT_803de2d8;
extern undefined4 DAT_803de2e0;
extern undefined4* DAT_803de2e8;
extern undefined4 DAT_803de2ec;
extern undefined4 DAT_803de2f0;
extern undefined4 DAT_803de2f4;
extern undefined4 DAT_803de2f8;
extern undefined4 DAT_803e29b0;
extern undefined4 DAT_803e29b4;
extern undefined4 DAT_803e29b8;
extern undefined4 DAT_803e29bc;
extern undefined4 DAT_803e29c0;
extern f64 DOUBLE_803e29c8;
extern f32 FLOAT_803e29c4;
extern s32 lbl_803DD610;
extern s32 lbl_803DD660;
extern AIDCallback lbl_803DD668;
extern s32 lbl_803DD66C;
extern u32 lbl_803DD670;
extern u32 lbl_803DD674;
extern u32 lbl_803DD678;
extern f32 lbl_803E1D50;
extern char lbl_803A57C0[0x50C];
extern OSMessageQueue lbl_803A5CCC;

/*
 * --INFO--
 *
 * Function: FUN_80117668
 * EN v1.0 Address: 0x80117668
 * EN v1.0 Size: 188b
 * EN v1.1 Address: 0x8011784C
 * EN v1.1 Size: 196b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_80117668(int param_1,int param_2)
{
  int iVar1;
  
  if (param_2 == 0) {
    iVar1 = FUN_80246a0c(-0x7fc59f00,FUN_801175b8,0,0x803a6100,0x1000,param_1,1);
    if (iVar1 == 0) {
      return 0;
    }
  }
  else {
    iVar1 = FUN_80246a0c(-0x7fc59f00,FUN_801175b4,param_2,0x803a6100,0x1000,param_1,1);
    if (iVar1 == 0) {
      return 0;
    }
  }
  FUN_802446f8((undefined4 *)&DAT_803a50e0,&DAT_803a50b4,3);
  FUN_802446f8((undefined4 *)&DAT_803a50c0,&DAT_803a50a8,3);
  DAT_803de2d8 = 1;
  return 1;
}

/*
 * --INFO--
 *
 * Function: THPPlayerDrawCurrentFrame
 * EN v1.0 Address: 0x80117668
 * EN v1.0 Size: 1280b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void THPPlayerDrawCurrentFrame(void *param_1,void *param_2,void *param_3,uint param_4,uint param_5)
{
  uint uVar1;
  uint uVar2;
  double dVar3;
  undefined8 uVar4;
  undefined4 local_98;
  undefined4 local_94;
  undefined4 local_90;
  undefined4 local_8c;
  undefined4 local_88;
  uint auStack_84 [8];
  uint auStack_64 [8];
  uint auStack_44 [17];
  
  uVar4 = FUN_80286840();
  gxSetZMode_(1,3,1);
  FUN_8025cce8(0,1,0,0);
  FUN_8025cdec(1);
  FUN_8025ce2c(0);
  FUN_80259288(2);
  gxSetPeControl_ZCompLoc_(1);
  FUN_8025c754(7,0,0,7,0);
  FUN_80258944(2);
  FUN_80258674(0,1,4,0x3c,0,0x7d);
  FUN_80258674(1,1,4,0x3c,0,0x7d);
  FUN_8025ca04(4);
  FUN_8025be54(0);
  FUN_8025c828(0,1,1,0xff);
  FUN_8025be80(0);
  FUN_8025c1a4(0,0xf,8,0xe,2);
  FUN_8025c2a8(0,0,0,0,0,0);
  FUN_8025c224(0,7,4,6,1);
  FUN_8025c368(0,1,0,0,0,0);
  GXSetBlendMode(0,0xc);
  FUN_8025c5f0(0,0x1c);
  FUN_8025c65c(0,0,0);
  FUN_8025c828(1,1,2,0xff);
  FUN_8025be80(1);
  FUN_8025c1a4(1,0xf,8,0xe,0);
  FUN_8025c2a8(1,0,0,1,0,0);
  FUN_8025c224(1,7,4,6,0);
  FUN_8025c368(1,1,0,0,0,0);
  GXSetBlendMode(1,0xd);
  FUN_8025c5f0(1,0x1d);
  FUN_8025c65c(1,0,0);
  FUN_8025c828(2,0,0,0xff);
  FUN_8025be80(2);
  FUN_8025c1a4(2,0xf,8,0xc,0);
  FUN_8025c2a8(2,0,0,0,1,0);
  FUN_8025c224(2,4,7,7,0);
  FUN_8025c368(2,0,0,0,1,0);
  FUN_8025c65c(2,0,0);
  FUN_8025c828(3,0xff,0xff,0xff);
  FUN_8025be80(3);
  FUN_8025c1a4(3,1,0,0xe,0xf);
  FUN_8025c2a8(3,0,0,0,1,0);
  FUN_8025c224(3,7,7,7,7);
  FUN_8025c368(3,0,0,0,1,0);
  FUN_8025c65c(3,0,0);
  GXSetBlendMode(3,0xe);
  local_8c = DAT_803e29b0;
  local_88 = DAT_803e29b4;
  FUN_8025c49c(1,(short *)&local_8c);
  local_90 = DAT_803e29b8;
  FUN_8025c510(0,(byte *)&local_90);
  local_94 = DAT_803e29bc;
  FUN_8025c510(1,(byte *)&local_94);
  local_98 = DAT_803e29c0;
  FUN_8025c510(2,(byte *)&local_98);
  FUN_8025c6b4(0,0,1,2,3);
  FUN_8025aa74(auStack_44,(uint)((ulonglong)uVar4 >> 0x20),param_4 & 0xffff,param_5 & 0xffff,1,0,0,
               '\0');
  dVar3 = (double)FLOAT_803e29c4;
  FUN_8025ace8(dVar3,dVar3,dVar3,auStack_44,0,0,0,'\0',0);
  FUN_8025b054(auStack_44,0);
  uVar1 = (int)(short)param_4 >> 1;
  uVar2 = (int)(short)param_5 >> 1;
  FUN_8025aa74(auStack_64,(uint)uVar4,uVar1 & 0xffff,uVar2 & 0xffff,1,0,0,'\0');
  dVar3 = (double)FLOAT_803e29c4;
  FUN_8025ace8(dVar3,dVar3,dVar3,auStack_64,0,0,0,'\0',0);
  FUN_8025b054(auStack_64,1);
  FUN_8025aa74(auStack_84,(uint)param_3,uVar1 & 0xffff,uVar2 & 0xffff,1,0,0,'\0');
  dVar3 = (double)FLOAT_803e29c4;
  FUN_8025ace8(dVar3,dVar3,dVar3,auStack_84,0,0,0,'\0',0);
  FUN_8025b054(auStack_84,2);
  FUN_8028688c();
  return;
}

/*
 * --INFO--
 *
 * Function: Movie_SetVolumeFade
 * EN v1.0 Address: 0x80117C30
 * EN v1.0 Size: 300b
 * EN v1.1 Address: 0x80117E10
 * EN v1.1 Size: 268b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
BOOL Movie_SetVolumeFade(int volume,int fadeFrames)
{
  BOOL interrupts;
  f32 targetVolume;
  int rampCount;
  
  if ((lbl_803A5D60.isOpen != 0) && (lbl_803A5D60.audioExists != 0)) {
    if (volume > 0x7f) {
      volume = 0x7f;
    }
    if (volume < 0) {
      volume = 0;
    }
    if (fadeFrames > 60000) {
      fadeFrames = 60000;
    }
    if (fadeFrames < 0) {
      fadeFrames = 0;
    }

    interrupts = OSDisableInterrupts();
    targetVolume = (f32)volume;
    lbl_803A5D60.targetVolume = targetVolume;
    if (fadeFrames != 0) {
      rampCount = fadeFrames << 5;
      lbl_803A5D60.rampCount = rampCount;
      lbl_803A5D60.deltaVolume = (targetVolume - lbl_803A5D60.curVolume) / (f32)rampCount;
    }
    else {
      lbl_803A5D60.rampCount = 0;
      lbl_803A5D60.curVolume = targetVolume;
    }
    OSRestoreInterrupts(interrupts);
    return TRUE;
  }
  return FALSE;
}

/*
 * --INFO--
 *
 * Function: AttractMovieAudio_Mix
 * EN v1.0 Address: 0x80117D5C
 * EN v1.0 Size: 940b
 * EN v1.1 Address: 0x80117F1C
 * EN v1.1 Size: 932b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void AttractMovieAudio_Mix(undefined2 *param_1,short *param_2,uint param_3)
{
  ushort uVar1;
  float fVar2;
  uint uVar3;
  int iVar4;
  short *psVar5;
  uint uVar6;
  
  if (param_2 == (short *)0x0) {
    if (((DAT_803a6a58 == 0) || (DAT_803a6a5d != '\x02')) || (DAT_803a6a5f == '\0')) {
      memset(param_1,0,param_3 << 2);
    }
    else {
      do {
        do {
          if (DAT_803a6ab0 == 0) {
            DAT_803a6ab0 = PopDecodedAudioBuffer(0);
            if (DAT_803a6ab0 == 0) {
              memset(param_1,0,param_3 << 2);
              return;
            }
            DAT_803a6aa8 = *(undefined4 *)(DAT_803a6ab0 + 0xc);
          }
          uVar3 = *(uint *)(DAT_803a6ab0 + 8);
        } while (uVar3 == 0);
        if (param_3 <= uVar3) {
          uVar3 = param_3;
        }
        psVar5 = *(short **)(DAT_803a6ab0 + 4);
        for (uVar6 = uVar3; uVar6 != 0; uVar6 = uVar6 - 1) {
          fVar2 = DAT_803a6a98;
          if (DAT_803a6aa0 != 0) {
            DAT_803a6aa0 = DAT_803a6aa0 + -1;
            fVar2 = DAT_803a6a94 + DAT_803a6a9c;
          }
          DAT_803a6a94 = fVar2;
          uVar1 = *(ushort *)(&DAT_8031b000 + (int)DAT_803a6a94 * 2);
          iVar4 = (int)((uint)uVar1 * (int)*psVar5) >> 0xf;
          if (iVar4 < -0x8000) {
            iVar4 = -0x8000;
          }
          if (0x7fff < iVar4) {
            iVar4 = 0x7fff;
          }
          *param_1 = (short)iVar4;
          iVar4 = (int)((uint)uVar1 * (int)psVar5[1]) >> 0xf;
          if (iVar4 < -0x8000) {
            iVar4 = -0x8000;
          }
          if (0x7fff < iVar4) {
            iVar4 = 0x7fff;
          }
          param_1[1] = (short)iVar4;
          param_1 = param_1 + 2;
          psVar5 = psVar5 + 2;
        }
        param_3 = param_3 - uVar3;
        *(uint *)(DAT_803a6ab0 + 8) = *(int *)(DAT_803a6ab0 + 8) - uVar3;
        *(short **)(DAT_803a6ab0 + 4) = psVar5;
        if (*(int *)(DAT_803a6ab0 + 8) == 0) {
          PushFreeAudioBuffer(DAT_803a6ab0);
          DAT_803a6ab0 = 0;
        }
      } while (param_3 != 0);
    }
  }
  else if (((DAT_803a6a58 == 0) || (DAT_803a6a5d != '\x02')) || (DAT_803a6a5f == '\0')) {
    memcpy(param_1,param_2,param_3 << 2);
  }
  else {
    do {
      do {
        if (DAT_803a6ab0 == 0) {
          DAT_803a6ab0 = PopDecodedAudioBuffer(0);
          if (DAT_803a6ab0 == 0) {
            memcpy(param_1,param_2,param_3 << 2);
            return;
          }
          DAT_803a6aa8 = *(undefined4 *)(DAT_803a6ab0 + 0xc);
        }
        uVar3 = *(uint *)(DAT_803a6ab0 + 8);
      } while (uVar3 == 0);
      if (param_3 <= uVar3) {
        uVar3 = param_3;
      }
      psVar5 = *(short **)(DAT_803a6ab0 + 4);
      for (uVar6 = uVar3; uVar6 != 0; uVar6 = uVar6 - 1) {
        fVar2 = DAT_803a6a98;
        if (DAT_803a6aa0 != 0) {
          DAT_803a6aa0 = DAT_803a6aa0 + -1;
          fVar2 = DAT_803a6a94 + DAT_803a6a9c;
        }
        DAT_803a6a94 = fVar2;
        uVar1 = *(ushort *)(&DAT_8031b000 + (int)DAT_803a6a94 * 2);
        iVar4 = (int)*param_2 + ((int)((uint)uVar1 * (int)*psVar5) >> 0xf);
        if (iVar4 < -0x8000) {
          iVar4 = -0x8000;
        }
        if (0x7fff < iVar4) {
          iVar4 = 0x7fff;
        }
        *param_1 = (short)iVar4;
        iVar4 = (int)param_2[1] + ((int)((uint)uVar1 * (int)psVar5[1]) >> 0xf);
        if (iVar4 < -0x8000) {
          iVar4 = -0x8000;
        }
        if (0x7fff < iVar4) {
          iVar4 = 0x7fff;
        }
        param_1[1] = (short)iVar4;
        param_1 = param_1 + 2;
        param_2 = param_2 + 2;
        psVar5 = psVar5 + 2;
      }
      param_3 = param_3 - uVar3;
      *(uint *)(DAT_803a6ab0 + 8) = *(int *)(DAT_803a6ab0 + 8) - uVar3;
      *(short **)(DAT_803a6ab0 + 4) = psVar5;
      if (*(int *)(DAT_803a6ab0 + 8) == 0) {
        PushFreeAudioBuffer(DAT_803a6ab0);
        DAT_803a6ab0 = 0;
      }
    } while (param_3 != 0);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80118108
 * EN v1.0 Address: 0x80118108
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x801182C0
 * EN v1.1 Size: 372b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80118108(void)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8011810c
 * EN v1.0 Address: 0x8011810C
 * EN v1.0 Size: 88b
 * EN v1.1 Address: 0x80118434
 * EN v1.1 Size: 108b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8011810c(void)
{
  int iVar1;
  int iVar2;
  int local_18 [5];
  
  if (DAT_803de2e0 != 0) {
    while( true ) {
      iVar1 = FUN_80244820((int *)&DAT_803a692c,local_18,0);
      iVar2 = local_18[0];
      if (iVar1 != 1) {
        iVar2 = 0;
      }
      if (iVar2 == 0) break;
      FUN_80119928(iVar2);
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80118164
 * EN v1.0 Address: 0x80118164
 * EN v1.0 Size: 76b
 * EN v1.1 Address: 0x801184A0
 * EN v1.1 Size: 72b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
bool FUN_80118164(uint param_1)
{
  bool bVar1;
  
  bVar1 = DAT_803a6a58 != 0;
  if (bVar1) {
    memcpy((void *)param_1,(void *)0x803a6a40,8);
  }
  return bVar1;
}

/*
 * --INFO--
 *
 * Function: AttractMovieAudio_DmaCallback
 * EN v1.0 Address: 0x80118018
 * EN v1.0 Size: 372b
 */
void AttractMovieAudio_DmaCallback(void)
{
  BOOL interrupts;

  if (lbl_803DD66C == 0) {
    lbl_803DD678 ^= 1;
    AIInitDMA((u32)(lbl_803A57C0 + (lbl_803DD678 * 0x280)), 0x280);
    interrupts = OSEnableInterrupts();
    AttractMovieAudio_Mix((undefined2 *)(lbl_803A57C0 + (lbl_803DD678 * 0x280)), NULL, 0xa0);
    DCFlushRange(lbl_803A57C0 + (lbl_803DD678 * 0x280), 0x280);
    OSRestoreInterrupts(interrupts);
  }
  else {
    if (lbl_803DD66C == 1) {
      if (lbl_803DD674 != 0) {
        lbl_803DD670 = lbl_803DD674;
      }
      lbl_803DD668();
      lbl_803DD674 = AIGetDMAStartAddr() + 0x80000000;
    }
    else {
      lbl_803DD668();
      lbl_803DD670 = AIGetDMAStartAddr() + 0x80000000;
    }

    lbl_803DD678 ^= 1;
    AIInitDMA((u32)(lbl_803A57C0 + (lbl_803DD678 * 0x280)), 0x280);
    interrupts = OSEnableInterrupts();
    if (lbl_803DD670 != 0) {
      DCInvalidateRange((void *)lbl_803DD670, 0x280);
    }
    AttractMovieAudio_Mix((undefined2 *)(lbl_803A57C0 + (lbl_803DD678 * 0x280)), (short *)lbl_803DD670, 0xa0);
    DCFlushRange(lbl_803A57C0 + (lbl_803DD678 * 0x280), 0x280);
    OSRestoreInterrupts(interrupts);
  }
}

/*
 * --INFO--
 *
 * Function: THPPlayerPostDrawDone
 * EN v1.0 Address: 0x8011818C
 * EN v1.0 Size: 108b
 */
void THPPlayerPostDrawDone(void)
{
  OSMessageQueue *queue;
  OSMessage msg;
  OSMessage textureSet;

  if (lbl_803DD660 != 0) {
    queue = &lbl_803A5CCC;
    while (TRUE) {
      if (OSReceiveMessage(queue, &msg, OS_MESSAGE_NOBLOCK) == TRUE) {
        textureSet = msg;
      }
      else {
        textureSet = NULL;
      }
      if (textureSet == NULL) {
        break;
      }
      PushFreeTextureSet(textureSet);
    }
  }
}

/*
 * --INFO--
 *
 * Function: THPPlayerGetVideoInfo
 * EN v1.0 Address: 0x801181F8
 * EN v1.0 Size: 72b
 */
BOOL THPPlayerGetVideoInfo(void *dst)
{
  if (lbl_803A5D60.isOpen != 0) {
    memcpy(dst, &lbl_803A5D60.videoInfo, sizeof(lbl_803A5D60.videoInfo));
    return TRUE;
  }
  return FALSE;
}

/*
 * --INFO--
 *
 * Function: fn_80118240
 * EN v1.0 Address: 0x80118240
 * EN v1.0 Size: 84b
 */
void fn_80118240(void)
{
  AttractMovieTextureSet *textureSet;

  if (lbl_803DD610 == 2) {
    textureSet = (AttractMovieTextureSet *)lbl_803A5D60.curAudioNumber;
    fn_8004C7AC(textureSet->yTexture, textureSet->uTexture, textureSet->vTexture,
                (s16)lbl_803A5D60.videoInfo.xSize, (s16)lbl_803A5D60.videoInfo.ySize);
  }
}

/*
 * --INFO--
 *
 * Function: AttractMovie_DrawTextureCallback
 * EN v1.0 Address: 0x80118294
 * EN v1.0 Size: 144b
 */
uint AttractMovie_DrawTextureCallback(undefined4 param_1, undefined4 *modelPtr, undefined4 renderOpIdx)
{
  AttractMovieTextureSet *textureSet;
  u8 *renderOp;

  if (modelPtr != NULL) {
    renderOp = ObjModel_GetRenderOp(*modelPtr, renderOpIdx);
  }
  else {
    renderOp = NULL;
  }

  if (((renderOp == NULL) || (renderOp[0x29] == 1)) && (lbl_803DD610 == 2)) {
    textureSet = (AttractMovieTextureSet *)lbl_803A5D60.curAudioNumber;
    THPPlayerDrawCurrentFrame(textureSet->yTexture, textureSet->uTexture, textureSet->vTexture,
                              (s16)lbl_803A5D60.videoInfo.xSize,
                              (s16)lbl_803A5D60.videoInfo.ySize);
    return TRUE;
  }
  return FALSE;
}

/*
 * --INFO--
 *
 * Function: ProperTimingForGettingNextFrame
 * EN v1.0 Address: 0x80118324
 * EN v1.0 Size: 328b
 */
int ProperTimingForGettingNextFrame(void)
{
  int frame;
  s64 tick;

  if ((lbl_803A5D60.playFlags & 2) != 0) {
    if (VIGetNextField() != 0) {
      return FALSE;
    }
    return TRUE;
  }

  if ((lbl_803A5D60.playFlags & 4) != 0) {
    if (VIGetNextField() != 1) {
      return FALSE;
    }
    return TRUE;
  }

  frame = (int)(lbl_803E1D50 * lbl_803A5D60.header.mFrameRate);
  if (VIGetTvFormat() == 1) {
    tick = lbl_803A5D60.retraceCount * frame;
    lbl_803A5D60.curCount = tick / 5000;
  }
  else {
    tick = lbl_803A5D60.retraceCount * frame;
    lbl_803A5D60.curCount = tick / 0x176a;
  }

  if (lbl_803A5D60.prevCount != lbl_803A5D60.curCount) {
    lbl_803A5D60.prevCount = lbl_803A5D60.curCount;
    return TRUE;
  }
  return FALSE;
}
