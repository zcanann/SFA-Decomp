#include "ghidra_import.h"
#include "main/mapEvent.h"
#include "main/dll/ped.h"

extern undefined4 FUN_80006b14();
extern uint GameBit_Get(int eventId);
extern undefined4 ObjGroup_FindNearestObject();
extern undefined4 ObjPath_GetPointWorldPosition();
extern undefined4 FUN_8003b818();
extern void Sfx_AddLoopedObjectSound(int obj, int sfxId);
extern void Sfx_RemoveLoopedObjectSound(int obj, int sfxId);
extern void Sfx_StopObjectChannel(int obj, int channel);
extern void ObjHits_DisableObject(int obj);
extern void ObjHits_EnableObject(int obj);
extern void GameBit_Set(int eventId, int value);
extern void objAudioFn_8006ef38(int obj, void *events, int pointCount, void *points,
                                void *scratch, f32 scaleX, f32 scaleZ);
extern int FUN_80286840();
extern undefined4 FUN_8028688c();

extern undefined4* DAT_803dd6d4;
extern undefined4* DAT_803dd708;
extern int *gObjectTriggerInterface;
extern f64 DOUBLE_803e5e88;
extern f32 lbl_803E520C;
extern f32 lbl_803E5210;
extern f32 lbl_803E5E78;
extern f32 lbl_803E5E7C;
extern f32 lbl_803E5E80;
extern f32 lbl_803E5E94;

extern int TreeBird_SeqFn(int obj, int param_2, int data);
void fn_801CDF94(int obj, int state, int flag);

typedef struct TreeBirdState {
  s16 gameBit;
  s16 triggerId;
  s16 immediateTrigger;
  u8 triggerLatched;
  u8 searchDelay;
  void *targetObj;
} TreeBirdState;

/*
 * --INFO--
 *
 * Function: treebird_init
 * EN v1.0 Address: 0x801CDBEC
 * EN v1.0 Size: 304b
 * EN v1.1 Address: 0x801CDC2C
 * EN v1.1 Size: 356b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off
void treebird_init(int obj,int setup)
{
  TreeBirdState *state;

  state = *(TreeBirdState **)(obj + 0xb8);
  *(void **)(obj + 0xbc) = TreeBird_SeqFn;
  *(s16 *)obj = (s16)((s8)*(u8 *)(setup + 0x18) << 8);
  *(s16 *)(obj + 2) = *(s16 *)(setup + 0x1a);
  *(s16 *)(obj + 4) = *(s16 *)(setup + 0x1c);
  state->triggerId = (s16)(s8)*(u8 *)(setup + 0x19);
  state->gameBit = *(s16 *)(setup + 0x1e);
  if (GameBit_Get((int)state->gameBit) != 0) {
    state->immediateTrigger = 0x154;
  }
  state->searchDelay = 4;
}
#pragma peephole reset
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: FUN_801cdd1c
 * EN v1.0 Address: 0x801CDD1C
 * EN v1.0 Size: 616b
 * EN v1.1 Address: 0x801CDD90
 * EN v1.1 Size: 628b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801cdd1c(undefined4 param_1,undefined4 param_2,int param_3)
{
  byte bVar1;
  short sVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  int iVar6;
  
  iVar3 = FUN_80286840();
  iVar6 = *(int *)(iVar3 + 0xb8);
  for (iVar5 = 0; iVar5 < (int)(uint)*(byte *)(param_3 + 0x8b); iVar5 = iVar5 + 1) {
    bVar1 = *(byte *)(param_3 + iVar5 + 0x81);
    if (bVar1 == 2) {
      iVar4 = 100;
      if (*(short *)(iVar3 + 0x46) == 0x5d) {
        do {
          (**(code **)(*DAT_803dd708 + 8))(iVar3,0xd3,0,1,0xffffffff,0);
          iVar4 = iVar4 + -1;
        } while (iVar4 != 0);
      }
      else {
        sVar2 = *(short *)(iVar6 + 2);
        if (sVar2 == 0) {
          do {
            (**(code **)(*DAT_803dd708 + 8))(iVar3,0xcd,0,1,0xffffffff,0);
            iVar4 = iVar4 + -1;
          } while (iVar4 != 0);
        }
        else if (sVar2 == 1) {
          do {
            (**(code **)(*DAT_803dd708 + 8))(iVar3,0xcf,0,1,0xffffffff,0);
            iVar4 = iVar4 + -1;
          } while (iVar4 != 0);
        }
      }
    }
    else if (bVar1 < 2) {
      if (bVar1 != 0) {
        iVar4 = 200;
        do {
          (**(code **)(*DAT_803dd708 + 8))(iVar3,0xcc,0,1,0xffffffff,0);
          iVar4 = iVar4 + -1;
        } while (iVar4 != 0);
      }
    }
    else if (bVar1 < 4) {
      iVar4 = 5;
      if (*(short *)(iVar3 + 0x46) == 0x5d) {
        do {
          (**(code **)(*DAT_803dd708 + 8))(iVar3,0xd4,0,1,0xffffffff,0);
          iVar4 = iVar4 + -1;
        } while (iVar4 != 0);
      }
      else {
        sVar2 = *(short *)(iVar6 + 2);
        if (sVar2 == 0) {
          do {
            (**(code **)(*DAT_803dd708 + 8))(iVar3,0xce,0,1,0xffffffff,0);
            iVar4 = iVar4 + -1;
          } while (iVar4 != 0);
        }
        else if (sVar2 == 1) {
          do {
            (**(code **)(*DAT_803dd708 + 8))(iVar3,0xd0,0,1,0xffffffff,0);
            iVar4 = iVar4 + -1;
          } while (iVar4 != 0);
        }
      }
    }
  }
  FUN_8028688c();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801cdf84
 * EN v1.0 Address: 0x801CDF84
 * EN v1.0 Size: 132b
 * EN v1.1 Address: 0x801CE004
 * EN v1.1 Size: 136b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801cdf84(int param_1)
{
  int iVar1;
  float local_18;
  undefined4 local_14;
  float local_10 [2];
  
  iVar1 = *(int *)(param_1 + 0xb8);
  FUN_8003b818(param_1);
  if (*(int *)(iVar1 + 8) != 0) {
    ObjPath_GetPointWorldPosition(param_1,0,local_10,&local_14,&local_18,0);
    *(float *)(*(int *)(iVar1 + 8) + 0xc) = local_10[0];
    *(undefined4 *)(*(int *)(iVar1 + 8) + 0x10) = local_14;
    *(float *)(*(int *)(iVar1 + 8) + 0x14) = local_18;
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801ce008
 * EN v1.0 Address: 0x801CE008
 * EN v1.0 Size: 288b
 * EN v1.1 Address: 0x801CE08C
 * EN v1.1 Size: 276b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801ce008(int param_1)
{
  undefined4 uVar1;
  uint uVar2;
  short *psVar3;
  float local_18 [4];
  
  psVar3 = *(short **)(param_1 + 0xb8);
  local_18[0] = lbl_803E5E94;
  if (*(char *)((int)psVar3 + 7) == '\0') {
    if (*(char *)(psVar3 + 3) == '\0') {
      if (psVar3[2] == 0) {
        uVar2 = GameBit_Get((int)*psVar3);
        if (uVar2 != 0) {
          (**(code **)(*DAT_803dd6d4 + 0x48))((int)psVar3[1],param_1,0xffffffff);
          *(undefined *)(psVar3 + 3) = 1;
        }
      }
      else {
        (**(code **)(*DAT_803dd6d4 + 0x54))();
        (**(code **)(*DAT_803dd6d4 + 0x48))((int)psVar3[1],param_1,1);
        *(undefined *)(psVar3 + 3) = 1;
      }
    }
  }
  else {
    uVar1 = ObjGroup_FindNearestObject(4,param_1,local_18);
    *(undefined4 *)(psVar3 + 4) = uVar1;
    if (*(int *)(psVar3 + 4) == 0) {
      *(char *)((int)psVar3 + 7) = *(char *)((int)psVar3 + 7) + -1;
    }
    else {
      *(undefined *)((int)psVar3 + 7) = 0;
    }
  }
  return;
}

extern int NW_geyser_SeqFn(int *obj, int p2, void *p3);

/*
 * --INFO--
 *
 * Function: nw_geyser_init
 * EN v1.0 Address: 0x801CDE50
 * EN v1.0 Size: 32b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off
void nw_geyser_init(int obj)
{
  *(ushort *)(obj + 0xb0) = (ushort)(*(ushort *)(obj + 0xb0) | 0x6000);
  *(void **)(obj + 0xbc) = NW_geyser_SeqFn;
}

char *fn_801CDE70(int *obj) { return *(char **)((char *)obj + 0xb8) + 0xc; }

extern MapEventInterface **gMapEventInterface;
void nw_geyser_free(int *obj) {
    (*gMapEventInterface)->setAnimEvent(*(s8*)((char*)obj + 0xac), 0x1f, 0);
}

void nw_geyser_update(int obj)
{
    if (GameBit_Get(0xa) != 0) {
        *(s16 *)(obj + 6) = 0x4000;
        *(u16 *)(obj + 0xb0) = (u16)(*(u16 *)(obj + 0xb0) | 0x8000);
        Sfx_RemoveLoopedObjectSound(obj, 0x372);
        Sfx_RemoveLoopedObjectSound(obj, 0x373);
        ObjHits_DisableObject(obj);
        GameBit_Set(0x398, 1);
    } else {
        Sfx_AddLoopedObjectSound(obj, 0x372);
        Sfx_AddLoopedObjectSound(obj, 0x373);
        (*(void (**)(int, int, int))(*(int *)gObjectTriggerInterface + 0x48))(0, obj, -1);
        ObjHits_EnableObject(obj);
    }
}

extern int objFindTexture(int *obj, int idx, int p3);
extern f32 lbl_803E5200;
extern f32 timeDelta;

int NW_geyser_SeqFn(int *obj, int p2, void *p3) {
    int *tex0;
    if (GameBit_Get(0xa) != 0) {
        *(u8 *)((char *)p3 + 0x90) = (u8)(*(u8 *)((char *)p3 + 0x90) | 4);
    }
    tex0 = (int *)objFindTexture(obj, 0, 0);
    objFindTexture(obj, 1, 0);
    *(s16 *)((char *)tex0 + 0xa) = (s16)(*(s16 *)((char *)tex0 + 0xa) + (s32)(lbl_803E5200 * timeDelta));
    if (*(s16 *)((char *)tex0 + 0xa) > 0x4e80) {
        *(s16 *)((char *)tex0 + 0xa) -= 0x4e80;
    }
    *(s16 *)((char *)p3 + 0x6e) = (s16)(*(s16 *)((char *)p3 + 0x70) & ~0x40);
    *(u8 *)((char *)p3 + 0x56) = 0;
    return 0;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
int fn_801CDE7C(int obj, int param_2, u8 *seqData)
{
    u8 *state;
    void *audioEvents;
    void *audioPoints;
    void *audioScratch;
    f32 audioScale;

    (void)param_2;

    state = *(u8 **)(obj + 0xb8);
    if ((state[0x43c] & 0x20) == 0) {
        Sfx_StopObjectChannel(obj, 0x7f);
        *(f32 *)(state + 0x54) = lbl_803E520C;
        state[0x43c] = (u8)(state[0x43c] & ~0x10);
        state[0x43c] = (u8)(state[0x43c] | 0x20);
    }
    if ((state[0x43c] & 4) != 0) {
        *(f32 *)(state + 0x18) = lbl_803E520C;
        *(s16 *)(seqData + 0x6e) = (s16)(*(s16 *)(seqData + 0x6e) & ~8);
        *(s16 *)(seqData + 0x6e) = (s16)(*(s16 *)(seqData + 0x6e) & ~0x40);
        fn_801CDF94(obj, (int)state, 1);
    }
    audioEvents = state + 0x440;
    audioPoints = state + 0x45c;
    audioScratch = state + 0x16c;
    audioScale = lbl_803E5210;
    objAudioFn_8006ef38(obj, audioEvents, 8, audioPoints, audioScratch,
                        audioScale, audioScale);
    if (seqData[0x8b] != 0) {
        *(u16 *)(obj + 0xb0) = (u16)(*(u16 *)(obj + 0xb0) & ~0x400);
        *(u32 *)(*(int *)(obj + 0x64) + 0x30) =
            *(u32 *)(*(int *)(obj + 0x64) + 0x30) | 4;
    }
    return 0;
}
#pragma peephole reset
#pragma scheduling reset

extern void fn_8003A168(int obj, void* p);
extern void fn_8003B228(int obj, void* p);
extern void fn_8003A230(int obj, void* p, f32 f);
extern void characterDoEyeAnims(int obj, void* p);
extern u8 lbl_803268B4[];
extern f32 lbl_803E5214;
extern f32 lbl_803E520C;

#pragma scheduling off
#pragma peephole off
void fn_801CDF94(int obj, int state, int flag)
{
    if (flag != 0 && *(void**)(state + 0x28) != NULL && *(f32*)(state + 0x18) < lbl_803E5214) {
        *(u8*)(state + 0x40c) = 1;
        *(f32*)(state + 0x410) = *(f32*)(*(int*)(state + 0x28) + 0xc);
        *(f32*)(state + 0x414) = *(f32*)(*(int*)(state + 0x28) + 0x10);
        *(f32*)(state + 0x418) = *(f32*)(*(int*)(state + 0x28) + 0x14);
    } else {
        *(u8*)(state + 0x40c) = 0;
    }
    if ((lbl_803268B4[*(u8*)(state + 0x408)] & 0x2) != 0) {
        fn_8003A168(obj, (void*)(state + 0x40c));
        fn_8003B228(obj, (void*)(state + 0x40c));
    } else {
        fn_8003A230(obj, (void*)(state + 0x40c), lbl_803E520C);
        characterDoEyeAnims(obj, (void*)(state + 0x40c));
    }
}
#pragma peephole reset
#pragma scheduling reset
