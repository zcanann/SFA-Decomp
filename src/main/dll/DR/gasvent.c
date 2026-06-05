#include "ghidra_import.h"
#include "main/audio/sfx_ids.h"
#include "main/dll/DR/gasvent.h"


#pragma peephole off
#pragma scheduling off
extern undefined4 FUN_80006824();
extern int FUN_80017a90();
extern int FUN_80017a98();
extern undefined4 ObjHitbox_SetCapsuleBounds();
extern undefined4 ObjHits_SetHitVolumeSlot();
extern void ObjHits_ClearSourceMask(int obj,int sourceMask);
extern void ObjHits_SetSourceMask(int obj,u8 sourceMask);
extern undefined4 ObjHits_ClearFlags();
extern undefined4 ObjHits_SetFlags();
extern undefined4 ObjHits_MarkObjectPositionDirty();
extern undefined4 ObjHits_SyncObjectPositionIfDirty();
extern undefined4 ObjHits_EnableObject();
extern int ObjHits_GetPriorityHit();
extern int ObjGroup_FindNearestObject();
extern void* ObjGroup_GetObjects();
extern undefined8 ObjGroup_RemoveObject();
extern undefined4 FUN_8008112c();
extern undefined4 FUN_800e8630();
extern undefined4 FUN_8013651c();
extern int FUN_8020a468();
extern undefined4 FUN_8020a90c();
extern uint FUN_80286838();
extern uint FUN_80286840();
extern undefined4 FUN_80286884();
extern undefined4 FUN_8028688c();

extern undefined4* DAT_803dd740;
extern f64 DOUBLE_803e4f90;
extern f64 DOUBLE_803e4f98;
extern f32 lbl_803E4F58;
extern f32 lbl_803E4F5C;
extern f32 lbl_803E4F74;
extern f32 lbl_803E4F78;
extern f32 lbl_803E4F7C;
extern f32 lbl_803E4F80;
extern f32 lbl_803E4F84;
extern f32 lbl_803E4F88;
extern f32 lbl_803E4FA0;

/*
 * --INFO--
 *
 * Function: FUN_801a1230
 * EN v1.0 Address: 0x801A1230
 * EN v1.0 Size: 224b
 * EN v1.1 Address: 0x801A1380
 * EN v1.1 Size: 244b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801a1230(int param_1,char param_2)
{
  int iVar1;
  int iVar2;
  
  iVar2 = *(int *)(param_1 + 0xb8);
  iVar1 = *(int *)(param_1 + 0x54);
  if (param_2 == '\0') {
    *(undefined *)(iVar1 + 0x6a) = *(undefined *)(*(int *)(param_1 + 0x50) + 99);
    *(undefined *)(iVar1 + 0x6b) = *(undefined *)(*(int *)(param_1 + 0x50) + 100);
    *(byte *)(iVar2 + 0x4a) = *(byte *)(iVar2 + 0x4a) & 0x7f;
    *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) & 0xf7;
    ObjHits_ClearFlags(param_1,0x400);
    *(byte *)(iVar2 + 0x49) = *(byte *)(iVar2 + 0x49) | 1;
  }
  else {
    *(undefined *)(iVar1 + 0x6a) = 1;
    *(undefined *)(iVar1 + 0x6b) = 1;
    *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) | 8;
    *(byte *)(iVar2 + 0x4a) = *(byte *)(iVar2 + 0x4a) & 0x7f | 0x80;
    *(byte *)(iVar2 + 0x49) = *(byte *)(iVar2 + 0x49) & 0xfd;
    ObjHits_SetFlags(param_1,0x480);
    ObjHits_ClearSourceMask(param_1,1);
    ObjHits_EnableObject(param_1);
    ObjHits_SyncObjectPositionIfDirty(param_1);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801a1310
 * EN v1.0 Address: 0x801A1310
 * EN v1.0 Size: 92b
 * EN v1.1 Address: 0x801A1474
 * EN v1.1 Size: 96b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801a1310(int param_1,float *param_2)
{
  int iVar1;
  
  iVar1 = *(int *)(param_1 + 0xb8);
  if (*(char *)(iVar1 + 0x15) != '\0') {
    return;
  }
  if (*(char *)(iVar1 + 0x17) != '\0') {
    return;
  }
  *(float *)(iVar1 + 0x24) = *(float *)(iVar1 + 0x24) + param_2[1];
  *(float *)(iVar1 + 0x20) = *(float *)(iVar1 + 0x20) + *param_2;
  *(float *)(iVar1 + 0x28) = *(float *)(iVar1 + 0x28) + param_2[2];
  *(byte *)(iVar1 + 0x49) = *(byte *)(iVar1 + 0x49) | 1;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801a136c
 * EN v1.0 Address: 0x801A136C
 * EN v1.0 Size: 744b
 * EN v1.1 Address: 0x801A14D4
 * EN v1.1 Size: 728b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801a136c(undefined4 param_1,undefined4 param_2,short param_3)
{
  float fVar1;
  uint uVar2;
  int iVar3;
  int iVar4;
  short extraout_r4;
  uint uVar5;
  short sVar6;
  double dVar7;
  double in_f29;
  double dVar8;
  double in_f30;
  double dVar9;
  double in_f31;
  double dVar10;
  double in_ps29_1;
  double in_ps30_1;
  double in_ps31_1;
  float local_68 [2];
  undefined8 local_60;
  undefined4 local_58;
  uint uStack_54;
  float local_28;
  float fStack_24;
  float local_18;
  float fStack_14;
  float local_8;
  float fStack_4;
  
  local_8 = (float)in_f31;
  fStack_4 = (float)in_ps31_1;
  local_18 = (float)in_f30;
  fStack_14 = (float)in_ps30_1;
  local_28 = (float)in_f29;
  fStack_24 = (float)in_ps29_1;
  uVar2 = FUN_80286840();
  local_68[0] = lbl_803E4F78;
  iVar3 = FUN_80017a98();
  iVar4 = ObjGroup_FindNearestObject(0x1e,uVar2,local_68);
  if (iVar4 != 0) {
    fVar1 = *(float *)(iVar4 + 0x10) - *(float *)(iVar3 + 0x10);
    if (fVar1 < lbl_803E4F58) {
      fVar1 = -fVar1;
    }
    if (lbl_803E4F7C <= fVar1) {
      dVar10 = (double)(*(float *)(iVar4 + 0xc) - *(float *)(uVar2 + 0xc));
      dVar9 = (double)(*(float *)(iVar4 + 0x10) - *(float *)(uVar2 + 0x10));
      dVar7 = (double)lbl_803E4F58;
      if (dVar9 <= dVar7) {
        dVar8 = (double)(*(float *)(iVar4 + 0x14) - *(float *)(uVar2 + 0x14));
        if (dVar9 != dVar7) {
          dVar7 = (double)(float)((double)*(float *)(uVar2 + 0x28) / dVar9);
        }
        sVar6 = extraout_r4;
        if ((double)lbl_803E4F74 <= dVar7) {
          FUN_80006824(uVar2,SFXsk_baptr1_c);
          dVar7 = (double)lbl_803E4F74;
          *(float *)(uVar2 + 0x28) = (float)dVar9;
          fVar1 = lbl_803E4F80;
          *(float *)(iVar4 + 0xc) = *(float *)(iVar4 + 0xc) + lbl_803E4F80;
          *(float *)(iVar4 + 0x2c) = *(float *)(iVar4 + 0x2c) + fVar1;
          if (lbl_803E4F84 < *(float *)(iVar4 + 0x2c)) {
            *(float *)(iVar4 + 0xc) = *(float *)(iVar4 + 0xc) - *(float *)(iVar4 + 0x2c);
            *(float *)(iVar4 + 0x2c) = lbl_803E4F58;
          }
          *(undefined2 *)(uVar2 + 2) = 0;
          *(undefined2 *)(uVar2 + 4) = 0;
          sVar6 = 0;
          param_3 = 0;
        }
        *(float *)(uVar2 + 0x24) = (float)(dVar10 * dVar7);
        *(float *)(uVar2 + 0x2c) = (float)(dVar8 * dVar7);
        uVar5 = (uint)sVar6;
        if (uVar5 != 0) {
          if (uVar5 == 1) {
            local_60 = (double)CONCAT44(0x43300000,(uint)*(ushort *)(uVar2 + 2));
            fVar1 = (float)((double)(lbl_803E4F88 - (float)(local_60 - DOUBLE_803e4f90)) * dVar7);
          }
          else {
            local_60 = (double)CONCAT44(0x43300000,(uint)*(ushort *)(uVar2 + 2));
            fVar1 = (float)(local_60 - DOUBLE_803e4f90) *
                    (float)(dVar7 * (double)(f32)(s32)(uVar5));
          }
          uStack_54 = (int)*(short *)(uVar2 + 2) ^ 0x80000000;
          local_58 = 0x43300000;
          iVar3 = (int)((f32)(s32)uStack_54 + fVar1);
          local_60 = (double)(longlong)iVar3;
          *(short *)(uVar2 + 2) = (short)iVar3;
        }
        uVar5 = (uint)param_3;
        if (uVar5 != 0) {
          fVar1 = lbl_803E4F58;
          if (uVar5 != 1) {
            fVar1 = (float)((double)CONCAT44(0x43300000,(uint)*(ushort *)(uVar2 + 4)) -
                           DOUBLE_803e4f90) *
                    (float)(dVar7 * (double)(f32)(s32)(uVar5));
          }
          uStack_54 = (int)*(short *)(uVar2 + 4) ^ 0x80000000;
          local_58 = 0x43300000;
          iVar3 = (int)((f32)(s32)uStack_54 + fVar1);
          local_60 = (double)(longlong)iVar3;
          *(short *)(uVar2 + 4) = (short)iVar3;
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
 * Function: FUN_801a1654
 * EN v1.0 Address: 0x801A1654
 * EN v1.0 Size: 840b
 * EN v1.1 Address: 0x801A17AC
 * EN v1.1 Size: 716b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801a1654(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)
{
  uint uVar1;
  int iVar2;
  int *piVar3;
  int iVar4;
  int *piVar5;
  int iVar6;
  int iVar7;
  int iVar8;
  double in_f29;
  double dVar9;
  double in_f30;
  double dVar10;
  double in_f31;
  double dVar11;
  double in_ps29_1;
  double in_ps30_1;
  double in_ps31_1;
  int local_58;
  undefined4 auStack_54 [11];
  float local_28;
  float fStack_24;
  float local_18;
  float fStack_14;
  float local_8;
  float fStack_4;
  
  local_8 = (float)in_f31;
  fStack_4 = (float)in_ps31_1;
  local_18 = (float)in_f30;
  fStack_14 = (float)in_ps30_1;
  local_28 = (float)in_f29;
  fStack_24 = (float)in_ps29_1;
  uVar1 = FUN_80286838();
  iVar8 = *(int *)(uVar1 + 0xb8);
  iVar2 = ObjHits_GetPriorityHit(uVar1,auStack_54,(int *)0x0,(uint *)0x0);
  if ((iVar2 != 0) ||
     ((*(char *)(*(int *)(uVar1 + 0x54) + 0xad) != '\0' && ((*(byte *)(iVar8 + 0x49) & 2) != 0)))) {
    *(char *)(iVar8 + 0x16) = *(char *)(iVar8 + 0x16) + '\x01';
    *(byte *)(iVar8 + 0x49) = *(byte *)(iVar8 + 0x49) | 1;
  }
  if (*(char *)(iVar8 + 0x16) != '\0') {
    if ((*(byte *)(iVar8 + 0x48) >> 6 & 1) != 0) {
      iVar6 = *(int *)(uVar1 + 0x4c);
      iVar2 = 0;
      if (*(short *)(iVar6 + 0x1a) == 0) {
        iVar2 = ObjGroup_FindNearestObject(0x3a,uVar1,(float *)0x0);
      }
      else {
        piVar3 = ObjGroup_GetObjects(0x3a,&local_58);
        piVar5 = piVar3;
        for (iVar7 = 0; iVar7 < local_58; iVar7 = iVar7 + 1) {
          iVar4 = FUN_8020a468(*piVar5);
          if (*(short *)(iVar6 + 0x1a) == iVar4) {
            iVar2 = piVar3[iVar7];
            break;
          }
          piVar5 = piVar5 + 1;
        }
      }
      if (iVar2 != 0) {
        dVar11 = (double)*(float *)(uVar1 + 0xc);
        dVar10 = (double)*(float *)(uVar1 + 0x10);
        dVar9 = (double)*(float *)(uVar1 + 0x14);
        *(undefined4 *)(uVar1 + 0xc) = *(undefined4 *)(iVar2 + 0xc);
        *(undefined4 *)(uVar1 + 0x10) = *(undefined4 *)(iVar2 + 0x10);
        *(undefined4 *)(uVar1 + 0x14) = *(undefined4 *)(iVar2 + 0x14);
        FUN_800e8630(uVar1);
        *(float *)(uVar1 + 0xc) = (float)dVar11;
        *(float *)(uVar1 + 0x10) = (float)dVar10;
        *(float *)(uVar1 + 0x14) = (float)dVar9;
      }
    }
    ObjHits_ClearFlags(uVar1,0x80);
    ObjHits_SetSourceMask(uVar1,1);
    ObjHitbox_SetCapsuleBounds(uVar1,0x14,-5,0x14);
    ObjHits_EnableObject(uVar1);
    ObjHits_MarkObjectPositionDirty(uVar1);
    ObjHits_SetHitVolumeSlot(uVar1,5,4,0);
    FUN_80006824(uVar1,SFXsk_bapt11_c);
    *(float *)(uVar1 + 0x10) = *(float *)(uVar1 + 0x10) + lbl_803E4FA0;
    FUN_8008112c((double)lbl_803E4F58,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                 uVar1,1,1,0,0,0,1,0);
    if (*(char *)(iVar8 + 0x15) != '\0') {
      (**(code **)(*DAT_803dd740 + 0x30))(uVar1,iVar8);
      *(undefined *)(iVar8 + 0x15) = 0;
    }
    *(undefined *)(iVar8 + 0x17) = 1;
    *(byte *)(iVar8 + 0x4a) = *(byte *)(iVar8 + 0x4a) & 0xdf;
    ObjGroup_RemoveObject(uVar1,0x19);
    if (*(int *)(uVar1 + 0x30) == 0) {
      *(float *)(iVar8 + 0x34) = lbl_803E4F5C;
    }
    else {
      *(float *)(iVar8 + 0x34) = lbl_803E4F5C;
    }
    iVar2 = FUN_80017a90();
    if (iVar2 != 0) {
      FUN_8013651c(iVar2);
    }
    *(byte *)(iVar8 + 0x49) = *(byte *)(iVar8 + 0x49) & 0xfd;
    if (*(int *)(iVar8 + 0x10) != 0) {
      FUN_8020a90c(*(int *)(iVar8 + 0x10));
    }
  }
  FUN_80286884();
  return;
}

/*
 * --INFO--
 *
 * Function: gunpowderbarrel_getExtraSize
 * EN v1.0 Address: 0x801A1894
 * EN v1.0 Size: 8b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int gunpowderbarrel_getExtraSize(void)
{
  return 0x58;
}

extern undefined4* lbl_803DCAC0;
#define gCarryableInterface lbl_803DCAC0
extern undefined4* gExpgfxInterface;
extern int Obj_IsObjectAlive(void* obj);
extern void ObjLink_DetachChild(int obj, void* child);

/*
 * --INFO--
 *
 * Function: gunpowderbarrel_free
 * EN v1.0 Address: 0x801A189C
 * EN v1.0 Size: 196b
 */
void gunpowderbarrel_free(int param_1, int param_2)
{
  int extra;
  void* child;
  extra = *(int*)(param_1 + 0xb8);
  (*(code*)(*(int *)gCarryableInterface + 0x10))(param_1);
  child = *(void**)(extra + 0x10);
  if (child != 0 && param_2 == 0) {
    if (Obj_IsObjectAlive(child) != 0) {
      ObjLink_DetachChild(param_1, *(void**)(extra + 0x10));
      *(int*)(extra + 0x10) = 0;
    }
  }
  ObjGroup_RemoveObject(param_1, 0x19);
  ObjGroup_RemoveObject(param_1, 0x16);
  if (*(unsigned char*)(extra + 0x17) != 0) {
    (*(code*)(*(int *)gExpgfxInterface + 0x18))(param_1);
  }
}

extern f32 lbl_803E42DC;

/*
 * --INFO--
 *
 * Function: gunpowderbarrel_render
 * EN v1.0 Address: 0x801A1960
 * EN v1.0 Size: 256b
 */
typedef struct {
  u8 playerHeld_ : 1;
  u8 unk40_ : 1;
  u8 held_ : 1;
  u8 rest_ : 5;
} GpbHeld4A;

extern void objRenderFn_8003b8f4(int *obj, int a, int b, int c, int d, f32 e);

void gunpowderbarrel_render(int *obj, int param_2, int param_3, int param_4, int param_5,
                            s8 visFlag)
{
  u8 *sub;
  int result;
  int *child;

  sub = *(u8 **)((char *)obj + 0xb8);
  if (sub[0x17] != 0 || ((GpbHeld4A *)(sub + 0x4a))->held_) {
    return;
  }
  if (sub[0x15] != 0) {
    *(s16 *)((char *)obj + 4) = 0;
    *(s16 *)((char *)obj + 2) = 0;
  }
  result = (*(int (**)(int *, int))(*(int *)gCarryableInterface + 0xc))(obj, visFlag);
  if (result != 0 || visFlag == -1) {
    objRenderFn_8003b8f4(obj, param_2, param_3, param_4, param_5, lbl_803E42DC);
  }
  child = *(int **)(sub + 0x10);
  if (child != 0) {
    (*(void (**)(int *, int, int, int, int, s8))(*(int *)(*(int *)((char *)child + 0x68)) + 0x10))(
        child, param_2, param_3, param_4, param_5, visFlag);
  }
}

/* Drift-recovery: v1.0 function set (the FUN_801a1xxx above are v1.1-shaped). */

typedef struct {
    u8 playerHeld : 1;  /* 0x80 */
    u8 unk40 : 1;       /* 0x40 */
    u8 held : 1;        /* 0x20 */
    u8 onGround : 1;    /* 0x10 */
    u8 wasOnGround : 1; /* 0x08 */
    u8 landed : 1;      /* 0x04 */
    u8 unk02 : 1;       /* 0x02 */
    u8 unk01 : 1;       /* 0x01 */
} GpbFlags4A;

typedef struct {
    u8 unk80 : 1;        /* 0x80 */
    u8 returnHome : 1;   /* 0x40 */
    u8 unkRest : 6;
} GpbFlags48;

extern int barrelgener_getLinkId(int *obj);
extern void saveGame_saveObjectPos(int *obj);
extern void Sfx_PlayFromObject(int *obj, int sfxId);
extern void spawnExplosion(int *obj, f32 scale, int a, int b, int c, int d, int e, int f, int g);
extern u8 *getTrickyObject(void);
extern void trickyImpress(u8 *tricky);
extern void timer_clearManualFlags(int *timer);
extern int objPosToMapBlockIdx(f32 x, f32 y, f32 z);
extern void objMove(int *obj, f32 x, f32 y, f32 z);
extern int fn_80062D60(int *obj, f32 x, f32 top, f32 z, f32 bottom, f32 *outY, int **outObj);
extern void ObjHits_AddContactObject(int *contact, int *obj);
extern void gunpowderbarrel_setPlayerHeldState(int *obj, u8 heldByPlayer);
extern void fn_801A0F58(int *obj, int a, int b);
extern f32 timeDelta;
extern f32 lbl_803E42C0;
extern f32 lbl_803E42C4;
extern f32 lbl_803E4308;
extern f32 lbl_803E430C;
extern f32 lbl_803E4310;
extern f32 lbl_803E4314;
extern f32 lbl_803E4318;
extern f32 lbl_803E431C;
extern f32 lbl_803E4320;
extern f32 lbl_803DBE88;

/* EN v1.0 0x801A1230  size: 708b  gunpowderbarrel_triggerExplosion: when hit
 * (or touched while resting on a damage source) blow the barrel up, optionally
 * re-saving its position at the owning generator first. */
void gunpowderbarrel_triggerExplosion(int *obj)
{
    u8 *sub;
    void *hitObj;
    int count;
    u8 *tricky;
    int *timer;

    sub = *(u8 **)((char *)obj + 0xb8);
    if (ObjHits_GetPriorityHit(obj, &hitObj, 0, 0) != 0 ||
        (*(s8 *)(*(u8 **)((char *)obj + 0x54) + 0xad) != 0 && (sub[0x49] & 2) != 0)) {
        sub[0x16] += 1;
        sub[0x49] = (u8)(sub[0x49] | 1);
    }
    if (sub[0x16] != 0) {
        if (((GpbFlags48 *)(sub + 0x48))->returnHome) {
            int *def = *(int **)((char *)obj + 0x4c);
            int *best = 0;
            int **objs;
            int i;
            int **p;
            if (*(s16 *)((char *)def + 0x1a) != 0) {
                objs = (int **)ObjGroup_GetObjects(0x3a, &count);
                for (i = 0, p = objs; i < count; i++) {
                    int id = barrelgener_getLinkId(*p);
                    if (*(s16 *)((char *)def + 0x1a) == id) {
                        best = objs[i];
                        break;
                    }
                    p++;
                }
            } else {
                best = (int *)ObjGroup_FindNearestObject(0x3a, obj, 0);
            }
            if (best != 0) {
                f32 x, y, z;
                x = *(f32 *)((char *)obj + 0xc);
                y = *(f32 *)((char *)obj + 0x10);
                z = *(f32 *)((char *)obj + 0x14);
                *(f32 *)((char *)obj + 0xc) = *(f32 *)((char *)best + 0xc);
                *(f32 *)((char *)obj + 0x10) = *(f32 *)((char *)best + 0x10);
                *(f32 *)((char *)obj + 0x14) = *(f32 *)((char *)best + 0x14);
                saveGame_saveObjectPos(obj);
                *(f32 *)((char *)obj + 0xc) = x;
                *(f32 *)((char *)obj + 0x10) = y;
                *(f32 *)((char *)obj + 0x14) = z;
            }
        }
        ObjHits_ClearFlags(obj, 0x80);
        ObjHits_SetSourceMask((int)obj, 1);
        ObjHitbox_SetCapsuleBounds(obj, 0x14, -5, 0x14);
        ObjHits_EnableObject(obj);
        ObjHits_SetHitVolumeSlot(obj, 5, 4, 0);
        Sfx_PlayFromObject(obj, SFXsk_bapt11_c);
        *(f32 *)((char *)obj + 0x10) += lbl_803E4308;
        spawnExplosion(obj, lbl_803E42C0, 1, 1, 0, 0, 0, 1, 0);
        if (sub[0x15] != 0) {
            (*(void (**)(int *, u8 *))(*(int *)gCarryableInterface + 0x30))(obj, sub);
            sub[0x15] = 0;
        }
        sub[0x17] = 1;
        ((GpbFlags4A *)(sub + 0x4a))->held = 0;
        ObjGroup_RemoveObject(obj, 0x19);
        if (*(void **)((char *)obj + 0x30) != 0) {
            *(f32 *)(sub + 0x34) = lbl_803E42C4;
        } else {
            *(f32 *)(sub + 0x34) = lbl_803E42C4;
        }
        tricky = getTrickyObject();
        if (tricky != 0) {
            trickyImpress(tricky);
        }
        sub[0x49] = (u8)(sub[0x49] & ~2);
        timer = *(int **)(sub + 0x10);
        if (timer != 0) {
            timer_clearManualFlags(timer);
        }
    }
}

/* EN v1.0 0x801A14F4  size: 928b  gunpowderbarrel_updatePhysics: gravity,
 * velocity clamps, ground probe + landing sfx, contact handling. */
void gunpowderbarrel_updatePhysics(int *obj)
{
    u8 *sub;
    int *contact;
    f32 outY;
    int block;
    f32 dt;

    sub = *(u8 **)((char *)obj + 0xb8);
    if (((GpbFlags4A *)(sub + 0x4a))->held) {
        return;
    }
    block = objPosToMapBlockIdx(*(f32 *)((char *)obj + 0xc), *(f32 *)((char *)obj + 0x10),
                                *(f32 *)((char *)obj + 0x14));
    if (block == -1) {
        if (sub[0x49] & 2) {
            sub[0x16] = 4;
        }
        return;
    }
    if (sub[0x16] == 0 && ((sub[0x49] & 2) || *(f32 *)(sub + 0x24) > lbl_803E430C)) {
        ObjHits_SetHitVolumeSlot(obj, 0xe, 1, 0);
        ObjHits_EnableObject(obj);
    }
    if (!((GpbFlags4A *)(sub + 0x4a))->playerHeld) {
        *(f32 *)(sub + 0x24) -= lbl_803E4310 * timeDelta;
    }
    {
        f32 v = *(f32 *)(sub + 0x20);
        *(f32 *)(sub + 0x20) = (v < lbl_803E4314) ? lbl_803E4314 : ((v > lbl_803E4318) ? lbl_803E4318 : v);
    }
    {
        f32 v = *(f32 *)(sub + 0x24);
        *(f32 *)(sub + 0x24) = (v < lbl_803E4314) ? lbl_803E4314 : ((v > lbl_803E4318) ? lbl_803E4318 : v);
    }
    {
        f32 v = *(f32 *)(sub + 0x28);
        *(f32 *)(sub + 0x28) = (v < lbl_803E4314) ? lbl_803E4314 : ((v > lbl_803E4318) ? lbl_803E4318 : v);
    }
    *(f32 *)((char *)obj + 0x24) = *(f32 *)(sub + 0x20);
    *(f32 *)((char *)obj + 0x28) = *(f32 *)(sub + 0x24);
    *(f32 *)((char *)obj + 0x2c) = *(f32 *)(sub + 0x28);
    dt = timeDelta;
    objMove(obj, *(f32 *)((char *)obj + 0x24) * dt, *(f32 *)((char *)obj + 0x28) * dt,
            *(f32 *)((char *)obj + 0x2c) * dt);
    ((GpbFlags4A *)(sub + 0x4a))->onGround = 0;
    if (!(sub[0x49] & 2)) {
        f32 top;
        f32 bottom;
        int below;
        int result;

        top = *(f32 *)((char *)obj + 0x84);
        bottom = *(f32 *)((char *)obj + 0x10);
        below = top < bottom;
        if (below) {
            bottom += lbl_803E4318;
        }
        if (!below) {
            top += lbl_803E4318;
        }
        result = fn_80062D60(obj, *(f32 *)((char *)obj + 0xc), top, *(f32 *)((char *)obj + 0x14),
                             bottom, &outY, &contact);
        if (result != 0) {
            if (result == 2) {
                sub[0x16] = 4;
            } else {
                if (!((GpbFlags4A *)(sub + 0x4a))->wasOnGround) {
                    if (((GpbFlags4A *)(sub + 0x4a))->landed) {
                        Sfx_PlayFromObject(obj, SFXsk_baptr1_c);
                    } else {
                        ((GpbFlags4A *)(sub + 0x4a))->landed = 1;
                    }
                }
                ((GpbFlags4A *)(sub + 0x4a))->onGround = 1;
                *(f32 *)((char *)obj + 0x10) = outY;
            }
        }
    }
    if (((GpbFlags4A *)(sub + 0x4a))->onGround) {
        f32 z = lbl_803E42C0;
        *(f32 *)((char *)obj + 0x24) = z;
        *(f32 *)((char *)obj + 0x28) = z;
        *(f32 *)((char *)obj + 0x2c) = z;
        *(f32 *)(sub + 0x20) = z;
        *(f32 *)(sub + 0x24) = z;
        *(f32 *)(sub + 0x28) = z;
        if (contact != 0) {
            u32 flags;
            ObjHits_AddContactObject(contact, obj);
            flags = *(u32 *)(*(int *)((char *)contact + 0x50) + 0x44);
            if ((flags & 0x40) && !(flags & 0x8000)) {
                *(int **)(sub + 0xc) = contact;
            } else if (*(f32 *)(sub + 0x38) < lbl_803E431C) {
                sub[0x16] = 4;
            }
        }
        if (((GpbFlags4A *)(sub + 0x4a))->playerHeld) {
            gunpowderbarrel_setPlayerHeldState(obj, 0);
        }
        *(f32 *)(sub + 0x38) = lbl_803E42C0;
    } else {
        if (*(f32 *)(sub + 0x24) < lbl_803E4320) {
            fn_801A0F58(obj, *(s16 *)(sub + 0x44), *(s16 *)(sub + 0x46));
        }
        if (!((GpbFlags4A *)(sub + 0x4a))->held && !((GpbFlags4A *)(sub + 0x4a))->playerHeld) {
            *(f32 *)(sub + 0x38) += *(f32 *)((char *)obj + 0x28);
            if (*(f32 *)(sub + 0x38) < -lbl_803DBE88) {
                sub[0x16] = 4;
            }
        }
    }
    ((GpbFlags4A *)(sub + 0x4a))->wasOnGround = ((GpbFlags4A *)(sub + 0x4a))->onGround;
}
