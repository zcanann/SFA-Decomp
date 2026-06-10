#include "main/audio/sfx_ids.h"
#include "main/effect_interfaces.h"
#include "main/expgfx.h"
#include "main/obj_placement.h"
#include "main/game_object.h"
#include "main/dll/pushable.h"
#include "main/dll/transporter.h"
#include "main/mapEventTypes.h"
#include "main/objanim.h"
#include "main/objanim_internal.h"
#include "main/objseq.h"

typedef struct InvhitObjectDef {
    u8 pad0[0x18 - 0x0];
    s16 unk18;
    s16 unk1A;
    void *unk1C;
} InvhitObjectDef;


typedef struct WarpPointObjectDef {
    u8 pad0[0x18 - 0x0];
    s16 unk18;
    s16 unk1A;
    void *unk1C;
    s16 unk20;
    u8 pad22[0x28 - 0x22];
} WarpPointObjectDef;


typedef struct PushableObjectDef {
    u8 pad0[0x18 - 0x0];
    s16 unk18;
    s16 unk1A;
    void *unk1C;
    s16 unk20;
    u8 unk22;
    u8 unk23;
    u8 pad24[0x28 - 0x24];
} PushableObjectDef;


typedef struct WarpPointPlacement {
    u8 pad0[0x18 - 0x0];
    s16 unk18;
    s16 unk1A;
    void *unk1C;
    s16 unk20;
    u8 unk22;
    u8 unk23;
    u8 pad24[0x48 - 0x24];
    f32 unk48;
    u8 pad4C[0x50 - 0x4C];
    f32 unk50;
    u8 pad54[0x114 - 0x54];
    f32 unk114;
    f32 unk118;
    u8 pad11C[0x128 - 0x11C];
    f32 unk128;
    f32 unk12C;
} WarpPointPlacement;


typedef struct WarpPointState {
    u8 pad0[0x8 - 0x0];
    f32 unk8;
    u8 unkC;
    u8 unkD;
    u8 padE[0x10 - 0xE];
    u8 unk10;
    u8 unk11;
    u8 pad12[0x18 - 0x12];
} WarpPointState;


static inline int *Transporter_GetActiveModel(void *obj) {
    ObjAnimComponent *objAnim = (ObjAnimComponent *)obj;
    return (int *)objAnim->banks[objAnim->bankIndex];
}

extern undefined4 FUN_80006824();
extern undefined4 FUN_800068f8();
extern undefined4 FUN_80006904();
extern uint FUN_80017690();
extern undefined8 FUN_80017698();
extern undefined4 FUN_8001771c();
extern undefined4 FUN_80017748();
extern undefined4 FUN_80017754();
extern u32 randomGetRange(int min, int max);
extern undefined4 FUN_80017778();
extern undefined4 FUN_800178b8();
extern ushort FUN_80017934();
extern undefined4 FUN_80017a7c();
extern undefined4 FUN_80017a88();
extern int FUN_80017a90();
extern int FUN_80017a98();
extern undefined8 FUN_80017ac8();
extern undefined4 FUN_80017ad0();
extern undefined4 FUN_800305f8();
extern undefined4 ObjHits_SetTargetMask();
extern undefined4 ObjHits_ClearHitVolumes();
extern undefined4 ObjHits_SetHitVolumeSlot();
extern undefined4 ObjHits_DisableObject();
extern undefined4 ObjHits_EnableObject();
extern undefined4 ObjHits_AddContactObject();
extern undefined8 ObjGroup_RemoveObject();
extern undefined4 ObjGroup_AddObject();
extern void Obj_FreeObject(int *obj);
extern int ObjMsg_Pop();
extern undefined4 ObjMsg_AllocQueue();
extern int ObjList_ContainsObject();
extern undefined4 ObjPath_GetPointWorldPosition();
extern undefined4 FUN_8003b540();
extern undefined4 FUN_8003b818();
extern undefined4 FUN_80053c98();
extern int FUN_80056600();
extern int FUN_800620e8();
extern char FUN_800632f4();
extern int FUN_80063a68();
extern undefined4 FUN_80063a74();
extern void trackDolphin_buildSweptBounds(uint *boundsOut,float *startPoints,float *endPoints,
                                          float *radii,int pointCount);
extern undefined4 FUN_8007f358();
extern int FUN_8007f3c8();
extern undefined4 FUN_800e82e0();
extern undefined4 FUN_800e8630();
extern undefined4 FUN_80135810();
extern int FUN_801365ac();
extern undefined4 FUN_801365b8();
extern undefined4 FUN_801743f0();
extern undefined4 FUN_80174524();
extern int fn_80174A80();
extern undefined4 fn_80174BFC();
extern undefined4 fn_8017510C();
extern int FUN_8028682c();
extern undefined8 FUN_80286834();
extern undefined8 FUN_8028683c();
extern int FUN_80286840();
extern undefined4 FUN_80286878();
extern undefined4 FUN_80286880();
extern undefined4 FUN_80286888();
extern undefined4 FUN_8028688c();
extern double FUN_80293900();
extern undefined4 FUN_80293f90();
extern undefined4 FUN_80294964();
extern uint FUN_80294bd8();
extern byte FUN_80294c20();
extern int FUN_80294c54();
extern uint FUN_80294d30();

extern undefined4 DAT_802c29f0;
extern undefined4 DAT_802c29f4;
extern undefined4 DAT_802c29f8;
extern undefined4 DAT_802c29fc;
extern undefined4 DAT_803ad340;
extern undefined4 DAT_803ad3e0;
extern undefined4 DAT_803ad3e4;
extern undefined4 DAT_803ad3e8;
extern undefined4 DAT_803dc070;
extern ObjectTriggerInterface **gObjectTriggerInterface;
extern undefined4* DAT_803dd72c;
extern undefined4 DAT_803dda60;
extern undefined4 DAT_803ddb38;
extern undefined4 DAT_803de738;
extern f64 DOUBLE_803e41c8;
extern f64 DOUBLE_803e41d0;
extern f64 DOUBLE_803e4210;
extern f64 DOUBLE_803e4268;
extern f64 DOUBLE_803e4278;
extern f64 DOUBLE_803e4290;
extern f64 DOUBLE_803e42a8;
extern f32 lbl_803DC074;
extern f32 lbl_803E41C0;
extern f32 lbl_803E41D8;
extern f32 lbl_803E41F0;
extern f32 lbl_803E4220;
extern f32 lbl_803E4224;
extern f32 lbl_803E4234;
extern f32 lbl_803E4238;
extern f32 lbl_803E423C;
extern f32 lbl_803E4240;
extern f32 lbl_803E4244;
extern f32 lbl_803E4248;
extern f32 lbl_803E424C;
extern f32 lbl_803E4250;
extern f32 lbl_803E4254;
extern f32 lbl_803E4258;
extern f32 lbl_803E425C;
extern f32 lbl_803E4260;
extern f32 lbl_803E4264;
extern f32 lbl_803E4270;
extern f32 lbl_803E4274;
extern f32 lbl_803E4284;
extern f32 lbl_803E4288;
extern f32 lbl_803E428C;
extern f32 lbl_803E4298;
extern f32 lbl_803E429C;
extern f32 lbl_803E42A0;
extern f32 lbl_803E42A4;
extern f32 lbl_803E42B0;
extern f32 lbl_803E42B4;
extern f32 lbl_803E42B8;
extern f32 lbl_803E42BC;
/*
 * --INFO--
 *
 * Function: pushable_setScale
 * EN v1.0 Address: 0x801755CC
 * EN v1.0 Size: 372b
 * EN v1.1 Address: 0x801758D4
 * EN v1.1 Size: 292b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
/* pushable_setScale: real v1.0 body defined at end of file (old v1.1 misimport removed). */

/*
 * --INFO--
 *
 * Function: FUN_80175740
 * EN v1.0 Address: 0x80175740
 * EN v1.0 Size: 108b
 * EN v1.1 Address: 0x801759F8
 * EN v1.1 Size: 128b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
uint FUN_80175740(int param_1,int param_2)
{
  float fVar1;
  float fVar2;
  float fVar3;
  int iVar4;
  double dVar5;
  
  iVar4 = ((PushableState *)param_1)->msgSenderObj;
  fVar1 = ((PushableState *)param_2)->cullDistance - ((PushableState *)param_1)->cullDistance;
  fVar2 = ((PushableState *)param_2)->scale - ((PushableState *)param_1)->scale;
  fVar3 = ((PushableState *)param_2)->timer_0x14 - ((PushableState *)param_1)->timer_0x14;
  dVar5 = FUN_80293900((double)(fVar3 * fVar3 + fVar1 * fVar1 + fVar2 * fVar2));
  return ((uint)(byte)((dVar5 < (double)*(float *)(iVar4 + 0xc)) << 3) << 0x1c) >> 0x1f;
}

/*
 * --INFO--
 *
 * Function: FUN_801757ac
 * EN v1.0 Address: 0x801757AC
 * EN v1.0 Size: 1832b
 * EN v1.1 Address: 0x80175A78
 * EN v1.1 Size: 2300b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801757ac(undefined8 param_1,double param_2,undefined4 param_3,undefined4 param_4,
                 int param_5)
{
  bool bVar1;
  short sVar2;
  ushort uVar3;
  float fVar4;
  float fVar5;
  int *piVar6;
  int iVar7;
  byte bVar9;
  uint uVar8;
  ushort *puVar10;
  int iVar11;
  float *pfVar12;
  int iVar13;
  float *pfVar14;
  int iVar15;
  double dVar16;
  double extraout_f1;
  double in_f30;
  double dVar17;
  double in_f31;
  double in_ps30_1;
  double in_ps31_1;
  undefined8 uVar18;
  float fStack_1b0;
  float local_1ac;
  float local_1a8;
  float local_1a4;
  float local_1a0;
  float local_19c;
  float local_198;
  uint auStack_194 [6];
  ushort local_17c [4];
  float local_174;
  float local_170;
  float local_16c;
  float local_168;
  float local_164 [12];
  float local_134 [12];
  float afStack_104 [32];
  float local_84 [4];
  undefined local_74;
  undefined local_70;
  undefined2 local_58;
  undefined4 local_50;
  uint uStack_4c;
  undefined4 local_48;
  uint uStack_44;
  float local_18;
  float fStack_14;
  float local_8;
  float fStack_4;
  
  local_8 = (float)in_f31;
  fStack_4 = (float)in_ps31_1;
  local_18 = (float)in_f30;
  fStack_14 = (float)in_ps30_1;
  uVar18 = FUN_80286834();
  piVar6 = (int *)((ulonglong)uVar18 >> 0x20);
  puVar10 = (ushort *)uVar18;
  dVar17 = extraout_f1;
  iVar7 = FUN_80017a98();
  iVar15 = piVar6[0x2e];
  iVar11 = 5;
  iVar13 = iVar15 + 0x14;
  while( true ) {
    bVar1 = iVar11 == 0;
    iVar11 = iVar11 + -1;
    if (bVar1) break;
    *(undefined4 *)(iVar13 + 0x114) = *(undefined4 *)(iVar13 + 0x110);
    *(undefined4 *)(iVar13 + 0x128) = *(undefined4 *)(iVar13 + 0x124);
    iVar13 = iVar13 + -4;
  }
  *(int *)(iVar15 + 0x118) = piVar6[3];
  *(int *)(iVar15 + 300) = piVar6[5];
  local_1a0 = *(float *)(puVar10 + 6);
  local_19c = lbl_803E4234 + *(float *)(puVar10 + 8);
  local_198 = *(float *)(puVar10 + 10);
  local_84[0] = lbl_803E4238;
  local_74 = 0xff;
  local_70 = 3;
  local_58 = 0;
  iVar13 = 0;
  dVar16 = (double)lbl_803E41C0;
  if (dVar17 <= dVar16) {
    if (param_2 <= dVar16) {
      if (param_2 < dVar16) {
        uStack_44 = *(int *)(iVar15 + 0x140) - 0x4000U ^ 0x80000000;
        local_48 = 0x43300000;
        dVar16 = (double)FUN_80293f90();
        local_1ac = (float)((double)lbl_803E423C * dVar16 + (double)local_1a0);
        local_1a8 = local_19c;
        uStack_4c = *(int *)(iVar15 + 0x140) - 0x4000U ^ 0x80000000;
        local_50 = 0x43300000;
        dVar16 = (double)FUN_80294964();
        local_1a4 = (float)((double)lbl_803E423C * dVar16 + (double)local_198);
        trackDolphin_buildSweptBounds(auStack_194,&local_1a0,&local_1ac,local_84,1);
        FUN_80063a74(0,auStack_194,0x208,'\x01');
        iVar13 = FUN_80063a68();
        if (iVar13 == 0) {
          iVar13 = FUN_800620e8(&local_1a0,&local_1ac,(float *)0x0,(int *)0x0,piVar6,1,0xffffffff,
                                0xff,0);
        }
        if (iVar13 != 0) {
          *(ushort *)(iVar15 + 0x100) = *(ushort *)(iVar15 + 0x100) | 0x400;
          fVar4 = lbl_803E41C0;
          *(float *)(iVar15 + 0x108) = lbl_803E41C0;
          *(float *)(iVar15 + 0x10c) = fVar4;
        }
      }
    }
    else {
      uStack_44 = *(int *)(iVar15 + 0x140) + 0x4000U ^ 0x80000000;
      local_48 = 0x43300000;
      dVar16 = (double)FUN_80293f90();
      local_1ac = (float)((double)lbl_803E423C * dVar16 + (double)local_1a0);
      local_1a8 = local_19c;
      uStack_4c = *(int *)(iVar15 + 0x140) + 0x4000U ^ 0x80000000;
      local_50 = 0x43300000;
      dVar16 = (double)FUN_80294964();
      local_1a4 = (float)((double)lbl_803E423C * dVar16 + (double)local_198);
      trackDolphin_buildSweptBounds(auStack_194,&local_1a0,&local_1ac,local_84,1);
      FUN_80063a74(0,auStack_194,0x208,'\x01');
      iVar13 = FUN_80063a68();
      if (iVar13 == 0) {
        iVar13 = FUN_800620e8(&local_1a0,&local_1ac,(float *)0x0,(int *)0x0,piVar6,1,0xffffffff,0xff
                              ,0);
      }
      if (iVar13 != 0) {
        *(ushort *)(iVar15 + 0x100) = *(ushort *)(iVar15 + 0x100) | 0x800;
        fVar4 = lbl_803E41C0;
        *(float *)(iVar15 + 0x108) = lbl_803E41C0;
        *(float *)(iVar15 + 0x10c) = fVar4;
      }
    }
  }
  else {
    uStack_4c = *(uint *)(iVar15 + 0x140) ^ 0x80000000;
    local_50 = 0x43300000;
    dVar16 = (double)FUN_80293f90();
    local_1ac = (float)((double)lbl_803E4238 * dVar16 + (double)local_1a0);
    local_1a8 = local_19c;
    uStack_44 = *(uint *)(iVar15 + 0x140) ^ 0x80000000;
    local_48 = 0x43300000;
    dVar16 = (double)FUN_80294964();
    local_1a4 = (float)((double)lbl_803E4238 * dVar16 + (double)local_198);
    trackDolphin_buildSweptBounds(auStack_194,&local_1a0,&local_1ac,local_84,1);
    FUN_80063a74(0,auStack_194,0x208,'\x01');
    iVar13 = FUN_80063a68();
    if (iVar13 == 0) {
      iVar13 = FUN_800620e8(&local_1a0,&local_1ac,(float *)0x0,(int *)0x0,piVar6,1,0xffffffff,0xff,0
                           );
    }
    if (iVar13 != 0) {
      *(ushort *)(iVar15 + 0x100) = *(ushort *)(iVar15 + 0x100) | 0x200;
      fVar4 = lbl_803E41C0;
      *(float *)(iVar15 + 0x108) = lbl_803E41C0;
      *(float *)(iVar15 + 0x10c) = fVar4;
    }
  }
  bVar9 = FUN_80294c20(iVar7);
  if ((bVar9 == 0) && ((*(byte *)(iVar15 + 0x114) >> 6 & 1) == 0)) {
    iVar13 = 1;
    dVar16 = (double)lbl_803E41C0;
    if (dVar17 <= dVar16) {
      if (dVar16 <= dVar17) {
        if (param_2 <= dVar16) {
          *(ushort *)(iVar15 + 0x100) = *(ushort *)(iVar15 + 0x100) | 0x400;
        }
        else {
          *(ushort *)(iVar15 + 0x100) = *(ushort *)(iVar15 + 0x100) | 0x800;
        }
      }
      else {
        *(ushort *)(iVar15 + 0x100) = *(ushort *)(iVar15 + 0x100) | 0x100;
      }
    }
    else {
      *(ushort *)(iVar15 + 0x100) = *(ushort *)(iVar15 + 0x100) | 0x200;
    }
    fVar4 = lbl_803E41C0;
    *(float *)(iVar15 + 0x108) = lbl_803E41C0;
    *(float *)(iVar15 + 0x10c) = fVar4;
  }
  if ((param_5 == 0) || ((*(ushort *)(iVar15 + 0x100) & 8) != 0)) {
    iVar7 = piVar6[0x16];
    bVar9 = *(byte *)(iVar7 + 0x10c);
    iVar13 = iVar15;
    for (iVar11 = 0; iVar11 < *(char *)(iVar15 + 0xb4); iVar11 = iVar11 + 1) {
      FUN_80017778((double)*(float *)(iVar13 + 0x18),(double)*(float *)(iVar13 + 0x1c),
                   (double)*(float *)(iVar13 + 0x20),(float *)(iVar7 + (bVar9 + 2) * 0x40),
                   (float *)(iVar13 + 0x78),(float *)(iVar13 + 0x7c),(float *)(iVar13 + 0x80));
      iVar13 = iVar13 + 0xc;
    }
    goto LAB_801762c4;
  }
  *(ushort *)(iVar15 + 0x100) = *(ushort *)(iVar15 + 0x100) | 2;
  *(char *)(iVar15 + 0x115) = *(char *)(iVar15 + 0x115) + -1;
  if (*(char *)(iVar15 + 0x115) < '\x01') {
    uVar8 = randomGetRange(0x28,0x3c);
    *(char *)(iVar15 + 0x115) = (char)uVar8;
    *(ushort *)(iVar15 + 0x100) = *(ushort *)(iVar15 + 0x100) | 0x20;
  }
  fVar4 = lbl_803E41C0;
  if ((*(ushort *)(iVar15 + 0x100) & 0x80) == 0) {
    if (iVar13 == 0) {
      *(float *)(iVar15 + 0x108) = (float)dVar17;
      *(float *)(iVar15 + 0x10c) = (float)param_2;
    }
  }
  else {
    *(float *)(iVar15 + 0x108) = lbl_803E41C0;
    *(float *)(iVar15 + 0x10c) = fVar4;
  }
  *(int *)(iVar15 + 0x140) = (int)(short)*puVar10;
  local_17c[0] = *puVar10;
  local_17c[1] = 0;
  local_17c[2] = 0;
  local_174 = lbl_803E4220;
  local_170 = lbl_803E41C0;
  local_16c = lbl_803E41C0;
  local_168 = lbl_803E41C0;
  FUN_80017754(afStack_104,local_17c);
  FUN_80017778((double)*(float *)(iVar15 + 0x10c),(double)lbl_803E41C0,
               (double)*(float *)(iVar15 + 0x108),afStack_104,(float *)(piVar6 + 9),&fStack_1b0,
               (float *)(piVar6 + 0xb));
  *(byte *)(iVar15 + 0x114) = *(byte *)(iVar15 + 0x114) & 0x7f | 0x80;
  FUN_80017a88((double)(float)piVar6[9],(double)lbl_803E41C0,(double)(float)piVar6[0xb],
               (int)piVar6);
  FUN_80006904();
  pfVar12 = local_134;
  pfVar14 = local_164;
  iVar13 = iVar15;
  for (iVar7 = 0; iVar7 < *(char *)(iVar15 + 0xb4); iVar7 = iVar7 + 1) {
    FUN_800068f8((double)*(float *)(iVar13 + 0x18),(double)*(float *)(iVar13 + 0x1c),
                 (double)*(float *)(iVar13 + 0x20),pfVar12,pfVar12 + 1,pfVar12 + 2,(int)piVar6);
    *pfVar14 = (float)piVar6[3] - *pfVar12;
    pfVar14[1] = (float)piVar6[4] - pfVar12[1];
    pfVar14[2] = (float)piVar6[5] - pfVar12[2];
    pfVar12 = pfVar12 + 3;
    iVar13 = iVar13 + 0xc;
    pfVar14 = pfVar14 + 3;
  }
  if ((*(ushort *)(iVar15 + 0x100) & 4) == 0) {
    fn_80174BFC();
  }
  FUN_80006904();
  if ((lbl_803E41C0 != *(float *)(iVar15 + 0x108)) ||
     (lbl_803E41C0 != *(float *)(iVar15 + 0x10c))) {
    iVar13 = piVar6[0x13];
    uVar3 = *(ushort *)(piVar6[0x2e] + 0x100);
    if ((uVar3 & 1) != 0) {
      *(ushort *)(piVar6[0x2e] + 0x100) = uVar3 & ~1;
      uVar8 = (uint)*(short *)(iVar13 + 0x18);
      if (-1 < (int)uVar8) {
        sVar2 = *(short *)((int)piVar6 + 0x46);
        if (sVar2 != 0x411) {
          if (sVar2 < 0x411) {
            if (sVar2 != 0x21e) {
LAB_801761f4:
              if (-1 < *(char *)(iVar13 + 0x23)) {
                FUN_80017698(uVar8,0);
              }
            }
          }
          else if (sVar2 != 0x7df) goto LAB_801761f4;
        }
      }
    }
  }
  fVar4 = (float)piVar6[3] - *(float *)(iVar15 + 0x128);
  fVar5 = (float)piVar6[5] - *(float *)(iVar15 + 0x13c);
  if ((lbl_803E4220 < fVar4 * fVar4 + fVar5 * fVar5) &&
     ((*(ushort *)(iVar15 + 0x100) & 0x20) != 0)) {
    FUN_80006824((uint)piVar6,SFXmn_cling02);
    *(ushort *)(iVar15 + 0x100) = *(ushort *)(iVar15 + 0x100) & ~0x20;
  }
LAB_801762c4:
  *(ushort *)(iVar15 + 0x100) = *(ushort *)(iVar15 + 0x100) & 0xf0ff;
  FUN_80286880();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80175ed4
 * EN v1.0 Address: 0x80175ED4
 * EN v1.0 Size: 228b
 * EN v1.1 Address: 0x80176374
 * EN v1.1 Size: 240b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80175ed4(int param_1)
{
  short sVar1;
  int iVar2;
  int iVar3;
  
  iVar3 = *(int *)&((GameObject *)param_1)->anim.placementData;
  iVar2 = *(int *)&((GameObject *)param_1)->extra;
  sVar1 = ((GameObject *)param_1)->anim.seqId;
  if (sVar1 == 0x411) {
    FUN_80017698((int)*(short *)(iVar2 + 0xac),0);
  }
  else if ((sVar1 < 0x411) && (sVar1 == 0x21e)) {
    FUN_80017698((int)*(short *)(iVar2 + 0xac),0);
  }
  else if ((((-1 < *(short *)(iVar3 + 0x18)) && (sVar1 != 0x54a)) && (sVar1 != 0x5ae)) &&
          ((sVar1 != 0x108 && (*(char *)(iVar2 + 0x146) != '\0')))) {
    FUN_800e8630(param_1);
  }
  if ((*(ushort *)(iVar2 + 0x100) & 1) != 0) {
    iVar2 = DAT_803de738 * 4;
    DAT_803de738 = DAT_803de738 + 1;
    *(undefined4 *)(&DAT_803ad340 + iVar2) = *(undefined4 *)(iVar3 + 0x14);
  }
  ObjGroup_RemoveObject(param_1,5);
  return;
}

/*
 * --INFO--
 *
 * Function: pushable_render
 * EN v1.0 Address: 0x80175FB8
 * EN v1.0 Size: 236b
 * EN v1.1 Address: 0x80176464
 * EN v1.1 Size: 300b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
/* pushable_render: recovered v1.0 body defined at end of file. */

/*
 * --INFO--
 *
 * Function: FUN_801765c8
 * EN v1.0 Address: 0x801765C8
 * EN v1.0 Size: 852b
 * EN v1.1 Address: 0x80176B94
 * EN v1.1 Size: 716b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801765c8(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 uint param_9)
{
  short sVar1;
  int iVar2;
  byte bVar4;
  uint uVar3;
  int iVar5;
  int iVar6;
  double dVar7;
  
  iVar5 = *(int *)(param_9 + 0x4c);
  iVar6 = *(int *)(param_9 + 0xb8);
  *(ushort *)(iVar6 + 0x100) = *(ushort *)(iVar6 + 0x100) & ~0x2;
  *(byte *)(iVar6 + 0x114) = *(byte *)(iVar6 + 0x114) & 0x7f;
  dVar7 = (double)lbl_803E41C0;
  if (dVar7 != (double)*(float *)(param_9 + 0x28)) {
    *(ushort *)(iVar6 + 0x100) = *(ushort *)(iVar6 + 0x100) | 2;
  }
  if ((*(byte *)(iVar6 + 0x114) >> 6 & 1) == 0) {
    iVar2 = FUN_80017a98();
    bVar4 = FUN_80294c20(iVar2);
    if (bVar4 != 0) goto LAB_80176c2c;
    *(byte *)(param_9 + 0xaf) = *(byte *)(param_9 + 0xaf) | 0x10;
  }
  else {
LAB_80176c2c:
    *(byte *)(param_9 + 0xaf) = *(byte *)(param_9 + 0xaf) & 0xef;
  }
  if (((*(byte *)(param_9 + 0xaf) & 4) != 0) && (uVar3 = FUN_80017690(0x913), uVar3 == 0)) {
    (*gObjectTriggerInterface)->runSequence(0, (void *)param_9, -1);
    FUN_80017698(0x913,1);
    return;
  }
  iVar2 = FUN_80017a98();
  if (((iVar2 != 0) && (uVar3 = FUN_80294bd8(iVar2,10), uVar3 != 0)) ||
     ((*(ushort *)(iVar6 + 0x100) & 4) != 0)) {
    *(undefined *)(iVar6 + 0x145) = 0x78;
  }
  if (*(char *)(iVar6 + 0x145) == '\0') {
    if (*(char *)(iVar6 + 0x146) != '\0') {
      FUN_800e82e0(param_9);
    }
  }
  else {
    *(char *)(iVar6 + 0x145) = *(char *)(iVar6 + 0x145) + -1;
  }
  sVar1 = *(short *)(param_9 + 0x46);
  if (sVar1 == 0x411) {
    iVar5 = fn_80174A80(dVar7,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,iVar6
                        );
  }
  else {
    if (0x410 < sVar1) {
      if (sVar1 == 0x54a) {
        uVar3 = FUN_80017690((int)*(short *)(iVar6 + 0xac));
        if (uVar3 != 0) {
          *(float *)(param_9 + 0xc) = (float)((double)*(float *)(iVar5 + 8) - DOUBLE_803e41c8);
          *(undefined4 *)(param_9 + 0x10) = *(undefined4 *)(iVar5 + 0xc);
          *(float *)(param_9 + 0x14) = (float)(DOUBLE_803e41d0 + (double)*(float *)(iVar5 + 0x10));
        }
        FUN_801743f0(param_9,iVar6);
      }
      goto LAB_80176e04;
    }
    if (sVar1 != 0x21e) {
      if ((sVar1 < 0x21e) && (sVar1 == 0x108)) {
        if ((lbl_803E41C0 == *(float *)(iVar6 + 0xf8)) &&
           (lbl_803E41C0 < *(float *)(iVar6 + 0xf4))) {
          FUN_80006824(param_9,SFXmn_dimbos26);
          FUN_80017698(0x272,1);
        }
        uVar3 = FUN_80017690(0x272);
        if (uVar3 != 0) {
          FUN_80017ad0(param_9);
          ObjHits_DisableObject(param_9);
          *(ushort *)(param_9 + 6) = *(ushort *)(param_9 + 6) | 0x4000;
        }
      }
      goto LAB_80176e04;
    }
    iVar5 = fn_80174A80(dVar7,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,iVar6
                        );
  }
  if (iVar5 != 0) {
    return;
  }
LAB_80176e04:
  sVar1 = *(short *)(param_9 + 0x46);
  if (((sVar1 != 0x54a) && (sVar1 != 0x5ae)) &&
     ((sVar1 != 0x108 &&
      ((*(char *)(iVar6 + 0x146) != '\0' && ((*(ushort *)(iVar6 + 0x100) & 8) == 0)))))) {
    FUN_800e8630(param_9);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8017691c
 * EN v1.0 Address: 0x8017691C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80176E60
 * EN v1.1 Size: 1552b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8017691c(undefined8 param_1,undefined8 param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80176920
 * EN v1.0 Address: 0x80176920
 * EN v1.0 Size: 200b
 * EN v1.1 Address: 0x80177470
 * EN v1.1 Size: 156b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_80176920(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,int param_9,undefined4 param_10
            ,int param_11,undefined4 param_12,undefined4 param_13,undefined4 param_14,
            undefined4 param_15,undefined4 param_16)
{
  int iVar1;
  
  if (((*(char *)(*(int *)(param_9 + 0x4c) + 0x1d) != '\x02') &&
      (*(char *)(param_11 + 0x80) == '\x01')) &&
     (iVar1 = (int)*(char *)(*(int *)(param_9 + 0x4c) + 0x1a), -1 < iVar1)) {
    FUN_80053c98(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,iVar1,'\x01',
                 param_11,param_12,param_13,param_14,param_15,param_16);
    *(undefined *)(param_11 + 0x80) = 0;
  }
  return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_801769e8
 * EN v1.0 Address: 0x801769E8
 * EN v1.0 Size: 2076b
 * EN v1.1 Address: 0x8017750C
 * EN v1.1 Size: 1632b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801769e8(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9,undefined4 param_10,undefined4 param_11,int param_12,int param_13,
                 undefined4 param_14,undefined4 param_15,undefined4 param_16)
{
  bool bVar1;
  char cVar2;
  float fVar3;
  float fVar4;
  float fVar5;
  short *psVar6;
  uint uVar7;
  int iVar8;
  short *psVar9;
  int iVar10;
  double dVar11;
  undefined8 uVar12;
  
  iVar10 = *(int *)(param_9 + 0x4c);
  psVar9 = *(short **)(param_9 + 0xb8);
  psVar6 = (short *)FUN_80017a98();
  if (psVar6 != (short *)0x0) {
    *psVar9 = *psVar9 - (ushort)DAT_803dc070;
    if (*psVar9 < 0) {
      *psVar9 = 0;
    }
    if ((((*(char *)(iVar10 + 0x1f) != '\0') && (*(char *)((int)psVar9 + 0xd) == '\0')) &&
        (-1 < DAT_803ddb38)) && ((int)DAT_803ddb38 == (int)*(char *)(iVar10 + 0x19))) {
      param_12 = FUN_80056600();
      param_11 = 0;
      param_13 = *DAT_803dd72c;
      (**(code **)(param_13 + 0x1c))(psVar6 + 6,(int)*psVar6);
      *(undefined *)((int)psVar9 + 0xd) = 1;
    }
    cVar2 = *(char *)(iVar10 + 0x1d);
    if (cVar2 == '\x02') {
      dVar11 = (double)*(float *)(psVar9 + 4);
      if ((double)lbl_803E4274 != dVar11) {
        param_2 = (double)(*(float *)(psVar6 + 0xc) - *(float *)(param_9 + 0x18));
        param_3 = (double)(*(float *)(psVar6 + 0xe) - *(float *)(param_9 + 0x1c));
        fVar3 = *(float *)(psVar6 + 0x10) - *(float *)(param_9 + 0x20);
        dVar11 = FUN_80293900((double)(fVar3 * fVar3 +
                                      (float)(param_2 * param_2 + (double)(float)(param_3 * param_3)
                                             )));
      }
      uVar7 = FUN_80017690((int)psVar9[1]);
      if (((uVar7 == 0) || (*(char *)(psVar9 + 6) != '\0')) ||
         ((*(char *)(iVar10 + 0x1c) == '\0' ||
          (((double)*(float *)(psVar9 + 4) < dVar11 ||
           (*(int *)(psVar6 + 0x18) != *(int *)(param_9 + 0x30))))))) {
        if ((*(char *)(psVar9 + 6) == '\x01') &&
           ((((uVar7 = FUN_80017690((int)psVar9[1]), uVar7 != 0 && (*psVar9 == 0)) &&
             (dVar11 <= (double)*(float *)(psVar9 + 4))) && (-1 < *(char *)(iVar10 + 0x1a))))) {
          uVar12 = FUN_80017698((int)psVar9[1],0);
          FUN_80053c98(uVar12,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                       (int)*(char *)(iVar10 + 0x1a),'\0',param_11,param_12,param_13,param_14,
                       param_15,param_16);
        }
      }
      else {
        (*gObjectTriggerInterface)->runSequence((int)psVar9[2], (void *)param_9, -1);
        *(undefined *)(psVar9 + 6) = 1;
      }
    }
    else if (cVar2 < '\x02') {
      if (cVar2 == '\0') {
        if ((-1 < DAT_803ddb38) || (uVar7 = FUN_80017690(0xd53), uVar7 != 0)) {
          param_2 = (double)(*(float *)(psVar6 + 6) - *(float *)(param_9 + 0xc));
          param_3 = (double)(*(float *)(psVar6 + 8) - *(float *)(param_9 + 0x10));
          fVar3 = *(float *)(psVar6 + 10) - *(float *)(param_9 + 0x14);
          dVar11 = FUN_80293900((double)(fVar3 * fVar3 +
                                        (float)(param_2 * param_2 +
                                               (double)(float)(param_3 * param_3))));
          if ((*(char *)(psVar9 + 6) == '\0') &&
             (((*(char *)(iVar10 + 0x1c) != '\0' && (dVar11 < (double)*(float *)(psVar9 + 4))) &&
              (*(int *)(psVar6 + 0x18) == *(int *)(param_9 + 0x30))))) {
            if (*(short *)(param_9 + 0x46) == 0x27e) {
              FUN_80017698(0xd53,1);
              iVar8 = FUN_80056600();
              param_13 = *DAT_803dd72c;
              (**(code **)(param_13 + 0x1c))(psVar6 + 6,(int)*psVar6,0,iVar8);
            }
            param_11 = 0xffffffff;
            param_12 = (int)*gObjectTriggerInterface;
            (*gObjectTriggerInterface)->runSequence((int)psVar9[2], (void *)param_9, -1);
            FUN_80017698(0xd53,0);
            DAT_803dda60 = 2;
            *(undefined *)(psVar9 + 6) = 1;
          }
        }
        if ((-1 < *(char *)(iVar10 + 0x1a)) &&
           (dVar11 = (double)FUN_8001771c((float *)(param_9 + 0x18),(float *)(psVar6 + 0xc)),
           dVar11 < (double)*(float *)(psVar9 + 4))) {
          FUN_80053c98(dVar11,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                       (int)*(char *)(iVar10 + 0x1a),'\x01',param_11,param_12,param_13,param_14,
                       param_15,param_16);
        }
      }
      else if (-1 < cVar2) {
        fVar3 = *(float *)(psVar6 + 6) - *(float *)(param_9 + 0xc);
        fVar4 = *(float *)(psVar6 + 8) - *(float *)(param_9 + 0x10);
        fVar5 = *(float *)(psVar6 + 10) - *(float *)(param_9 + 0x14);
        dVar11 = FUN_80293900((double)(fVar5 * fVar5 + fVar3 * fVar3 + fVar4 * fVar4));
        if (((-1 < DAT_803ddb38) && (*(char *)(iVar10 + 0x1c) != '\0')) &&
           ((dVar11 < (double)lbl_803E4270 &&
            (*(int *)(psVar6 + 0x18) == *(int *)(param_9 + 0x30))))) {
          (*gObjectTriggerInterface)->runSequence(1, (void *)param_9, -1);
          DAT_803dda60 = 2;
        }
        if ((((*psVar9 == 0) &&
             (dVar11 < (double)(float)((double)CONCAT44(0x43300000,
                                                        (int)*(char *)(iVar10 + 0x1e) ^ 0x80000000)
                                      - DOUBLE_803e4278))) &&
            (bVar1 = -1 < *(char *)(iVar10 + 0x1a), bVar1)) && (bVar1)) {
          (*gObjectTriggerInterface)->runSequence(0, (void *)param_9, -1);
        }
      }
    }
    else if (cVar2 == '\x04') {
      dVar11 = (double)*(float *)(psVar9 + 4);
      if ((double)lbl_803E4274 != dVar11) {
        param_2 = (double)(*(float *)(psVar6 + 0xc) - *(float *)(param_9 + 0x18));
        param_3 = (double)(*(float *)(psVar6 + 0xe) - *(float *)(param_9 + 0x1c));
        fVar3 = *(float *)(psVar6 + 0x10) - *(float *)(param_9 + 0x20);
        dVar11 = FUN_80293900((double)(fVar3 * fVar3 +
                                      (float)(param_2 * param_2 + (double)(float)(param_3 * param_3)
                                             )));
      }
      if (((-1 < DAT_803ddb38) && (*(char *)(psVar9 + 6) == '\0')) &&
         ((*(char *)(iVar10 + 0x1c) != '\0' &&
          ((dVar11 < (double)*(float *)(psVar9 + 4) &&
           (*(int *)(psVar6 + 0x18) == *(int *)(param_9 + 0x30))))))) {
        param_11 = 0xffffffff;
        param_12 = (int)*gObjectTriggerInterface;
        (*gObjectTriggerInterface)->runSequence((int)psVar9[2], (void *)param_9, -1);
        DAT_803dda60 = 2;
        *(undefined *)(psVar9 + 6) = 1;
      }
      uVar7 = FUN_80017690((int)psVar9[1]);
      if ((((uVar7 != 0) && (*psVar9 == 0)) && (dVar11 <= (double)*(float *)(psVar9 + 4))) &&
         (-1 < *(char *)(iVar10 + 0x1a))) {
        uVar12 = FUN_80017698((int)psVar9[1],0);
        FUN_80053c98(uVar12,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                     (int)*(char *)(iVar10 + 0x1a),'\x01',param_11,param_12,param_13,param_14,
                     param_15,param_16);
      }
    }
    else if (cVar2 < '\x04') {
      fVar3 = *(float *)(psVar6 + 6) - *(float *)(param_9 + 0xc);
      fVar4 = *(float *)(psVar6 + 8) - *(float *)(param_9 + 0x10);
      fVar5 = *(float *)(psVar6 + 10) - *(float *)(param_9 + 0x14);
      dVar11 = FUN_80293900((double)(fVar5 * fVar5 + fVar3 * fVar3 + fVar4 * fVar4));
      uVar7 = FUN_80017690((int)psVar9[1]);
      if (((uVar7 != 0) && (*(char *)(psVar9 + 6) == '\0')) &&
         ((*(char *)(iVar10 + 0x1c) != '\0' &&
          ((dVar11 < (double)*(float *)(psVar9 + 4) &&
           (*(int *)(psVar6 + 0x18) == *(int *)(param_9 + 0x30))))))) {
        FUN_80017698((int)psVar9[1],0);
        (*gObjectTriggerInterface)->runSequence((int)psVar9[2], (void *)param_9, -1);
        *(undefined *)(psVar9 + 6) = 1;
      }
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80177204
 * EN v1.0 Address: 0x80177204
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80177B6C
 * EN v1.1 Size: 236b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80177204(short *param_1,int param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80177208
 * EN v1.0 Address: 0x80177208
 * EN v1.0 Size: 68b
 * EN v1.1 Address: 0x80177C58
 * EN v1.1 Size: 68b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80177208(int param_1)
{
  if (*(char *)(*(int *)&((GameObject *)param_1)->extra + 8) == '\x04') {
    (*gExpgfxInterface)->freeSource2((u32)param_1);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8017724c
 * EN v1.0 Address: 0x8017724C
 * EN v1.0 Size: 32b
 * EN v1.1 Address: 0x80177C9C
 * EN v1.1 Size: 40b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8017724c(int param_1)
{
  FUN_8003b818(param_1);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801776f0
 * EN v1.0 Address: 0x801776F0
 * EN v1.0 Size: 32b
 * EN v1.1 Address: 0x801782E8
 * EN v1.1 Size: 40b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801776f0(int param_1)
{
  FUN_8003b818(param_1);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80177710
 * EN v1.0 Address: 0x80177710
 * EN v1.0 Size: 356b
 * EN v1.1 Address: 0x80178310
 * EN v1.1 Size: 404b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80177710(ushort *param_1)
{
  int iVar1;
  undefined uVar2;
  float *pfVar3;
  ushort *puVar4;
  ushort local_28;
  ushort local_26;
  ushort local_24;
  float local_20;
  float local_1c;
  float local_18;
  float local_14;
  
  iVar1 = FUN_80017a98();
  pfVar3 = *(float **)(param_1 + 0x5c);
  if ((iVar1 != 0) && (puVar4 = *(ushort **)(iVar1 + 200), puVar4 != (ushort *)0x0)) {
    param_1[2] = puVar4[2];
    param_1[1] = puVar4[1];
    *param_1 = *puVar4;
    if (*(char *)(*(int *)(param_1 + 0x26) + 0x19) == '\0') {
      uVar2 = 1;
    }
    else {
      uVar2 = 3;
    }
    ObjHits_SetHitVolumeSlot((int)param_1,0x10,uVar2,0);
    *pfVar3 = *pfVar3 - lbl_803DC074;
    local_1c = lbl_803E429C;
    if (*pfVar3 <= lbl_803E429C) {
      *pfVar3 = *pfVar3 + lbl_803E42A0;
      *(float *)(param_1 + 0x12) = local_1c;
      *(float *)(param_1 + 0x16) = local_1c;
      *(float *)(param_1 + 0x14) = lbl_803E42A4;
      local_18 = local_1c;
      local_14 = local_1c;
      local_20 = lbl_803E4298;
      local_24 = puVar4[2];
      local_26 = puVar4[1];
      local_28 = *puVar4;
      FUN_80017748(&local_28,(float *)(param_1 + 0x12));
      ObjPath_GetPointWorldPosition(puVar4,0,(float *)(param_1 + 6),(undefined4 *)(param_1 + 8),
                   (float *)(param_1 + 10),0);
      ObjHits_EnableObject((int)param_1);
    }
    *(undefined4 *)(param_1 + 0x40) = *(undefined4 *)(param_1 + 6);
    *(undefined4 *)(param_1 + 0x42) = *(undefined4 *)(param_1 + 8);
    *(undefined4 *)(param_1 + 0x44) = *(undefined4 *)(param_1 + 10);
    *(float *)(param_1 + 6) = *(float *)(param_1 + 0x12) * lbl_803DC074 + *(float *)(param_1 + 6);
    *(float *)(param_1 + 8) = *(float *)(param_1 + 0x14) * lbl_803DC074 + *(float *)(param_1 + 8);
    *(float *)(param_1 + 10) =
         *(float *)(param_1 + 0x16) * lbl_803DC074 + *(float *)(param_1 + 10);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80177874
 * EN v1.0 Address: 0x80177874
 * EN v1.0 Size: 92b
 * EN v1.1 Address: 0x801784A4
 * EN v1.1 Size: 84b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80177874(int param_1,int param_2)
{
  **(float **)&((GameObject *)param_1)->extra =
       (float)((double)CONCAT44(0x43300000,(int)*(short *)(param_2 + 0x1a) ^ 0x80000000) -
              DOUBLE_803e42a8);
  ObjHits_SetTargetMask(param_1,1);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801778d0
 * EN v1.0 Address: 0x801778D0
 * EN v1.0 Size: 16b
 * EN v1.1 Address: 0x801784F8
 * EN v1.1 Size: 16b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801778d0(int param_1)
{
  *(undefined *)(*(int *)&((GameObject *)param_1)->extra + 0x10) = 1;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801778e0
 * EN v1.0 Address: 0x801778E0
 * EN v1.0 Size: 396b
 * EN v1.1 Address: 0x80178508
 * EN v1.1 Size: 312b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_801778e0(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
            undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,int param_9,
            int param_10)
{
  float fVar1;
  short *psVar2;
  undefined4 uVar3;
  int iVar4;
  float *pfVar5;
  ushort local_28;
  short local_26;
  short local_24;
  float local_20;
  float local_1c;
  float local_18;
  float local_14;
  
  psVar2 = (short *)FUN_80017a90();
  local_1c = lbl_803E42B0;
  if ((*(char *)(param_10 + 0x10) == '\0') && (psVar2 != (short *)0x0)) {
    *(float *)(param_9 + 0x24) = lbl_803E42B0;
    *(float *)(param_9 + 0x28) = local_1c;
    *(float *)(param_9 + 0x2c) = lbl_803E42B4;
    local_18 = local_1c;
    local_14 = local_1c;
    local_20 = lbl_803E42B8;
    local_24 = psVar2[2];
    local_26 = psVar2[1];
    iVar4 = FUN_801365ac((int)psVar2);
    local_28 = *psVar2 + (short)iVar4;
    FUN_80017748(&local_28,(float *)(param_9 + 0x24));
    if ((psVar2[0x58] & 0x800U) == 0) {
      pfVar5 = (float *)(psVar2 + 6);
    }
    else {
      pfVar5 = (float *)FUN_801365b8((int)psVar2);
    }
    fVar1 = lbl_803E42BC;
    *(float *)(param_10 + 4) = -(lbl_803E42BC * *(float *)(param_9 + 0x24) - *pfVar5);
    *(float *)(param_10 + 8) = -(fVar1 * *(float *)(param_9 + 0x28) - pfVar5[1]);
    *(float *)(param_10 + 0xc) = -(fVar1 * *(float *)(param_9 + 0x2c) - pfVar5[2]);
    if (*(char *)(param_10 + 0x11) == '\0') {
      ObjHits_ClearHitVolumes(param_9);
    }
    else {
      *(char *)(param_10 + 0x11) = *(char *)(param_10 + 0x11) + -1;
    }
    uVar3 = 1;
  }
  else {
    FUN_80017ac8(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9);
    uVar3 = 0;
  }
  return uVar3;
}


/* Trivial 4b 0-arg blr leaves. */
void invhit_hitDetect(void) {}
void invhit_release(void) {}
void invhit_initialise(void) {}
void iceblast_free(void) {}
void iceblast_hitDetect(void) {}
void iceblast_release(void) {}
void iceblast_initialise(void) {}

extern unsigned long GameBit_Set(int eventId, int value);
extern int saveGame_saveObjectPos(int *obj);
extern int lbl_803DDAB8;
extern int lbl_803AC6E0[];

#pragma scheduling off
#pragma peephole off
void pushable_free(int *obj) {
    u8 *def = *(u8**)&((GameObject *)obj)->anim.placementData;
    PushableState *sub = ((GameObject *)obj)->extra;
    s16 type = ((GameObject *)obj)->anim.seqId;
    int v;

    switch (type) {
    case 0x21e:
        GameBit_Set(sub->gameBit, 0);
        break;
    case 0x411:
        GameBit_Set(sub->gameBit, 0);
        break;
    default:
        if (*(s16*)(def + 0x18) > -1 && type != 0x54a && type != 0x5ae && type != 0x108 && sub->savePosEnabled != 0) {
            saveGame_saveObjectPos(obj);
        }
        break;
    }
    if ((sub->flags & 1) != 0) {
        int val = ((ObjPlacement *)def)->mapId;
        v = lbl_803DDAB8;
        lbl_803DDAB8 = v + 1;
        lbl_803AC6E0[v] = val;
    }
    ObjGroup_RemoveObject(obj, 5);
}

/* 8b "li r3, N; blr" returners. */
int pushable_getExtraSize(void) { return 0x148; }
int pushable_getObjectTypeId(void) { return 0x48; }
int WarpPoint_getExtraSize(void) { return 0x10; }
int WarpPoint_getObjectTypeId(void) { return 0x1; }
int invhit_getExtraSize(void) { return 0xc; }
int invhit_getObjectTypeId(void) { return 0x0; }
int iceblast_getExtraSize(void) { return 0x4; }
int iceblast_getObjectTypeId(void) { return 0x0; }
int flameblast_getExtraSize(void) { return 0x14; }

extern void fn_80098B18(int obj, float f, int a, int b, int c, int d);
extern f32 lbl_803E3618;
extern f32 lbl_803E3620;
extern f32 lbl_803E3628;
extern f32 lbl_803E362C;
#pragma peephole on
void flameblast_render(int *obj) {
    f32 vec[3];
    f32 f = lbl_803E362C * *(f32 *)((GameObject *)obj)->extra + lbl_803E3628;
    vec[0] = lbl_803E3618;
    vec[1] = lbl_803E3620;
    vec[2] = lbl_803E3618;
    fn_80098B18((int)obj, f, 2, 0, 0, (int)vec);
}

/* 16b chained patterns. */
void objSetAnimSpeedTo1(int *obj) { u8 v = 0x1; *((u8*)((int**)obj)[0xb8/4] + 0x10) = v; }

/* render-with-fn(lbl) (no visibility check). */
extern f32 lbl_803E35E8;
extern void objRenderFn_8003b8f4(int *obj, int a, int b, int c, int d, f32 scale);
extern f32 lbl_803E3600;
void invhit_render(int *obj, int a, int b, int c, int d) { objRenderFn_8003b8f4(obj, a, b, c, d, lbl_803E35E8); }
void iceblast_render(int *obj, int a, int b, int c, int d) { objRenderFn_8003b8f4(obj, a, b, c, d, lbl_803E3600); }

#pragma peephole off
void WarpPoint_render(int *obj, int p1, int p2, int p3, int p4, s8 visible) {
    int *p = *(int **)&((GameObject *)obj)->anim.placementData;
    if (visible == 0) return;
    if (*(s8 *)((char *)p + 0x1d) == 1) return;
}
void invhit_free(int obj) {
    char *inner = ((GameObject *)obj)->extra;
    switch (*(u8 *)(inner + 8)) {
        case 4:
            (*gExpgfxInterface)->freeSource2((u32)obj);
            break;
    }
}

#pragma peephole on
void iceblast_init(int obj, s16 *p) {
    *(f32 *)((GameObject *)obj)->extra = (f32)*(s16 *)((char *)p + 0x1a);
    ObjHits_SetTargetMask(obj, 1);
}

extern void warpToMap(int mapId, int flag);

#pragma peephole off
int WarpPoint_SeqFn(int *obj, int unused, ObjAnimUpdateState *animUpdate) {
    int *p = *(int **)&((GameObject *)obj)->anim.placementData;
    if (*(s8 *)((char *)p + 0x1d) != 2) {
        if (animUpdate->triggerCommand == 1) {
            int v = (s8)*(u8 *)((char *)p + 0x1a);
            if (v > -1) {
                warpToMap(v, 1);
                animUpdate->triggerCommand = 0;
            }
        }
    }
    return 0;
}

extern f32 timeDelta;
extern f32 lbl_803E3630;
extern f32 lbl_803E3634;
extern int fn_8017805C(int *obj, f32 *state);

void flameblast_update(int *obj) {
    f32 *state = ((GameObject *)obj)->extra;
    state[0] = state[0] + timeDelta;
    if (state[0] > lbl_803E3630) {
        state[0] = state[0] - lbl_803E3630;
        if (fn_8017805C(obj, state) == 0) {
            return;
        }
    } else {
        if (state[0] > lbl_803E3634) {
            if (*(u8 *)((char *)state + 0x11) == 0) {
                ObjHits_SetHitVolumeSlot(obj, 0x1a, 1, 0);
            }
        }
    }
    ((GameObject *)obj)->anim.localPosX = ((GameObject *)obj)->anim.velocityX * state[0] + state[1];
    ((GameObject *)obj)->anim.localPosY = ((GameObject *)obj)->anim.velocityY * state[0] + state[2];
    ((GameObject *)obj)->anim.localPosZ = ((GameObject *)obj)->anim.velocityZ * state[0] + state[3];
}

extern f32 lbl_803E3604;
extern f32 lbl_803E3608;
extern f32 lbl_803E360C;
extern void *Obj_GetPlayerObject(void);
extern void vecRotateZXY(void *in, void *out);
extern f32 lbl_803E3638;

void flameblast_init(int *obj, u8 *def) {
    f32 *state = ((GameObject *)obj)->extra;
    fn_8017805C(obj, state);
    state[0] = lbl_803E3638 * (f32)(s32)*(s16 *)((char *)def + 0x1a);
    *(u8 *)((char *)state + 0x11) = 2;
}

void WarpPoint_init(int *obj, u8 *def) {
    s16 *state = ((GameObject *)obj)->extra;
    ((GameObject *)obj)->animEventCallback = (void *)WarpPoint_SeqFn;
    *(s16 *)obj = (s16)((u32)def[0x18] << 8);
    state[0] = 0x1e;
    ((WarpPointState *)state)->unk8 = (f32)((s32)*(s8 *)((char *)def + 0x1e) << 2);
    state[1] = ((WarpPointObjectDef *)def)->unk20;
    state[2] = (s16)(s32)*(s8 *)((char *)def + 0x1b);
    if (*(s8 *)((char *)def + 0x1c) != 0) {
        ((WarpPointState *)state)->unkC = 0;
    } else {
        ((WarpPointState *)state)->unkC = 1;
    }
    if (*(s8 *)((char *)def + 0x1d) == 2) {
        state[0] = 0;
    }
    if (((ObjPlacement *)def)->mapId == 0x4B675 || ((ObjPlacement *)def)->mapId == 0x46882) {
        *(u8 *)((char *)def + 0x1f) = 1;
    } else {
        *(u8 *)((char *)def + 0x1f) = 0;
    }
}

void iceblast_update(int *obj) {
    int *path;
    int *def;
    f32 *state;
    int *player;
    struct { s16 dir[3]; s16 pad; f32 pos[4]; } vec;
    player = (int *)Obj_GetPlayerObject();
    state = ((GameObject *)obj)->extra;
    def = *(int **)&((GameObject *)obj)->anim.placementData;
    if (player != NULL && (path = ((GameObject *)player)->unkC8) != NULL) {
        ((GameObject *)obj)->anim.rotZ = *(s16 *)((char *)path + 4);
        ((GameObject *)obj)->anim.rotY = *(s16 *)((char *)path + 2);
        *(s16 *)obj = *(s16 *)path;
    } else {
        return;
    }
    ObjHits_SetHitVolumeSlot(obj, 0x10, *(s8 *)((char *)def + 0x19) != 0 ? 3 : 1, 0);
    state[0] = state[0] - timeDelta;
    if (state[0] <= lbl_803E3604) {
        f32 zero;
        state[0] = state[0] + lbl_803E3608;
        zero = lbl_803E3604;
        ((f32 *)obj)[9] = zero;
        ((f32 *)obj)[11] = zero;
        ((f32 *)obj)[10] = lbl_803E360C;
        vec.pos[1] = zero;
        vec.pos[2] = zero;
        vec.pos[3] = zero;
        vec.pos[0] = lbl_803E3600;
        vec.dir[2] = *(s16 *)((char *)path + 4);
        vec.dir[1] = *(s16 *)((char *)path + 2);
        vec.dir[0] = *(s16 *)path;
        vecRotateZXY(&vec, (f32 *)((char *)obj + 0x24));
        ObjPath_GetPointWorldPosition((int)path, 0, &((GameObject *)obj)->anim.localPosX, &((GameObject *)obj)->anim.localPosY, &((GameObject *)obj)->anim.localPosZ, 0);
        ObjHits_EnableObject((u32)obj);
    }
    ((GameObject *)obj)->anim.previousLocalPosX = ((GameObject *)obj)->anim.localPosX;
    ((GameObject *)obj)->anim.previousLocalPosY = ((GameObject *)obj)->anim.localPosY;
    ((GameObject *)obj)->anim.previousLocalPosZ = ((GameObject *)obj)->anim.localPosZ;
    ((GameObject *)obj)->anim.localPosX = ((GameObject *)obj)->anim.velocityX * timeDelta + ((GameObject *)obj)->anim.localPosX;
    ((GameObject *)obj)->anim.localPosY = ((GameObject *)obj)->anim.velocityY * timeDelta + ((GameObject *)obj)->anim.localPosY;
    ((GameObject *)obj)->anim.localPosZ = ((GameObject *)obj)->anim.velocityZ * timeDelta + ((GameObject *)obj)->anim.localPosZ;
}

extern s16 *getTrickyObject(void);
extern int fn_80138F90(void);
extern f32 *trickyGetQueuedPathParticlePos(s16 *tricky);
extern f32 lbl_803E361C;
extern f32 lbl_803E3624;

#pragma opt_common_subs off
int fn_8017805C(int *obj, f32 *state) {
    s16 *tricky;
    f32 *pf;
    f32 k;
    struct { s16 dir[3]; s16 pad; f32 pos[4]; } vec;

    tricky = getTrickyObject();
    if (*(u8 *)((char *)state + 0x10) != 0 || tricky == NULL) {
        Obj_FreeObject(obj);
        return 0;
    }
    {
        f32 f = lbl_803E3618;
        ((GameObject *)obj)->anim.velocityX = f;
        ((GameObject *)obj)->anim.velocityY = f;
        ((GameObject *)obj)->anim.velocityZ = lbl_803E361C;
        vec.pos[1] = f;
        vec.pos[2] = f;
        vec.pos[3] = f;
        vec.pos[0] = lbl_803E3620;
    }
    vec.dir[2] = tricky[2];
    vec.dir[1] = tricky[1];
    vec.dir[0] = tricky[0] + fn_80138F90();
    vecRotateZXY(&vec, &((GameObject *)obj)->anim.velocityX);
    if ((((GameObject *)tricky)->objectFlags & 0x800) != 0) {
        pf = trickyGetQueuedPathParticlePos(tricky);
    } else {
        pf = (f32 *)((char *)tricky + 0xc);
    }
    k = lbl_803E3624;
    state[1] = -(k * ((GameObject *)obj)->anim.velocityX - pf[0]);
    state[2] = -(k * ((GameObject *)obj)->anim.velocityY - pf[1]);
    state[3] = -(k * ((GameObject *)obj)->anim.velocityZ - pf[2]);
    if (*(u8 *)((char *)state + 0x11) != 0) {
        *(u8 *)((char *)state + 0x11) -= 1;
    } else {
        ObjHits_ClearHitVolumes(obj);
    }
    return 1;
}
#pragma opt_common_subs reset

#pragma opt_common_subs off
typedef struct InvHitState {
    f32 anchorX;
    f32 anchorZ;
    u8 mode;
} InvHitState;

void invhit_init(int *obj, u8 *def) {
    InvHitState *state = ((GameObject *)obj)->extra;
    char *sub;

    state->mode = def[0x1a];
    sub = *(char **)&((GameObject *)obj)->anim.hitReactState;
    ((ObjHitsPriorityState *)sub)->flags = ((ObjHitsPriorityState *)sub)->flags & ~1;
    switch (state->mode) {
    case 0:
        ((GameObject *)obj)->unkF8 = def[0x18];
        break;
    case 6:
        sub[0x62] = 1;
        ((ObjHitsPriorityState *)sub)->primaryRadius = 0x23;
        ((ObjHitsPriorityState *)sub)->flags = ((ObjHitsPriorityState *)sub)->flags | 0x45;
        sub[0x6e] = 0xb;
        sub[0x6f] = 1;
        sub[0xae] = 0;
        sub[0xaf] = 0;
        *(int *)&((ObjHitsPriorityState *)sub)->objectHitMask = 0x10;
        *(int *)&((ObjHitsPriorityState *)sub)->skeletonHitMask = 0x10;
        sub[0x6a] = 0;
        sub[0x6b] = 0;
        break;
    case 3:
        ((GameObject *)obj)->unkF8 = def[0x18];
        ((GameObject *)obj)->unkF4 = 0;
        break;
    case 5:
        ((GameObject *)obj)->unkF8 = def[0x18];
        ((GameObject *)obj)->unkF4 = 0;
        break;
    case 7:
        sub[0x62] = 1;
        ((ObjHitsPriorityState *)sub)->primaryRadius = def[0x18];
        ((ObjHitsPriorityState *)sub)->flags = ((ObjHitsPriorityState *)sub)->flags | 0x45;
        sub[0xae] = 0;
        sub[0x6e] = 0xa;
        sub[0x6f] = 0;
        sub[0xaf] = 0;
        *(int *)&((ObjHitsPriorityState *)sub)->objectHitMask = 0x10;
        *(int *)&((ObjHitsPriorityState *)sub)->skeletonHitMask = 0x10;
        sub[0x6a] = 0;
        sub[0x6b] = 0;
        break;
    case 1:
        sub[0x62] = 1;
        ((ObjHitsPriorityState *)sub)->primaryRadius = def[0x18];
        ((ObjHitsPriorityState *)sub)->flags = ((ObjHitsPriorityState *)sub)->flags | 0x45;
        sub[0xae] = 0;
        sub[0x6e] = 0xb;
        sub[0x6f] = 1;
        sub[0xaf] = 0;
        sub[0x6e] = 0x11;
        sub[0x6f] = 1;
        *(int *)&((ObjHitsPriorityState *)sub)->objectHitMask = 0x10;
        *(int *)&((ObjHitsPriorityState *)sub)->skeletonHitMask = 0x10;
        sub[0x6a] = 0;
        sub[0x6b] = 0;
        break;
    case 2:
        ((ObjHitsPriorityState *)sub)->shapeFlags = def[0x19];
        ((ObjHitsPriorityState *)sub)->primaryRadius = def[0x18];
        ((ObjHitsPriorityState *)sub)->flags = ((ObjHitsPriorityState *)sub)->flags | 1;
        sub[0xae] = 0;
        sub[0xaf] = 0;
        sub[0x6a] = 0;
        sub[0x6b] = 0;
        break;
    case 4:
        sub[0x62] = 1;
        ((ObjHitsPriorityState *)sub)->primaryRadius = 0xa;
        ((ObjHitsPriorityState *)sub)->flags = 3;
        *(int *)&((ObjHitsPriorityState *)sub)->objectHitMask = 0x10;
        ((GameObject *)obj)->unkF8 = 0x78;
        {
            char *anchorObj = *(char **)&((InvhitObjectDef *)def)->unk1C;
            if (anchorObj != NULL) {
                state->anchorX = ((GameObject *)anchorObj)->anim.localPosX;
                state->anchorZ = *(f32 *)(*(char **)&((InvhitObjectDef *)def)->unk1C + 0x14);
            }
        }
        break;
    }
    ((GameObject *)obj)->objectFlags = ((GameObject *)obj)->objectFlags | 0x6000;
}
#pragma opt_common_subs reset

extern void *Obj_GetPlayerObject2(void);
extern int playerIsDisguised(void *player);
extern u32 GameBit_Get(int eventId);
extern int fn_80295A04(void *player, int a);
extern void pushable_savePos(int *obj);
extern int fn_80174668(int *obj, PushableState *state);
extern void fn_80174438(int *obj, PushableState *state);
extern void Sfx_PlayFromObject(int *obj, int sfxId);
extern void Obj_RemoveFromUpdateList(int *obj);
extern f32 lbl_803E3528;
extern f64 lbl_803E3530;
extern f64 lbl_803E3538;

void pushable_update(int *obj) {
    PushableState *state;
    u8 *def;
    void *player;

    def = *(u8 **)&((GameObject *)obj)->anim.placementData;
    state = ((GameObject *)obj)->extra;
    state->flags = state->flags & ~2;
    state->moveFlags.b7 = 0;
    if (lbl_803E3528 != ((GameObject *)obj)->anim.velocityY) {
        state->flags = state->flags | 2;
    }
    if (state->moveFlags.b6 == 0) {
        if (playerIsDisguised(Obj_GetPlayerObject()) != 0) goto LAB_clear;
        *(u8 *)&((GameObject *)obj)->anim.resetHitboxMode = *(u8 *)&((GameObject *)obj)->anim.resetHitboxMode | 0x10;
    } else {
    LAB_clear:
        *(u8 *)&((GameObject *)obj)->anim.resetHitboxMode = *(u8 *)&((GameObject *)obj)->anim.resetHitboxMode & ~0x10;
    }
    if ((*(u8 *)&((GameObject *)obj)->anim.resetHitboxMode & 4) != 0 && GameBit_Get(0x913) == 0) {
        (*gObjectTriggerInterface)->runSequence(0, obj, -1);
        GameBit_Set(0x913, 1);
        return;
    }
    player = Obj_GetPlayerObject();
    if ((player != NULL && fn_80295A04(player, 10) != 0) || (state->flags & 4) != 0) {
        state->savePosDelay = 0x78;
    }
    if (state->savePosDelay != 0) {
        state->savePosDelay -= 1;
    } else {
        if (state->savePosEnabled != 0) {
            pushable_savePos(obj);
        }
    }
    switch (((GameObject *)obj)->anim.seqId) {
    case 0x21e:
        if (fn_80174668(obj, state) == 0) break;
        return;
    case 0x411:
        if (fn_80174668(obj, state) == 0) break;
        return;
    case 0x54a:
        if (GameBit_Get(state->gameBit) != 0) {
            ((GameObject *)obj)->anim.localPosX = (f32)((f64)((ObjPlacement *)def)->posX - lbl_803E3530);
            ((GameObject *)obj)->anim.localPosY = ((ObjPlacement *)def)->posY;
            ((GameObject *)obj)->anim.localPosZ = (f32)(lbl_803E3538 + (f64)((ObjPlacement *)def)->posZ);
        }
        fn_80174438(obj, state);
        break;
    case 0x108:
        if (lbl_803E3528 == state->prevWaterDepth && state->waterDepth > lbl_803E3528) {
            Sfx_PlayFromObject(obj, 0x68);
            GameBit_Set(0x272, 1);
        }
        if (GameBit_Get(0x272) != 0) {
            Obj_RemoveFromUpdateList(obj);
            ObjHits_DisableObject(obj);
            ((GameObject *)obj)->anim.flags = ((GameObject *)obj)->anim.flags | OBJANIM_FLAG_HIDDEN;
        }
        break;
    }
    {
        s16 t = ((GameObject *)obj)->anim.seqId;
        if (t != 0x54a && t != 0x5ae && t != 0x108 && state->savePosEnabled != 0 &&
            (state->flags & 8) == 0) {
            saveGame_saveObjectPos(obj);
        }
    }
}

extern f32 sqrtf(f32 x);
extern u32 fn_80296118(void);
extern f32 lbl_803AC780[];
extern u8 framesThisStep;
extern EffectInterface **gPartfxInterface;
extern s8 hitDetectFn_80065e50(int *obj, f32 x, f32 y, f32 z, f32 ***list, int a, int b);
extern f32 lbl_803E35EC;
extern f32 lbl_803E35F0;
extern f32 lbl_803E35F4;

void invhit_update(int *obj) {
    InvHitState *state;
    int i;

    state = ((GameObject *)obj)->extra;
    ((GameObject *)obj)->anim.previousLocalPosX = ((GameObject *)obj)->anim.localPosX;
    ((GameObject *)obj)->anim.previousLocalPosY = ((GameObject *)obj)->anim.localPosY;
    ((GameObject *)obj)->anim.previousLocalPosZ = ((GameObject *)obj)->anim.localPosZ;
    switch (state->mode) {
    case 0: {
        char *victim = (char *)Obj_GetPlayerObject();
        while (victim != NULL) {
            f32 dx = ((GameObject *)obj)->anim.localPosX - ((PushableState *)victim)->cullDistance;
            f32 dy = ((GameObject *)obj)->anim.localPosY - ((PushableState *)victim)->scale;
            f32 dz = ((GameObject *)obj)->anim.localPosZ - ((PushableState *)victim)->timer_0x14;
            f32 dist = sqrtf(dx * dx + dy * dy + dz * dz);
            if (dist < (f32)((GameObject *)obj)->unkF8) {
                u8 *victimHits = *(u8 **)&((GameObject *)victim)->anim.hitReactState;
                victimHits[0x71] += 1;
                ((ObjHitsPriorityState *)victimHits)->flags = ((ObjHitsPriorityState *)victimHits)->flags & ~1;
                (*(u8 **)&((GameObject *)obj)->anim.hitReactState)[0x71] += 1;
            }
            if (((GameObject *)victim)->anim.classId == 1) {
                victim = (char *)getTrickyObject();
            } else {
                victim = NULL;
            }
        }
        break;
    }
    case 3:
        if (Obj_GetPlayerObject() != NULL) {
            lbl_803AC780[0] = ((GameObject *)obj)->anim.worldPosX;
            lbl_803AC780[1] = ((GameObject *)obj)->anim.worldPosY;
            lbl_803AC780[2] = ((GameObject *)obj)->anim.worldPosZ;
        }
        break;
    case 5: {
        void *pl = Obj_GetPlayerObject();
        u32 v = fn_80296118();
        if (pl != NULL && v != 0) {
            lbl_803AC780[0] = ((GameObject *)obj)->anim.worldPosX;
            lbl_803AC780[1] = ((GameObject *)obj)->anim.worldPosY;
            lbl_803AC780[2] = ((GameObject *)obj)->anim.worldPosZ;
        }
        break;
    }
    case 1:
        ObjList_ContainsObject(((GameObject *)obj)->unkF4);
        break;
    case 7: {
        char *hitState = *(char **)&((GameObject *)obj)->anim.hitReactState;
        char *ownerHitState = *(char **)(((GameObject *)obj)->unkF4 + 0x54);
        char *ownerHitSlot = ownerHitState;

        i = 0;
        for (; i < *(s8 *)(ownerHitState + 0x71); i++) {
            if (*(int **)(ownerHitSlot + 0x7c) == obj) {
                *(s16 *)(hitState + 0x60) = *(s16 *)(hitState + 0x60) & ~1;
                Obj_FreeObject(obj);
            }
            ownerHitSlot += 4;
        }
        break;
    }
    case 4: {
        char *hitState = *(char **)&((GameObject *)obj)->anim.hitReactState;
        char *targetObj;
        f32 **hits[2];
        f32 reach;
        f32 dx2;
        f32 dz2;
        s8 cnt;
        f32 thr;

        ((GameObject *)obj)->unkF8 -= framesThisStep;
        if (*(void **)&((ObjHitsPriorityState *)hitState)->lastHitObject != NULL) {
            ((ObjHitsPriorityState *)hitState)->flags = 0;
        }
        targetObj = *(char **)&((GameObject *)obj)->unkF4;
        if (targetObj != NULL) {
            f32 dx;
            f32 dz;
            f32 k;
            f32 qt;
            f32 d;

            if (ObjList_ContainsObject(targetObj) == 0) break;
            dx = ((GameObject *)targetObj)->anim.localPosX - ((GameObject *)obj)->anim.localPosX;
            dz = ((GameObject *)targetObj)->anim.localPosZ - ((GameObject *)obj)->anim.localPosZ;
            k = lbl_803E35EC;
            qt = dx / k;
            ((GameObject *)obj)->anim.localPosX = qt * timeDelta + ((GameObject *)obj)->anim.localPosX;
            qt = dz / k;
            ((GameObject *)obj)->anim.localPosZ = qt * timeDelta + ((GameObject *)obj)->anim.localPosZ;
            dx = ((GameObject *)targetObj)->anim.localPosX - state->anchorX;
            dz = ((GameObject *)targetObj)->anim.localPosZ - state->anchorZ;
            reach = lbl_803E35F0 + sqrtf(dx * dx + dz * dz);
            dx2 = ((GameObject *)obj)->anim.localPosX - state->anchorX;
            dz2 = ((GameObject *)obj)->anim.localPosZ - state->anchorZ;
            d = sqrtf(dx2 * dx2 + dz2 * dz2);
            if (d > reach) {
                f32 r = reach / d;
                dx2 = dx2 * r;
                dz2 = dz2 * r;
                ((GameObject *)obj)->anim.localPosX = state->anchorX + dx2;
                ((GameObject *)obj)->anim.localPosZ = state->anchorZ + dz2;
            }
            (*gPartfxInterface)->spawnObject(obj, 0x25, NULL, 0, -1,
                                                                NULL);
            (*gPartfxInterface)->spawnObject(obj, 0x56, NULL, 0, -1,
                                                                NULL);
        }
        cnt = hitDetectFn_80065e50(obj, ((GameObject *)obj)->anim.localPosX, ((GameObject *)obj)->anim.localPosY,
                                   ((GameObject *)obj)->anim.localPosZ, hits, 0, 0);
        thr = lbl_803E35F4;
        for (i = 0; i < cnt; i++) {
            f32 h = *hits[0][i];
            f32 oy = ((GameObject *)obj)->anim.localPosY;
            if (h < thr + oy && h > oy - thr) {
                ((GameObject *)obj)->anim.localPosY = h;
                i = cnt;
            }
        }
        break;
    }
    }
}

extern int getCurMapLayer(void);
extern MapEventInterface **gMapEventInterface;
extern f32 Vec_distance(f32 *a, f32 *b);
extern s16 lbl_803DCEB8;
extern u8 lbl_803DCDE0;
extern f32 lbl_803E35D8;
extern f32 lbl_803E35DC;

void WarpPoint_update(int *obj) {
    char *def;
    s16 *state;
    char *player;
    f32 dist;

    def = *(char **)&((GameObject *)obj)->anim.placementData;
    state = ((GameObject *)obj)->extra;
    player = (char *)Obj_GetPlayerObject();
    if (player == NULL) {
        return;
    }
    *state -= framesThisStep;
    if (*state < 0) {
        *state = 0;
    }
    if (*(u8 *)(def + 0x1f) != 0 && ((WarpPointState *)state)->unkD == 0 && lbl_803DCEB8 > -1 &&
        lbl_803DCEB8 == *(s8 *)(def + 0x19)) {
        (*gMapEventInterface)->triggerEvent((int)(player + 0xc), *(s16 *)player,
                                                                 0, getCurMapLayer());
        ((WarpPointState *)state)->unkD = 1;
    }
    switch (*(s8 *)(def + 0x1d)) {
    case 0:
        if (lbl_803DCEB8 > -1 || GameBit_Get(0xd53) != 0) {
            f32 dx = ((GameObject *)player)->anim.localPosX - ((GameObject *)obj)->anim.localPosX;
            f32 dy = ((PushableState *)player)->scale - ((GameObject *)obj)->anim.localPosY;
            f32 dz = ((PushableState *)player)->timer_0x14 - ((GameObject *)obj)->anim.localPosZ;
            dist = sqrtf(dx * dx + dy * dy + dz * dz);
            if (((WarpPointState *)state)->unkC == 0 && *(s8 *)(def + 0x1c) != 0 &&
                dist < ((WarpPointState *)state)->unk8 &&
                *(u32 *)&((GameObject *)player)->anim.parent == *(u32 *)&((GameObject *)obj)->anim.parent) {
                if (((GameObject *)obj)->anim.seqId == 0x27e) {
                    GameBit_Set(0xd53, 1);
                    (*gMapEventInterface)->triggerEvent(
                        (int)(player + 0xc), *(s16 *)player, 0, getCurMapLayer());
                }
                (*gObjectTriggerInterface)->runSequence(state[2], obj, -1);
                GameBit_Set(0xd53, 0);
                lbl_803DCDE0 = 2;
                ((WarpPointState *)state)->unkC = 1;
            }
        }
        if (*(s8 *)(def + 0x1a) > -1) {
            f32 d2 = Vec_distance(&((GameObject *)obj)->anim.worldPosX, (f32 *)(player + 0x18));
            if (d2 < ((WarpPointState *)state)->unk8) {
                warpToMap(*(s8 *)(def + 0x1a), 1);
            }
        }
        break;
    case 1: {
        f32 dx = ((GameObject *)player)->anim.localPosX - ((GameObject *)obj)->anim.localPosX;
        f32 dy = ((PushableState *)player)->scale - ((GameObject *)obj)->anim.localPosY;
        f32 dz = ((PushableState *)player)->timer_0x14 - ((GameObject *)obj)->anim.localPosZ;
        dist = sqrtf(dx * dx + dy * dy + dz * dz);
        if (lbl_803DCEB8 > -1 && *(s8 *)(def + 0x1c) != 0 && dist < lbl_803E35D8 &&
            *(u32 *)&((GameObject *)player)->anim.parent == *(u32 *)&((GameObject *)obj)->anim.parent) {
            (*gObjectTriggerInterface)->runSequence(1, obj, -1);
            lbl_803DCDE0 = 2;
        }
        if (*state == 0 && dist < (f32)*(s8 *)(def + 0x1e) && *(s8 *)(def + 0x1a) > -1 &&
            *(s8 *)(def + 0x1a) > -1) {
            (*gObjectTriggerInterface)->runSequence(0, obj, -1);
        }
        break;
    }
    case 2:
        if (lbl_803E35DC != (dist = ((WarpPointState *)state)->unk8)) {
            f32 dx = ((GameObject *)player)->anim.worldPosX - ((GameObject *)obj)->anim.worldPosX;
            f32 dy = ((PushableState *)player)->probeLocal[0].y - ((GameObject *)obj)->anim.worldPosY;
            f32 dz = ((PushableState *)player)->probeLocal[0].z - ((GameObject *)obj)->anim.worldPosZ;
            dist = sqrtf(dx * dx + dy * dy + dz * dz);
        }
        if (GameBit_Get(state[1]) != 0 && ((WarpPointState *)state)->unkC == 0 &&
            *(s8 *)(def + 0x1c) != 0 && dist <= ((WarpPointState *)state)->unk8 &&
            *(u32 *)&((GameObject *)player)->anim.parent == *(u32 *)&((GameObject *)obj)->anim.parent) {
            (*gObjectTriggerInterface)->runSequence(state[2], obj, -1);
            ((WarpPointState *)state)->unkC = 1;
        } else {
            if (((WarpPointState *)state)->unkC == 1 && GameBit_Get(state[1]) != 0 && *state == 0 &&
                dist <= ((WarpPointState *)state)->unk8 && *(s8 *)(def + 0x1a) > -1) {
                GameBit_Set(state[1], 0);
                warpToMap(*(s8 *)(def + 0x1a), 0);
            }
        }
        break;
    case 3: {
        f32 dx = ((GameObject *)player)->anim.localPosX - ((GameObject *)obj)->anim.localPosX;
        f32 dy = ((PushableState *)player)->scale - ((GameObject *)obj)->anim.localPosY;
        f32 dz = ((PushableState *)player)->timer_0x14 - ((GameObject *)obj)->anim.localPosZ;
        dist = sqrtf(dx * dx + dy * dy + dz * dz);
        if (GameBit_Get(state[1]) != 0 && ((WarpPointState *)state)->unkC == 0 &&
            *(s8 *)(def + 0x1c) != 0 && dist < ((WarpPointState *)state)->unk8 &&
            *(u32 *)&((GameObject *)player)->anim.parent == *(u32 *)&((GameObject *)obj)->anim.parent) {
            GameBit_Set(state[1], 0);
            (*gObjectTriggerInterface)->runSequence(state[2], obj, -1);
            ((WarpPointState *)state)->unkC = 1;
        }
        break;
    }
    case 4:
        if (lbl_803E35DC != (dist = ((WarpPointState *)state)->unk8)) {
            f32 dx = ((GameObject *)player)->anim.worldPosX - ((GameObject *)obj)->anim.worldPosX;
            f32 dy = ((PushableState *)player)->probeLocal[0].y - ((GameObject *)obj)->anim.worldPosY;
            f32 dz = ((PushableState *)player)->probeLocal[0].z - ((GameObject *)obj)->anim.worldPosZ;
            dist = sqrtf(dx * dx + dy * dy + dz * dz);
        }
        if (lbl_803DCEB8 > -1 && ((WarpPointState *)state)->unkC == 0 && *(s8 *)(def + 0x1c) != 0 &&
            dist < ((WarpPointState *)state)->unk8 &&
            *(u32 *)&((GameObject *)player)->anim.parent == *(u32 *)&((GameObject *)obj)->anim.parent) {
            (*gObjectTriggerInterface)->runSequence(state[2], obj, -1);
            lbl_803DCDE0 = 2;
            ((WarpPointState *)state)->unkC = 1;
        }
        if (GameBit_Get(state[1]) != 0 && *state == 0 && dist <= ((WarpPointState *)state)->unk8 &&
            *(s8 *)(def + 0x1a) > -1) {
            GameBit_Set(state[1], 0);
            warpToMap(*(s8 *)(def + 0x1a), 1);
        }
        break;
    }
}

extern void objSetSlot(s16 *obj, int slot);
extern int modelFileHeaderGetCullDistance(int hdr);
extern void Model_GetVertexPosition(int *model, int idx, f32 *out);
extern void debugPrintf(char *fmt, ...);
extern char sPushPullObjectHitpointOverflow[];
extern void Matrix_TransformPoint(f32 *matrix, f32 x, f32 y, f32 z, f32 *outX, f32 *outY, f32 *outZ);
extern int arrayIndexOf(int *array, int count, int value);
extern void fn_8007FE04(int *array, int *count, int value);
extern f32 lbl_803E358C;
extern f32 lbl_803E35CC;
extern f32 lbl_803E3558;
extern f32 lbl_803E3540;
extern f32 lbl_803E3588;

void pushable_init(s16 *obj, char *def) {
    PushableState *state;
    int *model;
    int *entry;
    f32 *mtx;
    int i;
    char *e;
    f32 vtx[3];

    if (((ObjPlacement *)def)->mapId == 0x30398) {
        ((PushableObjectDef *)def)->unk23 = 1;
    } else {
        *(s8 *)&((PushableObjectDef *)def)->unk23 = -1;
    }
    *obj = ((PushableObjectDef *)def)->unk22 << 8;
    ((GameObject *)obj)->anim.localPosY = lbl_803E358C + ((ObjPlacement *)def)->posY;
    ObjGroup_AddObject(obj, 5);
    objSetSlot(obj, 0x5a);
    ((GameObject *)obj)->animEventCallback = (void *)fn_8017510C;
    state = ((GameObject *)obj)->extra;
    state->pointCount = 0;
    entry = Transporter_GetActiveModel(obj);
    model = (int *)*entry;
    state->unk_B0 = *(int *)&((PushableObjectDef *)def)->unk1C;
    state->scale = (f32)*(u16 *)&((PushableObjectDef *)def)->unk20 / lbl_803E35CC;
    state->scale = state->scale * *(f32 *)(*(int *)&((GameObject *)obj)->anim.modelInstance + 4);
    state->cullDistance = state->scale * (f32)(u16)modelFileHeaderGetCullDistance(*entry) + lbl_803E3558;
    state->timer_0x14 = lbl_803E3528;
    state->gameBit = ((PushableObjectDef *)def)->unk18;
    ObjAnim_SetCurrentMove((int)obj, 0, lbl_803E3528, 0);
    ObjMsg_AllocQueue(obj, 4);
    ObjHits_EnableObject(obj);
    {
        f32 minY = lbl_803E3540;
        for (i = 0; i < *(u16 *)((char *)model + 0xe4); i++) {
            Model_GetVertexPosition(model, i, vtx);
            if (vtx[1] < minY) {
                minY = vtx[1];
            }
        }
        for (i = 0; i < *(u16 *)((char *)model + 0xe4); i++) {
            Model_GetVertexPosition(model, i, vtx);
            if (vtx[1] == minY) {
                int found = 0;
                int j = 0;
                u8 cnt = *(u8 *)&state->pointCount;

                for (; j < (s8)cnt; j++) {
                    char *p = (char *)state + j * 0xc;
                    if (vtx[0] == *(f32 *)(p + 0x48) && vtx[2] == *(f32 *)(p + 0x50)) {
                        found = 1;
                        j = (s8)cnt;
                    }
                }
                if (found == 0) {
                    *(f32 *)((u8 *)state + (s8)cnt * 0xc + 0x48) = vtx[0];
                    *(f32 *)((u8 *)state + state->pointCount * 0xc + 0x4c) = vtx[1];
                    *(f32 *)((u8 *)state + state->pointCount * 0xc + 0x50) = vtx[2];
                    state->pointCount += 1;
                }
            }
        }
    }
    if (state->pointCount > 4) {
        state->pointCount = 4;
        debugPrintf(sPushPullObjectHitpointOverflow);
    }
    {
        char *mi = *(char **)((char *)obj + 0x58);
        mtx = (f32 *)(mi + ((*(u8 *)(mi + 0x10c) + 2) << 4) * 4);
    }
    i = 0;
    e = (char *)state;
    {
        f32 zero = lbl_803E3528;
        for (; i < state->pointCount; i++) {
            f32 v;
            ((PushableState *)e)->probeLocal[0].x = ((PushableState *)e)->cornerLocal[0].x;
            ((PushableState *)e)->probeLocal[0].y = ((PushableState *)e)->cornerLocal[0].y;
            ((PushableState *)e)->probeLocal[0].z = ((PushableState *)e)->cornerLocal[0].z;
            v = ((PushableState *)e)->probeLocal[0].x;
            if (v < zero) {
                ((PushableState *)e)->probeLocal[0].x = v + lbl_803E358C;
            } else {
                ((PushableState *)e)->probeLocal[0].x = v - lbl_803E358C;
            }
            v = ((PushableState *)e)->probeLocal[0].z;
            if (v < zero) {
                ((PushableState *)e)->probeLocal[0].z = v + lbl_803E358C;
            } else {
                ((PushableState *)e)->probeLocal[0].z = v - lbl_803E358C;
            }
            v = ((PushableState *)e)->cornerLocal[0].x;
            if (v < zero) {
                ((PushableState *)e)->cornerLocal[0].x = v + lbl_803E3588;
            } else {
                ((PushableState *)e)->cornerLocal[0].x = v - lbl_803E3588;
                state->cornerIdxPosX = i;
            }
            v = ((PushableState *)e)->cornerLocal[0].z;
            if (v < zero) {
                ((PushableState *)e)->cornerLocal[0].z = v + lbl_803E3588;
            } else {
                ((PushableState *)e)->cornerLocal[0].z = v - lbl_803E3588;
                state->cornerIdxPosZ = i;
            }
            Matrix_TransformPoint(mtx, ((PushableState *)e)->probeLocal[0].x, ((PushableState *)e)->probeLocal[0].y, ((PushableState *)e)->probeLocal[0].z,
                                  (f32 *)(e + 0x78), (f32 *)(e + 0x7c), (f32 *)(e + 0x80));
            e += 0xc;
        }
    }
    i = 0;
    e = (char *)state;
    for (; i < state->pointCount; i++) {
        if (i != state->cornerIdxPosX && ((PushableState *)e)->cornerLocal[0].x < lbl_803E3528) {
            if ((int)((PushableState *)e)->cornerLocal[0].z == (int)*(f32 *)((u8 *)state + state->cornerIdxPosX * 0xc + 0x50)) {
                state->cornerIdxNegX = i;
            }
        }
        if (i != state->cornerIdxPosZ && ((PushableState *)e)->cornerLocal[0].z < lbl_803E3528) {
            if ((int)((PushableState *)e)->cornerLocal[0].x == (int)*(f32 *)((u8 *)state + state->cornerIdxPosZ * 0xc + 0x48)) {
                state->cornerIdxNegZ = i;
            }
        }
        e += 0xc;
    }
    state->savePosEnabled = 1;
    switch (((GameObject *)obj)->anim.seqId) {
    case 0x21e:
        fn_80174A80(obj, state);
        break;
    case 0x411:
        fn_80174A80(obj, state);
        break;
    case 0x7df:
        fn_80174588(obj, state);
        break;
    case 0x1cb:
        if (((PushableObjectDef *)def)->unk18 > -1 && GameBit_Get(((PushableObjectDef *)def)->unk18) != 0) {
            state->flags = state->flags | 0x81;
            *(u8 *)&((GameObject *)obj)->anim.resetHitboxMode = *(u8 *)&((GameObject *)obj)->anim.resetHitboxMode | 8;
            pushable_savePos((int *)obj);
        }
        state->savePosEnabled = 0;
        break;
    default:
        if (((PushableObjectDef *)def)->unk18 > -1 && GameBit_Get(((PushableObjectDef *)def)->unk18) != 0) {
            state->flags = state->flags | 1;
        }
        break;
    }
    {
        char *r = *(char **)&((GameObject *)obj)->anim.modelState;
        if (r != NULL) {
            *(u32 *)(r + 0x30) = *(u32 *)(r + 0x30) | 0xa10;
            (*(char **)&((GameObject *)obj)->anim.modelState)[0x3a] = 0x60;
            (*(char **)&((GameObject *)obj)->anim.modelState)[0x3b] = 0x40;
        }
    }
    state->flags = state->flags | 0x40;
    if (arrayIndexOf(lbl_803AC6E0, lbl_803DDAB8, ((ObjPlacement *)def)->mapId) != -1) {
        state->flags = state->flags | 1;
        fn_8007FE04(lbl_803AC6E0, &lbl_803DDAB8, ((ObjPlacement *)def)->mapId);
    }
}


extern int lbl_802C2270[];
extern int fn_802969F0(void);
extern void setMatrixFromObjectPos(f32 *mtx, void *vec);
extern void objMove(int *obj, f32 x, f32 y, f32 z);
extern void Obj_BuildTransformMatrices(int *obj);
extern void Obj_TransformLocalPointToWorld(f32 x, f32 y, f32 z, f32 *ox, f32 *oy, f32 *oz, int *obj);
extern void hitDetect_calcSweptSphereBounds(int *boundsOut, f32 *startPoints, f32 *endPoints, int *box, int count);
extern void hitDetectFn_800691c0(int *obj, int *bounds, int a, int b);
extern f32 lbl_803E35A8;
extern f32 lbl_803E35AC;
extern f32 lbl_803E35B0;
extern f32 lbl_803E35B4;
extern f32 lbl_803E35B8;
extern f32 lbl_803E35BC;
extern f32 lbl_803E35C0;
extern f32 lbl_803E35C4;
extern f32 lbl_803E35C8;

typedef struct { int a, b, c, d; } PushableBox16;
typedef struct { u8 pad[0x24]; f32 vx; u8 pad2[4]; f32 vz; } PushableObjPos;

void pushable_hitDetect(int *obj) {
    PushableState *state;
    f32 *w;
    f32 *wp;
    u8 *e;
    int i;
    int cnt2;
    int cntE;
    s8 cnt;
    f32 *hp;
    f32 acc;
    f32 wpos[12];
    f32 mtx[16];
    int sweep[6];
    struct { s16 dir[3]; s16 pad; f32 pos[4]; } vec;
    f32 hp4[4];
    PushableBox16 box;
    int list;
    f32 tmpY;

    box = *(PushableBox16 *)lbl_802C2270;
    Obj_GetPlayerObject();
    state = ((GameObject *)obj)->extra;
    state->timer_0x110 = state->timer_0x110 - timeDelta;
    if (state->timer_0x110 <= lbl_803E3528) {
        state->timer_0x110 = lbl_803E3528;
    }
    if (state->moveFlags.b7 == 0) {
        f32 k;
        if (fn_802969F0() == 0xd) {
            k = lbl_803E35A8;
        } else {
            k = lbl_803E35AC;
        }
        state->pushAmountX = state->pushAmountX * k;
        if (state->pushAmountX < lbl_803E35B0 && state->pushAmountX > lbl_803E35B4) {
            state->pushAmountX = lbl_803E3528;
        }
        state->pushAmountZ = state->pushAmountZ * k;
        if (state->pushAmountZ < lbl_803E35B0 && state->pushAmountZ > lbl_803E35B4) {
            state->pushAmountZ = lbl_803E3528;
        }
        if (lbl_803E3528 != state->pushAmountX || lbl_803E3528 != state->pushAmountZ) {
            vec.dir[0] = state->yaw;
            vec.dir[1] = 0;
            vec.dir[2] = 0;
            vec.pos[0] = lbl_803E3588;
            vec.pos[1] = lbl_803E3528;
            vec.pos[2] = lbl_803E3528;
            vec.pos[3] = lbl_803E3528;
            setMatrixFromObjectPos(mtx, &vec);
            Matrix_TransformPoint(mtx, state->pushAmountZ, lbl_803E3528, state->pushAmountX,
                                  (f32 *)((char *)obj + 0x24), &tmpY, (f32 *)((char *)obj + 0x2c));
            objMove(obj, ((f32 *)obj)[9], lbl_803E3528, ((f32 *)obj)[11]);
            if ((state->flags & 4) == 0) {
                fn_80174BFC(obj, state);
            }
            state->flags = state->flags | 2;
        }
    }
    state->moveFlags.b6 = 1;
    switch (((GameObject *)obj)->anim.seqId) {
    case 0x108:
        if (GameBit_Get(0x272) != 0) {
            return;
        }
        break;
    case 0x21e:
        if (GameBit_Get(state->gameBit) != 0) {
            return;
        }
        break;
    case 0x411:
        if (GameBit_Get(state->gameBit) != 0) {
            return;
        }
        break;
    case 0x85a:
        state->moveFlags.b6 = 0;
        break;
    case 0x54a:
        break;
    }
    if ((state->flags & 4) != 0) {
        ((GameObject *)obj)->anim.velocityY = -(lbl_803E35B8 * timeDelta - ((GameObject *)obj)->anim.velocityY);
        ((GameObject *)obj)->anim.localPosY = ((GameObject *)obj)->anim.velocityY * timeDelta + ((GameObject *)obj)->anim.localPosY;
    }
    if ((state->flags & 2) != 0 || (state->flags & 4) != 0) {
        Obj_BuildTransformMatrices(obj);
        i = 0;
        wp = wpos;
        w = wp;
        e = (u8 *)state;
        for (; i < state->pointCount; i++) {
            Obj_TransformLocalPointToWorld(((PushableState *)e)->cornerLocal[0].x, ((PushableState *)e)->cornerLocal[0].y, ((PushableState *)e)->cornerLocal[0].z,
                                           w, w + 1, w + 2, obj);
            w += 3;
            e += 0xc;
        }
        hitDetect_calcSweptSphereBounds(sweep, (f32 *)state->cornerWorld, wpos, (int *)&box, 4);
        sweep[1] = (int)((f32)sweep[1] - lbl_803E35BC);
        sweep[4] = (int)((f32)sweep[4] + lbl_803E35BC);
        hitDetectFn_800691c0(obj, sweep, 1, 1);
        tmpY = lbl_803E3528;
        cnt2 = 0;
        cntE = 0;
        i = 0;
        hp = hp4;
        for (; i < state->pointCount; i++) {
            f32 y = wp[1];
            s8 found;

            *hp = y;
            acc = lbl_803E3528;
            cnt = hitDetectFn_80065e50(obj, wp[0], y, wp[2], (f32 ***)&list, -1, 0);
            found = 0;
            if (cnt != 0) {
                int j = 0;
                int off = 0;

                for (; j < cnt; j++) {
                    f32 *h = *(f32 **)(list + off);
                    if (*(s8 *)((char *)h + 0x14) == 0xe) {
                        f32 d = h[0] - ((GameObject *)obj)->anim.localPosY;
                        if (d > lbl_803E3528) {
                            acc = acc + d;
                            cntE++;
                        }
                    } else if (found == 0) {
                        f32 v = h[0];
                        if (v < lbl_803E3558 + wp[1] && v > wp[1] - lbl_803E35C0 && h[2] > lbl_803E35C4) {
                            u32 o;
                            *hp = v;
                            tmpY = tmpY + v;
                            o = *(u32 *)(*(int *)(list + off) + 0x10);
                            if (o != 0) {
                                ObjHits_AddContactObject(o, obj);
                            }
                            cnt2++;
                            found = 1;
                        }
                    }
                    off += 4;
                }
            }
            wp += 3;
            hp++;
        }
        state->prevWaterDepth = state->waterDepth;
        if (cntE != 0) {
            state->waterDepth = acc / (f32)cntE;
        } else {
            state->waterDepth = lbl_803E3528;
        }
        if (cnt2 != 0 && state->timer_0x110 <= lbl_803E3528) {
            ((GameObject *)obj)->anim.velocityY = lbl_803E3528;
            ((GameObject *)obj)->anim.localPosY = lbl_803E358C + tmpY / (f32)cnt2;
            state->flags = state->flags & ~0xc;
        } else {
            if ((state->flags & 4) == 0) {
                state->timer_0x110 = lbl_803E35C8;
            }
            state->flags = state->flags | 0xc;
        }
    }
    Obj_BuildTransformMatrices(obj);
    i = 0;
    e = (u8 *)state;
    for (; i < state->pointCount; i++) {
        Obj_TransformLocalPointToWorld(((PushableState *)e)->probeLocal[0].x, ((PushableState *)e)->probeLocal[0].y, ((PushableState *)e)->probeLocal[0].z,
                                       (f32 *)(e + 0x78), (f32 *)(e + 0x7c), (f32 *)(e + 0x80), obj);
        e += 0xc;
    }
}

extern f32 mathSinf(f32 x);
extern f32 mathCosf(f32 x);
extern int hitDetectFn_80067958(int a, f32 *start, f32 *end, int b, void *buf, int c);
extern int objBboxFn_800640cc(f32 *start, f32 *end, f32 radius, int a, int b, int *obj, int c, int d, int e, int f);
extern f32 lbl_803E3590;
extern f32 lbl_803E3594;
extern f32 lbl_803E359C;
extern f32 lbl_803E35A0;
extern f32 lbl_803E35A4;

typedef struct {
    f32 r[4];
    s8 b10;
    u8 pad1[3];
    u8 b14;
    u8 pad2[0x17];
    s16 h2c;
    s16 pad3;
} SetScaleParams;

int pushable_setScale(int *obj, s16 *tgt, int flag, f32 dx, f32 dz) {
    SetScaleParams *pp;
    PushableState *state;
    char ret;
    void *player;
    int hit;
    char *p;
    f32 *w;
    f32 *e2;
    f32 *d;
    int i;
    SetScaleParams params;
    char hitbuf[64];
    f32 mtx[16];
    f32 wpos[12];
    f32 deltas[12];
    struct { s16 dir[3]; s16 pad; f32 pos[4]; } vec;
    int sweep[6];
    f32 start[3];
    f32 end[3];
    f32 tmpY;

    player = Obj_GetPlayerObject();
    state = ((GameObject *)obj)->extra;
    ret = 0;
    i = 5;
    p = (char *)state + 0x14;
    while (p -= 4, i-- != 0) {
        *(f32 *)(p + 0x118) = *(f32 *)(p + 0x114);
        *(f32 *)(p + 0x12c) = *(f32 *)(p + 0x128);
    }
    state->posHistX[0] = ((GameObject *)obj)->anim.localPosX;
    state->posHistZ[0] = ((GameObject *)obj)->anim.localPosZ;
    start[0] = ((GameObject *)tgt)->anim.localPosX;
    start[1] = lbl_803E359C + ((GameObject *)tgt)->anim.localPosY;
    start[2] = ((GameObject *)tgt)->anim.localPosZ;
    pp = &params;
    pp->r[0] = lbl_803E35A0;
    pp->b10 = -1;
    pp->b14 = 3;
    pp->h2c = 0;
    hit = 0;
    if (dx > lbl_803E3528) {
        end[0] = lbl_803E35A0 * mathSinf(lbl_803E3590 * (f32)state->yaw / lbl_803E3594) + start[0];
        end[1] = start[1];
        end[2] = lbl_803E35A0 * mathCosf(lbl_803E3590 * (f32)state->yaw / lbl_803E3594) + start[2];
        hitDetect_calcSweptSphereBounds(sweep, start, end, (int *)pp, 1);
        hitDetectFn_800691c0(NULL, sweep, 0x208, 1);
        hit = hitDetectFn_80067958(0, start, end, 1, hitbuf, 8);
        if (hit == 0) {
            hit = objBboxFn_800640cc(start, end, pp->r[0], 0, 0, obj, 1, -1, 0xff, 0);
        }
        if (hit != 0) {
            f32 t;
            state->flags = state->flags | 0x200;
            t = lbl_803E3528;
            state->pushAmountX = t;
            state->pushAmountZ = t;
        }
    } else if (dz > lbl_803E3528) {
        end[0] = lbl_803E35A4 * mathSinf(lbl_803E3590 * (f32)(state->yaw + 0x4000) / lbl_803E3594) + start[0];
        end[1] = start[1];
        end[2] = lbl_803E35A4 * mathCosf(lbl_803E3590 * (f32)(state->yaw + 0x4000) / lbl_803E3594) + start[2];
        hitDetect_calcSweptSphereBounds(sweep, start, end, (int *)pp, 1);
        hitDetectFn_800691c0(NULL, sweep, 0x208, 1);
        hit = hitDetectFn_80067958(0, start, end, 1, hitbuf, 8);
        if (hit == 0) {
            hit = objBboxFn_800640cc(start, end, pp->r[0], 0, 0, obj, 1, -1, 0xff, 0);
        }
        if (hit != 0) {
            f32 t;
            state->flags = state->flags | 0x800;
            t = lbl_803E3528;
            state->pushAmountX = t;
            state->pushAmountZ = t;
        }
    } else if (dz < lbl_803E3528) {
        end[0] = lbl_803E35A4 * mathSinf(lbl_803E3590 * (f32)(state->yaw - 0x4000) / lbl_803E3594) + start[0];
        end[1] = start[1];
        end[2] = lbl_803E35A4 * mathCosf(lbl_803E3590 * (f32)(state->yaw - 0x4000) / lbl_803E3594) + start[2];
        hitDetect_calcSweptSphereBounds(sweep, start, end, (int *)pp, 1);
        hitDetectFn_800691c0(NULL, sweep, 0x208, 1);
        hit = hitDetectFn_80067958(0, start, end, 1, hitbuf, 8);
        if (hit == 0) {
            hit = objBboxFn_800640cc(start, end, pp->r[0], 0, 0, obj, 1, -1, 0xff, 0);
        }
        if (hit != 0) {
            f32 t;
            state->flags = state->flags | 0x400;
            t = lbl_803E3528;
            state->pushAmountX = t;
            state->pushAmountZ = t;
        }
    }
    if (playerIsDisguised(player) == 0 && state->moveFlags.b6 == 0) {
        hit = 1;
        if (dx > lbl_803E3528) {
            state->flags = state->flags | 0x200;
        } else if (dx < lbl_803E3528) {
            state->flags = state->flags | 0x100;
        } else if (dz > lbl_803E3528) {
            state->flags = state->flags | 0x800;
        } else {
            state->flags = state->flags | 0x400;
        }
        {
            f32 t = lbl_803E3528;
            state->pushAmountX = t;
            state->pushAmountZ = t;
        }
    }
    if (flag != 0 && (state->flags & 8) == 0) {
        state->flags = state->flags | 2;
        state->pushSfxTimer -= 1;
        if (state->pushSfxTimer <= 0) {
            state->pushSfxTimer = randomGetRange(0x28, 0x3c);
            state->flags = state->flags | 0x20;
        }
        if ((state->flags & 0x80) != 0) {
            f32 t = lbl_803E3528;
            state->pushAmountX = t;
            state->pushAmountZ = t;
        } else if (hit == 0) {
            state->pushAmountX = dx;
            state->pushAmountZ = dz;
        }
        state->yaw = *tgt;
        vec.dir[0] = *tgt;
        vec.dir[1] = 0;
        vec.dir[2] = 0;
        vec.pos[0] = lbl_803E3588;
        vec.pos[1] = lbl_803E3528;
        vec.pos[2] = lbl_803E3528;
        vec.pos[3] = lbl_803E3528;
        setMatrixFromObjectPos(mtx, &vec);
        Matrix_TransformPoint(mtx, state->pushAmountZ, lbl_803E3528, state->pushAmountX,
                              (f32 *)((char *)obj + 0x24), &tmpY, (f32 *)((char *)obj + 0x2c));
        state->moveFlags.b7 = 1;
        objMove(obj, ((PushableObjPos *)obj)->vx, lbl_803E3528, ((PushableObjPos *)obj)->vz);
        Obj_BuildTransformMatrices(obj);
        w = wpos;
        e2 = (f32 *)state;
        d = deltas;
        for (i = 0; i < state->pointCount; i++) {
            Obj_TransformLocalPointToWorld(*(f32 *)((char *)e2 + 0x18), *(f32 *)((char *)e2 + 0x1c),
                                           *(f32 *)((char *)e2 + 0x20), w, w + 1, w + 2, obj);
            d[0] = ((GameObject *)obj)->anim.localPosX - w[0];
            d[1] = ((GameObject *)obj)->anim.localPosY - w[1];
            d[2] = ((GameObject *)obj)->anim.localPosZ - w[2];
            w += 3;
            e2 = (f32 *)((char *)e2 + 0xc);
            d += 3;
        }
        if ((state->flags & 4) == 0) {
            fn_80174BFC(obj, state);
        }
        Obj_BuildTransformMatrices(obj);
        if (lbl_803E3528 != state->pushAmountX || lbl_803E3528 != state->pushAmountZ) {
            PushableState *st2 = ((GameObject *)obj)->extra;
            char *def2 = *(char **)&((GameObject *)obj)->anim.placementData;
            u16 fl2 = st2->flags;
            if ((fl2 & 1) != 0) {
                s16 t;
                st2->flags = fl2 & ~1;
                t = *(s16 *)(def2 + 0x18);
                if (t > -1) {
                    switch (((GameObject *)obj)->anim.seqId) {
                    case 0x21e:
                        break;
                    case 0x411:
                        break;
                    case 0x7df:
                        break;
                    default:
                        if (*(s8 *)(def2 + 0x23) > -1) {
                            GameBit_Set(t, 0);
                        }
                        break;
                    }
                }
            }
        }
        {
            f32 f5 = ((GameObject *)obj)->anim.localPosX - state->posHistX[4];
            f32 f6 = ((GameObject *)obj)->anim.localPosZ - state->posHistZ[4];
            if (f5 * f5 + f6 * f6 > lbl_803E3588 && (state->flags & 0x20) != 0) {
                Sfx_PlayFromObject(obj, 100);
                state->flags = state->flags & ~0x20;
            }
        }
    } else {
        char *mi = *(char **)((char *)obj + 0x58);
        f32 *mtx2 = (f32 *)(mi + ((*(u8 *)(mi + 0x10c) + 2) << 4) * 4);
        e2 = (f32 *)state;
        for (i = 0; i < state->pointCount; i++) {
            Matrix_TransformPoint(mtx2, *(f32 *)((char *)e2 + 0x18), *(f32 *)((char *)e2 + 0x1c),
                                  *(f32 *)((char *)e2 + 0x20), (f32 *)((char *)e2 + 0x78),
                                  (f32 *)((char *)e2 + 0x7c), (f32 *)((char *)e2 + 0x80));
            e2 = (f32 *)((char *)e2 + 0xc);
        }
    }
    {
        u16 fl = state->flags;
        if ((fl & 0x100) != 0) {
            ret = 1;
        } else if ((fl & 0x200) != 0) {
            ret = 2;
        } else if ((fl & 0x400) != 0) {
            ret = 3;
        } else if ((fl & 0x800) != 0) {
            ret = 4;
        } else if ((fl & 8) != 0) {
            ret = 5;
        }
        state->flags = fl & ~0xf00;
    }
    return ret;
}

extern void fn_8003B5E0(int a, int b, int c, int d);

void pushable_render(int *obj, int p1, int p2, int p3, int p4, s8 visible) {
    if (visible != 0) {
        PushableState *state = ((GameObject *)obj)->extra;
        switch (((GameObject *)obj)->anim.seqId) {
        case 0x21e:
            if (GameBit_Get(state->gameBit) == 0) {
                break;
            }
            return;
        case 0x411:
            if (GameBit_Get(state->gameBit) == 0) {
                break;
            }
            return;
        case 0x54a: {
            f32 v = state->timer_0x14;
            f32 zero = lbl_803E3528;
            if (v > zero) {
                state->timer_0x14 = v - timeDelta;
                if (state->timer_0x14 <= zero) {
                    state->timer_0x14 = zero;
                } else {
                    fn_8003B5E0(0xc8, 0, 0, 0xff);
                }
            }
            break;
        }
        }
        {
            char *hdr = (char *)Transporter_GetActiveModel(obj);
            *(u16 *)(*(char **)hdr + 2) = *(u16 *)(*(char **)hdr + 2) | 2;
        }
        objRenderFn_8003b8f4(obj, p1, p2, p3, p4, lbl_803E3588);
    }
}
