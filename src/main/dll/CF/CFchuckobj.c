#include "main/asset_load.h"
#include "main/dll/CF/CFchuckobj.h"
#include "main/dll/rom_curve_interface.h"
#include "main/effect_interfaces.h"
#include "main/expgfx.h"
#include "main/game_object.h"
#include "main/dll/CF/CFTreasSharpy.h"
#include "main/dll/CF/warp_pad.h"
#include "main/objseq.h"
#include "main/resource.h"

typedef struct WarpPadPlayerStandingOnPlacement {
    u8 pad0[0x20 - 0x0];
    s16 unk20;
    u8 pad22[0x28 - 0x22];
} WarpPadPlayerStandingOnPlacement;


extern undefined4 FUN_80006824();
extern int FUN_80006a10();
extern undefined4 FUN_80006b0c();
extern undefined4 FUN_80006b14();
extern undefined4 FUN_80017640();
extern uint GameBit_Get(int eventId);
extern undefined4 GameBit_Set(int eventId,int value);
extern undefined4 FUN_80017710();
extern double FUN_80017714();
extern undefined4 FUN_80017748();
extern void vecRotateZXY(s16* in, f32* out);
extern u32 randomGetRange(int min, int max);
extern undefined4 FUN_80017814();
extern undefined4 FUN_80017830();
extern int FUN_80017a98();
extern undefined4 FUN_80017ac8();
extern undefined8 ObjGroup_RemoveObject();
extern undefined4 ObjGroup_AddObject();
extern void Obj_FreeObject(int obj);
extern int ObjTrigger_IsSet();
extern f32 Vec_xzDistance(f32* posA, f32* posB);
extern f32 vec3f_distanceSquared(f32* posA, f32* posB);
extern void objfx_spawnArcedBurst(int obj, int enabled, f32 radius, int particleKind,
                                   int particleId, int lifetime, f32 scaleX, f32 scaleY,
                                   f32 scaleZ, void* args, int arg9);
extern undefined4 FUN_800810f8();
extern undefined4 FUN_8011e868();
extern int Obj_GetPlayerObject(void);
extern int Curve_AdvanceAlongPath(int curve, f32 progress);
extern void* mmAlloc(int size, int heap, int flags);
extern undefined4 FUN_80286838();
extern undefined8 FUN_8028683c();
extern undefined4 FUN_80286884();
extern undefined4 FUN_80286888();
extern double FUN_80293900();
extern f32 sqrtf(f32 value);

extern undefined4 DAT_803ad410;
extern undefined4 DAT_803ad41e;
extern undefined4 DAT_803dc070;
extern ModgfxInterface **gModgfxInterface;
extern undefined4* DAT_803dd71c;
extern EffectInterface **gPartfxInterface;
extern ObjectTriggerInterface **gObjectTriggerInterface;
extern undefined4 DAT_803dda60;
extern undefined4 DAT_803ddb38;
extern u8 lbl_803DCDE0;
extern s16 lbl_803DCEB8;
extern u8 framesThisStep;
extern f32 timeDelta;
extern f64 DOUBLE_803e4af0;
extern f64 DOUBLE_803e4af8;
extern f64 DOUBLE_803e4b28;
extern f64 DOUBLE_803e4b70;
extern f32 FLOAT_803dc074;
extern f32 FLOAT_803e4ae4;
extern f32 FLOAT_803e4ae8;
extern f32 FLOAT_803e4b00;
extern f32 FLOAT_803e4b04;
extern f32 FLOAT_803e4b08;
extern f32 FLOAT_803e4b10;
extern f32 FLOAT_803e4b14;
extern f32 FLOAT_803e4b18;
extern f32 FLOAT_803e4b1c;
extern f32 FLOAT_803e4b20;
extern f32 FLOAT_803e4b30;
extern f32 FLOAT_803e4b34;
extern f32 FLOAT_803e4b38;
extern f32 FLOAT_803e4b3c;
extern f32 FLOAT_803e4b40;
extern f32 FLOAT_803e4b44;
extern f32 FLOAT_803e4b48;
extern f32 FLOAT_803e4b4c;
extern f32 FLOAT_803e4b50;
extern f32 FLOAT_803e4b54;
extern f32 FLOAT_803e4b58;
extern f32 FLOAT_803e4b5c;
extern f32 FLOAT_803e4b60;
extern f32 FLOAT_803e4b64;
extern f32 FLOAT_803e4b68;
extern f32 FLOAT_803e4b78;
extern f32 lbl_803E3E50;
extern f32 lbl_803E3E68;
extern f32 lbl_803E3E6C;
extern f32 lbl_803E3E70;
extern f32 lbl_803E3E78;
extern f32 lbl_803E3E7C;
extern f32 lbl_803E3E80;
extern f32 lbl_803E3E84;
extern f32 lbl_803E3E88;
extern f32 lbl_803E3E98;
extern f32 lbl_803E3E9C;
extern f32 lbl_803E3EA0;
extern f32 lbl_803E3EA4;
extern f32 lbl_803E3EA8;
extern f32 lbl_803E3EAC;
extern f32 lbl_803E3EB0;
extern f32 lbl_803E3EB4;
extern f32 lbl_803E3EB8;
extern f32 lbl_803E3EBC;
extern f32 lbl_803E3EC0;
extern f32 lbl_803E3EC4;
extern f32 lbl_803E3EC8;
extern f32 lbl_803E3ECC;
extern f32 lbl_803E3ED0;
extern f32 lbl_803E3EE0;

extern void setAButtonIcon(int iconId);

/*
 * --INFO--
 *
 * Function: fxemit_init
 * EN v1.0 Address: 0x8018EFE0
 * EN v1.0 Size: 376b
 * EN v1.1 Address: 0x8018F020
 * EN v1.1 Size: 400b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void fxemit_init(FxEmitObject *obj, FxEmitPlacement *setup)
{
  FxEmitState *state;
  s16 emitCount;

  obj->objAnim.rotX = 0;
  obj->seqCallback = fxemit_SeqFn;
  state = obj->state;

  state->triggerRadius = (f32)((s32)setup->triggerRadius << 2);
  state->effectMode = setup->effectMode;
  state->effectId = setup->effectId;
  emitCount = setup->emitCount;
  state->emitCount = emitCount;
  obj->objAnim.rootMotionScale = lbl_803E3E50;
  state->enableBit = setup->enableBit;
  state->stopBit = setup->stopBit;
  state->suppressed = 0;

  if (emitCount < 1) {
    obj->emitCooldown = emitCount;
  } else {
    obj->emitCooldown = 0;
  }

  if (state->stopBit != -1 && GameBit_Get(state->stopBit) != 0) {
    state->suppressed = 1;
  }

  obj->objAnim.rotX = (s16)(setup->initialYaw << 8);
  obj->objAnim.rotY = (s16)(setup->initialPitch << 8);
  obj->objAnim.rotZ = (s16)(setup->initialRoll << 8);
  state->sfxTimer = (s16)(setup->sfxPeriod * 100);
  state->initialX = obj->objAnim.localPosX;
  state->startDelay = (s16)randomGetRange(0, 10);
  state->altEffectId = 0;
}

#pragma dont_inline on
void areafxemit_emitBurst(AreaFxEmitObject *obj, int count)
{
  AreaFxEmitState *state;
  s16 i;
  struct {
    s16 hw[6];
    f32 vec[3];
  } args;

  state = obj->state;
  if (count > 0) {
    for (i = 0; i < count; i++) {
      {
        u16 sx = state->extentX;
        args.vec[0] = (f32)(s32)randomGetRange(-sx, sx);
      }
      {
        u16 sy = state->extentY;
        args.vec[1] = (f32)(s32)randomGetRange(-sy, sy);
      }
      {
        u16 sz = state->extentZ;
        args.vec[2] = (f32)(s32)randomGetRange(-sz, sz);
      }
      vecRotateZXY(state->emitAngles, args.vec);
      {
        u8 type = state->emitType;
        if (type == 4 || type == 6) {
          args.vec[0] += obj->objAnim.localPosX;
          args.vec[1] += obj->objAnim.localPosY;
          args.vec[2] += obj->objAnim.localPosZ;
          (*gPartfxInterface)->spawnObject(obj, state->effectId, &args, 0x200001, -1, NULL);
        } else {
          (*gPartfxInterface)->spawnObject(obj, state->effectId, &args, 2, -1, NULL);
        }
      }
    }
  }
}
#pragma dont_inline reset

/*
 * --INFO--
 *
 * Function: FUN_8018f158
 * EN v1.0 Address: 0x8018F158
 * EN v1.0 Size: 92b
 * EN v1.1 Address: 0x8018F1B0
 * EN v1.1 Size: 100b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling on
#pragma peephole on


/*
 * --INFO--
 *
 * Function: FUN_8018f4fc
 * EN v1.0 Address: 0x8018F4FC
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8018F55C
 * EN v1.1 Size: 360b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off


/*
 * --INFO--
 *
 * Function: FUN_8018f500
 * EN v1.0 Address: 0x8018F500
 * EN v1.0 Size: 336b
 * EN v1.1 Address: 0x8018F6C4
 * EN v1.1 Size: 400b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling on
#pragma peephole on


/*
 * --INFO--
 *
 * Function: FUN_8018f650
 * EN v1.0 Address: 0x8018F650
 * EN v1.0 Size: 1620b
 * EN v1.1 Address: 0x8018F854
 * EN v1.1 Size: 2220b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8018f650(void)
{
  byte bVar1;
  int iVar2;
  int *piVar3;
  short sVar4;
  int iVar5;
  double in_f31;
  double dVar6;
  double in_ps31_1;
  ushort local_68;
  undefined2 local_66;
  short local_64;
  undefined auStack_60 [8];
  float local_58;
  float local_54;
  float local_50;
  float local_4c;
  undefined4 local_48;
  uint uStack_44;
  undefined4 local_40;
  uint uStack_3c;
  undefined4 local_38;
  uint uStack_34;
  float local_8;
  float fStack_4;
  
  local_8 = (float)in_f31;
  fStack_4 = (float)in_ps31_1;
  iVar2 = FUN_8028683c();
  iVar5 = *(int *)(iVar2 + 0xb8);
  local_58 = FLOAT_803e4b00;
  bVar1 = *(byte *)(iVar5 + 8);
  if (bVar1 == 0) {
    if (*(short *)(iVar5 + 0xc) < 1) {
      uStack_34 = randomGetRange(-(uint)*(ushort *)(iVar5 + 0x14),(uint)*(ushort *)(iVar5 + 0x14));
      local_54 = (f32)(s32)uStack_34;
      uStack_3c = randomGetRange(-(uint)*(ushort *)(iVar5 + 0x18),(uint)*(ushort *)(iVar5 + 0x18));
      local_50 = (f32)(s32)uStack_3c;
      uStack_44 = randomGetRange(-(uint)*(ushort *)(iVar5 + 0x16),(uint)*(ushort *)(iVar5 + 0x16));
      local_4c = (f32)(s32)uStack_44;
      local_68 = *(ushort *)(iVar5 + 0x1a);
      local_66 = *(undefined2 *)(iVar5 + 0x1c);
      local_64 = *(short *)(iVar5 + 0x1e);
      if (*(int *)(iVar2 + 0x30) != 0) {
        local_64 = local_64 + *(short *)(*(int *)(iVar2 + 0x30) + 4);
      }
      FUN_80017748(&local_68,&local_54);
      local_54 = local_54 + *(float *)(iVar2 + 0xc);
      local_50 = local_50 + *(float *)(iVar2 + 0x10);
      local_4c = local_4c + *(float *)(iVar2 + 0x14);
      (*gPartfxInterface)->spawnObject((void *)iVar2, *(undefined2 *)(iVar5 + 10),
                                       auStack_60, 0x200001, -1, NULL);
    }
    else {
      dVar6 = DOUBLE_803e4af8;
      for (sVar4 = 0; sVar4 < *(short *)(iVar5 + 0xc); sVar4 = sVar4 + 1) {
        uStack_44 = randomGetRange(-(uint)*(ushort *)(iVar5 + 0x14),(uint)*(ushort *)(iVar5 + 0x14));
        local_54 = (float)((double)CONCAT44(0x43300000,uStack_44) - dVar6);
        uStack_3c = randomGetRange(-(uint)*(ushort *)(iVar5 + 0x18),(uint)*(ushort *)(iVar5 + 0x18));
        local_50 = (float)((double)CONCAT44(0x43300000,uStack_3c) - dVar6);
        uStack_34 = randomGetRange(-(uint)*(ushort *)(iVar5 + 0x16),(uint)*(ushort *)(iVar5 + 0x16));
        local_4c = (float)((double)CONCAT44(0x43300000,uStack_34) - dVar6);
        local_68 = *(ushort *)(iVar5 + 0x1a);
        local_66 = *(undefined2 *)(iVar5 + 0x1c);
        local_64 = *(short *)(iVar5 + 0x1e);
        if (*(int *)(iVar2 + 0x30) != 0) {
          local_64 = local_64 + *(short *)(*(int *)(iVar2 + 0x30) + 4);
        }
        FUN_80017748(&local_68,&local_54);
        local_54 = local_54 + *(float *)(iVar2 + 0xc);
        local_50 = local_50 + *(float *)(iVar2 + 0x10);
        local_4c = local_4c + *(float *)(iVar2 + 0x14);
        (*gPartfxInterface)->spawnObject((void *)iVar2, *(undefined2 *)(iVar5 + 10),
                                         auStack_60, 0x200001, -1, NULL);
      }
    }
  }
  else if (bVar1 == 1) {
    piVar3 = (int *)FUN_80006b14(*(ushort *)(iVar5 + 10) + 0x58 & 0xffff);
    if (*(short *)(iVar5 + 0xc) < 1) {
      (**(code **)(*piVar3 + 4))(iVar2,0,0,1,0xffffffff,0);
    }
    else {
      for (sVar4 = 0; sVar4 < *(short *)(iVar5 + 0xc); sVar4 = sVar4 + 1) {
        (**(code **)(*piVar3 + 4))(iVar2,0,0,1,0xffffffff,0);
      }
    }
    FUN_80006b0c((undefined *)piVar3);
  }
  else if (bVar1 == 2) {
    piVar3 = (int *)FUN_80006b14(*(ushort *)(iVar5 + 10) + 0xab & 0xffff);
    if (*(short *)(iVar5 + 0xc) < 1) {
      (**(code **)(*piVar3 + 4))(iVar2,0,0,1,0xffffffff,*(ushort *)(iVar5 + 10) & 0xff,0);
    }
    else {
      for (sVar4 = 0; sVar4 < *(short *)(iVar5 + 0xc); sVar4 = sVar4 + 1) {
        (**(code **)(*piVar3 + 4))(iVar2,0,0,1,0xffffffff,*(ushort *)(iVar5 + 10) & 0xff,0);
      }
    }
    FUN_80006b0c((undefined *)piVar3);
  }
  else if (bVar1 == 3) {
    if (*(short *)(iVar5 + 0xc) < 1) {
      uStack_34 = randomGetRange(-(uint)*(ushort *)(iVar5 + 0x14),(uint)*(ushort *)(iVar5 + 0x14));
      local_54 = (f32)(s32)uStack_34;
      uStack_3c = randomGetRange(-(uint)*(ushort *)(iVar5 + 0x18),(uint)*(ushort *)(iVar5 + 0x18));
      local_50 = (f32)(s32)uStack_3c;
      uStack_44 = randomGetRange(-(uint)*(ushort *)(iVar5 + 0x16),(uint)*(ushort *)(iVar5 + 0x16));
      local_4c = (f32)(s32)uStack_44;
      local_68 = *(ushort *)(iVar5 + 0x1a);
      local_66 = *(undefined2 *)(iVar5 + 0x1c);
      local_64 = *(short *)(iVar5 + 0x1e);
      if (*(int *)(iVar2 + 0x30) != 0) {
        local_64 = local_64 + *(short *)(*(int *)(iVar2 + 0x30) + 4);
      }
      FUN_80017748(&local_68,&local_54);
      (*gPartfxInterface)->spawnObject((void *)iVar2, *(undefined2 *)(iVar5 + 10),
                                       auStack_60, 2, -1, NULL);
    }
    else {
      dVar6 = DOUBLE_803e4af8;
      for (sVar4 = 0; sVar4 < *(short *)(iVar5 + 0xc); sVar4 = sVar4 + 1) {
        uStack_34 = randomGetRange(-(uint)*(ushort *)(iVar5 + 0x14),(uint)*(ushort *)(iVar5 + 0x14));
        local_54 = (float)((double)CONCAT44(0x43300000,uStack_34) - dVar6);
        uStack_3c = randomGetRange(-(uint)*(ushort *)(iVar5 + 0x18),(uint)*(ushort *)(iVar5 + 0x18));
        local_50 = (float)((double)CONCAT44(0x43300000,uStack_3c) - dVar6);
        uStack_44 = randomGetRange(-(uint)*(ushort *)(iVar5 + 0x16),(uint)*(ushort *)(iVar5 + 0x16));
        local_4c = (float)((double)CONCAT44(0x43300000,uStack_44) - dVar6);
        local_68 = *(ushort *)(iVar5 + 0x1a);
        local_66 = *(undefined2 *)(iVar5 + 0x1c);
        local_64 = *(short *)(iVar5 + 0x1e);
        if (*(int *)(iVar2 + 0x30) != 0) {
          local_64 = local_64 + *(short *)(*(int *)(iVar2 + 0x30) + 4);
        }
        FUN_80017748(&local_68,&local_54);
        (*gPartfxInterface)->spawnObject((void *)iVar2, *(undefined2 *)(iVar5 + 10),
                                         auStack_60, 2, -1, NULL);
      }
    }
  }
  else if (5 < bVar1) {
    if (*(short *)(iVar5 + 0xc) < 1) {
      uStack_34 = randomGetRange(-(uint)*(ushort *)(iVar5 + 0x14),(uint)*(ushort *)(iVar5 + 0x14));
      local_54 = (f32)(s32)uStack_34;
      uStack_3c = randomGetRange(-(uint)*(ushort *)(iVar5 + 0x18),(uint)*(ushort *)(iVar5 + 0x18));
      local_50 = (f32)(s32)uStack_3c;
      uStack_44 = randomGetRange(-(uint)*(ushort *)(iVar5 + 0x16),(uint)*(ushort *)(iVar5 + 0x16));
      local_4c = (f32)(s32)uStack_44;
      FUN_80017748((ushort *)(iVar5 + 0x1a),&local_54);
      if (*(char *)(iVar5 + 8) == '\x06') {
        local_54 = local_54 + *(float *)(iVar2 + 0xc);
        local_50 = local_50 + *(float *)(iVar2 + 0x10);
        local_4c = local_4c + *(float *)(iVar2 + 0x14);
        (*gPartfxInterface)->spawnObject((void *)iVar2, *(undefined2 *)(iVar5 + 10),
                                         auStack_60, 0x200001, -1, NULL);
      }
      else {
        (*gPartfxInterface)->spawnObject((void *)iVar2, *(undefined2 *)(iVar5 + 10),
                                         auStack_60, 2, -1, NULL);
      }
    }
    else {
      dVar6 = DOUBLE_803e4af8;
      for (sVar4 = 0; sVar4 < *(short *)(iVar5 + 0xc); sVar4 = sVar4 + 1) {
        uStack_34 = randomGetRange(-(uint)*(ushort *)(iVar5 + 0x14),(uint)*(ushort *)(iVar5 + 0x14));
        local_54 = (float)((double)CONCAT44(0x43300000,uStack_34) - dVar6);
        uStack_3c = randomGetRange(-(uint)*(ushort *)(iVar5 + 0x18),(uint)*(ushort *)(iVar5 + 0x18));
        local_50 = (float)((double)CONCAT44(0x43300000,uStack_3c) - dVar6);
        uStack_44 = randomGetRange(-(uint)*(ushort *)(iVar5 + 0x16),(uint)*(ushort *)(iVar5 + 0x16));
        local_4c = (float)((double)CONCAT44(0x43300000,uStack_44) - dVar6);
        FUN_80017748((ushort *)(iVar5 + 0x1a),&local_54);
        if (*(char *)(iVar5 + 8) == '\x06') {
          local_54 = local_54 + *(float *)(iVar2 + 0xc);
          local_50 = local_50 + *(float *)(iVar2 + 0x10);
          local_4c = local_4c + *(float *)(iVar2 + 0x14);
          (*gPartfxInterface)->spawnObject((void *)iVar2, *(undefined2 *)(iVar5 + 10),
                                           auStack_60, 0x200001, -1, NULL);
        }
        else {
          (*gPartfxInterface)->spawnObject((void *)iVar2, *(undefined2 *)(iVar5 + 10),
                                           auStack_60, 2, -1, NULL);
        }
      }
    }
  }
  FUN_80286888();
  return;
}


/*
 * --INFO--
 *
 * Function: FUN_8018fd14
 * EN v1.0 Address: 0x8018FD14
 * EN v1.0 Size: 52b
 * EN v1.1 Address: 0x8019018C
 * EN v1.1 Size: 64b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off


/*
 * --INFO--
 *
 * Function: FUN_8018fd48
 * EN v1.0 Address: 0x8018FD48
 * EN v1.0 Size: 380b
 * EN v1.1 Address: 0x801901CC
 * EN v1.1 Size: 392b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling on
#pragma peephole on


/*
 * --INFO--
 *
 * Function: FUN_8018fec4
 * EN v1.0 Address: 0x8018FEC4
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80190354
 * EN v1.1 Size: 368b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off


/*
 * --INFO--
 *
 * Function: FUN_8018ffbc
 * EN v1.0 Address: 0x8018FFBC
 * EN v1.0 Size: 72b
 * EN v1.1 Address: 0x801905C8
 * EN v1.1 Size: 80b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling on
#pragma peephole on


/*
 * --INFO--
 *
 * Function: FUN_80190004
 * EN v1.0 Address: 0x80190004
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80190618
 * EN v1.1 Size: 580b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off


/*
 * --INFO--
 *
 * Function: FUN_80190008
 * EN v1.0 Address: 0x80190008
 * EN v1.0 Size: 320b
 * EN v1.1 Address: 0x8019085C
 * EN v1.1 Size: 332b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling on
#pragma peephole on


/*
 * --INFO--
 *
 * Function: warpPadFn_8019042c
 * EN v1.0 Address: 0x80190148
 * EN v1.0 Size: 1148b
 * EN v1.1 Address: 0x801909A8
 * EN v1.1 Size: 1376b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off
void warpPadFn_8019042c(int param_1)
{
    WarpPadState *state;
    int player;
    u8 flags;
    u8 i;
    struct {
        s16 unk0;
        s16 mode;
        s16 effectId;
        s16 count;
        f32 scale;
        f32 pos[3];
    } fx;

    state = ((GameObject *)param_1)->extra;
    player = Obj_GetPlayerObject();
    fx.pos[0] = lbl_803E3E98;
    fx.pos[1] = lbl_803E3E9C;
    fx.pos[2] = lbl_803E3E98;
    flags = state->flags;

    if ((flags & 0x40) != 0) {
        if ((flags & 8) != 0) {
            fx.effectId = 0xc0e;
            fx.mode = 1;
        } else if ((flags & 0x10) != 0) {
            fx.effectId = 0xc7e;
            fx.mode = 2;
        } else {
            fx.effectId = 0xc13;
            fx.mode = 0;
        }
    } else if ((flags & 8) != 0) {
        if (vec3f_distanceSquared(&((GameObject *)param_1)->anim.worldPosX, (f32 *)(player + 0x18)) < lbl_803E3EA0) {
            if (((state->flags & 0xa0) != 0) && (state->countdownActive == 0)) {
                objfx_spawnArcedBurst(param_1, 1, lbl_803E3EA4, 2, 7, 100,
                                       lbl_803E3EA8, lbl_803E3EA8, lbl_803E3EAC, &fx, 0);
            } else {
                objfx_spawnArcedBurst(param_1, 1, lbl_803E3EB0, 1, 6, 100,
                                       lbl_803E3EA8, lbl_803E3EA8, lbl_803E3EAC, &fx, 0);
            }
        }
        fx.effectId = 0xc0e;
        fx.mode = 1;
    } else if ((flags & 0x10) != 0) {
        if (vec3f_distanceSquared(&((GameObject *)param_1)->anim.worldPosX, (f32 *)(player + 0x18)) < lbl_803E3EA0) {
            if (((state->flags & 0xa0) != 0) && (state->countdownActive == 0)) {
                objfx_spawnArcedBurst(param_1, 1, lbl_803E3EA4, 2, 7, 100,
                                       lbl_803E3EA8, lbl_803E3EA8, lbl_803E3EAC, &fx, 0);
            } else {
                objfx_spawnArcedBurst(param_1, 1, lbl_803E3EB0, 5, 6, 100,
                                       lbl_803E3EA8, lbl_803E3EA8, lbl_803E3EAC, &fx, 0);
            }
        }
        fx.effectId = 0xc7e;
        fx.mode = 2;
    } else {
        if (vec3f_distanceSquared(&((GameObject *)param_1)->anim.worldPosX, (f32 *)(player + 0x18)) < lbl_803E3EA0) {
            if (((state->flags & 0xa0) != 0) && (state->countdownActive == 0)) {
                objfx_spawnArcedBurst(param_1, 1, lbl_803E3EA4, 2, 7, 100,
                                       lbl_803E3EA8, lbl_803E3EA8, lbl_803E3EAC, &fx, 0);
            } else {
                objfx_spawnArcedBurst(param_1, 1, lbl_803E3EB0, 3, 6, 100,
                                       lbl_803E3EA8, lbl_803E3EA8, lbl_803E3EAC, &fx, 0);
            }
        }
        fx.effectId = 0xc13;
        fx.mode = 0;
    }

    if ((state->flags & 4) != 0) {
        if (state->pulseTimer < lbl_803E3EB4) {
            if ((f32)(s32)randomGetRange(0, 0x1e0) < state->pulseTimer * lbl_803E3EB0) {
                (*gPartfxInterface)->spawnObject((void *)param_1, 0x7ca, &fx, 2, -1, NULL);
            }
        } else if (state->pulseTimer < lbl_803E3EB8) {
            if ((f32)(s32)randomGetRange(0, 0x1e0) < state->pulseTimer / lbl_803E3EBC) {
                (*gPartfxInterface)->spawnObject((void *)param_1, 0x7ca, &fx, 2, -1, NULL);
            }
            fx.count = 0x28;
            fx.unk0 = 0;
            fx.scale = lbl_803E3EC0 * ((state->pulseTimer - lbl_803E3EB4) / lbl_803E3EC4);
            (*gPartfxInterface)->spawnObject((void *)param_1, 0x7d2, &fx, 2, -1, NULL);
            state->flags = state->flags | 2;
        } else if (state->pulseTimer < lbl_803E3EC8) {
            if ((f32)(s32)randomGetRange(0, 0x1e0) < state->pulseTimer * lbl_803E3EB0) {
                (*gPartfxInterface)->spawnObject((void *)param_1, 0x7ca, &fx, 2, -1, NULL);
            }
            if ((state->flags & 2) != 0) {
                state->flags = state->flags & ~2;
                fx.count = 0x46;
                fx.scale = lbl_803E3ECC;
                for (i = 0xf; i != 0; i--) {
                    (*gPartfxInterface)->spawnObject((void *)param_1, 0x7d2, &fx, 2, -1, NULL);
                }
            }
        } else if (state->pulseTimer >= lbl_803E3ED0) {
            state->pulseTimer = lbl_803E3E98;
            state->flags = state->flags & ~4;
        }
        state->pulseTimer = state->pulseTimer + timeDelta;
    }
}

/* Drift-recovery: add new fns with v1.0 names. */
extern u8 lbl_803AC7B0[];
extern void mm_free(void* p);



typedef struct CFEmitterFxArgs {
    u32 unk0;
    u32 unk4;
    f32 scale;
    f32 pos[3];
} CFEmitterFxArgs;

#define CF_EMITTER_RANDOMIZE_OFFSET(state, pos)               \
    do {                                                      \
        u16 range;                                            \
        range = (state)->extentX;                      \
        (pos)[0] = (f32)(s32)randomGetRange(-range, range);   \
        range = (state)->extentY;                      \
        (pos)[1] = (f32)(s32)randomGetRange(-range, range);   \
        range = (state)->extentZ;                      \
        (pos)[2] = (f32)(s32)randomGetRange(-range, range);   \
    } while (0)

#define CF_EMITTER_SPAWN_PARTFX(obj, effectId, args, flags, modelId, arg6) \
    (*gPartfxInterface)->spawnObject((void *)(obj), (effectId), (args), (flags), (modelId), \
        (void *)(arg6))

#define CF_EMITTER_ROTATE_FROM_LOCAL(obj, state, args)            \
    do {                                                          \
        s16 rot[3];                                               \
        rot[0] = (state)->emitAngles[0];                         \
        rot[1] = (state)->emitAngles[1];                         \
        rot[2] = (state)->emitAngles[2];                         \
        if ((obj)->objAnim.parent != NULL) {                      \
            rot[2] += ((ObjAnimComponent *)(obj)->objAnim.parent)->rotZ; \
        }                                                         \
        vecRotateZXY(rot, (args)->pos);                        \
    } while (0)

#define CF_EMITTER_ADD_OBJECT_POSITION(obj, args)                 \
    do {                                                          \
        (args)->pos[0] += (obj)->objAnim.localPosX;               \
        (args)->pos[1] += (obj)->objAnim.localPosY;               \
        (args)->pos[2] += (obj)->objAnim.localPosZ;               \
    } while (0)

void areafxemit_emitEffect(AreaFxEmitObject *obj)
{
    AreaFxEmitState *state;
    int count;
    s16 i;
    u8 type;
    void* resource;
    CFEmitterFxArgs args;

    state = obj->state;
    args.scale = lbl_803E3E68;
    type = state->emitType;
    count = state->emitCount;

    if (type == 0) {
        if (count > 0) {
            for (i = 0; i < count; i++) {
                CF_EMITTER_RANDOMIZE_OFFSET(state, args.pos);
                CF_EMITTER_ROTATE_FROM_LOCAL(obj, state, &args);
                CF_EMITTER_ADD_OBJECT_POSITION(obj, &args);
                CF_EMITTER_SPAWN_PARTFX(obj, state->effectId, &args, 0x200001, -1, 0);
            }
        } else {
            CF_EMITTER_RANDOMIZE_OFFSET(state, args.pos);
            CF_EMITTER_ROTATE_FROM_LOCAL(obj, state, &args);
            CF_EMITTER_ADD_OBJECT_POSITION(obj, &args);
            CF_EMITTER_SPAWN_PARTFX(obj, state->effectId, &args, 0x200001, -1, 0);
        }
    } else if (type == 1) {
        resource = Resource_Acquire((u16)(state->effectId + 0x58), 1);
        if (count > 0) {
            for (i = 0; i < count; i++) {
                (*(void (**)(int, int, int, int, int, int))(*(int*)resource + 4))((int)obj, 0, 0, 1, -1, 0);
            }
        } else {
            (*(void (**)(int, int, int, int, int, int))(*(int*)resource + 4))((int)obj, 0, 0, 1, -1, 0);
        }
        Resource_Release(resource);
    } else if (type == 2) {
        resource = Resource_Acquire((u16)(state->effectId + 0xab), 1);
        if (count > 0) {
            for (i = 0; i < count; i++) {
                (*(void (**)(int, int, int, int, int, int, int))(*(int*)resource + 4))(
                    (int)obj, 0, 0, 1, -1, state->effectId & 0xff, 0);
            }
        } else {
            (*(void (**)(int, int, int, int, int, int, int))(*(int*)resource + 4))(
                (int)obj, 0, 0, 1, -1, state->effectId & 0xff, 0);
        }
        Resource_Release(resource);
    } else if (type == 3) {
        if (count > 0) {
            for (i = 0; i < count; i++) {
                CF_EMITTER_RANDOMIZE_OFFSET(state, args.pos);
                CF_EMITTER_ROTATE_FROM_LOCAL(obj, state, &args);
                CF_EMITTER_SPAWN_PARTFX(obj, state->effectId, &args, 2, -1, 0);
            }
        } else {
            CF_EMITTER_RANDOMIZE_OFFSET(state, args.pos);
            CF_EMITTER_ROTATE_FROM_LOCAL(obj, state, &args);
            CF_EMITTER_SPAWN_PARTFX(obj, state->effectId, &args, 2, -1, 0);
        }
    } else if (type > 5) {
        if (count > 0) {
            for (i = 0; i < count; i++) {
                CF_EMITTER_RANDOMIZE_OFFSET(state, args.pos);
                vecRotateZXY(state->emitAngles, args.pos);
                if (state->emitType == 6) {
                    CF_EMITTER_ADD_OBJECT_POSITION(obj, &args);
                    CF_EMITTER_SPAWN_PARTFX(obj, state->effectId, &args, 0x200001, -1, 0);
                } else {
                    CF_EMITTER_SPAWN_PARTFX(obj, state->effectId, &args, 2, -1, 0);
                }
            }
        } else {
            CF_EMITTER_RANDOMIZE_OFFSET(state, args.pos);
            vecRotateZXY(state->emitAngles, args.pos);
            if (state->emitType == 6) {
                CF_EMITTER_ADD_OBJECT_POSITION(obj, &args);
                CF_EMITTER_SPAWN_PARTFX(obj, state->effectId, &args, 0x200001, -1, 0);
            } else {
                CF_EMITTER_SPAWN_PARTFX(obj, state->effectId, &args, 2, -1, 0);
            }
        }
    }
}

int areafxemit_SeqFn(AreaFxEmitObject *obj, int unused, ObjAnimUpdateState *animUpdate)
{
    u8 i;
    for (i = 0; i < animUpdate->eventCount; i++) {
        switch ((s32)animUpdate->eventIds[i]) {
        case 1:
            areafxemit_emitEffect(obj);
            break;
        }
    }
    return 0;
}

void areafxemit_update(AreaFxEmitObject *obj)
{
    AreaFxEmitState *state;
    ObjAnimComponent *player;
    s16 period;
    f32 xDelta;
    f32 yDelta;
    f32 zDelta;
    f32 distance;
    f32 radius;

    state = obj->state;
    player = (ObjAnimComponent *)Obj_GetPlayerObject();
    if ((player != NULL) &&
        (((state->enableBit == -1) || (GameBit_Get(state->enableBit) != 0)) &&
         (state->suppressed == 0))) {
        if (GameBit_Get(state->stopBit) != 0) {
            state->suppressed = 1;
        }
        period = state->emitCount;
        if ((-1 < period) || ((-1 >= period && (obj->emitCooldown < 1)))) {
            xDelta = obj->objAnim.worldPosX - player->worldPosX;
            yDelta = obj->objAnim.worldPosY - player->worldPosY;
            zDelta = obj->objAnim.worldPosZ - player->worldPosZ;
            if (period == 0) {
                state->suppressed = 1;
            }
            distance = sqrtf(zDelta * zDelta + xDelta * xDelta + yDelta * yDelta);
            radius = state->triggerRadius;
            if (distance <= radius || radius == lbl_803E3E6C) {
                if ((3 < state->emitType) &&
                    ((state->lastDistance > radius && (radius != lbl_803E3E6C)))) {
                    areafxemit_emitBurst(obj, AREAFXEMIT_APPROACH_BURST_COUNT);
                }
                areafxemit_emitEffect(obj);
            }
            obj->emitCooldown = -period;
            state->lastDistance = distance;
        } else if ((period < 0) && (0 < obj->emitCooldown)) {
            obj->emitCooldown = obj->emitCooldown - (u32)framesThisStep;
        }
    }
}

void areafxemit_init(AreaFxEmitObject *obj, AreaFxEmitPlacement *setup)
{
    AreaFxEmitState *state;
    s16 period;
    s16 angle;

    obj->seqCallback = areafxemit_SeqFn;
    state = obj->state;

    state->triggerRadius = (f32)((s32)setup->triggerRadius << 2);
    state->emitType = setup->emitType;
    state->effectId = setup->effectId;
    period = setup->emitCount;
    state->emitCount = period;
    state->enableBit = setup->enableBit;
    state->stopBit = setup->stopBit;
    state->suppressed = 0;
    state->extentX = (u16)(setup->extentX << 2);
    state->extentZ = (u16)(setup->extentZ << 2);
    state->extentY = (u16)(setup->extentY << 2);

    angle = (s16)(setup->initialRoll << 8);
    state->emitAngles[2] = angle;
    obj->objAnim.rotZ = angle;
    angle = (s16)(setup->initialPitch << 8);
    state->emitAngles[1] = angle;
    obj->objAnim.rotY = angle;
    angle = (s16)(setup->initialYaw << 8);
    state->emitAngles[0] = angle;
    obj->objAnim.rotX = angle;
    obj->objAnim.rootMotionScale = lbl_803E3E70;

    if (period < 1) {
        obj->emitCooldown = period;
    } else {
        obj->emitCooldown = 0;
    }

    if (state->stopBit != -1 && GameBit_Get(state->stopBit) != 0) {
        state->suppressed = 1;
    }
}

void lfxemitter_init(LfxEmitterObject *obj, LfxEmitterPlacement *setup)
{
    LfxEmitterState *state;
    int curveFlags;

    state = obj->state;
    curveFlags = 0x21;
    obj->objAnim.rootMotionScale = lbl_803E3E80 * obj->objAnim.modelInstance->rootMotionScaleBase;

    state->configIndex = setup->configIndex;
    state->lifeTimer = setup->lifeTimer;
    state->unk114 = -2;
    state->enableBit = setup->enableBit;
    state->spinRoll = setup->spinRoll;
    state->spinPitch = setup->spinPitch;
    state->spinYaw = setup->spinYaw;
    obj->objAnim.localPosX = setup->initialX;
    obj->objAnim.localPosY = setup->initialY;
    obj->objAnim.localPosZ = setup->initialZ;

    if (state->lifeTimer != 0) {
        state->hasLifeTimer = 1;
    } else {
        state->hasLifeTimer = 0;
    }

    if (setup->followCurve != 0) {
        state->flags = state->flags | LFXEMITTER_FLAG_FOLLOW_CURVE;
        state->curveSpeed = (f32)setup->curveSpeed / lbl_803E3E84;
        (*gRomCurveInterface)->initCurve(state, obj, lbl_803E3E88, &curveFlags, -1);
    }
    ObjGroup_AddObject((int)obj, LFXEMITTER_OBJ_GROUP);
}

int lfxemitter_setScale(void) { return -1; }

void areafxemit_render(int p1, int p2, int p3, int p4, int p5, s8 visible) { if (visible == 0) return; }

void lfxemitter_initialise(void)
{
    *(s16*)(lbl_803AC7B0 + 14) = 10000;
}

int lfxemitter_func0B(LfxEmitterObject *obj)
{
    LfxEmitterState* state = obj->state;
    int v = (int)state->config;
    return (u32)(-v | v) >> 31;
}

void fn_8018FF48(undefined2* src, undefined2* dst)
{
    *dst = *src;
    dst[1] = src[1];
    ((s16 *)dst)[2] = ((s16 *)src)[2];
    ((s16 *)dst)[3] = ((s16 *)src)[3];
    ((s16 *)dst)[4] = ((s16 *)src)[4];
    ((s16 *)dst)[5] = ((s16 *)src)[5];
    ((s16 *)dst)[6] = ((s16 *)src)[6];
    dst[7] = src[7];
    *(undefined*)(dst + 9) = *(undefined*)(src + 9);
    *(undefined*)((int)dst + 0x13) = *(undefined*)((int)src + 0x13);
    *(undefined*)((int)dst + 0x1b) = *(undefined*)((int)src + 0x1b);
    *(undefined*)(dst + 0xe) = *(undefined*)(src + 0xe);
    *(undefined*)((int)dst + 0x1d) = *(undefined*)((int)src + 0x1d);
    *(undefined*)(dst + 0xf) = *(undefined*)(src + 0xf);
    *(undefined*)((int)dst + 0x1f) = *(undefined*)((int)src + 0x1f);
    *(undefined*)(dst + 0x10) = *(undefined*)(src + 0x10);
    *(undefined*)((int)dst + 0x21) = *(undefined*)((int)src + 0x21);
    *(undefined*)(dst + 0x11) = *(undefined*)(src + 0x11);
    *(undefined*)((int)dst + 0x15) = *(undefined*)((int)src + 0x15);
    *(undefined*)((int)dst + 0x23) = *(undefined*)((int)src + 0x23);
    *(undefined*)(dst + 0xb) = *(undefined*)(src + 0xb);
    *(undefined*)(dst + 0x12) = *(undefined*)(src + 0x12);
    *(undefined*)((int)dst + 0x17) = *(undefined*)((int)src + 0x17);
    *(undefined*)((int)dst + 0x25) = *(undefined*)((int)src + 0x25);
    *(undefined*)(dst + 0xc) = *(undefined*)(src + 0xc);
    *(undefined*)(dst + 0x13) = *(undefined*)(src + 0x13);
    *(undefined*)((int)dst + 0x19) = *(undefined*)((int)src + 0x19);
    *(undefined*)((int)dst + 0x27) = *(undefined*)((int)src + 0x27);
    *(undefined*)(dst + 0xd) = *(undefined*)(src + 0xd);
    *(undefined*)(dst + 0x14) = *(undefined*)(src + 0x14);
}

void lfxemitter_update(LfxEmitterObject *obj)
{
    LfxEmitterState *state;
    ObjAnimComponent *player;
    void* config;

    state = obj->state;
    player = (ObjAnimComponent *)Obj_GetPlayerObject();

    obj->objAnim.rotX = obj->objAnim.rotX + state->spinYaw;
    obj->objAnim.rotZ = obj->objAnim.rotZ + state->spinRoll;
    obj->objAnim.rotY = obj->objAnim.rotY + state->spinPitch;

    if ((state->flags & LFXEMITTER_FLAG_FOLLOW_CURVE) != 0) {
        if ((Curve_AdvanceAlongPath((int)state, state->curveSpeed) != 0) ||
            (state->curveIdx != 0)) {
            (*gRomCurveInterface)->goNextPoint(state);
        }
        obj->objAnim.localPosX = state->curveSample[0];
        obj->objAnim.localPosY = state->curveSample[1];
        obj->objAnim.localPosZ = state->curveSample[2];
    } else {
        obj->objAnim.localPosX = obj->objAnim.velocityX * timeDelta + obj->objAnim.localPosX;
        obj->objAnim.localPosY = obj->objAnim.velocityY * timeDelta + obj->objAnim.localPosY;
        obj->objAnim.localPosZ = obj->objAnim.velocityZ * timeDelta + obj->objAnim.localPosZ;
        if (((state->flags & LFXEMITTER_FLAG_DAMP_Y_VELOCITY) != 0) && (obj->objAnim.velocityY > lbl_803E3E78)) {
            obj->objAnim.velocityY = lbl_803E3E7C * timeDelta + obj->objAnim.velocityY;
        }
    }

    if ((player != NULL) &&
        ((state->enableBit == -1) || (GameBit_Get(state->enableBit) != 0))) {
        if (state->hasLifeTimer != 0) {
            state->lifeTimer = state->lifeTimer - framesThisStep;
            if (state->lifeTimer <= 0) {
                Obj_FreeObject((int)obj);
            }
        }
        if (state->configLoaded == 0) {
            if (((int)state != 0) && (state->configIndex == (*(u16*)(lbl_803AC7B0 + 0xe) - 1))) {
                config = mmAlloc(LFXEMITTER_CONFIG_BYTES, 0x12, 0);
                state->config = config;
                if (config != NULL) {
                    fn_8018FF48((undefined2*)lbl_803AC7B0, (undefined2*)config);
                }
            } else {
                config = mmAlloc(LFXEMITTER_CONFIG_BYTES, 0x12, 0);
                state->config = config;
                getTabEntry(config, 0xc, state->configIndex * LFXEMITTER_CONFIG_BYTES, LFXEMITTER_CONFIG_BYTES);
                config = state->config;
                if (config != NULL) {
                    fn_8018FF48((undefined2*)config, (undefined2*)lbl_803AC7B0);
                }
            }
            state->configLoaded = 1;
        }
    }
}

void warpPadPlayerStandingOn(int obj)
{
    int def;
    WarpPadState *state;
    int player;
    s16 gameBit;

    def = *(int *)&((GameObject *)obj)->anim.placementData;
    state = ((GameObject *)obj)->extra;
    gameBit = *(s16*)(def + 0x20);
    if (gameBit != -1) {
        if (GameBit_Get(gameBit) != 0) {
            state->flags = state->flags & 0x7f;
        } else {
            state->flags = state->flags | 0x80;
        }
    }

    if ((*(u8 *)&((GameObject *)obj)->anim.resetHitboxMode & 4) != 0) {
        setAButtonIcon(0x1b);
        if (GameBit_Get(0x912) == 0) {
            (*gObjectTriggerInterface)->runSequence(2, (void *)obj, -1);
            GameBit_Set(0x912, 1);
            return;
        }
    }

    player = Obj_GetPlayerObject();
    if (player == 0) {
        return;
    }

    if ((state->triggerMode == 0) && (state->countdownActive == 0) &&
        ((((GameObject *)obj)->objectFlags & 0x1000) == 0)) {
        if (lbl_803DCEB8 > -1) {
            player = Obj_GetPlayerObject();
            if (Vec_xzDistance((f32*)(obj + 0x18), (f32*)(player + 0x18)) < lbl_803E3EE0) {
                (*gObjectTriggerInterface)->runSequence(1, (void *)obj, -1);
                ((GameObject *)obj)->countF4 = state->activateDelay;
                state->triggerMode = 0;
                state->countdownActive = 1;
                lbl_803DCDE0 = 2;
                goto updateTimer;
            }
        }
        gameBit = ((WarpPadPlayerStandingOnPlacement *)def)->unk20;
        if (((gameBit == -1) ||
             ((GameBit_Get(gameBit) != 0) && ((*(u8 *)&((GameObject *)obj)->anim.resetHitboxMode & 4) != 0))) &&
            (ObjTrigger_IsSet(obj) != 0)) {
            (*gObjectTriggerInterface)->runSequence(0, (void *)obj, -1);
            ((GameObject *)obj)->countF4 = state->activateDelay;
            state->triggerMode = 1;
            state->countdownActive = 1;
        }
    }

updateTimer:
    if (state->countdownActive != 0) {
        if (((GameObject *)obj)->countF4 > 0) {
            ((GameObject *)obj)->countF4 = ((GameObject *)obj)->countF4 - framesThisStep;
        } else {
            ((GameObject *)obj)->countF4 = 0;
            state->countdownActive = 0;
        }
    }
    state->cooldownTimer = state->cooldownTimer - timeDelta;
    if (state->cooldownTimer <= *(f32 *)&lbl_803E3E98) {
        state->cooldownTimer = lbl_803E3E98;
        state->unk0A = -1;
    }
}

void areafxemit_free(AreaFxEmitObject *obj)
{
    (*gExpgfxInterface)->freeSource2((u32)obj);
}

void lfxemitter_free(LfxEmitterObject *obj)
{
    LfxEmitterState* state = obj->state;
    int* ptr = (int*)state->config;
    if (ptr != NULL) {
        mm_free(ptr);
    }
    ObjGroup_RemoveObject((int)obj, LFXEMITTER_OBJ_GROUP);
}


/* Trivial 4b 0-arg blr leaves. */
void fxemit_release(void) {}
void fxemit_initialise(void) {}
void areafxemit_hitDetect(void) {}
void areafxemit_release(void) {}
void areafxemit_initialise(void) {}
void lfxemitter_render(void) {}
void lfxemitter_hitDetect(void) {}
void lfxemitter_release(void) {}

/* 8b "li r3, N; blr" returners. */
int areafxemit_getExtraSize(void) { return 0x20; }
int areafxemit_getObjectTypeId(void) { return 0x0; }
int lfxemitter_getExtraSize(void) { return 0x124; }
int lfxemitter_getObjectTypeId(void) { return 0x0; }
