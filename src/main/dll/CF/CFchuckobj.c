#include "main/dll/CF/CFchuckobj.h"
#include "main/dll/CF/CFTreasSharpy.h"

/*
 * Per-object extra state for the areafxemit volume particle emitter
 * (areafxemit_getExtraSize == 0x20).
 */
typedef struct AreaFxEmitState {
    f32 triggerRadius; /* (s8)setup[0x18] << 2; sentinel value = always emit */
    f32 lastDistance; /* player distance at the last emit check */
    u8 emitType; /* setup[0x1f]; 4/6 = world-positioned spawn (flag 0x200001), >3 bursts on approach */
    u8 pad09;
    u16 effectId;
    s16 emitCount; /* setup+0x22; >0: spawns per emit; <=0: negated re-emit cooldown; 0 also suppresses */
    s16 enableBit; /* gamebit gate, -1 = always on */
    s16 stopBit; /* gamebit; once set the emitter suppresses */
    s16 suppressed;
    u16 extentX; /* setup[0x1c] << 2 -- random offset half-extents */
    u16 extentZ; /* setup[0x1d] << 2 */
    u16 extentY; /* setup[0x1e] << 2 */
    s16 emitAngles[3]; /* yaw/pitch/roll, mirrored to obj+0/2/4 */
} AreaFxEmitState;

STATIC_ASSERT(sizeof(AreaFxEmitState) == 0x20);

/*
 * Per-object extra state for the lfxemitter curve-following emitter
 * (lfxemitter_getExtraSize == 0x124). The leading 0x108 bytes are the
 * rom-curve walker record (the state pointer itself is handed to
 * Curve_AdvanceAlongPath / gRomCurveInterface).
 */
typedef struct LfxEmitterState {
    u8 curve00[0x10];
    int curveIdx; /* Curve.idx */
    u8 curve14[0x68 - 0x14];
    f32 curveSample[3]; /* Curve.sample -- walked world position */
    u8 curve74[0x108 - 0x74];
    void *config; /* mmAlloc(0x28) copy of the lbl_803AC7B0-format record */
    f32 curveSpeed; /* (s8)setup[0x25] / lbl_803E3E84 */
    s16 lifeTimer; /* setup+0x20; frames until Obj_FreeObject when armed */
    s16 configIndex; /* setup+0x1e; tab entry index */
    s16 unk114; /* -2 at init */
    s16 enableBit; /* setup+0x22; gamebit gate, -1 = always on */
    s16 spinRoll; /* setup+0x18 -> obj+4 */
    s16 spinPitch; /* setup+0x1a -> obj+2 */
    s16 spinYaw; /* setup+0x1c -> obj+0 */
    u8 hasLifeTimer;
    u8 configLoaded;
    u8 flags; /* 1 = follow curve, 2 = damp upward Y velocity */
    u8 pad121[3];
} LfxEmitterState;

STATIC_ASSERT(sizeof(LfxEmitterState) == 0x124);
STATIC_ASSERT(offsetof(LfxEmitterState, config) == 0x108);


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
extern void* Resource_Acquire(int id, int flags);
extern void Resource_Release(void* handle);
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
extern void getTabEntry(void* dst, int fileId, int offset, int size);
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
extern undefined4* DAT_803dd6d4;
extern undefined4* DAT_803dd6f8;
extern undefined4* DAT_803dd6fc;
extern undefined4* DAT_803dd708;
extern undefined4* DAT_803dd71c;
extern int* gPartfxInterface;
extern int* gObjectTriggerInterface;
extern int* gRomCurveInterface;
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

#pragma scheduling off
#pragma peephole off
#pragma dont_inline on
void areafxemit_emitBurst(int obj, int count)
{
  AreaFxEmitState *sub;
  s16 i;
  struct {
    s16 hw[6];
    f32 vec[3];
  } args;

  sub = *(AreaFxEmitState **)(obj + 0xb8);
  if (count > 0) {
    for (i = 0; i < count; i++) {
      {
        u16 sx = sub->extentX;
        args.vec[0] = (f32)(s32)randomGetRange(-sx, sx);
      }
      {
        u16 sy = sub->extentY;
        args.vec[1] = (f32)(s32)randomGetRange(-sy, sy);
      }
      {
        u16 sz = sub->extentZ;
        args.vec[2] = (f32)(s32)randomGetRange(-sz, sz);
      }
      vecRotateZXY(sub->emitAngles, args.vec);
      {
        u8 type = sub->emitType;
        if (type == 4 || type == 6) {
          args.vec[0] += *(f32 *)(obj + 0xc);
          args.vec[1] += *(f32 *)(obj + 0x10);
          args.vec[2] += *(f32 *)(obj + 0x14);
          (*(void (**)(int, int, void *, int, int, int))(*gPartfxInterface + 8))(
              obj, sub->effectId, &args, 0x200001, -1, 0);
        } else {
          (*(void (**)(int, int, void *, int, int, int))(*gPartfxInterface + 8))(
              obj, sub->effectId, &args, 2, -1, 0);
        }
      }
    }
  }
}
#pragma dont_inline reset
#pragma peephole reset
#pragma scheduling reset

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
void FUN_8018f158(undefined4 param_1)
{
  (**(code **)(*DAT_803dd6f8 + 0x18))();
  (**(code **)(*DAT_803dd6fc + 0x14))(param_1);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8018f1b4
 * EN v1.0 Address: 0x8018F1B4
 * EN v1.0 Size: 840b
 * EN v1.1 Address: 0x8018F214
 * EN v1.1 Size: 840b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8018f1b4(short *param_1)
{
  short sVar1;
  float fVar2;
  float fVar3;
  float fVar4;
  int iVar5;
  uint uVar6;
  int iVar7;
  float *pfVar8;
  double dVar9;
  
  pfVar8 = *(float **)(param_1 + 0x5c);
  iVar7 = *(int *)(param_1 + 0x26);
  if (*(short *)((int)pfVar8 + 0x12) == 0) {
    *(float *)(param_1 + 6) = *(float *)(param_1 + 0x12) * FLOAT_803dc074 + *(float *)(param_1 + 6);
    *(float *)(param_1 + 8) = *(float *)(param_1 + 0x14) * FLOAT_803dc074 + *(float *)(param_1 + 8);
    *(float *)(param_1 + 10) =
         *(float *)(param_1 + 0x16) * FLOAT_803dc074 + *(float *)(param_1 + 10);
    *(undefined4 *)(param_1 + 0xc) = *(undefined4 *)(param_1 + 6);
    *(undefined4 *)(param_1 + 0xe) = *(undefined4 *)(param_1 + 8);
    *(undefined4 *)(param_1 + 0x10) = *(undefined4 *)(param_1 + 10);
    iVar5 = FUN_80017a98();
    if ((iVar5 != 0) && (iVar7 != 0)) {
      if ((*(char *)(iVar7 + 0x29) != '\0') && (*(char *)(iVar7 + 0x29) != -1)) {
        if (*(short *)((int)pfVar8 + 0x1a) < 1) {
          *(undefined2 *)(pfVar8 + 6) = 0;
          *(ushort *)((int)pfVar8 + 0x1a) = (ushort)*(byte *)(iVar7 + 0x29) * 100;
          if (*(ushort *)(iVar7 + 0x2a) != 0) {
            FUN_80006824((uint)param_1,*(ushort *)(iVar7 + 0x2a));
          }
        }
        else {
          *(undefined2 *)(pfVar8 + 6) = 1;
        }
        *(ushort *)((int)pfVar8 + 0x1a) = *(short *)((int)pfVar8 + 0x1a) - (ushort)DAT_803dc070;
      }
      if (*(char *)(iVar7 + 0x27) == '\x7f') {
        *param_1 = *param_1 + (ushort)DAT_803dc070 * 10;
      }
      else {
        *param_1 = *param_1 + (short)*(char *)(iVar7 + 0x27) * (ushort)DAT_803dc070 * 100;
      }
      if (*(char *)(iVar7 + 0x26) == '\x7f') {
        param_1[1] = param_1[1] + (ushort)DAT_803dc070 * 10;
      }
      else {
        param_1[1] = param_1[1] + (short)*(char *)(iVar7 + 0x26) * (ushort)DAT_803dc070 * 100;
      }
      if (*(char *)(iVar7 + 0x25) == '\x7f') {
        param_1[2] = param_1[2] + (ushort)DAT_803dc070 * 10;
      }
      else {
        param_1[2] = param_1[2] + (short)*(char *)(iVar7 + 0x25) * (ushort)DAT_803dc070 * 100;
      }
      if ((((int)*(short *)(pfVar8 + 5) == 0xffffffff) ||
          (uVar6 = GameBit_Get((int)*(short *)(pfVar8 + 5)), uVar6 != 0)) &&
         (*(short *)(pfVar8 + 6) == 0)) {
        if (((int)*(short *)((int)pfVar8 + 0x16) != 0xffffffff) &&
           (uVar6 = GameBit_Get((int)*(short *)((int)pfVar8 + 0x16)), uVar6 != 0)) {
          *(undefined2 *)(pfVar8 + 6) = 1;
        }
        if (*(char *)(iVar7 + 0x29) == -1) {
          *(undefined2 *)(pfVar8 + 6) = 1;
        }
        sVar1 = *(short *)((int)pfVar8 + 0xe);
        if ((-1 < sVar1) || ((-1 >= sVar1 && (*(int *)(param_1 + 0x7a) < 1)))) {
          fVar2 = *(float *)(param_1 + 0xc) - *(float *)(iVar5 + 0x18);
          fVar3 = *(float *)(param_1 + 0xe) - *(float *)(iVar5 + 0x1c);
          fVar4 = *(float *)(param_1 + 0x10) - *(float *)(iVar5 + 0x20);
          if (sVar1 == 0) {
            *(undefined2 *)(pfVar8 + 6) = 1;
          }
          dVar9 = FUN_80293900((double)(fVar4 * fVar4 + fVar2 * fVar2 + fVar3 * fVar3));
          if ((dVar9 <= (double)*pfVar8) || ((double)FLOAT_803e4ae4 == (double)*pfVar8)) {
            fxemit_emitEffect((FxEmitObject *)param_1);
          }
          *(int *)(param_1 + 0x7a) = -(int)*(short *)((int)pfVar8 + 0xe);
        }
        else if ((sVar1 < 0) && (0 < *(int *)(param_1 + 0x7a))) {
          *(uint *)(param_1 + 0x7a) = *(int *)(param_1 + 0x7a) - (uint)DAT_803dc070;
        }
      }
    }
  }
  else {
    *(short *)((int)pfVar8 + 0x12) = *(short *)((int)pfVar8 + 0x12) - (short)(int)FLOAT_803dc074;
    if (*(short *)((int)pfVar8 + 0x12) < 0) {
      *(undefined2 *)((int)pfVar8 + 0x12) = 0;
    }
  }
  return;
}

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
void FUN_8018f4fc(undefined2 *param_1,int param_2)
{
}

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
void FUN_8018f500(void)
{
  int iVar1;
  short sVar2;
  int iVar3;
  double in_f31;
  double dVar4;
  double in_ps31_1;
  undefined8 uVar5;
  undefined auStack_58 [12];
  float local_4c;
  float local_48;
  float local_44;
  undefined4 local_40;
  uint uStack_3c;
  undefined4 local_38;
  uint uStack_34;
  undefined4 local_30;
  uint uStack_2c;
  float local_8;
  float fStack_4;
  
  local_8 = (float)in_f31;
  fStack_4 = (float)in_ps31_1;
  uVar5 = FUN_8028683c();
  iVar1 = (int)((ulonglong)uVar5 >> 0x20);
  iVar3 = *(int *)(iVar1 + 0xb8);
  if (0 < (int)uVar5) {
    dVar4 = DOUBLE_803e4af8;
    for (sVar2 = 0; (int)sVar2 < (int)uVar5; sVar2 = sVar2 + 1) {
      uStack_3c = randomGetRange(-(uint)*(ushort *)(iVar3 + 0x14),(uint)*(ushort *)(iVar3 + 0x14));
      local_4c = (float)((double)CONCAT44(0x43300000,uStack_3c) - dVar4);
      uStack_34 = randomGetRange(-(uint)*(ushort *)(iVar3 + 0x18),(uint)*(ushort *)(iVar3 + 0x18));
      local_48 = (float)((double)CONCAT44(0x43300000,uStack_34) - dVar4);
      uStack_2c = randomGetRange(-(uint)*(ushort *)(iVar3 + 0x16),(uint)*(ushort *)(iVar3 + 0x16));
      local_44 = (float)((double)CONCAT44(0x43300000,uStack_2c) - dVar4);
      FUN_80017748((ushort *)(iVar3 + 0x1a),&local_4c);
      if ((*(char *)(iVar3 + 8) == '\x04') || (*(char *)(iVar3 + 8) == '\x06')) {
        local_4c = local_4c + *(float *)(iVar1 + 0xc);
        local_48 = local_48 + *(float *)(iVar1 + 0x10);
        local_44 = local_44 + *(float *)(iVar1 + 0x14);
        (**(code **)(*DAT_803dd708 + 8))
                  (iVar1,*(undefined2 *)(iVar3 + 10),auStack_58,0x200001,0xffffffff,0);
      }
      else {
        (**(code **)(*DAT_803dd708 + 8))
                  (iVar1,*(undefined2 *)(iVar3 + 10),auStack_58,2,0xffffffff,0);
      }
    }
  }
  FUN_80286888();
  return;
}

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
      (**(code **)(*DAT_803dd708 + 8))
                (iVar2,*(undefined2 *)(iVar5 + 10),auStack_60,0x200001,0xffffffff,0);
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
        (**(code **)(*DAT_803dd708 + 8))
                  (iVar2,*(undefined2 *)(iVar5 + 10),auStack_60,0x200001,0xffffffff,0);
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
      (**(code **)(*DAT_803dd708 + 8))(iVar2,*(undefined2 *)(iVar5 + 10),auStack_60,2,0xffffffff,0);
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
        (**(code **)(*DAT_803dd708 + 8))
                  (iVar2,*(undefined2 *)(iVar5 + 10),auStack_60,2,0xffffffff,0);
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
        (**(code **)(*DAT_803dd708 + 8))
                  (iVar2,*(undefined2 *)(iVar5 + 10),auStack_60,0x200001,0xffffffff,0);
      }
      else {
        (**(code **)(*DAT_803dd708 + 8))
                  (iVar2,*(undefined2 *)(iVar5 + 10),auStack_60,2,0xffffffff,0);
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
          (**(code **)(*DAT_803dd708 + 8))
                    (iVar2,*(undefined2 *)(iVar5 + 10),auStack_60,0x200001,0xffffffff,0);
        }
        else {
          (**(code **)(*DAT_803dd708 + 8))
                    (iVar2,*(undefined2 *)(iVar5 + 10),auStack_60,2,0xffffffff,0);
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
 * Function: FUN_8018fca4
 * EN v1.0 Address: 0x8018FCA4
 * EN v1.0 Size: 112b
 * EN v1.1 Address: 0x80190100
 * EN v1.1 Size: 140b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_8018fca4(undefined4 param_1,undefined4 param_2,int param_3)
{
  byte bVar1;
  
  for (bVar1 = 0; bVar1 < *(byte *)(param_3 + 0x8b); bVar1 = bVar1 + 1) {
    if (*(char *)(param_3 + bVar1 + 0x81) == '\x01') {
      FUN_8018f650();
    }
  }
  return 0;
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
void FUN_8018fd14(void)
{
  (**(code **)(*DAT_803dd6f8 + 0x18))();
  return;
}

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
void FUN_8018fd48(int param_1)
{
  short sVar1;
  float fVar2;
  float fVar3;
  float fVar4;
  int iVar5;
  uint uVar6;
  float *pfVar7;
  double dVar8;
  double dVar9;
  
  pfVar7 = *(float **)(param_1 + 0xb8);
  iVar5 = FUN_80017a98();
  if ((iVar5 != 0) &&
     ((((int)*(short *)((int)pfVar7 + 0xe) == 0xffffffff ||
       (uVar6 = GameBit_Get((int)*(short *)((int)pfVar7 + 0xe)), uVar6 != 0)) &&
      (*(short *)((int)pfVar7 + 0x12) == 0)))) {
    uVar6 = GameBit_Get((int)*(short *)(pfVar7 + 4));
    if (uVar6 != 0) {
      *(undefined2 *)((int)pfVar7 + 0x12) = 1;
    }
    sVar1 = *(short *)(pfVar7 + 3);
    if ((-1 < sVar1) || ((-1 >= sVar1 && (*(int *)(param_1 + 0xf4) < 1)))) {
      fVar2 = *(float *)(param_1 + 0x18) - *(float *)(iVar5 + 0x18);
      fVar3 = *(float *)(param_1 + 0x1c) - *(float *)(iVar5 + 0x1c);
      fVar4 = *(float *)(param_1 + 0x20) - *(float *)(iVar5 + 0x20);
      if (sVar1 == 0) {
        *(undefined2 *)((int)pfVar7 + 0x12) = 1;
      }
      dVar8 = FUN_80293900((double)(fVar4 * fVar4 + fVar2 * fVar2 + fVar3 * fVar3));
      dVar9 = (double)*pfVar7;
      if ((dVar8 <= dVar9) || ((double)FLOAT_803e4b04 == dVar9)) {
        if ((3 < *(byte *)(pfVar7 + 2)) &&
           ((dVar9 < (double)pfVar7[1] && ((double)FLOAT_803e4b04 != dVar9)))) {
          FUN_8018f500();
        }
        FUN_8018f650();
      }
      *(int *)(param_1 + 0xf4) = -(int)*(short *)(pfVar7 + 3);
      pfVar7[1] = (float)dVar8;
    }
    else if ((sVar1 < 0) && (0 < *(int *)(param_1 + 0xf4))) {
      *(uint *)(param_1 + 0xf4) = *(int *)(param_1 + 0xf4) - (uint)DAT_803dc070;
    }
  }
  return;
}

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
void FUN_8018fec4(undefined2 *param_1,int param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8018fec8
 * EN v1.0 Address: 0x8018FEC8
 * EN v1.0 Size: 244b
 * EN v1.1 Address: 0x801904C4
 * EN v1.1 Size: 260b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8018fec8(undefined2 *param_1,undefined2 *param_2)
{
  *param_2 = *param_1;
  param_2[1] = param_1[1];
  param_2[2] = param_1[2];
  param_2[3] = param_1[3];
  param_2[4] = param_1[4];
  param_2[5] = param_1[5];
  param_2[6] = param_1[6];
  param_2[7] = param_1[7];
  *(undefined *)(param_2 + 9) = *(undefined *)(param_1 + 9);
  *(undefined *)((int)param_2 + 0x13) = *(undefined *)((int)param_1 + 0x13);
  *(undefined *)((int)param_2 + 0x1b) = *(undefined *)((int)param_1 + 0x1b);
  *(undefined *)(param_2 + 0xe) = *(undefined *)(param_1 + 0xe);
  *(undefined *)((int)param_2 + 0x1d) = *(undefined *)((int)param_1 + 0x1d);
  *(undefined *)(param_2 + 0xf) = *(undefined *)(param_1 + 0xf);
  *(undefined *)((int)param_2 + 0x1f) = *(undefined *)((int)param_1 + 0x1f);
  *(undefined *)(param_2 + 0x10) = *(undefined *)(param_1 + 0x10);
  *(undefined *)((int)param_2 + 0x21) = *(undefined *)((int)param_1 + 0x21);
  *(undefined *)(param_2 + 0x11) = *(undefined *)(param_1 + 0x11);
  *(undefined *)((int)param_2 + 0x15) = *(undefined *)((int)param_1 + 0x15);
  *(undefined *)((int)param_2 + 0x23) = *(undefined *)((int)param_1 + 0x23);
  *(undefined *)(param_2 + 0xb) = *(undefined *)(param_1 + 0xb);
  *(undefined *)(param_2 + 0x12) = *(undefined *)(param_1 + 0x12);
  *(undefined *)((int)param_2 + 0x17) = *(undefined *)((int)param_1 + 0x17);
  *(undefined *)((int)param_2 + 0x25) = *(undefined *)((int)param_1 + 0x25);
  *(undefined *)(param_2 + 0xc) = *(undefined *)(param_1 + 0xc);
  *(undefined *)(param_2 + 0x13) = *(undefined *)(param_1 + 0x13);
  *(undefined *)((int)param_2 + 0x19) = *(undefined *)((int)param_1 + 0x19);
  *(undefined *)((int)param_2 + 0x27) = *(undefined *)((int)param_1 + 0x27);
  *(undefined *)(param_2 + 0xd) = *(undefined *)(param_1 + 0xd);
  *(undefined *)(param_2 + 0x14) = *(undefined *)(param_1 + 0x14);
  return;
}

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
void FUN_8018ffbc(int param_1)
{
  uint uVar1;
  
  uVar1 = *(uint *)(*(int *)(param_1 + 0xb8) + 0x108);
  if (uVar1 != 0) {
    FUN_80017814(uVar1);
  }
  ObjGroup_RemoveObject(param_1,0x1c);
  return;
}

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
void FUN_80190004(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 short *param_9)
{
}

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
void FUN_80190008(int param_1,int param_2)
{
  int iVar1;
  undefined4 local_18 [2];
  undefined4 local_10;
  uint uStack_c;
  
  iVar1 = *(int *)(param_1 + 0xb8);
  local_18[0] = 0x21;
  *(float *)(param_1 + 8) = FLOAT_803e4b18 * *(float *)(*(int *)(param_1 + 0x50) + 4);
  *(undefined2 *)(iVar1 + 0x112) = *(undefined2 *)(param_2 + 0x1e);
  *(undefined2 *)(iVar1 + 0x110) = *(undefined2 *)(param_2 + 0x20);
  *(undefined2 *)(iVar1 + 0x114) = 0xfffe;
  *(undefined2 *)(iVar1 + 0x116) = *(undefined2 *)(param_2 + 0x22);
  *(undefined2 *)(iVar1 + 0x118) = *(undefined2 *)(param_2 + 0x18);
  *(undefined2 *)(iVar1 + 0x11a) = *(undefined2 *)(param_2 + 0x1a);
  *(undefined2 *)(iVar1 + 0x11c) = *(undefined2 *)(param_2 + 0x1c);
  *(undefined4 *)(param_1 + 0xc) = *(undefined4 *)(param_2 + 8);
  *(undefined4 *)(param_1 + 0x10) = *(undefined4 *)(param_2 + 0xc);
  *(undefined4 *)(param_1 + 0x14) = *(undefined4 *)(param_2 + 0x10);
  if (*(short *)(iVar1 + 0x110) == 0) {
    *(undefined *)(iVar1 + 0x11e) = 0;
  }
  else {
    *(undefined *)(iVar1 + 0x11e) = 1;
  }
  if (*(char *)(param_2 + 0x24) != '\0') {
    *(byte *)(iVar1 + 0x120) = *(byte *)(iVar1 + 0x120) | 1;
    uStack_c = (int)*(char *)(param_2 + 0x25) ^ 0x80000000;
    local_10 = 0x43300000;
    *(float *)(iVar1 + 0x10c) =
         (float)((double)CONCAT44(0x43300000,uStack_c) - DOUBLE_803e4b28) / FLOAT_803e4b1c;
    (**(code **)(*DAT_803dd71c + 0x8c))((double)FLOAT_803e4b20,iVar1,param_1,local_18,0xffffffff);
  }
  ObjGroup_AddObject(param_1,0x1c);
  return;
}

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
/*
 * Per-object extra state for the warp-pad transporter
 * (transporter_getExtraSize == 0x10; helpers shared by the
 * CFwalltorch/mmp_asteroid transporter updates).
 */
typedef struct WarpPadState {
    f32 pulseTimer; /* counts up while flag 4; periodic idle fx */
    f32 cooldownTimer; /* counts down; on expiry unk0A is reset to -1 */
    s16 activateDelay; /* frames loaded into obj+0xF4 when triggered */
    s16 unk0A;
    u8 countdownActive;
    u8 triggerMode; /* 0 = proximity warp, 1 = trigger/gamebit warp */
    u8 flags; /* 0x80 gamebit-disabled, 0x40/0x10/0x8 warp fx type, 4 pulse fx, 2 latch */
    u8 pad0F;
} WarpPadState;

STATIC_ASSERT(sizeof(WarpPadState) == 0x10);

void warpPadFn_8019042c(int param_1)
{
    WarpPadState *state;
    int player;
    u8 flags;
    u8 i;
    f32 timer;
    struct {
        s16 unk0;
        s16 mode;
        s16 effectId;
        s16 count;
        f32 scale;
        f32 pos[3];
    } fx;

    state = *(WarpPadState **)(param_1 + 0xb8);
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
        if (vec3f_distanceSquared((f32 *)(param_1 + 0x18), (f32 *)(player + 0x18)) < lbl_803E3EA0) {
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
        if (vec3f_distanceSquared((f32 *)(param_1 + 0x18), (f32 *)(player + 0x18)) < lbl_803E3EA0) {
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
        if (vec3f_distanceSquared((f32 *)(param_1 + 0x18), (f32 *)(player + 0x18)) < lbl_803E3EA0) {
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
        timer = state->pulseTimer;
        if (timer < lbl_803E3EB4) {
            if ((f32)(s32)randomGetRange(0, 0x1e0) < timer * lbl_803E3EB0) {
                (*(void (**)(int, int, void *, int, int, int))(*gPartfxInterface + 8))(
                    param_1, 0x7ca, &fx, 2, -1, 0);
            }
        } else if (timer < lbl_803E3EB8) {
            if ((f32)(s32)randomGetRange(0, 0x1e0) < timer / lbl_803E3EBC) {
                (*(void (**)(int, int, void *, int, int, int))(*gPartfxInterface + 8))(
                    param_1, 0x7ca, &fx, 2, -1, 0);
            }
            fx.count = 0x28;
            fx.unk0 = 0;
            fx.scale = lbl_803E3EC0 * ((timer - lbl_803E3EB4) / lbl_803E3EC4);
            (*(void (**)(int, int, void *, int, int, int))(*gPartfxInterface + 8))(
                param_1, 0x7d2, &fx, 2, -1, 0);
            state->flags = state->flags | 2;
        } else if (timer < lbl_803E3EC8) {
            if ((f32)(s32)randomGetRange(0, 0x1e0) < timer * lbl_803E3EB0) {
                (*(void (**)(int, int, void *, int, int, int))(*gPartfxInterface + 8))(
                    param_1, 0x7ca, &fx, 2, -1, 0);
            }
            if ((state->flags & 2) != 0) {
                state->flags = state->flags & ~2;
                fx.count = 0x46;
                fx.scale = lbl_803E3ECC;
                for (i = 0xf; i != 0; i--) {
                    (*(void (**)(int, int, void *, int, int, int))(*gPartfxInterface + 8))(
                        param_1, 0x7d2, &fx, 2, -1, 0);
                }
            }
        } else if (timer >= lbl_803E3ED0) {
            state->pulseTimer = lbl_803E3E98;
            state->flags = state->flags & ~4;
        }
        state->pulseTimer = state->pulseTimer + timeDelta;
    }
}

/* Drift-recovery: add new fns with v1.0 names. */
extern u8 lbl_803AC7B0[];
extern int* gExpgfxInterface;
extern void mm_free(void* p);

#pragma scheduling off
#pragma peephole off


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
    (*(void (**)(int, int, void*, int, int, int))(*gPartfxInterface + 8))( \
        (obj), (effectId), (args), (flags), (modelId), (arg6))

#define CF_EMITTER_ROTATE_FROM_LOCAL(obj, state, args)            \
    do {                                                          \
        s16 rot[3];                                               \
        rot[0] = (state)->emitAngles[0];                         \
        rot[1] = (state)->emitAngles[1];                         \
        rot[2] = (state)->emitAngles[2];                         \
        if (*(int*)((obj) + 0x30) != 0) {                         \
            rot[2] += *(s16*)(*(int*)((obj) + 0x30) + 4);         \
        }                                                         \
        vecRotateZXY(rot, (args)->pos);                        \
    } while (0)

#define CF_EMITTER_ADD_OBJECT_POSITION(obj, args)                 \
    do {                                                          \
        (args)->pos[0] += *(f32*)((obj) + 0xc);                   \
        (args)->pos[1] += *(f32*)((obj) + 0x10);                  \
        (args)->pos[2] += *(f32*)((obj) + 0x14);                  \
    } while (0)

void areafxemit_emitEffect(int* obj)
{
    int object;
    AreaFxEmitState *state;
    int count;
    s16 i;
    u8 type;
    void* resource;
    CFEmitterFxArgs args;

    object = (int)obj;
    state = *(AreaFxEmitState **)(object + 0xb8);
    args.scale = lbl_803E3E68;
    type = state->emitType;
    count = state->emitCount;

    if (type == 0) {
        if (count > 0) {
            for (i = 0; i < count; i++) {
                CF_EMITTER_RANDOMIZE_OFFSET(state, args.pos);
                CF_EMITTER_ROTATE_FROM_LOCAL(object, state, &args);
                CF_EMITTER_ADD_OBJECT_POSITION(object, &args);
                CF_EMITTER_SPAWN_PARTFX(object, state->effectId, &args, 0x200001, -1, 0);
            }
        } else {
            CF_EMITTER_RANDOMIZE_OFFSET(state, args.pos);
            CF_EMITTER_ROTATE_FROM_LOCAL(object, state, &args);
            CF_EMITTER_ADD_OBJECT_POSITION(object, &args);
            CF_EMITTER_SPAWN_PARTFX(object, state->effectId, &args, 0x200001, -1, 0);
        }
    } else if (type == 1) {
        resource = Resource_Acquire((u16)(state->effectId + 0x58), 1);
        if (count > 0) {
            for (i = 0; i < count; i++) {
                (*(void (**)(int*, int, int, int, int, int))(*(int*)resource + 4))(obj, 0, 0, 1, -1, 0);
            }
        } else {
            (*(void (**)(int*, int, int, int, int, int))(*(int*)resource + 4))(obj, 0, 0, 1, -1, 0);
        }
        Resource_Release(resource);
    } else if (type == 2) {
        resource = Resource_Acquire((u16)(state->effectId + 0xab), 1);
        if (count > 0) {
            for (i = 0; i < count; i++) {
                (*(void (**)(int*, int, int, int, int, int, int))(*(int*)resource + 4))(
                    obj, 0, 0, 1, -1, state->effectId & 0xff, 0);
            }
        } else {
            (*(void (**)(int*, int, int, int, int, int, int))(*(int*)resource + 4))(
                obj, 0, 0, 1, -1, state->effectId & 0xff, 0);
        }
        Resource_Release(resource);
    } else if (type == 3) {
        if (count > 0) {
            for (i = 0; i < count; i++) {
                CF_EMITTER_RANDOMIZE_OFFSET(state, args.pos);
                CF_EMITTER_ROTATE_FROM_LOCAL(object, state, &args);
                CF_EMITTER_SPAWN_PARTFX(object, state->effectId, &args, 2, -1, 0);
            }
        } else {
            CF_EMITTER_RANDOMIZE_OFFSET(state, args.pos);
            CF_EMITTER_ROTATE_FROM_LOCAL(object, state, &args);
            CF_EMITTER_SPAWN_PARTFX(object, state->effectId, &args, 2, -1, 0);
        }
    } else if (type > 5) {
        if (count > 0) {
            for (i = 0; i < count; i++) {
                CF_EMITTER_RANDOMIZE_OFFSET(state, args.pos);
                vecRotateZXY(state->emitAngles, args.pos);
                if (state->emitType == 6) {
                    CF_EMITTER_ADD_OBJECT_POSITION(object, &args);
                    CF_EMITTER_SPAWN_PARTFX(object, state->effectId, &args, 0x200001, -1, 0);
                } else {
                    CF_EMITTER_SPAWN_PARTFX(object, state->effectId, &args, 2, -1, 0);
                }
            }
        } else {
            CF_EMITTER_RANDOMIZE_OFFSET(state, args.pos);
            vecRotateZXY(state->emitAngles, args.pos);
            if (state->emitType == 6) {
                CF_EMITTER_ADD_OBJECT_POSITION(object, &args);
                CF_EMITTER_SPAWN_PARTFX(object, state->effectId, &args, 0x200001, -1, 0);
            } else {
                CF_EMITTER_SPAWN_PARTFX(object, state->effectId, &args, 2, -1, 0);
            }
        }
    }
}

int areafxemit_SeqFn(int* obj, int p2, u8* state)
{
    u8 i;
    for (i = 0; i < state[139]; i++) {
        switch ((s32)state[i + 129]) {
        case 1:
            areafxemit_emitEffect(obj);
            break;
        }
    }
    return 0;
}

void areafxemit_update(int* obj)
{
    AreaFxEmitState *state;
    int player;
    s16 period;
    f32 xDelta;
    f32 yDelta;
    f32 zDelta;
    f32 distance;
    f32 radius;

    state = *(AreaFxEmitState **)((u8*)obj + 0xb8);
    player = Obj_GetPlayerObject();
    if ((player != 0) &&
        (((state->enableBit == -1) || (GameBit_Get(state->enableBit) != 0)) &&
         (state->suppressed == 0))) {
        if (GameBit_Get(state->stopBit) != 0) {
            state->suppressed = 1;
        }
        period = state->emitCount;
        if ((-1 < period) || ((-1 >= period && (*(s32*)((u8*)obj + 0xf4) < 1)))) {
            xDelta = *(f32*)((u8*)obj + 0x18) - *(f32*)(player + 0x18);
            yDelta = *(f32*)((u8*)obj + 0x1c) - *(f32*)(player + 0x1c);
            zDelta = *(f32*)((u8*)obj + 0x20) - *(f32*)(player + 0x20);
            if (period == 0) {
                state->suppressed = 1;
            }
            distance = sqrtf(zDelta * zDelta + xDelta * xDelta + yDelta * yDelta);
            radius = state->triggerRadius;
            if (distance <= radius || radius == lbl_803E3E6C) {
                if ((3 < state->emitType) &&
                    ((state->lastDistance > radius && (radius != lbl_803E3E6C)))) {
                    areafxemit_emitBurst((int)obj, 0x23);
                }
                areafxemit_emitEffect(obj);
            }
            *(s32*)((u8*)obj + 0xf4) = -period;
            state->lastDistance = distance;
        } else if ((period < 0) && (0 < *(s32*)((u8*)obj + 0xf4))) {
            *(s32*)((u8*)obj + 0xf4) = *(s32*)((u8*)obj + 0xf4) - (u32)framesThisStep;
        }
    }
}

void areafxemit_init(int obj, int setup)
{
    AreaFxEmitState *state;
    s16 period;
    s16 angle;

    *(int (**)(int*, int, u8*))(obj + 0xbc) = areafxemit_SeqFn;
    state = *(AreaFxEmitState **)(obj + 0xb8);

    state->triggerRadius = (f32)((s32)*(s8*)(setup + 0x18) << 2);
    state->emitType = *(u8*)(setup + 0x1f);
    state->effectId = *(u16*)(setup + 0x20);
    period = *(s16*)(setup + 0x22);
    state->emitCount = period;
    state->enableBit = *(s16*)(setup + 0x24);
    state->stopBit = *(s16*)(setup + 0x26);
    state->suppressed = 0;
    state->extentX = (u16)(*(u8*)(setup + 0x1c) << 2);
    state->extentZ = (u16)(*(u8*)(setup + 0x1d) << 2);
    state->extentY = (u16)(*(u8*)(setup + 0x1e) << 2);

    angle = (s16)(*(s8*)(setup + 0x19) << 8);
    state->emitAngles[2] = angle;
    *(s16*)(obj + 4) = angle;
    angle = (s16)(*(s8*)(setup + 0x1a) << 8);
    state->emitAngles[1] = angle;
    *(s16*)(obj + 2) = angle;
    angle = (s16)(*(s8*)(setup + 0x1b) << 8);
    state->emitAngles[0] = angle;
    *(s16*)(obj + 0) = angle;
    *(f32*)(obj + 8) = lbl_803E3E70;

    if (period < 1) {
        *(s32*)(obj + 0xf4) = period;
    } else {
        *(s32*)(obj + 0xf4) = 0;
    }

    if (state->stopBit != -1 && GameBit_Get(state->stopBit) != 0) {
        state->suppressed = 1;
    }
}

void lfxemitter_init(int obj, int setup)
{
    LfxEmitterState *state;
    int curveFlags;

    state = *(LfxEmitterState **)(obj + 0xb8);
    curveFlags = 0x21;
    *(f32*)(obj + 8) = lbl_803E3E80 * *(f32*)(*(int*)(obj + 0x50) + 4);

    state->configIndex = *(s16*)(setup + 0x1e);
    state->lifeTimer = *(s16*)(setup + 0x20);
    state->unk114 = -2;
    state->enableBit = *(s16*)(setup + 0x22);
    state->spinRoll = *(s16*)(setup + 0x18);
    state->spinPitch = *(s16*)(setup + 0x1a);
    state->spinYaw = *(s16*)(setup + 0x1c);
    *(f32*)(obj + 0xc) = *(f32*)(setup + 8);
    *(f32*)(obj + 0x10) = *(f32*)(setup + 0xc);
    *(f32*)(obj + 0x14) = *(f32*)(setup + 0x10);

    if (state->lifeTimer != 0) {
        state->hasLifeTimer = 1;
    } else {
        state->hasLifeTimer = 0;
    }

    if (*(u8*)(setup + 0x24) != 0) {
        state->flags = state->flags | 1;
        state->curveSpeed = (f32)*(s8*)(setup + 0x25) / lbl_803E3E84;
        (*(void (**)(int, int, f32, int*, int))(*(int*)(*gRomCurveInterface) + 0x8c))(
            (int)state, obj, lbl_803E3E88, &curveFlags, -1);
    }
    ObjGroup_AddObject(obj, 0x1c);
}

int lfxemitter_setScale(void) { return -1; }

void areafxemit_render(int p1, int p2, int p3, int p4, int p5, s8 visible) { if (visible == 0) return; }

void lfxemitter_initialise(void)
{
    *(s16*)(lbl_803AC7B0 + 14) = 10000;
}

int lfxemitter_func0B(int* obj)
{
    LfxEmitterState* state = *(LfxEmitterState**)((char*)obj + 0xb8);
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

void lfxemitter_update(int obj)
{
    LfxEmitterState *state;
    int player;
    void* config;

    state = *(LfxEmitterState **)(obj + 0xb8);
    player = Obj_GetPlayerObject();

    *(s16*)(obj + 0) = *(s16*)(obj + 0) + state->spinYaw;
    *(s16*)(obj + 4) = *(s16*)(obj + 4) + state->spinRoll;
    *(s16*)(obj + 2) = *(s16*)(obj + 2) + state->spinPitch;

    if ((state->flags & 1) != 0) {
        if ((Curve_AdvanceAlongPath((int)state, state->curveSpeed) != 0) ||
            (state->curveIdx != 0)) {
            (*(void (**)(int))(*(int*)(*gRomCurveInterface) + 0x90))((int)state);
        }
        *(f32*)(obj + 0xc) = state->curveSample[0];
        *(f32*)(obj + 0x10) = state->curveSample[1];
        *(f32*)(obj + 0x14) = state->curveSample[2];
    } else {
        *(f32*)(obj + 0xc) = *(f32*)(obj + 0x24) * timeDelta + *(f32*)(obj + 0xc);
        *(f32*)(obj + 0x10) = *(f32*)(obj + 0x28) * timeDelta + *(f32*)(obj + 0x10);
        *(f32*)(obj + 0x14) = *(f32*)(obj + 0x2c) * timeDelta + *(f32*)(obj + 0x14);
        if (((state->flags & 2) != 0) && (*(f32*)(obj + 0x28) > lbl_803E3E78)) {
            *(f32*)(obj + 0x28) = lbl_803E3E7C * timeDelta + *(f32*)(obj + 0x28);
        }
    }

    if ((player != 0) &&
        ((state->enableBit == -1) || (GameBit_Get(state->enableBit) != 0))) {
        if (state->hasLifeTimer != 0) {
            state->lifeTimer = state->lifeTimer - framesThisStep;
            if (state->lifeTimer <= 0) {
                Obj_FreeObject(obj);
            }
        }
        if (state->configLoaded == 0) {
            if (((int)state != 0) && (state->configIndex == (*(u16*)(lbl_803AC7B0 + 0xe) - 1))) {
                config = mmAlloc(0x28, 0x12, 0);
                state->config = config;
                if (config != NULL) {
                    fn_8018FF48((undefined2*)lbl_803AC7B0, (undefined2*)config);
                }
            } else {
                config = mmAlloc(0x28, 0x12, 0);
                state->config = config;
                getTabEntry(config, 0xc, state->configIndex * 0x28, 0x28);
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

    def = *(int*)(obj + 0x4c);
    state = *(WarpPadState **)(obj + 0xb8);
    gameBit = *(s16*)(def + 0x20);
    if (gameBit != -1) {
        if (GameBit_Get(gameBit) != 0) {
            state->flags = state->flags & 0x7f;
        } else {
            state->flags = state->flags | 0x80;
        }
    }

    if ((*(u8*)(obj + 0xaf) & 4) != 0) {
        setAButtonIcon(0x1b);
        if (GameBit_Get(0x912) == 0) {
            (*(void (**)(int, int, int))(*(int*)(*gObjectTriggerInterface) + 0x48))(2, obj, -1);
            GameBit_Set(0x912, 1);
            return;
        }
    }

    player = Obj_GetPlayerObject();
    if (player == 0) {
        return;
    }

    if ((state->triggerMode == 0) && (state->countdownActive == 0) &&
        ((*(u16*)(obj + 0xb0) & 0x1000) == 0)) {
        if (lbl_803DCEB8 > -1) {
            player = Obj_GetPlayerObject();
            if (Vec_xzDistance((f32*)(obj + 0x18), (f32*)(player + 0x18)) < lbl_803E3EE0) {
                (*(void (**)(int, int, int))(*(int*)(*gObjectTriggerInterface) + 0x48))(1, obj, -1);
                *(s32*)(obj + 0xf4) = state->activateDelay;
                state->triggerMode = 0;
                state->countdownActive = 1;
                lbl_803DCDE0 = 2;
                goto updateTimer;
            }
        }
        gameBit = *(s16*)(def + 0x20);
        if (((gameBit == -1) ||
             ((GameBit_Get(gameBit) != 0) && ((*(u8*)(obj + 0xaf) & 4) != 0))) &&
            (ObjTrigger_IsSet(obj) != 0)) {
            (*(void (**)(int, int, int))(*(int*)(*gObjectTriggerInterface) + 0x48))(0, obj, -1);
            *(s32*)(obj + 0xf4) = state->activateDelay;
            state->triggerMode = 1;
            state->countdownActive = 1;
        }
    }

updateTimer:
    if (state->countdownActive != 0) {
        if (*(s32*)(obj + 0xf4) > 0) {
            *(s32*)(obj + 0xf4) = *(s32*)(obj + 0xf4) - framesThisStep;
        } else {
            *(s32*)(obj + 0xf4) = 0;
            state->countdownActive = 0;
        }
    }
    state->cooldownTimer = state->cooldownTimer - timeDelta;
    if (state->cooldownTimer <= lbl_803E3E98) {
        state->cooldownTimer = lbl_803E3E98;
        state->unk0A = -1;
    }
}

void areafxemit_free(int* obj)
{
    ((void(*)(int*))((void**)*gExpgfxInterface)[6])(obj);
}

void lfxemitter_free(int* obj)
{
    LfxEmitterState* state = *(LfxEmitterState**)((char*)obj + 0xb8);
    int* ptr = (int*)state->config;
    if (ptr != NULL) {
        mm_free(ptr);
    }
    ObjGroup_RemoveObject(obj, 28);
}

#pragma peephole reset
#pragma scheduling reset

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
