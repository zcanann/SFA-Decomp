#include "ghidra_import.h"
#include "main/mapEvent.h"
#include "main/dll/IM/IMicicle.h"


#pragma peephole off
#pragma scheduling off
extern undefined8 FUN_80006724();
extern undefined8 FUN_80006824();
extern undefined4 FUN_80006958();
extern uint FUN_80017690();
extern undefined8 FUN_80017698();
extern undefined4 FUN_80017710();
extern undefined4 FUN_8001771c();
extern int FUN_80017738();
extern undefined4 FUN_80017744();
extern u32 randomGetRange(int min, int max);
extern undefined4 FUN_800178b8();
extern undefined4 FUN_80017a50();
extern undefined4 FUN_80017a7c();
extern int FUN_80017a90();
extern int FUN_80017a98();
extern undefined8 FUN_80017ac8();
extern int FUN_80017af8();
extern undefined8 ObjGroup_RemoveObject();
extern undefined4 ObjGroup_AddObject();
extern int Obj_GetYawDeltaToObject();
extern undefined4 FUN_8003b818();
extern undefined4 FUN_80041ff8();
extern undefined4 FUN_80042b9c();
extern undefined4 FUN_80042bec();
extern undefined4 FUN_80044404();
extern int FUN_80056600();
extern undefined4 FUN_800632d8();
extern uint FUN_8007f6c8();
extern undefined4 FUN_8007f6e4();
extern undefined4 FUN_8007f718();
extern int FUN_8007f764();
extern undefined4 FUN_80080f3c();
extern undefined4 FUN_8017c5c4();
extern undefined4 FUN_801a35f4();
extern undefined4 SH_LevelControl_runBloopEvent();
extern undefined4 FUN_801d8480();
extern undefined4 FUN_80247cd8();
extern undefined4 FUN_80286830();
extern int FUN_80286840();
extern undefined4 FUN_8028687c();
extern undefined4 FUN_8028688c();
extern undefined4 FUN_80293f90();
extern undefined4 FUN_80294964();
extern byte FUN_80294c20();
extern undefined4 FUN_80294c30();
extern uint countLeadingZeros();

extern undefined4 DAT_802c2a68;
extern undefined4 DAT_802c2a6c;
extern undefined4 DAT_802c2a70;
extern int DAT_803239f0;
extern undefined4 DAT_803239fd;
extern undefined4 DAT_80323b28;
extern undefined4 DAT_80323b30;
extern undefined4 DAT_80323b3c;
extern short DAT_80323c58;
extern undefined4 DAT_803dcafc;
extern undefined4 DAT_803dcb00;
extern undefined4* DAT_803dd6d0;
extern undefined4* DAT_803dd6d4;
extern undefined4* DAT_803dd708;
extern undefined4* DAT_803dd72c;
extern f64 DOUBLE_803e5020;
extern f64 DOUBLE_803e5048;
extern f64 DOUBLE_803e5060;
extern f64 DOUBLE_803e5078;
extern f64 DOUBLE_803e5090;
extern f64 DOUBLE_803e50a8;
extern f32 lbl_803DC074;
extern f32 lbl_803DCAF8;
extern f32 lbl_803E4FF4;
extern f32 lbl_803E5028;
extern f32 lbl_803E502C;
extern f32 lbl_803E5030;
extern f32 lbl_803E5034;
extern f32 lbl_803E5038;
extern f32 lbl_803E5040;
extern f32 lbl_803E5050;
extern f32 lbl_803E5058;
extern f32 lbl_803E5074;
extern f32 lbl_803E5080;
extern f32 lbl_803E5084;
extern f32 lbl_803E5088;
extern f32 lbl_803E508C;
extern f32 lbl_803E5098;
extern f32 lbl_803E509C;
extern f32 lbl_803E50A0;
extern uint GameBit_Get(int eventId);
extern void GameBit_Set(int eventId, int value);
extern void Obj_BuildWorldTransformMatrix(void *obj, f32 *mtx, int flags);
extern void PSMTXMultVecSR(f32 *mtx, f32 *src, f32 *dst);
extern f32 sin(f32 angle);
extern f32 fn_80293E80(f32 angle);
extern int fn_80080150(void *timer);
extern void s16toFloat(void *p, int duration);
extern int timerCountDown(void *timer);
extern void Sfx_PlayFromObject(int obj, int sfxId);
extern int *gPartfxInterface;
extern f32 timeDelta;
extern f32 lbl_803DBE90;
extern int lbl_803DBE94;
extern int lbl_803DBE98;
extern int lbl_80322ED8[];
extern f32 lbl_803E4390;
extern f32 lbl_803E4394;
extern f32 lbl_803E4398;
extern f32 lbl_803E439C;
extern f32 lbl_803E43A0;
extern f32 lbl_803E43A4;
extern f32 lbl_803E43A8;
extern f32 lbl_803E43AC;

/*
 * --INFO--
 *
 * Function: cfforcefield_update
 * EN v1.0 Address: 0x801A39D0
 * EN v1.0 Size: 1128b
 * EN v1.1 Address: 0x801A3B20
 * EN v1.1 Size: 124b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void cfforcefield_update(u8 *obj)
{
  typedef struct ForceFieldEmitter {
    int effectId;
    int pad04;
    int angleStep;
    int pad0c;
    int pad10;
    f32 waveScale;
  } ForceFieldEmitter;
  u8 *data;
  u8 *state;
  int style;
  f32 strength;

  data = *(u8 **)(obj + 0x4c);
  state = *(u8 **)(obj + 0xb8);
  *(f32 *)(obj + 0x24) = lbl_803E4390;
  *(f32 *)(obj + 0x28) = lbl_803E4390;
  *(f32 *)(obj + 0x2c) = lbl_803E4390;

  if (GameBit_Get(*(s16 *)(data + 0x1e)) == 0) {
    return;
  }

  if ((s8)state[0] < 0) {
    state[0] = (u8)((state[0] & ~0x80) | (((u8)GameBit_Get(*(s16 *)(data + 0x20)) & 1) << 7));
    return;
  }

  style = (s8)data[0x19] % 3;
  if (*(f32 *)(state + 4) == lbl_803E4390) {
    strength = lbl_803E4394;
  } else {
    strength = lbl_803E4398 * *(f32 *)(state + 4);
  }

  {
    f32 mtx[3][4];
    ForceFieldEmitter *emitter = (ForceFieldEmitter *)((u8 *)lbl_80322ED8 + style * 0x18);
    int angle;
    Obj_BuildWorldTransformMatrix(obj, (f32 *)mtx, 0);
    *(s16 *)(obj + 4) = (s16)((f32)(s32)*(s16 *)(obj + 4) + lbl_803E439C * timeDelta);

    for (angle = -0x7fff; angle < 0x7fff; angle += emitter->angleStep) {
      f32 local[3];
      f32 world[3];
      int phaseOffset = (s32)(lbl_803E43A8 * emitter->waveScale);
      f32 phase = (lbl_803E43A4 * (f32)(angle + phaseOffset)) / lbl_803E43AC;

      local[0] = lbl_803E43A0 * (strength * lbl_803DBE90) * sin(phase) +
                 (f32)randomGetRange(-lbl_803DBE94, lbl_803DBE94);
      local[1] = lbl_803E43A0 * (strength * lbl_803DBE90) * fn_80293E80(phase) +
                 (f32)randomGetRange(-lbl_803DBE94, lbl_803DBE94);
      local[2] = lbl_803E4390;
      PSMTXMultVecSR((f32 *)mtx, local, local);
      world[0] = local[0] + *(f32 *)(obj + 0xc);
      world[1] = local[1] + *(f32 *)(obj + 0x10);
      world[2] = local[2] + *(f32 *)(obj + 0x14);
      ((void (*)(u8 *, int, f32 *, int, int, f32 *))(*(int *)(*gPartfxInterface + 8)))(
          obj, emitter->effectId, world, 0x200001, -1, (f32 *)(obj + 0x24));
      ((void (*)(u8 *, int, f32 *, int, int, f32 *))(*(int *)(*gPartfxInterface + 8)))(
          obj, emitter->effectId, world, 0x200001, -1, (f32 *)(obj + 0x24));
      ((void (*)(u8 *, int, f32 *, int, int, f32 *))(*(int *)(*gPartfxInterface + 8)))(
          obj, emitter->effectId, world, 0x200001, -1, (f32 *)(obj + 0x24));
    }
  }

  if (fn_80080150(state + 4) != 0) {
    *(s16 *)(obj + 2) = (s16)((f32)(s32)lbl_803DBE98 * timeDelta + (f32)(s32)*(s16 *)(obj + 2));
    if (timerCountDown(state + 4) != 0) {
      state[0] = (u8)(state[0] | 0x80);
      *(s16 *)(obj + 2) = 0;
    }
  } else if (GameBit_Get(*(s16 *)(data + 0x20)) != 0) {
    s16toFloat(state + 4, 0x3c);
    Sfx_PlayFromObject((int)obj, 0x366);
    if (*(int *)(*(int *)(obj + 0x4c) + 0x14) != 0x47f5e) {
      Sfx_PlayFromObject((int)obj, 0x409);
    }
  }
}

/*
 * --INFO--
 *
 * Function: FUN_801a3ac0
 * EN v1.0 Address: 0x801A3AC0
 * EN v1.0 Size: 516b
 * EN v1.1 Address: 0x801A3B9C
 * EN v1.1 Size: 340b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801a3ac0(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 uint param_9)
{
  uint uVar1;
  int iVar2;
  undefined4 in_r7;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  int iVar3;
  int iVar4;
  int iVar5;
  int iVar6;
  undefined8 uVar7;
  
  iVar3 = *(int *)(param_9 + 0xb8);
  iVar5 = *(int *)(param_9 + 0x4c);
  if (*(char *)(iVar3 + 0x6e4) != '\x02') {
    if (*(char *)(iVar3 + 0x6e4) == '\0') {
      uVar1 = FUN_80017690((int)*(short *)(iVar5 + 0x40));
      if (uVar1 != 0) {
        FUN_801a35f4(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,iVar5,0
                     ,iVar3,in_r7,in_r8,in_r9,in_r10);
        if (*(int *)(iVar3 + 0x6d0) != 0) {
          FUN_80006824(param_9,(ushort)*(int *)(iVar3 + 0x6d0));
        }
        *(undefined *)(iVar3 + 0x6e4) = 1;
        *(undefined *)(param_9 + 0x36) = 0;
      }
    }
    else {
      iVar4 = 0;
      iVar6 = iVar3;
      do {
        if (*(int *)(iVar6 + 0x690) != 0) {
          iVar2 = (**(code **)(**(int **)(*(int *)(iVar6 + 0x690) + 0x68) + 0x20))();
          if (iVar2 != 1) {
            if (iVar2 < 1) {
              if (-1 < iVar2) {
                FUN_80017698((int)*(short *)(iVar5 + 0x3e),1);
                if ((*(uint *)(iVar3 + 0x6cc) & 1 << iVar4) == 0) {
                  *(uint *)(iVar3 + 0x6cc) = *(uint *)(iVar3 + 0x6cc) | 1 << iVar4;
                }
              }
            }
            else if (iVar2 < 3) {
              uVar7 = FUN_80017698((int)*(short *)(iVar5 + 0x3e),1);
              FUN_80017ac8(uVar7,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                           *(int *)(iVar6 + 0x690));
              *(undefined4 *)(iVar6 + 0x690) = 0;
            }
          }
        }
        iVar6 = iVar6 + 4;
        iVar4 = iVar4 + 1;
      } while (iVar4 < 0xf);
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801a3cc4
 * EN v1.0 Address: 0x801A3CC4
 * EN v1.0 Size: 548b
 * EN v1.1 Address: 0x801A3CF0
 * EN v1.1 Size: 660b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801a3cc4(undefined2 *param_1,int param_2)
{
  char cVar1;
  uint uVar2;
  int iVar3;
  int *piVar4;
  int iVar5;
  int iVar6;
  
  ObjGroup_AddObject((int)param_1,0x21);
  iVar5 = *(int *)(param_1 + 0x5c);
  cVar1 = *(char *)(param_2 + 0x18);
  if (cVar1 == '\0') {
    cVar1 = '\x01';
  }
  *(char *)(iVar5 + 0x6d4) = cVar1;
  *(undefined4 *)(iVar5 + 0x6cc) = 0;
  *(undefined4 *)(iVar5 + 0x690) = 0;
  *(undefined4 *)(iVar5 + 0x694) = 0;
  *(undefined4 *)(iVar5 + 0x698) = 0;
  *(undefined4 *)(iVar5 + 0x69c) = 0;
  *(undefined4 *)(iVar5 + 0x6a0) = 0;
  *(undefined4 *)(iVar5 + 0x6a4) = 0;
  *(undefined4 *)(iVar5 + 0x6a8) = 0;
  *(undefined4 *)(iVar5 + 0x6ac) = 0;
  *(undefined4 *)(iVar5 + 0x6b0) = 0;
  *(undefined4 *)(iVar5 + 0x6b4) = 0;
  *(undefined4 *)(iVar5 + 0x6b8) = 0;
  *(undefined4 *)(iVar5 + 0x6bc) = 0;
  *(undefined4 *)(iVar5 + 0x6c0) = 0;
  *(undefined4 *)(iVar5 + 0x6c4) = 0;
  *(undefined4 *)(iVar5 + 0x6c8) = 0;
  *param_1 = *(undefined2 *)(param_2 + 0x1a);
  param_1[1] = *(undefined2 *)(param_2 + 0x1c);
  param_1[2] = *(undefined2 *)(param_2 + 0x1e);
  uVar2 = FUN_80017690((int)*(short *)(param_2 + 0x3e));
  if (uVar2 != 0) {
    *(undefined *)(iVar5 + 0x6e4) = 2;
  }
  cVar1 = '\0';
  piVar4 = &DAT_803239f0;
  iVar6 = 2;
  do {
    iVar3 = (int)(short)param_1[0x23];
    if (iVar3 == *piVar4) {
      *(char *)(iVar5 + 0x6e5) = cVar1;
      break;
    }
    if (iVar3 == piVar4[4]) {
      *(char *)(iVar5 + 0x6e5) = cVar1 + '\x01';
      break;
    }
    if (iVar3 == piVar4[8]) {
      *(char *)(iVar5 + 0x6e5) = cVar1 + '\x02';
      break;
    }
    if (iVar3 == piVar4[0xc]) {
      *(char *)(iVar5 + 0x6e5) = cVar1 + '\x03';
      break;
    }
    if (iVar3 == piVar4[0x10]) {
      *(char *)(iVar5 + 0x6e5) = cVar1 + '\x04';
      break;
    }
    if (iVar3 == piVar4[0x14]) {
      *(char *)(iVar5 + 0x6e5) = cVar1 + '\x05';
      break;
    }
    if (iVar3 == piVar4[0x18]) {
      *(char *)(iVar5 + 0x6e5) = cVar1 + '\x06';
      break;
    }
    if (iVar3 == piVar4[0x1c]) {
      *(char *)(iVar5 + 0x6e5) = cVar1 + '\a';
      break;
    }
    piVar4 = piVar4 + 0x20;
    cVar1 = cVar1 + '\b';
    iVar6 = iVar6 + -1;
  } while (iVar6 != 0);
  if (*(char *)(param_2 + 0x3d) == '\0') {
    *(undefined *)(param_2 + 0x3d) = 0x14;
  }
  *(float *)(param_1 + 4) =
       (*(float *)(*(int *)(param_1 + 0x28) + 4) *
       (float)((double)CONCAT44(0x43300000,(int)*(char *)(param_2 + 0x3d) ^ 0x80000000) -
              DOUBLE_803e5020)) / lbl_803E4FF4;
  if (((&DAT_803239fd)[(uint)*(byte *)(iVar5 + 0x6e5) * 0x10] & 1) != 0) {
    param_1[0x58] = param_1[0x58] | 0x4000;
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801a3ee8
 * EN v1.0 Address: 0x801A3EE8
 * EN v1.0 Size: 936b
 * EN v1.1 Address: 0x801A3F84
 * EN v1.1 Size: 1128b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801a3ee8(void)
{
  int iVar1;
  char cVar2;
  float fVar3;
  ushort *puVar4;
  uint uVar5;
  int iVar6;
  byte *pbVar7;
  int iVar8;
  int iVar9;
  undefined4 *puVar10;
  double dVar11;
  double in_f24;
  double dVar12;
  double in_f25;
  double dVar13;
  double in_f26;
  double dVar14;
  double in_f27;
  double dVar15;
  double in_f28;
  double in_f29;
  double dVar16;
  double in_f30;
  double in_f31;
  double dVar17;
  double in_ps24_1;
  double in_ps25_1;
  double in_ps26_1;
  double in_ps27_1;
  double in_ps28_1;
  double in_ps29_1;
  double in_ps30_1;
  double in_ps31_1;
  float local_138;
  float local_134;
  float local_130;
  undefined auStack_12c [12];
  float local_120;
  float local_11c;
  float local_118;
  float afStack_114 [13];
  undefined8 local_e0;
  undefined8 local_d8;
  undefined4 local_d0;
  uint uStack_cc;
  undefined8 local_c8;
  undefined8 local_c0;
  undefined4 local_b8;
  uint uStack_b4;
  float local_78;
  float fStack_74;
  float local_68;
  float fStack_64;
  float local_58;
  float fStack_54;
  float local_48;
  float fStack_44;
  float local_38;
  float fStack_34;
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
  local_38 = (float)in_f28;
  fStack_34 = (float)in_ps28_1;
  local_48 = (float)in_f27;
  fStack_44 = (float)in_ps27_1;
  local_58 = (float)in_f26;
  fStack_54 = (float)in_ps26_1;
  local_68 = (float)in_f25;
  fStack_64 = (float)in_ps25_1;
  local_78 = (float)in_f24;
  fStack_74 = (float)in_ps24_1;
  puVar4 = (ushort *)FUN_80286830();
  fVar3 = lbl_803E5028;
  iVar8 = *(int *)(puVar4 + 0x26);
  pbVar7 = *(byte **)(puVar4 + 0x5c);
  *(float *)(puVar4 + 0x16) = lbl_803E5028;
  *(float *)(puVar4 + 0x14) = fVar3;
  *(float *)(puVar4 + 0x12) = fVar3;
  uVar5 = FUN_80017690((int)*(short *)(iVar8 + 0x1e));
  if (uVar5 != 0) {
    if ((char)*pbVar7 < '\0') {
      uVar5 = FUN_80017690((int)*(short *)(iVar8 + 0x20));
      *pbVar7 = (byte)((uVar5 & 0xff) << 7) | *pbVar7 & 0x7f;
    }
    else {
      cVar2 = *(char *)(iVar8 + 0x19);
      uVar5 = countLeadingZeros(((uint)(byte)((*(float *)(pbVar7 + 4) == lbl_803E5028) << 1) <<
                                0x1c) >> 0x1d ^ 1);
      fVar3 = lbl_803E502C;
      if (uVar5 >> 5 == 0) {
        fVar3 = lbl_803E5030 * *(float *)(pbVar7 + 4);
      }
      dVar14 = (double)fVar3;
      FUN_80017a50(puVar4,afStack_114,'\0');
      dVar15 = DOUBLE_803e5048;
      local_e0 = (double)CONCAT44(0x43300000,(int)(short)puVar4[2] ^ 0x80000000);
      iVar6 = (int)(lbl_803E5034 * lbl_803DC074 + (float)(local_e0 - DOUBLE_803e5048));
      local_d8 = (double)(longlong)iVar6;
      puVar4[2] = (ushort)iVar6;
      iVar6 = ((int)cVar2 % 3) * 0x18;
      puVar10 = (undefined4 *)(&DAT_80323b28 + iVar6);
      dVar16 = (double)lbl_803E5040;
      dVar17 = (double)lbl_803E5038;
      dVar13 = (double)lbl_803E5028;
      for (iVar9 = -0x7fff; iVar9 < 0x7fff; iVar9 = iVar9 + *(int *)(&DAT_80323b30 + iVar6)) {
        uVar5 = randomGetRange(-DAT_803dcafc,DAT_803dcafc);
        local_d8 = (double)CONCAT44(0x43300000,uVar5 ^ 0x80000000);
        dVar12 = (double)(float)(local_d8 - dVar15);
        iVar1 = (int)(dVar16 * (double)*(float *)(&DAT_80323b3c + iVar6));
        local_e0 = (double)(longlong)iVar1;
        uStack_cc = iVar9 + iVar1 ^ 0x80000000;
        local_d0 = 0x43300000;
        dVar11 = (double)FUN_80294964();
        local_138 = (float)((double)(float)(dVar17 * (double)(float)(dVar14 * (double)lbl_803DCAF8
                                                                    )) * dVar11 + dVar12);
        uVar5 = randomGetRange(-DAT_803dcafc,DAT_803dcafc);
        local_c8 = (double)CONCAT44(0x43300000,uVar5 ^ 0x80000000);
        dVar12 = (double)(float)(local_c8 - dVar15);
        iVar1 = (int)(dVar16 * (double)*(float *)(&DAT_80323b3c + iVar6));
        local_c0 = (double)(longlong)iVar1;
        uStack_b4 = iVar9 + iVar1 ^ 0x80000000;
        local_b8 = 0x43300000;
        dVar11 = (double)FUN_80293f90();
        local_134 = (float)((double)(float)(dVar17 * (double)(float)(dVar14 * (double)lbl_803DCAF8
                                                                    )) * dVar11 + dVar12);
        local_130 = (float)dVar13;
        FUN_80247cd8(afStack_114,&local_138,&local_138);
        local_120 = local_138 + *(float *)(puVar4 + 6);
        local_11c = local_134 + *(float *)(puVar4 + 8);
        local_118 = local_130 + *(float *)(puVar4 + 10);
        (**(code **)(*DAT_803dd708 + 8))
                  (puVar4,*puVar10,auStack_12c,0x200001,0xffffffff,puVar4 + 0x12);
        (**(code **)(*DAT_803dd708 + 8))
                  (puVar4,*puVar10,auStack_12c,0x200001,0xffffffff,puVar4 + 0x12);
        (**(code **)(*DAT_803dd708 + 8))
                  (puVar4,*puVar10,auStack_12c,0x200001,0xffffffff,puVar4 + 0x12);
      }
      uVar5 = FUN_8007f6c8((float *)(pbVar7 + 4));
      if (uVar5 == 0) {
        uVar5 = FUN_80017690((int)*(short *)(iVar8 + 0x20));
        if (uVar5 != 0) {
          FUN_8007f718((float *)(pbVar7 + 4),0x3c);
          FUN_80006824((uint)puVar4,0x366);
          if (*(int *)(*(int *)(puVar4 + 0x26) + 0x14) != 0x47f5e) {
            FUN_80006824((uint)puVar4,0x409);
          }
        }
      }
      else {
        uStack_b4 = DAT_803dcb00 ^ 0x80000000;
        local_b8 = 0x43300000;
        local_c0 = (double)CONCAT44(0x43300000,(int)(short)puVar4[1] ^ 0x80000000);
        iVar8 = (int)((float)((double)CONCAT44(0x43300000,uStack_b4) - DOUBLE_803e5048) *
                      lbl_803DC074 + (float)(local_c0 - DOUBLE_803e5048));
        local_c8 = (double)(longlong)iVar8;
        puVar4[1] = (ushort)iVar8;
        iVar8 = FUN_8007f764((float *)(pbVar7 + 4));
        if (iVar8 != 0) {
          *pbVar7 = *pbVar7 & 0x7f | 0x80;
          puVar4[1] = 0;
        }
      }
    }
  }
  FUN_8028687c();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801a4290
 * EN v1.0 Address: 0x801A4290
 * EN v1.0 Size: 88b
 * EN v1.1 Address: 0x801A43EC
 * EN v1.1 Size: 100b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801a4290(undefined2 *param_1,int param_2)
{
  uint uVar1;
  byte *pbVar2;
  
  pbVar2 = *(byte **)(param_1 + 0x5c);
  *param_1 = (short)((int)*(char *)(param_2 + 0x18) << 8);
  uVar1 = FUN_80017690((int)*(short *)(param_2 + 0x20));
  *pbVar2 = (byte)((uVar1 & 0xff) << 7) | *pbVar2 & 0x7f;
  FUN_8007f6e4((undefined4 *)(pbVar2 + 4));
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801a42e8
 * EN v1.0 Address: 0x801A42E8
 * EN v1.0 Size: 528b
 * EN v1.1 Address: 0x801A4450
 * EN v1.1 Size: 476b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801a42e8(undefined4 param_1,undefined4 param_2,int param_3)
{
  byte bVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  uint uVar5;
  byte *pbVar6;
  bool bVar7;
  bool bVar8;
  double dVar9;
  
  iVar2 = FUN_80286840();
  iVar3 = FUN_80017a98();
  iVar4 = FUN_80017a90();
  if (iVar3 == 0) {
    bVar7 = false;
  }
  else {
    dVar9 = (double)FUN_80017710((float *)(iVar2 + 0x18),(float *)(iVar3 + 0x18));
    bVar7 = dVar9 < (double)lbl_803E5050;
  }
  if (iVar4 == 0) {
    bVar8 = false;
  }
  else {
    dVar9 = (double)FUN_80017710((float *)(iVar2 + 0x18),(float *)(iVar4 + 0x18));
    bVar8 = dVar9 < (double)lbl_803E5050;
  }
  pbVar6 = *(byte **)(iVar2 + 0xb8);
  iVar2 = *(int *)(iVar2 + 0x4c);
  if (*pbVar6 >> 5 == 0) {
    uVar5 = FUN_80017690((int)*(short *)(iVar2 + 0x18));
    if (((uVar5 != 0) &&
        (((int)*(short *)(iVar2 + 0x22) == 0xffffffff ||
         (uVar5 = FUN_80017690((int)*(short *)(iVar2 + 0x22)), uVar5 != 0)))) &&
       ((FUN_80017698((int)*(short *)(iVar2 + 0x1a),1), bVar7 || (bVar8)))) {
      *pbVar6 = *pbVar6 & 0x1f | 0x40;
    }
  }
  else if (((*pbVar6 >> 5 == 1) &&
           (((uVar5 = FUN_80017690((int)*(short *)(iVar2 + 0x18)), uVar5 != 0 ||
             (((int)*(short *)(iVar2 + 0x22) != 0xffffffff &&
              (uVar5 = FUN_80017690((int)*(short *)(iVar2 + 0x22)), uVar5 != 0)))) && (!bVar7)))) &&
          (!bVar8)) {
    *pbVar6 = *pbVar6 & 0x1f | 0x60;
  }
  bVar1 = *pbVar6;
  if (bVar1 >> 5 == 2) {
    if (*(char *)(param_3 + 0x80) == '\x02') {
      *pbVar6 = bVar1 & 0x1f | 0x20;
    }
  }
  else if ((bVar1 >> 5 == 3) && (*(char *)(param_3 + 0x80) == '\x01')) {
    *pbVar6 = bVar1 & 0x1f;
  }
  FUN_8028688c();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801a44f8
 * EN v1.0 Address: 0x801A44F8
 * EN v1.0 Size: 40b
 * EN v1.1 Address: 0x801A462C
 * EN v1.1 Size: 52b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801a44f8(int param_1,int param_2,int param_3,int param_4,int param_5,s8 visible)
{
  if (visible != 0) {
    FUN_8003b818(param_1);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801a4520
 * EN v1.0 Address: 0x801A4520
 * EN v1.0 Size: 172b
 * EN v1.1 Address: 0x801A4660
 * EN v1.1 Size: 168b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801a4520(int param_1)
{
  int iVar1;
  
  if (*(int *)(param_1 + 0xf4) == 0) {
    iVar1 = *(int *)(param_1 + 0x4c);
    if ((*(short *)(iVar1 + 0x1c) != 0) && (**(byte **)(param_1 + 0xb8) >> 5 != 0)) {
      (**(code **)(*DAT_803dd6d4 + 0x54))();
    }
    iVar1 = (int)*(char *)(iVar1 + 0x1e);
    if (iVar1 != -1) {
      (**(code **)(*DAT_803dd6d4 + 0x48))(iVar1,param_1,0xffffffff);
    }
    *(undefined4 *)(param_1 + 0xf4) = 1;
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801a45cc
 * EN v1.0 Address: 0x801A45CC
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x801A4708
 * EN v1.1 Size: 132b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801a45cc(short *param_1,int param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_801a45d0
 * EN v1.0 Address: 0x801A45D0
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x801A478C
 * EN v1.1 Size: 244b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801a45d0(short *param_1,undefined4 *param_2)
{
}

/*
 * --INFO--
 *
 * Function: cflevelcontrol_free
 * EN v1.0 Address: 0x801A45D4
 * EN v1.0 Size: 36b
 * EN v1.1 Address: 0x801A4880
 * EN v1.1 Size: 36b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void cflevelcontrol_free(int param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_801a45f8
 * EN v1.0 Address: 0x801A45F8
 * EN v1.0 Size: 40b
 * EN v1.1 Address: 0x801A48A4
 * EN v1.1 Size: 56b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801a45f8(int param_1,int param_2,int param_3,int param_4,int param_5,s8 visible)
{
  if (visible != 0) {
    FUN_8003b818(param_1);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801a4620
 * EN v1.0 Address: 0x801A4620
 * EN v1.0 Size: 76b
 * EN v1.1 Address: 0x801A48DC
 * EN v1.1 Size: 108b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801a4620(undefined2 *param_1,int param_2)
{
  ObjGroup_AddObject((int)param_1,0x1e);
  *param_1 = (short)((int)*(char *)(param_2 + 0x18) << 8);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801a466c
 * EN v1.0 Address: 0x801A466C
 * EN v1.0 Size: 40b
 * EN v1.1 Address: 0x801A4948
 * EN v1.1 Size: 52b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801a466c(int param_1,int param_2,int param_3,int param_4,int param_5,s8 visible)
{
  if (visible != 0) {
    FUN_8003b818(param_1);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801a4694
 * EN v1.0 Address: 0x801A4694
 * EN v1.0 Size: 380b
 * EN v1.1 Address: 0x801A497C
 * EN v1.1 Size: 348b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801a4694(ushort *param_1)
{
  int iVar1;
  uint uVar2;
  int iVar3;
  undefined uVar4;
  int iVar5;
  double dVar6;
  double dVar7;
  double dVar8;
  
  iVar5 = *(int *)(param_1 + 0x26);
  iVar1 = FUN_80017a98();
  uVar4 = 0xff;
  uVar2 = FUN_80017690((int)*(short *)(iVar5 + 0x20));
  if (uVar2 != 0) {
    iVar3 = Obj_GetYawDeltaToObject(param_1,iVar1,(float *)0x0);
    iVar3 = (int)(short)iVar3;
    if (iVar3 < 0) {
      iVar3 = -iVar3;
    }
    if (iVar3 < 0x4001) {
      dVar8 = (double)(float)((double)CONCAT44(0x43300000,(int)*(short *)(iVar5 + 0x1a) ^ 0x80000000
                                              ) - DOUBLE_803e5078);
      dVar6 = (double)FUN_8001771c((float *)(param_1 + 0xc),(float *)(iVar1 + 0x18));
      dVar7 = (double)FUN_80006958((double)*(float *)(param_1 + 6),(double)*(float *)(param_1 + 8),
                                   (double)*(float *)(param_1 + 10));
      if (dVar7 < dVar6) {
        dVar6 = (double)FUN_80006958((double)*(float *)(param_1 + 6),(double)*(float *)(param_1 + 8)
                                     ,(double)*(float *)(param_1 + 10));
      }
      if (dVar6 < dVar8) {
        uVar4 = (undefined)(int)(lbl_803E5074 * (float)(dVar6 / dVar8));
      }
      *(undefined *)(param_1 + 0x1b) = uVar4;
    }
    else {
      *(undefined *)(param_1 + 0x1b) = 0;
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801a4810
 * EN v1.0 Address: 0x801A4810
 * EN v1.0 Size: 276b
 * EN v1.1 Address: 0x801A4AD8
 * EN v1.1 Size: 180b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_801a4810(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
            undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
            undefined4 param_9,undefined4 param_10,int param_11)
{
  undefined4 uVar1;
  int iVar2;
  undefined8 uVar3;
  
  for (iVar2 = 0; iVar2 < (int)(uint)*(byte *)(param_11 + 0x8b); iVar2 = iVar2 + 1) {
    if (*(char *)(param_11 + iVar2 + 0x81) == '\x01') {
      FUN_80017698(0xdcb,1);
      uVar3 = FUN_80017698(0x4a3,0);
      FUN_80041ff8(uVar3,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0x2b);
      FUN_80042b9c(0,0,1);
      uVar1 = FUN_80044404(0x2b);
      FUN_80042bec(uVar1,0);
    }
  }
  return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_801a4924
 * EN v1.0 Address: 0x801A4924
 * EN v1.0 Size: 40b
 * EN v1.1 Address: 0x801A4B8C
 * EN v1.1 Size: 52b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801a4924(int param_1,int param_2,int param_3,int param_4,int param_5,s8 visible)
{
  if (visible != 0) {
    FUN_8003b818(param_1);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801a494c
 * EN v1.0 Address: 0x801A494C
 * EN v1.0 Size: 2272b
 * EN v1.1 Address: 0x801A4BC0
 * EN v1.1 Size: 1516b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801a494c(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)
{
  int iVar1;
  int iVar2;
  int iVar3;
  char cVar6;
  uint uVar4;
  uint uVar5;
  byte bVar7;
  undefined uVar8;
  undefined4 in_r7;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  int iVar9;
  undefined8 extraout_f1;
  undefined8 uVar10;
  undefined4 local_28;
  undefined4 local_24;
  undefined4 local_20;
  
  iVar1 = FUN_80286840();
  iVar9 = *(int *)(iVar1 + 0xb8);
  iVar2 = FUN_80017a98();
  local_28 = DAT_802c2a68;
  local_24 = DAT_802c2a6c;
  local_20 = DAT_802c2a70;
  if ((*(byte *)(iVar9 + 0xc) >> 3 & 1) != 0) {
    iVar3 = FUN_80017af8(0x47fae);
    FUN_8017c5c4(iVar3);
    iVar3 = FUN_80017af8(0x47f83);
    FUN_8017c5c4(iVar3);
    iVar3 = FUN_80017af8(0x47f8f);
    FUN_8017c5c4(iVar3);
    iVar3 = FUN_80017af8(0x47fa2);
    FUN_8017c5c4(iVar3);
    iVar3 = FUN_80017af8(0x29f2);
    FUN_8017c5c4(iVar3);
    iVar3 = FUN_80017af8(0x29f3);
    FUN_8017c5c4(iVar3);
    iVar3 = FUN_80017af8(0x29ef);
    FUN_8017c5c4(iVar3);
    iVar3 = FUN_80017af8(0x29ee);
    FUN_8017c5c4(iVar3);
    *(byte *)(iVar9 + 0xc) = *(byte *)(iVar9 + 0xc) & 0xf7;
  }
  cVar6 = (**(code **)(*DAT_803dd72c + 0x40))(0x1d);
  uVar10 = extraout_f1;
  if ((cVar6 == '\x01') && (uVar4 = FUN_80017690(0x40), uVar4 != 0)) {
    uVar10 = (**(code **)(*DAT_803dd72c + 0x44))(0x1d,2);
  }
  uVar4 = FUN_80017690(0x974);
  uVar4 = uVar4 & 0xff;
  uVar5 = FUN_80017690(0x975);
  uVar5 = uVar5 & 0xff;
  bVar7 = *(byte *)(iVar9 + 0xc) >> 5 & 1;
  if ((bVar7 == 0) || ((*(byte *)(iVar9 + 0xc) >> 4 & 1) == 0)) {
    if ((bVar7 == 0) && ((*(byte *)(iVar9 + 0xc) >> 4 & 1) == 0)) {
      if ((uVar4 != 0) || (uVar5 != 0)) {
        uVar10 = FUN_80006824(0,0x109);
      }
    }
    else if ((uVar4 != 0) && (uVar5 != 0)) {
      uVar10 = FUN_80006824(0,0x7e);
    }
  }
  *(byte *)(iVar9 + 0xc) = (byte)(uVar4 << 5) & 0x20 | *(byte *)(iVar9 + 0xc) & 0xdf;
  *(byte *)(iVar9 + 0xc) = (byte)(uVar5 << 4) & 0x10 | *(byte *)(iVar9 + 0xc) & 0xef;
  if (*(int *)(iVar1 + 0xf4) == 0) {
    uVar10 = FUN_80006724(uVar10,param_2,param_3,param_4,param_5,param_6,param_7,param_8,iVar1,iVar1
                          ,0x56,0,in_r7,in_r8,in_r9,in_r10);
    uVar4 = FUN_80017690(0xd73);
    if (uVar4 == 0) {
      uVar10 = FUN_80006724(uVar10,param_2,param_3,param_4,param_5,param_6,param_7,param_8,iVar1,
                            iVar1,0xd,0,in_r7,in_r8,in_r9,in_r10);
      uVar10 = FUN_80006724(uVar10,param_2,param_3,param_4,param_5,param_6,param_7,param_8,iVar1,
                            iVar1,0x11,0,in_r7,in_r8,in_r9,in_r10);
      FUN_80006724(uVar10,param_2,param_3,param_4,param_5,param_6,param_7,param_8,iVar1,iVar1,0xe,0,
                   in_r7,in_r8,in_r9,in_r10);
      FUN_80080f3c((double)lbl_803E5084,0);
      uVar10 = FUN_80017698(0xd73,1);
    }
    uVar4 = FUN_80017690(0xdca);
    if (uVar4 != 0) {
      uVar10 = FUN_80006724(uVar10,param_2,param_3,param_4,param_5,param_6,param_7,param_8,iVar1,
                            iVar1,0xd,0,in_r7,in_r8,in_r9,in_r10);
      uVar10 = FUN_80006724(uVar10,param_2,param_3,param_4,param_5,param_6,param_7,param_8,iVar1,
                            iVar1,0x7e,0,in_r7,in_r8,in_r9,in_r10);
      FUN_80006724(uVar10,param_2,param_3,param_4,param_5,param_6,param_7,param_8,iVar1,iVar1,0x7d,0
                   ,in_r7,in_r8,in_r9,in_r10);
      FUN_80080f3c((double)lbl_803E5084,1);
      FUN_80017698(0xdca,0);
      FUN_80042b9c(0,0,1);
    }
    *(undefined4 *)(iVar1 + 0xf4) = 1;
  }
  uVar4 = FUN_80017690(0x94f);
  if ((uVar4 != 0) && ((*(ushort *)(iVar2 + 0xb0) & 0x1000) == 0)) {
    FUN_80017698(0x94e,0);
  }
  uVar4 = FUN_80017690(0x94e);
  if ((uVar4 == 0) || (bVar7 = FUN_80294c20(iVar2), bVar7 != 0)) {
    if ((uVar4 == 0) && (bVar7 = FUN_80294c20(iVar2), bVar7 == 0)) {
      iVar2 = FUN_80017a98();
      FUN_80294c30(iVar2,1);
    }
  }
  else {
    iVar2 = FUN_80017a98();
    FUN_80294c30(iVar2,0);
  }
  uVar4 = FUN_80017690(0xd3d);
  if (uVar4 != 0) {
    iVar2 = FUN_80056600();
    iVar3 = *DAT_803dd72c;
    (**(code **)(iVar3 + 0x24))(&local_28,0,iVar2,1);
    uVar10 = FUN_80017698(0xd3d,0);
    uVar10 = FUN_80006724(uVar10,param_2,param_3,param_4,param_5,param_6,param_7,param_8,iVar1,iVar1
                          ,0xd,0,iVar3,in_r8,in_r9,in_r10);
    FUN_80006724(uVar10,param_2,param_3,param_4,param_5,param_6,param_7,param_8,iVar1,iVar1,0x11,0,
                 iVar3,in_r8,in_r9,in_r10);
    FUN_80080f3c((double)lbl_803E5080,1);
  }
  iVar1 = (**(code **)(*DAT_803dd6d0 + 0x10))();
  if (iVar1 == 0x47) {
    if (*(char *)(iVar9 + 0xd) != 'G') {
      FUN_80017698(0xc0,1);
    }
  }
  else if (*(char *)(iVar9 + 0xd) == 'G') {
    FUN_80017698(0x1a8,1);
  }
  uVar8 = (**(code **)(*DAT_803dd6d0 + 0x10))();
  *(undefined *)(iVar9 + 0xd) = uVar8;
  SH_LevelControl_runBloopEvent(iVar9 + 8,4,-1,-1,0x983,(int *)0xb0);
  SH_LevelControl_runBloopEvent(iVar9 + 8,8,-1,-1,0x983,(int *)0x38);
  FUN_801d8480(iVar9 + 8,0x100,-1,-1,0x983,(int *)0x16);
  FUN_801d8480(iVar9 + 8,0x80,-1,-1,0x983,(int *)0x39);
  uVar4 = FUN_80017690(0x983);
  if (uVar4 == 0) {
    uVar4 = FUN_80017690(0xe23);
    if (uVar4 == 0) {
      FUN_801d8480(iVar9 + 8,0x200,-1,-1,0x984,(int *)0xad);
      SH_LevelControl_runBloopEvent(iVar9 + 8,0x40,-1,-1,0x984,(int *)0x16);
    }
    uVar4 = FUN_80017690(0x984);
    if (uVar4 != 0) {
      SH_LevelControl_runBloopEvent(iVar9 + 8,0x20,-1,-1,0xe23,(int *)0x17);
      FUN_801d8480(iVar9 + 8,0x400,-1,-1,0xe23,(int *)0x16);
    }
  }
  SH_LevelControl_runBloopEvent(iVar9 + 8,1,0x1a8,0xc0,0xdb8,(int *)0xae);
  SH_LevelControl_runBloopEvent(iVar9 + 8,0x10,-1,-1,0xe1d,(int *)0x36);
  SH_LevelControl_runBloopEvent(iVar9 + 8,0x1000,-1,-1,0xe1d,(int *)0xf1);
  SH_LevelControl_runBloopEvent(iVar9 + 8,2,-1,-1,0xb46,(int *)0xaf);
  SH_LevelControl_runBloopEvent(iVar9 + 8,0x800,-1,-1,0xcbb,(int *)0xc4);
  FUN_8028688c();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801a522c
 * EN v1.0 Address: 0x801A522C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x801A51AC
 * EN v1.1 Size: 448b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801a522c(int param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_801a5230
 * EN v1.0 Address: 0x801A5230
 * EN v1.0 Size: 496b
 * EN v1.1 Address: 0x801A536C
 * EN v1.1 Size: 472b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801a5230(undefined4 param_1,undefined4 param_2,int param_3,float *param_4)
{
  float fVar1;
  double dVar2;
  undefined2 *puVar3;
  int iVar4;
  int iVar5;
  int iVar6;
  undefined8 uVar7;
  float local_58;
  float local_54;
  float local_50;
  float local_4c;
  float local_48;
  float local_44;
  float local_40;
  float local_3c;
  float local_38;
  undefined4 local_30;
  uint uStack_2c;
  undefined4 local_28;
  uint uStack_24;
  undefined4 local_20;
  uint uStack_1c;
  
  uVar7 = FUN_80286840();
  puVar3 = (undefined2 *)((ulonglong)uVar7 >> 0x20);
  iVar4 = (int)uVar7;
  *(undefined4 *)(puVar3 + 6) = *(undefined4 *)(iVar4 + 8);
  *(undefined4 *)(puVar3 + 8) = *(undefined4 *)(iVar4 + 0xc);
  *(undefined4 *)(puVar3 + 10) = *(undefined4 *)(iVar4 + 0x10);
  fVar1 = lbl_803E5088;
  if (param_3 == 0) {
    *param_4 = lbl_803E5088;
    param_4[1] = fVar1;
    param_4[2] = fVar1;
    local_40 = fVar1;
    local_3c = fVar1;
    local_38 = fVar1;
    iVar5 = **(int **)(*(int *)(puVar3 + 0x3e) + (uint)*(byte *)(iVar4 + 0x18) * 4);
    for (iVar6 = 0; dVar2 = DOUBLE_803e5090, fVar1 = lbl_803E508C,
        uStack_2c = (uint)*(ushort *)(iVar5 + 0xe4), iVar6 < (int)uStack_2c; iVar6 = iVar6 + 1) {
      FUN_800178b8(iVar5,iVar6,&local_4c);
      local_40 = local_4c + local_40;
      local_3c = local_48 + local_3c;
      local_38 = local_44 + local_38;
    }
    local_30 = 0x43300000;
    *param_4 = local_40 *
               (lbl_803E508C / (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e5090));
    uStack_24 = (uint)*(ushort *)(iVar5 + 0xe4);
    local_28 = 0x43300000;
    param_4[1] = local_3c * (fVar1 / (float)((double)CONCAT44(0x43300000,uStack_24) - dVar2));
    uStack_1c = (uint)*(ushort *)(iVar5 + 0xe4);
    local_20 = 0x43300000;
    param_4[2] = local_38 * (fVar1 / (float)((double)CONCAT44(0x43300000,uStack_1c) - dVar2));
  }
  param_4[3] = *param_4;
  param_4[4] = param_4[1];
  param_4[5] = param_4[2];
  FUN_801a5420(puVar3,(int)param_4,iVar4);
  local_58 = *param_4;
  local_54 = param_4[1];
  local_50 = param_4[2];
  FUN_80017744(puVar3,&local_58);
  fVar1 = *(float *)(puVar3 + 4);
  local_58 = local_58 * fVar1;
  local_54 = local_54 * fVar1;
  local_50 = local_50 * fVar1;
  *(undefined *)((int)param_4 + 0x67) = 0xff;
  *(undefined *)((int)param_4 + 0x66) = 0;
  FUN_8028688c();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801a5420
 * EN v1.0 Address: 0x801A5420
 * EN v1.0 Size: 724b
 * EN v1.1 Address: 0x801A5544
 * EN v1.1 Size: 680b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801a5420(undefined2 *param_1,int param_2,int param_3)
{
  float fVar1;
  double dVar2;
  int iVar3;
  uint uVar4;
  float local_48 [2];
  undefined4 local_40;
  uint uStack_3c;
  undefined4 local_38;
  uint uStack_34;
  undefined4 local_30;
  uint uStack_2c;
  undefined4 local_28;
  uint uStack_24;
  undefined4 local_20;
  uint uStack_1c;
  undefined4 local_18;
  uint uStack_14;
  
  local_48[0] = lbl_803E5088;
  *param_1 = *(undefined2 *)(param_3 + 0x1a);
  param_1[1] = *(undefined2 *)(param_3 + 0x1c);
  param_1[2] = *(undefined2 *)(param_3 + 0x1e);
  dVar2 = DOUBLE_803e50a8;
  fVar1 = lbl_803E5098;
  uStack_3c = (int)*(short *)(param_3 + 0x20) ^ 0x80000000;
  local_40 = 0x43300000;
  *(float *)(param_1 + 0x12) =
       (f32)(s32)uStack_3c / lbl_803E5098;
  uStack_34 = (int)*(short *)(param_3 + 0x22) ^ 0x80000000;
  local_38 = 0x43300000;
  *(float *)(param_1 + 0x14) = (float)((double)CONCAT44(0x43300000,uStack_34) - dVar2) / fVar1;
  uStack_2c = (int)*(short *)(param_3 + 0x24) ^ 0x80000000;
  local_30 = 0x43300000;
  *(float *)(param_1 + 0x16) = (float)((double)CONCAT44(0x43300000,uStack_2c) - dVar2) / fVar1;
  uStack_24 = (int)*(short *)(param_3 + 0x2c) ^ 0x80000000;
  local_28 = 0x43300000;
  *(float *)(param_2 + 0x18) = (float)((double)CONCAT44(0x43300000,uStack_24) - dVar2);
  uStack_1c = (int)*(short *)(param_3 + 0x2e) ^ 0x80000000;
  local_20 = 0x43300000;
  *(float *)(param_2 + 0x1c) = (float)((double)CONCAT44(0x43300000,uStack_1c) - dVar2);
  uStack_14 = (int)*(short *)(param_3 + 0x30) ^ 0x80000000;
  local_18 = 0x43300000;
  *(float *)(param_2 + 0x20) = (float)((double)CONCAT44(0x43300000,uStack_14) - dVar2);
  if (*(short *)(param_3 + 0x3a) == 0) {
    FUN_800632d8((double)*(float *)(param_1 + 6),(double)(*(float *)(param_1 + 8) - lbl_803E509C),
                 (double)*(float *)(param_1 + 10),param_1,local_48,0);
    *(float *)(param_2 + 0x54) = *(float *)(param_1 + 8) - local_48[0];
  }
  else {
    *(float *)(param_2 + 0x54) =
         *(float *)(param_1 + 8) +
         (float)((double)CONCAT44(0x43300000,(int)*(short *)(param_3 + 0x3a) ^ 0x80000000) - dVar2);
  }
  dVar2 = DOUBLE_803e50a8;
  fVar1 = lbl_803E509C;
  uStack_14 = (int)*(short *)(param_3 + 0x32) ^ 0x80000000;
  local_18 = 0x43300000;
  *(float *)(param_2 + 0x24) =
       (f32)(s32)uStack_14 / lbl_803E509C;
  uStack_1c = (int)*(short *)(param_3 + 0x34) ^ 0x80000000;
  local_20 = 0x43300000;
  *(float *)(param_2 + 0x28) = (float)((double)CONCAT44(0x43300000,uStack_1c) - dVar2) / fVar1;
  uStack_24 = (int)*(short *)(param_3 + 0x36) ^ 0x80000000;
  local_28 = 0x43300000;
  *(float *)(param_2 + 0x2c) = (float)((double)CONCAT44(0x43300000,uStack_24) - dVar2) / fVar1;
  fVar1 = lbl_803E50A0;
  uStack_2c = (int)*(short *)(param_3 + 0x26) ^ 0x80000000;
  local_30 = 0x43300000;
  *(float *)(param_2 + 0x30) =
       (float)((double)CONCAT44(0x43300000,uStack_2c) - dVar2) / lbl_803E50A0;
  uStack_34 = (int)*(short *)(param_3 + 0x28) ^ 0x80000000;
  local_38 = 0x43300000;
  *(float *)(param_2 + 0x34) = (float)((double)CONCAT44(0x43300000,uStack_34) - dVar2) / fVar1;
  uStack_3c = (int)*(short *)(param_3 + 0x2a) ^ 0x80000000;
  local_40 = 0x43300000;
  *(float *)(param_2 + 0x38) = (float)((double)CONCAT44(0x43300000,uStack_3c) - dVar2) / fVar1;
  *(undefined4 *)(param_2 + 0x58) = 0;
  if (*(short *)(param_3 + 0x38) == 0) {
    *(undefined4 *)(param_2 + 0x5c) = 0xffffffff;
  }
  else {
    uVar4 = randomGetRange(0,100);
    iVar3 = (uint)*(ushort *)(param_3 + 0x38) * (uVar4 + 100);
    iVar3 = iVar3 / 200 + (iVar3 >> 0x1f);
    *(int *)(param_2 + 0x5c) = iVar3 - (iVar3 >> 0x1f);
  }
  return;
}


/* Trivial 4b 0-arg blr leaves. */
void cfforcefield_release(void) {}
void cfforcefield_initialise(void) {}
void slidingdoor_free(void) {}
void slidingdoor_hitDetect(void) {}
void slidingdoor_release(void) {}
void slidingdoor_initialise(void) {}
void attractor_hitDetect(void) {}
void attractor_update(void) {}
void attractor_release(void) {}
void attractor_initialise(void) {}
void cfmagicwall_free(void) {}
void cfmagicwall_hitDetect(void) {}
void cfmagicwall_release(void) {}
void cfmagicwall_initialise(void) {}
void cflevelcontrol_hitDetect(void) {}
void cflevelcontrol_release(void) {}
void cflevelcontrol_initialise(void) {}

extern void storeZeroToFloatParam(void* p);
extern void s16toFloat(void* p, int duration);
extern int CFLevelControl_SeqFn(int p1, int p2, void *p3);
extern void GameBit_Set(int eventId, int value);
extern uint GameBit_Get(int eventId);
extern void objSetSlot(void *obj, int resourceId);
extern s16 lbl_80323008[];
extern int *gMapEventInterface;

#pragma peephole off
#pragma scheduling off
void cflevelcontrol_init(u8* obj, u8* params) {
    u8* sub;
    int i;
    s16* p;

    sub = *(u8**)(obj + 0xb8);
    *(int*)(sub + 8) = 0;
    sub[0xd] = (u8)-1;
    storeZeroToFloatParam(sub);
    s16toFloat(sub, 0x1e0);
    sub[0xc] = (u8)(sub[0xc] & ~0x40);
    *(void**)(obj + 0xbc) = (void*)&CFLevelControl_SeqFn;
    GameBit_Set(0x983, *(int*)(*(int*)(obj + 0x4c) + 0x14) != 0x2cef ? 1 : 0);
    if (GameBit_Get(0x2fe) == 0) {
        p = lbl_80323008;
        for (i = 0; i < 0x17; i++) {
            GameBit_Set(*p, 0);
            p++;
        }
    }
    ((MapEventInterface *)*gMapEventInterface)->setAnimEvent((s8)obj[0xac], 4, 0);
    ((MapEventInterface *)*gMapEventInterface)->setAnimEvent((s8)obj[0xac], 0x11, 0);
    ((MapEventInterface *)*gMapEventInterface)->setAnimEvent((s8)obj[0xac], 0x15, 0);
    ((MapEventInterface *)*gMapEventInterface)->setAnimEvent((s8)obj[0xac], 0x16, 0);
    sub[0xc] = (u8)((sub[0xc] & ~0x20) | (((u8)GameBit_Get(0x974) & 1) << 5));
    sub[0xc] = (u8)((sub[0xc] & ~0x10) | (((u8)GameBit_Get(0x975) & 1) << 4));
    objSetSlot(obj, 0x51);
    sub[0xc] = (u8)(sub[0xc] | 0x08);
}
#pragma scheduling reset
#pragma peephole reset
void exploded_free(void) {}
void exploded_hitDetect(void) {}
void exploded_release(void) {}
void exploded_initialise(void) {}

/* 8b "li r3, N; blr" returners. */
int slidingdoor_getExtraSize(void) { return 0x1; }
int slidingdoor_getObjectTypeId(void) { return 0x0; }
int attractor_getExtraSize(void) { return 0x0; }
int attractor_getObjectTypeId(void) { return 0x0; }
int cfmagicwall_getExtraSize(void) { return 0x0; }
int cfmagicwall_getObjectTypeId(void) { return 0x0; }
int cflevelcontrol_getExtraSize(void) { return 0x10; }
int cflevelcontrol_getObjectTypeId(void) { return 0x0; }
int exploded_getExtraSize(void) { return 0x6c; }

/* Pattern wrappers. */
u8 exploded_setScale(int *obj) { return *(u8*)((char*)((int**)obj)[0xb8/4] + 0x69); }

/* render-with-objRenderFn_8003b8f4 pattern. */
extern f32 lbl_803E43BC;
extern void objRenderFn_8003b8f4(f32);
extern f32 lbl_803E43D0;
extern f32 lbl_803E43D8;
extern f32 lbl_803E43DC;
extern void *Obj_GetPlayerObject(void);
extern f32 Vec_distance(void *a, void *b);
extern f32 Camera_DistanceToCurrentViewPosition(f32 x, f32 y, f32 z);
extern f32 lbl_803E43E8;
extern f32 lbl_803E43F4;
#pragma peephole off
void slidingdoor_render(int p1, int p2, int p3, int p4, int p5, s8 visible) { s32 v = visible; if (v != 0) objRenderFn_8003b8f4(lbl_803E43BC); }
void attractor_render(int p1, int p2, int p3, int p4, int p5, s8 visible) { s32 v = visible; if (v != 0) objRenderFn_8003b8f4(lbl_803E43D0); }
void cfmagicwall_render(int p1, int p2, int p3, int p4, int p5, s8 visible) { s32 v = visible; if (v != 0) objRenderFn_8003b8f4(lbl_803E43D8); }
void cflevelcontrol_render(int p1, int p2, int p3, int p4, int p5, s8 visible) { s32 v = visible; if (v != 0) objRenderFn_8003b8f4(lbl_803E43E8); }
void exploded_render(int p1, int p2, int p3, int p4, int p5, s8 visible) { s32 v = visible; if (v != 0) objRenderFn_8003b8f4(lbl_803E43F4); }
#pragma peephole reset

void cfmagicwall_update(int obj) {
    int data = *(int *)(obj + 0x4c);
    int player = (int)Obj_GetPlayerObject();
    int alpha = 0xff;

    if (GameBit_Get(*(s16 *)(data + 0x20)) != 0) {
        int yaw = (s16)Obj_GetYawDeltaToObject(obj, player, NULL);

        if (yaw < 0) {
            yaw = -yaw;
        }

        if (yaw > 0x4000) {
            *(char *)(obj + 0x36) = 0;
            return;
        }

        {
            f32 playerDistance;
            f32 range;
            f32 fadeDistance;
            range = (f32)(s32)*(s16 *)(data + 0x1a);
            playerDistance = Vec_distance((void *)(obj + 0x18), (void *)(player + 0x18));
            fadeDistance = Camera_DistanceToCurrentViewPosition(
                *(f32 *)(obj + 0xc), *(f32 *)(obj + 0x10), *(f32 *)(obj + 0x14));

            if (fadeDistance < playerDistance) {
                fadeDistance = Camera_DistanceToCurrentViewPosition(
                    *(f32 *)(obj + 0xc), *(f32 *)(obj + 0x10), *(f32 *)(obj + 0x14));
            } else {
                fadeDistance = playerDistance;
            }

            if (fadeDistance < range) {
                alpha = (s32)(lbl_803E43DC * (fadeDistance / range));
            }

            *(char *)(obj + 0x36) = alpha;
        }
    }
}

extern int ObjList_FindObjectById(int objectId);
extern void fn_8017C294(int obj);
extern void Sfx_PlayFromObject(int obj, int sfxId);
extern void getEnvfxActImmediately(void *obj, void *target, int animId, int flags);
extern void skyFn_80088e54(int mode, f32 brightness);
extern void unlockLevel(int a, int b, int c);
extern int playerIsDisguised(int player);
extern void fn_80295CF4(int player, int mode);
extern int getCurMapLayer(void);
extern int *gCameraInterface;
extern int lbl_802C22E8[];
extern f32 lbl_803E43EC;
extern void SCGameBitLatch_Update(void *latch, int mask, int clearIfSetBit, int clearIfClearBit,
                                  int latchBit, int musicId);
extern void SCGameBitLatch_UpdateInverted(void *latch, int mask, int clearIfSetBit,
                                          int clearIfClearBit, int latchBit, int musicId);

void cflevelcontrol_update(int obj) {
    u8 *state = *(u8 **)(obj + 0xb8);
    int player = (int)Obj_GetPlayerObject();
    int triggerPos[3];
    u32 bit974;
    u32 bit975;
    u32 old974;
    u32 bit94e;
    int cameraMode;

    triggerPos[0] = lbl_802C22E8[0];
    triggerPos[1] = lbl_802C22E8[1];
    triggerPos[2] = lbl_802C22E8[2];

    if (((u32)state[0xc] >> 3 & 1) != 0) {
        fn_8017C294(ObjList_FindObjectById(0x47fae));
        fn_8017C294(ObjList_FindObjectById(0x47f83));
        fn_8017C294(ObjList_FindObjectById(0x47f8f));
        fn_8017C294(ObjList_FindObjectById(0x47fa2));
        fn_8017C294(ObjList_FindObjectById(0x29f2));
        fn_8017C294(ObjList_FindObjectById(0x29f3));
        fn_8017C294(ObjList_FindObjectById(0x29ef));
        fn_8017C294(ObjList_FindObjectById(0x29ee));
        state[0xc] = (u8)(state[0xc] & ~0x08);
    }

    if (((MapEventInterface *)*gMapEventInterface)->getMode(0x1d) == 1 &&
        GameBit_Get(0x40) != 0) {
        ((MapEventInterface *)*gMapEventInterface)->setMode(0x1d, 2);
    }

    bit974 = (u8)GameBit_Get(0x974);
    bit975 = (u8)GameBit_Get(0x975);
    old974 = ((u32)state[0xc] >> 5) & 1;

    if (old974 == 0 || (((u32)state[0xc] >> 4) & 1) == 0) {
        if (old974 == 0 && (((u32)state[0xc] >> 4) & 1) == 0) {
            if (bit974 != 0 || bit975 != 0) {
                Sfx_PlayFromObject(0, 0x109);
            }
        } else if (bit974 != 0 && bit975 != 0) {
            Sfx_PlayFromObject(0, 0x7e);
        }
    }

    state[0xc] = (u8)((state[0xc] & ~0x20) | ((bit974 & 1) << 5));
    state[0xc] = (u8)((state[0xc] & ~0x10) | ((bit975 & 1) << 4));

    if (*(int *)(obj + 0xf4) == 0) {
        getEnvfxActImmediately((void *)obj, (void *)obj, 0x56, 0);
        if (GameBit_Get(0xd73) == 0) {
            getEnvfxActImmediately((void *)obj, (void *)obj, 0xd, 0);
            getEnvfxActImmediately((void *)obj, (void *)obj, 0x11, 0);
            getEnvfxActImmediately((void *)obj, (void *)obj, 0xe, 0);
            skyFn_80088e54(0, lbl_803E43EC);
            GameBit_Set(0xd73, 1);
        }

        if (GameBit_Get(0xdca) != 0) {
            getEnvfxActImmediately((void *)obj, (void *)obj, 0xd, 0);
            getEnvfxActImmediately((void *)obj, (void *)obj, 0x7e, 0);
            getEnvfxActImmediately((void *)obj, (void *)obj, 0x7d, 0);
            skyFn_80088e54(1, lbl_803E43EC);
            GameBit_Set(0xdca, 0);
            unlockLevel(0, 0, 1);
        }

        *(int *)(obj + 0xf4) = 1;
    }

    if (GameBit_Get(0x94f) != 0 && (*(u16 *)(player + 0xb0) & 0x1000) == 0) {
        GameBit_Set(0x94e, 0);
    }

    bit94e = GameBit_Get(0x94e);
    if (bit94e != 0) {
        if (playerIsDisguised(player) == 0) {
            fn_80295CF4((int)Obj_GetPlayerObject(), 0);
        }
    } else if (playerIsDisguised(player) == 0) {
        fn_80295CF4((int)Obj_GetPlayerObject(), 1);
    }

    if (GameBit_Get(0xd3d) != 0) {
        ((void (*)(int *, int, int, int))(*(int *)(*gMapEventInterface + 0x24)))(
            triggerPos, 0, getCurMapLayer(), 1);
        GameBit_Set(0xd3d, 0);
        getEnvfxActImmediately((void *)obj, (void *)obj, 0xd, 0);
        getEnvfxActImmediately((void *)obj, (void *)obj, 0x11, 0);
        skyFn_80088e54(1, lbl_803E43E8);
    }

    cameraMode = ((int (*)(void))(*(int *)(*gCameraInterface + 0x10)))();
    if (cameraMode == 0x47) {
        if ((s8)state[0xd] != 0x47) {
            GameBit_Set(0xc0, 1);
        }
    } else if ((s8)state[0xd] == 0x47) {
        GameBit_Set(0x1a8, 1);
    }
    state[0xd] = (s8)((int (*)(void))(*(int *)(*gCameraInterface + 0x10)))();

    SCGameBitLatch_Update(state + 8, 4, -1, -1, 0x983, 0xb0);
    SCGameBitLatch_Update(state + 8, 8, -1, -1, 0x983, 0x38);
    SCGameBitLatch_UpdateInverted(state + 8, 0x100, -1, -1, 0x983, 0x16);
    SCGameBitLatch_UpdateInverted(state + 8, 0x80, -1, -1, 0x983, 0x39);

    if (GameBit_Get(0x983) == 0) {
        if (GameBit_Get(0xe23) == 0) {
            SCGameBitLatch_UpdateInverted(state + 8, 0x200, -1, -1, 0x984, 0xad);
            SCGameBitLatch_Update(state + 8, 0x40, -1, -1, 0x984, 0x16);
        }
        if (GameBit_Get(0x984) != 0) {
            SCGameBitLatch_Update(state + 8, 0x20, -1, -1, 0xe23, 0x17);
            SCGameBitLatch_UpdateInverted(state + 8, 0x400, -1, -1, 0xe23, 0x16);
        }
    }

    SCGameBitLatch_Update(state + 8, 1, 0x1a8, 0xc0, 0xdb8, 0xae);
    SCGameBitLatch_Update(state + 8, 0x10, -1, -1, 0xe1d, 0x36);
    SCGameBitLatch_Update(state + 8, 0x1000, -1, -1, 0xe1d, 0xf1);
    SCGameBitLatch_Update(state + 8, 2, -1, -1, 0xb46, 0xaf);
    SCGameBitLatch_Update(state + 8, 0x800, -1, -1, 0xcbb, 0xc4);
}

/* ObjGroup_RemoveObject(x, N) wrappers. */
#pragma scheduling off
#pragma peephole off
void attractor_free(int x) { ObjGroup_RemoveObject(x, 0x1e); }
#pragma peephole reset
#pragma scheduling reset

/* state encode: ((obj->_X)->_Y << shift) | const. */
u32 exploded_getObjectTypeId(int *obj) { return (*((u8*)((int**)obj)[0x4c/4] + 0x18) << 11) | 0x400; }

/* byte-to-short shift8 pattern. */
#pragma peephole off
void cfmagicwall_init(s16 *dst, void* src) { s8 v = *((s8*)src + 0x18); s16 t = v << 8; *dst = t; }
#pragma peephole reset

/* attractor_setScale: branch on s8 flag at +0x19 of obj->_4C; if set return s16 at +0x1a, else 0. */
#pragma peephole off
int attractor_setScale(int *obj) {
    int *p = (int*)((int**)obj)[0x4c/4];
    if ((s8)*((u8*)p + 0x19) != 0) {
        return *(s16*)((char*)p + 0x1a);
    }
    return 0;
}
#pragma peephole reset

/* attractor_init: ObjGroup_AddObject(obj, 0x1e); byte<<8 -> sth at obj. */
#pragma scheduling off
#pragma peephole off
void attractor_init(s16 *obj, void *data) {
    ObjGroup_AddObject(obj, 0x1e);
    {
        s8 v = *((s8*)data + 0x18);
        s16 t = v << 8;
        *obj = t;
    }
}
#pragma peephole reset
#pragma scheduling reset

/* exploded_update: switch on state at obj->_b8->_69; case 1 calls fn_801A5298. Then countdown timer at _5c/_58 with framesThisStep, updates _36 byte and flags _06. */
extern u8 framesThisStep;
extern int fn_801A5298(s16 *obj, int state);
#pragma scheduling off
#pragma peephole off
void exploded_update(int *obj) {
    int *o = obj;
    int *state = (int*)o[0xb8/4];
    u8 stateVal = *((u8*)state + 0x69);
    int flag;
    switch (stateVal) {
    case 0:
        break;
    case 1:
        if (fn_801A5298((s16 *)o, (int)state) != 0) {
            *((u8*)state + 0x69) = 0;
        }
        break;
    case 2:
        break;
    }
    if (state[0x5c/4] != -1) {
        s32 elapsedFrames = state[0x58/4] + framesThisStep;
        s32 durationFrames;
        state[0x58/4] = elapsedFrames;
        durationFrames = state[0x5c/4];
        if (elapsedFrames >= durationFrames) {
            state[0x5c/4] = -1;
            *((u8*)o + 0x36) = 0;
            *(s16*)((char*)o + 0x6) = (s16)(*(s16*)((char*)o + 0x6) | 0x4000);
            flag = 1;
        } else {
            s32 remainingFrames = durationFrames - state[0x58/4];
            if (remainingFrames < 0xff) {
                *((u8*)o + 0x36) = (u8)remainingFrames;
            }
            flag = 0;
        }
        if (flag != 0) {
            *((u8*)state + 0x69) = 2;
        }
    }
}
#pragma peephole reset
#pragma scheduling reset

extern int fn_801A3E9C(u8* obj, int unused, u8* data);
extern f32 lbl_803E43B8;
extern f32 lbl_803E43C0;
extern f32 lbl_803E4428;
extern void* Obj_GetPlayerObject(void);
extern void* getTrickyObject(void);
extern f32 Vec_xzDistance(f32* a, f32* b);
extern int atan2i(int y, int x);
extern void fn_801A4DB8(int obj, int data, int extra, int sub);
extern void GameBit_Set(int eventId, int value);
extern uint GameBit_Get(int eventId);

/* fn_801A3E9C: slidingdoor "think" routine. Tracks whether the player or
 * tricky is within lbl_803E43B8 xz-distance and steps a 3-bit state field
 * (state[0] bits 5..7) through the door's open/close machine. Returns 1
 * while in the static states (0/1) and 0 while in transition (2/3). */
#pragma scheduling off
int fn_801A3E9C(u8* obj, int unused, u8* data) {
    register int playerNear;
    register int trickyNear;
    register u8* state;
    u8* params;
    u32 mode;
    int result;
    void* player;
    void* tricky;

    player = Obj_GetPlayerObject();
    tricky = getTrickyObject();

    if (player != NULL) {
        playerNear = Vec_xzDistance((f32*)(obj + 0x18), (f32*)((u8*)player + 0x18)) < lbl_803E43B8;
    } else {
        playerNear = 0;
    }

    if (tricky != NULL) {
        trickyNear = Vec_xzDistance((f32*)(obj + 0x18), (f32*)((u8*)tricky + 0x18)) < lbl_803E43B8;
    } else {
        trickyNear = 0;
    }

    state = *(u8**)(obj + 0xb8);
    params = *(u8**)(obj + 0x4c);
    mode = ((u32)state[0] >> 5) & 7;

    if (mode == 0) {
        if (GameBit_Get(*(s16*)(params + 0x18)) != 0 &&
            (*(s16*)(params + 0x22) == -1 ||
             GameBit_Get(*(s16*)(params + 0x22)) != 0)) {
            GameBit_Set(*(s16*)(params + 0x1a), 1);
            if (playerNear != 0 || trickyNear != 0) {
                state[0] = (u8)((state[0] & ~0xe0) | (2 << 5));
            }
        }
    } else if (mode == 1) {
        if ((GameBit_Get(*(s16*)(params + 0x18)) != 0 ||
             (*(s16*)(params + 0x22) != -1 &&
              GameBit_Get(*(s16*)(params + 0x22)) != 0)) &&
            playerNear == 0 && trickyNear == 0) {
            state[0] = (u8)((state[0] & ~0xe0) | (3 << 5));
        }
    }

    {
        register int cur = state[0];
        if (((cur >> 5) & 7) == 2) {
            if (data[0x80] == 2) {
                state[0] = (u8)((cur & ~0xe0) | (1 << 5));
            }
        } else if (((cur >> 5) & 7) == 3) {
            if (data[0x80] == 1) {
                state[0] = (u8)(cur & ~0xe0);
            }
        }
    }

    result = 0;
    {
        u32 m3 = ((u32)state[0] >> 5) & 7;
        if (m3 != 2) {
            if (m3 != 3) result = 1;
        }
    }
    return result;
}
#pragma scheduling reset
/* gObjectTriggerInterface: pointer to a vtable (used for state-machine dispatches). */
extern u32 *gObjectTriggerInterface;

/* slidingdoor_update: triggered-once handler. If obj->_f4 is already set,
 * skip. Otherwise: if data->_1c (event id) is non-zero AND obj->_b8->_0
 * bits 5..7 are set, dispatch vtable[0x15] on the event. Then if
 * (s8)data->_1e is not -1, dispatch vtable[0x12] with the id, obj, -1.
 * Finally latch obj->_f4 = 1. */
#pragma scheduling off
#pragma peephole off
void slidingdoor_update(u8* obj) {
    u8* sub;
    u8* data;
    if (*(s32*)(obj + 0xf4) != 0) return;
    sub = *(u8**)(obj + 0xb8);
    data = *(u8**)(obj + 0x4c);
    if (*(s16*)(data + 0x1c) != 0) {
        u32 mode = (u32)((sub[0] >> 5) & 7);
        if (mode != 0) {
            (*(void (***)(u8*))gObjectTriggerInterface)[0x15](obj);
        }
    }
    {
        s8 id = (s8)data[0x1e];
        if (id != -1) {
            (*(void (***)(s8, u8*, int))gObjectTriggerInterface)[0x12](id, obj, -1);
        }
    }
    *(u32*)(obj + 0xf4) = 1;
}
#pragma peephole reset
#pragma scheduling reset

/* exploded_init: store (s8)data[0x18] at obj->_ad, convert (s8)data[0x3d]
 * to f32 and stash (obj->_50->_04 * raw) / lbl_803E4428 at obj+0x8, then
 * invoke fn_801A4DB8(obj, data, ?, sub). Finally, set sub[0x69] = 1 if any
 * of the 6 halfwords at data+0x20..+0x2a is non-zero, else 0. */
#pragma scheduling off
#pragma peephole off
void exploded_init(u8* obj, u8* data, int extra) {
    u8* sub;
    *(s8*)(obj + 0xad) = (s8)data[0x18];
    sub = *(u8**)(obj + 0xb8);
    *(f32*)(obj + 0x8) = (*(f32*)((char*)(*(u8**)(obj + 0x50)) + 4) * (f32)(s32)(s8)data[0x3d]) / lbl_803E4428;
    fn_801A4DB8((int)obj, (int)data, extra, (int)sub);
    if (*(s16*)(data + 0x20) != 0 ||
        *(s16*)(data + 0x22) != 0 ||
        *(s16*)(data + 0x24) != 0 ||
        *(s16*)(data + 0x26) != 0 ||
        *(s16*)(data + 0x28) != 0 ||
        *(s16*)(data + 0x2a) != 0) {
        sub[0x69] = 1;
    } else {
        sub[0x69] = 0;
    }
}
#pragma peephole reset
#pragma scheduling reset

/* attractor_func0B: dispatch on (s8)obj->_4c->_19 — state 0/3+ store NULL,
 * state 1 stores obj, state 2 computes atan2 of (player - obj) deltas
 * (truncated to int), latches angle+0x8000 into obj+0, then stores obj. */
#pragma scheduling off
#pragma peephole off
void attractor_func0B(u8* obj, void** out) {
    void* result = NULL;
    s8 state = *(s8*)((char*)(*(u8**)(obj + 0x4c)) + 0x19);
    switch (state) {
    case 0:
        break;
    case 1:
        result = obj;
        break;
    case 2: {
        u8* player = (u8*)Obj_GetPlayerObject();
        int angle = atan2i(
            (int)(*(f32*)(player + 0xc) - *(f32*)(obj + 0xc)),
            (int)(*(f32*)(player + 0x14) - *(f32*)(obj + 0x14))
        );
        *(s16*)obj = (s16)(angle + 0x8000);
        result = obj;
        break;
    }
    }
    *out = result;
}
#pragma peephole reset
#pragma scheduling reset

/* slidingdoor_init: clear obj+0xf4, copy data[0x1f]<<8 into obj+0; install
 * fn_801A3E9C as obj->thinkRoutine; convert data[0x21] to f32, scale by
 * lbl_803E43C0 and obj->_50->[4], stash at obj+0x8; then clear bits 5..7 of
 * obj->_b8->_0. */
#pragma scheduling off
#pragma peephole off
void slidingdoor_init(u8* obj, u8* data) {
    typedef struct SlidingDoorSubFlags {
        u8 doorState : 3;
        u8 rest : 5;
    } SlidingDoorSubFlags;
    u8* sub;
    f32 v;
    u32 doorState = 0;
    *(u32*)(obj + 0xf4) = doorState;
    *(s16*)obj = (s16)(data[0x1f] << 8);
    *(int(**)(u8*, int, u8*))(obj + 0xbc) = fn_801A3E9C;
    v = (f32)(u32)data[0x21] * lbl_803E43C0;
    *(f32*)(obj + 0x8) = v;
    *(f32*)(obj + 0x8) = *(f32*)(obj + 0x8) * *(f32*)((char*)(*(u8**)(obj + 0x50)) + 4);
    sub = *(u8**)(obj + 0xb8);
    ((SlidingDoorSubFlags *)sub)->doorState = doorState;
}
#pragma peephole reset
#pragma scheduling reset

/* CFLevelControl_SeqFn: loop through u8 array at +0x81 of param 3; on element==1, do game state setup. */
extern void GameBit_Set(int eventId, int value);
extern void loadMapAndParent(int mapId);
extern void unlockLevel(int a, int b, int c);
extern int mapGetDirIdx(int mapId);
extern void lockLevel(int dirIdx, int b);
#pragma scheduling off
#pragma peephole off
int CFLevelControl_SeqFn(int p1, int p2, void *p3) {
    int i;
    u8 *base = (u8*)p3;
    for (i = 0; i < (int)base[0x8b]; i++) {
        int v = base[0x81 + i];
        switch (v) {
        case 1:
            GameBit_Set(0xdcb, 1);
            GameBit_Set(0x4a3, 0);
            loadMapAndParent(0x2b);
            unlockLevel(0, 0, 1);
            lockLevel(mapGetDirIdx(0x2b), 0);
            break;
        }
    }
    return 0;
}
#pragma peephole reset
#pragma scheduling reset

/* cfforcefield_init: byte<<8 sth; insert GameBit_Get bit into bit-7 of *(u8*)obj->_B8; storeZeroToFloatParam. */
extern uint GameBit_Get(int eventId);
extern void storeZeroToFloatParam(void *p);
#pragma scheduling off
#pragma peephole off
void cfforcefield_init(s16 *obj, void *data) {
    register u8 *flagPtr = (u8*)((int**)obj)[0xb8/4];
    {
        s8 v = *((s8*)data + 0x18);
        s16 t = v << 8;
        *obj = t;
    }
    {
        u32 bitval = (u32)GameBit_Get(*(s16*)((char*)data + 0x20)) & 1;
        flagPtr[0] = (u8)((flagPtr[0] & ~0x80) | (bitval << 7));
    }
    storeZeroToFloatParam(flagPtr + 4);
}
#pragma peephole reset
#pragma scheduling reset

extern void Obj_TransformLocalPointByWorldMatrix(void *obj, void *state, f32 *out, int flags);
extern void fn_80065684(double x, double y, double z, void *obj, f32 *out, int flags);
extern f32 timeDelta;
extern f32 lbl_803E43F0;
extern f32 lbl_803E43F4;
extern f32 lbl_803E4400;
extern f32 lbl_803E4404;
extern f32 lbl_803E4408;
extern f64 lbl_803E4410;
extern f32 lbl_803E4418;
extern f32 lbl_803E441C;
extern f32 lbl_803E4420;
extern f32 lbl_803E4424;

/* Exploded debris setup: seed object angles, linear velocity, angular velocity,
 * ground clearance, and the randomized lifetime countdown. */
#pragma scheduling off
#pragma peephole off
void fn_801A4F90(s16 *obj, int state, int data)
{
  f32 floorY[2];

  floorY[0] = lbl_803E43F0;
  obj[0] = *(s16 *)(data + 0x1a);
  obj[1] = *(s16 *)(data + 0x1c);
  obj[2] = *(s16 *)(data + 0x1e);

  *(f32 *)((char *)obj + 0x24) = (f32)(s32)*(s16 *)(data + 0x20) / lbl_803E4400;
  *(f32 *)((char *)obj + 0x28) = (f32)(s32)*(s16 *)(data + 0x22) / lbl_803E4400;
  *(f32 *)((char *)obj + 0x2c) = (f32)(s32)*(s16 *)(data + 0x24) / lbl_803E4400;
  *(f32 *)(state + 0x18) = (f32)(s32)*(s16 *)(data + 0x2c);
  *(f32 *)(state + 0x1c) = (f32)(s32)*(s16 *)(data + 0x2e);
  *(f32 *)(state + 0x20) = (f32)(s32)*(s16 *)(data + 0x30);

  if (*(s16 *)(data + 0x3a) == 0) {
    fn_80065684((double)*(f32 *)((char *)obj + 0xc),
                (double)(*(f32 *)((char *)obj + 0x10) - lbl_803E4404),
                (double)*(f32 *)((char *)obj + 0x14), obj, floorY, 0);
    *(f32 *)(state + 0x54) = *(f32 *)((char *)obj + 0x10) - floorY[0];
  }
  else {
    *(f32 *)(state + 0x54) =
        *(f32 *)((char *)obj + 0x10) + (f32)(s32)*(s16 *)(data + 0x3a);
  }

  *(f32 *)(state + 0x24) = (f32)(s32)*(s16 *)(data + 0x32) / lbl_803E4404;
  *(f32 *)(state + 0x28) = (f32)(s32)*(s16 *)(data + 0x34) / lbl_803E4404;
  *(f32 *)(state + 0x2c) = (f32)(s32)*(s16 *)(data + 0x36) / lbl_803E4404;
  *(f32 *)(state + 0x30) = (f32)(s32)*(s16 *)(data + 0x26) / lbl_803E4408;
  *(f32 *)(state + 0x34) = (f32)(s32)*(s16 *)(data + 0x28) / lbl_803E4408;
  *(f32 *)(state + 0x38) = (f32)(s32)*(s16 *)(data + 0x2a) / lbl_803E4408;

  *(s32 *)(state + 0x58) = 0;
  if (*(s16 *)(data + 0x38) == 0) {
    *(s32 *)(state + 0x5c) = -1;
  }
  else {
    int lifetime = (u16)*(s16 *)(data + 0x38) * ((int)randomGetRange(0, 100) + 100);
    lifetime = lifetime / 200 + (lifetime >> 31);
    *(s32 *)(state + 0x5c) = lifetime - (lifetime >> 31);
  }
}
#pragma peephole reset
#pragma scheduling reset

/* Exploded debris physics step: integrate local velocity and spin, bounce from
 * the stored floor height, and return nonzero once the shard comes to rest. */
#pragma scheduling off
#pragma peephole off
int fn_801A5298(s16 *obj, int state)
{
  int stopped;
  f32 speed;
  f32 worldBefore[3];
  f32 worldAfter[3];

  stopped = 0;
  Obj_TransformLocalPointByWorldMatrix(obj, (void *)state, worldBefore, 0);
  *(f32 *)((char *)obj + 0x24) =
      timeDelta * *(f32 *)(state + 0x30) + *(f32 *)((char *)obj + 0x24);
  *(f32 *)((char *)obj + 0x28) =
      timeDelta * *(f32 *)(state + 0x34) + *(f32 *)((char *)obj + 0x28);
  *(f32 *)((char *)obj + 0x2c) =
      timeDelta * *(f32 *)(state + 0x38) + *(f32 *)((char *)obj + 0x2c);
  *(f32 *)(state + 0x18) = timeDelta * *(f32 *)(state + 0x24) + *(f32 *)(state + 0x18);
  *(f32 *)(state + 0x1c) = timeDelta * *(f32 *)(state + 0x28) + *(f32 *)(state + 0x1c);
  *(f32 *)(state + 0x20) = timeDelta * *(f32 *)(state + 0x2c) + *(f32 *)(state + 0x20);

  if (*(f32 *)(state + 0x54) <= worldBefore[1]) {
    *(u8 *)(state + 0x66) &= ~0x04;
  }
  else {
    if (((*(f32 *)((char *)obj + 0x28) < lbl_803E43F0) && ((*(u8 *)(state + 0x66) & 4) != 0)) ||
        (lbl_803E43F0 == *(f32 *)((char *)obj + 0x28))) {
      *(f32 *)(state + 0x34) = lbl_803E43F0;
      *(f32 *)(state + 0x2c) = lbl_803E43F0;
      *(f32 *)(state + 0x20) = lbl_803E43F0;
      *(f32 *)(state + 0x28) = lbl_803E43F0;
      *(f32 *)(state + 0x1c) = lbl_803E43F0;
      *(f32 *)(state + 0x24) = lbl_803E43F0;
      *(f32 *)(state + 0x18) = lbl_803E43F0;
      *(f32 *)((char *)obj + 0x28) = lbl_803E43F0;
      *(f32 *)(state + 0x30) = *(f32 *)(state + 0x30) * lbl_803E4418;
      *(f32 *)((char *)obj + 0x24) = *(f32 *)((char *)obj + 0x24) * lbl_803E4418;
      *(f32 *)(state + 0x38) = *(f32 *)(state + 0x38) * lbl_803E4418;
      *(f32 *)((char *)obj + 0x2c) = *(f32 *)((char *)obj + 0x2c) * lbl_803E4418;
      speed = *(f32 *)((char *)obj + 0x24);
      if (speed < lbl_803E43F0) {
        speed = -speed;
      }
      if (speed < lbl_803E441C) {
        speed = *(f32 *)((char *)obj + 0x2c);
        if (speed < lbl_803E43F0) {
          speed = -speed;
        }
        if (speed < lbl_803E441C) {
          stopped = 1;
        }
      }
    }
    if (*(f32 *)((char *)obj + 0x28) < lbl_803E43F0) {
      *(f32 *)((char *)obj + 0x28) = lbl_803E4420 * -*(f32 *)((char *)obj + 0x28);
      *(f32 *)((char *)obj + 0x24) = *(f32 *)((char *)obj + 0x24) * lbl_803E4418;
      *(f32 *)((char *)obj + 0x2c) = *(f32 *)((char *)obj + 0x2c) * lbl_803E4418;
      *(f32 *)(state + 0x34) = lbl_803E4424;
      *(f32 *)(state + 0x2c) = -*(f32 *)(state + 0x2c);
    }
    *(u8 *)(state + 0x66) |= 4;
  }

  obj[0] = (s16)(s32)(*(f32 *)(state + 0x18) * timeDelta + (f32)(s32)obj[0]);
  obj[1] = (s16)(s32)(*(f32 *)(state + 0x1c) * timeDelta + (f32)(s32)obj[1]);
  obj[2] = (s16)(s32)(*(f32 *)(state + 0x20) * timeDelta + (f32)(s32)obj[2]);
  Obj_TransformLocalPointByWorldMatrix(obj, (void *)state, worldAfter, 0);
  *(f32 *)((char *)obj + 0xc) += worldBefore[0] - worldAfter[0];
  *(f32 *)((char *)obj + 0x10) += worldBefore[1] - worldAfter[1];
  *(f32 *)((char *)obj + 0x14) += worldBefore[2] - worldAfter[2];
  *(f32 *)((char *)obj + 0xc) =
      *(f32 *)((char *)obj + 0x24) * timeDelta + *(f32 *)((char *)obj + 0xc);
  *(f32 *)((char *)obj + 0x10) =
      *(f32 *)((char *)obj + 0x28) * timeDelta + *(f32 *)((char *)obj + 0x10);
  *(f32 *)((char *)obj + 0x14) =
      *(f32 *)((char *)obj + 0x2c) * timeDelta + *(f32 *)((char *)obj + 0x14);
  return stopped;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void fn_801A4DB8(int p1, int p2, int flag, int p3)
{
  extern void Model_GetVertexPosition(int, int, f32 *);
  extern void fn_801A4F90(s16 *, int, int);
  extern void fn_800218AC(int, int);
  extern f32 lbl_803E43F0;
  extern f32 lbl_803E43F4;

  *(f32 *)(p1 + 0xc) = *(f32 *)(p2 + 0x8);
  *(f32 *)(p1 + 0x10) = *(f32 *)(p2 + 0xc);
  *(f32 *)(p1 + 0x14) = *(f32 *)(p2 + 0x10);

  if (flag == 0) {
    int *mesh;
    f32 sum[3];
    f32 pos[3];
    int i;

    *(f32 *)(p3 + 0) = lbl_803E43F0;
    *(f32 *)(p3 + 4) = lbl_803E43F0;
    *(f32 *)(p3 + 8) = lbl_803E43F0;
    sum[0] = lbl_803E43F0;
    sum[1] = lbl_803E43F0;
    sum[2] = lbl_803E43F0;

    mesh = *(int **)(*(int *)(*(int *)(p1 + 0x7c) + (u32)*(u8 *)(p2 + 0x18) * 4));
    for (i = 0; i < *(u16 *)((char *)mesh + 0xe4); i++) {
      Model_GetVertexPosition((int)mesh, i, pos);
      sum[0] = pos[0] + sum[0];
      sum[1] = pos[1] + sum[1];
      sum[2] = pos[2] + sum[2];
    }

    *(f32 *)(p3 + 0) = sum[0] * (lbl_803E43F4 / (f32)(u32)*(u16 *)((char *)mesh + 0xe4));
    *(f32 *)(p3 + 4) = sum[1] * (lbl_803E43F4 / (f32)(u32)*(u16 *)((char *)mesh + 0xe4));
    *(f32 *)(p3 + 8) = sum[2] * (lbl_803E43F4 / (f32)(u32)*(u16 *)((char *)mesh + 0xe4));
  }

  *(f32 *)(p3 + 0xc) = *(f32 *)(p3 + 0);
  *(f32 *)(p3 + 0x10) = *(f32 *)(p3 + 4);
  *(f32 *)(p3 + 0x14) = *(f32 *)(p3 + 8);
  fn_801A4F90((s16 *)p1, p3, p2);

  {
    f32 tv[3];
    tv[0] = *(f32 *)(p3 + 0);
    tv[1] = *(f32 *)(p3 + 4);
    tv[2] = *(f32 *)(p3 + 8);
    fn_800218AC(p1, (int)tv);
    tv[0] = tv[0] * *(f32 *)(p1 + 0x8);
    tv[1] = tv[1] * *(f32 *)(p1 + 0x8);
    tv[2] = tv[2] * *(f32 *)(p1 + 0x8);
  }

  *(u8 *)(p3 + 0x67) = 255;
  *(u8 *)(p3 + 0x66) = 0;
}
#pragma peephole reset
#pragma scheduling reset
