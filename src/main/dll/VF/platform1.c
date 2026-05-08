#include "ghidra_import.h"
#include "main/dll/VF/platform1.h"

extern undefined4 Sfx_SetObjectSfxVolume();
extern undefined4 Sfx_PlayFromObject();
extern undefined4 Sfx_KeepAliveLoopedObjectSound();
extern double FUN_80006b34();
extern byte FUN_80006b44();
extern uint FUN_80006bf8();
extern uint randomGetRange();
extern uint FUN_80017a98();
extern int ObjList_GetObjects();
extern int FUN_8002fc3c();
extern undefined4 ObjAnim_SetCurrentMove();
extern undefined4 FUN_80080eec();
extern undefined4 FUN_8011e800();
extern undefined4 fn_8011F3EC();
extern undefined4 FUN_801de914();
extern uint FUN_80286840();
extern undefined4 FUN_8028688c();
extern u8 *Obj_GetPlayerObject(void);

extern undefined4 DAT_803dc070;
extern undefined4* DAT_803dd6cc;
extern undefined4* DAT_803dd6d0;
extern undefined4* DAT_803dd6d4;
extern undefined4 DAT_803de890;
extern f64 DOUBLE_803e6340;
extern f32 lbl_803DC074;
extern f32 lbl_803E6300;
extern f32 lbl_803E6304;
extern f32 lbl_803E6308;
extern f32 lbl_803E630C;
extern f32 lbl_803E6310;
extern f32 lbl_803E6314;
extern f32 lbl_803E6318;
extern f32 lbl_803E631C;
extern f32 lbl_803E6320;
extern f32 lbl_803E6324;
extern f32 lbl_803E6328;
extern f32 lbl_803E632C;
extern f32 lbl_803E6330;
extern f32 lbl_803E6334;
extern f32 lbl_803E6338;
extern f32 lbl_803E633C;

#define PLATFORM1_OBJECT_TYPE_OFFSET 0x46
#define PLATFORM1_TRACK_VALUE_OFFSET 0x98
#define PLATFORM1_MODEL_ID_OFFSET 0xa0
#define PLATFORM1_STATE_OFFSET 0xb8

#define PLATFORM1_ANCHOR_OBJECT_TYPE 0x3ff
#define PLATFORM1_PEER_OBJECT_TYPE 0x282
#define PLATFORM1_ACTIVE_MODEL_ID 0x401
#define PLATFORM1_IDLE_MODEL_ID 0

#define PLATFORM1_LOOP_SFX_ID 0x3af
#define PLATFORM1_PLAYER_SFX_ID 0x13a
#define PLATFORM1_PLATFORM_SFX_ID 0x4a3

/*
 * --INFO--
 *
 * Function: platform1_control
 * EN v1.0 Address: 0x801DE430
 * EN v1.0 Size: 3368b
 * EN v1.1 Address: 0x801DEA20
 * EN v1.1 Size: 2596b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off
void platform1_control(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                       undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                       undefined4 param_9,undefined4 param_10,int param_11,int param_12,
                       int *param_13,undefined4 param_14,undefined4 param_15,int param_16)
{
  float fVar1;
  uint uVar2;
  uint uVar3;
  int iVar4;
  byte bVar7;
  int iVar5;
  uint uVar6;
  uint *puVar8;
  Platform1State *state;
  double dVar10;
  double dVar11;
  double dVar12;
  double in_f19;
  double in_f20;
  double in_f21;
  double in_f22;
  double dVar13;
  double in_f23;
  double dVar14;
  double in_f24;
  double dVar15;
  double in_f25;
  double dVar16;
  double in_f26;
  double dVar17;
  double in_f27;
  double dVar18;
  double in_f28;
  double dVar19;
  double in_f29;
  double dVar20;
  double in_f30;
  double dVar21;
  double in_f31;
  double dVar22;
  double in_ps19_1;
  double in_ps20_1;
  double in_ps21_1;
  double in_ps22_1;
  double in_ps23_1;
  double in_ps24_1;
  double in_ps25_1;
  double in_ps26_1;
  double in_ps27_1;
  double in_ps28_1;
  double in_ps29_1;
  double in_ps30_1;
  double in_ps31_1;
  int local_128;
  int local_124;
  int local_120;
  int local_11c;
  int *local_118;
  int local_114;
  int *local_110;
  int local_10c;
  int local_108;
  int local_104 [2];
  undefined local_fc;
  undefined4 local_f8;
  uint uStack_f4;
  undefined8 local_f0;
  float local_c8;
  float fStack_c4;
  float local_b8;
  float fStack_b4;
  float local_a8;
  float fStack_a4;
  float local_98;
  float fStack_94;
  float local_88;
  float fStack_84;
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
  local_88 = (float)in_f23;
  fStack_84 = (float)in_ps23_1;
  local_98 = (float)in_f22;
  fStack_94 = (float)in_ps22_1;
  local_a8 = (float)in_f21;
  fStack_a4 = (float)in_ps21_1;
  local_b8 = (float)in_f20;
  fStack_b4 = (float)in_ps20_1;
  local_c8 = (float)in_f19;
  fStack_c4 = (float)in_ps19_1;
  uVar2 = (uint)param_1;
  state = *(Platform1State **)(uVar2 + PLATFORM1_STATE_OFFSET);
  uVar3 = (uint)Obj_GetPlayerObject();
  state->flags = state->flags | PLATFORM1_FLAG_ACTIVE;
  fn_8011F3EC(0xf);
  DAT_803de890 = 0;
  state->linkedObject = 0;
  iVar4 = ObjList_GetObjects(local_104,&local_108);
  while (local_104[0] < local_108) {
    state->linkedObject = *(int *)(iVar4 + local_104[0] * 4);
    local_104[0] = local_104[0] + 1;
    if (*(short *)(state->linkedObject + PLATFORM1_OBJECT_TYPE_OFFSET) == PLATFORM1_ANCHOR_OBJECT_TYPE) {
      local_104[0] = local_108;
    }
  }
  for (iVar4 = 0; fVar1 = lbl_803E6300, iVar4 < (int)(uint)*(byte *)(param_11 + 0x8b);
      iVar4 = iVar4 + 1) {
    bVar7 = *(byte *)(param_11 + iVar4 + 0x81);
    if (bVar7 == 3) {
      iVar5 = ObjList_GetObjects(&local_110,&local_10c);
      puVar8 = (uint *)(iVar5 + (int)local_110 * 4);
      for (; param_12 = local_10c, param_13 = local_110, (int)local_110 < local_10c;
          local_110 = (int *)((int)local_110 + 1)) {
        if ((*puVar8 != uVar2) &&
            (*(short *)(*puVar8 + PLATFORM1_OBJECT_TYPE_OFFSET) == PLATFORM1_PEER_OBJECT_TYPE)) {
          iVar5 = *(int *)(iVar5 + (int)local_110 * 4);
          (**(code **)(**(int **)(iVar5 + 0x68) + 0x20))(iVar5,2);
          break;
        }
        puVar8 = puVar8 + 1;
      }
    }
    else if (bVar7 < 3) {
      if (bVar7 == 1) {
        state->flags = state->flags | PLATFORM1_TRIGGER_FLAG_01;
      }
      else if (bVar7 != 0) {
        state->flags = state->flags | PLATFORM1_TRIGGER_FLAG_02;
        state->transitionStep = 0;
        param_12 = 0;
        param_13 = (int *)*DAT_803dd6d4;
        (*(code *)param_13[0x14])(0x48,3,0);
      }
    }
    else if (bVar7 == 5) {
      if (state->linkedObject != 0) {
        *(float *)(uVar3 + PLATFORM1_TRACK_VALUE_OFFSET) = lbl_803E6300;
        *(float *)(state->linkedObject + PLATFORM1_TRACK_VALUE_OFFSET) = fVar1;
        ObjAnim_SetCurrentMove((double)*(float *)(uVar3 + PLATFORM1_TRACK_VALUE_OFFSET),param_2,param_3,
                     param_4,param_5,param_6,param_7,param_8,uVar3,PLATFORM1_ACTIVE_MODEL_ID,0,
                     param_12,param_13,param_14,param_15,param_16);
        ObjAnim_SetCurrentMove((double)*(float *)(state->linkedObject + PLATFORM1_TRACK_VALUE_OFFSET),param_2,
                     param_3,param_4,param_5,param_6,param_7,param_8,state->linkedObject,
                     PLATFORM1_IDLE_MODEL_ID,0,param_12,param_13,param_14,param_15,param_16);
        state->prevTrackOffset = state->currentTrackOffset;
      }
    }
    else if (bVar7 < 5) {
      iVar5 = ObjList_GetObjects(&local_118,&local_114);
      puVar8 = (uint *)(iVar5 + (int)local_118 * 4);
      for (; param_12 = local_114, param_13 = local_118, (int)local_118 < local_114;
          local_118 = (int *)((int)local_118 + 1)) {
        if ((*puVar8 != uVar2) &&
            (*(short *)(*puVar8 + PLATFORM1_OBJECT_TYPE_OFFSET) == PLATFORM1_PEER_OBJECT_TYPE)) {
          iVar5 = *(int *)(iVar5 + (int)local_118 * 4);
          (**(code **)(**(int **)(iVar5 + 0x68) + 0x20))(iVar5,3);
          break;
        }
        puVar8 = puVar8 + 1;
      }
    }
  }
  if (((state->flags & PLATFORM1_TRIGGER_MASK) != 0) && (0x18 < state->loopSfxHandle)) {
    iVar4 = (**(code **)(*DAT_803dd6d0 + 0x10))();
    if (iVar4 != 0x48) {
      local_104[1] = 3;
      local_fc = 1;
      param_12 = 8;
      param_13 = local_104 + 1;
      param_14 = 0;
      param_15 = 0xff;
      param_16 = *DAT_803dd6d0;
      (**(code **)(param_16 + 0x1c))(0x48,1,3);
    }
    if (*(short *)(uVar3 + PLATFORM1_MODEL_ID_OFFSET) != PLATFORM1_ACTIVE_MODEL_ID) {
      ObjAnim_SetCurrentMove((double)*(float *)(uVar3 + PLATFORM1_TRACK_VALUE_OFFSET),param_2,param_3,
                   param_4,param_5,param_6,param_7,param_8,uVar3,PLATFORM1_ACTIVE_MODEL_ID,0,
                   param_12,param_13,param_14,param_15,param_16);
    }
    iVar4 = state->linkedObject;
    if (*(short *)(iVar4 + PLATFORM1_MODEL_ID_OFFSET) != PLATFORM1_IDLE_MODEL_ID) {
      ObjAnim_SetCurrentMove((double)*(float *)(iVar4 + PLATFORM1_TRACK_VALUE_OFFSET),param_2,param_3,param_4,
                   param_5,param_6,param_7,param_8,iVar4,PLATFORM1_IDLE_MODEL_ID,0,param_12,
                   param_13,param_14,param_15,param_16);
    }
    *(undefined2 *)(param_11 + 0x6e) = 0xffff;
    *(undefined *)(param_11 + 0x56) = 0;
    Sfx_KeepAliveLoopedObjectSound(uVar2,PLATFORM1_LOOP_SFX_ID);
    dVar13 = (double)lbl_803E6304;
    dVar14 = (double)lbl_803E630C;
    dVar15 = (double)lbl_803E6308;
    dVar16 = (double)lbl_803E6310;
    dVar17 = (double)lbl_803E631C;
    dVar18 = (double)lbl_803E6318;
    dVar19 = (double)lbl_803E6314;
    dVar20 = (double)lbl_803E6324;
    dVar21 = (double)lbl_803E6328;
    dVar22 = (double)lbl_803E6334;
    dVar12 = DOUBLE_803e6340;
    for (iVar4 = 0; iVar4 < (int)(uint)DAT_803dc070; iVar4 = iVar4 + 1) {
      if (state->linkedObject == 0) goto LAB_801df3c4;
      uStack_f4 = state->currentTrackOffset + 0xb24U ^ 0x80000000;
      local_f8 = 0x43300000;
      dVar10 = (double)(float)((double)(float)((double)CONCAT44(0x43300000,uStack_f4) - dVar12) /
                              dVar13);
      dVar11 = (double)(float)(dVar14 * dVar10 + dVar15);
      if (dVar11 < dVar16) {
        dVar11 = -dVar11;
      }
      dVar10 = (double)(float)((double)(float)(dVar17 * dVar10 + dVar18) * dVar11 + dVar19);
      uVar6 = FUN_80006bf8(0);
      if (((uVar6 & 0x100) != 0) && (bVar7 = FUN_80006b44(), bVar7 == 0)) {
        state->offsetVelocity = (int)((float)state->offsetVelocity - lbl_803E6320);
      }
      if ((double)(float)state->offsetVelocity < dVar20) {
        state->offsetVelocity = (int)(float)dVar20;
      }
      uVar6 = state->currentTrackOffset;
      if ((-0x46dd < (int)uVar6) && ((int)uVar6 < -0xb23)) {
        state->currentTrackOffset =
            (int)((float)((double)CONCAT44(0x43300000,uVar6 ^ 0x80000000) - DOUBLE_803e6340) +
                  (float)state->offsetVelocity);
      }
      local_f0 = (double)CONCAT44(0x43300000,state->prevTrackOffset ^ 0x80000000);
      uVar6 = state->currentTrackOffset;
      uStack_f4 = uVar6 ^ 0x80000000;
      local_f8 = 0x43300000;
      in_f19 = (double)(float)((double)((float)(local_f0 - dVar12) -
                                       (float)((double)CONCAT44(0x43300000,uStack_f4) - dVar12)) /
                              dVar21);
      if ((int)uVar6 < -0x46dc) {
        state->transitionStep = 0;
        state->flags = state->flags & ~PLATFORM1_TRIGGER_MASK;
        state->flags = state->flags | PLATFORM1_FLAG_EXIT_NEGATIVE;
        iVar4 = ObjList_GetObjects(&local_120,&local_11c);
        puVar8 = (uint *)(iVar4 + local_120 * 4);
        goto LAB_801defcc;
      }
      if (-0xb24 < (int)uVar6) {
        state->transitionStep = 3;
        state->flags = state->flags & ~PLATFORM1_TRIGGER_MASK;
        state->flags = state->flags | PLATFORM1_FLAG_EXIT_POSITIVE;
        iVar4 = ObjList_GetObjects(&local_128,&local_124);
        puVar8 = (uint *)(iVar4 + local_128 * 4);
        goto LAB_801df0d8;
      }
      if (0 < state->loopSfxHandle) {
        (**(code **)(*DAT_803dd6d4 + 0x74))();
      }
      if ((double)(float)state->offsetVelocity < dVar21) {
        state->offsetVelocity =
            (int)(float)((double)lbl_803E6330 * dVar10 + (double)(float)state->offsetVelocity);
      }
      local_f0 = (double)CONCAT44(0x43300000,state->prevTrackOffset ^ 0x80000000);
      uStack_f4 = state->currentTrackOffset ^ 0x80000000;
      local_f8 = 0x43300000;
      iVar5 = FUN_8002fc3c((double)(float)((double)((float)(local_f0 - dVar12) -
                                                   (float)((double)CONCAT44(0x43300000,uStack_f4) -
                                                          dVar12)) / dVar22),(double)lbl_803DC074)
      ;
      if ((iVar5 != 0) && (*(float *)(uVar3 + PLATFORM1_TRACK_VALUE_OFFSET) < lbl_803E6310)) {
        *(float *)(uVar3 + PLATFORM1_TRACK_VALUE_OFFSET) =
            lbl_803E6314 + *(float *)(uVar3 + PLATFORM1_TRACK_VALUE_OFFSET);
      }
      local_f0 = (double)CONCAT44(0x43300000,state->currentTrackOffset ^ 0x80000000);
      uStack_f4 = state->prevTrackOffset ^ 0x80000000;
      local_f8 = 0x43300000;
      iVar5 = FUN_8002fc3c((double)(float)((double)((float)(local_f0 - dVar12) -
                                                   (float)((double)CONCAT44(0x43300000,uStack_f4) -
                                                          dVar12)) / dVar22),(double)lbl_803DC074)
      ;
      if (iVar5 != 0) {
        fVar1 = *(float *)(state->linkedObject + PLATFORM1_TRACK_VALUE_OFFSET);
        if (fVar1 < lbl_803E6310) {
          *(float *)(state->linkedObject + PLATFORM1_TRACK_VALUE_OFFSET) = lbl_803E6314 + fVar1;
        }
      }
      state->prevTrackOffset = state->currentTrackOffset;
    }
    state->playerSfxTimer = (int)((float)state->playerSfxTimer - lbl_803DC074);
    if ((double)(float)state->playerSfxTimer < (double)lbl_803E6310) {
      if ((double)lbl_803E6310 <= in_f19) {
        uVar6 = randomGetRange(0x78,0xf0);
        local_f0 = (double)CONCAT44(0x43300000,uVar6 ^ 0x80000000);
        state->playerSfxTimer = (int)(float)(local_f0 - DOUBLE_803e6340);
      }
      else {
        uVar6 = randomGetRange(0x28,100);
        local_f0 = (double)CONCAT44(0x43300000,uVar6 ^ 0x80000000);
        state->playerSfxTimer = (int)(float)(local_f0 - DOUBLE_803e6340);
      }
      Sfx_PlayFromObject(uVar3,PLATFORM1_PLAYER_SFX_ID);
    }
    state->platformSfxTimer = (int)((float)state->platformSfxTimer - lbl_803DC074);
    if ((double)(float)state->platformSfxTimer < (double)lbl_803E6310) {
      if (in_f19 <= (double)lbl_803E6310) {
        uVar3 = randomGetRange(0x78,0xf0);
        local_f0 = (double)CONCAT44(0x43300000,uVar3 ^ 0x80000000);
        state->platformSfxTimer = (int)(float)(local_f0 - DOUBLE_803e6340);
      }
      else {
        uVar3 = randomGetRange(0x28,100);
        local_f0 = (double)CONCAT44(0x43300000,uVar3 ^ 0x80000000);
        state->platformSfxTimer = (int)(float)(local_f0 - DOUBLE_803e6340);
      }
      Sfx_PlayFromObject(uVar2,PLATFORM1_PLATFORM_SFX_ID);
    }
    if (in_f19 < (double)lbl_803E6310) {
      in_f19 = -in_f19;
    }
    iVar4 = (int)((double)lbl_803E6338 * in_f19);
    local_f0 = (double)(longlong)iVar4;
    if (100 < iVar4) {
      iVar4 = 100;
    }
    Sfx_SetObjectSfxVolume((double)lbl_803E633C,uVar2,PLATFORM1_LOOP_SFX_ID,(byte)iVar4);
  }
LAB_801df3c4:
  return;
LAB_801defcc:
  if (local_11c <= local_120) goto LAB_801defd8;
  if ((*puVar8 != uVar2) &&
      (*(short *)(*puVar8 + PLATFORM1_OBJECT_TYPE_OFFSET) == PLATFORM1_PEER_OBJECT_TYPE)) {
    iVar4 = *(int *)(iVar4 + local_120 * 4);
    (**(code **)(**(int **)(iVar4 + 0x68) + 0x20))(iVar4,4);
    goto LAB_801defd8;
  }
  puVar8 = puVar8 + 1;
  local_120 = local_120 + 1;
  goto LAB_801defcc;
LAB_801defd8:
  dVar12 = FUN_80006b34();
  local_f0 = (double)(longlong)(int)(dVar12 / (double)lbl_803E632C);
  FUN_801de914();
  FUN_8011e800(0);
  if (0 < state->loopSfxHandle) {
    FUN_80080eec(state->loopSfxHandle);
  }
  (**(code **)(*DAT_803dd6cc + 0xc))(0x14,1);
  DAT_803de890 = 2;
  goto LAB_801df3c4;
LAB_801df0d8:
  if (local_124 <= local_128) goto LAB_801df0e4;
  if ((*puVar8 != uVar2) &&
      (*(short *)(*puVar8 + PLATFORM1_OBJECT_TYPE_OFFSET) == PLATFORM1_PEER_OBJECT_TYPE)) {
    iVar4 = *(int *)(iVar4 + local_128 * 4);
    (**(code **)(**(int **)(iVar4 + 0x68) + 0x20))(iVar4,4);
    goto LAB_801df0e4;
  }
  puVar8 = puVar8 + 1;
  local_128 = local_128 + 1;
  goto LAB_801df0d8;
LAB_801df0e4:
  FUN_8011e800(0);
  if (0 < state->loopSfxHandle) {
    FUN_80080eec(state->loopSfxHandle);
  }
  (**(code **)(*DAT_803dd6cc + 0xc))(0x14,1);
  DAT_803de890 = 2;
  goto LAB_801df3c4;
}
#pragma peephole reset
#pragma scheduling reset


/* Trivial 4b 0-arg blr leaves. */
void sc_totemstrength_free(void) {}
void sc_totemstrength_hitDetect(void) {}
void sc_totemstrength_release(void) {}
void sc_totemstrength_initialise(void) {}
void paymentkiosk_free(void) {}
void paymentkiosk_hitDetect(void) {}

/* 8b "li r3, N; blr" returners. */
int sc_totemstrength_getExtraSize(void) { return 0x34; }
int sc_totemstrength_func08(void) { return 0x0; }
int paymentkiosk_getExtraSize(void) { return 0x3; }
int paymentkiosk_func08(void) { return 0x1; }

/* render-with-fn(lbl) (no visibility check). */
extern f32 lbl_803E567C;
extern void fn_8003B8F4(f32);
#pragma scheduling off
#pragma peephole off
void sc_totemstrength_render(void) { fn_8003B8F4(lbl_803E567C); }
#pragma peephole reset
#pragma scheduling reset
