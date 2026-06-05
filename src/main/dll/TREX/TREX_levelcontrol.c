#include "ghidra_import.h"
#include "main/dll/TREX/TREX_levelcontrol.h"


#pragma peephole off
#pragma scheduling off
extern undefined4 FUN_8000680c();
extern undefined4 FUN_80006824();
extern undefined4 FUN_800068fc();
extern undefined4 FUN_80006920();
extern undefined4 FUN_800069bc();
extern undefined4 FUN_8001771c();
extern uint FUN_80017730();
extern undefined8 FUN_80017748();
extern u32 randomGetRange(int min, int max);
extern undefined4 FUN_80017a28();
extern int FUN_80017a98();
extern void* FUN_80017aa4();
extern undefined4 FUN_80017ae4();
extern uint FUN_80017ae8();
extern int FUN_80017b00();
extern void ModelLightStruct_free(void *effect);
extern int ObjHits_GetPriorityHit();
extern undefined4 ObjPath_GetPointWorldPosition();
extern undefined4 FUN_8008112c();
extern uint FUN_8028683c();
extern undefined4 FUN_80286888();
extern double FUN_80293900();

extern undefined4 DAT_803dc070;
extern undefined4* gExpgfxInterface;
extern undefined4* DAT_803dd708;
extern f32 lbl_803E6520;
extern f32 lbl_803E6524;
extern f32 lbl_803E6528;
extern f32 lbl_803E652C;
extern f32 lbl_803E6530;
extern f32 lbl_803E6534;
extern f32 lbl_803E6538;
extern f32 lbl_803E653C;
extern f32 lbl_803E6540;
extern f32 lbl_803E6544;

/*
 * --INFO--
 *
 * Function: SB_ShipGun_update
 * EN v1.0 Address: 0x801E34C0
 * EN v1.0 Size: 2312b
 * EN v1.1 Address: 0x801E3AB0
 * EN v1.1 Size: 2132b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
extern u8 *Obj_GetPlayerObject(void);
extern int ObjList_GetObjects(int *outIndex,int *outCount);
extern void spawnExplosion(double scale,int obj,int p3,int p4,int p5,int p6,int p7,int p8,int p9);
extern void Obj_SetModelColorFadeRecursive(int obj,int p2,int p3,int p4,int p5,int p6);
extern int Sfx_PlayFromObject();
extern void Sfx_StopObjectChannel();
extern s16 getAngle(f32 dx,f32 dz);
extern f32 sqrtf(f32);
extern char Obj_IsLoadingLocked(void);
extern void Obj_GetWorldPosition(int obj,float *x,float *y,float *z);
extern void mathFn_80021ac8(void *a,void *b);
extern void *Obj_AllocObjectSetup(int size,int objType);
extern u16 *Obj_SetupObject(void *setup,int p2,int p3,int p4,int p5);
extern void Camera_EnableViewYOffset(void);
extern void CameraShake_SetAllMagnitudes(f32 mag);
extern f32 Vec_distance(float *a,float *b);
extern u8 framesThisStep;
extern undefined4 *gPartfxInterface;
extern f32 lbl_803E5888;
extern f32 lbl_803E588C;
extern f32 lbl_803E5890;
extern f32 lbl_803E5894;
extern f32 lbl_803E5898;
extern f32 lbl_803E589C;
extern f32 lbl_803E58A0;
extern f32 lbl_803E58A4;
extern f32 lbl_803E58A8;
extern f32 lbl_803E58AC;

void SB_ShipGun_update(int obj)
{
  char cVar1;
  float fVar2;
  u8 *player;
  int iVar5;
  int *piVar10;
  int iVar6;
  int iVar7;
  uint uVar8;
  u16 *puVar9;
  int iVar11;
  float local_54 [3];
  float local_58;
  float local_5c;
  float local_60;
  ushort local_68 [4];
  float local_6c;
  float local_70;
  float local_74;
  float local_78;
  float local_7c;
  float local_80;
  int local_84;
  int local_88;
  f32 fdx;
  f32 fdy;
  f32 fdz;
  f32 dist;
  int i;

  player = Obj_GetPlayerObject();
  piVar10 = *(int **)(obj + 0xb8);
  iVar11 = *(int *)(obj + 0x4c);
  if (*(short *)(*(int *)(obj + 0x30) + 0x46) == SB_SHIPGUN_WM_GALLEON_ALIAS_OBJECT_TYPE) {
    *(short *)(*(int *)(obj + 0x54) + 0x60) = *(short *)(*(int *)(obj + 0x54) + 0x60) & ~1;
    *(undefined *)((int)piVar10 + 0xd) = 0;
  }
  else {
    if (*(uint *)piVar10 == 0) {
      iVar5 = ObjList_GetObjects(&local_84,&local_88);
      for (i = local_84; i < local_88; i = i + 1) {
        iVar6 = *(int *)(iVar5 + i * 4);
        if (*(short *)(iVar6 + 0x46) == SB_SHIPGUN_CLOUDRUNNER_ALIAS_OBJECT_TYPE) {
          *piVar10 = iVar6;
          i = local_88;
        }
      }
    }
    iVar5 = *(int *)(obj + 0x30);
    if (((void *)iVar5 != NULL) &&
        (*(short *)(iVar5 + 0x46) == SB_SHIPGUN_GALLEON_ALIAS_OBJECT_TYPE)) {
      iVar6 = (*(code *)(**(int **)(iVar5 + 0x68) + 0x24))(iVar5);
    }
    else {
      iVar6 = 0;
      *(undefined *)((int)piVar10 + 10) = 4;
    }
    *(undefined *)((int)piVar10 + 0xd) = 1;
    cVar1 = *(char *)((int)piVar10 + 10);
    switch (cVar1) {
    case 0:
      if (((void *)iVar5 != NULL) &&
         (iVar5 = (*(code *)(**(int **)(iVar5 + 0x68) + 0x28))(iVar5), iVar5 == 0)) {
        if (*(char *)(iVar11 + 0x19) == '\0') {
          *(undefined *)((int)piVar10 + 10) = 2;
          *(undefined2 *)(piVar10 + 2) = SB_SHIPGUN_WAKE_DELAY;
        }
        else {
          *(undefined *)((int)piVar10 + 10) = 2;
          *(undefined2 *)(piVar10 + 2) = 0;
        }
      }
      *(short *)(*(int *)(obj + 0x54) + 0x60) = *(short *)(*(int *)(obj + 0x54) + 0x60) & ~1;
      break;
    case 2:
      {
          *(short *)(*(int *)(obj + 0x54) + 0x60) = *(short *)(*(int *)(obj + 0x54) + 0x60) | 1;
          iVar11 = (*(code *)(**(int **)(iVar5 + 0x68) + 0x28))(iVar5);
          if ((iVar11 == 0) &&
             (iVar7 = ObjHits_GetPriorityHit(obj,0,0,0), iVar7 != 0)) {
            Obj_SetModelColorFadeRecursive(obj,SB_SHIPGUN_HIT_REACT_TYPE,SB_SHIPGUN_HIT_REACT_POWER,0,0,1);
            Sfx_PlayFromObject(obj,SB_SHIPGUN_HIT_ANIM_A);
            *(s8 *)((int)piVar10 + 0xb) += 1;
            if (*(char *)((int)piVar10 + 0xb) == SB_SHIPGUN_FIRST_DAMAGE_HIT_COUNT) {
              *(s8 *)(piVar10 + 3) -= 1;
              *(undefined *)((int)piVar10 + 10) = 3;
              if ((void *)iVar5 != NULL) {
                (*(code *)(**(int **)(iVar5 + 0x68) + 0x20))(iVar5);
              }
            }
            else if (*(char *)((int)piVar10 + 0xb) == SB_SHIPGUN_SECOND_DAMAGE_HIT_COUNT) {
              Sfx_PlayFromObject(obj,SB_SHIPGUN_HIT_ANIM_B);
              *(s8 *)(piVar10 + 3) -= 1;
              *(undefined *)((int)piVar10 + 10) = 3;
              if ((void *)iVar5 != NULL) {
                (*(code *)(**(int **)(iVar5 + 0x68) + 0x20))(iVar5);
              }
            }
          }
          if (((void *)iVar5 != NULL) && (iVar11 != 0)) {
            *(undefined *)((int)piVar10 + 10) = 3;
          }
          fdx = *(float *)(player + 0x18) - *(float *)(obj + 0x18);
          fdz = *(float *)(player + 0x20) - *(float *)(obj + 0x20);
          *(short *)(piVar10 + 1) = (short)(((uint)(u16)getAngle(-fdz,fdx) & 0xffff) << 1);
          fdy = *(float *)(player + 0x1c) - *(float *)(obj + 0x1c);
          dist = sqrtf(fdx * fdx + fdz * fdz);
          *(short *)((int)piVar10 + 6) = getAngle(-fdy,dist);
          if (*(short *)((int)piVar10 + 6) <= 8000) {
            if (*(short *)((int)piVar10 + 6) < -8000) {
              *(short *)((int)piVar10 + 6) = -8000;
            }
          }
          else {
            *(short *)((int)piVar10 + 6) = 8000;
          }
          *(ushort *)(piVar10 + 2) = *(short *)(piVar10 + 2) - (ushort)framesThisStep;
          if ((*(short *)(piVar10 + 2) < 0) && (Obj_IsLoadingLocked() != '\0')) {
            Obj_GetWorldPosition(obj,&local_78,&local_7c,&local_80);
            local_5c = lbl_803E588C;
            local_58 = lbl_803E588C;
            local_54[0] = lbl_803E588C;
            local_60 = lbl_803E5888;
            local_68[0] = *(ushort *)(piVar10 + 1);
            local_68[1] = 0;
            local_68[2] = 0;
            local_74 = lbl_803E5890;
            local_70 = lbl_803E5894;
            local_6c = lbl_803E588C;
            mathFn_80021ac8(local_68,&local_74);
            iVar11 = (int)Obj_AllocObjectSetup(SB_SHIPGUN_CANNONBALL_ALLOC_SIZE,SB_CANNONBALL_ALIAS_OBJECT_TYPE);
            *(float *)(iVar11 + 8) = local_78;
            *(float *)(iVar11 + 0xc) = local_7c;
            *(float *)(iVar11 + 0x10) = local_80;
            *(undefined *)(iVar11 + 4) = SB_SHIPGUN_CANNONBALL_MODEL_FIELD;
            *(undefined *)(iVar11 + 5) = SB_SHIPGUN_CANNONBALL_FLAGS_FIELD;
            *(undefined *)(iVar11 + 6) = SB_SHIPGUN_CANNONBALL_BYTE_FF;
            *(undefined *)(iVar11 + 7) = SB_SHIPGUN_CANNONBALL_BYTE_FF;
            puVar9 = Obj_SetupObject((void *)iVar11,5,0xffffffff,0xffffffff,0);
            iVar11 = *piVar10;
            fdx = *(float *)(iVar11 + 0x18) - *(float *)(obj + 0x18);
            fdy = *(float *)(iVar11 + 0x1c) - (*(float *)(obj + 0x1c) - lbl_803E5898);
            fdz = *(float *)(iVar11 + 0x20) - *(float *)(obj + 0x20);
            dist = sqrtf(fdz * fdz + (fdx * fdx + fdy * fdy));
            local_78 = lbl_803E589C / dist;
            *(float *)(puVar9 + 0x12) = fdx * local_78;
            *(float *)(puVar9 + 0x14) = fdy * local_78;
            *(float *)(puVar9 + 0x16) = fdz * local_78;
            fVar2 = lbl_803E58A0;
            *(float *)(puVar9 + 6) = fVar2 * *(float *)(puVar9 + 0x12) + *(float *)(puVar9 + 6);
            *(float *)(puVar9 + 8) = fVar2 * *(float *)(puVar9 + 0x14) + *(float *)(puVar9 + 8);
            *(float *)(puVar9 + 10) = fVar2 * *(float *)(puVar9 + 0x16) + *(float *)(puVar9 + 10);
            *puVar9 = getAngle(*(float *)(puVar9 + 0x12),*(float *)(puVar9 + 0x16));
            *(undefined4 *)(puVar9 + 0x7a) = SB_SHIPGUN_CANNONBALL_LIFETIME;
            *(int *)(puVar9 + 0x7c) = *piVar10;
            Camera_EnableViewYOffset();
            CameraShake_SetAllMagnitudes(lbl_803E58A4);
            Sfx_PlayFromObject(obj,SB_SHIPGUN_FIRE_ANIM);
            *(s8 *)((int)piVar10 + 0xe) += 1;
            if (*(char *)((int)piVar10 + 0xe) == SB_SHIPGUN_VOLLEY_SIZE) {
              if (iVar6 < SB_SHIPGUN_FAST_FIRE_GALLEON_PHASE) {
                uVar8 = randomGetRange(0,SB_SHIPGUN_FIRE_DELAY_VARIANCE);
                *(short *)(piVar10 + 2) = (short)uVar8 + SB_SHIPGUN_SLOW_FIRE_DELAY;
              }
              else {
                uVar8 = randomGetRange(0,SB_SHIPGUN_FIRE_DELAY_VARIANCE);
                *(short *)(piVar10 + 2) = (short)uVar8 + SB_SHIPGUN_FAST_FIRE_DELAY;
              }
              *(undefined *)((int)piVar10 + 0xe) = 0;
            }
            else if (iVar6 < SB_SHIPGUN_FAST_FIRE_GALLEON_PHASE) {
              *(undefined2 *)(piVar10 + 2) = SB_SHIPGUN_SLOW_FIRE_DELAY;
            }
            else {
              *(undefined2 *)(piVar10 + 2) = SB_SHIPGUN_FAST_FIRE_DELAY;
            }
          }
      }
      break;
    case 3:
      *(short *)(*(int *)(obj + 0x54) + 0x60) = *(short *)(*(int *)(obj + 0x54) + 0x60) & ~1;
      if (*(char *)(piVar10 + 3) == '\0') {
        spawnExplosion((double)lbl_803E5890,obj,1,1,1,0,1,1,0);
        *(undefined *)((int)piVar10 + 10) = 4;
      }
      else {
        *(undefined *)((int)piVar10 + 10) = 5;
      }
      break;
    case 4:
      {
      local_60 = lbl_803E58A8;
      local_68[3] = SB_SHIPGUN_SMOKE_PARTICLE_FLAGS;
      ObjPath_GetPointWorldPosition(obj,0,&local_5c,&local_58,local_54,0);
      local_5c = local_5c - *(float *)(obj + 0x18);
      local_58 = local_58 - *(float *)(obj + 0x1c);
      local_54[0] = local_54[0] - *(float *)(obj + 0x20);
      for (iVar11 = 0; iVar11 < (int)(uint)framesThisStep; iVar11 = iVar11 + 1) {
        (*(code *)(*gPartfxInterface + 8))(obj,SB_SHIPGUN_SMOKE_PARTICLE_ID,local_68,
                                           SB_SHIPGUN_SMOKE_PARTICLE_PARAM,0xffffffff,0);
      }
      }
      break;
    case 5:
      *(short *)(*(int *)(obj + 0x54) + 0x60) = *(short *)(*(int *)(obj + 0x54) + 0x60) & ~1;
      if (((void *)iVar5 != NULL) &&
         (iVar5 = (*(code *)(**(int **)(iVar5 + 0x68) + 0x28))(iVar5), iVar5 == 0)) {
        if (*(char *)(iVar11 + 0x19) == '\0') {
          if (SB_SHIPGUN_FAST_FIRE_GALLEON_PHASE <= iVar6) {
            *(undefined *)((int)piVar10 + 10) = 2;
            *(undefined2 *)(piVar10 + 2) = SB_SHIPGUN_WAKE_DELAY;
          }
        }
        else if (SB_SHIPGUN_FAST_FIRE_GALLEON_PHASE <= iVar6) {
          *(undefined *)((int)piVar10 + 10) = 2;
          *(undefined2 *)(piVar10 + 2) = 0;
        }
      }
      local_60 = lbl_803E58A8;
      local_68[3] = SB_SHIPGUN_SMOKE_PARTICLE_FLAGS;
      ObjPath_GetPointWorldPosition(obj,0,&local_5c,&local_58,local_54,0);
      local_5c = local_5c - *(float *)(obj + 0x18);
      local_58 = local_58 - *(float *)(obj + 0x1c);
      local_54[0] = local_54[0] - *(float *)(obj + 0x20);
      for (iVar11 = 0; iVar11 < (int)(uint)framesThisStep; iVar11 = iVar11 + 1) {
        (*(code *)(*gPartfxInterface + 8))(obj,SB_SHIPGUN_SMOKE_PARTICLE_ID,local_68,
                                           SB_SHIPGUN_SMOKE_PARTICLE_PARAM,0xffffffff,0);
      }
      break;
    }
    if (*(char *)(piVar10 + 3) == '\0') {
      dist = Vec_distance((float *)(player + 0x18),(float *)(obj + 0x18));
      if (lbl_803E58AC <= dist) {
        Sfx_StopObjectChannel(obj,SB_SHIPGUN_RANGE_FAR_ANIM);
      }
      else {
        Sfx_PlayFromObject(obj,SB_SHIPGUN_RANGE_NEAR_ANIM);
      }
    }
  }
  return;
}


/* Trivial 4b 0-arg blr leaves. */
void SB_CannonBall_release(void) {}
void SB_CannonBall_initialise(void) {}

#pragma scheduling off
#pragma peephole off
void SB_ShipGun_init(int obj)
{
  int state;

  state = *(int *)(obj + 0xb8);
  *(u8 *)(state + 0xd) = 0;
  *(u8 *)(state + 0xc) = SB_SHIPGUN_START_HEALTH;
  *(u8 *)(state + 0xe) = 0;
}
#pragma peephole reset
#pragma scheduling reset

/* 8b "li r3, N; blr" returners. */
int SB_CannonBall_getExtraSize(void) { return SB_CANNONBALL_EXTRA_SIZE; }
int SB_CannonBall_getObjectTypeId(void) { return 0x0; }

#pragma scheduling off
#pragma peephole off
void SB_CannonBall_free(int obj)
{
  int state;

  state = *(int *)(obj + 0xb8);
  (*(void (*)(int))(*(int *)(*gExpgfxInterface + 0x18)))(obj);
  if (*(void **)(state + 0x20) != 0) {
    ModelLightStruct_free(*(void **)(state + 0x20));
    *(undefined4 *)(state + 0x20) = 0;
  }
}
#pragma peephole reset
#pragma scheduling reset

int SB_FireBall_getExtraSize(void) { return SB_FIREBALL_EXTRA_SIZE; }
int SB_FireBall_getObjectTypeId(void) { return 0x0; }

void SB_FireBall_free(int obj)
{
  (*(void (*)(int))(*(int *)(*gExpgfxInterface + 0x18)))(obj);
}

/* render-with-objRenderFn_8003b8f4 pattern. */
extern f32 lbl_803E58B0;
extern void objRenderFn_8003b8f4(f32);
extern f32 lbl_803E58D8;
#pragma peephole off
void SB_CannonBall_render(int p1, int p2, int p3, int p4, int p5, s8 visible) { s32 v = visible; if (v != 0) objRenderFn_8003b8f4(lbl_803E58B0); }
void SB_FireBall_render(int p1, int p2, int p3, int p4, int p5, s8 visible) { s32 v = visible; if (v != 0) objRenderFn_8003b8f4(lbl_803E58D8); }
#pragma peephole reset

extern undefined4 *gPartfxInterface;
extern u8 framesThisStep;
extern f32 timeDelta;
extern f32 lbl_803E58BC;
extern f64 lbl_803E58C0;
extern void Obj_FreeObject(int *obj);
extern void objfx_spawnFlaggedTrailBurst(int *obj, f32 f, int a, int b, int c, int d);
#pragma scheduling off
#pragma peephole off
void SB_CannonBall_update(int *obj) {
    int *state = *(int **)((char *)obj + 0xb8);
    if ((*(s8 *)((char *)state + 0x1a) & SB_CANNONBALL_INITIAL_BURST_FLAG) != 0) {
        (*((void (***)(int *, int, int, int, int, int))gPartfxInterface))[2](obj, SB_CANNONBALL_BURST_PARTICLE_ID, 0, 1, -1, 0);
        (*((void (***)(int *, int, int, int, int, int))gPartfxInterface))[2](obj, SB_CANNONBALL_BURST_PARTICLE_ID, 0, 1, -1, 0);
        (*((void (***)(int *, int, int, int, int, int))gPartfxInterface))[2](obj, SB_CANNONBALL_BURST_PARTICLE_ID, 0, 1, -1, 0);
        *(s8 *)((char *)state + 0x1a) = (s8)(*(s8 *)((char *)state + 0x1a) & ~SB_CANNONBALL_INITIAL_BURST_FLAG);
    } else {
        objfx_spawnFlaggedTrailBurst(obj, lbl_803E58BC, SB_CANNONBALL_SETUP_SIZE, SB_CANNONBALL_SETUP_MODEL_ID, SB_CANNONBALL_SETUP_PARAM, 0);
        objfx_spawnFlaggedTrailBurst(obj, lbl_803E58BC, SB_CANNONBALL_SETUP_SIZE, SB_CANNONBALL_SETUP_MODEL_ID, SB_CANNONBALL_SETUP_PARAM, 0);
    }
    (*((void (***)(int *, int, int, int, int, int))gPartfxInterface))[2](obj, SB_CANNONBALL_TRAIL_PARTICLE_ID, 0, 1, -1, 0);
    *(s16 *)((char *)obj + 2) += SB_CANNONBALL_ROTATION_STEP;
    if ((*(s8 *)((char *)state + 0x1a) & SB_CANNONBALL_TRAJECTORY_INITIALIZED_FLAG) == 0) {
        *(f32 *)state = *(f32 *)((char *)obj + 0x24);
        *(f32 *)((char *)state + 4) = *(f32 *)((char *)obj + 0x28);
        *(f32 *)((char *)state + 8) = *(f32 *)((char *)obj + 0x2c);
        *(s8 *)((char *)state + 0x1a) = (s8)(*(s8 *)((char *)state + 0x1a) | SB_CANNONBALL_TRAJECTORY_INITIALIZED_FLAG);
        *(f32 *)((char *)state + 0xc) = *(f32 *)((char *)obj + 0xc);
        *(f32 *)((char *)state + 0x10) = *(f32 *)((char *)obj + 0x10);
        *(f32 *)((char *)state + 0x14) = *(f32 *)((char *)obj + 0x14);
    }
    {
        f64 scale = lbl_803E58C0;
        *(f32 *)((char *)state + 0xc) = (f32)(scale * (f64)(*(f32 *)state * timeDelta) + (f64)*(f32 *)((char *)state + 0xc));
        *(f32 *)((char *)state + 0x10) = (f32)(scale * (f64)(*(f32 *)((char *)state + 4) * timeDelta) + (f64)*(f32 *)((char *)state + 0x10));
        *(f32 *)((char *)state + 0x14) = (f32)(scale * (f64)(*(f32 *)((char *)state + 8) * timeDelta) + (f64)*(f32 *)((char *)state + 0x14));
    }
    *(f32 *)((char *)obj + 0xc) = *(f32 *)((char *)state + 0xc);
    *(f32 *)((char *)obj + 0x10) = *(f32 *)((char *)state + 0x10);
    *(f32 *)((char *)obj + 0x14) = *(f32 *)((char *)state + 0x14);
    *(int *)((char *)obj + 0xf4) = *(int *)((char *)obj + 0xf4) - (int)framesThisStep;
    if (*(int *)((char *)obj + 0xf4) < 0) {
        Obj_FreeObject(obj);
    }
    if (*(s16 *)((char *)state + 0x18) > SB_CANNONBALL_HITBOX_ENABLE_DELAY) {
        *(u8 *)(*(int *)((char *)obj + 0x54) + 0x6e) = SB_CANNONBALL_HITBOX_TYPE;
        *(u8 *)(*(int *)((char *)obj + 0x54) + 0x6f) = SB_CANNONBALL_HITBOX_PRIORITY;
        *(int *)(*(int *)((char *)obj + 0x54) + 0x48) = SB_CANNONBALL_HITBOX_SIZE;
        *(int *)(*(int *)((char *)obj + 0x54) + 0x4c) = SB_CANNONBALL_HITBOX_SIZE;
        *(s16 *)(*(int *)((char *)obj + 0x54) + 0x60) =
            *(s16 *)(*(int *)((char *)obj + 0x54) + 0x60) | SB_CANNONBALL_SOLID_HITBOX_FLAG;
    } else {
        *(s16 *)(*(int *)((char *)obj + 0x54) + 0x60) =
            *(s16 *)(*(int *)((char *)obj + 0x54) + 0x60) & ~SB_CANNONBALL_SOLID_HITBOX_FLAG;
    }
    *(s16 *)((char *)state + 0x18) += framesThisStep;
}
#pragma peephole reset
#pragma scheduling reset
extern f32 lbl_803E58B4;
extern f32 lbl_803E58B8;
#pragma scheduling off
#pragma peephole off
void SB_CannonBall_hitDetect(int *obj) {
    int *state = *(int **)((char *)obj + 0xb8);
    f32 t = *(f32 *)((char *)state + 0x1c);
    f32 zero = lbl_803E58B4;

    if (t > zero) {
        *(f32 *)((char *)state + 0x1c) = t - timeDelta;
        if (*(f32 *)((char *)state + 0x1c) <= zero) {
            Obj_FreeObject(obj);
        }
        return;
    }

    {
        int *side = *(int **)((char *)obj + 0x54);
        int *target = *(int **)((char *)side + 0x50);
        s16 type;
        if (target == NULL) return;
        type = *(s16 *)((char *)target + 0x46);
        if (type == SB_CLOUDBALL_ALIAS_OBJECT_TYPE) return;
        if (type == SB_CANNONBALL_ALIAS_OBJECT_TYPE) return;
    }

    if (zero != t) return;

    Sfx_PlayFromObject(obj, SB_CANNONBALL_IMPACT_SFX);
    {
        int *p = *(int **)((char *)obj + 0x54);
        *(s16 *)((char *)p + 0x60) = (s16)(*(s16 *)((char *)p + 0x60) & ~SB_CANNONBALL_SOLID_HITBOX_FLAG);
    }
    *(f32 *)((char *)state + 0x1c) = lbl_803E58B8;
    *(u8 *)((char *)obj + 0x36) = SB_CANNONBALL_IMPACT_VISUAL_TIMER;

    {
        int i;
        for (i = SB_CANNONBALL_SMOKE_PARTICLE_COUNT; i != 0; i--) {
            (*((void (***)(int *, int, int, int, int, int))gPartfxInterface))[2](
                obj, SB_CANNONBALL_IMPACT_SMOKE_PARTICLE_ID, 0, 1, -1, 0);
        }
    }
    {
        int i;
        for (i = SB_CANNONBALL_SPARK_PARTICLE_COUNT; i != 0; i--) {
            (*((void (***)(int *, int, int, int, int, int))gPartfxInterface))[2](
                obj, SB_CANNONBALL_IMPACT_SPARK_PARTICLE_ID, 0, 1, -1, 0);
        }
    }
}
#pragma peephole reset
#pragma scheduling reset

extern u8 *objCreateLight(int *obj, int v);
extern void modelLightStruct_setLightKind(u8 *p, int v);
extern void modelLightStruct_setDiffuseColor(u8 *p, int a, int b, int c, int d);
extern void lightSetFieldBC_8001db14(u8 *p, int v);
extern void modelLightStruct_setDistanceAttenuation(u8 *p, f32 a, f32 b);
extern f32 lbl_803E58C8;
extern f32 lbl_803E58CC;
extern f32 lbl_803E58D0;
#pragma scheduling off
#pragma peephole off
void SB_CannonBall_init(int *obj) {
    int *state = *(int **)((char *)obj + 0xb8);
    if (*(u8 **)((char *)state + 0x20) == NULL) {
        *(u8 **)((char *)state + 0x20) = objCreateLight(obj, SB_CANNONBALL_LIGHT_KIND);
        if (*(u8 **)((char *)state + 0x20) != NULL) {
            modelLightStruct_setLightKind(*(u8 **)((char *)state + 0x20), SB_CANNONBALL_LIGHT_FIELD50);
            modelLightStruct_setDiffuseColor(*(u8 **)((char *)state + 0x20), SB_CANNONBALL_LIGHT_RED, SB_CANNONBALL_LIGHT_GREEN, SB_CANNONBALL_LIGHT_BLUE, SB_CANNONBALL_LIGHT_ALPHA);
            lightSetFieldBC_8001db14(*(u8 **)((char *)state + 0x20), SB_CANNONBALL_LIGHT_FIELD_BC);
            modelLightStruct_setDistanceAttenuation(*(u8 **)((char *)state + 0x20), lbl_803E58C8, lbl_803E58CC);
        }
    }
    {
        int *p = *(int **)((char *)obj + 0x54);
        *(s16 *)((char *)p + 0x60) = (s16)(*(s16 *)((char *)p + 0x60) & ~SB_CANNONBALL_SOLID_HITBOX_FLAG);
    }
    *(f32 *)((char *)obj + 0x8) = *(f32 *)((char *)obj + 0x8) * lbl_803E58D0;
    *(s8 *)((char *)state + 0x1a) = (s8)(*(s8 *)((char *)state + 0x1a) | SB_CANNONBALL_INITIAL_BURST_FLAG);
    Sfx_PlayFromObject(obj, SB_CANNONBALL_LAUNCH_SFX);
    Sfx_PlayFromObject(obj, SB_CANNONBALL_LOOP_SFX);
}
#pragma peephole reset
#pragma scheduling reset
