#include "ghidra_import.h"
#include "main/game_object.h"
#include "main/audio/sfx_ids.h"
#include "main/dll/wallanimator.h"
#include "main/objanim.h"
#include "main/objanim_internal.h"
#include "main/objhits_types.h"


extern undefined4 FUN_80006824();
extern undefined4 FUN_80006b14();
extern undefined4 FUN_800175cc();
extern undefined4 FUN_80017620();
extern u32 randomGetRange(int min, int max);
extern undefined4 FUN_80017a98();
extern int FUN_80017af8();
extern undefined4 FUN_800305f8();
extern undefined4 ObjHitbox_SetSphereRadius();
extern undefined4 ObjHits_DisableObject();
extern undefined4 FUN_8003b818();
extern undefined4 FUN_8008112c();
extern undefined8 FUN_80286840();
extern undefined4 FUN_8028688c();
extern void objRenderFn_8003b8f4(double scale);
extern void queueGlowRender(void *light);

extern undefined4* DAT_803dd708;
extern undefined4* DAT_803dd70c;
extern undefined4* DAT_803dd738;
extern undefined4 DAT_803de710;
extern f64 DOUBLE_803e3d08;
extern f64 DOUBLE_803e3d80;
extern f32 lbl_803DC074;
extern f32 lbl_803E3CF8;
extern f32 lbl_803E3D14;
extern f32 lbl_803E3D38;
extern f32 lbl_803E3D3C;
extern f32 lbl_803E3D60;
extern f32 lbl_803E3D64;
extern f32 lbl_803E3D68;
extern f32 lbl_803E3D6C;
extern f32 lbl_803E3D70;
extern f32 lbl_803E3D78;
extern f32 timeDelta;
extern f32 lbl_803E30D0;
extern f32 lbl_803E30D4;
extern f32 lbl_803E30D8;
extern f32 lbl_803E30E0;

extern int ObjList_FindObjectById(int id);

typedef struct KaldaChompMeState {
    f32 progress;
    f32 step;
    f32 targetProgress;
    u8 moveId;
    u8 pad0D[3];
} KaldaChompMeState;

/*
 * --INFO--
 *
 * Function: kaldachompme_setLinkedMouthMode
 * EN v1.0 Address: 0x80169360
 * EN v1.0 Size: 556b
 */
#pragma scheduling off
#pragma peephole off
void kaldachompme_setLinkedMouthMode(u8 *obj, u8 mode)
{
    KaldaChompMeState *state;
    int obj2;

    if (obj == NULL) {
        return;
    }
    switch (*(int *)(*(int *)&((GameObject *)obj)->anim.placementData + 0x14)) {
    case 0x43d14:
        obj2 = ObjList_FindObjectById(0x4b3b5);
        break;
    case 0x41be9:
        obj2 = ObjList_FindObjectById(0x4b3f9);
        break;
    case 0x41cc4:
        obj2 = ObjList_FindObjectById(0x4b402);
        break;
    case 0x41cc5:
        obj2 = ObjList_FindObjectById(0x4b403);
        break;
    case 0x41cc6:
        obj2 = ObjList_FindObjectById(0x4b404);
        break;
    case 0x41cc7:
        obj2 = ObjList_FindObjectById(0x4b40b);
        break;
    case 0x41cc8:
        obj2 = ObjList_FindObjectById(0x4b40c);
        break;
    case 0x41cc9:
        obj2 = ObjList_FindObjectById(0x4b40f);
        break;
    case 0x41cd2:
        obj2 = ObjList_FindObjectById(0x4b410);
        break;
    case 0x41ccc:
        obj2 = ObjList_FindObjectById(0x4b411);
        break;
    case 0x41cd5:
        obj2 = ObjList_FindObjectById(0x4b414);
        break;
    case 0x41cd6:
        obj2 = ObjList_FindObjectById(0x4b415);
        break;
    case 0x41cd9:
        obj2 = ObjList_FindObjectById(0x4b453);
        break;
    default:
        return;
    }
    state = *(KaldaChompMeState **)(obj2 + 0xb8);
    if (state != NULL) {
        switch (mode) {
        case 1:
            state->targetProgress = lbl_803E30D0;
            state->progress = lbl_803E30D4;
            state->step = lbl_803E30D8;
            state->moveId = 0;
            break;
        case 2:
            state->targetProgress = lbl_803E30D0;
            state->progress = lbl_803E30D4;
            state->step = lbl_803E30D8;
            state->moveId = 1;
            break;
        }
    }
}
#pragma peephole reset
#pragma scheduling reset

int kaldachompme_getExtraSize(void)
{
  return 0x10;
}

int kaldachompme_getObjectTypeId(void)
{
  return 0;
}

void kaldachompme_free(void)
{
}

#pragma peephole off
void kaldachompme_render(undefined4 param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,
                         undefined4 param_5,s8 renderFlag)
{
  s32 v = renderFlag;
  if (v != 0) {
    objRenderFn_8003b8f4(lbl_803E30D0);
  }
}
#pragma peephole reset

void kaldachompme_hitDetect(void)
{
}

#pragma scheduling off
#pragma peephole off
void kaldachompme_update(int obj)
{
  float target;
  float current;
  float step;
  KaldaChompMeState *extra;

  extra = ((GameObject *)obj)->extra;
  current = extra->progress;
  target = extra->targetProgress;
  if (current != target) {
    step = extra->step;
    if (step > lbl_803E30D4) {
      if (current < target) {
        extra->progress = current + step * timeDelta;
      }
      else {
        extra->progress = target;
      }
    }
    else {
      if (current > target) {
        extra->progress = current + step * timeDelta;
      }
      else {
        extra->progress = target;
      }
    }
  }
  ObjAnim_SetCurrentMove(obj,extra->moveId,extra->progress,0);
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void kaldachompme_init(int obj,int params)
{
  ((GameObject *)obj)->anim.rotZ = (s16)(*(u8 *)(params + 0x18) << 8);
  ((GameObject *)obj)->anim.rotY = (s16)(*(u8 *)(params + 0x19) << 8);
  ((GameObject *)obj)->anim.rotX = (s16)(*(u8 *)(params + 0x1a) << 8);
  ((GameObject *)obj)->unkB0 = (u16)(((GameObject *)obj)->unkB0 | 0x2000);
  ObjAnim_SetCurrentMove(obj,0,lbl_803E30D4,0);
}
#pragma peephole reset
#pragma scheduling reset

void kaldachompme_release(void)
{
}

void kaldachompme_initialise(void)
{
}

ObjectDescriptor gKaldaChompMeObjDescriptor = {
    0, 0, 0, OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)kaldachompme_initialise,
    (ObjectDescriptorCallback)kaldachompme_release,
    0,
    (ObjectDescriptorCallback)kaldachompme_init,
    (ObjectDescriptorCallback)kaldachompme_update,
    (ObjectDescriptorCallback)kaldachompme_hitDetect,
    (ObjectDescriptorCallback)kaldachompme_render,
    (ObjectDescriptorCallback)kaldachompme_free,
    (ObjectDescriptorCallback)kaldachompme_getObjectTypeId,
    kaldachompme_getExtraSize,
};

/*
 * --INFO--
 *
 * Function: FUN_801695e8
 * EN v1.0 Address: 0x801695E8
 * EN v1.0 Size: 548b
 * EN v1.1 Address: 0x8016980C
 * EN v1.1 Size: 576b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801695e8(int param_1,byte param_2)
{
  float *pfVar1;
  int iVar2;
  
  if (param_1 == 0) {
    return;
  }
  iVar2 = *(int *)(*(int *)(param_1 + 0x4c) + 0x14);
  if (iVar2 == 0x41ccc) {
    iVar2 = FUN_80017af8(0x4b411);
  }
  else if (iVar2 < 0x41ccc) {
    if (iVar2 == 0x41cc6) {
      iVar2 = FUN_80017af8(0x4b404);
    }
    else if (iVar2 < 0x41cc6) {
      if (iVar2 == 0x41cc4) {
        iVar2 = FUN_80017af8(0x4b402);
      }
      else if (iVar2 < 0x41cc4) {
        if (iVar2 != 0x41be9) {
          return;
        }
        iVar2 = FUN_80017af8(0x4b3f9);
      }
      else {
        iVar2 = FUN_80017af8(0x4b403);
      }
    }
    else if (iVar2 == 0x41cc9) {
      iVar2 = FUN_80017af8(0x4b40f);
    }
    else {
      if (0x41cc8 < iVar2) {
        return;
      }
      if (iVar2 < 0x41cc8) {
        iVar2 = FUN_80017af8(0x4b40b);
      }
      else {
        iVar2 = FUN_80017af8(0x4b40c);
      }
    }
  }
  else if (iVar2 == 0x41cd6) {
    iVar2 = FUN_80017af8(0x4b415);
  }
  else if (iVar2 < 0x41cd6) {
    if (iVar2 == 0x41cd2) {
      iVar2 = FUN_80017af8(0x4b410);
    }
    else {
      if (iVar2 < 0x41cd2) {
        return;
      }
      if (iVar2 < 0x41cd5) {
        return;
      }
      iVar2 = FUN_80017af8(0x4b414);
    }
  }
  else if (iVar2 == 0x43d14) {
    iVar2 = FUN_80017af8(0x4b3b5);
  }
  else {
    if (0x43d13 < iVar2) {
      return;
    }
    if (iVar2 != 0x41cd9) {
      return;
    }
    iVar2 = FUN_80017af8(0x4b453);
  }
  pfVar1 = *(float **)(iVar2 + 0xb8);
  if (pfVar1 != (float *)0x0) {
    if (param_2 == 2) {
      pfVar1[2] = lbl_803E3D68;
      *pfVar1 = lbl_803E3D6C;
      pfVar1[1] = lbl_803E3D70;
      *(undefined *)(pfVar1 + 3) = 1;
    }
    else if ((param_2 < 2) && (param_2 != 0)) {
      pfVar1[2] = lbl_803E3D68;
      *pfVar1 = lbl_803E3D6C;
      pfVar1[1] = lbl_803E3D70;
      *(undefined *)(pfVar1 + 3) = 0;
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8016980c
 * EN v1.0 Address: 0x8016980C
 * EN v1.0 Size: 40b
 * EN v1.1 Address: 0x80169A4C
 * EN v1.1 Size: 52b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8016980c(int param_1,int param_2,int param_3,int param_4,int param_5,s8 visible)
{
  if (visible != 0) {
    FUN_8003b818(param_1);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80169834
 * EN v1.0 Address: 0x80169834
 * EN v1.0 Size: 300b
 * EN v1.1 Address: 0x80169A80
 * EN v1.1 Size: 140b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80169834(undefined8 param_1,undefined8 param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9,undefined4 param_10,undefined4 param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)
{
  float fVar1;
  float *pfVar2;
  double dVar3;
  double dVar4;
  
  pfVar2 = *(float **)(param_9 + 0xb8);
  dVar4 = (double)*pfVar2;
  fVar1 = pfVar2[2];
  dVar3 = (double)fVar1;
  if (dVar4 != dVar3) {
    param_3 = (double)pfVar2[1];
    if (param_3 <= (double)lbl_803E3D6C) {
      if (dVar4 <= dVar3) {
        *pfVar2 = fVar1;
      }
      else {
        *pfVar2 = (float)(param_3 * (double)lbl_803DC074 + dVar4);
      }
    }
    else if (dVar3 <= dVar4) {
      *pfVar2 = fVar1;
    }
    else {
      *pfVar2 = (float)(param_3 * (double)lbl_803DC074 + dVar4);
    }
  }
  FUN_800305f8((double)*pfVar2,dVar4,param_3,param_4,param_5,param_6,param_7,param_8,param_9,
               (uint)*(byte *)(pfVar2 + 3),0,param_12,param_13,param_14,param_15,param_16);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80169960
 * EN v1.0 Address: 0x80169960
 * EN v1.0 Size: 228b
 * EN v1.1 Address: 0x80169B0C
 * EN v1.1 Size: 116b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80169960(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 short *param_9,int param_10,undefined4 param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)
{
  param_9[2] = (ushort)*(byte *)(param_10 + 0x18) << 8;
  param_9[1] = (ushort)*(byte *)(param_10 + 0x19) << 8;
  *param_9 = (ushort)*(byte *)(param_10 + 0x1a) << 8;
  param_9[0x58] = param_9[0x58] | 0x2000;
  FUN_800305f8((double)lbl_803E3D6C,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
               param_9,0,0,param_12,param_13,param_14,param_15,param_16);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80169a44
 * EN v1.0 Address: 0x80169A44
 * EN v1.0 Size: 448b
 * EN v1.1 Address: 0x80169B80
 * EN v1.1 Size: 328b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80169a44(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 uint param_9)
{
  uint uVar1;
  int *piVar2;
  int local_18 [2];
  undefined4 local_10;
  uint uStack_c;
  
  piVar2 = *(int **)(param_9 + 0xb8);
  *(undefined *)(param_9 + 0x36) = 0;
  *(undefined4 *)(param_9 + 0xf4) = 0xdc;
  (*(ObjHitsPriorityState **)(param_9 + 0x54))->flags &= ~1;
  if (*piVar2 != 0) {
    FUN_800175cc((double)lbl_803E3D78,*piVar2,'\0');
  }
  if (*(short *)(param_9 + 0x46) == 0x869) {
    uVar1 = randomGetRange(0,1);
    uStack_c = randomGetRange(0x32,0x3c);
    FUN_8008112c((double)(float)((double)CONCAT44(0x43300000,uStack_c) - DOUBLE_803e3d80),param_2,
                 param_3,param_4,param_5,param_6,param_7,param_8,param_9,1,1,0,uVar1 & 0xff,0,1,0);
  }
  else {
    for (local_18[0] = 0; local_18[0] < 0x19; local_18[0] = local_18[0] + 1) {
      (**(code **)(*DAT_803dd708 + 8))(param_9,0x715,0,1,0xffffffff,local_18);
    }
    FUN_80006824(param_9,SFXsc_attack03);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80169c04
 * EN v1.0 Address: 0x80169C04
 * EN v1.0 Size: 48b
 * EN v1.1 Address: 0x80169CC8
 * EN v1.1 Size: 48b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80169c04(int param_1)
{
  if (**(uint **)(param_1 + 0xb8) != 0) {
    FUN_80017620(**(uint **)(param_1 + 0xb8));
  }
  return;
}


/* Trivial 4b 0-arg blr leaves. */
void kaldachompspit_hitDetect(void) {}

/* 8b "li r3, N; blr" returners. */
int kaldachompspit_getExtraSize(void) { return 0x4; }
int kaldachompspit_getObjectTypeId(void) { return 0x0; }

extern void ModelLightStruct_free(void *p);
#pragma scheduling off
#pragma peephole off
void kaldachompspit_free(int *obj) {
    void *p = *(void **)((GameObject *)obj)->extra;
    if (p != NULL) {
        ModelLightStruct_free(p);
    }
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void kaldachompspit_render(void *obj, int p2, int p3, int p4, int p5, s8 visible)
{
    u8 *light = **(u8 ***)&((GameObject *)obj)->extra;
    if (light != NULL && light[0x2f8] != 0 && light[0x4c] != 0) {
        queueGlowRender(light);
    }
    if (visible != 0) {
        ((void (*)(void *, int, int, int, int, f32))objRenderFn_8003b8f4)(obj, p2, p3, p4, p5, lbl_803E30E0);
    }
}
#pragma peephole reset
#pragma scheduling reset

extern void modelLightStruct_setEnabled(int light, int onoff, f32 intensity);
extern void spawnExplosion(int obj, f32 scale, int a, int b, int c, int d, int e, int f, int g);
extern void Sfx_PlayFromObject(int obj, u32 sfxId);
extern void Sfx_StopObjectChannel(int obj, int channel);
extern void Sfx_SetObjectChannelVolume(int obj, int channel, u8 vol, f32 scale);
extern int Obj_FreeObject(int obj);
extern int objMove(int obj, f32 vx, f32 vy, f32 vz);
extern int ObjHits_SetHitVolumeSlot(int obj, int volumeIdx, int hitType, int extra);
extern void ObjHits_EnableObject(int obj);
extern int getAngle(f32 a, f32 b);
extern f32 sqrtf(f32 x);
extern int Obj_GetPlayerObject(void);
extern int getTrickyObject(void);
extern void fn_80098B18(int obj, f32 scale, int a, int b, int c, int d);
extern int *gPartfxInterface;
extern f64 lbl_803E30E8;
extern f32 lbl_803E30F0;
extern f32 lbl_803E30F4;
extern f32 lbl_803E30F8;
extern f32 lbl_803E30FC;
extern f64 lbl_803E3100;
void kaldachompspit_burst(int obj);

/*
 * --INFO--
 *
 * Function: kaldachompspit_update
 * EN v1.0 Address: 0x801698E8
 * EN v1.0 Size: 988b
 */
#pragma scheduling off
#pragma peephole off
void kaldachompspit_update(int obj)
{
    u32 *state;
    f32 vx;
    f32 vy;
    f32 vz;
    u32 ptr;
    s16 v;
    int rnd;
    f32 t;
    u8 glow;
    s8 drift;

    state = ((GameObject *)obj)->extra;
    ((GameObject *)obj)->unkF4 = (int)((f32)((GameObject *)obj)->unkF4 - timeDelta);
    if (((GameObject *)obj)->unkF4 < 0) {
        Sfx_StopObjectChannel(obj, 0x7f);
        Obj_FreeObject(obj);
    } else if (*(u8 *)(obj + 0x36) != 0) {
        if (((GameObject *)obj)->unkF4 < 0x11b) {
            ((GameObject *)obj)->anim.velocityY = -(lbl_803E30F0 * timeDelta - ((GameObject *)obj)->anim.velocityY);
            if ((f32)(u32)*(u8 *)(obj + 0x36) - (t = lbl_803E30F4 * timeDelta) > lbl_803E30F8) {
                *(u8 *)(obj + 0x36) = (f32)(u32)*(u8 *)(obj + 0x36) - t;
            } else {
                Sfx_StopObjectChannel(obj, 0x7f);
                *(u8 *)(obj + 0x36) = 0;
            }
            Sfx_SetObjectChannelVolume(obj, 0x40, (u8)(*(u8 *)(obj + 0x36) >> 1), lbl_803E30FC);
        }
        vx = ((GameObject *)obj)->anim.velocityX * timeDelta;
        vy = ((GameObject *)obj)->anim.velocityY * timeDelta;
        vz = ((GameObject *)obj)->anim.velocityZ * timeDelta;
        objMove(obj, vx, vy, vz);
        if (((GameObject *)obj)->anim.seqId == 0x869) {
            ObjHits_SetHitVolumeSlot(obj, 0x1f, 1, 0);
            ((GameObject *)obj)->anim.rotX += 0x100;
            ((GameObject *)obj)->anim.rotY += 0x800;
        } else {
            ObjHits_SetHitVolumeSlot(obj, 0xa, 1, 0);
            ((GameObject *)obj)->anim.rotX = getAngle(vx, vz) - 0x8000;
            ((GameObject *)obj)->anim.rotY = 0x4000 - getAngle(sqrtf(vx * vx + vz * vz), vy);
        }
        ObjHits_EnableObject(obj);
        if ((*(ObjHitsPriorityState **)&((GameObject *)obj)->anim.hitReactState)->lastHitObject != 0) {
            if (((GameObject *)obj)->unkF4 < 0x17c) {
                kaldachompspit_burst(obj);
                return;
            }
            if (((*(ObjHitsPriorityState **)&((GameObject *)obj)->anim.hitReactState)->lastHitObject == Obj_GetPlayerObject()) ||
                ((*(ObjHitsPriorityState **)&((GameObject *)obj)->anim.hitReactState)->lastHitObject == getTrickyObject())) {
                kaldachompspit_burst(obj);
                return;
            }
        }
        if ((*(ObjHitsPriorityState **)&((GameObject *)obj)->anim.hitReactState)->contactFlags != 0) {
            kaldachompspit_burst(obj);
        } else {
            if (((GameObject *)obj)->anim.seqId == 0x869) {
                fn_80098B18(obj, lbl_803E30E0, 1, 0, 0, 0);
            } else {
                (**(void (**)(int, int, int, int, int, void *))(*gPartfxInterface + 0x8))(
                    obj, 0x714, 0, 2, -1, (u8 *)(obj + 0x36));
                (**(void (**)(int, int, int, int, int, void *))(*gPartfxInterface + 0x8))(
                    obj, 0x715, 0, 1, -1, 0);
                (**(void (**)(int, int, int, int, int, void *))(*gPartfxInterface + 0x8))(
                    obj, 0x715, 0, 1, -1, 0);
            }
            ptr = *state;
            if ((ptr != 0) && (*(u8 *)(ptr + 0x2f8) != 0) && (*(u8 *)(ptr + 0x4c) != 0)) {
                rnd = randomGetRange(-0x19, 0x19);
                ptr = *state;
                glow = *(u8 *)(ptr + 0x2f9);
                drift = *(s8 *)(ptr + 0x2fa);
                v = glow + (drift + rnd);
                if (v < 0) {
                    v = 0;
                    *(u8 *)(ptr + 0x2fa) = 0;
                } else if (v > 0xff) {
                    v = 0xff;
                    *(u8 *)(ptr + 0x2fa) = 0;
                }
                *(u8 *)(*state + 0x2f9) = v;
            }
        }
    }
}
#pragma peephole reset
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: kaldachompspit_burst
 * EN v1.0 Address: 0x801696D4
 * EN v1.0 Size: 312b
 */
#pragma scheduling off
#pragma peephole off
void kaldachompspit_burst(int obj)
{
    int i;
    u32 *state;
    u8 rnd;

    state = ((GameObject *)obj)->extra;
    *(u8 *)(obj + 0x36) = 0;
    ((GameObject *)obj)->unkF4 = 0xdc;
    (*(ObjHitsPriorityState **)&((GameObject *)obj)->anim.hitReactState)->flags &= ~1;
    if (*state != 0) {
        modelLightStruct_setEnabled(*state, 0, lbl_803E30E0);
    }
    if (((GameObject *)obj)->anim.seqId == 0x869) {
        rnd = randomGetRange(0, 1);
        spawnExplosion(obj, (f32)(int)randomGetRange(0x32, 0x3c), 1, 1, 0, rnd, 0, 1, 0);
    } else {
        for (i = 0; i < 0x19; i++) {
            (**(void (**)(int, int, int, int, int, int *))(*gPartfxInterface + 0x8))(
                obj, 0x715, 0, 1, -1, &i);
        }
        Sfx_PlayFromObject(obj, 0x279);
    }
}
#pragma peephole reset
#pragma scheduling reset
