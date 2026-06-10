#include "main/dll/MMP/MMP_asteroid.h"
#include "ghidra_import.h"
#include "main/audio/sfx_ids.h"
#include "main/dll/xyzanimator.h"
#include "main/effect_interfaces.h"
#include "main/expgfx.h"
#include "main/objhits_types.h"
#include "main/game_object.h"

extern undefined4 FUN_800067e8();
extern undefined8 FUN_8000680c();
extern undefined4 FUN_80006814();
extern undefined4 FUN_80006824();
extern undefined4 FUN_800068c4();
extern undefined4 FUN_80006920();
extern undefined4 FUN_800069bc();
extern undefined4 FUN_8001753c();
extern undefined4 FUN_8001754c();
extern undefined4 FUN_80017588();
extern undefined4 FUN_80017594();
extern undefined4 FUN_8001759c();
extern undefined4 FUN_800175b0();
extern undefined4 FUN_800175bc();
extern undefined4 FUN_800175cc();
extern undefined4 FUN_800175d0();
extern undefined4 FUN_800175ec();
extern undefined4 FUN_80017620();
extern void* FUN_80017624();
extern int FUN_80017730();
extern u32 randomGetRange(int min, int max);
extern undefined4 FUN_80017a88();
extern int FUN_80017a90();
extern int FUN_80017a98();
extern void* FUN_80017aa4();
extern undefined4 FUN_80017ac8();
extern undefined4 FUN_80017ae4();
extern uint FUN_80017ae8();
extern undefined4 ObjHitbox_SetSphereRadius();
extern undefined4 ObjHits_SetHitVolumeSlot();
extern undefined4 ObjHits_DisableObject();
extern undefined8 ObjHits_EnableObject();
extern void ObjHits_SetTargetMask(int obj,undefined mask);
extern int ObjHits_GetPriorityHit();
extern int ObjGroup_FindNearestObject();
extern undefined4 ObjPath_GetPointWorldPosition();
extern undefined4 FUN_8003b818();
extern undefined4 FUN_8005fe14();
extern uint FUN_8007f6c8();
extern undefined4 FUN_8007f718();
extern int FUN_8007f764();
extern int FUN_8007f7c0();
extern undefined4 FUN_80081110();
extern undefined4 FUN_8008112c();
extern undefined4 FUN_80169a44();
extern undefined4 FUN_8020a4ac();
extern undefined4 FUN_80247e94();
extern undefined4 FUN_80247eb8();
extern undefined4 FUN_80247edc();
extern undefined4 FUN_80247ef8();
extern int FUN_8028683c();
extern int FUN_80286840();
extern undefined4 FUN_80286888();
extern undefined4 FUN_8028688c();
extern double FUN_80293900();
extern int Sfx_PlayFromObjectLimited(int obj,int sfxId,int maxCount);
extern void s16toFloat(void *timer,int duration);

typedef struct {
    s16 unk00;         /* 0x00 */
    s16 loopSfx;       /* 0x02 */
    s16 explodeSfx;    /* 0x04 */
    s16 unk06;         /* 0x06 */
    s16 burstFx;       /* 0x08 */
    s16 auraFx;        /* 0x0A */
    s16 unk0C;         /* 0x0C */
    s16 unk0E;         /* 0x0E */
    s16 targetGroup;   /* 0x10 */
    u8 noVertical : 1; /* 0x12 bit 7 */
    u8 timed : 1;      /* 0x12 bit 6 */
    u8 smoothTurn : 1; /* 0x12 bit 5 */
    u8 usePath : 1;    /* 0x12 bit 4 */
} PollenFragmentDef;

/* pollenfragment extra block (head; timers at 0x20/0x24 stay raw addr args). */
typedef struct PollenFragmentExtra {
    u8 unk00[0xC];
    f32 velX;
    f32 velY;
    f32 velZ;
    u8 unk18[4];
    PollenFragmentDef *def; /* 0x1C */
} PollenFragmentExtra;


extern void storeZeroToFloatParam(void *timer);

extern undefined4 DAT_803dc070;
extern EffectInterface **gPartfxInterface;
extern f64 DOUBLE_803e3d80;
extern f64 DOUBLE_803e3d98;
extern f64 DOUBLE_803e3dc8;
extern f64 DOUBLE_803e3de8;
extern f64 DOUBLE_803e3e20;
extern f64 DOUBLE_803e3e28;
extern f32 lbl_803DC074;
extern f32 lbl_803DC9B0;
extern f32 lbl_803DC9B4;
extern f32 lbl_803E3D78;
extern f32 lbl_803E3D88;
extern f32 lbl_803E3D8C;
extern f32 lbl_803E3D90;
extern f32 lbl_803E3D94;
extern f32 lbl_803E3DA0;
extern f32 lbl_803E3DA4;
extern f32 lbl_803E3DA8;
extern f32 lbl_803E3DAC;
extern f32 lbl_803E3DB0;
extern f32 lbl_803E3DB4;
extern f32 lbl_803E3DB8;
extern f32 lbl_803E3DBC;
extern f32 lbl_803E3DC0;
extern f32 lbl_803E3DC4;
extern f32 lbl_803E3DD0;
extern f32 lbl_803E3DD4;
extern f32 lbl_803E3DD8;
extern f32 lbl_803E3DDC;
extern f32 lbl_803E3DE0;
extern f32 lbl_803E3DF0;
extern f32 lbl_803E3DF4;
extern f32 lbl_803E3DF8;
extern f32 lbl_803E3DFC;
extern f32 lbl_803E3E00;
extern f32 lbl_803E3E04;
extern f32 lbl_803E3E08;
extern f32 lbl_803E3E0C;
extern f32 lbl_803E3E10;
extern f32 lbl_803E3E14;
extern f32 lbl_803E3E18;
extern f64 lbl_803E3190;
extern f32 lbl_803E3198;
extern f32 lbl_803E319C;

/*
 * --INFO--
 *
 * Function: kaldachompspit_render
 * EN v1.0 Address: 0x8016984C
 * EN v1.0 Size: 152b
 * EN v1.1 Address: 0x80169CF8
 * EN v1.1 Size: 156b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void kaldachompspit_render(undefined4 param_1,undefined4 param_2,undefined4 param_3,
                           undefined4 param_4,undefined4 param_5,char visible)
{
  int iVar1;
  int iVar2;
  
  iVar1 = FUN_8028683c();
  iVar2 = **(int **)(iVar1 + 0xb8);
  if (((iVar2 != 0) && (*(char *)(iVar2 + 0x2f8) != '\0')) && (((XyzAnimatorState *)iVar2)->unk4C != '\0')) {
    FUN_8005fe14(iVar2);
  }
  if (visible != '\0') {
    FUN_8003b818(iVar1);
  }
  FUN_80286888();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80169d38
 * EN v1.0 Address: 0x80169D38
 * EN v1.0 Size: 1300b
 * EN v1.1 Address: 0x80169D94
 * EN v1.1 Size: 988b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80169d38(undefined8 param_1,undefined8 param_2,undefined8 param_3,double param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 short *param_9)
{
  short sVar1;
  int iVar2;
  uint uVar3;
  int *piVar4;
  undefined8 uVar5;
  double dVar6;
  double dVar7;
  double dVar8;
  double dVar9;
  double dVar10;
  undefined8 local_48;
  undefined8 local_40;
  
  piVar4 = *(int **)(param_9 + 0x5c);
  *(int *)(param_9 + 0x7a) = (int)((f32)(s32)(*(uint *)(param_9 + 0x7a)) - lbl_803DC074);
  if (*(int *)(param_9 + 0x7a) < 0) {
    uVar5 = FUN_8000680c((int)param_9,0x7f);
    FUN_80017ac8(uVar5,param_2,param_3,param_4,param_5,param_6,param_7,param_8,(int)param_9);
  }
  else if (*(char *)(param_9 + 0x1b) != '\0') {
    if (*(int *)(param_9 + 0x7a) < 0x11b) {
      *(float *)(param_9 + 0x14) = -(lbl_803E3D88 * lbl_803DC074 - *(float *)(param_9 + 0x14));
      local_40 = (double)CONCAT44(0x43300000,(uint)*(byte *)(param_9 + 0x1b));
      param_4 = (double)(lbl_803E3D8C * lbl_803DC074);
      if ((float)((double)(float)(local_40 - DOUBLE_803e3d98) - param_4) <= lbl_803E3D90) {
        FUN_8000680c((int)param_9,0x7f);
        *(undefined *)(param_9 + 0x1b) = 0;
      }
      else {
        local_40 = (double)CONCAT44(0x43300000,(uint)*(byte *)(param_9 + 0x1b));
        *(char *)(param_9 + 0x1b) =
             (char)(int)((double)(float)(local_40 - DOUBLE_803e3d98) - param_4);
      }
      FUN_80006814((double)lbl_803E3D94,(int)param_9,0x40,
                   (byte)((int)(uint)*(byte *)(param_9 + 0x1b) >> 1));
    }
    dVar10 = (double)(*(float *)(param_9 + 0x12) * lbl_803DC074);
    dVar8 = (double)(*(float *)(param_9 + 0x14) * lbl_803DC074);
    dVar6 = (double)(*(float *)(param_9 + 0x16) * lbl_803DC074);
    dVar7 = dVar6;
    dVar9 = dVar8;
    FUN_80017a88(dVar10,dVar8,dVar6,(int)param_9);
    if (param_9[0x23] == 0x869) {
      ObjHits_SetHitVolumeSlot((int)param_9,0x1f,1,0);
      *param_9 = *param_9 + 0x100;
      param_9[1] = param_9[1] + 0x800;
    }
    else {
      ObjHits_SetHitVolumeSlot((int)param_9,10,1,0);
      iVar2 = FUN_80017730();
      *param_9 = (short)iVar2 + -0x8000;
      dVar8 = dVar9;
      FUN_80293900((double)(float)(dVar10 * dVar10 + (double)(float)(dVar7 * dVar7)));
      iVar2 = FUN_80017730();
      param_9[1] = 0x4000 - (short)iVar2;
    }
    uVar5 = ObjHits_EnableObject((int)param_9);
    if (*(int *)(*(int *)(param_9 + 0x2a) + 0x50) != 0) {
      if (*(int *)(param_9 + 0x7a) < 0x17c) {
        FUN_80169a44(uVar5,dVar8,dVar6,param_4,param_5,param_6,param_7,param_8,(uint)param_9);
        return;
      }
      iVar2 = FUN_80017a98();
      if ((*(int *)(*(int *)(param_9 + 0x2a) + 0x50) == iVar2) ||
         (iVar2 = FUN_80017a90(), *(int *)(*(int *)(param_9 + 0x2a) + 0x50) == iVar2)) {
        FUN_80169a44(uVar5,dVar8,dVar6,param_4,param_5,param_6,param_7,param_8,(uint)param_9);
        return;
      }
    }
    if (*(char *)(*(int *)(param_9 + 0x2a) + 0xad) == '\0') {
      if (param_9[0x23] == 0x869) {
        FUN_80081110(param_9,1,0,0,(undefined4 *)0x0);
      }
      else {
        (*gPartfxInterface)->spawnObject((void *)param_9, 0x714, NULL, 2, -1, param_9 + 0x1b);
        (*gPartfxInterface)->spawnObject((void *)param_9, 0x715, NULL, 1, -1, NULL);
        (*gPartfxInterface)->spawnObject((void *)param_9, 0x715, NULL, 1, -1, NULL);
      }
      iVar2 = *piVar4;
      if (((iVar2 != 0) && (*(char *)(iVar2 + 0x2f8) != '\0')) && (*(char *)(iVar2 + 0x4c) != '\0'))
      {
        uVar3 = randomGetRange(0xffffffe7,0x19);
        iVar2 = *piVar4;
        sVar1 = (ushort)*(byte *)(iVar2 + 0x2f9) + (short)*(char *)(iVar2 + 0x2fa) + (short)uVar3;
        if (sVar1 < 0) {
          sVar1 = 0;
          *(undefined *)(iVar2 + 0x2fa) = 0;
        }
        else if (0xff < sVar1) {
          sVar1 = 0xff;
          *(undefined *)(iVar2 + 0x2fa) = 0;
        }
        *(char *)(*piVar4 + 0x2f9) = (char)sVar1;
      }
    }
    else {
      FUN_80169a44(uVar5,dVar8,dVar6,param_4,param_5,param_6,param_7,param_8,(uint)param_9);
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: kaldachompspit_init
 * EN v1.0 Address: 0x80169CC4
 * EN v1.0 Size: 552b
 * EN v1.1 Address: 0x8016A170
 * EN v1.1 Size: 560b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
extern void Sfx_PlayFromObject(int obj, int sfxId);
extern void *objCreateLight(int obj, int kind);
extern void modelLightStruct_setLightKind(int light, int value);
extern void modelLightStruct_setPosition(int light, f32 x, f32 y, f32 z);
extern void modelLightStruct_setDiffuseColor(int light, int r, int g, int b, int a);
extern void modelLightStruct_setSpecularColor(int light, int r, int g, int b, int a);
extern void modelLightStruct_setupGlow(int light, int a, int r, int g, int b, int alpha, f32 radius);
extern void modelLightStruct_setDiffuseTargetColor(int light, int r, int g, int b, int a);
extern void modelLightStruct_setDistanceAttenuation(int light, f32 near, f32 far);
extern void lightSetField4D(int light, int v);
extern void modelLightStruct_setEnabled(int light, int enabled, f32 scale);
extern void modelLightStruct_startColorFade(int light, int a, int b);
extern f32 lbl_803E30E0;
extern f32 lbl_803E30F8;
extern f32 lbl_803E3108;
extern f32 lbl_803E310C;

void kaldachompspit_init(int obj)
{
    int *extra;

    extra = *(int **)&((GameObject *)obj)->extra;
    ((GameObject *)obj)->unkF4 = 400;
    ObjHits_DisableObject(obj);
    ((GameObject *)obj)->anim.alpha = 0xff;
    Sfx_PlayFromObject(obj, 0x278);
    ((GameObject *)obj)->objectFlags |= 0x2000;
    if (*(void **)extra == NULL) {
        *extra = (int)objCreateLight(obj, 1);
        if (*(void **)extra != NULL) {
            modelLightStruct_setLightKind(*extra, 2);
        }
    }
    if (*(void **)extra != NULL) {
        f32 k = lbl_803E30F8;
        modelLightStruct_setPosition(*extra, k, k, k);
        if (((GameObject *)obj)->anim.seqId == 0x869) {
            modelLightStruct_setDiffuseColor(*extra, 0xff, 0xc0, 0, 0xff);
            modelLightStruct_setSpecularColor(*extra, 0xff, 0xc0, 0, 0xff);
            modelLightStruct_setupGlow(*extra, 0, 0xff, 0xc0, 0, 0x7f, lbl_803E3108 * (lbl_803E310C * ((GameObject *)obj)->anim.rootMotionScale));
            modelLightStruct_setDiffuseTargetColor(*extra, 0xff, 0xd2, 0, 0xff);
        } else {
            modelLightStruct_setDiffuseColor(*extra, 0, 0xff, 0, 0xff);
            modelLightStruct_setSpecularColor(*extra, 0, 0xff, 0, 0xff);
            modelLightStruct_setupGlow(*extra, 0, 0, 0xff, 0, 0x28, lbl_803E310C * ((GameObject *)obj)->anim.rootMotionScale);
            modelLightStruct_setDiffuseTargetColor(*extra, 0, 0xff, 0, 0xff);
        }
        {
            int a = (int)(lbl_803E310C * ((GameObject *)obj)->anim.rootMotionScale);
            modelLightStruct_setDistanceAttenuation(*extra, (f32)a, (f32)(a + 0x28));
        }
        lightSetField4D(*extra, 1);
        modelLightStruct_setEnabled(*extra, 1, lbl_803E30E0);
        modelLightStruct_startColorFade(*extra, 1, 3);
    }
}

/*
 * --INFO--
 *
 * Function: FUN_8016a534
 * EN v1.0 Address: 0x8016A534
 * EN v1.0 Size: 416b
 * EN v1.1 Address: 0x8016A3A0
 * EN v1.1 Size: 372b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int FUN_8016a534(double param_1,double param_2,float *param_3,float *param_4,char param_5)
{
  int iVar1;
  double dVar2;
  double dVar3;
  double dVar4;
  double dVar5;
  double dVar6;
  
  dVar2 = FUN_80293900((double)((*param_3 - *param_4) * (*param_3 - *param_4) +
                               (param_3[2] - param_4[2]) * (param_3[2] - param_4[2])));
  dVar3 = (double)(param_3[1] - param_4[1]);
  dVar5 = (double)(float)(dVar2 * (double)lbl_803E3DA8);
  dVar2 = (double)(float)((double)(float)((double)lbl_803E3DAC * param_2) * param_2);
  dVar6 = (double)(float)(param_1 * param_1);
  dVar4 = (double)(float)(-(double)(float)(param_2 * dVar3) - dVar6);
  dVar3 = (double)(float)(dVar4 * dVar4 -
                         (double)((float)((double)lbl_803E3DB0 * dVar2) *
                                 (float)(dVar3 * dVar3 + (double)(float)(dVar5 * dVar5))));
  if (dVar3 < (double)lbl_803E3DB4) {
    iVar1 = 0x2000;
  }
  else {
    if (param_5 == '\0') {
      dVar3 = FUN_80293900(dVar3);
      dVar2 = (double)(lbl_803E3DB8 * (float)(-dVar4 - dVar3)) / dVar2;
    }
    else {
      dVar3 = FUN_80293900(dVar3);
      dVar2 = (double)(lbl_803E3DB8 * (float)(-dVar4 + dVar3)) / dVar2;
    }
    dVar2 = FUN_80293900((double)(float)dVar2);
    FUN_80293900(-(double)(float)((double)(float)(dVar5 / dVar2) * (double)(float)(dVar5 / dVar2) -
                                 dVar6));
    iVar1 = FUN_80017730();
  }
  return iVar1;
}

#pragma dont_inline on
void fn_8016A660(int obj)
{
  extern u8 Obj_IsLoadingLocked(void);
  extern u8 *Obj_AllocObjectSetup(int size, int type);
  extern u8 *Obj_SetupObject(u8 *obj, int a, int b, int c, int d);
  extern f32 lbl_803E3144;
  extern f32 lbl_803E3148;
  int burstCounter;
  PollenExtra *extra;
  u8 *fragment;

  extra = *(PollenExtra **)&((GameObject *)obj)->extra;
  if (Obj_IsLoadingLocked() != 0) {
    burstCounter = POLLEN_FRAGMENT_BURST_COUNTER_START;
    do {
      fragment = Obj_AllocObjectSetup(POLLEN_FRAGMENT_SETUP_SIZE, POLLEN_FRAGMENT_OBJECT_ID);
      ((GameObject *)fragment)->anim.rootMotionScale = ((GameObject *)obj)->anim.localPosX;
      ((GameObject *)fragment)->anim.localPosX = ((GameObject *)obj)->anim.localPosY;
      ((GameObject *)fragment)->anim.localPosY = ((GameObject *)obj)->anim.localPosZ;
      *(u8 *)&((GameObject *)fragment)->anim.rotZ = 1;
      *(u8 *)(fragment + 5) = 1;
      *(u8 *)&((GameObject *)fragment)->anim.flags = 0xff;
      *(u8 *)(fragment + 7) = 0xff;
      fragment = Obj_SetupObject(fragment, POLLEN_FRAGMENT_SETUP_KIND, -1, -1, 0);
      if (fragment != 0) {
        ((GameObject *)fragment)->anim.rotY = 0;
        ((GameObject *)fragment)->anim.rotX = (s16)randomGetRange(0, POLLEN_FRAGMENT_RANDOM_ANGLE_MAX);
        ((GameObject *)fragment)->anim.velocityX =
            lbl_803E3144 *
                (f32)(s32)randomGetRange(POLLEN_FRAGMENT_RANDOM_OFFSET_MIN,
                                         POLLEN_FRAGMENT_RANDOM_OFFSET_MAX) +
            ((GameObject *)obj)->anim.velocityX;
        ((GameObject *)fragment)->anim.velocityY =
            lbl_803E3148 *
                (f32)(s32)randomGetRange(POLLEN_FRAGMENT_RANDOM_OFFSET_MIN,
                                         POLLEN_FRAGMENT_RANDOM_OFFSET_MAX) +
            ((GameObject *)obj)->anim.velocityY;
        ((GameObject *)fragment)->anim.velocityZ =
            lbl_803E3144 *
                (f32)(s32)randomGetRange(POLLEN_FRAGMENT_RANDOM_OFFSET_MIN,
                                         POLLEN_FRAGMENT_RANDOM_OFFSET_MAX) +
            ((GameObject *)obj)->anim.velocityZ;
        *(int *)(fragment + POLLEN_FRAGMENT_PARENT_OBJECT_OFFSET) = obj;
      }
    } while (burstCounter-- != 0);
    extra->fragmentSpawnTimer = POLLEN_FRAGMENT_SPAWN_TIMER_FRAMES;
  }
}
#pragma dont_inline reset

/*
 * --INFO--
 *
 * Function: FUN_8016a6d4
 * EN v1.0 Address: 0x8016A6D4
 * EN v1.0 Size: 52b
 * EN v1.1 Address: 0x8016A514
 * EN v1.1 Size: 56b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8016a6d4(int obj)
{
  (*gExpgfxInterface)->freeSource2((u32)obj);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8016a708
 * EN v1.0 Address: 0x8016A708
 * EN v1.0 Size: 904b
 * EN v1.1 Address: 0x8016A54C
 * EN v1.1 Size: 712b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8016a708(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 short *param_9)
{
  int iVar1;
  double dVar2;
  double dVar3;
  double dVar4;
  double dVar5;
  int local_58;
  int local_54 [3];
  longlong local_48;
  
  if (0 < (int)*(uint *)(param_9 + 0x7a)) {
    local_54[2] = *(uint *)(param_9 + 0x7a) ^ 0x80000000;
    local_54[1] = 0x43300000;
    dVar2 = (double)(float)((double)CONCAT44(0x43300000,local_54[2]) - DOUBLE_803e3dc8);
    iVar1 = (int)(dVar2 - (double)lbl_803DC074);
    local_48 = (longlong)iVar1;
    *(int *)(param_9 + 0x7a) = iVar1;
    if (*(int *)(param_9 + 0x7a) < 1) {
      FUN_80017ac8(dVar2,param_2,param_3,param_4,param_5,param_6,param_7,param_8,(int)param_9);
      return;
    }
  }
  if (*(char *)(param_9 + 0x1b) != '\0') {
    dVar5 = (double)(*(float *)(param_9 + 0x12) * lbl_803DC074);
    dVar4 = (double)(*(float *)(param_9 + 0x14) * lbl_803DC074);
    dVar3 = (double)(*(float *)(param_9 + 0x16) * lbl_803DC074);
    dVar2 = dVar3;
    FUN_80017a88(dVar5,dVar4,dVar3,(int)param_9);
    *(float *)(param_9 + 0x14) = lbl_803E3DBC * lbl_803DC074 + *(float *)(param_9 + 0x14);
    if (*(float *)(param_9 + 0x14) < lbl_803E3DC0) {
      *(float *)(param_9 + 0x14) = lbl_803E3DC0;
    }
    iVar1 = FUN_80017730();
    *param_9 = (short)iVar1 + -0x8000;
    FUN_80293900((double)(float)(dVar5 * dVar5 + (double)(float)(dVar2 * dVar2)));
    iVar1 = FUN_80017730();
    param_9[1] = 0x4000 - (short)iVar1;
    ObjHits_SetHitVolumeSlot((int)param_9,10,1,0);
    ObjHits_EnableObject((int)param_9);
    if ((*(int *)(*(int *)(param_9 + 0x2a) + 0x50) == 0) ||
       ((iVar1 = FUN_80017a98(), *(int *)(*(int *)(param_9 + 0x2a) + 0x50) != iVar1 &&
        (iVar1 = FUN_80017a90(), *(int *)(*(int *)(param_9 + 0x2a) + 0x50) != iVar1)))) {
      if (*(char *)(*(int *)(param_9 + 0x2a) + 0xad) == '\0') {
        if ((double)*(float *)(param_9 + 8) < (double)lbl_803E3DC4) {
          FUN_80017ac8((double)*(float *)(param_9 + 8),dVar4,dVar3,param_4,param_5,param_6,param_7,
                       param_8,(int)param_9);
        }
      }
      else {
        *(undefined *)(param_9 + 0x1b) = 0;
        param_9[0x7a] = 0;
        param_9[0x7b] = 0x78;
        *(ushort *)(*(int *)(param_9 + 0x2a) + 0x60) =
             *(ushort *)(*(int *)(param_9 + 0x2a) + 0x60) & ~1;
        for (local_58 = 0; local_58 < 0x19; local_58 = local_58 + 1) {
          (*gPartfxInterface)->spawnObject((void *)param_9, 0x715, NULL, 1, -1, &local_58);
        }
        FUN_80006824((uint)param_9,SFXsc_attack03);
      }
    }
    else {
      *(undefined *)(param_9 + 0x1b) = 0;
      param_9[0x7a] = 0;
      param_9[0x7b] = 0x78;
      *(ushort *)(*(int *)(param_9 + 0x2a) + 0x60) =
           *(ushort *)(*(int *)(param_9 + 0x2a) + 0x60) & ~1;
      for (local_54[0] = 0; local_54[0] < 0x19; local_54[0] = local_54[0] + 1) {
        (*gPartfxInterface)->spawnObject((void *)param_9, 0x715, NULL, 1, -1, local_54);
      }
      FUN_80006824((uint)param_9,SFXsc_attack03);
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8016aa90
 * EN v1.0 Address: 0x8016AA90
 * EN v1.0 Size: 84b
 * EN v1.1 Address: 0x8016A814
 * EN v1.1 Size: 112b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8016aa90(uint param_1)
{
  *(undefined4 *)(param_1 + 0xf4) = 0;
  ObjHits_DisableObject(param_1);
  ((GameObject *)param_1)->anim.alpha = 0xff;
  FUN_80006824(param_1,SFXsc_attack02);
  ((GameObject *)param_1)->objectFlags = ((GameObject *)param_1)->objectFlags | 0x6000;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8016aae4
 * EN v1.0 Address: 0x8016AAE4
 * EN v1.0 Size: 52b
 * EN v1.1 Address: 0x8016A884
 * EN v1.1 Size: 48b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8016aae4(int obj)
{
  (*gExpgfxInterface)->freeSource2((u32)obj);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8016ab18
 * EN v1.0 Address: 0x8016AB18
 * EN v1.0 Size: 40b
 * EN v1.1 Address: 0x8016A8B4
 * EN v1.1 Size: 48b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8016ab18(int param_1,int param_2,int param_3,int param_4,int param_5,s8 visible)
{
  if (visible != 0) {
    FUN_8003b818(param_1);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8016ab40
 * EN v1.0 Address: 0x8016AB40
 * EN v1.0 Size: 104b
 * EN v1.1 Address: 0x8016A8E4
 * EN v1.1 Size: 108b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8016ab40(int param_1)
{
  float fVar1;
  
  if ((*(ObjHitsPriorityState **)&((GameObject *)param_1)->anim.hitReactState)->contactFlags != 0) {
    ((GameObject *)param_1)->anim.localPosX = (*(ObjHitsPriorityState **)&((GameObject *)param_1)->anim.hitReactState)->contactPosX;
    ((GameObject *)param_1)->anim.localPosY = (*(ObjHitsPriorityState **)&((GameObject *)param_1)->anim.hitReactState)->contactPosY;
    ((GameObject *)param_1)->anim.localPosZ = (*(ObjHitsPriorityState **)&((GameObject *)param_1)->anim.hitReactState)->contactPosZ;
    fVar1 = lbl_803E3DD4;
    ((GameObject *)param_1)->anim.velocityX = lbl_803E3DD4;
    ((GameObject *)param_1)->anim.velocityY = fVar1;
    ((GameObject *)param_1)->anim.velocityZ = fVar1;
    ((GameObject *)param_1)->anim.alpha = 0;
    ObjHits_DisableObject(param_1);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8016aba8
 * EN v1.0 Address: 0x8016ABA8
 * EN v1.0 Size: 700b
 * EN v1.1 Address: 0x8016A950
 * EN v1.1 Size: 444b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8016aba8(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 uint param_9)
{
  bool bVar1;
  int iVar2;
  int iVar3;
  double dVar4;
  double dVar5;
  
  iVar3 = *(int *)&((GameObject *)param_9)->extra;
  if (*(short *)(iVar3 + 0x12) == 0) {
    dVar5 = (double)((GameObject *)param_9)->anim.velocityY;
    ((GameObject *)param_9)->anim.velocityY = -(float)((double)lbl_803E3DD8 * (double)lbl_803DC074 - dVar5);
    dVar4 = (double)lbl_803E3DD4;
    if ((dVar4 <= dVar5) && ((double)((GameObject *)param_9)->anim.velocityY <= dVar4)) {
      FUN_8016ae64(dVar4,dVar5,param_3,param_4,param_5,param_6,param_7,param_8,param_9);
      FUN_80006824(param_9,SFXsc_projhitneg22);
      ((GameObject *)param_9)->anim.alpha = 0;
    }
    param_2 = (double)(((GameObject *)param_9)->anim.velocityY * lbl_803DC074);
    param_3 = (double)(((GameObject *)param_9)->anim.velocityZ * lbl_803DC074);
    FUN_80017a88((double)(((GameObject *)param_9)->anim.velocityX * lbl_803DC074),param_2,param_3,param_9);
    ObjHits_SetHitVolumeSlot(param_9,0x16,1,0);
    ObjHitbox_SetSphereRadius(param_9,7);
    param_1 = ObjHits_EnableObject(param_9);
    if (((*(ObjHitsPriorityState **)&((GameObject *)param_9)->anim.hitReactState)->lastHitObject != 0) &&
       ((iVar2 = FUN_80017a98(), (*(ObjHitsPriorityState **)&((GameObject *)param_9)->anim.hitReactState)->lastHitObject == iVar2 ||
        (iVar2 = FUN_80017a90(), (*(ObjHitsPriorityState **)&((GameObject *)param_9)->anim.hitReactState)->lastHitObject == iVar2)))) {
      FUN_800069bc();
      FUN_80006920((double)lbl_803E3DD0);
      FUN_80006824(param_9,SFXsc_objselectyeah22);
      ((GameObject *)param_9)->anim.alpha = 0;
      *(undefined2 *)(iVar3 + 0x12) = 0x3c;
      param_1 = ObjHits_DisableObject(param_9);
    }
    if ((s8)((GameObject *)param_9)->anim.alpha == -1) {
      iVar2 = 2;
      do {
        (*gPartfxInterface)->spawnObject((void *)param_9, 0x4ba, NULL, 1, -1, NULL);
        iVar2 = iVar2 + -1;
      } while (iVar2 != -1);
    }
  }
  else {
    *(short *)(iVar3 + 0x12) = *(short *)(iVar3 + 0x12) + -1;
  }
  if ((((GameObject *)param_9)->anim.alpha == 0) && (*(short *)(iVar3 + 0x12) == 0)) {
    FUN_80017ac8(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8016ae64
 * EN v1.0 Address: 0x8016AE64
 * EN v1.0 Size: 576b
 * EN v1.1 Address: 0x8016AB0C
 * EN v1.1 Size: 408b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8016ae64(double param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5
                 ,undefined8 param_6,undefined8 param_7,undefined8 param_8,int param_9)
{
  bool bVar1;
  uint uVar2;
  undefined2 *puVar3;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  int iVar4;
  int iVar5;
  double extraout_f1;
  
  iVar4 = *(int *)&((GameObject *)param_9)->extra;
  uVar2 = FUN_80017ae8();
  if ((uVar2 & 0xff) != 0) {
    iVar5 = 5;
    do {
      puVar3 = FUN_80017aa4(0x24,0x482);
      *(undefined4 *)(puVar3 + 4) = *(undefined4 *)&((GameObject *)param_9)->anim.localPosX;
      *(undefined4 *)(puVar3 + 6) = *(undefined4 *)&((GameObject *)param_9)->anim.localPosY;
      *(undefined4 *)(puVar3 + 8) = *(undefined4 *)&((GameObject *)param_9)->anim.localPosZ;
      *(undefined *)(puVar3 + 2) = 1;
      *(undefined *)((int)puVar3 + 5) = 1;
      *(undefined *)(puVar3 + 3) = 0xff;
      *(undefined *)((int)puVar3 + 7) = 0xff;
      puVar3 = (undefined2 *)
               FUN_80017ae4(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,puVar3,5
                            ,0xff,0xffffffff,(uint *)0x0,in_r8,in_r9,in_r10);
      param_1 = extraout_f1;
      if (puVar3 != (undefined2 *)0x0) {
        puVar3[1] = 0;
        uVar2 = randomGetRange(0,0xffff);
        *puVar3 = (short)uVar2;
        uVar2 = randomGetRange(0xffffffce,0x32);
        *(float *)(puVar3 + 0x12) =
             lbl_803E3DDC *
             (f32)(s32)(uVar2) +
             ((GameObject *)param_9)->anim.velocityX;
        uVar2 = randomGetRange(0xffffffce,0x32);
        *(float *)(puVar3 + 0x14) =
             lbl_803E3DE0 *
             (f32)(s32)(uVar2) +
             ((GameObject *)param_9)->anim.velocityY;
        uVar2 = randomGetRange(0xffffffce,0x32);
        param_2 = (double)(f32)(s32)(uVar2)
        ;
        param_1 = (double)lbl_803E3DDC;
        *(float *)(puVar3 + 0x16) = (float)(param_1 * param_2 + (double)((GameObject *)param_9)->anim.velocityZ);
        *(int *)(puVar3 + 0x62) = param_9;
      }
      iVar5 = iVar5 + -1;
    } while (iVar5 != -1);
    *(undefined2 *)(iVar4 + 0x12) = 0x3c;
  }
  return;
}

/*
 * --INFO--
 *
 * Function: pollenfragment_init
 * EN v1.0 Address: 0x8016B0A4
 * EN v1.0 Size: 208b
 * EN v1.1 Address: 0x8016ACA4
 * EN v1.1 Size: 248b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void pollenfragment_init(int obj,int config)
{
  bool keepSpawning;
  s8 pollenType;
  uint randomValue;
  int spawnCount;
  undefined4 *state;
  
  state = *(undefined4 **)&((GameObject *)obj)->extra;
  if (*(char *)(config + 0x19) == '\x01') {
    *(float *)(state + 2) = lbl_803E3198;
  }
  else {
    randomValue = randomGetRange(0xb4,300);
    *(float *)(state + 2) = (float)(int)randomValue;
  }
  pollenType = *(s8 *)(config + 0x19);
  if ((s8)pollenType < 0) {
    pollenType = 0;
  }
  else if (pollenType > 5u) {
    pollenType = 5;
  }
  *(s8 *)(config + 0x19) = pollenType;
  state[7] = (u32)lbl_8032059C[*(char *)(config + 0x19)];
  if ((int)*(short *)state[7] != 0) {
    Sfx_PlayFromObjectLimited(obj,(int)*(short *)state[7] & 0xffff,3);
  }
  spawnCount = 4;
  do {
    (*gPartfxInterface)->spawnObject((void *)obj, (int)*(short *)(state[7] + 6),
                                     NULL, 1, -1, NULL);
  } while (spawnCount-- != 0);
  if (!((PollenFragmentDef *)state[7])->timed) {
    *(float *)(state + 2) = lbl_803E319C;
  }
  ObjHits_SetTargetMask(obj,4);
  state[6] = 0;
  *(f32 *)(state + 1) = *(f32 *)(state[7] + 0xc);
  *state = 0;
  s16toFloat(state + 9,0xe10);
  storeZeroToFloatParam(state + 8);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8016b174
 * EN v1.0 Address: 0x8016B174
 * EN v1.0 Size: 104b
 * EN v1.1 Address: 0x8016AD9C
 * EN v1.1 Size: 100b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8016b174(int param_1)
{
  uint uVar1;
  int iVar2;
  
  iVar2 = *(int *)&((GameObject *)param_1)->extra;
  uVar1 = *(uint *)&((XyzAnimatorState *)iVar2)->unk18;
  if (uVar1 != 0) {
    FUN_80017620(uVar1);
    ((XyzAnimatorState *)iVar2)->unk18 = 0;
  }
  (*gExpgfxInterface)->freeSource2((u32)param_1);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8016b1dc
 * EN v1.0 Address: 0x8016B1DC
 * EN v1.0 Size: 76b
 * EN v1.1 Address: 0x8016AE00
 * EN v1.1 Size: 112b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8016b1dc(void)
{
  int iVar1;
  uint uVar2;
  
  iVar1 = FUN_80286840();
  uVar2 = FUN_8007f6c8((float *)(*(int *)(iVar1 + 0xb8) + 0x20));
  if (uVar2 == 0) {
    FUN_8003b818(iVar1);
  }
  FUN_8028688c();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8016b228
 * EN v1.0 Address: 0x8016B228
 * EN v1.0 Size: 512b
 * EN v1.1 Address: 0x8016AE70
 * EN v1.1 Size: 332b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8016b228(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 uint param_9)
{
  uint uVar1;
  int iVar2;
  int iVar3;
  undefined4 auStack_18 [4];
  
  iVar3 = *(int *)&((GameObject *)param_9)->extra;
  uVar1 = FUN_8007f6c8((float *)(iVar3 + 0x20));
  if (uVar1 == 0) {
    iVar2 = ObjHits_GetPriorityHit(param_9,auStack_18,(int *)0x0,(uint *)0x0);
    if ((iVar2 == 0xe) || (iVar2 == 0xf)) {
      if (*(short *)(((XyzAnimatorState *)iVar3)->unk1C + 4) != -1) {
        FUN_8008112c((double)lbl_803E3DF4,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                     param_9,0,1,0,1,0,1,0);
        FUN_800067e8(param_9,*(ushort *)(((XyzAnimatorState *)iVar3)->unk1C + 4),3);
      }
      ObjHits_DisableObject(param_9);
      FUN_8007f718((float *)(iVar3 + 0x20),0x78);
    }
    if ((*(ObjHitsPriorityState **)&((GameObject *)param_9)->anim.hitReactState)->contactFlags != 0) {
      ObjHits_DisableObject(param_9);
      *(float *)&((XyzAnimatorState *)iVar3)->unk8 = lbl_803E3DF8;
      if (*(short *)(((XyzAnimatorState *)iVar3)->unk1C + 4) != -1) {
        FUN_8008112c((double)lbl_803E3DF4,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                     param_9,0,1,0,1,0,1,0);
        FUN_800067e8(param_9,*(ushort *)(((XyzAnimatorState *)iVar3)->unk1C + 4),3);
      }
      FUN_8007f718((float *)(iVar3 + 0x20),0x78);
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8016b428
 * EN v1.0 Address: 0x8016B428
 * EN v1.0 Size: 2092b
 * EN v1.1 Address: 0x8016AFBC
 * EN v1.1 Size: 1428b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8016b428(undefined8 param_1,undefined8 param_2,undefined8 param_3,double param_4,
                 double param_5,double param_6,undefined8 param_7,undefined8 param_8,ushort *param_9
                 )
{
  bool bVar1;
  float fVar2;
  int iVar3;
  uint uVar4;
  int *piVar5;
  undefined8 extraout_f1;
  undefined8 uVar6;
  double dVar7;
  double dVar8;
  float local_68;
  float local_64;
  float local_60;
  float afStack_5c [3];
  float local_50;
  float local_4c;
  float local_48;
  undefined4 local_40;
  uint uStack_3c;
  undefined4 local_38;
  uint uStack_34;
  longlong local_30;
  undefined4 local_28;
  uint uStack_24;
  undefined4 local_20;
  uint uStack_1c;
  longlong local_18;
  
  piVar5 = *(int **)(param_9 + 0x5c);
  iVar3 = FUN_8007f7c0();
  if (iVar3 == 0) {
    uVar6 = extraout_f1;
    uVar4 = FUN_8007f6c8((float *)(piVar5 + 8));
    if (uVar4 == 0) {
      iVar3 = FUN_8007f764((float *)(piVar5 + 9));
      if (iVar3 != 0) {
        FUN_8007f718((float *)(piVar5 + 8),0x78);
      }
      if (*(int *)(param_9 + 0x62) != 0) {
        *piVar5 = *(int *)(param_9 + 0x62);
        param_9[0x62] = 0;
        param_9[99] = 0;
      }
      if ((*(byte *)(piVar5[7] + 0x12) >> 6 & 1) != 0) {
        piVar5[2] = (int)((float)piVar5[2] - lbl_803DC074);
        dVar7 = (double)(float)piVar5[2];
        if (dVar7 <= (double)lbl_803E3DF8) {
          if (*(char *)(param_9 + 0x1b) == -1) {
            iVar3 = 2;
            do {
              (*gPartfxInterface)->spawnObject((void *)param_9, (int)*(short *)(piVar5[7] + 8),
                                               NULL, 1, -1, NULL);
              iVar3 = iVar3 + -1;
            } while (iVar3 != -1);
          }
          piVar5[2] = (int)lbl_803E3DF8;
          if ((uint)*(byte *)(param_9 + 0x1b) < (uint)DAT_803dc070 << 3) {
            *(undefined *)(param_9 + 0x1b) = 0;
            FUN_80017ac8(dVar7,param_2,param_3,param_4,param_5,param_6,param_7,param_8,(int)param_9)
            ;
            return;
          }
          *(byte *)(param_9 + 0x1b) = *(byte *)(param_9 + 0x1b) - (char)((uint)DAT_803dc070 << 3);
        }
      }
      if (*(short *)(piVar5[7] + 10) != -1) {
        (*gPartfxInterface)->spawnObject((void *)param_9, (int)*(short *)(piVar5[7] + 10), NULL, 1, -1, NULL);
      }
      iVar3 = ObjGroup_FindNearestObject((int)*(short *)(piVar5[7] + 0x10),param_9,(float *)0x0);
      if ((iVar3 != 0) &&
         (((*(byte *)(piVar5[7] + 0x12) >> 6 & 1) == 0 || ((float)piVar5[2] < lbl_803E3DFC)))) {
        if ((*(byte *)(piVar5[7] + 0x12) >> 4 & 1) == 0) {
          local_68 = *(float *)(iVar3 + 0x18);
          local_64 = *(float *)(iVar3 + 0xa8) * *(float *)(iVar3 + 8) * lbl_803E3E00 +
                     *(float *)(iVar3 + 0x1c);
          local_60 = *(float *)(iVar3 + 0x20);
        }
        else {
          ObjPath_GetPointWorldPosition(iVar3,0,&local_68,&local_64,&local_60,0);
        }
        FUN_80247eb8(&local_68,(float *)(param_9 + 0xc),&local_50);
        SeekTwiceBeforeRead(&local_50);
        FUN_80247ef8(&local_50,&local_50);
        FUN_80247eb8(&local_50,(float *)(piVar5 + 3),afStack_5c);
        piVar5[3] = (int)local_50;
        piVar5[4] = (int)local_4c;
        piVar5[5] = (int)local_48;
        FUN_80247edc((double)lbl_803E3DF4,afStack_5c,afStack_5c);
        FUN_80247e94(&local_50,afStack_5c,&local_50);
        param_6 = (double)lbl_803E3DF4;
        param_5 = (double)lbl_803E3DFC;
        *(float *)(param_9 + 0x12) =
             *(float *)(param_9 + 0x12) +
             (float)((double)((float)(param_6 + (double)(float)piVar5[2]) *
                             local_50 * (float)piVar5[1]) / param_5);
        *(float *)(param_9 + 0x16) =
             *(float *)(param_9 + 0x16) +
             (float)((double)((float)(param_6 + (double)(float)piVar5[2]) *
                             local_48 * (float)piVar5[1]) / param_5);
        if (-1 < *(char *)(piVar5[7] + 0x12)) {
          param_4 = (double)*(float *)(param_9 + 0x14);
          *(float *)(param_9 + 0x14) =
               (float)(param_4 +
                      (double)(float)((double)((float)(param_6 + (double)(float)piVar5[2]) *
                                              lbl_803E3E04 * local_4c * (float)piVar5[1]) /
                                     param_5));
        }
      }
      fVar2 = lbl_803E3E08;
      *(float *)(param_9 + 0x12) = *(float *)(param_9 + 0x12) * lbl_803E3E08;
      *(float *)(param_9 + 0x16) = *(float *)(param_9 + 0x16) * fVar2;
      *(float *)(param_9 + 0x14) = *(float *)(param_9 + 0x14) * lbl_803E3E0C;
      if (*(char *)(piVar5[7] + 0x12) < '\0') {
        *(float *)(param_9 + 0x14) =
             *(float *)(param_9 + 0x14) -
             (lbl_803E3E10 * lbl_803DC074 * (float)piVar5[2]) / lbl_803E3E14;
      }
      dVar8 = DOUBLE_803e3e28;
      dVar7 = DOUBLE_803e3e20;
      if ((*(byte *)(piVar5[7] + 0x12) >> 5 & 1) == 0) {
        if (param_9[0x23] == 0x482) {
          uStack_3c = (uint)DAT_803dc070;
          local_40 = 0x43300000;
          uStack_34 = (int)(short)*param_9 ^ 0x80000000;
          local_38 = 0x43300000;
          iVar3 = (int)(lbl_803E3E18 * lbl_803DC9B0 *
                        (float)((double)CONCAT44(0x43300000,uStack_3c) - DOUBLE_803e3e20) +
                       (float)((double)CONCAT44(0x43300000,uStack_34) - DOUBLE_803e3e28));
          local_30 = (longlong)iVar3;
          *param_9 = (ushort)iVar3;
          uStack_24 = (uint)DAT_803dc070;
          local_28 = 0x43300000;
          uStack_1c = (int)(short)param_9[1] ^ 0x80000000;
          local_20 = 0x43300000;
          iVar3 = (int)(lbl_803DC9B4 * (float)((double)CONCAT44(0x43300000,uStack_24) - dVar7) +
                       (float)((double)CONCAT44(0x43300000,uStack_1c) - dVar8));
          local_18 = (longlong)iVar3;
          param_9[1] = (ushort)iVar3;
          param_4 = dVar7;
        }
      }
      else {
        FUN_8020a4ac((double)lbl_803E3DF8,(double)lbl_803E3DF0,param_9,(float *)(param_9 + 0x12)
                     ,10);
        param_9[2] = param_9[2] + (ushort)DAT_803dc070 * 0x500;
      }
      FUN_800068c4((uint)param_9,*(ushort *)(piVar5[7] + 2));
      dVar7 = (double)(*(float *)(param_9 + 0x14) * lbl_803DC074);
      dVar8 = (double)(*(float *)(param_9 + 0x16) * lbl_803DC074);
      FUN_80017a88((double)(*(float *)(param_9 + 0x12) * lbl_803DC074),dVar7,dVar8,(int)param_9);
      ObjHits_SetHitVolumeSlot((int)param_9,0x16,1,0);
      ObjHits_EnableObject((int)param_9);
      iVar3 = *(int *)(*(int *)(param_9 + 0x2a) + 0x50);
      if (((iVar3 != 0) && (*(ushort *)(iVar3 + 0x46) != param_9[0x23])) && (iVar3 != *piVar5)) {
        piVar5[2] = (int)lbl_803E3DF8;
        ObjHits_DisableObject((int)param_9);
        if (*(short *)(piVar5[7] + 4) != -1) {
          FUN_8008112c((double)lbl_803E3DF4,dVar7,dVar8,param_4,param_5,param_6,param_7,param_8,
                       param_9,0,1,0,1,0,1,0);
          FUN_800067e8((uint)param_9,*(ushort *)(piVar5[7] + 4),3);
        }
        FUN_8007f718((float *)(piVar5 + 8),0x78);
      }
    }
    else {
      iVar3 = FUN_8007f764((float *)(piVar5 + 8));
      if (iVar3 != 0) {
        FUN_80017ac8(uVar6,param_2,param_3,param_4,param_5,param_6,param_7,param_8,(int)param_9);
      }
    }
  }
  else {
    FUN_80017ac8(extraout_f1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,(int)param_9);
  }
  return;
}


/* Trivial 4b 0-arg blr leaves. */
void kaldachompspit_release(void) {}
void kaldachompspit_initialise(void) {}
void pinponspike_render(void) {}
void pinponspike_hitDetect(void) {}
void pinponspike_release(void) {}
void pinponspike_initialise(void) {}
void pollen_release(void) {}
void pollen_initialise(void) {}
void pollenfragment_release(void) {}
void pollenfragment_initialise(void) {}
void mikabomb_hitDetect(void) {}

extern ModgfxInterface **gModgfxInterface;
extern f32 lbl_803E313C;
void pinponspike_free(int obj) {
    (*gExpgfxInterface)->freeSource2((u32)obj);
}
void pollen_free(int obj) {
    (*gExpgfxInterface)->freeSource2((u32)obj);
}
void pinponspike_init(int obj) {
    ((GameObject *)obj)->unkF4 = 0;
    ObjHits_DisableObject(obj);
    ((GameObject *)obj)->anim.alpha = 0xff;
    Sfx_PlayFromObject(obj, SFXsc_attack02);
    ((GameObject *)obj)->objectFlags |= 0x6000;
}
void pollen_hitDetect(int obj) {
    ObjHitsPriorityState *hitState = *(ObjHitsPriorityState **)&((GameObject *)obj)->anim.hitReactState;
    if (hitState->contactFlags != 0) {
        f32 fz;
        ((GameObject *)obj)->anim.localPosX = (*(ObjHitsPriorityState **)&((GameObject *)obj)->anim.hitReactState)->contactPosX;
        ((GameObject *)obj)->anim.localPosY = (*(ObjHitsPriorityState **)&((GameObject *)obj)->anim.hitReactState)->contactPosY;
        ((GameObject *)obj)->anim.localPosZ = (*(ObjHitsPriorityState **)&((GameObject *)obj)->anim.hitReactState)->contactPosZ;
        fz = lbl_803E313C;
        ((GameObject *)obj)->anim.velocityX = fz;
        ((GameObject *)obj)->anim.velocityY = fz;
        ((GameObject *)obj)->anim.velocityZ = fz;
        ((GameObject *)obj)->anim.alpha = 0;
        ObjHits_DisableObject(obj);
    }
}
void pollenfragment_free(int obj) {
    int *inner = ((GameObject *)obj)->extra;
    if ((void *)inner[6] != NULL) {
        ModelLightStruct_free((void *)inner[6]);
        inner[6] = 0;
    }
    (*gExpgfxInterface)->freeSource2((u32)obj);
}
void mikabomb_free(int obj, int mode) {
    void **inner = ((GameObject *)obj)->extra;
    if (inner[0] != NULL && mode == 0) {
        Obj_FreeObject(inner[0]);
        inner[0] = NULL;
    }
    (*gModgfxInterface)->detachSource((void *)obj);
}

/* 8b "li r3, N; blr" returners. */
int pinponspike_getExtraSize(void) { return 0x0; }
int pinponspike_getObjectTypeId(void) { return 0x0; }
int pollen_getExtraSize(void) { return 0x14; }
int pollen_getObjectTypeId(void) { return 0x0; }
int pollenfragment_getExtraSize(void) { return 0x28; }
int pollenfragment_getObjectTypeId(void) { return 0x0; }
int mikabomb_getExtraSize(void) { return 0x10; }
int mikabomb_getObjectTypeId(void) { return 0x0; }

/* render-with-objRenderFn_8003b8f4 pattern. */
extern f32 lbl_803E3138;
extern void objRenderFn_8003b8f4(f32);
extern f32 lbl_803E31C0;
void pollen_render(int p1, int p2, int p3, int p4, int p5, s8 visible) { s32 v = visible; if (v != 0) objRenderFn_8003b8f4(lbl_803E3138); }
void mikabomb_render(int p1, int p2, int p3, int p4, int p5, s8 visible) { s32 v = visible; if (v != 0) objRenderFn_8003b8f4(lbl_803E31C0); }

extern void kaldachompspit_free(void);
extern void kaldachompspit_update(void);
extern int kaldachompspit_getObjectTypeId(void);
extern int kaldachompspit_getExtraSize(void);

ObjectDescriptor gKaldaChompSpitObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)kaldachompspit_initialise,
    (ObjectDescriptorCallback)kaldachompspit_release,
    0,
    (ObjectDescriptorCallback)kaldachompspit_init,
    (ObjectDescriptorCallback)kaldachompspit_update,
    (ObjectDescriptorCallback)kaldachompspit_hitDetect,
    (ObjectDescriptorCallback)kaldachompspit_render,
    (ObjectDescriptorCallback)kaldachompspit_free,
    (ObjectDescriptorCallback)kaldachompspit_getObjectTypeId,
    kaldachompspit_getExtraSize,
};

ObjectDescriptor gPinPonSpikeObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)pinponspike_initialise,
    (ObjectDescriptorCallback)pinponspike_release,
    0,
    (ObjectDescriptorCallback)pinponspike_init,
    (ObjectDescriptorCallback)pinponspike_update,
    (ObjectDescriptorCallback)pinponspike_hitDetect,
    (ObjectDescriptorCallback)pinponspike_render,
    (ObjectDescriptorCallback)pinponspike_free,
    (ObjectDescriptorCallback)pinponspike_getObjectTypeId,
    pinponspike_getExtraSize,
};

ObjectDescriptor gPollenObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)pollen_initialise,
    (ObjectDescriptorCallback)pollen_release,
    0,
    (ObjectDescriptorCallback)pollen_init,
    (ObjectDescriptorCallback)pollen_update,
    (ObjectDescriptorCallback)pollen_hitDetect,
    (ObjectDescriptorCallback)pollen_render,
    (ObjectDescriptorCallback)pollen_free,
    (ObjectDescriptorCallback)pollen_getObjectTypeId,
    pollen_getExtraSize,
};

PollenFragmentConfig lbl_80320538 = {
    0x0000,
    0x049F,
    0x00B9,
    0x04BA,
    0x04BA,
    -1,
    0.2f,
    0x0000,
    0xC000,
};

PollenFragmentConfig lbl_8032054C = {
    0x02FA,
    0x02FB,
    0x0496,
    0x068F,
    0x068F,
    0x068F,
    0.4f,
    0x0026,
    0x7000,
};

PollenFragmentConfig lbl_80320560 = {
    0x02FA,
    0x02FB,
    0x0496,
    0x068F,
    0x068F,
    0x068F,
    0.4f,
    0x0026,
    0x2000,
};

PollenFragmentConfig lbl_80320574 = {
    0x02FA,
    0x02FB,
    0x0496,
    0x068F,
    0x068F,
    -1,
    0.2f,
    0x0000,
    0x2000,
};

PollenFragmentConfig lbl_80320588 = {
    0x02FA,
    0x02FB,
    0x0496,
    0x068F,
    0x068F,
    0x068F,
    0.4f,
    0x0026,
    0x3000,
};

PollenFragmentConfig *lbl_8032059C[] = {
    &lbl_80320538,
    &lbl_8032054C,
    &lbl_80320560,
    &lbl_80320574,
    &lbl_80320588,
};

extern int fn_80080150(int p);
extern f32 lbl_803E3158;

void pollenfragment_render(int *obj, int p2, int p3, int p4, int p5) {
    int *state = ((GameObject *)obj)->extra;
    if (fn_80080150((int)((char *)state + 0x20)) != 0) return;
    ((void(*)(int*, int, int, int, int, f32))objRenderFn_8003b8f4)(obj, p2, p3, p4, p5, lbl_803E3158);
}

ObjectDescriptor gPollenFragmentObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)pollenfragment_initialise,
    (ObjectDescriptorCallback)pollenfragment_release,
    0,
    (ObjectDescriptorCallback)pollenfragment_init,
    (ObjectDescriptorCallback)pollenfragment_update,
    (ObjectDescriptorCallback)pollenfragment_hitDetect,
    (ObjectDescriptorCallback)pollenfragment_render,
    (ObjectDescriptorCallback)pollenfragment_free,
    (ObjectDescriptorCallback)pollenfragment_getObjectTypeId,
    pollenfragment_getExtraSize,
};

extern f32 lbl_803E3148;

void pollen_init(int *obj) {
    s16 *state = ((GameObject *)obj)->extra;
    state[0] = (s16)randomGetRange(-0x8000, 0x7fff);
    *(f32 *)&((XyzAnimatorState *)state)->unkC = lbl_803E3148 * (f32)(s32)randomGetRange(0xfa0, 0x1388);
    *(s16 *)((char *)state + 4) = (s16)randomGetRange(-0x8000, 0x7fff);
    *(f32 *)&((XyzAnimatorState *)state)->unk8 = lbl_803E313C;
    *(s16 *)((char *)state + 6) = (s16)randomGetRange(0xe6, 0x1f4);
    *(s16 *)((char *)state + 0x10) = 0;
    *(s16 *)((char *)state + 0x12) = 0;
    ((GameObject *)obj)->anim.alpha = 0xff;
    ObjHits_DisableObject(obj);
    {
        int *p = *(int **)((char *)obj + 0x64);
        if (p != NULL) {
            *(int *)((char *)p + 0x30) = *(int *)((char *)p + 0x30) | 0x810;
        }
    }
}

/* ==== v1.0 recovered functions (drift additions) ==== */


typedef struct {
    f32 x, y, z;
} XyzVec;

extern f32 timeDelta;
extern u8 framesThisStep;
extern f32 lbl_803DBD48;
extern f32 lbl_803DBD4C;
extern f32 lbl_803E3110;
extern f32 lbl_803E3114;
extern f32 lbl_803E3118;
extern f32 lbl_803E311C;
extern f32 lbl_803E3120;
extern f32 lbl_803E3124;
extern f32 lbl_803E3128;
extern f32 lbl_803E312C;
extern f64 lbl_803E3130;
extern f32 lbl_803E3140;
extern f32 lbl_803E315C;
extern f32 lbl_803E3160;
extern f32 lbl_803E3164;
extern f32 lbl_803E3168;
extern f32 lbl_803E316C;
extern f32 lbl_803E3170;
extern f32 lbl_803E3174;
extern f32 lbl_803E3178;
extern f32 lbl_803E317C;
extern f32 lbl_803E3180;
extern f64 lbl_803E3188;
extern f32 sqrtf(f32 x);
extern int getAngle(f32 a, f32 b);
extern void objMove(int obj, f32 x, f32 y, f32 z);
extern void *Obj_GetPlayerObject(void);
extern void *getTrickyObject(void);
extern void Camera_EnableViewYOffset(void);
extern void CameraShake_SetAllMagnitudes(f32 mag);
extern int getCurSeqNo(void);
extern int timerCountDown(int timer);
extern void spawnExplosion(int obj, f32 scale, int p3, int p4, int p5, int p6, int p7, int p8, int p9);
extern void Obj_SmoothTurnAnglesTowardVelocity(int obj, void *vel, int rate, f32 a, f32 b);
extern void Sfx_KeepAliveLoopedObjectSound(int obj, int sfxId);
extern void PSVECSubtract(void *a, void *b, void *out);
extern f32 PSVECMag(void *v);
extern void PSVECNormalize(void *src, void *dst);
extern void PSVECScale(void *src, void *dst, f32 scale);
extern void PSVECAdd(void *a, void *b, void *out);

int fn_80169EF4(f32 speed, f32 grav, f32 *from, f32 *to, u8 flag) {
    f32 a;
    f32 dist;
    f32 dx;
    f32 dy;
    f32 dz;
    f32 t;
    f32 disc;

    dx = from[0] - to[0];
    dz = from[2] - to[2];
    dist = sqrtf(dx * dx + dz * dz);
    dy = from[1] - to[1];
    dist = dist * lbl_803E3110;
    a = grav * (lbl_803E3114 * grav);
    grav = -(grav * dy) - (speed = speed * speed);
    disc = grav * grav - (lbl_803E3118 * a) * (dy * dy + dist * dist);
    if (disc >= lbl_803E311C) {
        if (flag) {
            t = (lbl_803E3120 * (-grav + sqrtf(disc))) / a;
        } else {
            t = (lbl_803E3120 * (-grav - sqrtf(disc))) / a;
        }
        t = sqrtf(t);
        a = dist / t;
        return getAngle(sqrtf(-(a * a - speed)), a);
    }
    return 0x2000;
}

void pinponspike_update(int obj) {
    f32 vx;
    f32 vy;
    f32 vz;

    if (((GameObject *)obj)->unkF4 > 0) {
        ((GameObject *)obj)->unkF4 = (int)((f32)((GameObject *)obj)->unkF4 - timeDelta);
        if (((GameObject *)obj)->unkF4 <= 0) {
            Obj_FreeObject(obj);
            return;
        }
    }
    if (((GameObject *)obj)->anim.alpha != 0) {
        vx = ((GameObject *)obj)->anim.velocityX * timeDelta;
        vy = ((GameObject *)obj)->anim.velocityY * timeDelta;
        vz = ((GameObject *)obj)->anim.velocityZ * timeDelta;
        objMove(obj, vx, vy, vz);
        ((GameObject *)obj)->anim.velocityY += lbl_803E3124 * timeDelta;
        if (((GameObject *)obj)->anim.velocityY < *(f32 *)&lbl_803E3128) {
            ((GameObject *)obj)->anim.velocityY = lbl_803E3128;
        }
        ((GameObject *)obj)->anim.rotX = getAngle(vx, vz) - 0x8000;
        ((GameObject *)obj)->anim.rotY = 0x4000 - getAngle(sqrtf(vx * vx + vz * vz), vy);
        ObjHits_SetHitVolumeSlot(obj, 10, 1, 0);
        ObjHits_EnableObject(obj);
        if ((*(ObjHitsPriorityState **)&((GameObject *)obj)->anim.hitReactState)->lastHitObject != 0 &&
            ((*(ObjHitsPriorityState **)&((GameObject *)obj)->anim.hitReactState)->lastHitObject == (int)Obj_GetPlayerObject() ||
             (*(ObjHitsPriorityState **)&((GameObject *)obj)->anim.hitReactState)->lastHitObject == (int)getTrickyObject())) {
            int i;
            ((GameObject *)obj)->anim.alpha = 0;
            ((GameObject *)obj)->unkF4 = 0x78;
            (*(ObjHitsPriorityState **)&((GameObject *)obj)->anim.hitReactState)->flags &= ~1;
            for (i = 0; i < 0x19; i++) {
                (*gPartfxInterface)->spawnObject((void *)obj, 0x715, NULL, 1, -1, &i);
            }
            Sfx_PlayFromObject(obj, 0x279);
        } else if ((*(ObjHitsPriorityState **)&((GameObject *)obj)->anim.hitReactState)->contactFlags != 0) {
            int i;
            ((GameObject *)obj)->anim.alpha = 0;
            ((GameObject *)obj)->unkF4 = 0x78;
            (*(ObjHitsPriorityState **)&((GameObject *)obj)->anim.hitReactState)->flags &= ~1;
            for (i = 0; i < 0x19; i++) {
                (*gPartfxInterface)->spawnObject((void *)obj, 0x715, NULL, 1, -1, &i);
            }
            Sfx_PlayFromObject(obj, 0x279);
        } else if (((GameObject *)obj)->anim.localPosY < lbl_803E312C) {
            Obj_FreeObject(obj);
        }
    }
}

void pollen_update(int obj) {
    PollenExtra *extra;
    int i;

    extra = *(PollenExtra **)&((GameObject *)obj)->extra;
    if (extra->fragmentSpawnTimer != 0) {
        extra->fragmentSpawnTimer -= 1;
    } else {
        f32 prev = ((GameObject *)obj)->anim.velocityY;
        ((GameObject *)obj)->anim.velocityY = -(lbl_803E3140 * timeDelta - prev);
        if (prev >= lbl_803E313C && ((GameObject *)obj)->anim.velocityY <= lbl_803E313C) {
            fn_8016A660(obj);
            Sfx_PlayFromObject(obj, 0xb7);
            ((GameObject *)obj)->anim.alpha = 0;
        }
        objMove(obj, ((GameObject *)obj)->anim.velocityX * timeDelta, ((GameObject *)obj)->anim.velocityY * timeDelta, ((GameObject *)obj)->anim.velocityZ * timeDelta);
        ObjHits_SetHitVolumeSlot(obj, 0x16, 1, 0);
        ObjHitbox_SetSphereRadius(obj, 7);
        ObjHits_EnableObject(obj);
        if ((*(ObjHitsPriorityState **)&((GameObject *)obj)->anim.hitReactState)->lastHitObject != 0 &&
            ((*(ObjHitsPriorityState **)&((GameObject *)obj)->anim.hitReactState)->lastHitObject == (int)Obj_GetPlayerObject() ||
             (*(ObjHitsPriorityState **)&((GameObject *)obj)->anim.hitReactState)->lastHitObject == (int)getTrickyObject())) {
            Camera_EnableViewYOffset();
            CameraShake_SetAllMagnitudes(lbl_803E3138);
            Sfx_PlayFromObject(obj, 0xb6);
            ((GameObject *)obj)->anim.alpha = 0;
            extra->fragmentSpawnTimer = 0x3c;
            ObjHits_DisableObject(obj);
        }
        if (((GameObject *)obj)->anim.alpha == 0xff) {
            i = 2;
            do {
                (*gPartfxInterface)->spawnObject((void *)obj, 0x4ba, NULL, 1, -1, NULL);
            } while (i-- != 0);
        }
    }
    if (((GameObject *)obj)->anim.alpha == 0 && extra->fragmentSpawnTimer == 0) {
        Obj_FreeObject(obj);
    }
}

void pollenfragment_hitDetect(int obj) {
    u8 *extra;
    int hit;
    u8 buf[16];

    extra = *(u8 **)&((GameObject *)obj)->extra;
    if (fn_80080150((int)(extra + 0x20)) == 0) {
        hit = ObjHits_GetPriorityHit(obj, buf, 0, 0);
        if (hit == 0xe || hit == 0xf) {
            if ((((PollenFragmentExtra *)extra)->def)->explodeSfx != -1) {
                spawnExplosion(obj, lbl_803E315C, 0, 1, 0, 1, 0, 1, 0);
                Sfx_PlayFromObjectLimited(obj, (u16)(((PollenFragmentExtra *)extra)->def)->explodeSfx, 3);
            }
            ObjHits_DisableObject(obj);
            s16toFloat(extra + 0x20, 0x78);
        }
        if ((*(ObjHitsPriorityState **)&((GameObject *)obj)->anim.hitReactState)->contactFlags != 0) {
            ObjHits_DisableObject(obj);
            *(f32 *)(extra + 8) = lbl_803E3160;
            if ((((PollenFragmentExtra *)extra)->def)->explodeSfx != -1) {
                spawnExplosion(obj, lbl_803E315C, 0, 1, 0, 1, 0, 1, 0);
                Sfx_PlayFromObjectLimited(obj, (u16)(((PollenFragmentExtra *)extra)->def)->explodeSfx, 3);
            }
            s16toFloat(extra + 0x20, 0x78);
        }
    }
}

void pollenfragment_update(int obj) {
    u8 *extra;
    u8 *nearObj;
    void *hit;
    int i;
    f32 w;
    f32 m;
    XyzVec dir;
    XyzVec sc;
    XyzVec pos;

    extra = *(u8 **)&((GameObject *)obj)->extra;
    if (getCurSeqNo() != 0) {
        Obj_FreeObject(obj);
        return;
    }
    if (fn_80080150((int)extra + 0x20) != 0) {
        if (timerCountDown((int)extra + 0x20) != 0) {
            Obj_FreeObject(obj);
        }
        return;
    }
    if (timerCountDown((int)extra + 0x24) != 0) {
        s16toFloat(extra + 0x20, 0x78);
    }
    if (*(void **)&((GameObject *)obj)->unkC4 != NULL) {
        *(int *)extra = *(int *)&((GameObject *)obj)->unkC4;
        *(int *)&((GameObject *)obj)->unkC4 = 0;
    }
    if ((((PollenFragmentExtra *)extra)->def)->timed) {
        *(f32 *)(extra + 8) -= timeDelta;
        if (*(f32 *)(extra + 8) <= lbl_803E3160) {
            if (((GameObject *)obj)->anim.alpha == 0xff) {
                i = 2;
                do {
                    (*gPartfxInterface)->spawnObject(
                        (void *)obj, (int)(((PollenFragmentExtra *)extra)->def)->burstFx, NULL,
                        1, -1, NULL);
                } while (i-- != 0);
            }
            *(f32 *)(extra + 8) = lbl_803E3160;
            if (((GameObject *)obj)->anim.alpha >= framesThisStep << 3) {
                ((GameObject *)obj)->anim.alpha -= framesThisStep << 3;
            } else {
                ((GameObject *)obj)->anim.alpha = 0;
                Obj_FreeObject(obj);
                return;
            }
        }
    }
    if ((((PollenFragmentExtra *)extra)->def)->auraFx != -1) {
        (*gPartfxInterface)->spawnObject((void *)obj,
                                         (int)(((PollenFragmentExtra *)extra)->def)->auraFx,
                                         NULL, 1, -1, NULL);
    }
    nearObj = (u8 *)ObjGroup_FindNearestObject((int)(((PollenFragmentExtra *)extra)->def)->targetGroup, obj, 0);
    if (nearObj != NULL &&
        (!(((PollenFragmentExtra *)extra)->def)->timed || *(f32 *)(extra + 8) < lbl_803E3164)) {
        if ((((PollenFragmentExtra *)extra)->def)->usePath) {
            ObjPath_GetPointWorldPosition(nearObj, 0, &pos.x, &pos.y, &pos.z, 0);
        } else {
            f32 prod;
            pos.x = ((GameObject *)nearObj)->anim.worldPosX;
            prod = ((GameObject *)nearObj)->anim.hitboxScale * ((GameObject *)nearObj)->anim.rootMotionScale;
            pos.y = prod * lbl_803E3168 + ((GameObject *)nearObj)->anim.worldPosY;
            pos.z = ((GameObject *)nearObj)->anim.worldPosZ;
        }
        PSVECSubtract(&pos, (void *)(obj + 0x18), &dir);
        PSVECMag(&dir);
        PSVECNormalize(&dir, &dir);
        PSVECSubtract(&dir, extra + 0xc, &sc);
        ((PollenFragmentExtra *)extra)->velX = dir.x;
        ((PollenFragmentExtra *)extra)->velY = dir.y;
        ((PollenFragmentExtra *)extra)->velZ = dir.z;
        PSVECScale(&sc, &sc, lbl_803E315C);
        PSVECAdd(&dir, &sc, &dir);
        ((GameObject *)obj)->anim.velocityX = ((GameObject *)obj)->anim.velocityX +
            ((*(f32 *)(extra + 8) + (w = lbl_803E315C)) * (dir.x * *(f32 *)(extra + 4))) / (m = lbl_803E3164);
        ((GameObject *)obj)->anim.velocityZ = ((GameObject *)obj)->anim.velocityZ +
            ((w + *(f32 *)(extra + 8)) * (dir.z * *(f32 *)(extra + 4))) / m;
        if (!(((PollenFragmentExtra *)extra)->def)->noVertical) {
            ((GameObject *)obj)->anim.velocityY = ((GameObject *)obj)->anim.velocityY +
                ((w + *(f32 *)(extra + 8)) * (lbl_803E316C * (dir.y * *(f32 *)(extra + 4)))) / m;
        }
    }
    ((GameObject *)obj)->anim.velocityX = ((GameObject *)obj)->anim.velocityX * (w = lbl_803E3170);
    ((GameObject *)obj)->anim.velocityZ = ((GameObject *)obj)->anim.velocityZ * w;
    ((GameObject *)obj)->anim.velocityY = ((GameObject *)obj)->anim.velocityY * lbl_803E3174;
    if ((((PollenFragmentExtra *)extra)->def)->noVertical) {
        ((GameObject *)obj)->anim.velocityY = ((GameObject *)obj)->anim.velocityY -
            (lbl_803E3178 * timeDelta * *(f32 *)(extra + 8)) / lbl_803E317C;
    }
    if ((((PollenFragmentExtra *)extra)->def)->smoothTurn) {
        Obj_SmoothTurnAnglesTowardVelocity(obj, (void *)(obj + 0x24), 10, lbl_803E3160, lbl_803E3158);
        ((GameObject *)obj)->anim.rotZ = ((GameObject *)obj)->anim.rotZ + framesThisStep * 0x500;
    } else if (((GameObject *)obj)->anim.seqId == 0x482) {
        ((GameObject *)obj)->anim.rotX = (s16)(int)(lbl_803E3180 * lbl_803DBD48 * (f32)(u32)framesThisStep + (f32)(int)((GameObject *)obj)->anim.rotX);
        ((GameObject *)obj)->anim.rotY = (s16)(int)(lbl_803DBD4C * (f32)(u32)framesThisStep + (f32)(int)((GameObject *)obj)->anim.rotY);
    }
    Sfx_KeepAliveLoopedObjectSound(obj, (u16)(((PollenFragmentExtra *)extra)->def)->loopSfx);
    objMove(obj, ((GameObject *)obj)->anim.velocityX * timeDelta, ((GameObject *)obj)->anim.velocityY * timeDelta, ((GameObject *)obj)->anim.velocityZ * timeDelta);
    ObjHits_SetHitVolumeSlot(obj, 0x16, 1, 0);
    ObjHits_EnableObject(obj);
    hit = (void *)(*(ObjHitsPriorityState **)&((GameObject *)obj)->anim.hitReactState)->lastHitObject;
    if (hit != NULL && *(s16 *)((u8 *)hit + 0x46) != ((GameObject *)obj)->anim.seqId && hit != *(void **)extra) {
        *(f32 *)(extra + 8) = lbl_803E3160;
        ObjHits_DisableObject(obj);
        if ((((PollenFragmentExtra *)extra)->def)->explodeSfx != -1) {
            spawnExplosion(obj, lbl_803E315C, 0, 1, 0, 1, 0, 1, 0);
            Sfx_PlayFromObjectLimited(obj, (u16)(((PollenFragmentExtra *)extra)->def)->explodeSfx, 3);
        }
        s16toFloat(extra + 0x20, 0x78);
    }
}
