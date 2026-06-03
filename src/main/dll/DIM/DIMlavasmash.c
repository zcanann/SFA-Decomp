#include "ghidra_import.h"
#include "main/dll/DIM/DIMlavasmash.h"

#define SFXmn_eggylaugh216 114
#define SFXfoot_run_jingle2 507

extern undefined4 FUN_8000680c();
extern undefined4 FUN_80006824();
extern undefined4 FUN_8001753c();
extern undefined4 FUN_80017544();
extern undefined4 FUN_8001754c();
extern undefined4 FUN_80017588();
extern undefined4 FUN_80017594();
extern undefined4 FUN_8001759c();
extern undefined4 FUN_800175b0();
extern undefined4 FUN_800175cc();
extern undefined4 FUN_800175d0();
extern undefined4 FUN_800175ec();
extern undefined4 FUN_80017620();
extern void* FUN_80017624();
extern uint GameBit_Get(int eventId);
extern undefined4 GameBit_Set(int eventId, int value);
extern u32 randomGetRange(int min, int max);
extern void Sfx_PlayFromObject(int obj,int sfxId);
extern int FUN_80017a90();
extern undefined4 FUN_80017ac8();
extern undefined4 ObjHits_SetHitVolumeSlot();
extern undefined4 ObjHits_DisableObject();
extern int getTrickyObject(void);
extern int Obj_GetPlayerObject(void);
extern void Obj_FreeObject(int obj);
extern void fn_80098B18(int obj,f32 scale,int type,int param_4,int param_5,int param_6);
extern undefined8 ObjGroup_RemoveObject();
extern undefined4 ObjGroup_AddObject();
extern int objCreateLight(int obj,int param_2);
extern void modelLightStruct_setField50(int light,int value);
extern void modelLightStruct_setColorsA8AC(int light,int r,int g,int b,int a);
extern void modelLightStruct_setColors100104(int light,int r,int g,int b,int a);
extern void lightDistAttenFn_8001dc38(int light,f32 near,f32 far);
extern void lightFn_8001db6c(int light,int mode,f32 value);
extern void lightVecFn_8001dd88(int light,f32 x,f32 y,f32 z);
extern void lightFn_8001d620(int light,int param_2,int param_3);
extern void lightSetFieldB0(int light,int r,int g,int b,int a);
extern void fn_8001D730(int light,int param_2,int r,int g,int b,int a,f32 radius);
extern void fn_8001D714(int light,f32 radius);
extern undefined4 FUN_8003b818();
extern undefined4 FUN_8005fe14();
extern undefined4 FUN_80081110();
extern int FUN_8028683c();
extern undefined4 FUN_80286888();
extern void dimlogfire_SeqFn(void);

extern undefined4* DAT_803dd6f8;
extern undefined4* DAT_803dd708;
extern f64 DOUBLE_803e54b0;
extern f64 DOUBLE_803e54d8;
extern f32 timeDelta;
extern f32 oneOverTimeDelta;
extern u8 framesThisStep;
extern s16 lbl_803DBEE8;
extern f32 lbl_803DC074;
extern s16 lbl_80323BC0[];
extern f32 lbl_803E4820;
extern f32 lbl_803E4824;
extern f32 lbl_803E4828;
extern f32 lbl_803E482C;
extern f32 lbl_803E4830;
extern f32 lbl_803E4834;
extern f32 lbl_803E4838;
extern f32 lbl_803E483C;
extern f64 lbl_803E4840;
extern f32 lbl_803E484C;
extern f32 lbl_803E4850;
extern f32 lbl_803E4854;
extern f64 lbl_803E4858;
extern f32 lbl_803E54AC;
extern f32 lbl_803E54B8;
extern f32 lbl_803E54BC;
extern f32 lbl_803E54C0;
extern f32 lbl_803E54C4;
extern f32 lbl_803E54C8;
extern f32 lbl_803E54CC;
extern f32 lbl_803E54D0;
extern f32 lbl_803E54D4;

/*
 * --INFO--
 *
 * Function: dimlogfire_update
 * EN v1.0 Address: 0x801B0924
 * EN v1.0 Size: 708b
 * EN v1.1 Address: 0x801B0B58
 * EN v1.1 Size: 204b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void dimlogfire_update(int obj)
{
  bool hitPulseB;
  byte stateId;
  float sparkAlpha;
  s16 lightAlpha;
  int light;
  int tricky;
  int *state;
  float local_28;
  float local_24;
  float local_20;

  state = *(int **)(obj + 0xb8);
  tricky = *(int *)(obj + 0x4c);
  *(byte *)(obj + 0xaf) = *(byte *)(obj + 0xaf) | 8;
  stateId = *(byte *)((int)state + 0x1a);
  if (stateId != 3) {
    if (stateId < 3) {
      if (stateId == 1) {
        if (*state != 0) {
          lightFn_8001db6c(*state,1,lbl_803E4824);
        }
        Sfx_PlayFromObject(obj,SFXmn_eggylaugh216);
        *(float *)(state + 4) = *(float *)(state + 4) - timeDelta;
        if (lbl_803E4828 < *(float *)(state + 4)) {
          tricky = 0;
        }
        else {
          tricky = 7;
          *(float *)(state + 4) = *(float *)(state + 4) + lbl_803E482C;
        }
        *(float *)(state + 5) = *(float *)(state + 5) - timeDelta;
        sparkAlpha = *(float *)(state + 5);
        hitPulseB = sparkAlpha <= lbl_803E4828;
        if (hitPulseB) {
          *(float *)(state + 5) = sparkAlpha + lbl_803E4820;
        }
        local_28 = lbl_803E4828;
        local_24 = lbl_803E482C;
        local_20 = lbl_803E4828;
        fn_80098B18(obj,*(float *)(obj + 8),2,tricky,hitPulseB,(int)&local_28);
        ObjHits_SetHitVolumeSlot(obj,0x1f,1,0);
        goto LAB_801b0b30;
      }
      if (stateId != 0) {
        if (*state != 0) {
          lightFn_8001db6c(*state,0,lbl_803E4824);
        }
        if (*(char *)(state + 7) < '\x01') {
          ObjHits_DisableObject(obj);
          *(undefined *)((int)state + 0x1a) = 1;
          *(undefined *)((int)state + 0x1d) = 1;
          GameBit_Set((int)*(short *)(tricky + 0x1e),1);
        }
        tricky = getTrickyObject();
        if (tricky != 0) {
          if ((*(byte *)(obj + 0xaf) & 4) != 0) {
            (*(void (**)(int,int,int,int))(**(int **)(tricky + 0x68) + 0x28))(tricky,obj,1,4);
          }
          *(byte *)(obj + 0xaf) = *(byte *)(obj + 0xaf) & 0xf7;
        }
        ObjHits_SetHitVolumeSlot(obj,0,0,0);
        goto LAB_801b0b30;
      }
    }
    else if (stateId < 5) {
      goto LAB_801b0b30;
    }
  }
  if (*(char *)(state + 6) == '\0') {
    *(undefined *)((int)state + 0x1a) = 1;
    *(undefined *)((int)state + 0x1d) = 1;
  }
  else {
    *(undefined *)((int)state + 0x1a) = 2;
  }
LAB_801b0b30:
  if (*(char *)((int)state + 0x1d) != '\0') {
    *(undefined *)((int)state + 0x1d) = 0;
  }
  light = *state;
  if (((light != 0) && (*(char *)(light + 0x2f8) != '\0')) && (*(char *)(light + 0x4c) != '\0')) {
    lightAlpha = (ushort)*(byte *)(light + 0x2f9) + *(char *)(light + 0x2fa) +
                 (short)randomGetRange(-0x19,0x19);
    if (lightAlpha < 0) {
      lightAlpha = 0;
      *(undefined *)(light + 0x2fa) = 0;
    }
    else if (0xff < lightAlpha) {
      lightAlpha = 0xff;
      *(undefined *)(light + 0x2fa) = 0;
    }
    *(char *)(*state + 0x2f9) = (char)lightAlpha;
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801b09dc
 * EN v1.0 Address: 0x801B09DC
 * EN v1.0 Size: 268b
 * EN v1.1 Address: 0x801B0C24
 * EN v1.1 Size: 336b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_801b09dc(uint param_1,undefined4 param_2,int param_3)
{
  byte bVar1;
  int iVar2;
  
  iVar2 = *(int *)(param_1 + 0xb8);
  if (*(char *)(iVar2 + 0x1a) == '\x01') {
    FUN_80006824(param_1,SFXmn_eggylaugh216);
  }
  else {
    FUN_8000680c(param_1,0x40);
  }
  bVar1 = *(byte *)(param_3 + 0x80);
  if (bVar1 == 2) {
    GameBit_Set(0x2e,1);
  }
  else if (bVar1 < 2) {
    if (bVar1 != 0) {
      *(byte *)(iVar2 + 0x1b) = *(byte *)(iVar2 + 0x1b) ^ 1;
    }
  }
  else if (bVar1 < 4) {
    *(undefined *)(iVar2 + 0x1a) = 4;
  }
  if (*(char *)(iVar2 + 0x1b) == '\0') {
    FUN_8000680c(param_1,1);
  }
  else {
    (**(code **)(*DAT_803dd708 + 8))(param_1,0xd7,0,0,0xffffffff,0);
    FUN_8000680c(param_1,5);
  }
  *(undefined *)(param_3 + 0x80) = 0;
  return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_801b0ae8
 * EN v1.0 Address: 0x801B0AE8
 * EN v1.0 Size: 256b
 * EN v1.1 Address: 0x801B0D74
 * EN v1.1 Size: 136b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801b0ae8(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9,int param_10)
{
  uint uVar1;
  uint *puVar2;
  undefined8 uVar3;
  
  puVar2 = *(uint **)(param_9 + 0xb8);
  uVar3 = (**(code **)(*DAT_803dd6f8 + 0x18))();
  uVar1 = puVar2[1];
  if ((uVar1 != 0) && (param_10 == 0)) {
    FUN_80017ac8(uVar3,param_2,param_3,param_4,param_5,param_6,param_7,param_8,uVar1);
  }
  ObjGroup_RemoveObject(param_9,0x31);
  uVar1 = *puVar2;
  if (uVar1 != 0) {
    FUN_80017620(uVar1);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: dimlogfire_init
 * EN v1.0 Address: 0x801B0BE8
 * EN v1.0 Size: 492b
 * EN v1.1 Address: 0x801B0DFC
 * EN v1.1 Size: 220b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void dimlogfire_init(int obj,int def)
{
  int eventActive;
  u32 radius;
  int *state;
  
  *(void **)(obj + 0xbc) = (void *)dimlogfire_SeqFn;
  ObjGroup_AddObject(obj,0x31);
  state = *(int **)(obj + 0xb8);
  *(undefined *)(state + 8) = 0;
  *(char *)(state + 6) = (char)*(short *)(def + 0x1a);
  *(char *)(state + 7) = (char)*(short *)(def + 0x1c);
  *(undefined *)((int)state + 0x1e) = *(undefined *)(state + 7);
  eventActive = GameBit_Get((int)*(short *)(def + 0x1e));
  if (eventActive != 0) {
    *(undefined *)((int)state + 0x1a) = 1;
    *(undefined *)((int)state + 0x1d) = 1;
  }
  *(ushort *)(obj + 0xb0) = *(ushort *)(obj + 0xb0) | 0x2000;
  state[4] = (int)lbl_803E482C;
  state[5] = (int)lbl_803E4820;
  if (*state == 0) {
    *state = objCreateLight(obj,1);
  }
  if (*state != 0) {
    modelLightStruct_setField50(*state,2);
    modelLightStruct_setColorsA8AC(*state,0xff,0x7f,0,0xff);
    modelLightStruct_setColors100104(*state,0xff,0x7f,0,0xff);
    radius = (int)(lbl_803E4830 * *(float *)(obj + 8)) ^ 0x80000000;
    lightDistAttenFn_8001dc38
              (*state,(float)((double)CONCAT44(0x43300000,radius) - lbl_803E4840),
               lbl_803E4834 + (float)((double)CONCAT44(0x43300000,radius) - lbl_803E4840));
    lightFn_8001db6c(*state,1,lbl_803E4828);
    lightVecFn_8001dd88(*state,lbl_803E4828,lbl_803E4838,lbl_803E4828);
    lightFn_8001d620(*state,1,3);
    lightSetFieldB0(*state,0xff,0x5c,0,0xff);
    fn_8001D730(*state,0,0xff,0x7f,0,0x87,lbl_803E483C * *(float *)(obj + 8));
    fn_8001D714(*state,lbl_803E4834);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: dimsnowball_getExtraSize
 * EN v1.0 Address: 0x801B0DD4
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x801B0F50
 * EN v1.1 Size: 8b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int dimsnowball_getExtraSize(void)
{
  return 0x10;
}

/*
 * --INFO--
 *
 * Function: dimsnowball_getObjectTypeId
 * EN v1.0 Address: 0x801B0DDC
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x801B0F58
 * EN v1.1 Size: 8b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int dimsnowball_getObjectTypeId(void)
{
  return 2;
}

/*
 * --INFO--
 *
 * Function: dimsnowball_free
 * EN v1.0 Address: 0x801B0DE4
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x801B0F60
 * EN v1.1 Size: 4b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void dimsnowball_free(void)
{
}

/* render-with-objRenderFn_8003b8f4 pattern. */
extern f32 lbl_803E4848;
extern void objRenderFn_8003b8f4(f32);
#pragma peephole off
void dimsnowball_render(int p1, int p2, int p3, int p4, int p5, s8 visible) { s32 v = visible; if (v != 0) objRenderFn_8003b8f4(lbl_803E4848); }

void dimsnowball_hitDetect(int *obj) {
    int *state = *(int**)((char*)obj + 0xb8);
    int *inner = (int*)state[0];
    if ((*(u16*)((char*)inner + 0xb0) & 0x40) == 0) return;
    state[0] = 0;
}

void dimsnowball_update(int obj)
{
  float currentX;
  float currentY;
  float currentZ;
  float nextX;
  float nextY;
  float nextZ;
  s16 pathIndex;
  s16 prevIndex;
  s16 nextIndex;
  s16 nextNextIndex;
  s16 lastIndex;
  int model;
  int player;
  int *state;
  f32 velocityLen;

  state = *(int **)(obj + 0xb8);
  player = Obj_GetPlayerObject();
  if (*state == 0) {
    Obj_FreeObject(obj);
    return;
  }
  pathIndex = (short)state[2];
  lastIndex = lbl_803DBEE8 - 1;
  if (pathIndex >= lastIndex) {
    Obj_FreeObject(obj);
    return;
  }
  prevIndex = pathIndex - 1;
  if (prevIndex < 0) {
    prevIndex = 0;
  }
  nextIndex = pathIndex + 1;
  if (nextIndex >= lbl_803DBEE8) {
    nextIndex = lastIndex;
  }
  nextNextIndex = pathIndex + 2;
  if (nextNextIndex >= lbl_803DBEE8) {
    nextNextIndex = lastIndex;
  }
  currentX = (float)((double)CONCAT44(0x43300000,(int)lbl_80323BC0[pathIndex * 3] ^ 0x80000000) -
                    lbl_803E4858) * lbl_803E484C;
  currentY = (float)((double)CONCAT44(0x43300000,(int)lbl_80323BC0[pathIndex * 3 + 1] ^ 0x80000000) -
                    lbl_803E4858) * lbl_803E484C;
  currentZ = (float)((double)CONCAT44(0x43300000,(int)lbl_80323BC0[pathIndex * 3 + 2] ^ 0x80000000) -
                    lbl_803E4858) * lbl_803E484C;
  nextX = (float)((double)CONCAT44(0x43300000,(int)lbl_80323BC0[nextIndex * 3] ^ 0x80000000) -
                 lbl_803E4858) * lbl_803E484C;
  nextY = (float)((double)CONCAT44(0x43300000,(int)lbl_80323BC0[nextIndex * 3 + 1] ^ 0x80000000) -
                 lbl_803E4858) * lbl_803E484C;
  nextZ = (float)((double)CONCAT44(0x43300000,(int)lbl_80323BC0[nextIndex * 3 + 2] ^ 0x80000000) -
                 lbl_803E4858) * lbl_803E484C;
  if (((nextY - ((float)((double)CONCAT44(0x43300000,(int)lbl_80323BC0[nextNextIndex * 3 + 1] ^
                                             0x80000000) - lbl_803E4858) * lbl_803E484C) <=
        lbl_803E4850) &&
      (currentY - ((float)((double)CONCAT44(0x43300000,(int)lbl_80323BC0[prevIndex * 3 + 1] ^
                                            0x80000000) - lbl_803E4858) * lbl_803E484C) <=
       lbl_803E4850)) && (*(char *)(state + 3) < '\x01')) {
    velocityLen = sqrtf(*(float *)(obj + 0x2c) * *(float *)(obj + 0x2c) +
                        *(float *)(obj + 0x24) * *(float *)(obj + 0x24) +
                        *(float *)(obj + 0x28) * *(float *)(obj + 0x28));
    if ((*(ushort *)(player + 0xb0) & 0x1000) == 0) {
      Sfx_PlayFromObject(obj,SFXfoot_run_jingle2);
    }
    *(undefined *)(state + 3) = 0x1e;
  }
  *(float *)(obj + 0xc) = lbl_803E4850 * (nextX - currentX) + currentX;
  *(float *)(obj + 0x10) = lbl_803E4850 * (nextY - currentY) + currentY;
  *(float *)(obj + 0x14) = lbl_803E4850 * (nextZ - currentZ) + currentZ;
  *(float *)(obj + 0xc) = *(float *)(obj + 0xc) + *(float *)(*state + 0xc);
  *(float *)(obj + 0x10) = *(float *)(obj + 0x10) + *(float *)(*state + 0x10);
  *(float *)(obj + 0x14) = *(float *)(obj + 0x14) + *(float *)(*state + 0x14);
  *(float *)(obj + 0x24) = oneOverTimeDelta * (*(float *)(obj + 0xc) - *(float *)(obj + 0x80));
  *(float *)(obj + 0x28) = oneOverTimeDelta * (*(float *)(obj + 0x10) - *(float *)(obj + 0x84));
  *(float *)(obj + 0x2c) = oneOverTimeDelta * (*(float *)(obj + 0x14) - *(float *)(obj + 0x88));
  state[2] = state[2] + framesThisStep;
  if ('\0' < *(char *)(state + 3)) {
    *(byte *)(state + 3) = *(char *)(state + 3) - framesThisStep;
  }
  *(short *)(obj + 2) =
       (short)(int)-(lbl_803E4854 * -*(float *)(obj + 0x2c) -
                    (float)((double)CONCAT44(0x43300000,(int)*(short *)(obj + 2) ^ 0x80000000) -
                           lbl_803E4858));
  *(short *)(obj + 4) =
       (short)(int)-(lbl_803E4854 * *(float *)(obj + 0x24) -
                    (float)((double)CONCAT44(0x43300000,(int)*(short *)(obj + 4) ^ 0x80000000) -
                           lbl_803E4858));
  model = *(int *)(obj + 0x54);
  if (model != 0) {
    *(ushort *)(model + 0x60) = *(ushort *)(model + 0x60) | 1;
    *(undefined *)(model + 0x6e) = 4;
    *(undefined *)(model + 0x6f) = 2;
    *(undefined4 *)(model + 0x48) = 0x10;
    *(undefined4 *)(model + 0x4c) = 0x10;
  }
  return;
}
#pragma peephole reset
