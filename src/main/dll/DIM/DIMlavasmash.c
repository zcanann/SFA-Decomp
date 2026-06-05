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
extern void modelLightStruct_startColorFade(int light,int param_2,int param_3);
extern void lightSetFieldB0(int light,int r,int g,int b,int a);
extern void modelLightStruct_setupGlow(int light,int param_2,int r,int g,int b,int a,f32 radius);
extern void modelLightStruct_setGlowProjectionRadius(int light,f32 radius);
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
#pragma peephole off
#pragma scheduling off
void dimlogfire_update(int obj)
{
    int a;
    int b;
    int rand;
    s16 alpha;
    uint light;
    int tricky;
    int *state;
    f32 local_28;
    f32 local_24;
    f32 local_20;

    state = *(int **)(obj + 0xb8);
    tricky = *(int *)(obj + 0x4c);
    *(u8 *)(obj + 0xaf) |= 8;
    switch (*(u8 *)((u8 *)state + 0x1a)) {
    case 1:
        if (*(void **)state != NULL) {
            lightFn_8001db6c(*state, 1, lbl_803E4824);
        }
        Sfx_PlayFromObject(obj, SFXmn_eggylaugh216);
        *(f32 *)(state + 4) = *(f32 *)(state + 4) - timeDelta;
        if (*(f32 *)(state + 4) <= lbl_803E4828) {
            a = 7;
            *(f32 *)(state + 4) = *(f32 *)(state + 4) + lbl_803E482C;
        } else {
            a = 0;
        }
        *(f32 *)(state + 5) = *(f32 *)(state + 5) - timeDelta;
        if (*(f32 *)(state + 5) <= lbl_803E4828) {
            b = 1;
            *(f32 *)(state + 5) = *(f32 *)(state + 5) + lbl_803E4820;
        } else {
            b = 0;
        }
        local_28 = lbl_803E4828;
        local_24 = lbl_803E482C;
        local_20 = lbl_803E4828;
        fn_80098B18(obj, *(f32 *)(obj + 8), 2, a, b, (int)&local_28);
        ObjHits_SetHitVolumeSlot(obj, 0x1f, 1, 0);
        break;
    case 2:
        if (*(void **)state != NULL) {
            lightFn_8001db6c(*state, 0, lbl_803E4824);
        }
        if (*(s8 *)((u8 *)state + 0x1c) <= 0) {
            ObjHits_DisableObject(obj);
            *(u8 *)((u8 *)state + 0x1a) = 1;
            *(u8 *)((u8 *)state + 0x1d) = 1;
            GameBit_Set(*(s16 *)(tricky + 0x1e), 1);
        }
        tricky = getTrickyObject();
        if ((uint)tricky != 0) {
            if ((*(u8 *)(obj + 0xaf) & 4) != 0) {
                (*(void (**)(int, int, int, int))(**(int **)(tricky + 0x68) + 0x28))(tricky, obj, 1, 4);
            }
            *(u8 *)(obj + 0xaf) &= ~8;
        }
        ObjHits_SetHitVolumeSlot(obj, 0, 0, 0);
        break;
    case 4:
        break;
    default:
        if (*(u8 *)((u8 *)state + 0x18) == 0) {
            *(u8 *)((u8 *)state + 0x1a) = 1;
            *(u8 *)((u8 *)state + 0x1d) = 1;
        } else {
            *(u8 *)((u8 *)state + 0x1a) = 2;
        }
        break;
    }
    if (*(s8 *)((u8 *)state + 0x1d) != 0) {
        *(u8 *)((u8 *)state + 0x1d) = 0;
    }
    light = *state;
    if (light != 0 && *(u8 *)(light + 0x2f8) != 0 && *(u8 *)(light + 0x4c) != 0) {
        rand = randomGetRange(-0x19, 0x19);
        light = *state;
        alpha = *(u8 *)(light + 0x2f9) + (*(s8 *)(light + 0x2fa) + rand);
        if (alpha < 0) {
            alpha = 0;
            *(u8 *)(light + 0x2fa) = 0;
        } else if (alpha > 0xff) {
            alpha = 0xff;
            *(u8 *)(light + 0x2fa) = 0;
        }
        *(u8 *)(*state + 0x2f9) = alpha;
    }
}
#pragma scheduling reset
#pragma peephole reset

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
#pragma peephole off
#pragma scheduling off
void dimlogfire_init(int obj, int def)
{
    int radius;
    int *state;

    *(void **)(obj + 0xbc) = (void *)dimlogfire_SeqFn;
    ObjGroup_AddObject(obj, 0x31);
    state = *(int **)(obj + 0xb8);
    *(u8 *)((u8 *)state + 0x20) = 0;
    *(u8 *)((u8 *)state + 0x18) = *(s16 *)(def + 0x1a);
    *(s8 *)((u8 *)state + 0x1c) = (s8)*(s16 *)(def + 0x1c);
    *(u8 *)((u8 *)state + 0x1e) = *(u8 *)((u8 *)state + 0x1c);
    if (GameBit_Get(*(s16 *)(def + 0x1e)) != 0) {
        *(u8 *)((u8 *)state + 0x1a) = 1;
        *(u8 *)((u8 *)state + 0x1d) = 1;
    }
    *(u16 *)(obj + 0xb0) |= 0x2000;
    *(f32 *)(state + 4) = lbl_803E482C;
    *(f32 *)(state + 5) = lbl_803E4820;
    if (*(void **)state == NULL) {
        *state = objCreateLight(obj, 1);
    }
    if (*(void **)state != NULL) {
        modelLightStruct_setField50(*state, 2);
        modelLightStruct_setColorsA8AC(*state, 0xff, 0x7f, 0, 0xff);
        modelLightStruct_setColors100104(*state, 0xff, 0x7f, 0, 0xff);
        radius = (int)(lbl_803E4830 * *(f32 *)(obj + 8));
        lightDistAttenFn_8001dc38(*state, (f32)radius, lbl_803E4834 + (f32)radius);
        lightFn_8001db6c(*state, 1, lbl_803E4828);
        lightVecFn_8001dd88(*state, lbl_803E4828, lbl_803E4838, lbl_803E4828);
        modelLightStruct_startColorFade(*state, 1, 3);
        lightSetFieldB0(*state, 0xff, 0x5c, 0, 0xff);
        modelLightStruct_setupGlow(*state, 0, 0xff, 0x7f, 0, 0x87, lbl_803E483C * *(f32 *)(obj + 8));
        modelLightStruct_setGlowProjectionRadius(*state, lbl_803E4834);
    }
}
#pragma scheduling reset
#pragma peephole reset

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

#pragma scheduling off
void dimsnowball_update(int obj)
{
    s16 idx[4];
    f32 x[4];
    f32 y[4];
    f32 z[4];
    void *ap;
    int *state;
    int player;
    int count;
    int last;
    u8 frames;
    u8 *model;
    f32 dy1;
    f32 dy2;
    f32 v24;

    ap = idx;
    ap = x;
    ap = y;
    ap = z;
    state = *(int **)(obj + 0xb8);
    player = Obj_GetPlayerObject();
    if (*(void **)state == NULL) {
        Obj_FreeObject(obj);
        return;
    }
    frames = framesThisStep;
    idx[1] = (s16)state[2];
    count = lbl_803DBEE8;
    last = count - 1;
    if (idx[1] >= last) {
        Obj_FreeObject(obj);
        return;
    }
    idx[0] = idx[1] - 1;
    if (idx[0] < 0) {
        idx[0] = 0;
    }
    idx[2] = idx[1] + 1;
    if (idx[2] >= count) {
        idx[2] = last;
    }
    idx[3] = idx[1] + 2;
    if (idx[3] >= count) {
        idx[3] = last;
    }
    idx[0] *= 3;
    x[0] = (f32)lbl_80323BC0[idx[0]] * lbl_803E484C;
    y[0] = (f32)lbl_80323BC0[idx[0] + 1] * lbl_803E484C;
    z[0] = (f32)lbl_80323BC0[idx[0] + 2] * lbl_803E484C;
    idx[1] *= 3;
    x[1] = (f32)lbl_80323BC0[idx[1]] * lbl_803E484C;
    y[1] = (f32)lbl_80323BC0[idx[1] + 1] * lbl_803E484C;
    z[1] = (f32)lbl_80323BC0[idx[1] + 2] * lbl_803E484C;
    idx[2] *= 3;
    x[2] = (f32)lbl_80323BC0[idx[2]] * lbl_803E484C;
    y[2] = (f32)lbl_80323BC0[idx[2] + 1] * lbl_803E484C;
    z[2] = (f32)lbl_80323BC0[idx[2] + 2] * lbl_803E484C;
    idx[3] *= 3;
    x[3] = (f32)lbl_80323BC0[idx[3]] * lbl_803E484C;
    y[3] = (f32)lbl_80323BC0[idx[3] + 1] * lbl_803E484C;
    z[3] = (f32)lbl_80323BC0[idx[3] + 2] * lbl_803E484C;
    dy1 = y[1] - y[0];
    dy2 = y[2] - y[3];
    if (dy2 <= lbl_803E4850 && dy1 <= lbl_803E4850 && *(s8 *)((u8 *)state + 0xc) <= 0) {
        sqrtf(*(f32 *)(obj + 0x2c) * *(f32 *)(obj + 0x2c) +
              (*(f32 *)(obj + 0x24) * *(f32 *)(obj + 0x24) + *(f32 *)(obj + 0x28) * *(f32 *)(obj + 0x28)));
        if ((*(u16 *)(player + 0xb0) & 0x1000) == 0) {
            Sfx_PlayFromObject(obj, SFXfoot_run_jingle2);
        }
        *(s8 *)((u8 *)state + 0xc) = 0x1e;
    }
    *(f32 *)(obj + 0xc) = lbl_803E4850 * (x[2] - x[1]) + x[1];
    *(f32 *)(obj + 0x10) = lbl_803E4850 * (y[2] - y[1]) + y[1];
    *(f32 *)(obj + 0x14) = lbl_803E4850 * (z[2] - z[1]) + z[1];
    *(f32 *)(obj + 0xc) = *(f32 *)(obj + 0xc) + *(f32 *)(*state + 0xc);
    *(f32 *)(obj + 0x10) = *(f32 *)(obj + 0x10) + *(f32 *)(*state + 0x10);
    *(f32 *)(obj + 0x14) = *(f32 *)(obj + 0x14) + *(f32 *)(*state + 0x14);
    *(f32 *)(obj + 0x24) = oneOverTimeDelta * (*(f32 *)(obj + 0xc) - *(f32 *)(obj + 0x80));
    *(f32 *)(obj + 0x28) = oneOverTimeDelta * (*(f32 *)(obj + 0x10) - *(f32 *)(obj + 0x84));
    *(f32 *)(obj + 0x2c) = oneOverTimeDelta * (*(f32 *)(obj + 0x14) - *(f32 *)(obj + 0x88));
    state[2] = state[2] + frames;
    if (*(s8 *)((u8 *)state + 0xc) > 0) {
        *(s8 *)((u8 *)state + 0xc) -= frames;
    }
    v24 = *(f32 *)(obj + 0x24);
    *(s16 *)(obj + 2) = (int)-(lbl_803E4854 * -*(f32 *)(obj + 0x2c) - (f32)*(s16 *)(obj + 2));
    *(s16 *)(obj + 4) = (int)-(lbl_803E4854 * v24 - (f32)*(s16 *)(obj + 4));
    model = *(u8 **)(obj + 0x54);
    if (model != NULL) {
        *(s16 *)(model + 0x60) |= 1;
        *(u8 *)(model + 0x6e) = 4;
        *(u8 *)(model + 0x6f) = 2;
        *(int *)(model + 0x48) = 0x10;
        *(int *)(model + 0x4c) = 0x10;
    }
}
#pragma scheduling reset
#pragma peephole reset
