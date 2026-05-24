#include "ghidra_import.h"
#include "main/dll/tFrameAnimator.h"

extern void *memset(void *dest, int value, u32 size);
extern void ObjHits_DisableObject(int obj);
extern void ObjMsg_AllocQueue(int obj, int capacity);
extern int *Obj_GetPlayerObject(void);
extern void GameBit_Set(int gameBit, int value);
extern u32 GameBit_Get(int gameBit);
extern int *gameTextGet(int textId);

extern void *gPathControlInterface;
extern u8 lbl_80320F30[];
extern f32 lbl_803E369C;

int fn_8017A048(int obj, int unused, u8 *setupData);

/*
 * --INFO--
 *
 * Function: sidekickball_init
 * EN v1.0 Address: 0x80179EB0
 * EN v1.0 Size: 1220b
 * EN v1.1 Address: 0x80179F40
 * EN v1.1 Size: 1204b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 sidekickball_init(int obj)
{
  u8 pathFlag;
  u8 *state;
  int objDef;

  pathFlag = 5;
  state = *(u8 **)(obj + 0xb8);
  memset(state, 0, 0x2cc);
  Obj_GetPlayerObject();
  state[0x274] = 0;
  *(f32 *)(state + 0x26c) = lbl_803E369C;
  *(u16 *)(obj + 0xb0) |= 0x2000;
  objDef = *(int *)(obj + 0x54);
  *(f32 *)(state + 0x268) = (f32)*(s16 *)(objDef + 0x5a);
  (*(void (**)(u8 *, int, int, int))(*(int *)gPathControlInterface + 4))(state, 0, 0x40007, 1);
  (*(void (**)(u8 *, int, u8 *, u8 *, int))(*(int *)gPathControlInterface + 8))(
      state, 1, lbl_80320F30, state + 0x268, 1);
  (*(void (**)(u8 *, int, u8 *, u8 *, u8 *))(*(int *)gPathControlInterface + 0xc))(
      state, 1, lbl_80320F30, state + 0x268, &pathFlag);
  (*(void (**)(int, u8 *))(*(int *)gPathControlInterface + 0x20))(obj, state);
  ObjHits_DisableObject(obj);
  state[0x25b] = 0;
  ObjMsg_AllocQueue(obj, 1);
  GameBit_Set(0x3f8, 0);
}


int area_getExtraSize(void) { return 0x0; }
int area_getObjectTypeId(void) { return 0x0; }
void area_free(void) {}
void area_render(void) {}
void area_hitDetect(void) {}
void area_update(void) {}

/* obj->u16_X |= MASK */
#pragma peephole off
void area_init(u16 *obj) { u32 v; v = *(u16*)((char*)obj + 0xb0); v |= 0xa000; *(u16*)((char*)obj + 0xb0) = (u16)v; }
#pragma peephole reset

void area_release(void) {}
void area_initialise(void) {}

/* Trivial 4b 0-arg blr leaves. */
void levelname_free(void) {}
void levelname_render(void) {}
void levelname_hitDetect(void) {}
void levelname_release(void) {}
void levelname_initialise(void) {}

extern u8 framesThisStep;
extern f32 Vec_distance(f32 *a, f32 *b);
extern f32 fn_80293E80(f32 v);
extern f32 lbl_803E36E0;
extern f32 lbl_803E36E4;
extern f32 lbl_803E36E8;

#pragma scheduling off
#pragma peephole off
void levelname_update(int *obj) {
    u8 *sub;
    int *player;

    sub = *(u8**)((char*)obj + 0xb8);
    switch (sub[0x14]) {
    case 0:
        player = Obj_GetPlayerObject();
        if (Vec_distance((f32*)((char*)obj + 0x18), (f32*)((char*)player + 0x18)) < (f32)(u32)sub[0xc]) {
            if (*(s16*)(sub + 0xe) != -1) {
                GameBit_Set(*(s16*)(sub + 0xe), 1);
            }
            sub[0x14] = 1;
        }
        break;
    case 1:
        *(s16*)(sub + 0x12) = (s16)(*(s16*)(sub + 0x12) + framesThisStep * 4);
        if (*(s16*)(sub + 0x12) > 0xdc) {
            *(s16*)(sub + 0x12) = 0xdc;
            sub[0x14] = 2;
        }
        break;
    case 2:
    {
        *(s16*)(sub + 0x10) += framesThisStep;
        if ((u32)*(s16*)(sub + 0x10) > (u32)*(int*)(sub + 8)) {
            sub[0x14] = 3;
        }
        *(s16*)(sub + 0x12) = (s16)((s32)(lbl_803E36E0 * fn_80293E80((lbl_803E36E4 * (f32)((s32)*(s16*)(sub + 0x10) * 0x500)) / lbl_803E36E8)) + 0xdc);
        break;
    }
    case 3:
        *(s16*)(sub + 0x12) = (s16)(*(s16*)(sub + 0x12) - framesThisStep * 4);
        if (*(s16*)(sub + 0x12) < 0) {
            *(s16*)(sub + 0x12) = 0;
            sub[0x14] = 4;
        }
        break;
    case 4:
        break;
    }
}
#pragma peephole reset
#pragma scheduling reset

void levelname_init(int obj, int objDef)
{
    int *state;
    int *text;

    state = *(int **)(obj + 0xb8);
    *(void **)(obj + 0xbc) = fn_8017A048;
    text = gameTextGet(*(int *)(objDef + 0x1c));
    state[1] = **(int **)(text + 2);
    state[2] = 0x64;
    state[0] = (int)text;
    *(u8 *)((char *)state + 0xc) = *(u8 *)(objDef + 0x20);
    *(s16 *)((char *)state + 0xe) = *(s16 *)(objDef + 0x18);
    *(u8 *)((char *)state + 0x14) = 0;
    *(s16 *)((char *)state + 0x12) = 0;
    *(s16 *)((char *)state + 0x10) = 0;
    if (*(s16 *)((char *)state + 0xe) != -1) {
        if (GameBit_Get(*(s16 *)((char *)state + 0xe)) != 0) {
            *(u8 *)((char *)state + 0x14) = 4;
        }
    }
    *(u16 *)(obj + 0xb0) |= 0x2000;
}

void ProjectileSwitch_free(void) {}

/* 8b "li r3, N; blr" returners. */
int levelname_getExtraSize(void) { return 0x18; }
int levelname_getObjectTypeId(void) { return 0x0; }
int ProjectileSwitch_getExtraSize(void) { return 0x8; }

#pragma scheduling off
#pragma peephole off
int ProjectileSwitch_getObjectTypeId(int *obj) {
    int v = (int)*(u8 *)((char *)*(int **)((char *)obj + 0x4c) + 0x1e) >> 2;
    int max = *(s8 *)((char *)*(int **)((char *)obj + 0x50) + 0x55);
    if (v >= max) {
        v = 0;
    }
    return ((u32)v << 11) | 0x400;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
int fn_8017A048(int obj, int unused, u8 *setupData) {
    int *state = *(int **)((char *)obj + 0xB8);
    int i;
    for (i = 0; i < setupData[0x8B]; i++) {
        if (setupData[0x81 + i] == 1) {
            if (*(s16 *)((char *)state + 0xE) != -1) {
                GameBit_Set(*(s16 *)((char *)state + 0xE), 1);
            }
            *(u8 *)((char *)state + 0x14) = 1;
            return 4;
        }
    }
    return 0;
}
#pragma peephole reset
#pragma scheduling reset

ObjectDescriptor gAreaObjDescriptor = {
    0, 0, 0, OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)area_initialise,
    (ObjectDescriptorCallback)area_release,
    0,
    (ObjectDescriptorCallback)area_init,
    (ObjectDescriptorCallback)area_update,
    (ObjectDescriptorCallback)area_hitDetect,
    (ObjectDescriptorCallback)area_render,
    (ObjectDescriptorCallback)area_free,
    (ObjectDescriptorCallback)area_getObjectTypeId,
    area_getExtraSize,
};
