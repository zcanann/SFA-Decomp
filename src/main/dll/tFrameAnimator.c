#include "main/dll/tFrameAnimator.h"
#include "main/game_object.h"
#include "main/dll/path_control_interface.h"
#include "main/dll/tframeanimator_state.h"
#include "main/objanim_internal.h"
#include "main/objlib.h"
#include "main/objanim_update.h"

typedef struct LevelnameState {
    u8 pad0[0x8 - 0x0];
    s32 unk8;
    u8 padC[0xE - 0xC];
    s16 unkE;
    s16 unk10;
    s16 unk12;
    u8 pad14[0x18 - 0x14];
} LevelnameState;


extern void *memset(void *dest, int value, u32 size);
extern int *Obj_GetPlayerObject(void);
extern void GameBit_Set(int gameBit, int value);
extern u32 GameBit_Get(int gameBit);
extern int *gameTextGet(int textId);

extern u8 lbl_80320F30[];
extern f32 lbl_803E369C;

int levelname_SeqFn(int obj, int unused, ObjAnimUpdateState *animUpdate);

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

  state = ((GameObject *)obj)->extra;
  pathFlag = 5;
  memset(state, 0, 0x2cc);
  Obj_GetPlayerObject();
  state[0x274] = 0;
  ((TFrameAnimatorState *)state)->unk26C = lbl_803E369C;
  ((GameObject *)obj)->objectFlags |= 0x2000;
  objDef = *(int *)&((GameObject *)obj)->anim.hitReactState;
  ((TFrameAnimatorState *)state)->primaryRadius = (f32)((ObjHitsPriorityState *)objDef)->primaryRadius;
  (*gPathControlInterface)->init(state, 0, 0x40007, 1);
  (*gPathControlInterface)->setLocalPointCollision(state, 1, lbl_80320F30, state + 0x268, 1);
  (*gPathControlInterface)->setup(state, 1, lbl_80320F30, state + 0x268, &pathFlag);
  (*gPathControlInterface)->attachObject((void *)obj, state);
  ObjHits_DisableObject(obj);
  state[0x25b] = 0;
  ObjMsg_AllocQueue((void *)obj, 1);
  GameBit_Set(0x3f8, 0);
}


int area_getExtraSize(void) { return 0x0; }
int area_getObjectTypeId(void) { return 0x0; }
void area_free(void) {}
void area_render(void) {}
void area_hitDetect(void) {}
void area_update(void) {}

/* obj->u16_X |= MASK */
void area_init(u16 *obj) { u32 v; v = ((GameObject *)obj)->objectFlags; v |= 0xa000; ((GameObject *)obj)->objectFlags = (u16)v; }

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
extern f32 mathSinf(f32 v);
extern f32 lbl_803E36E0;
extern f32 lbl_803E36E4;
extern f32 lbl_803E36E8;

void levelname_update(int *obj) {
    u8 *sub;
    int *player;

    sub = ((GameObject *)obj)->extra;
    switch (sub[0x14]) {
    case 0:
        player = Obj_GetPlayerObject();
        if (Vec_distance(&((GameObject *)obj)->anim.worldPosX, &((GameObject *)player)->anim.worldPosX) < (f32)(u32)sub[0xc]) {
            if (((LevelnameState *)sub)->unkE != -1) {
                GameBit_Set(((LevelnameState *)sub)->unkE, 1);
            }
            sub[0x14] = 1;
        }
        break;
    case 1:
        ((LevelnameState *)sub)->unk12 = (s16)(((LevelnameState *)sub)->unk12 + framesThisStep * 4);
        if (((LevelnameState *)sub)->unk12 > 0xdc) {
            ((LevelnameState *)sub)->unk12 = 0xdc;
            sub[0x14] = 2;
        }
        break;
    case 2:
    {
        ((LevelnameState *)sub)->unk10 += framesThisStep;
        if ((u32)((LevelnameState *)sub)->unk10 > (u32)((LevelnameState *)sub)->unk8) {
            sub[0x14] = 3;
        }
        ((LevelnameState *)sub)->unk12 = (s16)((s32)(lbl_803E36E0 * mathSinf((lbl_803E36E4 * (f32)((s32)((LevelnameState *)sub)->unk10 * 0x500)) / lbl_803E36E8)) + 0xdc);
        break;
    }
    case 3:
        ((LevelnameState *)sub)->unk12 = (s16)(((LevelnameState *)sub)->unk12 - framesThisStep * 4);
        if (((LevelnameState *)sub)->unk12 < 0) {
            ((LevelnameState *)sub)->unk12 = 0;
            sub[0x14] = 4;
        }
        break;
    case 4:
        break;
    }
}

void levelname_init(int obj, int objDef)
{
    int *state;
    int *text;

    state = ((GameObject *)obj)->extra;
    ((GameObject *)obj)->animEventCallback = (void *)levelname_SeqFn;
    text = gameTextGet(*(int *)(objDef + 0x1c));
    ((TFrameAnimatorState *)state)->unk4 = **(int **)(text + 2);
    ((TFrameAnimatorState *)state)->duration = 0x64;
    ((TFrameAnimatorState *)state)->textRecord = (int)text;
    ((TFrameAnimatorState *)state)->unkC = *(u8 *)(objDef + 0x20);
    ((TFrameAnimatorState *)state)->enableGameBit = *(s16 *)(objDef + 0x18);
    ((TFrameAnimatorState *)state)->phase = 0;
    ((TFrameAnimatorState *)state)->unk12 = 0;
    ((TFrameAnimatorState *)state)->elapsedFrames = 0;
    if (((TFrameAnimatorState *)state)->enableGameBit != -1) {
        if (GameBit_Get(((TFrameAnimatorState *)state)->enableGameBit) != 0) {
            ((TFrameAnimatorState *)state)->phase = 4;
        }
    }
    ((GameObject *)obj)->objectFlags |= 0x2000;
}

void ProjectileSwitch_free(void) {}

/* 8b "li r3, N; blr" returners. */
int levelname_getExtraSize(void) { return 0x18; }
int levelname_getObjectTypeId(void) { return 0x0; }
int ProjectileSwitch_getExtraSize(void) { return 0x8; }

int ProjectileSwitch_getObjectTypeId(int *obj) {
    ObjAnimComponent *objAnim = (ObjAnimComponent *)obj;
    int v = (int)*(u8 *)((char *)*(int **)&((GameObject *)obj)->anim.placementData + 0x1e) >> 2;
    int max = objAnim->modelInstance->modelCount;
    if (v >= max) {
        v = 0;
    }
    return ((u32)v << 11) | 0x400;
}

int levelname_SeqFn(int obj, int unused, ObjAnimUpdateState *animUpdate) {
    int *state = ((GameObject *)obj)->extra;
    int i;
    for (i = 0; i < animUpdate->eventCount; i++) {
        if (animUpdate->eventIds[i] == 1) {
            if (((TFrameAnimatorState *)state)->enableGameBit != -1) {
                GameBit_Set(((TFrameAnimatorState *)state)->enableGameBit, 1);
            }
            ((TFrameAnimatorState *)state)->phase = 1;
            return 4;
        }
    }
    return 0;
}

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
