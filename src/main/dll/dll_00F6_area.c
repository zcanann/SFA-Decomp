#include "main/dll/tFrameAnimator.h"
#include "main/game_object.h"
#include "main/dll/tframeanimator_state.h"

typedef struct LevelnameState
{
    u8 pad0[0x8 - 0x0];
    s32 unk8;
    u8 padC[0xE - 0xC];
    s16 unkE;
    s16 unk10;
    s16 unk12;
    u8 pad14[0x18 - 0x14];
} LevelnameState;


extern int* Obj_GetPlayerObject(void);
extern void GameBit_Set(int gameBit, int value);
extern u32 GameBit_Get(int gameBit);
extern int* gameTextGet(int textId);



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


int area_getExtraSize(void) { return 0x0; }
int area_getObjectTypeId(void) { return 0x0; }

void area_free(void)
{
}

void area_render(void)
{
}

void area_hitDetect(void)
{
}

void area_update(void)
{
}

/* obj->u16_X |= MASK */
void area_init(u16* obj)
{
    u32 v;
    v = ((GameObject*)obj)->objectFlags;
    v |= 0xa000;
    ((GameObject*)obj)->objectFlags = (u16)v;
}

void area_release(void)
{
}

void area_initialise(void)
{
}

/* Trivial 4b 0-arg blr leaves. */
void levelname_free(void);

void levelname_render(void);

void levelname_hitDetect(void);

void levelname_release(void);

void levelname_initialise(void);

extern u8 framesThisStep;
extern f32 Vec_distance(f32 * a, f32 * b);
extern f32 mathSinf(f32 v);
extern f32 lbl_803E36E0;
extern f32 lbl_803E36E4;
extern f32 lbl_803E36E8;

void levelname_update(int* obj);

void levelname_init(int obj, int objDef);

void ProjectileSwitch_free(void);

/* 8b "li r3, N; blr" returners. */
int levelname_getExtraSize(void);
int levelname_getObjectTypeId(void);
int ProjectileSwitch_getExtraSize(void);


int levelname_SeqFn(int obj, int unused, ObjAnimUpdateState* animUpdate);

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
