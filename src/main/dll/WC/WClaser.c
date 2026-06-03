#include "ghidra_import.h"
#include "main/dll/WC/WClaser.h"

extern uint GameBit_Get(int eventId);
extern undefined4 GameBit_Set(int eventId, int value);
extern int Obj_GetPlayerObject(void);
extern undefined4 *ObjGroup_GetObjects(int group, int *countOut);
extern void ObjMsg_AllocQueue(void *obj, int capacity);
extern void objSetSlot(int *obj, int slot);
extern void objHitDetectFn_80062e84(int player, int hitObj, int mode);
extern void objRenderFn_8003b8f4(f32 scale);
extern void fn_80065574(int a, int *obj, int b);
extern int WM_Galleon_SeqFn(int p1, int p2, void *p3);
extern void fn_80296BBC(int player);
extern void buttonDisable(int controller, int mask);
extern void textureFree(void *resource);
extern int ObjAnim_AdvanceCurrentMove(int obj, f32 moveStepScale, f32 deltaTime, void *events);
extern int ObjAnim_SetCurrentMove(int obj, int moveId, f32 moveProgress, int flags);

typedef struct WCLaserMapEventInterface {
    u8 pad00[0x4C];
    int (*getAnimEvent)(int mapId, int eventId);
    void (*setAnimEvent)(int mapId, int eventId, int value);
} WCLaserMapEventInterface;

extern WCLaserMapEventInterface **gMapEventInterface;
extern int *gObjectTriggerInterface;
extern int *gScreenTransitionInterface;
extern int *gModgfxInterface;

extern f32 timeDelta;
extern u8 lbl_803DDC78;
extern f32 lbl_803E5CEC;
extern f32 lbl_803E5CF0;
extern f32 lbl_803E5CF4;
extern f32 lbl_803E5CF8;
extern f32 lbl_803E5D00;
extern f32 lbl_803E5D04;
extern f32 lbl_803E5D08;

#define OBJ_U8(obj, offset) (*(u8 *)((u8 *)(obj) + (offset)))
#define OBJ_S8(obj, offset) (*(s8 *)((u8 *)(obj) + (offset)))
#define OBJ_S16(obj, offset) (*(s16 *)((u8 *)(obj) + (offset)))
#define OBJ_S32(obj, offset) (*(s32 *)((u8 *)(obj) + (offset)))
#define OBJ_F32(obj, offset) (*(f32 *)((u8 *)(obj) + (offset)))
#define OBJ_PTR(obj, offset) (*(void **)((u8 *)(obj) + (offset)))

#define MAP_EVENT_TEST(mapId, eventId) \
    (*gMapEventInterface)->getAnimEvent((mapId), (eventId))
#define MAP_EVENT_SET(mapId, eventId, value) \
    (*gMapEventInterface)->setAnimEvent((mapId), (eventId), (value))
#define OBJECT_TRIGGER_REFRESH(eventId, obj, arg) \
    ((void (*)(int, int *, int))(*(u32 *)((u8 *)*gObjectTriggerInterface + 0x48)))((eventId), (obj), (arg))
#define SCREEN_TRANSITION_START(kind, value) \
    ((void (*)(int, int))(*(u32 *)((u8 *)*gScreenTransitionInterface + 0xc)))((kind), (value))

#pragma scheduling off
#pragma peephole off
void WM_Galleon_update(int *obj)
{
    int player;
    u8 *state;
    int gameBitA4;

    if (GameBit_Get(0x78) != 0) {
        return;
    }

    if (OBJ_S16(obj, 0x46) == 0x188) {
        OBJ_U8(obj, 0x36) = 0x80;
        return;
    }

    player = Obj_GetPlayerObject();
    state = (u8 *)OBJ_PTR(obj, 0xb8);

    if (GameBit_Get(0x429) != 0) {
        if ((u8)MAP_EVENT_TEST(OBJ_U8(obj, 0x34), 2) != 0) {
            MAP_EVENT_SET(OBJ_U8(obj, 0x34), 1, 0);
            MAP_EVENT_SET(OBJ_U8(obj, 0x34), 2, 0);
        }
    } else if ((GameBit_Get(0xd0) == 0) && ((u8)MAP_EVENT_TEST(OBJ_U8(obj, 0x34), 2) == 0)) {
        MAP_EVENT_SET(OBJ_U8(obj, 0x34), 1, 1);
        MAP_EVENT_SET(OBJ_U8(obj, 0x34), 2, 1);
    }

    if (GameBit_Get(0xd0) == 0) {
        if ((state[0xc] == 0) && (GameBit_Get(0x429) == 0)) {
            MAP_EVENT_SET(OBJ_U8(obj, 0x34), 1, 1);
            MAP_EVENT_SET(OBJ_U8(obj, 0x34), 2, 1);
            state[0xc] = 1;
        }
    } else {
        if ((u8)MAP_EVENT_TEST(OBJ_U8(obj, 0x34), 4) == 0) {
            MAP_EVENT_SET(OBJ_U8(obj, 0x34), 4, 1);
        }
        if (state[0xc] != 0) {
            state[0xc] = 0;
        }
    }

    gameBitA4 = GameBit_Get(0xa4);
    if (gameBitA4 != 0) {
        OBJ_S32(obj, 0xf4) = 10;
    }
    if (gameBitA4 == 0) {
        OBJ_F32(player, 0xc) = lbl_803E5CEC;
        OBJ_F32(player, 0x10) = lbl_803E5CF0;
        OBJ_F32(player, 0x14) = lbl_803E5CF4;
        objHitDetectFn_80062e84(player, (int)obj, 0);
        fn_80296BBC(player);
        OBJ_S32(obj, 0xf8) = 1;
    } else if (OBJ_S32(obj, 0xf8) == 1) {
        OBJ_F32(obj, 0xc) = *(f32 *)(state + 0);
        OBJ_F32(obj, 0x10) = *(f32 *)(state + 4);
        OBJ_F32(obj, 0x14) = *(f32 *)(state + 8);
        OBJ_S16(obj, 0) = *(s16 *)(state + 0xe);
        OBJECT_TRIGGER_REFRESH(0, obj, -1);
        OBJ_S32(obj, 0xf8) = 2;
    }
}

void WM_Galleon_init(int *obj, u8 *init)
{
    u8 *state;
    int i;

    state = (u8 *)OBJ_PTR(obj, 0xb8);
    if (GameBit_Get(0x78) != 0) {
        return;
    }
    if (OBJ_S16(obj, 0x46) == 0x188) {
        return;
    }
    objSetSlot(obj, 0x5a);
    OBJ_PTR(obj, 0xbc) = (void *)&WM_Galleon_SeqFn;
    OBJ_S16(obj, 0) = (s16)((s8)init[0x18] << 8);
    OBJ_S32(obj, 0xf4) = 9;
    *(f32 *)(state + 0) = OBJ_F32(obj, 0xc);
    *(f32 *)(state + 4) = OBJ_F32(obj, 0x10);
    *(f32 *)(state + 8) = OBJ_F32(obj, 0x14);
    *(s16 *)(state + 0xe) = OBJ_S16(obj, 0);
    fn_80065574(0, obj, 0);
    for (i = 0; i < 5; i++) {
        MAP_EVENT_SET(OBJ_U8(obj, 0x34), i, 0);
    }
    GameBit_Set(0xa4, 1);
}
#pragma peephole reset
#pragma scheduling reset

void WM_Galleon_release(void) {}
void WM_Galleon_initialise(void) {}

#pragma scheduling off
#pragma peephole off
int WM_seqobject_SeqFn(int p1, int p2, u8 *arg3)
{
    int i;

    for (i = 0; i < (int)arg3[0x8b]; i++) {
        if (arg3[0x81 + i] == 1) {
            lbl_803DDC78 = (u8)(1 - lbl_803DDC78);
        }
    }
    arg3[0x80] = 0;
    arg3[0x56] = 0;
    return 0;
}
#pragma peephole reset
#pragma scheduling reset

int WM_seqobject_getExtraSize(void) { return 1; }
int WM_seqobject_getObjectTypeId(void) { return 0; }
void WM_seqobject_free(void) {}

#pragma peephole off
void WM_seqobject_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;

    if (v != 0) {
        objRenderFn_8003b8f4(lbl_803E5CF8);
    }
}
#pragma peephole reset

void WM_seqobject_hitDetect(void) {}

#pragma scheduling off
#pragma peephole off
void WM_seqobject_update(int *obj)
{
    int count;
    int countdown;
    int *objects;
    int found;
    int i;
    int setupType;

    setupType = OBJ_S8(OBJ_PTR(obj, 0x4c), 0x19);
    if (setupType == 8) {
        return;
    }
    if (setupType >= 8) {
        return;
    }
    if (setupType != 0) {
        return;
    }
    if (OBJ_S32(obj, 0xf4) != 0) {
        return;
    }
    if (GameBit_Get(0xa4) != 0) {
        return;
    }
    if (GameBit_Get(0x78) != 0) {
        return;
    }

    objects = (int *)ObjGroup_GetObjects(6, &count);
    found = 0;
    for (i = 0; i < count; i++) {
        if (OBJ_S16(*(int **)(objects + i), 0x46) == 0x139) {
            found = 1;
        }
    }

    if (found != 0) {
        if (OBJ_S32(obj, 0xf8) == 0) {
            OBJECT_TRIGGER_REFRESH(0, obj, -1);
            OBJ_S32(obj, 0xf4) = 1;
            GameBit_Set(0xa4, 1);
        } else {
            SCREEN_TRANSITION_START(0x50, 1);
        }
    } else {
        OBJ_S32(obj, 0xf8) = 0x14;
        SCREEN_TRANSITION_START(0x50, 1);
    }

    countdown = OBJ_S32(obj, 0xf8) - 1;
    OBJ_S32(obj, 0xf8) = countdown;
    if (countdown < 0) {
        OBJ_S32(obj, 0xf8) = 0;
    }
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void WM_seqobject_init(int *obj, s8 *def)
{
    s16 angle;

    angle = (s16)((s32)def[0x18] << 8);
    OBJ_S16(obj, 0) = angle;
    OBJ_PTR(obj, 0xbc) = (void *)WM_seqobject_SeqFn;
    OBJ_S32(obj, 0xf8) = 0x14;
}
#pragma peephole reset
#pragma scheduling reset

void WM_seqobject_release(void) {}
void WM_seqobject_initialise(void) {}

#pragma scheduling off
#pragma peephole off
int dll_1FB_SeqFn(int *obj, int unused, s16 *p)
{
    int *state = (int *)OBJ_PTR(obj, 0xb8);
    s16 mode = *(s16 *)((u8 *)state + 6);
    u8 flags;

    if ((mode == 1) || (mode == 2)) {
        flags = (u8)(OBJ_U8(obj, 0xaf) | 8);
        OBJ_U8(obj, 0xaf) = flags;
    }
    *(s16 *)((u8 *)p + 0x70) = -1;
    *(u8 *)((u8 *)p + 0x56) = 0;
    return 0;
}
#pragma peephole reset
#pragma scheduling reset

int dll_1FB_getExtraSize_ret_12(void) { return 0xc; }
int dll_1FB_getObjectTypeId(void) { return 0; }
void dll_1FB_free_nop(void) {}

#pragma scheduling off
#pragma peephole off
void dll_1FB_render(int *obj, int p2, int p3, int p4, int p5, s8 visible)
{
    u8 *state = (u8 *)OBJ_PTR(obj, 0xb8);

    if (visible != 0) {
        if (state[9] == 0) {
            ((void (*)(int *, int, int, int, int, f32))objRenderFn_8003b8f4)(obj, p2, p3, p4, p5, lbl_803E5D00);
        }
    }
}
#pragma peephole reset
#pragma scheduling reset

void dll_1FB_hitDetect_nop(void) {}

#pragma scheduling off
#pragma peephole off
void dll_1FB_update(int *obj)
{
    u8 *state = (u8 *)OBJ_PTR(obj, 0xb8);

    if (((OBJ_U8(obj, 0xaf) & 1) != 0) && (*(s16 *)(state + 6) == 2) &&
        (GameBit_Get(0x9ad) == 0)) {
        OBJECT_TRIGGER_REFRESH(4, obj, -1);
        buttonDisable(0, 0x100);
        GameBit_Set(0x9ad, 1);
    }
    ObjAnim_AdvanceCurrentMove((int)obj, lbl_803E5D04, timeDelta, 0);
}

void dll_1FB_init(int *obj, u8 *def)
{
    u8 *state;

    state = (u8 *)OBJ_PTR(obj, 0xb8);
    ObjMsg_AllocQueue(obj, 4);
    OBJ_PTR(obj, 0xbc) = (void *)dll_1FB_SeqFn;
    OBJ_S16(obj, 0) = (s16)((s8)def[0x18] << 8);
    OBJ_S16(obj, 2) = *(s16 *)(def + 0x1c);
    *(s16 *)(state + 4) = (s16)(s8)def[0x19];
    *(s16 *)(state + 6) = *(s16 *)(def + 0x1a);
    ObjAnim_SetCurrentMove((int)obj, (int)*(s16 *)(state + 4) + 0x100, lbl_803E5D08, 0);
}
#pragma peephole reset
#pragma scheduling reset

void dll_1FB_release_nop(void) {}
void dll_1FB_initialise_nop(void) {}

int LaserBeam_getExtraSize(void) { return 0x50; }
int LaserBeam_getObjectTypeId(void) { return 0; }

#pragma scheduling off
#pragma peephole off
void LaserBeam_init(int *obj)
{
    void **state;

    state = (void **)OBJ_PTR(obj, 0xb8);
    ((void (*)(int *))(*(u32 *)((u8 *)*gModgfxInterface + 0x18)))(obj);
    if (state[0] != 0) {
        textureFree(state[0]);
        state[0] = 0;
    }
}
#pragma peephole reset
#pragma scheduling reset

void LaserBeam_render(void) {}
void LaserBeam_hitDetect(void) {}
