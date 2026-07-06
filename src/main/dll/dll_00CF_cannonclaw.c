/*
 * dll_00CF cannonclaw - combined object DLL holding three independent
 * object descriptors:
 *
 *   gGrimbleObjDescriptor       - the Grimble enemy (logic in dll_00D0).
 *   gTumbleWeedBushObjDescriptor - the tumbleweed bush (logic elsewhere).
 *   cannonclaw                  - a trigger-once cannon-arm awakener: plays
 *                                 move 0x208 until the Tricky object's gate
 *                                 game bit fires, then disables its own
 *                                 hits and stops animating (unkF4 latch).
 *
 * This TU owns grimble_initialiseStateHandlerTables (builds Grimble's two
 * state-handler dispatch tables in .bss) and the small cannonclaw_* object
 * callbacks. The Grimble/TumbleWeedBush bodies live in their own TUs.
 */
#include "main/game_object.h"
#include "main/dll/barrel.h"
#include "main/dll/scarab.h"
#include "main/gamebits.h"
#include "main/objhits.h"
extern void* gGrimbleStateHandlersA[10];
extern void* gGrimbleStateHandlersB[6];
extern void objRenderModelAndHitVolumes(int obj, int p2, int p3, int p4, int p5, f32 scale);
extern void* getTrickyObject(void);
extern void* ObjList_FindObjectById(int id);
extern f32 timeDelta;
extern f32 lbl_803E2F30;
extern f32 lbl_803E2F34;
extern f32 lbl_803E2F38;

void cannonclaw_free(void)
{
}

void cannonclaw_hitDetect(void)
{
}

int cannonclaw_getExtraSize(void) { return 0x0; }
int cannonclaw_getObjectTypeId(void) { return 0x0; }

#pragma dont_inline on
#pragma scheduling off
void grimble_initialiseStateHandlerTables(void)
{
    gGrimbleStateHandlersA[0] = grimble_stateHandlerA00;
    gGrimbleStateHandlersA[1] = grimble_stateHandlerA01;
    gGrimbleStateHandlersA[2] = grimble_stateHandlerA02;
    gGrimbleStateHandlersA[3] = grimble_stateHandlerA03;
    gGrimbleStateHandlersA[4] = grimble_stateHandlerA04;
    gGrimbleStateHandlersA[5] = grimble_stateHandlerA05;
    gGrimbleStateHandlersA[6] = grimble_stateHandlerA06;
    gGrimbleStateHandlersA[7] = grimble_stateHandlerA07;
    gGrimbleStateHandlersA[8] = grimble_stateHandlerA08;
    gGrimbleStateHandlersA[9] = grimble_stateHandlerA09;
    gGrimbleStateHandlersB[0] = grimble_stateHandlerB00;
    gGrimbleStateHandlersB[1] = grimble_stateHandlerB01;
    gGrimbleStateHandlersB[2] = scarab_updateProximityGate;
    gGrimbleStateHandlersB[3] = grimble_stateHandlerB03;
    gGrimbleStateHandlersB[4] = grimble_stateHandlerB04;
    gGrimbleStateHandlersB[5] = grimble_stateHandlerB05;
}
#pragma dont_inline reset

#pragma peephole off
void cannonclaw_render(int obj, int p2, int p3, int p4, int p5, s8 visible)
{
    if (visible != 0)
    {
        switch (((GameObject*)obj)->unkF4)
        {
        case 0:
            ((void(*)(int, int, int, int, int, f32))objRenderModelAndHitVolumes)(obj, p2, p3, p4, p5, lbl_803E2F30);
            break;
        default:
            break;
        }
    }
}

ObjectDescriptor gGrimbleObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)grimble_initialise,
    (ObjectDescriptorCallback)grimble_release,
    0,
    (ObjectDescriptorCallback)grimble_init,
    (ObjectDescriptorCallback)grimble_update,
    (ObjectDescriptorCallback)grimble_hitDetect,
    (ObjectDescriptorCallback)grimble_render,
    (ObjectDescriptorCallback)grimble_free,
    (ObjectDescriptorCallback)grimble_getObjectTypeId,
    grimble_getExtraSize,
};

#define CANNONCLAW_OBJID_TRICKY 0x1723
#define CANNONCLAW_MOVE_ARM 0x208

void cannonclaw_update(u8* obj)
{
    u8* trickyState;
    getTrickyObject();
    trickyState = ObjList_FindObjectById(CANNONCLAW_OBJID_TRICKY);
    if (((GameObject*)obj)->unkF4 != 0) return;
    if (((GameObject*)obj)->anim.currentMove != CANNONCLAW_MOVE_ARM)
    {
        ObjAnim_SetCurrentMove((int)obj, CANNONCLAW_MOVE_ARM, lbl_803E2F34, 0);
    }
    ((ObjAnimAdvanceObjectFirstF32Fn)ObjAnim_AdvanceCurrentMove)((int)obj, lbl_803E2F38, timeDelta, NULL);
    if (trickyState == NULL) return;
    if (GameBit_Get(((GameObject*)trickyState)->anim.placementData[13]) == 0) return;
    ((GameObject*)obj)->unkF4 = 1;
    *(u8*)&((GameObject*)obj)->anim.resetHitboxMode = (u8)(*(u8*)&((GameObject*)obj)->anim.resetHitboxMode | INTERACT_FLAG_DISABLED);
    ObjHits_DisableObject((u32)obj);
}

void cannonclaw_release(void)
{
}

void cannonclaw_initialise(void)
{
}

void tumbleweedbush_free(void);
void tumbleweedbush_hitDetect(void);
void tumbleweedbush_release(void);
void tumbleweedbush_initialise(void);
void tumbleweedbush_init(u8* obj, u8* params, int param3);
int tumbleweedbush_getExtraSize(void);
int tumbleweedbush_getObjectTypeId(void);
void tumbleweedbush_update(int* obj);
void tumbleweedbush_render(int p1, int p2, int p3, int p4, int p5, s8 visible);
void tumbleweedbush_setScale(u8* obj, void* match);

void cannonclaw_init(s16* dst, void* src)
{
    s8 v = *((s8*)src + 0x28);
    s16 t = v << 8;
    *dst = t;
}

ObjectDescriptor11WithPadding gTumbleWeedBushObjDescriptor = {
    {
        0,
        0,
        0,
        OBJECT_DESCRIPTOR_FLAGS_11_SLOTS,
        (ObjectDescriptorCallback)tumbleweedbush_initialise,
        (ObjectDescriptorCallback)tumbleweedbush_release,
        0,
        (ObjectDescriptorCallback)tumbleweedbush_init,
        (ObjectDescriptorCallback)tumbleweedbush_update,
        (ObjectDescriptorCallback)tumbleweedbush_hitDetect,
        (ObjectDescriptorCallback)tumbleweedbush_render,
        (ObjectDescriptorCallback)tumbleweedbush_free,
        (ObjectDescriptorCallback)tumbleweedbush_getObjectTypeId,
        tumbleweedbush_getExtraSize,
        (ObjectDescriptorCallback)tumbleweedbush_setScale,
    },
    0,
};
