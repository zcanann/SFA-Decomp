/*
 * dll_00CF cannonclaw - a trigger-once cannon-arm awakener: plays move 0x208
 * until the Tricky object's gate game bit fires, then disables its own hits
 * and stops animating (unkF4 latch).
 *
 * This TU also owns grimble_initialiseStateHandlerTables (builds Grimble's
 * two state-handler dispatch tables in .bss). The Grimble/TumbleWeedBush
 * bodies and object descriptors live in their own TUs (dll_00D0/dll_00D1).
 */
#include "main/game_object.h"
#include "main/object_api.h"
#include "main/dll/barrel.h"
#include "main/dll/scarab.h"
#include "main/gamebits.h"
#include "main/objhits.h"
#include "main/frame_timing.h"
#include "main/gameplay_runtime.h"

#define CANNONCLAW_OBJID_TRICKY 0x1723
#define CANNONCLAW_MOVE_ARM     0x208

extern void* gGrimbleStateHandlersA[10];
extern void* gGrimbleStateHandlersB[6];
extern f32 lbl_803E2F30;
extern f32 lbl_803E2F34;
extern f32 lbl_803E2F38;

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
#pragma scheduling reset

int cannonclaw_getExtraSize(void)
{
    return 0x0;
}
int cannonclaw_getObjectTypeId(void)
{
    return 0x0;
}

void cannonclaw_free(void)
{
}

#pragma scheduling off
#pragma peephole off
void cannonclaw_render(int obj, int p2, int p3, int p4, int p5, s8 visible)
{
    if (visible != 0)
    {
        switch (((GameObject*)obj)->unkF4)
        {
        case 0:
            ((void (*)(int, int, int, int, int, f32))objRenderModelAndHitVolumes)(obj, p2, p3, p4, p5, lbl_803E2F30);
            break;
        default:
            break;
        }
    }
}

void cannonclaw_hitDetect(void)
{
}

void cannonclaw_update(u8* obj)
{
    GameObject* trickyObj;
    getTrickyObject();
    trickyObj = ObjList_FindObjectById(CANNONCLAW_OBJID_TRICKY);
    if (((GameObject*)obj)->unkF4 != 0)
        return;
    if (((GameObject*)obj)->anim.currentMove != CANNONCLAW_MOVE_ARM)
    {
        ObjAnim_SetCurrentMove((int)obj, CANNONCLAW_MOVE_ARM, lbl_803E2F34, 0);
    }
    ObjAnim_AdvanceCurrentMove((int)obj, lbl_803E2F38, timeDelta, NULL);
    if (trickyObj == NULL)
        return;
    if (mainGetBit(trickyObj->anim.placementData[13]) == 0)
        return;
    ((GameObject*)obj)->unkF4 = 1;
    *(u8*)&((GameObject*)obj)->anim.resetHitboxMode =
        (u8)(*(u8*)&((GameObject*)obj)->anim.resetHitboxMode | INTERACT_FLAG_DISABLED);
    ObjHits_DisableObject((u32)obj);
}

void cannonclaw_init(s16* dst, void* src)
{
    s8 v = *((s8*)src + 0x28);
    s16 t = v << 8;
    *dst = t;
}

void cannonclaw_release(void)
{
}

void cannonclaw_initialise(void)
{
}
