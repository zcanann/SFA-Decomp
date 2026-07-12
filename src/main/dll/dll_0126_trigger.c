/*
 * trigger (DLL 0x126) - generic scripted trigger object.
 *
 * Trigger_init dispatches on the placement's object-sequence type id
 * (*(s16*)params: 0x4b/0x4c/0x4d/0x4e/0x50/0x54/0x230/0xf4) to set up the
 * instance's range/timer state, then Trigger_hitDetect picks a target
 * (player / Tricky / Arwing / camera / nearest object of a group, per the
 * placement's mode byte at 0x43), tracks its position, and on a positive
 * activation runs the trigger's command list through objInterpretSeq.
 *
 * objInterpretSeq walks up to 8 four-byte command entries. Each entry is
 * a flags byte at [0], opcode at [1], and args at [2]/[3]. The flags byte
 * gates whether the entry runs: bit0 = run on enter (p3 > 0), bit1 = run on
 * exit (p3 < 0), bit2/bit3 = once-only for the enter/exit direction (latched
 * against sflags bit0/bit1), bit4 = unconditional (ignore enter/exit), bit5 =
 * override-disabled (run even when the trigger's disabled flag, *state & 4,
 * is set). A zero opcode entry is skipped.
 * On a matching entry it fires the corresponding effect: player anims, sfx,
 * triggered camera actions, sky / cloud / lighting / time-of-day toggles,
 * game-bit set/toggle, env effects, map-layer navigation, level
 * lock/load/unload, save/restart points, texture preload, and NPC
 * dialogue. p3 carries the activation direction (1 = enter, -1 = exit).
 *
 * Trigger_render/update/release/initialise are stubs; Trigger_free stops
 * any sfx the trigger started.
 */
#include "main/dll/DR/hightop.h"
#include "main/dll/player_api.h"
#include "main/camera_interface.h"
#include "main/effect_interfaces.h"
#include "main/game_ui_interface.h"
#include "main/game_object.h"
#include "main/dll/ARW/dll_029A_arwarwing.h"
#include "main/object_api.h"
#include "main/objlib.h"
#include "main/mapEventTypes.h"
#include "main/objseq.h"
#include "main/sky_state.h"
#include "main/lightmap.h"
#include "main/rcp_dolphin.h"
#include "main/shader.h"
#include "dolphin/os/OSReport.h"
#include "main/model.h"
#include "main/sky_api.h"
#include "main/gamebit_ids.h"
#include "main/dll/dll_0126_trigger.h"
#include "main/dll/dll_02B5_timer.h"
#include "main/dll/headdisplay.h"
#include "main/dll/mmp_gyservent.h"

/* group owned by another DLL, queried here */
#define TIMER_OBJGROUP                  0x4c /* DLL 0x2B5 timer */
#define TARGET_OBJGROUP                 0xf  /* player-target group; nearest object gets the trigger's sequence */
#define TRICKY_TARGET_OBJGROUP          0x32 /* nearest object searched from the tricky object */
#define TRICKY_TARGET_OBJGROUP_FALLBACK 0x31 /* fallback group when TRICKY_TARGET_OBJGROUP has none */

/* Env-effect ids co-activated by the type-3 command (p[3] sub-case); the A set
   runs for sub-cases 0/1, the B set for sub-case 2. Opaque distinct roles per index. */
#define TRIGGER_ENVFX_A0 0x134
#define TRIGGER_ENVFX_A1 0x135
#define TRIGGER_ENVFX_A2 0x142
#define TRIGGER_ENVFX_B0 0x136
#define TRIGGER_ENVFX_B1 0x137
#define TRIGGER_ENVFX_B2 0x143

/*
 * TriggerState+0 status byte (`*state`). See objInterpretSeq / Trigger_hitDetect.
 */
#define TRIGGER_SFLAG_ENTERED     0x01 /* enter-direction command list has run (latch) */
#define TRIGGER_SFLAG_EXITED      0x02 /* exit-direction command list has run (latch) */
#define TRIGGER_SFLAG_DISABLED    0x04 /* trigger's game bit was already set at init: fire enter once */
#define TRIGGER_SFLAG_SEED_TARGET 0x40 /* first hit: seed target position from current, not previous */

/*
 * Per-command-entry flags byte (entry[0] in the 4-byte command records at
 * placementData+0x18). Gates whether the entry runs for a given activation leg.
 */
#define TRIGGER_CMD_ON_ENTER          0x01 /* run when activation direction is enter (legCode > 0) */
#define TRIGGER_CMD_ON_EXIT           0x02 /* run when activation direction is exit (legCode < 0) */
#define TRIGGER_CMD_ONCE_ENTER        0x04 /* enter leg runs only once (latched vs SFLAG_ENTERED) */
#define TRIGGER_CMD_ONCE_EXIT         0x08 /* exit leg runs only once (latched vs SFLAG_EXITED) */
#define TRIGGER_CMD_UNCONDITIONAL     0x10 /* ignore enter/exit gating */
#define TRIGGER_CMD_OVERRIDE_DISABLED 0x20 /* run even when SFLAG_DISABLED is set */

extern f32 lbl_803E40F8; /* unnamed f32 constant from the shared .sdata2 pool (range divisor) */
extern int* gPlayerShadowInterface;
extern f32 lbl_803E40D8;
extern f32 lbl_803E40FC;
extern f32 lbl_803E4100;
extern f32 lbl_803E4104; /* unnamed f32 constant from the shared .sdata2 pool (hit-detect distance seed) */
extern u8 framesThisStep;

extern int getLActions();
extern void Sfx_StopFromObject(void* obj, int sfxId);
extern void objSetSlot(u8* obj, s8 slot);
extern int mainGetBit(int eventId);
extern void Sfx_PlayFromObject(int obj, int sfxId);
extern void fn_80295918(int obj, int sel, f32 fval);
extern void fn_8006FC00(int v);
extern void timeOfDayFn_80055038(void);
extern int getEnvfxAct(int a, int b, u16 idx, int d);
extern void crash(int a, int b, int c, int d, int e, int f, int g, int h);
extern void mainSetBits(int eventId, int value);
extern int getTrickyObject(void);
extern void gameTextFn_80125ba4(int id);
extern void envFxFn_800887cc(void);
extern int return1_800202BC(void);
extern int fn_80198B68(int obj, int p2);
extern void fn_80198DE8(int obj, int target);
extern void fn_80198A00(int obj, int target);

void Trigger_render(void)
{
}

void Trigger_update(void)
{
}

void Trigger_release(void)
{
}

void Trigger_initialise(void)
{
}
#pragma reset

void Trigger_free(GameObject* obj)
{
    u8 i;
    u8* entry = *(u8**)&(obj)->anim.placementData + 0x18;
    i = 0;

    while (i < 8)
    {
        if ((entry[0] & (TRIGGER_CMD_ON_ENTER | TRIGGER_CMD_ON_EXIT)) != 0 && entry[1] != 3 && entry[1] == 4)
        {
            Sfx_StopFromObject(obj, (u16)((entry[2] << 8) | entry[3]));
        }
        i++;
        entry += 4;
    }
}

void Trigger_init(u8* obj, u8* params)
{
    u8* state;
    f32 range;

    objSetSlot(obj, 0x28);
    state = ((GameObject*)obj)->extra;
    switch (((TriggerPlacement*)params)->typeId)
    {
    case 0x4b:
        range = (f32)(s32)(((TriggerPlacement*)params)->size[0] * 2);
        ((TriggerState*)state)->rangeSq = range * range;
        ((GameObject*)obj)->anim.rotZ = 0;
        ((GameObject*)obj)->anim.rotY = 0;
        ((GameObject*)obj)->anim.rotX = (s16)(((TriggerPlacement*)params)->rot[0] << 8);
        ((GameObject*)obj)->anim.rootMotionScale = range / lbl_803E40F8;
        break;
    case 0x4c:
        ((TriggerState*)state)->gateBits[0] = ((TriggerPlacement*)params)->gateBitSrc[0];
        objFn_80198fa4((GameObject*)obj, (MmpGyserventPlacement*)params);
        break;
    case 0x230:
        ((TriggerState*)state)->rangeSq = (f32)(s32)(((TriggerPlacement*)params)->size[0] * 2);
        ((TriggerState*)state)->rangeSq = ((TriggerState*)state)->rangeSq * ((TriggerState*)state)->rangeSq;
        break;
    case 0x4d:
        ((GameObject*)obj)->anim.rotX = (s16)(((TriggerPlacement*)params)->rot[0] << 8);
        ((GameObject*)obj)->anim.rotY = (s16)(((TriggerPlacement*)params)->rot[1] << 8);
        ((GameObject*)obj)->anim.rotZ = 0;
        break;
    case 0x54:
        ((TriggerState*)state)->gateBits[0] = ((TriggerPlacement*)params)->gateBitSrc[0];
        ((TriggerState*)state)->gateBits[1] = ((TriggerPlacement*)params)->gateBitSrc[1];
        ((TriggerState*)state)->gateBits[2] = ((TriggerPlacement*)params)->gateBitSrc[2];
        ((TriggerState*)state)->gateBits[3] = ((TriggerPlacement*)params)->gateBitSrc[3];
        ((TriggerFlags8A*)(state + 0x8a))->bit7 = 0;
        break;
    case 0x4e:
    case 0x4f:
    case 0x50:
        break;
    case 0xf4:
        break;
    default:
        break;
    }
    ((TriggerState*)state)->gameBit = ((TriggerPlacement*)params)->gameBitSrc;
    if (mainGetBit(((TriggerState*)state)->gameBit) == 1)
    {
        state[0] = (u8)(state[0] | TRIGGER_SFLAG_DISABLED);
    }
    state[0] = (u8)(state[0] | TRIGGER_SFLAG_SEED_TARGET);
}

int Trigger_getExtraSize(void)
{
    return 0xac;
}
int Trigger_getObjectTypeId(void)
{
    return 0x0;
}

void objInterpretSeq(int obj, int seqArg, int legCode, int distSq)
{
    char* desc = (char*)&gTriggerObjDescriptor;
    u8* state = ((GameObject*)obj)->extra;
    u8* p = (u8*)(*(int*)&((GameObject*)obj)->anim.placementData + 0x18);
    u8 i = 0;
    u8 b;
    u8 sflags;
    u8 c;
    int t;
    int t2;
    int* tbl;
    u32 op;
    u32 v;
    u32 bit;
    u32 sel;
    s16 angleDiff;
    int ang;
    int count;
    int first;
    int id;
    GameObject** objects;

    while (i < 8)
    {
        if (p[1] != 0 &&
            ((sflags = *state, (sflags & TRIGGER_SFLAG_DISABLED) == 0) || (*p & TRIGGER_CMD_OVERRIDE_DISABLED) != 0))
        {
            b = *p;
            if ((b & TRIGGER_CMD_UNCONDITIONAL) == 0)
            {
                if ((s8)legCode == 1)
                {
                    if ((b & TRIGGER_CMD_ON_ENTER) != 0)
                    {
                        if ((sflags & TRIGGER_SFLAG_ENTERED) != 0)
                        {
                            if ((b & TRIGGER_CMD_ONCE_ENTER) == 0)
                            {
                                goto next;
                            }
                        }
                        goto run;
                    }
                }
                else if ((s8)legCode == -1 && (b & TRIGGER_CMD_ON_EXIT) != 0)
                {
                    if ((sflags & TRIGGER_SFLAG_EXITED) != 0)
                    {
                        if ((b & TRIGGER_CMD_ONCE_EXIT) == 0)
                        {
                            goto next;
                        }
                    }
                    goto run;
                }
            }
            else if ((b & TRIGGER_CMD_ON_ENTER) != 0)
            {
                if ((s8)legCode < 0)
                {
                    goto next;
                }
                goto run;
            }
            else if ((b & TRIGGER_CMD_ON_EXIT) == 0 || (s8)legCode <= 0)
            {
            run:
                switch (p[1])
                {
                case 1:
                    switch (p[2])
                    {
                    case 0:
                    case 1:
                    case 2:
                    case 3:
                    case 4:
                    case 5:
                    case 6:
                    case 7:
                        break;
                    case 8:
                        t = (int)Obj_GetPlayerObject();
                        if ((void*)t != NULL)
                        {
                            fn_80295918(t, 1, lbl_803E40D8);
                        }
                        break;
                    case 9:
                        t = (int)Obj_GetPlayerObject();
                        if ((void*)t != NULL)
                        {
                            fn_80295918(t, 10, lbl_803E40D8);
                        }
                        break;
                    case 10:
                        t = (int)Obj_GetPlayerObject();
                        if ((void*)t != NULL)
                        {
                            fn_80295918(t, 0xb, lbl_803E40D8);
                        }
                        break;
                    case 0xb:
                        t = (int)Obj_GetPlayerObject();
                        if ((void*)t != NULL)
                        {
                            fn_80295918(t, 1, lbl_803E40FC);
                        }
                        break;
                    }
                    break;
                case 4:
                    if ((s8)legCode >= 0)
                    {
                        Sfx_PlayFromObject(obj, (u16)((p[2] << 8) | p[3]));
                    }
                    else
                    {
                        Sfx_StopFromObject((void*)obj, (u16)((p[2] << 8) | p[3]));
                    }
                    break;
                case 6:
                    (*gCameraInterface)->loadTriggeredCamAction(p[2], p[3], 0);
                    break;
                case 8:
                    switch (p[2])
                    {
                    case 0:
                        if (p[3] > 1)
                        {
                            p[3] = 1;
                        }
                        setDrawCloudsAndLights(p[3]);
                        break;
                    case 1:
                        if (p[3] > 1)
                        {
                            p[3] = 1;
                        }
                        gameFlagFn_8005ce6c(p[3]);
                        break;
                    case 2:
                        if (p[3] > 1)
                        {
                            p[3] = 1;
                        }
                        setDrawLights(p[3]);
                        break;
                    case 3:
                        if (p[3] > 1)
                        {
                            p[3] = 1;
                        }
                        (*gCloudActionInterface)->func09Nop(p[3]);
                        break;
                    case 4:
                        (*(VtableFn*)(*gPlayerShadowInterface + 0xc))(p[3]);
                        break;
                    case 5:
                        fn_8006FC00(p[3]);
                        break;
                    case 6:
                        if (p[3] != 0)
                        {
                            skyFn_80088c94(7, 1);
                        }
                        else
                        {
                            skyFn_80088c94(7, 0);
                        }
                        break;
                    case 7:
                        if (p[3] != 0)
                        {
                            gameFlagFn_8005cd24(1);
                        }
                        else
                        {
                            gameFlagFn_8005cd24(0);
                        }
                        break;
                    case 8:
                        if (p[3] != 0)
                        {
                            timeOfDayFn_80055038();
                        }
                        else
                        {
                            timeOfDayFn_80055000();
                        }
                        break;
                    case 9:
                        skyFn_80088e54(getSkyStructField24C() ^ 1, (f32)(u32)p[3]);
                        break;
                    case 10:
                        skyFn_80088e54(0, (f32)(u32)p[3]);
                        break;
                    case 0xb:
                        skyFn_80088e54(1, (f32)(u32)p[3]);
                        break;
                    }
                    break;
                case 5:
                    if (((TriggerState*)state)->rangeSq == lbl_803E40D8)
                    {
                        break;
                    }
                    break;
                case 10:
                    getEnvfxAct(obj, seqArg, (u16)((p[2] << 8) | p[3]), distSq);
                    OSReport(desc + 0x68, (int)((GameObject*)obj)->anim.classId, (p[2] << 8) | p[3], distSq);
                    break;
                case 0xd:
                    getLActions(obj, seqArg, (u16)((p[2] << 8) | p[3]), legCode, distSq, 0);
                    break;
                case 0xb:
                    switch (p[2])
                    {
                    case 0:
                    case 3:
                        t = ObjGroup_FindNearestObject(TARGET_OBJGROUP, obj, 0);
                        if ((void*)t != NULL)
                        {
                            (*gObjectTriggerInterface)->runSequence(p[3], (void*)t, -1);
                        }
                        break;
                    case 1:
                        (*gObjectTriggerInterface)->setFlag(p[3], 1);
                        break;
                    case 2:
                        (*gObjectTriggerInterface)->setFlag(p[3], 0);
                        break;
                    }
                    break;
                case 0xc:
                    id = (u16)((p[2] << 8) | p[3]);
                    objects = ObjList_GetObjects(&first, &count);
                    for (; first < count; first++)
                    {
                        t2 = (int)objects[first];
                        tbl = *(int**)(t2 + 0x4c);
                        if (tbl == NULL)
                        {
                            continue;
                        }
                        switch (((TriggerPlacement*)tbl)->typeId)
                        {
                        case 0x4b:
                        case 0x4c:
                        case 0x4d:
                        case 0x4e:
                        case 0x4f:
                        case 0x50:
                        case 0x54:
                        case 0x230:
                            if (((TriggerPlacement*)tbl)->triggerId == id)
                            {
                                objInterpretSeq(t2, seqArg, legCode, distSq);
                            }
                            break;
                        }
                    }
                    break;
                case 0x10:
                    Obj_SetActiveModelIndex(Obj_GetPlayerObject(), p[2]);
                    break;
                case 0x12:
                    op = (u16)((p[2] << 8) | p[3]);
                    bit = op & 0x3fff;
                    v = mainGetBit(bit);
                    sel = op >> 14 & 3;
                    if (sel == 0)
                    {
                        v = 0;
                    }
                    else if (sel == 1)
                    {
                        v = 0xffffffff;
                    }
                    else if (sel == 2)
                    {
                        v = ~v;
                    }
                    mainSetBits(bit, v);
                    break;
                case 0x21:
                    op = (u16)((p[2] << 8) | p[3]);
                    bit = op & 0x1fff;
                    mainSetBits(bit, mainGetBit(bit) ^ (1 << (op >> 13 & 7)));
                    break;
                case 0x13:
                    (*gMapEventInterface)
                        ->setObjGroupStatus((int)((GameObject*)obj)->anim.mapEventSlot, (p[2] << 8) | p[3], 1);
                    break;
                case 0x27:
                    id = (p[2] << 8) | p[3];
                    mapLoadDataFiles(id);
                    loadModelAndAnimTabs();
                    OSReport(desc + 0xa8, id);
                    break;
                case 0x28:
                    id = (p[2] << 8) | p[3];
                    mapUnload(id, 0x20000000);
                    OSReport(desc + 0xc4, id);
                    break;
                case 0x2e:
                    defragMemory(0);
                    break;
                case 0x2a:
                    lockLevel(p[2], p[3]);
                    OSReport(desc + 0xe0, p[2], p[3]);
                    break;
                case 0x2b:
                    unlockLevel(p[2], p[3], 0);
                    OSReport(desc + 0x114, p[2], p[3]);
                    break;
                case 0x2f:
                    t = ObjGroup_FindNearestObject(TIMER_OBJGROUP, obj, 0);
                    if ((void*)t != NULL)
                    {
                        timer_addDuration((GameObject*)(t), p[3] * 0x3c);
                    }
                    break;
                case 0x14:
                    (*gMapEventInterface)
                        ->setObjGroupStatus((int)((GameObject*)obj)->anim.mapEventSlot, (p[2] << 8) | p[3], 0);
                    break;
                case 0x22:
                    id = (p[2] << 8) | p[3];
                    c = (u8)(*gMapEventInterface)->getObjGroupStatus((int)((GameObject*)obj)->anim.mapEventSlot, id);
                    (*gMapEventInterface)->setObjGroupStatus((int)((GameObject*)obj)->anim.mapEventSlot, id, c ^ 1);
                    break;
                case 0x15:
                    t = (int)getTablesBinEntry((u16)((p[2] << 8) | p[3]) + 2);
                    if ((void*)t != NULL)
                    {
                        for (tbl = (int*)t; *tbl != -1; tbl++)
                        {
                            if ((void*)getLoadedTexture(*tbl) == NULL)
                            {
                                crash(0x32, 3, 0, *tbl, 0, 0, 0, 0);
                            }
                        }
                    }
                    break;
                case 0x16:
                    t = (int)getTablesBinEntry((u16)((p[2] << 8) | p[3]) + 2);
                    if ((void*)t != NULL)
                    {
                        for (tbl = (int*)t; *tbl != -1; tbl++)
                        {
                            t2 = (int)getLoadedTexture(*tbl);
                            if ((void*)t2 != NULL)
                            {
                                textureFree((u8*)t2);
                            }
                        }
                    }
                    break;
                case 0x18:
                    (*gMapEventInterface)->setMapAct((int)((GameObject*)obj)->anim.mapEventSlot, (p[2] << 8) | p[3]);
                    break;
                case 0x1a:
                    (*gMapEventInterface)->setObjGroupStatus(p[3], p[2], 1);
                    break;
                case 0x1b:
                    (*gMapEventInterface)->setObjGroupStatus(p[3], p[2], 0);
                    break;
                case 0x1e:
                    (*gMapEventInterface)->setMapAct(p[3], p[2]);
                    break;
                case 0x11:
                    mainSetBits(GAMEBIT_TrickyTalk, (p[2] << 8) | p[3]);
                    break;
                case 0x1f:
                    t = (int)Obj_GetPlayerObject();
                    angleDiff = ((GameObject*)obj)->anim.rotX - (u16) * (s16*)t;
                    if (angleDiff > 0x8000)
                    {
                        angleDiff = (angleDiff - 0x10000) + 1;
                    }
                    if (angleDiff < -0x8000)
                    {
                        angleDiff = (angleDiff + 0x10000) - 1;
                    }
                    if (angleDiff >= 0)
                    {
                        ang = angleDiff;
                    }
                    else
                    {
                        ang = -angleDiff;
                    }
                    if (ang > 0x4000)
                    {
                        (*gMapEventInterface)
                            ->savePoint(obj + 0xc, (int)(s16)(((GameObject*)obj)->anim.rotX + 0x8000), p[3],
                                        getCurMapLayer());
                    }
                    else
                    {
                        (*gMapEventInterface)
                            ->savePoint(obj + 0xc, (int)((GameObject*)obj)->anim.rotX, p[3], getCurMapLayer());
                    }
                    break;
                case 0x20:
                    if (p[2] == 0)
                    {
                        goToNextMapLayer();
                    }
                    else
                    {
                        goToPrevMapLayer();
                    }
                    break;
                case 0x23:
                    switch (p[2])
                    {
                    case 0:
                        (*gMapEventInterface)
                            ->restartPoint((void*)(obj + 0xc), (int)((GameObject*)obj)->anim.rotX, getCurMapLayer(), 0);
                        break;
                    case 1:
                        (*gMapEventInterface)->clearRestartPoint();
                        break;
                    case 2:
                        (*gMapEventInterface)->gotoRestartPoint();
                        break;
                    case 3:
                        (*gMapEventInterface)
                            ->restartPoint((void*)(obj + 0xc), (int)((GameObject*)obj)->anim.rotX, getCurMapLayer(), 1);
                        break;
                    }
                    break;
                case 0x26:
                    t = getTrickyObject();
                    if ((void*)t != NULL)
                    {
                        switch (p[2])
                        {
                        case 0:
                            (*(VtableFn*)(**(int**)(t + 0x68) + 0x3c))();
                            break;
                        case 1:
                            Obj_FreeObject(getTrickyObject());
                            break;
                        case 2:
                            t2 = ObjGroup_FindNearestObject(TRICKY_TARGET_OBJGROUP, t, 0);
                            if ((void*)t2 == NULL)
                            {
                                t2 = ObjGroup_FindNearestObject(TRICKY_TARGET_OBJGROUP_FALLBACK, t, 0);
                            }
                            if ((void*)t2 != NULL)
                            {
                                (*(VtableFn*)(**(int**)(t + 0x68) + 0x38))(t, t2);
                            }
                            break;
                        case 3:
                            mainSetBits(GAMEBIT_NoBallsAllowed, 0);
                            break;
                        case 4:
                            mainSetBits(GAMEBIT_NoBallsAllowed, 1);
                            break;
                        }
                    }
                    break;
                case 0x1c:
                    switch (p[2])
                    {
                    case 0:
                        mainSetBits(GAMEBIT_ENV_disableDayFX1, p[3] == 0);
                        break;
                    case 1:
                        mainSetBits(GAMEBIT_ENV_disableDayFX2, p[3] == 0);
                        break;
                    case 2:
                        mainSetBits(GAMEBIT_ENV_disableDayFX3, p[3] == 0);
                        break;
                    case 3:
                        switch (p[3])
                        {
                        case 0:
                            mainSetBits(GAMEBIT_ENV_isOutdoor, 1);
                            getEnvfxAct((int)Obj_GetPlayerObject(), (int)Obj_GetPlayerObject(), TRIGGER_ENVFX_A0, 0);
                            getEnvfxAct((int)Obj_GetPlayerObject(), (int)Obj_GetPlayerObject(), TRIGGER_ENVFX_A1, 0);
                            getEnvfxAct((int)Obj_GetPlayerObject(), (int)Obj_GetPlayerObject(), TRIGGER_ENVFX_A2, 0);
                            break;
                        case 1:
                            mainSetBits(GAMEBIT_ENV_isOutdoor, 0);
                            getEnvfxAct((int)Obj_GetPlayerObject(), (int)Obj_GetPlayerObject(), TRIGGER_ENVFX_A0, 0);
                            getEnvfxAct((int)Obj_GetPlayerObject(), (int)Obj_GetPlayerObject(), TRIGGER_ENVFX_A1, 0);
                            getEnvfxAct((int)Obj_GetPlayerObject(), (int)Obj_GetPlayerObject(), TRIGGER_ENVFX_A2, 0);
                            envFxFn_800887cc();
                            break;
                        case 2:
                            mainSetBits(GAMEBIT_ENV_isOutdoor, 1);
                            getEnvfxAct((int)Obj_GetPlayerObject(), (int)Obj_GetPlayerObject(), TRIGGER_ENVFX_B0, 0);
                            getEnvfxAct((int)Obj_GetPlayerObject(), (int)Obj_GetPlayerObject(), TRIGGER_ENVFX_B1, 0);
                            getEnvfxAct((int)Obj_GetPlayerObject(), (int)Obj_GetPlayerObject(), TRIGGER_ENVFX_B2, 0);
                            break;
                        }
                        break;
                    }
                    break;
                case 0x1d:
                    if (p[2] != 0)
                    {
                        mainSetBits(GAMEBIT_ITEM_DinoHorn_Disabled, 0);
                        mainSetBits(GAMEBIT_ITEM_Firefly_Disabled, 0);
                        mainSetBits(GAMEBIT_Tricky_CantFeed, 0);
                    }
                    else
                    {
                        mainSetBits(GAMEBIT_ITEM_DinoHorn_Disabled, 1);
                        mainSetBits(GAMEBIT_ITEM_Firefly_Disabled, 1);
                        mainSetBits(GAMEBIT_Tricky_CantFeed, 1);
                    }
                    break;
                case 0x2c:
                    **(f32**)(seqArg + 0xb8) = lbl_803E4100 * (f32)(s32)((p[2] << 8) | p[3]);
                    break;
                case 0x2d:
                    t = (int)Obj_GetPlayerObject();
                    if ((void*)t != NULL)
                    {
                        (*gGameUIInterface)->showNpcDialogue((p[2] << 8) | p[3], 0x14, 0x8c, 1);
                    }
                    else if ((void*)getArwing() != NULL)
                    {
                        gameTextFn_80125ba4((p[2] << 8) | p[3]);
                    }
                    break;
                }
            }
        }
    next:
        i++;
        p += 4;
    }
    if ((s8)legCode > 0)
    {
        *state |= TRIGGER_SFLAG_ENTERED;
        mainSetBits(((TriggerState*)state)->gameBit, 1);
    }
    else if ((s8)legCode < 0)
    {
        *state |= TRIGGER_SFLAG_EXITED;
    }
}

void Trigger_hitDetect(GameObject* obj)
{
    u8* state = (obj)->extra;
    u8* def = *(u8**)&(obj)->anim.placementData;
    int triggerObj;
    int trickyObj;
    int target;
    int ok;
    int ok2;
    int inside;
    int wasInside;
    int i;
    u8 targetKind;
    s16 ty;
    f32 dist[1];

    dist[0] = lbl_803E4104;
    if (((TriggerPlacement*)def)->triggerId <= 0 || ((TriggerPlacement*)def)->typeId == 0xf4)
    {
        triggerObj = (int)Obj_GetPlayerObject();
        if ((void*)triggerObj != NULL)
        {
            inside = (int)playerGetFocusObject((GameObject*)triggerObj);
            if ((void*)inside != NULL)
            {
                triggerObj = inside;
            }
        }
        else
        {
            triggerObj = (int)getArwing();
        }
        trickyObj = getTrickyObject();
        if ((void*)triggerObj != NULL || (void*)trickyObj != NULL)
        {
            if ((*state & TRIGGER_SFLAG_DISABLED) != 0)
            {
                objInterpretSeq((int)obj, triggerObj, 1, 0);
                *state &= ~TRIGGER_SFLAG_DISABLED;
                *state |= TRIGGER_SFLAG_ENTERED;
            }
            else
            {
                ok = 1;
                targetKind = ((TriggerPlacement*)def)->target;
                if (targetKind > 2)
                {
                    target = ObjGroup_FindNearestObject(targetKind - 1, (int)obj, dist);
                    if ((void*)target == NULL)
                    {
                        ok = 0;
                    }
                }
                else
                {
                    switch (targetKind)
                    {
                    case 0:
                        target = triggerObj;
                        if ((void*)triggerObj == NULL)
                        {
                            ok = 0;
                        }
                        break;
                    case 1:
                        target = trickyObj;
                        if ((void*)trickyObj == NULL)
                        {
                            ok = 0;
                        }
                        break;
                    case 2:
                        target = (int)(*gCameraInterface)->getCamera();
                        break;
                    }
                }
                if (ok)
                {
                    if ((*state & TRIGGER_SFLAG_SEED_TARGET) != 0)
                    {
                        switch (((TriggerPlacement*)def)->target)
                        {
                        case 2:
                            ((TriggerState*)state)->targetPosX = ((GameObject*)target)->anim.worldPosX;
                            ((TriggerState*)state)->targetPosY = ((GameObject*)target)->anim.worldPosY;
                            ((TriggerState*)state)->targetPosZ = ((GameObject*)target)->anim.worldPosZ;
                            break;
                        case 0:
                        case 1:
                            ((TriggerState*)state)->targetPosX = ((GameObject*)target)->anim.previousWorldPosX;
                            ((TriggerState*)state)->targetPosY = ((GameObject*)target)->anim.previousWorldPosY;
                            ((TriggerState*)state)->targetPosZ = ((GameObject*)target)->anim.previousWorldPosZ;
                            break;
                        default:
                            ((TriggerState*)state)->targetPosX = ((GameObject*)target)->anim.previousLocalPosX;
                            ((TriggerState*)state)->targetPosY = ((GameObject*)target)->anim.previousLocalPosY;
                            ((TriggerState*)state)->targetPosZ = ((GameObject*)target)->anim.previousLocalPosZ;
                            break;
                        }
                        *state &= ~TRIGGER_SFLAG_SEED_TARGET;
                    }
                    else
                    {
                        ((TriggerState*)state)->targetPosX = ((TriggerState*)state)->prevTargetPosX;
                        ((TriggerState*)state)->targetPosY = ((TriggerState*)state)->prevTargetPosY;
                        ((TriggerState*)state)->targetPosZ = ((TriggerState*)state)->prevTargetPosZ;
                    }
                    switch (((TriggerPlacement*)def)->target)
                    {
                    case 0:
                    case 1:
                    case 2:
                        ((TriggerState*)state)->prevTargetPosX = ((GameObject*)target)->anim.worldPosX;
                        ((TriggerState*)state)->prevTargetPosY = ((GameObject*)target)->anim.worldPosY;
                        ((TriggerState*)state)->prevTargetPosZ = ((GameObject*)target)->anim.worldPosZ;
                        break;
                    default:
                        ((TriggerState*)state)->prevTargetPosX = ((GameObject*)target)->anim.localPosX;
                        ((TriggerState*)state)->prevTargetPosY = ((GameObject*)target)->anim.localPosY;
                        ((TriggerState*)state)->prevTargetPosZ = ((GameObject*)target)->anim.localPosZ;
                        break;
                    }
                }
                switch (((TriggerPlacement*)def)->typeId)
                {
                case 0x4b:
                    if (ok)
                    {
                        objSeqFn_801992ec(obj, target);
                    }
                    break;
                case 0x230:
                    if (ok)
                    {
                        objSeqMoveFn_80199188(obj, target);
                    }
                    break;
                case 0x4c:
                    ok2 = 1;
                    if (((TriggerState*)state)->gateBits[0] != -1 &&
                        mainGetBit(((TriggerState*)state)->gateBits[0]) == 0u)
                    {
                        ok2 = 0;
                    }
                    if (ok2 && ok)
                    {
                        fn_80198DE8((int)obj, target);
                    }
                    break;
                case 0x4e:
                    ((TriggerState*)state)->timer = *(int*)&((TriggerState*)state)->timer + framesThisStep;
                    if (((TriggerState*)state)->timer >= (u32)((TriggerPlacement*)def)->triggerDelayFrames)
                    {
                        objInterpretSeq((int)obj, 0, 1, 0);
                    }
                    break;
                case 0x4d:
                    if (ok)
                    {
                        TriggerState* st = (TriggerState*)(obj)->extra;
                        inside = fn_80198B68((int)obj, (int)&st->prevTargetPosX);
                        wasInside = fn_80198B68((int)obj, (int)&st->targetPosX);
                        if (inside != 0)
                        {
                            if (wasInside == 0)
                            {
                                objInterpretSeq((int)obj, target, 1, 0);
                            }
                            else
                            {
                                objInterpretSeq((int)obj, target, 2, 0);
                            }
                        }
                        else if (wasInside != 0)
                        {
                            objInterpretSeq((int)obj, target, -1, 0);
                        }
                        else
                        {
                            objInterpretSeq((int)obj, target, -2, 0);
                        }
                    }
                    break;
                case 0x50:
                    objInterpretSeq((int)obj, triggerObj, 1, 0);
                    if (return1_800202BC() != 0)
                    {
                        Obj_FreeObject(obj);
                    }
                    break;
                case 0x54:
                    ok = 1;
                    i = 0;
                    while (i < 4 && ok)
                    {
                        s16 gate = ((TriggerState*)state)->gateBits[i];
                        if (gate != -1 && mainGetBit(gate) == 0u)
                        {
                            ok = 0;
                        }
                        i++;
                    }
                    if (ok && ((TriggerFlags8A*)(state + 0x8a))->bit7 == 0)
                    {
                        ((TriggerFlags8A*)(state + 0x8a))->bit7 = 1;
                        objInterpretSeq((int)obj, triggerObj, 1, 0);
                    }
                    if (!ok)
                    {
                        ((TriggerFlags8A*)(state + 0x8a))->bit7 = 0;
                    }
                    break;
                case 0xf4:
                    if (ok)
                    {
                        fn_80198A00((int)obj, target);
                    }
                    break;
                }
            }
        }
    }
}

ObjectDescriptor gTriggerObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)Trigger_initialise,
    (ObjectDescriptorCallback)Trigger_release,
    0,
    (ObjectDescriptorCallback)Trigger_init,
    (ObjectDescriptorCallback)Trigger_update,
    (ObjectDescriptorCallback)Trigger_hitDetect,
    (ObjectDescriptorCallback)Trigger_render,
    (ObjectDescriptorCallback)Trigger_free,
    (ObjectDescriptorCallback)Trigger_getObjectTypeId,
    Trigger_getExtraSize,
};
