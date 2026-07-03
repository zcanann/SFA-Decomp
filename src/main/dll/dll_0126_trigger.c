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
#include "main/camera_interface.h"
#include "main/effect_interfaces.h"
#include "main/game_ui_interface.h"
#include "main/game_object.h"
#include "main/mapEventTypes.h"
#include "main/objseq.h"
#include "main/sky_state.h"
#include "main/lightmap.h"
#include "main/rcp_dolphin.h"
#include "main/shader.h"
#include "main/sfa_shared_decls.h"

typedef struct TriggerPlacement
{
    u8 pad0[0x38 - 0x0];
    s16 unk38;
    u8 pad3A[0x46 - 0x3A];
    u16 triggerDelayFrames; /* 0x46: frames the timer must reach before firing */
} TriggerPlacement;

typedef struct ObjInterpretSeqPlacement
{
    u8 pad0[0x2 - 0x0];
    s8 commandVariant; /* 0x2: sub-selector dispatched per interpret-seq opcode */
    u8 pad3[0x4 - 0x3];
    s16 unk4;
    u8 unk6;
    u8 pad7[0x8 - 0x7];
} ObjInterpretSeqPlacement;

typedef struct TriggerState
{
    u8 pad0[0x4 - 0x0];
    f32 rangeSq;
    u32 timer;
    u8 padC[0x1C - 0xC];
    f32 targetPosX;
    f32 targetPosY;
    f32 targetPosZ;
    f32 prevTargetPosX;
    f32 prevTargetPosY;
    f32 prevTargetPosZ;
    u8 pad34[0x80 - 0x34];
    s16 gameBit;
    s16 gateBits[4];
    u8 pad8A[0xAC - 0x8A];
} TriggerState;

/* flag byte at TriggerState + 0x8A; bit7 = the 0x54 once-only latch */
typedef struct
{
    u8 bit7 : 1;
    u8 lo : 7;
} TriggerFlags8A;

STATIC_ASSERT(offsetof(TriggerPlacement, unk38) == 0x38);
STATIC_ASSERT(offsetof(TriggerPlacement, triggerDelayFrames) == 0x46);
STATIC_ASSERT(offsetof(ObjInterpretSeqPlacement, commandVariant) == 0x2);
STATIC_ASSERT(offsetof(ObjInterpretSeqPlacement, unk4) == 0x4);
STATIC_ASSERT(offsetof(ObjInterpretSeqPlacement, unk6) == 0x6);
STATIC_ASSERT(offsetof(TriggerState, rangeSq) == 0x4);
STATIC_ASSERT(offsetof(TriggerState, timer) == 0x8);
STATIC_ASSERT(offsetof(TriggerState, targetPosX) == 0x1C);
STATIC_ASSERT(offsetof(TriggerState, gameBit) == 0x80);
STATIC_ASSERT(offsetof(TriggerState, gateBits) == 0x82);
STATIC_ASSERT(sizeof(TriggerState) == 0xAC);

extern int getLActions();
extern int objFn_80198fa4();
extern int ObjGroup_FindNearestObject(int group, int obj, int p3);
extern void Sfx_StopFromObject(void* obj, int sfxId);
extern void objSetSlot(u8* obj, s8 slot);
extern int GameBit_Get(int eventId);
extern f32 lbl_803E40F8; /* unnamed f32 constant from the shared .sdata2 pool (range divisor) */
extern void Sfx_PlayFromObject(int obj, int sfxId);
extern int* gPlayerShadowInterface;

extern int Obj_GetPlayerObject(void);
extern void fn_80295918(int obj, int sel, f32 fval);



extern void fn_8006FC00(int v);



extern void timeOfDayFn_80055038(void);
extern void skyFn_80088e54(int mode, f32 brightness);
extern int getEnvfxAct(int a, int b, u16 idx, int d);
extern int ObjList_GetObjects(int* first, int* count);


extern void crash(int a, int b, int c, int d, int e, int f, int g, int h);
extern void textureFree(int tex);
extern void Obj_SetActiveModelIndex(int obj, int idx);
extern void GameBit_Set(int eventId, int value);

extern int getTrickyObject(void);




extern void gameTextFn_80125ba4(int id);
extern int getArwing(void);

extern void timer_addDuration(int timer, int dur);
extern void envFxFn_800887cc(void);


extern f32 lbl_803E40D8;
extern f32 lbl_803E40FC;
extern f32 lbl_803E4100;
extern int fn_802972A8(void);
extern int return1_800202BC(void);
extern int fn_80198B68(int obj, int p2);
extern void objSeqFn_801992ec(int obj, int target);
extern void fn_80198DE8(int obj, int target);
extern void fn_80198A00(int obj, int target);
extern void objSeqMoveFn_80199188(int obj, int target);
extern f32 lbl_803E4104; /* unnamed f32 constant from the shared .sdata2 pool (hit-detect distance seed) */
extern u8 framesThisStep;

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

void Trigger_free(void* obj)
{
    u8 i;
    u8* entry = *(u8**)&((GameObject*)obj)->anim.placementData + 0x18;
    i = 0;

    while (i < 8)
    {
        if ((entry[0] & 3) != 0 && entry[1] != 3 && entry[1] == 4)
        {
            Sfx_StopFromObject(obj, (u16)((entry[2] << 8) | entry[3]));
        }
        i++;
        entry += 4;
    }
}

void Trigger_init(u8* obj, u8* params)
{
    u8* sub;
    f32 t;

    objSetSlot(obj, 0x28);
    sub = ((GameObject*)obj)->extra;
    switch (*(s16*)params)
    {
    case 0x4b:
        t = (f32)(s32)(params[0x3a] * 2);
        ((TriggerState*)sub)->rangeSq = t * t;
        ((GameObject*)obj)->anim.rotZ = 0;
        ((GameObject*)obj)->anim.rotY = 0;
        ((GameObject*)obj)->anim.rotX = (s16)(params[0x3d] << 8);
        ((GameObject*)obj)->anim.rootMotionScale = t / lbl_803E40F8;
        break;
    case 0x4c:
        ((TriggerState*)sub)->gateBits[0] = *(s16*)(params + 0x48);
        objFn_80198fa4(obj, params);
        break;
    case 0x230:
        ((TriggerState*)sub)->rangeSq = (f32)(s32)(params[0x3a] * 2);
        ((TriggerState*)sub)->rangeSq = ((TriggerState*)sub)->rangeSq * ((TriggerState*)sub)->rangeSq;
        break;
    case 0x4d:
        ((GameObject*)obj)->anim.rotX = (s16)(params[0x3d] << 8);
        ((GameObject*)obj)->anim.rotY = (s16)(params[0x3e] << 8);
        ((GameObject*)obj)->anim.rotZ = 0;
        break;
    case 0x54:
        ((TriggerState*)sub)->gateBits[0] = *(s16*)(params + 0x48);
        ((TriggerState*)sub)->gateBits[1] = *(s16*)(params + 0x4a);
        ((TriggerState*)sub)->gateBits[2] = *(s16*)(params + 0x4c);
        ((TriggerState*)sub)->gateBits[3] = *(s16*)(params + 0x4e);
        ((TriggerFlags8A*)(sub + 0x8a))->bit7 = 0;
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
    ((TriggerState*)sub)->gameBit = *(s16*)(params + 0x44);
    if (GameBit_Get(((TriggerState*)sub)->gameBit) == 1)
    {
        sub[0] = (u8)(sub[0] | 0x04);
    }
    sub[0] = (u8)(sub[0] | 0x40);
}

int Trigger_getExtraSize(void) { return 0xac; }
int Trigger_getObjectTypeId(void) { return 0x0; }

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
    s16 d;
    int ang;
    int count;
    int first;
    int id;

    while (i < 8)
    {
        if (p[1] != 0 && ((sflags = *state, (sflags & 4) == 0) || (*p & 0x20) != 0))
        {
            b = *p;
            if ((b & 0x10) == 0)
            {
                if ((s8)legCode == 1)
                {
                    if ((b & 1) != 0)
                    {
                        if ((sflags & 1) != 0)
                        {
                            if ((b & 4) == 0)
                            {
                                goto next;
                            }
                        }
                        goto run;
                    }
                }
                else if ((s8)legCode == -1 && (b & 2) != 0)
                {
                    if ((sflags & 2) != 0)
                    {
                        if ((b & 8) == 0)
                        {
                            goto next;
                        }
                    }
                    goto run;
                }
            }
            else if ((b & 1) != 0)
            {
                if ((s8)legCode < 0)
                {
                    goto next;
                }
                goto run;
            }
            else if ((b & 2) == 0 || (s8)legCode <= 0)
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
                        t = Obj_GetPlayerObject();
                        if ((void*)t != NULL)
                        {
                            fn_80295918(t, 1, lbl_803E40D8);
                        }
                        break;
                    case 9:
                        t = Obj_GetPlayerObject();
                        if ((void*)t != NULL)
                        {
                            fn_80295918(t, 10, lbl_803E40D8);
                        }
                        break;
                    case 10:
                        t = Obj_GetPlayerObject();
                        if ((void*)t != NULL)
                        {
                            fn_80295918(t, 0xb, lbl_803E40D8);
                        }
                        break;
                    case 0xb:
                        t = Obj_GetPlayerObject();
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
                        t = ObjGroup_FindNearestObject(0xf, obj, 0);
                        if ((void*)t != NULL)
                        {
                            (*gObjectTriggerInterface)
                                ->runSequence(p[3], (void*)t, -1);
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
                    t = ObjList_GetObjects(&first, &count);
                    for (; first < count; first++)
                    {
                        t2 = *(int*)(t + first * 4);
                        tbl = *(int**)(t2 + 0x4c);
                        if (tbl == NULL)
                        {
                            continue;
                        }
                        switch (*(s16*)tbl)
                        {
                        case 0x4b:
                        case 0x4c:
                        case 0x4d:
                        case 0x4e:
                        case 0x4f:
                        case 0x50:
                        case 0x54:
                        case 0x230:
                            if (*(s16*)((char*)tbl + 0x38) == id)
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
                    v = GameBit_Get(bit);
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
                    GameBit_Set(bit, v);
                    break;
                case 0x21:
                    op = (u16)((p[2] << 8) | p[3]);
                    bit = op & 0x1fff;
                    GameBit_Set(bit, GameBit_Get(bit) ^ (1 << (op >> 13 & 7)));
                    break;
                case 0x13:
                    (*gMapEventInterface)->setObjGroupStatus(
                        (int)((GameObject*)obj)->anim.mapEventSlot, (p[2] << 8) | p[3], 1);
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
                    t = ObjGroup_FindNearestObject(0x4c, obj, 0);
                    if ((void*)t != NULL)
                    {
                        timer_addDuration(t, p[3] * 0x3c);
                    }
                    break;
                case 0x14:
                    (*gMapEventInterface)->setObjGroupStatus(
                        (int)((GameObject*)obj)->anim.mapEventSlot, (p[2] << 8) | p[3], 0);
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
                                textureFree(t2);
                            }
                        }
                    }
                    break;
                case 0x18:
                    (*gMapEventInterface)->setMapAct(
                        (int)((GameObject*)obj)->anim.mapEventSlot, (p[2] << 8) | p[3]);
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
                    GameBit_Set(0x4e3, (p[2] << 8) | p[3]);
                    break;
                case 0x1f:
                    t = Obj_GetPlayerObject();
                    d = ((GameObject*)obj)->anim.rotX - (u16) * (s16*)t;
                    if (d > 0x8000)
                    {
                        d = (d - 0x10000) + 1;
                    }
                    if (d < -0x8000)
                    {
                        d = (d + 0x10000) - 1;
                    }
                    if (d >= 0)
                    {
                        ang = d;
                    }
                    else
                    {
                        ang = -d;
                    }
                    if (ang > 0x4000)
                    {
                        (*gMapEventInterface)->savePoint(obj + 0xc,
                                                            (int)(s16)(((GameObject*)obj)->anim.rotX + 0x8000),
                                                            p[3], getCurMapLayer());
                    }
                    else
                    {
                        (*gMapEventInterface)->savePoint(obj + 0xc, (int)((GameObject*)obj)->anim.rotX,
                                                            p[3], getCurMapLayer());
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
                        (*gMapEventInterface)->restartPoint((void*)(obj + 0xc), (int)((GameObject*)obj)->anim.rotX,
                                                                    getCurMapLayer(), 0);
                        break;
                    case 1:
                        (*gMapEventInterface)->clearRestartPoint();
                        break;
                    case 2:
                        (*gMapEventInterface)->gotoRestartPoint();
                        break;
                    case 3:
                        (*gMapEventInterface)->restartPoint((void*)(obj + 0xc), (int)((GameObject*)obj)->anim.rotX,
                                                                    getCurMapLayer(), 1);
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
                            t2 = ObjGroup_FindNearestObject(0x32, t, 0);
                            if ((void*)t2 == NULL)
                            {
                                t2 = ObjGroup_FindNearestObject(0x31, t, 0);
                            }
                            if ((void*)t2 != NULL)
                            {
                                (*(VtableFn*)(**(int**)(t + 0x68) + 0x38))(t, t2);
                            }
                            break;
                        case 3:
                            GameBit_Set(0xd00, 0);
                            break;
                        case 4:
                            GameBit_Set(0xd00, 1);
                            break;
                        }
                    }
                    break;
                case 0x1c:
                    switch (p[2])
                    {
                    case 0:
                        GameBit_Set(0x3ab, p[3] == 0);
                        break;
                    case 1:
                        GameBit_Set(0x3ac, p[3] == 0);
                        break;
                    case 2:
                        GameBit_Set(0x3af, p[3] == 0);
                        break;
                    case 3:
                        switch (p[3])
                        {
                        case 0:
                            GameBit_Set(0x3b0, 1);
                            getEnvfxAct(Obj_GetPlayerObject(), Obj_GetPlayerObject(), 0x134, 0);
                            getEnvfxAct(Obj_GetPlayerObject(), Obj_GetPlayerObject(), 0x135, 0);
                            getEnvfxAct(Obj_GetPlayerObject(), Obj_GetPlayerObject(), 0x142, 0);
                            break;
                        case 1:
                            GameBit_Set(0x3b0, 0);
                            getEnvfxAct(Obj_GetPlayerObject(), Obj_GetPlayerObject(), 0x134, 0);
                            getEnvfxAct(Obj_GetPlayerObject(), Obj_GetPlayerObject(), 0x135, 0);
                            getEnvfxAct(Obj_GetPlayerObject(), Obj_GetPlayerObject(), 0x142, 0);
                            envFxFn_800887cc();
                            break;
                        case 2:
                            GameBit_Set(0x3b0, 1);
                            getEnvfxAct(Obj_GetPlayerObject(), Obj_GetPlayerObject(), 0x136, 0);
                            getEnvfxAct(Obj_GetPlayerObject(), Obj_GetPlayerObject(), 0x137, 0);
                            getEnvfxAct(Obj_GetPlayerObject(), Obj_GetPlayerObject(), 0x143, 0);
                            break;
                        }
                        break;
                    }
                    break;
                case 0x1d:
                    if (p[2] != 0)
                    {
                        GameBit_Set(0x966, 0);
                        GameBit_Set(0x967, 0);
                        GameBit_Set(0x968, 0);
                    }
                    else
                    {
                        GameBit_Set(0x966, 1);
                        GameBit_Set(0x967, 1);
                        GameBit_Set(0x968, 1);
                    }
                    break;
                case 0x2c:
                    **(f32**)(seqArg + 0xb8) = lbl_803E4100 * (f32)(s32)((p[2] << 8) | p[3]);
                    break;
                case 0x2d:
                    t = Obj_GetPlayerObject();
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
        *state |= 1;
        GameBit_Set(((TriggerState*)state)->gameBit, 1);
    }
    else if ((s8)legCode < 0)
    {
        *state |= 2;
    }
}

void Trigger_hitDetect(int obj)
{
    u8* state = ((GameObject*)obj)->extra;
    u8* def = *(u8**)&((GameObject*)obj)->anim.placementData;
    int t;
    int tk;
    int target;
    int ok;
    int ok2;
    int inside;
    int wasInside;
    int i;
    u8 c;
    s16 ty;
    f32 dist[1];

    dist[0] = lbl_803E4104;
    if (((TriggerPlacement*)def)->unk38 <= 0 || *(s16*)def == 0xf4)
    {
        t = Obj_GetPlayerObject();
        if ((void*)t != NULL)
        {
            inside = fn_802972A8();
            if ((void*)inside != NULL)
            {
                t = inside;
            }
        }
        else
        {
            t = getArwing();
        }
        tk = getTrickyObject();
        if ((void*)t != NULL || (void*)tk != NULL)
        {
            if ((*state & 4) != 0)
            {
                objInterpretSeq(obj, t, 1, 0);
                *state &= ~4;
                *state |= 1;
            }
            else
            {
                ok = 1;
                c = def[0x43];
                if (c > 2)
                {
                    target = ObjGroup_FindNearestObject(c - 1, obj, (int)dist);
                    if ((void*)target == NULL)
                    {
                        ok = 0;
                    }
                }
                else
                {
                    switch (c)
                    {
                    case 0:
                        target = t;
                        if ((void*)t == NULL)
                        {
                            ok = 0;
                        }
                        break;
                    case 1:
                        target = tk;
                        if ((void*)tk == NULL)
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
                    if ((*state & 0x40) != 0)
                    {
                        switch (def[0x43])
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
                        *state &= ~0x40;
                    }
                    else
                    {
                        ((TriggerState*)state)->targetPosX = ((TriggerState*)state)->prevTargetPosX;
                        ((TriggerState*)state)->targetPosY = ((TriggerState*)state)->prevTargetPosY;
                        ((TriggerState*)state)->targetPosZ = ((TriggerState*)state)->prevTargetPosZ;
                    }
                    switch (def[0x43])
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
                switch (*(s16*)def)
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
                    if (((TriggerState*)state)->gateBits[0] != -1 && GameBit_Get(((TriggerState*)state)->gateBits[0]) == 0u)
                    {
                        ok2 = 0;
                    }
                    if (ok2 && ok)
                    {
                        fn_80198DE8(obj, target);
                    }
                    break;
                case 0x4e:
                    ((TriggerState*)state)->timer = *(int*)&((TriggerState*)state)->timer + framesThisStep;
                    if (((TriggerState*)state)->timer >= (u32)((TriggerPlacement*)def)->triggerDelayFrames)
                    {
                        objInterpretSeq(obj, 0, 1, 0);
                    }
                    break;
                case 0x4d:
                    if (ok)
                    {
                        TriggerState* st = (TriggerState*)((GameObject*)obj)->extra;
                        inside = fn_80198B68(obj, (int)&st->prevTargetPosX);
                        wasInside = fn_80198B68(obj, (int)&st->targetPosX);
                        if (inside != 0)
                        {
                            if (wasInside == 0)
                            {
                                objInterpretSeq(obj, target, 1, 0);
                            }
                            else
                            {
                                objInterpretSeq(obj, target, 2, 0);
                            }
                        }
                        else if (wasInside != 0)
                        {
                            objInterpretSeq(obj, target, -1, 0);
                        }
                        else
                        {
                            objInterpretSeq(obj, target, -2, 0);
                        }
                    }
                    break;
                case 0x50:
                    objInterpretSeq(obj, t, 1, 0);
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
                        if (gate != -1 && GameBit_Get(gate) == 0u)
                        {
                            ok = 0;
                        }
                        i++;
                    }
                    if (ok && ((TriggerFlags8A*)(state + 0x8a))->bit7 == 0)
                    {
                        ((TriggerFlags8A*)(state + 0x8a))->bit7 = 1;
                        objInterpretSeq(obj, t, 1, 0);
                    }
                    if (!ok)
                    {
                        ((TriggerFlags8A*)(state + 0x8a))->bit7 = 0;
                    }
                    break;
                case 0xf4:
                    if (ok)
                    {
                        fn_80198A00(obj, target);
                    }
                    break;
                }
            }
        }
    }
}
