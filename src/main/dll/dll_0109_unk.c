/*
 * dll_0109 - two unrelated placed objects sharing this DLL:
 *
 *  - A map-event sequence dispatcher (Dll109_SeqFn) keyed off the
 *    placement mapId at ObjPlacement+0x14. Sequence event opcodes drive
 *    level locks/loads, map-act progression, sky/env restores and an
 *    accumulator state block; the opcode>=0xC cases write the four
 *    FLOAT_803e48xx presets into three accumulator slots and toggle a
 *    flag word on a linked object.
 *  - A "carryable that breaks and respawns" object: on a priority hit it
 *    plays a break fx + sfx, optionally drops a setup object, then runs a
 *    timer before re-enabling itself once off-screen.
 */
#include "main/carryable_interface.h"
#include "main/effect_interfaces.h"
#include "main/obj_placement.h"
#include "main/frustum.h"
#include "main/game_object.h"
#include "main/audio/sfx_ids.h"
#include "main/mapEvent.h"
#include "main/dll/CF/CFBaby.h"

/* per-object extra block read by dll_109_render */
typedef struct Dll109State
{
    u8 pad0[0xA - 0x0];
    u8 unkA;
    u8 padB[0x10 - 0xB];
} Dll109State;

/* ObjHits / object-setup helpers (home TU: obj hit-volume + setup code) */
extern undefined4 ObjHitbox_SetSphereRadius();
extern undefined4 ObjHits_ClearHitVolumes();
extern undefined8 ObjHits_SetHitVolumeSlot();
extern undefined4 ObjHits_DisableObject();
extern undefined4 ObjHits_EnableObject();
extern int ObjHits_GetPriorityHit();
extern u8 Obj_IsLoadingLocked(void);
extern int Obj_AllocObjectSetup(int size, int type);
extern int Obj_SetupObject(int setup, int arg1, int arg2, int arg3, int arg4);
extern void Sfx_PlayFromObject(int obj, int sfxId);

/* sequence-dispatch helpers consumed by Dll109_SeqFn */
extern undefined4 FUN_80041ff8();
extern undefined4 FUN_800427c8();
extern undefined4 FUN_80042800();
extern undefined4 FUN_80042b9c();
extern undefined4 FUN_80042bec();
extern undefined4 FUN_80043030();
extern undefined4 FUN_80044404();
extern undefined4 FUN_80053c98();

/* accumulator-slot presets written by sequence opcodes 0xC..0x17 */
extern f32 FLOAT_803e4830;
extern f32 FLOAT_803e4840;
extern f32 FLOAT_803e4844;
extern f32 FLOAT_803e4848;

extern f32 timeDelta;
extern f32 lbl_803E3B44; /* respawn timer reset value */
extern f32 lbl_803E3B48; /* respawn timer threshold */
extern f32 lbl_803E3B40; /* render alpha/param */
extern void objRenderFn_8003b8f4(f32);

/* sequence-event dispatcher (SeqFn); param_9 = obj. Float params are
   register pass-throughs to the FUN_8004xxxx sequence helpers. */
undefined4
FUN_80189054(undefined8 param_1, double param_2, double param_3, undefined8 param_4, undefined8 param_5,
             undefined8 param_6, undefined8 param_7, undefined8 param_8, int param_9, undefined4 param_10
             , ObjAnimUpdateState* animUpdate, int param_12, undefined4 param_13, undefined4 param_14,
             undefined4 param_15, undefined4 param_16)
{
    undefined4 handle;
    char mapAct;
    int mapId;
    int scratch;
    int extra;
    int placement;
    int i;
    undefined8 extraout_f1;
    undefined8 extraout_f1_00;
    undefined8 extraout_f1_01;
    undefined8 extraout_f1_02;
    undefined8 extraout_f1_03;
    undefined8 f1Arg;

    placement = *(int*)&((GameObject*)param_9)->anim.placementData;
    extra = *(int*)&((GameObject*)param_9)->extra;
    i = 0;
    scratch = (int)animUpdate;
    do
    {
        if ((int)(uint)animUpdate->eventCount <= i)
        {
            return 0;
        }
        switch (animUpdate->eventIds[i])
        {
        case 2:
        case 0x65:
            scratch = *(int*)(placement + 0x14);
            if (scratch == 0x49f5a)
            {
                FUN_80041ff8(param_1, param_2, param_3, param_4, param_5, param_6, param_7, param_8, 0x26);
                scratch = 1;
                FUN_80042b9c(0, 0, 1);
                handle = FUN_80044404(0x26);
                FUN_80042bec(handle, 0);
                handle = FUN_80044404(0xb);
                FUN_80042bec(handle, 1);
            }
            else if (scratch < 0x49f5a)
            {
                if (scratch == 0x451b9)
                {
                    mapAct = (*gMapEventInterface)->getMapAct(0xd);
                    param_1 = extraout_f1;
                    if (mapAct == 2)
                    {
                        FUN_80041ff8(extraout_f1, param_2, param_3, param_4, param_5, param_6, param_7, param_8, 0xb);
                        scratch = 1;
                        FUN_80042b9c(0, 0, 1);
                        handle = FUN_80044404(0xb);
                        FUN_80042bec(handle, 0);
                    }
                    else
                    {
                        FUN_80041ff8(extraout_f1, param_2, param_3, param_4, param_5, param_6, param_7, param_8, 0x29);
                        scratch = 1;
                        FUN_80042b9c(0, 0, 1);
                        handle = FUN_80044404(0x29);
                        FUN_80042bec(handle, 0);
                    }
                }
                else
                {
                    if ((0x451b8 < scratch) || (scratch != 0x43775)) goto LAB_801893dc;
                    FUN_80041ff8(param_1, param_2, param_3, param_4, param_5, param_6, param_7, param_8, 0x29);
                    scratch = 1;
                    FUN_80042b9c(0, 0, 1);
                    handle = FUN_80044404(0x29);
                    FUN_80042bec(handle, 0);
                }
            }
            else if (scratch == 0x4cd65)
            {
                FUN_80041ff8(param_1, param_2, param_3, param_4, param_5, param_6, param_7, param_8, 0x41);
                scratch = 1;
                FUN_80042b9c(0, 0, 1);
                handle = FUN_80044404(0x41);
                FUN_80042bec(handle, 0);
                handle = FUN_80044404(0xb);
                FUN_80042bec(handle, 1);
            }
            else
            {
            LAB_801893dc:
                FUN_80041ff8(param_1, param_2, param_3, param_4, param_5, param_6, param_7, param_8, 0x29);
                scratch = 1;
                FUN_80042b9c(0, 0, 1);
                handle = FUN_80044404(0x29);
                FUN_80042bec(handle, 0);
            }
            break;
        case 3:
        case 100:
            mapId = *(int*)(placement + 0x14);
            if (mapId == 0x49f5a)
            {
                scratch = 0;
                param_12 = (int)*gMapEventInterface;
                /* MapEventInterface+0x50: setObjGroupStatus */
                param_1 = (**(code**)(param_12 + 0x50))(0xb, 4);
            }
            else if (mapId < 0x49f5a)
            {
                if (mapId == 0x451b9)
                {
                    mapAct = (*gMapEventInterface)->getMapAct(0xd);
                    param_1 = extraout_f1_00;
                    if (mapAct == 2)
                    {
                        f1Arg = extraout_f1_00;
                        FUN_80042b9c(0, 0, 1);
                        FUN_80044404(0xd);
                        FUN_80043030(f1Arg, param_2, param_3, param_4, param_5, param_6, param_7, param_8);
                        (*gMapEventInterface)->setObjGroupStatus(0xd, 10, 0);
                        (*gMapEventInterface)->setObjGroupStatus(0xd, 0xb, 0);
                        scratch = 0;
                        param_12 = (int)*gMapEventInterface;
                        /* MapEventInterface+0x50: setObjGroupStatus */
                        param_1 = (**(code**)(param_12 + 0x50))(0xd, 0xe);
                    }
                }
                else if ((mapId < 0x451b9) && (mapId == 0x43775))
                {
                    scratch = 1;
                    FUN_80042b9c(0, 0, 1);
                    FUN_80044404(7);
                    param_1 = FUN_80043030(param_1, param_2, param_3, param_4, param_5, param_6, param_7, param_8);
                }
            }
            else if (mapId == 0x4cd65)
            {
                scratch = 1;
                FUN_80042b9c(0, 0, 1);
                FUN_80044404(0xb);
                param_1 = FUN_80043030(param_1, param_2, param_3, param_4, param_5, param_6, param_7, param_8);
            }
            break;
        case 5:
            mapId = *(int*)(placement + 0x14);
            if (mapId == 0x451b9)
            {
                mapAct = (*gMapEventInterface)->getMapAct(0xd);
                param_1 = extraout_f1_01;
                if (mapAct == 2)
                {
                    param_1 = FUN_80042800();
                }
            }
            else if (mapId < 0x451b9)
            {
                if (mapId == 0x43775)
                {
                LAB_801895a4:
                    param_1 = FUN_80042800();
                }
            }
            else if (mapId == 0x49f5a) goto LAB_801895a4;
            break;
        case 6:
            mapId = *(int*)(placement + 0x14);
            if (mapId == 0x451b9)
            {
                mapAct = (*gMapEventInterface)->getMapAct(0xd);
                param_1 = extraout_f1_02;
                if (mapAct == 2)
                {
                    param_1 = FUN_800427c8();
                }
            }
            else if (mapId < 0x451b9)
            {
                if (mapId == 0x43775)
                {
                LAB_80189614:
                    param_1 = FUN_800427c8();
                }
            }
            else if (mapId == 0x49f5a) goto LAB_80189614;
            break;
        case 7:
        case 0x66:
            mapId = *(int*)(placement + 0x14);
            if (mapId == 0x49f5a)
            {
                param_1 = FUN_80053c98(param_1, param_2, param_3, param_4, param_5, param_6, param_7, param_8, 0x32,
                                       '\0', scratch, param_12, param_13, param_14, param_15, param_16);
            }
            else if (mapId < 0x49f5a)
            {
                if ((mapId == 0x451b9) &&
                    (mapAct = (*gMapEventInterface)->getMapAct(0xd), param_1 = extraout_f1_03,
                        mapAct == 2))
                {
                    scratch = (int)*gMapEventInterface;
                    /* MapEventInterface+0x44: setMapAct */
                    f1Arg = (**(code**)(scratch + 0x44))(0xb, 5);
                    param_1 = FUN_80053c98(f1Arg, param_2, param_3, param_4, param_5, param_6, param_7, param_8, 0x4e,
                                           '\0', scratch, param_12, param_13, param_14, param_15, param_16);
                }
            }
            else if (mapId == 0x4cd65)
            {
                FUN_80053c98(param_1, param_2, param_3, param_4, param_5, param_6, param_7, param_8, 0x7f, '\0', scratch
                             , param_12, param_13, param_14, param_15, param_16);
                scratch = (int)*gMapEventInterface;
                /* MapEventInterface+0x44: setMapAct */
                param_1 = (**(code**)(scratch + 0x44))(0x41, 2);
            }
            break;
        case 10:
            *(u8*)(extra + 0x1a) = 1;
            break;
        case 0xb:
            *(u8*)(extra + 0x1a) = 0;
            break;
        case 0xc:
            *(float*)(extra + 4) = FLOAT_803e4830;
            break;
        case 0xd:
            *(float*)(extra + 4) = FLOAT_803e4840;
            break;
        case 0xe:
            *(float*)(extra + 4) = FLOAT_803e4844;
            break;
        case 0xf:
            *(float*)(extra + 4) = FLOAT_803e4848;
            break;
        case 0x10:
            *(float*)(extra + 8) = FLOAT_803e4830;
            break;
        case 0x11:
            *(float*)(extra + 8) = FLOAT_803e4840;
            break;
        case 0x12:
            *(float*)(extra + 8) = FLOAT_803e4844;
            break;
        case 0x13:
            *(float*)(extra + 8) = FLOAT_803e4848;
            break;
        case 0x14:
            *(float*)(extra + 0xc) = FLOAT_803e4830;
            break;
        case 0x15:
            *(float*)(extra + 0xc) = FLOAT_803e4840;
            break;
        case 0x16:
            *(float*)(extra + 0xc) = FLOAT_803e4844;
            break;
        case 0x17:
            *(float*)(extra + 0xc) = FLOAT_803e4848;
            break;
        case 0x18:
            mapId = *(int*)(extra + 0x10);
            if (mapId != 0)
            {
                *(ushort*)(mapId + 6) = *(ushort*)(mapId + 6) & 0xbfff;
            }
            break;
        case 0x19:
            mapId = *(int*)(extra + 0x10);
            if (mapId != 0)
            {
                *(ushort*)(mapId + 6) = *(ushort*)(mapId + 6) | 0x4000;
            }
        }
        i = i + 1;
    }
    while (true);
}


void dll_109_hitDetect_nop(void)
{
}

void dll_109_release_nop(void)
{
}

void dll_109_initialise_nop(void)
{
}

int dll_109_getExtraSize_ret_16(void) { return 0x10; }
int dll_109_getObjectTypeId(void) { return 0x0; }

typedef struct CarryableBreakRespawnState
{
    u8 pad0[0xa];
    u8 state;
    u8 padB;
    f32 timer;
} CarryableBreakRespawnState;

#pragma scheduling off
#pragma peephole off
void carryable_break_respawn_update(int obj)
{
    CarryableBreakRespawnState* state;
    ObjPlacement* placement;
    int setup;
    u32 hitVolume;

    state = ((GameObject*)obj)->extra;
    placement = (ObjPlacement*)((GameObject*)obj)->anim.placementData;
    switch (state->state)
    {
    case 0:
        (*gCarryableInterface)->getAnimState(obj, (int)state);
        if (ObjHits_GetPriorityHit(obj, 0, 0, &hitVolume) != 0)
        {
            /* CarryableInterface+0x30: break/anim-state slot */
            (*(void (*)(int, CarryableBreakRespawnState*))*(int*)((u8*)*gCarryableInterface + 0x30))(obj, state);
            Sfx_PlayFromObject(obj, SFXen_rfall5_c);
            ObjHitbox_SetSphereRadius(obj, 0x28);
            ObjHits_SetHitVolumeSlot(obj, 5, 4, 0);
            if (Obj_IsLoadingLocked() != 0)
            {
                setup = Obj_AllocObjectSetup(0x24, 0x253);
                ((ObjPlacement*)setup)->posX = ((GameObject*)obj)->anim.localPosX;
                ((ObjPlacement*)setup)->posY = ((GameObject*)obj)->anim.localPosY;
                ((ObjPlacement*)setup)->posZ = ((GameObject*)obj)->anim.localPosZ;
                Obj_SetupObject(setup, 5, ((GameObject*)obj)->anim.mapEventSlot, -1,
                                *(int*)&((GameObject*)obj)->anim.parent);
            }
            (*gPartfxInterface)->spawnObject((void*)obj, 0x355, NULL, 0, -1, NULL);
            (*gPartfxInterface)->spawnObject((void*)obj, 0x352, NULL, 0, -1, NULL);
            state->state = 1;
        }
        break;
    case 1:
        ObjHits_ClearHitVolumes();
        ObjHits_DisableObject(obj);
        *(u8*)&((GameObject*)obj)->anim.resetHitboxMode |= 8;
        state->state = 2;
        state->timer = lbl_803E3B44;
        ((GameObject*)obj)->anim.localPosX = placement->posX;
        ((GameObject*)obj)->anim.localPosY = placement->posY;
        ((GameObject*)obj)->anim.localPosZ = placement->posZ;
        break;
    case 2:
        state->timer += timeDelta;
        if (state->timer > lbl_803E3B48)
        {
            if (ViewFrustum_IsSphereVisible(&((GameObject*)obj)->anim.localPosX,
                                            ((GameObject*)obj)->anim.hitboxScale * ((GameObject*)obj)->anim.
                                            rootMotionScale) == 0)
            {
                ObjHits_EnableObject(obj);
                *(u8*)&((GameObject*)obj)->anim.resetHitboxMode &= ~8;
                state->state = 0;
            }
        }
        break;
    }
}

void dll_109_init(int obj, u8* p)
{
    ((GameObject*)obj)->anim.rotX = (s16)((s32)p[0x1a] << 8);
    ((GameObject*)obj)->objectFlags |= 0x2000;
    (*gCarryableInterface)->initAnim((void*)obj, *(int*)&((GameObject*)obj)->extra, 0x21);
    /* CarryableInterface+0x2c slot */
    (*(void (**)(int*, int))((u8*)*gCarryableInterface + 0x2c))(((GameObject*)obj)->extra, 1);
}

#pragma dont_inline on
void decoration11a_expandBoundsWithVertex(f32* vertex, f32* maxOut, f32* minOut);
#pragma dont_inline reset

#pragma scheduling on
#pragma peephole on
void dll_109_free(int obj)
{
    (*gCarryableInterface)->free(obj);
}

#pragma scheduling off
#pragma peephole off
void dll_109_render(int obj, int p1, int p2, int p3, int p4, s8 visible)
{
    Dll109State* state = ((GameObject*)obj)->extra;
    if (state->unkA == 0)
    {
        if ((*gCarryableInterface)->isVisible(obj, visible) != 0)
        {
            ((void (*)(int, int, int, int, int, f32))objRenderFn_8003b8f4)(obj, p1, p2, p3, p4, lbl_803E3B40);
        }
    }
}
