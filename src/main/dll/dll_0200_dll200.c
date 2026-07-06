/*
 * dll200 (DLL 0x200) - an arwing-attachment / flying NPC whose behaviour
 * is selected by the current map-event mode for its placement slot
 * (gMapEventInterface->getMapAct). Per mode it plays idle/move anims,
 * lets the player interact (A-button) to spend magic and grant game
 * bits, runs trigger sequences (dll_200_SeqFn / fn_801F2974), and in
 * mode 2 (fn_801F2290) steers a wandering attachment toward scripted
 * targets (gArwingAttachmentTargets) via getAngle/sqrtf. Object body is Dll200State
 * (0x28); render scales through objRenderModelAndHitVolumes and gates on
 * GameBit 0x2bd when the placement's map-act is 4.
 */
#include "main/dll/dll200state_struct.h"
#include "main/game_ui_interface.h"
#include "main/game_object.h"
#include "main/mapEvent.h"
#include "main/objHitReact.h"
#include "main/objanim_update.h"
#include "main/objseq.h"
#include "main/gamebits.h"
#include "main/dll/dll_80220608_shared.h"

#define PAD_BUTTON_A 0x100

typedef struct IntVec3
{
    int unk0;
    int unk4;
    int unk8;
} IntVec3;

STATIC_ASSERT(sizeof(Dll200State) == 0x28);

/* Dll200State.mode high bit: set while an ObjHitReact reaction is playing,
 * which suspends the normal map-act scripted update for that tick. */
#define DLL200_MODE_HITREACTING 0x80

extern void playerAddRemoveMagic(int obj, int amount);
extern void fn_80296474(int player, int a, int b);
extern ObjHitReactEntry gArwingAttachmentHitReactTable[];
extern f32 lbl_803E5DC0;
extern f32 lbl_803E5D98;

#pragma dont_inline on
void fn_801F20D4(int obj)
{
    extern int gArwingAttachmentItemSetIdle[];
    extern f32 lbl_803E5D98;
    extern f32 lbl_803E5D9C;
    extern f32 gArwingAttachmentU32ToDoubleBias;

    int state;
    IntVec3 itemSet;

    state = *(int*)&((GameObject*)obj)->extra;
    Obj_GetPlayerObject();
    itemSet = *(IntVec3*)gArwingAttachmentItemSetIdle;
    if ((*(u8*)&((GameObject*)obj)->anim.resetHitboxMode & INTERACT_FLAG_DISABLED) != 0)
    {
        *(u8*)&((GameObject*)obj)->anim.resetHitboxMode ^= INTERACT_FLAG_DISABLED;
    }
    if (GameBit_Get(763) == 0)
    {
        if (((GameObject*)obj)->anim.currentMove != 7)
        {
            ObjAnim_SetCurrentMove(obj, 7, lbl_803E5D98, 0);
        }
        ((ObjAnimAdvanceObjectFirstF32Fn)ObjAnim_AdvanceCurrentMove)
            (obj, lbl_803E5D9C, (f32)(u32)framesThisStep, NULL);
    }
    else
    {
        if (((GameObject*)obj)->anim.currentMove != 2)
        {
            ObjAnim_SetCurrentMove(obj, 2, lbl_803E5D98, 0);
        }
        ((ObjAnimAdvanceObjectFirstF32Fn)ObjAnim_AdvanceCurrentMove)
            (obj, lbl_803E5D9C, (f32)(u32)framesThisStep, NULL);
    }
    if ((*(u8*)&((GameObject*)obj)->anim.resetHitboxMode & INTERACT_FLAG_ACTIVATED) != 0 && GameBit_Get(763) == 0)
    {
        GameBit_Set(763, 1);
        *(u8*)&((Dll200State*)state)->counter27 = 0;
        buttonDisable(0, PAD_BUTTON_A);
    }
    else if ((*(u8*)&((GameObject*)obj)->anim.resetHitboxMode & INTERACT_FLAG_ACTIVATED) != 0)
    {
        if ((*gGameUIInterface)->isOneOfItemsBeingUsed((s32*)&itemSet, 3) > -1)
        {
            GameBit_Set(784, 1);
            *(u8*)&((Dll200State*)state)->counter27 += 1;
            buttonDisable(0, PAD_BUTTON_A);
        }
    }
}
#pragma dont_inline reset

#pragma dont_inline on
void fn_801F27E4(int obj)
{
    extern int fn_80296A14(void);
    extern f32 lbl_803E5D98;
    extern f32 lbl_803E5D9C;
    extern f32 gArwingAttachmentU32ToDoubleBias;

    int state;

    state = *(int*)&((GameObject*)obj)->extra;
    if (((GameObject*)obj)->anim.currentMove != 2)
    {
        ObjAnim_SetCurrentMove(obj, 2, lbl_803E5D98, 0);
    }
    ((ObjAnimAdvanceObjectFirstF32Fn)ObjAnim_AdvanceCurrentMove)
        (obj, lbl_803E5D9C, (f32)(u32)framesThisStep, NULL);
    ((Dll200State*)state)->latch24 = 1;
    if (((Dll200State*)state)->latch24 == 0)
    {
        if ((*(u8*)&((GameObject*)obj)->anim.resetHitboxMode & INTERACT_FLAG_ACTIVATED) != 0)
        {
            GameBit_Set(208, 1);
            ((Dll200State*)state)->latch24 = 1;
            buttonDisable(0, PAD_BUTTON_A);
        }
    }
    else
    {
        *(u8*)&((GameObject*)obj)->anim.resetHitboxMode &= ~INTERACT_FLAG_DISABLED;
        if ((*(u8*)&((GameObject*)obj)->anim.resetHitboxMode & INTERACT_FLAG_ACTIVATED) != 0)
        {
            Obj_GetPlayerObject();
            if (fn_80296A14() > 0)
            {
                ((Dll200State*)state)->mode25 = 2;
                (*gObjectTriggerInterface)->runSequence(2, (void*)obj, -1);
                buttonDisable(0, PAD_BUTTON_A);
            }
            else
            {
                if (GameBit_Get(177) == 0 || GameBit_Get(178) == 0 || GameBit_Get(179) == 0)
                {
                    ((Dll200State*)state)->mode25 = 1;
                    (*gObjectTriggerInterface)->runSequence(1, (void*)obj, -1);
                    buttonDisable(0, PAD_BUTTON_A);
                }
            }
        }
    }
}
#pragma dont_inline reset

void dll_200_free_nop(void)
{
}

void dll_200_hitDetect_nop(void)
{
}

void dll_200_release_nop(void)
{
}

void dll_200_initialise_nop(void)
{
}

int dll_200_getExtraSize_ret_40(void) { return sizeof(Dll200State); }
int dll_200_getObjectTypeId(void) { return 0x1; }

/* returns immediately if not visible; when the placement's map-act is 4,
 * gate render on GameBit 0x2bd, otherwise render directly via
 * objRenderModelAndHitVolumes. */
void dll_200_render(int* obj, int p1, int p2, int p3, int p4, s8 visible)
{
    extern void objRenderModelAndHitVolumes(void* obj, int p1, int p2, int p3, int p4, f32 scale);
    int areaId;
    if (visible == 0) return;
    areaId = (*gMapEventInterface)->getMapAct((int)((GameObject*)obj)->anim.mapEventSlot);
    if ((u8)areaId == 4)
    {
        if ((u32)GameBit_Get(0x2bd) == 0u) return;
        objRenderModelAndHitVolumes(obj, p1, p2, p3, p4, lbl_803E5DC0);
        return;
    }
    objRenderModelAndHitVolumes(obj, p1, p2, p3, p4, lbl_803E5DC0);
}

int dll_200_SeqFn(int obj, int unused, ObjAnimUpdateState* animUpdate, int arg3);

void dll_200_init(int* obj, int* arg)
{
    Dll200State* state;
    ((GameObject*)obj)->unkF4 = 0;
    ((GameObject*)obj)->anim.rotX = (s16)((s32)*(s8*)((char*)arg + 0x18) << 8);
    ((GameObject*)obj)->animEventCallback = dll_200_SeqFn;
    state = ((GameObject*)obj)->extra;
    state->defNoLow = (u8)*(s16*)arg;
    state->unk1C = 0;
    state->unk18 = 0;
    state->homeX = *(f32*)((char*)arg + 0x8);
    state->homeY = *(f32*)((char*)arg + 0xc);
    state->homeZ = *(f32*)((char*)arg + 0x10);
    state->latch24 = GameBit_Get(0xd0);
    state->counter27 = 0;
    state->mode = 1;
    state->prevMode = 0xc;
    state->modeTimer = 0x12c;
    state->animSpeed = lbl_803E5D98;
    state->unk14 = lbl_803E5DC0;
}

int fn_801F2974(int* obj, int unused, ObjAnimUpdateState* animUpdate, int arg3);

#pragma opt_strength_reduction off
int dll_200_SeqFn(int obj, int unused, ObjAnimUpdateState* animUpdate, int arg3)
{
    u8 mode;
    int i;
    int state;

    mode = (*gMapEventInterface)->getMapAct((int)((GameObject*)obj)->anim.mapEventSlot);
    switch (mode)
    {
    case 0:
        break;
    case 1:
        fn_801F2974((int*)obj, unused, animUpdate, arg3);
        break;
    case 2:
        break;
    case 4:
        *(u8*)&((GameObject*)obj)->anim.resetHitboxMode = (u8)(*(u8*)&((GameObject*)obj)->anim.resetHitboxMode | INTERACT_FLAG_DISABLED);
        break;
    case 6:
        state = *(int*)&((GameObject*)obj)->extra;
        *(u8*)&((GameObject*)obj)->anim.resetHitboxMode = (u8)(*(u8*)&((GameObject*)obj)->anim.resetHitboxMode | INTERACT_FLAG_DISABLED);
        for (i = 0; i < animUpdate->eventCount; i++)
        {
            switch (animUpdate->eventIds[i])
            {
            case 0:
                break;
            case 1:
                if (*(u8*)&((Dll200State*)state)->counter27 >= 2)
                {
                    GameBit_Set(0x314, 1);
                }
                break;
            }
        }
        break;
    }
    return 0;
}
#pragma opt_strength_reduction reset

#pragma opt_strength_reduction off
int fn_801F2974(int* obj, int unused, ObjAnimUpdateState* animUpdate, int arg3)
{
    int state;
    int player;
    int i;

    player = Obj_GetPlayerObject();
    state = *(int*)&((GameObject*)obj)->extra;
    *(u8*)&((GameObject*)obj)->anim.resetHitboxMode = (u8)(*(u8*)&((GameObject*)obj)->anim.resetHitboxMode | INTERACT_FLAG_DISABLED);

    for (i = 0; i < animUpdate->eventCount; i++)
    {
        u8 mode = ((Dll200State*)state)->mode25;
        if (mode == 1)
        {
            if (animUpdate->eventIds[i] == 4)
            {
                playerAddRemoveMagic(player, 5);
            }
        }
        else if (mode != 2)
        {
            u8 eventId = animUpdate->eventIds[i];
            if (eventId == 1)
            {
                GameBit_Set(208, 1);
                ((Dll200State*)state)->latch24 = 1;
            }
            else if (eventId == 2)
            {
                fn_80296474(player, 0, 1);
                playerAddRemoveMagic(player, 5);
            }
        }
    }
    return 0;
}
#pragma opt_strength_reduction reset

void fn_801F2290(int obj);

void dll_200_update(int obj)
{
    extern f32 lbl_803E5D98;
    extern f32 lbl_803E5D9C;
    u8 ev;
    u8 ret;
    Dll200State* state;

    state = ((GameObject*)obj)->extra;
    ret = ObjHitReact_Update(obj, gArwingAttachmentHitReactTable, 11,
                             (u8)((state->mode & DLL200_MODE_HITREACTING) ? 1 : 0),
                             &state->hitReactVec);
    if (ret != 0)
    {
        state->mode = (u8)(state->mode | DLL200_MODE_HITREACTING);
    }
    else
    {
        state->mode = (u8)(state->mode & ~DLL200_MODE_HITREACTING);
        ev = (*gMapEventInterface)->getMapAct((int)((GameObject*)obj)->anim.mapEventSlot);
        switch (ev)
        {
        case 1:
            fn_801F27E4(obj);
            break;
        case 2:
            fn_801F2290(obj);
            break;
        case 4:
            *(u8*)&((GameObject*)obj)->anim.resetHitboxMode = (u8)(*(u8*)&((GameObject*)obj)->anim.resetHitboxMode | INTERACT_FLAG_DISABLED);
            if (((GameObject*)obj)->anim.currentMove != 2)
            {
                ObjAnim_SetCurrentMove(obj, 2, lbl_803E5D98, 0);
            }
            ((ObjAnimAdvanceObjectFirstF32Fn)ObjAnim_AdvanceCurrentMove)
                (obj, lbl_803E5D9C, (f32)(u32)framesThisStep, NULL);
            break;
        case 6:
            fn_801F20D4(obj);
            break;
        case 0:
        case 3:
        case 5:
            return;
        }
    }
}

typedef struct ArwAttachTarget
{
    f32 x;
    f32 y;
    f32 moveId;
    f32 altMoveId;
    f32 speed;
} ArwAttachTarget;

void fn_801F2290(int obj)
{
    extern int gArwingAttachmentItemSetWander[];
    extern ArwAttachTarget gArwingAttachmentTargets[];
    extern char sArwingAttachmentDiffFormat[];
    extern f32 lbl_803E5D98;
    extern f32 lbl_803E5DA8;
    extern f32 lbl_803E5DAC;
    extern f32 lbl_803E5DB0;
    extern f32 lbl_803E5DB4;
    Dll200State* state;
    u8 mode;
    s16 ang;
    s16 diff;
    f32 dx;
    f32 dy;
    f32 dist;
    f32 spd;
    IntVec3 itemSet;
    ObjAnimEventList animEvents;

    state = ((GameObject*)obj)->extra;
    Obj_GetPlayerObject();
    itemSet = *(IntVec3*)gArwingAttachmentItemSetWander;
    ((GameObject*)obj)->anim.localPosY = state->homeY;
    if (GameBit_Get(0x1fc) != 0)
    {
        *(u8*)&((GameObject*)obj)->anim.resetHitboxMode = (u8)(*(u8*)&((GameObject*)obj)->anim.resetHitboxMode & ~INTERACT_FLAG_DISABLED);
        if ((*(u8*)&((GameObject*)obj)->anim.resetHitboxMode & INTERACT_FLAG_ACTIVATED) != 0 &&
            (*gGameUIInterface)->isOneOfItemsBeingUsed((s32*)&itemSet, 3) > -1)
        {
            GameBit_Set(0x4d1, 1);
            state->counter27 += 1;
            GameBit_Set(0x310, 1);
            buttonDisable(0, PAD_BUTTON_A);
        }
    }
    else
    {
        *(u8*)&((GameObject*)obj)->anim.resetHitboxMode = (u8)(*(u8*)&((GameObject*)obj)->anim.resetHitboxMode | INTERACT_FLAG_DISABLED);
        if (state->modeTimer <= 0)
        {
            switch (randomGetRange(1, 4))
            {
            case 1:
                state->prevMode = state->mode;
                state->mode = 1;
                state->modeTimer = 400;
                break;
            case 2:
                state->prevMode = state->mode;
                state->mode = 2;
                state->modeTimer = 400;
                break;
            case 3:
                state->prevMode = state->mode;
                state->mode = 3;
                state->modeTimer = 400;
                break;
            case 4:
                state->prevMode = state->mode;
                state->mode = 4;
                state->modeTimer = 400;
                break;
            case 5:
                state->prevMode = state->mode;
                state->mode = 5;
                state->modeTimer = 400;
                break;
            }
        }
        else
        {
            mode = state->mode;
            if (mode == 12)
            {
                ang = getAngle(gArwingAttachmentTargets[state->prevMode].x,
                               gArwingAttachmentTargets[state->prevMode].y);
                diff = (s16)(ang - ((GameObject*)obj)->anim.rotX);
                fn_80137948(sArwingAttachmentDiffFormat, diff);
                if (diff < -1000 || diff > 1000)
                {
                    if (diff > 0)
                    {
                        ((GameObject*)obj)->anim.rotX = (s16)(((GameObject*)obj)->anim.rotX + framesThisStep * 100);
                    }
                    else
                    {
                        ((GameObject*)obj)->anim.rotX = (s16)(((GameObject*)obj)->anim.rotX - framesThisStep * 100);
                    }
                }
                else
                {
                    ObjAnim_SetCurrentMove(obj, gArwingAttachmentTargets[state->prevMode].moveId,
                                           lbl_803E5D98, 0);
                    state->animSpeed = gArwingAttachmentTargets[state->prevMode].speed;
                    state->mode = 13;
                }
            }
            else if (mode == 13)
            {
                if (((ObjAnimAdvanceObjectFirstF32Fn)ObjAnim_AdvanceCurrentMove)
                    (obj, state->animSpeed, timeDelta, &animEvents) != 0)
                {
                    if ((f32)(int)((GameObject*)obj)->anim.currentMove ==
                        gArwingAttachmentTargets[state->prevMode].moveId)
                    {
                        ObjAnim_SetCurrentMove(obj,
                                               gArwingAttachmentTargets[state->prevMode].altMoveId,
                                               lbl_803E5D98, 0);
                        state->animSpeed = gArwingAttachmentTargets[state->prevMode].speed;
                    }
                }
                state->modeTimer -= framesThisStep;
                if (state->modeTimer <= 0)
                {
                    state->modeTimer = 0;
                }
            }
            else
            {
                dx = gArwingAttachmentTargets[mode].x - (((GameObject*)obj)->anim.localPosX - state->homeX);
                dy = gArwingAttachmentTargets[mode].y - (((GameObject*)obj)->anim.localPosZ - state->homeZ);
                dist = sqrtf(dx * dx + dy * dy);
                ang = getAngle(dx, dy);
                diff = (s16)(ang - ((GameObject*)obj)->anim.rotX);
                if (diff >= -1000 && diff <= 1000)
                {
                    if (((GameObject*)obj)->anim.currentMove != 59)
                    {
                        ObjAnim_SetCurrentMove(obj, 59, lbl_803E5D98, 0);
                        state->animSpeed = lbl_803E5DA8;
                    }
                    spd = lbl_803E5DAC;
                    ((GameObject*)obj)->anim.velocityX = spd * (dx / dist);
                    ((GameObject*)obj)->anim.velocityZ = spd * (dy / dist);
                    ((ObjAnimSampleRootCurveObjectFirstFn)ObjAnim_SampleRootCurvePhase)
                        (obj, spd, &state->animSpeed);
                }
                else
                {
                    if (((GameObject*)obj)->anim.currentMove != 12)
                    {
                        ObjAnim_SetCurrentMove(obj, 12, lbl_803E5D98, 0);
                        state->animSpeed = lbl_803E5DB0;
                    }
                    if (diff > 0)
                    {
                        ((GameObject*)obj)->anim.rotX = (s16)(((GameObject*)obj)->anim.rotX + framesThisStep * 300);
                    }
                    else
                    {
                        ((GameObject*)obj)->anim.rotX = (s16)(((GameObject*)obj)->anim.rotX - framesThisStep * 300);
                    }
                }
                if (dist < lbl_803E5DB4)
                {
                    state->prevMode = state->mode;
                    state->mode = 12;
                    spd = lbl_803E5D98;
                    ((GameObject*)obj)->anim.velocityX = spd;
                    ((GameObject*)obj)->anim.velocityZ = spd;
                }
                ((GameObject*)obj)->anim.localPosX = ((GameObject*)obj)->anim.velocityX * timeDelta + ((GameObject*)obj)
                    ->anim.localPosX;
                ((GameObject*)obj)->anim.localPosZ = ((GameObject*)obj)->anim.velocityZ * timeDelta + ((GameObject*)obj)
                    ->anim.localPosZ;
                ((ObjAnimAdvanceObjectFirstF32Fn)ObjAnim_AdvanceCurrentMove)
                    (obj, state->animSpeed, timeDelta, &animEvents);
            }
        }
    }
}

ObjHitReactEntry gArwingAttachmentHitReactTable[] =
{
    { 731, -1, -1, { 0xFF, 0xFF }, 0, { 0, 0, 0 }, 0.0f, { 0, 0, 0, 0 } },
    { 731, -1, -1, { 0xFF, 0xFF }, 0, { 0, 0, 0 }, 0.0f, { 0, 0, 0, 0 } },
    { 731, -1, -1, { 0xFF, 0xFF }, 0, { 0, 0, 0 }, 0.0f, { 0, 0, 0, 0 } },
    { 731, -1, -1, { 0xFF, 0xFF }, 0, { 0, 0, 0 }, 0.0f, { 0, 0, 0, 0 } },
    { 731, -1, -1, { 0xFF, 0xFF }, 0, { 0, 0, 0 }, 0.0f, { 0, 0, 0, 0 } },
    { 731, -1, -1, { 0xFF, 0xFF }, 0, { 0, 0, 0 }, 0.0f, { 0, 0, 0, 0 } },
    { 731, -1, -1, { 0xFF, 0xFF }, 0, { 0, 0, 0 }, 0.0f, { 0, 0, 0, 0 } },
    { 731, -1, -1, { 0xFF, 0xFF }, 0, { 0, 0, 0 }, 0.0f, { 0, 0, 0, 0 } },
    { 731, -1, -1, { 0xFF, 0xFF }, 0, { 0, 0, 0 }, 0.0f, { 0, 0, 0, 0 } },
    { 731, -1, -1, { 0xFF, 0xFF }, 0, { 0, 0, 0 }, 0.0f, { 0, 0, 0, 0 } },
    { 731, -1, -1, { 0xFF, 0xFF }, 0, { 0, 0, 0 }, 0.0f, { 0, 0, 0, 0 } },
};

ArwAttachTarget gArwingAttachmentTargets[] =
{
    { 0.0f, 0.0f, 0.0f, 0.0f, 0.02f },
    { 79.0f, 152.0f, 20.0f, 20.0f, 0.01f },
    { 138.0f, -6.0f, 20.0f, 20.0f, 0.02f },
    { -73.0f, -48.0f, 20.0f, 20.0f, 0.02f },
    { -248.0f, -7.0f, 0.0f, 0.0f, 0.02f },
    { 0.0f, 0.0f, 0.0f, 0.0f, 0.02f },
};

#include "main/object_descriptor.h"

ObjectDescriptor dll_200 = {
    0, 0, 0, OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)dll_200_initialise_nop,
    (ObjectDescriptorCallback)dll_200_release_nop,
    0,
    (ObjectDescriptorCallback)dll_200_init,
    (ObjectDescriptorCallback)dll_200_update,
    (ObjectDescriptorCallback)dll_200_hitDetect_nop,
    (ObjectDescriptorCallback)dll_200_render,
    (ObjectDescriptorCallback)dll_200_free_nop,
    (ObjectDescriptorCallback)dll_200_getObjectTypeId,
    (ObjectDescriptorExtraSizeCallback)dll_200_getExtraSize_ret_40,
};
char sArwingAttachmentDiffFormat[9] = "diff %d\n";
