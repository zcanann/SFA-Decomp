/*
 * dll200 (DLL 0x200) - an arwing-attachment / flying NPC whose behaviour
 * is selected by the current map-event mode for its placement slot
 * (gMapEventInterface->getMapAct). Per mode it plays idle/move anims,
 * lets the player interact (A-button) to spend magic and grant game
 * bits, runs trigger sequences (dll_200_SeqFn / fn_801F2974), and in
 * mode 2 (fn_801F2290) steers a wandering attachment toward scripted
 * targets (gArwingAttachmentTargets) via getAngle/sqrtf. Object body is Dll200State
 * (0x28); render scales through objRenderFn_8003b8f4 and gates on
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

    int sub;
    IntVec3 stk;

    sub = *(int*)&((GameObject*)obj)->extra;
    Obj_GetPlayerObject();
    stk = *(IntVec3*)gArwingAttachmentItemSetIdle;
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
        *(u8*)&((Dll200State*)sub)->counter27 = 0;
        buttonDisable(0, 256);
    }
    else if ((*(u8*)&((GameObject*)obj)->anim.resetHitboxMode & INTERACT_FLAG_ACTIVATED) != 0)
    {
        if ((*gGameUIInterface)->isOneOfItemsBeingUsed((s32*)&stk, 3) > -1)
        {
            GameBit_Set(784, 1);
            *(u8*)&((Dll200State*)sub)->counter27 += 1;
            buttonDisable(0, 256);
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

    int sub;

    sub = *(int*)&((GameObject*)obj)->extra;
    if (((GameObject*)obj)->anim.currentMove != 2)
    {
        ObjAnim_SetCurrentMove(obj, 2, lbl_803E5D98, 0);
    }
    ((ObjAnimAdvanceObjectFirstF32Fn)ObjAnim_AdvanceCurrentMove)
        (obj, lbl_803E5D9C, (f32)(u32)framesThisStep, NULL);
    ((Dll200State*)sub)->latch24 = 1;
    if (((Dll200State*)sub)->latch24 == 0)
    {
        if ((*(u8*)&((GameObject*)obj)->anim.resetHitboxMode & INTERACT_FLAG_ACTIVATED) != 0)
        {
            GameBit_Set(208, 1);
            ((Dll200State*)sub)->latch24 = 1;
            buttonDisable(0, 256);
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
                ((Dll200State*)sub)->mode25 = 2;
                (*gObjectTriggerInterface)->runSequence(2, (void*)obj, -1);
                buttonDisable(0, 256);
            }
            else
            {
                if (GameBit_Get(177) == 0 || GameBit_Get(178) == 0 || GameBit_Get(179) == 0)
                {
                    ((Dll200State*)sub)->mode25 = 1;
                    (*gObjectTriggerInterface)->runSequence(1, (void*)obj, -1);
                    buttonDisable(0, 256);
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
 * objRenderFn_8003b8f4. */
void dll_200_render(int* obj, int p1, int p2, int p3, int p4, s8 visible)
{
    extern void objRenderFn_8003b8f4(void* obj, int p1, int p2, int p3, int p4, f32 scale);
    int areaId;
    if (visible == 0) return;
    areaId = (*gMapEventInterface)->getMapAct((int)((GameObject*)obj)->anim.mapEventSlot);
    if ((u8)areaId == 4)
    {
        if ((u32)GameBit_Get(0x2bd) == 0u) return;
        objRenderFn_8003b8f4(obj, p1, p2, p3, p4, lbl_803E5DC0);
        return;
    }
    objRenderFn_8003b8f4(obj, p1, p2, p3, p4, lbl_803E5DC0);
}

int dll_200_SeqFn(int obj, int unused, ObjAnimUpdateState* animUpdate, int arg3);

void dll_200_init(int* obj, int* arg)
{
    Dll200State* b;
    ((GameObject*)obj)->unkF4 = 0;
    ((GameObject*)obj)->anim.rotX = (s16)((s32)*(s8*)((char*)arg + 0x18) << 8);
    ((GameObject*)obj)->animEventCallback = dll_200_SeqFn;
    b = ((GameObject*)obj)->extra;
    b->defNoLow = (u8)*(s16*)arg;
    b->unk1C = 0;
    b->unk18 = 0;
    b->homeX = *(f32*)((char*)arg + 0x8);
    b->homeY = *(f32*)((char*)arg + 0xc);
    b->homeZ = *(f32*)((char*)arg + 0x10);
    b->latch24 = GameBit_Get(0xd0);
    b->counter27 = 0;
    b->mode = 1;
    b->prevMode = 0xc;
    b->modeTimer = 0x12c;
    b->animSpeed = lbl_803E5D98;
    b->unk14 = lbl_803E5DC0;
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
    Dll200State* b;

    b = ((GameObject*)obj)->extra;
    ret = ObjHitReact_Update(obj, gArwingAttachmentHitReactTable, 11,
                             (u8)((b->mode & DLL200_MODE_HITREACTING) ? 1 : 0),
                             &b->hitReactVec);
    if (ret != 0)
    {
        b->mode = (u8)(b->mode | DLL200_MODE_HITREACTING);
    }
    else
    {
        b->mode = (u8)(b->mode & ~DLL200_MODE_HITREACTING);
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
    Dll200State* b;
    u8 m;
    s16 ang;
    s16 diff;
    f32 dx;
    f32 dy;
    f32 dist;
    f32 spd;
    IntVec3 stk;
    ObjAnimEventList animEvents;

    b = ((GameObject*)obj)->extra;
    Obj_GetPlayerObject();
    stk = *(IntVec3*)gArwingAttachmentItemSetWander;
    ((GameObject*)obj)->anim.localPosY = b->homeY;
    if (GameBit_Get(0x1fc) != 0)
    {
        *(u8*)&((GameObject*)obj)->anim.resetHitboxMode = (u8)(*(u8*)&((GameObject*)obj)->anim.resetHitboxMode & ~INTERACT_FLAG_DISABLED);
        if ((*(u8*)&((GameObject*)obj)->anim.resetHitboxMode & INTERACT_FLAG_ACTIVATED) != 0 &&
            (*gGameUIInterface)->isOneOfItemsBeingUsed((s32*)&stk, 3) > -1)
        {
            GameBit_Set(0x4d1, 1);
            b->counter27 += 1;
            GameBit_Set(0x310, 1);
            buttonDisable(0, 0x100);
        }
    }
    else
    {
        *(u8*)&((GameObject*)obj)->anim.resetHitboxMode = (u8)(*(u8*)&((GameObject*)obj)->anim.resetHitboxMode | INTERACT_FLAG_DISABLED);
        if (b->modeTimer <= 0)
        {
            switch (randomGetRange(1, 4))
            {
            case 1:
                b->prevMode = b->mode;
                b->mode = 1;
                b->modeTimer = 400;
                break;
            case 2:
                b->prevMode = b->mode;
                b->mode = 2;
                b->modeTimer = 400;
                break;
            case 3:
                b->prevMode = b->mode;
                b->mode = 3;
                b->modeTimer = 400;
                break;
            case 4:
                b->prevMode = b->mode;
                b->mode = 4;
                b->modeTimer = 400;
                break;
            case 5:
                b->prevMode = b->mode;
                b->mode = 5;
                b->modeTimer = 400;
                break;
            }
        }
        else
        {
            m = b->mode;
            if (m == 12)
            {
                ang = getAngle(gArwingAttachmentTargets[b->prevMode].x,
                               gArwingAttachmentTargets[b->prevMode].y);
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
                    ObjAnim_SetCurrentMove(obj, gArwingAttachmentTargets[b->prevMode].moveId,
                                           lbl_803E5D98, 0);
                    b->animSpeed = gArwingAttachmentTargets[b->prevMode].speed;
                    b->mode = 13;
                }
            }
            else if (m == 13)
            {
                if (((ObjAnimAdvanceObjectFirstF32Fn)ObjAnim_AdvanceCurrentMove)
                    (obj, b->animSpeed, timeDelta, &animEvents) != 0)
                {
                    if ((f32)(int)((GameObject*)obj)->anim.currentMove ==
                        gArwingAttachmentTargets[b->prevMode].moveId)
                    {
                        ObjAnim_SetCurrentMove(obj,
                                               gArwingAttachmentTargets[b->prevMode].altMoveId,
                                               lbl_803E5D98, 0);
                        b->animSpeed = gArwingAttachmentTargets[b->prevMode].speed;
                    }
                }
                b->modeTimer -= framesThisStep;
                if (b->modeTimer <= 0)
                {
                    b->modeTimer = 0;
                }
            }
            else
            {
                dx = gArwingAttachmentTargets[m].x - (((GameObject*)obj)->anim.localPosX - b->homeX);
                dy = gArwingAttachmentTargets[m].y - (((GameObject*)obj)->anim.localPosZ - b->homeZ);
                dist = sqrtf(dx * dx + dy * dy);
                ang = getAngle(dx, dy);
                diff = (s16)(ang - ((GameObject*)obj)->anim.rotX);
                if (diff >= -1000 && diff <= 1000)
                {
                    if (((GameObject*)obj)->anim.currentMove != 59)
                    {
                        ObjAnim_SetCurrentMove(obj, 59, lbl_803E5D98, 0);
                        b->animSpeed = lbl_803E5DA8;
                    }
                    spd = lbl_803E5DAC;
                    ((GameObject*)obj)->anim.velocityX = spd * (dx / dist);
                    ((GameObject*)obj)->anim.velocityZ = spd * (dy / dist);
                    ((ObjAnimSampleRootCurveObjectFirstFn)ObjAnim_SampleRootCurvePhase)
                        (obj, spd, &b->animSpeed);
                }
                else
                {
                    if (((GameObject*)obj)->anim.currentMove != 12)
                    {
                        ObjAnim_SetCurrentMove(obj, 12, lbl_803E5D98, 0);
                        b->animSpeed = lbl_803E5DB0;
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
                    b->prevMode = b->mode;
                    b->mode = 12;
                    spd = lbl_803E5D98;
                    ((GameObject*)obj)->anim.velocityX = spd;
                    ((GameObject*)obj)->anim.velocityZ = spd;
                }
                ((GameObject*)obj)->anim.localPosX = ((GameObject*)obj)->anim.velocityX * timeDelta + ((GameObject*)obj)
                    ->anim.localPosX;
                ((GameObject*)obj)->anim.localPosZ = ((GameObject*)obj)->anim.velocityZ * timeDelta + ((GameObject*)obj)
                    ->anim.localPosZ;
                ((ObjAnimAdvanceObjectFirstF32Fn)ObjAnim_AdvanceCurrentMove)
                    (obj, b->animSpeed, timeDelta, &animEvents);
            }
        }
    }
}
