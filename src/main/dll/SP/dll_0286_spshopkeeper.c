#include "main/dll_000A_expgfx.h"
#include "main/dll/shopkeeperstate_struct.h"
#include "main/dll/pushcartstate97_types.h"
#include "main/game_object.h"
#include "main/mapEvent.h"
#include "main/dll/DR/DRpushcart.h"
#include "main/dll/dll_002E_moveLib.h"
#include "main/objseq.h"
#include "main/objtexture.h"
#include "main/player_control_interface.h"
#include "main/screen_transition.h"

STATIC_ASSERT(sizeof(ShopItemState) == 0xEC);

STATIC_ASSERT(sizeof(ShopkeeperState) == 0x9D8);
STATIC_ASSERT(offsetof(ShopkeeperState, msgStack) == 0x9B0);

extern uint GameBit_Get(int eventId);
extern undefined4 GameBit_Set(int eventId, int value);
extern u32 randomGetRange(int min, int max);
extern undefined4 ObjGroup_FindNearestObject();
extern void dll_2E_func06();

extern f32 lbl_803E59D8;
extern void objRenderFn_8003b8f4(f32);

#pragma scheduling on
#pragma peephole on
extern void Stack_Free();
extern void* lbl_803AD068[8];
extern void* lbl_803DDC58;
extern void DRlaserturret_startLinkedTarget(int);
extern void DRlaserturret_updateTracking(int);
extern void DRlaserturret_updateIdle(int);
extern void TREX_Lazerwall_updateTimedChallenge(int);
extern void TREX_Lazerwall_waitForStartBit(int);
extern void TREX_Lazerwall_popQueuedState(int);
extern void fn_801E66EC(int);
extern void fn_801E66E4(int);
extern void fn_801E66DC(int);
extern void* Obj_GetPlayerObject(void);
extern f32 lbl_803E5A20;
extern f32 timeDelta;
extern f32 lbl_803E59DC;
extern void gameTextShow(int);
extern u32 ObjGroup_FindNearestObject(int kind, int obj, f32* out);
extern int playerGetMoney(void* player);
extern void characterDoEyeAnims(int obj, int p2);
extern void dll_2E_func03(int, int);
extern f32 shopKeeperRotateFn_801e7c4c(s16* obj, void* player, int mode);
extern f32 lbl_803E59F0;
extern f32 lbl_803E5A28;
extern void* allocModelStruct_800139e8(int, int);
extern void dll_2E_func05(int, int, int, int, int);
extern int fn_801E76A0(int obj, int p2, ObjSeqState* seq, s8 advance);
extern void DRlaserturret_startTimedChallenge(int);
extern void DRlaserturret_handlePromptChoice(int);
extern void setAButtonIcon(int icon);
extern void setBButtonIcon(int icon);
extern void warpToMap(int mapId, int flag);
extern int getCurUiDll(void);
extern int* getDLL16(void);
extern void playerAddMoney(void* player, int amount);
extern f32 sqrtf(f32 x);
extern f32 lbl_803E5A24;

undefined4 FUN_801e76a0(int obj)
{
    uint gbit;
    undefined4 result;
    int state;

    state = *(int*)&((GameObject*)obj)->extra;
    gbit = GameBit_Get(0xcef);
    if (gbit == 0)
    {
        result = 0;
    }
    else
    {
        gbit = GameBit_Get(0xad3);
        if (gbit == 0)
        {
            GameBit_Set(0xad3, 1);
            state = *(int*)(state + 0x9b4);
            (**(code**)(**(int**)&((GameObject*)state)->anim.dll + 0x24))(state, 1, 2);
        }
        result = 2;
    }
    return result;
}

#pragma scheduling off
#pragma peephole off
void fn_801E7DC8(int p1, int p2, int count)
{
    extern u8 Obj_IsLoadingLocked(void);
    extern void hitDetectFn_800658a4(int, f32, f32, f32, int*, int);
    extern int Obj_AllocObjectSetup(int, int);
    extern void Obj_SetupObject(int, int, int, int, int);
    extern MapEventInterface** gMapEventInterface;
    int i;
    int local;
    int o;

    if (Obj_IsLoadingLocked() == 0) return;

    (*gMapEventInterface)->setObjGroupStatus((s32)((GameObject*)p1)->anim.mapEventSlot, 6, 1);

    hitDetectFn_800658a4(p1, ((GameObject*)p1)->anim.localPosX, ((GameObject*)p1)->anim.localPosY,
                         ((GameObject*)p1)->anim.localPosZ, &local, 0);

    for (i = 0; i < count; i++)
    {
        o = Obj_AllocObjectSetup(36, 1151);
        *(f32*)(o + 8) = ((GameObject*)p1)->anim.localPosX;
        *(f32*)(o + 12) = ((GameObject*)p1)->anim.localPosY;
        *(f32*)(o + 16) = ((GameObject*)p1)->anim.localPosZ;
        *(s8*)(o + 24) = randomGetRange(-128, 127);
        *(s16*)(o + 26) = ((GameObject*)p1)->anim.localPosY - *(f32*)&local;
        *(u8*)(o + 5) = 1;
        *(u8*)(o + 7) = 255;
        *(u8*)(o + 4) = 16;
        *(u8*)(o + 6) = 6;
        *(int*)(o + 20) = ((ShopkeeperState*)p2)->vendorObj;
        Obj_SetupObject(o, 5, ((GameObject*)p1)->anim.mapEventSlot, -1, *(int*)&((GameObject*)p1)->anim.parent);
    }

    for (i = 0; i < count; i++)
    {
        o = Obj_AllocObjectSetup(36, 1151);
        *(f32*)(o + 8) = ((GameObject*)p1)->anim.localPosX;
        *(f32*)(o + 12) = ((GameObject*)p1)->anim.localPosY;
        *(f32*)(o + 16) = ((GameObject*)p1)->anim.localPosZ;
        *(s8*)(o + 24) = randomGetRange(-128, 127);
        *(s16*)(o + 26) = ((GameObject*)p1)->anim.localPosY - *(f32*)&local;
        *(u8*)(o + 5) = 1;
        *(u8*)(o + 7) = 255;
        *(u8*)(o + 4) = 16;
        *(u8*)(o + 6) = 6;
        *(u8*)(o + 25) = 1;
        *(int*)(o + 20) = ((ShopkeeperState*)p2)->vendorObj;
        Obj_SetupObject(o, 5, ((GameObject*)p1)->anim.mapEventSlot, -1, *(int*)&((GameObject*)p1)->anim.parent);
    }
}

void shopkeeper_free(int obj)
{
    Stack_Free(*(undefined4*)(*(int*)&((GameObject*)obj)->extra + 0x9b0));
    return;
}

void shopkeeper_render(int obj, int p2, int p3, int p4, int p5, s8 visible)
{
    int state = *(int*)&((GameObject*)obj)->extra;
    float local_18[4];
    local_18[0] = lbl_803E59D8;
    if (*(s16*)(state + 0x274) != 7 && visible != 0)
    {
        ((void (*)(int, int, int, int, int, f32))objRenderFn_8003b8f4)
            (obj, p2, p3, p4, p5, lbl_803E59D8);
        dll_2E_func06(obj, state + 0x35c, 0);
    }
    if ((*(u8*)(state + 0x9d4) & 0x20) != 0)
    {
        (*gBoneParticleEffectInterface)->spawnEffect((void*)obj, 0x7ef, local_18, 0x50, NULL);
    }
}

int fn_801E86F4(int obj, int p2, ObjSeqState* seq);

void shopkeeper_hitDetect(void)
{
}

void shopkeeper_release(void)
{
}

void shopitem_hitDetect(void);

int shopkeeper_getExtraSize(void) { return 0x9d8; }
int shopkeeper_getObjectTypeId(void) { return 0x0; }
int shopitem_getExtraSize(void);

void shopkeeper_initialise(void)
{
    lbl_803AD068[0] = (void*)DRlaserturret_startLinkedTarget;
    lbl_803AD068[1] = (void*)DRlaserturret_updateTracking;
    lbl_803AD068[2] = (void*)DRlaserturret_updateIdle;
    lbl_803AD068[3] = (void*)TREX_Lazerwall_updateTimedChallenge;
    lbl_803AD068[4] = (void*)TREX_Lazerwall_waitForStartBit;
    lbl_803AD068[5] = (void*)TREX_Lazerwall_popQueuedState;
    lbl_803AD068[6] = (void*)fn_801E66EC;
    lbl_803AD068[7] = (void*)fn_801E66E4;
    lbl_803DDC58 = (void*)fn_801E66DC;
}

void shopkeeper_update(int obj)
{
    void* player;
    int state;
    f32 dist;
    player = Obj_GetPlayerObject();
    state = *(int*)&((GameObject*)obj)->extra;
    dist = lbl_803E5A20;
    ((ShopkeeperState*)state)->flags9D4 &= ~0x20;
    if (((ShopkeeperState*)state)->textTimer > lbl_803E59DC)
    {
        gameTextShow(0x433);
        ((ShopkeeperState*)state)->textTimer = ((ShopkeeperState*)state)->textTimer - timeDelta;
        if (((ShopkeeperState*)state)->textTimer < lbl_803E59DC)
        {
            ((ShopkeeperState*)state)->textTimer = *(f32*)&lbl_803E59DC;
        }
    }
    if ((((ShopkeeperState*)state)->flags9D4 & 0x04) != 0)
    {
        shopKeeperRotateFn_801e7c4c((s16*)obj, player, 1);
    }
    ((GameObject*)obj)->anim.rootMotionScale = ((GameObject*)obj)->anim.modelInstance->rootMotionScaleBase;
    if (*(void**)&((ShopkeeperState*)state)->vendorObj == NULL)
    {
        ((ShopkeeperState*)state)->vendorObj = ObjGroup_FindNearestObject(9, obj, &dist);
    }
    ((ShopkeeperState*)state)->playerMoney = (s16)playerGetMoney(player);
    (*gPlayerInterface)->update((void*)obj, (void*)state, timeDelta, timeDelta, lbl_803AD068,
                                &lbl_803DDC58);
    dll_2E_func03(obj, state + 0x35C);
    characterDoEyeAnims(obj, state + 0x980);
    ((GameObject*)obj)->anim.alpha = ((ShopkeeperState*)state)->opacity;
}

void shopkeeper_init(int obj)
{
    int state = *(int*)&((GameObject*)obj)->extra;
    ((GameObject*)obj)->objectFlags |= 0x2000;
    ((GameObject*)obj)->animEventCallback = (void*)fn_801E76A0;
    ((GameObject*)obj)->anim.modelState->flags |= 0x810;
    ((ShopkeeperState*)state)->unk9B8 = lbl_803E59F0 * (f32)(s32)
    randomGetRange(0xF, 0x23);
    ((ShopkeeperState*)state)->msgStack = allocModelStruct_800139e8(4, 4);
    ((ShopkeeperState*)state)->opacity = 0xFF;
    ((ShopkeeperState*)state)->textTimer = lbl_803E5A28;
    dll_2E_func05(obj, state + 0x35C, -0x1C71, 0x3555, 2);
    ((ShopkeeperState*)state)->unk96D |= 0x12;
}

int fn_801E76A0(int obj, int p2, ObjSeqState* seq, s8 advance)
{
    int state;
    int state2;
    void* player;
    int slot;
    int i;
    int digit;
    int hundreds;
    ObjTextureRuntimeSlot* tex;
    int* uiDll;
    f32 range;
    f32 speed;

    state = state2 = *(int*)&((GameObject*)obj)->extra;
    player = Obj_GetPlayerObject();
    range = lbl_803E59D8;
    ((ShopkeeperState*)state)->flags9D4 &= ~0x20;
    if (((ShopkeeperState*)state)->flags9D4 & 0x10)
    {
        if ((*gScreenTransitionInterface)->isFinished() != 0)
        {
            (*gScreenTransitionInterface)->step(0x1E, 1);
            (*gObjectTriggerInterface)->endSequence((s8)seq->slot);
        }
        return 0;
    }
    if (dll_2E_func07(obj, seq, (char*)(state + 0x35C), 0, 0) != 0)
    {
        return 1;
    }
    seq->freeCallback = (ObjAnimSequenceFreeCallback)DRlaserturret_startTimedChallenge;
    seq->flags &= ~0x20;
    speed = lbl_803E59DC;
    ((ShopkeeperState*)state2)->animSpeed = speed;
    ((ShopkeeperState*)state)->flags9D4 |= 4;
    if (advance != 0)
    {
        ((int (*)(int, f32, f32, void*))ObjAnim_AdvanceCurrentMove)(obj, speed, timeDelta, NULL);
    }
    if (((GameObject*)obj)->seqIndex == -1)
    {
        if ((s8)seq->movementState != 0)
        {
            slot = (*(int (**)(int))((char*)**(int***)(((ShopkeeperState*)state)->vendorObj + 0x68) + 0x44))(
                ((ShopkeeperState*)state)->vendorObj);
            if (slot != -1)
            {
                ((ShopkeeperState*)state)->price = (s16)(
                    *(int (**)(int, int))((char*)**(int***)(((ShopkeeperState*)state)->vendorObj + 0x68) + 0x38))(
                    ((ShopkeeperState*)state)->vendorObj, slot);
                ((ShopkeeperState*)state)->unk9CE = (s16)(
                    *(int (**)(int, int))((char*)**(int***)(((ShopkeeperState*)state)->vendorObj + 0x68) + 0x30))(
                    ((ShopkeeperState*)state)->vendorObj, slot);
                ((ShopkeeperState*)state)->priceShown = ((ShopkeeperState*)state)->price;
                ((ShopkeeperState*)state)->unk9D2 = 0;
                digit = ((ShopkeeperState*)state)->price;
                tex = objFindTexture((void*)obj, 8, 0);
                tex->textureId = (digit % 10) * 0x100;
                tex = objFindTexture((void*)obj, 7, 0);
                tex->textureId = ((digit / 10) % 10) * 0x100;
                hundreds = digit / 100;
                if (hundreds > 9)
                {
                    hundreds = 9;
                }
                tex = objFindTexture((void*)obj, 6, 0);
                tex->textureId = hundreds << 8;
            }
            seq->movementState = 0;
            seq->conditionCallback = (ObjAnimSequenceConditionCallback)DRlaserturret_handlePromptChoice;
        }
        if ((*(int (**)(int))((char*)**(int***)(((ShopkeeperState*)state)->vendorObj + 0x68) + 0x44))(
            ((ShopkeeperState*)state)->vendorObj) != -1)
        {
            setAButtonIcon(0x12);
            setBButtonIcon(0xA);
        }
    }
    for (i = 0; i < seq->eventCount; i++)
    {
        switch (seq->eventIds[i])
        {
        case 1:
            fn_801E7DC8(obj, state, ((ShopkeeperState*)state)->amount);
            ((ShopkeeperState*)state)->flags9D4 |= 2;
            break;
        case 2:
            (*gPlayerInterface)->setState((void*)obj, (void*)state2, 3);
            (*gBoneParticleEffectInterface)->spawnEffect((void*)obj, 0x7EF, &range, 0x50, NULL);
            ((ShopkeeperState*)state)->opacity = 0;
            break;
        case 3:
            (*gPlayerInterface)->setState((void*)obj, (void*)state2, 2);
            ((ShopkeeperState*)state)->flags9D4 |= 0x20;
            ((ShopkeeperState*)state)->opacity = 0xFF;
            break;
        case 4:
            if (((GameObject*)player)->anim.seqId == 0)
            {
                warpToMap(0xF, 0);
            }
            else
            {
                warpToMap(0xE, 0);
            }
            break;
        case 5:
            if (getCurUiDll() == 0x10)
            {
                uiDll = getDLL16();
                (*(void (**)(int))(*uiDll + 0x10))(0);
            }
            break;
        case 6:
            if (getCurUiDll() == 0x10)
            {
                uiDll = getDLL16();
                (*(void (**)(int))(*uiDll + 0x10))(2);
            }
            break;
        case 7:
            if (getCurUiDll() == 0x10)
            {
                uiDll = getDLL16();
                (*(void (**)(int))(*uiDll + 0x10))(4);
            }
            break;
        case 9:
            playerAddMoney(player, ((ShopkeeperState*)state)->amount);
            break;
        case 10:
            playerAddMoney(player, -(int)((ShopkeeperState*)state)->amount);
            break;
        case 0xB:
            (*gBoneParticleEffectInterface)->spawnEffect((void*)obj, 0x7EF, &range, 0x50, NULL);
            break;
        case 0xC:
            ((ShopkeeperState*)state)->amount = 1;
            digit = ((ShopkeeperState*)state)->amount;
            tex = objFindTexture((void*)obj, 8, 0);
            tex->textureId = (digit % 10) * 0x100;
            tex = objFindTexture((void*)obj, 7, 0);
            tex->textureId = ((digit / 10) % 10) * 0x100;
            digit = digit / 100;
            if (digit > 9)
            {
                digit = 9;
            }
            tex = objFindTexture((void*)obj, 6, 0);
            tex->textureId = digit << 8;
            break;
        }
    }
    ((GameObject*)obj)->anim.alpha = ((ShopkeeperState*)state)->opacity;
    return 0;
}

f32 shopKeeperRotateFn_801e7c4c(s16* obj, void* player, int mode)
{
    f32 dist;
    f32 dx;
    f32 dz;
    u16 angle;
    int diff;

    dx = ((GameObject*)player)->anim.localPosX - ((GameObject*)obj)->anim.localPosX;
    dz = ((GameObject*)player)->anim.localPosZ - ((GameObject*)obj)->anim.localPosZ;
    dist = sqrtf(dx * dx + dz * dz);
    if (dist != lbl_803E59DC)
    {
        dx /= dist;
        dz /= dist;
    }
    if (dist > lbl_803E5A24)
    {
        angle = (u16)getAngle(dx, dz);
        if (mode != 0)
        {
            *obj = (s16)angle;
        }
        else
        {
            diff = angle - (u16) * obj;
            if (diff > 0x8000)
            {
                diff -= 0xFFFF;
            }
            if (diff < -0x8000)
            {
                diff += 0xFFFF;
            }
            if (diff > 0x2000)
            {
                diff -= 0x2000;
            }
            else if (diff < -0x2000)
            {
                diff += 0x2000;
            }
            else
            {
                diff = 0;
            }
            *obj = (s16)(int)((f32)(diff >> 3) * timeDelta + (f32) * obj);
        }
    }
    return dist;
}
