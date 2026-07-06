/*
 * spshopkeeper (DLL 0x286) - the SnowHorn shopkeeper vendor character.
 *
 * He latches onto the nearest shop stall (object group 9, vendorObj), turns
 * to face the player and runs the purchase flow via his animEventCallback
 * (fn_801E76A0): reading the shop's current item price through the stall's
 * interface vtable, pushing the three price digits into his number-texture
 * slots, and handling buy/cancel through the screen-transition + UI dll.
 * fn_801E7DC8 scatters the paid scarab coins (object type 1151). Per-frame
 * look-at and eye animation run through the shared dll_2E (moveLib) blocks.
 */
#include "main/dll_000A_expgfx.h"
#include "main/dll/shopkeeperstate_struct.h"
#include "main/dll/pushcartstate97_types.h"
#include "main/game_object.h"
#include "main/mapEvent.h"
#include "main/obj_placement.h"
#include "main/dll/dll_002E_moveLib.h"
#include "main/objtexture.h"
#include "main/player_control_interface.h"
#include "main/screen_transition.h"
#include "main/objlib.h"
#include "main/engine_shared.h"
#include "main/dll/SP/dll_0286_spshopkeeper.h"

#define SPSHOPKEEPER_OBJFLAG_HITDETECT_DISABLED 0x2000

STATIC_ASSERT(sizeof(ShopItemState) == 0xEC);

STATIC_ASSERT(sizeof(ShopkeeperState) == 0x9D8);
STATIC_ASSERT(offsetof(ShopkeeperState, msgStack) == 0x9B0);

/* Obj_AllocObjectSetup(36,...) buffer composed in fn_801E7DC8. Head is the
 * common ObjPlacement; mapId slot (0x14) is repurposed as an int (vendorObj),
 * tail (0x18..0x1B) is file-local. */
typedef struct ShopkeeperSpawnSetup
{
    ObjPlacement base; /* 0x00..0x17 */
    s8 rotXByte;       /* 0x18: scarab spawn rotX (1/256 turns) */
    u8 kind;           /* 0x19: scarab variant (see SpscarabPlacement.kind) */
    s16 groundY;       /* 0x1A: scarab ground-height delta (see SpscarabState.groundY) */
    u8 pad1C[0x24 - 0x1C];
} ShopkeeperSpawnSetup;

STATIC_ASSERT(offsetof(ShopkeeperSpawnSetup, rotXByte) == 0x18);
STATIC_ASSERT(offsetof(ShopkeeperSpawnSetup, kind) == 0x19);
STATIC_ASSERT(offsetof(ShopkeeperSpawnSetup, groundY) == 0x1A);
STATIC_ASSERT(sizeof(ShopkeeperSpawnSetup) == 0x24);

/* object type id of the scarab coins the shopkeeper scatters (DLL 0x287) */
#define OBJTYPE_SPSCARAB 1151

/* ShopkeeperState.flags9D4 bits */
enum
{
    SHOPKEEPER_FLAG_PURCHASED = 0x02, /* purchase event fired */
    SHOPKEEPER_FLAG_FACING = 0x04,    /* turn to face the player */
    SHOPKEEPER_FLAG_LEAVING = 0x10,   /* leaving / screen transition */
    SHOPKEEPER_FLAG_TICK = 0x20       /* per-frame tick effect this frame */
};

extern void dll_2E_func06();
extern f32 lbl_803E59D8;
extern void objRenderModelAndHitVolumes(int obj, int p2, int p3, int p4, int p5, f32 scale);
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
extern f32 lbl_803E5A20;
extern f32 lbl_803E59DC;
extern int playerGetMoney(void* player);
extern void characterDoEyeAnims(int obj, int p2);
extern void dll_2E_func03(int, int);
extern f32 shopKeeperRotateFn_801e7c4c(s16* obj, void* player, int mode);
extern f32 lbl_803E59F0;
extern f32 lbl_803E5A28;
extern void dll_2E_func05(int, int, int, int, int);

extern void DRlaserturret_startTimedChallenge(int);
extern void DRlaserturret_handlePromptChoice(int);
extern void setAButtonIcon(int x);
extern void setBButtonIcon(int icon);
extern void warpToMap(int idx, s8 transType);
extern void playerAddMoney(void* player, int amount);
extern f32 lbl_803E5A24;

void fn_801E7DC8(int obj, int state, int count)
{
    extern u8 Obj_IsLoadingLocked(void);
    extern int hitDetectFn_800658a4(int a, f32 b, f32 val, f32 d, f32* out, int e);
    extern int Obj_AllocObjectSetup(int, int);
    extern void* Obj_SetupObject(int a, int b, int c, int d, int e);
    int i;
    f32 groundHeight;
    int o;

    if (Obj_IsLoadingLocked() == 0) return;

    (*gMapEventInterface)->setObjGroupStatus((s32)((GameObject*)obj)->anim.mapEventSlot, 6, 1);

    hitDetectFn_800658a4(obj, ((GameObject*)obj)->anim.localPosX, ((GameObject*)obj)->anim.localPosY,
                         ((GameObject*)obj)->anim.localPosZ, &groundHeight, 0);

    for (i = 0; i < count; i++)
    {
        o = Obj_AllocObjectSetup(0x24, OBJTYPE_SPSCARAB);
        ((ShopkeeperSpawnSetup*)o)->base.posX = ((GameObject*)obj)->anim.localPosX;
        ((ShopkeeperSpawnSetup*)o)->base.posY = ((GameObject*)obj)->anim.localPosY;
        ((ShopkeeperSpawnSetup*)o)->base.posZ = ((GameObject*)obj)->anim.localPosZ;
        ((ShopkeeperSpawnSetup*)o)->rotXByte = randomGetRange(-128, 127);
        ((ShopkeeperSpawnSetup*)o)->groundY = ((GameObject*)obj)->anim.localPosY - groundHeight;
        ((ShopkeeperSpawnSetup*)o)->base.color[1] = 1;
        ((ShopkeeperSpawnSetup*)o)->base.color[3] = 255;
        ((ShopkeeperSpawnSetup*)o)->base.color[0] = 16;
        ((ShopkeeperSpawnSetup*)o)->base.color[2] = 6;
        ((ShopkeeperSpawnSetup*)o)->base.mapId = ((ShopkeeperState*)state)->vendorObj;
        Obj_SetupObject(o, 5, ((GameObject*)obj)->anim.mapEventSlot, -1, *(int*)&((GameObject*)obj)->anim.parent);
    }

    for (i = 0; i < count; i++)
    {
        o = Obj_AllocObjectSetup(0x24, OBJTYPE_SPSCARAB);
        ((ShopkeeperSpawnSetup*)o)->base.posX = ((GameObject*)obj)->anim.localPosX;
        ((ShopkeeperSpawnSetup*)o)->base.posY = ((GameObject*)obj)->anim.localPosY;
        ((ShopkeeperSpawnSetup*)o)->base.posZ = ((GameObject*)obj)->anim.localPosZ;
        ((ShopkeeperSpawnSetup*)o)->rotXByte = randomGetRange(-128, 127);
        ((ShopkeeperSpawnSetup*)o)->groundY = ((GameObject*)obj)->anim.localPosY - groundHeight;
        ((ShopkeeperSpawnSetup*)o)->base.color[1] = 1;
        ((ShopkeeperSpawnSetup*)o)->base.color[3] = 255;
        ((ShopkeeperSpawnSetup*)o)->base.color[0] = 16;
        ((ShopkeeperSpawnSetup*)o)->base.color[2] = 6;
        ((ShopkeeperSpawnSetup*)o)->kind = 1;
        ((ShopkeeperSpawnSetup*)o)->base.mapId = ((ShopkeeperState*)state)->vendorObj;
        Obj_SetupObject(o, 5, ((GameObject*)obj)->anim.mapEventSlot, -1, *(int*)&((GameObject*)obj)->anim.parent);
    }
}

void shopkeeper_free(int obj)
{
    Stack_Free(((ShopkeeperState*)((GameObject*)obj)->extra)->msgStack);
    return;
}

void shopkeeper_render(int obj, int p2, int p3, int p4, int p5, s8 visible)
{
    int state = *(int*)&((GameObject*)obj)->extra;
    f32 fxParams[4];
    fxParams[0] = lbl_803E59D8;
    if (((ShopkeeperState*)state)->controlMode != 7 && visible != 0)
    {
        ((void (*)(int, int, int, int, int, f32))objRenderModelAndHitVolumes)
            (obj, p2, p3, p4, p5, lbl_803E59D8);
        dll_2E_func06(obj, state + 0x35c, 0);
    }
    if ((((ShopkeeperState*)state)->flags9D4 & SHOPKEEPER_FLAG_TICK) != 0)
    {
        (*gBoneParticleEffectInterface)->spawnEffect((void*)obj, 0x7ef, fxParams, 0x50, NULL);
    }
}


void shopkeeper_hitDetect(void)
{
}

void shopkeeper_release(void)
{
}


int shopkeeper_getExtraSize(void) { return 0x9d8; }
int shopkeeper_getObjectTypeId(void) { return 0x0; }

void shopkeeper_initialise(void)
{
    lbl_803AD068[0] = DRlaserturret_startLinkedTarget;
    lbl_803AD068[1] = DRlaserturret_updateTracking;
    lbl_803AD068[2] = DRlaserturret_updateIdle;
    lbl_803AD068[3] = TREX_Lazerwall_updateTimedChallenge;
    lbl_803AD068[4] = TREX_Lazerwall_waitForStartBit;
    lbl_803AD068[5] = TREX_Lazerwall_popQueuedState;
    lbl_803AD068[6] = fn_801E66EC;
    lbl_803AD068[7] = fn_801E66E4;
    lbl_803DDC58 = fn_801E66DC;
}

void shopkeeper_update(int obj)
{
    void* player;
    int state;
    f32 dist;
    player = Obj_GetPlayerObject();
    state = *(int*)&((GameObject*)obj)->extra;
    dist = lbl_803E5A20;
    ((ShopkeeperState*)state)->flags9D4 &= ~SHOPKEEPER_FLAG_TICK;
    if (((ShopkeeperState*)state)->textTimer > lbl_803E59DC)
    {
        gameTextShow(0x433);
        ((ShopkeeperState*)state)->textTimer = ((ShopkeeperState*)state)->textTimer - timeDelta;
        if (((ShopkeeperState*)state)->textTimer < lbl_803E59DC)
        {
            ((ShopkeeperState*)state)->textTimer = *(f32*)&lbl_803E59DC;
        }
    }
    if ((((ShopkeeperState*)state)->flags9D4 & SHOPKEEPER_FLAG_FACING) != 0)
    {
        shopKeeperRotateFn_801e7c4c((s16*)obj, player, 1);
    }
    ((GameObject*)obj)->anim.rootMotionScale = ((GameObject*)obj)->anim.modelInstance->rootMotionScaleBase;
    if (*(void**)&((ShopkeeperState*)state)->vendorObj == NULL)
    {
        ((ShopkeeperState*)state)->vendorObj = ObjGroup_FindNearestObject(9, obj, &dist);
    }
    ((ShopkeeperState*)state)->playerMoney = playerGetMoney(player);
    (*gPlayerInterface)->update((void*)obj, (void*)state, timeDelta, timeDelta, lbl_803AD068,
                                &lbl_803DDC58);
    dll_2E_func03(obj, state + 0x35C);
    characterDoEyeAnims(obj, state + 0x980);
    ((GameObject*)obj)->anim.alpha = ((ShopkeeperState*)state)->opacity;
}

void shopkeeper_init(int obj)
{
    int state = *(int*)&((GameObject*)obj)->extra;
    ((GameObject*)obj)->objectFlags |= SPSHOPKEEPER_OBJFLAG_HITDETECT_DISABLED;
    ((GameObject*)obj)->animEventCallback = fn_801E76A0;
    ((GameObject*)obj)->anim.modelState->flags |= 0x810;
    ((ShopkeeperState*)state)->unk9B8 = lbl_803E59F0 * (f32)(s32)randomGetRange(0xF, 0x23);
    ((ShopkeeperState*)state)->msgStack = allocModelStruct_800139e8(4, 4);
    ((ShopkeeperState*)state)->opacity = 0xFF;
    ((ShopkeeperState*)state)->textTimer = lbl_803E5A28;
    dll_2E_func05(obj, state + 0x35C, -0x1C71, 0x3555, 2);
    ((ShopkeeperState*)state)->unk96D |= 0x12;
}

int fn_801E76A0(int obj, int p2, ObjSeqState* seq, s8 advance)
{
    int state;
    int digit;
    int slot;
    int i;
    int state2;
    void* player;
    int hundreds;
    ObjTextureRuntimeSlot* tex;
    int* uiDll;
    f32 range;
    f32 speed;

    state = *(int*)&((GameObject*)obj)->extra;
    /* second copy of the extra pointer; the (int)(long) round-trip is
     * load-bearing - it splits the value web so state2 gets its own
     * register home (md5-verified: removing it changes codegen) */
    state2 = (int)(long)*(int*)&((GameObject*)obj)->extra;
    player = Obj_GetPlayerObject();
    range = lbl_803E59D8;
    ((ShopkeeperState*)state)->flags9D4 &= ~SHOPKEEPER_FLAG_TICK;
    if (((ShopkeeperState*)state)->flags9D4 & SHOPKEEPER_FLAG_LEAVING)
    {
        if ((*gScreenTransitionInterface)->isFinished() != 0)
        {
            (*gScreenTransitionInterface)->step(0x1E, 1);
            (*gObjectTriggerInterface)->endSequence(*(s8*)&seq->slot);
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
    ((ShopkeeperState*)state)->flags9D4 |= SHOPKEEPER_FLAG_FACING;
    if (advance != 0)
    {
        ((int (*)(int, f32, f32, void*))ObjAnim_AdvanceCurrentMove)(obj, speed, timeDelta, NULL);
    }
    if (((GameObject*)obj)->seqIndex == -1)
    {
        if ((s8)seq->movementState != 0)
        {
            slot = (*(int (**)(int))((char*)*((GameObject*)((ShopkeeperState*)state)->vendorObj)->anim.dll + 0x44))(
                ((ShopkeeperState*)state)->vendorObj);
            if (slot != -1)
            {
                ((ShopkeeperState*)state)->price = (s16)(
                    *(int (**)(int, int))((char*)*((GameObject*)((ShopkeeperState*)state)->vendorObj)->anim.dll + 0x38))(
                    ((ShopkeeperState*)state)->vendorObj, slot);
                ((ShopkeeperState*)state)->unk9CE = (s16)(
                    *(int (**)(int, int))((char*)*((GameObject*)((ShopkeeperState*)state)->vendorObj)->anim.dll + 0x30))(
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
        if ((*(int (**)(int))((char*)*((GameObject*)((ShopkeeperState*)state)->vendorObj)->anim.dll + 0x44))(
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
            ((ShopkeeperState*)state)->flags9D4 |= SHOPKEEPER_FLAG_PURCHASED;
            break;
        case 2:
            (*gPlayerInterface)->setState((void*)obj, (void*)state2, 3);
            (*gBoneParticleEffectInterface)->spawnEffect((void*)obj, 0x7EF, &range, 0x50, NULL);
            ((ShopkeeperState*)state)->opacity = 0;
            break;
        case 3:
            (*gPlayerInterface)->setState((void*)obj, (void*)state2, 2);
            ((ShopkeeperState*)state)->flags9D4 |= SHOPKEEPER_FLAG_TICK;
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
        diff = getAngle(dx, dz) & 0xffff;
        if (mode != 0)
        {
            *obj = diff;
        }
        else
        {
            diff = diff - (u16)*obj;
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
            *obj = (s16)((f32)(diff >> 3) * timeDelta + (f32) * (s16*)obj);
        }
    }
    return dist;
}
