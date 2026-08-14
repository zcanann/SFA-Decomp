/*
 * DLL 644 - a purchasable item displayed at a shopkeeper's
 * stall. Each instance finds its nearest vendor object (ObjGroup kind 9)
 * and drives buying through the vendor's vtable: query availability/price
 * (slots 0x28/0x2C/0x38/0x3C) and commit a purchase (slot 0x40) when the
 * player presses A with enough money. The behaviour branches on the
 * object's romDefNo variant:
 *   0x462  spawns an ambient particle fx on init
 *   0x464  static item (no spline advance)
 *   0x467  item that rides a B-spline path (Curve_EvalBSpline) with a
 *          trailing particle stream
 *   0x468  sparkle/lightning item with a custom post-render pass
 *          (shopitem_renderSparkle) and FUEL_CELL_OBJECT_GROUP membership
 * Help text and the A-button buy prompt are raised from the per-frame
 * resetHitboxMode interaction bits.
 */
#include "main/dll/partfx_interface.h"
#include "dlls/objects/291_fuelCell.h"
#include "main/frame_timing.h"
#include "main/object_render.h"
#include "sys/objects.h"
#include "main/objfx.h"
#include "main/dll/player_api.h"
#include "main/curve_eval.h"
#include "main/objseq.h"
#include "main/objtype.h"
#include "main/dll/dll_0284_shopitem.h"
#include "main/dll/dll_020B_firefly.h"
#include "main/dll/SP/dll_0285_spshop.h"
#include "main/dll/tricky_api.h"
#include "main/dll/dll_0000_gameui_api.h"
#include "main/gameloop_api.h"
#include "main/newclouds.h"
#include "main/model.h"
#include "main/pad.h"
#include "dlls/object_descriptor.h"
#include "dolphin/gx/GXPixel.h"
#include "dolphin/gx/GXTev.h"
#include "dolphin/pad.h"
#include "main/vecmath.h"
#include "main/obj_message.h"
#include "main/objprint_render_api.h"
#include "track/intersect_depth_state_api.h"
#include "main/hud_visibility_api.h"

#define SHOPITEM_TARGET_OBJGROUP 9

/* anim.romDefNo variants selecting per-item behaviour (see file header) */
#define SHOPITEM_MSG_IN_RANGE 0x7000a /* sent to player when purchase is offered */
#define SHOPITEM_SEQ_AMBIENT  0x462   /* spawns an ambient particle fx on init */
#define SHOPITEM_SEQ_STATIC   0x464   /* static item, no spline advance */
#define SHOPITEM_SEQ_BSPLINE  0x467   /* rides a B-spline path with trailing particles */
#define SHOPITEM_SEQ_SPARKLE  0x468   /* sparkle/lightning item with custom post-render pass */

/* ambient particle spawned on init for the SHOPITEM_SEQ_AMBIENT item */
#define SHOPITEM_PARTFX_AMBIENT 0x3F1

typedef struct ShopSparkleSpawn
{
    f32 x;
    f32 y;
    f32 z;
    int owner;
    u8 pad[0x28]; /* opaque scratch passed by address to lightningCreate */
} ShopSparkleSpawn;

/* Per-instance placement descriptor (anim.placementData / shopitem_init's
 * data arg): item slot index queried against the vendor vtable, model bank
 * index, packed rotation bytes, and the spline Y offset for the 0x467 path. */
typedef struct ShopItemDef
{
    u8 pad0[0xC];
    f32 splineYOffset;
    u8 padC[0x18 - 0x10];
    s8 bankIndex;
    u8 itemSlot;
    u8 rotXByte;
    u8 rotYByte;
} ShopItemDef;

STATIC_ASSERT(offsetof(ShopItemDef, splineYOffset) == 0xC);
STATIC_ASSERT(offsetof(ShopItemDef, bankIndex) == 0x18);
STATIC_ASSERT(offsetof(ShopItemDef, itemSlot) == 0x19);
STATIC_ASSERT(offsetof(ShopItemDef, rotXByte) == 0x1A);
STATIC_ASSERT(offsetof(ShopItemDef, rotYByte) == 0x1B);

STATIC_ASSERT(sizeof(ShopItemState) == 0xEC);

STATIC_ASSERT(sizeof(ShopkeeperState) == 0x9D8);
STATIC_ASSERT(offsetof(ShopkeeperState, msgStack) == 0x9B0);

void shopitem_sparkleBlendSetup(GameObject* obj);
void shopitem_renderSparkle(GameObject* obj, int p2, int p3, int p4, int p5);
int shopitem_SeqFn(GameObject* obj, int unused, ObjSeqState* seq);
int shopitem_getExtraSize(void);
int shopitem_getObjectTypeId(void);
void shopitem_free(GameObject* obj);
void shopitem_render(GameObject* obj, int p2, int p3, int p4, int p5, s8 visible);
void shopitem_hitDetect(void);
void shopitem_update(GameObject* obj);
void shopitem_init(GameObject* obj, ShopItemDef* data);
void shopitem_release(void);
void shopitem_initialise(void);

void shopitem_sparkleBlendSetup(GameObject* obj)
{
    if (obj->anim.renderAlpha == 0xFF)
    {
        GXSetBlendMode(GX_BM_NONE, GX_BL_ONE, GX_BL_ZERO, GX_LO_NOOP);
    }
    else
    {
        GXSetBlendMode(GX_BM_BLEND, GX_BL_SRCALPHA, GX_BL_ONE, GX_LO_NOOP);
    }
    gxSetZMode_(1, GX_LEQUAL, 0);
    gxSetPeControl_ZCompLoc_(1);
    GXSetAlphaCompare(GX_ALWAYS, 0, GX_AOP_AND, GX_ALWAYS, 0);
}

void shopitem_renderSparkle(GameObject* obj, int p2, int p3, int p4, int p5)
{
    ShopItemState* state = *(ShopItemState**)&obj->extra;
    u8 i;
    u8 spawned = 0;
    ShopSparkleSpawn v;
    f32 scale;

    if (state->flagsE8.flag_40)
    {
        objfx_spawnDirectionalBurst(obj, 5, 1.0f, 1, 1, 0x14, 3.5f, NULL, 0);
    }
    else
    {
        objfx_spawnDirectionalBurst(obj, 5, 1.0f, 1, 1, 0x14, 4.5f, NULL, 0);
    }
    {
        Shader* renderOp = ObjModel_GetRenderOp(Obj_GetActiveModel(obj)->file, 0);
        renderOp->alphaOverride = 0x7F;
    }
    objRenderModelAndHitVolumes(obj, p2, p3, p4, p5, 1.0f);
    for (i = 0; i < 10; i++)
    {
        if (state->lightningHandles[i] != NULL)
        {
            lightningRender(state->lightningHandles[i]);
            if (getHudHiddenFrameCount() == 0)
            {
                state->lightningTimers[i] += timeDelta;
                state->lightningHandles[i]->timer = (u16)(int)(0.5f + state->lightningTimers[i]);
                if (state->lightningHandles[i]->timer > 0x14)
                {
                    mm_free_(state->lightningHandles[i]);
                    state->lightningHandles[i] = NULL;
                }
            }
        }
        else
        {
            if (spawned == 0 && getHudHiddenFrameCount() == 0)
            {
                v.owner = (int)obj;
                v.x = obj->anim.localPosX;
                v.y = obj->anim.localPosY;
                v.z = obj->anim.localPosZ;
                if ((u32)v.owner == (u32)obj)
                {
                    if (state->flagsE8.flag_40)
                    {
                        scale = 0.0017f;
                    }
                    else
                    {
                        scale = 0.003f;
                    }
                    v.x = scale * (f32)(int)(randomGetRange(0, 2000) - 1000) + v.x;
                    v.y = scale * (f32)(int)(randomGetRange(0, 2000) - 1000) + v.y;
                    v.z = scale * (f32)(int)(randomGetRange(0, 2000) - 1000) + v.z;
                }
                state->lightningHandles[i] =
                    lightningCreate((const Vec3f*)&obj->anim.localPosX, (const Vec3f*)&v, 4.0f, 0.2f,
                                            0x14, 0x40, 0);
                state->lightningTimers[i] = 0.0f;
                spawned = 1;
            }
        }
    }
}

void shopitem_onSeqFree(GameObject* obj)
{
    ShopItemState* state = obj->extra;
    ShopItemDef* def = (ShopItemDef*)obj->anim.placementData;
    PushcartState97* b = &state->flags97;
    if (b->flag_40 == 0)
    {
        GameObject* vptr = (GameObject*)state->vendorObj;
        ShopInterface* cls = SHOP_INTERFACE(vptr);
        if (cls->isItemBought(vptr, def->itemSlot) != 0)
        {
            b->flag_80 = 1;
        }
    }
    setHudForceShowMask(0);
    {
        GameObject* vptr2 = (GameObject*)state->vendorObj;
        ShopInterface* cls2 = SHOP_INTERFACE(vptr2);
        cls2->setItemIndex(vptr2, -1);
    }
}

int shopitem_SeqFn(GameObject* obj, int unused, ObjSeqState* seq)
{
    int sub = (int)obj->extra;
    ObjAnimComponent* objAnim = &obj->anim;
    ShopItemState* s = (ShopItemState*)sub;

    seq->freeCallback = (ObjAnimSequenceFreeCallback)shopitem_onSeqFree;
    seq->flags &= ~4;
    seq->savedFlags &= ~4;

    if ((int)objAnim->banks[objAnim->bankIndex] != 0)
    {
        ObjAnim_AdvanceCurrentMove(obj, 0.005f, timeDelta, NULL);
    }

    switch ((obj)->anim.romDefNo)
    {
    case SHOPITEM_SEQ_BSPLINE:
    {
        f32 splineT = s->splineT;
        if (splineT > 1.0f)
        {
            u32 segCounter;
            s->splineT = splineT - 1.0f;
            segCounter = s->segCounter;
            if (segCounter >= 4)
            {
                s->segCounter += 1;
            }
            else
            {
                firefly_pickWanderTarget(obj, (FireFlyState*)sub);
            }
            firefly_shiftPathHistory(obj, (FireFlyState*)sub);
        }
    }
        {
            (obj)->anim.localPosX =
                Curve_EvalBSpline(s->controlX, s->splineT, 0);
            (obj)->anim.localPosY =
                Curve_EvalBSpline(s->controlY, s->splineT, 0);
            (obj)->anim.localPosZ =
                Curve_EvalBSpline(s->controlZ, s->splineT, 0);
            s->splineT =
                s->splineSpeed * timeDelta + s->splineT;
            (obj)->anim.rotX = getAngle((obj)->anim.localPosX - (obj)->anim.previousLocalPosX,
                                        (obj)->anim.localPosZ - (obj)->anim.previousLocalPosZ);
            (*gPartfxInterface)->spawnObject((void*)obj, 415, NULL, 1, -1, NULL);
            (*gPartfxInterface)->spawnObject((void*)obj, 416, NULL, 1, -1, NULL);
        }
        break;
    }
    return 0;
}

int shopitem_getExtraSize(void)
{
    return sizeof(ShopItemState);
}
int shopitem_getObjectTypeId(void)
{
    return 0x0;
}

void shopitem_free(GameObject* obj)
{
    (*gExpgfxInterface)->freeSource((int)obj);
    switch ((obj)->anim.romDefNo)
    {
    case SHOPITEM_SEQ_SPARKLE:
        objFreeObjectType(obj, FUEL_CELL_OBJECT_GROUP);
        break;
    }
}

void shopitem_render(GameObject* obj, int p2, int p3, int p4, int p5, s8 visible)
{
    if (visible != 0)
    {
        if ((obj)->anim.romDefNo == SHOPITEM_SEQ_SPARKLE)
        {
            shopitem_renderSparkle(obj, 0, 0, 0, 0);
        }
        else
        {
            objRenderModelAndHitVolumes(obj, p2, p3, p4, p5, 1.0f);
        }
    }
}

void shopitem_hitDetect(void)
{
}

void shopitem_update(GameObject* obj)
{
    ShopItemDef* def = (ShopItemDef*)(obj)->anim.placementData;
    void* player = Obj_GetPlayerObject();
    int state = (int)obj->extra;
    f32 range = 10000.0f;
    ShopItemState* s = (ShopItemState*)state;
    int money;
    int price;

    if (s->flags97.flag_40)
    {
        (obj)->anim.flags = (s16)((obj)->anim.flags | OBJANIM_FLAG_HIDDEN);
        (obj)->objectFlags = (u16)((obj)->objectFlags | OBJECT_OBJFLAG_UPDATE_DISABLED);
        (obj)->anim.resetHitboxFlags |= INTERACT_FLAG_DISABLED;
    }
    else if (s->flags97.flag_80)
    {
        s->msgParam = -1;
        ObjMsg_SendToObject(Obj_GetPlayerObject(), SHOPITEM_MSG_IN_RANGE, obj, state + 0x88);
        s->flags97.flag_80 = 0;
        s->flags97.flag_40 = 1;
    }
    else
    {
        if (*(u32*)&s->vendorObj == 0)
        {
            int item;
            s->vendorObj = (int)objGetNearestTypeTo(SHOPITEM_TARGET_OBJGROUP, obj, &range);
            item = s->vendorObj;
            if ((u32)item != 0)
            {
                if (SHOP_INTERFACE(item)->isItemAvailable((GameObject*)item,
                                                          def->itemSlot) == 0 ||
                    SHOP_INTERFACE(s->vendorObj)
                            ->isItemBought((GameObject*)s->vendorObj, def->itemSlot) != 0)
                {
                    s->flags97.flag_40 = 1;
                    (obj)->anim.flags = (s16)((obj)->anim.flags | OBJANIM_FLAG_HIDDEN);
                    (obj)->objectFlags = (u16)((obj)->objectFlags | OBJECT_OBJFLAG_UPDATE_DISABLED);
                    (obj)->anim.resetHitboxFlags |= INTERACT_FLAG_DISABLED;
                }
                s->helpTextId = (s16)SHOP_INTERFACE(s->vendorObj)
                                    ->getItemTextId((GameObject*)s->vendorObj, def->itemSlot);
            }
        }
        else
        {
            if ((obj)->anim.resetHitboxFlags & INTERACT_FLAG_IN_RANGE)
            {
                forceAButtonIcon(0x12);
                showHelpText(s->helpTextId);
            }
            if ((obj)->anim.resetHitboxFlags & INTERACT_FLAG_ACTIVATED)
            {
                money = playerGetMoney(player);
                price = SHOP_INTERFACE(s->vendorObj)
                            ->getItemPrice((GameObject*)s->vendorObj, def->itemSlot);
                SHOP_INTERFACE(s->vendorObj)
                    ->setItemIndex((GameObject*)s->vendorObj, def->itemSlot);
                switch ((obj)->anim.romDefNo)
                {
                case SHOPITEM_SEQ_BSPLINE:
                    (obj)->anim.localPosY =
                        20.0f + ((ShopItemDef*)(obj)->anim.placementData)->splineYOffset;
                    break;
                }
                if (money >= price)
                {
                    setHudForceShowMask(3);
                    (*gObjectTriggerInterface)->runSequence(0, (void*)obj, -1);
                }
                else
                {
                    (*gObjectTriggerInterface)->runSequence(1, (void*)obj, -1);
                }
                buttonDisable(0, PAD_BUTTON_A);
            }
            switch ((obj)->anim.romDefNo)
            {
            case SHOPITEM_SEQ_BSPLINE:
            {
                f32 splineT = s->splineT;
                if (splineT > 1.0f)
                {
                    u32 segCounter;
                    s->splineT = splineT - 1.0f;
                    segCounter = s->segCounter;
                    if (segCounter >= 4)
                    {
                        s->segCounter++;
                    }
                    else
                    {
                        firefly_pickWanderTarget(obj, (FireFlyState*)state);
                    }
                    firefly_shiftPathHistory(obj, (FireFlyState*)state);
                }
                (obj)->anim.localPosX =
                    Curve_EvalBSpline(s->controlX, s->splineT, 0);
                (obj)->anim.localPosY =
                    Curve_EvalBSpline(s->controlY, s->splineT, 0);
                (obj)->anim.localPosZ =
                    Curve_EvalBSpline(s->controlZ, s->splineT, 0);
                s->splineT =
                    s->splineSpeed * timeDelta + s->splineT;
                (obj)->anim.rotX = getAngle((obj)->anim.localPosX - (obj)->anim.previousLocalPosX,
                                            (obj)->anim.localPosZ - (obj)->anim.previousLocalPosZ);
                (*gPartfxInterface)->spawnObject((void*)obj, 0x19F, NULL, 1, -1, NULL);
                (*gPartfxInterface)->spawnObject((void*)obj, 0x1A0, NULL, 1, -1, NULL);
                break;
            }
            }
        }
        if ((obj)->anim.romDefNo != SHOPITEM_SEQ_STATIC && (obj)->anim.romDefNo != SHOPITEM_SEQ_BSPLINE)
        {
            ObjAnim_AdvanceCurrentMove(obj, 0.005f, timeDelta, NULL);
        }
        if (((obj)->anim.resetHitboxFlags & INTERACT_FLAG_DISABLED) == 0)
        {
            objUpdateHitVolumeTransforms(obj);
        }
    }
}

void shopitem_init(GameObject* obj, ShopItemDef* data)
{
    ObjAnimComponent* objAnim;
    int state = (int)obj->extra;
    ShopItemState* s = (ShopItemState*)state;

    objAnim = &obj->anim;
    (obj)->objectFlags |= OBJECT_OBJFLAG_HITDETECT_DISABLED;
    (obj)->animEventCallback = shopitem_SeqFn;
    objAnim->bankIndex = (s8)data->bankIndex;
    (obj)->anim.rotX = (s16)(data->rotXByte << 8);
    (obj)->anim.rotY = (s16)(data->rotYByte << 8);
    if ((s32)objAnim->bankIndex >= objAnim->modelInstance->modelCount)
    {
        objAnim->bankIndex = 0;
    }
    switch ((obj)->anim.romDefNo)
    {
    case SHOPITEM_SEQ_BSPLINE:
        firefly_initFlightRec(obj, (FireFlyState*)state);
        break;
    case SHOPITEM_SEQ_AMBIENT:
        (*gPartfxInterface)->spawnObject((void*)obj, SHOPITEM_PARTFX_AMBIENT, NULL, 4, -1, NULL);
        break;
    case SHOPITEM_SEQ_SPARKLE:
        ObjModel_SetPostRenderCallback(Obj_GetActiveModel(obj), shopitem_sparkleBlendSetup);
        objAddObjectType(obj, FUEL_CELL_OBJECT_GROUP);
        break;
    }
}

void shopitem_release(void)
{
}

void shopitem_initialise(void)
{
}

ObjectDescriptor gShopItemObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)shopitem_initialise,
    (ObjectDescriptorCallback)shopitem_release,
    0,
    (ObjectDescriptorCallback)shopitem_init,
    (ObjectDescriptorCallback)shopitem_update,
    (ObjectDescriptorCallback)shopitem_hitDetect,
    (ObjectDescriptorCallback)shopitem_render,
    (ObjectDescriptorCallback)shopitem_free,
    (ObjectDescriptorCallback)shopitem_getObjectTypeId,
    (ObjectDescriptorExtraSizeCallback)shopitem_getExtraSize,
};
