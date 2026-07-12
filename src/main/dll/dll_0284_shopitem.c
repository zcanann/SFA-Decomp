/*
 * shopitem (DLL 0x284) - a purchasable item displayed at a shopkeeper's
 * stall. Each instance finds its nearest vendor object (ObjGroup kind 9)
 * and drives buying through the vendor's vtable: query availability/price
 * (slots 0x28/0x2C/0x38/0x3C) and commit a purchase (slot 0x40) when the
 * player presses A with enough money. The behaviour branches on the
 * object's seqId variant:
 *   0x462  spawns an ambient particle fx on init
 *   0x464  static item (no spline advance)
 *   0x467  item that rides a B-spline path (Curve_EvalBSpline) with a
 *          trailing particle stream
 *   0x468  sparkle/lightning item with a custom post-render pass
 *          (fn_801E83B0) and ObjGroup membership 0x4F
 * Help text and the A-button buy prompt are raised from the per-frame
 * resetHitboxMode interaction bits.
 */
#include "main/dll_000A_expgfx.h"
#include "main/vecmath.h"
#include "main/dll/shopkeeperstate_struct.h"
#include "main/dll/pushcartstate97_types.h"
#include "main/game_object.h"
#include "main/object_api.h"
#include "main/objfx.h"
#include "main/dll/player_api.h"
#include "main/curve_eval.h"
#include "main/objseq.h"
#include "main/dll/dll_0284_shopitem.h"
#include "main/dll/tricky.h"
#include "main/gameloop_api.h"
#include "main/newclouds.h"
#include "main/model.h"
#include "main/pad.h"

#define SHOPITEM_OBJGROUP        0x4F
#define SHOPITEM_TARGET_OBJGROUP 9

#define SHOPITEM_OBJFLAG_HITDETECT_DISABLED 0x2000
#define SHOPITEM_OBJFLAG_UPDATE_DISABLED    0x8000
#define PAD_BUTTON_A                        0x100

/* anim.seqId variants selecting per-item behaviour (see file header) */
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

extern u64 ObjGroup_RemoveObject();
extern void objRenderModelAndHitVolumes(int obj, int p2, int p3, int p4, int p5, f32 scale);
extern void fn_801E83B0(int obj, int, int, int, int);
extern void GXSetBlendMode(int type, int src, int dst, int op);
extern void gxSetZMode_(u32 compareEnable, int compareFunc, u32 updateEnable);
extern void gxSetPeControl_ZCompLoc_(u32 zCompLoc);
extern void GXSetAlphaCompare(int comp0, u8 ref0, int op, int comp1, u8 ref1);

#define GX_BM_NONE     0
#define GX_BM_BLEND    1
#define GX_BL_ZERO     0
#define GX_BL_ONE      1
#define GX_BL_SRCALPHA 4
#define GX_LO_NOOP     5
#define GX_LEQUAL      3
#define GX_ALWAYS      7
#define GX_AOP_AND     0

extern f32 timeDelta;
extern int ObjGroup_FindNearestObject(int group, u32 obj, float* maxDistance);
extern void ObjGroup_AddObject(u32 obj, int group);
extern void fn_801F4C28(int, int);
extern void ObjMsg_SendToObject(void* to, int msg, int obj, void* data);
extern void forceAButtonIcon(int icon);

extern void objRenderFn_80041018(int obj);
extern void fn_801F4D54(int obj, int sub);
extern void fn_801F4ECC(int obj, int sub);

/* .sdata2 constant pool */
static const f32 lbl_803E5A30 = 1.0f;
static const f32 lbl_803E5A34 = 3.5f;
static const f32 lbl_803E5A38 = 4.5f;
static const f32 lbl_803E5A3C = 0.5f;
static const f32 lbl_803E5A40 = 0.0017f;
static const f32 lbl_803E5A44 = 0.003f;
static const f32 lbl_803E5A48 = 4.0f;
static const f32 lbl_803E5A4C = 0.2f;
static const f32 lbl_803E5A50 = 0.0f;
static const f64 lbl_803E5A58 = 4503601774854144.0;
static const f32 lbl_803E5A60 = 0.005f;
static const f32 lbl_803E5A64 = 10000.0f;
static const f32 lbl_803E5A68 = 20.0f;

void fn_801E832C(int obj)
{
    if (*(u8*)(obj + 0x37) == 0xFF)
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

void fn_801E83B0(int obj, int p2, int p3, int p4, int p5)
{
    ShopItemState* state = *(ShopItemState**)&((GameObject*)obj)->extra;
    u8 i;
    u8 spawned = 0;
    ShopSparkleSpawn v;
    PushcartState97* b = (PushcartState97*)&state->flagsE8;
    f32 scale;

    if (b->flag_40)
    {
        objfx_spawnDirectionalBurstLegacy(obj, 5, lbl_803E5A30, 1, 1, 0x14, lbl_803E5A34, 0, 0);
    }
    else
    {
        objfx_spawnDirectionalBurstLegacy(obj, 5, lbl_803E5A30, 1, 1, 0x14, lbl_803E5A38, 0, 0);
    }
    {
        ModelRenderOp* renderOp = ObjModel_GetRenderOp(Obj_GetActiveModel((GameObject*)obj)->file, 0);
        renderOp->alphaOverride = 0x7F;
    }
    ((void (*)(int, int, int, int, int, f32))objRenderModelAndHitVolumes)(obj, p2, p3, p4, p5, lbl_803E5A30);
    for (i = 0; i < 10; i++)
    {
        if (state->lightningHandles[i] != NULL)
        {
            lightningRender(state->lightningHandles[i]);
            if (getHudHiddenFrameCount() == 0)
            {
                state->lightningTimers[i] += timeDelta;
                state->lightningHandles[i]->timer = (u16)(int)(lbl_803E5A3C + state->lightningTimers[i]);
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
                v.owner = obj;
                v.x = ((GameObject*)obj)->anim.localPosX;
                v.y = ((GameObject*)obj)->anim.localPosY;
                v.z = ((GameObject*)obj)->anim.localPosZ;
                if ((u32)v.owner == obj)
                {
                    if (b->flag_40)
                    {
                        scale = lbl_803E5A40;
                    }
                    else
                    {
                        scale = lbl_803E5A44;
                    }
                    v.x = scale * (f32)(int)(randomGetRange(0, 2000) - 1000) + v.x;
                    v.y = scale * (f32)(int)(randomGetRange(0, 2000) - 1000) + v.y;
                    v.z = scale * (f32)(int)(randomGetRange(0, 2000) - 1000) + v.z;
                }
                state->lightningHandles[i] =
                    lightningCreatePromoted((const Vec3f*)(obj + 0xC), (const Vec3f*)&v, lbl_803E5A48, lbl_803E5A4C,
                                            0x14, 0x40, 0);
                state->lightningTimers[i] = lbl_803E5A50;
                spawned = 1;
            }
        }
    }
}

void shopitem_onSeqFree(GameObject* obj)
{
    int state = *(int*)&obj->extra;
    int def = *(int*)&obj->anim.placementData;
    PushcartState97* b = (PushcartState97*)(state + 0x97);
    if (b->flag_40 == 0)
    {
        int* vptr = (int*)((ShopItemState*)state)->vendorObj;
        int* cls = **(int***)((char*)vptr + 0x68);
        if ((*(int (*)(int*, int))cls[0x2C / 4])(vptr, ((ShopItemDef*)def)->itemSlot) != 0)
        {
            b->flag_80 = 1;
        }
    }
    hudFn_8011f38c(0);
    {
        int* vptr2 = (int*)((ShopItemState*)state)->vendorObj;
        int* cls2 = **(int***)((char*)vptr2 + 0x68);
        (*(void (*)(int*, int))cls2[0x40 / 4])(vptr2, -1);
    }
}

int shopitem_SeqFn(GameObject* obj, int unused, ObjSeqState* seq)
{
    int sub = *(int*)&(obj)->extra;
    ObjAnimComponent* objAnim = (ObjAnimComponent*)obj;

    seq->freeCallback = (ObjAnimSequenceFreeCallback)shopitem_onSeqFree;
    seq->flags &= ~4;
    seq->savedFlags &= ~4;

    if ((int)objAnim->banks[objAnim->bankIndex] != 0)
    {
        ObjAnim_AdvanceCurrentMove((int)obj, lbl_803E5A60, timeDelta, NULL);
    }

    switch ((obj)->anim.seqId)
    {
    case SHOPITEM_SEQ_BSPLINE:
    {
        f32 t = ((ShopItemState*)sub)->splineT;
        if (t > lbl_803E5A30)
        {
            u32 segCounter;
            ((ShopItemState*)sub)->splineT = t - lbl_803E5A30;
            segCounter = ((ShopItemState*)sub)->segCounter;
            if (segCounter >= 4)
            {
                ((ShopItemState*)sub)->segCounter += 1;
            }
            else
            {
                fn_801F4D54((int)obj, sub);
            }
            fn_801F4ECC((int)obj, sub);
        }
    }
        {
            (obj)->anim.localPosX = Curve_EvalBSplineValuesFirst(sub + 4, ((ShopItemState*)sub)->splineT, 0);
            (obj)->anim.localPosY = Curve_EvalBSplineValuesFirst(sub + 0x14, ((ShopItemState*)sub)->splineT, 0);
            (obj)->anim.localPosZ = Curve_EvalBSplineValuesFirst(sub + 0x24, ((ShopItemState*)sub)->splineT, 0);
            ((ShopItemState*)sub)->splineT =
                ((ShopItemState*)sub)->splineSpeed * timeDelta + ((ShopItemState*)sub)->splineT;
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
    switch ((obj)->anim.seqId)
    {
    case SHOPITEM_SEQ_SPARKLE:
        ObjGroup_RemoveObject(obj, SHOPITEM_OBJGROUP);
        break;
    }
}

void shopitem_render(GameObject* obj, int p2, int p3, int p4, int p5, s8 visible)
{
    if (visible != 0)
    {
        if ((obj)->anim.seqId == SHOPITEM_SEQ_SPARKLE)
        {
            fn_801E83B0((int)obj, 0, 0, 0, 0);
        }
        else
        {
            objRenderModelAndHitVolumes((int)obj, p2, p3, p4, p5, lbl_803E5A30);
        }
    }
}

void shopitem_hitDetect(void)
{
}

void shopitem_update(GameObject* obj)
{
    int def = *(int*)&(obj)->anim.placementData;
    void* player = Obj_GetPlayerObject();
    int state = *(int*)&(obj)->extra;
    f32 range = lbl_803E5A64;
    PushcartState97* b = (PushcartState97*)(state + 0x97);
    int money;
    int price;

    if (b->flag_40)
    {
        (obj)->anim.flags = (s16)((obj)->anim.flags | OBJANIM_FLAG_HIDDEN);
        (obj)->objectFlags = (u16)((obj)->objectFlags | SHOPITEM_OBJFLAG_UPDATE_DISABLED);
        *(u8*)&(obj)->anim.resetHitboxMode |= INTERACT_FLAG_DISABLED;
    }
    else if (b->flag_80)
    {
        ((ShopItemState*)state)->msgParam = -1;
        ObjMsg_SendToObject(Obj_GetPlayerObject(), SHOPITEM_MSG_IN_RANGE, (int)obj, (void*)(state + 0x88));
        b->flag_80 = 0;
        b->flag_40 = 1;
    }
    else
    {
        if (*(u32*)&((ShopItemState*)state)->vendorObj == 0)
        {
            int item;
            ((ShopItemState*)state)->vendorObj = ObjGroup_FindNearestObject(SHOPITEM_TARGET_OBJGROUP, (int)obj, &range);
            item = ((ShopItemState*)state)->vendorObj;
            if ((u32)item != 0)
            {
                if ((*(int (**)(int, int))((char*)**(int***)(item + 0x68) + 0x28))(
                        item, ((ShopItemDef*)def)->itemSlot) == 0 ||
                    (*(int (**)(int, int))((char*)**(int***)(((ShopItemState*)state)->vendorObj + 0x68) + 0x2C))(
                        ((ShopItemState*)state)->vendorObj, ((ShopItemDef*)def)->itemSlot) != 0)
                {
                    b->flag_40 = 1;
                    (obj)->anim.flags = (s16)((obj)->anim.flags | OBJANIM_FLAG_HIDDEN);
                    (obj)->objectFlags = (u16)((obj)->objectFlags | SHOPITEM_OBJFLAG_UPDATE_DISABLED);
                    *(u8*)&(obj)->anim.resetHitboxMode |= INTERACT_FLAG_DISABLED;
                }
                ((ShopItemState*)state)->helpTextId =
                    (s16)(*(int (**)(int, int))((char*)**(int***)(((ShopItemState*)state)->vendorObj + 0x68) + 0x3C))(
                        ((ShopItemState*)state)->vendorObj, ((ShopItemDef*)def)->itemSlot);
            }
        }
        else
        {
            if (*(u8*)&(obj)->anim.resetHitboxMode & INTERACT_FLAG_IN_RANGE)
            {
                forceAButtonIcon(0x12);
                showHelpText(((ShopItemState*)state)->helpTextId);
            }
            if (*(u8*)&(obj)->anim.resetHitboxMode & INTERACT_FLAG_ACTIVATED)
            {
                money = playerGetMoney(player);
                price = (*(int (**)(int, int))((char*)**(int***)(((ShopItemState*)state)->vendorObj + 0x68) + 0x38))(
                    ((ShopItemState*)state)->vendorObj, ((ShopItemDef*)def)->itemSlot);
                (*(int (**)(int, int))((char*)**(int***)(((ShopItemState*)state)->vendorObj + 0x68) + 0x40))(
                    ((ShopItemState*)state)->vendorObj, ((ShopItemDef*)def)->itemSlot);
                switch ((obj)->anim.seqId)
                {
                case SHOPITEM_SEQ_BSPLINE:
                    (obj)->anim.localPosY =
                        lbl_803E5A68 + ((ShopItemDef*)*(int*)&(obj)->anim.placementData)->splineYOffset;
                    break;
                }
                if (money >= price)
                {
                    hudFn_8011f38c(3);
                    (*gObjectTriggerInterface)->runSequence(0, (void*)obj, -1);
                }
                else
                {
                    (*gObjectTriggerInterface)->runSequence(1, (void*)obj, -1);
                }
                buttonDisable(0, PAD_BUTTON_A);
            }
            switch ((obj)->anim.seqId)
            {
            case SHOPITEM_SEQ_BSPLINE:
            {
                f32 t = ((ShopItemState*)state)->splineT;
                if (t > lbl_803E5A30)
                {
                    u32 segCounter;
                    ((ShopItemState*)state)->splineT = t - lbl_803E5A30;
                    segCounter = ((ShopItemState*)state)->segCounter;
                    if (segCounter >= 4)
                    {
                        ((ShopItemState*)state)->segCounter++;
                    }
                    else
                    {
                        fn_801F4D54((int)obj, state);
                    }
                    fn_801F4ECC((int)obj, state);
                }
                (obj)->anim.localPosX = Curve_EvalBSplineValuesFirst(state + 4, ((ShopItemState*)state)->splineT, 0);
                (obj)->anim.localPosY = Curve_EvalBSplineValuesFirst(state + 0x14, ((ShopItemState*)state)->splineT, 0);
                (obj)->anim.localPosZ = Curve_EvalBSplineValuesFirst(state + 0x24, ((ShopItemState*)state)->splineT, 0);
                ((ShopItemState*)state)->splineT =
                    ((ShopItemState*)state)->splineSpeed * timeDelta + ((ShopItemState*)state)->splineT;
                (obj)->anim.rotX = getAngle((obj)->anim.localPosX - (obj)->anim.previousLocalPosX,
                                            (obj)->anim.localPosZ - (obj)->anim.previousLocalPosZ);
                (*gPartfxInterface)->spawnObject((void*)obj, 0x19F, NULL, 1, -1, NULL);
                (*gPartfxInterface)->spawnObject((void*)obj, 0x1A0, NULL, 1, -1, NULL);
                break;
            }
            }
        }
        if ((obj)->anim.seqId != SHOPITEM_SEQ_STATIC && (obj)->anim.seqId != SHOPITEM_SEQ_BSPLINE)
        {
            ObjAnim_AdvanceCurrentMove((int)obj, lbl_803E5A60, timeDelta, NULL);
        }
        if ((*(u8*)&(obj)->anim.resetHitboxMode & INTERACT_FLAG_DISABLED) == 0)
        {
            objRenderFn_80041018((int)obj);
        }
    }
}

void shopitem_init(GameObject* obj, int data)
{
    ObjAnimComponent* objAnim;
    int state = *(int*)&(obj)->extra;

    objAnim = (ObjAnimComponent*)obj;
    (obj)->objectFlags |= SHOPITEM_OBJFLAG_HITDETECT_DISABLED;
    (obj)->animEventCallback = shopitem_SeqFn;
    objAnim->bankIndex = (s8)((ShopItemDef*)data)->bankIndex;
    (obj)->anim.rotX = (s16)(((ShopItemDef*)data)->rotXByte << 8);
    (obj)->anim.rotY = (s16)(((ShopItemDef*)data)->rotYByte << 8);
    if ((s32)objAnim->bankIndex >= objAnim->modelInstance->modelCount)
    {
        objAnim->bankIndex = 0;
    }
    switch ((obj)->anim.seqId)
    {
    case SHOPITEM_SEQ_BSPLINE:
        fn_801F4C28((int)obj, state);
        break;
    case SHOPITEM_SEQ_AMBIENT:
        (*gPartfxInterface)->spawnObject((void*)obj, SHOPITEM_PARTFX_AMBIENT, NULL, 4, -1, NULL);
        break;
    case SHOPITEM_SEQ_SPARKLE:
        ObjModel_SetPostRenderCallback(Obj_GetActiveModel(obj), fn_801E832C);
        ObjGroup_AddObject((int)obj, SHOPITEM_OBJGROUP);
        break;
    }
}

void shopitem_release(void)
{
}

void shopitem_initialise(void)
{
}
