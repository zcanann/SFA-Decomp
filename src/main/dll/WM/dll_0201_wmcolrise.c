/*
 * wmcolrise (DLL 0x0201) - the rising column platform at Krazoa Palace.
 * TU: 0x801F2E80-0x801F30DC (WM_colrise_* only).
 *
 * While its game bit allows and something stands on a column higher
 * than 3.0 above it (the rider registry the shared platform
 * helpers maintain), the column rises 0.25/tick toward
 * placement height + 120 and plays its rumble; otherwise it sinks
 * 0.125/tick back to placement height.
 */
#include "main/audio/sfx_ids.h"
#include "main/obj_placement.h"
#include "main/game_object.h"
#include "main/dll/ARW/ARWarwingattachment.h"
#include "main/audio/sfx.h"

typedef struct WMColrisePlacement
{
    ObjPlacement base; /* base.posY = the column's rest height */
    s8 rotXByte;       /* 0x18: rotX in 1/256 turns */
    u8 pad19[5];
    s16 gameBit;       /* 0x1E: rise-allowed gate, -1 = always */
} WMColrisePlacement;

STATIC_ASSERT(offsetof(WMColrisePlacement, gameBit) == 0x1E);

typedef struct WMColriseState
{
    s16 gameBit;
    u8 raiseTimer;
    u8 pad3;
} WMColriseState;

int WM_colrise_SeqFn(int obj, int unused, ObjAnimUpdateState* animUpdate)
{
    animUpdate->hitVolumePair = -1;
    animUpdate->sequenceEventActive = 0;
    return 0;
}

int WM_colrise_getExtraSize(void) { return sizeof(WMColriseState); }
int WM_colrise_getObjectTypeId(void) { return 0x0; }

void WM_colrise_free(void)
{
}

extern void objRenderFn_8003b8f4(f32);
extern f32 lbl_803E5DC8; /* 1.0: render scale */

void WM_colrise_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0) objRenderFn_8003b8f4(lbl_803E5DC8);
}

void WM_colrise_hitDetect(void)
{
}



extern f32 timeDelta;
extern const f32 lbl_803E5DCC; /* 3.0: rider height to trigger the rise */
extern f32 lbl_803E5DD0; /* 20.0 */
extern f32 lbl_803E5DD4; /* 100.0: raised height above placement */
extern f32 lbl_803E5DD8; /* 0.5: settle speed when overshot */
extern f32 lbl_803E5DDC; /* 0.25: rise speed */
extern f32 lbl_803E5DE0; /* 0.125: sink speed */

/* the rider registry hanging off anim+0x58 (engine field not yet
   named in ObjAnimComponent): the shared platform helpers push the
   objects standing on this one into riders[]. */
typedef struct ObjRiderRegistry
{
    u8 pad000[0x100];
    int riders[3]; /* 0x100 */
    u8 pad10C[3];
    s8 riderCount; /* 0x10F */
} ObjRiderRegistry;

STATIC_ASSERT(offsetof(ObjRiderRegistry, riderCount) == 0x10F);

#define OBJ_RIDER_REGISTRY(o) (*(ObjRiderRegistry**)((char*)(o) + 0x58))

void WM_colrise_update(int* obj)
{
    u8* def;
    WMColriseState* sub;
    s32 reached;
    f32 target;
    int i;

    def = *(u8**)&((GameObject*)obj)->anim.placementData;
    sub = ((GameObject*)obj)->extra;
    sub->raiseTimer -= 1;
    if ((s8)sub->raiseTimer < 0) sub->raiseTimer = 0;
    /* rearm the 60-frame rise window while any rider sits more than
       3.0 above the column */
    if ((s8)OBJ_RIDER_REGISTRY(obj)->riderCount > 0)
    {
        for (i = 0; i < OBJ_RIDER_REGISTRY(obj)->riderCount; i++)
        {
            GameObject* rider = (GameObject*)OBJ_RIDER_REGISTRY(obj)->riders[i];
            if (rider->anim.localPosY - ((GameObject*)obj)->anim.localPosY > lbl_803E5DCC)
            {
                sub->raiseTimer = 0x3c;
            }
        }
    }
    reached = 0;
    if ((sub->gameBit == -1 || (u32)GameBit_Get(sub->gameBit) != 0) && (s8)sub->raiseTimer != 0)
    {
        target = lbl_803E5DD0 + (lbl_803E5DD4 + ((WMColrisePlacement*)def)->base.posY);
        if (((GameObject*)obj)->anim.localPosY > target)
        {
            ((GameObject*)obj)->anim.localPosY = ((GameObject*)obj)->anim.localPosY - lbl_803E5DD8 * timeDelta;
            if (((GameObject*)obj)->anim.localPosY > target)
            {
                ((GameObject*)obj)->anim.localPosY = target;
            }
        }
        else
        {
            ((GameObject*)obj)->anim.localPosY = lbl_803E5DDC * timeDelta + ((GameObject*)obj)->anim.localPosY;
            if (((GameObject*)obj)->anim.localPosY > target)
            {
                ((GameObject*)obj)->anim.localPosY = target;
            }
            else
            {
                reached = 1;
            }
        }
    }
    else
    {
        ((GameObject*)obj)->anim.localPosY = ((GameObject*)obj)->anim.localPosY - lbl_803E5DE0 * timeDelta;
        if (((GameObject*)obj)->anim.localPosY < ((WMColrisePlacement*)def)->base.posY)
        {
            ((GameObject*)obj)->anim.localPosY = ((WMColrisePlacement*)def)->base.posY;
        }
        else
        {
            reached = 1;
        }
    }
    if ((s8)reached != 0)
    {
        Sfx_PlayFromObject((int)obj, SFXmn_crusty9c);
    }
    else
    {
        Sfx_StopObjectChannel((int)obj, 8);
    }
}

void WM_colrise_init(s16* obj, s8* def)
{
    WMColriseState* state = ((GameObject*)obj)->extra;
    ((GameObject*)obj)->animEventCallback = WM_colrise_SeqFn;
    obj[0] = (s16)((s32)((WMColrisePlacement*)def)->rotXByte << 8);
    state->gameBit = ((WMColrisePlacement*)def)->gameBit;
}

void WM_colrise_release(void)
{
}

void WM_colrise_initialise(void)
{
}
