#include "main/obj_placement.h"
#include "main/game_object.h"
#include "main/audio/sfx_ids.h"
#include "main/effect_interfaces.h"
#include "main/mapEventTypes.h"
#include "main/objseq.h"
#include "main/dll/DB/DBstealerworm.h"
#include "main/dll/DB/sbgalleon_state.h"

/* SB_Propeller_getExtraSize == 0x10. */
typedef struct SBPropellerState
{
    f32 smokeTimer; /* 0x00: countdown to the next smoke burst */
    f32 spinBlend; /* 0x04 */
    int spinRate; /* 0x08: init 1200 */
    s8 health; /* 0x0c: init 4 */
    u8 pad0D[3];
} SBPropellerState;

STATIC_ASSERT(sizeof(SBPropellerState) == 0x10);

/* SB_ShipHead_getExtraSize == 0x10. */
typedef struct SBShipHeadState
{
    int target; /* 0x00: the 0x8c galleon-side object */
    s8 health; /* 0x04: init 4 */
    u8 pad05[3];
    f32 swayA; /* 0x08 */
    f32 swayB; /* 0x0c */
} SBShipHeadState;

STATIC_ASSERT(sizeof(SBShipHeadState) == 0x10);

extern undefined8 ObjGroup_RemoveObject();


/*
 * --INFO--
 *
 * Function: SB_Galleon_animEventCallback
 * EN v1.0 Address: 0x801E1AAC
 * EN v1.0 Size: 764b
 * EN v1.1 Address: 0x801E18DC
 * EN v1.1 Size: 668b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */


/*
 * --INFO--
 *
 * Function: fn_801E1588
 * EN v1.0 Address: 0x801E1588
 * EN v1.0 Size: 1316b
 * EN v1.1 Address: 0x801E1B78
 * EN v1.1 Size: 1316b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */




/*
 * --INFO--
 *
 * Function: SB_Propeller_update
 * EN v1.0 Address: 0x801E21B4
 * EN v1.0 Size: 1364b
 * EN v1.1 Address: 0x801E2BBC
 * EN v1.1 Size: 1212b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
extern u8 framesThisStep;


/*
 * --INFO--
 *
 * Function: SB_Propeller_init
 * EN v1.0 Address: 0x801E2708
 * EN v1.0 Size: 152b
 * EN v1.1 Address: 0x801E3078
 * EN v1.1 Size: 176b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */

/*
 * --INFO--
 *
 * Function: SB_ShipHead_render
 * EN v1.0 Address: 0x801E27C4
 * EN v1.0 Size: 380b
 * EN v1.1 Address: 0x801E314C
 * EN v1.1 Size: 392b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */

/*
 * --INFO--
 *
 * Function: SB_ShipHead_update
 * EN v1.0 Address: 0x801E2940
 * EN v1.0 Size: 1892b
 * EN v1.1 Address: 0x801E32D4
 * EN v1.1 Size: 1384b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */



/* Trivial 4b 0-arg blr leaves. */


void SB_ShipMast_free(void)
{
}

void SB_ShipMast_hitDetect(void)
{
}

void SB_ShipMast_init(void)
{
}

void SB_ShipMast_release(void)
{
}

void SB_ShipMast_initialise(void)
{
}

extern f32 lbl_803E586C;
extern f32 lbl_803E5870;
extern f32 lbl_803E5874;
extern f32 lbl_803E5878;

void SB_ShipMast_update(int* obj)
{
    extern u8 framesThisStep;
    int* parent;
    int pf4;
    f32 speed;

    parent = *(int**)&((GameObject*)obj)->anim.parent;
    if (parent == NULL) return;
    pf4 = ((GameObject*)parent)->unkF4;
    ((GameObject*)obj)->anim.localPosX = lbl_803E586C;
    ((GameObject*)obj)->anim.localPosY = lbl_803E586C;
    ((GameObject*)obj)->anim.localPosZ = lbl_803E586C;
    if (*(s16*)((char*)*(int**)&((GameObject*)obj)->anim.parent + 0x46) == 0x139)
    {
        if (pf4 >= 0xa && pf4 < 0xd)
        {
            if (((GameObject*)obj)->anim.currentMove != 0)
            {
                ObjAnim_SetCurrentMove((int)obj, 0, lbl_803E586C, 0);
            }
            if (pf4 >= 0xc)
            {
                speed = lbl_803E5870;
            }
            else
            {
                speed = lbl_803E5874;
            }
        }
        else
        {
            if (((GameObject*)obj)->anim.currentMove != 1)
            {
                ObjAnim_SetCurrentMove((int)obj, 1, lbl_803E586C, 0);
            }
            speed = lbl_803E5878;
        }
    }
    else
    {
        if (((GameObject*)obj)->anim.currentMove != 1)
        {
            ObjAnim_SetCurrentMove((int)obj, 1, lbl_803E586C, 0);
        }
        speed = lbl_803E5878;
    }
    ((ObjAnimAdvanceObjectFirstF32Fn)ObjAnim_AdvanceCurrentMove)((int)obj, speed, (f32)(u32)framesThisStep, NULL);
}

/* 8b "li r3, N; blr" returners. */
int SB_Galleon_getExtraSize(void);
int SB_ShipMast_getExtraSize(void) { return 0x0; }
int SB_ShipMast_getObjectTypeId(void) { return 0x0; }
int SB_ShipGun_getExtraSize(void);

/* sda21 accessors. */

/* Pattern wrappers. */

/* 16b chained patterns. */

/* render-with-objRenderFn_8003b8f4 pattern. */
extern void objRenderFn_8003b8f4(f32);
extern f32 lbl_803E5868;


void SB_ShipMast_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0) objRenderFn_8003b8f4(lbl_803E5868);
}

/* ObjGroup_RemoveObject(x, N) wrappers. */
void SB_ShipHead_free(int x);

/* SB_Propeller_hitDetect: guard on 0x46 == 0x69c, copy halfword from sda21 ptr. */

/* SB_ShipGun_free: expgfx interface freeObject callback. */

/* SB_Galleon_setScale: state machine; advance counter, optionally play sfx. */

/* SB_Galleon_hitDetect: per-step expgfx spawn loop. */




/*
 * --INFO--
 *
 * Function: SB_Galleon_update
 * EN v1.0 Address: 0x801E21AC
 * EN v1.0 Size: 568b
 */


/*
 * --INFO--
 *
 * Function: SB_Galleon_init
 * EN v1.0 Address: 0x801E23E4
 * EN v1.0 Size: 388b
 */



/* SB_Galleon_free: textureFree manager textures, ObjGroup_RemoveObject, kill music, set bit. */


/* SB_ShipHead_init: add to group, alloc msg queue, set state + bias positions. */


/* SB_ShipGun_render: conditional render with multiple flag checks. */


/* SB_Galleon_modelMtxFn: returns -2 / -1 / state byte depending on flags. */

/* SB_Galleon_func0E: state byte == 1 -> compute from 0x7c; else return 0x640. */
