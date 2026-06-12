#include "main/obj_placement.h"
#include "main/dll/sbshipheadstate_struct.h"
#include "main/dll/sbpropellerstate_struct.h"
#include "main/game_object.h"
#include "main/audio/sfx_ids.h"
#include "main/effect_interfaces.h"
#include "main/mapEventTypes.h"
#include "main/objseq.h"
#include "main/dll/DB/DBstealerworm.h"
#include "main/dll/DB/sbgalleon_state.h"

STATIC_ASSERT(sizeof(SBPropellerState) == 0x10);

STATIC_ASSERT(sizeof(SBShipHeadState) == 0x10);

extern undefined8 ObjGroup_RemoveObject();

extern u8 framesThisStep;

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

int SB_Galleon_getExtraSize(void);
int SB_ShipMast_getExtraSize(void) { return 0x0; }
int SB_ShipMast_getObjectTypeId(void) { return 0x0; }
int SB_ShipGun_getExtraSize(void);

extern void objRenderFn_8003b8f4(f32);
extern f32 lbl_803E5868;

void SB_ShipMast_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0) objRenderFn_8003b8f4(lbl_803E5868);
}

void SB_ShipHead_free(int x);
