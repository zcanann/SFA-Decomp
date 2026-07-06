/*
 * sbshipmast (DLL 0x1EB) - the mast/rigging attachment of the SB Galleon
 * boss ship. It rides its parent galleon object, pinning its local position
 * to the origin every frame, and picks one of three animation play speeds
 * depending on the galleon's animation type (anim.seqId 0x139) and its
 * unkF4 phase counter. The remaining handlers (free/hitDetect/init/release/
 * initialise) are stubs - the mast is purely cosmetic.
 */
#include "main/dll/sbshipheadstate_struct.h"
#include "main/dll/sbpropellerstate_struct.h"
#include "main/dll/DB/DBstealerworm.h"
#include "main/dll/VF/vf_shared.h"

STATIC_ASSERT(sizeof(SBPropellerState) == 0x10);

STATIC_ASSERT(sizeof(SBShipHeadState) == 0x10);

/* parent galleon anim.seqId selecting the rigging-animation behavior */
#define SB_GALLEON_SEQID 0x139


int SB_ShipMast_getExtraSize(void) { return 0x0; }

int SB_ShipMast_getObjectTypeId(void) { return 0x0; }

void SB_ShipMast_free(void)
{
}

void SB_ShipMast_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0)
    {
        objRenderModelAndHitVolumes(p1, p2, p3, p4, p5, 1.0f);
    }
}

void SB_ShipMast_hitDetect(void)
{
}

void SB_ShipMast_update(GameObject* obj)
{
    GameObject* parent;
    int phase;
    f32 speed;

    parent = obj->anim.parent;
    if (parent == NULL) return;
    phase = parent->unkF4;
    obj->anim.localPosX = 0.0f;
    obj->anim.localPosY = 0.0f;
    obj->anim.localPosZ = 0.0f;
    if (((GameObject*)obj->anim.parent)->anim.seqId == SB_GALLEON_SEQID)
    {
        if (phase >= 0xa && phase < 0xd)
        {
            if (obj->anim.currentMove != 0)
            {
                ObjAnim_SetCurrentMove((int)obj, 0, 0.0f, 0);
            }
            if (phase >= 0xc)
            {
                speed = -0.003f;
            }
            else
            {
                speed = 0.003f;
            }
        }
        else
        {
            if (obj->anim.currentMove != 1)
            {
                ObjAnim_SetCurrentMove((int)obj, 1, 0.0f, 0);
            }
            speed = 0.03f;
        }
    }
    else
    {
        if (obj->anim.currentMove != 1)
        {
            ObjAnim_SetCurrentMove((int)obj, 1, 0.0f, 0);
        }
        speed = 0.03f;
    }
    ((ObjAnimAdvanceObjectFirstF32Fn)ObjAnim_AdvanceCurrentMove)((int)obj, speed, (f32)(u32)framesThisStep, NULL);
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
