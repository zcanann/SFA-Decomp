/*
 * imspacering (DLL 0x170) - one of the spinning rings that orbit the
 * SpaceCraft cinematic object on the Ice Mountain map.
 *
 * Each ring picks a random spin axis at init (X or Y) and tumbles
 * continuously on that axis plus Z. While the ring generator
 * (imspaceringgen) has published a leader object in gSpaceRingLeader,
 * every ring copies the leader's alpha and chases its world position so
 * the whole swarm tracks the spacecraft.
 */
#include "main/game_object.h"
#include "main/engine_shared.h"

extern void objRenderModelAndHitVolumes(int obj, int p2, int p3, int p4, int p5, f32 scale);
extern void objMove(int obj, f32 dx, f32 dy, f32 dz);
extern GameObject* lbl_803DDB48;
extern f32 lbl_803E47B8;

int imspacering_getExtraSize(void) { return 0x0; }
int imspacering_getObjectTypeId(void) { return 0x0; }

void imspacering_free(void)
{
}

void imspacering_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0) objRenderModelAndHitVolumes(p1, p2, p3, p4, p5, lbl_803E47B8);
}

void imspacering_hitDetect(void)
{
}

void imspacering_update(GameObject* obj)
{
    s16* placement = *(s16**)&obj->anim.placementData;
    if (obj->unkF4 != 0)
    {
        obj->anim.rotX = (s16)(obj->anim.rotX + placement[0xd] * framesThisStep);
    }
    else
    {
        obj->anim.rotY = (s16)(obj->anim.rotY + placement[0xd] * framesThisStep);
    }
    obj->anim.rotZ = (s16)(obj->anim.rotZ + placement[0xe] * framesThisStep);
    if (lbl_803DDB48 != NULL)
    {
        obj->anim.alpha = lbl_803DDB48->anim.alpha;
        objMove((int)obj,
                lbl_803DDB48->anim.localPosX - obj->anim.localPosX,
                lbl_803DDB48->anim.localPosY - obj->anim.localPosY,
                lbl_803DDB48->anim.localPosZ - obj->anim.localPosZ);
    }
}

void imspacering_init(GameObject* obj, s8* placement)
{
    obj->anim.rotX = (s16)((s32)placement[0x18] << 8);
    obj->unkF4 = randomGetRange(0, 1);
}

void imspacering_release(void)
{
}

void imspacering_initialise(void)
{
}
