/*
 * visanimator (DLL 0x013A) - per-map-block visibility animator object.
 *
 * On init it reads its placement def (a WaveanimatorObjectDef overlay): a
 * game bit (WaveanimatorObjectDef::originX), a gate bit index
 * (WaveanimatorObjectDef::spanX) and a base visibility bit
 * (WaveanimatorObjectDef::spanY). The gate bit's current state XORs the
 * visibility bit so the object's drawn state tracks the game bit, and
 * gateNow/gatePrev are primed. Each update re-reads the game bit (from
 * anim.placementData[0xC]) while the object sits on a loaded map block; on a
 * gate transition it toggles visBit and raises the refresh-pending flag
 * (VisAnimatorState.flags bit 1), which it then clears the same frame.
 */
#include "main/game_object.h"
#include "main/lightmap_api.h"
#include "main/dll/waveanimatorobjectdef_struct.h"
#include "main/dll/visanimatorstate_struct.h"
#include "main/dll/dll_80220608_shared.h"
#include "main/dll/dll_013A_visanimator.h"

STATIC_ASSERT(sizeof(VisAnimatorState) == 0x5);

#define VISANIMATOR_OBJFLAG_HIDDEN             0x4000
#define VISANIMATOR_OBJFLAG_HITDETECT_DISABLED 0x2000

int VisAnimator_getExtraSize(void)
{
    return sizeof(VisAnimatorState);
}
int VisAnimator_getObjectTypeId(void)
{
    return 0x0;
}

void VisAnimator_free(void)
{
}

void VisAnimator_render(void)
{
}

void VisAnimator_hitDetect(void)
{
}

#pragma scheduling off
#pragma peephole off
void VisAnimator_update(int* obj)
{
    s16* placement = ((GameObject*)obj)->anim.placementData;
    VisAnimatorState* vstate = (VisAnimatorState*)((GameObject*)obj)->extra;
    int idx =
        objPosToMapBlockIdx((double)((GameObject*)obj)->anim.localPosX, (double)((GameObject*)obj)->anim.localPosY,
                            (double)((GameObject*)obj)->anim.localPosZ);
    int gate;
    if (mapGetBlock(idx) == NULL)
    {
        vstate->flags |= 1;
        return;
    }
    gate = mainGetBit(placement[0x18 / 2]);
    vstate->gateNow = (u8)(vstate->gateMask & gate);
    if (vstate->gatePrev != vstate->gateNow)
    {
        vstate->visBit = (s8)(vstate->visBit ^ 1);
        vstate->flags |= 1;
    }
    vstate->gatePrev = vstate->gateNow;
    if (vstate->flags & 1)
    {
        vstate->flags &= ~1;
    }
}

void VisAnimator_init(int* obj, int* desc)
{
    VisAnimatorState* vstate;
    u32 gate;
    u8 gateBit;
    int baseVisBit;
    ((GameObject*)obj)->objectFlags |= (VISANIMATOR_OBJFLAG_HIDDEN | VISANIMATOR_OBJFLAG_HITDETECT_DISABLED);
    vstate = (VisAnimatorState*)((GameObject*)obj)->extra;
    baseVisBit = *(s8*)((char*)desc + 0x1B);
    vstate->visBit = baseVisBit;
    vstate->gateMask = (u8)(1 << *(u8*)&((WaveanimatorObjectDef*)desc)->spanX);
    gate = mainGetBit(((WaveanimatorObjectDef*)desc)->originX);
    if ((vstate->gateMask & gate) != 0)
    {
        vstate->visBit = vstate->visBit ^ 1;
    }
    mapGetBlock(objPosToMapBlockIdx((double)((GameObject*)obj)->anim.localPosX,
                                    (double)((GameObject*)obj)->anim.localPosY,
                                    (double)((GameObject*)obj)->anim.localPosZ));
    gate = mainGetBit(((WaveanimatorObjectDef*)desc)->originX);
    gateBit = (u8)(vstate->gateMask & gate);
    vstate->gateNow = gateBit;
    vstate->gatePrev = gateBit;
    vstate->flags |= 1;
}

void VisAnimator_release(void)
{
}

void VisAnimator_initialise(void)
{
}
