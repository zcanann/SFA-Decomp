/*
 * drenergydisc (DLL 0x279) - an energy-disc dressing object whose
 * activation is driven by two placement game bits.
 *
 * While the "active" game bit (placement 0x20) is set the disc plays a
 * one-shot servo whir on its first frame active, forces its texture to
 * the energised id and scrolls the texture's T coordinate each step.
 * When the "move" game bit (placement 0x1E) is set the disc switches to
 * animation move lbl_803E6BB0. init seeds the spawn rotation from the
 * placement and primes the activated/texture state from the active bit.
 */
#include "main/dll/dll_80220608_shared.h"
#include "main/game_object.h"

#include "main/audio/sfx_ids.h"
#include "main/audio/sfx_trigger_ids.h"

#include "main/dll/DR/dll_0279_drenergydisc.h"

#define DRENERGYDISC_OBJFLAG_HIDDEN             0x4000
#define DRENERGYDISC_OBJFLAG_HITDETECT_DISABLED 0x2000

int DR_EnergyDisc_getExtraSize(void)
{
    return 1;
}

int DR_EnergyDisc_getObjectTypeId(void)
{
    return 0;
}

void DR_EnergyDisc_free(void)
{
}

void DR_EnergyDisc_render(void)
{
}

void DR_EnergyDisc_hitDetect(void)
{
}

void DR_EnergyDisc_update(int obj)
{
    ObjTextureRuntimeSlot* texture;
    DrEnergyDiscState* state = ((GameObject*)obj)->extra;
    int setup = *(int*)&((GameObject*)obj)->anim.placementData;

    if ((u32)mainGetBit(((DrenergydiscPlacement*)setup)->activeGameBit) != 0)
    {
        if (state->activated == 0)
        {
            state->activated = 1;
            Sfx_PlayFromObject(obj, SFXTRIG_id_30c);
        }

        texture = objFindTexture((void*)obj, 0, 0);
        if (texture != NULL)
        {
            texture->textureId = 0x100;
        }

        texture = objFindTexture((void*)obj, 0, 0);
        if (texture != NULL)
        {
            texture->offsetT = texture->offsetT + lbl_803DC380 * framesThisStep;
            if (texture->offsetT < -0x1000)
            {
                texture->offsetT = 0;
            }
        }
    }

    if ((u32)mainGetBit(((DrenergydiscPlacement*)setup)->moveGameBit) != 0)
    {
        ObjAnim_SetCurrentMove(obj, 0, lbl_803E6BB0, 0);
    }
}

void DR_EnergyDisc_init(u8* obj, u8* setup)
{
    ObjTextureRuntimeSlot* texture;
    DrEnergyDiscState* state = ((GameObject*)obj)->extra;
    s16 spawnRotX;

    spawnRotX = (s16)((s8)setup[0x18] << 8);
    ((GameObject*)obj)->anim.rotX = spawnRotX;
    if ((u32)mainGetBit(((DrenergydiscPlacement*)setup)->activeGameBit) != 0)
    {
        state->activated = 1;
        Sfx_PlayFromObject((int)obj, SFXTRIG_id_30c);
        texture = objFindTexture(obj, 0, 0);
        if (texture != NULL)
        {
            texture->textureId = 0x100;
        }
    }
    else
    {
        state->activated = 0;
        texture = objFindTexture(obj, 0, 0);
        if (texture != NULL)
        {
            texture->textureId = 0;
        }
    }
    ((GameObject*)obj)->objectFlags = (u16)(((GameObject*)obj)->objectFlags |
                                            (DRENERGYDISC_OBJFLAG_HIDDEN | DRENERGYDISC_OBJFLAG_HITDETECT_DISABLED));
}

void DR_EnergyDisc_release(void)
{
}

void DR_EnergyDisc_initialise(void)
{
}
