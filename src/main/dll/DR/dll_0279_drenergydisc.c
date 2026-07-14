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
#include "main/audio/sfx.h"
#include "main/frame_timing.h"
#include "main/gamebits.h"
#include "main/game_object.h"
#include "main/objanim.h"
#include "main/objtexture.h"
#include "main/object_descriptor.h"

#include "main/audio/sfx_ids.h"
#include "main/audio/sfx_trigger_ids.h"

#include "main/dll/DR/dll_0279_drenergydisc.h"

int lbl_803DC380 = -400;

__declspec(section ".sdata2") f32 lbl_803E6BB0 = 1.0f;
#pragma explicit_zero_data on
__declspec(section ".sdata2") f32 lbl_803E6BB4 = 0.0f;
#pragma explicit_zero_data off

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

void DR_EnergyDisc_update(GameObject* obj)
{
    ObjTextureRuntimeSlot* texture;
    DrEnergyDiscState* state = (obj)->extra;
    DrenergydiscPlacement* setup = (DrenergydiscPlacement*)obj->anim.placementData;

    if ((u32)mainGetBit(setup->activeGameBit) != 0)
    {
        if (state->activated == 0)
        {
            state->activated = 1;
            Sfx_PlayFromObject((int)obj, SFXTRIG_id_30c);
        }

        texture = objFindTexture(obj, 0, 0);
        if (texture != NULL)
        {
            texture->textureId = 0x100;
        }

        texture = objFindTexture(obj, 0, 0);
        if (texture != NULL)
        {
            texture->offsetT = texture->offsetT + lbl_803DC380 * framesThisStep;
            if (texture->offsetT < -0x1000)
            {
                texture->offsetT = 0;
            }
        }
    }

    if ((u32)mainGetBit(setup->moveGameBit) != 0)
    {
        ObjAnim_SetCurrentMove((int)obj, 0, lbl_803E6BB0, 0);
    }
}

void DR_EnergyDisc_init(GameObject* obj, DrenergydiscPlacement* setup)
{
    ObjTextureRuntimeSlot* texture;
    DrEnergyDiscState* state = obj->extra;
    s16 spawnRotX;

    spawnRotX = (s16)(setup->rotXByte << 8);
    obj->anim.rotX = spawnRotX;
    if ((u32)mainGetBit(setup->activeGameBit) != 0)
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
    obj->objectFlags =
        (u16)(obj->objectFlags | (DRENERGYDISC_OBJFLAG_HIDDEN | DRENERGYDISC_OBJFLAG_HITDETECT_DISABLED));
}

void DR_EnergyDisc_release(void)
{
}

void DR_EnergyDisc_initialise(void)
{
}

ObjectDescriptor gDrEnergyDiscObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)DR_EnergyDisc_initialise,
    (ObjectDescriptorCallback)DR_EnergyDisc_release,
    0,
    (ObjectDescriptorCallback)DR_EnergyDisc_init,
    (ObjectDescriptorCallback)DR_EnergyDisc_update,
    (ObjectDescriptorCallback)DR_EnergyDisc_hitDetect,
    (ObjectDescriptorCallback)DR_EnergyDisc_render,
    (ObjectDescriptorCallback)DR_EnergyDisc_free,
    (ObjectDescriptorCallback)DR_EnergyDisc_getObjectTypeId,
    (ObjectDescriptorExtraSizeCallback)DR_EnergyDisc_getExtraSize,
};

u32 lbl_8032AD00[12] = {
    0xFFFFFFFF, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
};
