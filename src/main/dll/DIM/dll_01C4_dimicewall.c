/*
 * dimicewall (DLL 0x1C4) - ice wall object for Dinosaur Island Mission.
 * On shatter (hp reaches zero), emits particle bursts and latches a gamebit;
 * while intact, allows Tricky to push through it.
 */
#include "main/dll/partfx_interface.h"
#include "main/dll/DIM/dll_01C4_dimicewall.h"
#include "main/dll/dll_0120_trickyguardspot.h"
#include "main/dll/dimicewallstate_struct.h"
#include "main/objprint_render_api.h"
#include "main/object.h"
#include "main/game_object.h"
#include "main/object_descriptor.h"
#include "main/obj_placement.h"
#include "main/gamebits.h"
#include "main/object_api.h"
#include "main/audio/sfx.h"
#include "main/audio/sfx_trigger_ids.h"

#define DIMICEWALL_OBJFLAG_HIDDEN 0x4000

#define DIMICEWALL_MAPID_NO_SFX 7433

typedef struct DimicewallPlacement
{
    ObjPlacement head; /* 0x00..0x17 (mapId at 0x14) */
    s8 rotX;
    s8 shatterScale;
    s16 hp;
    u8 pad1C[0x1E - 0x1C];
    s16 shatterGameBit;
} DimicewallPlacement;

STATIC_ASSERT(offsetof(DimicewallPlacement, rotX) == 0x18);
STATIC_ASSERT(offsetof(DimicewallPlacement, shatterScale) == 0x19);
STATIC_ASSERT(offsetof(DimicewallPlacement, hp) == 0x1A);
STATIC_ASSERT(offsetof(DimicewallPlacement, shatterGameBit) == 0x1E);
STATIC_ASSERT(sizeof(DimicewallState) == 0x2);


int dimicewall_countdownCallback(GameObject *obj, int delta)
{
    DimicewallState* inner = (obj)->extra;
    inner->hp = (s8)(inner->hp - delta);
    return inner->hp <= 0;
}

int dimicewall_getExtraSize(void) { return 0x2; }

void dimicewall_update(GameObject* obj)
{
    DimicewallState* state = obj->extra;
    DimicewallPlacement* placement = (DimicewallPlacement*)obj->anim.placementData;
    obj->anim.resetHitboxFlags |= INTERACT_FLAG_DISABLED;
    if (state->shattered == 0)
    {
        if (state->hp <= 0)
        {
            PartFxSpawnParams desc;
            int i;
            desc.scale = (f32)placement->shatterScale / 50.0f;
            desc.posZ = 0.0f;
            for (i = 45; i != 0; i--)
            {
                desc.posX = desc.scale * (0.1f * (f32)(int)
                randomGetRange(-250, 250)
                )
                ;
                desc.posY = desc.scale * (0.1f * (f32)(int)
                randomGetRange(0, 450)
                )
                ;
                (*gPartfxInterface)->spawnObject((int*)obj, 2041, &desc, 2, -1, NULL);
            }
            for (i = 25; i != 0; i--)
            {
                desc.posX = desc.scale * (0.1f * (f32)(int)
                randomGetRange(-250, 250)
                )
                ;
                desc.posY = desc.scale * (0.1f * (f32)(int)
                randomGetRange(0, 450)
                )
                ;
                (*gPartfxInterface)->spawnObject((int*)obj, 2042, &desc, 2, -1, NULL);
            }
            if ((u32)placement->head.mapId != DIMICEWALL_MAPID_NO_SFX)
            {
                Sfx_PlayFromObject((int)obj, SFXTRIG_barrel_bounce1);
            }
            state->shattered = 1;
            if (placement->shatterGameBit != -1)
            {
                mainSetBits(placement->shatterGameBit, 1);
            }
        }
        else
        {
            GameObject* tricky = getTrickyObject();
            if (tricky != NULL)
            {
                if ((obj->anim.resetHitboxFlags & INTERACT_FLAG_IN_RANGE) != 0)
                {
                    (*(TrickyGuardSpotInterfaceVTable**)tricky->anim.dll)->setGuardSpotAction(
                        &tricky->anim, obj, 1, 4);
                }
                obj->anim.resetHitboxFlags &= ~INTERACT_FLAG_DISABLED;
                objRenderFn_80041018(obj);
            }
        }
    }
}

void dimicewall_init(GameObject* obj, DimicewallPlacement* placement)
{
    DimicewallState* state = obj->extra;
    state->hp = (s8)placement->hp;
    if (placement->shatterGameBit != -1)
    {
        state->shattered = mainGetBit(placement->shatterGameBit);
    }
    obj->anim.rotX = (s16)((s32)placement->rotX << 8);
    obj->objectFlags |= DIMICEWALL_OBJFLAG_HIDDEN;
}

ObjectDescriptor gDIMIceWallObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    0,
    0,
    0,
    (ObjectDescriptorCallback)dimicewall_init,
    (ObjectDescriptorCallback)dimicewall_update,
    0,
    0,
    0,
    0,
    dimicewall_getExtraSize,
};

