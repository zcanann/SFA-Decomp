/*
 * dimicewall (DLL 0x1C4) — ice wall object for Dinosaur Island Mission.
 * On shatter (hp reaches zero), emits particle bursts and latches a gamebit;
 * while intact, allows Tricky to push through it.
 */
#include "main/dll/dimicewallstate_struct.h"
#include "main/objprint_render_api.h"
#include "main/object.h"
#include "main/effect_interfaces.h"
#include "main/game_object.h"
#include "main/object_descriptor.h"
#include "main/gamebits.h"
#include "main/object_api.h"
#include "main/audio/sfx.h"
#include "main/audio/sfx_trigger_ids.h"

#define DIMICEWALL_OBJFLAG_HIDDEN 0x4000

#define DIMICEWALL_MAPID_NO_SFX 7433

typedef struct DimicewallPlacement
{
    u8 pad0[0x14 - 0x0];
    s32 mapId;
    u8 pad18[0x19 - 0x18];
    s8 shatterScale;
    u8 pad1A[0x1E - 0x1A];
    s16 shatterGameBit;
} DimicewallPlacement;



extern f32 lbl_803E4880;
extern f32 lbl_803E4884;

int fn_801B17F4(GameObject *obj, int delta)
{
    DimicewallState* inner = (obj)->extra;
    inner->hp = (s8)(inner->hp - delta);
    return inner->hp <= 0;
}

int dimicewall_getExtraSize(void) { return 0x2; }

void dimicewall_update(int* obj)
{
    int* extra = ((GameObject*)obj)->extra;
    int* def = *(int**)&((GameObject*)obj)->anim.placementData;
    *(u8*)&((GameObject*)obj)->anim.resetHitboxMode |= INTERACT_FLAG_DISABLED;
    if (((DimicewallState*)extra)->shattered == 0)
    {
        if (((DimicewallState*)extra)->hp <= 0)
        {
            f32 desc[6];
            int i;
            desc[2] =(f32)(s8)((DimicewallPlacement*)def)->shatterScale / lbl_803E4880;
            desc[5] = lbl_803E4884;
            for (i = 45; i != 0; i--)
            {
                desc[3] = desc[2] * (0.1f * (f32)(int)
                randomGetRange(-250, 250)
                )
                ;
                desc[4] = desc[2] * (0.1f * (f32)(int)
                randomGetRange(0, 450)
                )
                ;
                (*gPartfxInterface)->spawnObject(obj, 2041, desc, 2, -1, NULL);
            }
            for (i = 25; i != 0; i--)
            {
                desc[3] = desc[2] * (0.1f * (f32)(int)
                randomGetRange(-250, 250)
                )
                ;
                desc[4] = desc[2] * (0.1f * (f32)(int)
                randomGetRange(0, 450)
                )
                ;
                (*gPartfxInterface)->spawnObject(obj, 2042, desc, 2, -1, NULL);
            }
            if ((u32)((DimicewallPlacement*)def)->mapId != DIMICEWALL_MAPID_NO_SFX)
            {
                Sfx_PlayFromObject((int)obj, SFXTRIG_barrel_bounce1);
            }
            ((DimicewallState*)extra)->shattered = 1;
            if (((DimicewallPlacement*)def)->shatterGameBit != -1)
            {
                mainSetBits(((DimicewallPlacement*)def)->shatterGameBit, 1);
            }
        }
        else
        {
            int* tricky = (int*)getTrickyObject();
            if (tricky != NULL)
            {
                if ((*(u8*)&((GameObject*)obj)->anim.resetHitboxMode & INTERACT_FLAG_IN_RANGE) != 0)
                {
                    (*(void (**)(int*, int*, int, int))(**(int**)((char*)tricky + 0x68) + 0x28))(tricky, obj, 1, 4);
                }
                *(u8*)&((GameObject*)obj)->anim.resetHitboxMode &= ~INTERACT_FLAG_DISABLED;
                objRenderFn_80041018((GameObject*)obj);
            }
        }
    }
}

void dimicewall_init(GameObject *obj, s8* p)
{
    char* inner = (obj)->extra;
    ((DimicewallState*)inner)->hp = (s8) * (s16*)(p + 0x1a);
    if (((DimicewallPlacement*)p)->shatterGameBit != -1)
    {
        ((DimicewallState*)inner)->shattered = mainGetBit(((DimicewallPlacement*)p)->shatterGameBit);
    }
    (obj)->anim.rotX = (s16)((s32)p[0x18] << 8);
    (obj)->objectFlags |= DIMICEWALL_OBJFLAG_HIDDEN;
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
