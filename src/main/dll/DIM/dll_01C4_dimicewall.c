/*
 * dimicewall (DLL 0x1C4) — ice wall object for Dinosaur Island Mission.
 * On shatter (hp reaches zero), emits particle bursts and latches a gamebit;
 * while intact, allows Tricky to push through it.
 */
#include "main/dll/dimicewallstate_struct.h"
#include "main/effect_interfaces.h"
#include "main/game_object.h"
#include "main/gamebits.h"
#include "main/dll/fx_800944A0_shared.h"
#include "main/audio/sfx.h"

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



extern void* getTrickyObject(void);
extern void objRenderFn_80041018(int* obj);
extern f32 lbl_803E4880;
extern f32 lbl_803E4884;

int dimicewall_getExtraSize(void) { return 0x2; }
int dimbarrier_getExtraSize(void);

void dimicewall_init(int obj, s8* p)
{
    char* inner = ((GameObject*)obj)->extra;
    *(s8*)(inner + 0) = (s8) * (s16*)(p + 0x1a);
    if (((DimicewallPlacement*)p)->shatterGameBit != -1)
    {
        ((DimicewallState*)inner)->shattered = GameBit_Get(((DimicewallPlacement*)p)->shatterGameBit);
    }
    ((GameObject*)obj)->anim.rotX = (s16)((s32)p[0x18] << 8);
    ((GameObject*)obj)->objectFlags |= 0x4000;
}

void dimgate_init(int obj, s8* p_unused_passthrough);

int fn_801B17F4(int obj, int delta)
{
    s8* inner = ((GameObject*)obj)->extra;
    inner[0] = (s8)(inner[0] - delta);
    return inner[0] <= 0;
}

void dimgate_update(int* obj);

void dimicewall_update(int* obj)
{
    int* extra = ((GameObject*)obj)->extra;
    int* def = *(int**)&((GameObject*)obj)->anim.placementData;
    *(u8*)&((GameObject*)obj)->anim.resetHitboxMode |= 8;
    if (((DimicewallState*)extra)->shattered == 0)
    {
        if (*(s8*)extra <= 0)
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
                Sfx_PlayFromObject((int)obj, 1147);
            }
            ((DimicewallState*)extra)->shattered = 1;
            if (((DimicewallPlacement*)def)->shatterGameBit != -1)
            {
                GameBit_Set(((DimicewallPlacement*)def)->shatterGameBit, 1);
            }
        }
        else
        {
            int* tricky = getTrickyObject();
            if (tricky != NULL)
            {
                if ((*(u8*)&((GameObject*)obj)->anim.resetHitboxMode & INTERACT_FLAG_IN_RANGE) != 0)
                {
                    (*(void (**)(int*, int*, int, int))(**(int**)((char*)tricky + 0x68) + 0x28))(tricky, obj, 1, 4);
                }
                *(u8*)&((GameObject*)obj)->anim.resetHitboxMode &= ~INTERACT_FLAG_DISABLED;
                objRenderFn_80041018(obj);
            }
        }
    }
}
