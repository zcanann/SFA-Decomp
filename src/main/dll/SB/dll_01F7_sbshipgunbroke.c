/*
 * SB_ShipGunBroke (DLL 0x01F7) - the wrecked variant of the galleon's deck
 * gun (SB_ShipGun) in the ShipBattle prologue (SB = the retail "ShipBattle"
 * map), shown after the gun has been shot out. TU: 0x801E4288-0x801E42F8.
 *
 * It is purely cosmetic: a static prop that is only rendered (and plays a
 * looping electrical-damage sfx) while a placement-supplied GameBit is set.
 * That GameBit is the gun's "destroyed" flag - its index is stored in the
 * placement record at offset 0x1E.
 */
#include "main/dll/shipbattlestate_struct.h"
#include "main/dll/sbkytecagestate_struct.h"
#include "main/dll/sbfireballstate_struct.h"
#include "main/dll/sbcloudballstate_struct.h"
#include "main/game_object.h"
#include "main/audio/sfx_ids.h"
#include "main/gamebits.h"
extern void objRenderModelAndHitVolumes(int obj, int p2, int p3, int p4, int p5, f32 scale);
extern f32 lbl_803E59C0;
extern void Sfx_PlayFromObject(int* obj, int sfxId);

/* Placement record for the broken ship-gun: only the destroyed-flag
   GameBit index (0x1E) is read by this DLL. */
typedef struct SBShipGunBrokePlacement
{
    u8 pad0[0x1E];
    s16 destroyedGameBit; /* 0x1E */
} SBShipGunBrokePlacement;

STATIC_ASSERT(sizeof(SBCloudBallState) == 0x24);
STATIC_ASSERT(sizeof(SBFireBallState) == 0x18);
STATIC_ASSERT(sizeof(SBKyteCageState) == 0x8);
STATIC_ASSERT(sizeof(ShipBattleState) == 0x140);

int SB_ShipGunBroke_getExtraSize(void) { return 0x1; }
int SB_ShipGunBroke_getObjectTypeId(void) { return 0x0; }

void SB_ShipGunBroke_free(void)
{
}

void SB_ShipGunBroke_render(GameObject* obj, int p2, int p3, int p4, int p5)
{
    SBShipGunBrokePlacement* placement = (SBShipGunBrokePlacement*)obj->anim.placementData;
    if ((u32)GameBit_Get(placement->destroyedGameBit) != 0u)
    {
        ((void(*)(GameObject*, int, int, int, int, f32))objRenderModelAndHitVolumes)(obj, p2, p3, p4, p5, lbl_803E59C0);
    }
}

void SB_ShipGunBroke_hitDetect(void)
{
}

void SB_ShipGunBroke_update(GameObject* obj)
{
    SBShipGunBrokePlacement* placement = (SBShipGunBrokePlacement*)obj->anim.placementData;
    if ((u32)GameBit_Get(placement->destroyedGameBit) != 0u)
    {
        Sfx_PlayFromObject((int*)obj, SFXen_nlite1_c);
    }
}

void SB_ShipGunBroke_init(void)
{
}

void SB_ShipGunBroke_release(void)
{
}

void SB_ShipGunBroke_initialise(void)
{
}
