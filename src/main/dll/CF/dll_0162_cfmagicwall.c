/*
 * cfmagicwall (DLL 0x162) - magic wall at CF (CloudRunner Fortress).
 * While the placement's game bit is set, fades the wall by viewing
 * angle and distance: invisible from behind (|yaw delta| > 1/4 turn),
 * otherwise alpha ramps from 0 up to full over the placement's range
 * using the nearer of player distance and camera distance.
 */
#include "main/game_object.h"
#include "main/obj_placement.h"
#include "main/gamebits.h"
#include "main/dll/fx_800944A0_shared.h"

typedef struct CfMagicWallMapData
{
    ObjPlacement base;
    s8 rotXByte;   /* 0x18: rotX in 1/256 turns */
    u8 pad19;
    s16 fadeRange; /* 0x1A: distance over which alpha ramps */
    u8 pad1C[4];
    s16 visibleEvent; /* 0x20: game bit enabling the fade logic */
    u8 pad22[0x28 - 0x22];
} CfMagicWallMapData;

STATIC_ASSERT(offsetof(CfMagicWallMapData, fadeRange) == 0x1A);
STATIC_ASSERT(offsetof(CfMagicWallMapData, visibleEvent) == 0x20);

/* a quarter turn: the wall is invisible when viewed from behind */
#define CFMAGICWALL_SIDE_ANGLE 0x4000

extern int Obj_GetYawDeltaToObject();
extern void objRenderFn_8003b8f4(int obj, int p2, int p3, int p4, int p5, f32 scale);

extern f32 Vec_distance(f32* a, f32* b);

extern f32 lbl_803E43D8; /* render scale */
extern f32 lbl_803E43DC; /* 255.0f - full alpha */

int cfmagicwall_getExtraSize(void) { return 0x0; }

int cfmagicwall_getObjectTypeId(void) { return 0x0; }

void cfmagicwall_free(void)
{
}

void cfmagicwall_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0) objRenderFn_8003b8f4(p1, p2, p3, p4, p5, lbl_803E43D8);
}

void cfmagicwall_hitDetect(void)
{
}

void cfmagicwall_update(int obj)
{
    int placement = *(int*)&((GameObject*)obj)->anim.placementData;
    int player = (int)Obj_GetPlayerObject();
    u8 alpha = 0xff;

    if (GameBit_Get(((CfMagicWallMapData*)placement)->visibleEvent) != 0)
    {
        int yaw = (s16)Obj_GetYawDeltaToObject(obj, player, NULL);

        yaw = (yaw >= 0) ? yaw : -yaw;

        if (yaw > CFMAGICWALL_SIDE_ANGLE)
        {
            ((GameObject*)obj)->anim.alpha = 0;
            return;
        }

        {
            f32 playerDistance;
            f32 range;
            f32 fadeDistance;
            range = (f32)(s32)((CfMagicWallMapData*)placement)->fadeRange;
            playerDistance = Vec_distance((void*)&((GameObject*)obj)->anim.worldPosX, (void*)(player + 0x18));
            fadeDistance = Camera_DistanceToCurrentViewPosition(
                ((GameObject*)obj)->anim.localPosX, ((GameObject*)obj)->anim.localPosY,
                ((GameObject*)obj)->anim.localPosZ);

            if (fadeDistance < playerDistance)
            {
                fadeDistance = Camera_DistanceToCurrentViewPosition(
                    ((GameObject*)obj)->anim.localPosX, ((GameObject*)obj)->anim.localPosY,
                    ((GameObject*)obj)->anim.localPosZ);
            }
            else
            {
                fadeDistance = playerDistance;
            }

            if (fadeDistance < range)
            {
                alpha = lbl_803E43DC * (fadeDistance / range);
            }

            ((GameObject*)obj)->anim.alpha = alpha;
        }
    }
}

void cfmagicwall_init(s16* dst, void* src)
{
    s8 v = *((s8*)src + 0x18);
    s16 t = v << 8;
    *dst = t;
}

void cfmagicwall_release(void)
{
}

void cfmagicwall_initialise(void)
{
}
