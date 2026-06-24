/*
 * dimbosscrackpar (DLL 0x1E6) - DIM boss crack-particle emitter objects.
 * Each instance is placed at a crack site in the DIM gut wall.  While the
 * associated game bit is set it spawns two particle effects per frame
 * (one indexed by placement particleIndex, plus a fixed glow burst).
 * The animEventCallback (dimbosscrackpar_SeqFn) does the same on sequence ticks.
 * NOTE: GameBit_Get is used implicitly (no include); adding gamebits.h changes
 * codegen at the  cast call sites — leave it implicit.
 */
#include "main/dll_000A_expgfx.h"
#include "main/game_object.h"

#define DIMBOSSCRACKPAR_BASE_PARTICLE_ID  1222 /* crack-site particle, offset by particleIndex */
#define DIMBOSSCRACKPAR_GLOW_PARTICLE_ID  1224 /* fixed glow burst particle */

typedef struct DimbosscrackparPlacement
{
    u8 pad0[0x1A - 0x0];
    s16 particleIndex; /* 0x1A: added to DIMBOSSCRACKPAR_BASE_PARTICLE_ID to select crack effect */
    u8 pad1C[0x1E - 0x1C];
    s16 triggerGameBit; /* 0x1E: game bit that gates particle emission */
} DimbosscrackparPlacement;

extern f32 lbl_803E4D98;

void dimbosscrackpar_hitDetect(void)
{
}

void dimbosscrackpar_release(void)
{
}

void dimbosscrackpar_initialise(void)
{
}

void magicmaker_update(int obj);

int dimbosscrackpar_SeqFn(int* obj)
{
    int* side = *(int**)&((GameObject*)obj)->anim.placementData;
    if ((u32)GameBit_Get(((DimbosscrackparPlacement*)side)->triggerGameBit) == 0u)
    {
        return 0;
    }
    (*gPartfxInterface)->spawnObject(
        obj, ((DimbosscrackparPlacement*)side)->particleIndex + DIMBOSSCRACKPAR_BASE_PARTICLE_ID, NULL, 2, -1, NULL);
    (*gPartfxInterface)->spawnObject(obj, DIMBOSSCRACKPAR_GLOW_PARTICLE_ID, NULL, 2, -1, NULL);
    return 0;
}

void dimbosscrackpar_update(int* obj)
{
    int* side = *(int**)&((GameObject*)obj)->anim.placementData;
    if ((u32)GameBit_Get(((DimbosscrackparPlacement*)side)->triggerGameBit) != 0u)
    {
        (*gPartfxInterface)->spawnObject(
            obj, ((DimbosscrackparPlacement*)side)->particleIndex + DIMBOSSCRACKPAR_BASE_PARTICLE_ID, NULL, 2, -1, NULL);
        (*gPartfxInterface)->spawnObject(obj, DIMBOSSCRACKPAR_GLOW_PARTICLE_ID, NULL, 2, -1, NULL);
    }
}

void dimbosscrackpar_free(int* obj)
{
    (*gExpgfxInterface)->freeSource2((u32)obj);
}

void dimbosscrackpar_render(int p1, int p2, int p3, int p4, int p5, s8 visible) { if (visible == 0) return; }

void dimbosscrackpar_init(s16* obj, s8* def)
{
    ((GameObject*)obj)->anim.rotX = 0;
    ((GameObject*)obj)->anim.rootMotionScale = lbl_803E4D98;
    ((GameObject*)obj)->animEventCallback = dimbosscrackpar_SeqFn;
    ((GameObject*)obj)->anim.rotX = (s16)((s32)def[0x24] << 8);
    ((GameObject*)obj)->anim.rotY = (s16)((s32)def[0x23] << 8);
    ((GameObject*)obj)->anim.rotZ = (s16)((s32)def[0x22] << 8);
}

void dimbossfire_hitDetect(void);

int dimbosscrackpar_getExtraSize(void) { return 0x0; }
int dimbosscrackpar_getObjectTypeId(void) { return 0x0; }
int dimbossfire_getExtraSize(void);
