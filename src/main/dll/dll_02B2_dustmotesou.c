/*
 * dustmotesou (DLL 0x02B2) - an ambient particle-effect emitter object.
 *
 * A placement-only object: it carries no per-instance extra state
 * (getExtraSize == 0) and does no rendering or hit detection. Its init
 * sets the model orientation from the placement bytes and flags the
 * object to spawn effects; its update spawns a particle effect every
 * tick, gated on an optional game bit.
 *
 * The effect spawned depends on the animation sequence the placement
 * selected:
 *   - DUSTMOTESOU_SEQ_TAIL_LIGHT -> a masked hit effect (trailing light),
 *   - DUSTMOTESOU_SEQ_FIREWORK   -> the firework hit-detect spawner,
 *   - otherwise (dust mote)      -> one of three burst styles chosen by
 *     mapData->burstMode (box / arced / directional), seeded with the
 *     placement's per-axis spread.
 *
 * The effectId / paramA / paramB fields gate each per-branch spawn: a zero
 * id or required param skips that branch. The gameBit field gates all
 * spawning when non-(-1) and clear.
 */
#include "main/dll/dll_80220608_shared.h"
#include "main/dll/dll_02B2_dustmotesou.h"

int dustmotesou_getExtraSize(void) { return 0; }

int dustmotesou_getObjectTypeId(void) { return 0; }

void dustmotesou_free(int obj)
{
    (*gExpgfxInterface)->freeSource2((u32)obj);
}

void dustmotesou_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    if (visible == 0)
    {
        return;
    }
}

void dustmotesou_hitDetect(void)
{
}

void dustmotesou_init(int obj, int setup)
{
    DustMoteSouObject* source = (DustMoteSouObject*)obj;
    DustMoteSouMapData* mapData = (DustMoteSouMapData*)setup;

    source->objAnim.rotZ = (s16)(mapData->rotZ << 8);
    source->objAnim.rotY = (s16)(mapData->rotY << 8);
    source->objAnim.rotX = (s16)(mapData->rotX << 8);
    source->objectFlags |= DUSTMOTESOU_OBJECT_FLAG_SPAWN_EFFECTS;
}

void dustmotesou_update(int obj)
{
    DustMoteSouObject* source = (DustMoteSouObject*)obj;
    DustMoteSouMapData* mapData = (DustMoteSouMapData*)source->objAnim.placementData;

    if (mapData->gameBit != -1 && (u32)GameBit_Get(mapData->gameBit) == 0)
    {
        return;
    }
    if (source->objAnim.seqId == DUSTMOTESOU_SEQ_TAIL_LIGHT)
    {
        if (mapData->effectId == 0 || mapData->effectParamA == 0)
        {
            return;
        }
        objfx_spawnMaskedHitEffect(obj, mapData->effectId, mapData->effectParamA, mapData->scale,
                                   mapData->effectParamB, 0);
        return;
    }
    if (source->objAnim.seqId == DUSTMOTESOU_SEQ_FIREWORK)
    {
        if (mapData->effectId == 0 || mapData->effectParamA == 0)
        {
            return;
        }
        hitDetectFn_80097070(obj, mapData->effectId, mapData->effectParamA,
                             mapData->scale, mapData->effectParamB, 0);
        return;
    }
    if (mapData->effectId == 0 || mapData->effectParamA == 0 || mapData->effectParamB == 0)
    {
        return;
    }
    if (mapData->burstMode == DUSTMOTESOU_BURST_BOX)
    {
        ((void (*)(int, int, f32, int, int, int, f32, f32, f32, int, int))objfx_spawnBoxBurst)(
            obj, mapData->effectId, mapData->scale, mapData->effectParamA, mapData->effectParamB,
            mapData->effectFlags, (f32)(u32)mapData->spreadX, (f32)(u32)mapData->spreadY,
            (f32)(u32)mapData->spreadZ, 0, 0);
    }
    else if (mapData->burstMode == DUSTMOTESOU_BURST_ARCED)
    {
        objfx_spawnArcedBurst(obj, mapData->effectId, mapData->scale,
                              mapData->effectParamA, mapData->effectParamB, mapData->effectFlags,
                              (f32)(u32)mapData->spreadX, (f32)(u32)mapData->spreadY,
                              (f32)(u32)mapData->spreadZ, 0, 0);
    }
    else
    {
        ((void (*)(int, int, int, int, f32, int, f32, int, int))objfx_spawnDirectionalBurst)(
            obj, mapData->effectId, mapData->effectParamA, mapData->effectParamB,
            mapData->scale, mapData->effectFlags, (f32)(u32)mapData->spreadX, 0, 0);
    }
}

void dustmotesou_release(void)
{
}

void dustmotesou_initialise(void)
{
}
