#include "main/dll/dll_80220608_shared.h"
#include "main/effect_interfaces.h"
#include "main/expgfx.h"
#include "main/dll/dustmotesou.h"

int dustmotesou_getExtraSize(void) { return 0; }

int dustmotesou_getObjectTypeId(void) { return 0; }

void dustmotesou_free(int obj)
{
    (*gExpgfxInterface)->freeSource2((u32)obj);
}

#pragma peephole off
void dustmotesou_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    if (visible != 0) {
        return;
    }
}
#pragma peephole reset

void dustmotesou_hitDetect(void) {}

#pragma peephole off
#pragma scheduling off
void dustmotesou_init(int obj, int setup)
{
    DustMoteSouObject *source = (DustMoteSouObject *)obj;
    DustMoteSouMapData *mapData = (DustMoteSouMapData *)setup;

    source->objAnim.rotZ = (s16)(mapData->rotZ << 8);
    source->objAnim.rotY = (s16)(mapData->rotY << 8);
    source->objAnim.rotX = (s16)(mapData->rotX << 8);
    source->objectFlags |= DUSTMOTESOU_OBJECT_FLAG_SPAWN_EFFECTS;
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void dustmotesou_update(int obj)
{
    DustMoteSouObject *source = (DustMoteSouObject *)obj;
    DustMoteSouMapData *mapData = (DustMoteSouMapData *)source->objAnim.placementData;

    if (mapData->gameBit != -1 && (u32)GameBit_Get(mapData->gameBit) == 0) {
        return;
    }
    if (source->objAnim.seqId == DUSTMOTESOU_SEQ_TAIL_LIGHT) {
        if (mapData->effectId == 0) {
            return;
        }
        if (mapData->effectParamA == 0) {
            return;
        }
        objfx_spawnMaskedHitEffect(obj, mapData->effectId, mapData->effectParamA, mapData->scale,
                    mapData->effectParamB, 0);
        return;
    }
    if (source->objAnim.seqId == DUSTMOTESOU_SEQ_FIREWORK) {
        if (mapData->effectId == 0) {
            return;
        }
        if (mapData->effectParamA == 0) {
            return;
        }
        hitDetectFn_80097070(obj, mapData->effectId, mapData->effectParamA,
                             mapData->scale, mapData->effectParamB, 0);
        return;
    }
    if (mapData->effectId == 0) {
        return;
    }
    if (mapData->effectParamA == 0) {
        return;
    }
    if (mapData->effectParamB == 0) {
        return;
    }
    if (mapData->burstMode == DUSTMOTESOU_BURST_BOX) {
        ((void (*)(int, int, int, int, f32, f32, f32, f32, int, int, int))objfx_spawnBoxBurst)(
            obj, mapData->effectId, mapData->effectParamA, mapData->effectParamB,
            mapData->scale, (f32)(u32)mapData->spreadX,
            (f32)(u32)mapData->spreadY, (f32)(u32)mapData->spreadZ,
            mapData->effectFlags, 0, 0);
    } else if (mapData->burstMode == DUSTMOTESOU_BURST_ARCED) {
        objfx_spawnArcedBurst(obj, mapData->effectId, mapData->scale,
                               mapData->effectParamA, mapData->effectParamB, mapData->effectFlags,
                               (f32)(u32)mapData->spreadX, (f32)(u32)mapData->spreadY,
                               (f32)(u32)mapData->spreadZ, 0, 0);
    } else {
        objfx_spawnDirectionalBurst(obj, mapData->effectId, mapData->effectParamA, mapData->effectParamB,
                       mapData->scale, (f32)(u32)mapData->spreadX,
                       mapData->effectFlags, 0, 0);
    }
}
#pragma scheduling reset
#pragma peephole reset

void dustmotesou_release(void) {}

void dustmotesou_initialise(void) {}
