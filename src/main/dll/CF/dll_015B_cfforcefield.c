/*
 * cfforcefield (DLL 0x15B) - force-field barrier at CF (CloudRunner
 * Fortress). While the placement's active game bit is set, sprays a
 * ring of particle bursts around the barrier each tick (three spawns
 * per ring step, ring radius scaled by the remaining collapse time).
 * When the collapse game bit is granted, a 60-frame timer spins the
 * field down (rotY ramp + shrinking ring) and then disables it; the
 * field re-arms if the collapse bit is cleared again.
 */
#include "main/game_object.h"
#include "main/obj_placement.h"
#include "main/effect_interfaces.h"
#include "main/gamebits.h"
#include "main/dll/fx_800944A0_shared.h"
#include "main/audio/sfx.h"
#include "main/audio/sfx_trigger_ids.h"

typedef struct CfForceFieldFlags
{
    u8 disabled : 1; /* 0x80: field collapsed; skip update work */
    u8 rest : 7;
} CfForceFieldFlags;

typedef struct CfForceFieldState
{
    CfForceFieldFlags flags; /* 0x00 */
    u8 pad01[3];
    f32 timer;               /* 0x04: collapse countdown, seconds */
} CfForceFieldState;

typedef struct CfForceFieldMapData
{
    ObjPlacement base;
    s8 rotXByte;       /* 0x18: rotX in 1/256 turns */
    s8 style;          /* 0x19: emitter style index (mod 3) */
    s16 unk1A;
    u8 pad1C[2];
    s16 activeEvent;   /* 0x1E: game bit keeping the field running */
    s16 collapseEvent; /* 0x20: game bit triggering the collapse */
    u8 pad22[0x28 - 0x22];
} CfForceFieldMapData;

/* per-style emitter tuning record in lbl_80322ED8 (3 entries) */
typedef struct CfForceFieldEmitter
{
    int effectId;
    int pad04;
    int angleStep;
    int pad0c;
    int pad10;
    f32 waveScale;
} CfForceFieldEmitter;

STATIC_ASSERT(offsetof(CfForceFieldState, timer) == 0x04);
STATIC_ASSERT(sizeof(CfForceFieldState) == 0x08);
STATIC_ASSERT(offsetof(CfForceFieldMapData, rotXByte) == 0x18);
STATIC_ASSERT(offsetof(CfForceFieldMapData, activeEvent) == 0x1E);
STATIC_ASSERT(offsetof(CfForceFieldMapData, collapseEvent) == 0x20);
STATIC_ASSERT(sizeof(CfForceFieldMapData) == 0x28);
STATIC_ASSERT(offsetof(CfForceFieldEmitter, angleStep) == 0x08);
STATIC_ASSERT(offsetof(CfForceFieldEmitter, waveScale) == 0x14);
STATIC_ASSERT(sizeof(CfForceFieldEmitter) == 0x18);

/* the second collapse jingle is skipped for the placement on this map */
#define CFFORCEFIELD_MAP_SILENT_COLLAPSE 0x47F5E

/* frames the collapse spin-down runs for */
#define CFFORCEFIELD_COLLAPSE_FRAMES 60


extern void Obj_BuildWorldTransformMatrix(u8* obj, f32* mtx, int flags);
extern void PSMTXMultVecSR(f32* mtx, f32* src, f32* dst);


extern int fn_80080150(f32* p);
extern void s16toFloat(f32* p, s16 val);
extern int timerCountDown(f32* p);

extern void storeZeroToFloatParam(f32* p);
extern f32 lbl_803DBE90; /* ring radius scale */
extern int lbl_803DBE94; /* burst position jitter, +/- units */
extern int lbl_803DBE98; /* collapse rotY rate */
extern int lbl_80322ED8[]; /* CfForceFieldEmitter[3] style table */
int cfforcefield_getExtraSize(void) { return sizeof(CfForceFieldState); }

int cfforcefield_getObjectTypeId(void) { return 0x0; }

void cfforcefield_free(void)
{
}

void cfforcefield_render(void)
{
}

void cfforcefield_hitDetect(void)
{
}

void cfforcefield_update(u8* obj)
{
    f32* wavePtr;
    int* stepPtr;
    CfForceFieldEmitter* emitter;
    int angle;
    CfForceFieldMapData* data;
    CfForceFieldState* state;
    int style;
    f32 val;
    int isZero;
    f32 strength;
    f32 z;
    f32 mtx[3][4];
    f32 world[6];
    f32 local[3];

    data = (CfForceFieldMapData*)((GameObject*)obj)->anim.placement;
    state = ((GameObject*)obj)->extra;
    z = 0.0f;
    ((GameObject*)obj)->anim.velocityZ = z;
    ((GameObject*)obj)->anim.velocityY = z;
    ((GameObject*)obj)->anim.velocityX = z;

    if (GameBit_Get(data->activeEvent) != 0)
    {
        if (!state->flags.disabled)
        {
            /* the ring runs at full strength until the collapse timer is
               started, then shrinks with the time left */
            style = data->style % 3;
            val = state->timer;
            isZero = (val != z);
            isZero = !isZero;
            if (isZero)
            {
                strength = 1.0f;
            }
            else
            {
                strength = 0.016666668f * val;
            }

            {
                Obj_BuildWorldTransformMatrix(obj, (f32*)mtx, 0);
                ((GameObject*)obj)->anim.rotZ = (s16)(512.0f * timeDelta + (f32)(s32)((GameObject*)obj)->anim.rotZ);

                angle = -0x7fff;
                emitter = (CfForceFieldEmitter*)((u8*)lbl_80322ED8 + style * 0x18);
                wavePtr = &emitter->waveScale;
                stepPtr = &emitter->angleStep;
                for (; angle < 0x7fff; angle += *stepPtr)
                {
                    local[0] = (f32)(int)randomGetRange(-lbl_803DBE94, lbl_803DBE94)
                             + 10.0f * (strength * lbl_803DBE90)
                                   * mathCosf(3.1415927f * (f32)(angle + (s32)(100.0f * *wavePtr)) / 32768.0f);
                    local[1] = (f32)(int)randomGetRange(-lbl_803DBE94, lbl_803DBE94)
                             + 10.0f * (strength * lbl_803DBE90)
                                   * mathSinf(3.1415927f * (f32)(angle + (s32)(100.0f * *wavePtr)) / 32768.0f);
                    local[2] = 0.0f;
                    PSMTXMultVecSR((f32*)mtx, local, local);
                    /* burst target = ring point in world space; the burst
                       inherits the field's velocity (obj + 0x24) */
                    world[3] = local[0] + ((GameObject*)obj)->anim.localPosX;
                    world[4] = local[1] + ((GameObject*)obj)->anim.localPosY;
                    world[5] = local[2] + ((GameObject*)obj)->anim.localPosZ;
                    (*gPartfxInterface)->spawnObject(obj, emitter->effectId, world, 0x200001, -1, obj + 0x24);
                    (*gPartfxInterface)->spawnObject(obj, emitter->effectId, world, 0x200001, -1, obj + 0x24);
                    (*gPartfxInterface)->spawnObject(obj, emitter->effectId, world, 0x200001, -1, obj + 0x24);
                }
            }

            if (fn_80080150(&state->timer) != 0)
            {
                ((GameObject*)obj)->anim.rotY = (s16)((f32)(s32)lbl_803DBE98 * timeDelta + (f32)(s32)((GameObject*)obj)->anim.rotY);
                if (timerCountDown(&state->timer) != 0)
                {
                    state->flags.disabled = 1;
                    ((GameObject*)obj)->anim.rotY = 0;
                }
            }
            else if (GameBit_Get(data->collapseEvent) != 0)
            {
                s16toFloat(&state->timer, CFFORCEFIELD_COLLAPSE_FRAMES);
                Sfx_PlayFromObject((int)obj, SFXTRIG_en_littletink22); /* field power-down */
                if (((CfForceFieldMapData*)((GameObject*)obj)->anim.placement)->base.mapId != CFFORCEFIELD_MAP_SILENT_COLLAPSE)
                {
                    Sfx_PlayFromObject((int)obj, SFXTRIG_sc_menuups16k_409); /* collapse jingle */
                }
            }
        }
        else
        {
            state->flags.disabled = GameBit_Get(data->collapseEvent);
        }
    }
}

void cfforcefield_init(GameObject* obj, CfForceFieldMapData* data)
{
    register CfForceFieldState* state = obj->extra;
    {
        s8 v = data->rotXByte;
        s16 t = v << 8;
        obj->anim.rotX = t;
    }
    state->flags.disabled = GameBit_Get(data->collapseEvent);
    storeZeroToFloatParam(&state->timer);
}

void cfforcefield_release(void)
{
}

void cfforcefield_initialise(void)
{
}
