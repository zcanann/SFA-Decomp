/*
 * cmbsrc (DLL 0x02B1) - a "combustible source": a placed light/effect
 * emitter (campfire, thruster vent, T-wall/T-pole flame) that glows,
 * pulses, cycles colour and spawns particles while active.
 *
 * Activation is gated three ways (cmbsrc_shouldActivate /
 * cmbsrc_shouldDeactivate): an optional game bit, the Thorntail-gate
 * sun-position test, and a hit-charge timer. While active the object
 * drives a ModelLight (diffuse/specular/glow), emits light pulses and
 * particles, and keeps a looped object sound alive. The hit logic
 * (cmbsrc_hitDetect) lets the source be damaged/recharged, clamping
 * hit charge to [0, CMBSRC_MAX_HIT_CHARGE].
 *
 * Per-instance behaviour is driven by the placement's flags /
 * behaviorFlags / seqId (CMBSRC_MAP_*, CMBSRC_BEHAVIOR_*, CMBSRC_SEQ_*)
 * defined in dll_02B1_cmbsrc.h.
 */
#include "main/dll/dll_80220608_shared.h"
#include "main/dll/dll_02B1_cmbsrc.h"

int cmbsrc_getExtraSize(void) { return CMBSRC_EXTRA_STATE_BYTES; }

int cmbsrc_getObjectTypeId(void) { return 0; }

void cmbsrc_initialise(void)
{
}

void cmbsrc_release(void)
{
}

int cmbsrc_updateAndReturnZero(int obj)
{
    cmbsrc_update(obj);
    return 0;
}

int cmbsrc_getColorIndex(int obj)
{
    CmbSrcObject* cmbsrc = (CmbSrcObject*)obj;
    CmbSrcState* state = cmbsrc->state;
    CmbSrcMapData* setup = (CmbSrcMapData*)cmbsrc->objAnim.placementData;

    if (setup->colorIndex == CMBSRC_MODE_COLOR_CYCLE)
    {
        int colorIndex = state->colorCycleIndex;
        return (s8)colorIndex;
    }
    return -1;
}

void cmbsrc_setExternalActive(int obj, u8 active)
{
    CmbSrcState* state = ((CmbSrcObject*)obj)->state;

    if (active != 0)
    {
        state->flags |= CMBSRC_STATE_EXTERNAL_ACTIVE;
    }
    else
    {
        state->flags &= ~CMBSRC_STATE_EXTERNAL_ACTIVE;
    }
}

void cmbsrc_free(int obj)
{
    CmbSrcState* state;
    CmbSrcObject* cmbsrc = (CmbSrcObject*)obj;
    state = cmbsrc->state;

    (*gExpgfxInterface)->freeSource(obj);
    if (state->light != NULL)
    {
        ModelLightStruct_free(state->light);
    }
    Sfx_StopObjectChannel((int)cmbsrc, CMBSRC_LOOP_SOUND_CHANNEL);
}

void cmbsrc_render(int obj, int p2, int p3, int p4, int p5, s8 visible)
{
    CmbSrcObject* cmbsrc = (CmbSrcObject*)obj;
    CmbSrcState* state = cmbsrc->state;
    CmbSrcMapData* setup = (CmbSrcMapData*)cmbsrc->objAnim.placementData;

    if (visible != 0)
    {
        state->flags |= CMBSRC_STATE_RENDERED;
        if (state->light != NULL && ((CmbSrcLight*)state->light)->glowType != 0 &&
            ((CmbSrcLight*)state->light)->enabled != 0)
        {
            queueGlowRender(state->light);
        }
        if ((setup->flags & CMBSRC_MAP_RENDER_MODEL) != 0)
        {
            objRenderFn_8003b8f4(obj, p2, p3, p4, p5, lbl_803E738C);
        }
    }
}

int cmbsrc_shouldActivate(int obj, int state, int setup)
{
    CmbSrcState* sourceState = (CmbSrcState*)state;
    CmbSrcMapData* mapData = (CmbSrcMapData*)setup;
    int result = 0;
    f32 sunTime;

    if (sourceState->light != NULL && modelLightStruct_getActiveState(sourceState->light) != 0)
    {
        return 0;
    }
    if (mapData->gameBit != -1 && GameBit_Get(mapData->gameBit) != 0)
    {
        result = 1;
    }
    else if ((sourceState->flags & CMBSRC_STATE_THORNTAIL_GATE) != 0 &&
        (*gSkyInterface)->getSunPosition(&sunTime) != 0)
    {
        result = 1;
    }
    if ((mapData->behaviorFlags & CMBSRC_BEHAVIOR_HIT_MODE_MASK) == 0x10)
    {
        f32 timer = sourceState->inactiveTimer;
        f32 limit = lbl_803E7360;
        if (timer != limit)
        {
            sourceState->inactiveTimer = timer - timeDelta;
            if (sourceState->inactiveTimer <= limit)
            {
                result = 1;
            }
        }
    }
    return result;
}

int cmbsrc_shouldDeactivate(int obj, int state, int setup)
{
    CmbSrcState* sourceState = (CmbSrcState*)state;
    CmbSrcMapData* mapData = (CmbSrcMapData*)setup;
    int result = 0;
    f32 sunTime;

    if (sourceState->light != NULL && modelLightStruct_getActiveState(sourceState->light) != 2)
    {
        return 0;
    }
    if (mapData->gameBit != -1 && GameBit_Get(mapData->gameBit) == 0)
    {
        result = 1;
    }
    else if ((sourceState->flags & CMBSRC_STATE_THORNTAIL_GATE) != 0 &&
        (*gSkyInterface)->getSunPosition(&sunTime) == 0)
    {
        result = 1;
    }
    else if (sourceState->hitCharge == 0)
    {
        sourceState->inactiveTimer = (f32)(u32)sourceState->inactiveFrameCount;
        result = 1;
    }
    return result;
}

void cmbsrc_hitDetect(int obj)
{
    CmbSrcObject* cmbsrc = (CmbSrcObject*)obj;
    CmbSrcMapData* setup = (CmbSrcMapData*)cmbsrc->objAnim.placementData;
    CmbSrcState* state = cmbsrc->state;
    int v;

    state->priorityHitType = 0;
    if ((setup->behaviorFlags & CMBSRC_BEHAVIOR_HIT_MODE_MASK) != 0)
    {
        state->priorityHitType = ObjHits_GetPriorityHit(obj, 0, 0, 0);
        if (state->priorityHitType == CMBSRC_HIT_TYPE_DAMAGE)
        {
            state->hitCharge -= 1;
            state->hitRecoverTimer = lbl_803E7384;
        }
        {
            f32 timer = state->hitRecoverTimer;
            f32 limit = lbl_803E7360;
            if (timer != limit)
            {
                state->hitRecoverTimer = timer - timeDelta;
                if (state->hitRecoverTimer <= limit)
                {
                    state->hitCharge += 1;
                    state->hitRecoverTimer = lbl_803E7384;
                }
            }
        }
        v = state->hitCharge;
        if (v < 0)
        {
            v = 0;
        }
        else if (v > CMBSRC_MAX_HIT_CHARGE)
        {
            v = CMBSRC_MAX_HIT_CHARGE;
        }
        state->hitCharge = v;
    }
}

int cmbsrc_cycleColor(int obj, int state)
{
    extern void modelLightStruct_setDiffuseTargetColor(ModelLight* light, int r, int g, int b, int a); /* #57 */
    CmbSrcObject* cmbsrc = (CmbSrcObject*)obj;
    CmbSrcState* sourceState = (CmbSrcState*)state;
    CmbSrcMapData* setup = (CmbSrcMapData*)cmbsrc->objAnim.placementData;
    int idx;

    sourceState->colorCycleTimer -= timeDelta;
    if (sourceState->colorCycleTimer <= lbl_803E7360)
    {
        sourceState->colorCycleTimer = lbl_803E7364;
        sourceState->colorCycleIndex += 1;
        if (sourceState->colorCycleIndex >= CMBSRC_COLOR_CYCLE_COUNT)
        {
            sourceState->colorCycleIndex = 0;
        }
        idx = gCmbsrcColorCycleIndexTable[sourceState->colorCycleIndex];
        if (sourceState->light != NULL)
        {
            modelLightStruct_setDiffuseColor(sourceState->light, gCmbsrcColorRgbTable[idx * 3],
                                             gCmbsrcColorRgbTable[idx * 3 + 1], gCmbsrcColorRgbTable[idx * 3 + 2], 0xff);
            modelLightStruct_setSpecularColor(sourceState->light, gCmbsrcColorRgbTable[idx * 3],
                                              gCmbsrcColorRgbTable[idx * 3 + 1], gCmbsrcColorRgbTable[idx * 3 + 2], 0xff);
            modelLightStruct_setDiffuseTargetColor(sourceState->light,
                                                   (int)(lbl_803E7368 * (f32)(u32)gCmbsrcColorRgbTable[idx * 3]),
                                                   (int)(lbl_803E7368 * (f32)(u32)gCmbsrcColorRgbTable[idx * 3 + 1]),
                                                   (int)(lbl_803E7368 * (f32)(u32)gCmbsrcColorRgbTable[idx * 3 + 2]),
                                                   0xff);
            if (setup->flags & CMBSRC_MAP_GLOW)
            {
                if (setup->flags & CMBSRC_MAP_GLOW_LARGE)
                {
                    modelLightStruct_setupGlow(sourceState->light, 0, gCmbsrcColorRgbTable[idx * 3], gCmbsrcColorRgbTable[idx * 3 + 1],
                                               gCmbsrcColorRgbTable[idx * 3 + 2], 0x87,
                                               lbl_803E736C * cmbsrc->objAnim.rootMotionScale);
                }
                else
                {
                    modelLightStruct_setupGlow(sourceState->light, 0, gCmbsrcColorRgbTable[idx * 3], gCmbsrcColorRgbTable[idx * 3 + 1],
                                               gCmbsrcColorRgbTable[idx * 3 + 2], 0x87,
                                               lbl_803E7370 * cmbsrc->objAnim.rootMotionScale);
                }
            }
        }
    }
    else
    {
        idx = gCmbsrcColorCycleIndexTable[sourceState->colorCycleIndex];
    }
    return idx;
}

void cmbsrc_updateVisuals(int obj, int state)
{
    CmbSrcObject* cmbsrc = (CmbSrcObject*)obj;
    CmbSrcState* sourceState = (CmbSrcState*)state;
    CmbSrcMapData* setup = (CmbSrcMapData*)cmbsrc->objAnim.placementData;
    int colorIdx = 0;
    int effectMode = 0;
    int subMode = 0;
    int viewSlot;
    f32 dist;
    f32 vec[3];
    f32 param[6];

    viewSlot = Camera_GetCurrentViewSlot();
    if (sourceState->active == 0)
    {
        sourceState->radius = lbl_803E7374 * setup->radius;
    }
    else
    {
        f32 fullRadius = lbl_803E7374 * setup->radius;
        f32 radiusScaled;
        sourceState->radius += interpolate(
            sourceState->hitCharge / lbl_803E7378 *
            (fullRadius - (radiusScaled = setup->radius * lbl_803E737C)) +
            radiusScaled - sourceState->radius,
            lbl_803E7380, timeDelta);
    }
    dist = Vec_distance(viewSlot + 0x44, obj + 0x18);
    if (sourceState->active == 1)
    {
        if (dist <= (f32)(u32)(setup->colorDistance << 3))
        {
            if (setup->colorIndex == CMBSRC_MODE_COLOR_CYCLE)
            {
                extern u8 cmbsrc_cycleColor(int obj, int state); /* #11 */
                colorIdx = cmbsrc_cycleColor(obj, state);
            }
            else
            {
                colorIdx = setup->colorIndex;
            }
        }
    }
    sourceState->effectTimer -= timeDelta;
    sourceState->pulseTimer -= timeDelta;
    if (sourceState->effectTimer <= lbl_803E7360)
    {
        if (setup->effectMode < CMBSRC_EFFECT_MODE_COUNT)
        {
            if (dist <= (f32)(u32)(setup->effectDistance << 3))
            {
                effectMode = setup->effectMode;
            }
        }
        if (sourceState->active == 0)
        {
            if (dist <= (f32)(u32)(setup->colorDistance << 3) &&
                (sourceState->flags & CMBSRC_STATE_SUPPRESS_IDLE_EFFECT) == 0)
            {
                effectMode = setup->effectMode;
                if (setup->effectMode == 0)
                {
                    effectMode = 2;
                }
            }
            else
            {
                effectMode = 0;
            }
        }
        if (sourceState->active == 1)
        {
            sourceState->effectTimer += lbl_803E7384;
        }
        else
        {
            sourceState->effectTimer += lbl_803E7378;
        }
    }
    if ((cmbsrc->objectFlags & 0x800) || (sourceState->flags & CMBSRC_STATE_EXTERNAL_ACTIVE))
    {
        switch (cmbsrc->objAnim.seqId)
        {
        case CMBSRC_SEQ_THUSTER_SOURCE:
            if (sourceState->active == 1)
            {
                if (dist <= (f32)(u32)(setup->colorDistance << 3))
                {
                    subMode = setup->pulseSubMode;
                }
            }
            objfx_spawnLightPulse(obj, sourceState->radius, colorIdx, effectMode, subMode,
                                  (f32)(u32)setup->pulseDistance / lbl_803E7388, 0);
            break;
        case CMBSRC_SEQ_DEFAULT:
        default:
            if (sourceState->active == 1)
            {
                if (sourceState->pulseTimer <= lbl_803E7360)
                {
                    if (setup->pulseSubMode < CMBSRC_SUBMODE_COUNT)
                    {
                        if (dist <= (f32)(u32)(setup->pulseDistance << 3))
                        {
                            subMode = setup->pulseSubMode;
                        }
                    }
                    sourceState->pulseTimer += lbl_803E738C;
                }
            }
            vec[0] = lbl_803E7360;
            if (cmbsrc->objAnim.seqId == CMBSRC_SEQ_TWALL)
            {
                if (sourceState->active == 0)
                {
                    vec[1] = lbl_803E7390;
                }
                else
                {
                    vec[1] = lbl_803E7394;
                }
            }
            else
            {
                if (sourceState->active == 0)
                {
                    vec[1] = lbl_803E7390;
                }
                else
                {
                    vec[1] = lbl_803E7360;
                }
            }
            vec[2] = *(volatile f32*)&lbl_803E7360;
            fn_80098B18(obj, sourceState->radius, colorIdx, effectMode, subMode, vec);
            break;
        }
    }
    if (sourceState->active == 1 && (setup->behaviorFlags & CMBSRC_BEHAVIOR_ACTIVE_PARTICLES))
    {
        sourceState->particleTimer -= timeDelta;
        if (sourceState->particleTimer <= lbl_803E7360)
        {
            if (cmbsrc->objectFlags & 0x800)
            {
                param[2] = sourceState->radius;
                (*gPartfxInterface)->spawnObject((void*)obj, CMBSRC_PARTICLE_EFFECT_ID, param,
                                                 2, -1, NULL);
            }
            sourceState->particleTimer += lbl_803E7398;
        }
    }
}

int cmbsrc_update(int obj)
{
    extern u8 cmbsrc_shouldDeactivate(int obj, int state, int setup); /* #57 */
    extern u8 cmbsrc_shouldActivate(int obj, int state, int setup); /* #57 */
    CmbSrcObject* cmbsrc = (CmbSrcObject*)obj;
    CmbSrcState* state = cmbsrc->state;
    CmbSrcMapData* setup = (CmbSrcMapData*)cmbsrc->objAnim.placementData;

    switch (state->active)
    {
    case 1:
        if (cmbsrc_shouldDeactivate(obj, (int)state, (int)setup))
        {
            state->active = 0;
            if (state->light != NULL)
            {
                modelLightStruct_setEnabled(state->light, 0, lbl_803E7374);
            }
            if (setup->flags & CMBSRC_MAP_LOOP_SOUND)
            {
                Sfx_StopObjectChannel(obj, CMBSRC_LOOP_SOUND_CHANNEL);
            }
            ObjHits_DisableObject(obj);
            if (setup->gameBit != -1)
            {
                GameBit_Set(setup->gameBit, 0);
            }
        }
        else
        {
            if (setup->flags & CMBSRC_MAP_LOOP_SOUND)
            {
                Sfx_KeepAliveLoopedObjectSound(obj,
                                               gCmbsrcColorSoundIdTable[((CmbSrcMapData*)cmbsrc->objAnim.placementData)->colorIndex]);
            }
            if (state->light != NULL && ((CmbSrcLight*)state->light)->glowType != 0 &&
                ((CmbSrcLight*)state->light)->enabled != 0)
            {
                s16 v = (s16)(((CmbSrcLight*)state->light)->glowAlpha +
                              ((CmbSrcLight*)state->light)->glowAlphaStep);
                if (v < 0)
                {
                    v = 0;
                    ((CmbSrcLight*)state->light)->glowAlphaStep = v;
                }
                else if (v > 0xc)
                {
                    v = (s16)(v + randomGetRange(-0xc, 0xc));
                    if (v > 0xff)
                    {
                        v = 0xff;
                        ((CmbSrcLight*)state->light)->glowAlphaStep = 0;
                    }
                }
                ((CmbSrcLight*)state->light)->glowAlpha = v;
            }
        }
        break;
    case 0:
        if (cmbsrc_shouldActivate(obj, (int)state, (int)setup))
        {
            state->active = 1;
            if (state->light != NULL)
            {
                modelLightStruct_setEnabled(state->light, 1, lbl_803E7374);
            }
            if (!state->hitFlags.disabled)
            {
                ObjHits_EnableObject(obj);
            }
            if (setup->gameBit != -1)
            {
                GameBit_Set(setup->gameBit, 1);
            }
            state->hitCharge = CMBSRC_MAX_HIT_CHARGE;
            state->inactiveTimer = lbl_803E7360;
        }
        break;
    }
    cmbsrc_updateVisuals(obj, (int)state);
}

void cmbsrc_init(int obj, u8* setup)
{
    extern void modelLightStruct_setDiffuseTargetColor(ModelLight* light, int r, int g, int b, int a); /* #57 */
    CmbSrcObject* cmbsrc = (CmbSrcObject*)obj;
    u8* c2;
    u8* c1;
    u8* c0;
    CmbSrcMapData* mapData = (CmbSrcMapData*)setup;
    CmbSrcState* state = cmbsrc->state;
    int lightVariant;

    switch (cmbsrc->objAnim.seqId)
    {
    case CMBSRC_SEQ_THUSTER_SOURCE:
        lightVariant = 1;
        break;
    case CMBSRC_SEQ_DEFAULT:
    default:
        lightVariant = 0;
        break;
    }
    cmbsrc->objAnim.rotZ = (s16)((u8)mapData->rotZ << 8);
    cmbsrc->objAnim.rotY = (s16)((u8)mapData->rotY << 8);
    cmbsrc->objAnim.rotX = (s16)((u8)mapData->rotX << 8);
    state->active = 1;
    state->hitCharge = CMBSRC_MAX_HIT_CHARGE;
    if (mapData->inactiveSeconds == 0)
    {
        state->inactiveFrameCount = CMBSRC_DEFAULT_INACTIVE_FRAMES;
    }
    else
    {
        state->inactiveFrameCount = mapData->inactiveSeconds * 0x3c;
    }
    if (mapData->flags & CMBSRC_MAP_START_ACTIVE)
    {
        state->flags |= CMBSRC_STATE_EXTERNAL_ACTIVE;
    }
    if (mapData->behaviorFlags & CMBSRC_BEHAVIOR_THORNTAIL_GATE)
    {
        state->flags |= CMBSRC_STATE_THORNTAIL_GATE;
    }
    if (mapData->behaviorFlags & CMBSRC_BEHAVIOR_SUPPRESS_IDLE_EFFECT)
    {
        state->flags |= CMBSRC_STATE_SUPPRESS_IDLE_EFFECT;
    }
    if (mapData->flags & CMBSRC_MAP_CREATE_LIGHT)
    {
        f32 sunTime;

        if (state->light == NULL)
        {
            state->light = objCreateLight(obj, 1);
        }
        if (state->light != NULL)
        {
            modelLightStruct_setLightKind(state->light, 2);
            if (cmbsrc->objAnim.seqId == CMBSRC_SEQ_THUSTER_SOURCE)
            {
                modelLightStruct_setPosition(state->light, lbl_803E7360, lbl_803E7360, lbl_803E7360);
            }
            else
            {
                modelLightStruct_setPosition(state->light, lbl_803E7360, lbl_803E73A8, lbl_803E7360);
            }
            modelLightStruct_setDiffuseColor(state->light,
                                             (c0 = &gCmbsrcColorRgbTable[(u8)lightVariant * 0x30])[mapData->colorIndex * 3],
                                             (c1 = c0 + 1)[mapData->colorIndex * 3],
                                             (c2 = c0 + 2)[mapData->colorIndex * 3], 0xff);
            modelLightStruct_setSpecularColor(state->light, c0[mapData->colorIndex * 3],
                                              c1[mapData->colorIndex * 3], c2[mapData->colorIndex * 3], 0xff);
            {
                f32 attn = mapData->behaviorFlags & CMBSRC_BEHAVIOR_WIDE_ATTENUATION ? lbl_803E73AC : lbl_803E73B0;
                int n = (int)(attn * cmbsrc->objAnim.rootMotionScale);
                modelLightStruct_setDistanceAttenuation(state->light, n, lbl_803E73B4 + n);
            }
            if (state->flags & CMBSRC_STATE_THORNTAIL_GATE)
            {
                if ((*gSkyInterface)->getSunPosition(&sunTime) != 0)
                {
                    modelLightStruct_setEnabled(state->light, 1, lbl_803E7374);
                }
                else
                {
                    modelLightStruct_setEnabled(state->light, 0, lbl_803E7374);
                    state->active = 0;
                }
            }
            modelLightStruct_startColorFade(state->light, 1, 3);
            modelLightStruct_setDiffuseTargetColor(state->light,
                                                   (int)(lbl_803E7368 * (f32)(u32)c0[mapData->colorIndex * 3]),
                                                   (int)(lbl_803E7368 * (f32)(u32)c1[mapData->colorIndex * 3]),
                                                   (int)(lbl_803E7368 * (f32)(u32)c2[mapData->colorIndex * 3]),
                                                   0xff);
            if (mapData->flags & CMBSRC_MAP_AFFECTS_AABB_LIGHT)
            {
                modelLightStruct_setAffectsAabbLightSelection(state->light, 1);
            }
            if (mapData->flags & CMBSRC_MAP_GLOW)
            {
                if (mapData->flags & CMBSRC_MAP_GLOW_LARGE)
                {
                    modelLightStruct_setupGlow(state->light, 0, c0[mapData->colorIndex * 3],
                                               c1[mapData->colorIndex * 3], c2[mapData->colorIndex * 3], 0x87,
                                               lbl_803E73B8 * cmbsrc->objAnim.rootMotionScale);
                }
                else
                {
                    modelLightStruct_setupGlow(state->light, 0, c0[mapData->colorIndex * 3],
                                               c1[mapData->colorIndex * 3], c2[mapData->colorIndex * 3], 0x87,
                                               lbl_803E7370 * cmbsrc->objAnim.rootMotionScale);
                }
            }
            {
                int m = mapData->glowProjectionMode & 0x3;
                if (m == 0)
                {
                    modelLightStruct_setGlowProjectionRadius(state->light, lbl_803E73BC);
                }
                else if (m == 1)
                {
                    modelLightStruct_setGlowProjectionRadius(state->light, lbl_803E7384);
                }
                else if (m == 2)
                {
                    modelLightStruct_setGlowProjectionRadius(state->light, lbl_803E73C0);
                }
                else
                {
                    modelLightStruct_setGlowProjectionRadius(state->light, lbl_803E7360);
                }
            }
            if (mapData->behaviorFlags & CMBSRC_BEHAVIOR_DISABLE_FIELD4D)
            {
                lightSetField4D(state->light, 0);
            }
            else
            {
                lightSetField4D(state->light, 1);
            }
        }
    }
    if (cmbsrc->objAnim.hitReactState != NULL)
    {
        state->hitFlags.disabled = 1;
        ObjHitbox_SetSphereRadius(obj,
                                  (int)(lbl_803E7374 *
                                      (mapData->radius * (cmbsrc->objAnim.rootMotionScale * gCmbsrcColorRadiusScaleTable[mapData->
                                          colorIndex]))));
        if (mapData->flags & CMBSRC_MAP_ENABLE_HIT_VOLUME)
        {
            ObjHits_SetHitVolumeSlot(obj, CMBSRC_HIT_VOLUME_SLOT, 1, 0);
            state->hitFlags.disabled = 0;
        }
        else
        {
            ObjHits_SetHitVolumeSlot(obj, 0, 0, 0);
        }
        if (mapData->behaviorFlags & CMBSRC_BEHAVIOR_SYNC_HIT_POSITION)
        {
            ObjHits_SyncObjectPositionIfDirty(obj);
            state->hitFlags.disabled = 0;
        }
        else
        {
            ObjHits_MarkObjectPositionDirty(obj);
        }
        if (mapData->behaviorFlags & CMBSRC_BEHAVIOR_HIT_MODE_MASK)
        {
            state->hitFlags.disabled = 0;
        }
        if (state->hitFlags.disabled)
        {
            ObjHits_DisableObject(obj);
        }
    }
    state->colorCycleTimer = randomGetRange(0, 0x64);
    state->radius = lbl_803E7374 * mapData->radius;
    cmbsrc->updateCallback = cmbsrc_updateAndReturnZero;
}
