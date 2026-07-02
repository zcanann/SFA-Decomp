/*
 * dimbosstonsil (DLL 0x1E2) - the DIM boss tonsil/uvula combat object.
 * Handles the tonsil's state machine (idle, hit-react, defeat), steam-effect
 * anim events, a dynamic point light that flickers in sync with the glowIntensity,
 * and the hit-count route-phase tracking (gDIMbosstonsilRoutePhase) that controls
 * which health phase the tonsil starts in across attempts.
 */
#include "main/mapEvent.h"
#include "main/game_object.h"
#include "main/objseq.h"
#include "main/dll/DIM/DIMbosstonsil.h"
#include "main/dll/baddie_state.h"
#include "main/effect_interfaces.h"
#include "main/player_control_interface.h"
#include "main/gamebits.h"
#include "main/sfa_shared_decls.h"

#define MODEL_LIGHT_KIND_POINT 2

extern void Music_Trigger(int id, int arg);
extern void modelLightStruct_getSpecularColor(void* light, void* red, void* green, void* blue, void* alpha);
extern void modelLightStruct_setGlowColor(void* light, u8 red, u8 green, u8 blue, int alpha);
extern int randomGetRange(int lo, int hi);


extern void skyFn_800895e0(int flags, u8 red, u8 green, u8 blue, u8 m1, u8 m2);
extern void getEnvfxAct(void* obj, void* source, int effectId, int arg);
extern void Sfx_PlayFromObject(void* obj, int sfxId);

extern void ObjGroup_RemoveObject(void* obj, int group);
extern void ModelLightStruct_free(void* light);
extern f32 timeDelta;
extern f32 lbl_803DDB9C;
extern f32 lbl_803DDBA0;
extern f32 lbl_803E4C90;
extern f32 lbl_803E4CB8;
extern f32 lbl_803E4CBC;
extern f32 lbl_803E4CC0;
extern f32 lbl_803E4CC4;
extern void objRenderFn_8003b8f4(void* obj, u32 p2, u32 p3, u32 p4, u32 p5, double scale);
extern void modelLightStruct_setPosition(f32 x, f32 y, f32 z);
extern void queueGlowRender(void* p);
extern void ObjPath_GetPointWorldPosition(void* obj, int idx, void* out0, void* out1, void* out2, int flag);
extern void* Obj_GetPlayerObject(void);
extern f32 lbl_803DDBA4;
extern f32 lbl_803E4CC8;
extern void* objCreateLight(int arg, u8 addToList);
extern void modelLightStruct_setLightKind(void* handle, int kind);
extern void modelLightStruct_setDiffuseColor(void* handle, int r, int g, int b, int a);
extern void modelLightStruct_setSpecularColor(void* handle, int r, int g, int b, int a);
extern void modelLightStruct_setDistanceAttenuation(void* handle, f32 min, f32 max);
extern void lightSetField4D(void* handle, int value);
extern void modelLightStruct_setGlowProjectionRadius(void* handle, f32 radius);
extern void modelLightStruct_setDiffuseTargetColor(void* handle, int r, int g, int b, int a);
extern void modelLightStruct_setSpecularTargetColor(void* handle, int r, int g, int b, int a);
extern void modelLightStruct_startColorFade(void* handle, int from, int to);
extern void modelLightStruct_setAffectsAabbLightSelection(void* handle, int enable);
extern void modelLightStruct_setupGlow(void* handle, int slot, int r, int g, int b, int a, f32 radius);
extern void DIMbosstonsil_updateHitReaction(void);
extern void DIMbosstonsil_enableHitReaction(void);
extern void DIMbosstonsil_chooseHitReaction(void);
extern void DIMbosstonsil_startIdleHitReaction(void);
extern f32 lbl_803DDB98;
extern f32 lbl_803E4C9C;
extern f32 lbl_803E4CA0;
extern f32 lbl_803E4CCC;

int dll_DIM_BossGutSpik_update(void* obj, u32 p2, ObjAnimUpdateState* animUpdate)
{
    extern u8 lbl_803DDBA8;
    extern void* gBaddieControlInterface;
    extern void modelLightStruct_setEnabled(void* light, int enabled, f32 value);
    extern u8 lbl_803DDBB0;
    extern int dimBossTonsil_newState_hitFightMain(void* obj, ObjAnimUpdateState* animUpdate, DIMbosstonsilState* state, DIMbosstonsilState* updateState);
    DIMbosstonsilState* state;
    DIMbosstonsilConfig* config;
    u8 red;
    u8 green;
    u8 blue;
    u8 alpha;
    s16 lightValue;
    int eventIndex;
    int eventId;
    int hitReactMode;
    int animOk;

    state = ((GameObject*)obj)->extra;
    config = *(DIMbosstonsilConfig**)&((GameObject*)obj)->anim.placementData;

    if (gDIMbosstonsilLight != NULL)
    {
        modelLightStruct_getSpecularColor(gDIMbosstonsilLight, &red, &green, &blue, &alpha);
        modelLightStruct_setGlowColor(gDIMbosstonsilLight, red, green, blue, 0xc0);
        if (gDIMbosstonsilLight->active != 0 && gDIMbosstonsilLight->visible != 0)
        {
            lightValue = gDIMbosstonsilLight->glowIntensity + gDIMbosstonsilLight->glowIntensityStep;
            if (lightValue < 0)
            {
                lightValue = 0;
                gDIMbosstonsilLight->glowIntensityStep = 0;
            }
            else if (lightValue > 0xc)
            {
                lightValue = lightValue + randomGetRange(-0xc, 0xc);
                if (lightValue > 0xff)
                {
                    lightValue = 0xff;
                    gDIMbosstonsilLight->glowIntensityStep = 0;
                }
            }
            gDIMbosstonsilLight->glowIntensity = lightValue;
        }
    }

    if (((GameObject*)obj)->unkF4 != 0)
    {
        return 0;
    }

    for (eventIndex = 0; eventIndex < (int)(u32)animUpdate->eventCount; eventIndex++)
    {
        eventId = animUpdate->eventIds[eventIndex];
        switch (eventId)
        {
        case DIMBOSSTONSIL_ANIM_EVENT_START_STEAM:
            skyFn_80089710(7, 1, 0);
            skyFn_800894a8(7, lbl_803E4CC4, *(f32*)&lbl_803E4CC4, lbl_803E4CB8);
            skyFn_800895e0(7, 0xff, 0xb4, 0xb4, 0x7f, 0x28);
            getEnvfxAct(obj, obj, DIMBOSSTONSIL_STEAM_ENVFX, 0);
            Music_Trigger(DIMBOSSTONSIL_STEAM_MUSIC, 1);
            break;
        case DIMBOSSTONSIL_ANIM_EVENT_ENABLE_AREA:
            (*gMapEventInterface)->setObjGroupStatus(DIMBOSSTONSIL_MAP_DIR, DIMBOSSTONSIL_MAP_AREA, 1);
            break;
        case DIMBOSSTONSIL_ANIM_EVENT_DISABLE_AREA:
            (*gMapEventInterface)->setObjGroupStatus(DIMBOSSTONSIL_MAP_DIR, DIMBOSSTONSIL_MAP_AREA, 0);
            break;
        case DIMBOSSTONSIL_ANIM_EVENT_ENABLE_LIGHT:
            if (gDIMbosstonsilLight != NULL)
            {
                modelLightStruct_setEnabled(gDIMbosstonsilLight, 1, lbl_803E4CB8);
            }
            break;
        case DIMBOSSTONSIL_ANIM_EVENT_DISABLE_LIGHT:
            if (gDIMbosstonsilLight != NULL)
            {
                modelLightStruct_setEnabled(gDIMbosstonsilLight, 0, lbl_803E4CB8);
            }
            break;
        }
    }

    if (lbl_803DDBA0 >= lbl_803DDB9C)
    {
        Sfx_PlayFromObject(obj, DIMBOSSTONSIL_RUMBLE_SFX);
        lbl_803DDB9C += lbl_803E4CBC;
        doRumble(lbl_803E4CC0);
    }
    lbl_803DDBA0 += timeDelta;

    if (((GameObject*)obj)->seqIndex != -1)
    {
        animOk = (*(int (**)(void*, DIMbosstonsilState*, int))(*(int*)gBaddieControlInterface + 0x30))
            (obj, state, 1);
        if (animOk == 0)
        {
            return 1;
        }
        if ((state->eventGameBit != -1) &&
            (GameBit_Get(state->eventGameBit) != 0))
        {
            (*gObjectTriggerInterface)->yield((ObjSeqState*)animUpdate, config->eventId);
            state->eventGameBit = -1;
        }

        hitReactMode = state->hitReactMode;
        switch (hitReactMode)
        {
        case 0:
            break;
        case 1:
            goto updateHitReaction;
        case 2:
            animUpdate->hitVolumePair = 0;
            dimBossTonsil_newState_hitFightMain(obj, animUpdate, state, state);
            if (state->hitReactMode == 1)
            {
                state->field270 = 0;
                (*gPlayerInterface)->update(obj, state, lbl_803E4CB8, *(f32*)&lbl_803E4CB8,
                                            &lbl_803DDBB0, &lbl_803DDBA8);
                animUpdate->sequenceEventActive = 0;
            }
            goto updateDone;
        }
        goto clearHitVolumePair;

    updateHitReaction:
        animOk = (*(int (**)(void*, ObjAnimUpdateState*, DIMbosstonsilState*, u8*, u8*, int))
                (*(int*)gBaddieControlInterface + 0x34))
            (obj, animUpdate, state, &lbl_803DDBB0, &lbl_803DDBA8, 0);
        if (animOk != 0)
        {
            (*(void (**)(void*, DIMbosstonsilState*, f32, int))(*(int*)gBaddieControlInterface + 0x2c))
                (obj, state, lbl_803E4C90, 1);
        }
        goto updateDone;

    clearHitVolumePair:
        animUpdate->hitVolumePair = -1;
        animUpdate->hitVolumePair &= ~0x40;

    updateDone:;
    }

    if (((GameObject*)obj)->seqIndex == -1)
    {
        state->stateFlags |= DIMBOSSTONSIL_STATE_FLAG_START_MOVE;
        return 0;
    }

    return 0;
}

void DIMbosstonsil_func0B(void)
{
}

int DIMbosstonsil_setScale(int obj)
{
    return (*(DIMbosstonsilState**)&((GameObject*)obj)->extra)->scale;
}

int DIMbosstonsil_getExtraSize(void)
{
    return DIMBOSSTONSIL_STATE_SIZE;
}

int DIMbosstonsil_getObjectTypeId(void)
{
    return DIMBOSSTONSIL_OBJECT_TYPE;
}

void DIMbosstonsil_free(void* obj)
{
    extern void* gBaddieControlInterface;
    DIMbosstonsilState* state;

    state = ((GameObject*)obj)->extra;
    ObjGroup_RemoveObject(obj, 3);
    (*(void (**)(void*, DIMbosstonsilState*, int))(*(int*)gBaddieControlInterface + 0x40))(obj, state, 1);
    if (gDIMbosstonsilLight != NULL)
    {
        ModelLightStruct_free(gDIMbosstonsilLight);
    }
}

#pragma opt_propagation off
void DIMbosstonsil_render(void* obj, u32 p2, u32 p3, u32 p4, u32 p5, char visible)
{
    struct
    {
        f32 x;
        f32 y;
        f32 z;
    } pathPoint;
    int partfxArgs[3];
    f32* pp;

    if (visible != 0)
    {
        switch (((GameObject*)obj)->unkF4)
        {
        case 0:
            {
                objRenderFn_8003b8f4(obj, p2, p3, p4, p5, (double)lbl_803E4CB8);

                ObjPath_GetPointWorldPosition(obj, 1, (pp = &pathPoint.x), &pathPoint.y, &pathPoint.z, 0);
                (*gPartfxInterface)->spawnObject(obj, 0x4bd, partfxArgs, 0x200001, -1, NULL);

                ObjPath_GetPointWorldPosition(obj, 0, pp, &pathPoint.y, &pathPoint.z, 0);
                (*gPartfxInterface)->spawnObject(obj, 0x4bd, partfxArgs, 0x200001, -1, NULL);

                if (gDIMbosstonsilLight != 0 && gDIMbosstonsilLight->active != 0 && gDIMbosstonsilLight->visible != 0)
                {
                    modelLightStruct_setPosition(pathPoint.x, pathPoint.y, pathPoint.z);
                    queueGlowRender(gDIMbosstonsilLight);
                }
                break;
            }
        }
    }
}
#pragma opt_propagation reset

void DIMbosstonsil_hitDetect(void* obj)
{
    extern int lbl_803DDBB0;
    (*gPlayerInterface)->updateVelocityState(obj, ((GameObject*)obj)->extra, &lbl_803DDBB0);
}

void DIMbosstonsil_update(void* obj)
{
    extern void* gBaddieControlInterface;
    extern int dimBossTonsil_newState_hitFightMain(void* obj, ObjAnimUpdateState* animUpdate, DIMbosstonsilState* state, DIMbosstonsilState* updateState);
    DIMbosstonsilState* state;
    DIMbosstonsilConfig* config;
    u8 red, green, blue, alpha;

    state = ((GameObject*)obj)->extra;
    config = *(DIMbosstonsilConfig**)&((GameObject*)obj)->anim.placementData;

    if (((GameObject*)obj)->unkF4 != 0) return;

    if (((GameObject*)obj)->unkF8 == 0)
    {
        ((GameObject*)obj)->anim.localPosX = config->spawnX;
        ((GameObject*)obj)->anim.localPosY = config->spawnY;
        ((GameObject*)obj)->anim.localPosZ = config->spawnZ;
        (*gObjectTriggerInterface)->runSequence((int)config->animObjId, obj, -1);
        ((GameObject*)obj)->unkF8 = 1;
        return;
    }

    if ((state->stateFlags & DIMBOSSTONSIL_STATE_FLAG_START_MOVE) != 0)
    {
        lbl_803DDBA4 = lbl_803E4CC8;
        (*(void (***)(void*, DIMbosstonsilState*, u8*, int, u8*, int, int, int, int))gBaddieControlInterface)[0xa](
            obj, state, state->animPoints, state->animFrame, &state->hitReactMode, 0, 0, 0, 1);
        state->stateFlags &= ~DIMBOSSTONSIL_STATE_FLAG_START_MOVE;
    }

    if ((*(int (***)(void*, DIMbosstonsilState*, int))gBaddieControlInterface)[0xc](obj, state, 1) == 0) return;

    state->targetObject = Obj_GetPlayerObject();
    dimBossTonsil_newState_hitFightMain(obj, NULL, state, state);

    if (gDIMbosstonsilLight == 0) return;

    modelLightStruct_getSpecularColor(gDIMbosstonsilLight, &red, &green, &blue, &alpha);
    modelLightStruct_setGlowColor(gDIMbosstonsilLight, red, green, blue, 0xc0);

    if (gDIMbosstonsilLight->active == 0) return;
    if (gDIMbosstonsilLight->visible == 0) return;

    {
        s16 r30_local;
        int sum;
        sum = gDIMbosstonsilLight->glowIntensity +
            gDIMbosstonsilLight->glowIntensityStep;
        r30_local = sum;
        if (r30_local < 0)
        {
            r30_local = 0;
            gDIMbosstonsilLight->glowIntensityStep = 0;
        }
        else if (r30_local > 0xc)
        {
            int rnd = randomGetRange(-0xc, 0xc);
            r30_local = (s16)(r30_local + rnd);
            if (r30_local > 0xff)
            {
                r30_local = 0xff;
                gDIMbosstonsilLight->glowIntensityStep = 0;
            }
        }
        gDIMbosstonsilLight->glowIntensity = r30_local;
    }
}

#pragma opt_propagation off
void DIMbosstonsil_init(int obj, u32 p2, int isAltVariant)
{
    extern u32* gBaddieControlInterface;
    extern void modelLightStruct_setEnabled(void* handle, int enable, f32 fade);

    u8 variant;
    int state;

    state = *(int*)&((GameObject*)obj)->extra;
    variant = 6;
    if (isAltVariant != 0)
    {
        variant = variant | 1;
    }
    (*(void (**)(int, u32, int, int, int, int, u8, f32))(*gBaddieControlInterface + 0x58))(obj, p2, state, 2, 2, 0x102, variant, lbl_803E4CCC);
    ((GameObject*)obj)->animEventCallback = dll_DIM_BossGutSpik_update;
    (*gPlayerInterface)->setState((void*)obj, (void*)state, 0);
    ((BaddieState*)state)->substate = 0;
    gDIMbosstonsilRoutePhase = GameBit_Get(0x20c);
    if (gDIMbosstonsilRoutePhase < 3)
    {
        *(s8*)(state + DIMBOSSTONSIL_HEALTH_PHASE_OFFSET) = 3 - gDIMbosstonsilRoutePhase;
    }
    else
    {
        *(s8*)(state + DIMBOSSTONSIL_HEALTH_PHASE_OFFSET) = 7 - gDIMbosstonsilRoutePhase;
    }
    lbl_803DDBA4 = lbl_803E4C90;
    lbl_803DDBA0 = lbl_803E4C90;
    lbl_803DDB98 = lbl_803E4C90;
    lbl_803DDB9C = lbl_803E4C9C;
    gDIMbosstonsilLight = objCreateLight(0, 1);
    if (gDIMbosstonsilLight != 0)
    {
        modelLightStruct_setLightKind(gDIMbosstonsilLight, MODEL_LIGHT_KIND_POINT);
        modelLightStruct_setDiffuseColor(gDIMbosstonsilLight, 0xff, 0, 0, 0x7f);
        modelLightStruct_setSpecularColor(gDIMbosstonsilLight, 0xff, 0, 0, 0x7f);
        modelLightStruct_setDistanceAttenuation(gDIMbosstonsilLight, lbl_803E4C9C, lbl_803E4CA0);
        lightSetField4D(gDIMbosstonsilLight, 1);
        modelLightStruct_setEnabled(gDIMbosstonsilLight, 1, lbl_803E4C90);
        modelLightStruct_setGlowProjectionRadius(gDIMbosstonsilLight, lbl_803E4CA0);
        modelLightStruct_setDiffuseTargetColor(gDIMbosstonsilLight, 0xff, 0x7f, 0, 0x40);
        modelLightStruct_setSpecularTargetColor(gDIMbosstonsilLight, 0xff, 0x7f, 0, 0x40);
        modelLightStruct_startColorFade(gDIMbosstonsilLight, 2, 0x3c);
        modelLightStruct_setAffectsAabbLightSelection(gDIMbosstonsilLight, 1);
        modelLightStruct_setupGlow(gDIMbosstonsilLight, 0, 0xff, 0, 0, 0x7f, lbl_803E4CA0);
    }
    return;
}

void DIMbosstonsil_release(void)
{
}

#pragma opt_propagation reset
void DIMbosstonsil_initialise(void)
{
    extern void (*lbl_803DDBA8[2])(void);
    extern void (*lbl_803DDBB0[2])(void);
    lbl_803DDBB0[0] = DIMbosstonsil_startIdleHitReaction;
    lbl_803DDBB0[1] = DIMbosstonsil_chooseHitReaction;
    lbl_803DDBA8[0] = DIMbosstonsil_enableHitReaction;
    lbl_803DDBA8[1] = DIMbosstonsil_updateHitReaction;
}
