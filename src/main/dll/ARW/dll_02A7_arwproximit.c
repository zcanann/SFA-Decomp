/*
 * arwproximit (DLL 0x2A7) - a proximity mine in the on-rails Arwing
 * sections. It spins in place and walks through a small phase machine
 * (state->phase): dormant until the Arwing approaches (phase 0), then it
 * spawns a glowing green light and fades in (phase 1); when the Arwing gets
 * closer the light turns red and a warning countdown starts (phase 2); on
 * timeout or a direct hit it detonates and arms its blast hitbox (phase 3),
 * then disables and frees the light (phase 4). It can also be destroyed
 * early by a player shot. The placement's textVariant selects which warning
 * / taunt text lines are shown.
 */
#include "main/dll/dll_80220608_shared.h"
#include "main/game_object.h"


typedef struct ARWProximitSetup
{
    u8 pad00[0x31];
    u8 textVariant;
} ARWProximitSetup;

typedef struct ARWProximitState
{
    s16 spinSpeed;
    u8 pad02[2];
    void* light;
    u8 pad08[4];
    f32 warningTimer;
    f32 despawnTimer;
    u8 phase;
    u8 textVariant;
    u8 pad16[2];
} ARWProximitState;

STATIC_ASSERT(sizeof(ARWProximitState) == 0x18);
STATIC_ASSERT(offsetof(ARWProximitState, spinSpeed) == 0x00);
STATIC_ASSERT(offsetof(ARWProximitState, light) == 0x04);
STATIC_ASSERT(offsetof(ARWProximitState, warningTimer) == 0x0c);
STATIC_ASSERT(offsetof(ARWProximitState, despawnTimer) == 0x10);
STATIC_ASSERT(offsetof(ARWProximitState, phase) == 0x14);
STATIC_ASSERT(offsetof(ARWProximitState, textVariant) == 0x15);
STATIC_ASSERT(offsetof(ARWProximitSetup, textVariant) == 0x31);

enum ArwProximitPhase
{
    ARWPROXIMIT_PHASE_DORMANT = 0,  /* hidden, waiting for the Arwing */
    ARWPROXIMIT_PHASE_FADEIN = 1,   /* light spawned, alpha fading in */
    ARWPROXIMIT_PHASE_WARNING = 2,  /* light turned red, countdown running */
    ARWPROXIMIT_PHASE_DETONATE = 3, /* exploded, blast hitbox active */
    ARWPROXIMIT_PHASE_DONE = 4      /* disabled, light freed */
};

int arwproximit_getExtraSize(void) { return 0x18; }

int arwproximit_getObjectTypeId(void) { return 0; }

void arwproximit_free(int obj)
{
    ARWProximitState* state = ((GameObject*)obj)->extra;
    if (state->light != NULL)
    {
        ModelLightStruct_free(state->light);
        state->light = NULL;
    }
}

void arwproximit_render(int obj, int p2, int p3, int p4, int p5, f32 scale)
{
    ARWProximitState* state = ((GameObject*)obj)->extra;
    if (state->light != NULL && modelLightStruct_getActiveState(state->light) != 0)
    {
        queueGlowRender(state->light);
    }
    objRenderFn_8003b8f4(obj, p2, p3, p4, p5, lbl_803E71E4);
}

void arwproximit_hitDetect(void)
{
}

void arwproximit_update(int obj)
{
    ObjAnimComponent* objAnim = &((GameObject*)obj)->anim;
    ARWProximitState* state = ((GameObject*)obj)->extra;

    if (state->textVariant == 1)
    {
        GameObject* arwing = (GameObject*)getArwing();
        if (arwing == NULL)
            arwing = (GameObject*)Obj_GetPlayerObject();
        if (Vec_distance((int)&objAnim->worldPosX, (int)&arwing->anim.worldPosX) < gArwProximityTauntDistance)
        {
            gameTextFn_80125ba4(0xb);
            state->textVariant = 0;
        }
    }

    switch (state->phase)
    {
    case ARWPROXIMIT_PHASE_DORMANT:
        {
            GameObject* arwing = (GameObject*)getArwing();
            if (arwing == NULL)
                arwing = (GameObject*)Obj_GetPlayerObject();
            if (Vec_distance((int)&objAnim->worldPosX, (int)&arwing->anim.worldPosX) < gArwProximityActivateDistance)
            {
                state->light = objCreateLight(obj, 1);
                if (state->light != NULL)
                {
                    modelLightStruct_setLightKind(state->light, MODEL_LIGHT_KIND_POINT);
                    modelLightStruct_setPosition(state->light, lbl_803E71D8, *(f32*)&lbl_803E71D8,
                                                 lbl_803E71F0);
                    modelLightStruct_setDiffuseColor(state->light, 0, 0xff, 0, 0);
                    modelLightStruct_setDiffuseTargetColor(state->light, 0, 0, 0, 0);
                    modelLightStruct_setDistanceAttenuation(state->light, lbl_803E71F0, lbl_803E71F4);
                    modelLightStruct_setupGlow(state->light, 0, 0, 0xff, 0, 0x64, lbl_803E71F8);
                    modelLightStruct_setGlowProjectionRadius(state->light, lbl_803E71F0);
                }
                ObjHits_EnableObject(obj);
                ObjHits_MarkObjectPositionDirty(obj);
                ((GameObject*)obj)->anim.flags &= ~OBJANIM_FLAG_HIDDEN;
                state->phase = ARWPROXIMIT_PHASE_FADEIN;
            }
            return;
        }
    case ARWPROXIMIT_PHASE_FADEIN:
    default:
        {
            GameObject* arwing;
            int alpha = (int)
            (gArwProximityFadeInRate * timeDelta + (f32)(u32)
            objAnim->alpha
            )
            ;
            if (alpha > 0xff)
                alpha = 0xff;
            objAnim->alpha = alpha;
            arwing = (GameObject*)getArwing();
            if (arwing == NULL)
                arwing = (GameObject*)Obj_GetPlayerObject();
            if (Vec_distance((int)&objAnim->worldPosX, (int)&arwing->anim.worldPosX) < gArwProximityWarningDistance)
            {
                if (state->light != NULL)
                {
                    modelLightStruct_setDiffuseColor(state->light, 0xff, 0, 0, 0);
                    modelLightStruct_setGlowColor(state->light, 0xff, 0, 0, 0x64);
                    modelLightStruct_startColorFade(state->light, 2, 0xa);
                }
                s16toFloat((void*)&state->warningTimer, 0x3c);
                state->phase = ARWPROXIMIT_PHASE_WARNING;
                if (state->textVariant == 2)
                {
                    if (randomGetRange(0, 1) != 0)
                        gameTextFn_80125ba4(0xf);
                    else
                        gameTextFn_80125ba4(0xc);
                }
            }
            break;
        }
    case ARWPROXIMIT_PHASE_WARNING:
        {
            u8 r, g, b, a;
            objAnim->alpha = 0xff;
            if (state->light != NULL)
            {
                modelLightStruct_getDiffuseColor(state->light, &r, &g, &b, &a);
                modelLightStruct_setGlowColor(state->light, r, g, b, 0x64);
            }
            if (timerCountDown((void*)&state->warningTimer) != 0 ||
                ((*(ObjHitsPriorityState**)&((GameObject*)obj)->anim.hitReactState)->lastHitObject != 0 &&
                    (*(ObjHitsPriorityState**)&((GameObject*)obj)->anim.hitReactState)->lastHitObject == getArwing()))
            {
                storeZeroToFloatParam((void*)&state->warningTimer);
                s16toFloat((void*)&state->despawnTimer, 0x14);
                if (state->light != NULL)
                    modelLightStruct_setEnabled(state->light, 0, lbl_803E71D8);
                spawnExplosion(obj, lbl_803E71E0, 1, 0, 1, 1, 0, 0, 1);
                ObjHitbox_SetSphereRadius(obj, 0x12c);
                ObjHits_SetHitVolumeSlot(obj, 5, 1, 0);
                ((GameObject*)obj)->anim.flags |= OBJANIM_FLAG_HIDDEN;
                ObjHits_MarkObjectPositionDirty(obj);
                state->phase = ARWPROXIMIT_PHASE_DETONATE;
            }
            break;
        }
    case ARWPROXIMIT_PHASE_DETONATE:
        if (timerCountDown((void*)&state->despawnTimer) != 0)
        {
            ObjHits_DisableObject(obj);
            state->phase = ARWPROXIMIT_PHASE_DONE;
        }
        break;
    case ARWPROXIMIT_PHASE_DONE:
        if (state->light != NULL)
        {
            ModelLightStruct_free(state->light);
            state->light = NULL;
        }
        return;
    }

    if (state->phase == ARWPROXIMIT_PHASE_FADEIN || state->phase == ARWPROXIMIT_PHASE_WARNING)
    {
        if (ObjHits_GetPriorityHit(obj, 0, 0, 0) != 0)
        {
            arwarwing_addScore(getArwing(), 0xa);
            if (state->textVariant == 3)
                gameTextFn_80125ba4(0xe);
            if (state->light != NULL)
                modelLightStruct_setEnabled(state->light, 0, lbl_803E71D8);
            spawnExplosion(obj, lbl_803E71DC, 1, 0, 0, 0, 0, 0, 1);
            ObjHits_DisableObject(obj);
            ((GameObject*)obj)->anim.flags |= OBJANIM_FLAG_HIDDEN;
            ObjHits_MarkObjectPositionDirty(obj);
            state->phase = ARWPROXIMIT_PHASE_DONE;
        }
        ((GameObject*)obj)->anim.rotZ =
            timeDelta * state->spinSpeed + (f32)((GameObject*)obj)->anim.rotZ;
        ((GameObject*)obj)->anim.rotY =
            timeDelta * state->spinSpeed + (f32)((GameObject*)obj)->anim.rotY;
    }

    if (state->light != NULL && modelLightStruct_getActiveState(state->light) != 0)
        modelLightStruct_updateGlowAlpha(state->light);
}

void arwproximit_init(int obj, int setup, int p3)
{
    ObjAnimComponent* objAnim = &((GameObject*)obj)->anim;
    ARWProximitState* state = ((GameObject*)obj)->extra;
    ARWProximitSetup* mapData = (ARWProximitSetup*)setup;

    state->spinSpeed = randomGetRange(0x64, 0x12c);
    state->textVariant = mapData->textVariant;
    if (p3 == 0)
    {
        ((GameObject*)obj)->anim.rotY = randomGetRange(0, 0xffff);
        ((GameObject*)obj)->anim.rotZ = randomGetRange(0, 0xffff);
        ((GameObject*)obj)->anim.rotX = randomGetRange(0, 0xffff);
        ((GameObject*)obj)->anim.flags |= OBJANIM_FLAG_HIDDEN;
        objAnim->alpha = 0;
    }
    storeZeroToFloatParam((void*)&state->warningTimer);
    storeZeroToFloatParam((void*)&state->despawnTimer);
    ObjHits_DisableObject(obj);
    ObjHits_MarkObjectPositionDirty(obj);
}

void arwproximit_release(void)
{
}

void arwproximit_initialise(void)
{
}
