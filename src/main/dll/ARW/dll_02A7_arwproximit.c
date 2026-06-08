#include "main/dll/dll_80220608_shared.h"
#include "main/game_object.h"
#include "main/objhits_types.h"

#pragma peephole on
#pragma scheduling on

typedef struct ARWProximitSetup {
    u8 pad00[0x31];
    u8 textVariant;
} ARWProximitSetup;

typedef struct ARWProximitState {
    s16 spinSpeed;
    u8 pad02[2];
    void *light;
    u8 pad08[4];
    u8 warningTimer[4];
    u8 despawnTimer[4];
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

int arwproximit_getExtraSize(void) { return 0x18; }
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
int arwproximit_getObjectTypeId(void) { return 0; }
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling off
void arwproximit_free(int obj)
{
    ARWProximitState *state = ((GameObject *)obj)->extra;
    if (state->light != NULL) {
        ModelLightStruct_free(state->light);
        state->light = NULL;
    }
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void arwproximit_render(int obj, int p2, int p3, int p4, int p5, f32 scale)
{
    ARWProximitState *state = ((GameObject *)obj)->extra;
    if (state->light != NULL && modelLightStruct_getActiveState(state->light) != 0) {
        queueGlowRender(state->light);
    }
    objRenderFn_8003b8f4(obj, p2, p3, p4, p5, lbl_803E71E4);
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
void arwproximit_hitDetect(void) {}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void arwproximit_update(int obj)
{
    ObjAnimComponent *objAnim = &((GameObject *)obj)->anim;
    ARWProximitState *state = ((GameObject *)obj)->extra;

    if (state->textVariant == 1) {
        char *arwing = (char *)getArwing();
        if (arwing == NULL)
            arwing = (char *)Obj_GetPlayerObject();
        if (Vec_distance(obj + 0x18, (int)(arwing + 0x18)) < lbl_803E71E8) {
            gameTextFn_80125ba4(0xb);
            state->textVariant = 0;
        }
    }

    switch (state->phase) {
    case 0: {
        char *arwing = (char *)getArwing();
        if (arwing == NULL)
            arwing = (char *)Obj_GetPlayerObject();
        if (Vec_distance(obj + 0x18, (int)(arwing + 0x18)) < lbl_803E71EC) {
            state->light = objCreateLight(obj, 1);
            if (state->light != NULL) {
                modelLightStruct_setLightKind(state->light, 2);
                modelLightStruct_setPosition(state->light, lbl_803E71D8, *(f32 *)&lbl_803E71D8,
                                    lbl_803E71F0);
                modelLightStruct_setDiffuseColor(state->light, 0, 0xff, 0, 0);
                modelLightStruct_setDiffuseTargetColor(state->light, 0, 0, 0, 0);
                modelLightStruct_setDistanceAttenuation(state->light, lbl_803E71F0, lbl_803E71F4);
                modelLightStruct_setupGlow(state->light, 0, 0, 0xff, 0, 0x64, lbl_803E71F8);
                modelLightStruct_setGlowProjectionRadius(state->light, lbl_803E71F0);
            }
            ObjHits_EnableObject(obj);
            ObjHits_MarkObjectPositionDirty(obj);
            ((GameObject *)obj)->anim.flags &= ~OBJANIM_FLAG_HIDDEN;
            state->phase = 1;
        }
        return;
    }
    case 1:
    default: {
        char *arwing;
        int a = (int)(lbl_803E71FC * timeDelta + (f32)(u32)objAnim->alpha);
        if (a > 0xff)
            a = 0xff;
        objAnim->alpha = a;
        arwing = (char *)getArwing();
        if (arwing == NULL)
            arwing = (char *)Obj_GetPlayerObject();
        if (Vec_distance(obj + 0x18, (int)(arwing + 0x18)) < lbl_803E7200) {
            if (state->light != NULL) {
                modelLightStruct_setDiffuseColor(state->light, 0xff, 0, 0, 0);
                modelLightStruct_setGlowColor(state->light, 0xff, 0, 0, 0x64);
                modelLightStruct_startColorFade(state->light, 2, 0xa);
            }
            s16toFloat((void *)state->warningTimer, 0x3c);
            state->phase = 2;
            if (state->textVariant == 2) {
                if (randomGetRange(0, 1) != 0)
                    gameTextFn_80125ba4(0xf);
                else
                    gameTextFn_80125ba4(0xc);
            }
        }
        break;
    }
    case 2: {
        u8 b0, b1, b2, b3;
        objAnim->alpha = 0xff;
        if (state->light != NULL) {
            modelLightStruct_getDiffuseColor(state->light, &b0, &b1, &b2, &b3);
            modelLightStruct_setGlowColor(state->light, b0, b1, b2, 0x64);
        }
        if (timerCountDown((void *)state->warningTimer) != 0 ||
            ((*(ObjHitsPriorityState **)&((GameObject *)obj)->anim.hitReactState)->lastHitObject != 0 &&
             (*(ObjHitsPriorityState **)&((GameObject *)obj)->anim.hitReactState)->lastHitObject == getArwing())) {
            storeZeroToFloatParam((void *)state->warningTimer);
            s16toFloat((void *)state->despawnTimer, 0x14);
            if (state->light != NULL)
                modelLightStruct_setEnabled(state->light, 0, lbl_803E71D8);
            spawnExplosion(obj, lbl_803E71E0, 1, 0, 1, 1, 0, 0, 1);
            ObjHitbox_SetSphereRadius(obj, 0x12c);
            ObjHits_SetHitVolumeSlot(obj, 5, 1, 0);
            ((GameObject *)obj)->anim.flags |= OBJANIM_FLAG_HIDDEN;
            ObjHits_MarkObjectPositionDirty(obj);
            state->phase = 3;
        }
        break;
    }
    case 3:
        if (timerCountDown((void *)state->despawnTimer) != 0) {
            ObjHits_DisableObject(obj);
            state->phase = 4;
        }
        break;
    case 4:
        if (state->light != NULL) {
            ModelLightStruct_free(state->light);
            state->light = NULL;
        }
        return;
    }

    if (state->phase == 1 || state->phase == 2) {
        if (ObjHits_GetPriorityHit(obj, 0, 0, 0) != 0) {
            arwarwing_addScore(getArwing(), 0xa);
            if (state->textVariant == 3)
                gameTextFn_80125ba4(0xe);
            if (state->light != NULL)
                modelLightStruct_setEnabled(state->light, 0, lbl_803E71D8);
            spawnExplosion(obj, lbl_803E71DC, 1, 0, 0, 0, 0, 0, 1);
            ObjHits_DisableObject(obj);
            ((GameObject *)obj)->anim.flags |= OBJANIM_FLAG_HIDDEN;
            ObjHits_MarkObjectPositionDirty(obj);
            state->phase = 4;
        }
        ((GameObject *)obj)->anim.rotZ =
            timeDelta * (f32)state->spinSpeed + (f32)((GameObject *)obj)->anim.rotZ;
        ((GameObject *)obj)->anim.rotY =
            timeDelta * (f32)state->spinSpeed + (f32)((GameObject *)obj)->anim.rotY;
    }

    if (state->light != NULL && modelLightStruct_getActiveState(state->light) != 0)
        modelLightStruct_updateGlowAlpha(state->light);
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void arwproximit_init(int obj, int setup, int p3)
{
    ObjAnimComponent *objAnim = &((GameObject *)obj)->anim;
    ARWProximitState *state = ((GameObject *)obj)->extra;
    ARWProximitSetup *mapData = (ARWProximitSetup *)setup;

    state->spinSpeed = (s16)randomGetRange(0x64, 0x12c);
    state->textVariant = mapData->textVariant;
    if (p3 == 0) {
        ((GameObject *)obj)->anim.rotY = (s16)randomGetRange(0, 0xffff);
        ((GameObject *)obj)->anim.rotZ = (s16)randomGetRange(0, 0xffff);
        ((GameObject *)obj)->anim.rotX = (s16)randomGetRange(0, 0xffff);
        ((GameObject *)obj)->anim.flags |= OBJANIM_FLAG_HIDDEN;
        objAnim->alpha = 0;
    }
    storeZeroToFloatParam((void *)state->warningTimer);
    storeZeroToFloatParam((void *)state->despawnTimer);
    ObjHits_DisableObject(obj);
    ObjHits_MarkObjectPositionDirty(obj);
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
void arwproximit_release(void) {}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
void arwproximit_initialise(void) {}
#pragma scheduling reset
#pragma peephole reset
