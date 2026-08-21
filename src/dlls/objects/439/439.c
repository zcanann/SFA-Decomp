/*
 * DLL 0x1B7 - shared implementation for the SC_MusicTree and
 * SC_BirchTre object mappings.
 */

#include "dlls/objects/439.h"

#include "dlls/objects/279_AppleOnTree.h"
#include "dlls/objects/438_SC_levelcon.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/math_api.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/frame_timing.h"
#include "main/dll/partfx_interface.h"
#include "main/gamebits_api.h"
#include "main/object_render.h"
#include "main/objHitReact_types.h"
#include "main/objfx.h"
#include "main/objprint_api.h"
#include "main/shader_api.h"
#include "main/vecmath.h"
#include "sys/objects.h"
#include "sys/objects/lifecycle.h"
#include "main/audio/sfx_play_api.h"
#include "main/obj_path.h"
#include "main/objhits.h"

#define SC_MUSIC_TREE_AMBIENT_EFFECT_PHASE_MIN      0x708
#define SC_MUSIC_TREE_AMBIENT_EFFECT_PHASE_MAX      0x1770
#define SC_MUSIC_TREE_AMBIENT_EFFECT_INITIAL_PHASE  1
#define SC_MUSIC_TREE_AMBIENT_EFFECT_GROWTH_END     10
#define SC_MUSIC_TREE_AMBIENT_EFFECT_RIPE_END       40
#define SC_MUSIC_TREE_AMBIENT_EFFECT_FALL_END       50
#define SC_MUSIC_TREE_AMBIENT_EFFECT_LANDED_END     10
#define SC_MUSIC_TREE_AMBIENT_EFFECT_FADE_END       50
#define SC_MUSIC_TREE_AMBIENT_EFFECT_ACCELERATION   -50
#define SC_MUSIC_TREE_AMBIENT_EFFECT_NO_DESPAWN_BIT -1

typedef struct ScMusicTreeAmbientEffectInterface {
    void* pad00[9];
    void (*setPosition)(GameObject* effect, f32* position);
    int (*getAnimState)(GameObject* effect);
} ScMusicTreeAmbientEffectInterface;

STATIC_ASSERT(offsetof(ScMusicTreeAmbientEffectInterface, setPosition) == 0x24);
STATIC_ASSERT(offsetof(ScMusicTreeAmbientEffectInterface, getAnimState) == 0x28);

#define SC_MUSIC_TREE_AMBIENT_EFFECT_INTERFACE(effect)                                                                 \
    (*(ScMusicTreeAmbientEffectInterface**)((GameObject*)(effect))->anim.dll)

/* Striking the three totem trees sets the combo bits watched by SC_levelcon. */
#define SC_MUSIC_TREE_MAP_TOTEM_1 0x30D9C
#define SC_MUSIC_TREE_MAP_TOTEM_2 0x30D9D
#define SC_MUSIC_TREE_MAP_TOTEM_3 0x30D9B

/* These three trees set their respective bits only while the gate bit is active. */
#define SC_MUSIC_TREE_MAP_GATE_1          0x448C2
#define SC_MUSIC_TREE_MAP_GATE_2          0x45178
#define SC_MUSIC_TREE_MAP_GATE_3          0x4517C
#define SC_MUSIC_TREE_GAMEBIT_GATE_1      0xC41
#define SC_MUSIC_TREE_GAMEBIT_GATE_2      0xC43
#define SC_MUSIC_TREE_GAMEBIT_GATE_ACTIVE 0xC44
#define SC_MUSIC_TREE_GAMEBIT_GATE_3      0xC45

/* The low nibble is the burst type passed to the effect helpers. */
#define SC_MUSIC_TREE_FLAG_BURST_TYPE_MASK 0x0F
#define SC_MUSIC_TREE_FLAG_APPROACH_BURST  0x10
#define SC_MUSIC_TREE_FLAG_HIT_ACTIVE      0x20
#define SC_MUSIC_TREE_FLAG_PRIORITY_HIT    0x40
#define SC_MUSIC_TREE_FLAG_SATELLITES      0x80

#define SC_MUSIC_TREE_HIT_EFFECT_MODE  8
#define SC_MUSIC_TREE_HIT_EFFECT_RED   0xFF
#define SC_MUSIC_TREE_HIT_EFFECT_GREEN 0xFF
#define SC_MUSIC_TREE_HIT_EFFECT_BLUE  0x78

void sc_musictree_spawnAmbientEffect(GameObject* obj, ScMusicTreeState* state, int unused, s8 index) {
    ScMusicTreePlacement* placement = (ScMusicTreePlacement*)obj->anim.placementData;
    int pathIndex;
    AppleOnTreePlacement* effectPlacement;

    (void)unused;

    if (Obj_CanSetupObject() != 0) {
        effectPlacement =
            (AppleOnTreePlacement*)Obj_AllocObjectSetup(APPLE_ON_TREE_PLACEMENT_SIZE, APPLE_ON_TREE_OBJECT_ID);
        effectPlacement->base.color[0] = placement->base.color[0];
        effectPlacement->base.color[2] = placement->base.color[2];
        effectPlacement->base.color[1] = placement->base.color[1];
        effectPlacement->base.color[3] = placement->base.color[3] - 10;
        pathIndex = index;
        effectPlacement->base.posX = state->ambientEffectPositions[pathIndex][0];
        effectPlacement->base.posY = state->ambientEffectPositions[pathIndex][1];
        effectPlacement->base.posZ = state->ambientEffectPositions[pathIndex][2];
        effectPlacement->phaseDuration =
            randomGetRange(SC_MUSIC_TREE_AMBIENT_EFFECT_PHASE_MIN, SC_MUSIC_TREE_AMBIENT_EFFECT_PHASE_MAX);
        effectPlacement->initialElapsedTime = SC_MUSIC_TREE_AMBIENT_EFFECT_INITIAL_PHASE;
        effectPlacement->growthEndFraction = SC_MUSIC_TREE_AMBIENT_EFFECT_GROWTH_END;
        effectPlacement->ripeEndFraction = SC_MUSIC_TREE_AMBIENT_EFFECT_RIPE_END;
        effectPlacement->fallEndFraction = SC_MUSIC_TREE_AMBIENT_EFFECT_FALL_END;
        effectPlacement->landedEndFraction = SC_MUSIC_TREE_AMBIENT_EFFECT_LANDED_END;
        effectPlacement->fadeEndFraction = SC_MUSIC_TREE_AMBIENT_EFFECT_FADE_END;
        effectPlacement->waterAccelerationPercent = SC_MUSIC_TREE_AMBIENT_EFFECT_ACCELERATION;
        effectPlacement->despawnGameBit = SC_MUSIC_TREE_AMBIENT_EFFECT_NO_DESPAWN_BIT;
        effectPlacement->unk18 = 0;
        state->ambientEffectHandles[pathIndex] =
            (int)objSetupObject(&effectPlacement->base, 5, -1, -1, obj->anim.parent);
    }
}

void sc_musictree_handleHitObject(GameObject* obj, ScMusicTreeState* state, int unusedEffectType) {
    int ident = ((ObjPlacement*)obj->anim.placementData)->ident;

    (void)unusedEffectType;

    switch (ident) {
    case SC_MUSIC_TREE_MAP_TOTEM_1:
        Sfx_PlayFromObject(obj, SFXTRIG_sdrstp_c);
        Sfx_PlayFromObject(obj, SFXTRIG_gland2_c);
        mainSetBits(SC_LEVEL_CONTROL_GAMEBIT_TOTEM_COMBO_1, 1);
        break;
    case SC_MUSIC_TREE_MAP_TOTEM_2:
        Sfx_PlayFromObject(obj, SFXTRIG_en_sdrstp_c);
        Sfx_PlayFromObject(obj, SFXTRIG_gland2_c);
        mainSetBits(SC_LEVEL_CONTROL_GAMEBIT_TOTEM_COMBO_2, 1);
        break;
    case SC_MUSIC_TREE_MAP_TOTEM_3:
        Sfx_PlayFromObject(obj, SFXTRIG_en_sdrstp_c_12d);
        Sfx_PlayFromObject(obj, SFXTRIG_gland2_c);
        mainSetBits(SC_LEVEL_CONTROL_GAMEBIT_TOTEM_COMBO_3, 1);
        break;
    case SC_MUSIC_TREE_MAP_GATE_1:
        if (mainGetBit(SC_MUSIC_TREE_GAMEBIT_GATE_ACTIVE) != 0) {
            mainSetBits(SC_MUSIC_TREE_GAMEBIT_GATE_1, 1);
        }
        break;
    case SC_MUSIC_TREE_MAP_GATE_2:
        if (mainGetBit(SC_MUSIC_TREE_GAMEBIT_GATE_ACTIVE) != 0) {
            mainSetBits(SC_MUSIC_TREE_GAMEBIT_GATE_2, 1);
        }
        break;
    case SC_MUSIC_TREE_MAP_GATE_3:
        if (mainGetBit(SC_MUSIC_TREE_GAMEBIT_GATE_ACTIVE) != 0) {
            mainSetBits(SC_MUSIC_TREE_GAMEBIT_GATE_3, 1);
        }
        break;
    }
    state->animationStep = 0.0225f;
}

int sc_musictree_getExtraSize(void) {
    return sizeof(ScMusicTreeState);
}

int sc_musictree_getObjectTypeId(void) {
    return 0;
}

void sc_musictree_free(void) {
}

void sc_musictree_render(GameObject* obj, int renderArg2, int renderArg3, int renderArg4, int renderArg5, s8 visible) {
    ScMusicTreePlacement* placement = (ScMusicTreePlacement*)obj->anim.placementData;
    ScMusicTreeState* stateCursor = obj->extra;
    int i;

    if (visible == 0) {
        return;
    }
    objSetColorFilter(placement->colorR, placement->colorG, placement->colorB);
    objRenderModelAndHitVolumes(obj, renderArg2, renderArg3, renderArg4, renderArg5, 1.0f);
    if ((stateCursor->flags & SC_MUSIC_TREE_FLAG_SATELLITES) != 0) {
        for (i = 0; i < SC_MUSIC_TREE_AMBIENT_EFFECT_COUNT; i++) {
            ObjPath_GetPointWorldPosition(obj, i, &stateCursor->ambientEffectPositions[0][0],
                                          &stateCursor->ambientEffectPositions[0][1],
                                          &stateCursor->ambientEffectPositions[0][2], 0);
            stateCursor = (ScMusicTreeState*)&stateCursor->ambientEffectPositions[0][0];
        }
    }
    obj->userData2 = 1;
}

void sc_musictree_hitDetect(void) {
}

void sc_musictree_update(GameObject* obj) {
    ScMusicTreeState* state = obj->extra;
    ObjAnimEventList animEvents;
    PartFxSpawnParams effectParams;
    int hitType;
    GameObject* hitObject;
    int hitSphereIndex;
    u32 hitVolume;
    int i;
    int* ambientEffectCursor;
    int* pathPointCursor;

    ObjAnim_AdvanceCurrentMove(obj, state->animationStep, timeDelta, &animEvents);
    if (state->flags == 0) {
        return;
    }
    if (state->proximityCooldown > 0.0f) {
        state->proximityCooldown = state->proximityCooldown - timeDelta;
    }
    if (state->animationStep > 0.0025f) {
        state->animationStep = state->animationStep - 0.001f;
    }
    if (((state->flags & SC_MUSIC_TREE_FLAG_SATELLITES) != 0) && (obj->userData2 != 0)) {
        for (i = 0, ambientEffectCursor = (int*)state, pathPointCursor = (int*)state;
             i < SC_MUSIC_TREE_AMBIENT_EFFECT_COUNT; i++) {
            if (*(void**)ambientEffectCursor == NULL) {
                sc_musictree_spawnAmbientEffect(obj, state, framesThisStep, i);
            } else {
                int ambientEffectState = SC_MUSIC_TREE_AMBIENT_EFFECT_INTERFACE(*ambientEffectCursor)
                                             ->getAnimState((GameObject*)*ambientEffectCursor);
                if (ambientEffectState > 3) {
                    *ambientEffectCursor = 0;
                } else {
                    SC_MUSIC_TREE_AMBIENT_EFFECT_INTERFACE(*ambientEffectCursor)
                        ->setPosition((GameObject*)*ambientEffectCursor,
                                      (f32*)((char*)pathPointCursor +
                                             offsetof(ScMusicTreeState, ambientEffectPositions)));
                }
            }
            ambientEffectCursor = (int*)((char*)ambientEffectCursor + sizeof(*ambientEffectCursor));
            pathPointCursor = (int*)((char*)pathPointCursor + sizeof(state->ambientEffectPositions[0]));
        }
    }
    if ((state->flags & SC_MUSIC_TREE_FLAG_HIT_ACTIVE) != 0) {
        if ((state->flags & (SC_MUSIC_TREE_FLAG_PRIORITY_HIT | SC_MUSIC_TREE_FLAG_SATELLITES)) != 0) {
            hitType = ObjHits_GetPriorityHitWithPosition(obj, &hitObject, &hitSphereIndex, &hitVolume,
                                                         &effectParams.posX, &effectParams.posY, &effectParams.posZ);
        } else {
            hitType = ObjHits_PollPriorityHitEffectWithCooldown(
                obj, SC_MUSIC_TREE_HIT_EFFECT_MODE, SC_MUSIC_TREE_HIT_EFFECT_RED, SC_MUSIC_TREE_HIT_EFFECT_GREEN,
                SC_MUSIC_TREE_HIT_EFFECT_BLUE, SFXTRIG_swdtest222, &state->hitEffectCooldown);
        }
        if (state->hitCooldown >= 0.0f) {
            state->hitCooldown = state->hitCooldown - timeDelta;
        }
        if ((hitType != 0) && (hitType != OBJHITREACT_COLLISION_SKIP_REACTION) && (state->hitCooldown <= 0.0f)) {
            if ((state->flags & (SC_MUSIC_TREE_FLAG_PRIORITY_HIT | SC_MUSIC_TREE_FLAG_SATELLITES)) != 0) {
                effectParams.posX = effectParams.posX + playerMapOffsetX;
                effectParams.posZ = effectParams.posZ + playerMapOffsetZ;
                objDoHitParticleFx((void*)obj, 0.014f, &effectParams, 1, 0);
                Obj_SetModelColorFadeRecursive(obj, 0xF, 0xC8, 0, 0, 1);
                sc_musictree_handleHitObject(obj, state, state->flags & SC_MUSIC_TREE_FLAG_BURST_TYPE_MASK);
            } else {
                Sfx_PlayFromObject(obj, SFXTRIG_swdtest222);
                Sfx_PlayFromObject(obj, SFXTRIG_gland2_c);
            }
            {
                f32 zero = 0.0f;
                effectParams.posX = zero;
                effectParams.posY = 200.0f * state->effectScale;
                effectParams.posZ = zero;
                objfx_spawnRandomBurst(obj, state->flags & SC_MUSIC_TREE_FLAG_BURST_TYPE_MASK, 0x14, &effectParams,
                                       80.0f * state->effectScale, 0);
            }
            state->animationStep = 0.0225f;
            state->hitCooldown = 20.0f;
            if ((state->flags & SC_MUSIC_TREE_FLAG_SATELLITES) != 0) {
                int* ambientEffect;
                int index;
                for (index = 0, ambientEffect = (int*)state; index < SC_MUSIC_TREE_AMBIENT_EFFECT_COUNT; index++) {
                    int handle = *ambientEffect;
                    if ((u32)handle != 0) {
                        int ambientEffectState =
                            SC_MUSIC_TREE_AMBIENT_EFFECT_INTERFACE(handle)->getAnimState((GameObject*)handle);
                        if (ambientEffectState > 1) {
                            ObjHits_RecordObjectHit((GameObject*)*ambientEffect, obj, 0xE, 1, 0);
                        }
                    }
                    ambientEffect = (int*)((char*)ambientEffect + sizeof(*ambientEffect));
                }
            }
        }
    }
    {
        GameObject* player = Obj_GetPlayerObject();
        f32 deltaX = obj->anim.localPosX - player->anim.localPosX;
        f32 deltaZ = obj->anim.localPosZ - player->anim.localPosZ;
        f32 distance = sqrtf(deltaX * deltaX + deltaZ * deltaZ);
        u16 distanceU16 = distance;
        if (distanceU16 < state->hearRadius) {
            if (((state->flags & SC_MUSIC_TREE_FLAG_APPROACH_BURST) != 0) &&
                (state->previousDistance >= state->hearRadius) && (state->proximityCooldown <= 0.0f)) {
                effectParams.posX = 0.0f;
                effectParams.posY = 0.75f * (200.0f * state->effectScale);
                effectParams.posZ = 0.0f;
                objfx_spawnRandomBurst(obj, state->flags & SC_MUSIC_TREE_FLAG_BURST_TYPE_MASK, 0xA, &effectParams,
                                       80.0f * state->effectScale, 1);
                state->proximityCooldown = 340.0f;
            }
            state->proximityBurstTimer = state->proximityBurstTimer - timeDelta;
            if (state->proximityBurstTimer <= 0.0f) {
                f32* rotatedBurstVector;
                *(rotatedBurstVector = &effectParams.posX) = 0.0f;
                effectParams.posY = 200.0f * state->effectScale;
                effectParams.posZ = 0.0f;
                vecRotateZXY(&obj->anim.rotX, rotatedBurstVector);
                objfx_spawnRandomBurst(obj, state->flags & SC_MUSIC_TREE_FLAG_BURST_TYPE_MASK, 1, &effectParams,
                                       80.0f * state->effectScale, 0);
                state->proximityBurstTimer += 30.0f;
            }
        }
        state->previousDistance = distanceU16;
    }
}

void sc_musictree_init(GameObject* obj, ScMusicTreePlacement* placement) {
    ScMusicTreeState* state = obj->extra;
    ObjAnimEventList animEvents;
    f32 ratio;
    f32 zero;

    state->animationStep = 0.0025f;
    zero = 0.0f;
    state->proximityBurstTimer = zero;
    state->hearRadius = (u16)((u32)placement->hearRadiusHalf << 1);
    state->flags = placement->flags;
    state->proximityCooldown = zero;
    state->effectScale = placement->scale;
    obj->anim.rotZ = (s16)((placement->rotZByte - 0x7F) << 7);
    obj->anim.rotY = (s16)((placement->rotYByte - 0x7F) << 7);
    obj->anim.rotX = (s16)((u32)placement->rotXByte << 8);
    obj->anim.rootMotionScale = 3.6f * placement->scale;
    obj->userData2 = 0;
    obj->objectFlags = (u16)(obj->objectFlags | OBJECT_OBJFLAG_HITDETECT_DISABLED);
    ratio = (f32)(s32)randomGetRange(1, 99) / 100.0f;
    ObjAnim_SetCurrentMove(obj, 0, ratio, 0);
    ObjAnim_AdvanceCurrentMove(obj, 1.0f, 1.0f, &animEvents);
    ObjHitbox_SetCapsuleBounds((ObjAnimComponent*)obj, (s32)(15.0f * state->effectScale), -5, 0xFF);
    if ((state->flags & SC_MUSIC_TREE_FLAG_SATELLITES) != 0) {
        state->flags = state->flags | SC_MUSIC_TREE_FLAG_HIT_ACTIVE;
    }
}

void sc_musictree_release(void) {
}

void sc_musictree_initialise(void) {
}

ObjectDescriptor gSC_MusicTreeObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)sc_musictree_initialise,
    (ObjectDescriptorCallback)sc_musictree_release,
    0,
    (ObjectDescriptorCallback)sc_musictree_init,
    (ObjectDescriptorCallback)sc_musictree_update,
    (ObjectDescriptorCallback)sc_musictree_hitDetect,
    (ObjectDescriptorCallback)sc_musictree_render,
    (ObjectDescriptorCallback)sc_musictree_free,
    (ObjectDescriptorCallback)sc_musictree_getObjectTypeId,
    sc_musictree_getExtraSize,
};
