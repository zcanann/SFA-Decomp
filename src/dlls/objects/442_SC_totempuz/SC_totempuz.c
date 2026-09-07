/*
 * SC_totempuz (DLL 0x1BA) controls the spinning LightFoot Village totem
 * puzzle.
 */
#include "dlls/objects/442_SC_totempuz.h"

#include "main/audio/sfx_limited_object_api.h"
#include "main/audio/sfx_play_api.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/frame_timing.h"
#include "main/gamebit_ids.h"
#include "main/gamebits_api.h"
#include "main/dll/partfx_interface.h"
#include "main/obj_list.h"
#include "main/objHitReact_types.h"
#include "main/objfx.h"
#include "main/objhits.h"
#include "main/objtexture.h"
#include "main/object_render.h"
#include "main/shader_api.h"
#include "main/vecmath.h"
#include "main/objseq.h"

/* Exact anim.romDefNo value used by peer scans; this is not the retail object-definition ID. */
#define SC_TOTEM_PUZZLE_SEQUENCE_ID       0x3c1
#define SC_TOTEM_PUZZLE_FLAG_REVERSED     0x1
#define SC_TOTEM_PUZZLE_FLAG_READY        0x2
#define SC_TOTEM_PUZZLE_FLAG_PULSE_ACTIVE 0x4

#define SC_TOTEM_PUZZLE_FORWARD_SOLVED_STEP 4
#define SC_TOTEM_PUZZLE_SOLVED_COUNT        5
#define SC_TOTEM_PUZZLE_CAP_INDEX           5
#define SC_TOTEM_PUZZLE_LAST_STEP_INDEX     7

#define SC_TOTEM_PUZZLE_GAMEBIT_ACTIVATED 0xc10

#define SC_TOTEM_PUZZLE_ANGLE_STEP        8192.0f
#define SC_TOTEM_PUZZLE_SOLVED_TEXTURE_ID 0x100

#define SC_TOTEM_PUZZLE_PARTICLE_COUNT      20
#define SC_TOTEM_PUZZLE_PARTICLE_INDEX      7
#define SC_TOTEM_PUZZLE_PARTICLE_SCALE      2.0f
#define SC_TOTEM_PUZZLE_PARTICLE_KIND       5
#define SC_TOTEM_PUZZLE_PARTICLE_MODE       7
#define SC_TOTEM_PUZZLE_PARTICLE_CHANCE     100
#define SC_TOTEM_PUZZLE_PARTICLE_ANGLE_BASE 25.0f
#define SC_TOTEM_PUZZLE_PARTICLE_ANGLE_LOW  25.0f
#define SC_TOTEM_PUZZLE_PARTICLE_ANGLE_HIGH 30.0f
#define SC_TOTEM_PUZZLE_PARTICLE_FLAGS      0

#define SC_TOTEM_PUZZLE_PULSE_FRAME_MIN 7
#define SC_TOTEM_PUZZLE_PULSE_FRAME_MAX 10
int sc_totempuzzle_animEventCallback(GameObject* unusedObj, int unused, ObjSeqState* unusedAnimUpdate) {
    int r;

    if (mainGetBit(GAMEBIT_SC_totempuzzle_running) != 0) {
        r = 0;
    } else {
        r = 1;
    }
    return r;
}

u8 sc_totempuzzle_checkSolvedSequence(GameObject* obj, ScTotemPuzzleState* state) {
    PartFxSpawnParams particleOrigin;
    int objectIndex;
    int objectCount;
    GameObject** objects;
    int solvedCount;
    u8 solvedThisObject;

    solvedThisObject = 0;
    solvedCount = 0;
    objects = ObjList_GetObjects(&objectIndex, &objectCount);

    while (objectIndex < objectCount) {
        GameObject* peer;
        ScTotemPuzzleState* peerState;
        s16 flags;

        peer = objects[objectIndex];
        if (peer->anim.romDefNo == SC_TOTEM_PUZZLE_SEQUENCE_ID) {
            peerState = peer->extra;
            flags = peerState->flags;
            if ((flags & SC_TOTEM_PUZZLE_FLAG_READY) != 0) {
                if ((flags & SC_TOTEM_PUZZLE_FLAG_REVERSED) != 0) {
                    if (peerState->stepIndex + 1 == SC_TOTEM_PUZZLE_FORWARD_SOLVED_STEP) {
                        solvedCount++;
                        if (peer == obj) {
                            state->angle = SC_TOTEM_PUZZLE_ANGLE_STEP * (f32)(state->stepIndex + 1);
                            obj->anim.rotX = (s16)(s32)state->angle;
                            solvedThisObject = 1;
                        }
                    } else if (peer == obj) {
                        Sfx_PlayFromObject(0, SFXTRIG_lowoxy_beep);
                    }
                } else if (peerState->stepIndex == SC_TOTEM_PUZZLE_FORWARD_SOLVED_STEP) {
                    solvedCount++;
                    if (peer == obj) {
                        state->angle = SC_TOTEM_PUZZLE_ANGLE_STEP * state->stepIndex;
                        obj->anim.rotX = (s16)(s32)state->angle;
                        solvedThisObject = 1;
                    }
                } else if (peer == obj) {
                    Sfx_PlayFromObject(0, SFXTRIG_lowoxy_beep);
                }
            }
        }
        objectIndex++;
    }

    if (solvedThisObject != 0) {
        ObjTextureRuntimeSlot* solvedTexture;

        particleOrigin.posX = 0.0f;
        particleOrigin.posY = 16.5f;
        particleOrigin.posZ = 0.0f;
        particleOrigin.scale = 1.0f;

        for (objectIndex = SC_TOTEM_PUZZLE_PARTICLE_COUNT; objectIndex != 0; objectIndex--) {
            objfx_spawnArcedBurst(obj, SC_TOTEM_PUZZLE_PARTICLE_INDEX, SC_TOTEM_PUZZLE_PARTICLE_SCALE,
                                  SC_TOTEM_PUZZLE_PARTICLE_KIND, SC_TOTEM_PUZZLE_PARTICLE_MODE,
                                  SC_TOTEM_PUZZLE_PARTICLE_CHANCE, SC_TOTEM_PUZZLE_PARTICLE_ANGLE_BASE,
                                  SC_TOTEM_PUZZLE_PARTICLE_ANGLE_LOW, SC_TOTEM_PUZZLE_PARTICLE_ANGLE_HIGH,
                                  &particleOrigin, SC_TOTEM_PUZZLE_PARTICLE_FLAGS);
        }

        solvedTexture = objFindTexture(obj, 0, 0);
        if (solvedTexture != NULL) {
            solvedTexture->textureId = SC_TOTEM_PUZZLE_SOLVED_TEXTURE_ID;
        }
    }

    if (solvedCount == SC_TOTEM_PUZZLE_SOLVED_COUNT) {
        if (solvedThisObject != 0) {
            Sfx_PlayFromObject(0, SFXTRIG_mpick1_b);
        }
        return 1;
    }

    if (solvedThisObject != 0) {
        Sfx_PlayFromObject(0, SFXTRIG_sc_menuups16k_409);
    }
    return 0;
}

int sc_totempuzzle_getExtraSize(void) {
    return sizeof(ScTotemPuzzleState);
}

int sc_totempuzzle_getObjectTypeId(void) {
    return 0;
}

void sc_totempuzzle_free(void) {
}

void sc_totempuzzle_render(GameObject* obj, int renderArg2, int renderArg3, int renderArg4, int renderArg5, s8 visible) {
    s32 visibleValue = visible;

    if (visibleValue != 0) {
        objRenderModelAndHitVolumes(obj, renderArg2, renderArg3, renderArg4, renderArg5, 1.0f);
    }
}

void sc_totempuzzle_hitDetect(void) {
}

s16 gTotemPuzzleStepAngles[6] = {-8192, 0, 8192, 16384, 24576, -32768};

void sc_totempuzzle_update(GameObject* obj) {
    ScTotemPuzzleState* state;
    int hitKind;
    GameObject** objects;
    GameObject* other;
    ObjTextureRuntimeSlot* texture;
    PartFxSpawnParams lightArgs;
    GameObject* hitObject;
    int hitSphereIndex;
    u32 hitVolume;
    int countA, startA;
    int countB, startB;

    state = obj->extra;
    hitKind = ObjHits_GetPriorityHitWithPosition(obj, &hitObject, &hitSphereIndex, &hitVolume, &lightArgs.posX,
                                                 &lightArgs.posY, &lightArgs.posZ);
    if ((obj->anim.bankIndex == SC_TOTEM_PUZZLE_CAP_INDEX) || (mainGetBit(GAMEBIT_SC_totempuzzle_running) != 0) ||
        (mainGetBit(SC_TOTEM_PUZZLE_GAMEBIT_ACTIVATED) == 0)) {
        if ((hitKind != 0) && (hitKind != OBJHITREACT_COLLISION_SKIP_REACTION)) {
            Sfx_PlayFromObject(obj, SFXTRIG_wp_swdtest222);
            lightArgs.posX += playerMapOffsetX;
            lightArgs.posZ += playerMapOffsetZ;
            objDoHitParticleFx((void*)obj, 0.014f, &lightArgs, 1, 0);
        }
        return;
    }

    if ((hitKind != 0) && (hitKind != OBJHITREACT_COLLISION_SKIP_REACTION)) {
        Sfx_PlayFromObject(obj, SFXTRIG_wp_swdtest222);
        lightArgs.posX += playerMapOffsetX;
        lightArgs.posZ += playerMapOffsetZ;
        objDoHitParticleFx((void*)obj, 0.014f, &lightArgs, 1, 0);
        state->flags ^= SC_TOTEM_PUZZLE_FLAG_READY;
        if ((state->flags & SC_TOTEM_PUZZLE_FLAG_READY) != 0) {
            f32 zero = 0.0f;

            if (state->pulseTimer != zero) {
                mainSetBits(GAMEBIT_SC_totempuzzle_running, sc_totempuzzle_checkSolvedSequence(obj, state));
            }
            objects = ObjList_GetObjects(&startA, &countA);
            while (startA < countA) {
                other = objects[startA];
                if ((other->anim.romDefNo == SC_TOTEM_PUZZLE_SEQUENCE_ID) && (other != obj)) {
                    ((ScTotemPuzzleState*)other->extra)->peerPhaseOffset += 0.65f;
                }
                startA++;
            }
        } else {
            objects = ObjList_GetObjects(&startB, &countB);
            while (startB < countB) {
                other = objects[startB];
                if ((other->anim.romDefNo == SC_TOTEM_PUZZLE_SEQUENCE_ID) && (other != obj)) {
                    ((ScTotemPuzzleState*)other->extra)->peerPhaseOffset += -0.65f;
                }
                startB++;
            }
            texture = objFindTexture(obj, 0, 0);
            if (texture != NULL) {
                texture->textureId = 0;
            }
        }
    }

    if ((state->flags & SC_TOTEM_PUZZLE_FLAG_READY) != 0) {
        return;
    }

    if ((state->flags & SC_TOTEM_PUZZLE_FLAG_PULSE_ACTIVE) != 0) {
        state->pulseTimer -= timeDelta;
        if (state->pulseTimer < 0.0f) {
            state->flags &= ~SC_TOTEM_PUZZLE_FLAG_PULSE_ACTIVE;
            Sfx_PlayFromObjectLimited(obj, SFXTRIG_mv_cagerat01, 2);
            if ((state->flags & SC_TOTEM_PUZZLE_FLAG_REVERSED) != 0) {
                if (--state->stepIndex < 0) {
                    state->angle += 65535.0f;
                    state->stepIndex = SC_TOTEM_PUZZLE_LAST_STEP_INDEX;
                }
            } else if (++state->stepIndex > SC_TOTEM_PUZZLE_LAST_STEP_INDEX) {
                state->angle -= 65535.0f;
                state->stepIndex = 0;
            }
        }
    } else if (((state->flags & SC_TOTEM_PUZZLE_FLAG_REVERSED) != 0) &&
               (state->angle > (SC_TOTEM_PUZZLE_ANGLE_STEP * (f32)(s32)(state->stepIndex + 1)))) {
        f32 step = 512.0f * state->peerPhaseOffset;
        state->angle -= step * timeDelta;
    } else if (state->angle < (SC_TOTEM_PUZZLE_ANGLE_STEP * (f32)(s32)state->stepIndex)) {
        f32 step = 512.0f * state->peerPhaseOffset;
        state->angle += step * timeDelta;
    } else {
        state->pulseTimer = state->pulseTimerReset / state->peerPhaseOffset;
        state->flags |= SC_TOTEM_PUZZLE_FLAG_PULSE_ACTIVE;
    }

    obj->anim.rotX = (s16)(s32)state->angle;
}

void sc_totempuzzle_init(GameObject* obj, const ScTotemPuzzlePlacement* placement) {
    ScTotemPuzzleState* state;
    ObjTextureRuntimeSlot* texture;
    int pulseFrames;
    f32 pulseTime;

    state = obj->extra;
    obj->anim.bankIndex = placement->puzzleIndex;
    if (obj->anim.bankIndex < 0 || obj->anim.bankIndex > SC_TOTEM_PUZZLE_CAP_INDEX) {
        obj->anim.bankIndex = 0;
    }
    if (obj->anim.bankIndex == SC_TOTEM_PUZZLE_CAP_INDEX) {
        texture = objFindTexture(obj, 0, 0);
        if (texture != NULL) {
            texture->textureId = SC_TOTEM_PUZZLE_SOLVED_TEXTURE_ID;
        }
    }
    state->stepIndex = obj->anim.bankIndex;
    if (mainGetBit(GAMEBIT_SC_totempuzzle_running) == 0) {
        state->angle = (f32)(s32)gTotemPuzzleStepAngles[state->stepIndex];
    } else {
        state->angle = 32768.0f;
        texture = objFindTexture(obj, 0, 0);
        if (texture != NULL) {
            texture->textureId = SC_TOTEM_PUZZLE_SOLVED_TEXTURE_ID;
        }
    }
    obj->anim.rotX = (s16)(s32)state->angle;
    pulseFrames = randomGetRange(SC_TOTEM_PUZZLE_PULSE_FRAME_MIN, SC_TOTEM_PUZZLE_PULSE_FRAME_MAX);
    pulseTime = pulseFrames;
    pulseTime = 10.0f * pulseTime;
    state->pulseTimerReset = pulseTime;
    state->pulseTimer = pulseTime;
    if (obj->anim.bankIndex & 1) {
        state->flags = SC_TOTEM_PUZZLE_FLAG_REVERSED;
    }
    state->peerPhaseOffset = 1.0f;
    obj->animEventCallback = sc_totempuzzle_animEventCallback;
    obj->objectFlags = (u16)(obj->objectFlags | (OBJECT_OBJFLAG_HIDDEN | OBJECT_OBJFLAG_HITDETECT_DISABLED));
}

void sc_totempuzzle_release(void) {
}

void sc_totempuzzle_initialise(void) {
}

ObjectDescriptor gSC_totempuzzleObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)sc_totempuzzle_initialise,
    (ObjectDescriptorCallback)sc_totempuzzle_release,
    0,
    (ObjectDescriptorCallback)sc_totempuzzle_init,
    (ObjectDescriptorCallback)sc_totempuzzle_update,
    (ObjectDescriptorCallback)sc_totempuzzle_hitDetect,
    (ObjectDescriptorCallback)sc_totempuzzle_render,
    (ObjectDescriptorCallback)sc_totempuzzle_free,
    (ObjectDescriptorCallback)sc_totempuzzle_getObjectTypeId,
    sc_totempuzzle_getExtraSize,
};
