/*
 * ChukChuk (DLL slot 204) - stationary IceBall-spitting enemy.
 *
 * Its texture glow primes an attack. A primed object fires when the player
 * enters its distance and facing arc; exhausting its priority-hit count hides
 * the object, records its game bit, and starts a steam effect.
 */
#include "dlls/objects/204_ChukChuk.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/math_api.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/dll/objfx_api.h"
#include "main/frame_timing.h"
#include "main/gamebits_api.h"
#include "main/object_render.h"
#include "main/objtexture.h"
#include "sys/objects.h"
#include "sys/objects/lifecycle.h"
#include "main/vecmath.h"
#include "main/audio/sfx_play_api.h"
#include "main/objhits.h"

#define CHUKCHUK_CHILD_OBJ_ICEBALL      1307
#define CHUKCHUK_ICEBALL_SETUP_SIZE     0x24
#define CHUKCHUK_MESSAGE_PROJECTILE_HIT 0x80
#define CHUKCHUK_PRIORITY_HIT_DAMAGE    14
#define CHUKCHUK_GLOW_RAMP_COUNT        16
#define CHUKCHUK_GLOW_PRIMED_PHASE      10
#define CHUKCHUK_STEAM_DURATION         60.0f

#define CHUKCHUK_FLAG_PRIMED        0x1
#define CHUKCHUK_FLAG_DEAD          0x2
#define CHUKCHUK_FLAG_FORCED_ATTACK 0x4

typedef struct ChukChukHitResult {
    u32 hitVolume;
    int sphereIndex;
    GameObject* hitObject;
    f32 toPlayer[3];
} ChukChukHitResult;

STATIC_ASSERT(offsetof(ChukChukHitResult, hitVolume) == 0x0);
STATIC_ASSERT(offsetof(ChukChukHitResult, sphereIndex) == 0x4);
STATIC_ASSERT(offsetof(ChukChukHitResult, hitObject) == 0x8);
STATIC_ASSERT(offsetof(ChukChukHitResult, toPlayer) == 0xC);
STATIC_ASSERT(sizeof(ChukChukHitResult) == 0x18);

u8 gChukChukGlowTextureRamp[CHUKCHUK_GLOW_RAMP_COUNT] = {0, 1, 1, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 1, 1, 0};

void chukChuk_spawnAimedIceBall(GameObject* obj) {
    ChukChukState* state;
    ObjPlacement* projectilePlacement;
    GameObject* projectile;
    GameObject* player;
    f32 travelTime;
    u8 canSetupObject;

    state = obj->extra;
    canSetupObject = Obj_CanSetupObject();
    if (canSetupObject > 0) {
        projectilePlacement = Obj_AllocObjectSetup(CHUKCHUK_ICEBALL_SETUP_SIZE, CHUKCHUK_CHILD_OBJ_ICEBALL);
        projectilePlacement->posX = obj->anim.localPosX;
        projectilePlacement->posY = 5.0f + obj->anim.localPosY;
        projectilePlacement->posZ = obj->anim.localPosZ;
        projectilePlacement->color[0] = 1;
        projectilePlacement->color[1] = 4;
        projectilePlacement->color[3] = 0xff;
        projectile = objSetupObject(projectilePlacement, 5, -1, -1, NULL);
        if (projectile != NULL) {
            player = Obj_GetPlayerObject();
            projectile->anim.velocityX = (player->anim.localPosX - obj->anim.localPosX) / (travelTime = 42.0f);
            projectile->anim.velocityY =
                (player->anim.localPosY + (f32)(u32)state->aimHeightY - obj->anim.localPosY) / travelTime;
            projectile->anim.velocityZ = (player->anim.localPosZ - obj->anim.localPosZ) / travelTime;
        }
    }
}

void ChukChuk_handleMessage(GameObject* obj, int message) {
    switch ((u8)message) {
    case CHUKCHUK_MESSAGE_PROJECTILE_HIT:
        Sfx_PlayFromObject(obj, SFXTRIG_baddie_rach_bite_26b);
        break;
    }
}

int ChukChuk_getExtraSize(void) {
    return sizeof(ChukChukState);
}

int ChukChuk_getObjectTypeId(void) {
    return 0;
}

void ChukChuk_free(GameObject* obj) {
    (void)obj;
}

void ChukChuk_render(GameObject* obj, int fwdArg2, int fwdArg3, int fwdArg4, int fwdArg5, s8 visible) {
    s32 visible32 = visible;

    if (visible32 != 0) {
        objRenderModelAndHitVolumes(obj, fwdArg2, fwdArg3, fwdArg4, fwdArg5, 1.0f);
    }
}

void ChukChuk_hitDetect(GameObject* obj) {
    (void)obj;
}

void ChukChuk_update(GameObject* obj) {
    ChukChukState* state;
    u16 playerDistance;
    GameObject* player;
    ObjTextureRuntimeSlot* texture;
    int relativeAngle;
    int attackRoll;
    f32 phaseLimit;
    f32 nextPhase;
    f32 playerDeltaX;
    f32 playerDeltaZ;
    ChukChukHitResult hitResult;

    state = obj->extra;
    if (state->steamTimer) {
        state->steamTimer -= timeDelta;
        objDoParticleFx(obj, 1.0f, 1, state->steamTimer / CHUKCHUK_STEAM_DURATION, NULL);
        if (state->steamTimer <= 0.0f) {
            state->steamTimer = 0.0f;
        }
    }
    if ((state->flags & CHUKCHUK_FLAG_DEAD) == 0) {
        texture = objFindTexture(obj, 0, 0);
        if (state->glowPhase < CHUKCHUK_GLOW_RAMP_COUNT) {
            if ((int)state->glowPhase == CHUKCHUK_GLOW_PRIMED_PHASE) {
                state->flags |= CHUKCHUK_FLAG_PRIMED;
            }
            texture->textureId = gChukChukGlowTextureRamp[(int)state->glowPhase] << 8;
            phaseLimit = CHUKCHUK_GLOW_RAMP_COUNT;
            nextPhase = (state->glowPhase += 1.0f);
            if (phaseLimit == nextPhase) {
                state->glowPhase = randomGetRange(CHUKCHUK_GLOW_RAMP_COUNT, 245);
            }
        } else {
            if (255.0f - state->glowPhase >= timeDelta) {
                state->glowPhase += timeDelta;
            } else {
                state->glowPhase = 0.0f;
            }
            texture->textureId = 0;
        }
        player = Obj_GetPlayerObject();
        playerDeltaX = player->anim.localPosX - obj->anim.localPosX;
        playerDeltaZ = player->anim.localPosZ - obj->anim.localPosZ;
        playerDistance = sqrtf(playerDeltaX * playerDeltaX + playerDeltaZ * playerDeltaZ);
        if (playerDistance < state->triggerDistance) {
            if (state->prevDistance >= state->triggerDistance) {
                state->flags = CHUKCHUK_FLAG_PRIMED | CHUKCHUK_FLAG_FORCED_ATTACK;
                state->glowPhase = 0.0f;
            }
            if ((state->flags & (CHUKCHUK_FLAG_PRIMED | CHUKCHUK_FLAG_FORCED_ATTACK)) != 0) {
                hitResult.toPlayer[0] = player->anim.worldPosX - obj->anim.worldPosX;
                hitResult.toPlayer[1] = player->anim.worldPosY - obj->anim.worldPosY;
                hitResult.toPlayer[2] = player->anim.worldPosZ - obj->anim.worldPosZ;
                relativeAngle = getAngle(hitResult.toPlayer[0], hitResult.toPlayer[2]) & 0xffff;
                relativeAngle -= obj->anim.rotX & 0xffff;
                if (relativeAngle > 0x8000) {
                    relativeAngle -= 0xffff;
                }
                if (relativeAngle < -0x8000) {
                    relativeAngle += 0xffff;
                }
                if (((u32)relativeAngle & 0xffff) < state->arcHalfAngle ||
                    ((u32)relativeAngle & 0xffff) > ((0xffff - state->arcHalfAngle) & 0xffff)) {
                    attackRoll = randomGetRange(0, 99);
                    if (attackRoll < state->attackChance || (state->flags & CHUKCHUK_FLAG_FORCED_ATTACK) != 0) {
                        Sfx_PlayFromObject(obj, SFXTRIG_baddie_zyck_lash_268);
                        chukChuk_spawnAimedIceBall(obj);
                    } else {
                        Sfx_PlayFromObject(obj, SFXTRIG_baddie_zyck_call02);
                    }
                } else {
                    Sfx_PlayFromObject(obj, SFXTRIG_baddie_zyck_call02);
                }
            }
        } else if ((state->flags & CHUKCHUK_FLAG_PRIMED) != 0) {
            Sfx_PlayFromObject(obj, SFXTRIG_baddie_zyck_call02);
        }
        state->prevDistance = playerDistance;
        if (ObjHits_GetPriorityHit(obj, &hitResult.hitObject, &hitResult.sphereIndex, &hitResult.hitVolume) ==
            CHUKCHUK_PRIORITY_HIT_DAMAGE) {
            state->hitsLeft -= 1;
            if (state->hitsLeft < 1) {
                ObjHits_DisableObject(obj);
                obj->anim.flags |= OBJANIM_FLAG_HIDDEN;
                state->flags |= CHUKCHUK_FLAG_DEAD;
                Sfx_PlayFromObject(obj, SFXTRIG_mn_lummy311_26a);
                mainSetBits(state->gameBit, 1);
                state->steamTimer = CHUKCHUK_STEAM_DURATION;
                Sfx_PlayFromObject(obj, SFXTRIG_baddie_zyck_lash);
            }
        }
        state->flags &= ~(CHUKCHUK_FLAG_PRIMED | CHUKCHUK_FLAG_FORCED_ATTACK);
    }
}

void ChukChuk_init(GameObject* obj, ChukChukPlacement* placement) {
    ChukChukState* state = obj->extra;
    obj->anim.resetHitboxFlags |= INTERACT_FLAG_DISABLED;
    state->gameBit = placement->gameBit;
    if (state->gameBit != -1 && mainGetBit(state->gameBit) != 0) {
        ObjHits_DisableObject(obj);
        obj->anim.flags = (s16)(obj->anim.flags | OBJANIM_FLAG_HIDDEN);
        state->flags = (u8)(state->flags | CHUKCHUK_FLAG_DEAD);
    } else {
        state->triggerDistance = (u16)(placement->triggerDistanceScale << 3);
        state->unk08 = placement->unk22;
        state->hitsLeft = placement->hitsLeft;
        state->arcHalfAngle = (u16)(placement->arcHalfAngleScale * 0xb6);
        state->attackChance = placement->attackChance;
        state->aimHeightY = placement->aimHeightY;
        obj->anim.rotX = (s16)(placement->rotX << 8);
    }
}

void ChukChuk_release(void) {
}

void ChukChuk_initialise(void) {
}

ObjectDescriptor11WithPadding gChukChukObjDescriptor = {
    {
        0,
        0,
        0,
        OBJECT_DESCRIPTOR_FLAGS_11_SLOTS,
        (ObjectDescriptorCallback)ChukChuk_initialise,
        (ObjectDescriptorCallback)ChukChuk_release,
        0,
        (ObjectDescriptorCallback)ChukChuk_init,
        (ObjectDescriptorCallback)ChukChuk_update,
        (ObjectDescriptorCallback)ChukChuk_hitDetect,
        (ObjectDescriptorCallback)ChukChuk_render,
        (ObjectDescriptorCallback)ChukChuk_free,
        (ObjectDescriptorCallback)ChukChuk_getObjectTypeId,
        ChukChuk_getExtraSize,
        (ObjectDescriptorCallback)ChukChuk_handleMessage,
    },
    0,
};
