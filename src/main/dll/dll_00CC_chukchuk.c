/*
 * chukchuk (DLL 0xCC) - the ChukChuk ice-spitter baddie and its IceBall
 * projectile. Idle ChukChuk ramps a glow texture; when index 10 is reached
 * it arms (flags bit 1) and, if the player crosses triggerDistance inside the
 * facing wedge (+/- arcHalfAngle around rotX), rolls attackChance% to spit an
 * IceBall (chukChuk_spawnAimedIceBall spawns object id 1307 aimed at the player + aimHeightY).
 * Taking priority-hit 14 decrements hitsLeft; on depletion it dies: disables
 * hits, hides, sets gameBit, and starts the steam-fade particle. gameBit set
 * at load means already destroyed -> spawn disabled + hidden.
 *
 * This TU also defines chukChuk_spawnAimedIceBall and the ChukChuk ObjectDescriptor.
 */
#include "main/obj_placement.h"
#include "main/dll/objfx_api.h"
#include "main/object_render.h"
#include "main/object.h"
#include "main/object_api.h"
#include "main/dll/chukchukstate_struct.h"
#include "main/game_object.h"
#include "main/objhits.h"
#include "main/audio/sfx_ids.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/dll/dll_00CC_chukchuk.h"
#include "main/objtexture.h"
#include "main/gamebits.h"
#include "main/frame_timing.h"
#include "main/vecmath.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/math_api.h"

/* child object id spawned by chukChuk_spawnAimedIceBall (docblock: IceBall aimed at the player) */
#define CHUKCHUK_CHILD_OBJ_ICEBALL 1307

/* sub->flags bits (see chukchukstate_struct.h) */
#define CHUKCHUK_FLAG_PRIMED        0x1
#define CHUKCHUK_FLAG_DEAD          0x2
#define CHUKCHUK_FLAG_FORCED_ATTACK 0x4

STATIC_ASSERT(sizeof(ChukChukState) == 0x18);
STATIC_ASSERT(offsetof(ChukChukState, flags) == 0x12);

/* glow-texture ramp table */
u8 gChukChukGlowTextureRamp[] = {0, 1, 1, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 1, 1, 0};

void chukChuk_spawnAimedIceBall(GameObject* obj)
{
    ChukChukState* state;
    int setup;
    u8* projectile;
    GameObject* player;
    f32 travelTime;

    state = obj->extra;
    if (Obj_IsLoadingLocked() != 0)
    {
        setup = (int)Obj_AllocObjectSetup(36, CHUKCHUK_CHILD_OBJ_ICEBALL);
        ((ObjPlacement*)setup)->posX = obj->anim.localPosX;
        ((ObjPlacement*)setup)->posY = 5.0f + obj->anim.localPosY;
        ((ObjPlacement*)setup)->posZ = obj->anim.localPosZ;
        ((ObjPlacement*)setup)->color[0] = 1;
        ((ObjPlacement*)setup)->color[1] = 4;
        ((ObjPlacement*)setup)->color[3] = 0xff;
        projectile = (u8*)Obj_SetupObject((ObjPlacement*)setup, 5, -1, -1, NULL);
        if (projectile != NULL)
        {
            player = Obj_GetPlayerObject();
            ((GameObject*)projectile)->anim.velocityX =
                (player->anim.localPosX - obj->anim.localPosX) / (travelTime = 42.0f);
            ((GameObject*)projectile)->anim.velocityY =
                (player->anim.localPosY + (f32)(u32)state->aimHeightY - obj->anim.localPosY) /
                travelTime;
            ((GameObject*)projectile)->anim.velocityZ =
                (player->anim.localPosZ - obj->anim.localPosZ) / travelTime;
        }
    }
}

void ChukChuk_handleMessage(GameObject* obj, int message)
{
    switch ((u8)message)
    {
    case 0x80:
        Sfx_PlayFromObject((int)obj, SFXTRIG_baddie_rach_bite_26b);
        break;
    }
}

int ChukChuk_getExtraSize(void)
{
    return sizeof(ChukChukState);
}
int ChukChuk_getObjectTypeId(void)
{
    return 0x0;
}

void ChukChuk_free(void)
{
}

void ChukChuk_render(GameObject* obj, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0)
        objRenderModelAndHitVolumes(obj, p2, p3, p4, p5, 1.0f);
}

void ChukChuk_hitDetect(void)
{
}

void ChukChuk_update(GameObject* obj)
{

    ChukChukState* state;
    u16 playerDistance;
    GameObject* player;
    ObjTextureRuntimeSlot* tex;
    int relativeAngle;
    int roll;
    f32 phaseLimit;
    f32 nextPhase;
    f32 dx;
    f32 dz;
    struct
    {
        int hitVolume;
        int sphereIndex;
        int hitObject;
        f32 toPlayer[3];
    } hitResult;

    state = obj->extra;
    if (state->steamTimer)
    {
        state->steamTimer -= timeDelta;
        objParticleFn_80099d84(obj, 1.0f, 1, state->steamTimer / 60.0f, 0);
        if (state->steamTimer <= 0.0f)
        {
            state->steamTimer = 0.0f;
        }
    }
    if ((state->flags & CHUKCHUK_FLAG_DEAD) == 0)
    {
        tex = objFindTexture(obj, 0, 0);
        if (state->glowPhase < 16.0f)
        {
            if ((int)state->glowPhase == 10)
            {
                state->flags |= CHUKCHUK_FLAG_PRIMED;
            }
            tex->textureId = gChukChukGlowTextureRamp[(int)state->glowPhase] << 8;
            phaseLimit = 16.0f;
            nextPhase = (state->glowPhase += 1.0f);
            if (phaseLimit == nextPhase)
            {
                state->glowPhase = (f32)(int)randomGetRange(16, 245);
            }
        }
        else
        {
            if (255.0f - state->glowPhase >= timeDelta)
            {
                state->glowPhase = state->glowPhase + timeDelta;
            }
            else
            {
                state->glowPhase = 0.0f;
            }
            tex->textureId = 0;
        }
        player = Obj_GetPlayerObject();
        dx = player->anim.localPosX - obj->anim.localPosX;
        dz = player->anim.localPosZ - obj->anim.localPosZ;
        playerDistance = sqrtf(dx * dx + dz * dz);
        if (playerDistance < state->triggerDistance)
        {
            if (state->prevDistance >= state->triggerDistance)
            {
                state->flags = CHUKCHUK_FLAG_PRIMED | CHUKCHUK_FLAG_FORCED_ATTACK;
                state->glowPhase = 0.0f;
            }
            if ((state->flags & (CHUKCHUK_FLAG_PRIMED | CHUKCHUK_FLAG_FORCED_ATTACK)) != 0)
            {
                hitResult.toPlayer[0] = player->anim.worldPosX - obj->anim.worldPosX;
                hitResult.toPlayer[1] = player->anim.worldPosY - obj->anim.worldPosY;
                hitResult.toPlayer[2] = player->anim.worldPosZ - obj->anim.worldPosZ;
                relativeAngle = getAngle(hitResult.toPlayer[0], hitResult.toPlayer[2]) & 0xffff;
                relativeAngle -= obj->anim.rotX & 0xffff;
                if (relativeAngle > 0x8000)
                {
                    relativeAngle -= 0xffff;
                }
                if (relativeAngle < -0x8000)
                {
                    relativeAngle += 0xffff;
                }
                if (((u32)relativeAngle & 0xffff) < state->arcHalfAngle ||
                    ((u32)relativeAngle & 0xffff) > ((0xffff - state->arcHalfAngle) & 0xffff))
                {
                    roll = randomGetRange(0, 99);
                    if (roll < state->attackChance || (state->flags & CHUKCHUK_FLAG_FORCED_ATTACK) != 0)
                    {
                        Sfx_PlayFromObject((int)obj, SFXTRIG_baddie_zyck_lash_268);
                        chukChuk_spawnAimedIceBall(obj);
                    }
                    else
                    {
                        Sfx_PlayFromObject((int)obj, SFXTRIG_baddie_zyck_call02);
                    }
                }
                else
                {
                    Sfx_PlayFromObject((int)obj, SFXTRIG_baddie_zyck_call02);
                }
            }
        }
        else if ((state->flags & CHUKCHUK_FLAG_PRIMED) != 0)
        {
            Sfx_PlayFromObject((int)obj, SFXTRIG_baddie_zyck_call02);
        }
        state->prevDistance = playerDistance;
        if (ObjHits_GetPriorityHit(obj, &hitResult.hitObject, &hitResult.sphereIndex,
                                   (u32*)&hitResult.hitVolume) == 14)
        {
            state->hitsLeft -= 1;
            if (state->hitsLeft < 1)
            {
                ObjHits_DisableObject(obj);
                obj->anim.flags |= OBJANIM_FLAG_HIDDEN;
                state->flags |= CHUKCHUK_FLAG_DEAD;
                Sfx_PlayFromObject((int)obj, SFXTRIG_mn_lummy311_26a);
                mainSetBits(state->gameBit, 1);
                state->steamTimer = 60.0f;
                Sfx_PlayFromObject((int)obj, SFXTRIG_baddie_zyck_lash);
            }
        }
        state->flags &= ~(CHUKCHUK_FLAG_PRIMED | CHUKCHUK_FLAG_FORCED_ATTACK);
    }
}

void ChukChuk_init(GameObject* obj, ChukChukPlacement* placement)
{
    ChukChukState* state = obj->extra;
    *(u8*)&obj->anim.resetHitboxMode =
        (u8)(*(u8*)&obj->anim.resetHitboxMode | INTERACT_FLAG_DISABLED);
    state->gameBit = placement->gameBit;
    if (state->gameBit != -1 && mainGetBit(state->gameBit) != 0)
    {
        ObjHits_DisableObject(obj);
        obj->anim.flags = (s16)(obj->anim.flags | OBJANIM_FLAG_HIDDEN);
        state->flags = (u8)(state->flags | CHUKCHUK_FLAG_DEAD);
    }
    else
    {
        state->triggerDistance = (u16)(placement->triggerDistanceScale << 3);
        state->unk08 = placement->unk22;
        state->hitsLeft = placement->hitsLeft;
        state->arcHalfAngle = (u16)(placement->arcHalfAngleScale * 0xb6);
        state->attackChance = placement->attackChance;
        state->aimHeightY = placement->aimHeightY;
        obj->anim.rotX = (s16)(placement->rotX << 8);
    }
}

void ChukChuk_release(void)
{
}

void ChukChuk_initialise(void)
{
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
