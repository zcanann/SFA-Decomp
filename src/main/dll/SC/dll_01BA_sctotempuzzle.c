/*
 * sctotempuzzle (DLL 0x1BA) - head of the SC totem-pole puzzle pair.
 * Holds dll 0x1BA's descriptor fns (gResourceDescriptors[0x1BA]); the unit
 * ends at 0x801DDA28 (initialise end). sc_totembond_SeqFn
 * (0x801DDC20) lives in the 01BB unit - it sits in dll 0x1BB's helper gap,
 * interleaved with sc_totembond_spawnGameBitOrbs (both DLLs shared one
 * original TU).
 *
 * Behaviour: the LightFoot Village totem puzzle - a stack of 4-6 totem
 * sections that spin independently; shoot each section as it comes around to
 * lock it, and the puzzle is solved when all sections line up. Inert until
 * GameBit 0xc10 activates it (only after both the tracking and strength trials
 * are done); solving it sets GameBit 0x639, which opens the gate to the Krazoa
 * shrine below the village. Distinct from sctotempole (the 4 standing totem
 * poles of the tracking test).
 */
#include "main/obj_list.h"
#include "main/object_descriptor.h"
#include "main/shader_api.h"
#include "main/game_object.h"
#include "main/objhits.h"
#include "main/objfx.h"
#include "main/objtexture.h"
#include "main/frame_timing.h"
#include "main/object_render.h"
#include "main/audio/sfx.h"
#include "main/dll/SC/sctotempuzzle.h"

typedef struct SCTotemPuzzleParticleBox
{
    u8 pad00[8];
    f32 alpha;
    f32 x;
    f32 y;
    f32 z;
} SCTotemPuzzleParticleBox;

#define SC_TOTEMPUZZLE_OBJECT_TYPE       0x3c1
#define SC_TOTEMPUZZLE_READY_FLAG        0x2
#define SC_TOTEMPUZZLE_REVERSED_FLAG     0x1
#define SC_TOTEMPUZZLE_PULSE_FLAG        0x4
#define SC_TOTEMPUZZLE_FORWARD_STEP      4
#define SC_TOTEMPUZZLE_SOLVED_COUNT      5
#define SC_TOTEMPUZZLE_CAP_INDEX         5
#define SC_TOTEMPUZZLE_SOLVED_TEXTURE_ID 0x100

#define SC_TOTEMPUZZLE_WRONG_SFX    0x487
#define SC_TOTEMPUZZLE_COMPLETE_SFX 0x7e
#define SC_TOTEMPUZZLE_PROGRESS_SFX 0x409

#define SC_TOTEMPUZZLE_OBJFLAG_HIDDEN             0x4000
#define SC_TOTEMPUZZLE_OBJFLAG_HITDETECT_DISABLED 0x2000

extern f32 lbl_803E5618;
extern const f32 lbl_803E561C;
extern const f32 lbl_803E5620;
extern f32 gTotemPuzzleAngleWrap;
extern f32 lbl_803E5628;
extern f32 lbl_803E562C;
extern f32 lbl_803E5630;

u8 sc_totempuzzle_checkSolvedSequence(ScTotemPuzzleObject* obj, ScTotemPuzzleState* state)
{
    SCTotemPuzzleParticleBox particleBox;
    int objectIndex;
    int objectCount;
    int* objects;
    int solvedCount;
    u8 solvedThisObject;

    solvedThisObject = 0;
    solvedCount = 0;
    objects = ObjList_GetObjects(&objectIndex, &objectCount);

    while (objectIndex < objectCount)
    {
        ScTotemPuzzleObject* peer;
        ScTotemPuzzleState* peerState;
        s16 flags;

        peer = (ScTotemPuzzleObject*)objects[objectIndex];
        if (peer->objectType == SC_TOTEMPUZZLE_OBJECT_TYPE)
        {
            peerState = peer->state;
            flags = peerState->flags;
            if ((flags & SC_TOTEMPUZZLE_READY_FLAG) != 0)
            {
                if ((flags & SC_TOTEMPUZZLE_REVERSED_FLAG) != 0)
                {
                    if (peerState->stepIndex + 1 == SC_TOTEMPUZZLE_FORWARD_STEP)
                    {
                        solvedCount++;
                        if (peer == obj)
                        {
                            state->angle = 8192.0f * (f32)(state->stepIndex + 1);
                            obj->yaw = (s16)(s32)state->angle;
                            solvedThisObject = 1;
                        }
                    }
                    else if (peer == obj)
                    {
                        Sfx_PlayFromObject(0, SC_TOTEMPUZZLE_WRONG_SFX);
                    }
                }
                else if (peerState->stepIndex == SC_TOTEMPUZZLE_FORWARD_STEP)
                {
                    solvedCount++;
                    if (peer == obj)
                    {
                        state->angle = 8192.0f * state->stepIndex;
                        obj->yaw = (s16)(s32)state->angle;
                        solvedThisObject = 1;
                    }
                }
                else if (peer == obj)
                {
                    Sfx_PlayFromObject(0, SC_TOTEMPUZZLE_WRONG_SFX);
                }
            }
        }
        objectIndex++;
    }

    if (solvedThisObject != 0)
    {
        ObjTextureRuntimeSlot* solvedTexture;
        particleBox.x = 0.0f;
        particleBox.y = 16.5f;
        particleBox.z = 0.0f;
        particleBox.alpha = 1.0f;

        for (objectIndex = 20; objectIndex != 0; objectIndex--)
        {
            objfx_spawnArcedBurst(obj, 7, 2.0f, 5, 7, 100, 25.0f, 25.0f, 30.0f, &particleBox, 0);
        }

        solvedTexture = objFindTexture((GameObject*)(obj), 0, 0);
        if (solvedTexture != NULL)
        {
            solvedTexture->textureId = SC_TOTEMPUZZLE_SOLVED_TEXTURE_ID;
        }
    }

    if (solvedCount == SC_TOTEMPUZZLE_SOLVED_COUNT)
    {
        if (solvedThisObject != 0)
        {
            Sfx_PlayFromObject(0, SC_TOTEMPUZZLE_COMPLETE_SFX);
        }
        return 1;
    }

    if (solvedThisObject != 0)
    {
        Sfx_PlayFromObject(0, SC_TOTEMPUZZLE_PROGRESS_SFX);
    }
    return 0;
}

int sc_totempuzzle_getExtraSize(void)
{
    return 0x14;
}

int sc_totempuzzle_getObjectTypeId(void)
{
    return 0;
}

void sc_totempuzzle_free(void)
{
}

void sc_totempuzzle_render(int obj, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;

    if (v != 0)
    {
        objRenderModelAndHitVolumes((GameObject*)obj, p2, p3, p4, p5, 1.0f);
    }
}

void sc_totempuzzle_hitDetect(void)
{
}

/* Tail of the TU (0x801DD46C..0x801DDA28) - formerly the head of
 * dll_01BB_sctotembond.c (the drift boundary at 0x801DD46C cut dll
 * 0x1BA between hitDetect and update; real edge = initialise end). */
#include "main/audio/sfx_ids.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/gamebits.h"

s16 gTotemPuzzleStepAngles[6] = {-8192, 0, 8192, 16384, 24576, -32768};

void sc_totempuzzle_update(ScTotemPuzzleObject* obj)
{
    ScTotemPuzzleState* state;
    int hitKind;
    int* objects;
    int other;
    ObjTextureRuntimeSlot* texture;
    f32 lightArgs[6];
    f32 hitNx, hitNy, hitNz;
    int countA, startA;
    int countB, startB;

    state = obj->state;
    hitKind = ObjHits_GetPriorityHitWithPosition((GameObject*)(obj), (int*)&hitNx, (int*)&hitNy, (u32*)&hitNz,
                                                 &lightArgs[3], &lightArgs[4], &lightArgs[5]);
    if ((obj->puzzleIndex == SC_TOTEMPUZZLE_CAP_INDEX) || (mainGetBit(GAMEBIT_SC_totempuzzle_running) != 0) ||
        (mainGetBit(0xc10) == 0))
    {
        if ((hitKind != 0) && (hitKind != 0x11))
        {
            Sfx_PlayFromObject((int)obj, SFXTRIG_wp_swdtest222);
            lightArgs[3] += playerMapOffsetX;
            lightArgs[5] += playerMapOffsetZ;
            objLightFn_8009a1dc((void*)obj, lbl_803E5618, lightArgs, 1, 0);
        }
        return;
    }

    if ((hitKind != 0) && (hitKind != 0x11))
    {
        Sfx_PlayFromObject((int)obj, SFXTRIG_wp_swdtest222);
        lightArgs[3] += playerMapOffsetX;
        lightArgs[5] += playerMapOffsetZ;
        objLightFn_8009a1dc((void*)obj, lbl_803E5618, lightArgs, 1, 0);
        state->flags ^= SC_TOTEMPUZZLE_READY_FLAG;
        if ((state->flags & SC_TOTEMPUZZLE_READY_FLAG) != 0)
        {
            f32 zero = 0.0f;
            if (state->pulseTimer != zero)
            {
                mainSetBits(GAMEBIT_SC_totempuzzle_running, sc_totempuzzle_checkSolvedSequence(obj, state));
            }
            objects = ObjList_GetObjects(&startA, &countA);
            while (startA < countA)
            {
                other = objects[startA];
                if ((((ScTotemPuzzleObject*)other)->objectType == SC_TOTEMPUZZLE_OBJECT_TYPE) &&
                    ((ScTotemPuzzleObject*)other != obj))
                {
                    ((ScTotemPuzzleObject*)other)->state->peerPhaseOffset += lbl_803E561C;
                }
                startA++;
            }
        }
        else
        {
            objects = ObjList_GetObjects(&startB, &countB);
            while (startB < countB)
            {
                other = objects[startB];
                if ((((ScTotemPuzzleObject*)other)->objectType == SC_TOTEMPUZZLE_OBJECT_TYPE) &&
                    ((ScTotemPuzzleObject*)other != obj))
                {
                    ((ScTotemPuzzleObject*)other)->state->peerPhaseOffset += lbl_803E5620;
                }
                startB++;
            }
            texture = objFindTexture((GameObject*)(obj), 0, 0);
            if (texture != NULL)
            {
                texture->textureId = 0;
            }
        }
    }

    if ((state->flags & SC_TOTEMPUZZLE_READY_FLAG) != 0)
    {
        return;
    }

    if ((state->flags & SC_TOTEMPUZZLE_PULSE_FLAG) != 0)
    {
        state->pulseTimer -= timeDelta;
        if (state->pulseTimer < 0.0f)
        {
            state->flags &= ~SC_TOTEMPUZZLE_PULSE_FLAG;
            Sfx_PlayFromObjectLimited((int)obj, SFXTRIG_mv_cagerat01, 2);
            if ((state->flags & SC_TOTEMPUZZLE_REVERSED_FLAG) != 0)
            {
                if (--state->stepIndex < 0)
                {
                    state->angle += gTotemPuzzleAngleWrap;
                    state->stepIndex = 7;
                }
            }
            else
            {
                if (++state->stepIndex > 7)
                {
                    state->angle -= gTotemPuzzleAngleWrap;
                    state->stepIndex = 0;
                }
            }
        }
    }
    else
    {
        if (((state->flags & SC_TOTEMPUZZLE_REVERSED_FLAG) != 0) &&
            (state->angle > (8192.0f * (f32)(s32)(state->stepIndex + 1))))
        {
            f32 step = lbl_803E5628 * state->peerPhaseOffset;
            state->angle -= step * timeDelta;
        }
        else if (state->angle < (8192.0f * (f32)(s32)state->stepIndex))
        {
            f32 step = lbl_803E5628 * state->peerPhaseOffset;
            state->angle += step * timeDelta;
        }
        else
        {
            state->pulseTimer = state->pulseTimerReset / state->peerPhaseOffset;
            state->flags |= SC_TOTEMPUZZLE_PULSE_FLAG;
        }
    }

    obj->yaw = (s16)(s32)state->angle;
}

void sc_totempuzzle_init(ScTotemPuzzleObject* obj, ScTotemPuzzleMapData* params)
{
    ScTotemPuzzleState* state;
    ObjTextureRuntimeSlot* tex;
    int pulseFrames;
    f32 pulseTime;

    state = obj->state;
    obj->puzzleIndex = params->puzzleIndex;
    if (obj->puzzleIndex < 0 || obj->puzzleIndex > SC_TOTEMPUZZLE_CAP_INDEX)
    {
        obj->puzzleIndex = 0;
    }
    if (obj->puzzleIndex == SC_TOTEMPUZZLE_CAP_INDEX)
    {
        tex = objFindTexture((GameObject*)(obj), 0, 0);
        if (tex != NULL)
        {
            tex->textureId = SC_TOTEMPUZZLE_SOLVED_TEXTURE_ID;
        }
    }
    state->stepIndex = obj->puzzleIndex;
    if (mainGetBit(GAMEBIT_SC_totempuzzle_running) == 0)
    {
        state->angle = (f32)(s32)gTotemPuzzleStepAngles[state->stepIndex];
    }
    else
    {
        state->angle = lbl_803E562C;
        tex = objFindTexture((GameObject*)(obj), 0, 0);
        if (tex != NULL)
        {
            tex->textureId = SC_TOTEMPUZZLE_SOLVED_TEXTURE_ID;
        }
    }
    obj->yaw = (s16)(s32)state->angle;
    pulseFrames = randomGetRange(7, 10);
    pulseTime = pulseFrames;
    pulseTime = lbl_803E5630 * pulseTime;
    state->pulseTimerReset = pulseTime;
    state->pulseTimer = pulseTime;
    if (obj->puzzleIndex & 1)
    {
        state->flags = 1;
    }
    state->peerPhaseOffset = 1.0f;
    obj->animEventCallback = sc_totempuzzle_animEventCallback;
    obj->objectFlags =
        (u16)(obj->objectFlags | (SC_TOTEMPUZZLE_OBJFLAG_HIDDEN | SC_TOTEMPUZZLE_OBJFLAG_HITDETECT_DISABLED));
}

void sc_totempuzzle_release(void)
{
}

void sc_totempuzzle_initialise(void)
{
}

/* descriptor/ptr table auto 0x80327a24-0x80327a60 */
ObjectDescriptor10WithPadding gSC_totempuzzleObjDescriptor = {
    {
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
    },
    0,
};
