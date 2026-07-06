/*
 * sctotempuzzle (DLL 0x1BA) - head of the SC totem-pole puzzle pair.
 * Holds dll 0x1BA's descriptor fns (gResourceDescriptors[0x1BA]); the unit
 * ends at 0x801DDA28 (initialise end). sc_totempuzzle_processAnimEvents
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
#include "main/objlib.h"
#include "main/objtexture.h"

#define SC_TOTEMPUZZLE_OBJECT_TYPE 0x3c1
#define SC_TOTEMPUZZLE_READY_FLAG 0x2
#define SC_TOTEMPUZZLE_REVERSED_FLAG 0x1
#define SC_TOTEMPUZZLE_PULSE_FLAG 0x4
#define SC_TOTEMPUZZLE_FORWARD_STEP 4
#define SC_TOTEMPUZZLE_SOLVED_COUNT 5
#define SC_TOTEMPUZZLE_CAP_INDEX 5
#define SC_TOTEMPUZZLE_SOLVED_TEXTURE_ID 0x100

#define SC_TOTEMPUZZLE_WRONG_SFX 0x487
#define SC_TOTEMPUZZLE_COMPLETE_SFX 0x7e
#define SC_TOTEMPUZZLE_PROGRESS_SFX 0x409

#define SC_TOTEMPUZZLE_OBJFLAG_HIDDEN 0x4000
#define SC_TOTEMPUZZLE_OBJFLAG_HITDETECT_DISABLED 0x2000

typedef struct SCTotemPuzzleState
{
    u8 pad00[0xc];
    f32 angleTarget;
    s16 step;
    s16 flags;
} SCTotemPuzzleState;

typedef struct SCTotemPuzzleObject
{
    s16 angle;
    u8 pad02[0x44];
    s16 objectType;
    u8 pad48[0x70];
    SCTotemPuzzleState* state;
} SCTotemPuzzleObject;

typedef struct SCTotemPuzzleParticleBox
{
    u8 pad00[8];
    f32 alpha;
    f32 x;
    f32 y;
    f32 z;
} SCTotemPuzzleParticleBox;

extern void Sfx_PlayFromObject(u32 obj, u16 sfxId);
extern void objfx_spawnArcedBurst(int obj, int enabled, f32 radius, int particleKind,
                                  int particleId, int lifetime, f32 scaleX, f32 scaleY,
                                  f32 scaleZ, void* args, int arg9);
extern void objRenderModelAndHitVolumes(int obj, int p2, int p3, int p4, int p5, f32 scale);
extern f32 gTotemPuzzleAngleStep;
extern f32 lbl_803E55F4;
extern f32 lbl_803E55F8;
extern f32 lbl_803E55FC;
extern f32 lbl_803E5600;
extern f32 lbl_803E5604;
extern f32 lbl_803E5608;

int sc_totempuzzle_checkSolvedSequence(SCTotemPuzzleObject* obj, SCTotemPuzzleState* state)
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
        SCTotemPuzzleObject* peer;
        SCTotemPuzzleState* peerState;
        s16 flags;

        peer = (SCTotemPuzzleObject*)objects[objectIndex];
        if (peer->objectType == SC_TOTEMPUZZLE_OBJECT_TYPE)
        {
            peerState = peer->state;
            flags = peerState->flags;
            if ((flags & SC_TOTEMPUZZLE_READY_FLAG) != 0)
            {
                if ((flags & SC_TOTEMPUZZLE_REVERSED_FLAG) != 0)
                {
                    if (peerState->step + 1 == SC_TOTEMPUZZLE_FORWARD_STEP)
                    {
                        solvedCount++;
                        if (peer == obj)
                        {
                            state->angleTarget = gTotemPuzzleAngleStep * (f32)(state->step + 1);
                            obj->angle = (s16)(s32)state->angleTarget;
                            solvedThisObject = 1;
                        }
                    }
                    else if (peer == obj)
                    {
                        Sfx_PlayFromObject(0, SC_TOTEMPUZZLE_WRONG_SFX);
                    }
                }
                else if (peerState->step == SC_TOTEMPUZZLE_FORWARD_STEP)
                {
                    solvedCount++;
                    if (peer == obj)
                    {
                        state->angleTarget = gTotemPuzzleAngleStep * state->step;
                        obj->angle = (s16)(s32)state->angleTarget;
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
        extern void objfx_spawnArcedBurst(SCTotemPuzzleObject* obj, int enabled, f32 radius, int particleKind,
                                          int particleCount, int lifetime, f32 speedA, f32 speedB, f32 scale,
                                          SCTotemPuzzleParticleBox* box, int flags);
        ObjTextureRuntimeSlot* solvedTexture;
        particleBox.x = lbl_803E55F4;
        particleBox.y = lbl_803E55F8;
        particleBox.z = lbl_803E55F4;
        particleBox.alpha = lbl_803E55FC;

        for (objectIndex = 20; objectIndex != 0; objectIndex--)
        {
            objfx_spawnArcedBurst(obj, 7, lbl_803E5600, 5, 7, 100, lbl_803E5604,
                                  *(f32*)&lbl_803E5604, lbl_803E5608, &particleBox, 0);
        }

        solvedTexture = objFindTexture(obj, 0, 0);
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

void sc_totempuzzle_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;

    if (v != 0)
    {
        objRenderModelAndHitVolumes(p1, p2, p3, p4, p5, lbl_803E55FC);
    }
}

void sc_totempuzzle_hitDetect(void)
{
}

/* Tail of the TU (0x801DD46C..0x801DDA28) - formerly the head of
 * dll_01BB_sctotembond.c (the drift boundary at 0x801DD46C cut dll
 * 0x1BA between hitDetect and update; real edge = initialise end). */
#include "main/dll/SC/sctotembond.h"
#include "main/audio/sfx_ids.h"
#include "main/objfx.h"
#include "main/gamebits.h"
#include "main/audio/sfx.h"
extern int ObjHits_GetPriorityHitWithPosition();
extern f32 playerMapOffsetX;
extern f32 playerMapOffsetZ;
extern f32 timeDelta;
extern f32 lbl_803E5618;
extern const f32 lbl_803E561C;
extern const f32 lbl_803E5620;
extern f32 gTotemPuzzleAngleWrap;
extern f32 lbl_803E5628;

s16 gTotemPuzzleStepAngles[6] = {-8192, 0, 8192, 16384, 24576, -32768};
extern f32 lbl_803E562C;
extern f32 lbl_803E5630;
extern void fn_801DD170(int obj);
extern int randomGetRange(int lo, int hi);

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
    hitKind = ObjHits_GetPriorityHitWithPosition(obj, &hitNx, &hitNy, &hitNz, &lightArgs[3],
                                                 &lightArgs[4], &lightArgs[5]);
    if ((obj->puzzleIndex == SC_TOTEMPUZZLE_CAP_INDEX) || (GameBit_Get(0x639) != 0) || (GameBit_Get(0xc10) == 0))
    {
        if ((hitKind != 0) && (hitKind != 0x11))
        {
            Sfx_PlayFromObject((int)obj, SFXtr_gal_prophitbird);
            lightArgs[3] += playerMapOffsetX;
            lightArgs[5] += playerMapOffsetZ;
            objLightFn_8009a1dc((void*)obj, lbl_803E5618, lightArgs, 1, 0);
        }
        return;
    }

    if ((hitKind != 0) && (hitKind != 0x11))
    {
        Sfx_PlayFromObject((int)obj, SFXtr_gal_prophitbird);
        lightArgs[3] += playerMapOffsetX;
        lightArgs[5] += playerMapOffsetZ;
        objLightFn_8009a1dc((void*)obj, lbl_803E5618, lightArgs, 1, 0);
        state->flags ^= SC_TOTEMPUZZLE_READY_FLAG;
        if ((state->flags & SC_TOTEMPUZZLE_READY_FLAG) != 0)
        {
            if (state->pulseTimer != lbl_803E55F4)
            {
                GameBit_Set(0x639, ((u8 (*)(ScTotemPuzzleObject*, ScTotemPuzzleState*))sc_totempuzzle_checkSolvedSequence)(obj, state));
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
            texture = objFindTexture(obj, 0, 0);
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
        if (state->pulseTimer < lbl_803E55F4)
        {
            state->flags &= ~SC_TOTEMPUZZLE_PULSE_FLAG;
            Sfx_PlayFromObjectLimited((int)obj, SFXtr_jbike_whine2, 2);
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
            (state->angle > (gTotemPuzzleAngleStep * (f32)(s32)(state->stepIndex + 1))))
        {
            f32 step = lbl_803E5628 * state->peerPhaseOffset;
            state->angle -= step * timeDelta;
        }
        else if (state->angle < (gTotemPuzzleAngleStep * (f32)(s32)state->stepIndex))
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

void sc_totempuzzle_release(void)
{
}

void sc_totempuzzle_initialise(void)
{
}

void sc_totempuzzle_init(ScTotemPuzzleObject* obj, ScTotemPuzzleMapData* params)
{
    ScTotemPuzzleState* state;
    ObjTextureRuntimeSlot* tex;
    int r;
    f32 fz;

    state = obj->state;
    obj->puzzleIndex = params->puzzleIndex;
    if (obj->puzzleIndex < 0 || obj->puzzleIndex > SC_TOTEMPUZZLE_CAP_INDEX)
    {
        obj->puzzleIndex = 0;
    }
    if (obj->puzzleIndex == SC_TOTEMPUZZLE_CAP_INDEX)
    {
        tex = objFindTexture(obj, 0, 0);
        if (tex != NULL)
        {
            tex->textureId = SC_TOTEMPUZZLE_SOLVED_TEXTURE_ID;
        }
    }
    state->stepIndex = obj->puzzleIndex;
    if (GameBit_Get(0x639) == 0)
    {
        state->angle = (f32)(s32)gTotemPuzzleStepAngles[state->stepIndex];
    }
    else
    {
        state->angle = lbl_803E562C;
        tex = objFindTexture(obj, 0, 0);
        if (tex != NULL)
        {
            tex->textureId = SC_TOTEMPUZZLE_SOLVED_TEXTURE_ID;
        }
    }
    obj->yaw = (s16)(s32)state->angle;
    r = randomGetRange(7, 10);
    fz = r;
    fz = lbl_803E5630 * fz;
    state->pulseTimerReset = fz;
    state->pulseTimer = fz;
    if (obj->puzzleIndex & 1)
    {
        state->flags = 1;
    }
    state->peerPhaseOffset = lbl_803E55FC;
    obj->animEventCallback = fn_801DD170;
    obj->objectFlags = (u16)(obj->objectFlags | (SC_TOTEMPUZZLE_OBJFLAG_HIDDEN | SC_TOTEMPUZZLE_OBJFLAG_HITDETECT_DISABLED));
}

/* descriptor/ptr table auto 0x80327a24-0x80327a60 */
u32 gSC_totempuzzleObjDescriptor[15] = { 0x00000000, 0x00000000, 0x00000000, 0x00090000, (u32)sc_totempuzzle_initialise, (u32)sc_totempuzzle_release, 0x00000000, (u32)sc_totempuzzle_init, (u32)sc_totempuzzle_update, (u32)sc_totempuzzle_hitDetect, (u32)sc_totempuzzle_render, (u32)sc_totempuzzle_free, (u32)sc_totempuzzle_getObjectTypeId, (u32)sc_totempuzzle_getExtraSize, 0x00000000 };
