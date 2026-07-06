/*
 * DLL 0x004D (cameramodenpcspeak) - the dialogue/"NPC speak" camera mode.
 *
 * Lazily allocates a single CameraModeNpcSpeakState (gCamNpcSpeakState) on first
 * init and frees it on free. init() seeds the anchor point from the init
 * params or, when none are given, from the focused NPC's position, then
 * picks a tuning preset from the mode id (0-8; mode 4 randomizes to 0-3)
 * that drives distance/height offsets, look-at scales and the starting
 * orbit angle. It chooses the shorter orbit direction toward the target and
 * flips it away from the NPC's facing where needed. update() places the
 * camera on that orbit each frame (mode 6 advances the orbit by a clamped
 * angular velocity), aims rotX/rotY at the look-at point, drives the blur
 * filter and converts the result back to local space. fn_8010DB7C is the
 * shared orbit-position solver used by both.
 */
#include "main/dll/CAM/camnpcspeak_state.h"
#include "main/mm.h"
#include "main/dll/CAM/cutCam.h"
#include "main/gameplay_runtime.h"
#include "main/object_transform.h"
extern s16 getAngle(f32 dx, f32 dz);
extern f32 sqrtf(f32 x);
extern float mathSinf(float x);
extern float mathCosf(float x);
extern int getFocusedNpc(void);
extern u32 Obj_GetYawDeltaToObject(); /* #57 */
extern void turnOnBlurFilter(f32 x, f32 y, f32 z, int a, int b);
extern f32 timeDelta;

void fn_8010DB7C(GameObject* target, f32* outX, f32* outY, f32* outZ);

extern CameraModeNpcSpeakState* gCamNpcSpeakState;
extern f32 gCamNpcSpeakPi;
extern f32 gCamNpcSpeakAngleToRadDivisor;
extern f32 lbl_803E19D8;
extern f32 lbl_803E19DC;
extern const f32 lbl_803E19E8;
extern f32 lbl_803E19EC;
extern f32 lbl_803E19F0;
extern f32 lbl_803E19F4;
extern f32 lbl_803E19F8;
extern f32 lbl_803E19FC;
extern f32 lbl_803E1A00;
extern f32 lbl_803E1A04;
extern f32 lbl_803E1A08;
extern f32 lbl_803E1A0C;
extern f32 lbl_803E1A10;
extern f32 lbl_803E1A14;
extern f32 lbl_803E1A18;
extern f32 lbl_803E1A1C;
extern f32 lbl_803E1A20;
extern f32 lbl_803DB9C0;
extern f32 lbl_803DB9A8;
extern f32 lbl_803DB9AC;
extern f32 lbl_803DB9B0;
extern f32 lbl_803DB9B4;
extern f32 lbl_803DB9B8;
extern int lbl_803DB9BC;
extern f32 lbl_803DD580;
extern f32 lbl_803DB9C4;

void CameraModeNpcSpeak_copyToCurrent_nop(void)
{
}

void CameraModeNpcSpeak_free(void)
{
    mm_free(gCamNpcSpeakState);
    gCamNpcSpeakState = 0;
    Rcp_DisableBlurFilter();
}

void CameraModeNpcSpeak_release(void)
{
}

void CameraModeNpcSpeak_initialise(void)
{
}

typedef struct CameraModeNpcSpeakInitParams
{
    f32 anchorX;
    f32 anchorY;
    f32 anchorZ;
    u8 mode;
} CameraModeNpcSpeakInitParams;

void CameraModeNpcSpeak_init(u8* obj, int unused, u8* initData)
{
    CameraObject* camera = (CameraObject*)obj;
#define target ((GameObject*)camera->anim.targetObj)
    u16 yawA, yawB;
    int mode = 0;
    int spd;
    int d1, d2;
    void* npc;
    f32 vc, vb, va;
    u8 traceWork[CAMCONTROL_TRACE_WORK_SIZE];

    if (gCamNpcSpeakState == NULL)
    {
        gCamNpcSpeakState = (CameraModeNpcSpeakState*)mmAlloc(sizeof(CameraModeNpcSpeakState), 15, 0);
    }

    if (initData != NULL)
    {
        CameraModeNpcSpeakInitParams* params = (CameraModeNpcSpeakInitParams*)initData;
        gCamNpcSpeakState->anchorX = params->anchorX;
        gCamNpcSpeakState->anchorY = params->anchorY;
        gCamNpcSpeakState->anchorZ = params->anchorZ;
        mode = params->mode;
    }
    else
    {
        GameObject* focus = (GameObject*)getFocusedNpc();
        f32* fpos;
        if (focus == NULL)
        {
            gCamNpcSpeakState->anchorX = lbl_803E19E8;
            gCamNpcSpeakState->anchorY = lbl_803E19E8;
            gCamNpcSpeakState->anchorZ = lbl_803E19E8;
        }
        fpos = *(f32**)((u8*)focus + 0x74);
        if (fpos == NULL)
        {
            gCamNpcSpeakState->anchorX = lbl_803E19E8;
            gCamNpcSpeakState->anchorY = lbl_803E19E8;
            gCamNpcSpeakState->anchorZ = lbl_803E19E8;
        }
        gCamNpcSpeakState->anchorX = fpos[0];
        gCamNpcSpeakState->anchorY = fpos[1];
        gCamNpcSpeakState->anchorZ = fpos[2];
    }
    if (mode == 4)
    {
        mode = randomGetRange(0, 3);
    }
    {
        f32 a, b;
        gCamNpcSpeakState->unk20 = 0;
        gCamNpcSpeakState->mode = mode;
        gCamNpcSpeakState->unk14 = lbl_803E19E8;
        a = lbl_803E19EC;
        gCamNpcSpeakState->targetHeightOffset = a;
        gCamNpcSpeakState->lookAtHeightOffset = lbl_803E19DC;
        gCamNpcSpeakState->lookAtYScale = lbl_803E19F0;
        b = lbl_803E19F4;
        gCamNpcSpeakState->anchorLerpScale = b;
        gCamNpcSpeakState->lookAtXZScale = b;
        gCamNpcSpeakState->minDistance = a;
    }
    gCamNpcSpeakState->orbitAngleOffset = randomGetRange(0x2000, 0x2c00);

    switch (mode)
    {
    case 0:
        gCamNpcSpeakState->distanceOffset = lbl_803E19F8;
        break;
    case 1:
        gCamNpcSpeakState->distanceOffset = lbl_803E19FC;
        break;
    case 2:
        gCamNpcSpeakState->distanceOffset = lbl_803E1A00;
        break;
    case 5:
        gCamNpcSpeakState->distanceOffset = lbl_803E1A04;
        break;
    case 3:
        gCamNpcSpeakState->distanceOffset = lbl_803DB9C0;
        gCamNpcSpeakState->orbitAngleOffset = randomGetRange(0xf00, 0x1f00);
        gCamNpcSpeakState->lookAtHeightOffset = lbl_803E19E8;
        break;
    case 6:
        gCamNpcSpeakState->targetHeightOffset = lbl_803DB9A8;
        gCamNpcSpeakState->lookAtHeightOffset = lbl_803DB9AC;
        gCamNpcSpeakState->anchorLerpScale = lbl_803DD580;
        gCamNpcSpeakState->lookAtYScale = lbl_803DB9B0;
        gCamNpcSpeakState->orbitAngleOffset = lbl_803DB9BC;
        gCamNpcSpeakState->lookAtXZScale = lbl_803DB9B4;
        gCamNpcSpeakState->distanceOffset = lbl_803DB9B8;
        gCamNpcSpeakState->orbitAngleVelocity = 0xb6;
        gCamNpcSpeakState->minDistance = lbl_803E19E8;
        break;
    case 7:
        gCamNpcSpeakState->distanceOffset = lbl_803E19F8;
        gCamNpcSpeakState->targetHeightOffset = lbl_803E1A08;
        gCamNpcSpeakState->anchorLerpScale = lbl_803E1A0C;
        gCamNpcSpeakState->lookAtXZScale = lbl_803E1A10;
        gCamNpcSpeakState->lookAtYScale = lbl_803E1A14;
        gCamNpcSpeakState->orbitAngleOffset = randomGetRange(0x1800, 0x1c00);
        break;
    case 8:
        gCamNpcSpeakState->distanceOffset = lbl_803E1A18;
        gCamNpcSpeakState->lookAtHeightOffset = lbl_803E1A1C;
        break;
    default:
        gCamNpcSpeakState->distanceOffset = lbl_803E19F8;
        break;
    }

    yawA = (u16)getAngle(camera->anim.worldPosX - gCamNpcSpeakState->anchorX,
                         camera->anim.worldPosZ - gCamNpcSpeakState->anchorZ);
    yawB = (u16)getAngle(target->anim.worldPosX - gCamNpcSpeakState->anchorX,
                         target->anim.worldPosZ - gCamNpcSpeakState->anchorZ);
    {
    CameraModeNpcSpeakState* st = gCamNpcSpeakState;
    spd = st->orbitAngleOffset;
    d1 = (yawB + spd) - yawA;
    if (d1 > 0x8000)
    {
        d1 -= 0xffff;
    }
    if (d1 < -0x8000)
    {
        d1 += 0xffff;
    }
    d2 = (yawB - spd) - yawA;
    if (d2 > 0x8000)
    {
        d2 -= 0xffff;
    }
    if (d2 < -0x8000)
    {
        d2 += 0xffff;
    }
    if (d1 < 0)
    {
        d1 = -d1;
    }
    if (d2 < 0)
    {
        d2 = -d2;
    }
    if (d2 < d1)
    {
        st->orbitAngleOffset = -spd;
        gCamNpcSpeakState->orbitAngleVelocity = -0x80;
    }
    }

    if (mode != 6 && mode != 7 && (npc = (void*)getFocusedNpc()) != NULL)
    {
        GameObject* tgt = target;
        s16 sd;
        int dd;
        sd = (s16)(yawB - (u16)tgt->anim.rotX);
        if (sd > 0x8000)
        {
            sd = (s16)(sd - 0xffff);
        }
        if (sd < -0x8000)
        {
            sd = (s16)(sd + 0xffff);
        }
        dd = sd - (u16)(s16)
        Obj_GetYawDeltaToObject((int)tgt, npc, 0);
        if (dd > 0x8000)
        {
            dd -= 0xffff;
        }
        if (dd < -0x8000)
        {
            dd += 0xffff;
        }
        if ((dd > 0x1000 && gCamNpcSpeakState->orbitAngleOffset > 0) ||
            (dd < -0x1000 && gCamNpcSpeakState->orbitAngleOffset < 0))
        {
            gCamNpcSpeakState->orbitAngleOffset = -gCamNpcSpeakState->orbitAngleOffset;
        }
    }

    fn_8010DB7C(target, &va, &vb, &vc);
    camcontrol_traceMove(&camera->anim.worldPosX, &va, &gCamNpcSpeakState->cameraX, traceWork, 3, 1,
                         1, lbl_803E1A20);
}
#undef target
#pragma opt_common_subs reset

void CameraModeNpcSpeak_update(u8* obj)
{
    CameraObject* camera = (CameraObject*)obj;
    CameraModeNpcSpeakState* speakState;
    GameObject* target = (GameObject*)camera->anim.targetObj;
    f32 ex, ez, ey;
    f32 dx, dy, dz;

    if (target == NULL)
    {
        return;
    }
    speakState = gCamNpcSpeakState;
    if (speakState->mode == 6)
    {
        speakState->orbitAngleOffset =
            (s32)((f32)speakState->orbitAngleVelocity * timeDelta + speakState->orbitAngleOffset);
        if (gCamNpcSpeakState->orbitAngleVelocity > 0 && gCamNpcSpeakState->orbitAngleOffset > 0xd6d8)
        {
            gCamNpcSpeakState->orbitAngleOffset = 0xd6d8;
        }
        else if (gCamNpcSpeakState->orbitAngleVelocity < 0 && gCamNpcSpeakState->orbitAngleOffset < -0xd6d8)
        {
            gCamNpcSpeakState->orbitAngleOffset = -0xd6d8;
        }
        fn_8010DB7C(target, &gCamNpcSpeakState->cameraX, &gCamNpcSpeakState->cameraY, &gCamNpcSpeakState->cameraZ);
    }
    camera->anim.worldPosX = gCamNpcSpeakState->cameraX;
    camera->anim.worldPosY = gCamNpcSpeakState->cameraY;
    camera->anim.worldPosZ = gCamNpcSpeakState->cameraZ;
    dx = target->anim.worldPosX - speakState->anchorX;
    dy = (target->anim.worldPosY + gCamNpcSpeakState->lookAtHeightOffset) - speakState->anchorY;
    dz = target->anim.worldPosZ - speakState->anchorZ;
    dx *= gCamNpcSpeakState->lookAtXZScale;
    dy *= gCamNpcSpeakState->lookAtYScale;
    dz *= gCamNpcSpeakState->lookAtXZScale;
    if (gCamNpcSpeakState->mode == 3)
    {
        camera->anim.rotY = (s16)(s32)
        getAngle(lbl_803DB9C4 * dy, sqrtf(dx * dx + dz * dz));
    }
    dx += speakState->anchorX;
    dy += speakState->anchorY;
    dz += speakState->anchorZ;
    ex = camera->anim.worldPosX - dx;
    ey = camera->anim.worldPosY - dy;
    ez = camera->anim.worldPosZ - dz;
    camera->anim.rotX = (s16)(0x8000 - getAngle(ex, ez));
    if (gCamNpcSpeakState->mode != 3)
    {
        camera->anim.rotY = (s16)(s32)
        getAngle(ey, sqrtf(ex * ex + ez * ez));
    }
    turnOnBlurFilter(speakState->anchorX, speakState->anchorY, speakState->anchorZ, 1, 0);
    Obj_TransformWorldPointToLocal(camera->anim.worldPosX, camera->anim.worldPosY, camera->anim.worldPosZ,
                                   &camera->anim.localPosX, &camera->anim.localPosY, &camera->anim.localPosZ,
                                   *(int*)&camera->anim.parent);
}

void fn_8010DB7C(GameObject* target, f32* outX, f32* outY, f32* outZ)
{
    CameraModeNpcSpeakState* state = gCamNpcSpeakState;
    f32 dx;
    f32 dz;
    f32 dist;
    u16 angle;
    f32 cosVal;
    f32 sinVal;

    dx = target->anim.worldPosX - state->anchorX;
    dz = target->anim.worldPosZ - state->anchorZ;
    dist = sqrtf(dx * dx + dz * dz);
    angle = getAngle(dx, dz);

    {
        f32 scale = gCamNpcSpeakState->anchorLerpScale;
        dx *= scale;
        dz *= scale;
    }
    dx += state->anchorX;
    dz += state->anchorZ;

    cosVal = mathSinf(gCamNpcSpeakPi * (f32)(s32)(angle + gCamNpcSpeakState->orbitAngleOffset) / gCamNpcSpeakAngleToRadDivisor);
    sinVal = mathCosf(gCamNpcSpeakPi * (f32)(s32)(angle + gCamNpcSpeakState->orbitAngleOffset) / gCamNpcSpeakAngleToRadDivisor);

    if (dist < gCamNpcSpeakState->minDistance)
    {
        dist = gCamNpcSpeakState->minDistance;
    }
    dist += gCamNpcSpeakState->distanceOffset;

    *outX = cosVal * dist + dx;
    *outY = (target->anim.worldPosY + gCamNpcSpeakState->targetHeightOffset) - lbl_803E19D8 * ((lbl_803E19DC + target->anim.
        worldPosY) - state->anchorY);
    *outZ = sinVal * dist + dz;
}
