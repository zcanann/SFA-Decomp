/*
 * DLL 0x004D (cameramodenpcspeak) - the dialogue/"NPC speak" camera mode.
 *
 * Lazily allocates a single CameraModeNpcSpeakState (lbl_803DD584) on first
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

extern s16 getAngle(f32 dx, f32 dz);
extern f32 sqrtf(f32 x);
extern f32 mathSinf(f32 x);
extern f32 mathCosf(f32 x);
extern void Rcp_DisableBlurFilter(void);
extern int getFocusedNpc(void);
extern int randomGetRange(int lo, int hi);
extern u32 Obj_GetYawDeltaToObject(); /* #57 */
extern void turnOnBlurFilter(f32 x, f32 y, f32 z, int a, int b);
extern f32 timeDelta;

void fn_8010DB7C(GameObject* target, f32* outX, f32* outY, f32* outZ);

extern CameraModeNpcSpeakState* lbl_803DD584;

extern f32 lbl_803E19D0;
extern f32 lbl_803E19D4;
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
    mm_free(lbl_803DD584);
    lbl_803DD584 = 0;
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

#pragma opt_common_subs off
void CameraModeNpcSpeak_init(u8* obj, int unused, u8* p3)
{
    CameraObject* camera = (CameraObject*)obj;
#define target ((GameObject*)camera->anim.targetObj)
    int mode = 0;
    int yawA, yawB;
    int spd;
    int d1, d2;
    void* npc;
    f32 vc, vb, va;
    u8 traceWork[CAMCONTROL_TRACE_WORK_SIZE];

    if (lbl_803DD584 == NULL)
    {
        lbl_803DD584 = (CameraModeNpcSpeakState*)mmAlloc(sizeof(CameraModeNpcSpeakState), 15, 0);
    }

    if (p3 != NULL)
    {
        CameraModeNpcSpeakInitParams* params = (CameraModeNpcSpeakInitParams*)p3;
        lbl_803DD584->anchorX = params->anchorX;
        lbl_803DD584->anchorY = params->anchorY;
        lbl_803DD584->anchorZ = params->anchorZ;
        mode = params->mode;
    }
    else
    {
        GameObject* focus = (GameObject*)getFocusedNpc();
        f32* fpos;
        if (focus == NULL)
        {
            lbl_803DD584->anchorX = lbl_803E19E8;
            lbl_803DD584->anchorY = lbl_803E19E8;
            lbl_803DD584->anchorZ = lbl_803E19E8;
        }
        fpos = *(f32**)((u8*)focus + 0x74);
        if (fpos == NULL)
        {
            lbl_803DD584->anchorX = lbl_803E19E8;
            lbl_803DD584->anchorY = lbl_803E19E8;
            lbl_803DD584->anchorZ = lbl_803E19E8;
        }
        lbl_803DD584->anchorX = fpos[0];
        lbl_803DD584->anchorY = fpos[1];
        lbl_803DD584->anchorZ = fpos[2];
    }
    if (mode == 4)
    {
        mode = randomGetRange(0, 3);
    }
    {
        f32 a, b;
        lbl_803DD584->unk20 = 0;
        lbl_803DD584->mode = mode;
        lbl_803DD584->unk14 = lbl_803E19E8;
        a = lbl_803E19EC;
        lbl_803DD584->targetHeightOffset = a;
        lbl_803DD584->lookAtHeightOffset = lbl_803E19DC;
        lbl_803DD584->lookAtYScale = lbl_803E19F0;
        b = lbl_803E19F4;
        lbl_803DD584->anchorLerpScale = b;
        lbl_803DD584->lookAtXZScale = b;
        lbl_803DD584->minDistance = a;
    }
    lbl_803DD584->orbitAngleOffset = randomGetRange(0x2000, 0x2c00);

    switch (mode)
    {
    case 0:
        lbl_803DD584->distanceOffset = lbl_803E19F8;
        break;
    case 1:
        lbl_803DD584->distanceOffset = lbl_803E19FC;
        break;
    case 2:
        lbl_803DD584->distanceOffset = lbl_803E1A00;
        break;
    case 5:
        lbl_803DD584->distanceOffset = lbl_803E1A04;
        break;
    case 3:
        lbl_803DD584->distanceOffset = lbl_803DB9C0;
        lbl_803DD584->orbitAngleOffset = randomGetRange(0xf00, 0x1f00);
        lbl_803DD584->lookAtHeightOffset = lbl_803E19E8;
        break;
    case 6:
        lbl_803DD584->targetHeightOffset = lbl_803DB9A8;
        lbl_803DD584->lookAtHeightOffset = lbl_803DB9AC;
        lbl_803DD584->anchorLerpScale = lbl_803DD580;
        lbl_803DD584->lookAtYScale = lbl_803DB9B0;
        lbl_803DD584->orbitAngleOffset = lbl_803DB9BC;
        lbl_803DD584->lookAtXZScale = lbl_803DB9B4;
        lbl_803DD584->distanceOffset = lbl_803DB9B8;
        lbl_803DD584->orbitAngleVelocity = 0xb6;
        lbl_803DD584->minDistance = lbl_803E19E8;
        break;
    case 7:
        lbl_803DD584->distanceOffset = lbl_803E19F8;
        lbl_803DD584->targetHeightOffset = lbl_803E1A08;
        lbl_803DD584->anchorLerpScale = lbl_803E1A0C;
        lbl_803DD584->lookAtXZScale = lbl_803E1A10;
        lbl_803DD584->lookAtYScale = lbl_803E1A14;
        lbl_803DD584->orbitAngleOffset = randomGetRange(0x1800, 0x1c00);
        break;
    case 8:
        lbl_803DD584->distanceOffset = lbl_803E1A18;
        lbl_803DD584->lookAtHeightOffset = lbl_803E1A1C;
        break;
    default:
        lbl_803DD584->distanceOffset = lbl_803E19F8;
        break;
    }

    yawA = getAngle(camera->anim.worldPosX - lbl_803DD584->anchorX,
                         camera->anim.worldPosZ - lbl_803DD584->anchorZ);
    yawB = (u16)getAngle(target->anim.worldPosX - lbl_803DD584->anchorX,
                         target->anim.worldPosZ - lbl_803DD584->anchorZ);
    spd = lbl_803DD584->orbitAngleOffset;
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
        lbl_803DD584->orbitAngleOffset = -spd;
        lbl_803DD584->orbitAngleVelocity = -0x80;
    }

    if (mode != 6 && mode != 7 && (npc = (void*)getFocusedNpc()) != NULL)
    {
        s16 sd;
        int dd;
        sd = (s16)(yawB - (u16)target->anim.rotX);
        if (sd > 0x8000)
        {
            sd -= 0xffff;
        }
        if (sd < -0x8000)
        {
            sd += 0xffff;
        }
        dd = sd - (u16)(s16)
        Obj_GetYawDeltaToObject((int)target, npc, 0);
        if (dd > 0x8000)
        {
            dd -= 0xffff;
        }
        if (dd < -0x8000)
        {
            dd += 0xffff;
        }
        if ((dd > 0x1000 && lbl_803DD584->orbitAngleOffset > 0) ||
            (dd < -0x1000 && lbl_803DD584->orbitAngleOffset < 0))
        {
            lbl_803DD584->orbitAngleOffset = -lbl_803DD584->orbitAngleOffset;
        }
    }

    fn_8010DB7C(target, &va, &vb, &vc);
    camcontrol_traceMove(&camera->anim.worldPosX, &va, &lbl_803DD584->cameraX, traceWork, 3, 1,
                         1, lbl_803E1A20);
}
#undef target
#pragma opt_common_subs reset

void CameraModeNpcSpeak_update(u8* obj)
{
    extern void Obj_TransformWorldPointToLocal(f32 x, f32 y, f32 z, f32* ox, f32* oy, f32* oz, int mtx); /* #57 */
    CameraObject* camera = (CameraObject*)obj;
    CameraModeNpcSpeakState* speakState;
    GameObject* target = (GameObject*)camera->anim.targetObj;
    f32 ex, ez, ey;
    f32 dx, dy, dz;

    if (target == NULL)
    {
        return;
    }
    speakState = lbl_803DD584;
    if (speakState->mode == 6)
    {
        speakState->orbitAngleOffset =
            (s32)((f32)speakState->orbitAngleVelocity * timeDelta + speakState->orbitAngleOffset);
        if (lbl_803DD584->orbitAngleVelocity > 0 && lbl_803DD584->orbitAngleOffset > 0xd6d8)
        {
            lbl_803DD584->orbitAngleOffset = 0xd6d8;
        }
        else if (lbl_803DD584->orbitAngleVelocity < 0 && lbl_803DD584->orbitAngleOffset < -0xd6d8)
        {
            lbl_803DD584->orbitAngleOffset = -0xd6d8;
        }
        fn_8010DB7C(target, &lbl_803DD584->cameraX, &lbl_803DD584->cameraY, &lbl_803DD584->cameraZ);
    }
    camera->anim.worldPosX = lbl_803DD584->cameraX;
    camera->anim.worldPosY = lbl_803DD584->cameraY;
    camera->anim.worldPosZ = lbl_803DD584->cameraZ;
    dx = target->anim.worldPosX - speakState->anchorX;
    dy = (target->anim.worldPosY + lbl_803DD584->lookAtHeightOffset) - speakState->anchorY;
    dz = target->anim.worldPosZ - speakState->anchorZ;
    dx *= lbl_803DD584->lookAtXZScale;
    dy *= lbl_803DD584->lookAtYScale;
    dz *= lbl_803DD584->lookAtXZScale;
    if (lbl_803DD584->mode == 3)
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
    if (lbl_803DD584->mode != 3)
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
    CameraModeNpcSpeakState* state = lbl_803DD584;
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
        f32 scale = lbl_803DD584->anchorLerpScale;
        dx *= scale;
        dz *= scale;
    }
    dx += state->anchorX;
    dz += state->anchorZ;

    cosVal = mathSinf(lbl_803E19D0 * (f32)(s32)(angle + lbl_803DD584->orbitAngleOffset) / lbl_803E19D4);
    sinVal = mathCosf(lbl_803E19D0 * (f32)(s32)(angle + lbl_803DD584->orbitAngleOffset) / lbl_803E19D4);

    if (dist < lbl_803DD584->minDistance)
    {
        dist = lbl_803DD584->minDistance;
    }
    dist += lbl_803DD584->distanceOffset;

    *outX = cosVal * dist + dx;
    *outY = (target->anim.worldPosY + lbl_803DD584->targetHeightOffset) - lbl_803E19D8 * ((lbl_803E19DC + target->anim.
        worldPosY) - state->anchorY);
    *outZ = sinVal * dist + dz;
}
