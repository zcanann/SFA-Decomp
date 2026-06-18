/*
 * DLL 0x004E - camera mode: world map.
 *
 * The world-map camera follows a focus object across the planet map. Its
 * state (CameraModeWorldMapState, allocated lazily in _init via lbl_803DD588)
 * tracks the orbit distance/velocity, a settle counter and a focus-blend
 * timer. _copyToCurrent feeds the mode byte and focus-object id from the
 * map UI; _update runs one of two cameras keyed on that mode:
 *   mode 0: free overview - C-stick yaws/pitches the orbit, L/R (button bits
 *           4/8) zoom, distance eased between lbl_803E1A3C..lbl_803E1A40, and
 *           a focus blend slews the camera toward the focus object.
 *   mode 1: locked path camera aimed from a fixed pitch, also driving the
 *           map marker/reticle object (0x43077) and widescreen offset.
 * Both modes orbit around the map reference object (0x42fff): mode 0 blends
 * the focus toward it, mode 1 aims the path camera from it.
 * Each frame _update also points the compass marker (0x431dc) and fades the
 * highlight object (0x4325b) by view angle. A 0xC-class screen transition
 * gates entry to each mode.
 */
#include "main/mm.h"
#include "main/dll/CAM/camworldmap_state.h"
#include "main/game_object.h"
#include "main/screen_transition.h"

extern s16 getAngle(f32 dx, f32 dz);
extern f32 sqrtf(f32 x);
extern f32 mathSinf(f32 x);
extern float mathCosf(float x);

#pragma scheduling on
#pragma peephole on
extern CameraModeWorldMapState* lbl_803DD588;
extern f32 lbl_803E1A40;
extern f32 lbl_803E1A28;
extern f32 lbl_803E1A80;
extern int ObjList_FindObjectById(int id);
extern int getButtonsHeld(int pad);
extern int getButtonsJustPressed(int pad);
extern int padGetCX(int pad);
extern int padGetCY(int pad);
extern int isWidescreen(void);
extern void fn_8012DDB8(int mode);
extern f32 lbl_80319DF8[];
extern f32 lbl_803E1A2C;
extern f32 lbl_803E1A30;
extern f32 lbl_803E1A34;
extern f32 lbl_803E1A38;
extern f32 lbl_803E1A3C;
extern f32 lbl_803E1A44;
extern f32 lbl_803E1A48;
extern f32 lbl_803E1A4C;
extern f32 lbl_803E1A50;
extern f32 lbl_803E1A54;
extern f32 lbl_803E1A58;
extern f32 lbl_803E1A5C;
extern f32 lbl_803E1A60;
extern f32 lbl_803E1A64;
extern f32 lbl_803E1A68;
extern f32 lbl_803E1A6C;

#pragma scheduling off
#pragma peephole off
void CameraModeWorldMap_release(void)
{
}

void CameraModeWorldMap_initialise(void)
{
}

void CameraModeWorldMap_init(int* obj)
{
    register u32 bitval;
    if (lbl_803DD588 == NULL)
    {
        lbl_803DD588 = (CameraModeWorldMapState*)mmAlloc(sizeof(CameraModeWorldMapState), 15, 0);
    }
    lbl_803DD588->distance = lbl_803E1A40;
    lbl_803DD588->distanceVelocity = lbl_803E1A28;
    bitval = 0;
    lbl_803DD588->mode = bitval;
    lbl_803DD588->previousMode = bitval;
    lbl_803DD588->flags.transitionActive = 0;
    lbl_803DD588->settleFrames = 1;
    lbl_803DD588->focusBlendTimer = 0;
    lbl_803DD588->focusObjectId = 0;
    *(f32*)((char*)obj + 0xB4) = lbl_803E1A80;
    ((GameObject*)obj)->anim.rotX = -32768;
}

void CameraModeWorldMap_copyToCurrent(int* p1, int kind)
{
    switch (kind)
    {
    case 0:
        if (p1 == NULL) return;
        lbl_803DD588->mode = *(u8*)p1;
        return;
    case 1:
    case 2:
        if (p1 == NULL) return;
        lbl_803DD588->focusObjectId = *p1;
        if (kind == 1)
        {
            lbl_803DD588->focusBlendTimer = 20;
        }
        else
        {
            lbl_803DD588->focusBlendTimer = 1;
        }
        return;
    }
}

#pragma opt_common_subs off
#pragma opt_common_subs reset

void CameraModeWorldMap_free(void)
{
    extern void mm_free(u32); /* #57 */
    mm_free((u32)lbl_803DD588);
    lbl_803DD588 = NULL;
}

#pragma dont_inline on
#pragma dont_inline reset

void CameraModeWorldMap_update(u8* obj)
{
    extern void Obj_TransformWorldPointToLocal(f32 x, f32 y, f32 z, f32* ox, f32* oy, f32* oz, int mtx); /* #57 */
    GameObject* camera = (GameObject*)obj;
    GameObject* focus;
    GameObject *objA, *objB;
    int buttons;
    f32 spd = lbl_803E1A28;
    f32 mdx, mdz;
    s16 e;

    focus = (GameObject*)camera->anim.targetObj;
    objA = (GameObject*)ObjList_FindObjectById(0x42fff);
    objB = (GameObject*)ObjList_FindObjectById(0x4325b);
    buttons = (u16)getButtonsHeld(0);
    getButtonsJustPressed(0);

    switch (lbl_803DD588->mode)
    {
    case 0:
        if (lbl_803DD588->previousMode != lbl_803DD588->mode)
        {
            lbl_803DD588->focusBlendTimer = 1;
            (*gScreenTransitionInterface)->start(0xc, 1);
            lbl_803DD588->settleFrames = 2;
            lbl_803DD588->flags.transitionActive = 1;
        }
        else
        {
            s16 dYaw, dPitch;
            if (lbl_803DD588->flags.transitionActive != 0 &&
                (*gScreenTransitionInterface)->isFinished() != 0)
            {
                fn_8012DDB8(0);
                (*gScreenTransitionInterface)->step(0xc, 1);
                lbl_803DD588->flags.transitionActive = 0;
                *(u8*)(*(int*)&((GameObject*)ObjList_FindObjectById(0x43077))->extra + 0x27d) = 0;
            }
            if (lbl_803DD588->flags.transitionActive == 0)
            {
                lbl_803DD588->settleFrames -= 1;
                if (lbl_803DD588->settleFrames < 1)
                {
                    lbl_803DD588->settleFrames = 1;
                }
                if (buttons & 8)
                {
                    spd = lbl_803E1A2C * lbl_803DD588->distance;
                }
                if (buttons & 4)
                {
                    spd = lbl_803E1A30 * lbl_803DD588->distance;
                }
                {
                    f32 a, b, rate, vel;
                    if (spd < lbl_803E1A28)
                    {
                        a = -spd;
                    }
                    else
                    {
                        a = spd;
                    }
                    vel = lbl_803DD588->distanceVelocity;
                    if (vel < lbl_803E1A28)
                    {
                        b = -vel;
                    }
                    else
                    {
                        b = vel;
                    }
                    if (b > a)
                    {
                        rate = lbl_803E1A34;
                    }
                    else
                    {
                        rate = lbl_803E1A38;
                    }
                    lbl_803DD588->distanceVelocity =
                        rate * (spd - vel) + lbl_803DD588->distanceVelocity;
                }
                lbl_803DD588->distance = lbl_803DD588->distance + lbl_803DD588->distanceVelocity;
                if (lbl_803DD588->distance < lbl_803E1A3C)
                {
                    lbl_803DD588->distance = lbl_803E1A3C;
                }
                if (lbl_803DD588->distance > lbl_803E1A40)
                {
                    lbl_803DD588->distance = lbl_803E1A40;
                }
                dYaw = (s16)((s8)padGetCX(0) * 3);
                dPitch = (s16)((s8)padGetCY(0) * 3);
                if (lbl_803DD588->focusBlendTimer != 0)
                {
                    GameObject* f = (GameObject*)ObjList_FindObjectById(lbl_803DD588->focusObjectId);
                    f32 dx = f->anim.worldPosX - objA->anim.worldPosX;
                    f32 dz = f->anim.worldPosZ - objA->anim.worldPosZ;
                    s16 d;
                    f32 cur;
                    lbl_803DD588->targetAngle = (s16)(0x8000 - getAngle(dx, dz));
                    d = (s16)(lbl_803DD588->targetAngle - (u16)camera->anim.rotX);
                    if (d > 0x8000)
                    {
                        d = (s16)(d - 0xffff);
                    }
                    if (d < -0x8000)
                    {
                        d += 0xffff;
                    }
                    camera->anim.rotX = camera->anim.rotX + d / lbl_803DD588->focusBlendTimer;
                    lbl_803DD588->targetAngle =
                        (s16)(0x47d0 - getAngle(sqrtf(dx * dx + dz * dz),
                                                f->anim.worldPosY - objA->anim.worldPosY));
                    d = (s16)(lbl_803DD588->targetAngle - (u16)camera->anim.rotY);
                    if (d > 0x8000)
                    {
                        d = (s16)(d - 0xffff);
                    }
                    if (d < -0x8000)
                    {
                        d += 0xffff;
                    }
                    camera->anim.rotY = camera->anim.rotY + d / lbl_803DD588->focusBlendTimer;
                    cur = lbl_803DD588->distance;
                    lbl_803DD588->distance =
                        cur + (f32)((s16)(s32)(lbl_803E1A44 - cur) /
                            (s32)lbl_803DD588->focusBlendTimer);
                    lbl_803DD588->focusBlendTimer -= 1;
                }
                camera->anim.rotX += dYaw;
                camera->anim.rotY += dPitch;
                if (camera->anim.rotY > 12000)
                {
                    camera->anim.rotY = 12000;
                }
                if (camera->anim.rotY < -12000)
                {
                    camera->anim.rotY = -12000;
                }
                {
                    f32 snYaw, csYaw, snPit, csPit;
                    f32 r, vy, h, px, pz;
                    f32 dxx, dyy, dzz;
                    snYaw = -mathCosf(lbl_803E1A48 * (f32)camera->anim.rotX / lbl_803E1A4C);
                    csYaw = mathSinf(lbl_803E1A48 * (f32)camera->anim.rotX / lbl_803E1A4C);
                    snPit = mathCosf(lbl_803E1A48 * (f32)(camera->anim.rotY + 0x320) / lbl_803E1A4C);
                    csPit = mathSinf(lbl_803E1A48 * (f32)(camera->anim.rotY + 0x320) /
                        lbl_803E1A4C);
                    r = lbl_803DD588->distance;
                    vy = r * csPit;
                    h = r * snPit;
                    px = h * csYaw;
                    pz = h * snYaw;
                    dxx = camera->anim.worldPosX - (focus->anim.worldPosX + px);
                    dyy = camera->anim.worldPosY - ((lbl_803E1A50 + focus->anim.worldPosY) + vy);
                    dzz = camera->anim.worldPosZ - (focus->anim.worldPosZ + pz);
                    camera->anim.worldPosX =
                        camera->anim.worldPosX - dxx / (f32)lbl_803DD588->settleFrames;
                    camera->anim.worldPosY =
                        camera->anim.worldPosY - dyy / (f32)lbl_803DD588->settleFrames;
                    camera->anim.worldPosZ =
                        camera->anim.worldPosZ - dzz / (f32)lbl_803DD588->settleFrames;
                }
            }
        }
        break;
    case 1:
        {
            GameObject* g = (GameObject*)ObjList_FindObjectById(0x43077);
            if (lbl_803DD588->previousMode != lbl_803DD588->mode)
            {
                (*gScreenTransitionInterface)->start(0xc, 1);
                lbl_803DD588->settleFrames = 2;
                lbl_803DD588->flags.transitionActive = 1;
            }
            else
            {
                if (lbl_803DD588->flags.transitionActive != 0 &&
                    (*gScreenTransitionInterface)->isFinished() != 0)
                {
                    fn_8012DDB8(1);
                    (*gScreenTransitionInterface)->step(0xc, 1);
                    lbl_803DD588->flags.transitionActive = 0;
                    *(u8*)(*(int*)&((GameObject*)ObjList_FindObjectById(0x43077))->extra + 0x27d) = 1;
                }
                if (lbl_803DD588->flags.transitionActive == 0)
                {
                    int ang;
                    s16 d;
                    u16 my;
                    lbl_803DD588->settleFrames -= 1;
                    if (lbl_803DD588->settleFrames < 1)
                    {
                        lbl_803DD588->settleFrames = 1;
                    }
                    ang = (u16) - getAngle(objA->anim.worldPosX - focus->anim.worldPosX,
                                           objA->anim.worldPosZ - focus->anim.worldPosZ);
                    d = (s16)((ang - 0x308f) - (u16)camera->anim.rotX);
                    if (d > 0x8000)
                    {
                        d = (s16)(d - 0xffff);
                    }
                    if (d < -0x8000)
                    {
                        d += 0xffff;
                    }
                    camera->anim.rotX = camera->anim.rotX + d / lbl_803DD588->settleFrames;
                    d = (s16)(0x7d0 - (u16)camera->anim.rotY);
                    if (d > 0x8000)
                    {
                        d = (s16)(d - 0xffff);
                    }
                    if (d < -0x8000)
                    {
                        d += 0xffff;
                    }
                    camera->anim.rotY = camera->anim.rotY + d / lbl_803DD588->settleFrames;
                    {
                        f32 a, sn, cs, sn54, cs54;
                        f32 t6, t5, px, pz;
                        f32 dxx, dyy, dzz;
                        a = lbl_803E1A48 * (f32)(u16)(ang - 0x39dc) / lbl_803E1A4C;
                        sn = -mathCosf(a);
                        cs = mathSinf(a);
                        sn54 = mathCosf(lbl_803E1A54);
                        cs54 = mathSinf(lbl_803E1A54);
                        t6 = lbl_803E1A58 * cs54;
                        t5 = lbl_803E1A58 * sn54;
                        px = t5 * cs;
                        pz = t5 * sn;
                        dxx = camera->anim.worldPosX - (focus->anim.worldPosX + px);
                        dyy = camera->anim.worldPosY -
                            (lbl_803E1A5C + (focus->anim.worldPosY + t6));
                        dzz = camera->anim.worldPosZ - (focus->anim.worldPosZ + pz);
                        camera->anim.worldPosX =
                            camera->anim.worldPosX - dxx / (f32)lbl_803DD588->settleFrames;
                        camera->anim.worldPosY =
                            camera->anim.worldPosY - dyy / (f32)lbl_803DD588->settleFrames;
                        camera->anim.worldPosZ =
                            camera->anim.worldPosZ - dzz / (f32)lbl_803DD588->settleFrames;
                    }
                    my = (u16)(camera->anim.rotX + 0x1388);
                    if (isWidescreen() != 0)
                    {
                        my = (u16)(my + 0x514);
                    }
                    {
                        f32 b = lbl_803E1A48 * (f32)my / lbl_803E1A4C;
                        f32 sb = mathCosf(b);
                        f32 cb = -mathSinf(b);
                        g->anim.localPosX = lbl_803E1A60 * cb + camera->anim.worldPosX;
                        g->anim.localPosY =
                            camera->anim.worldPosY + lbl_80319DF8[(s8) * (u8*)&g->anim.bankIndex];
                        g->anim.localPosZ = lbl_803E1A60 * sb + camera->anim.worldPosZ;
                        g->anim.rotX = (s16)(-0xbb8 - my);
                    }
                }
            }
            break;
        }
    }

    lbl_803DD588->previousMode = lbl_803DD588->mode;
    {
        GameObject* marker = (GameObject*)ObjList_FindObjectById(0x431dc);
        mdx = marker->anim.worldPosX - camera->anim.worldPosX;
        mdz = marker->anim.worldPosZ - camera->anim.worldPosZ;
        marker->anim.rotX = (s16)(getAngle(mdx, mdz) + 0x8000);
        marker->anim.rotY = (s16)(0x8000 - getAngle(sqrtf(mdx * mdx + mdz * mdz),
                                                    marker->anim.worldPosY - camera->anim.worldPosY));
        marker->anim.rootMotionScale = lbl_803E1A64 + lbl_803E1A68 / lbl_803DD588->distance;
        objB->anim.rotX = marker->anim.rotX;
        objB->anim.rotY = marker->anim.rotY;
        objB->anim.rootMotionScale = marker->anim.rootMotionScale;
    }

    e = (s16)(objB->anim.rotX - 0x2198);
    if (e > -0x2000 && e < 0x2000)
    {
        f32 lim = lbl_803E1A28;
        if (lbl_803E1A28 <=
            lbl_803E1A6C *
            (mathCosf(lbl_803E1A48 * (f32)((objB->anim.rotX - 0x2198) * 2) / lbl_803E1A4C) *
                mathCosf(lbl_803E1A48 * (f32)((objB->anim.rotY - 0x4000) * 2) / lbl_803E1A4C)))
        {
            lim = lbl_803E1A6C *
            (mathCosf(lbl_803E1A48 * (f32)((objB->anim.rotX - 0x2198) * 2) / lbl_803E1A4C) *
                mathCosf(lbl_803E1A48 * (f32)((objB->anim.rotY - 0x4000) * 2) / lbl_803E1A4C));
        }
        objB->anim.alpha = (s32)lim;
    }
    else
    {
        objB->anim.alpha = 0;
    }

    Obj_TransformWorldPointToLocal(camera->anim.worldPosX, camera->anim.worldPosY, camera->anim.worldPosZ,
                                   &camera->anim.localPosX, &camera->anim.localPosY, &camera->anim.localPosZ,
                                   *(int*)&camera->anim.parent);
}
