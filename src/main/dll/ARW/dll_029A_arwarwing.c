#include "main/dll/dll_80220608_shared.h"
#include "main/effect_interfaces.h"
#include "main/game_object.h"
#include "global.h"
#include "main/audio/sfx_ids.h"
#include "main/mapEventTypes.h"

#include "main/dll/ARW/arwing_state.h"

#pragma peephole on
#pragma scheduling on
int getArwing(void) { return lbl_803DDD88; }
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
int arwarwing_getExtraSize(void) { return 0x498; }
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
int arwarwing_getObjectTypeId(void) { return 0; }
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling off
void arwarwing_free(int obj)
{
    ArwingState *state = ((GameObject *)obj)->extra;

    ObjGroup_RemoveObject(obj, 0x26);
    lbl_803DDD88 = 0;
    if (state->light != NULL) {
        ModelLightStruct_free(state->light);
    }
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
void arwarwing_release(void) {}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
void arwarwing_initialise(void) {}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void arwarwing_render(int obj, int p2, int p3, int p4, int p5)
{
    ArwingState *state = ((GameObject *)obj)->extra;
    int dx, dy;

    if (state->hitShake != 0) {
        dx = (int)(lbl_803E6FF4 *
                   mathSinf(lbl_803E6EFC * (f32)(u32) * (u16 *)&state->shakePitch / lbl_803E6F00));
        dy = (int)(lbl_803E6F5C *
                   mathSinf(lbl_803E6EFC * (f32)(u32) * (u16 *)&state->shakeYaw / lbl_803E6F00));
        ((GameObject *)obj)->anim.rotY = (s16)(((GameObject *)obj)->anim.rotY + dx);
        ((GameObject *)obj)->anim.rotZ = (s16)(((GameObject *)obj)->anim.rotZ + dy);
    }
    objRenderFn_8003b8f4(obj, p2, p3, p4, p5, lbl_803E6ED0);
    if (state->hitShake != 0) {
        ((GameObject *)obj)->anim.rotY = (s16)(((GameObject *)obj)->anim.rotY - dx);
        ((GameObject *)obj)->anim.rotZ = (s16)(((GameObject *)obj)->anim.rotZ - dy);
    }
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void arwarwing_hitDetect(int obj)
{
    ArwingState *state = ((GameObject *)obj)->extra;
    f32 pos[3];
    f32 mtx[12];

    if ((((GameObject *)obj)->objectFlags & 0x1000) != 0 && state->aimSnapshotValid != 0) {
        Obj_BuildWorldTransformMatrix(obj, mtx, 0);
        PSMTXMultVec(mtx, &state->aimOffsetX, pos);
        pos[0] += playerMapOffsetX;
        pos[2] += playerMapOffsetZ;
        fn_8008020C((s16)(0x8000 - *(s16 *)obj + state->aimYaw),
                    (s16)(((GameObject *)obj)->anim.rotY + state->aimPitch),
                    (s16)(((GameObject *)obj)->anim.rotZ + state->aimRoll),
                    pos[0], pos[1], pos[2], lbl_803E6FF8);
    }
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling off
void fn_8022D460(int arwing, f32 val) { (*(ArwingState **)(arwing + 0xb8))->unk20 = val; }
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling off
int fn_8022D46C(int arwing) { return (s16)(*(ArwingState **)(arwing + 0xb8))->rotYCur; }
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling off
void fn_8022D47C(int arwing, int p2) { (*(ArwingState **)(arwing + 0xb8))->rotYCur = (s16)p2; }
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling off
void fn_8022D48C(int out, int arwing)
{
    *(Vec12 *)out = *(Vec12 *)&(*(ArwingState **)(arwing + 0xb8))->velX;
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling off
void fn_8022D4AC(int arwing, int in)
{
    ArwingState *state = *(ArwingState **)(arwing + 0xb8);
    state->velX = *(f32 *)(in + 0);
    state->velY = *(f32 *)(in + 4);
    state->velZ = *(f32 *)(in + 8);
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling off
void fn_8022D4CC(int arwing, int in)
{
    int v = *(int *)(arwing + 0xb8) + 0x48;
    PSVECAdd(v, in, v);
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling off
void fn_8022D4F8(int arwing) { (*(ArwingState **)(arwing + 0xb8))->activeBombObj = 0; }
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling off
int arwarwing_getRequiredRingCount(int arwing) { return (*(ArwingState **)(arwing + 0xb8))->requiredRings; }
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling off
int arwarwing_getCollectedRingCount(int arwing) { return (*(ArwingState **)(arwing + 0xb8))->collectedRings; }
#pragma scheduling reset
#pragma peephole reset

#pragma scheduling off
void arwarwing_addScore(int arwing, u8 amount)
{
    ArwingState *state = *(ArwingState **)(arwing + 0xb8);
    u16 v;
    state->score = state->score + amount;
    v = state->score;
    if (v > 0x270f) {
        v = 0x270f;
    }
    state->score = v;
}
#pragma scheduling reset

#pragma scheduling off
int arwarwing_getScore(int arwing)
{
    ArwingState *state = *(ArwingState **)(arwing + 0xb8);
    if (state->score > 0x270f) {
        state->score = 0x270f;
    }
    return state->score;
}
#pragma scheduling reset

#pragma peephole on
#pragma scheduling off
int arwarwing_getBombCount(int arwing) { return (*(ArwingState **)(arwing + 0xb8))->bombCount; }
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling off
int arwarwing_getMaxShield(int arwing) { return *(s8 *)&(*(ArwingState **)(arwing + 0xb8))->maxShield; }
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling off
int arwarwing_getShield(int arwing) { return *(s8 *)&(*(ArwingState **)(arwing + 0xb8))->shield; }
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling off
int fn_8022D5A0(int arwing) { return ((*(ArwingState **)(arwing + 0xb8))->counter475)++; }
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling off
int fn_8022D5B4(int arwing) { return ((*(ArwingState **)(arwing + 0xb8))->counter474)++; }
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling off
int fn_8022D5C8(int arwing) { return ((*(ArwingState **)(arwing + 0xb8))->counter473)++; }
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling off
int fn_8022D5DC(int arwing) { return ((*(ArwingState **)(arwing + 0xb8))->counter472)++; }
#pragma scheduling reset
#pragma peephole reset

#pragma scheduling off
int arwarwing_incrementCollectedRingCount(int arwing)
{
    ArwingState *state = *(ArwingState **)(arwing + 0xb8);
    if (state->collectedRings == 9) {
        state->score = state->score + 0x64;
        if (state->score > 0x270f) {
            state->score = 0x270f;
        }
    }
    return (state->collectedRings)++;
}
#pragma scheduling reset

#pragma peephole off
#pragma scheduling off
void arwarwing_addMaxShield(int arwing, int p2)
{
    ArwingState *state = *(ArwingState **)(arwing + 0xb8);
    *(s8 *)&state->maxShield = state->maxShield + p2;
}
#pragma scheduling reset
#pragma peephole reset

#pragma scheduling off
void arwarwing_addShield(int arwing, int p2)
{
    ArwingState *state = *(ArwingState **)(arwing + 0xb8);
    s8 v;

    *(s8 *)&state->shield = state->shield + p2;
    v = *(s8 *)&state->shield;
    if (v < 0) {
        v = 0;
    } else if (v > *(s8 *)&state->maxShield) {
        v = *(s8 *)&state->maxShield;
    }
    *(s8 *)&state->shield = v;
    if (*(s8 *)&state->shield > 3) {
        Sfx_StopObjectChannel(arwing, 4);
    }
}
#pragma scheduling reset

#pragma peephole off
#pragma scheduling off
void fn_8022BCD0(int p, int q) {
    u8 flag;
    struct {
        u8 pad[6];
        s16 type;
        f32 a;
        f32 b;
        f32 c;
        f32 d;
    } emit;
    flag = 0;
    if ((s8) * (u8 *)(q + 0x468) <= 4) {
        if ((*(u8 *)(q + 0x476))++ % 2 != 0) {
            emit.a = lbl_803E6F08;
            emit.b = lbl_803E6F0C;
            emit.c = lbl_803E6F10;
            emit.d = lbl_803E6F14;
            if ((s8) * (u8 *)(q + 0x468) <= 2)
                emit.type = 0x61a8;
            else
                emit.type = -0x63c0;
            (*gPartfxInterface)->spawnObject((void *)p, 0x7d0, &emit.pad, 4, -1, &flag);
        }
    }
    if ((s8) * (u8 *)(q + 0x468) <= 2) {
        emit.a = lbl_803E6F18;
        emit.type = 0xc0a;
        emit.b = lbl_803E6ECC;
        emit.c = lbl_803E6F1C;
        emit.d = lbl_803E6F20;
        (*gPartfxInterface)->spawnObject((void *)p, 0x7d1, &emit.pad, 4, -1, &flag);
    }
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling off
void fn_8022C680(int obj) {
    switch ((s8) * (u8 *)(obj + 0xac)) {
    case 0x3a:
        if ((u32)GameBit_Get(0xc85) != 0) {
            GameBit_Set(0x405, 0);
            (*gMapEventInterface)->setMode(0xb, 5);
            (*gMapEventInterface)->setAnimEvent(0xb, 0xa, 1);
            (*gMapEventInterface)->setAnimEvent(0xb, 0xb, 1);
            warpToMap(0x22, 0);
        } else {
            warpToMap(0x6c, 0);
        }
        break;
    case 0x3b:
        warpToMap(0x77, 0);
        break;
    case 0x3d:
        warpToMap(0x78, 0);
        break;
    case 0x3c:
        warpToMap(0x63, 0);
        break;
    case 0x3e:
        warpToMap(0x79, 0);
        break;
    }
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void arwarwing_updateWeaponFire(int obj, int state) {
    int fire;
    fn_8022A9C8(obj, state);
    {
        f32 t = ((ArwingState *)state)->fireCooldown;
        if (t > lbl_803E6ECC) {
            ((ArwingState *)state)->fireCooldown = t - timeDelta;
            if (((ArwingState *)state)->fireCooldown >= lbl_803E6ECC)
                return;
            ((ArwingState *)state)->fireCooldown = lbl_803E6ECC;
        }
    }
    fire = 0;
    if (((ArwingState *)state)->inputFlags2 & 0x100) {
        ((ArwingState *)state)->fireTimer -= timeDelta;
        if (((ArwingState *)state)->fireTimer <= lbl_803E6ECC)
            fire = 1;
    }
    if ((((ArwingState *)state)->inputFlags & 0x100) == 0 && fire == 0)
        return;
    ((ArwingState *)state)->fireTimer = lbl_803E6F04;
    switch ((s8) ((ArwingState *)state)->laserLevel) {
    case 2:
        arwarwing_spawnLaserShot(obj, state, 0, 2, 1);
        arwarwing_spawnLaserShot(obj, state, 1, 2, 0);
        break;
    case 1:
        arwarwing_spawnLaserShot(obj, state, 0, 1, 1);
        arwarwing_spawnLaserShot(obj, state, 1, 1, 0);
        break;
    default:
        arwarwing_spawnLaserShot(obj, state, ((ArwingState *)state)->laserSide, 0, 1);
        ((ArwingState *)state)->laserSide = (((ArwingState *)state)->laserSide ^ 1) & 0xff;
        break;
    }
    ((ArwingState *)state)->fireCooldown = (f32)(u32) ((ArwingState *)state)->fireDelay;
}
#pragma scheduling reset
#pragma peephole reset

#pragma scheduling off
void arwarwing_update(int obj)
{
    int state = *(int *)&((GameObject *)obj)->extra;
    f32 camPos[2];
    s16 camRot[3];
    u8 mode;
    int p;
    f32 t;
    f32 throttle;

    if ((((ArwingState *)state)->flags477 & 1) == 0) {
        fn_8022CDEC(obj, state);
        return;
    }
    mode = ((ArwingState *)state)->mode;
    if (mode == 5) {
        t = ((ArwingState *)state)->modeTimer - timeDelta;
        ((ArwingState *)state)->modeTimer = t;
        if (t <= lbl_803E6ECC) {
            ((ArwingState *)state)->mode = 6;
            (*gScreenTransitionInterface)->start(0x14, 1);
            ((ArwingState *)state)->modeTimer = lbl_803E6F34;
        }
        return;
    }
    if (mode == 6) {
        t = ((ArwingState *)state)->modeTimer - timeDelta;
        ((ArwingState *)state)->modeTimer = t;
        if (t <= lbl_803E6ECC) {
            if (*(s8 *)(obj + 0xac) == 0x26) {
                unlockLevel(0, 0, 1);
                lockLevel(mapGetDirIdx(0x26), 0);
                lockLevel(mapGetDirIdx(0xb), 1);
                warpToMap(0x32, 0);
            } else {
                warpToMap(0x60, 0);
            }
        }
        return;
    }
    if (mode == 4) {
        t = ((ArwingState *)state)->modeTimer - timeDelta;
        ((ArwingState *)state)->modeTimer = t;
        if (t <= lbl_803E6ECC) {
            ((ArwingState *)state)->mode = 5;
            ((ArwingState *)state)->modeTimer = lbl_803E6F24;
            ((GameObject *)obj)->anim.flags = (s16)(((GameObject *)obj)->anim.flags | OBJANIM_FLAG_HIDDEN);
            spawnExplosion(obj, lbl_803E6F28, 1, 0, 1, 1, 0, 1, 0);
        }
        ((ArwingState *)state)->rotZCur =
            (int)(lbl_803E6F6C * timeDelta + (f32) ((ArwingState *)state)->rotZCur);
        ((GameObject *)obj)->anim.rotZ = (s16) ((ArwingState *)state)->rotZCur;
        ((ArwingState *)state)->velY = ((ArwingState *)state)->velY - lbl_803E6EF8 * timeDelta;
        objMove(obj, ((ArwingState *)state)->velX * timeDelta, ((ArwingState *)state)->velY * timeDelta,
                ((ArwingState *)state)->velZ * timeDelta);
        fn_8022AE1C(obj, state);
        ((GameObject *)((ArwingState *)state)->thrusterL)->anim.flags |= OBJANIM_FLAG_HIDDEN;
        ((GameObject *)((ArwingState *)state)->thrusterR)->anim.flags |= OBJANIM_FLAG_HIDDEN;
    } else {
        fn_8022A670(obj, state);
        if ((((GameObject *)obj)->anim.flags & OBJANIM_FLAG_HIDDEN) != 0) {
            *(s16 *)&((ArwingState *)state)->inputFlags2 = 0;
            *(s16 *)&((ArwingState *)state)->inputFlags = 0;
            ((GameObject *)((ArwingState *)state)->thrusterL)->anim.flags |= OBJANIM_FLAG_HIDDEN;
            ((GameObject *)((ArwingState *)state)->thrusterR)->anim.flags |= OBJANIM_FLAG_HIDDEN;
        } else {
            ((GameObject *)((ArwingState *)state)->thrusterL)->anim.flags &= ~OBJANIM_FLAG_HIDDEN;
            throttle = lbl_803E6FFC * timeDelta +
                       (f32)(u32)((GameObject *)((ArwingState *)state)->thrusterL)->anim.alpha;
            if (throttle > lbl_803E7000) throttle = lbl_803E7000;
            ((GameObject *)((ArwingState *)state)->thrusterL)->anim.alpha = (u8)(int)throttle;
            ((GameObject *)((ArwingState *)state)->thrusterR)->anim.flags &= ~OBJANIM_FLAG_HIDDEN;
            ((GameObject *)((ArwingState *)state)->thrusterR)->anim.alpha = (u8)(int)throttle;
        }
        ((ArwingState *)state)->velTargetX = -((ArwingState *)state)->stickX * ((ArwingState *)state)->maxSpeedX;
        ((ArwingState *)state)->velTargetY = -((ArwingState *)state)->stickY * ((ArwingState *)state)->maxSpeedY;
        ((ArwingState *)state)->velTargetZ = ((ArwingState *)state)->maxSpeedZ * ((ArwingState *)state)->speedScaleZ;
        ((ArwingState *)state)->rotXTarget =
            (int)(-((ArwingState *)state)->stickX * ((ArwingState *)state)->rotXRange);
        ((ArwingState *)state)->rotYTarget = (int)(((ArwingState *)state)->stickY * ((ArwingState *)state)->rotYRange);
        ((ArwingState *)state)->rotZTarget = (int)(((ArwingState *)state)->stickX * ((ArwingState *)state)->rotZRange);
        ((ArwingState *)state)->rotZTrimTarget =
            (int)(((ArwingState *)state)->rotZTrimRange *
                  (((ArwingState *)state)->lTriggerTrim + ((ArwingState *)state)->rTriggerTrim));
        fn_8022AECC(obj, state);
        arwarwing_updateWeaponFire(obj, state);
        fn_8022B8A0(obj, state);

        *(s16 *)(((ArwingState *)state)->wingVec[0] + 0) =
            (int)((f32)(-((ArwingState *)state)->rotZCur) * ((ArwingState *)state)->wingFlexScale);
        *(s16 *)(((ArwingState *)state)->wingVec[0] + 4) =
            (int)((f32) ((ArwingState *)state)->rotZCur * ((ArwingState *)state)->wingFlexScale);
        *(s16 *)(((ArwingState *)state)->wingVec[1] + 0) =
            (int)((f32)(-((ArwingState *)state)->rotZCur) * ((ArwingState *)state)->wingFlexScale);
        *(s16 *)(((ArwingState *)state)->wingVec[1] + 4) =
            (int)((f32) ((ArwingState *)state)->rotZCur * ((ArwingState *)state)->wingFlexScale);
        p = (int)((f32) ((ArwingState *)state)->rotZCur * ((ArwingState *)state)->wingFlexScale);
        *(s16 *)(((ArwingState *)state)->wingVec[2] + 4) = p;
        *(s16 *)(((ArwingState *)state)->wingVec[2] + 0) = p;
        p = (int)((f32) ((ArwingState *)state)->rotZCur * ((ArwingState *)state)->wingFlexScale);
        *(s16 *)(((ArwingState *)state)->wingVec[3] + 4) = p;
        *(s16 *)(((ArwingState *)state)->wingVec[3] + 0) = p;

        *(s16 *)(((ArwingState *)state)->wingVec[0] + 0) =
            (int)((f32)(-((ArwingState *)state)->rotYCur) * ((ArwingState *)state)->wingFlexScale +
                  (f32) * (s16 *)(((ArwingState *)state)->wingVec[0] + 0));
        *(s16 *)(((ArwingState *)state)->wingVec[0] + 4) =
            (int)((f32) ((ArwingState *)state)->rotYCur * ((ArwingState *)state)->wingFlexScale +
                  (f32) * (s16 *)(((ArwingState *)state)->wingVec[0] + 4));
        *(s16 *)(((ArwingState *)state)->wingVec[1] + 0) =
            (int)((f32)(-((ArwingState *)state)->rotYCur) * ((ArwingState *)state)->wingFlexScale +
                  (f32) * (s16 *)(((ArwingState *)state)->wingVec[1] + 0));
        *(s16 *)(((ArwingState *)state)->wingVec[1] + 4) =
            (int)((f32) ((ArwingState *)state)->rotYCur * ((ArwingState *)state)->wingFlexScale +
                  (f32) * (s16 *)(((ArwingState *)state)->wingVec[1] + 4));
        *(s16 *)(((ArwingState *)state)->wingVec[2] + 0) =
            (int)((f32)(-((ArwingState *)state)->rotYCur) * ((ArwingState *)state)->wingFlexScale +
                  (f32) * (s16 *)(((ArwingState *)state)->wingVec[2] + 0));
        *(s16 *)(((ArwingState *)state)->wingVec[2] + 4) =
            (int)((f32)(-((ArwingState *)state)->rotYCur) * ((ArwingState *)state)->wingFlexScale +
                  (f32) * (s16 *)(((ArwingState *)state)->wingVec[2] + 4));
        *(s16 *)(((ArwingState *)state)->wingVec[3] + 0) =
            (int)((f32)(-((ArwingState *)state)->rotYCur) * ((ArwingState *)state)->wingFlexScale +
                  (f32) * (s16 *)(((ArwingState *)state)->wingVec[3] + 0));
        *(s16 *)(((ArwingState *)state)->wingVec[3] + 4) =
            (int)((f32)(-((ArwingState *)state)->rotYCur) * ((ArwingState *)state)->wingFlexScale +
                  (f32) * (s16 *)(((ArwingState *)state)->wingVec[3] + 4));
    }

    fn_8022C30C(obj, state);
    (*(void (**)(void *, int))(*gCameraInterface + 0x60))((void *)(state + 0x2c), 0xc);
    camRot[0] = ((GameObject *)obj)->anim.rotX;
    camRot[1] = ((GameObject *)obj)->anim.rotY;
    camRot[2] = (s16) ((ArwingState *)state)->rotZCur;
    (*(void (**)(void *, int))(*gCameraInterface + 0x60))(camRot, 6);
    camPos[0] = ((ArwingState *)state)->maxSpeedZ;
    camPos[1] = ((ArwingState *)state)->velZ;
    (*(void (**)(void *, int))(*gCameraInterface + 0x60))(camPos, 8);
    fn_8022BE14(obj, state);
    fn_8022C0D0(obj, state);
    fn_8022BCD0(obj, state);
}
#pragma scheduling reset

#pragma peephole off
#pragma scheduling off
void arwarwing_spawnLaserShot(int obj, int state, int side, int level, int linkEffect) {
    f32 pz, py, px;
    int proj;
    if (Obj_IsLoadingLocked() == 0)
        return;
    if (side == 0) {
        ObjPath_GetPointWorldPosition(obj, 3, &px, &py, &pz, 0);
        arwarwinggu_setActiveVisible(*(int *)(state + 8), 1, level == 2);
    } else {
        ObjPath_GetPointWorldPosition(obj, 4, &px, &py, &pz, 0);
        arwarwinggu_setActiveVisible(((ArwingState *)state)->gunObjR, 1, level == 2);
    }
    {
        int setup = Obj_AllocObjectSetup(0x20, 0x604);
        *(f32 *)(setup + 8) = px;
        *(f32 *)(setup + 0xc) = py;
        *(f32 *)(setup + 0x10) = pz;
        *(u8 *)(setup + 0x1a) = *(s16 *)obj >> 8;
        *(u8 *)(setup + 0x19) = ((GameObject *)obj)->anim.rotY >> 8;
        *(u8 *)(setup + 0x18) = 0;
        *(u8 *)(setup + 4) = 1;
        *(u8 *)(setup + 5) = 1;
    }
    proj = loadObjectAtObject(obj);
    if (proj == 0)
        return;
    if (level == 0) {
        Sfx_PlayFromObject(proj, SFXbaddie_rach_call1);
    } else if (level == 1) {
        Sfx_PlayFromObject(proj, SFXbaddie_rach_call2);
    } else {
        Sfx_PlayFromObject(proj, SFXbaddie_eba_bigswipe);
        Obj_SetActiveModelIndex(proj, 1);
    }
    if (linkEffect != 0)
        arwprojectile_createLinkedEffect(proj, 1);
    arwprojectile_setLifetime(proj, ((ArwingState *)state)->projLifetime);
    arwprojectile_placeForward(proj, ((ArwingState *)state)->projSpeed);
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
void arwarwing_addBomb(int arwing)
{
    ArwingState *state = *(ArwingState **)(arwing + 0xb8);
    if (state->bombCount < state->maxBombCount) {
        (state->bombCount)++;
    }
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
void arwarwing_upgradeLaserLevel(int arwing)
{
    ArwingState *state = *(ArwingState **)(arwing + 0xb8);
    if ((s8)state->laserLevel < 2) {
        (state->laserLevel)++;
    }
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling off
int fn_8022D710(int arwing)
{
    int result = 0;
    u32 v = (*(ArwingState **)(arwing + 0xb8))->mode;
    if (v == 5 || v == 6) {
        result = 1;
    }
    return result;
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
int fn_8022D738(int arwing) { return (*(ArwingState **)(arwing + 0xb8))->mode == 1; }
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
int fn_8022D750(int arwing) { return (*(ArwingState **)(arwing + 0xb8))->mode == 4; }
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void fn_8022C30C(int obj, int state)
{
    int vec;
    f32 vol;

    vec = objModelGetVecFn_800395d8(((ArwingState *)state)->escortObj, 0x14);

    if (((ArwingState *)state)->mode < 4 && (u32)GameBit_Get(0x9d6) == 0 && (u32)GameBit_Get(0x9d8) == 0) {
        vol = (f32)((lbl_803E6F48 + fn_802945E0(((ArwingState *)state)->velZ / ((ArwingState *)state)->maxSpeedZ)) *
                    lbl_803E6F50);
        Sfx_KeepAliveLoopedObjectSound(obj, SFXbaddie_pinpon_launch);
        Sfx_SetObjectChannelVolume(obj, 0x40, 0xfe, vol);
    }

    fn_8022F270(((ArwingState *)state)->escortObj, ((ArwingState *)state)->enginePitch);

    if (((ArwingState *)state)->rollCooldown <= lbl_803E6ECC) {
        if ((((ArwingState *)state)->flags477 & 0x2) == 0) {
            if ((((ArwingState *)state)->inputFlags & 0x800) != 0) {
                ((ArwingState *)state)->flags477 &= ~0x4;
                ((ArwingState *)state)->flags477 |= 0x2;
                ((ArwingState *)state)->wingFlexTarget = lbl_803E6F58;
                Sfx_PlayFromObjectLimited(obj, SFXbaddie_eba_smallswipe2, 3);
            }
        } else {
            ((ArwingState *)state)->speedScaleZ = ((ArwingState *)state)->speedScaleRollL;
            ((ArwingState *)state)->accelZ = ((ArwingState *)state)->accelZRollL;
            if ((((ArwingState *)state)->inputFlagsPrev & 0x800) != 0) {
                ((ArwingState *)state)->flags477 &= ~0x2;
                ((ArwingState *)state)->wingFlexTarget = lbl_803E6F5C;
            }
        }
        if ((((ArwingState *)state)->flags477 & 0x4) == 0) {
            if ((((ArwingState *)state)->inputFlags & 0x400) != 0) {
                ((ArwingState *)state)->flags477 &= ~0x2;
                ((ArwingState *)state)->flags477 |= 0x4;
                ((ArwingState *)state)->wingFlexTarget = lbl_803E6F60;
                Sfx_PlayFromObjectLimited(obj, SFXbaddie_kalda_distress, 3);
            }
        } else {
            ((ArwingState *)state)->speedScaleZ = ((ArwingState *)state)->speedScaleRollR;
            ((ArwingState *)state)->accelZ = ((ArwingState *)state)->accelZRollR;
            if ((((ArwingState *)state)->inputFlagsPrev & 0x400) != 0) {
                ((ArwingState *)state)->flags477 &= ~0x4;
                ((ArwingState *)state)->wingFlexTarget = lbl_803E6F5C;
            }
        }
    } else {
        if ((((ArwingState *)state)->inputFlags & 0xc00) != 0) {
            Sfx_PlayFromObject(obj, 0x381);
        }
        ((ArwingState *)state)->rollCooldown -= timeDelta;
        if (((ArwingState *)state)->rollCooldown <= lbl_803E6ECC) {
            ((ArwingState *)state)->wingFlexTarget = lbl_803E6F5C;
        }
    }

    if ((((ArwingState *)state)->flags477 & 0x6) == 0) {
        ((ArwingState *)state)->speedScaleZ = lbl_803E6ED0;
        ((ArwingState *)state)->accelZ = ((ArwingState *)state)->accelZNeutral;
        if (((ArwingState *)state)->rollRegenDelay <= lbl_803E6ECC) {
            ((ArwingState *)state)->rollEnergy = lbl_803E6F64 * timeDelta + ((ArwingState *)state)->rollEnergy;
        } else {
            ((ArwingState *)state)->rollRegenDelay -= timeDelta;
        }
    } else {
        ((ArwingState *)state)->rollEnergy -= timeDelta;
        ((ArwingState *)state)->rollRegenDelay = lbl_803E6F38;
    }

    ((ArwingState *)state)->rollEnergy = ((ArwingState *)state)->rollEnergy < lbl_803E6ECC
                                 ? lbl_803E6ECC
                                 : ((ArwingState *)state)->rollEnergy > ((ArwingState *)state)->rollEnergyMax
                                       ? ((ArwingState *)state)->rollEnergyMax
                                       : ((ArwingState *)state)->rollEnergy;

    if (((ArwingState *)state)->rollEnergy <= lbl_803E6ECC) {
        ((ArwingState *)state)->flags477 &= ~0x6;
        ((ArwingState *)state)->rollCooldown = ((ArwingState *)state)->rollCooldownInit;
        ((ArwingState *)state)->rollEnergy = ((ArwingState *)state)->rollEnergyMax;
        ((ArwingState *)state)->wingFlexTarget = lbl_803E6F68;
        ((ArwingState *)state)->rollRegenDelay = lbl_803E6ECC;
    }

    if ((u32)vec != 0) {
        int n;
        ((ArwingState *)state)->wingFlexCur =
            lbl_803E6EF8 * (((ArwingState *)state)->wingFlexTarget - ((ArwingState *)state)->wingFlexCur) + ((ArwingState *)state)->wingFlexCur;
        n = (int)((ArwingState *)state)->wingFlexCur;
        *(s16 *)(vec + 0xa) = n;
        *(s16 *)(vec + 0x8) = n;
        *(s16 *)(vec + 0x6) = n;
    }
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling off
void fn_8022C7A4(int obj) { (*(ArwingState **)&((GameObject *)obj)->extra)->aimSnapshotValid = 0; }
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void fn_8022CDEC(int obj, int state)
{
    int found;
    int mev;
    f32 radius;

    radius = lbl_803E6FC0;
    mev = (int)(*gMapEventInterface)->getState(*gMapEventInterface);

    if (*(void **)&((ArwingState *)state)->escortObj == 0) {
        ((ArwingState *)state)->escortObj = ObjList_FindNearestObjectByDefNo(obj, 0x606, &radius);
        if (*(void **)&((ArwingState *)state)->escortObj != 0) {
            ObjLink_AttachChild(obj, ((ArwingState *)state)->escortObj, 0);
        }
    }

    if (((ArwingState *)state)->fullLoadout != 0) {
        if (*(void **)&((ArwingState *)state)->bombObj == 0) {
            ((ArwingState *)state)->bombObj = ObjList_FindNearestObjectByDefNo(obj, 0x611, &radius);
            if (*(void **)&((ArwingState *)state)->bombObj != 0) {
                ObjLink_AttachChild(obj, ((ArwingState *)state)->bombObj, 0);
            }
        }
        if (*(void **)&((ArwingState *)state)->gunObjL == 0) {
            ((ArwingState *)state)->gunObjL = ObjList_FindNearestObjectByDefNo(obj, 0x610, &radius);
            if (*(void **)&((ArwingState *)state)->gunObjL != 0) {
                ObjLink_AttachChild(obj, ((ArwingState *)state)->gunObjL, 0);
            }
        }
        if (*(void **)&((ArwingState *)state)->gunObjR == 0) {
            ((ArwingState *)state)->gunObjR = ObjList_FindNearestObjectByDefNo(obj, 0x615, &radius);
            if (*(void **)&((ArwingState *)state)->gunObjR != 0) {
                ObjLink_AttachChild(obj, ((ArwingState *)state)->gunObjR, 0);
            }
        }
    }

    if (*(void **)&((ArwingState *)state)->thrusterL == 0 && *(void **)&((ArwingState *)state)->thrusterR == 0) {
        int setup;
        setup = Obj_AllocObjectSetup(0x20, 0x6de);
        *(u8 *)(setup + 0x4) = 1;
        *(u8 *)(setup + 0x5) = 1;
        ((ArwingState *)state)->thrusterL = ((int (*)(int, int))loadObjectAtObject)(obj, setup);
        setup = Obj_AllocObjectSetup(0x20, 0x6de);
        *(u8 *)(setup + 0x4) = 1;
        *(u8 *)(setup + 0x5) = 1;
        ((ArwingState *)state)->thrusterR = ((int (*)(int, int))loadObjectAtObject)(obj, setup);
    }

    found = 0;
    if (((ArwingState *)state)->fullLoadout != 0) {
        if (((ArwingState *)state)->light == 0) {
            *(int *)&((ArwingState *)state)->light = (int)objCreateLight(obj, 1);
            if (((ArwingState *)state)->light != 0) {
                modelLightStruct_setLightKind(((ArwingState *)state)->light, 2);
                modelLightStruct_setPosition(((ArwingState *)state)->light, lbl_803E6ECC, lbl_803E6FC4, lbl_803E6FC8);
                lightSetFieldBC_8001db14(((ArwingState *)state)->light, 1);
                modelLightStruct_setDiffuseColor(((ArwingState *)state)->light, 0x28, 0x7d, 0xff, 0);
                modelLightStruct_setDistanceAttenuation(((ArwingState *)state)->light, lbl_803E6FCC, lbl_803E6FD0);
                modelLightStruct_startColorFade(((ArwingState *)state)->light, 1, 1);
                modelLightStruct_setDiffuseTargetColor(((ArwingState *)state)->light, 0x14, 0x64, 0xc8, 0);
            }
        }
        if (*(void **)&((ArwingState *)state)->escortObj != 0 && *(void **)&((ArwingState *)state)->bombObj != 0 && *(void **)&((ArwingState *)state)->gunObjL != 0 &&
            *(void **)&((ArwingState *)state)->gunObjR != 0) {
            found = 1;
        }
    } else {
        if (*(void **)&((ArwingState *)state)->escortObj != 0) {
            found = 1;
        }
    }

    if (found != 0) {
        (*(void (**)(int, int))(*gCameraInterface + 0x28))(obj, 0);
        ((ArwingState *)state)->flags477 |= 1;
        ((ArwingState *)state)->maxSpeedX = lbl_803E6F70;
        ((ArwingState *)state)->accelX = lbl_803E6F74;
        ((ArwingState *)state)->maxSpeedY = lbl_803E6F78;
        ((ArwingState *)state)->accelY = lbl_803E6F7C;
        ((ArwingState *)state)->maxSpeedZ = lbl_803E6F78;
        ((ArwingState *)state)->accelZ = lbl_803E6F7C;
        ((ArwingState *)state)->maxAccelZ = lbl_803E6F80;
        ((ArwingState *)state)->minAccelZ = lbl_803E6F84;
        ((ArwingState *)state)->speedScaleZ = lbl_803E6ED0;
        ((ArwingState *)state)->rotXRange = lbl_803E6F88;
        ((ArwingState *)state)->rotXGain = lbl_803E6F74;
        ((ArwingState *)state)->rotYRange = lbl_803E6F8C;
        ((ArwingState *)state)->rotYGain = lbl_803E6F7C;
        ((ArwingState *)state)->rotZRange = lbl_803E6F90;
        ((ArwingState *)state)->rotZGain = lbl_803E6F94;
        ((ArwingState *)state)->rotZTrimRange = lbl_803E6F98;
        ((ArwingState *)state)->rotZTrimGain = lbl_803E6F9C;
        ((ArwingState *)state)->rotZBlendThreshold = lbl_803E6FA0;
        ((ArwingState *)state)->rotZBlendRate = lbl_803E6FA4;
        ((ArwingState *)state)->barrelRollSpeed = lbl_803E6FA8;
        ((ArwingState *)state)->unk3FA = 0x19;
        ((ArwingState *)state)->barrelRollDecelRange = lbl_803E6FAC;
        ((ArwingState *)state)->rootMotionScale = lbl_803E6FB0;
        ((GameObject *)obj)->anim.rootMotionScale = lbl_803E6FB0;
        ((ArwingState *)state)->barrelRollMaxSpeedScale = lbl_803E6FB4;
        ((ArwingState *)state)->barrelRollAccelScale = lbl_803E6FB8;
        ((ArwingState *)state)->speedScaleRollL = lbl_803E6FBC;
        ((ArwingState *)state)->speedScaleRollR = lbl_803E6F64;
        ((ArwingState *)state)->accelZRollL = lbl_803E6FD4;
        ((ArwingState *)state)->accelZRollR = lbl_803E6F74;
        ((ArwingState *)state)->accelZNeutral = lbl_803E6FD8;
        ((ArwingState *)state)->rollCooldownInit = lbl_803E6FDC;
        ((ArwingState *)state)->rollEnergyMax = lbl_803E6FE0;
        ((ArwingState *)state)->unkA8 = lbl_803E6F2C;
        ((ArwingState *)state)->rollEnergy = ((ArwingState *)state)->rollEnergyMax;
        ((ArwingState *)state)->unkA4 = ((ArwingState *)state)->unkA8;
        ((ArwingState *)state)->wingFlexCur = lbl_803E6F5C;
        ((ArwingState *)state)->wingFlexTarget = lbl_803E6F5C;
        if (*(s8 *)(obj + 0xac) == 0x26) {
            ((ArwingState *)state)->velZ = lbl_803E6ECC;
        } else {
            ((ArwingState *)state)->velZ = lbl_803E6F78;
        }
        *(s16 *)&((ArwingState *)state)->projLifetime = 0x28;
        ((ArwingState *)state)->projSpeed = lbl_803E6FE0;
        *(s16 *)&((ArwingState *)state)->fireDelay = 0x6;
        ((ArwingState *)state)->bombProjectileParam = 0x5a;
        ((ArwingState *)state)->bombProjectileLifetime = lbl_803E6F34;
        ((ArwingState *)state)->bombFireDelay = 0xc;
        ((ArwingState *)state)->maxBombCount = 0x3;
        ((ArwingState *)state)->wingVec[0] = objModelGetVecFn_800395d8(obj, 0);
        ((ArwingState *)state)->wingVec[1] = objModelGetVecFn_800395d8(obj, 1);
        ((ArwingState *)state)->wingVec[2] = objModelGetVecFn_800395d8(obj, 2);
        ((ArwingState *)state)->wingVec[3] = objModelGetVecFn_800395d8(obj, 3);
        ((ArwingState *)state)->wingFlexScale = lbl_803E6F64;
        *(s16 *)&((ArwingState *)state)->enginePitch = 0xaf;
        ((ArwingState *)state)->maxShield = *(u8 *)(mev + 0x1);
        ((ArwingState *)state)->shield = ((ArwingState *)state)->maxShield;
        ((ArwingState *)state)->bobSpeedThreshold = lbl_803E6EF8;
        ((ArwingState *)state)->bobRotZRate = lbl_803E6EF0;
        ((ArwingState *)state)->bobRotZAmp = lbl_803E6FE4;
        ((ArwingState *)state)->bobXRate = lbl_803E6EF4;
        ((ArwingState *)state)->bobXAmp = lbl_803E6FD4;
        ((ArwingState *)state)->bobYRate = lbl_803E6FE8;
        ((ArwingState *)state)->bobYAmp = lbl_803E6F80;
        ((ArwingState *)state)->bobBlendRate = lbl_803E6FA4;
        ((ArwingState *)state)->homeX = ((GameObject *)obj)->anim.localPosX;
        ((ArwingState *)state)->homeY = ((GameObject *)obj)->anim.localPosY;
        ((ArwingState *)state)->homeZ = ((GameObject *)obj)->anim.localPosZ;
        ((ArwingState *)state)->unk20 = lbl_803E6FEC;
        ((ArwingState *)state)->unk28 = lbl_803E6FF0;
        ((ArwingState *)state)->unk24 = lbl_803E6EF0;
    }
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void fn_8022D308(int obj)
{
    ArwingState *state = ((GameObject *)obj)->extra;
    f32 v7c = lbl_803E6F7C;
    f32 v74 = lbl_803E6F74;

    state->maxSpeedX = lbl_803E6F70;
    state->accelX = v74;
    state->maxSpeedY = lbl_803E6F78;
    state->accelY = v7c;
    state->maxSpeedZ = lbl_803E6F78;
    state->accelZ = v7c;
    state->maxAccelZ = lbl_803E6F80;
    state->minAccelZ = lbl_803E6F84;
    state->speedScaleZ = lbl_803E6ED0;
    state->rotXRange = lbl_803E6F88;
    state->rotXGain = v74;
    state->rotYRange = lbl_803E6F8C;
    state->rotYGain = v7c;
    state->rotZRange = lbl_803E6F90;
    state->rotZGain = lbl_803E6F94;
    state->rotZTrimRange = lbl_803E6F98;
    state->rotZTrimGain = lbl_803E6F9C;
    state->rotZBlendThreshold = lbl_803E6FA0;
    state->rotZBlendRate = lbl_803E6FA4;
    state->barrelRollSpeed = lbl_803E6FA8;
    state->unk3FA = 0x19;
    state->barrelRollDecelRange = lbl_803E6FAC;
    state->rootMotionScale = lbl_803E6FB0;
    state->barrelRollMaxSpeedScale = lbl_803E6FB4;
    state->barrelRollAccelScale = lbl_803E6FB8;
    state->speedScaleRollL = lbl_803E6FBC;
    state->speedScaleRollR = lbl_803E6F64;
    state->rollEnergy = state->rollEnergyMax;
    state->unkA4 = state->unkA8;
    state->wingFlexCur = lbl_803E6F5C;
    state->wingFlexTarget = lbl_803E6F5C;
    state->velX = lbl_803E6ECC;
    state->velY = lbl_803E6ECC;
    state->velZ = lbl_803E6ECC;
    state->laserLevel = 0;
    ((GameObject *)obj)->anim.localPosX = state->homeX;
    ((GameObject *)obj)->anim.localPosY = state->homeY;
    ((GameObject *)obj)->anim.localPosZ = state->homeZ;
    state->rotYCur = 0;
    state->rotZCur = 0;
    ((GameObject *)obj)->anim.rotX = 0;
    ((GameObject *)obj)->anim.rotY = 0;
    ((GameObject *)obj)->anim.rotZ = 0;
    arwarwingbo_setActiveVisible(state->bombObj, 0, 0);
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void fn_8022BE14(int obj, int state)
{
    int sub = state + 0xc0;
    int dmg;

    (*(void (**)(int, int, f32))(*gPathControlInterface + 0x10))(obj, sub, timeDelta);
    (*(void (**)(int, int))(*gPathControlInterface + 0x14))(obj, sub);
    (*(void (**)(int, int, f32))(*gPathControlInterface + 0x18))(obj, sub, timeDelta);

    if (((ArwingState *)state)->hitShake == 0 || ((ArwingState *)state)->mode == 4) {
        dmg = (s8)*(u8 *)(sub + 0x260);
        if (dmg == 0)
            return;
        if (((ArwingState *)state)->mode == 4) {
            ((ArwingState *)state)->mode = 5;
            ((ArwingState *)state)->modeTimer = lbl_803E6F24;
            ((GameObject *)obj)->anim.flags |= OBJANIM_FLAG_HIDDEN;
            spawnExplosion(obj, lbl_803E6F28, 1, 0, 1, 1, 0, 1, 0);
            return;
        }
        if ((dmg & 1) && (s8)*(u8 *)(sub + 0xb8) == 8)
            ((ArwingState *)state)->shield = 0;
        else
            ((ArwingState *)state)->shield = ((ArwingState *)state)->shield - 1;
        doRumble(lbl_803E6F2C);
        if ((s8)((ArwingState *)state)->shield <= 0) {
            arwarwingbo_setActiveVisible(((ArwingState *)state)->bombObj, 0, 0);
            if ((s8)*(u8 *)(obj + 0xac) == 0x26)
                GameBit_Set(0xe74, 1);
            else
                ((ArwingState *)state)->mode = 4;
            ((ArwingState *)state)->modeTimer = lbl_803E6F30;
            Sfx_PlayFromObject(obj, 0x380);
            Music_Trigger(0xd6, 1);
        } else if ((s8)*(u8 *)(*(int *)&((GameObject *)obj)->extra + 0x468) <= 3) {
            Sfx_KeepAliveLoopedObjectSound(obj, 0x37f);
        }
        Sfx_PlayFromObject(obj, SFXbaddie_rach_bite);
        ((ArwingState *)state)->flags339 |= 0x80;
        Obj_SetModelColorFadeRecursive(obj, 0x4b, 0xc8, 0, 0, 1);
        ((ArwingState *)state)->damageFlashTimer = lbl_803E6F34;
        ((ArwingState *)state)->hitShake = 1;
        ((ArwingState *)state)->shakeYaw = 0;
        ((ArwingState *)state)->shakePitch = 0;
        ((ArwingState *)state)->knockVelX = *(f32 *)(sub + 0x1a0);
        ((ArwingState *)state)->knockVelZ = *(f32 *)(sub + 0x1a4);
        Camera_EnableViewYOffset();
        CameraShake_SetAllMagnitudes(lbl_803E6F38);
    } else {
        ((ArwingState *)state)->shakeYaw = lbl_803E6F3C * timeDelta + (f32)*(u16 *)&((ArwingState *)state)->shakeYaw;
        ((ArwingState *)state)->shakePitch = lbl_803E6F40 * timeDelta + (f32)*(u16 *)&((ArwingState *)state)->shakePitch;
    }
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void fn_8022C0D0(int obj, int state)
{
    int hitVol;
    int hitObj;

    if (objGetFlagsE5_2(obj) != 0)
        return;
    if (ObjHits_GetPriorityHit(obj, &hitObj, 0, &hitVol) != 0 && hitVol != 0) {
        if (((ArwingState *)state)->mode == 4) {
            ((ArwingState *)state)->mode = 5;
            ((ArwingState *)state)->modeTimer = lbl_803E6F24;
            ((GameObject *)obj)->anim.flags |= OBJANIM_FLAG_HIDDEN;
            spawnExplosion(obj, lbl_803E6F28, 1, 0, 1, 1, 0, 1, 0);
        } else {
            if (*(s16 *)(hitObj + 0x46) == 0x6ae && ((ArwingState *)state)->mode == 1) {
                Sfx_PlayFromObject(obj, SFXbaddie_eggsnatch_movelp);
                return;
            }
            doRumble(lbl_803E6F2C);
            ((ArwingState *)state)->shield = ((ArwingState *)state)->shield - hitVol;
            Sfx_PlayFromObject(obj, SFXbaddie_vambat_death);
            ((ArwingState *)state)->flags339 |= 0x80;
            Obj_SetModelColorFadeRecursive(obj, 0x4b, 0xc8, 0, 0, 1);
            ((ArwingState *)state)->damageFlashTimer = lbl_803E6F34;
            ((ArwingState *)state)->hitShake = 1;
            ((ArwingState *)state)->shakeYaw = 0;
            ((ArwingState *)state)->shakePitch = 0;
            ((ArwingState *)state)->knockVelX = lbl_803E6ECC;
            ((ArwingState *)state)->knockVelZ = lbl_803E6ECC;
            Camera_EnableViewYOffset();
            CameraShake_SetAllMagnitudes(lbl_803E6F2C);
        }
    }
    if (((ArwingState *)state)->mode != 4 && ((ArwingState *)state)->mode != 5 &&
        ((ArwingState *)state)->mode != 6 && (s8)((ArwingState *)state)->shield <= 0) {
        arwarwingbo_setActiveVisible(((ArwingState *)state)->bombObj, 0, 0);
        if ((s8)*(u8 *)(obj + 0xac) == 0x26)
            GameBit_Set(0xe74, 1);
        ((ArwingState *)state)->mode = 4;
        ((ArwingState *)state)->modeTimer = lbl_803E6F30;
        Sfx_PlayFromObject(obj, 0x380);
        Music_Trigger(0xd6, 1);
        unlockLevel(0, 0, 1);
        loadMapAndParent(0x29);
        lockLevel(mapGetDirIdx(0x29), 0);
    } else if ((s8)*(u8 *)(*(int *)&((GameObject *)obj)->extra + 0x468) <= 3) {
        Sfx_KeepAliveLoopedObjectSound(obj, 0x37f);
    }
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
int arwarwing_SeqFn(int obj, int p2, int script)
{
    int state = *(int *)&((GameObject *)obj)->extra;
    int i;

    Camera_GetCurrentViewSlot();
    *(int *)(script + 0xe8) = (int)fn_8022C7A4;
    if ((((ArwingState *)state)->flags477 & 1) == 0) {
        fn_8022CDEC(obj, state);
        return 0;
    }
    fn_8022C30C(obj, state);
    fn_8022A9C8(obj, state);
    if (((ArwingState *)state)->bombObj != 0)
        arwarwingbo_setActiveVisible(((ArwingState *)state)->bombObj, 0, 0);
    ((GameObject *)((ArwingState *)state)->thrusterL)->anim.flags |= OBJANIM_FLAG_HIDDEN;
    ((GameObject *)((ArwingState *)state)->thrusterL)->anim.alpha = 0;
    ((GameObject *)((ArwingState *)state)->thrusterR)->anim.flags |= OBJANIM_FLAG_HIDDEN;
    ((GameObject *)((ArwingState *)state)->thrusterR)->anim.alpha = 0;
    ((GameObject *)obj)->anim.flags &= ~OBJANIM_FLAG_HIDDEN;

    for (i = 0; i < *(u8 *)(script + 0x8b); i++) {
        switch (*(u8 *)(script + i + 0x81)) {
        case 8: {
            int cam = Camera_GetCurrentViewSlot();
            ((ArwingState *)state)->aimOffsetX = *(f32 *)(cam + 0xc) - ((GameObject *)obj)->anim.localPosX;
            ((ArwingState *)state)->aimOffsetY = *(f32 *)(cam + 0x10) - ((GameObject *)obj)->anim.localPosY;
            ((ArwingState *)state)->aimOffsetZ = *(f32 *)(cam + 0x14) - ((GameObject *)obj)->anim.localPosZ;
            ((ArwingState *)state)->aimYaw = ((GameObject *)obj)->anim.rotX - (u16)*(s16 *)(cam + 0);
            if (((ArwingState *)state)->aimYaw > 32768)
                ((ArwingState *)state)->aimYaw -= 65535;
            if (((ArwingState *)state)->aimYaw < -32768)
                ((ArwingState *)state)->aimYaw += 65535;
            ((ArwingState *)state)->aimPitch = ((GameObject *)obj)->anim.rotY - (u16)*(s16 *)(cam + 2);
            if (((ArwingState *)state)->aimPitch > 32768)
                ((ArwingState *)state)->aimPitch -= 65535;
            if (((ArwingState *)state)->aimPitch < -32768)
                ((ArwingState *)state)->aimPitch += 65535;
            ((ArwingState *)state)->aimRoll = *(s16 *)(cam + 4) - ((GameObject *)obj)->anim.rotZ;
            ((ArwingState *)state)->aimSnapshotValid = 1;
            break;
        }
        case 9:
            ((ArwingState *)state)->aimSnapshotValid = 0;
            break;
        case 1:
            clearLoadedFileFlags_blocks1();
            warpToMap(0x60, 0);
            break;
        case 2:
            clearLoadedFileFlags_blocks1();
            fn_8022C680(obj);
            break;
        case 0xa:
            if (Obj_IsLoadingLocked()) {
                int setup = Obj_AllocObjectSetup(0x24, 0x608);
                int o;
                *(f32 *)(setup + 8) = ((GameObject *)obj)->anim.localPosX;
                *(f32 *)(setup + 0xc) = ((GameObject *)obj)->anim.localPosY;
                *(f32 *)(setup + 0x10) = ((GameObject *)obj)->anim.localPosZ;
                *(u8 *)(setup + 4) = 1;
                *(u8 *)(setup + 5) = 1;
                o = loadObjectAtObject(obj);
                if (o != 0)
                    fn_8022F558(o, 0x12c);
            }
            break;
        case 0xb:
            ((ArwingState *)state)->bombCount = 1;
            fn_8022B764(obj, state, ((ArwingState *)state)->bombSide);
            ((ArwingState *)state)->bombSide ^= 1;
            break;
        case 0xc:
            arwarwing_spawnLaserShot(obj, state, 0, 1, 1);
            arwarwing_spawnLaserShot(obj, state, 1, 1, 0);
            break;
        case 4:
            unlockLevel(0, 0, 1);
            mapUnload(0, 0x80000000);
            setLoadedFileFlags_blocks1();
            break;
        case 5:
            if (((ArwingState *)state)->levelIndex == 0 && GameBit_Get(0xc85)) {
                loadMapAndParent(0xb);
                lockLevel(mapGetDirIdx(0xb), 0);
            } else {
                loadMapAndParent(lbl_803DC3C8[((ArwingState *)state)->levelIndex]);
                lockLevel(mapGetDirIdx(lbl_803DC3C8[((ArwingState *)state)->levelIndex]), 0);
            }
            switch ((s8)*(u8 *)(obj + 0xac)) {
            case 0x3b:
                (*gMapEventInterface)->setAnimEvent(0x13, 0, 1);
                (*gMapEventInterface)->setAnimEvent(0x13, 0x16, 1);
                break;
            case 0x3d:
                GameBit_Set(0x36a, 0);
                (*gMapEventInterface)->setAnimEvent(0xd, 0, 1);
                (*gMapEventInterface)->setAnimEvent(0xd, 1, 1);
                (*gMapEventInterface)->setAnimEvent(0xd, 5, 1);
                (*gMapEventInterface)->setAnimEvent(0xd, 0xa, 1);
                (*gMapEventInterface)->setAnimEvent(0xd, 0xb, 1);
                GameBit_Set(0xe05, 0);
                break;
            case 0x3c:
                GameBit_Set(0x458, 0);
                GameBit_Set(0x47c, 0);
                GameBit_Set(0x4a3, 0);
                (*gMapEventInterface)->setAnimEvent(0xc, 0, 1);
                GameBit_Set(0xd73, 0);
                break;
            case 0x3e:
                GameBit_Set(0x5db, 0);
                (*gMapEventInterface)->setAnimEvent(2, 0xf, 1);
                (*gMapEventInterface)->setAnimEvent(2, 0x10, 1);
                GameBit_Set(0xe7b, 0);
                GameBit_Set(0x9e9, 0);
                break;
            }
            break;
        case 6:
            unlockLevel(0, 0, 1);
            loadMapAndParent(0x29);
            lockLevel(mapGetDirIdx(0x29), 0);
            break;
        case 7:
            if (!((Arw339Flags *)(state + 0x339))->scoreFlag) {
                int s2 = *(int *)&((GameObject *)obj)->extra;
                *(u16 *)(s2 + 0x47c) = *(u16 *)(s2 + 0x47c) + 0xc8;
                if (*(u16 *)(s2 + 0x47c) > 0x270f)
                    *(u16 *)(s2 + 0x47c) = 0x270f;
            }
            registerNewScore((s8)((ArwingState *)state)->scoreSlot, ((ArwingState *)state)->score,
                             ((ArwingState *)state)->collectedRings, 2);
            break;
        case 0xd:
            gameTextFn_80125ba4(0x13);
            break;
        case 0xe:
            gameTextFn_80125ba4(0x14);
            break;
        }
    }
    return 0;
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void arwarwing_init(int obj)
{
    int state;
    int sub;
    ArwInitCfg cfg;

    cfg.a = lbl_802C25E8.a;
    cfg.b = lbl_802C25E8.b;
    cfg.c = lbl_802C25E8.c;
    state = *(int *)&((GameObject *)obj)->extra;
    sub = state + 0xc0;
    ((GameObject *)obj)->animEventCallback = (void *)arwarwing_SeqFn;
    (*(void (**)(int, int, int, int))(*gPathControlInterface + 4))(sub, 4, 0x1040006, 1);
    (*(void (**)(int, int, void *, void *, void *))(*gPathControlInterface + 0xc))(sub, 3, lbl_8032B408, lbl_8032B480, &cfg);
    (*(void (**)(int, int))(*gPathControlInterface + 0x20))(obj, sub);
    ObjGroup_AddObject(obj, 0x26);
    lbl_803DDD88 = obj;
    ObjHits_SetTargetMask(obj, 1);
    ((ArwingState *)state)->fullLoadout = 1;
    switch ((s8)*(u8 *)(obj + 0xac) - 0x26) {
    case 27:
    default:
        ((ArwingState *)state)->fullLoadout = 0;
        break;
    case 20:
        ((ArwingState *)state)->levelIndex = 0;
        ((ArwingState *)state)->requiredRings = 1;
        ((ArwingState *)state)->scoreSlot = 0;
        break;
    case 21:
        ((ArwingState *)state)->levelIndex = 1;
        ((ArwingState *)state)->requiredRings = 3;
        ((ArwingState *)state)->scoreSlot = 1;
        break;
    case 23:
        ((ArwingState *)state)->levelIndex = 2;
        ((ArwingState *)state)->requiredRings = 7;
        ((ArwingState *)state)->scoreSlot = 3;
        break;
    case 22:
        ((ArwingState *)state)->levelIndex = 3;
        ((ArwingState *)state)->requiredRings = 5;
        ((ArwingState *)state)->scoreSlot = 2;
        break;
    case 24:
        ((ArwingState *)state)->levelIndex = 4;
        ((ArwingState *)state)->requiredRings = 0xa;
        ((ArwingState *)state)->scoreSlot = 4;
        break;
    case 0:
        break;
    }
}
#pragma scheduling reset
#pragma peephole reset
