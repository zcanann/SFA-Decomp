#include "main/dll/dll_80220608_shared.h"

#pragma peephole on
#pragma scheduling off
int gf_levelcon_handleScriptEvents(int obj, int eventId, u8 *script)
{
    int state = *(int *)(obj + 0xb8);
    int i;

    script[0x56] = 0;
    for (i = 0; i < script[0x8b]; i++) {
        switch (script[0x81 + i]) {
        case 0:
            break;
        case 1:
            skyFn_80089710(7, 1, 0);
            skyFn_800895e0(7, 0x96, 0xc8, 0xf0, 0, 0);
            skyFn_800894a8(7, lbl_803E7460, lbl_803E7464, lbl_803E7468);
            getEnvfxAct(obj, obj, 0x21f, 0);
            break;
        case 8:
            *(f32 *)(state + 0xc) = lbl_803E746C;
            break;
        case 2:
            skyFn_80089710(7, 1, 0);
            skyFn_800895e0(7, (int)lbl_803E7470, (int)lbl_803E7474, (int)lbl_803E7478, 0, 0);
            skyFn_800894a8(7, lbl_803E7464, lbl_803E747C, lbl_803E7464);
            getEnvfxAct(obj, obj, 0x21d, 0);
            break;
        case 3:
            gf_levelcon_findLinkedObjects(obj);
            if (*(void **)state != NULL) {
                pointlight_setEffectState(*(int *)state, 1);
            }
            break;
        case 4:
            gf_levelcon_findLinkedObjects(obj);
            if (*(void **)state != NULL) {
                pointlight_setEffectState(*(int *)state, 0);
            }
            break;
        case 5:
            skyFn_80089710(7, 1, 0);
            skyFn_800895e0(7, 0x96, 0xc8, 0xf0, 0, 0);
            skyFn_800894a8(7, lbl_803E7480, lbl_803E747C, lbl_803E7464);
            getEnvfxAct(obj, obj, 0x21e, 0);
            break;
        case 6:
            loadMapAndParent(0x29);
            break;
        case 7:
            unlockLevel(0, 0, 1);
            unlockLevel(0, 1, 1);
            mapUnload(mapGetDirIdx(0xb), 0x20000000);
            break;
        case 9:
            unlockLevel(0, 0, 1);
            loadUiDll(4);
            warpToMap(0x12, 0);
            creditsStart();
            break;
        case 10:
            skyFn_80089710(7, 1, 0);
            skyFn_800895e0(7, 0x96, 0xc8, 0xf0, 0, 0);
            skyFn_800894a8(7, lbl_803E7484, lbl_803E747C, lbl_803E7464);
            getEnvfxAct(obj, obj, 0x21f, 0);
            break;
        case 11:
            skyFn_80089710(7, 1, 0);
            skyFn_800895e0(7, (int)lbl_803E7470, (int)lbl_803E7474, (int)lbl_803E7478, 0, 0);
            skyFn_800894a8(7, lbl_803E7484, lbl_803E747C, lbl_803E7464);
            getEnvfxAct(obj, obj, 0x21d, 0);
            break;
        }
    }

    if (*(f32 *)(state + 0xc) > lbl_803E7488) {
        gameTextShow(0x476);
        *(f32 *)(state + 0xc) -= timeDelta;
        if (*(f32 *)(state + 0xc) < lbl_803E7488) {
            *(f32 *)(state + 0xc) = lbl_803E7488;
        }
    }

    {
        s16 *p = *(s16 **)(state + 4);
        if (p != NULL) {
            *p += (int)(lbl_803E748C * timeDelta);
        }
    }
    {
        s16 *p = *(s16 **)(state + 8);
        if (p != NULL) {
            *p -= (int)(lbl_803E748C * timeDelta);
        }
    }
    return 0;
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
int gf_levelcon_getExtraSize(void) { return 0x10; }
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
int gf_levelcon_getObjectTypeId(void) { return 0; }
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
void gf_levelcon_hitDetect(void) {}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
void gf_levelcon_initialise(void) {}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
void gf_levelcon_release(void) {}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling off
void gf_levelcon_free(void)
{
    setIsOvercast(1);
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling off
void gf_levelcon_update(int obj)
{
    *(void **)(obj + 0xbc) = (void *)gf_levelcon_handleScriptEvents;
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void gf_levelcon_render(int obj, int p2, int p3, int p4, int p5, s8 visible)
{
    if (visible != 0) {
        objRenderFn_8003b8f4(obj, p2, p3, p4, p5, lbl_803E7480);
    }
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling off
void gf_levelcon_init(int obj)
{
    setIsOvercast(0);
    (*(void (**)(int, int))(*gScreenTransitionInterface + 0xc))(0x258, 1);
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void gf_levelcon_findLinkedObjects(int obj)
{
    int state = *(int *)(obj + 0xb8);
    int *objects;
    int objectCount;
    int objectIndex;
    int o;

    *(int *)(state + 0) = 0;
    *(int *)(state + 4) = 0;
    *(int *)(state + 8) = 0;
    objects = ObjList_GetObjects(&objectIndex, &objectCount);
    for (; objectIndex < objectCount; objectIndex++) {
        o = objects[objectIndex];
        if ((u32)o != (u32)obj && *(void **)(o + 0x4c) != NULL) {
            switch (*(int *)(*(int *)(o + 0x4c) + 0x14)) {
            case 0x477E3:
                *(int *)(state + 0) = o;
                break;
            case 0x4A946:
                *(int *)(state + 4) = o;
                break;
            case 0x4A947:
                *(int *)(state + 8) = o;
                break;
            }
        }
    }
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void fn_80239DD8(int p1, int p2)
{
    f32 maxDist;
    int near;
    int newObj;

    maxDist = lbl_803E7490;
    if (Obj_IsLoadingLocked()) {
        near = ObjList_FindNearestObjectByDefNo(p1, 0x7e5, &maxDist);
        if (near != 0) {
            newObj = Obj_AllocObjectSetup(0x24, 0x608);
            *(f32 *)(newObj + 8) = *(f32 *)(near + 0xc);
            *(f32 *)(newObj + 0xc) = *(f32 *)(near + 0x10);
            *(f32 *)(newObj + 0x10) = *(f32 *)(near + 0x14);
            *(u8 *)(newObj + 4) = 1;
            *(u8 *)(newObj + 5) = 1;
            *(int *)(p2 + 0x10) = ((int (*)(int, int))loadObjectAtObject)(p1, newObj);
            if (*(void **)(p2 + 0x10) != NULL) {
                *(u8 *)(*(int *)(p2 + 0x10) + 0x36) = 0xff;
                *(u8 *)(*(int *)(p2 + 0x10) + 0x37) = 0xff;
                *(int *)(p2 + 0x90) = 0x12c;
            }
        }
    }
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling off
void fn_80239EAC(int p1, int p2)
{
    f32 dx, dy, dz;
    int *objs;
    int obj;
    int i;
    int count;
    int defNo;

    objs = ObjGroup_GetObjects(2, &count);
    for (i = 0; i < count; i++) {
        obj = *objs;
        defNo = *(s16 *)(*(int *)(obj + 0x4c));
        if (defNo == 0x80d || defNo == 0x859) {
            dy = *(f32 *)(p2 + 0xc4) - *(f32 *)(obj + 0x10);
            dz = *(f32 *)(p2 + 0xc8) - *(f32 *)(obj + 0x14);
            dx = *(f32 *)(p2 + 0xc0) - *(f32 *)(obj + 0xc);
            *(s16 *)(obj + 0) = (s16)getAngle(dx, dz);
            *(s16 *)(obj + 2) = -(s16)getAngle(dy, dz);
            arwprojectile_placeForward(obj, (f32)(u32)lbl_803DC4E8);
        }
        objs++;
    }
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void fn_8023A168(int p1, int p2)
{
    int yawRnd;
    int pitchRnd;
    int newObj;
    int proj;

    if (Obj_IsLoadingLocked()) {
        yawRnd = (s16)(randomGetRange(-0x1f40, 0x1f40) - 0x8000);
        pitchRnd = randomGetRange(-0x1f40, 0x1f40) >> 8;
        newObj = Obj_AllocObjectSetup(0x20, 0x80d);
        *(f32 *)(newObj + 8) = *(f32 *)(p2 + 0xc0);
        *(f32 *)(newObj + 0xc) = *(f32 *)(p2 + 0xc4);
        *(f32 *)(newObj + 0x10) = *(f32 *)(p2 + 0xc8);
        *(u8 *)(newObj + 0x1a) = (*(s16 *)p1 + yawRnd) >> 8;
        *(u8 *)(newObj + 0x19) = pitchRnd;
        *(u8 *)(newObj + 0x18) = 0;
        *(u8 *)(newObj + 4) = 1;
        *(u8 *)(newObj + 5) = 1;
        proj = ((int (*)(int, int))loadObjectAtObject)(p1, newObj);
        if (proj != 0) {
            *(f32 *)(proj + 8) = lbl_803E74B0;
            arwprojectile_setLifetime(proj, 0x6e);
            arwprojectile_placeForward(proj, lbl_803E74AC);
        }
    }
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void fn_8023A268(int p1, int p2)
{
    f32 dx, dz, dist;
    int yaw;
    int newObj;
    int proj;

    if (Obj_IsLoadingLocked()) {
        dx = *(f32 *)(p2 + 0xc0) - *(f32 *)(*(int *)p2 + 0xc);
        dz = *(f32 *)(p2 + 0xc8) - *(f32 *)(*(int *)p2 + 0x14);
        dist = sqrtf(dx * dx + dz * dz);
        yaw = (u16)getAngle(dx, dz);
        lbl_803DDDBC = (u16)getAngle(*(f32 *)(p2 + 0xc4) - *(f32 *)(*(int *)p2 + 0x10), dist) >> 8;
        newObj = Obj_AllocObjectSetup(0x20, 0x7e4);
        *(f32 *)(newObj + 8) = *(f32 *)(p2 + 0xc0);
        *(f32 *)(newObj + 0xc) = *(f32 *)(p2 + 0xc4);
        *(f32 *)(newObj + 0x10) = *(f32 *)(p2 + 0xc8);
        *(u8 *)(newObj + 0x1a) = (*(s16 *)p1 + yaw) >> 8;
        *(u8 *)(newObj + 0x19) = lbl_803DDDBC;
        *(u8 *)(newObj + 0x18) = 0;
        *(u8 *)(newObj + 4) = 1;
        *(u8 *)(newObj + 5) = 1;
        proj = ((int (*)(int, int))loadObjectAtObject)(p1, newObj);
        if (proj != 0) {
            arwprojectile_setLifetime(proj, lbl_803DC4DC);
            arwprojectile_placeForward(proj, (f32)(u32)lbl_803DC4D8);
        }
    }
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void fn_80239FCC(int p1, int p2)
{
    f32 ang;
    int yaw;
    int rndYaw;
    int rndDur;
    int newObj;
    int proj;

    if (Obj_IsLoadingLocked()) {
        yaw = lbl_803DDDC4;
        lbl_803DDDC0 = lbl_803DDDC6;
        rndYaw = (s16)randomGetRange(-0x8000, 0x7fff);
        rndDur = randomGetRange(0x64, 0x12c);
        newObj = Obj_AllocObjectSetup(0x20, 0x859);
        ang = lbl_803E74A0 * (f32)(u32)rndYaw / lbl_803E74A4;
        *(f32 *)(newObj + 8) = (f32)(u32)rndDur * fn_80293E80(ang) + *(f32 *)(*(int *)p2 + 0xc);
        *(f32 *)(newObj + 0xc) = (f32)(u32)rndDur * sin(ang) + *(f32 *)(*(int *)p2 + 0x10);
        *(f32 *)(newObj + 0x10) = *(f32 *)(p2 + 0xc8) - lbl_803E74A8;
        *(u8 *)(newObj + 0x1a) = (*(s16 *)p1 + yaw) >> 8;
        *(u8 *)(newObj + 0x19) = lbl_803DDDC0;
        *(u8 *)(newObj + 0x18) = 0;
        *(u8 *)(newObj + 4) = 1;
        *(u8 *)(newObj + 5) = 1;
        proj = ((int (*)(int, int))loadObjectAtObject)(p1, newObj);
        if (proj != 0) {
            *(f32 *)(proj + 8) = lbl_803DC4E4;
            arwprojectile_setLifetime(proj, lbl_803DC4E0);
            arwprojectile_placeForward(proj, lbl_803E74AC);
        }
    }
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling off
void fn_8023A3E4(int p1, int p2)
{
    int hitVol;
    int hitType;
    int hitObj;
    u8 i;
    int got;

    got = ObjHits_GetPriorityHit(p1, &hitObj, &hitType, &hitVol);
    for (i = 0; i < 4; i++) {
        int v = *(u8 *)(p2 + 0xb2 + i) - framesThisStep;
        if (v < 0)
            v = 0;
        *(u8 *)(p2 + 0xb2 + i) = v;
    }
    if (got != 0) {
        if (hitType == 3) {
            if (*(s16 *)(hitObj + 0x46) == 0x605 &&
                *(u8 *)(p2 + hitType + 0xb2) == 0 &&
                *(u8 *)(p2 + hitType + 0xae) != 0 &&
                *(int *)(p2 + 0x88) == 0xc) {
                Obj_SetModelColorFadeRecursive(p1, 0x19, 0xc8, 0, 0, 1);
                *(u8 *)(p2 + hitType + 0xae) = *(u8 *)(p2 + hitType + 0xae) - 1;
                *(u8 *)(p2 + hitType + 0xb2) = 0xc8;
            }
        } else if (hitType >= 0 && hitType < 3) {
            if (*(u8 *)(p2 + hitType + 0xae) != 0 && *(u8 *)(p2 + hitType + 0xb2) == 0) {
                *(u8 *)(p2 + hitType + 0xae) = *(u8 *)(p2 + hitType + 0xae) - 1;
                *(u8 *)(p2 + hitType + 0xb2) = 6;
                if (*(u8 *)(p2 + hitType + 0xae) != 0)
                    Sfx_PlayFromObject(p1, 0x484);
                else
                    Sfx_PlayFromObject(p1, 0x485);
                switch (hitType) {
                case 0:
                    *(s16 *)(p2 + 0xa2) = -0xfa;
                    break;
                case 1:
                    *(s16 *)(p2 + 0xa2) = 0xfa;
                    break;
                case 2:
                    *(s16 *)(p2 + 0xa4) = -0xc8;
                    break;
                }
            }
        }
    }
    for (i = 0; i < 3; i++) {
        int state;
        int adjusted;
        int texIdx;
        int *tex;

        if (*(u8 *)(p2 + i + 0xae) != 0) {
            if (*(u8 *)(p2 + i + 0xb2) != 0)
                *(u8 *)(p2 + i + 0xb9) = 1;
            else
                *(u8 *)(p2 + i + 0xb9) = 0;
        } else {
            *(u8 *)(p2 + i + 0xb9) = 2;
        }
        state = *(u8 *)(p2 + i + 0xb9);
        adjusted = state;
        texIdx = (&lbl_803DC4C8)[i];
        if (texIdx < 2 && state == 1)
            adjusted = 0;
        tex = objFindTexture(p1, texIdx * 2, 0);
        *tex = adjusted << 8;
        if (texIdx == 2 && state == 1)
            state = 0;
        tex = objFindTexture(p1, texIdx * 2 + 1, 0);
        *tex = state << 8;
    }
}
#pragma scheduling reset
#pragma peephole reset
