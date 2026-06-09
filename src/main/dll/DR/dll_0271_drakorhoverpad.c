#include "main/dll/DR/dr_shared.h"
#include "main/game_object.h"

#include "main/audio/sfx_ids.h"
int drakorhoverpad_func0B(void) { return 0x1; }

int drakorhoverpad_func0E(void) { return 0x1; }

int drakorhoverpad_func10(void) { return 0x0; }

void drakorhoverpad_func11(void) {}

int drakorhoverpad_func14(void) { return 0x0; }

void drakorhoverpad_func15(void) {}

#include "global.h"

/* Rom-curve follow block embedded at state+0x4 (passed to the curve
 * interface; drakorhoverpad_update receives it as its first arg). */
typedef struct DrakorPadCurve {
    f32 unk00;
    u8 pad04[0xc];
    int unk10;
    u8 pad14[0x54];
    f32 unk68;
    f32 unk6C;
    f32 unk70;
    f32 unk74;
    f32 unk78;
    f32 unk7C;
    int pointIdx;    /* 0x80 */
    u8 pad84[0xc];
    int unk90;
    u8 pad94[8];
    u8 *pointDef;    /* 0x9c */
    u8 *pointDef2;   /* 0xa0 */
    void *unkA4;
    u8 padA8[0x10];
    f32 vecB8[4];
    u8 padC8[0x10];
    f32 vecD8[4];
    u8 padE8[0x10];
    f32 vecF8[4];
} DrakorPadCurve;
STATIC_ASSERT(sizeof(DrakorPadCurve) == 0x108);

/* drakorhoverpad_getExtraSize == 0x17c. */
typedef struct DrakorHoverpadState {
    f32 unk00;
    DrakorPadCurve curve; /* 0x004 */
    u8 pad10C[4];
    f32 speed;        /* 0x110 */
    f32 targetSpeed;  /* 0x114 */
    f32 unk118;
    f32 unk11C;
    f32 unk120;
    u8 pad124[0x30];
    f32 unk154;
    f32 unk158;
    f32 unk15C;
    f32 unk160;
    f32 unk164;
    f32 unk168;
    u8 pad16C[4];
    int unk170;
    s16 unk174;
    s16 unk176;
    u8 pad178[4];
} DrakorHoverpadState;
STATIC_ASSERT(sizeof(DrakorHoverpadState) == 0x17c);

int drakorhoverpad_getExtraSize(void) { return 0x17c; }

int drakorhoverpad_getObjectTypeId(void) { return 0x0; }

void drakorhoverpad_hitDetect(void) {}

void drakorhoverpad_initialise(void) {}

void drakorhoverpad_release(void) {}

#pragma scheduling off
#pragma peephole off
void drakorhoverpad_initMain(int obj, void *desc) {
    u8 *p = ((GameObject *)obj)->extra;
    HoverpadFlags *f = (HoverpadFlags *)(p + 0x178);
    Flags377 *g = (Flags377 *)(p + 0x179);
    f32 v;

    *(s16 *)obj = (s16)(*(s8 *)((char *)desc + 0x18) << 8);
    ((DrakorHoverpadState *)p)->unk118 = (f32)*(s16 *)((char *)desc + 0x1a);
    v = lbl_803E6A3C;
    ((DrakorHoverpadState *)p)->speed = v;
    f->bit20 = 0;
    f->b40 = 1;
    ((DrakorHoverpadState *)p)->unk170 = 0;
    ((DrakorHoverpadState *)p)->unk11C = v;
    ((DrakorHoverpadState *)p)->unk120 = v;
    ((DrakorHoverpadState *)p)->unk176 = 0;
    switch (*(s16 *)desc) {
    case 1812:
        g->f10 = 1;
        g->f04 = 1;
        g->f08 = 0;
        break;
    case 1048:
        g->f10 = 0;
        g->f04 = 0;
        g->f08 = 1;
        break;
    }
    ObjGroup_AddObject(obj, 70);
    ObjGroup_AddObject(obj, 10);
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
#pragma dont_inline on
int drakorhoverpad_init(int obj) {
    u8 *p = ((GameObject *)obj)->extra;
    HoverpadFlags *f = (HoverpadFlags *)(p + 0x178);

    if (f->b40 == 0) {
        if (f->state > 3) {
            if (lbl_803E6A3C == ((DrakorHoverpadState *)p)->speed) {
                f->state = 0;
            }
        }
    }
    if (f->b01 != GameBit_Get(1654)) {
        f->b01 ^= 1;
        *(f32 *)p = -*(f32 *)p;
        if (f->state == 3) {
            f->state = 0;
            *(f32 *)p = lbl_803E6A38;
        }
        if (f->state == 4) {
            f->state = 0;
            *(f32 *)p = lbl_803E6A74;
        }
        if (f->b40 != 0) {
            if (lbl_803E6A3C == *(f32 *)p) {
                if (f->b01 != 0) {
                    *(f32 *)p = lbl_803E6A74;
                } else {
                    *(f32 *)p = lbl_803E6A38;
                }
            }
        }
        Sfx_PlayFromObject(obj, SFXfend_fox_keytap3);
    }
    return 0;
}
#pragma dont_inline reset
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void drakorhoverpad_render(void *obj, undefined4 p2, undefined4 p3, undefined4 p4, undefined4 p5, char visible) {
    u8 *p = ((GameObject *)obj)->extra;
    if (visible) {
        objRenderFn_8003b8f4(obj, p2, p3, p4, p5, (double)lbl_803E6A48);
        *(s16 *)(p + 0x176) += framesThisStep;
        if (*(s16 *)(p + 0x176) == 0 || *(s16 *)(p + 0x176) > 10) {
            *(s16 *)(p + 0x176) = 0;
            *(f32 *)(p + 0x154) = ((GameObject *)obj)->anim.localPosX + (f32)(int)randomGetRange(-30, 30);
            *(f32 *)(p + 0x158) = ((GameObject *)obj)->anim.localPosY;
            *(f32 *)(p + 0x15c) = ((GameObject *)obj)->anim.localPosZ + (f32)(int)randomGetRange(-30, 30);
            *(f32 *)(p + 0x160) = ((GameObject *)obj)->anim.localPosX + (f32)(int)randomGetRange(-120, 120);
            *(f32 *)(p + 0x164) = ((GameObject *)obj)->anim.localPosY - lbl_803E6A88;
            *(f32 *)(p + 0x168) = ((GameObject *)obj)->anim.localPosZ + (f32)(int)randomGetRange(-120, 120);
        }
    }
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
#pragma dont_inline on
int drakorhoverpad_pickUnmaskedNextPoint(int *pad, int exclude, int maxIndex) {
    int collected[4];
    int pt;
    int count;
    u32 bit;
    int i;

    count = 0;
    bit = 1;
    for (i = 0; i < 4; i++) {
        pt = pad[7 + i];
        if (pt > -1 && (*(s8 *)((char *)pad + 0x1b) & bit) == 0 && pt != exclude) {
            collected[count] = pt;
            count++;
        }
        bit <<= 1;
    }
    if (count == 0) {
        return -1;
    }
    if (maxIndex != -1 && maxIndex > count - 1) {
        maxIndex = count - 1;
    }
    if (maxIndex == -1) {
        maxIndex = randomGetRange(0, count - 1);
    }
    return collected[maxIndex];
}
#pragma dont_inline reset
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
#pragma dont_inline on
int drakorhoverpad_pickMaskedNextPoint(int *pad, int exclude, int maxIndex) {
    int collected[4];
    int pt;
    int count;
    u32 bit;
    int i;

    count = 0;
    bit = 1;
    for (i = 0; i < 4; i++) {
        pt = pad[7 + i];
        if (pt > -1 && (*(s8 *)((char *)pad + 0x1b) & bit) != 0 && pt != exclude) {
            collected[count] = pt;
            count++;
        }
        bit <<= 1;
    }
    if (count == 0) {
        return -1;
    }
    if (maxIndex != -1 && maxIndex > count - 1) {
        maxIndex = count - 1;
    }
    if (maxIndex == -1) {
        maxIndex = randomGetRange(0, count - 1);
    }
    return collected[maxIndex];
}
#pragma dont_inline reset
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
int drakorhoverpad_update(void *curve, int arg) {
    u8 *p = (u8 *)curve;
    u8 *cur;
    int result;

    if (curve == NULL) {
        return 1;
    }
    cur = *(u8 **)&((GameObject *)p)->anim.currentMove;
    if (cur == NULL || ((GameObject *)p)->anim.targetObj == NULL) {
        return 1;
    }
    *(u8 **)&((GameObject *)p)->anim.activeMoveProgress = cur;
    *(u8 **)&((GameObject *)p)->anim.currentMove = *(u8 **)&((GameObject *)p)->anim.targetObj;
    memcpy(p + 0xa8, p + 0xb8, 16);
    memcpy(p + 0xc8, p + 0xd8, 16);
    memcpy(p + 0xe8, p + 0xf8, 16);
    if (*(int *)&((GameObject *)p)->anim.previousLocalPosX != 0) {
        result = drakorhoverpad_pickMaskedNextPoint(*(int **)&((GameObject *)p)->anim.currentMove, -1, arg);
    } else {
        result = drakorhoverpad_pickUnmaskedNextPoint(*(int **)&((GameObject *)p)->anim.currentMove, -1, arg);
    }
    if (result == -1) {
        ((GameObject *)p)->anim.targetObj = NULL;
        return 1;
    }
    ((GameObject *)p)->anim.targetObj = (*gRomCurveInterface)->getById(result);
    if (((GameObject *)p)->anim.targetObj == NULL) {
        return 1;
    }
    if (*(int *)&((GameObject *)p)->anim.previousLocalPosX != 0) {
        *(f32 *)&((GameObject *)p)->extra = *(f32 *)(*(u8 **)&((GameObject *)p)->anim.currentMove + 8);
        *(f32 *)&((GameObject *)p)->animEventCallback = *(f32 *)(*(u8 **)&((GameObject *)p)->anim.activeMoveProgress + 8);
        *(f32 *)&((GameObject *)p)->unkC0 = lbl_803E6A38 * ((f32)(u32)*(u8 *)(*(u8 **)&((GameObject *)p)->anim.currentMove + 0x2e) * mathSinf(lbl_803E6A54 * (f32)(int)(*(s8 *)(*(u8 **)&((GameObject *)p)->anim.currentMove + 0x2c) << 8) / lbl_803E6A58));
        *(f32 *)&((GameObject *)p)->unkC4 = lbl_803E6A38 * ((f32)(u32)*(u8 *)(*(u8 **)&((GameObject *)p)->anim.activeMoveProgress + 0x2e) * mathSinf(lbl_803E6A54 * (f32)(int)(*(s8 *)(*(u8 **)&((GameObject *)p)->anim.activeMoveProgress + 0x2c) << 8) / lbl_803E6A58));
        *(f32 *)(p + 0xd8) = *(f32 *)(*(u8 **)&((GameObject *)p)->anim.currentMove + 0xc);
        *(f32 *)&((GameObject *)p)->unkDC = *(f32 *)(*(u8 **)&((GameObject *)p)->anim.activeMoveProgress + 0xc);
        *(f32 *)(p + 0xe0) = lbl_803E6A38 * ((f32)(u32)*(u8 *)(*(u8 **)&((GameObject *)p)->anim.currentMove + 0x2e) * mathSinf(lbl_803E6A54 * (f32)(int)(*(s8 *)(*(u8 **)&((GameObject *)p)->anim.currentMove + 0x2d) << 8) / lbl_803E6A58));
        *(f32 *)(p + 0xe4) = lbl_803E6A38 * ((f32)(u32)*(u8 *)(*(u8 **)&((GameObject *)p)->anim.activeMoveProgress + 0x2e) * mathSinf(lbl_803E6A54 * (f32)(int)(*(s8 *)(*(u8 **)&((GameObject *)p)->anim.activeMoveProgress + 0x2d) << 8) / lbl_803E6A58));
        *(f32 *)&((GameObject *)p)->unkF8 = *(f32 *)(*(u8 **)&((GameObject *)p)->anim.currentMove + 0x10);
        ((GameObject *)p)->unkFC = *(f32 *)(*(u8 **)&((GameObject *)p)->anim.activeMoveProgress + 0x10);
        ((GameObject *)p)->unk100 = lbl_803E6A38 * ((f32)(u32)*(u8 *)(*(u8 **)&((GameObject *)p)->anim.currentMove + 0x2e) * mathCosf(lbl_803E6A54 * (f32)(int)(*(s8 *)(*(u8 **)&((GameObject *)p)->anim.currentMove + 0x2c) << 8) / lbl_803E6A58));
        ((GameObject *)p)->unk104 = lbl_803E6A38 * ((f32)(u32)*(u8 *)(*(u8 **)&((GameObject *)p)->anim.activeMoveProgress + 0x2e) * mathCosf(lbl_803E6A54 * (f32)(int)(*(s8 *)(*(u8 **)&((GameObject *)p)->anim.activeMoveProgress + 0x2c) << 8) / lbl_803E6A58));
    } else {
        *(f32 *)&((GameObject *)p)->extra = *(f32 *)(*(u8 **)&((GameObject *)p)->anim.currentMove + 8);
        *(f32 *)&((GameObject *)p)->animEventCallback = *(f32 *)(*(u8 **)&((GameObject *)p)->anim.currentMove + 8);
        *(f32 *)&((GameObject *)p)->unkC0 = lbl_803E6A38 * ((f32)(u32)*(u8 *)(*(u8 **)&((GameObject *)p)->anim.currentMove + 0x2e) * mathSinf(lbl_803E6A54 * (f32)(int)(*(s8 *)(*(u8 **)&((GameObject *)p)->anim.currentMove + 0x2c) << 8) / lbl_803E6A58));
        *(f32 *)&((GameObject *)p)->unkC4 = lbl_803E6A38 * ((f32)(u32)*(u8 *)(*(u8 **)&((GameObject *)p)->anim.currentMove + 0x2e) * mathSinf(lbl_803E6A54 * (f32)(int)(*(s8 *)(*(u8 **)&((GameObject *)p)->anim.currentMove + 0x2c) << 8) / lbl_803E6A58));
        *(f32 *)(p + 0xd8) = *(f32 *)(*(u8 **)&((GameObject *)p)->anim.currentMove + 0xc);
        *(f32 *)&((GameObject *)p)->unkDC = *(f32 *)(*(u8 **)&((GameObject *)p)->anim.currentMove + 0xc);
        *(f32 *)(p + 0xe0) = lbl_803E6A38 * ((f32)(u32)*(u8 *)(*(u8 **)&((GameObject *)p)->anim.currentMove + 0x2e) * mathSinf(lbl_803E6A54 * (f32)(int)(*(s8 *)(*(u8 **)&((GameObject *)p)->anim.currentMove + 0x2d) << 8) / lbl_803E6A58));
        *(f32 *)(p + 0xe4) = lbl_803E6A38 * ((f32)(u32)*(u8 *)(*(u8 **)&((GameObject *)p)->anim.currentMove + 0x2e) * mathSinf(lbl_803E6A54 * (f32)(int)(*(s8 *)(*(u8 **)&((GameObject *)p)->anim.currentMove + 0x2d) << 8) / lbl_803E6A58));
        *(f32 *)&((GameObject *)p)->unkF8 = *(f32 *)(*(u8 **)&((GameObject *)p)->anim.currentMove + 0x10);
        ((GameObject *)p)->unkFC = *(f32 *)(*(u8 **)&((GameObject *)p)->anim.currentMove + 0x10);
        ((GameObject *)p)->unk100 = lbl_803E6A38 * ((f32)(u32)*(u8 *)(*(u8 **)&((GameObject *)p)->anim.currentMove + 0x2e) * mathCosf(lbl_803E6A54 * (f32)(int)(*(s8 *)(*(u8 **)&((GameObject *)p)->anim.currentMove + 0x2c) << 8) / lbl_803E6A58));
        ((GameObject *)p)->unk104 = lbl_803E6A38 * ((f32)(u32)*(u8 *)(*(u8 **)&((GameObject *)p)->anim.currentMove + 0x2e) * mathCosf(lbl_803E6A54 * (f32)(int)(*(s8 *)(*(u8 **)&((GameObject *)p)->anim.currentMove + 0x2c) << 8) / lbl_803E6A58));
    }
    if (*(int *)&((GameObject *)p)->anim.previousWorldPosY != 0) {
        curvesSetupMoveNetworkCurve(curve);
    }
    if (*(int *)&((GameObject *)p)->anim.previousLocalPosX != 0) {
        Curve_AdvanceAlongPath(curve, lbl_803E6A70);
    } else {
        Curve_AdvanceAlongPath(curve, lbl_803E6A48);
    }
    return 0;
}
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void drakorhoverpad_updateMain(int obj) {
    u8 *p = ((GameObject *)obj)->extra;
    int q = *(int *)&((GameObject *)obj)->anim.placementData;
    HoverpadFlags *f = (HoverpadFlags *)(p + 0x178);
    Flags377 *g = (Flags377 *)(p + 0x179);
    u8 *curve;
    int curveArg;
    f32 curvePos[3];
    f32 diff[3];
    int evOut;
    f32 phase;
    f32 wobbleY;
    f32 limit;
    f32 absH;
    f32 absV;
    int nearest;
    int yawDelta;
    int c;

    Obj_GetPlayerObject();
    if (drakorhoverpad_init(obj) != 0) {
        return;
    }
    if (f->bit20 == 0) {
        f->bit20 = GameBit_Get(*(s16 *)((char *)q + 0x20));
        *(f32 *)(p + 0x114) = lbl_803E6A3C;
        if (f->bit20 != 0) {
            curveArg = 0x2a;
            (*gRomCurveInterface)->initCurve(p + 4, (void *)obj, lbl_803E6A4C, &curveArg, -1);
            Curve_AdvanceAlongPath(p + 4, lbl_803E6A50);
            ((GameObject *)obj)->anim.localPosX = *(f32 *)&((GameObject *)p)->anim.jointPoseData;
            ((GameObject *)obj)->anim.localPosY = *(f32 *)(p + 0x70);
            ((GameObject *)obj)->anim.localPosZ = *(f32 *)(p + 0x74);
            *(f32 *)p = lbl_803E6A38;
            Sfx_PlayFromObject(obj, SFXfend_fox_keytap2);
            Sfx_PlayFromObject(obj, SFXfend_pep_wakeup);
        }
        return;
    }
    curve = p + 4;
    if (g->f08 != 0) {
        phase = lbl_803E6A54 *
                (f32)(int)getAngle(sqrtf(*(f32 *)(curve + 0x74) * *(f32 *)(curve + 0x74) +
                                         *(f32 *)(curve + 0x7c) * *(f32 *)(curve + 0x7c)),
                                   *(f32 *)(curve + 0x78)) /
                lbl_803E6A58;
        wobbleY = lbl_803E6A8C * mathCosf(phase);
        limit = lbl_803E6A90 * (lbl_803E6A94 * mathSinf(phase));
        if (f->b40 != 0) {
            absH = *(f32 *)p;
            if (absH < lbl_803E6A3C) {
                absH = -absH;
            }
            absV = *(f32 *)(p + 0x110);
            if (absV < lbl_803E6A3C) {
                absV = -absV;
            }
            if (absV > lbl_803E6A38 + absH) {
                limit = limit + lbl_803E6A38;
            }
        }
        if (f->state != 0) {
            limit = limit + lbl_803E6A38;
        }
        *(f32 *)(p + 0x110) = *(f32 *)(p + 0x114) + (*(f32 *)(p + 0x110) + wobbleY);
        absV = *(f32 *)(p + 0x110);
        if (absV < lbl_803E6A3C) {
            absV = -absV;
        }
        if (absV < limit) {
            *(f32 *)(p + 0x110) = *(f32 *)p;
        } else {
            if (*(f32 *)(p + 0x110) > *(f32 *)p) {
                *(f32 *)(p + 0x110) = *(f32 *)(p + 0x110) + -limit;
            } else {
                *(f32 *)(p + 0x110) = *(f32 *)(p + 0x110) + limit;
            }
        }
        ObjHits_SetHitVolumeSlot(obj, 8, 1, 0);
    } else {
        ObjHits_DisableObject(obj);
        *(f32 *)(p + 0x110) = *(f32 *)p;
        lbl_803DC2F8 = lbl_803E6A38 * *(f32 *)p;
    }
    if (*(f32 *)(p + 0x110) < lbl_803E6A3C) {
        (*gRomCurveInterface)->setClosed(p + 4, 1);
    } else {
        (*gRomCurveInterface)->setClosed(p + 4, 0);
    }
    *(f32 *)(p + 0x114) = lbl_803E6A3C;
    if (lbl_803E6A3C != *(f32 *)(p + 0x110)) {
        Curve_AdvanceAlongPath(curve, *(f32 *)(p + 0x110));
        if ((*(int *)(curve + 0x80) != 0) != (*(int *)(curve + 0x10) != 0)) {
            if (drakorhoverpad_handlePathPointEvent(obj, *(u8 *)(*(int *)(curve + 0xa0) + 0x18),
                                                    *(u8 *)(*(int *)(curve + 0xa4) + 0x18),
                                                    &evOut) != 0) {
                drakorhoverpad_update(curve, evOut);
            }
        }
    }
    curvePos[0] = *(f32 *)(curve + 0x68);
    curvePos[1] = *(f32 *)(curve + 0x6c);
    curvePos[2] = *(f32 *)(curve + 0x70);
    curvePos[1] = curvePos[1] + (lbl_803E6A48 + mathSinf(lbl_803E6A54 *
                                                            (f32)(int)*(s16 *)(p + 0x174) /
                                                            lbl_803E6A58));
    *(s16 *)(p + 0x174) = (s16)(*(s16 *)(p + 0x174) + framesThisStep * 0x320);
    if (g->f10 != 0) {
        nearest = ObjGroup_FindNearestObject(0x45, obj, 0);
        if (nearest != 0) {
            yawDelta = Obj_GetYawDeltaToObject(obj, nearest, 0);
            if (yawDelta < -0x200) {
                yawDelta = -0x200;
            } else if (yawDelta > 0x200) {
                yawDelta = 0x200;
            }
            *(s16 *)obj = (s16)(*(s16 *)obj + yawDelta);
            if (((GameObject *)obj)->anim.rotY != 0) {
                c = ((GameObject *)obj)->anim.rotY;
                if (c < -0x100) {
                    c = -0x100;
                } else if (c > 0x100) {
                    c = 0x100;
                }
                ((GameObject *)obj)->anim.rotY = (s16)(((GameObject *)obj)->anim.rotY - c);
            }
            ((GameObject *)obj)->anim.rotZ = (s16)(yawDelta * lbl_803DC2FC);
        }
    } else {
        phase = sqrtf(*(f32 *)(curve + 0x74) * *(f32 *)(curve + 0x74) +
                      *(f32 *)(curve + 0x7c) * *(f32 *)(curve + 0x7c));
        yawDelta = (s16)((s16)(getAngle(*(f32 *)(curve + 0x74), *(f32 *)(curve + 0x7c)) + 0x8000) -
                         *(s16 *)obj);
        ((GameObject *)obj)->anim.rotY = getAngle(*(f32 *)(curve + 0x78), phase);
        if (yawDelta < -0x800) {
            yawDelta = -0x800;
        } else if (yawDelta > 0x800) {
            yawDelta = 0x800;
        }
        if (*(f32 *)(p + 0x110) < lbl_803E6A3C) {
            ((GameObject *)obj)->anim.rotZ = yawDelta;
        } else {
            ((GameObject *)obj)->anim.rotZ = -yawDelta;
        }
        c = yawDelta;
        if (c < -0x100) {
            c = -0x100;
        } else if (c > 0x100) {
            c = 0x100;
        }
        *(s16 *)obj = (s16)(*(s16 *)obj + c);
        c = ((GameObject *)obj)->anim.rotY;
        if (c < -0x64) {
            c = -0x64;
        } else if (c > 0x64) {
            c = 0x64;
        }
        ((GameObject *)obj)->anim.rotY = c;
    }
    PSVECSubtract(curvePos, &((GameObject *)obj)->anim.localPosX, diff);
    Obj_SteerVelocityTowardVector(obj, &((GameObject *)obj)->anim.velocityX, diff, lbl_803DC2F8,
                lbl_803DC2F8 / lbl_803E6A98, lbl_803E6A9C);
    PSVECAdd(&((GameObject *)obj)->anim.localPosX, &((GameObject *)obj)->anim.velocityX, &((GameObject *)obj)->anim.localPosX);
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
int drakorhoverpad_handlePathPointEvent(int obj, u8 a, u8 b, void *out) {
    u8 *p = ((GameObject *)obj)->extra;
    HoverpadFlags *f = (HoverpadFlags *)(p + 0x178);
    Flags377 *g = (Flags377 *)(p + 0x179);
    int player;
    f32 m;
    f32 absP;

    player = (int)Obj_GetPlayerObject();
    *(int *)out = -1;
    switch (a) {
    case 1:
        player = (int)Obj_GetPlayerObject();
        *(f32 *)(p + 0x110) = lbl_803E6A78 * -*(f32 *)(p + 0x110);
        *(f32 *)p = lbl_803E6A3C;
        if (*(void **)((char *)player + 0x30) == (void *)obj) {
            Camera_EnableViewYOffset();
            if (*(f32 *)(p + 0x110) >= lbl_803E6A3C) {
                m = *(f32 *)(p + 0x110);
            } else {
                m = -*(f32 *)(p + 0x110);
            }
            CameraShake_SetAllMagnitudes(m);
        }
        break;
    case 3:
        if (f->b40 != 0) {
            break;
        }
        if (*(f32 *)(p + 0x110) <= lbl_803E6A3C) {
            break;
        }
        if (f->bit80 != 0) {
            break;
        }
        player = (int)Obj_GetPlayerObject();
        *(f32 *)(p + 0x110) = lbl_803E6A78 * -*(f32 *)(p + 0x110);
        *(f32 *)p = lbl_803E6A3C;
        if (*(void **)((char *)player + 0x30) == (void *)obj) {
            Camera_EnableViewYOffset();
            if (*(f32 *)(p + 0x110) >= lbl_803E6A3C) {
                m = *(f32 *)(p + 0x110);
            } else {
                m = -*(f32 *)(p + 0x110);
            }
            CameraShake_SetAllMagnitudes(m);
        }
        return 1;
    case 4:
        if (*(f32 *)(p + 0x110) <= lbl_803E6A3C) {
            break;
        }
        if (f->b40 != 0) {
            GameBit_Set(0x660, 1);
        } else if (GameBit_Get(0x661) != 0) {
            if (*(f32 *)p < lbl_803E6A3C) {
                *(f32 *)(p + 0x114) += lbl_803E6A74;
            } else {
                *(f32 *)(p + 0x114) += lbl_803E6A38;
            }
        } else {
            GameBit_Set(0x788, 1);
            f->state = 1;
            *(f32 *)p = lbl_803E6A3C;
        }
        break;
    case 9:
        if (*(f32 *)(p + 0x110) >= lbl_803E6A3C) {
            break;
        }
        if (GameBit_Get(0x661) != 0) {
            if (*(f32 *)p < lbl_803E6A3C) {
                *(f32 *)(p + 0x114) += lbl_803E6A74;
            } else {
                *(f32 *)(p + 0x114) += lbl_803E6A38;
            }
        } else {
            f->state = 1;
            *(f32 *)p = lbl_803E6A3C;
        }
        break;
    case 5:
        if (f->b40 != 0) {
            break;
        }
        f->state = 2;
        break;
    case 6:
        if (f->b40 != 0) {
            break;
        }
        if (*(f32 *)p < lbl_803E6A3C) {
            *(f32 *)(p + 0x114) += lbl_803E6A7C;
        } else {
            *(f32 *)(p + 0x114) += lbl_803E6A80;
        }
        break;
    case 7:
        if (*(f32 *)p > lbl_803E6A3C) {
            break;
        }
        f->state = 3;
        *(f32 *)p = lbl_803E6A3C;
        Sfx_PlayFromObject(obj, SFXfend_rob_servo1);
        break;
    case 17:
        if (*(f32 *)p < lbl_803E6A3C) {
            break;
        }
        f->state = 4;
        *(f32 *)p = lbl_803E6A3C;
        Sfx_PlayFromObject(obj, SFXfend_rob_servo1);
        break;
    case 10:
        if (g->p1 == 0) {
            break;
        }
        if (GameBit_Get(0x689) != 0) {
            break;
        }
        GameBit_Set(0x689, 1);
        break;
    case 11:
        if (g->p1 == 0) {
            break;
        }
        if (*(void **)((char *)player + 0x30) != (void *)obj) {
            break;
        }
        GameBit_Set(0x68a, 1);
        break;
    case 12:
        if (g->p1 == 0) {
            break;
        }
        if (*(void **)((char *)player + 0x30) != (void *)obj) {
            break;
        }
        GameBit_Set(0x68b, 1);
        break;
    case 13:
        if (GameBit_Get(0x68a) == 0) {
            break;
        }
        if (*(f32 *)p < lbl_803E6A3C) {
            break;
        }
        player = (int)Obj_GetPlayerObject();
        *(f32 *)(p + 0x110) = lbl_803E6A78 * -*(f32 *)(p + 0x110);
        *(f32 *)p = lbl_803E6A3C;
        if (*(void **)((char *)player + 0x30) == (void *)obj) {
            Camera_EnableViewYOffset();
            if (*(f32 *)(p + 0x110) >= lbl_803E6A3C) {
                m = *(f32 *)(p + 0x110);
            } else {
                m = -*(f32 *)(p + 0x110);
            }
            CameraShake_SetAllMagnitudes(m);
        }
        break;
    case 14:
        if (g->p1 == 0) {
            break;
        }
        if (*(f32 *)p > lbl_803E6A3C) {
            break;
        }
        player = (int)Obj_GetPlayerObject();
        *(f32 *)(p + 0x110) = lbl_803E6A78 * -*(f32 *)(p + 0x110);
        *(f32 *)p = lbl_803E6A3C;
        if (*(void **)((char *)player + 0x30) == (void *)obj) {
            Camera_EnableViewYOffset();
            if (*(f32 *)(p + 0x110) >= lbl_803E6A3C) {
                m = *(f32 *)(p + 0x110);
            } else {
                m = -*(f32 *)(p + 0x110);
            }
            CameraShake_SetAllMagnitudes(m);
        }
        break;
    case 15:
        if (f->b40 != 0) {
            break;
        }
        GameBit_Set(0x788, 1);
        break;
    case 16:
        if (*(f32 *)p >= lbl_803E6A3C) {
            absP = *(f32 *)p;
        } else {
            absP = -*(f32 *)p;
        }
        if (lbl_803E6A38 == absP) {
            *(f32 *)p = *(f32 *)p * lbl_803E6A84;
        } else {
            *(f32 *)p = lbl_803E6A38 * *(f32 *)p;
        }
        Sfx_PlayFromObject(obj, SFXfend_fox_keytap3);
        break;
    case 20:
        g->f10 = !g->f10;
        break;
    case 21:
        g->p6 = 1;
        *(f32 *)p = lbl_803E6A3C;
        break;
    }
    switch (b) {
    case 8:
        if (GameBit_Get(0x67f) != 0) {
            *(int *)out = 1;
        } else {
            *(int *)out = 0;
        }
        break;
    case 2:
        GameBit_Set(0x7ba, 1);
        break;
    case 18:
        *(int *)out = 0;
        break;
    case 19:
        *(int *)out = 1;
        break;
    }
    return 1;
}
#pragma peephole reset
#pragma scheduling reset

int drakorhoverpad_setScale(int obj) {
    u8 *p = ((GameObject *)obj)->extra;
    return (p[0x179] >> 2) & 1;
}

#pragma peephole off
int drakorhoverpad_render2(int obj) {
    u8 *p = ((GameObject *)obj)->extra;
    return ((p[0x179] >> 2) & 1) == 0;
}
#pragma peephole reset

#pragma scheduling off
void drakorhoverpad_func12(int obj, f32 *a, int *b) {
    *a = lbl_803E6A3C;
    *b = 0;
}
#pragma scheduling reset

void drakorhoverpad_modelMtxFn(int obj, f32 *a, f32 *b, f32 *c) {
    *a = ((GameObject *)obj)->anim.localPosX;
    *b = lbl_803E6A40 + ((GameObject *)obj)->anim.localPosY;
    *c = ((GameObject *)obj)->anim.localPosZ;
}

f32 drakorhoverpad_func13(int obj, f32 *out) {
    *out = lbl_803E6A44;
    return lbl_803E6A3C;
}

#pragma scheduling off
void drakorhoverpad_free(int obj) {
    ObjGroup_RemoveObject(obj, 0x46);
    ObjGroup_RemoveObject(obj, 0xa);
}
#pragma scheduling reset

void drakorhoverpad_func17(int obj, int sel, int *out) {
    switch (sel) {
    case 2:
        *out = *(s16 *)obj;
        break;
    case 3:
        *out = 0x1000;
        break;
    case 4:
        *out = 1;
        break;
    }
}

#pragma scheduling off
void drakorhoverpad_func0F(int obj, f32 *ox, f32 *oy, f32 *oz) {
    ObjPosParams pos;
    f32 mtx[16];
    int *src = Obj_GetPlayerObject();
    if (src == 0) {
        src = (int *)obj;
    }
    pos.x = *(f32 *)((char *)src + 0xc);
    pos.y = *(f32 *)((char *)src + 0x10);
    pos.z = *(f32 *)((char *)src + 0x14);
    pos.rx = *(s16 *)src;
    pos.ry = *(s16 *)((char *)src + 0x2);
    pos.rz = *(s16 *)((char *)src + 0x4);
    pos.scale = lbl_803E6A48;
    setMatrixFromObjectPos(mtx, &pos);
    Matrix_TransformPoint(mtx, lbl_803E6A3C, lbl_803DC300, lbl_803DC304, ox, oy, oz);
}
#pragma scheduling reset

#pragma peephole off
void drakorhoverpad_resetPendingMotion(int obj) {
    char *p = ((GameObject *)obj)->extra;
    if (((BitFlags8 *)(p + 0x179))->b6 != 0) {
        ((BitFlags8 *)(p + 0x179))->b6 = 0;
        *(f32 *)p = lbl_803E6A38;
    }
}
#pragma peephole reset

#pragma scheduling off
void drakorhoverpad_func16(int obj, f32 scale) {
    f32 *mtx;
    ObjPosParams pos;
    mtx = (f32 *)ObjPath_GetPointModelMtx(obj, 0);
    pos.x = lbl_803E6A3C;
    pos.y = lbl_803E6A40;
    pos.z = lbl_803E6A3C;
    pos.rx = 0;
    pos.ry = 0;
    pos.rz = 0;
    pos.scale = scale / *(f32 *)(*(int *)&((GameObject *)obj)->anim.modelInstance + 0x4);
    setMatrixFromObjectPos(lbl_803AD1C8, &pos);
    mtx44_mult(lbl_803AD1C8, mtx, lbl_803AD1C8);
    fn_8003B950(lbl_803AD1C8);
}
#pragma scheduling reset
