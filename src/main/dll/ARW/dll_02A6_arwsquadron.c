#include "main/dll/dll_80220608_shared.h"
#include "main/game_object.h"
#include "main/audio/sfx_ids.h"
#include "main/objanim_internal.h"
#include "main/objhits_types.h"

#pragma peephole on
#pragma scheduling on
#include "global.h"

/* arwsquadron_getExtraSize == 0x164 (enemy squadron fighter). */
typedef struct ArwSquadronState {
    u8 pad000[0x68];
    f32 unk68;
    f32 unk6C;
    f32 unk70;
    u8 pad74[0x28];
    int unk9C;
    u8 padA0[0x68];
    f32 pathX;       /* 0x108 */
    f32 pathY;
    f32 pathZ;       /* 0x110 */
    f32 emitX;       /* 0x114 */
    f32 emitY;
    f32 emitZ;       /* 0x11c */
    f32 unk120;
    u8 pad124[0xc];
    f32 unk130;
    f32 unk134;
    f32 unk138;
    int leaderObj;   /* 0x13c */
    s16 unk140;
    s16 unk142;
    s16 unk144;
    u16 unk146;
    u16 unk148;
    u16 unk14A;
    u16 unk14C;
    s16 volleyTimer; /* 0x14e */
    s16 unk150;
    s16 unk152;
    u8 unk154;
    u8 unk155;
    u8 unk156;
    u8 unk157;
    u8 health158;    /* 0x158 */
    u8 unk159;
    u8 unk15A;
    u8 unk15B;
    u8 unk15C;
    u8 unk15D;
    u8 unk15E;
    u8 unk15F;
    u8 pad160[4];
} ArwSquadronState;
STATIC_ASSERT(sizeof(ArwSquadronState) == 0x164);

int arwsquadron_getExtraSize(void) { return 0x164; }
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
int arwsquadron_getObjectTypeId(void) { return 0; }
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
void arwsquadron_free(void) {}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
void arwsquadron_render(int obj, int p2, int p3, int p4, int p5)
{
    objRenderFn_8003b8f4(obj, p2, p3, p4, p5, lbl_803E7188);
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
void arwsquadron_hitDetect(void) {}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void arwsquadron_spawnProjectile(int obj, int pathIdx, int angle, u8 flag) {
    f32 pz, py, px;
    int proj;
    if (Obj_IsLoadingLocked() == 0)
        return;
    ObjPath_GetPointWorldPosition(obj, pathIdx, &px, &py, &pz, 0);
    {
        int setup = Obj_AllocObjectSetup(0x20, 0x6ae);
        *(f32 *)(setup + 8) = px;
        *(f32 *)(setup + 0xc) = py;
        *(f32 *)(setup + 0x10) = pz;
        *(u8 *)(setup + 0x1a) = (*(s16 *)obj + 0x10000 + angle - 0x8000) >> 8;
        *(u8 *)(setup + 0x19) = -((GameObject *)obj)->anim.rotY >> 8;
        *(u8 *)(setup + 0x18) = 0;
        *(u8 *)(setup + 4) = 1;
        *(u8 *)(setup + 5) = 1;
    }
    proj = loadObjectAtObject(obj);
    if (proj == 0)
        return;
    if (flag != 0)
        arwprojectile_createLinkedEffect(proj, 1);
    arwprojectile_setLifetime(proj, 0x4b);
    arwprojectile_placeForward(proj, lbl_803E71A8);
    Sfx_PlayFromObjectLimited(proj, SFXbaddie_eba_smallswipe1, 4);
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void arwsquadron_init(int obj, int setup)
{
    SquadFlags *flags;
    int s;
    int tmp;

    tmp = lbl_803E7160;
    s = *(int *)&((GameObject *)obj)->extra;
    flags = (SquadFlags *)(s + 0x160);

    ((GameObject *)obj)->anim.rotX = *(u8 *)(setup + 0x18) << 8;
    ((GameObject *)obj)->anim.rotY = *(u8 *)(setup + 0x19) << 8;
    ((GameObject *)obj)->anim.rotZ = *(u8 *)(setup + 0x1a) << 8;
    flags->b10 = 1;
    *(u8 *)(s + 0x15e) = 1;
    *(f32 *)(s + 0x108) = (f32)(u32) * (u8 *)(setup + 0x30) * lbl_803E716C;
    *(f32 *)(s + 0x10c) = *(f32 *)(s + 0x108);
    *(s16 *)(s + 0x140) = *(u8 *)(setup + 0x1b) << 4;
    *(s16 *)(s + 0x142) = *(u8 *)(setup + 0x1c) << 4;
    *(s16 *)(s + 0x144) = *(u8 *)(setup + 0x1d) << 4;
    ObjHits_SetTargetMask(obj, 4);

    if (*(s16 *)(setup + 0x0) == 0x616 || *(s16 *)(setup + 0x0) == 0x617) {
        *(u8 *)(s + 0x15c) = 3;
        if (*(s16 *)(setup + 0x0) == 0x616) {
            flags->b10 = 0;
        }
        if (*(s16 *)(setup + 0x0) == 0x616) {
            *(f32 *)(s + 0x130) = lbl_803E71C0;
        } else {
            *(f32 *)(s + 0x130) = lbl_803E71C4;
        }
        *(u8 *)(s + 0x157) = 5;
        *(u8 *)(s + 0x158) = 0;
        if (*(s16 *)(setup + 0x0) == 0x616) {
            *(u8 *)(s + 0x156) = 2;
        } else {
            *(u8 *)(s + 0x156) = 1;
        }
        *(s16 *)(s + 0x140) = randomGetRange(-0x12c, 0x12c);
        *(s16 *)(s + 0x142) = randomGetRange(-0x12c, 0x12c);
        *(s16 *)(s + 0x144) = randomGetRange(-0x12c, 0x12c);
        flags->b80 = 1;
    } else if (*(s16 *)(setup + 0x0) == 0x7f0) {
        *(u8 *)(s + 0x15c) = 2;
        flags->b10 = 0;
        *(f32 *)(s + 0x130) = lbl_803E71C0;
    } else {
        *(u8 *)(s + 0x15c) = 1;
        *(f32 *)(s + 0x130) = lbl_803E71C4;
        *(u8 *)(s + 0x156) = 1;
        *(u8 *)(s + 0x157) = 0x14;
        *(u8 *)(s + 0x158) = 0;
        *(f32 *)(s + 0x11c) = lbl_803E71C8;
        *(f32 *)(s + 0x120) = lbl_803E7170;
        flags->b80 = 1;
        switch (((GameObject *)obj)->anim.seqId) {
        case 0x6d6:
            *(u8 *)(s + 0x15a) = 1;
            *(u8 *)(s + 0x15b) = 2;
            *(f32 *)(s + 0x114) = lbl_803E71CC;
            *(f32 *)(s + 0x118) = lbl_803E71D0;
            break;
        case 0x6d5:
            *(u8 *)(s + 0x15a) = 0;
            *(u8 *)(s + 0x15b) = 1;
            break;
        case 0x6d7:
            *(u8 *)(s + 0x15a) = 1;
            *(u8 *)(s + 0x15b) = 1;
            *(f32 *)(s + 0x114) = lbl_803E71CC;
            *(f32 *)(s + 0x118) = lbl_803E71D0;
            break;
        default:
            *(u8 *)(s + 0x15a) = 1;
            *(u8 *)(s + 0x15b) = 1;
            *(f32 *)(s + 0x114) = lbl_803E7170;
            *(f32 *)(s + 0x118) = lbl_803E71D0;
            break;
        }
    }

    *(f32 *)(s + 0x134) = (f32)(u32) * (u16 *)(setup + 0x24);
    if (*(f32 *)(s + 0x134) > *(f32 *)(s + 0x130)) {
        *(f32 *)(s + 0x134) = *(f32 *)(s + 0x130);
    }
    *(u8 *)(obj + 0x36) = 0;
    ((GameObject *)obj)->anim.flags |= 0x4000;
    storeZeroToFloatParam((void *)(s + 0x12c));

    if (*(u8 *)(setup + 0x2f) != 0) {
        if (*(u8 *)(s + 0x15c) == 1 || *(u8 *)(s + 0x15c) == 2) {
            tmp = 0x28;
        } else {
            tmp = 2;
        }
        if ((u8)(*(int (**)(int, int, f32, int *, int))(*gRomCurveInterface + 0x8c))(
                s, obj, lbl_803E71D4, &tmp, -1) == 0) {
            flags->b40 = 1;
            ((GameObject *)obj)->anim.localPosX = *(f32 *)(s + 0x68);
            ((GameObject *)obj)->anim.localPosY = *(f32 *)(s + 0x6c);
            ((GameObject *)obj)->anim.localPosZ = *(f32 *)(s + 0x70);
            arwsquadron_applyCommandParams(obj, s);
        }
    }

    *(u16 *)(s + 0x146) = randomGetRange(0, 0xffff);
    *(u16 *)(s + 0x148) = randomGetRange(0, 0xffff);
    *(u16 *)(s + 0x14a) = randomGetRange(0xc8, 0x12c);
    *(u16 *)(s + 0x14c) = randomGetRange(0xc8, 0x12c);
    *(f32 *)(s + 0x138) = (f32)(int)randomGetRange(0x3e8, 0x7d0);
    *(u8 *)(s + 0x15d) = *(u8 *)(setup + 0x31);
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void arwsquadron_applyCommandParams(int p1, int p2)
{
    SquadCmdFlags *flags = (SquadCmdFlags *)(p2 + 0x160);
    int cmds = ((ArwSquadronState *)p2)->unk9C;
    int i;

    if ((s8)*(u8 *)(cmds + 0x19) == 0x28) {
        for (i = 0; i < 2; i++) {
            int cmd;
            f32 val;
            if (i == 0) {
                cmd = *(u8 *)(cmds + 0x18);
                val = (f32)(s8)*(u8 *)(cmds + 0x1a);
            } else {
                cmd = *(u8 *)(cmds + 0x2f);
                val = (f32)*(u8 *)(cmds + 0x30);
            }
            switch ((u8)cmd) {
            case 3:
                ((ArwSquadronState *)p2)->pathY = val * lbl_803E716C;
                break;
            case 1:
                if (!flags->f80) {
                    int s = *(int *)(p1 + 0x4c);
                    flags->f80 = 1;
                    if (((ArwSquadronState *)p2)->unk15C == 1) {
                        flags->f20 = 0;
                        storeZeroToFloatParam((void *)(p2 + 0x124));
                        s16toFloat((void *)(p2 + 0x124), *(u8 *)(s + 0x2c));
                    }
                }
                break;
            case 2:
                flags->f80 = 0;
                break;
            case 4:
                if (!flags->f08) {
                    flags->f08 = 1;
                    ((ArwSquadronState *)p2)->unk144 = lbl_803E7170 * val;
                }
                break;
            case 5:
                flags->f08 = 0;
                break;
            }
        }
    }
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void arwsquadron_followPath(int p1, int p2)
{
    int state = *(int *)(p1 + 0x4c);
    int r;

    r = Obj_UpdateRomCurveFollowVelocity(p1, p2, ((ArwSquadronState *)p2)->pathX, lbl_803E719C, ((ArwSquadronState *)p2)->pathX, 1);
    if (r == -1) {
        *(s16 *)(p1 + 6) |= 0x4000;
        ObjHits_DisableObject(p1);
        ((ArwSquadronState *)p2)->unk159 = 4;
    } else {
        if (r != 0)
            arwsquadron_applyCommandParams(p1, p2);
        if (*(u8 *)(state + 0x2f) == 2) {
            if (((ArwSquadronState *)p2)->unk15C == 2)
                Obj_SmoothTurnAnglesTowardVelocity(p1, p1 + 0x24, 0xf, lbl_803E71A0, lbl_803E7188);
            else
                Obj_SmoothTurnAnglesTowardVelocity(p1, p1 + 0x24, 0xf,
                            ((SquadCmdFlags *)(p2 + 0x160))->f08 ? lbl_803E7168 : lbl_803E71A0,
                            lbl_803E7188);
        }
        ((ArwSquadronState *)p2)->pathX += interpolate(((ArwSquadronState *)p2)->pathY - ((ArwSquadronState *)p2)->pathX,
                                            lbl_803E71A4, timeDelta);
        objMove(p1, *(f32 *)(p1 + 0x24) * timeDelta, *(f32 *)(p1 + 0x28) * timeDelta,
                *(f32 *)(p1 + 0x2c) * timeDelta);
    }
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void arwsquadron_updateVolley(int p1, int p2, int p3)
{
    SquadCmdFlags *flags = (SquadCmdFlags *)(p2 + 0x160);

    if (!flags->f20) {
        if (timerCountDown((void *)(p2 + 0x124)) != 0) {
            flags->f20 = 1;
            storeZeroToFloatParam((void *)(p2 + 0x128));
            s16toFloat((void *)(p2 + 0x128), *(u8 *)(p3 + 0x2d));
            *(u8 *)(p2 + 0x155) = (s8)*(u8 *)(p3 + 0x2e);
            *(s16 *)(p2 + 0x14e) = -*(u16 *)(p3 + 0x2a);
        }
    } else if (timerCountDown((void *)(p2 + 0x128)) != 0) {
        arwsquadron_spawnProjectile(p1, 0, *(s16 *)(p2 + 0x14e),
                                    (s8)*(u8 *)(p2 + 0x155) == *(u8 *)(p3 + 0x2e) ? 1 : 0);
        if (*(u8 *)(p2 + 0x15b) > 1)
            arwsquadron_spawnProjectile(p1, 1, *(s16 *)(p2 + 0x14e), 0);
        *(u8 *)(p2 + 0x155) = *(u8 *)(p2 + 0x155) - 1;
        storeZeroToFloatParam((void *)(p2 + 0x128));
        s16toFloat((void *)(p2 + 0x128), *(u8 *)(p3 + 0x2d));
        *(s16 *)(p2 + 0x14e) = *(s16 *)(p2 + 0x14e) + *(u16 *)(p3 + 0x2a) * 2 / *(u8 *)(p3 + 0x2e);
        if ((s8)*(u8 *)(p2 + 0x155) <= 0) {
            flags->f20 = 0;
            storeZeroToFloatParam((void *)(p2 + 0x124));
            s16toFloat((void *)(p2 + 0x124), *(u8 *)(p3 + 0x2c));
        }
    }
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void arwsquadron_emitEffects(int p1, int p2)
{
    u8 flag = 1;
    SquadPfx pfx;

    if ((s8)((ArwSquadronState *)p2)->unk15E <= 2) {
        int cnt = ((ArwSquadronState *)p2)->unk15F;
        ((ArwSquadronState *)p2)->unk15F = cnt + 1;
        if (cnt % 2 != 0) {
            ObjPath_GetPointLocalPosition(p2, 4, &pfx.fx, &pfx.fy, &pfx.fz);
            pfx.f8 = ((ArwSquadronState *)p2)->emitZ;
            pfx.s6 = ((s8)((ArwSquadronState *)p2)->unk15E <= 1) ? 0x61a8 : -0x63c0;
            (*(void (**)(int, int, void *, int, int, void *))(*gPartfxInterface + 8))(
                p1, 0x7d0, &pfx, 4, -1, &flag);
        }
    }
    if ((s8)((ArwSquadronState *)p2)->unk15E <= 1) {
        pfx.s6 = 0xc0a;
        ObjPath_GetPointLocalPosition(p2, 5, &pfx.fx, &pfx.fy, &pfx.fz);
        pfx.f8 = ((ArwSquadronState *)p2)->unk120;
        (*(void (**)(int, int, void *, int, int, void *))(*gPartfxInterface + 8))(
            p1, 0x7d1, &pfx, 4, -1, &flag);
    }
    if (((ArwSquadronState *)p2)->unk15A != 0 && (s8)((ArwSquadronState *)p2)->unk15E > 1) {
        pfx.s0 = 0;
        pfx.s2 = 0;
        pfx.s4 = 0;
        pfx.f8 = lbl_803E7168;
        ObjPath_GetPointLocalPosition(p2, 2, &pfx.fx, &pfx.fy, &pfx.fz);
        objfx_spawnLightPulse(p1, ((ArwSquadronState *)p2)->emitX, 2, 0, 0, ((ArwSquadronState *)p2)->emitY, (int)&pfx);
    }
    if (((ArwSquadronState *)p2)->unk15A > 1 && (s8)((ArwSquadronState *)p2)->unk15E > 1) {
        ObjPath_GetPointLocalPosition(p2, 3, &pfx.fx, &pfx.fy, &pfx.fz);
        objfx_spawnLightPulse(p1, ((ArwSquadronState *)p2)->emitX, 2, 0, 0, ((ArwSquadronState *)p2)->emitY, (int)&pfx);
    }
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void arwsquadron_handleDamage(int obj, int state)
{
    SquadCmdFlags *flags = (SquadCmdFlags *)(state + 0x160);
    int hitObj;
    int hitVol;
    int arwing;

    if (((GameObject *)obj)->anim.hitReactState == NULL)
        return;
    if (((ArwSquadronState *)state)->unk154 != 0) {
        ((ArwSquadronState *)state)->pathZ -= timeDelta;
        if (((ArwSquadronState *)state)->pathZ <= lbl_803E7168)
            ((ArwSquadronState *)state)->unk154 = 0;
        if (flags->f10) {
            ((ArwSquadronState *)state)->unk150 = lbl_803E71AC * timeDelta + (f32)*(u16 *)&((ArwSquadronState *)state)->unk150;
            ((ArwSquadronState *)state)->unk152 = lbl_803E71B0 * timeDelta + (f32)*(u16 *)&((ArwSquadronState *)state)->unk152;
        }
    }
    if (ObjHits_GetPriorityHit(obj, &hitObj, 0, &hitVol) != 0 ||
        (*(ObjHitsPriorityState **)&((GameObject *)obj)->anim.hitReactState)->lastHitObject != 0) {
        if (flags->f10) {
            if (((ArwSquadronState *)state)->unk154 == 0)
                Sfx_PlayFromObjectLimited(obj, SFXbaddie_mika_death, 4);
            Obj_SetModelColorFadeRecursive(obj, 0xf, 0xc8, 0, 0, 1);
            ((ArwSquadronState *)state)->pathZ = lbl_803E71B4;
            ((ArwSquadronState *)state)->unk154 = 1;
            ((ArwSquadronState *)state)->unk150 = 0;
            ((ArwSquadronState *)state)->unk152 = 0;
            ((ArwSquadronState *)state)->unk15E = ((ArwSquadronState *)state)->unk15E - hitVol;
            if ((s8)((ArwSquadronState *)state)->unk15E <= 0) {
                storeZeroToFloatParam((void *)(state + 0x12c));
                s16toFloat((void *)(state + 0x12c), 0x78);
                if (((ArwSquadronState *)state)->unk15C == 1) {
                    spawnExplosion(obj, lbl_803E719C, 1, 0, 1, 1, 0, 0, 0);
                    ((GameObject *)obj)->anim.flags |= 0x4000;
                    ObjHits_DisableObject(obj);
                    ((ArwSquadronState *)state)->unk159 = 4;
                    ((ArwSquadronState *)state)->unk159 = 3;
                    if (((ArwSquadronState *)state)->unk15D == 3)
                        gameTextFn_80125ba4(0xe);
                } else {
                    spawnExplosion(obj, lbl_803E719C, 1, 0, 0, 1, 0, 0, 3);
                    ((GameObject *)obj)->anim.flags |= 0x4000;
                    ObjHits_DisableObject(obj);
                    ((ArwSquadronState *)state)->unk159 = 3;
                }
                arwing = getArwing();
                if (arwing != 0)
                    arwarwing_addScore(arwing, ((ArwSquadronState *)state)->unk157);
            } else {
                arwing = getArwing();
                if (arwing != 0)
                    arwarwing_addScore(arwing, ((ArwSquadronState *)state)->health158);
            }
        } else if (((ArwSquadronState *)state)->unk154 == 0) {
            Sfx_PlayFromObjectLimited(obj, SFXbaddie_invin_hit, 4);
        }
    }
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void arwsquadron_followLeader(int p1, int p2)
{
    int leader = ((ArwSquadronState *)p2)->leaderObj;
    int leaderState = *(int *)(leader + 0xb8);
    int wstate = *(int *)(p1 + 0x4c);
    ArwProjPosSrc src;
    f32 mtx[12];
    f32 out[3];

    *(s16 *)&((ArwSquadronState *)p2)->unk146 = (f32)((ArwSquadronState *)p2)->unk14A * timeDelta + (f32)((ArwSquadronState *)p2)->unk146;
    *(s16 *)&((ArwSquadronState *)p2)->unk148 = (f32)((ArwSquadronState *)p2)->unk14C * timeDelta + (f32)((ArwSquadronState *)p2)->unk148;
    src.pos[0] = *(f32 *)(leader + 0xc);
    src.pos[1] = *(f32 *)(leader + 0x10);
    src.pos[2] = *(f32 *)(leader + 0x14);
    src.scale = lbl_803E7188;
    src.rot[0] = *(s16 *)(leader + 0);
    src.rot[1] = *(s16 *)(leader + 2);
    src.rot[2] = *(s16 *)(leader + 4);
    out[0] = lbl_803E7190 * mathSinf(lbl_803E7194 * (f32)((ArwSquadronState *)p2)->unk146 / lbl_803E7198) +
             lbl_803E718C * (f32)(s8)*(u8 *)(wstate + 0x26);
    out[1] = lbl_803E7190 * mathSinf(lbl_803E7194 * (f32)((ArwSquadronState *)p2)->unk148 / lbl_803E7198) +
             lbl_803E718C * (f32)(s8)*(u8 *)(wstate + 0x27);
    out[2] = lbl_803E718C * (f32)(s8)*(u8 *)(wstate + 0x1e);
    setMatrixFromObjectTransposed(&src, mtx);
    PSMTXMultVec(mtx, out, (void *)(p1 + 0xc));
    *(f32 *)(p1 + 0x24) = *(f32 *)(leader + 0x24);
    *(f32 *)(p1 + 0x28) = *(f32 *)(leader + 0x28);
    *(f32 *)(p1 + 0x2c) = *(f32 *)(leader + 0x2c);
    *(s16 *)(p1 + 0) = *(s16 *)(leader + 0);
    *(s16 *)(p1 + 2) = *(s16 *)(leader + 2);
    if (!((SquadCmdFlags *)(p2 + 0x160))->f08) {
        *(s16 *)(p1 + 4) =
            ((ArwSquadronState *)leaderState)->unk138 *
                mathSinf(lbl_803E7194 * (f32)((ArwSquadronState *)p2)->unk146 / lbl_803E7198) +
            (f32)*(s16 *)(leader + 4);
    }
    ((SquadCmdFlags *)(p2 + 0x160))->f80 = ((SquadCmdFlags *)(leaderState + 0x160))->f80;
    if (((ArwSquadronState *)p2)->unk144 > 0)
        ((SquadCmdFlags *)(p2 + 0x160))->f08 = ((SquadCmdFlags *)(leaderState + 0x160))->f08;
    if (((ArwSquadronState *)leaderState)->unk159 == 4) {
        *(s16 *)(p1 + 6) |= 0x4000;
        ObjHits_DisableObject(p1);
        ((ArwSquadronState *)p2)->unk159 = 4;
        ((ArwSquadronState *)p2)->unk159 = 4;
    }
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void arwsquadron_update(int obj)
{
    int state = *(int *)&((GameObject *)obj)->extra;
    int setup = *(int *)&((GameObject *)obj)->anim.placementData;
    SquadCmdFlags *flags = (SquadCmdFlags *)(state + 0x160);
    u8 s = ((ArwSquadronState *)state)->unk159;

    if (s == 4 || s == 3)
        return;

    if (((ArwSquadronState *)state)->unk15D == 1) {
        int aim = getArwing();
        f32 d;
        int inRange;
        if (aim == 0)
            aim = Obj_GetPlayerObject();
        d = ((GameObject *)obj)->anim.localPosZ - *(f32 *)(aim + 0x14);
        inRange = (d < lbl_803E71B8 && d > lbl_803E7164);
        if (inRange) {
            if (randomGetRange(0, 1) != 0)
                gameTextFn_80125ba4(0x10);
            else
                gameTextFn_80125ba4(0xd);
            ((ArwSquadronState *)state)->unk15D = 0;
        }
    }

    switch (((ArwSquadronState *)state)->unk159) {
    case 0: {
        int setupL = *(int *)&((GameObject *)obj)->anim.placementData;
        int leader = obj;
        int enable;
        getArwing();
        if (*(int *)(setupL + 0x20) > 0) {
            if (((ArwSquadronState *)state)->leaderObj == 0)
                ((ArwSquadronState *)state)->leaderObj = ObjList_FindObjectById(*(int *)(setupL + 0x20));
            leader = ((ArwSquadronState *)state)->leaderObj;
        }
        if (leader == 0) {
            enable = 0;
        } else {
            f32 thr = ((ArwSquadronState *)state)->unk130;
            int aim = getArwing();
            f32 d;
            int inRange;
            if (aim == 0)
                aim = Obj_GetPlayerObject();
            d = *(f32 *)(leader + 0x14) - *(f32 *)(aim + 0x14);
            inRange = (d < thr && d > lbl_803E7164);
            if (!inRange) {
                enable = 0;
            } else if (*(s16 *)(setupL + 0x32) > 0) {
                enable = GameBit_Get(*(s16 *)(setupL + 0x32)) != 0;
            } else {
                f32 thr2 = ((ArwSquadronState *)state)->unk134;
                int aim2 = getArwing();
                f32 d2;
                int inRange2;
                if (aim2 == 0)
                    aim2 = Obj_GetPlayerObject();
                d2 = *(f32 *)(leader + 0x14) - *(f32 *)(aim2 + 0x14);
                inRange2 = (d2 < thr2 && d2 > lbl_803E7164);
                if (!inRange2)
                    enable = GameBit_Get(*(s16 *)(setupL + 0x32)) != 0;
                else
                    enable = 1;
            }
        }
        if (enable) {
            ((GameObject *)obj)->anim.flags &= ~0x4000;
            ObjHits_EnableObject(obj);
            ((ArwSquadronState *)state)->unk159 = 1;
            setupL = *(int *)&((GameObject *)obj)->anim.placementData;
            if (((ArwSquadronState *)state)->unk15C == 1) {
                flags->f20 = 0;
                storeZeroToFloatParam((void *)(state + 0x124));
                s16toFloat((void *)(state + 0x124), *(u8 *)(setupL + 0x2c));
            }
        }
        return;
    }
    case 1: {
        int setupL = *(int *)&((GameObject *)obj)->anim.placementData;
        int leader = obj;
        int disable;
        *(u8 *)(obj + 0x36) = 0xff;
        getArwing();
        if (((ArwSquadronState *)state)->leaderObj != 0)
            leader = ((ArwSquadronState *)state)->leaderObj;
        if (leader == 0) {
            disable = 0;
        } else {
            f32 thr = ((ArwSquadronState *)state)->unk130;
            int aim = getArwing();
            f32 d;
            int inRange;
            if (aim == 0)
                aim = Obj_GetPlayerObject();
            d = *(f32 *)(leader + 0x14) - *(f32 *)(aim + 0x14);
            inRange = (d < thr && d > lbl_803E7164);
            if (inRange) {
                disable = 0;
            } else if (*(s16 *)(setupL + 0x32) > 0) {
                disable = GameBit_Get(*(s16 *)(setupL + 0x32)) != 0;
            } else {
                f32 thr2 = ((ArwSquadronState *)state)->unk134;
                int aim2 = getArwing();
                f32 d2;
                int inRange2;
                if (aim2 == 0)
                    aim2 = Obj_GetPlayerObject();
                d2 = *(f32 *)(leader + 0x14) - *(f32 *)(aim2 + 0x14);
                inRange2 = (d2 < thr2 && d2 > lbl_803E7164);
                if (!inRange2)
                    disable = GameBit_Get(*(s16 *)(setupL + 0x32)) != 0;
                else
                    disable = 1;
            }
        }
        if (disable) {
            ((GameObject *)obj)->anim.flags |= 0x4000;
            ObjHits_DisableObject(obj);
            ((ArwSquadronState *)state)->unk159 = 4;
            return;
        }
        if (((ArwSquadronState *)state)->unk15C != 2) {
            if (*(u8 *)(setup + 0x2f) != 2) {
                ((GameObject *)obj)->anim.rotX =
                    (f32)((ArwSquadronState *)state)->unk140 * timeDelta + (f32)((GameObject *)obj)->anim.rotX;
                ((GameObject *)obj)->anim.rotY =
                    (f32)((ArwSquadronState *)state)->unk142 * timeDelta + (f32)((GameObject *)obj)->anim.rotY;
            }
            if (flags->f08 || *(u8 *)(setup + 0x2f) != 2) {
                ((GameObject *)obj)->anim.rotZ =
                    (f32)((ArwSquadronState *)state)->unk144 * timeDelta + (f32)((GameObject *)obj)->anim.rotZ;
            }
        }
        if (((ArwSquadronState *)state)->leaderObj != 0) {
            arwsquadron_followLeader(obj, state);
        } else if (flags->f40) {
            arwsquadron_followPath(obj, state);
        }
        if (flags->f80) {
            setupL = *(int *)&((GameObject *)obj)->anim.placementData;
            ObjHits_SetHitVolumeSlot(obj, 0x13, ((ArwSquadronState *)state)->unk156, 0);
            if (((ArwSquadronState *)state)->unk15C == 1)
                arwsquadron_updateVolley(obj, state, setupL);
        }
        break;
    }
    case 3:
    case 4:
        return;
    default:
        break;
    }

    arwsquadron_handleDamage(obj, state);
    if (((ArwSquadronState *)state)->unk15C == 1)
        arwsquadron_emitEffects(obj, state);
    if (((ObjAnimComponent *)obj)->modelInstance->flags == 0)
        ((int (*)(int, f32, f32, void *))ObjAnim_AdvanceCurrentMove)(obj, lbl_803E71BC, timeDelta, 0);
}
#pragma scheduling reset
#pragma peephole reset
