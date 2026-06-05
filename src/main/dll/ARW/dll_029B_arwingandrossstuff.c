#include "main/dll/dll_80220608_shared.h"
#include "main/audio/sfx_ids.h"


#pragma peephole on
#pragma scheduling on
int arwingandrossstuff_getExtraSize(void) { return 0x20; }
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
int arwingandrossstuff_getObjectTypeId(void) { return 0; }
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling off
void arwingandrossstuff_free(int obj)
{
    int state = *(int *)(obj + 0xb8);

    ObjGroup_RemoveObject(obj, 0x2);
    if (*(void **)(state + 0x14) != NULL) {
        ModelLightStruct_free(*(void **)(state + 0x14));
    }
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling on
void arwingandrossstuff_render(int obj, int p2, int p3, int p4, int p5, s8 visible)
{
    if (visible != 0) {
        objRenderFn_8003b8f4(obj, p2, p3, p4, p5, lbl_803E701C);
    }
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
void arwingandrossstuff_release(void) {}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
void arwingandrossstuff_initialise(void) {}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void arwingandrossstuff_hitDetect(int obj)
{
    int state = *(int *)(obj + 0xb8);
    int arwing = getArwing();

    if (*(s16 *)(obj + 0x46) == 0x80d) {
        int hit;
        int vol;

        if (ObjHits_GetPriorityHit(obj, &hit, 0, &vol) != 0) {
            spawnExplosion(obj, lbl_803E7014, 1, 0, 0, 1, 0, 0, 3);
            *(s16 *)(obj + 6) |= 0x4000;
            ObjHits_DisableObject(obj);
            *(f32 *)(state + 0x10) = lbl_803E7028;
        }
    }
    if (*(void **)(*(int *)(obj + 0x54) + 0x50) != NULL && *(u8 *)(state + 1) == 0) {
        if (*(s16 *)(obj + 0x46) != 0x6ae) {
            Sfx_PlayFromObjectLimited(obj, SFXbaddie_invin_hit, 4);
        }
        if (*(s16 *)(obj + 0x46) == 0x7e4) {
            struct {
                f32 x, y, z;
            } v, w;
            f32 ang = lbl_803E7030 *
                      (f32)(s16)(-getAngle(*(f32 *)(obj + 0xc) - *(f32 *)(arwing + 0xc),
                                           *(f32 *)(obj + 0x10) - *(f32 *)(arwing + 0x10))) /
                      lbl_803E7034;

            v.x = lbl_803E702C * fn_80293E80(ang);
            v.y = lbl_803E7038 * sin(ang);
            v.z = lbl_803E7008;
            w = v;
            fn_8022D4AC(arwing, (int)&w);
            doRumble(lbl_803E703C);
        }
        if (*(void **)(*(int *)(obj + 0x54) + 0x50) == (void *)arwing) {
            if (fn_8022D738(arwing) != 0) {
                struct {
                    f32 x, y, z;
                } d;

                PSVECNormalize((void *)(obj + 0x24), (void *)(obj + 0x24));
                d.x = *(f32 *)(obj + 0xc) - *(f32 *)(arwing + 0xc);
                d.y = *(f32 *)(obj + 0x10) - *(f32 *)(arwing + 0x10);
                d.z = *(f32 *)(obj + 0x14) - *(f32 *)(arwing + 0x14);
                PSVECNormalize(&d, &d);
                C_VECHalfAngle((void *)(obj + 0x24), &d, (void *)(obj + 0x24));
                *(f32 *)(obj + 0x24) *= *(f32 *)(state + 8);
                *(f32 *)(obj + 0x28) *= *(f32 *)(state + 8);
                *(f32 *)(obj + 0x2c) *= *(f32 *)(state + 8);
                *(u8 *)(state + 1) = 1;
            }
        }
        *(f32 *)(state + 0x10) = lbl_803E7028;
        *(u8 *)(obj + 0x36) = 0;
        projectileParticleFxFn_80099660(obj, lbl_803E701C, *(u8 *)state);
        if (*(int *)(state + 0x14) != 0) {
            ModelLightStruct_free(*(void **)(state + 0x14));
            *(int *)(state + 0x14) = 0;
        }
    }
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling off
void arwprojectile_setLifetime(int obj, int lifetime)
{
    int state = *(int *)(obj + 0xb8);

    *(f32 *)(state + 4) = (f32)lifetime;
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void arwprojectile_placeForward(int obj, f32 dist)
{
    int state = *(int *)(obj + 0xb8);
    f32 mtx[16];
    ArwProjPosSrc src;

    *(f32 *)(state + 8) = dist;
    src.pos[0] = lbl_803E7008;
    src.pos[1] = lbl_803E7008;
    src.pos[2] = lbl_803E7008;
    src.rot[0] = *(s16 *)obj;
    src.rot[1] = *(s16 *)(obj + 2);
    src.rot[2] = 0;
    src.scale = lbl_803E701C;
    setMatrixFromObjectPos(mtx, &src);
    Matrix_TransformPoint(mtx, lbl_803E7008, lbl_803E7008, *(f32 *)(state + 8),
                          (f32 *)(obj + 0x24), (f32 *)(obj + 0x28), (f32 *)(obj + 0x2c));
    *(s16 *)obj += 0x8000;
    *(s16 *)(obj + 2) = -*(s16 *)(obj + 2);
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling off
void arwingandrossstuff_init(int obj, u8 *setup)
{
    int state = *(int *)(obj + 0xb8);
    int linked;

    *(s16 *)obj = (s16)(setup[0x1a] << 8);
    *(s16 *)(obj + 2) = (s16)(setup[0x19] << 8);
    *(u8 *)(obj + 0x36) = 1;
    switch (*(s16 *)(obj + 0x46)) {
    case 0x80d:
        *(s16 *)(state + 0x1a) = randomGetRange(-0x1f4, 0x1f4);
        *(s16 *)(state + 0x1c) = randomGetRange(-0x1f4, 0x1f4);
        /* fallthrough */
    case 0x6ae:
    case 0x7e4:
        ObjHits_SetTargetMask(obj, 4);
        *(u8 *)state = 4;
        *(u8 *)(state + 0x18) = 2;
        break;
    case 0x655:
        ObjHits_SetTargetMask(obj, 1);
        *(u8 *)state = 0;
        *(u8 *)(state + 0x18) = 1;
        break;
    case 0x604:
        ObjHits_SetTargetMask(obj, 1);
        if (*(s8 *)(obj + 0xad) != 0) {
            *(u8 *)state = 2;
            *(u8 *)(state + 0x18) = 2;
        } else {
            *(u8 *)state = 1;
            *(u8 *)(state + 0x18) = 2;
        }
        break;
    default:
        ObjHits_SetTargetMask(obj, 1);
        *(u8 *)state = 2;
        break;
    }
    linked = *(int *)(obj + 0x54);
    if (linked != 0) {
        *(s16 *)(linked + 0xb2) = 1;
    }
    ObjGroup_AddObject(obj, 2);
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void arwingandrossstuff_update(int obj)
{
    int state = *(int *)(obj + 0xb8);
    int arwing = getArwing();

    if (arwing != 0 && (*(u16 *)(arwing + 0xb0) & 0x1000) != 0) {
        Obj_FreeObject(obj);
        return;
    }
    if (*(f32 *)(state + 0x10) > lbl_803E7008) {
        *(f32 *)(state + 0x10) -= timeDelta;
        if (*(f32 *)(state + 0x10) <= lbl_803E7008) {
            Obj_FreeObject(obj);
        }
        return;
    }
    ObjHits_SetHitVolumeSlot(obj, 0xf, *(u8 *)(state + 0x18), 0);
    *(u8 *)(obj + 0x36) = 0xff;
    if (*(f32 *)(state + 4) > lbl_803E7008) {
        *(f32 *)(state + 4) -= timeDelta;
        if (*(f32 *)(state + 4) <= lbl_803E7008) {
            *(f32 *)(state + 4) = lbl_803E7008;
            Obj_FreeObject(obj);
            return;
        }
        if (*(s8 *)(*(int *)(obj + 0x54) + 0xad) != 0) {
            if (*(s16 *)(obj + 0x46) != 0x6ae) {
                Sfx_PlayFromObjectLimited(obj, SFXbaddie_invin_hit, 4);
            }
            *(f32 *)(state + 0x10) = lbl_803E7028;
            *(u8 *)(obj + 0x36) = 0;
            projectileParticleFxFn_80099660(obj, lbl_803E701C, *(u8 *)state);
            if (*(int *)(state + 0x14) != 0) {
                ModelLightStruct_free(*(void **)(state + 0x14));
                *(int *)(state + 0x14) = 0;
            }
        }
        objMove(obj, *(f32 *)(obj + 0x24) * timeDelta, *(f32 *)(obj + 0x28) * timeDelta,
                *(f32 *)(obj + 0x2c) * timeDelta);
        if (*(s16 *)(obj + 0x46) == 0x80d) {
            *(s16 *)(obj + 4) += *(s16 *)(state + 0x1a);
            *(s16 *)(obj + 2) += *(s16 *)(state + 0x1c);
        }
        if (*(s16 *)(obj + 0x46) == 0x7e4) {
            *(f32 *)(obj + 8) += lbl_803DC3D0;
            ObjHitbox_SetSphereRadius(obj, (int)(*(f32 *)(obj + 8) * lbl_803DC3D8));
            *(s16 *)(obj + 4) = (int)((f32)*(s16 *)(obj + 4) + lbl_803DC3D4);
        }
    }
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void arwprojectile_createLinkedEffect(int obj, u8 enable) {
    int state = *(int *)(obj + 0xb8);
    if (enable == 0)
        return;
    if (*(void **)(state + 0x14) != NULL)
        return;
    *(void **)(state + 0x14) = objCreateLight(obj, 1);
    if (*(void **)(state + 0x14) == NULL)
        return;
    modelLightStruct_setLightKind(*(void **)(state + 0x14), 2);
    modelLightStruct_setPosition(*(void **)(state + 0x14), lbl_803E7008, lbl_803E7008, lbl_803E7008);
    lightSetFieldBC_8001db14(*(void **)(state + 0x14), 1);
    if (*(s16 *)(obj + 0x46) == 0x6ae) {
        modelLightStruct_setDiffuseColor(*(void **)(state + 0x14), 0xff, 0x14, 0x50, 0);
    } else if ((s8) * (u8 *)(obj + 0xad) == 0) {
        modelLightStruct_setDiffuseColor(*(void **)(state + 0x14), 0x3c, 0xff, 0x5a, 0);
    } else {
        modelLightStruct_setDiffuseColor(*(void **)(state + 0x14), 0x3c, 0x5a, 0xff, 0);
    }
    if (*(s16 *)(obj + 0x46) == 0x655) {
        modelLightStruct_setDistanceAttenuation(*(void **)(state + 0x14), lbl_803E700C, lbl_803E7010);
    } else {
        modelLightStruct_setDistanceAttenuation(*(void **)(state + 0x14), lbl_803E7014, lbl_803E7018);
    }
    modelLightStruct_setAffectsAabbLightSelection(*(void **)(state + 0x14), 1);
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling off
void fn_8022ED74(int obj, int v) { *(f32 *)(*(int *)(obj + 0xb8) + 0x0) = (f32)v; }
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
void fn_8022ECE0(int obj, f32 param)
{
    int state = *(int *)(obj + 0xb8);
    f32 mtx[12];
    ArwProjPosSrc src;

    *(f32 *)(state + 4) = param;
    src.pos[0] = lbl_803E7044;
    src.pos[1] = lbl_803E7044;
    src.pos[2] = lbl_803E7044;
    src.rot[0] = *(s16 *)obj;
    src.rot[1] = *(s16 *)(obj + 2);
    src.rot[2] = 0;
    src.scale = lbl_803E704C;
    setMatrixFromObjectPos(mtx, &src);
    Matrix_TransformPoint(mtx, lbl_803E7044, lbl_803E7044, *(f32 *)(state + 4),
                          (f32 *)(obj + 0x24), (f32 *)(obj + 0x28), (f32 *)(obj + 0x2c));
}
#pragma scheduling reset
#pragma peephole reset
