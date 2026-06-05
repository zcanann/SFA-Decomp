#include "main/dll/dll_80220608_shared.h"

#pragma peephole on
#pragma scheduling on
int cmbsrc_getExtraSize(void) { return 0x28; }
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
int cmbsrc_getObjectTypeId(void) { return 0; }
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
void cmbsrc_initialise(void) {}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
void cmbsrc_release(void) {}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling off
int cmbsrc_updateAndReturnZero(int obj)
{
    cmbsrc_update(obj);
    return 0;
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling off
int cmbsrc_getColorIndex(int obj)
{
    int state = *(int *)(obj + 0xb8);
    int setup = *(int *)(obj + 0x4c);

    if (*(u8 *)(setup + 0x1b) == 0xf) {
        int colorIndex = *(u8 *)(state + 0x23);
        return (s8)colorIndex;
    }
    return -1;
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void cmbsrc_setExternalActive(int obj, u8 active)
{
    int state = *(int *)(obj + 0xb8);

    if (active != 0) {
        *(u8 *)(state + 0x22) |= 0x2;
    } else {
        *(u8 *)(state + 0x22) &= ~0x2;
    }
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling off
void cmbsrc_free(int obj)
{
    int state = *(int *)(obj + 0xb8);

    (*(void (**)(int))(*gExpgfxInterface + 0x14))(obj);
    if (*(void **)state != NULL) {
        ModelLightStruct_free(*(void **)state);
    }
    Sfx_StopObjectChannel(obj, 0x40);
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void cmbsrc_render(int obj, int p2, int p3, int p4, int p5, s8 visible)
{
    int state = *(int *)(obj + 0xb8);
    int setup = *(int *)(obj + 0x4c);

    if (visible != 0) {
        *(u8 *)(state + 0x22) |= 0x1;
        if (*(void **)state != NULL && *(u8 *)(*(int *)state + 0x2f8) != 0 &&
            *(u8 *)(*(int *)state + 0x4c) != 0) {
            queueGlowRender(*(void **)state);
        }
        if ((*(u8 *)(setup + 0x29) & 0x8) != 0) {
            objRenderFn_8003b8f4(obj, p2, p3, p4, p5, lbl_803E738C);
        }
    }
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
int cmbsrc_shouldActivate(int obj, int state, int setup)
{
    int result = 0;
    int hitOut;

    if (*(void **)state != NULL && fn_8001DB64(*(void **)state) != 0) {
        return 0;
    }
    if (*(s16 *)(setup + 0x24) != -1 && GameBit_Get(*(s16 *)(setup + 0x24)) != 0) {
        result = 1;
    } else if ((*(u8 *)(state + 0x22) & 0x4) != 0 &&
               (*(int (**)(int *))(*gSHthorntailAnimationInterface + 0x24))(&hitOut) != 0) {
        result = 1;
    }
    if ((*(u8 *)(setup + 0x2a) & 0x30) == 0x10) {
        if (*(f32 *)(state + 0x14) != lbl_803E7360) {
            *(f32 *)(state + 0x14) -= timeDelta;
            if (*(f32 *)(state + 0x14) <= lbl_803E7360) {
                result = 1;
            }
        }
    }
    return result;
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
int cmbsrc_shouldDeactivate(int obj, int state, int setup)
{
    int result = 0;
    int hitOut;

    if (*(void **)state != NULL && fn_8001DB64(*(void **)state) != 2) {
        return 0;
    }
    if (*(s16 *)(setup + 0x24) != -1 && (u32)GameBit_Get(*(s16 *)(setup + 0x24)) == 0) {
        result = 1;
    } else if ((*(u8 *)(state + 0x22) & 0x4) != 0 &&
               (*(int (**)(int *))(*gSHthorntailAnimationInterface + 0x24))(&hitOut) == 0) {
        result = 1;
    } else if (*(s8 *)(state + 0x26) == 0) {
        *(f32 *)(state + 0x14) = (f32)(u32)*(u16 *)(state + 0x20);
        result = 1;
    }
    return result;
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void cmbsrc_hitDetect(int obj)
{
    int setup = *(int *)(obj + 0x4c);
    int state = *(int *)(obj + 0xb8);
    int v;

    *(u8 *)(state + 0x24) = 0;
    if ((*(u8 *)(setup + 0x2a) & 0x30) != 0) {
        *(u8 *)(state + 0x24) = (u8)ObjHits_GetPriorityHit(obj, 0, 0, 0);
        if (*(u8 *)(state + 0x24) == 0x10) {
            *(u8 *)(state + 0x26) -= 1;
            *(f32 *)(state + 0x1c) = lbl_803E7384;
        }
        if (*(f32 *)(state + 0x1c) != lbl_803E7360) {
            *(f32 *)(state + 0x1c) -= timeDelta;
            if (*(f32 *)(state + 0x1c) <= lbl_803E7360) {
                *(u8 *)(state + 0x26) += 1;
                *(f32 *)(state + 0x1c) = lbl_803E7384;
            }
        }
        v = *(s8 *)(state + 0x26);
        if (v < 0) {
            v = 0;
        } else if (v > 0xf) {
            v = 0xf;
        }
        *(s8 *)(state + 0x26) = (s8)v;
    }
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
int cmbsrc_cycleColor(int obj, int state)
{
    int setup = *(int *)(obj + 0x4c);
    int idx;

    *(f32 *)(state + 0x10) -= timeDelta;
    if (*(f32 *)(state + 0x10) <= lbl_803E7360) {
        *(f32 *)(state + 0x10) = lbl_803E7364;
        *(u8 *)(state + 0x23) += 1;
        if (*(u8 *)(state + 0x23) >= 3) {
            *(u8 *)(state + 0x23) = 0;
        }
        idx = lbl_803DC3E0[*(u8 *)(state + 0x23)];
        if (*(void **)state != NULL) {
            int base = idx * 3;
            modelLightStruct_setColorsA8AC(*(void **)state, lbl_8032BD50[base],
                                           lbl_8032BD50[base + 1], lbl_8032BD50[base + 2], 0xff);
            modelLightStruct_setColors100104(*(void **)state, lbl_8032BD50[base],
                                             lbl_8032BD50[base + 1], lbl_8032BD50[base + 2], 0xff);
            lightSetFieldB0(*(void **)state,
                            (int)(lbl_803E7368 * (f32)(u32)lbl_8032BD50[base]),
                            (int)(lbl_803E7368 * (f32)(u32)lbl_8032BD50[base + 1]),
                            (int)(lbl_803E7368 * (f32)(u32)lbl_8032BD50[base + 2]), 0xff);
            if (*(u8 *)(setup + 0x29) & 0x40) {
                if (*(u8 *)(setup + 0x29) & 0x80) {
                    modelLightStruct_setupGlow(*(void **)state, 0, lbl_8032BD50[base], lbl_8032BD50[base + 1],
                                lbl_8032BD50[base + 2], 0x87, lbl_803E736C * *(f32 *)(obj + 8));
                } else {
                    modelLightStruct_setupGlow(*(void **)state, 0, lbl_8032BD50[base], lbl_8032BD50[base + 1],
                                lbl_8032BD50[base + 2], 0x87, lbl_803E7370 * *(f32 *)(obj + 8));
                }
            }
        }
    } else {
        idx = lbl_803DC3E0[*(u8 *)(state + 0x23)];
    }
    return idx;
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void cmbsrc_updateVisuals(int obj, int state)
{
    int setup = *(int *)(obj + 0x4c);
    int colorIdx = 0;
    int effectMode = 0;
    int subMode = 0;
    int viewSlot;
    f32 dist;
    f32 vec[3];
    f32 param[3];

    viewSlot = Camera_GetCurrentViewSlot();
    if (*(u8 *)(state + 0x25) == 0) {
        *(f32 *)(state + 0x18) = lbl_803E7374 * *(f32 *)(setup + 0x20);
    } else {
        *(f32 *)(state + 0x18) += interpolate(
            (f32)*(s8 *)(state + 0x26) / lbl_803E7378 *
                    (lbl_803E7374 * *(f32 *)(setup + 0x20) -
                     *(f32 *)(setup + 0x20) * lbl_803E737C) +
                *(f32 *)(setup + 0x20) * lbl_803E737C - *(f32 *)(state + 0x18),
            lbl_803E7380, timeDelta);
    }
    dist = Vec_distance(viewSlot + 0x44, obj + 0x18);
    if (*(u8 *)(state + 0x25) == 1) {
        if (dist <= (f32)(u32)(*(u8 *)(setup + 0x26) << 3)) {
            if (*(u8 *)(setup + 0x1b) == 0xf) {
                colorIdx = (u8)cmbsrc_cycleColor(obj, state);
            } else {
                colorIdx = *(u8 *)(setup + 0x1b);
            }
        }
    }
    *(f32 *)(state + 0x4) -= timeDelta;
    *(f32 *)(state + 0x8) -= timeDelta;
    if (*(f32 *)(state + 0x4) <= lbl_803E7360) {
        if (*(u8 *)(setup + 0x1c) < 9) {
            if (dist <= (f32)(u32)(*(u8 *)(setup + 0x27) << 3)) {
                effectMode = *(u8 *)(setup + 0x1c);
            }
        }
        if (*(u8 *)(state + 0x25) == 0) {
            if (dist <= (f32)(u32)(*(u8 *)(setup + 0x26) << 3) &&
                (*(u8 *)(state + 0x22) & 0x8) == 0) {
                effectMode = *(u8 *)(setup + 0x1c);
                if (*(u8 *)(setup + 0x1c) == 0) {
                    effectMode = 2;
                }
            } else {
                effectMode = 0;
            }
        }
        if (*(u8 *)(state + 0x25) == 1) {
            *(f32 *)(state + 0x4) += lbl_803E7384;
        } else {
            *(f32 *)(state + 0x4) += lbl_803E7378;
        }
    }
    if ((*(u16 *)(obj + 0xb0) & 0x800) || (*(u8 *)(state + 0x22) & 0x2)) {
        switch (*(s16 *)(obj + 0x46)) {
        case 0x758:
            if (*(u8 *)(state + 0x25) == 1) {
                if (dist <= (f32)(u32)(*(u8 *)(setup + 0x26) << 3)) {
                    subMode = *(u8 *)(setup + 0x1d);
                }
            }
            objfx_spawnLightPulse(obj, *(f32 *)(state + 0x18), colorIdx, effectMode, subMode,
                                  (f32)(u32)*(u8 *)(setup + 0x28) / lbl_803E7388, 0);
            break;
        case 0x6e8:
        default:
            if (*(u8 *)(state + 0x25) == 1) {
                if (*(f32 *)(state + 0x8) <= lbl_803E7360) {
                    if (*(u8 *)(setup + 0x1d) < 4) {
                        if (dist <= (f32)(u32)(*(u8 *)(setup + 0x28) << 3)) {
                            subMode = *(u8 *)(setup + 0x1d);
                        }
                    }
                    *(f32 *)(state + 0x8) += lbl_803E738C;
                }
            }
            vec[0] = lbl_803E7360;
            if (*(s16 *)(obj + 0x46) == 0x853) {
                if (*(u8 *)(state + 0x25) == 0) {
                    vec[1] = lbl_803E7390;
                } else {
                    vec[1] = lbl_803E7394;
                }
            } else {
                if (*(u8 *)(state + 0x25) == 0) {
                    vec[1] = lbl_803E7390;
                } else {
                    vec[1] = lbl_803E7360;
                }
            }
            vec[2] = lbl_803E7360;
            fn_80098B18(obj, *(f32 *)(state + 0x18), colorIdx, effectMode, subMode, vec);
            break;
        }
    }
    if (*(u8 *)(state + 0x25) == 1 && (*(u8 *)(setup + 0x2a) & 0x2)) {
        *(f32 *)(state + 0xc) -= timeDelta;
        if (*(f32 *)(state + 0xc) <= lbl_803E7360) {
            if (*(u16 *)(obj + 0xb0) & 0x800) {
                param[2] = *(f32 *)(state + 0x18);
                (*(void (**)(int, int, void *, int, int, int))(*gPartfxInterface + 0x8))(
                    obj, 0x7cb, param, 2, -1, 0);
            }
            *(f32 *)(state + 0xc) += lbl_803E7398;
        }
    }
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
int cmbsrc_update(int obj)
{
    int state = *(int *)(obj + 0xb8);
    int setup = *(int *)(obj + 0x4c);

    switch (*(u8 *)(state + 0x25)) {
    case 1:
        if (cmbsrc_shouldDeactivate(obj, state, setup)) {
            *(u8 *)(state + 0x25) = 0;
            if (*(void **)state != NULL) {
                lightFn_8001db6c(*(void **)state, 0, lbl_803E7374);
            }
            if (*(u8 *)(setup + 0x29) & 0x2) {
                Sfx_StopObjectChannel(obj, 0x40);
            }
            ObjHits_DisableObject(obj);
            if (*(s16 *)(setup + 0x24) != -1) {
                GameBit_Set(*(s16 *)(setup + 0x24), 0);
            }
        } else {
            if (*(u8 *)(setup + 0x29) & 0x2) {
                Sfx_KeepAliveLoopedObjectSound(obj,
                    lbl_8032BD00[*(u8 *)(*(int *)(obj + 0x4c) + 0x1b)]);
            }
            if (*(void **)state != NULL && *(u8 *)(*(int *)state + 0x2f8) != 0 &&
                *(u8 *)(*(int *)state + 0x4c) != 0) {
                s16 v = (s16)(*(u8 *)(*(int *)state + 0x2f9) + *(s8 *)(*(int *)state + 0x2fa));
                if (v < 0) {
                    v = 0;
                    *(u8 *)(*(int *)state + 0x2fa) = 0;
                } else if (v > 0xc) {
                    v = (s16)(v + randomGetRange(-0xc, 0xc));
                    if (v > 0xff) {
                        v = 0xff;
                        *(u8 *)(*(int *)state + 0x2fa) = 0;
                    }
                }
                *(u8 *)(*(int *)state + 0x2f9) = (u8)v;
            }
        }
        break;
    case 0:
        if (cmbsrc_shouldActivate(obj, state, setup)) {
            *(u8 *)(state + 0x25) = 1;
            if (*(void **)state != NULL) {
                lightFn_8001db6c(*(void **)state, 1, lbl_803E7374);
            }
            if (!((CmbsrcHitFlag *)(state + 0x27))->disabled) {
                ObjHits_EnableObject(obj);
            }
            if (*(s16 *)(setup + 0x24) != -1) {
                GameBit_Set(*(s16 *)(setup + 0x24), 1);
            }
            *(u8 *)(state + 0x26) = 0xf;
            *(f32 *)(state + 0x14) = lbl_803E7360;
        }
        break;
    }
    cmbsrc_updateVisuals(obj, state);
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void cmbsrc_init(int obj, u8 *setup)
{
    int state = *(int *)(obj + 0xb8);
    int lightVariant;

    switch (*(s16 *)(obj + 0x46)) {
    case 0x758:
        lightVariant = 1;
        break;
    case 0x6e8:
    default:
        lightVariant = 0;
        break;
    }
    *(s16 *)(obj + 4) = (s16)(setup[0x18] << 8);
    *(s16 *)(obj + 2) = (s16)(setup[0x19] << 8);
    *(s16 *)(obj + 0) = (s16)(setup[0x1a] << 8);
    *(u8 *)(state + 0x25) = 1;
    *(u8 *)(state + 0x26) = 0xf;
    if (setup[0x2b] == 0) {
        *(u16 *)(state + 0x20) = 0x258;
    } else {
        *(u16 *)(state + 0x20) = setup[0x2b] * 0x3c;
    }
    if (setup[0x29] & 0x1) {
        *(u8 *)(state + 0x22) |= 0x2;
    }
    if (setup[0x2a] & 0x1) {
        *(u8 *)(state + 0x22) |= 0x4;
    }
    if (setup[0x2a] & 0x80) {
        *(u8 *)(state + 0x22) |= 0x8;
    }
    if (setup[0x29] & 0x10) {
        u8 *colorTbl;
        int ci;
        int local;

        if (*(void **)state == NULL) {
            *(void **)state = objCreateLight(obj, 1);
        }
        if (*(void **)state != NULL) {
            modelLightStruct_setField50(*(void **)state, 2);
            if (*(s16 *)(obj + 0x46) == 0x758) {
                lightVecFn_8001dd88(*(void **)state, lbl_803E7360, lbl_803E7360, lbl_803E7360);
            } else {
                lightVecFn_8001dd88(*(void **)state, lbl_803E7360, lbl_803E73A8, lbl_803E7360);
            }
            colorTbl = &lbl_8032BD50[lightVariant * 0x30];
            ci = setup[0x1b] * 3;
            modelLightStruct_setColorsA8AC(*(void **)state, colorTbl[ci], colorTbl[ci + 1],
                                           colorTbl[ci + 2], 0xff);
            modelLightStruct_setColors100104(*(void **)state, colorTbl[ci], colorTbl[ci + 1],
                                             colorTbl[ci + 2], 0xff);
            {
                int n = (int)((setup[0x2a] & 0x8 ? lbl_803E73AC : lbl_803E73B0) *
                              *(f32 *)(obj + 8));
                lightDistAttenFn_8001dc38(*(void **)state, (f32)n, lbl_803E73B4 + (f32)n);
            }
            if (*(u8 *)(state + 0x22) & 0x4) {
                if ((*(int (**)(void *))(*gSHthorntailAnimationInterface + 0x24))(&local) != 0) {
                    lightFn_8001db6c(*(void **)state, 1, lbl_803E7374);
                } else {
                    lightFn_8001db6c(*(void **)state, 0, lbl_803E7374);
                    *(u8 *)(state + 0x25) = 0;
                }
            }
            modelLightStruct_startColorFade(*(void **)state, 1, 3);
            lightSetFieldB0(*(void **)state,
                            (int)(lbl_803E7368 * (f32)(u32)colorTbl[ci]),
                            (int)(lbl_803E7368 * (f32)(u32)colorTbl[ci + 1]),
                            (int)(lbl_803E7368 * (f32)(u32)colorTbl[ci + 2]), 0xff);
            if (setup[0x29] & 0x20) {
                lightSetField2FB(*(void **)state, 1);
            }
            if (setup[0x29] & 0x40) {
                if (setup[0x29] & 0x80) {
                    modelLightStruct_setupGlow(*(void **)state, 0, colorTbl[ci], colorTbl[ci + 1],
                                colorTbl[ci + 2], 0x87, lbl_803E73B8 * *(f32 *)(obj + 8));
                } else {
                    modelLightStruct_setupGlow(*(void **)state, 0, colorTbl[ci], colorTbl[ci + 1],
                                colorTbl[ci + 2], 0x87, lbl_803E7370 * *(f32 *)(obj + 8));
                }
            }
            {
                int m = setup[0x2c] & 0x3;
                if (m == 0) {
                    modelLightStruct_setGlowProjectionRadius(*(void **)state, lbl_803E73BC);
                } else if (m == 1) {
                    modelLightStruct_setGlowProjectionRadius(*(void **)state, lbl_803E7384);
                } else if (m == 2) {
                    modelLightStruct_setGlowProjectionRadius(*(void **)state, lbl_803E73C0);
                } else {
                    modelLightStruct_setGlowProjectionRadius(*(void **)state, lbl_803E7360);
                }
            }
            if (setup[0x2a] & 0x4) {
                lightSetField4D(*(void **)state, 0);
            } else {
                lightSetField4D(*(void **)state, 1);
            }
        }
    }
    if (*(void **)(obj + 0x54) != NULL) {
        ((CmbsrcHitFlag *)(state + 0x27))->disabled = 1;
        ObjHitbox_SetSphereRadius(obj,
            (int)(lbl_803E7374 *
                  (*(f32 *)(setup + 0x20) * (*(f32 *)(obj + 8) * lbl_8032BD10[setup[0x1b]]))));
        if (setup[0x29] & 0x4) {
            ObjHits_SetHitVolumeSlot(obj, 0x1f, 1, 0);
            ((CmbsrcHitFlag *)(state + 0x27))->disabled = 0;
        } else {
            ObjHits_SetHitVolumeSlot(obj, 0, 0, 0);
        }
        if (setup[0x2a] & 0x40) {
            ObjHits_SyncObjectPositionIfDirty(obj);
            ((CmbsrcHitFlag *)(state + 0x27))->disabled = 0;
        } else {
            ObjHits_MarkObjectPositionDirty(obj);
        }
        if (setup[0x2a] & 0x30) {
            ((CmbsrcHitFlag *)(state + 0x27))->disabled = 0;
        }
        if (((CmbsrcHitFlag *)(state + 0x27))->disabled) {
            ObjHits_DisableObject(obj);
        }
    }
    *(f32 *)(state + 0x10) = (f32)randomGetRange(0, 0x64);
    *(f32 *)(state + 0x18) = lbl_803E7374 * *(f32 *)(setup + 0x20);
    *(void **)(obj + 0xbc) = (void *)cmbsrc_updateAndReturnZero;
}
#pragma scheduling reset
#pragma peephole reset
