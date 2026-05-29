#include "main/dll/dll_80220608_shared.h"

#pragma peephole on
#pragma scheduling on
int tree_getExtraSize(void) { return 0x5c; }
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void tree_spawnAmbientEffect(int obj, int p2, s8 index)
{
    int setup = *(int *)(obj + 0x4c);
    int idx;
    int newObj;

    if (Obj_IsLoadingLocked()) {
        newObj = Obj_AllocObjectSetup(0x28, 0x210);
        *(u8 *)(newObj + 0x4) = *(u8 *)(setup + 0x4);
        *(u8 *)(newObj + 0x6) = *(u8 *)(setup + 0x6);
        *(u8 *)(newObj + 0x5) = *(u8 *)(setup + 0x5);
        *(u8 *)(newObj + 0x7) = *(u8 *)(setup + 0x7) - 0xa;
        idx = index;
        *(f32 *)(newObj + 0x8) = *(f32 *)(p2 + idx * 0xc + 0xc);
        *(f32 *)(newObj + 0xc) = *(f32 *)(p2 + idx * 0xc + 0x10);
        *(f32 *)(newObj + 0x10) = *(f32 *)(p2 + idx * 0xc + 0x14);
        *(u16 *)(newObj + 0x1c) = randomGetRange(0x708, 0x1770);
        *(s16 *)(newObj + 0x1e) = 0;
        *(u8 *)(newObj + 0x20) = 0xa;
        *(u8 *)(newObj + 0x21) = 0x28;
        *(u8 *)(newObj + 0x22) = 0x32;
        *(u8 *)(newObj + 0x23) = 0xa;
        *(u8 *)(newObj + 0x24) = 0x28;
        *(s8 *)(newObj + 0x25) = -0x28;
        *(s16 *)(newObj + 0x26) = -1;
        *(int *)(newObj + 0x18) = 0;
        *(int *)(p2 + idx * 4) =
            Obj_SetupObject(newObj, 5, *(s8 *)(obj + 0xac), -1, *(int *)(obj + 0x30));
    }
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void tree_updateAmbientEffects(int obj, int p2)
{
    int i;
    int handlePtr;
    int posPtr;

    if (*(int *)(obj + 0xf8) != 0) {
        handlePtr = p2;
        posPtr = p2;
        for (i = 0; i < 3; i++) {
            if (*(int *)handlePtr == 0) {
                *(f32 *)(handlePtr + 0x30) -= timeDelta;
                if (*(f32 *)(handlePtr + 0x30) <= lbl_803E72F8) {
                    *(f32 *)(handlePtr + 0x30) = (f32)randomGetRange(0x3c, 0x12c);
                    tree_spawnAmbientEffect(obj, p2, i);
                }
            } else {
                if ((*(int (**)(int))(*(int *)(*(int *)handlePtr + 0x68) + 0x28))(
                        *(int *)handlePtr) > 3) {
                    *(int *)handlePtr = 0;
                } else {
                    (*(void (**)(int, int))(*(int *)(*(int *)handlePtr + 0x68) + 0x24))(
                        *(int *)handlePtr, posPtr + 0xc);
                }
            }
            handlePtr += 4;
            posPtr += 0xc;
        }
    }
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void tree_render(int obj, int p2, int p3, int p4, int p5, s8 visible)
{
    int setup = *(int *)(obj + 0x4c);
    int state = *(int *)(obj + 0xb8);
    int i;

    if (visible != 0) {
        fn_8003B608(*(u8 *)(setup + 0x20), *(u8 *)(setup + 0x21), *(u8 *)(setup + 0x22));
        objRenderFn_8003b8f4(obj, p2, p3, p4, p5, lbl_803E7308);
        if (*(u16 *)(state + 0x58) & 0x80) {
            for (i = 0; i < 3; i++) {
                ObjPath_GetPointWorldPosition(obj, i, (f32 *)(state + 0xc),
                    (f32 *)(state + 0x10), (f32 *)(state + 0x14), 0);
                state += 0xc;
            }
        }
        *(int *)(obj + 0xf8) = 1;
    }
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void tree_init(int obj, u8 *setup)
{
    int state = *(int *)(obj + 0xb8);
    ObjAnimEventList animOut;

    *(f32 *)(state + 0x44) = lbl_803E730C;
    *(f32 *)(state + 0x40) = lbl_803E72F8;
    *(u16 *)(state + 0x54) = setup[0x1d] << 1;
    *(u16 *)(state + 0x58) = setup[0x1e];
    *(u16 *)(state + 0x58) = *(u16 *)(state + 0x58) << 8;
    *(u16 *)(state + 0x58) |= setup[0x1c];
    *(f32 *)(state + 0x3c) = lbl_803E72F8;
    *(s16 *)(obj + 4) = (s16)(setup[0x18] << 8);
    *(s16 *)(obj + 2) = (s16)(setup[0x19] << 8);
    *(s16 *)(obj + 0) = (s16)(setup[0x1a] << 8);
    *(u8 *)(obj + 0xaf) |= 0x8;
    *(u16 *)(obj + 0xb0) |= 0x2000;
    *(int *)(obj + 0xf8) = 0;
    if (setup[0x1b] != 0) {
        *(f32 *)(state + 0x48) = (f32)(u32)setup[0x1b] / lbl_803E7328;
        *(f32 *)(obj + 8) = *(f32 *)(state + 0x48);
        if (*(f32 *)(obj + 8) == lbl_803E72F8) {
            *(f32 *)(obj + 8) = lbl_803E7308;
        }
        *(f32 *)(obj + 8) = *(f32 *)(obj + 8) * *(f32 *)(*(int *)(obj + 0x50) + 4);
    } else {
        *(f32 *)(state + 0x48) = lbl_803E7308;
    }
    ObjAnim_SetCurrentMove(obj, 0, lbl_803E72F8, 0);
    ObjAnim_AdvanceCurrentMove(lbl_803E7308, lbl_803E7308, obj, &animOut);
    if (*(u16 *)(state + 0x58) & 0x80) {
        *(u16 *)(state + 0x58) |= 0x20;
    }
    switch (*(s16 *)(obj + 0x46)) {
    case 0x798:
        *(u16 *)(state + 0x5a) = 0xa;
        break;
    case 0x799:
        *(u16 *)(state + 0x5a) = 0x9;
        break;
    case 0x70d:
        *(u16 *)(state + 0x5a) = 0x8;
        break;
    case 0x70c:
        *(u16 *)(state + 0x5a) = 0x7;
        ObjHitbox_SetCapsuleBounds(obj, (int)(lbl_803E732C * *(f32 *)(obj + 8)), -0x5, 0x64);
        break;
    case 0x625:
        *(u16 *)(state + 0x5a) = 0x6;
        break;
    case 0x77a:
        *(u16 *)(state + 0x5a) = 0x5;
        break;
    case 0x624:
        *(u16 *)(state + 0x5a) = 0x4;
        break;
    case 0x39:
        *(u16 *)(state + 0x5a) = 0x3;
        break;
    case 0x10b:
        *(u16 *)(state + 0x5a) = 0x2;
        break;
    case 0x5d1:
        *(u16 *)(state + 0x5a) = 0x1;
        break;
    default:
        *(u16 *)(state + 0x5a) = 0x0;
        break;
    }
    if (!(*(u16 *)(state + 0x58) & 0x20)) {
        ObjHits_DisableObject(obj);
    }
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void tree_update(int obj)
{
    int state = *(int *)(obj + 0xb8);
    int hit;
    int player;
    int i;
    int hp;
    f32 dx, dz, dist;
    f32 out8, outc, out10;
    f32 vec14[3];
    f32 colorVec[3];
    f32 intensity;
    f32 *ctbl;
    ObjAnimEventList animOut;

    ObjAnim_AdvanceCurrentMove(*(f32 *)(state + 0x44), timeDelta, obj, &animOut);
    if (*(u16 *)(state + 0x58) != 0) {
        if (*(f32 *)(state + 0x3c) > lbl_803E72F8) {
            *(f32 *)(state + 0x3c) -= timeDelta;
        }
        if (*(f32 *)(state + 0x44) > lbl_803E730C) {
            *(f32 *)(state + 0x44) -= lbl_803E7310;
        }
        if (*(u16 *)(state + 0x58) & 0x80) {
            tree_updateAmbientEffects(obj, state);
        }
        if (*(u16 *)(state + 0x58) & 0x20) {
            if (*(u16 *)(state + 0x58) & 0xc0) {
                hit = ObjHits_GetPriorityHitWithPosition(obj, &out10, &outc, &out8,
                                                         &colorVec[0], &colorVec[1], &colorVec[2]);
            } else {
                hit = ObjHits_PollPriorityHitEffectWithCooldown(obj, 8, 0xff, 0xff, 0x78, 0x129,
                                                                state + 0x50);
            }
            if (*(f32 *)(state + 0x4c) >= lbl_803E72F8) {
                *(f32 *)(state + 0x4c) -= timeDelta;
            }
            if (hit != 0 && hit != 0x11 && *(f32 *)(state + 0x4c) <= lbl_803E72F8) {
                if (*(u16 *)(state + 0x58) & 0xc0) {
                    colorVec[0] += playerMapOffsetX;
                    colorVec[2] += playerMapOffsetZ;
                    objLightFn_8009a1dc(obj, lbl_803E7314, vec14, 1, 0);
                    Obj_SetModelColorFadeRecursive(obj, 0xf, 0xc8, 0, 0, 1);
                }
                if (*(u16 *)(state + 0x58) & 0xf) {
                    intensity = *(f32 *)(state + 0x48);
                    ctbl = &lbl_8032BBE0[*(u16 *)(state + 0x5a) * 4];
                    colorVec[0] = intensity * ctbl[0];
                    colorVec[1] = intensity * ctbl[1];
                    colorVec[2] = intensity * ctbl[2];
                    mathFn_80021ac8(obj, colorVec);
                    fn_80096C94(obj, *(u16 *)(state + 0x58) & 0xf, 0x14, vec14,
                                *(f32 *)(state + 0x48) * ctbl[3], 0);
                }
                *(f32 *)(state + 0x44) = lbl_803E7318;
                *(f32 *)(state + 0x4c) = lbl_803E731C;
                if (*(u16 *)(state + 0x58) & 0x80) {
                    if (hit != 0) {
                        hp = state;
                        for (i = 0; i < 3; i++) {
                            if (*(int *)hp != 0) {
                                if ((*(int (**)(int))(*(int *)(*(int *)hp + 0x68) + 0x28))(
                                        *(int *)hp) > 1) {
                                    ObjHits_RecordObjectHit(*(int *)(state + i * 4), obj, 0xe, 1, 0);
                                    break;
                                }
                            }
                            hp += 4;
                        }
                    }
                }
            }
        }
        player = Obj_GetPlayerObject();
        if (player != 0 && !(*(u16 *)(state + 0x58) & 0x100) && (*(u16 *)(state + 0x58) & 0xf)) {
            dx = *(f32 *)(obj + 0xc) - *(f32 *)(player + 0xc);
            dz = *(f32 *)(obj + 0x14) - *(f32 *)(player + 0x14);
            dist = sqrtf(dx * dx + dz * dz);
            hit = (int)dist;
            if ((u16)hit < *(u16 *)(state + 0x54)) {
                if ((*(u16 *)(state + 0x58) & 0x10) &&
                    *(u16 *)(state + 0x56) >= *(u16 *)(state + 0x54) &&
                    *(f32 *)(state + 0x3c) <= lbl_803E72F8) {
                    intensity = *(f32 *)(state + 0x48);
                    ctbl = &lbl_8032BBE0[*(u16 *)(state + 0x5a) * 4];
                    colorVec[0] = intensity * ctbl[0];
                    colorVec[1] = intensity * ctbl[1];
                    colorVec[2] = intensity * ctbl[2];
                    mathFn_80021ac8(obj, colorVec);
                    fn_80096C94(obj, *(u16 *)(state + 0x58) & 0xf, 0x14, vec14,
                                *(f32 *)(state + 0x48) * ctbl[3], 1);
                    *(f32 *)(state + 0x3c) = lbl_803E7320;
                }
                *(f32 *)(state + 0x40) -= timeDelta;
                if (*(f32 *)(state + 0x40) <= lbl_803E72F8) {
                    intensity = *(f32 *)(state + 0x48);
                    ctbl = &lbl_8032BBE0[*(u16 *)(state + 0x5a) * 4];
                    colorVec[0] = intensity * ctbl[0];
                    colorVec[1] = intensity * ctbl[1];
                    colorVec[2] = intensity * ctbl[2];
                    mathFn_80021ac8(obj, colorVec);
                    fn_80096C94(obj, *(u16 *)(state + 0x58) & 0xf, 1, vec14,
                                *(f32 *)(state + 0x48) * ctbl[3], 0);
                    *(f32 *)(state + 0x40) += lbl_803E7324;
                }
            }
            *(u16 *)(state + 0x56) = hit;
        }
    }
}
#pragma scheduling reset
#pragma peephole reset
