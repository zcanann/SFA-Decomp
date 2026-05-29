#include "ghidra_import.h"
#include "main/dll/DB/DBbonedust.h"
#include "main/objanim.h"
#include "main/unknown/autos/placeholder_80295318.h"
#include "main/dll/player_80295318_shared.h"

#pragma scheduling off
#pragma peephole off
int lightfoot_getExtraSize(void)
{
    return 0x440;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
int lightfoot_getObjectTypeId(void)
{
    return 0x14b;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void lightfoot_hitDetect(void)
{
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void lightfoot_release(void)
{
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void lightfoot_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0) {
        if (*(int *)(p1 + 0xf4) == 0) {
            objRenderFn_8003b8f4(lbl_803E8188);
        }
    }
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void lightfoot_initialise(void)
{
    lbl_803DB0DC[0] = (int)fn_802B8108;
    lbl_803DB0DC[1] = (int)fn_802B7D28;
    lbl_803DB0DC[2] = (int)fn_802B7BF0;
    lbl_803DB0DC[3] = (int)fn_802B7B0C;
    lbl_803DB0DC[4] = (int)fn_802B78A4;
    lbl_803DB0D0[0] = (int)Lightfoot_UpdateChallengeGateInteraction;
    lbl_803DB0D0[1] = (int)fn_802B735C;
    lbl_803DB0D0[2] = (int)fn_802B7298;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void lightfoot_free(int obj, int p2)
{
    int i;
    int count;
    int inner = *(int *)((char *)obj + 0xb8);
    ObjGroup_RemoveObject(obj, 3);
    count = *(u8 *)((char *)obj + 0xeb);
    for (i = 0; i < count; i++) {
        void *child = *(void **)((char *)obj + 0xc8);
        if (child != NULL) {
            ObjLink_DetachChild(obj, child);
            if (p2 == 0) {
                Obj_FreeObject((int)child);
            }
        }
    }
    (*(void (*)(int, int, int))(*(int *)(*gBaddieControlInterface + 0x40)))(obj, inner, 0x20);
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void lightfoot_update(int obj)
{
    int inner = *(int *)((char *)obj + 0xb8);
    int p30 = *(int *)((char *)obj + 0x4c);
    int anim = *(int *)((char *)inner + 0x40c);
    f32 snd[3];
    f32 buf[6];
    u8 i;

    if (*(f32 *)((char *)anim + 0x10) != lbl_803E8180) {
        *(f32 *)((char *)anim + 0x10) -= timeDelta;
        if (*(f32 *)((char *)anim + 0x10) <= lbl_803E8180) {
            Obj_FreeObject(obj);
        }
    }

    if (*(s16 *)((char *)obj + 0x46) == 0x27c && *(s16 *)((char *)inner + 0x3f2) != -1) {
        switch (*(int *)((char *)p30 + 0x14)) {
        case 0x4993F:
        case 0x49940:
        case 0x49941:
            if (GameBit_Get(0xc44)) {
                *(int *)((char *)obj + 0xf4) = GameBit_Get(*(s16 *)((char *)inner + 0x3f2));
            } else {
                *(int *)((char *)obj + 0xf4) = 1;
            }
            break;
        case 0x499AC:
        case 0x499AE:
        case 0x499AF:
            if (GameBit_Get(0xc42) && GameBit_Get(*(s16 *)((char *)inner + 0x3f2)) == 0) {
                void *other = ObjList_FindObjectById(0x499B5);
                if (other != NULL &&
                    Vec_distance((char *)obj + 0x18, (char *)other + 0x18) < lbl_803E8214) {
                    GameBit_Set(*(s16 *)((char *)inner + 0x3f2), 1);
                    buf[3] = lbl_803E8180;
                    buf[4] = lbl_803E8218;
                    buf[5] = lbl_803E8180;
                    for (i = 0x14; i != 0; i--) {
                        objFn_800972dc(obj, 5, lbl_803E81D0, 5, 6, 0x64, lbl_803E8218, buf, 0);
                    }
                    if (GameBit_Get(0xc3b) && GameBit_Get(0xc3c) && GameBit_Get(0xc3d)) {
                        Sfx_PlayFromObject(0, 0x7e);
                    } else {
                        Sfx_PlayFromObject(0, 0x409);
                    }
                }
                *(int *)((char *)obj + 0xf4) = GameBit_Get(*(s16 *)((char *)inner + 0x3f2));
            } else {
                *(int *)((char *)obj + 0xf4) = 1;
            }
            break;
        case 0x499B0:
        case 0x499B1:
        case 0x499B2:
            if (GameBit_Get(0xc46) && GameBit_Get(*(s16 *)((char *)inner + 0x3f2)) == 0) {
                void *other = ObjList_FindObjectById(0x499B6);
                if (other != NULL &&
                    Vec_distance((char *)obj + 0x18, (char *)other + 0x18) < lbl_803E8214) {
                    GameBit_Set(*(s16 *)((char *)inner + 0x3f2), 1);
                    buf[3] = lbl_803E8180;
                    buf[4] = lbl_803E8218;
                    buf[5] = lbl_803E8180;
                    for (i = 0x14; i != 0; i--) {
                        objFn_800972dc(obj, 5, lbl_803E81D0, 5, 6, 0x64, lbl_803E8218, buf, 0);
                    }
                    if (GameBit_Get(0xc3e) && GameBit_Get(0xc3f) && GameBit_Get(0xc40)) {
                        Sfx_PlayFromObject(0, 0x7e);
                    } else {
                        Sfx_PlayFromObject(0, 0x409);
                    }
                }
                *(int *)((char *)obj + 0xf4) = GameBit_Get(*(s16 *)((char *)inner + 0x3f2));
            } else {
                *(int *)((char *)obj + 0xf4) = 1;
            }
            break;
        default:
            *(int *)((char *)obj + 0xf4) = GameBit_Get(*(s16 *)((char *)inner + 0x3f2)) == 0;
            break;
        }

        if (*(int *)((char *)obj + 0xf4) != 0) {
            ObjHits_DisableObject(obj);
            *(s16 *)((char *)obj + 0x6) |= 0x4000;
        } else {
            ObjHits_EnableObject(obj);
            *(s16 *)((char *)obj + 0x6) &= ~0x4000;
        }
    }

    if (*(int *)((char *)obj + 0xf4) != 0) {
        if ((*(int *)((char *)p30 + 0x14) == 0x499B5 && GameBit_Get(0xc42) &&
             (GameBit_Get(0xc3b) == 0 || GameBit_Get(0xc3c) == 0 || GameBit_Get(0xc3d) == 0)) ||
            (*(int *)((char *)p30 + 0x14) == 0x499B6 && GameBit_Get(0xc46) &&
             (GameBit_Get(0xc3e) == 0 || GameBit_Get(0xc3f) == 0 || GameBit_Get(0xc40) == 0))) {
            buf[3] = lbl_803E8180;
            buf[4] = lbl_803E821C;
            buf[5] = lbl_803E8180;
            objParticleFn_80097734(obj, 5, lbl_803E8220, 1, 6, 0x32, lbl_803E8214, lbl_803E8214,
                                   lbl_803E8224, buf, 0);
        }
    } else {
        fn_802B85E4(obj, inner);
        if (*(u16 *)((char *)inner + 0x400) & 0x2) {
            Lightfoot_RecordCompletedChallengeTargetHit(obj, inner, anim);
            fn_802B84D0(obj);
            *(int *)((char *)obj + 0xf8) = 0;
            *(u16 *)((char *)inner + 0x400) &= ~0x4;
        }
        fn_802B86B8(obj, inner, inner);
        if ((*(u8 *)((char *)inner + 0x404) & 1) && (*(u16 *)((char *)obj + 0xb0) & 0x800)) {
            int a40c = *(int *)((char *)inner + 0x40c);
            int mode;
            *(f32 *)((char *)a40c + 0xc) -= timeDelta;
            if (*(f32 *)((char *)a40c + 0xc) <= lbl_803E8180) {
                mode = 3;
                *(f32 *)((char *)a40c + 0xc) += lbl_803E81C0;
            } else {
                mode = 0;
            }
            snd[0] = lbl_803E8180;
            snd[1] = lbl_803E81C4;
            snd[2] = lbl_803E8180;
            Sfx_KeepAliveLoopedObjectSound(obj, 0x455);
            fn_80098B18(lbl_803E81C8 * *(f32 *)((char *)obj + 0x8), obj, 3, mode, 0, snd);
        }
        *(f32 *)((char *)anim + 0x14) -= timeDelta;
    }
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void lightfoot_init(int obj, int p2, int p3)
{
    int inner = *(int *)((char *)obj + 0xb8);
    int sub;
    int flags = 0x16;

    if (p3 != 0) {
        flags = (u8)(flags | 1);
    }
    (*(void (*)(int, int, int, int, int, int, int, f32))(*(int *)(*gBaddieControlInterface + 0x58)))(
        obj, p2, inner, 5, 3, 0x108, flags, lbl_803E8228);
    *(int *)((char *)obj + 0xbc) = (int)fn_802B8864;
    *(s16 *)((char *)inner + 0x274) = 0;
    *(s16 *)((char *)inner + 0x270) = 0;
    *(u16 *)((char *)obj + 0xb0) = (u16)(*(u16 *)((char *)obj + 0xb0) | 0x2000);
    sub = *(int *)((char *)inner + 0x40c);
    *(s16 *)((char *)sub + 0x26) = -1;
    *(s16 *)((char *)sub + 0x28) = *(s16 *)((char *)sub + 0x26);
    *(u16 *)((char *)obj + 0xb0) =
        (u16)(*(u16 *)((char *)obj + 0xb0) | (*(s8 *)((char *)p2 + 0x28) & 0x7));
    if (*(s16 *)((char *)p2 + 0x1a) == 0x64c) {
        *(s16 *)((char *)inner + 0x274) = 2;
        *(s16 *)((char *)inner + 0x270) = 1;
        ObjHits_DisableObject(obj);
        *(s16 *)((char *)sub + 0x24) = (u16)randomGetRange(0, 3);
        *(s16 *)((char *)sub + 0x28) = 0x6f1;
        *(int *)((char *)sub + 0) = (int)&lbl_803DC6F0;
        *(int *)((char *)sub + 4) = (int)&lbl_803DC6F4;
        *(u8 *)((char *)obj + 0xaf) = (u8)(*(u8 *)((char *)obj + 0xaf) | 8);
        *(int *)((char *)obj + 0xf8) = 0;
    } else {
        switch (*(int *)((char *)p2 + 0x14)) {
        case 0x34316:
            *(int *)((char *)sub + 0) = (int)&lbl_803DC714;
            *(int *)((char *)sub + 4) = (int)&lbl_803DC718;
            ObjHits_DisableObject(obj);
            *(u8 *)((char *)obj + 0xaf) = (u8)(*(u8 *)((char *)obj + 0xaf) | 8);
            *(f32 *)((char *)obj + 0x98) = (f32)(s32)randomGetRange(0, 0x63) / lbl_803E817C;
            break;
        case 0x33e3c:
            *(int *)((char *)sub + 0) = (int)&lbl_803DC6F0;
            *(int *)((char *)sub + 4) = (int)&lbl_803DC6F4;
            *(s16 *)((char *)sub + 0x28) = 0x6f1;
            *(u8 *)((char *)obj + 0xaf) = (u8)(*(u8 *)((char *)obj + 0xaf) | 8);
            *(f32 *)((char *)obj + 0x98) = (f32)(s32)randomGetRange(0, 0x63) / lbl_803E817C;
            break;
        case 0x33e34:
            *(int *)((char *)sub + 0) = (int)&lbl_803DC6FC;
            *(int *)((char *)sub + 4) = (int)&lbl_803DC700;
            *(s16 *)((char *)sub + 0x28) = 0x6f1;
            *(u8 *)((char *)obj + 0xaf) = (u8)(*(u8 *)((char *)obj + 0xaf) | 8);
            *(f32 *)((char *)obj + 0x98) = (f32)(s32)randomGetRange(0, 0x63) / lbl_803E817C;
            break;
        case 0x45c47:
            *(int *)((char *)sub + 0) = (int)&lbl_803DC708;
            *(int *)((char *)sub + 4) = (int)&lbl_803DC70C;
            ObjHits_DisableObject(obj);
            *(s16 *)((char *)sub + 0x28) = 0x6f2;
            *(u8 *)((char *)obj + 0xaf) = (u8)(*(u8 *)((char *)obj + 0xaf) | 8);
            *(f32 *)((char *)obj + 0x98) = (f32)(s32)randomGetRange(0, 0x63) / lbl_803E817C;
            break;
        case 0x460b6:
            *(int *)((char *)sub + 0) = (int)&lbl_803DC720;
            *(int *)((char *)sub + 4) = (int)&lbl_803DC724;
            ObjHits_DisableObject(obj);
            *(u8 *)((char *)obj + 0xaf) = (u8)(*(u8 *)((char *)obj + 0xaf) | 8);
            *(f32 *)((char *)obj + 0x98) = (f32)(s32)randomGetRange(0, 0x63) / lbl_803E817C;
            break;
        case 0x3433f:
            *(int *)((char *)sub + 0) = (int)((char *)lbl_80334EE8 + 0x30);
            *(int *)((char *)sub + 4) = (int)((char *)lbl_80334EE8 + 0x40);
            *(u8 *)((char *)obj + 0xaf) = (u8)(*(u8 *)((char *)obj + 0xaf) | 8);
            *(f32 *)((char *)obj + 0x98) = (f32)(s32)randomGetRange(0, 0x63) / lbl_803E817C;
            break;
        case 0x46a51:
            if (GameBit_Get(0xc52)) {
                *(u8 *)((char *)obj + 0xaf) = (u8)(*(u8 *)((char *)obj + 0xaf) | 8);
            }
            *(int *)((char *)sub + 0) = (int)lbl_80334EE8;
            *(int *)((char *)sub + 4) = (int)((char *)lbl_80334EE8 + 0x10);
            break;
        case 0x46a55:
            if (GameBit_Get(0xc53)) {
                *(u8 *)((char *)obj + 0xaf) = (u8)(*(u8 *)((char *)obj + 0xaf) | 8);
            }
            *(int *)((char *)sub + 0) = (int)lbl_80334EE8;
            *(int *)((char *)sub + 4) = (int)((char *)lbl_80334EE8 + 0x10);
            break;
        case 0x49928:
            if (GameBit_Get(0xc54)) {
                *(u8 *)((char *)obj + 0xaf) = (u8)(*(u8 *)((char *)obj + 0xaf) | 8);
            }
            *(int *)((char *)sub + 0) = (int)lbl_80334EE8;
            *(int *)((char *)sub + 4) = (int)((char *)lbl_80334EE8 + 0x10);
            break;
        case 0x499ac:
        case 0x499ae:
        case 0x499af:
        case 0x499b0:
        case 0x499b1:
        case 0x499b2:
            *(s16 *)((char *)inner + 0x270) = 2;
            *(int *)((char *)sub + 0) = (int)((char *)lbl_80334EE8 + 0x30);
            *(int *)((char *)sub + 4) = (int)((char *)lbl_80334EE8 + 0x40);
            *(f32 *)((char *)sub + 0x14) = (f32)(s32)randomGetRange(0x78, 0xb4);
            *(f32 *)((char *)obj + 0x98) = (f32)(s32)randomGetRange(0, 0x63) / lbl_803E817C;
            break;
        case 0x499b5:
        case 0x499b6:
            *(int *)((char *)obj + 0xf4) = 1;
            *(int *)((char *)sub + 0) = (int)((char *)lbl_80334EE8 + 0x30);
            *(int *)((char *)sub + 4) = (int)((char *)lbl_80334EE8 + 0x40);
            break;
        default:
            *(int *)((char *)sub + 0) = (int)lbl_80334EE8;
            *(int *)((char *)sub + 4) = (int)((char *)lbl_80334EE8 + 0x10);
            break;
        }
    }
    fn_802B84D0(obj);
    ObjAnim_SetMoveProgress((f32)(s32)randomGetRange(0, 0x63) / lbl_803E817C,
                            (ObjAnimComponent *)obj);
    if (randomGetRange(0, 1) != 0) {
        *(s16 *)((char *)sub + 0x2a) = 0x133;
    } else {
        *(s16 *)((char *)sub + 0x2a) = 0x134;
    }
    *(f32 *)((char *)sub + 0xc) = lbl_803E81C0;
    if (*(int *)((char *)obj + 0xf4) != 0) {
        ObjHits_DisableObject(obj);
    }
}
#pragma peephole reset
#pragma scheduling reset

