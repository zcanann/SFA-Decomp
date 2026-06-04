#include "main/dll/WM/wm_shared.h"

int wmwallcrawler_getExtraSize(void) { return 0x29c; }

int wmwallcrawler_getObjectTypeId(void) { return 0x0; }

void wmwallcrawler_release(void) {}

void wmwallcrawler_initialise(void) {}


extern int getTrickyObject(void);
extern void ObjAnim_SetCurrentMove(int obj, int n, f32 v, int m);
extern int ObjAnim_AdvanceCurrentMove(int obj, f32 v, f32 t, int n);
extern void objRemoveFromListFn_8002ce88(int obj);
extern void Sfx_StopObjectChannel(int obj, int channel);
extern int fn_80080150(void *timer);
extern int randFn_80080100(int max);
extern void Vec3_Normalize(f32 *v);
extern f32 sqrtf(f32 x);
extern int hitDetectFn_80065e50(int obj, f32 x, f32 y, f32 z, f32 ***out, int a, int b);
extern int *gPathControlInterface;
extern f32 lbl_803DC130;
extern u8 lbl_803DDCB8;
extern f32 lbl_803E5FB0;
extern f32 lbl_803E5FB4;
extern f32 lbl_803E5FBC;
extern f32 lbl_803E5FC0;
extern f32 lbl_803E5FC4;
extern f32 lbl_803E5FC8;
extern f32 lbl_803E5FCC;
extern f32 lbl_803E5FD0;
extern f32 lbl_803E5FD4;
extern f32 lbl_803E5FD8;
extern f32 lbl_803E5FDC;
extern f32 lbl_803E5FE0;
extern f32 lbl_803E5FE4;
extern f32 lbl_803E5FE8;
extern f32 lbl_803E5FEC;
extern f32 lbl_803E5FF0;
extern f32 lbl_803E5FF4;
extern f32 lbl_803E5FF8;
extern f32 lbl_803E5FFC;
extern f32 lbl_803E6000;
extern f32 lbl_803E6004;
extern f32 lbl_803E6008;
extern f32 lbl_803E600C;
extern f32 lbl_803E6010;
extern f32 lbl_803E6014;
extern f32 lbl_803E6018;
extern void fn_801F8008(int a, f32 *b);

#pragma scheduling off
#pragma peephole off
void wmwallcrawler_update(s16 *obj)
{
    u8 *st;
    int bestIdx;
    f32 speed;
    u8 sum;
    u32 player;
    int k;
    int n;
    int idx;
    u32 tricky;
    s16 ang;
    f32 dist;
    f32 sq;
    f32 **walk;
    s8 mode;
    f32 **list;
    f32 **list2;
    f32 best;

    st = *(u8 **)((u8 *)obj + 0xb8);
    bestIdx = 0;
    speed = lbl_803E5FB4;
    sum = 0;
    list = 0;
    best = lbl_803E5FBC;
    if ((*(u16 *)(st + 0x294) & 0x10) == 0) {
        player = (u32)Obj_GetPlayerObject();
    } else {
        player = ObjGroup_FindNearestObject(10, (int)obj, &best);
    }
    if (player != 0) {
        sq = (f32)GameBit_Get(0x789);
        lbl_803DC130 = lbl_803E5FC0 * sq + lbl_803E5FC0;
        if (*(s8 *)(st + 0x296) == 6) {
            *((u8 *)obj + 0xaf) |= 8;
            if (obj[0x50] != 1) {
                ObjAnim_SetCurrentMove((int)obj, 1, lbl_803E5FB0, 0);
                Sfx_PlayFromObject((int)obj, 0x73);
            }
            if (lbl_803E5FC4 < *(f32 *)(obj + 0x4c)) {
                *(f32 *)(obj + 4) = *(f32 *)(obj + 4) * lbl_803E5FC8;
            }
            if (ObjAnim_AdvanceCurrentMove((int)obj, lbl_803E5FCC, (f32)framesThisStep, 0) != 0) {
                if (*(s16 *)(st + 0x292) != 0 && *(s16 *)(st + 0x292) != -1) {
                    GameBit_Set(*(s16 *)(st + 0x292), GameBit_Get(*(s16 *)(st + 0x292)) + 1);
                }
                if (*(void **)(*(int *)((u8 *)obj + 0x4c) + 0x14) == 0) {
                    ObjHits_DisableObject((int)obj);
                    Obj_FreeObject((int)obj);
                } else {
                    objRemoveFromListFn_8002ce88((int)obj);
                    ObjHits_DisableObject((int)obj);
                    ObjGroup_RemoveObject((int)obj, 3);
                    obj[3] |= 0x4000;
                }
            }
        } else {
            if ((*(u16 *)(st + 0x294) & 8) != 0) {
                if (timerCountDown(st + 0x28a) != 0) {
                    for (k = 0; k < 0x1e; k++) {
                        (**(void (**)(int, int, int, int, int, int))(*gPartfxInterface + 8))((int)obj, 0x1a3, 0, 0, -1, 0);
                    }
                    s16toFloat(st + 0x28c, 100);
                    return;
                }
                if (timerCountDown(st + 0x28c) != 0) {
                    *((u8 *)obj + 0xaf) |= 8;
                    if (*(void **)(*(int *)((u8 *)obj + 0x4c) + 0x14) == 0) {
                        ObjHits_DisableObject((int)obj);
                        Obj_FreeObject((int)obj);
                    } else {
                        objRemoveFromListFn_8002ce88((int)obj);
                        ObjHits_DisableObject((int)obj);
                        ObjGroup_RemoveObject((int)obj, 3);
                        obj[3] |= 0x4000;
                    }
                    return;
                }
            }
            for (k = 0; k < 6; k++) {
                sum += GameBit_Get(k + 0x2aa);
            }
            if (sum < 6) {
                if (fn_80080150(st + 0x288) != 0) {
                    timerCountDown(st + 0x288);
                } else {
                    mode = *(s8 *)(st + 0x296);
                    if ((mode == 3 || mode == 1 || mode == 5) && (*(u16 *)(st + 0x294) & 0x80) == 0) {
                        if (mode == 5) {
                            if (lbl_803E5FD0 > lbl_803E5FD4 + *(f32 *)(st + 0x26c)) {
                                *(u8 *)(st + 0x296) = 3;
                                *(s16 *)(st + 0x288) = 0x14;
                            }
                        } else if (*(f32 *)(st + 0x26c) > lbl_803E5FD0) {
                            *(u16 *)(st + 0x290) -= framesThisStep;
                            if (randFn_80080100(0x32) != 0) {
                                Sfx_PlayFromObject((int)obj, 0x74);
                            }
                            if (*(s16 *)(st + 0x290) < 1) {
                                if ((*(u16 *)(st + 0x294) & 0x100) == 0) {
                                    if (*(void **)(*(int *)((u8 *)obj + 0x4c) + 0x14) == 0) {
                                        ObjHits_DisableObject((int)obj);
                                        Obj_FreeObject((int)obj);
                                    } else {
                                        objRemoveFromListFn_8002ce88((int)obj);
                                        ObjHits_DisableObject((int)obj);
                                        ObjGroup_RemoveObject((int)obj, 3);
                                        obj[3] |= 0x4000;
                                    }
                                } else {
                                    *(u8 *)(st + 0x296) = 6;
                                }
                                return;
                            }
                            if (*(s8 *)(st + 0x296) != 5) {
                                Sfx_StopObjectChannel((int)obj, 0x10);
                                *(u8 *)(st + 0x296) = 5;
                                dist = lbl_803E5FD8;
                                *(f32 *)(obj + 0x12) = -*(f32 *)(obj + 0x12) * dist;
                                *(f32 *)(obj + 0x16) = -*(f32 *)(obj + 0x16) * dist;
                            }
                        }
                    }
                    if ((*(u16 *)(st + 0x294) & 0x200) != 0 && *(s8 *)(st + 0x296) != 5 &&
                        (tricky = getTrickyObject()) != 0 &&
                        Vec_distance(obj + 0xc, (void *)(tricky + 0x18)) < lbl_803E5FD4 &&
                        (**(u8 (**)(int))(*(int *)(*(int *)(tricky + 0x68)) + 0x44))(tricky) != 0) {
                        *(u8 *)(st + 0x296) = 5;
                        Sfx_PlayFromObject((int)obj, 0x74);
                    }
                    if (*(s8 *)(st + 0x296) == 5) {
                        if ((*(u16 *)(st + 0x294) & 2) != 0) {
                            (**(void (**)(s16 *, u8 *, f32))(*gPathControlInterface + 0x10))(obj, st, timeDelta);
                            (**(void (**)(s16 *, u8 *))(*gPathControlInterface + 0x14))(obj, st);
                            (**(void (**)(s16 *, u8 *, f32))(*gPathControlInterface + 0x18))(obj, st, timeDelta);
                        }
                        sq = *(f32 *)(obj + 0x12) * *(f32 *)(obj + 0x12) + *(f32 *)(obj + 0x16) * *(f32 *)(obj + 0x16);
                        if (lbl_803E5FB0 != sq) {
                            speed = sqrtf(sq);
                        }
                        *(f32 *)(st + 0x284) = lbl_803E5FDC * speed;
                        ObjAnim_AdvanceCurrentMove((int)obj, *(f32 *)(st + 0x284), (f32)framesThisStep, 0);
                        *(f32 *)(obj + 6) = *(f32 *)(obj + 0x12) * timeDelta + *(f32 *)(obj + 6);
                        *(f32 *)(obj + 10) = *(f32 *)(obj + 0x16) * timeDelta + *(f32 *)(obj + 10);
                        *(u16 *)(st + 0x290) -= framesThisStep;
                        if ((*(u16 *)(st + 0x294) & 4) != 0) {
                            best = lbl_803E5FBC;
                            n = hitDetectFn_80065e50((int)obj, *(f32 *)(obj + 6), *(f32 *)(obj + 8), *(f32 *)(obj + 10), &list, 0, 0);
                            idx = 0;
                            walk = list;
                            if (n > 0) {
                                do {
                                    dist = **walk - *(f32 *)(obj + 8);
                                    if (dist < lbl_803E5FB0) {
                                        dist = dist * lbl_803E5FE0;
                                    }
                                    if (dist < best) {
                                        bestIdx = idx;
                                        best = dist;
                                    }
                                    walk++;
                                    idx++;
                                    n--;
                                } while (n != 0);
                            }
                            if (list == 0) {
                                *(f32 *)(obj + 8) = *(f32 *)(st + 0x274);
                            } else {
                                *(f32 *)(obj + 8) = *list[bestIdx];
                                fn_801F8008((int)obj, list[bestIdx]);
                            }
                        } else {
                            *(f32 *)(obj + 8) = *(f32 *)(st + 0x274);
                        }
                        if ((*(u16 *)(st + 0x294) & 0x80) == 0 && *(s16 *)(st + 0x290) < 1) {
                            if ((*(u16 *)(st + 0x294) & 0x100) != 0) {
                                *(u8 *)(st + 0x296) = 6;
                            } else {
                                *(u8 *)(st + 0x296) = 0;
                                Sfx_StopObjectChannel((int)obj, 0x18);
                                *(f32 *)(obj + 6) = *(f32 *)(st + 0x270);
                                *(f32 *)(obj + 8) = *(f32 *)(st + 0x274) + (f32)*(s16 *)(st + 0x28e);
                                *(f32 *)(obj + 10) = *(f32 *)(st + 0x278);
                            }
                        } else if ((*(u16 *)(st + 0x294) & 0x200) != 0 && randomGetRange(0, 0x14) == 0) {
                            *(u8 *)(st + 0x296) = 3;
                            s16toFloat(st + 0x288, (s16)(randomGetRange(0, 0x14) + 0x32));
                        }
                    } else {
                        dist = Vec_xzDistance((f32 *)(player + 0x18), (f32 *)(obj + 0xc));
                        if (dist < *(f32 *)(st + 0x268) || GameBit_Get(0x1d9) != 0) {
                            mode = *(s8 *)(st + 0x296);
                            if (mode == 0) {
                                *(u8 *)(st + 0x296) = 1;
                                s16toFloat(st + 0x288, 2);
                                obj[2] = 0;
                            } else if (mode == 1) {
                                if (*(f32 *)(obj + 0x14) > lbl_803E5FE4) {
                                    *(f32 *)(obj + 0x14) = lbl_803E5FE8 * timeDelta + *(f32 *)(obj + 0x14);
                                }
                                if (*(f32 *)(obj + 8) < *(f32 *)(st + 0x274)) {
                                    *(f32 *)(obj + 8) = *(f32 *)(st + 0x274);
                                    *(f32 *)(obj + 0x14) = lbl_803E5FB0;
                                    *(u8 *)(st + 0x296) = 3;
                                    s16toFloat(st + 0x288, (s16)(randomGetRange(0, 0x14) + 0x32));
                                    *(f32 *)(st + 0x268) = *(f32 *)(st + 0x268) * lbl_803E5FEC;
                                    ObjAnim_SetCurrentMove((int)obj, 0, lbl_803E5FB0, 0);
                                }
                            } else if (mode == 3) {
                                Sfx_PlayFromObject((int)obj, 0x47);
                                if ((*(u16 *)(st + 0x294) & 2) != 0) {
                                    (**(void (**)(s16 *, u8 *, f32))(*gPathControlInterface + 0x10))(obj, st, timeDelta);
                                    (**(void (**)(s16 *, u8 *))(*gPathControlInterface + 0x14))(obj, st);
                                    (**(void (**)(s16 *, u8 *, f32))(*gPathControlInterface + 0x18))(obj, st, timeDelta);
                                }
                                if ((*(u16 *)(st + 0x294) & 4) != 0) {
                                    best = lbl_803E5FBC;
                                    n = hitDetectFn_80065e50((int)obj, *(f32 *)(obj + 6), *(f32 *)(obj + 8), *(f32 *)(obj + 10), &list, 0, 0);
                                    idx = 0;
                                    walk = list;
                                    if (n > 0) {
                                        do {
                                            dist = **walk - *(f32 *)(obj + 8);
                                            if (dist < lbl_803E5FB0) {
                                                dist = dist * lbl_803E5FE0;
                                            }
                                            if (dist < best) {
                                                bestIdx = idx;
                                                best = dist;
                                            }
                                            walk++;
                                            idx++;
                                            n--;
                                        } while (n != 0);
                                    }
                                    if (list == 0) {
                                        *(f32 *)(obj + 8) = *(f32 *)(st + 0x274);
                                    } else {
                                        *(f32 *)(obj + 8) = *list[bestIdx];
                                        fn_801F8008((int)obj, list[bestIdx]);
                                    }
                                } else {
                                    *(f32 *)(obj + 8) = *(f32 *)(st + 0x274);
                                }
                                *(f32 *)(obj + 0x12) = ((*(f32 *)(player + 0xc) - *(f32 *)(obj + 6)) / lbl_803E5FF0) * timeDelta;
                                *(f32 *)(obj + 0x14) = ((*(f32 *)(player + 0x10) - *(f32 *)(obj + 8)) / lbl_803E5FF0) * timeDelta;
                                *(f32 *)(obj + 0x16) = ((*(f32 *)(player + 0x14) - *(f32 *)(obj + 10)) / lbl_803E5FF0) * timeDelta;
                                if ((*(u16 *)(st + 0x294) & 0x20) != 0 &&
                                    sqrtf(*(f32 *)(obj + 0x16) * *(f32 *)(obj + 0x16) +
                                          *(f32 *)(obj + 0x12) * *(f32 *)(obj + 0x12) +
                                          *(f32 *)(obj + 0x14) * *(f32 *)(obj + 0x14)) > lbl_803DC130) {
                                    Vec3_Normalize((f32 *)(obj + 0x12));
                                    *(f32 *)(obj + 0x12) = *(f32 *)(obj + 0x12) * timeDelta * lbl_803DC130;
                                    *(f32 *)(obj + 0x14) = *(f32 *)(obj + 0x14) * timeDelta * lbl_803DC130;
                                    *(f32 *)(obj + 0x16) = *(f32 *)(obj + 0x16) * timeDelta * lbl_803DC130;
                                }
                                if (obj[0x50] == 0 && (*(u16 *)(st + 0x294) & 0x400) != 0 && dist < lbl_803E5FF4) {
                                    ObjAnim_SetCurrentMove((int)obj, 2, lbl_803E5FB0, 0);
                                }
                                if (dist < lbl_803E5FF8 ||
                                    ((*(u16 *)(st + 0x294) & 0x10) != 0 &&
                                     (*(u16 *)(*(int *)((u8 *)obj + 0x54) + 0x60) & 8) != 0 &&
                                     dist < lbl_803E5FFC)) {
                                    lbl_803DDCB8 += 1;
                                    if (obj[0x50] == 2 && *(f32 *)(obj + 0x4c) > lbl_803E6000 && *(f32 *)(obj + 0x4c) < lbl_803E6004) {
                                        ObjMsg_SendToObject(player, 0x60004, (int)obj, 1);
                                        lbl_803DDCB8 = 0;
                                    }
                                    if (GameBit_Get(0x1d9) != 0) {
                                        lbl_803DDCB8 = 0;
                                    } else if (lbl_803DDCB8 >= 3 || ((*(u16 *)(st + 0x294) & 0x10) != 0 && lbl_803DDCB8 >= 3)) {
                                            Sfx_PlayFromObject((int)obj, 0x75);
                                            if ((*(u16 *)(st + 0x294) & 0x10) == 0) {
                                                ObjMsg_SendToObject(player, 0x60004, (int)obj, 1);
                                            } else {
                                                *(u8 *)(st + 0x299) = (*(u8 *)(st + 0x299) & 0x7f) | 0x80;
                                            }
                                            lbl_803DDCB8 = 0;
                                    }
                                    if ((*(u16 *)(st + 0x294) & 0x10) == 0) {
                                        *(f32 *)(obj + 6) = lbl_803E6008 * -*(f32 *)(obj + 0x12) + *(f32 *)(obj + 6);
                                        *(f32 *)(obj + 10) = lbl_803E6008 * -*(f32 *)(obj + 0x16) + *(f32 *)(obj + 10);
                                    } else {
                                        *(f32 *)(obj + 6) = lbl_803E600C * -*(f32 *)(obj + 0x12) + *(f32 *)(obj + 6);
                                        *(f32 *)(obj + 10) = lbl_803E600C * -*(f32 *)(obj + 0x16) + *(f32 *)(obj + 10);
                                    }
                                    s16toFloat(st + 0x288, (s16)(randomGetRange(0, 0x14) + 100));
                                }
                                ang = getAngle(*(f32 *)(player + 0xc) - *(f32 *)(obj + 6), *(f32 *)(player + 0x14) - *(f32 *)(obj + 10));
                                obj[0] = ang + 0x7fff;
                                sq = *(f32 *)(obj + 0x12) * *(f32 *)(obj + 0x12) + *(f32 *)(obj + 0x16) * *(f32 *)(obj + 0x16);
                                if (lbl_803E5FB0 != sq) {
                                    speed = sqrtf(sq);
                                }
                                switch (obj[0x50]) {
                                case 0:
                                    *(f32 *)(st + 0x284) = lbl_803E6010 * speed;
                                    break;
                                case 2:
                                    *(f32 *)(st + 0x284) = lbl_803E6014;
                                    break;
                                case 1:
                                    *(f32 *)(st + 0x284) = lbl_803E5FCC;
                                    break;
                                }
                                if (ObjAnim_AdvanceCurrentMove((int)obj, *(f32 *)(st + 0x284), (f32)framesThisStep, 0) != 0 && obj[0x50] != 0) {
                                    ObjAnim_SetCurrentMove((int)obj, 0, lbl_803E5FB0, 0);
                                }
                                *(f32 *)(obj + 6) = *(f32 *)(obj + 0x12) * timeDelta + *(f32 *)(obj + 6);
                                *(f32 *)(obj + 10) = *(f32 *)(obj + 0x16) * timeDelta + *(f32 *)(obj + 10);
                            }
                        } else if (*(s8 *)(st + 0x296) == 1) {
                            if (*(f32 *)(obj + 0x14) > lbl_803E5FE0) {
                                *(f32 *)(obj + 0x14) = lbl_803E6018 * timeDelta + *(f32 *)(obj + 0x14);
                            }
                            if (*(f32 *)(obj + 8) < *(f32 *)(st + 0x274)) {
                                *(f32 *)(obj + 8) = *(f32 *)(st + 0x274);
                                *(f32 *)(obj + 0x14) = lbl_803E5FB0;
                                *(u8 *)(st + 0x296) = 3;
                                s16toFloat(st + 0x288, (s16)(randomGetRange(0, 0x14) + 0x32));
                                *(f32 *)(st + 0x268) = *(f32 *)(st + 0x268) * lbl_803E5FEC;
                                ObjAnim_SetCurrentMove((int)obj, 0, lbl_803E5FB0, 0);
                            }
                            *(f32 *)(obj + 8) = *(f32 *)(obj + 0x14) * timeDelta + *(f32 *)(obj + 8);
                        }
                        if (*(s8 *)(st + 0x296) == 0) {
                            *(f32 *)(obj + 8) = *(f32 *)(obj + 0x14) * timeDelta + *(f32 *)(obj + 8);
                        }
                        if (randFn_80080100(0x32) != 0) {
                            Sfx_PlayFromObject((int)obj, 0x76);
                        }
                    }
                }
            } else if (*(void **)(*(int *)((u8 *)obj + 0x4c) + 0x14) == 0) {
                ObjHits_DisableObject((int)obj);
                Obj_FreeObject((int)obj);
            } else {
                objRemoveFromListFn_8002ce88((int)obj);
                ObjHits_DisableObject((int)obj);
                ObjGroup_RemoveObject((int)obj, 3);
                obj[3] |= 0x4000;
            }
        }
    }
}
#pragma peephole reset
#pragma scheduling reset

#pragma peephole off
#pragma scheduling off
int fn_801F7FF4(int obj) {
    *(u8 *)(*(int *)(obj + 0xb8) + 0x296) = 1;
    return 0;
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void wmwallcrawler_free(int obj) {
    ObjGroup_RemoveObject(obj, 3);
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void wmwallcrawler_render(int p1, int p2, int p3, int p4, int p5, s8 vis) {
    int *inner = *(int **)(p1 + 0xb8);
    if ((*(u16 *)((char *)inner + 0x294) & 0x40) != 0 && (u8)*(u8 *)(p1 + 0x36) < 0xff) {
        if (*(u8 *)(p1 + 0x36) > 0xff - framesThisStep) {
            *(u8 *)(p1 + 0x36) = 0xff;
            *(u16 *)((char *)inner + 0x294) &= ~0x40;
        } else {
            *(u8 *)(p1 + 0x36) += framesThisStep;
        }
    }
    if (vis != 0 && *(s16 *)((char *)inner + 0x28c) == 0) {
        objRenderFn_8003b8f4(lbl_803E5FB4);
    }
}
#pragma scheduling reset
#pragma peephole reset

extern void mathFn_80021ac8(void* mtx, f32* vec);
extern f32 lbl_803E5FB0;
typedef struct { s16 r0, r1, r2; f32 m8, mc, m10, m14; } WcXf;

#pragma peephole off
#pragma scheduling off
void fn_801F8008(int a, f32* b)
{
    WcXf mtx;
    f32 in[3];
    u16 ang, ang2;
    in[0] = b[1];
    in[1] = b[2];
    in[2] = b[3];
    mtx.mc = lbl_803E5FB0;
    mtx.m10 = lbl_803E5FB0;
    mtx.m14 = lbl_803E5FB0;
    mtx.m8 = lbl_803E5FB4;
    mtx.r2 = 0;
    mtx.r1 = 0;
    mtx.r0 = *(s16*)a;
    mathFn_80021ac8(&mtx, in);
    ang = getAngle(in[0], in[1]);
    ang2 = getAngle(in[2], in[1]);
    *(s16*)(a + 2) = (s16)ang2;
    *(s16*)(a + 4) = (s16)ang;
}
#pragma scheduling reset
#pragma peephole reset

extern void objRemoveFromListFn_8002ce88(int obj);
extern f32 lbl_803E5FB8;
typedef struct { u8 hit:1; u8 _r299:7; } WcHitBits;

#pragma peephole off
#pragma scheduling off
void wmwallcrawler_hitDetect(int obj)
{
    int inner = *(int*)(obj + 0xb8);
    f32 stk = lbl_803E5FB8;
    if (ObjHits_GetPriorityHit(obj, 0, 0, 0) != 0) {
        if ((*(u16*)(inner + 0x294) & 0x100) != 0) {
            *(u8*)(inner + 0x296) = 6;
        } else if (*(void**)(*(int*)(obj + 0x4c) + 0x14) == NULL) {
            ObjHits_DisableObject(obj);
            Obj_FreeObject(obj);
        } else {
            objRemoveFromListFn_8002ce88(obj);
            ObjHits_DisableObject(obj);
            ObjGroup_RemoveObject(obj, 3);
            *(s16*)(obj + 6) = *(s16*)(obj + 6) | 0x4000;
        }
    } else if (((WcHitBits*)(inner + 0x299))->hit != 0) {
        int target;
        if ((*(u16*)(inner + 0x294) & 0x10) == 0) {
            target = (int)Obj_GetPlayerObject();
        } else {
            target = ObjGroup_FindNearestObject(0xa, obj, &stk);
        }
        ObjHits_RecordObjectHit(target, obj, 0xb, 1, 0);
        *(u8*)(inner + 0x296) = 6;
        ((WcHitBits*)(inner + 0x299))->hit = 0;
    }
}
#pragma scheduling reset
#pragma peephole reset

extern int* gPathControlInterface;
extern u16 lbl_80328DD0[];
extern u8 lbl_80328DE0[];
extern u8 lbl_803DC134;
extern f32 lbl_803E6030;
extern f32 lbl_803E6034;

#pragma peephole off
#pragma scheduling off
void wmwallcrawler_init(int obj, int spawn)
{
    int inner = *(int*)(obj + 0xb8);
    u16 flags;
    ObjGroup_AddObject(obj, 3);
    *(s16*)obj = (s16)((s8)*(u8*)(spawn + 0x18) << 8);
    ObjMsg_AllocQueue(obj, 2);
    *(f32*)(inner + 0x270) = *(f32*)(spawn + 8);
    *(f32*)(inner + 0x274) = *(f32*)(spawn + 0xc);
    *(f32*)(inner + 0x278) = *(f32*)(spawn + 0x10);
    *(f32*)(inner + 0x268) = (f32)(int)*(s16*)(spawn + 0x1a);
    *(u8*)(inner + 0x298) = *(u8*)(spawn + 0x19);
    *(u16*)(inner + 0x294) = lbl_80328DD0[*(u8*)(inner + 0x298)];
    storeZeroToFloatParam((void*)(inner + 0x28a));
    storeZeroToFloatParam((void*)(inner + 0x28c));
    storeZeroToFloatParam((void*)(inner + 0x288));
    flags = *(u16*)(inner + 0x294);
    if ((flags & 1) != 0) {
        *(s16*)(obj + 4) = 0;
        *(u8*)(inner + 0x296) = 1;
    } else if ((flags & 8) != 0) {
        s16toFloat((void*)(inner + 0x28a), 0x4b0);
        *(f32*)(inner + 0x268) = lbl_803E6030;
        *(s16*)(obj + 4) = 0;
        *(u8*)(inner + 0x296) = 1;
    } else {
        s16toFloat((void*)(inner + 0x288), 0x190);
        *(s16*)(obj + 4) = -0x7fff;
        *(u8*)(inner + 0x296) = 0;
    }
    if ((*(u16*)(inner + 0x294) & 0x40) != 0) {
        *(u8*)(obj + 0x36) = 0;
    }
    *(f32*)(inner + 0x284) = lbl_803E5FB0;
    *(s16*)(inner + 0x28e) = *(s16*)(spawn + 0x1c);
    *(f32*)(obj + 0x10) = *(f32*)(spawn + 0xc) + (f32)(int)*(s16*)(inner + 0x28e);
    *(s16*)(inner + 0x290) = (s16)(randomGetRange(0, 0x50) + 0x190);
    *(f32*)(inner + 0x26c) = lbl_803E6034;
    *(s16*)(inner + 0x292) = *(s16*)(spawn + 0x1e);
    if ((*(u16*)(inner + 0x294) & 2) != 0) {
        *(u8*)(inner + 0x25b) = 1;
        (*(void (**)(int, int, int, int))(*(int*)gPathControlInterface + 4))(inner, 0, 0, 1);
        (*(void (**)(int, int, u8*, u8*, int))(*(int*)gPathControlInterface + 8))(inner, 1, lbl_80328DE0, &lbl_803DC134, 4);
        (*(void (**)(int, int))(*(int*)gPathControlInterface + 0x20))(obj, inner);
        *(u32*)inner |= 0x40008;
    }
    *(int*)(obj + 0xbc) = (int)fn_801F7FF4;
    ObjHits_EnableObject(obj);
    ObjHits_SyncObjectPositionIfDirty(obj);
}
#pragma scheduling reset
#pragma peephole reset
