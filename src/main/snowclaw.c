#include "ghidra_import.h"

#define SFXdn_rexthrash11 20
#define SFXsp_sa_climb02 242
#define SFXswapstone_mumble 740

typedef struct {
    u8 b0 : 1;
    u8 flag6 : 1;
    u8 rest : 6;
} SnowclawAaFlags;

typedef struct {
    s16 v[5];
} SnowClawAnimTbl;

extern void Obj_FreeObject(int obj);
extern u32 GameBit_Get(int id);
extern int Obj_GetPlayerObject(void);
extern u32 fn_802972A8(int obj);
extern int ObjGroup_FindNearestObject(int kind, int obj, f32 *maxDistance);
extern void s16toFloat(void *p, int duration);
extern u8 lbl_8032A310[];
extern f32 lbl_803E66EC;
extern int lbl_803DDD38;
extern void storeZeroToFloatParam(void *p);
extern void objSeqInitFn_80080078(void *table, int n);
extern void objRenderFn_8003b8f4(f32 e);
extern int randomGetRange(int min, int max);
extern int Obj_SetupObject(int obj, int a, int b, int c, int d);
extern u8 Obj_IsLoadingLocked(void);
extern int Obj_AllocObjectSetup(int extraSize, int id);
extern int objUpdateOpacity(int sub);
extern void ObjLink_AttachChild(int obj, int child, int c);
extern void ObjPath_GetPointWorldPosition(int obj, int idx, f32 *x, f32 *y, f32 *z, int e);
extern void objParticleFn_80099d84(int obj, f32 a, int b, f32 c, int d);
extern f32 lbl_803E66F0;
extern f32 lbl_803E6708;
extern f32 lbl_803E670C;
extern f32 lbl_803E6710;
extern int getAngle(f32 dx, f32 dz);
extern void Sfx_PlayFromObject(int obj, int sfxId);
extern void *loadObjectAtObject(int obj, int spawn);
extern f32 lbl_803E66E0;
extern int ObjHits_GetPriorityHit(int *sub, int *hit, int c, int d);
extern void ObjHits_RecordObjectHit(int *sub, int hit, int c, int d, int e);
extern void ObjLink_DetachChild(int obj, int *child);
extern void spawnExplosion(int obj, f32 f, int a, int b, int c, int d, int e, int g, int h);
extern void ObjAnim_SetCurrentMove(int obj, int move, f32 f, int e);
extern int *gObjectTriggerInterface;
extern f32 fn_80293E80(f32 a);
extern f32 sin(f32 a);
extern u32 lbl_8032A350[8];
extern u8 framesThisStep;
extern f32 lbl_803E6720;
extern f32 lbl_803E6724;
extern f32 lbl_803E6728;
extern f32 lbl_803E672C;
extern f32 lbl_803E6730;
extern f32 lbl_803E6734;
extern f32 lbl_803E6738;
extern f32 lbl_803E66F4;
extern void ObjHits_DisableObject(int obj);
extern SnowClawAnimTbl lbl_802C2540;
extern f32 lbl_803DC224;
extern f32 lbl_803E66E4;
extern f32 lbl_803E66E8;
extern f32 lbl_803E66F8;
extern int ObjAnim_AdvanceCurrentMove(f32 moveStepScale, f32 deltaTime, int objAnim, void *events);
extern void Object_ObjAnimSetSecondaryBlendMove(int obj, uint moveId, int eventState);
extern int Obj_GetYawDeltaToObject(int obj, int other, int flags);
extern int randFn_80080100(int range);
extern void ObjHits_EnableObject(int obj);
extern int *ObjGroup_GetObjects(int group, int *countOut);
extern int seqStreamLookupFn_8007fff8(void *table, int count, int key);
extern int timerCountDown(void *timer);
extern int fn_801EC9F4(int obj);
extern int fn_801EC9BC(int obj);
extern void fn_80098B18(int obj, f32 scale, int type, int mode, int arg5, f32 *vec);
extern u32 lbl_802C2520[8];
extern s16 lbl_8032A340[];
extern int lbl_803DC220;
extern f32 lbl_803DC218;
extern f32 lbl_803DC21C;

int snowclaw_getExtraSize(void);
int snowclaw_getObjectTypeId(void);
void snowclaw_release(void);
void snowclaw_initialise(void);
void snowclaw_free(int obj);
void snowclaw_init(int *obj, u8 *init);
void snowclaw_spawnDropBomb(int obj, int a, int b, int c);
void snowclaw_updateMountAttack(int obj, int mount);
void snowclaw_syncMountTransform(int obj, int sub, int p2, int p3, int p4, int p5, int opacity, int a8, int a9);
void snowclaw_render(int obj, int p2, int p3, int p4, int p5, s8 vis);
void snowclaw_hitDetect(int obj);
void snowclaw_update(int obj);
int snowclaw_animEventCallback(int obj, int a2, int evt);

int snowclaw_getExtraSize(void) { return 0xb0; }

int snowclaw_getObjectTypeId(void) { return 0x3; }

void snowclaw_release(void) {}

void snowclaw_initialise(void) {}

#pragma scheduling off
#pragma peephole off
void snowclaw_free(int obj) {
    if (*(void **)(obj + 0xc8) != NULL) {
        Obj_FreeObject(*(int *)(obj + 0xc8));
    }
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void snowclaw_init(int *obj, u8 *init) {
    u8 *table;
    int *inner;
    int *sub;

    table = lbl_8032A310;
    *(void **)((char *)obj + 0xbc) = (void *)snowclaw_animEventCallback;
    sub = *(int **)((char *)obj + 0x64);
    if (sub != NULL) {
        *(int *)((char *)sub + 0x30) |= 0x4000;
        *(u8 *)((char *)*(int **)((char *)obj + 0x64) + 0x3a) = 0x64;
        *(u8 *)((char *)*(int **)((char *)obj + 0x64) + 0x3b) = 0x96;
    }
    inner = *(int **)((char *)obj + 0xb8);
    *(int *)inner = 0;
    *(u8 *)((char *)inner + 0xa2) = init[0x27];
    *(u8 *)((char *)inner + 0xa4) = 4;
    *(s8 *)((char *)inner + 0xa5) = -1;
    switch (*(s16 *)((char *)obj + 0x46)) {
    case 0x16d:
    case 0x170:
    default:
        *(int *)((char *)inner + 4) = (int)(table + 0x58);
        *(s16 *)((char *)inner + 0xa8) = 0x100;
        break;
    case 0x389:
    case 0x38a:
    case 0x4d3:
        *(int *)((char *)inner + 4) = (int)(table + 0x54);
        *(s16 *)((char *)inner + 0xa8) = 0x400;
        /* fall through */
    case 0x3e8:
        *(int *)((char *)inner + 4) = (int)(table + 0x5c);
        *(s16 *)((char *)inner + 0xa8) = 0x400;
        break;
    }
    *(u8 *)((char *)inner + 0xa6) = 0;
    *(int *)((char *)inner + 0x9c) = 0x64;
    *(f32 *)((char *)inner + 0x30) = lbl_803E66EC;
    storeZeroToFloatParam((char *)inner + 0x98);
    s16toFloat((char *)inner + 0x98, (s16)*(int *)(table + 0x3c));
    objSeqInitFn_80080078(table, 6);
    lbl_803DDD38 = 0x96;
    *(u8 *)((char *)inner + 0xaa) &= ~0x80;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void snowclaw_spawnDropBomb(int obj, int a, int b, int c) {
    int player;
    int obj2;
    char *spawned;

    player = Obj_GetPlayerObject();
    if (Obj_IsLoadingLocked() != 0) {
        obj2 = Obj_AllocObjectSetup(0x24, 0x5ff);
        *(s16 *)(obj2 + 0x0) = 0x5ff;
        *(u8 *)(obj2 + 0x4) = 2;
        *(u8 *)(obj2 + 0x6) = 0xff;
        *(u8 *)(obj2 + 0x5) = 1;
        *(u8 *)(obj2 + 0x7) = 0xff;
        *(s8 *)(obj2 + 0x19) = (s8)b;
        *(f32 *)(obj2 + 0x8) = *(f32 *)(obj + 0xc);
        *(f32 *)(obj2 + 0xc) = lbl_803E66E0 + *(f32 *)(obj + 0x10);
        *(f32 *)(obj2 + 0x10) = *(f32 *)(obj + 0x14);
        *(s8 *)(obj2 + 0x18) = (s8)(u8)((((getAngle(*(f32 *)(player + 0xc) - *(f32 *)(obj + 0xc),
                                                   *(f32 *)(player + 0x14) - *(f32 *)(obj + 0x14)) & 0xffff) >> 8) + 0x8000) >> 8);
        Sfx_PlayFromObject(obj, SFXswapstone_mumble);
        switch ((u8)b) {
        case 0:
            *(s16 *)(obj2 + 0x1a) = (s16)lbl_803DDD38;
            break;
        case 1:
            *(s16 *)(obj2 + 0x1a) = (s16)(getAngle(*(f32 *)(player + 0xc) - *(f32 *)(obj + 0xc),
                                                    *(f32 *)(player + 0x14) - *(f32 *)(obj + 0x14)) + 0x8000);
            break;
        }
        spawned = loadObjectAtObject(obj, obj2);
        if (spawned != NULL) {
            *(int *)(spawned + 0xf4) = (u8)c;
            *(int *)(spawned + 0xc4) = a;
        }
    }
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void snowclaw_updateMountAttack(int obj, int mount) {
    char *inner;
    f32 moveStep;
    f32 mountPhase;
    int mountFlag;
    int magnitude;
    int turnSign;
    int delay;

    inner = *(char **)(obj + 0xb8);
    mountPhase = (*(f32 (*)(int, f32 *))(*(int *)(*(int *)(*(int *)(mount + 0x68)) + 0x44)))(mount, &moveStep);
    moveStep = lbl_803DC224 + lbl_803E66E4 * (mountPhase * lbl_803DC224);
    (*(void (*)(int, f32 *, int *))(*(int *)(*(int *)(*(int *)(mount + 0x68)) + 0x40)))(mount, &mountPhase, &mountFlag);
    magnitude = (int)(lbl_803E66E8 * mountPhase);
    if (magnitude < 0) {
        magnitude = -magnitude;
    }

    if (mountFlag != 0 && *(s16 *)(obj + 0xa0) == *(u16 *)(inner + 0xa8)) {
        Object_ObjAnimSetSecondaryBlendMove(obj, *(u16 *)(inner + 0xa8) + 1, magnitude);
    } else {
        Object_ObjAnimSetSecondaryBlendMove(obj, *(u16 *)(inner + 0xa8) + 2, magnitude);
    }

    if (ObjAnim_AdvanceCurrentMove(moveStep, (f32)(u8)framesThisStep, obj, NULL) != 0 &&
        *(s16 *)(obj + 0xa0) != *(u16 *)(inner + 0xa8)) {
        *(f32 *)(inner + 0x30) = lbl_803E66EC;
        delay = *(int *)(inner + 0x9c);
        if (delay < 1) {
            delay = 1;
        } else if (delay > 0x190) {
            delay = 0x190;
        }
        *(int *)(inner + 0x9c) = delay;

        if (randFn_80080100(2) == 0) {
            ObjAnim_SetCurrentMove(obj, *(u16 *)(inner + 0xa8), lbl_803E66F0, 0);
        } else {
            turnSign = (u32)(s16)Obj_GetYawDeltaToObject(obj, Obj_GetPlayerObject(), 0) >> 31;
            if (turnSign == 0) {
                *(f32 *)(inner + 0x30) = lbl_803E66F4;
                Sfx_PlayFromObject(obj, 0x2e3);
            } else {
                *(f32 *)(inner + 0x30) = lbl_803E66F8;
                Sfx_PlayFromObject(obj, 0x2e2);
            }
            ObjAnim_SetCurrentMove(obj, *(u16 *)(inner + 0xa8) + (turnSign != 0 ? 4 : 8),
                                   lbl_803E66F0, 0);
            *(int *)(inner + 0x9c) += 0x64;
        }
    }
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
#pragma dont_inline on
void snowclaw_syncMountTransform(int obj, int sub, int p2, int p3, int p4, int p5, int opacity, int a8, int a9) {
    f32 va, vb, vc;

    if (a9 != 0 && (s8)opacity != 0 && a8 > 0) {
        u8 saved = *(u8 *)(sub + 0x37);
        *(u8 *)(sub + 0x37) = (u8)a8;
        (*(void (*)(int, int, int, int, int, int))(*(int *)(*(int *)(*(int *)(sub + 0x68)) + 0x10)))(sub, p2, p3, p4, p5, -1);
        *(u8 *)(sub + 0x37) = saved;
    }
    *(f32 *)(obj + 0x8c) = *(f32 *)(obj + 0x18);
    *(f32 *)(obj + 0x90) = *(f32 *)(obj + 0x1c);
    *(f32 *)(obj + 0x94) = *(f32 *)(obj + 0x20);
    *(f32 *)(obj + 0x80) = *(f32 *)(obj + 0xc);
    *(f32 *)(obj + 0x84) = *(f32 *)(obj + 0x10);
    *(f32 *)(obj + 0x88) = *(f32 *)(obj + 0x14);
    (*(void (*)(int, f32 *, f32 *, f32 *))(*(int *)(*(int *)(*(int *)(sub + 0x68)) + 0x28)))(sub, &va, &vb, &vc);
    *(f32 *)(obj + 0xc) = va;
    *(f32 *)(obj + 0x10) = vb;
    *(f32 *)(obj + 0x14) = vc;
    *(s16 *)(obj + 0x0) = *(s16 *)(sub + 0x0);
    *(s16 *)(obj + 0x2) = *(s16 *)(sub + 0x2);
    *(s16 *)(obj + 0x4) = *(s16 *)(sub + 0x4);
    *(f32 *)(obj + 0x18) = *(f32 *)(obj + 0xc);
    *(f32 *)(obj + 0x1c) = *(f32 *)(obj + 0x10);
    *(f32 *)(obj + 0x20) = *(f32 *)(obj + 0x14);
    *(f32 *)(obj + 0x24) = *(f32 *)(sub + 0x24);
    *(f32 *)(obj + 0x28) = *(f32 *)(sub + 0x28);
    *(f32 *)(obj + 0x2c) = *(f32 *)(sub + 0x2c);
}
#pragma dont_inline reset
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void snowclaw_render(int obj, int p2, int p3, int p4, int p5, s8 vis) {
    int *inner;
    int sub;
    int found;
    int opacity;
    int oldFlag;
    f32 dist;
    int near;

    dist = lbl_803E6708;
    inner = *(int **)(obj + 0xb8);
    sub = *(int *)inner;
    if (*(u8 *)((char *)obj + 0x36) < 5) {
        *(f32 *)((char *)inner + 0xac) = lbl_803E66F0;
    }
    found = 0;
    opacity = vis;
    if (*(s8 *)((char *)inner + 0xa4) >= 0 && sub != 0) {
        if ((*(int (*)(int))(*(int *)(*(int *)(sub + 0x68) + 0x38)))(sub) == 2) {
            found = 1;
        }
    }
    if (found != 0) {
        *(s16 *)((char *)obj + 6) |= 8;
        opacity = (s8)objUpdateOpacity(sub);
        snowclaw_syncMountTransform(obj, sub, p2, p3, p4, p5, opacity, *(u8 *)((char *)inner + 0xa0), 1);
    } else {
        *(s16 *)((char *)obj + 6) &= ~8;
    }
    if ((s8)opacity != 0 && *(u8 *)((char *)inner + 0xa0) != 0) {
        oldFlag = *(u8 *)((char *)obj + 0x37);
        if (found != 0) {
            *(u8 *)((char *)obj + 0x37) = *(u8 *)((char *)inner + 0xa0);
        }
        if (*(u8 *)((char *)obj + 0xeb) == 0 && *(s16 *)((char *)obj + 0x46) == 0x389 &&
            ((*(u8 *)((char *)inner + 0xaa) >> 7) & 1) != 0) {
            near = ObjGroup_FindNearestObject(0x1e, obj, &dist);
            if (near != 0 &&
                (*(int (*)(int))(*(int *)(*(int *)(near + 0x68) + 0x24)))(near) != 0 &&
                (*(int (*)(int, int))(*(int *)(*(int *)(near + 0x68) + 0x20)))(near, 0) != 0) {
                ObjLink_AttachChild(obj, near, 0);
            }
        }
        ((void (*)(int, int, int, int, int, f32))objRenderFn_8003b8f4)(obj, p2, p3, p4, p5, lbl_803E670C);
        ObjPath_GetPointWorldPosition(obj, 1, (f32 *)((char *)inner + 0x18), (f32 *)((char *)inner + 0x1c), (f32 *)((char *)inner + 0x20), 0);
        *(u8 *)((char *)obj + 0x37) = oldFlag;
        if (((*(u8 *)((char *)inner + 0xaa) >> 6) & 1) != 0) {
            if (*(f32 *)((char *)inner + 0xac) != lbl_803E66F0) {
                *(f32 *)((char *)inner + 0xac) = lbl_803E670C + (f32)(s32)(0xff - *(u8 *)((char *)obj + 0x36)) / lbl_803E6710;
            } else {
                *(u8 *)((char *)inner + 0xaa) &= ~0x40;
            }
            objParticleFn_80099d84(obj, lbl_803E670C, 3, *(f32 *)((char *)inner + 0xac), 0);
        }
    }
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void snowclaw_hitDetect(int obj) {
    int *inner;
    int *sub;
    int *near;
    int *player;
    int hit;
    f32 dist;
    s8 a5;

    inner = *(int **)(obj + 0xb8);
    dist = lbl_803E6720;
    sub = *(int **)inner;
    if (sub == 0) {
        return;
    }
    if (ObjHits_GetPriorityHit(sub, &hit, 0, 0) == 0x15 && *(s8 *)((char *)inner + 0xa4) >= 0) {
        ObjHits_RecordObjectHit(sub, hit, 0x15, 1, 0);
        if (*(s8 *)((char *)inner + 0xa5) < 0) {
            *(s8 *)((char *)inner + 0xa4) -= 1;
            Sfx_PlayFromObject(obj, SFXsp_sa_climb02);
            Sfx_PlayFromObject(obj, SFXdn_rexthrash11);
            Sfx_PlayFromObject(obj, (u16)lbl_8032A350[*(s8 *)((char *)inner + 0xa4)]);
            *(s8 *)((char *)inner + 0xa5) = 0x14;
            *(int *)((char *)inner + 0x9c) -= 0x28;
            if (*(s8 *)((char *)inner + 0xa4) < 0) {
                int *sub2;

                spawnExplosion(obj, lbl_803E6724, 1, 1, 1, 1, 0, 1, 0);
                sub2 = *(int **)inner;
                if (sub2 != 0) {
                    (*(void (*)(int *, int))(*(int *)(*(int *)(*(int *)((char *)sub2 + 0x68)) + 0x3c)))(sub2, 0);
                }
                if (*(s16 *)((char *)obj + 0x46) == 0x389) {
                    near = (int *)ObjGroup_FindNearestObject(0x1e, obj, &dist);
                    if (near != 0) {
                        ObjLink_DetachChild(obj, near);
                        (*(void (*)(int *, int))(*(int *)(*(int *)(*(int *)((char *)near + 0x68)) + 0x20)))(near, 2);
                    }
                }
                if (*(s16 *)((char *)obj + 0x46) == 0x16d || *(s16 *)((char *)obj + 0x46) == 0x170) {
                    (*(void (*)(int, int, int))(*(int *)(*gObjectTriggerInterface + 0x48)))(0, obj, 1);
                } else {
                    (*(void (*)(int, int, int))(*(int *)(*gObjectTriggerInterface + 0x48)))(0, obj, 3);
                }
                ((SnowclawAaFlags *)((char *)inner + 0xaa))->flag6 = 1;
                *(f32 *)((char *)inner + 0xac) = lbl_803E670C;
                *(f32 *)((char *)inner + 0x24) = lbl_803E6728 * fn_80293E80((f32)*(s16 *)((char *)obj + 0) * lbl_803E672C / lbl_803E6730);
                *(f32 *)((char *)inner + 0x28) = lbl_803E6734 * (f32)(int)randomGetRange(0x28, 0x64);
                *(f32 *)((char *)inner + 0x2c) = lbl_803E6728 * sin((f32)*(s16 *)((char *)obj + 0) * lbl_803E672C / lbl_803E6730);
                player = (int *)fn_802972A8(Obj_GetPlayerObject());
                if (player != 0) {
                    int *sub3 = *(int **)((char *)player + 0xb8);
                    if (sub3 != 0) {
                        *(f32 *)((char *)sub3 + 0x4c4) = lbl_803E6738;
                    }
                }
            } else {
                ObjAnim_SetCurrentMove(obj, *(u16 *)((char *)inner + 0xa8) + 9, lbl_803E66F0, 0);
                *(f32 *)((char *)inner + 0x30) = lbl_803E66F4;
            }
        }
    }
    sub = *(int **)inner;
    if (sub != 0 && (*(int (*)(int *))(*(int *)(*(int *)(*(int *)((char *)sub + 0x68)) + 0x38)))(sub) == 2) {
        snowclaw_syncMountTransform(obj, (int)sub, 0, 0, 0, 0, 0, 0, 0);
    }
    a5 = *(s8 *)((char *)inner + 0xa5);
    if (a5 >= 0) {
        *(s8 *)((char *)inner + 0xa5) = a5 - framesThisStep;
    }
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void snowclaw_update(int obj) {
    char *inner;
    int *objects;
    int objectCount;
    int i;
    int targetType;
    int sub;
    int choice;
    int turnSign;
    int pulseIndex;
    u32 pulseTypes[4];
    u32 pulseModes[4];
    f32 pulseVec[3];

    inner = *(char **)(obj + 0xb8);
    if (*(u8 *)(inner + 0xa1) != 0 && ((*(u8 *)(inner + 0xaa) >> 6) & 1) != 0) {
        *(f32 *)(inner + 0xac) = lbl_803E66F0;
    }
    *(u8 *)(inner + 0xa1) = 0;
    *(u8 *)(inner + 0xa0) = 0xff;

    if (*(s8 *)(inner + 0xa4) < 0) {
        if (*(s8 *)(inner + 0xa4) < -10) {
            *(s16 *)(obj + 6) |= 0x4000;
            *(s16 *)(*(int *)inner + 6) |= 0x4000;
            ObjHits_DisableObject(obj);
            ObjHits_DisableObject(*(int *)inner);
        } else {
            *(u8 *)(inner + 0xa4) = *(u8 *)(inner + 0xa4) - 1;
        }
        return;
    }

    ObjHits_EnableObject(obj);
    sub = *(int *)inner;
    if (sub != 0) {
        ObjHits_EnableObject(sub);
    }

    if (*(s8 *)(inner + 0xa2) != *(s8 *)(inner + 0xa3)) {
        if (*(int *)(obj + 0xc8) != 0) {
            Obj_FreeObject(*(int *)(obj + 0xc8));
            *(int *)(obj + 0xc8) = 0;
            *(u8 *)(obj + 0xeb) = 0;
        }
        if (*(s8 *)(inner + 0xa2) > 0 && Obj_IsLoadingLocked() != 0) {
            *(int *)(obj + 0xc8) =
                Obj_SetupObject(Obj_AllocObjectSetup(0x18, lbl_802C2540.v[*(s8 *)(inner + 0xa2)]),
                                4, *(s8 *)(obj + 0xac), -1, *(int *)(obj + 0x30));
            *(u8 *)(obj + 0xeb) = 1;
        }
        *(u8 *)(inner + 0xa3) = *(u8 *)(inner + 0xa2);
    }

    if (*(void **)inner == NULL) {
        objects = ObjGroup_GetObjects(0xa, &objectCount);
        targetType = seqStreamLookupFn_8007fff8(lbl_8032A310, 6, *(s16 *)(obj + 0x46));
        for (i = 0; i < objectCount; i++) {
            if (*(s16 *)(objects[i] + 0x46) == targetType) {
                *(int *)inner = objects[i];
                i = objectCount;
            }
        }
    }

    if (GameBit_Get(*(s16 *)(*(int *)(inner + 4))) == 0) {
        return;
    }

    sub = *(int *)inner;
    if (sub != 0 && *(s8 *)(inner + 0xa4) != 0 &&
        *(s16 *)(obj + 0xa0) == *(u16 *)(inner + 0xa8) && fn_801EC9F4(sub) != 0 &&
        timerCountDown(inner + 0x98) != 0) {
        choice = randomGetRange(0, 1);
        *(int *)(inner + 0x94) = *(u16 *)(inner + 0xa8) + 5;
        turnSign = (u32)(s16)Obj_GetYawDeltaToObject(obj, Obj_GetPlayerObject(), 0) >> 31;
        if (turnSign == 0 || *(s16 *)(obj + 0x46) == 0x389) {
            ObjAnim_SetCurrentMove(obj, *(u16 *)(inner + 0xa8) + 6, lbl_803E66F0, 0);
            snowclaw_spawnDropBomb(*(int *)inner, obj, (u8)choice, 2);
        } else {
            ObjAnim_SetCurrentMove(obj, *(u16 *)(inner + 0xa8) + 5, lbl_803E66F0, 0);
            snowclaw_spawnDropBomb(*(int *)inner, obj, (u8)choice, 0);
        }
        s16toFloat(inner + 0x98, lbl_8032A340[fn_801EC9BC(*(int *)inner) - 1]);
    }

    sub = *(int *)inner;
    if (sub != 0) {
        snowclaw_updateMountAttack(obj, sub);
    }

    if (randFn_80080100(0x12c) != 0) {
        Sfx_PlayFromObject(obj, 0x2e5);
    }

    if (*(s8 *)(inner + 0xa4) < 4) {
        pulseTypes[0] = lbl_802C2520[0];
        pulseTypes[1] = lbl_802C2520[1];
        pulseTypes[2] = lbl_802C2520[2];
        pulseTypes[3] = lbl_802C2520[3];
        pulseModes[0] = lbl_802C2520[4];
        pulseModes[1] = lbl_802C2520[5];
        pulseModes[2] = lbl_802C2520[6];
        pulseModes[3] = lbl_802C2520[7];
        pulseIndex = 3 - *(s8 *)(inner + 0xa4);
        i = *(u8 *)(inner + 0xa6);
        *(u8 *)(inner + 0xa6) = i + 1;
        if ((i % lbl_803DC220) != 0) {
            pulseVec[0] = lbl_803E66F0;
            pulseVec[1] = lbl_803DC21C;
            pulseVec[2] = lbl_803E66F0;
            fn_80098B18(obj, lbl_803DC218, (u8)pulseTypes[pulseIndex],
                        (u8)pulseModes[pulseIndex], 0, pulseVec);
        }
    }
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
int snowclaw_animEventCallback(int obj, int a2, int evt) {
    int *sub;
    int *inner;
    int i;
    SnowClawAnimTbl tbl;
    f32 dist;

    dist = lbl_803E6708;
    inner = *(int **)((char *)obj + 0xb8);
    *(u8 *)((char *)inner + 0xa1) = 1;
    ObjHits_DisableObject(obj);
    if (*(int **)inner != 0) {
        ObjHits_DisableObject(*(int *)inner);
    }
    if (*(s16 *)((char *)obj + 0xb4) != -1 &&
        (*(s16 *)((char *)obj + 0x46) == 0x16d || *(s16 *)((char *)obj + 0x46) == 0x170) &&
        GameBit_Get(0x3a3) != 0) {
        (*(void (*)(int))(*(int *)(*gObjectTriggerInterface + 0x4c)))(*(s16 *)((char *)obj + 0xb4));
        *(f32 *)((char *)inner + 0xac) = lbl_803E66F0;
        return 4;
    }
    *(s16 *)((char *)obj + 6) &= ~0x4000;
    sub = *(int **)inner;
    *(u8 *)((char *)inner + 0xa0) = 0xff;
    if (sub != 0) {
        s16 v6 = *(s16 *)((char *)sub + 6);
        if (v6 & 0x4000) {
            *(s16 *)((char *)sub + 6) = v6 & ~0x4000;
            (*(void (*)(int *, int))(*(int *)(*(int *)(*(int *)((char *)sub + 0x68)) + 0x3c)))(sub, 2);
        }
    }
    if (*(u8 *)((char *)evt + 0x7e) == 2) {
        *(u8 *)((char *)evt + 0x90) |= 8;
    }
    *(s16 *)((char *)evt + 0x6e) = *(s16 *)((char *)evt + 0x70);
    for (i = 0; i < *(u8 *)((char *)evt + 0x8b); i++) {
        int idx = i + 0x81;
        switch (*(u8 *)((char *)evt + idx)) {
        case 3:
            *(s8 *)((char *)inner + 0xa2) = -1;
            break;
        case 4:
            if (GameBit_Get(0xb7d) != 0) {
                *(u8 *)((char *)evt + 0x90) |= 4;
            }
            break;
        case 5:
            if (GameBit_Get(*(s16 *)(*(int *)((char *)inner + 4))) != 0) {
                *(u8 *)((char *)evt + 0x90) |= 4;
            }
            break;
        case 2:
            if (sub != 0) {
                *(f32 *)((char *)inner + 0x8) = lbl_803E670C;
                *(f32 *)((char *)inner + 0xc) = *(f32 *)((char *)inner + 0x18);
                *(f32 *)((char *)inner + 0x10) = *(f32 *)((char *)inner + 0x1c);
                *(f32 *)((char *)inner + 0x14) = *(f32 *)((char *)inner + 0x20);
                (*(void (*)(int *, int))(*(int *)(*(int *)(*(int *)((char *)sub + 0x68)) + 0x3c)))(sub, 2);
                ObjAnim_SetCurrentMove(obj, *(u16 *)((char *)inner + 0xa8), lbl_803E66F0, 1);
                {
                    int *gx = *(int **)((char *)obj + 0x64);
                    if (gx != 0) {
                        *(int *)((char *)gx + 0x30) |= 0x1000;
                    }
                }
                *(s16 *)((char *)evt + 0x6e) &= ~4;
            }
            break;
        case 1:
            sub = *(int **)inner;
            if (sub != 0) {
                (*(void (*)(int *, int))(*(int *)(*(int *)(*(int *)((char *)sub + 0x68)) + 0x3c)))(sub, 0);
                *(s16 *)((char *)evt + 0x6e) |= 4;
            }
            break;
        case 6: {
            int *found = (int *)ObjGroup_FindNearestObject(0x1e, obj, &dist);
            if (found != 0) {
                (*(void (*)(int *, int))(*(int *)(*(int *)(*(int *)((char *)found + 0x68)) + 0x20)))(found, 2);
                ((SnowclawAaFlags *)((char *)inner + 0xaa))->b0 = 0;
            }
            break;
        }
        case 7: {
            int *found = (int *)ObjGroup_FindNearestObject(0x1e, obj, &dist);
            if (found != 0) {
                (*(void (*)(int *, int))(*(int *)(*(int *)(*(int *)((char *)found + 0x68)) + 0x20)))(found, 0);
                ((SnowclawAaFlags *)((char *)inner + 0xaa))->b0 = 1;
            }
            break;
        }
        }
        *(u8 *)((char *)evt + idx) = 0;
    }
    tbl = lbl_802C2540;
    if (*(s8 *)((char *)inner + 0xa2) != *(s8 *)((char *)inner + 0xa3)) {
        if (*(int **)((char *)obj + 0xc8) != 0) {
            Obj_FreeObject(*(int *)((char *)obj + 0xc8));
            *(int *)((char *)obj + 0xc8) = 0;
            *(u8 *)((char *)obj + 0xeb) = 0;
        }
        if (*(s8 *)((char *)inner + 0xa2) > 0 && Obj_IsLoadingLocked() != 0) {
            *(int *)((char *)obj + 0xc8) =
                Obj_SetupObject(Obj_AllocObjectSetup(0x18, tbl.v[*(s8 *)((char *)inner + 0xa2)]), 4,
                                *(s8 *)((char *)obj + 0xac), -1, *(int *)((char *)obj + 0x30));
            *(u8 *)((char *)obj + 0xeb) = 1;
        }
        *(s8 *)((char *)inner + 0xa3) = *(s8 *)((char *)inner + 0xa2);
    }
    if (sub != 0 && (*(int (*)(int *))(*(int *)(*(int *)(*(int *)((char *)sub + 0x68)) + 0x38)))(sub) == 2) {
        *(s16 *)((char *)evt + 0x6e) &= ~3;
    }
    return 0;
}
#pragma peephole reset
#pragma scheduling reset
