#include "ghidra_import.h"

extern int GameBit_Get(int id);
extern void GameBit_Set(int id, int value);
extern void Sfx_PlayFromObject(int obj, int sfxId);
extern u32 randomGetRange(int min, int max);
extern int ObjAnim_SetCurrentMove(int obj, int moveId, f32 blend, int flag);
extern void ObjAnim_AdvanceCurrentMove(int obj, void *stk, f32 a, f32 b);
extern void ObjHitbox_SetCapsuleBounds(int obj, int radius, int a, int b);
extern int ObjHits_GetPriorityHitWithPosition(int obj, int *type, int *a, int *b, f32 *x, f32 *y, f32 *z);
extern int ObjHits_PollPriorityHitEffectWithCooldown(int obj, int a, int b, int c, int d, int e, int *state);
extern void ObjHits_RecordObjectHit(int target, int src, int a, int b, int c);
extern int *ObjList_GetObjects(int *startIndex, int *objectCount);
extern int Obj_AllocObjectSetup(int a, int b);
extern int Obj_SetupObject(int s, int a, int b, int c, int d);
extern int ObjLink_AttachChild(int parent, int child, int a);
extern int ObjLink_DetachChild(int parent, int child);
extern void cmbsrc_setExternalActive(int obj, int active);
extern void Obj_FreeObject(int obj);
extern u8 Obj_IsLoadingLocked(int obj);
extern void *Obj_GetPlayerObject(void);
extern void objSetSlot(int obj, int slot);
extern void Obj_SetModelColorFadeRecursive(int obj, int r, int g, int b, int a, int frames);
extern void objLightFn_8009a1dc(int obj, f32 *pos, int kind, int p4);
extern void fn_80096C94(int obj, int mode, int p3, void *vec, f32 f, int flag);
extern void mathFn_80021ac8(int obj, void *vec);
extern f32 sqrtf(f32 x);
extern f32 fn_8001461C(void);
extern void fn_801DBFA0(int obj, int inner, u8 frames, int idx);
extern void fn_801DC0BC(int obj, int inner, int p3);

extern void objRenderFn_8003b8f4(f32);

extern int *gObjectTriggerInterface;
extern int *gTitleMenuControlInterface;

extern f32 timeDelta;
extern u8 framesThisStep;
extern f32 playerMapOffsetX;
extern f32 playerMapOffsetZ;

extern u8 lbl_803DB411;
extern int lbl_803DC068;
extern int lbl_803DDC08;
extern f32 lbl_803E5588;
extern f32 lbl_803E558C;
extern f32 lbl_803E5590;
extern f32 lbl_803E5594;
extern f32 lbl_803E5598;
extern f32 lbl_803E559C;
extern f32 lbl_803E55A0;
extern f32 lbl_803E55A4;
extern f32 lbl_803E55A8;
extern f32 lbl_803E55AC;
extern f32 lbl_803E55B0;
extern f32 lbl_803E55B4;
extern f32 lbl_803E55B8;
extern f32 lbl_803E55BC;
extern f32 lbl_803E55C0;
extern f64 lbl_803E55C8;
extern f32 lbl_803E55D0;
extern f32 lbl_803E55D4;
extern f32 lbl_803E55D8;
extern f32 lbl_803E55DC;
extern f32 lbl_803E55E0;
extern f64 lbl_803E55E8;

#pragma peephole off
#pragma scheduling off
void sc_musictree_update(int obj)
{
    int inner = *(int *)(obj + 0xb8);
    f32 stk;
    int rcType;
    f32 hx, hy, hz;
    int hr1, hr2, hr3;
    int i;
    int *p;
    int *q;
    f32 vec[3];
    s16 dist;

    ObjAnim_AdvanceCurrentMove(obj, &stk, *(f32 *)(inner + 0x34), timeDelta);
    if (*(u8 *)(inner + 0x4c) == 0) {
        return;
    }
    if (*(f32 *)(inner + 0x3c) > lbl_803E5590) {
        *(f32 *)(inner + 0x3c) = *(f32 *)(inner + 0x3c) - timeDelta;
    }
    if (*(f32 *)(inner + 0x34) > lbl_803E5594) {
        *(f32 *)(inner + 0x34) = *(f32 *)(inner + 0x34) - lbl_803E5598;
    }
    if ((*(u8 *)(inner + 0x4c) & 0x80) && *(int *)(obj + 0xf8) != 0) {
        p = (int *)inner;
        q = (int *)inner;
        for (i = 0; i < 3; i++) {
            if (*p == 0) {
                fn_801DBFA0(obj, inner, framesThisStep, i);
            } else {
                int r = (*(int (**)(int))(*(int *)(*p + 0x68) + 0x28))(*p);
                if (r > 3) {
                    *p = 0;
                } else {
                    (*(void (**)(int, int))(*(int *)(*(int *)*p + 0x68) + 0x24))(*p, (int)q + 0xc);
                }
            }
            p = (int *)((char *)p + 4);
            q = (int *)((char *)q + 0xc);
        }
    }
    if ((*(u8 *)(inner + 0x4c) & 0x20) == 0) {
        goto end;
    }
    if (*(u8 *)(inner + 0x4c) & 0xc0) {
        rcType = ObjHits_GetPriorityHitWithPosition(obj, &hr1, &hr2, &hr3, &hx, &hy, &hz);
    } else {
        rcType = ObjHits_PollPriorityHitEffectWithCooldown(obj, 8, 0xff, 0xff, 0x78, 0x129, (int *)(inner + 0x44));
    }
    if (*(f32 *)(inner + 0x40) > lbl_803E5590) {
        *(f32 *)(inner + 0x40) = *(f32 *)(inner + 0x40) - timeDelta;
    }
    if (rcType == 0) goto end;
    if (rcType == 0x11) goto end;
    if (*(f32 *)(inner + 0x40) >= lbl_803E5590) goto end;
    if (*(u8 *)(inner + 0x4c) & 0xc0) {
        hx = hx + playerMapOffsetX;
        hz = hz + playerMapOffsetZ;
        objLightFn_8009a1dc(obj, &hx, 1, 0);
        Obj_SetModelColorFadeRecursive(obj, 0xf, 0xc8, 0, 0, 1);
        fn_801DC0BC(obj, inner, *(u8 *)(inner + 0x4c) & 0xf);
    } else {
        Sfx_PlayFromObject(obj, 0x129);
        Sfx_PlayFromObject(obj, 0x12a);
    }
    {
        f32 zero = lbl_803E5590;
        vec[0] = zero;
        vec[1] = lbl_803E55A0 * *(f32 *)(inner + 0x38);
        vec[2] = zero;
        fn_80096C94(obj, *(u8 *)(inner + 0x4c) & 0xf, 0x14, vec, lbl_803E55A4 * *(f32 *)(inner + 0x38), 0);
    }
    *(f32 *)(inner + 0x34) = lbl_803E5588;
    *(f32 *)(inner + 0x40) = lbl_803E55A8;
    if (*(u8 *)(inner + 0x4c) & 0x80) {
        int *pp = (int *)inner;
        int idx;
        for (idx = 0; idx < 3; idx++) {
            int rc = *pp;
            if (rc != 0) {
                int rr = (*(int (**)(int))(*(int *)(*(int *)rc + 0x68) + 0x28))(rc);
                if (rr > 1) {
                    ObjHits_RecordObjectHit(*pp, obj, 0xe, 1, 0);
                }
            }
            pp = (int *)((char *)pp + 4);
        }
    }
end:
    {
        void *player = Obj_GetPlayerObject();
        f32 dx = *(f32 *)(obj + 0xc) - *(f32 *)((char *)player + 0xc);
        f32 dz = *(f32 *)(obj + 0x14) - *(f32 *)((char *)player + 0x14);
        f32 d = sqrtf(dx * dx + dz * dz);
        s32 dl = (s32)d;
        u16 du = (u16)dl;
        s16 hr = *(s16 *)(inner + 0x48);
        if (du < (u16)hr) {
            if ((*(u8 *)(inner + 0x4c) & 0x10) && (u16)*(s16 *)(inner + 0x4a) >= du && *(f32 *)(inner + 0x3c) <= lbl_803E5590) {
                vec[0] = lbl_803E5590;
                vec[1] = lbl_803E55AC * (lbl_803E55A0 * *(f32 *)(inner + 0x38));
                vec[2] = lbl_803E5590;
                fn_80096C94(obj, *(u8 *)(inner + 0x4c) & 0xf, 0xa, vec, lbl_803E55A4 * *(f32 *)(inner + 0x38), 1);
                *(f32 *)(inner + 0x3c) = lbl_803E55B0;
            }
            *(f32 *)(inner + 0x30) = *(f32 *)(inner + 0x30) - timeDelta;
            if (*(f32 *)(inner + 0x30) <= lbl_803E5590) {
                vec[0] = lbl_803E5590;
                vec[1] = lbl_803E55A0 * *(f32 *)(inner + 0x38);
                vec[2] = lbl_803E5590;
                mathFn_80021ac8(obj, vec);
                fn_80096C94(obj, *(u8 *)(inner + 0x4c) & 0xf, 1, vec, lbl_803E55A4 * *(f32 *)(inner + 0x38), 0);
                *(f32 *)(inner + 0x30) = *(f32 *)(inner + 0x30) + lbl_803E55B4;
            }
        }
        dist = (s16)dl;
        *(s16 *)(inner + 0x4a) = dist;
    }
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void sc_musictree_init(int obj, int p2)
{
    int inner = *(int *)(obj + 0xb8);
    f32 stk;
    u32 rnd;
    f32 ratio;
    f32 zero;

    *(f32 *)(inner + 0x34) = lbl_803E5594;
    zero = lbl_803E5590;
    *(f32 *)(inner + 0x30) = zero;
    *(u16 *)(inner + 0x48) = (u16)((u32)*(u8 *)(p2 + 0x1b) << 1);
    *(u8 *)(inner + 0x4c) = *(u8 *)(p2 + 0x23);
    *(f32 *)(inner + 0x3c) = zero;
    *(int *)(inner + 0x38) = *(int *)(p2 + 0x1c);
    *(s16 *)(obj + 4) = (s16)((*(u8 *)(p2 + 0x18) - 0x7f) << 7);
    *(s16 *)(obj + 2) = (s16)((*(u8 *)(p2 + 0x19) - 0x7f) << 7);
    *(s16 *)(obj + 0) = (s16)((u32)*(u8 *)(p2 + 0x1a) << 8);
    *(f32 *)(obj + 8) = lbl_803E55B8 * *(f32 *)(p2 + 0x1c);
    *(int *)(obj + 0xf8) = 0;
    *(u16 *)(obj + 0xb0) = (u16)(*(u16 *)(obj + 0xb0) | 0x2000);
    rnd = randomGetRange(1, 99);
    ratio = (f32)(s32)rnd / lbl_803E55BC;
    ObjAnim_SetCurrentMove(obj, 0, ratio, 0);
    ObjAnim_AdvanceCurrentMove(obj, &stk, lbl_803E5588, lbl_803E5588);
    ObjHitbox_SetCapsuleBounds(obj, (s16)(s32)(lbl_803E55C0 * *(f32 *)(inner + 0x38)), -5, 0xff);
    if (*(u8 *)(inner + 0x4c) & 0x80) {
        *(u8 *)(inner + 0x4c) = *(u8 *)(inner + 0x4c) | 0x20;
    }
}
#pragma scheduling reset
#pragma peephole reset

void sc_musictree_release(void) {}
void sc_musictree_initialise(void) {}

void sc_totempole_sortCompletionGameBits(int *bits, int param2)
{
    u16 stk[20];
    u8 i, j;
    s32 changed = 0;

    for (i = 0; i < 3; i++) {
        u32 v = GameBit_Get(*(u16 *)((char *)bits + (u32)i * 2));
        stk[i] = (u16)v;
    }
    stk[3] = (u16)param2;
    for (i = 0; i < 3; i++) {
        for (j = 0; j < 3; j++) {
            u16 a = stk[j + 1];
            if (a != 0) {
                u16 b = stk[j];
                if ((a < b) || (b == 0)) {
                    stk[j] = a;
                    stk[j + 1] = b;
                    changed = 1;
                }
            }
        }
    }
    for (i = 0; i < 3; i++) {
        GameBit_Set(*(u16 *)((char *)bits + (u32)i * 2), (u32)stk[i]);
    }
    (void)changed;
}

int sc_totempole_getExtraSize(void) { return 0x8; }
int sc_totempole_getObjectTypeId(void) { return 0x0; }
void sc_totempole_free(void) {}

#pragma peephole off
void sc_totempole_render(int p1, int p2, int p3, int p4, int p5, s8 visible) { s32 v = visible; if (v != 0) objRenderFn_8003b8f4(lbl_803E55D0); }
#pragma peephole reset

void sc_totempole_hitDetect(void) {}

void sc_totempole_update(int obj)
{
    int inner = *(int *)(obj + 0xb8);
    int played = 0;
    f32 stk;
    s32 v;
    int *arr;
    int idx;
    int count;
    int i;

    *(u8 *)(inner + 3) = *(u8 *)(inner + 2);
    v = GameBit_Get(*(u16 *)(inner + 0));
    *(u8 *)(inner + 2) = (u8)v;
    if (*(u8 *)(inner + 3) != *(u8 *)(inner + 2)) {
        if (*(u8 *)(inner + 2) == 0) {
            Sfx_PlayFromObject(obj, 0x3ad);
            *(f32 *)(inner + 4) = lbl_803E55DC;
        } else {
            Sfx_PlayFromObject(obj, 0x3ad);
            *(f32 *)(inner + 4) = lbl_803E55D4;
            if (GameBit_Get(0x81) != 0 && GameBit_Get(0x82) != 0 && GameBit_Get(0x83) != 0 && GameBit_Get(0x84) != 0) {
                Sfx_PlayFromObject(0, 0x7e);
                played = 1;
                arr = ObjList_GetObjects(&idx, &count);
                for (i = idx; i < count; i++) {
                    if (arr[i] != obj && *(s16 *)(arr[i] + 0x46) == 0x282) {
                        (*(void (**)(int, int))(*(int *)(*(int *)(arr[i] + 0x68)) + 0x20))(arr[i], 6);
                        break;
                    }
                }
                {
                    f64 d = (f64)fn_8001461C();
                    s32 t = (s32)(d / (f64)lbl_803E55D8);
                    (void)t;
                }
                sc_totempole_sortCompletionGameBits((int *)&lbl_803DC068, 0);
            }
            if (!played) {
                Sfx_PlayFromObject(0, 0x109);
            }
        }
    }
    ObjAnim_AdvanceCurrentMove(obj, &stk, *(f32 *)(inner + 4), timeDelta);
    ObjHits_PollPriorityHitEffectWithCooldown(obj, 8, 0xff, 0xff, 0x78, 0x129, (int *)&lbl_803DDC08);
}

#pragma peephole off
#pragma scheduling off
void sc_totempole_init(int obj, int p2)
{
    int inner = *(int *)(obj + 0xb8);
    switch (*(int *)(p2 + 0x14)) {
    case 0x44916:
        *(s16 *)inner = 0x84;
        break;
    case 0x44909:
        *(s16 *)inner = 0x83;
        break;
    case 0x4490C:
        *(s16 *)inner = 0x81;
        break;
    case 0x4490F:
        *(s16 *)inner = 0x82;
        break;
    }
    *(s16 *)obj = (s16)((u32)*(u8 *)(p2 + 0x1a) << 8);
}
#pragma scheduling reset
#pragma peephole reset

void sc_totempole_release(void) {}
void sc_totempole_initialise(void) {}

int sc_cloudrunnera_getExtraSize(void) { return 0x140; }
int sc_cloudrunnera_getObjectTypeId(void) { return 0xb; }

#pragma scheduling off
#pragma peephole off
void sc_cloudrunnera_free(int *obj)
{
    void *inner = *(void **)((char *)obj + 0xb8);
    ((void (*)(void *))(*(int *)(*gObjectTriggerInterface + 0x24)))(inner);
    ((void (*)(int *, int, int, int, int))(*(int *)(*gTitleMenuControlInterface + 0x8)))(obj, 0xffff, 0, 0, 0);
}
#pragma peephole reset
#pragma scheduling reset

#pragma peephole off
void sc_cloudrunnera_render(int p1, int p2, int p3, int p4, int p5, s8 visible) { s32 v = visible; if (v != 0) objRenderFn_8003b8f4(lbl_803E55E0); }
#pragma peephole reset

void sc_cloudrunnera_hitDetect(void) {}

void sc_cloudrunnera_update(int obj)
{
    int trig;
    int inner = *(int *)(obj + 0xb8);
    int sub;
    int slot;
    int i;
    int *arr;
    int idx, count;
    int matchCount;
    int found;

    if (sub = *(int *)(obj + 0x4c), sub == 0) goto tail;
    if (*(s16 *)(sub + 0x18) == -1) goto tail;
    {
        f64 d = (f64)(u32)lbl_803DB411 - lbl_803E55E8;
        trig = ((int (*)(int, f32))(*(int *)(*(int *)*gObjectTriggerInterface + 0x14)))(obj, (f32)d);
    }
    if (trig != 0 && *(s16 *)(obj + 0xb4) == -2) {
        s32 mark = (s8)*(u8 *)(inner + 0x57);
        found = 0;
        arr = ObjList_GetObjects(&idx, &count);
        matchCount = 0;
        idx = 0;
        for (; idx < count; idx++) {
            int o = arr[idx];
            s16 t = *(s16 *)(o + 0xb4);
            if (t == mark) found = o;
            if (t == -2 && *(s16 *)(o + 0x44) == 0x10) {
                int innerO = *(int *)(o + 0xb8);
                s32 v = (s8)*(u8 *)(innerO + 0x57);
                if (mark == v) matchCount++;
            }
        }
        if (matchCount <= 1 && found != 0 && *(s16 *)(found + 0xb4) != -1) {
            *(s16 *)(found + 0xb4) = -1;
            ((void (*)(int))(*(int *)(*(int *)*gObjectTriggerInterface + 0x4c)))(mark);
        }
        *(s16 *)(obj + 0xb4) = -1;
    }

    for (i = 0; i < *(u8 *)(inner + 0x8b); i++) {
        s8 mode = *(s8 *)(inner + 0x81 + i);
        if (mode == 1) {
            slot = *(int *)(obj + 0xc8);
            if (slot != 0) {
                ((void (*)(int, int))(*(int *)(*(int *)*gObjectTriggerInterface + 0x4c)))(slot, 0);
            }
        } else if (mode < 1) {
            if (mode < 0) continue;
            if (*(int *)(obj + 0xc8) != 0) continue;
            if (!Obj_IsLoadingLocked(obj)) continue;
            {
                int setup = Obj_AllocObjectSetup(0x30, 0x6e8);
                int newObj;
                *(u8 *)(setup + 0x1b) = 0x9;
                *(u8 *)(setup + 0x1c) = 0;
                *(u8 *)(setup + 0x1d) = 0;
                *(f32 *)(setup + 0x20) = lbl_803E55E0;
                *(u8 *)(setup + 0x26) = 0xff;
                *(u8 *)(setup + 0x27) = 0xff;
                *(u8 *)(setup + 0x28) = 0xff;
                *(s16 *)(setup + 0x24) = -1;
                *(u8 *)(setup + 0x4) = 2;
                *(u8 *)(setup + 0x5) = 1;
                *(u8 *)(setup + 0x6) = 0xff;
                *(u8 *)(setup + 0x7) = 0xff;
                *(u8 *)(setup + 0x29) = 1;
                *(u8 *)(setup + 0x2a) = 0;
                newObj = Obj_SetupObject(setup, 5, (s8)*(u8 *)(obj + 0xac), -1, *(int *)(obj + 0x30));
                *(s16 *)(newObj + 6) = (s16)(*(s16 *)(newObj + 6) | 0x4000);
                ObjLink_AttachChild(obj, newObj, 0);
                Sfx_PlayFromObject(obj, 0x10f);
            }
        } else if (mode < 3) {
            int innerSlot = *(int *)(obj + 0xc8);
            if (innerSlot != 0) {
                ObjLink_DetachChild(obj, innerSlot);
                Obj_FreeObject(innerSlot);
            }
        }
    }
    {
        int s = *(int *)(obj + 0xc8);
        if (s != 0) {
            *(s16 *)(s + 4) = *(s16 *)(obj + 4);
            *(s16 *)(*(int *)(obj + 0xc8) + 2) = (s16)(*(s16 *)(obj + 2) + 0xe38);
            *(s16 *)(*(int *)(obj + 0xc8) + 0) = (s16)(*(s16 *)(obj + 0) + -0x8000);
        }
    }
tail:
    ;
}

void sc_cloudrunnera_init(int obj, int p2)
{
    int inner;
    f64 d;
    f32 base;
    s16 v;

    objSetSlot(obj, 0x64);
    inner = *(int *)(obj + 0xb8);
    *(s16 *)(inner + 0x6a) = *(s16 *)(p2 + 0x1a);
    *(s16 *)(inner + 0x6e) = -1;
    base = lbl_803E55E0;
    d = (f64)(u32)*(u8 *)(p2 + 0x24) - lbl_803E55E8;
    *(f32 *)(inner + 0x24) = base / (base + (f32)d);
    *(int *)(inner + 0x28) = -1;
    *(int *)(obj + 0xf8) = 0;

    if (*(int *)(obj + 0xf4) == 0 && *(s16 *)(p2 + 0x18) != 1) {
        ((void (*)(int, int))(*(int *)(*(int *)*gObjectTriggerInterface + 0x1c)))(inner, p2);
        *(int *)(obj + 0xf4) = *(s16 *)(p2 + 0x18) + 1;
    } else if (*(int *)(obj + 0xf4) != 0 && *(s16 *)(p2 + 0x18) != *(int *)(obj + 0xf4) - 1) {
        ((void (*)(int))(*(int *)(*(int *)*gObjectTriggerInterface + 0x24)))(inner);
        if (*(s16 *)(p2 + 0x18) != -1) {
            ((void (*)(int, int))(*(int *)(*(int *)*gObjectTriggerInterface + 0x1c)))(inner, p2);
        }
        *(int *)(obj + 0xf4) = *(s16 *)(p2 + 0x18) + 1;
    }
    if (*(int *)(obj + 0x64) != 0) {
        *(u8 *)(*(int *)(obj + 0x64) + 0x3a) = 0x64;
        *(u8 *)(*(int *)(obj + 0x64) + 0x3b) = 0x96;
    }
}

void sc_cloudrunnera_release(void) {}
void sc_cloudrunnera_initialise(void) {}

#pragma scheduling off
#pragma peephole off
int fn_801DD170(void) {
    int r;
    if (GameBit_Get(0x639) != 0) { r = 0; } else { r = 1; }
    return r;
}
#pragma peephole reset
#pragma scheduling reset
