#include "main/objanim.h"
#include "main/game_object.h"
#include "main/obj_placement.h"
#include "main/objanim_internal.h"
#include "main/objseq.h"

extern u32 GameBit_Get(int id);
extern void GameBit_Set(int id, int value);
extern void Sfx_PlayFromObject(int obj, int sfxId);
extern u32 randomGetRange(int min, int max);
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
extern u8 Obj_IsLoadingLocked(void);
extern void *Obj_GetPlayerObject(void);
extern void objSetSlot(int obj, int slot);
extern void Obj_SetModelColorFadeRecursive(int obj, int r, int g, int b, int a, int frames);
extern void objLightFn_8009a1dc(int obj, f32 scale, void *pos, int mode, int param);
extern void objfx_spawnRandomBurst(int obj, int mode, int p3, void *vec, f32 f, int flag);
extern void vecRotateZXY(int obj, void *vec);
extern f32 sqrtf(f32 x);
extern f32 fn_8001461C(void);
extern void sc_musictree_spawnAmbientEffect(int obj, int inner, u8 frames, int idx);
extern void sc_musictree_handleHitObject(int obj, int inner, int effectType);

extern void objRenderFn_8003b8f4(f32);

extern ObjectTriggerInterface **gObjectTriggerInterface;
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

typedef struct SCMusicTreeState {
    int ambientEffect[3];
    f32 pathPoint[3][3];
    f32 proximityBurstTimer;
    f32 animSpeed;
    f32 scale;
    f32 proximityCooldown;
    f32 hitCooldown;
    int hitCooldownState;
    u16 hearRadius;
    s16 previousDistance;
    u8 flags;
    u8 pad4D[0x50 - 0x4D];
} SCMusicTreeState;

typedef struct SCMusicTreeSetup {
    ObjPlacement base;
    u8 rotXByte;
    u8 rotZByte;
    u8 yawByte;
    u8 hearRadiusHalf;
    f32 scale;
    u8 pad20[0x23 - 0x20];
    u8 flags;
} SCMusicTreeSetup;

STATIC_ASSERT(sizeof(SCMusicTreeSetup) == 0x24);
STATIC_ASSERT(offsetof(SCMusicTreeSetup, rotXByte) == 0x18);
STATIC_ASSERT(offsetof(SCMusicTreeSetup, rotZByte) == 0x19);
STATIC_ASSERT(offsetof(SCMusicTreeSetup, yawByte) == 0x1A);
STATIC_ASSERT(offsetof(SCMusicTreeSetup, hearRadiusHalf) == 0x1B);
STATIC_ASSERT(offsetof(SCMusicTreeSetup, scale) == 0x1C);
STATIC_ASSERT(offsetof(SCMusicTreeSetup, flags) == 0x23);

#pragma peephole off
#pragma scheduling off
void sc_musictree_update(int obj)
{
    int inner = *(int *)&((GameObject *)obj)->extra;
    f32 stk[7];
    f32 vec[3];
    f32 vec2[3];
    int rcType;
    int hr1, hr2, hr3;
    int i;
    int *p;
    int *q;

    ObjAnim_AdvanceCurrentMove(*(f32 *)(inner + 0x34), timeDelta, obj,
                               (ObjAnimEventList *)&stk);
    if (*(u8 *)(inner + 0x4c) == 0) {
        return;
    }
    if (*(f32 *)(inner + 0x3c) > lbl_803E5590) {
        *(f32 *)(inner + 0x3c) = *(f32 *)(inner + 0x3c) - timeDelta;
    }
    if (*(f32 *)(inner + 0x34) > lbl_803E5594) {
        *(f32 *)(inner + 0x34) = *(f32 *)(inner + 0x34) - lbl_803E5598;
    }
    if ((*(u8 *)(inner + 0x4c) & 0x80) && ((GameObject *)obj)->unkF8 != 0) {
        p = (int *)inner;
        q = (int *)inner;
        for (i = 0; i < 3; i++) {
            if (*(void **)p == NULL) {
                sc_musictree_spawnAmbientEffect(obj, inner, framesThisStep, (s8)i);
            } else {
                int r = (*(int (**)(int))(*(int *)(*(int *)(*p + 0x68)) + 0x28))(*p);
                if (r > 3) {
                    *p = 0;
                } else {
                    (*(void (**)(int, int))(*(int *)(*(int *)(*p + 0x68)) + 0x24))(*p, (int)q + 0xc);
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
        rcType = ObjHits_GetPriorityHitWithPosition(obj, &hr1, &hr2, &hr3, &vec[0], &vec[1], &vec[2]);
    } else {
        rcType = ObjHits_PollPriorityHitEffectWithCooldown(obj, 8, 0xff, 0xff, 0x78, 0x129, (int *)(inner + 0x44));
    }
    if (*(f32 *)(inner + 0x40) >= lbl_803E5590) {
        *(f32 *)(inner + 0x40) = *(f32 *)(inner + 0x40) - timeDelta;
    }
    if (rcType == 0) goto end;
    if (rcType == 0x11) goto end;
    if (!(*(f32 *)(inner + 0x40) <= lbl_803E5590)) goto end;
    if (*(u8 *)(inner + 0x4c) & 0xc0) {
        vec[0] = vec[0] + playerMapOffsetX;
        vec[2] = vec[2] + playerMapOffsetZ;
        objLightFn_8009a1dc(obj, lbl_803E559C, vec2, 1, 0);
        Obj_SetModelColorFadeRecursive(obj, 0xf, 0xc8, 0, 0, 1);
        sc_musictree_handleHitObject(obj, inner, *(u8 *)(inner + 0x4c) & 0xf);
    } else {
        Sfx_PlayFromObject(obj, 0x129);
        Sfx_PlayFromObject(obj, 0x12a);
    }
    {
        f32 zero = lbl_803E5590;
        vec[0] = zero;
        vec[1] = lbl_803E55A0 * *(f32 *)(inner + 0x38);
        vec[2] = zero;
        objfx_spawnRandomBurst(obj, *(u8 *)(inner + 0x4c) & 0xf, 0x14, vec2, lbl_803E55A4 * *(f32 *)(inner + 0x38), 0);
    }
    *(f32 *)(inner + 0x34) = lbl_803E5588;
    *(f32 *)(inner + 0x40) = lbl_803E55A8;
    if (*(u8 *)(inner + 0x4c) & 0x80) {
        int *pp;
        int idx;
        for (idx = 0, pp = (int *)inner; idx < 3; idx++) {
            int rc = *pp;
            if ((u32)rc != 0) {
                int rr = (*(int (**)(int))(*(int *)(*(int *)(rc + 0x68)) + 0x28))(rc);
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
        f32 dx = ((GameObject *)obj)->anim.localPosX - *(f32 *)((char *)player + 0xc);
        f32 dz = ((GameObject *)obj)->anim.localPosZ - *(f32 *)((char *)player + 0x14);
        f32 d = sqrtf(dx * dx + dz * dz);
        if ((u16)(s32)d < *(u16 *)(inner + 0x48)) {
            if ((*(u8 *)(inner + 0x4c) & 0x10) && *(u16 *)(inner + 0x4a) >= (u16)(s32)d && *(f32 *)(inner + 0x3c) <= lbl_803E5590) {
                vec[0] = lbl_803E5590;
                vec[1] = lbl_803E55AC * (lbl_803E55A0 * *(f32 *)(inner + 0x38));
                vec[2] = lbl_803E5590;
                objfx_spawnRandomBurst(obj, *(u8 *)(inner + 0x4c) & 0xf, 0xa, vec2, lbl_803E55A4 * *(f32 *)(inner + 0x38), 1);
                *(f32 *)(inner + 0x3c) = lbl_803E55B0;
            }
            *(f32 *)(inner + 0x30) = *(f32 *)(inner + 0x30) - timeDelta;
            if (*(f32 *)(inner + 0x30) <= lbl_803E5590) {
                vec[0] = lbl_803E5590;
                vec[1] = lbl_803E55A0 * *(f32 *)(inner + 0x38);
                vec[2] = lbl_803E5590;
                vecRotateZXY(obj, vec);
                objfx_spawnRandomBurst(obj, *(u8 *)(inner + 0x4c) & 0xf, 1, vec2, lbl_803E55A4 * *(f32 *)(inner + 0x38), 0);
                *(f32 *)(inner + 0x30) = *(f32 *)(inner + 0x30) + lbl_803E55B4;
            }
        }
        *(u16 *)(inner + 0x4a) = (s32)d;
    }
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void sc_musictree_init(int obj, SCMusicTreeSetup *setup)
{
    SCMusicTreeState *state = ((GameObject *)obj)->extra;
    f32 stk[7];
    f32 ratio;
    f32 zero;

    state->animSpeed = lbl_803E5594;
    zero = lbl_803E5590;
    state->proximityBurstTimer = zero;
    state->hearRadius = (u16)((u32)setup->hearRadiusHalf << 1);
    state->flags = setup->flags;
    state->proximityCooldown = zero;
    state->scale = setup->scale;
    ((GameObject *)obj)->anim.rotZ = (s16)((setup->rotXByte - 0x7f) << 7);
    ((GameObject *)obj)->anim.rotY = (s16)((setup->rotZByte - 0x7f) << 7);
    ((GameObject *)obj)->anim.rotX = (s16)((u32)setup->yawByte << 8);
    ((GameObject *)obj)->anim.rootMotionScale = lbl_803E55B8 * setup->scale;
    ((GameObject *)obj)->unkF8 = 0;
    ((GameObject *)obj)->objectFlags = (u16)(((GameObject *)obj)->objectFlags | 0x2000);
    ratio = (f32)(s32)randomGetRange(1, 99) / lbl_803E55BC;
    ObjAnim_SetCurrentMove(obj, 0, ratio, 0);
    ((int (*)(int, f32, f32, void *))ObjAnim_AdvanceCurrentMove)(obj, lbl_803E558C, *(f32 *)&lbl_803E558C,
                               (ObjAnimEventList *)&stk);
    ObjHitbox_SetCapsuleBounds(obj, (s32)(lbl_803E55C0 * state->scale), -5, 0xff);
    if (state->flags & 0x80) {
        state->flags = state->flags | 0x20;
    }
}
#pragma scheduling reset
#pragma peephole reset

void sc_musictree_release(void) {}
void sc_musictree_initialise(void) {}

typedef struct SCTotemPoleState {
    u16 gameBit;
    u8 currentState;
    u8 previousState;
    f32 animSpeed;
} SCTotemPoleState;

#define SC_TOTEMPOLE_OBJECT_TYPE 0x282
#define SC_TOTEMPOLE_GAMEBIT_FRONT 0x81
#define SC_TOTEMPOLE_GAMEBIT_LEFT 0x82
#define SC_TOTEMPOLE_GAMEBIT_RIGHT 0x83
#define SC_TOTEMPOLE_GAMEBIT_REAR 0x84
#define SC_TOTEMPOLE_SETUP_REAR 0x44916
#define SC_TOTEMPOLE_SETUP_RIGHT 0x44909
#define SC_TOTEMPOLE_SETUP_FRONT 0x4490C
#define SC_TOTEMPOLE_SETUP_LEFT 0x4490F

#pragma peephole off
#pragma scheduling off
int sc_totempole_sortCompletionGameBits(u16 *bits, u16 param2)
{
    u16 stk[4];
    u8 i, j;
    s32 changed = 0;

    for (i = 0; i < 3; i++) {
        u16 v = (u16)GameBit_Get(bits[i]);
        stk[i] = v;
    }
    stk[3] = param2;
    for (i = 0; i < 3; i++) {
        for (j = 0; j < 3; j++) {
            if (stk[j + 1] != 0) {
                u16 b = stk[j];
                if ((stk[j + 1] < b) || (b == 0)) {
                    stk[j] = stk[j + 1];
                    stk[j + 1] = b;
                    changed = 1;
                }
            }
        }
    }
    for (i = 0; i < 3; i++) {
        GameBit_Set(bits[i], (u32)stk[i]);
    }
    return changed;
}
#pragma scheduling reset
#pragma peephole reset

int sc_totempole_getExtraSize(void) { return 0x8; }
int sc_totempole_getObjectTypeId(void) { return 0x0; }
void sc_totempole_free(void) {}

#pragma peephole off
void sc_totempole_render(int p1, int p2, int p3, int p4, int p5, s8 visible) { s32 v = visible; if (v != 0) objRenderFn_8003b8f4(lbl_803E55D0); }
#pragma peephole reset

void sc_totempole_hitDetect(void) {}

#pragma peephole off
#pragma scheduling off
void sc_totempole_update(int obj)
{
    SCTotemPoleState *state = ((GameObject *)obj)->extra;
    f32 stk[8];
    int played;
    int *arr;
    int count;
    int idx;

    state->previousState = state->currentState;
    state->currentState = (u8)GameBit_Get(state->gameBit);
    if (state->previousState != state->currentState) {
        if (state->currentState != 0) {
            Sfx_PlayFromObject(obj, 0x3ad);
            state->animSpeed = lbl_803E55D4;
            played = 0;
            if (GameBit_Get(SC_TOTEMPOLE_GAMEBIT_FRONT) != 0 &&
                GameBit_Get(SC_TOTEMPOLE_GAMEBIT_LEFT) != 0 &&
                GameBit_Get(SC_TOTEMPOLE_GAMEBIT_RIGHT) != 0 &&
                GameBit_Get(SC_TOTEMPOLE_GAMEBIT_REAR) != 0) {
                Sfx_PlayFromObject(0, 0x7e);
                played = 1;
                arr = ObjList_GetObjects(&idx, &count);
                for (; idx < count; idx++) {
                    void *o = (void *)arr[idx];
                    if (o != (void *)obj && *(s16 *)((char *)o + 0x46) == SC_TOTEMPOLE_OBJECT_TYPE) {
                        (*(void (**)(int, int))(*(int *)(*(int *)(arr[idx] + 0x68)) + 0x20))(arr[idx], 6);
                        break;
                    }
                }
                ((int (*)(u16 *, int))sc_totempole_sortCompletionGameBits)(
                    (u16 *)&lbl_803DC068, (s32)(fn_8001461C() / lbl_803E55D8));
            }
            if (!played) {
                Sfx_PlayFromObject(0, 0x109);
            }
        } else {
            Sfx_PlayFromObject(obj, 0x3ad);
            state->animSpeed = lbl_803E55DC;
        }
    }
    ((int (*)(int, f32, f32, void *))ObjAnim_AdvanceCurrentMove)(obj, state->animSpeed, timeDelta, (ObjAnimEventList *)&stk);
    ObjHits_PollPriorityHitEffectWithCooldown(obj, 8, 0xff, 0xff, 0x78, 0x129, (int *)&lbl_803DDC08);
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void sc_totempole_init(int obj, int p2)
{
    SCTotemPoleState *state = ((GameObject *)obj)->extra;
    switch (*(int *)(p2 + 0x14)) {
    case SC_TOTEMPOLE_SETUP_REAR:
        state->gameBit = SC_TOTEMPOLE_GAMEBIT_REAR;
        break;
    case SC_TOTEMPOLE_SETUP_RIGHT:
        state->gameBit = SC_TOTEMPOLE_GAMEBIT_RIGHT;
        break;
    case SC_TOTEMPOLE_SETUP_FRONT:
        state->gameBit = SC_TOTEMPOLE_GAMEBIT_FRONT;
        break;
    case SC_TOTEMPOLE_SETUP_LEFT:
        state->gameBit = SC_TOTEMPOLE_GAMEBIT_LEFT;
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
    void *inner = ((GameObject *)obj)->extra;
    (*gObjectTriggerInterface)->freeState(inner);
    ((void (*)(int *, int, int, int, int))(*(int *)(*gTitleMenuControlInterface + 0x8)))(obj, 0xffff, 0, 0, 0);
}
#pragma peephole reset
#pragma scheduling reset

#pragma peephole off
void sc_cloudrunnera_render(int p1, int p2, int p3, int p4, int p5, s8 visible) { s32 v = visible; if (v != 0) objRenderFn_8003b8f4(lbl_803E55E0); }
#pragma peephole reset

void sc_cloudrunnera_hitDetect(void) {}

#pragma peephole off
#pragma scheduling off
void sc_cloudrunnera_update(int obj)
{
    int i;
    int inner = *(int *)&((GameObject *)obj)->extra;
    void *sub;
    int idx, count;

    sub = ((GameObject *)obj)->anim.placementData;
    if (sub == NULL) return;
    if (*(s16 *)((char *)sub + 0x18) == -1) return;
    idx = (*gObjectTriggerInterface)->update((u8 *)obj, (f32)(u32)lbl_803DB411);
    if (idx != 0 && ((GameObject *)obj)->unkB4 == -2) {
        int found;
        s32 mark = *(s8 *)(inner + 0x57);
        int *arr;
        int n;
        int markCopy;
        int matchCount;

        found = 0;
        arr = ObjList_GetObjects(&idx, &count);
        matchCount = 0;
        idx = 0;
        markCopy = mark;
        n = count;
        for (; idx < n; idx++) {
            int o = *arr;
            s16 t = *(s16 *)(o + 0xb4);
            if (t == mark) {
                found = o;
            }
            if (t == -2 && *(s16 *)(o + 0x44) == 0x10) {
                inner = *(int *)(o + 0xb8);
                if (markCopy == (s8)*(u8 *)(inner + 0x57)) {
                    matchCount++;
                }
            }
            arr++;
        }
        if (matchCount <= 1 && (u32)found != 0 && *(s16 *)(found + 0xb4) != -1) {
            *(s16 *)(found + 0xb4) = -1;
            (*gObjectTriggerInterface)->endSequence(markCopy);
        }
        ((GameObject *)obj)->unkB4 = -1;
    }

    for (i = 0; i < *(u8 *)(inner + 0x8b); i++) {
        switch (*(u8 *)(inner + i + 0x81)) {
        case 0: {
            int setup;
            int newObj;
            if (*(void **)&((GameObject *)obj)->unkC8 != NULL) {
                break;
            }
            if (Obj_IsLoadingLocked() == 0) {
                break;
            }
            setup = Obj_AllocObjectSetup(0x30, 0x6e8);
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
            newObj = Obj_SetupObject(setup, 5, *(s8 *)(obj + 0xac), -1, *(int *)&((GameObject *)obj)->anim.parent);
            ((GameObject *)newObj)->anim.flags = (s16)(((GameObject *)newObj)->anim.flags | 0x4000);
            ObjLink_AttachChild(obj, newObj, 0);
            Sfx_PlayFromObject(obj, 0x10f);
            break;
        }
        case 1: {
            if (*(void **)&((GameObject *)obj)->unkC8 != NULL) {
                cmbsrc_setExternalActive(*(int *)&((GameObject *)obj)->unkC8, 0);
            }
            break;
        }
        case 2: {
            int innerSlot = *(int *)&((GameObject *)obj)->unkC8;
            if ((u32)innerSlot != 0) {
                ObjLink_DetachChild(obj, innerSlot);
                Obj_FreeObject(innerSlot);
            }
            break;
        }
        }
    }
    {
        int t = *(int *)&((GameObject *)obj)->unkC8;
        if ((u32)t != 0) {
            *(s16 *)(t + 4) = ((GameObject *)obj)->anim.rotZ;
            *(s16 *)(*(int *)&((GameObject *)obj)->unkC8 + 2) = (s16)(((GameObject *)obj)->anim.rotY + 0xe38);
            *(s16 *)(*(int *)&((GameObject *)obj)->unkC8 + 0) = (s16)(((GameObject *)obj)->anim.rotX + -0x8000);
        }
    }
}
#pragma scheduling reset
#pragma peephole reset

#pragma scheduling off
void sc_cloudrunnera_init(int obj, int p2)
{
    int inner;
    f32 base;

    objSetSlot(obj, 0x64);
    inner = *(int *)(obj + 0xb8);
    *(s16 *)(inner + 0x6a) = *(s16 *)(p2 + 0x1a);
    *(s16 *)(inner + 0x6e) = -1;
    base = lbl_803E55E0;
    *(f32 *)(inner + 0x24) = base / (base + (f32)(u32)*(u8 *)(p2 + 0x24));
    *(int *)(inner + 0x28) = -1;
    *(int *)(obj + 0xf8) = 0;

    if (*(int *)(obj + 0xf4) == 0 && *(s16 *)(p2 + 0x18) != 1) {
        (*gObjectTriggerInterface)
            ->loadAnimData((u8 *)inner, (u8 *)p2);
        *(int *)(obj + 0xf4) = *(s16 *)(p2 + 0x18) + 1;
    } else if (*(int *)(obj + 0xf4) != 0 && *(s16 *)(p2 + 0x18) != *(int *)(obj + 0xf4) - 1) {
        (*gObjectTriggerInterface)->freeState((u8 *)inner);
        if (*(s16 *)(p2 + 0x18) != -1) {
            (*gObjectTriggerInterface)
                ->loadAnimData((u8 *)inner, (u8 *)p2);
        }
        *(int *)(obj + 0xf4) = *(s16 *)(p2 + 0x18) + 1;
    }
    if (((GameObject *)obj)->anim.modelState != NULL) {
        ((GameObject *)obj)->anim.modelState->shadowTintA = 0x64;
        ((GameObject *)obj)->anim.modelState->shadowTintB = 0x96;
    }
}
#pragma scheduling reset

void sc_cloudrunnera_release(void) {}
void sc_cloudrunnera_initialise(void) {}

#pragma peephole off
int fn_801DD170(void) {
    int r;
    if (GameBit_Get(0x639) != 0) { r = 0; } else { r = 1; }
    return r;
}
#pragma peephole reset
