#include "ghidra_import.h"
#include "main/dll/dimmagicbridge.h"


extern u32 GameBit_Get(int eventId);
extern int GameBit_Set(int eventId, int value);
extern char *Obj_GetPlayerObject(void);
extern int ObjMsg_Pop(int obj, int *msgOut, int *paramOut, int *flagsOut);
extern char *ObjGroup_FindNearestObject(int group, char *from, f32 *distInOut);
extern void Obj_FreeObject(char *obj);
extern f32 Vec_distance(f32 *a, f32 *b);
extern int *Resource_Acquire(int id, int kind);
extern void Resource_Release(int *res);

extern int *gTitleMenuControlInterface;
extern int *gObjectTriggerInterface;
extern int *gModgfxInterface;
extern int *gMapEventInterface;

extern byte framesThisStep;

extern f32 lbl_803E515C;
extern f32 lbl_803E5160;
extern f32 lbl_803E5164;
extern f32 lbl_803E5168;
extern f32 lbl_803E516C;
extern f32 lbl_803E5170;
extern f32 lbl_803E5174;

/*
 * --INFO--
 *
 * Function: dll_199_update
 * EN v1.0 Address: 0x801CAD80
 * EN v1.0 Size: 2228b
 */
#pragma scheduling off
void dll_199_update(int obj)
{
    short *state;
    char *player;
    int queue;
    int *res;
    char *found;
    f32 dist;
    int flags;
    int msg;
    int param;
    f32 dz;
    u32 n;
    int delta;

    state = *(short **)(obj + 0xb8);
    player = Obj_GetPlayerObject();
    dist = lbl_803E515C;
    *(f32 *)(obj + 0x18) = *(f32 *)(obj + 0xc);
    *(f32 *)(obj + 0x1c) = *(f32 *)(obj + 0x10);
    *(f32 *)(obj + 0x20) = *(f32 *)(obj + 0x14);
    queue = *(int *)(obj + 0xb8);
    flags = 0;
    while (ObjMsg_Pop(obj, &msg, &param, &flags) != 0) {
        switch (msg) {
        case 0x30005:
            *(s16 *)(queue + 6) = -3;
            break;
        case 0x30006:
            *(s16 *)(queue + 6) = 0x10;
            break;
        }
    }
    GameBit_Set(0x127, 1);
    delta = state[3];
    if (delta != 0) {
        state[2] += delta;
        if (state[2] <= 0xc) {
            state[2] = 0xc;
            state[3] = 0;
        }
        else if (state[2] >= 0x46) {
            state[2] = 0x46;
            state[3] = 0;
        }
        (**(void (**)(int, int))(*gTitleMenuControlInterface + 0x38))(2, state[2] & 0xff);
    }
    delta = state[5];
    if (delta != 0) {
        state[4] += delta;
        if ((state[4] <= 1) && (state[5] <= 0)) {
            state[4] = 1;
            state[5] = 0;
        }
        else if ((state[4] >= 0x46) && (state[5] >= 0)) {
            state[4] = 0x46;
            state[5] = 0;
        }
        (**(void (**)(int, int))(*gTitleMenuControlInterface + 0x38))(3, state[4] & 0xff);
    }
    if (state[1] > 0) {
        state[1] -= framesThisStep;
        if (state[1] <= 0) {
            state[1] = 0;
            if (*(u8 *)((char *)state + 0x12) == 0) {
                (**(void (**)(int, int, int, int, int))(*gTitleMenuControlInterface + 0x18))(3, 0x2c, 0x50, state[4], 0);
                *(u8 *)((char *)state + 0x12) = 1;
            }
        }
    }
    else {
        found = ObjGroup_FindNearestObject(0xe, player, &dist);
        if ((found != 0) && (dist < lbl_803E5160) && (dist > lbl_803E5164)) {
            dz = *(f32 *)(found + 0x14) - *(f32 *)(player + 0x14);
            if (dz <= lbl_803E5168) {
                if (dz < lbl_803E5168) {
                    dz = dz * lbl_803E516C;
                }
                if (state[4] != 0x1e) {
                    state[4] = 0x1e;
                }
                n = (int)((f32)state[4] * ((dz - lbl_803E5164) / lbl_803E5170));
                if ((s16)n < 1) {
                    n = 1;
                }
                (**(void (**)(int, int))(*gTitleMenuControlInterface + 0x38))(3, n & 0xff);
                n = (int)((f32)state[2] * ((lbl_803E5170 - (dz - lbl_803E5164)) / lbl_803E5170));
                if ((s16)n < 1) {
                    n = 1;
                }
                (**(void (**)(int, int))(*gTitleMenuControlInterface + 0x38))(2, n & 0xff);
            }
        }
        switch (*(u8 *)((char *)state + 0xf)) {
        case 0:
            if ((GameBit_Get(0x5b5) == 0) && (GameBit_Get(0x594) != 0)) {
                GameBit_Set(0x5b5, 1);
            }
            GameBit_Set(0x5b9, 0);
            if (Vec_distance((f32 *)(obj + 0x18), (f32 *)(player + 0x18)) < (f32)state[0]) {
                *(u8 *)((char *)state + 0xf) = 1;
                GameBit_Set(0x129, 0);
                (**(void (**)(int, int, int))(*gObjectTriggerInterface + 0x48))(0, obj, 0xffffffff);
                res = Resource_Acquire(0x83, 1);
                (**(void (**)(int, int, int, int, int, int))(*res + 4))(obj, 0, 0, 1, 0xffffffff, 0);
                Resource_Release(res);
                res = Resource_Acquire(0x84, 1);
                (**(void (**)(int, int, int, int, int, int))(*res + 4))(obj, 0, 0, 1, 0xffffffff, 0);
                Resource_Release(res);
                GameBit_Set(0x126, 0);
                (**(void (**)(short *))(*gModgfxInterface + 0x20))(state + 6);
            }
            break;
        case 1:
            if (*(u8 *)((char *)state + 0x10) == 1) {
                *(u8 *)((char *)state + 0xf) = 2;
                state[1] = 0xa0;
            }
            break;
        case 2:
            if ((*(u8 *)((char *)state + 0xe) == 0) && (GameBit_Get(0x1cd) == 0)) {
                GameBit_Set(0x1cd, 1);
            }
            if (GameBit_Get(0x5b2) != 0) {
                *(u8 *)((char *)state + 0xe) += 1;
                state[1] = 100;
                if (*(u8 *)((char *)state + 0xe) == 1) {
                    (**(void (**)(int, int, int))(*gObjectTriggerInterface + 0x48))(3, obj, 0xffffffff);
                }
            }
            break;
        case 7:
            (**(void (**)(int, int, int))(*gObjectTriggerInterface + 0x48))(5, obj, 0xffffffff);
            *(u8 *)((char *)state + 0xf) = 3;
            state[1] = 0;
            state[5] = -3;
            break;
        case 8:
            (**(void (**)(int, int, int))(*gObjectTriggerInterface + 0x48))(4, obj, 0xffffffff);
            *(u8 *)((char *)state + 0xf) = 6;
            state[1] = 0;
            state[5] = -3;
            break;
        case 6:
            (**(void (**)(int, int, int, int, int))(*gTitleMenuControlInterface + 0x18))(3, 0x35, 0x50, state[4] & 0xff, 0);
            state[5] = 1;
            (**(void (**)(int, int, int))(*gObjectTriggerInterface + 0x48))(2, obj, 0xffffffff);
            dist = lbl_803E5174;
            found = ObjGroup_FindNearestObject(3, (char *)obj, &dist);
            if (found != 0) {
                Obj_FreeObject(found);
            }
            *(u8 *)((char *)state + 0xf) = 0;
            state[1] = 400;
            GameBit_Set(0x129, 1);
            GameBit_Set(0x126, 1);
            GameBit_Set(0x127, 1);
            GameBit_Set(0x5b2, 0);
            GameBit_Set(0x5b9, 1);
            res = Resource_Acquire(0x6a, 1);
            state[6] = (**(short (**)(int, int, int, int, int, int))(*res + 4))(obj, 0, 0, 0x402, 0xffffffff, 0);
            Resource_Release(res);
            GameBit_Set(0x1cd, 0);
            *(u8 *)((char *)state + 0xe) = 0;
            *(u8 *)((char *)state + 0x10) = 0;
            break;
        case 3:
            dist = lbl_803E5174;
            found = ObjGroup_FindNearestObject(3, (char *)obj, &dist);
            if (found != 0) {
                Obj_FreeObject(found);
            }
            if (GameBit_Get(0x1ce) != 0) {
                state[4] = 1;
                (**(void (**)(int, int, int, int, int))(*gTitleMenuControlInterface + 0x18))(3, 0x2c, 0x50, state[4] & 0xff, 0);
                state[5] = 1;
                GameBit_Set(0x129, 1);
                *(u8 *)((char *)state + 0xf) = 5;
            }
            else {
                GameBit_Set(0x126, 0);
                (**(void (**)(int, int, int, int, int))(*gTitleMenuControlInterface + 0x18))(3, 0x2a, 0x50, state[4] & 0xff, 0);
                state[5] = 1;
                (**(void (**)(int, int, int))(*gObjectTriggerInterface + 0x48))(1, obj, 0xffffffff);
            }
            break;
        case 4:
            if (GameBit_Get(0xfd) == 0) {
                GameBit_Set(0xfd, 1);
            }
            GameBit_Set(0x1cf, 0);
            GameBit_Set(0x127, 0);
            *(u8 *)((char *)state + 0xf) = 5;
            (**(void (**)(int, int, int, int, int))(*gTitleMenuControlInterface + 0x18))(3, 0x2c, 0x50, state[4] & 0xff, 0);
            GameBit_Set(0x1ce, 1);
            (**(void (**)(int, int))(*gMapEventInterface + 0x44))(0xb, 6);
            break;
        }
    }
}
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
extern int dll_199_SeqFn(int obj, int p2, u8 *p3);
extern void ObjMsg_AllocQueue(int obj, int n);
extern int GameBit_Set(int eventId, int value);
extern u32 GameBit_Get(int eventId);
extern int *Resource_Acquire(int id, int kind);
extern void Resource_Release(int *res);
extern int *gTitleMenuControlInterface;

/*
 * --INFO--
 *
 * Function: dll_199_init
 * EN v1.0 Address: 0x801CB634
 * EN v1.0 Size: 364b
 */
void dll_199_init(int obj, int def)
{
    short *state;
    int *res;
    short id;

    state = *(short **)(obj + 0xb8);
    *(s16 *)obj = 0;
    *state = 10;
    if (*(s16 *)(def + 0x1a) > 0) {
        *state = *(s16 *)(def + 0x1a) >> 8;
    }
    *(u8 *)((char *)state + 0xf) = 0;
    *(u8 *)(state + 8) = 0;
    state[1] = 0;
    *(u8 *)(state + 7) = 0;
    *(void **)(obj + 0xbc) = (void *)&dll_199_SeqFn;
    ObjMsg_AllocQueue(obj, 4);
    GameBit_Set(0x129, 1);
    GameBit_Set(0x1cf, 0);
    GameBit_Set(0x126, 1);
    GameBit_Set(0x127, 1);
    GameBit_Set(0x1cd, 0);
    GameBit_Set(0x1e7, 0);
    state[2] = 0xc;
    state[4] = 0x1e;
    state[1] = 200;
    (**(void (**)(int, int, int, int, int))(*gTitleMenuControlInterface + 0x18))(2, 0x2b, 0x50, 1, 0);
    state[3] = 0;
    state[5] = 0;
    *(u8 *)(state + 9) = 0;
    res = Resource_Acquire(0x6a, 1);
    id = (**(short (**)(int, int, int, int, int, int))(*res + 4))(obj, 0, 0, 0x402, 0xffffffff, 0);
    state[6] = id;
    Resource_Release(res);
}

extern byte framesThisStep;
extern u8 Obj_IsLoadingLocked(void);
extern int Obj_AllocObjectSetup(int size, int typeId);
extern char *Obj_SetupObject(int setup, int a, int b, int c, int d);
extern void Sfx_PlayFromObject(int obj, int sfx);

/*
 * --INFO--
 *
 * Function: dll_19A_update
 * EN v1.0 Address: 0x801CB7F0
 * EN v1.0 Size: 612b
 */
void dll_19A_update(int obj)
{
    int setup;
    short *state;
    int *res;
    int newObj;
    char *r;

    setup = *(int *)(obj + 0x4c);
    state = *(short **)(obj + 0xb8);
    if (GameBit_Get(0x5b9) != 0) {
        *(int *)(obj + 0xf8) = 0;
        *state = 100;
        state[1] = 0;
        *(u8 *)(obj + 0x37) = 0xff;
        *(u8 *)(obj + 0x36) = 0xff;
    }
    else {
        if ((*(int *)(obj + 0xf8) == 0) && (GameBit_Get(*(s8 *)(setup + 0x1f) + 0x1cd) != 0)) {
            res = Resource_Acquire(0x82, 1);
            (**(void (**)(int, int, int, int, int, int))(*res + 4))(obj, 0, 0, 1, 0xffffffff, 0);
            (**(void (**)(int, int, int, int, int, int))(*res + 4))(obj, 1, 0, 1, 0xffffffff, 0);
            Sfx_PlayFromObject(obj, 0xaf);
            Resource_Release(res);
            state[1] = 1;
            *(int *)(obj + 0xf8) = 1;
        }
        if (state[1] != 0) {
            *state -= state[1] * framesThisStep;
        }
        if ((*state <= 0) && (Obj_IsLoadingLocked() != 0)) {
            newObj = Obj_AllocObjectSetup(0x38, 0x2d0);
            *(f32 *)(newObj + 8) = *(f32 *)(setup + 8);
            *(f32 *)(newObj + 0xc) = *(f32 *)(setup + 0xc);
            *(f32 *)(newObj + 0x10) = *(f32 *)(setup + 0x10);
            *(u8 *)(newObj + 4) = *(u8 *)(setup + 4);
            *(u8 *)(newObj + 5) = *(u8 *)(setup + 5);
            *(u8 *)(newObj + 6) = *(u8 *)(setup + 6);
            *(u8 *)(newObj + 7) = *(u8 *)(setup + 7);
            *(u8 *)(newObj + 0x27) = 1;
            *(s16 *)(newObj + 0x18) = 0x1e7;
            *(s16 *)(newObj + 0x30) = 0xffff;
            *(s8 *)(newObj + 0x2a) = *(s16 *)obj >> 8;
            *(u8 *)(newObj + 0x2b) = 2;
            if (GameBit_Get(0x1ce) != 0) {
                *(s16 *)(newObj + 0x22) = 0x49;
            }
            else {
                *(s16 *)(newObj + 0x22) = 0xffff;
            }
            *(u8 *)(newObj + 0x29) = 0xff;
            *(s8 *)(newObj + 0x2e) = -1;
            *(u8 *)(newObj + 0x32) = *(u8 *)(setup + 0x1f);
            r = Obj_SetupObject(newObj, 5, *(s8 *)(obj + 0xac), 0xffffffff, *(int *)(obj + 0x30));
            if ((r != 0) && (*(void **)(r + 0xb8) != 0)) {
                *(u8 *)(*(int *)(r + 0xb8) + 0x404) = 0x20;
            }
            *state = 100;
            state[1] = 0;
        }
    }
}

/* Trivial 4b 0-arg blr leaves. */
void dll_199_release(void) {}
void dll_199_initialise(void) {}
void dll_19A_free(void) {}
void dll_19A_hitDetect(void) {}
void dll_19A_release(void) {}
void dll_19A_initialise(void) {}

/* 8b "li r3, N; blr" returners. */
int dll_19A_getExtraSize(void) { return 0x4; }
int dll_19A_getObjectTypeId(void) { return 0x0; }

#pragma scheduling off
#pragma peephole off
void dll_19A_init(int obj, s8 *def) {
    int *state = *(int **)((char *)obj + 0xB8);
    *(s16 *)obj = (s16)((s32)def[0x1E] << 8);
    *(int *)((char *)obj + 0xF8) = 0;
    *(s16 *)state = 100;
    *(s16 *)((char *)state + 2) = 0;
    *(u8 *)((char *)obj + 0x37) = 0xFF;
    *(u8 *)((char *)obj + 0x36) = 0xFF;
}
#pragma peephole reset
#pragma scheduling reset

/* render-with-objRenderFn_8003b8f4 pattern. */
extern f32 lbl_803E5180;
extern void objRenderFn_8003b8f4(f32);
#pragma peephole off
void dll_19A_render(int p1, int p2, int p3, int p4, int p5, s8 visible) { s32 v = visible; if (v != 0) objRenderFn_8003b8f4(lbl_803E5180); }
#pragma peephole reset
