#include "main/dll/dimmagicbridge_state.h"
#include "ghidra_import.h"
#include "main/obj_placement.h"
#include "main/effect_interfaces.h"
#include "main/game_object.h"
#include "main/dll/dimmagicbridge.h"
#include "main/mapEventTypes.h"
#include "main/objseq.h"
#include "main/resource.h"

typedef struct Dll19APlacement {
    u8 pad0[0x4 - 0x0];
    u8 unk4;
    u8 unk5;
    u8 unk6;
    u8 unk7;
    u8 pad8[0x1F - 0x8];
    s8 unk1F;
} Dll19APlacement;


typedef struct Dll19AState {
    u8 pad0[0x7 - 0x0];
    u8 unk7;
    u8 unk8;
    u8 unk9;
    u8 padA[0x10 - 0xA];
} Dll19AState;


typedef struct Dll199ObjectDef {
    u8 pad0[0x1A - 0x0];
    s16 unk1A;
    u8 pad1C[0x20 - 0x1C];
} Dll199ObjectDef;


typedef struct Dll199State {
    u8 pad0[0x2 - 0x0];
    s16 unk2;
    u8 pad4[0xE - 0x4];
    u8 unkE;
    u8 unkF;
    u8 unk10;
    u8 pad11[0x12 - 0x11];
    u8 unk12;
    u8 pad13[0x18 - 0x13];
} Dll199State;



extern u32 GameBit_Get(int eventId);
extern int GameBit_Set(int eventId, int value);
extern char *Obj_GetPlayerObject(void);
extern int ObjMsg_Pop(int obj, int *msgOut, int *paramOut, int *flagsOut);
extern char *ObjGroup_FindNearestObject(int group, char *from, f32 *distInOut);
extern void Obj_FreeObject(char *obj);
extern f32 Vec_distance(f32 *a, f32 *b);

extern int *gTitleMenuControlInterface;
extern ObjectTriggerInterface **gObjectTriggerInterface;
extern ModgfxInterface **gModgfxInterface;
extern MapEventInterface **gMapEventInterface;

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
#pragma peephole on
void dll_199_update(int obj)
{
    short *state;
    char *player;
    int queue;
    char *found;
    f32 dist;
    int flags;
    int msg;
    int param;
    f32 dz;
    u32 n;
    int delta;

    state = ((GameObject *)obj)->extra;
    player = Obj_GetPlayerObject();
    dist = lbl_803E515C;
    ((GameObject *)obj)->anim.worldPosX = ((GameObject *)obj)->anim.localPosX;
    ((GameObject *)obj)->anim.worldPosY = ((GameObject *)obj)->anim.localPosY;
    ((GameObject *)obj)->anim.worldPosZ = ((GameObject *)obj)->anim.localPosZ;
    queue = *(int *)&((GameObject *)obj)->extra;
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
            if (((Dll199State *)state)->unk12 == 0) {
                (**(void (**)(int, int, int, int, int))(*gTitleMenuControlInterface + 0x18))(3, 0x2c, 0x50, state[4], 0);
                ((Dll199State *)state)->unk12 = 1;
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
                n = (int)((f32)state[2] * ((lbl_803E5170 - (dz - lbl_803E5164)) / *(f32 *)&lbl_803E5170));
                if ((s16)n < 1) {
                    n = 1;
                }
                (**(void (**)(int, int))(*gTitleMenuControlInterface + 0x38))(2, n & 0xff);
            }
        }
        switch (((Dll199State *)state)->unkF) {
        case 0:
            if ((GameBit_Get(0x5b5) == 0) && (GameBit_Get(0x594) != 0)) {
                GameBit_Set(0x5b5, 1);
            }
            GameBit_Set(0x5b9, 0);
            if (Vec_distance((f32 *)(obj + 0x18), (f32 *)(player + 0x18)) < (f32)state[0]) {
                ((Dll199State *)state)->unkF = 1;
                GameBit_Set(0x129, 0);
                (*gObjectTriggerInterface)->runSequence(0, (void *)obj, 0xffffffff);
                {
                    int *res = Resource_Acquire(0x83, 1);
                    (**(void (**)(int, int, int, int, int, int))(*res + 4))(obj, 0, 0, 1, 0xffffffff, 0);
                    Resource_Release(res);
                }
                {
                    int *res = Resource_Acquire(0x84, 1);
                    (**(void (**)(int, int, int, int, int, int))(*res + 4))(obj, 0, 0, 1, 0xffffffff, 0);
                    Resource_Release(res);
                }
                GameBit_Set(0x126, 0);
                (*gModgfxInterface)->releaseHandle(state + 6);
            }
            break;
        case 1:
            if (((Dll199State *)state)->unk10 == 1) {
                ((Dll199State *)state)->unkF = 2;
                state[1] = 0xa0;
            }
            break;
        case 2:
            if ((((Dll199State *)state)->unkE == 0) && (GameBit_Get(0x1cd) == 0)) {
                GameBit_Set(0x1cd, 1);
            }
            if (GameBit_Get(0x5b2) != 0) {
                ((Dll199State *)state)->unkE += 1;
                state[1] = 100;
                if (((Dll199State *)state)->unkE == 1) {
                    (*gObjectTriggerInterface)->runSequence(3, (void *)obj, 0xffffffff);
                }
            }
            break;
        case 7:
            (*gObjectTriggerInterface)->runSequence(5, (void *)obj, 0xffffffff);
            ((Dll199State *)state)->unkF = 3;
            state[1] = 0;
            state[5] = -3;
            break;
        case 8:
            (*gObjectTriggerInterface)->runSequence(4, (void *)obj, 0xffffffff);
            ((Dll199State *)state)->unkF = 6;
            state[1] = 0;
            state[5] = -3;
            break;
        case 6:
            (**(void (**)(int, int, int, int, int))(*gTitleMenuControlInterface + 0x18))(3, 0x35, 0x50, state[4] & 0xff, 0);
            state[5] = 1;
            (*gObjectTriggerInterface)->runSequence(2, (void *)obj, 0xffffffff);
            dist = lbl_803E5174;
            found = ObjGroup_FindNearestObject(3, (char *)obj, &dist);
            if (found != 0) {
                Obj_FreeObject(found);
            }
            ((Dll199State *)state)->unkF = 0;
            state[1] = 400;
            GameBit_Set(0x129, 1);
            GameBit_Set(0x126, 1);
            GameBit_Set(0x127, 1);
            GameBit_Set(0x5b2, 0);
            GameBit_Set(0x5b9, 1);
            {
                int *res = Resource_Acquire(0x6a, 1);
                state[6] = (**(short (**)(int, int, int, int, int, int))(*res + 4))(obj, 0, 0, 0x402, 0xffffffff, 0);
                Resource_Release(res);
            }
            GameBit_Set(0x1cd, 0);
            ((Dll199State *)state)->unkE = 0;
            ((Dll199State *)state)->unk10 = 0;
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
                ((Dll199State *)state)->unkF = 5;
            }
            else {
                GameBit_Set(0x126, 0);
                (**(void (**)(int, int, int, int, int))(*gTitleMenuControlInterface + 0x18))(3, 0x2a, 0x50, state[4] & 0xff, 0);
                state[5] = 1;
                (*gObjectTriggerInterface)->runSequence(1, (void *)obj, 0xffffffff);
            }
            break;
        case 4:
            if (GameBit_Get(0xfd) == 0) {
                GameBit_Set(0xfd, 1);
            }
            GameBit_Set(0x1cf, 0);
            GameBit_Set(0x127, 0);
            ((Dll199State *)state)->unkF = 5;
            (**(void (**)(int, int, int, int, int))(*gTitleMenuControlInterface + 0x18))(3, 0x2c, 0x50, state[4] & 0xff, 0);
            GameBit_Set(0x1ce, 1);
            (*gMapEventInterface)->setMode(0xb, 6);
            break;
        }
    }
}

extern void ObjMsg_AllocQueue(int obj, int n);

/*
 * --INFO--
 *
 * Function: dll_199_init
 * EN v1.0 Address: 0x801CB634
 * EN v1.0 Size: 364b
 */
#pragma peephole off
void dll_199_init(int obj, int def)
{
    short *state;
    int *res;
    short id;

    state = ((GameObject *)obj)->extra;
    *(s16 *)obj = 0;
    *state = 10;
    if (((Dll199ObjectDef *)def)->unk1A > 0) {
        *state = ((Dll199ObjectDef *)def)->unk1A >> 8;
    }
    ((Dll199State *)state)->unkF = 0;
    *(u8 *)(state + 8) = 0;
    state[1] = 0;
    *(u8 *)(state + 7) = 0;
    ((GameObject *)obj)->animEventCallback = (void *)dll_199_SeqFn;
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

    setup = *(int *)&((GameObject *)obj)->anim.placementData;
    state = ((GameObject *)obj)->extra;
    if (GameBit_Get(0x5b9) != 0) {
        ((GameObject *)obj)->unkF8 = 0;
        *state = 100;
        state[1] = 0;
        *(u8 *)(obj + 0x37) = 0xff;
        ((GameObject *)obj)->anim.alpha = 0xff;
    }
    else {
        if ((((GameObject *)obj)->unkF8 == 0) && (GameBit_Get(((Dll19APlacement *)setup)->unk1F + 0x1cd) != 0)) {
            res = Resource_Acquire(0x82, 1);
            (**(void (**)(int, int, int, int, int, int))(*res + 4))(obj, 0, 0, 1, 0xffffffff, 0);
            (**(void (**)(int, int, int, int, int, int))(*res + 4))(obj, 1, 0, 1, 0xffffffff, 0);
            Sfx_PlayFromObject(obj, 0xaf);
            Resource_Release(res);
            state[1] = 1;
            ((GameObject *)obj)->unkF8 = 1;
        }
        if (state[1] != 0) {
            *state -= state[1] * framesThisStep;
        }
        if ((*state <= 0) && (Obj_IsLoadingLocked() != 0)) {
            newObj = Obj_AllocObjectSetup(0x38, 0x2d0);
            *(f32 *)(newObj + 8) = ((ObjPlacement *)setup)->posX;
            *(f32 *)(newObj + 0xc) = ((ObjPlacement *)setup)->posY;
            *(f32 *)(newObj + 0x10) = ((ObjPlacement *)setup)->posZ;
            *(u8 *)(newObj + 4) = ((Dll19APlacement *)setup)->unk4;
            *(u8 *)(newObj + 5) = ((Dll19APlacement *)setup)->unk5;
            *(u8 *)(newObj + 6) = ((Dll19APlacement *)setup)->unk6;
            *(u8 *)(newObj + 7) = ((Dll19APlacement *)setup)->unk7;
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
            {
                int linkIdx = ((Dll19APlacement *)setup)->unk1F;
                *(u8 *)(newObj + 0x32) = linkIdx;
            }
            r = Obj_SetupObject(newObj, 5, ((GameObject *)obj)->anim.mapEventSlot, 0xffffffff, *(int *)&((GameObject *)obj)->anim.parent);
            if ((r != 0) && (((GameObject *)r)->extra != 0)) {
                *(u8 *)(*(int *)&((GameObject *)r)->extra + 0x404) = 0x20;
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

void dll_19A_init(int obj, s8 *def) {
    int *state = ((GameObject *)obj)->extra;
    *(s16 *)obj = (s16)((s32)def[0x1E] << 8);
    ((GameObject *)obj)->unkF8 = 0;
    *(s16 *)state = 100;
    ((Dll199State *)state)->unk2 = 0;
    *(u8 *)((char *)obj + 0x37) = 0xFF;
    ((GameObject *)obj)->anim.alpha = 0xFF;
}

/* render-with-objRenderFn_8003b8f4 pattern. */
extern f32 lbl_803E5180;
extern void objRenderFn_8003b8f4(f32);
void dll_19A_render(int p1, int p2, int p3, int p4, int p5, s8 visible) { s32 v = visible; if (v != 0) objRenderFn_8003b8f4(lbl_803E5180); }
