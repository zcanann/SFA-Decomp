#include "ghidra_import.h"
#include "main/dll/WC/WCpressureSwitch.h"


#pragma peephole off
#pragma scheduling off
extern uint GameBit_Get(int eventId);
extern undefined8 GameBit_Set(int eventId, int value);
extern u32 randomGetRange(int min, int max);
extern void getLActions(int obj, int obj2, int action, int p4, int p5, int p6);
extern void* FUN_80017aa4();
extern int FUN_80017ae4();
extern uint FUN_80017ae8();
extern void* ObjGroup_GetObjects();
extern void Resource_Release(void *resource);
extern void objRenderFn_8003b8f4(void *obj, int p2, int p3, int p4, int p5, f32 scale);
extern undefined4 FUN_80286840();
extern undefined4 FUN_8028688c();

extern undefined4 DAT_803dc070;
extern u32 lbl_803DC0F0;
extern u8 framesThisStep;
extern s8 lbl_803DDC70;
extern undefined4* DAT_803dd708;
extern undefined4 DAT_803de8e8;
extern int *gScreensInterface;
extern undefined4 *lbl_803DCA94;
extern void *lbl_803DDC74;
extern f64 DOUBLE_803e6978;
extern f32 lbl_803E5CE8;
extern f32 lbl_803E6960;
extern f32 lbl_803E6964;
extern f32 lbl_803E6968;
extern f32 lbl_803E696C;
extern f32 lbl_803E6970;
extern f32 lbl_803E6974;

typedef struct WCGalleonMapEventInterface {
    u8 pad00[0x4C];
    int (*getAnimEvent)(int mapId, int eventId);
    void (*setAnimEvent)(int mapId, int eventId, int value);
} WCGalleonMapEventInterface;

extern WCGalleonMapEventInterface **gMapEventInterface;

#define WM_GALLEON_GAMEBIT_CUTSCENE_DONE 0x429
#define WM_GALLEON_GAMEBIT_CLEAR_DOOR 0xD1
#define WM_GALLEON_COMMAND_OPENED 1
#define WM_GALLEON_COMMAND_CLEAR_LACTIONS 2
#define WM_GALLEON_COMMAND_SCREEN_FADE 3
#define WM_GALLEON_COMMAND_ACTION_12 4
#define WM_GALLEON_COMMAND_ACTION_13 5
#define WM_GALLEON_COMMAND_CLEAR_MAP_EVENTS 6
#define WM_GALLEON_COMMAND_SHOW_MODEL 7
#define WM_GALLEON_COMMAND_HIDE_MODEL 8
#define WM_GALLEON_COMMAND_ACTION_11 9
#define WM_GALLEON_ACTION_OPENED 10
#define WM_GALLEON_ACTION_11 11
#define WM_GALLEON_ACTION_12 12
#define WM_GALLEON_ACTION_13 13

#define OBJ_U8(obj, offset) (*(u8 *)((u8 *)(obj) + (offset)))
#define OBJ_S16(obj, offset) (*(s16 *)((u8 *)(obj) + (offset)))
#define OBJ_S32(obj, offset) (*(s32 *)((u8 *)(obj) + (offset)))

/*
 * --INFO--
 *
 * Function: WM_ObjCreator_update
 * EN v1.0 Address: 0x801EF3A8
 * EN v1.0 Size: 3548b
 * EN v1.1 Address: 0x801EF9E0
 * EN v1.1 Size: 2956b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
extern u8 Obj_IsLoadingLocked(void);
extern int Obj_AllocObjectSetup(int a, int b);
extern int Obj_SetupObject(int setup, int a, int b, int c, int d);
extern int *ObjGroup_GetObjects2(int group, int *countOut);
extern int *gPartfxInterface;
extern s16 lbl_803DDC68;
extern f32 lbl_803E5CC8;
extern f32 lbl_803E5CCC;
extern f32 lbl_803E5CD0;
extern f32 lbl_803E5CD4;
extern f32 lbl_803E5CD8;
extern f32 lbl_803E5CDC;

void WM_ObjCreator_update(int obj) {
    int def;
    s16 *state;
    int count;
    struct { s16 dir[3]; s16 pad; f32 pos[4]; } vec;

    def = *(int *)(obj + 0x4c);
    state = *(s16 **)(obj + 0xb8);
    if (Obj_IsLoadingLocked() != 0) {
        switch (*(s16 *)(def + 0x1a)) {
        case 0: {
            s8 ok = 0;
            if (*(int *)(obj + 0xf8) == 0) {
                int *objs;
                int k;
                ok = 1;
                if (GameBit_Get(0x78) != 0) {
                    ok = 0;
                }
                objs = ObjGroup_GetObjects2(3, &count);
                k = 0;
                while (k < count && ok) {
                    if (*(s16 *)(*objs + 0x46) == 0x139) {
                        ok = 0;
                    }
                    objs += 1;
                    k += 1;
                }
            }
            if (ok) {
                int setup = Obj_AllocObjectSetup(0x24, 0x139);
                int spawned;
                *(f32 *)(setup + 8) = *(f32 *)(def + 8);
                *(f32 *)(setup + 0xc) = *(f32 *)(def + 0xc);
                *(f32 *)(setup + 0x10) = *(f32 *)(def + 0x10);
                *(u8 *)(setup + 4) = *(u8 *)(def + 4);
                *(u8 *)(setup + 5) = *(u8 *)(def + 5);
                *(u8 *)(setup + 6) = *(u8 *)(def + 6);
                *(u8 *)(setup + 7) = *(u8 *)(def + 7);
                *(s16 *)(setup + 0x1e) = 0xffff;
                *(s16 *)(setup + 0x1a) = 2;
                *(u8 *)(setup + 0x18) = *(u8 *)(def + 0x1e);
                spawned = Obj_SetupObject(setup, 5, *(s8 *)(obj + 0xac), -1, *(int *)(obj + 0x30));
                if (spawned != 0) {
                    *(int *)(spawned + 0xf4) = 8;
                }
                *(int *)(obj + 0xf8) = 1;
            }
            break;
        }
        case 1:
            if ((GameBit_Get(state[0]) != 0 || state[0] == -1) &&
                (state[2] -= framesThisStep, state[2] <= 0)) {
                int setup = Obj_AllocObjectSetup(0x28, 0x263);
                int spawned;
                *(u8 *)(setup + 4) = 0x20;
                *(u8 *)(setup + 5) = 2;
                *(u8 *)(setup + 7) = 0xff;
                *(f32 *)(setup + 8) = *(f32 *)(obj + 0xc);
                *(f32 *)(setup + 0xc) = *(f32 *)(obj + 0x10);
                *(f32 *)(setup + 0x10) = *(f32 *)(obj + 0x14);
                *(s16 *)(setup + 0x20) = 0x50;
                *(s16 *)(setup + 0x1e) = 0x10f;
                *(s16 *)(setup + 0x22) = 0xffff;
                *(s16 *)(setup + 0x18) = randomGetRange(-500, 500) + 0x5dc;
                *(s16 *)(setup + 0x1a) = 0;
                *(s16 *)(setup + 0x1c) = randomGetRange(-500, 500) + 0x5dc;
                spawned = Obj_SetupObject(setup, 5, *(s8 *)(obj + 0xac), -1, *(int *)(obj + 0x30));
                if (spawned != 0) {
                    *(f32 *)(spawned + 0x24) = lbl_803E5CCC + (f32)(int)randomGetRange(0, 10);
                }
                state[2] = state[1] + (s16)randomGetRange(0, state[3]);
            }
            break;
        case 5:
            if ((GameBit_Get(state[0]) != 0 || state[0] == -1) &&
                (state[2] -= framesThisStep, state[2] <= 0)) {
                int setup = Obj_AllocObjectSetup(0x24, 0x275);
                int spawned;
                *(u8 *)(setup + 0x18) = randomGetRange(-0x7f, 0x7e);
                *(f32 *)(setup + 8) = *(f32 *)(obj + 0xc) + (f32)(int)randomGetRange(-100, 100);
                *(f32 *)(setup + 0xc) = *(f32 *)(obj + 0x10);
                *(f32 *)(setup + 0x10) = *(f32 *)(obj + 0x14) + (f32)(int)randomGetRange(-100, 100);
                *(s16 *)(setup + 0x1a) = 0x31;
                *(s16 *)(setup + 0x1c) = 200;
                spawned = Obj_SetupObject(setup, 5, *(s8 *)(obj + 0xac), -1, *(int *)(obj + 0x30));
                if (spawned != 0) {
                    lbl_803DDC68 += 1;
                }
                state[2] = state[1] + (s16)randomGetRange(0, state[3]);
            }
            break;
        case 8:
            if ((GameBit_Get(state[0]) != 0 || state[0] == -1) &&
                (state[2] -= framesThisStep, state[2] <= 0)) {
                int setup = Obj_AllocObjectSetup(0x38, 0x4ac);
                int spawned;
                GameBit_Set(state[0], 0);
                *(u8 *)(setup + 0x2a) = randomGetRange(-0x7f, 0x7e);
                *(f32 *)(setup + 8) = *(f32 *)(obj + 0xc);
                *(f32 *)(setup + 0xc) = *(f32 *)(obj + 0x10);
                *(f32 *)(setup + 0x10) = *(f32 *)(obj + 0x14);
                *(s16 *)(setup + 0x18) = state[0];
                *(s16 *)(setup + 0x22) = 1;
                spawned = Obj_SetupObject(setup, 5, *(s8 *)(obj + 0xac), -1, *(int *)(obj + 0x30));
                if (spawned != 0) {
                    (*(void (*)(int, int, void *, int, int, int))*(int *)(*gPartfxInterface + 8))(obj, 0x1c3, 0, 2, -1, 0);
                }
                state[2] = state[1] + (s16)randomGetRange(0, state[3]);
            }
            break;
        case 2:
            if ((GameBit_Get(state[0]) != 0 || state[0] == -1) &&
                (state[2] -= framesThisStep, state[2] <= 0)) {
                int setup = Obj_AllocObjectSetup(0x28, 0x263);
                int spawned;
                *(u8 *)(setup + 4) = 4;
                *(u8 *)(setup + 5) = 2;
                *(f32 *)(setup + 8) = *(f32 *)(def + 8);
                *(f32 *)(setup + 0xc) = *(f32 *)(def + 0xc) + (f32)(int)randomGetRange(-0x28, 0x28);
                *(f32 *)(setup + 0x10) = *(f32 *)(def + 0x10) + (f32)(int)randomGetRange(-0x28, 0x28);
                *(s16 *)(setup + 0x20) = 100;
                *(s16 *)(setup + 0x1e) = 0x10f;
                *(s16 *)(setup + 0x22) = 0xffff;
                *(s16 *)(setup + 0x18) = randomGetRange(-500, 500) + 0x5dc;
                *(s16 *)(setup + 0x1c) = randomGetRange(-500, 500) + 0x5dc;
                spawned = Obj_SetupObject(setup, 5, *(s8 *)(obj + 0xac), -1, *(int *)(obj + 0x30));
                if (spawned != 0) {
                    *(f32 *)(spawned + 0x24) = lbl_803E5CD0 - (f32)(int)randomGetRange(0, 10);
                }
                state[2] = state[1] + (s16)randomGetRange(0, state[3]);
            }
            break;
        case 4:
            if (GameBit_Get(state[0]) != 0 || state[0] == -1) {
                int n = 2;
                do {
                    int setup;
                    int spawned;
                    n -= 1;
                    setup = Obj_AllocObjectSetup(0x28, 0x263);
                    *(u8 *)(setup + 4) = 0x20;
                    *(u8 *)(setup + 5) = 2;
                    *(u8 *)(setup + 7) = 0xff;
                    *(f32 *)(setup + 8) = *(f32 *)(obj + 0xc);
                    *(f32 *)(setup + 0xc) = *(f32 *)(obj + 0x10);
                    *(f32 *)(setup + 0x10) = *(f32 *)(obj + 0x14);
                    *(s16 *)(setup + 0x20) = 400;
                    *(s16 *)(setup + 0x1e) = 0xf;
                    *(s16 *)(setup + 0x22) = 0x222;
                    *(s16 *)(setup + 0x18) = 0;
                    *(s16 *)(setup + 0x1a) = 0;
                    *(s16 *)(setup + 0x1c) = 0;
                    *(u8 *)(setup + 0x24) = 0;
                    spawned = Obj_SetupObject(setup, 5, *(s8 *)(obj + 0xac), -1, *(int *)(obj + 0x30));
                    if (spawned != 0) {
                        *(u8 *)(*(int *)(spawned + 0xb8) + 0x120) |= 2;
                        *(f32 *)(spawned + 0x24) = lbl_803E5CD4 * (f32)(int)randomGetRange(-0x23, 0x23);
                        *(f32 *)(spawned + 0x2c) = lbl_803E5CD4 * (f32)(int)randomGetRange(-0x23, 0x23);
                        vec.pos[2] = lbl_803E5CD8;
                        *(f32 *)(spawned + 0x28) = lbl_803E5CD8;
                        vec.pos[0] = lbl_803E5CC8;
                        vec.dir[0] = 0;
                        vec.dir[1] = 0;
                        vec.dir[2] = 0;
                        vec.pos[1] = *(f32 *)(spawned + 0x24);
                        vec.pos[3] = *(f32 *)(spawned + 0x2c);
                        (*(void (*)(int, int, void *, int, int, int))*(int *)(*gPartfxInterface + 8))(spawned, 0x1a7, &vec, 0x10000, -1, 0);
                    }
                } while (n != 0);
                GameBit_Set(state[0], 0);
            }
            break;
        case 7:
            if ((GameBit_Get(state[0]) != 0 || state[0] == -1) &&
                (state[2] -= framesThisStep, state[2] <= 0)) {
                int setup = Obj_AllocObjectSetup(0x28, 0x263);
                *(u8 *)(setup + 4) = 4;
                *(u8 *)(setup + 5) = 2;
                *(f32 *)(setup + 8) = *(f32 *)(def + 8) + (f32)(int)randomGetRange(-0x28, 0x28);
                *(f32 *)(setup + 0xc) = *(f32 *)(def + 0xc) + (f32)(int)randomGetRange(0, 0x14);
                *(f32 *)(setup + 0x10) = *(f32 *)(def + 0x10) + (f32)(int)randomGetRange(-0x28, 0x28);
                *(s16 *)(setup + 0x20) = 0x1c2;
                *(s16 *)(setup + 0x1e) = randomGetRange(0, 2) + 0x1cc;
                *(s16 *)(setup + 0x22) = 0xffff;
                *(s16 *)(setup + 0x18) = randomGetRange(-500, 500) + 0x5dc;
                *(s16 *)(setup + 0x1c) = randomGetRange(-500, 500) + 0x5dc;
                Obj_SetupObject(setup, 5, *(s8 *)(obj + 0xac), -1, *(int *)(obj + 0x30));
                state[2] = state[1] + (s16)randomGetRange(0, state[3]);
            }
            break;
        case 6:
            if (GameBit_Get(state[0]) != 0 || state[0] == -1) {
                int setup = Obj_AllocObjectSetup(0x24, 700);
                int n;
                *(f32 *)(setup + 8) = *(f32 *)(obj + 0xc) + (f32)(int)randomGetRange(-0x104, 0x104);
                *(f32 *)(setup + 0xc) = lbl_803E5CDC + *(f32 *)(obj + 0x10);
                *(f32 *)(setup + 0x10) = *(f32 *)(obj + 0x14) + (f32)(int)randomGetRange(-0x50, 0x50);
                *(u8 *)(setup + 4) = 0x20;
                *(u8 *)(setup + 5) = 2;
                *(u8 *)(setup + 7) = 0xff;
                *(s16 *)(setup + 0x1e) = 0xffff;
                *(s8 *)(setup + 0x18) = (u16)*(s16 *)obj >> 8;
                Obj_SetupObject(setup, 5, *(s8 *)(obj + 0xac), -1, *(int *)(obj + 0x30));
                {
                    f32 size = lbl_803E5CC8;
                    f32 yoff = lbl_803E5CDC;
                    for (n = randomGetRange(2, 5); n != 0; n -= 1) {
                        vec.pos[0] = size;
                        vec.dir[0] = 0;
                        vec.dir[1] = 0;
                        vec.dir[2] = 0;
                        vec.pos[1] = (f32)(int)randomGetRange(-200, 200);
                        vec.pos[3] = (f32)(int)randomGetRange(-0x14, 0x14);
                        vec.pos[2] = yoff;
                        (*(void (*)(int, int, void *, int, int, int))*(int *)(*gPartfxInterface + 8))(obj, 0x1a6, &vec, 0x10002, -1, 0);
                    }
                }
                GameBit_Set(state[0], 0);
            }
            break;
        }
    }
}


/* Trivial 4b 0-arg blr leaves. */
void WM_ObjCreator_release(void) {}
void WM_ObjCreator_initialise(void) {}
void WM_Galleon_hitDetect(void) {}

void WM_Galleon_free(int *obj, int leavingMap)
{
    if (*(s16 *)((char *)obj + 0x46) != 0x188) {
        u8 *state = *(u8 **)((char *)obj + 0xb8);
        if (state[0xc] != 0 && leavingMap == 0) {
            state[0xc] = 0;
        }
        if (lbl_803DDC74 != NULL) {
            Resource_Release(lbl_803DDC74);
            lbl_803DDC74 = NULL;
        }
    }
}

void WM_Galleon_render(void *obj, int p2, int p3, int p4, int p5, s8 visible)
{
    if (GameBit_Get(0x78) != 0) {
        return;
    }
    if (visible == 0) {
        return;
    }
    if (*(s16 *)((char *)obj + 0x46) == 0x188 && *(s32 *)(*(u8 **)((char *)obj + 0x30) + 0xf4) >= 7) {
        return;
    }

    objRenderFn_8003b8f4(obj, p2, p3, p4, p5, lbl_803E5CE8);

    if (lbl_803DDC70 != 0) {
        (*(void (**)(int))(*(int *)gScreensInterface + 0x4))(1);
    }
}

/* 8b "li r3, N; blr" returners. */
int WM_Galleon_getExtraSize(void) { return 0x10; }
int WM_Galleon_getObjectTypeId(void) { return 0x0; }

void WM_ObjCreator_init(int *obj, s8 *def) {
    s16 *state = *(s16**)((char*)obj + 0xb8);
    *(s16*)obj = (s16)((s32)def[0x1e] << 8);
    state[0] = *(s16*)((char*)def + 0x18);
    state[1] = *(s16*)((char*)def + 0x1c);
    state[2] = state[1];
    state[3] = (s16)(s32)def[0x1f];
}

int WM_Galleon_SeqFn(int obj, int unused, u8 *script)
{
    int i;

    lbl_803DC0F0 = framesThisStep;
    *(s16 *)(script + 0x6e) = -1;
    script[0x56] = 0;
    for (i = 0; i < (int)script[0x8b]; i++) {
        switch (script[0x81 + i]) {
        case WM_GALLEON_COMMAND_OPENED:
            OBJ_S32(obj, 0xf4) = WM_GALLEON_ACTION_OPENED;
            break;
        case WM_GALLEON_COMMAND_ACTION_11:
            OBJ_S32(obj, 0xf4) = WM_GALLEON_ACTION_11;
            break;
        case WM_GALLEON_COMMAND_ACTION_12:
            OBJ_S32(obj, 0xf4) = WM_GALLEON_ACTION_12;
            break;
        case WM_GALLEON_COMMAND_ACTION_13:
            OBJ_S32(obj, 0xf4) = WM_GALLEON_ACTION_13;
            break;
        case WM_GALLEON_COMMAND_CLEAR_MAP_EVENTS:
            (*gMapEventInterface)->setAnimEvent(OBJ_U8(obj, 0x34), 1, 0);
            (*gMapEventInterface)->setAnimEvent(OBJ_U8(obj, 0x34), 2, 0);
            (*gMapEventInterface)->setAnimEvent(OBJ_U8(obj, 0x34), 4, 0);
            GameBit_Set(WM_GALLEON_GAMEBIT_CLEAR_DOOR, 0);
            break;
        case WM_GALLEON_COMMAND_CLEAR_LACTIONS:
            getLActions(obj, obj, 0x77, 0, 0, 0);
            getLActions(obj, obj, 0x78, 0, 0, 0);
            getLActions(obj, obj, 0x80, 0, 0, 0);
            break;
        case WM_GALLEON_COMMAND_SCREEN_FADE:
            (*(void (**)(int, int, int))((u8 *)*lbl_803DCA94 + 0x14))(0, 0x1e, 0x50);
            break;
        case WM_GALLEON_COMMAND_SHOW_MODEL:
            lbl_803DDC70 = 1;
            break;
        case WM_GALLEON_COMMAND_HIDE_MODEL:
            lbl_803DDC70 = 0;
            break;
        }
    }

    if (GameBit_Get(WM_GALLEON_GAMEBIT_CUTSCENE_DONE) != 0) {
        if ((u8)(*gMapEventInterface)->getAnimEvent(OBJ_U8(obj, 0x34), 2) != 0) {
            (*gMapEventInterface)->setAnimEvent(OBJ_U8(obj, 0x34), 1, 0);
            (*gMapEventInterface)->setAnimEvent(OBJ_U8(obj, 0x34), 2, 0);
        }
    }
    return 0;
}
