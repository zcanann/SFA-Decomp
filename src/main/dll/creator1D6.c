#include "ghidra_import.h"
#include "main/dll/creator1D6.h"

extern undefined4 FUN_8000680c();
extern undefined4 GameBit_Set(int eventId, int value);
extern int FUN_80017a90();
extern undefined4 ObjGroup_AddObject();
extern int ObjGroup_FindNearestObjectForObject(int group, int *obj, f32 *maxDistance);
extern int **ObjGroup_GetObjects(int group, int *countOut);
extern void ObjHits_DisableObject(int *obj);
extern void ObjHits_EnableObject(int *obj);
extern int Obj_GetPlayerObject(void);
extern void fn_80296D20(int playerObj, int *obj);
extern undefined4 FUN_801ce244();

extern undefined4 DAT_80327428;
extern undefined4 DAT_80327458;
extern undefined4* DAT_803dd6e8;
extern undefined4* DAT_803dd71c;
extern undefined4* DAT_803dd728;
extern undefined4 DAT_803e5ea0;
extern f32 lbl_803E5EE4;
extern f32 lbl_803E5EEC;
extern f32 lbl_803E5EF0;
extern f32 lbl_803E5270;
extern f32 lbl_803E5274;

typedef struct NwIceState {
    int *linkedObj;
} NwIceState;

extern u32 GameBit_Get(int eventId);
extern int *getTrickyObject(void);
extern void fn_8014C66C(int *obj, int *target);
extern f32 fn_8014C5D0(int *obj);
extern int *ObjList_FindObjectById(int objId);
extern f32 vec3f_distanceSquared(f32 *a, f32 *b);
extern void fn_80138920(int *obj, int a, int b);
extern f32 timeDelta;
extern const f32 lbl_803E5260;
extern f32 lbl_803E5264;
extern f32 lbl_803E5268;
extern char *gMapEventInterface;
extern int lbl_802C23E8[];

typedef struct NwTrickyIds {
    int ids[3];
} NwTrickyIds;

typedef struct NwObjPos {
    u8 pad[0x18];
    f32 pos[3];
} NwObjPos;

/*
 * --INFO--
 *
 * Function: nw_tricky_update
 * EN v1.0 Address: 0x801CF7E8
 * EN v1.0 Size: 796b
 * EN v1.1 Address: 0x801CFAC0
 * EN v1.1 Size: 668b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off
#pragma opt_loop_invariants off
void nw_tricky_update(int *obj)
{
    int count;
    NwTrickyIds ids;
    char *state;
    int *tricky;
    int *player;
    int **objects;
    int **scan;
    int i;
    int *ip;
    int *found;
    f32 dPlayer;
    f32 t;

    state = *(char **)((char *)obj + 0xb8);
    tricky = getTrickyObject();
    player = (int *)Obj_GetPlayerObject();
    ids = *(NwTrickyIds *)lbl_802C23E8;

    if (tricky == NULL) {
        return;
    }

    switch (*(u8 *)state) {
    case 0:
        if (GameBit_Get(0xd11)) {
            objects = ObjGroup_GetObjects(3, &count);
            for (i = 0, scan = objects; i < count; scan++, i++) {
                if (*(s16 *)((char *)*scan + 0x46) == 0x13a) {
                    fn_8014C66C(*scan, player);
                }
            }
            GameBit_Set(0x4e4, 1);
            *(u8 *)state = 1;
        } else {
            if (GameBit_Get(0x544)) {
                if (!(*(u8 (**)(int *))(*(char **)*(char **)((char *)tricky + 0x68) + 0x40))(tricky)) {
                    GameBit_Set(0x4e4, 0);
                    *(f32 *)(state + 4) = lbl_803E5260;
                }

                for (i = 0, ip = ids.ids; i < 3; ip++, i++) {
                    found = ObjList_FindObjectById(*ip);
                    if (found != NULL && fn_8014C5D0(found) > lbl_803E5260) {
                        (*(void (**)(int *, int, int *))(*(char **)*(char **)((char *)tricky + 0x68) + 0x34))(tricky, 1, found);
                        break;
                    }
                }

                *(f32 *)(state + 4) += timeDelta;
                t = *(f32 *)(state + 4);
                if (t >= lbl_803E5264) {
                    *(f32 *)(state + 4) = t - lbl_803E5264;
                    fn_80138920(tricky, 0x152, 0x1000);
                }
            }

            objects = ObjGroup_GetObjects(3, &count);
            for (i = 0, scan = objects; i < count; scan++, i++) {
                if (*(s16 *)((char *)*scan + 0x46) == 0x13a) {
                    dPlayer = vec3f_distanceSquared(((NwObjPos *)*scan)->pos, ((NwObjPos *)player)->pos);
                    if (vec3f_distanceSquared(((NwObjPos *)*scan)->pos, ((NwObjPos *)tricky)->pos) < dPlayer) {
                        fn_8014C66C(*scan, tricky);
                    } else {
                        fn_8014C66C(*scan, player);
                    }
                }
            }
        }
        break;
    case 1:
        if (!(*(u16 *)((char *)tricky + 0xb0) & 0x1000)) {
            *(f32 *)(state + 4) += timeDelta;
        }
        if (GameBit_Get(0x4e3) == 1) {
            if (*(*(u8 *(**)(void))(*(char **)gMapEventInterface + 0x94))() >= 4) {
                GameBit_Set(0x4e3, 0xff);
            }
        }
        t = *(f32 *)(state + 4);
        if (t >= lbl_803E5268) {
            *(f32 *)(state + 4) = t - lbl_803E5268;
            if (GameBit_Get(0x4e3) == 0xff) {
                if (*(*(u8 *(**)(void))(*(char **)gMapEventInterface + 0x94))() < 4) {
                    GameBit_Set(0x4e3, 1);
                }
            }
        }
        break;
    }
}
#pragma opt_loop_invariants reset
#pragma peephole reset
#pragma scheduling reset


/* Trivial 4b 0-arg blr leaves. */
void nw_animice_render(void) {}
void nw_animice_hitDetect(void) {}
void nw_animice_update(void) {}
void nw_animice_release(void) {}
void nw_animice_initialise(void) {}
void nw_ice_render(void) {}

/* 8b "li r3, N; blr" returners. */
int nw_animice_SeqFn(void) { return 0x0; }
int nw_animice_getExtraSize(void) { return 0x0; }
int nw_animice_getObjectTypeId(void) { return 0x0; }
int nw_ice_getExtraSize(void) { return 0x4; }

/* ObjGroup_RemoveObject(x, N) wrappers. */
#pragma scheduling off
#pragma peephole off
void nw_animice_free(int x) { ObjGroup_RemoveObject(x, 0x3d); }
void nw_ice_free(int x) { ObjGroup_RemoveObject(x, 0x3c); }
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void nw_ice_update(int *obj) {
    NwIceState *state;
    int *setup;
    int i;
    int **scan;
    int **objects;
    int *candidate;
    int count;
    f32 nearestDist;

    nearestDist = lbl_803E5270;
    state = *(NwIceState **)((char *)obj + 0xb8);
    if (state->linkedObj != NULL) {
        *(f32 *)((char *)obj + 0xc) = *(f32 *)((char *)state->linkedObj + 0xc);
        *(f32 *)((char *)obj + 0x10) = *(f32 *)((char *)state->linkedObj + 0x10);
        *(f32 *)((char *)obj + 0x14) = *(f32 *)((char *)state->linkedObj + 0x14);
        *(s16 *)obj = *(s16 *)state->linkedObj;
        ObjGroup_FindNearestObjectForObject(0x3c, obj, &nearestDist);

        if (*(u8 *)((char *)state->linkedObj + 0x36) < 0xc0) {
            ObjHits_DisableObject(obj);
            fn_80296D20(Obj_GetPlayerObject(), obj);
        } else {
            ObjHits_EnableObject(obj);
        }

        if ((*(u8 *)((char *)state->linkedObj + 0x36) < 0xc0) || (nearestDist < lbl_803E5274)) {
            *(u16 *)((char *)obj + 0xb0) = (u16)(*(u16 *)((char *)obj + 0xb0) | 0x100);
        } else {
            *(u16 *)((char *)obj + 0xb0) = (u16)(*(u16 *)((char *)obj + 0xb0) & ~0x100);
        }
    } else {
        objects = ObjGroup_GetObjects(0x3d, &count);
        setup = *(int **)((char *)obj + 0x4c);
        scan = objects;
        for (i = 0; i < count; scan++, i++) {
            candidate = *scan;
            if ((obj != candidate) &&
                (*(u8 *)((char *)setup + 0x1b) ==
                 *(u8 *)((char *)*(int **)((char *)candidate + 0x4c) + 0x1b))) {
                state->linkedObj = objects[i];
                break;
            }
        }
    }
}
#pragma peephole reset
#pragma scheduling reset

/* call(x, N) wrappers. */
#pragma scheduling off
#pragma peephole off
void nw_ice_init(int x) { ObjGroup_AddObject(x, 0x3c); }
#pragma peephole reset
#pragma scheduling reset

extern void nw_tricky_SeqFn(void);
#pragma scheduling off
#pragma peephole off
void nw_tricky_init(int *obj) {
    *(void **)((char *)obj + 0xbc) = (void *)nw_tricky_SeqFn;
    *(u16 *)((char *)obj + 0xb0) = (u16)(*(u16 *)((char *)obj + 0xb0) | 0x6000);
}
void nw_animice_init(int *obj) {
    *(void **)((char *)obj + 0xbc) = (void *)nw_animice_SeqFn;
    *(u16 *)((char *)obj + 0xb0) = (u16)(*(u16 *)((char *)obj + 0xb0) | 0x6000);
    ObjGroup_AddObject(obj, 0x3d);
}
#pragma peephole reset
#pragma scheduling reset
