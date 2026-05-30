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

/*
 * --INFO--
 *
 * Function: nw_tricky_update
 * EN v1.0 Address: 0x801CF7E8
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x801CFAC0
 * EN v1.1 Size: 668b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void nw_tricky_update(undefined2 *param_1,int param_2,int param_3)
{
}

/*
 * --INFO--
 *
 * Function: FUN_801cf7ec
 * EN v1.0 Address: 0x801CF7EC
 * EN v1.0 Size: 44b
 * EN v1.1 Address: 0x801CFD5C
 * EN v1.1 Size: 52b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_801cf7ec(void)
{
  int iVar1;
  
  iVar1 = FUN_80017a90();
  FUN_8000680c(iVar1,0x10);
  return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_801cf818
 * EN v1.0 Address: 0x801CF818
 * EN v1.0 Size: 40b
 * EN v1.1 Address: 0x801CFD90
 * EN v1.1 Size: 40b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801cf818(void)
{
  GameBit_Set(0x4e4,1);
  return;
}


/* Trivial 4b 0-arg blr leaves. */
void nw_animice_render(void) {}
void nw_animice_hitDetect(void) {}
void nw_animice_update(void) {}
void nw_animice_release(void) {}
void nw_animice_initialise(void) {}
void nw_ice_render(void) {}

/* 8b "li r3, N; blr" returners. */
int fn_801CFB24(void) { return 0x0; }
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

extern void fn_801CF78C(void);
#pragma scheduling off
#pragma peephole off
void nw_tricky_init(int *obj) {
    *(void **)((char *)obj + 0xbc) = (void *)fn_801CF78C;
    *(u16 *)((char *)obj + 0xb0) = (u16)(*(u16 *)((char *)obj + 0xb0) | 0x6000);
}
void nw_animice_init(int *obj) {
    *(void **)((char *)obj + 0xbc) = (void *)fn_801CFB24;
    *(u16 *)((char *)obj + 0xb0) = (u16)(*(u16 *)((char *)obj + 0xb0) | 0x6000);
    ObjGroup_AddObject(obj, 0x3d);
}
#pragma peephole reset
#pragma scheduling reset
