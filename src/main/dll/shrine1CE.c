#include "ghidra_import.h"
#include "main/dll/shrine1CE.h"
#include "main/audio/sfx_ids.h"


#define SFXsc_gemrun1022 175

#pragma peephole off
#pragma scheduling off
extern undefined4 getLActions();
extern undefined4 FUN_80006824();
extern undefined4 FUN_80006b0c();
extern undefined4 FUN_80006b14();
extern uint FUN_80017690();
extern undefined4 FUN_80017698();
extern undefined4 FUN_8001771c();
extern uint FUN_80017a98();
extern void* FUN_80017aa4();
extern undefined4 FUN_80017ae4();
extern uint FUN_80017ae8();
extern undefined4 ObjMsg_AllocQueue();
extern undefined4 FUN_8003b818();
extern undefined4 FUN_80135814();
extern int FUN_80286834();
extern undefined4 FUN_80286880();
extern undefined4 FUN_80294d68();

extern undefined4 DAT_803dc070;
extern undefined4* DAT_803dd6d4;
extern undefined4* DAT_803dd6f0;
extern undefined4* DAT_803dd6f8;
extern undefined4* DAT_803dd6fc;
extern f64 DOUBLE_803e5e40;
extern f32 lbl_803DC074;
extern f32 lbl_803E5E24;
extern f32 lbl_803E5E28;
extern f32 lbl_803E5E2C;
extern f32 lbl_803E5E30;
extern f32 lbl_803E5E34;
extern f32 lbl_803E5E38;
extern f32 lbl_803E5E4C;

/*
 * --INFO--
 *
 * Function: dll_19B_update
 * EN v1.0 Address: 0x801CBD88
 * EN v1.0 Size: 2124b
 * EN v1.1 Address: 0x801CC33C
 * EN v1.1 Size: 2032b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
extern int Obj_GetPlayerObject(void);
extern int ObjGroup_FindNearestObject(int group, int obj, f32 *outDist);
extern int ObjMsg_Pop(int obj, int *msg, int *a, int *b);
extern uint GameBit_Get(int eventId);
extern int GameBit_Set(int eventId, int value);
extern int Resource_Acquire(int id, int mode);
extern void Resource_Release(int handle);
extern f32 Vec_distance(f32 *a, f32 *b);
extern void fn_80296B78(int obj, int a);
extern void fn_80137948(char *fmt, ...);
extern char sShrineTimeFormat[];
extern void *gTitleMenuControlInterface;
extern int *gObjectTriggerInterface;
extern int *gModgfxInterface;
extern f32 lbl_803E518C;
extern f32 lbl_803E5190;
extern f32 lbl_803E5194;
extern f32 lbl_803E5198;
extern f32 lbl_803E519C;
extern f32 lbl_803E51A0;
extern f32 timeDelta;
extern u8 framesThisStep;

#pragma peephole on
void dll_19B_update(int obj)
{
    s16 *st;
    int player;
    int near;
    s16 *st2;
    int v;
    f32 dy;
    f32 dist;
    int unk16;
    int msg;
    int unk8;
    int handle;

    st = *(s16 **)(obj + 0xb8);
    player = Obj_GetPlayerObject();
    dist = lbl_803E518C;
    st2 = *(s16 **)(obj + 0xb8);
    unk16 = 0;
    while (ObjMsg_Pop(obj, &msg, &unk8, &unk16) != 0) {
        switch (msg) {
        case 0x30005:
            st2[3] = -3;
            break;
        case 0x30006:
            st2[3] = 0x10;
            break;
        }
    }
    GameBit_Set(0x127, 1);
    if (st[3] != 0) {
        st[2] = st[2] + st[3];
        if (st[2] <= 12) {
            st[2] = 12;
            st[3] = 0;
        } else if (st[2] >= 70) {
            st[2] = 70;
            st[3] = 0;
        }
        (*(void (**)(int, int))(*(int *)gTitleMenuControlInterface + 0x38))(2, st[2] & 0xff);
    }
    if (st[5] != 0) {
        st[4] = st[4] + st[5];
        if (st[4] <= 1 && st[5] <= 0) {
            st[4] = 1;
            st[5] = 0;
        } else if (st[4] >= 70 && st[5] >= 0) {
            st[4] = 70;
            st[5] = 0;
        }
        (*(void (**)(int, int))(*(int *)gTitleMenuControlInterface + 0x38))(3, st[4] & 0xff);
    }
    if (st[1] > 0) {
        st[1] -= framesThisStep;
        if (st[1] <= 0) {
            st[1] = 0;
            if (*(u8 *)((char *)st + 0x16) == 0) {
                (*(void (**)(int, int, int, int, int))(*(int *)gTitleMenuControlInterface + 0x18))(
                    3, 0x2c, 0x50, st[4], 0);
                *(u8 *)((char *)st + 0x16) = 1;
            }
        }
    } else {
        near = ObjGroup_FindNearestObject(0xe, player, &dist);
        if (near != 0 && dist < lbl_803E5190 && dist > lbl_803E5194) {
            dy = *(f32 *)(near + 0x14) - *(f32 *)(player + 0x14);
            if (dy <= lbl_803E5198) {
                if (dy < lbl_803E5198) {
                    dy = dy * lbl_803E519C;
                }
                if (st[4] != 30) {
                    st[4] = 30;
                }
                v = (int)((f32)st[4] * ((dy - lbl_803E5194) / lbl_803E51A0));
                if ((s16)v < 1) {
                    v = 1;
                }
                (*(void (**)(int, int))(*(int *)gTitleMenuControlInterface + 0x38))(3, v & 0xff);
                v = (int)((f32)st[2] * ((lbl_803E51A0 - (dy - lbl_803E5194)) / lbl_803E51A0));
                if ((s16)v < 1) {
                    v = 1;
                }
                (*(void (**)(int, int))(*(int *)gTitleMenuControlInterface + 0x38))(2, v & 0xff);
            }
        }
        switch (*(u8 *)((char *)st + 0x13)) {
        case 0:
            if (Vec_distance((f32 *)(obj + 0x18), (f32 *)(player + 0x18)) < (f32)st[0]) {
                *(u8 *)((char *)st + 0x13) = 1;
                GameBit_Set(0x129, 0);
                (*(void (**)(int, int, int))(*(int *)gObjectTriggerInterface + 0x48))(0, obj, -1);
                handle = Resource_Acquire(0x83, 1);
                (*(s16 (**)(int, int, int, int, int, int))(*(int *)handle + 4))(obj, 1, 0, 1, -1, 0);
                Resource_Release(handle);
                handle = Resource_Acquire(0x84, 1);
                (*(s16 (**)(int, int, int, int, int, int))(*(int *)handle + 4))(obj, 0, 0, 1, -1, 0);
                Resource_Release(handle);
                GameBit_Set(0x126, 0);
                (*(void (**)(s16 *))(*(int *)gModgfxInterface + 0x20))(st + 6);
            }
            break;
        case 1:
            if (*(u8 *)((char *)st + 0x14) == 1) {
                *(u8 *)((char *)st + 0x13) = 2;
                st[1] = 160;
            }
            break;
        case 2:
            if (*(u8 *)((char *)st + 0x12) == 0 && (u32)GameBit_Get(0x1d3) == 0) {
                GameBit_Set(0x1d3, 1);
            }
            if ((u32)GameBit_Get(0x1d8) != 0) {
                *(u8 *)((char *)st + 0x12) += 1;
                GameBit_Set(0x1d8, 0);
            }
            st[7] -= (int)timeDelta;
            fn_80137948(sShrineTimeFormat, st[7]);
            if (st[7] <= 0) {
                GameBit_Set(0x1d4, 1);
                (*(void (**)(int, int, int))(*(int *)gObjectTriggerInterface + 0x48))(2, obj, -1);
                st[1] = 10;
                *(u8 *)((char *)st + 0x13) = 6;
                (*(void (**)(int, int, int, int, int))(*(int *)gTitleMenuControlInterface + 0x18))(
                    3, 0x35, 0x50, st[4] & 0xff, 0);
                st[5] = 1;
                GameBit_Set(0x1d3, 0);
            } else if (*(u8 *)((char *)st + 0x12) == 1) {
                *(u8 *)((char *)st + 0x13) = 3;
                st[1] = 200;
                st[5] = -3;
            }
            break;
        case 3:
            if ((u32)GameBit_Get(0x1d1) != 0) {
                st[4] = 1;
                (*(void (**)(int, int, int, int, int))(*(int *)gTitleMenuControlInterface + 0x18))(
                    3, 0x2c, 0x50, st[4] & 0xff, 0);
                st[5] = 1;
                GameBit_Set(0x129, 1);
                *(u8 *)((char *)st + 0x13) = 5;
            } else {
                fn_80296B78(player, -1);
                GameBit_Set(0x126, 0);
                (*(void (**)(int, int, int, int, int))(*(int *)gTitleMenuControlInterface + 0x18))(
                    3, 0x2a, 0x50, st[4] & 0xff, 0);
                st[5] = 1;
                (*(void (**)(int, int, int))(*(int *)gObjectTriggerInterface + 0x48))(1, obj, -1);
                *(u8 *)((char *)st + 0x13) = 4;
            }
            break;
        case 4:
            if ((u32)GameBit_Get(0xfd) == 0) {
                GameBit_Set(0xfd, 1);
            }
            GameBit_Set(0x1d2, 0);
            GameBit_Set(0x127, 0);
            *(u8 *)((char *)st + 0x13) = 5;
            (*(void (**)(int, int, int, int, int))(*(int *)gTitleMenuControlInterface + 0x18))(
                3, 0x2c, 0x50, st[4] & 0xff, 0);
            break;
        case 6:
            *(u8 *)((char *)st + 0x13) = 0;
            *(u8 *)((char *)st + 0x14) = 0;
            st[1] = 400;
            GameBit_Set(0x129, 1);
            GameBit_Set(0x126, 1);
            GameBit_Set(0x127, 1);
            handle = Resource_Acquire(0x6a, 1);
            st[6] = (*(s16 (**)(int, int, int, int, int, int))(*(int *)handle + 4))(obj, 2, 0, 0x402, -1, 0);
            Resource_Release(handle);
            GameBit_Set(0x1d8, 0);
            *(u8 *)((char *)st + 0x12) = 0;
            st[7] = 4000;
            GameBit_Set(0x1d4, 0);
            break;
        }
    }
}


/* Trivial 4b 0-arg blr leaves. */
void dll_19B_release(void) {}
void dll_19B_initialise(void) {}
void dll_19C_free(void) {}
void dll_19C_hitDetect(void) {}
void dll_19C_release(void) {}
void dll_19C_initialise(void) {}
void dll_19D_render(void) {}
void dll_19D_release(void) {}
void dll_19D_initialise(void) {}

/* 8b "li r3, N; blr" returners. */
int dll_19C_getExtraSize(void) { return 0x8; }
int dll_19C_getObjectTypeId(void) { return 0x0; }
int dll_19D_getExtraSize(void) { return 0x38; }
int dll_19D_getObjectTypeId(void) { return 0x0; }
int dll_19E_getExtraSize(void) { return 0x10; }
int dll_19E_getObjectTypeId(void) { return 0x1; }

/* render-with-objRenderFn_8003b8f4 pattern. */
extern f32 lbl_803E51B0;
extern void objRenderFn_8003b8f4(f32);
#pragma peephole off
void dll_19C_render(int p1, int p2, int p3, int p4, int p5, s8 visible) { s32 v = visible; if (v != 0) objRenderFn_8003b8f4(lbl_803E51B0); }
#pragma peephole reset

/* Stubs to align function set with v1.0 asm. */
extern u8 framesThisStep;
extern f32 timeDelta;
extern u8 Obj_IsLoadingLocked(void);
extern void* Obj_AllocObjectSetup(int size, int type);
extern int* Obj_SetupObject(void* setup, int a, int b, int c, void* d);
extern void ObjHits_ClearHitVolumes(int obj);
extern void Obj_FreeObject(int obj);
extern void Sfx_PlayFromObject(int obj, int sfx);
extern int Resource_Acquire(int id, int mode);
extern void Resource_Release(int handle);
extern f32 lbl_803E51B4;

#pragma scheduling off
#pragma peephole off
void dll_19C_update(int *obj) {
    extern uint GameBit_Get(int);
    u8 *def;
    u8 *sub;
    int res;
    void *setup;

    def = *(u8**)((char*)obj + 0x4c);
    sub = *(u8**)((char*)obj + 0xb8);
    if (*(int*)((char*)obj + 0xf8) != 0) {
        if (GameBit_Get(0x1d4) != 0) {
            *(int*)((char*)obj + 0xf8) = 0;
        }
    }
    if (*(int*)((char*)obj + 0xf8) == 0) {
        if (GameBit_Get(0x1d3) != 0) {
            res = Resource_Acquire(0x82, 1);
            ((void(*)(int*, int, int, int, int, int))((void**)*(int*)res)[1])(obj, 0, 0, 1, -1, 0);
            ((void(*)(int*, int, int, int, int, int))((void**)*(int*)res)[1])(obj, 1, 0, 1, -1, 0);
            Sfx_PlayFromObject(0, SFXsc_gemrun1022);
            Resource_Release(res);
            *(s16*)(sub + 6) = 1;
            *(int*)((char*)obj + 0xf8) = 1;
        }
    }
    if (*(s16*)(sub + 6) != 0) {
        *(s16*)(sub + 4) = (s16)(*(s16*)(sub + 4) - *(s16*)(sub + 6) * framesThisStep);
    }
    if (*(s16*)(sub + 4) <= 0 && (s8)def[0x1f] == 0 && (u8)Obj_IsLoadingLocked() != 0) {
        setup = Obj_AllocObjectSetup(0x18, 0x248);
        *(f32*)((char*)setup + 8) = *(f32*)(def + 8);
        *(f32*)((char*)setup + 0xc) = lbl_803E51B4 + *(f32*)(def + 0xc);
        *(f32*)((char*)setup + 0x10) = *(f32*)(def + 0x10);
        *(s16*)setup = 0x248;
        *(int*)((char*)setup + 0x14) = -1;
        *(u8*)((char*)setup + 4) = def[4];
        *(u8*)((char*)setup + 5) = def[5];
        *(u8*)((char*)setup + 6) = def[6];
        *(u8*)((char*)setup + 7) = def[7];
        Obj_SetupObject(setup, 5, *(s8*)((char*)obj + 0xac), -1, *(void**)((char*)obj + 0x30));
        *(s16*)(sub + 4) = 0x64;
        *(s16*)(sub + 6) = 0;
    }
}
#pragma peephole reset
#pragma scheduling reset

extern void dll_19B_SeqFn(int p1, int p2, void *p3);
extern int GameBit_Set(int eventId, int value);
extern void *gTitleMenuControlInterface;

#pragma scheduling off
#pragma peephole off
void dll_19B_init(u8 *obj, u8 *params) {
    register u8 *sub;
    int res;

    sub = *(u8**)(obj + 0xb8);
    *(s16*)obj = 0;
    *(s16*)sub = 0xa;
    if (*(s16*)(params + 0x1a) > 0) {
        *(s16*)sub = (s16)(*(s16*)(params + 0x1a) >> 8);
    }
    sub[0x13] = 0;
    sub[0x14] = 0;
    *(s16*)(sub + 2) = 0;
    sub[0x12] = 0;
    *(void**)(obj + 0xbc) = (void*)&dll_19B_SeqFn;
    ObjMsg_AllocQueue(obj, 4);
    GameBit_Set(0x129, 1);
    GameBit_Set(0x1d2, 0);
    GameBit_Set(0x126, 1);
    GameBit_Set(0x127, 1);
    GameBit_Set(0x2d, 1);
    GameBit_Set(0x40, 1);
    GameBit_Set(0x1d7, 1);
    GameBit_Set(0x1d8, 0);
    *(s16*)(sub + 4) = 0xc;
    *(s16*)(sub + 8) = 0x1e;
    *(s16*)(sub + 2) = 0xc8;
    ((void(*)(int, int, int, int, int))((void**)*(void**)gTitleMenuControlInterface)[6])(2, 0x2b, 0x50, 1, 0);
    *(s16*)(sub + 6) = 0;
    *(s16*)(sub + 0xa) = 0;
    sub[0x16] = 0;
    *(s16*)(sub + 0x10) = 0xc8;
    *(s16*)(sub + 0xe) = 0xfa0;
    res = Resource_Acquire(0x6a, 1);
    *(s16*)(sub + 0xc) = ((s16(*)(u8*, int, int, int, int, int))((void**)*(int*)res)[1])(obj, 1, 0, 0x402, -1, 0);
    Resource_Release(res);
    *(f32*)(obj + 0x18) = *(f32*)(obj + 0xc);
    *(f32*)(obj + 0x1c) = *(f32*)(obj + 0x10);
    *(f32*)(obj + 0x20) = *(f32*)(obj + 0x14);
}
#pragma peephole reset
#pragma scheduling reset

extern undefined4 *gExpgfxInterface;

/*
 * Function: dll_19C_init
 * EN v1.0 Address: 0x801CC950
 * EN v1.0 Size: 64b
 */
#pragma scheduling off
#pragma peephole off
void dll_19C_init(int obj, u8 *initData)
{
    register int self = obj;
    register int state = *(int *)(self + 0xb8);
    *(short *)self = (short)((int)(signed char)initData[0x1e] << 8);
    *(int *)(self + 0xf8) = 0;
    *(short *)(state + 4) = 0x64;
    *(short *)(state + 6) = 0;
    *(int *)state = 0;
    *(u8 *)(self + 0x37) = 0xff;
    *(u8 *)(self + 0x36) = 0xff;
}
#pragma peephole reset
#pragma scheduling reset

/*
 * Function: dll_19D_free
 * EN v1.0 Address: 0x801CC9A8
 * EN v1.0 Size: 132b
 */
#pragma scheduling off
#pragma peephole off
void dll_19D_free(int obj)
{
    register int self = obj;
    register int state = *(int *)(self + 0xb8);
    if ((*(u8 *)(state + 0x36) & 2) == 0) {
        getLActions(self, self, 1, 0, 0, 0);
        *(u8 *)(state + 0x36) = (u8)((u32)*(u8 *)(state + 0x36) | 0x2);
    }
    (*(void (**)(int))((char *)*(int *)gExpgfxInterface + 0x18))(self);
}
#pragma peephole reset
#pragma scheduling reset

extern int ObjHits_SetHitVolumeSlot(int obj, int volumeIdx, int hitType, int extra);

/*
 * Function: dll_19D_init
 * EN v1.0 Address: 0x801CCECC
 * EN v1.0 Size: 208b
 */
#pragma scheduling off
#pragma peephole off
void dll_19D_init(int obj)
{
    register int self = obj;
    register int state2 = *(int *)(self + 0x4c);
    int slot;

    if ((int)(signed char)*(u8 *)(state2 + 0x19) != 0) {
        slot = 3;
    } else {
        slot = 1;
    }
    ObjHits_SetHitVolumeSlot(self, 0xe, slot, 0);

    if ((int)(signed char)*(u8 *)(state2 + 0x19) == 1) {
        getLActions(self, self, 0x203, 0, 0, 0);
    } else if ((int)(signed char)*(u8 *)(state2 + 0x19) == 2) {
        getLActions(self, self, 0x204, 0, 0, 0);
    } else {
        getLActions(self, self, 0x201, 0, 0, 0);
    }
}
#pragma peephole reset
#pragma scheduling reset

extern undefined4 *gPartfxInterface;
extern f32 lbl_803E51B8;
extern f64 lbl_803E51C0;

/*
 * Function: dll_19D_hitDetect
 * EN v1.0 Address: 0x801CCA30
 * EN v1.0 Size: 276b
 */
#pragma scheduling off
#pragma peephole off
void dll_19D_hitDetect(int obj)
{
    register int self = obj;
    register int state = *(int *)(self + 0xb8);
    int state2 = *(int *)(self + 0x4c);
    float vec[6];
    int linkObj;
    void *linkSubObj;

    vec[3] = lbl_803E51B8;
    vec[4] = lbl_803E51B8;
    vec[5] = lbl_803E51B8;
    vec[2] = (float)(int)(s8)*(u8 *)(state2 + 0x19);

    linkObj = *(int *)(self + 0x54);
    linkSubObj = *(void **)(linkObj + 0x50);
    if (linkSubObj == 0) return;
    if (*(short *)((u8 *)linkSubObj + 0x46) == 0x248) return;

    (*(code *)((char *)*(int *)gPartfxInterface + 0x8))(self, 0x2a0, vec, 1, -1, 0);
    (*(code *)((char *)*(int *)gPartfxInterface + 0x8))(self, 0x2a0, vec, 1, -1, 0);
    (*(code *)((char *)*(int *)gPartfxInterface + 0x8))(self, 0x2a0, vec, 1, -1, 0);
    *(short *)(state + 0x32) = 0x32;
}
#pragma peephole reset
#pragma scheduling reset

/*
 * Function: dll_19D_update
 * EN v1.0 Address: 0x801CCB44
 * EN v1.0 Size: 904b
 */
#pragma scheduling off
#pragma peephole off
void dll_19D_update(int obj)
{
    register int self = obj;
    register int state = *(int *)(self + 0xb8);
    int def = *(int *)(self + 0x4c);
    int linkObj;
    float vec[6];
    int lifetime;
    s16 timer;
    u32 frames;
    f32 zero;

    vec[3] = lbl_803E51B8;
    vec[4] = lbl_803E51B8;
    vec[5] = lbl_803E51B8;
    vec[2] = (float)(int)(s8)*(u8 *)(def + 0x19);

    if ((*(u8 *)(state + 0x36) & 1) == 0) {
        *(f32 *)(state + 0x8) = *(f32 *)(self + 0xc);
        *(f32 *)(state + 0xc) = *(f32 *)(self + 0x10);
        *(f32 *)(state + 0x10) = *(f32 *)(self + 0x14);
        *(u8 *)(state + 0x36) = (u8)((u32)*(u8 *)(state + 0x36) | 1);
    }

    linkObj = *(int *)(self + 0x54);
    if (*(s8 *)(linkObj + 0xad) != 0) {
        Sfx_PlayFromObject(self, SFXsc_mpick1_b);
        (*(code *)((char *)*(int *)gPartfxInterface + 0x8))(self, 0x2a0, vec, 1, -1, 0);
        (*(code *)((char *)*(int *)gPartfxInterface + 0x8))(self, 0x2a0, vec, 1, -1, 0);
        (*(code *)((char *)*(int *)gPartfxInterface + 0x8))(self, 0x2a0, vec, 1, -1, 0);
        *(s16 *)(state + 0x32) = 0x32;
    }

    if (*(s16 *)(state + 0x32) != 0) {
        if ((*(u8 *)(state + 0x36) & 2) == 0) {
            getLActions(self, self, 1, 0, 0, 0);
            *(u8 *)(state + 0x36) = (u8)((u32)*(u8 *)(state + 0x36) | 2);
        }
        zero = lbl_803E51B8;
        *(f32 *)(self + 0x24) = zero;
        *(f32 *)(self + 0x28) = zero;
        *(f32 *)(self + 0x2c) = zero;
        ObjHits_ClearHitVolumes(self);
        *(s16 *)(state + 0x32) -= 1;
        if (*(s16 *)(state + 0x32) <= 0) {
            Obj_FreeObject(self);
        }
    } else {
        *(f32 *)(self + 0x80) = *(f32 *)(self + 0xc);
        *(f32 *)(self + 0x84) = *(f32 *)(self + 0x10);
        *(f32 *)(self + 0x88) = *(f32 *)(self + 0x14);

        *(s16 *)(self + 0x0) = (s16)(*(s16 *)(self + 0x0) + *(s16 *)(state + 0x2e) * (u16)framesThisStep);
        *(s16 *)(self + 0x4) = (s16)(*(s16 *)(self + 0x4) + *(s16 *)(state + 0x2c) * (u16)framesThisStep);
        (*(code *)((char *)*(int *)gPartfxInterface + 0x8))(self, 0x29d, vec, 4, -1, 0);

        if ((*(s16 *)(state + 0x30) -= (u16)framesThisStep) <= 0) {
            (*(code *)((char *)*(int *)gPartfxInterface + 0x8))(self, 0x29e, vec, 4, -1, 0);
            (*(code *)((char *)*(int *)gPartfxInterface + 0x8))(self, 0x29f, vec, 4, -1, 0);
            (*(code *)((char *)*(int *)gPartfxInterface + 0x8))(self, 0x2a1, vec, 4, -1, 0);
            *(s16 *)(state + 0x30) = 0x32;
        }

        *(f32 *)(state + 0x8) = *(f32 *)(self + 0x24) * timeDelta + *(f32 *)(state + 0x8);
        *(f32 *)(state + 0xc) = *(f32 *)(self + 0x28) * timeDelta + *(f32 *)(state + 0xc);
        *(f32 *)(state + 0x10) = *(f32 *)(self + 0x2c) * timeDelta + *(f32 *)(state + 0x10);
        *(u16 *)(state + 0x34) = *(u16 *)(state + 0x34) + (u16)framesThisStep * 0x5dc;
        *(f32 *)(self + 0xc) = *(f32 *)(state + 0x8);
        *(f32 *)(self + 0x10) = *(f32 *)(state + 0xc);
        *(f32 *)(self + 0x14) = *(f32 *)(state + 0x10);

        frames = framesThisStep;
        lifetime = *(int *)(self + 0xf4);
        *(int *)(self + 0xf4) = lifetime - frames;
        if ((int)(lifetime - frames) < 0) {
            Obj_FreeObject(self);
        }
    }
}
#pragma peephole reset
#pragma scheduling reset
