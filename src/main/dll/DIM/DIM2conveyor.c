#include "ghidra_import.h"
#include "main/dll/DIM/DIM2conveyor.h"

extern uint GameBit_Get(int eventId);
extern undefined4 GameBit_Set(int eventId, int value);
extern undefined8 ObjGroup_RemoveObject();
extern undefined4 ObjGroup_AddObject();

/*
 * --INFO--
 *
 * Function: dimlavasmash_init
 * EN v1.0 Address: 0x801B3658
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x801B367C
 * EN v1.1 Size: 636b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
extern int dimlavasmash_SeqFn(int obj, int p2, char *r5);
extern void dimlavasmash_setBlockSurfaceFlags(int *block, int mode, int v);
extern int objPosToMapBlockIdx(f32 x, f32 y, f32 z);
extern int *mapGetBlock(int idx);
#pragma scheduling off
#pragma peephole off
void dimlavasmash_init(s16 *obj, s8 *def) {
    int *block;
    char *inner;
    obj[0] = (s16)((s32)def[0x18] << 8);
    *(int *)((char *)obj + 0xbc) = (int)&dimlavasmash_SeqFn;
    inner = *(char **)((char *)obj + 0xb8);
    *(u8 *)(inner + 1) = (u8)*(s16 *)(def + 0x1a);
    *(s8 *)(inner + 0) = (s8)*(s16 *)(def + 0x1c);
    *(u8 *)(inner + 2) = (u8)GameBit_Get(*(s16 *)(def + 0x1e));
    if (*(u8 *)(inner + 2) == 1) {
        block = mapGetBlock(objPosToMapBlockIdx(*(f32 *)((char *)obj + 0xc), *(f32 *)((char *)obj + 0x10), *(f32 *)((char *)obj + 0x14)));
        if (block != NULL) {
            dimlavasmash_setBlockSurfaceFlags(block, 1, *(u8 *)(inner + 1));
            dimlavasmash_setBlockSurfaceFlags(block, 0, *(u8 *)(inner + 1) + 1);
        }
    }
    *(s8 *)((char *)obj + 0xad) = def[0x19];
    {
        s16 *p = *(s16 **)((char *)obj + 0x54);
        p[0x30] = (s16)(p[0x30] & ~1);
    }
    *(u16 *)((char *)obj + 0xb0) = (u16)(*(u16 *)((char *)obj + 0xb0) | 0x2000);
}
#pragma peephole reset
#pragma scheduling reset

/* Trivial 4b 0-arg blr leaves. */
void dimlavasmash_release(void) {}
void dimlavasmash_initialise(void) {}
void dimbridgecogmai_hitDetect(void) {}
void dimbridgecogmai_initialise(void) {}
void dimdismountpoint_hitDetect(void) {}
void dimdismountpoint_release(void) {}
void dimdismountpoint_initialise(void) {}

extern int* ObjGroup_FindNearestObject(int group, int *obj, f32 *dist);
extern void objRenderFn_80041018(int obj);
extern f32 lbl_803E4910;

#pragma scheduling off
#pragma peephole off
void dimdismountpoint_update(int *obj) {
    extern uint GameBit_Get(int eventId);
    int *nearest;
    f32 d;

    d = lbl_803E4910;
    nearest = ObjGroup_FindNearestObject(0xa, obj, &d);
    *(u8*)((char*)obj + 0xaf) = (u8)(*(u8*)((char*)obj + 0xaf) & ~8);
    if (GameBit_Get(0x3e3) != 0) {
        *(u8*)((char*)obj + 0xe4) = 1;
        *(u8*)((char*)obj + 0xaf) = (u8)(*(u8*)((char*)obj + 0xaf) & ~0x10);
    } else {
        *(u8*)((char*)obj + 0xe4) = 0;
        if (nearest != NULL &&
            ((int (*)(int*, int*))(*(int *)(*(int *)*(int **)((char*)nearest + 0x68) + 0x20)))(nearest, obj) != 0) {
            *(u8*)((char*)obj + 0xaf) = (u8)(*(u8*)((char*)obj + 0xaf) & ~0x10);
        } else {
            *(u8*)((char*)obj + 0xaf) = (u8)(*(u8*)((char*)obj + 0xaf) | 0x10);
        }
    }
    if ((*(u32*)(*(int*)((char*)obj + 0x50) + 0x44) & 1) != 0 && *(void **)((char*)obj + 0x74) != NULL) {
        objRenderFn_80041018((int)obj);
    }
}
#pragma peephole reset
#pragma scheduling reset

extern f32 lbl_803E4908;
extern f32 lbl_803E4914;
extern f32 lbl_803E4918;
extern f32 fn_80293E80(f32 x);
extern f32 sin(f32 x);
extern uint GameBit_Get(int eventId);
extern unsigned long GameBit_Set(int eventId, int value);

#pragma peephole off
#pragma scheduling off
void dimdismountpoint_init(u8* obj, u8* params) {
    f32 *sub;

    ObjGroup_AddObject(obj, 0x13);
    *(s16*)obj = (s16)((s8)params[0x18] << 8);
    sub = *(f32**)(obj + 0xb8);
    sub[0] = fn_80293E80(lbl_803E4914 * (f32)(s32)*(s16*)obj / lbl_803E4918);
    sub[1] = lbl_803E4908;
    sub[2] = sin(lbl_803E4914 * (f32)(s32)*(s16*)obj / lbl_803E4918);
    sub[3] = -(sub[0] * *(f32*)(obj + 0xc) + sub[1] * *(f32*)(obj + 0x10) + sub[2] * *(f32*)(obj + 0x14));
    *(int*)(obj + 0xf8) = 1;
}
#pragma scheduling reset
#pragma peephole reset

/* 8b "li r3, N; blr" returners. */
int dimbridgecogmai_getExtraSize(void) { return 0x1; }
int dimbridgecogmai_getObjectTypeId(void) { return 0x0; }
int dimdismountpoint_getExtraSize(void) { return 0x10; }

/* render-with-objRenderFn_8003b8f4 pattern. */
extern f32 lbl_803E4900;
extern void objRenderFn_8003b8f4(f32);
#pragma peephole off
void dimbridgecogmai_render(int p1, int p2, int p3, int p4, int p5, s8 visible) { s32 v = visible; if (v != 0) objRenderFn_8003b8f4(lbl_803E4900); }
#pragma peephole reset

/* ObjGroup_RemoveObject(x, N) wrappers. */
#pragma scheduling off
#pragma peephole off
void dimbridgecogmai_free(int x) { ObjGroup_RemoveObject(x, 0xf); }
void dimdismountpoint_free(int x) { ObjGroup_RemoveObject(x, 0x13); }
#pragma peephole reset
#pragma scheduling reset

void dimbridgecogmai_release(void) {}
int dimdismountpoint_getObjectTypeId(void) { return 0; }

extern int dimbridgecogmai_SeqFn(int obj, int p2, char *r5);
#pragma scheduling off
#pragma peephole off
void dimbridgecogmai_init(int *obj, int *def) {
    *(u8 *)*(int **)((char *)obj + 0xb8) = 100;
    *(s16 *)obj = (s16)((u32)*(u8 *)((char *)def + 0x1c) << 8);
    *(void **)((char *)obj + 0xbc) = (void *)dimbridgecogmai_SeqFn;
    ObjGroup_AddObject(obj, 15);
    if ((u8)GameBit_Get(*(s16 *)((char *)def + 0x18)) != 0) {
        *(u16 *)((char *)obj + 0xb0) = (u16)(*(u16 *)((char *)obj + 0xb0) | 0x8000);
    }
    *(u16 *)((char *)obj + 0xb0) = (u16)(*(u16 *)((char *)obj + 0xb0) | 0x6000);
}
#pragma peephole reset
#pragma scheduling reset

extern f32 lbl_803E490C;
extern void objRenderFn_80041018(int obj);
#pragma scheduling off
#pragma peephole off
void dimdismountpoint_render(int obj, int p1, int p2, int p3, int p4, s8 visible) {
    if (visible == 0 || *(int *)(obj + 0xf8) != 0) {
        if (*(int *)(obj + 0xf8) != 0) {
            objRenderFn_80041018(obj);
        }
    } else {
        objRenderFn_8003b8f4(lbl_803E490C);
    }
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
int dimbridgecogmai_SeqFn(int obj, int p2, char *r5) {
    char *param = *(char **)(obj + 0x4c);
    r5[0x56] = 0;
    if ((*(u8 *)(param + 0x1d) & 0x2) != 0 && *(u8 *)(r5 + 0x80) == 1) {
        GameBit_Set(*(s16 *)(param + 0x18), 1);
        *(u8 *)(r5 + 0x80) = 0;
    }
    return 0;
}
#pragma peephole reset
#pragma scheduling reset

extern int *gObjectTriggerInterface;
#pragma scheduling off
#pragma peephole off

void dimbridgecogmai_update(int *obj) {
    u8 *def;
    int code;
    u8 bits;
    int callArg;

    def = *(u8**)((char*)obj + 0x4c);
    if (GameBit_Get(*(s16*)(def + 0x1a)) != 0) {
        if ((s8)def[0x1e] != -1) {
            switch (*(s16*)(def + 0x1a)) {
            case 0x17a:
                if (GameBit_Get(0x181) != 0) {
                    *(u16*)((char*)obj + 0xb0) = (u16)(*(u16*)((char*)obj + 0xb0) | 0x8000);
                    code = -1;
                    callArg = 0;
                } else {
                    GameBit_Set(*(s16*)(def + 0x1a), 0);
                    code = 0x1f;
                    callArg = 1;
                }
                break;
            case 0x1e3:
                bits = (u8)GameBit_Get(0x182);
                bits = (u8)(bits | (GameBit_Get(0x183) << 1));
                bits = (u8)(bits | (GameBit_Get(0x184) << 2));
                if (bits == 7) {
                    *(u16*)((char*)obj + 0xb0) = (u16)(*(u16*)((char*)obj + 0xb0) | 0x8000);
                    code = -1;
                    callArg = 2;
                } else {
                    GameBit_Set(*(s16*)(def + 0x1a), 0);
                    code = 0x1d;
                    if ((bits & 4) != 0) {
                        code = code | 2;
                        if ((bits & 2) != 0) {
                            code = code | 0x20;
                        }
                    }
                    callArg = 1;
                }
                break;
            default:
                callArg = 0;
                break;
            }
            ((void(*)(int, int*, int))((void**)*gObjectTriggerInterface)[18])(callArg, obj, code);
        }
        if ((def[0x1d] & 2) == 0) {
            GameBit_Set(*(s16*)(def + 0x18), 1);
        }
    }
}

void dimdismountpoint_func11(int obj, int flag) {
    (*(void (*)(int, int, int))(*(int *)(*gObjectTriggerInterface + 0x48)))((flag ^ 1) + 2, obj, -1);
}

extern int Obj_GetPlayerObject(void);
extern f32 lbl_803E4908;
int dimdismountpoint_setScale(int obj) {
    int *player = (int *)Obj_GetPlayerObject();
    int *state = *(int **)((char *)obj + 0xB8);
    f32 result;
    int side;

    result = *(f32 *)((char *)state + 0xC) +
             (*(f32 *)((char *)state + 8) * *(f32 *)((char *)player + 0x14) +
              (*(f32 *)((char *)state + 0) * *(f32 *)((char *)player + 0xC) +
               *(f32 *)((char *)state + 4) * *(f32 *)((char *)player + 0x10)));

    if (result >= lbl_803E4908) {
        side = 0;
    } else {
        side = 1;
    }
    (*(void (*)(int, int, int))(*(int *)(*gObjectTriggerInterface + 0x48)))(side, obj, -1);
    return side;
}
#pragma peephole reset
#pragma scheduling reset
