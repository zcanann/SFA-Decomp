#include "main/dll/WM/wm_shared.h"

int wmwallcrawler_getExtraSize(void) { return 0x29c; }

int wmwallcrawler_getObjectTypeId(void) { return 0x0; }

void wmwallcrawler_release(void) {}

void wmwallcrawler_initialise(void) {}

#pragma peephole off
#pragma scheduling off
int fn_801F7FF4(int obj) {
    *(u8 *)(*(int *)(obj + 0xb8) + 0x296) = 1;
    return 0;
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void wmwallcrawler_free(int obj) {
    ObjGroup_RemoveObject(obj, 3);
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void wmwallcrawler_render(int p1, int p2, int p3, int p4, int p5, s8 vis) {
    int *inner = *(int **)(p1 + 0xb8);
    if ((*(u16 *)((char *)inner + 0x294) & 0x40) != 0 && (u8)*(u8 *)(p1 + 0x36) < 0xff) {
        if (*(u8 *)(p1 + 0x36) > 0xff - framesThisStep) {
            *(u8 *)(p1 + 0x36) = 0xff;
            *(u16 *)((char *)inner + 0x294) &= ~0x40;
        } else {
            *(u8 *)(p1 + 0x36) += framesThisStep;
        }
    }
    if (vis != 0 && *(s16 *)((char *)inner + 0x28c) == 0) {
        objRenderFn_8003b8f4(lbl_803E5FB4);
    }
}
#pragma scheduling reset
#pragma peephole reset

extern void mathFn_80021ac8(void* mtx, f32* vec);
extern f32 lbl_803E5FB0;
typedef struct { s16 r0, r1, r2; f32 m8, mc, m10, m14; } WcXf;

#pragma peephole off
#pragma scheduling off
void fn_801F8008(int a, f32* b)
{
    WcXf mtx;
    f32 in[3];
    u16 ang, ang2;
    in[0] = b[1];
    in[1] = b[2];
    in[2] = b[3];
    mtx.mc = lbl_803E5FB0;
    mtx.m10 = lbl_803E5FB0;
    mtx.m14 = lbl_803E5FB0;
    mtx.m8 = lbl_803E5FB4;
    mtx.r2 = 0;
    mtx.r1 = 0;
    mtx.r0 = *(s16*)a;
    mathFn_80021ac8(&mtx, in);
    ang = getAngle(in[0], in[1]);
    ang2 = getAngle(in[2], in[1]);
    *(s16*)(a + 2) = (s16)ang2;
    *(s16*)(a + 4) = (s16)ang;
}
#pragma scheduling reset
#pragma peephole reset

extern void objRemoveFromListFn_8002ce88(int obj);
extern f32 lbl_803E5FB8;
typedef struct { u8 hit:1; u8 _r299:7; } WcHitBits;

#pragma peephole off
#pragma scheduling off
void wmwallcrawler_hitDetect(int obj)
{
    int inner = *(int*)(obj + 0xb8);
    f32 stk = lbl_803E5FB8;
    if (ObjHits_GetPriorityHit(obj, 0, 0, 0) != 0) {
        if ((*(u16*)(inner + 0x294) & 0x100) != 0) {
            *(u8*)(inner + 0x296) = 6;
        } else if (*(void**)(*(int*)(obj + 0x4c) + 0x14) == NULL) {
            ObjHits_DisableObject(obj);
            Obj_FreeObject(obj);
        } else {
            objRemoveFromListFn_8002ce88(obj);
            ObjHits_DisableObject(obj);
            ObjGroup_RemoveObject(obj, 3);
            *(s16*)(obj + 6) = *(s16*)(obj + 6) | 0x4000;
        }
    } else if (((WcHitBits*)(inner + 0x299))->hit != 0) {
        int target;
        if ((*(u16*)(inner + 0x294) & 0x10) == 0) {
            target = (int)Obj_GetPlayerObject();
        } else {
            target = ObjGroup_FindNearestObject(0xa, obj, &stk);
        }
        ObjHits_RecordObjectHit(target, obj, 0xb, 1, 0);
        *(u8*)(inner + 0x296) = 6;
        ((WcHitBits*)(inner + 0x299))->hit = 0;
    }
}
#pragma scheduling reset
#pragma peephole reset

extern int* gPathControlInterface;
extern u16 lbl_80328DD0[];
extern u8 lbl_80328DE0[];
extern u8 lbl_803DC134;
extern f32 lbl_803E6030;
extern f32 lbl_803E6034;

#pragma peephole off
#pragma scheduling off
void wmwallcrawler_init(int obj, int spawn)
{
    int inner = *(int*)(obj + 0xb8);
    u16 flags;
    ObjGroup_AddObject(obj, 3);
    *(s16*)obj = (s16)((s8)*(u8*)(spawn + 0x18) << 8);
    ObjMsg_AllocQueue(obj, 2);
    *(f32*)(inner + 0x270) = *(f32*)(spawn + 8);
    *(f32*)(inner + 0x274) = *(f32*)(spawn + 0xc);
    *(f32*)(inner + 0x278) = *(f32*)(spawn + 0x10);
    *(f32*)(inner + 0x268) = (f32)(int)*(s16*)(spawn + 0x1a);
    *(u8*)(inner + 0x298) = *(u8*)(spawn + 0x19);
    *(u16*)(inner + 0x294) = lbl_80328DD0[*(u8*)(inner + 0x298)];
    storeZeroToFloatParam((void*)(inner + 0x28a));
    storeZeroToFloatParam((void*)(inner + 0x28c));
    storeZeroToFloatParam((void*)(inner + 0x288));
    flags = *(u16*)(inner + 0x294);
    if ((flags & 1) != 0) {
        *(s16*)(obj + 4) = 0;
        *(u8*)(inner + 0x296) = 1;
    } else if ((flags & 8) != 0) {
        s16toFloat((void*)(inner + 0x28a), 0x4b0);
        *(f32*)(inner + 0x268) = lbl_803E6030;
        *(s16*)(obj + 4) = 0;
        *(u8*)(inner + 0x296) = 1;
    } else {
        s16toFloat((void*)(inner + 0x288), 0x190);
        *(s16*)(obj + 4) = -0x7fff;
        *(u8*)(inner + 0x296) = 0;
    }
    if ((*(u16*)(inner + 0x294) & 0x40) != 0) {
        *(u8*)(obj + 0x36) = 0;
    }
    *(f32*)(inner + 0x284) = lbl_803E5FB0;
    *(s16*)(inner + 0x28e) = *(s16*)(spawn + 0x1c);
    *(f32*)(obj + 0x10) = *(f32*)(spawn + 0xc) + (f32)(int)*(s16*)(inner + 0x28e);
    *(s16*)(inner + 0x290) = (s16)(randomGetRange(0, 0x50) + 0x190);
    *(f32*)(inner + 0x26c) = lbl_803E6034;
    *(s16*)(inner + 0x292) = *(s16*)(spawn + 0x1e);
    if ((*(u16*)(inner + 0x294) & 2) != 0) {
        *(u8*)(inner + 0x25b) = 1;
        (*(void (**)(int, int, int, int))(*(int*)gPathControlInterface + 4))(inner, 0, 0, 1);
        (*(void (**)(int, int, u8*, u8*, int))(*(int*)gPathControlInterface + 8))(inner, 1, lbl_80328DE0, &lbl_803DC134, 4);
        (*(void (**)(int, int))(*(int*)gPathControlInterface + 0x20))(obj, inner);
        *(u32*)inner |= 0x40008;
    }
    *(int*)(obj + 0xbc) = (int)fn_801F7FF4;
    ObjHits_EnableObject(obj);
    ObjHits_SyncObjectPositionIfDirty(obj);
}
#pragma scheduling reset
#pragma peephole reset
