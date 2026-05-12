#include "ghidra_import.h"
#include "main/dll/backpack.h"

extern void fn_801641B0(int obj);
extern void fn_80164940(int obj);
extern void fn_80164C44(int obj);
extern int GameBit_Set(int eventId, int value);
extern void Sfx_PlayFromObject(int obj, int sfxId);
extern void Sfx_KeepAliveLoopedObjectSound(int obj, int sfxId);
extern void ObjHits_DisableObject(int obj);
extern void ObjHits_SetHitVolumeSlot(int obj, int a, int b, int c);
extern void fn_80098B18(int obj, float f, int a, int b, int c, int d);

extern void* lbl_803DCAB8;
extern void* lbl_803DCA8C;
extern void* lbl_803DCAA8;
extern void* pDll_expgfx;
extern f32 lbl_803E2FC8;
extern f32 lbl_803E2FCC;
extern f32 lbl_803E2FD0;
extern f32 lbl_803E2FB4;
extern u8 lbl_803DBD40[8];
extern u8 lbl_80320288[0xc];

extern u32 randomGetRange(int min, int max);
extern void ObjGroup_AddObject(int obj, int group);
extern void ObjMsg_AllocQueue(int obj, int capacity);

/*
 * --INFO--
 *
 * Function: tumbleweed_update
 * EN v1.0 Address: 0x80164EE4
 * EN v1.0 Size: 72b
 */
#pragma push
#pragma scheduling off
#pragma peephole off
void tumbleweed_update(int obj) {
    if (*(s16*)(obj + 0x46) == 0x39d) {
        fn_80164940(obj);
    } else {
        fn_801641B0(obj);
    }
    fn_80164C44(obj);
}
#pragma pop

/* 8b "li r3, N; blr" returners. */
int fn_801650D0(void) { return 0x0; }

/*
 * --INFO--
 *
 * Function: tumbleweed_init
 * EN v1.0 Address: 0x80164F2C
 * EN v1.0 Size: 420b
 */
#pragma push
#pragma scheduling off
#pragma peephole off
void tumbleweed_init(int obj, int defData) {
    int aux = *(int*)(obj + 0xb8);
    u32 rnd;

    *(f32*)(aux + 0x288) = *(f32*)(obj + 0xc);
    *(f32*)(aux + 0x28c) = *(f32*)(obj + 0x14);
    *(s16*)(aux + 0x26a) = (short)(lbl_803E2FCC * *(f32*)(defData + 0x1c));
    *(u8*)(aux + 0x279) = *(u8*)(defData + 0x1b);
    *(f32*)(aux + 0x26c) = *(f32*)(obj + 0x8);
    rnd = randomGetRange(0xc8, 0x1f4);
    *(f32*)(aux + 0x270) = *(f32*)(aux + 0x26c) / (f32)(s32)rnd;
    *(u32*)(aux + 0x284) = 0;
    *(f32*)(obj + 0x8) = lbl_803E2FD0;
    (*(int(**)(int, int, int, int))(*(int*)lbl_803DCAA8 + 0x4))(aux, 0, 0x40000, 1);
    (*(int(**)(int, int, void*, void*, int))(*(int*)lbl_803DCAA8 + 0x8))(aux, 1, lbl_80320288, lbl_803DBD40, 8);
    (*(int(**)(int, int))(*(int*)lbl_803DCAA8 + 0x20))(obj, aux);
    *(u8*)(aux + 0x278) = 0;
    rnd = randomGetRange(-0x12c, 0x12c);
    *(f32*)(aux + 0x2a0) = lbl_803E2FB4 + (f32)(s32)rnd;
    ObjGroup_AddObject(obj, 3);
    ObjGroup_AddObject(obj, 0x31);
    ObjHits_DisableObject(obj);
    ObjMsg_AllocQueue(obj, 1);
    if (*(s16*)(obj + 0x46) == 0x4ba) {
        *(u8*)(aux + 0x27a) = (u8)(*(u8*)(aux + 0x27a) | 0x10);
    }
}
#pragma pop

/*
 * --INFO--
 *
 * Function: fn_80164C44
 * EN v1.0 Address: 0x80164C44
 * EN v1.0 Size: 672b
 */
#pragma push
#pragma scheduling off
#pragma peephole off
void fn_80164C44(int obj) {
    int aux = *(int*)(obj + 0xb8);
    int i;
    s16 type;

    if ((*(u8*)(aux + 0x27a) & 1) != 0) {
        switch (*(s16*)(obj + 0x46)) {
        case 0x4ba:
        case 0x39d:
        case 0x4c1:
            i = 0x14;
            do {
                (*(void(**)(int, int, int, int, int, int))(*(int*)pDll_expgfx + 0x8))(obj, 0x34d, 0, 2, -1, 0);
                i = i - 1;
            } while (i != 0);
            break;
        default:
            i = 0x14;
            do {
                (*(void(**)(int, int, int, int, int, int))(*(int*)pDll_expgfx + 0x8))(obj, 0x32e, 0, 2, -1, 0);
                i = i - 1;
            } while (i != 0);
            break;
        }
        Sfx_PlayFromObject(obj, 0x27d);
        *(u8*)(aux + 0x27a) = (u8)(*(u8*)(aux + 0x27a) & ~1);
    }

    if ((*(u8*)(aux + 0x27a) & 2) != 0) {
        switch (*(s16*)(obj + 0x46)) {
        case 0x4ba:
        case 0x39d:
        case 0x4c1:
            (*(void(**)(int, int, int, int, int, int))(*(int*)pDll_expgfx + 0x8))(obj, 0x34c, 0, 2, -1, 0);
            break;
        default:
            (*(void(**)(int, int, int, int, int, int))(*(int*)pDll_expgfx + 0x8))(obj, 0x32d, 0, 2, -1, 0);
            break;
        }
        *(u8*)(aux + 0x27a) = (u8)(*(u8*)(aux + 0x27a) & ~2);
    }

    if ((*(u8*)(aux + 0x27a) & 4) != 0) {
        *(u8*)(obj + 0x36) = 0;
        *(u8*)(aux + 0x278) = 5;
        *(f32*)(aux + 0x270) = lbl_803E2FC8;
        ObjHits_DisableObject(obj);
        *(u8*)(aux + 0x27a) = (u8)(*(u8*)(aux + 0x27a) & ~4);
    }

    if ((*(u8*)(aux + 0x27a) & 0x10) != 0 && (*(u16*)(obj + 0xb0) & 0x800) != 0) {
        u8 bVar2;
        ObjHits_SetHitVolumeSlot(obj, 0x1f, 1, 0);
        bVar2 = (u8)(*(s8*)(aux + 0x27b) + 1);
        *(u8*)(aux + 0x27b) = bVar2;
        if ((int)(uint)bVar2 % 6 == 0) {
            fn_80098B18(obj, *(f32*)(obj + 0x8), 1, 0, 0, 0);
        } else {
            fn_80098B18(obj, *(f32*)(obj + 0x8), 1, 3, 0, 0);
        }
        Sfx_KeepAliveLoopedObjectSound(obj, 0x451);
    }
}
#pragma pop

/*
 * --INFO--
 *
 * Function: fn_801650D8
 * EN v1.0 Address: 0x801650D8
 * EN v1.0 Size: 176b
 */
#pragma push
#pragma scheduling off
#pragma peephole off
int fn_801650D8(int obj, int target) {
    int *aux = *(int**)(obj + 0xb8);
    if ((s8)*(u8*)(target + 0x27a) != 0) {
        (*(int(**)(int, int, int, int))(*(int*)lbl_803DCAB8 + 0x4c))(obj, (int)*(s16*)((char*)aux + 0x3f0), -1, 0);
        (*(int(**)(int, int, int, int, int))(*(int*)lbl_803DCA8C + 0x58))(obj, target, 0x3c, 0xa, 0);
        GameBit_Set((int)*(s16*)((char*)aux + 0x3f2), 1);
        *(u8*)((char*)aux + 0x405) = 0;
    }
    return 0;
}
#pragma pop
