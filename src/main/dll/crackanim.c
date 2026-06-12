/* === moved from main/dll/groundAnimator.c [8017D818-8017E1A0) (TU re-split, docs/boundary_audit.md) === */
#include "main/dll/groundanimator_state.h"
#include "main/audio/sfx_ids.h"
#include "main/dll/groundAnimator.h"
#include "main/effect_interfaces.h"
#include "main/expgfx.h"
#include "main/game_object.h"
#include "main/objanim_internal.h"
#include "main/objanim_update.h"
#include "main/objseq.h"

typedef struct Dll115Placement
{
    u8 pad0[0x18 - 0x0];
    u8 unk18;
    s8 unk19;
    u8 pad1A[0x38 - 0x1A];
    u8 unk38;
    u8 unk39;
    u8 unk3A;
    u8 unk3B;
    s16 unk3C;
    u8 pad3E[0x40 - 0x3E];
} Dll115Placement;


typedef struct WmColumnPlacement
{
    u8 pad0[0x18 - 0x0];
    u8 unk18;
    u8 unk19;
    u8 pad1A[0x1E - 0x1A];
    s16 unk1E;
    u8 pad20[0x38 - 0x20];
    u8 unk38;
    u8 unk39;
    u8 unk3A;
    u8 unk3B;
    s16 unk3C;
    u8 pad3E[0x40 - 0x3E];
} WmColumnPlacement;


extern u32 randomGetRange(int min, int max);
extern undefined4 ObjMsg_SendToObject();
extern uint GameBit_Get(int eventId);
extern void GameBit_Set(int eventId, int value);
extern f32 Vec_distance(float* posA, float* posB);

extern ObjectTriggerInterface** gObjectTriggerInterface;

typedef void (*GroundAnimatorFreeFn)(int obj);
typedef int (*GroundAnimatorVisibleFn)(int obj, int visible);
typedef int (*GroundAnimatorAnimStateFn)(int obj, int state);
typedef void (*GroundAnimatorSetVisibleFn)(int state, int visible);
typedef void (*GroundAnimatorInitAnimFn)(void* obj, undefined4 state, int param_3);

/*
 * --INFO--
 *
 * Function: dll_115_update
 * EN v1.0 Address: 0x8017D0D4
 * EN v1.0 Size: 232b
 * EN v1.1 Address: 0x8017D134
 * EN v1.1 Size: 244b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
typedef struct
{
    s16 pad0[12];
    s16 ev18;
    s16 pad1a[7];
    s16 ev28;
    u8 pad2a[0x16];
    u8 id40;
} Dll115MapRow;


/*
 * --INFO--
 *
 * Function: dll_115_init
 * EN v1.0 Address: 0x8017D1BC
 * EN v1.0 Size: 36b
 * EN v1.1 Address: 0x8017D228
 * EN v1.1 Size: 36b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */

/*
 * --INFO--
 *
 * Function: dll_115_release_nop
 * EN v1.0 Address: 0x8017D1E0
 * EN v1.0 Size: 40b
 * EN v1.1 Address: 0x8017D24C
 * EN v1.1 Size: 52b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */

/*
 * --INFO--
 *
 * Function: dll_115_initialise_nop
 * EN v1.0 Address: 0x8017D208
 * EN v1.0 Size: 404b
 * EN v1.1 Address: 0x8017D280
 * EN v1.1 Size: 376b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */

/*
 * --INFO--
 *
 * Function: wm_column_getExtraSize
 * EN v1.0 Address: 0x8017D39C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8017D3F8
 * EN v1.1 Size: 240b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */

/*
 * --INFO--
 *
 * Function: wm_column_getObjectTypeId
 * EN v1.0 Address: 0x8017D3A0
 * EN v1.0 Size: 232b
 * EN v1.1 Address: 0x8017D4E8
 * EN v1.1 Size: 236b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */

/*
 * --INFO--
 *
 * Function: wm_column_free
 * EN v1.0 Address: 0x8017D488
 * EN v1.0 Size: 36b
 * EN v1.1 Address: 0x8017D5D4
 * EN v1.1 Size: 36b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */

/*
 * --INFO--
 *
 * Function: wm_column_render
 * EN v1.0 Address: 0x8017D4AC
 * EN v1.0 Size: 40b
 * EN v1.1 Address: 0x8017D5F8
 * EN v1.1 Size: 52b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */

/*
 * --INFO--
 *
 * Function: wm_column_hitDetect
 * EN v1.0 Address: 0x8017D4D4
 * EN v1.0 Size: 424b
 * EN v1.1 Address: 0x8017D62C
 * EN v1.1 Size: 420b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */

/*
 * --INFO--
 *
 * Function: wm_column_update
 * EN v1.0 Address: 0x8017D67C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8017D7D0
 * EN v1.1 Size: 276b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */

/*
 * --INFO--
 *
 * Function: wm_column_init
 * EN v1.0 Address: 0x8017D680
 * EN v1.0 Size: 76b
 * EN v1.1 Address: 0x8017D8E4
 * EN v1.1 Size: 72b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */

/*
 * --INFO--
 *
 * Function: wm_column_release
 * EN v1.0 Address: 0x8017D6CC
 * EN v1.0 Size: 100b
 * EN v1.1 Address: 0x8017D92C
 * EN v1.1 Size: 128b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */

/*
 * --INFO--
 *
 * Function: wm_column_initialise
 * EN v1.0 Address: 0x8017D730
 * EN v1.0 Size: 880b
 * EN v1.1 Address: 0x8017D9AC
 * EN v1.1 Size: 784b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */

ObjectDescriptor gWM_ColumnObjDescriptor = {
    0, 0, 0, OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)wm_column_initialise,
    (ObjectDescriptorCallback)wm_column_release,
    0,
    (ObjectDescriptorCallback)wm_column_init,
    (ObjectDescriptorCallback)wm_column_update,
    (ObjectDescriptorCallback)wm_column_hitDetect,
    (ObjectDescriptorCallback)wm_column_render,
    (ObjectDescriptorCallback)wm_column_free,
    (ObjectDescriptorCallback)wm_column_getObjectTypeId,
    wm_column_getExtraSize,
};

extern void appleontree_init();
extern void appleontree_update();
extern void appleontree_render(int obj, int p1, int p2, int p3, int p4, s8 visible);
extern void appleontree_free(int* obj);
extern int appleontree_getExtraSize(void);
extern void appleontree_setScale(void);
extern u8 appleontree_modelMtxFn(int* obj);

ObjectDescriptor13 gAppleOnTreeObjDescriptor = {
    0, 0, 0, OBJECT_DESCRIPTOR_FLAGS_13_SLOTS,
    0,
    0,
    0,
    (ObjectDescriptorCallback)appleontree_init,
    (ObjectDescriptorCallback)appleontree_update,
    0,
    (ObjectDescriptorCallback)appleontree_render,
    (ObjectDescriptorCallback)appleontree_free,
    0,
    appleontree_getExtraSize,
    (ObjectDescriptorCallback)appleontree_setScale,
    (ObjectDescriptorCallback)appleontree_func0B,
    (ObjectDescriptorCallback)appleontree_modelMtxFn,
};

u32 jumptable_803214DC[] = {
    (u32)((u8*)appleontree_update + 0x170),
    (u32)((u8*)appleontree_update + 0x274),
    (u32)((u8*)appleontree_update + 0x3C4),
    (u32)((u8*)appleontree_update + 0x4E8),
    (u32)((u8*)appleontree_update + 0x554),
    (u32)((u8*)appleontree_update + 0x6C8),
    (u32)((u8*)appleontree_update + 0x71C),
};

/* appleontree extra block (size 0x64 = appleontree_getExtraSize). */
typedef struct AppleOnTreeState
{
    u8 unk00[8];
    f32 unk08;
    f32 unk0C;
    u8 unk10[0x24 - 0x10];
    f32 unk24;
    f32 unk28;
    f32 unk2C;
    f32 unk30;
    f32 unk34;
    u16 healthRestore;
    u8 unk3A;
    u8 pad3B;
    f32 unk3C;
    f32 unk40;
    f32 bounceVel;
    s16 rotX;
    s16 rotY;
    s16 rotZ;
    u8 pad4E[2];
    f32 unk50;
    u8 pad54[6];
    u8 unk5A;
    u8 pad5B;
    s16 unk5C;
    s16 unk5E;
    f32 unk60;
} AppleOnTreeState;


/*
 * --INFO--
 *
 * Function: appleontree_func0B
 * EN v1.0 Address: 0x8017DAA0
 * EN v1.0 Size: 160b
 * EN v1.1 Address: 0x8017DCBC
 * EN v1.1 Size: 240b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void appleontree_func0B(int obj, float* pos)
{
    AppleOnTreeState* state = ((GameObject*)obj)->extra;

    if (state->unk3A == 4)
    {
        return;
    }
    if (state->unk3A == 5)
    {
        return;
    }
    if (state->unk3A == 6)
    {
        return;
    }
    ((GameObject*)obj)->anim.localPosX = pos[0];
    ((GameObject*)obj)->anim.localPosY = pos[1];
    ((GameObject*)obj)->anim.localPosZ = pos[2];
}

/*
 * --INFO--
 *
 * Function: FUN_8017db40
 * EN v1.0 Address: 0x8017DB40
 * EN v1.0 Size: 792b
 * EN v1.1 Address: 0x8017DDAC
 * EN v1.1 Size: 668b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling on
#pragma peephole on

/*
 * --INFO--
 *
 * Function: FUN_8017de58
 * EN v1.0 Address: 0x8017DE58
 * EN v1.0 Size: 672b
 * EN v1.1 Address: 0x8017E048
 * EN v1.1 Size: 380b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */

/* appleontree_handleCollectableHit: ground-animator collectable hit handler. When player is in
 * range, either send a trigger event (first contact) or apply healing +
 * particle FX + sfx + free-or-disable. */
extern f32 Vec_xzDistance(float* a, float* b);
extern void itemPickupDoParticleFx(int obj, f32 scale, int p3, int p4);
extern void Sfx_PlayFromObject(int obj, int sfxId);
extern void Obj_FreeObject(int obj);
extern f32 lbl_803E37C8;
extern f32 lbl_803E37EC;
extern f32 lbl_803E37F0;
#pragma scheduling off
#pragma peephole off
void appleontree_handleCollectableHit(int obj)
{
    extern void playerAddHealth(int player, u16 amount); /* #57 */
    extern int Obj_GetPlayerObject(void); /* #57 */
    extern undefined4 ObjHits_DisableObject(); /* #57 */
    int state = *(int*)&((GameObject*)obj)->extra;
    int player = Obj_GetPlayerObject();

    if (!(Vec_xzDistance((float*)(player + 0x18), (float*)(obj + 0x18)) < lbl_803E37EC)) return;
    if (!(Vec_distance((float*)(player + 0x18), (float*)(obj + 0x18)) < lbl_803E37F0)) return;

    if (GameBit_Get(0x90f) == 0)
    {
        (*gObjectTriggerInterface)->setObjects(0x444, 0, 0);
        ((AppleOnTreeState*)state)->unk5C = -1;
        ((AppleOnTreeState*)state)->unk5E = 0;
        ((AppleOnTreeState*)state)->unk60 = lbl_803E37C8;
        ObjMsg_SendToObject(player, 0x7000a, obj, (int*)(state + 0x5c));
        GameBit_Set(0x90f, 1);
        ((AppleOnTreeState*)state)->unk5A = (u8)(((AppleOnTreeState*)state)->unk5A | 4);
    }
    else
    {
        playerAddHealth(player, ((AppleOnTreeState*)state)->healthRestore);
        itemPickupDoParticleFx(obj, lbl_803E37C8, 0xff, 0x28);
        Sfx_PlayFromObject(obj, SFXen_waterblock_stop);
        state = *(int*)&((GameObject*)obj)->extra;
        if ((((GameObject*)obj)->anim.flags & 0x2000) != 0)
        {
            Obj_FreeObject(obj);
        }
        else
        {
            if (((GameObject*)obj)->anim.hitReactState != NULL)
            {
                ObjHits_DisableObject(obj);
            }
            ((AppleOnTreeState*)state)->unk5A = (u8)(((AppleOnTreeState*)state)->unk5A | 2);
        }
    }
}


/*
 * --INFO--
 *
 * Function: FUN_8017e12c
 * EN v1.0 Address: 0x8017E12C
 * EN v1.0 Size: 48b
 * EN v1.1 Address: 0x8017E1F4
 * EN v1.1 Size: 56b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling on
#pragma peephole on


/*
 * --INFO--
 *
 * Function: FUN_8017e15c
 * EN v1.0 Address: 0x8017E15C
 * EN v1.0 Size: 612b
 * EN v1.1 Address: 0x8017E22C
 * EN v1.1 Size: 608b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */

/*
 * --INFO--
 *
 * Function: FUN_8017e3c0
 * EN v1.0 Address: 0x8017E3C0
 * EN v1.0 Size: 624b
 * EN v1.1 Address: 0x8017E48C
 * EN v1.1 Size: 620b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */


/* Trivial 4b 0-arg blr leaves. */
#pragma scheduling off
#pragma peephole off
void appleontree_setScale(void)
{
}

/* 8b "li r3, N; blr" returners. */
int appleontree_getExtraSize(void) { return 0x64; }

/* Pattern wrappers. */
u8 appleontree_modelMtxFn(int* obj) { return ((AppleOnTreeState*)((int**)obj)[0xb8 / 4])->unk3A; }

void appleontree_free(int* obj)
{
    (*gExpgfxInterface)->freeSource((u32)obj);
}

void appleontree_render(int obj, int p1, int p2, int p3, int p4, s8 visible)
{
    extern void objRenderFn_8003b8f4(int param_1, int param_2, int param_3, int param_4, int param_5, f32 scale); /* #57 */
    AppleOnTreeState* inner = ((GameObject*)obj)->extra;
    if ((inner->unk5A & 2) == 0)
    {
        objRenderFn_8003b8f4(obj, p1, p2, p3, p4, lbl_803E37C8);
    }
}

/* v1.0 ground-animator drop physics (drift twins of FUN_8017db40/FUN_8017e15c/FUN_8017e3c0). */
extern f32 timeDelta;
extern f32 sqrtf(f32);
extern int fn_80065684(int obj, f32 x, f32 y, f32 z, f32* out, int flag);
extern WaterfxInterface** gWaterfxInterface;
extern f32 lbl_803E37D4;
extern f32 lbl_803E37D8;
extern f32 lbl_803E37DC;
extern f32 lbl_803E37E0;
extern f32 lbl_803E37E4;
extern f32 lbl_803E37E8;
extern f32 lbl_803E37F4;
extern f32 lbl_803E37F8;
extern f32 lbl_803E37FC;
extern f32 lbl_803E3800;

void fn_8017D854(int obj, int msg)
{
    extern undefined4 ObjHits_DisableObject(); /* #57 */
    int state = *(int*)&((GameObject*)obj)->extra;
    int v;

    switch (msg)
    {
    case 0:
        v = 2;
        break;
    case 1:
        v = 2;
        break;
    case 2:
        v = 2;
        break;
    default:
        v = 0;
        break;
    }
    ((AppleOnTreeState*)state)->healthRestore = (u16)v;
    ((AppleOnTreeState*)state)->unk3A = 4;
    ((AppleOnTreeState*)state)->unk08 = timeDelta;
    ((AppleOnTreeState*)state)->unk0C = timeDelta;
    ((AppleOnTreeState*)state)->rotX = (s16)randomGetRange(-0x8000, 0x7fff);
    ((AppleOnTreeState*)state)->rotY = (s16)randomGetRange(-0x8000, 0x7fff);
    ((AppleOnTreeState*)state)->rotZ = 0x2000;

    if (fn_80065684(obj, ((GameObject*)obj)->anim.localPosX, ((GameObject*)obj)->anim.localPosY,
                    ((GameObject*)obj)->anim.localPosZ,
                    (f32*)(state + 0x30), 0) == 0)
    {
        state = *(int*)&((GameObject*)obj)->extra;
        if ((((GameObject*)obj)->anim.flags & 0x2000) != 0)
        {
            Obj_FreeObject(obj);
        }
        else
        {
            if (((GameObject*)obj)->anim.hitReactState != NULL)
            {
                ObjHits_DisableObject(obj);
            }
            ((AppleOnTreeState*)state)->unk5A = (u8)(((AppleOnTreeState*)state)->unk5A | 2);
        }
    }
    else
    {
        f32 m = ((AppleOnTreeState*)state)->unk40;
        f32 g = lbl_803E37D8 * m;
        f32 q = sqrtf(-(g * ((AppleOnTreeState*)state)->unk30 - lbl_803E37D4));
        f32 t = lbl_803E37DC * m;
        f32 a;
        f32 r;

        if (t >= lbl_803E37D4)
        {
            a = t;
        }
        else
        {
            a = -t;
        }
        if (a <= lbl_803E37E0)
        {
            r = lbl_803E37C8;
        }
        else
        {
            f32 r1 = (lbl_803E37E4 - q) / t;
            f32 r2 = (lbl_803E37E4 + q) / t;
            r = (r1 > 0.0f) ? r1 : r2;
        }
        ((AppleOnTreeState*)state)->unk50 = r;

        if (((AppleOnTreeState*)state)->unk28 < lbl_803E37D4)
        {
            ((AppleOnTreeState*)state)->unk30 = -(lbl_803E37D8 * ((AppleOnTreeState*)state)->unk24 - ((AppleOnTreeState
                *)state)->unk30);
        }
        else
        {
            ((AppleOnTreeState*)state)->unk30 = lbl_803E37E8 * (lbl_803E37D8 * ((AppleOnTreeState*)state)->unk24) + ((
                AppleOnTreeState*)state)->unk30;
        }

        if (((AppleOnTreeState*)state)->unk30 <= lbl_803E37D4)
        {
            state = *(int*)&((GameObject*)obj)->extra;
            if ((((GameObject*)obj)->anim.flags & 0x2000) != 0)
            {
                Obj_FreeObject(obj);
            }
            else
            {
                if (((GameObject*)obj)->anim.hitReactState != NULL)
                {
                    ObjHits_DisableObject(obj);
                }
                ((AppleOnTreeState*)state)->unk5A = (u8)(((AppleOnTreeState*)state)->unk5A | 2);
            }
        }
        else
        {
            ((AppleOnTreeState*)state)->unk2C = ((GameObject*)obj)->anim.localPosY;
            ((AppleOnTreeState*)state)->unk34 = ((GameObject*)obj)->anim.localPosY - ((AppleOnTreeState*)state)->unk30;
            if (((GameObject*)obj)->anim.hitReactState != NULL)
            {
                ObjHits_DisableObject(obj);
            }
            Sfx_PlayFromObject(obj, SFXen_bridge_stops);
        }
    }
}

int fn_8017DCD4(int p, int state, f32 y)
{
    f32 zero = lbl_803E37D4;
    f32 m = ((AppleOnTreeState*)state)->unk40;

    if (zero != m)
    {
        if (((AppleOnTreeState*)state)->unk30 - (((AppleOnTreeState*)state)->unk2C - y) < zero)
        {
            f32 b = ((AppleOnTreeState*)state)->bounceVel;
            if (zero == b)
            {
                f32 g = lbl_803E37D8 * m;
                f32 q = sqrtf(b * b - g * ((AppleOnTreeState*)state)->unk30);
                f32 t = lbl_803E37DC * m;
                f32 a;
                f32 r;

                if (t >= lbl_803E37D4)
                {
                    a = t;
                }
                else
                {
                    a = -t;
                }
                if (a <= lbl_803E37E0)
                {
                    r = lbl_803E37C8;
                }
                else
                {
                    f32 r1 = (-b - q) / t;
                    f32 r2 = (-b + q) / t;
                    r = (r1 > 0.0f) ? r1 : r2;
                }
                ((AppleOnTreeState*)state)->unk0C = ((AppleOnTreeState*)state)->unk0C - r;
                ((AppleOnTreeState*)state)->unk2C = ((AppleOnTreeState*)state)->unk2C - ((AppleOnTreeState*)state)->
                    unk30;
                ((AppleOnTreeState*)state)->unk30 = lbl_803E37D4;
                ((GameObject*)p)->anim.localPosY = ((AppleOnTreeState*)state)->unk2C;
                ((GameObject*)p)->anim.rotX = ((AppleOnTreeState*)state)->rotX;
                ((GameObject*)p)->anim.rotY = ((AppleOnTreeState*)state)->rotY;
                ((GameObject*)p)->anim.rotZ = ((AppleOnTreeState*)state)->rotZ;
                ((AppleOnTreeState*)state)->bounceVel = -((AppleOnTreeState*)state)->unk28;
                if ((((AppleOnTreeState*)state)->unk5A & 8) == 0)
                {
                    Sfx_PlayFromObject(p, 0x407);
                    ((AppleOnTreeState*)state)->unk5A = (u8)(((AppleOnTreeState*)state)->unk5A | 8);
                }
                return 1;
            }
            else if (b < lbl_803E37F4)
            {
                ((GameObject*)p)->anim.localPosY = ((AppleOnTreeState*)state)->unk2C;
                ((AppleOnTreeState*)state)->unk40 = zero;
                ((AppleOnTreeState*)state)->bounceVel = zero;
                return 1;
            }
            else
            {
                f32 g;
                f32 q;
                f32 t;
                f32 a;
                f32 r;
                m = m + ((AppleOnTreeState*)state)->unk3C;
                g = lbl_803E37D8 * m;
                q = sqrtf(b * b - g * ((AppleOnTreeState*)state)->unk30);
                t = lbl_803E37DC * m;

                if (t >= lbl_803E37D4)
                {
                    a = t;
                }
                else
                {
                    a = -t;
                }
                if (a <= lbl_803E37E0)
                {
                    r = lbl_803E37C8;
                }
                else
                {
                    f32 r1 = (-b - q) / t;
                    f32 r2 = (-b + q) / t;
                    r = (r1 > 0.0f) ? r1 : r2;
                }
                ((AppleOnTreeState*)state)->unk0C = ((AppleOnTreeState*)state)->unk0C - r;
                ((GameObject*)p)->anim.localPosY = ((AppleOnTreeState*)state)->unk2C;
                ((AppleOnTreeState*)state)->bounceVel = ((AppleOnTreeState*)state)->bounceVel * lbl_803E37F8;
                return 0;
            }
        }
        else
        {
            ((GameObject*)p)->anim.localPosY = y;
            return 1;
        }
    }
    return 1;
}

int fn_8017DF34(int p, int state, f32 y)
{
    if (lbl_803E37D4 == ((AppleOnTreeState*)state)->unk3C)
    {
        if (((AppleOnTreeState*)state)->unk30 - (((AppleOnTreeState*)state)->unk2C - y) <= lbl_803E37D4)
        {
            f32 b;
            f32 m = ((AppleOnTreeState*)state)->unk40;
            f32 g;
            f32 q;
            f32 t;
            f32 a;
            f32 r;
            b = ((AppleOnTreeState*)state)->bounceVel;
            g = lbl_803E37D8 * m;
            q = sqrtf(b * b - g * ((AppleOnTreeState*)state)->unk30);
            t = lbl_803E37DC * m;

            if (t >= lbl_803E37D4)
            {
                a = t;
            }
            else
            {
                a = -t;
            }
            if (a <= lbl_803E37E0)
            {
                r = lbl_803E37C8;
            }
            else
            {
                f32 r2;
                f32 nb;
                nb = -b;
                r = (nb - q) / t;
                r2 = (nb + q) / t;
                r = (r > *(f32*)&lbl_803E37D4) ? r : r2;
            }
            ((AppleOnTreeState*)state)->unk0C = ((AppleOnTreeState*)state)->unk0C - r;
            ((AppleOnTreeState*)state)->unk2C = ((AppleOnTreeState*)state)->unk2C - ((AppleOnTreeState*)state)->unk30;
            ((AppleOnTreeState*)state)->unk30 = lbl_803E37D4;
            ((GameObject*)p)->anim.localPosY = ((AppleOnTreeState*)state)->unk2C;
            ((GameObject*)p)->anim.rotX = ((AppleOnTreeState*)state)->rotX;
            ((GameObject*)p)->anim.rotY = ((AppleOnTreeState*)state)->rotY;
            ((GameObject*)p)->anim.rotZ = ((AppleOnTreeState*)state)->rotZ;
            {
                f32 g2 = lbl_803E37DC * ((AppleOnTreeState*)state)->unk40;
                ((AppleOnTreeState*)state)->bounceVel = g2 * r + ((AppleOnTreeState*)state)->bounceVel;
            }
            ((AppleOnTreeState*)state)->unk3C = ((AppleOnTreeState*)state)->unk28;
            ((WaterfxSpawnSplashBurstAtPointFn)(*gWaterfxInterface)->spawnSplashBurst)(
                (void*)p, ((GameObject*)p)->anim.localPosX, ((AppleOnTreeState*)state)->unk34,
                ((GameObject*)p)->anim.localPosZ);
            return 0;
        }
        else
        {
            ((GameObject*)p)->anim.localPosY = y;
            return 1;
        }
    }
    else if (y - ((AppleOnTreeState*)state)->unk2C >= lbl_803E37D4)
    {
        f32 b;
        f32 m = ((AppleOnTreeState*)state)->unk40 + ((AppleOnTreeState*)state)->unk3C;
        f32 g;
        f32 q;
        f32 t;
        f32 a;
        f32 r;
        b = ((AppleOnTreeState*)state)->bounceVel;
        g = lbl_803E37D8 * m;
        q = sqrtf(b * b - g * ((AppleOnTreeState*)state)->unk30);
        t = lbl_803E37DC * m;

        if (t >= lbl_803E37D4)
        {
            a = t;
        }
        else
        {
            a = -t;
        }
        if (a <= lbl_803E37E0)
        {
            r = lbl_803E37C8;
        }
        else
        {
            f32 r2;
            f32 nb;
            nb = -b;
            r = (nb - q) / t;
            r2 = (nb + q) / t;
            r = (r > *(f32*)&lbl_803E37D4) ? r : r2;
        }
        ((AppleOnTreeState*)state)->unk0C = ((AppleOnTreeState*)state)->unk0C - r;
        ((GameObject*)p)->anim.localPosY = ((AppleOnTreeState*)state)->unk2C;
        ((AppleOnTreeState*)state)->unk3C = lbl_803E37FC;
        ((AppleOnTreeState*)state)->bounceVel = lbl_803E3800;
        return 0;
    }
    else
    {
        ((GameObject*)p)->anim.localPosY = y;
        return 1;
    }
}

/* segment pragma-stack balance (re-split): */
#pragma scheduling reset
#pragma scheduling reset
#pragma scheduling reset
#pragma scheduling reset
#pragma peephole reset
#pragma peephole reset
#pragma peephole reset
#pragma peephole reset

#include "main/audio/sfx_ids.h"
#include "main/effect_interfaces.h"
#include "main/game_object.h"
#include "main/dll/crackanim_state.h"
#include "main/dll/baddie_state.h"
#include "main/dll/crackanim.h"

typedef struct AppleontreeObjectDef
{
    u8 pad0[0x18 - 0x0];
    u32 unk18;
    u16 duration;
    u16 elapsed;
    u8 unk20;
    u8 unk21;
    u8 unk22;
    u8 unk23;
    u8 unk24;
    s8 unk25;
    s16 unk26;
} AppleontreeObjectDef;


extern undefined4 FUN_80017a78();
extern undefined4 FUN_8002fc3c();
extern int ObjHits_GetPriorityHit();
extern int ObjMsg_Pop();
extern undefined4 FUN_80039520();

extern void itemPickupDoParticleFx(int obj, f32 f1, int p3, int p4);
extern void Obj_SetActiveModelIndex(int obj, int idx);
extern void ObjMsg_AllocQueue(int obj, int capacity);
extern int* objFindTexture(int obj, int textureId, int modelIdx);

extern undefined4* gSHthorntailAnimationInterface;
extern EffectInterface** gPartfxInterface;
extern f64 lbl_803E3820;
extern f32 lbl_803E3828;
extern f32 lbl_803E382C;
extern f32 lbl_803E3830;
extern f32 lbl_803E3834;
extern f32 lbl_803E3838;
extern f32 lbl_803E37CC;
extern f32 lbl_803E37D0;
extern f32 lbl_803E3804;
extern f32 lbl_803E3808;
extern f32 lbl_803E380C;
extern f32 lbl_803E3810;
extern f32 lbl_803E3814;
extern f32 lbl_803E3818;

/*
 * --INFO--
 *
 * Function: appleontree_update
 * EN v1.0 Address: 0x8017E1A0
 * EN v1.0 Size: 2460b
 * EN v1.1 Address: 0x8017E6F8
 * EN v1.1 Size: 1988b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void appleontree_update(int param_1)
{
    extern void playerAddHealth(u8* player, int v); /* #57 */
    extern u8* Obj_GetPlayerObject(void); /* #57 */
    extern int FUN_8017e3c0(); /* #57 */
    extern int FUN_8017e15c(); /* #57 */
    extern undefined4 FUN_8017de58(); /* #57 */
    extern undefined4 FUN_8017db40(); /* #57 */
    extern undefined8 ObjHits_DisableObject(); /* #57 */
    float fa;
    undefined2* obj;
    int val;
    undefined4* wordPtr2;
    uint bitVal;
    int* wordPtr;
    int placement;
    int state;
    f32 fc;
    f32 fb;
    f32 fd;
    f32 frac;
    int msg;
    undefined msgExtra[4];

    obj = (undefined2*)param_1;
    state = *(int*)(obj + 0x5c);
    placement = *(int*)(obj + 0x26);
    msg = 0;
    if ((*(byte*)(state + 0x5a) & 4) != 0)
    {
        while (val = ObjMsg_Pop((int)obj, &msg, (uint*)0x0, (uint*)0x0), val != 0)
        {
            switch (msg)
            {
            case 0x7000b:
                {
                    playerAddHealth(Obj_GetPlayerObject(), (int)*(u16*)(state + 0x38));
                    itemPickupDoParticleFx((int)obj, lbl_803E37C8, 0xff, 0x28);
                    Sfx_PlayFromObject((int)obj, SFXen_waterblock_stop);
                    val = *(int*)(obj + 0x5c);
                    if (((GameObject*)obj)->anim.flags & 0x2000)
                    {
                        Obj_FreeObject((int)obj);
                    }
                    else
                    {
                        if (*(void**)(obj + 0x2a) != 0)
                        {
                            ObjHits_DisableObject((int)obj);
                        }
                        *(byte*)(val + 0x5a) = *(byte*)(val + 0x5a) | 2;
                    }
                    *(byte*)(state + 0x5a) = *(byte*)(state + 0x5a) & ~4;
                }
            }
        }
        if ((*(byte*)(state + 0x5a) & 4) != 0) goto switchD_8017e864_caseD_7;
    }
    if ((*(byte*)(state + 0x5a) & 2) == 0)
    {
        *(float*)(state + 8) = *(float*)(state + 8) + timeDelta;
        fa = *(float*)(state + 0xc);
        *(float*)(state + 0xc) = fa + timeDelta;
        fb = *(float*)(state + 8);
        frac = fb / *(float*)(state + 4);
        switch (*(undefined*)(state + 0x3a))
        {
        case 0:
            val = ObjHits_GetPriorityHit((int)obj, (undefined4*)0x0, (int*)0x0, (uint*)0x0);
            if ((val != 0) ||
                ((*(short*)(placement + 0x26) != -1 &&
                    (bitVal = GameBit_Get((int)*(short*)(placement + 0x26)), bitVal != 0))))
            {
                state = *(int*)(obj + 0x5c);
                placement = 0;
                do
                {
                    (*gPartfxInterface)->spawnObject(obj, 0x55a, NULL, 2, -1, NULL);
                    placement = placement + 1;
                }
                while (placement < 8);
                if (*(void**)(obj + 0x2a) != 0)
                {
                    ObjHits_DisableObject((int)obj);
                }
                *(byte*)(state + 0x5a) = *(byte*)(state + 0x5a) | 2;
                *(float*)(state + 8) = timeDelta;
                *(undefined*)(state + 0x3a) = 5;
            }
            else
            {
                if (frac > *(float*)(state + 0x10))
                {
                    *(float*)(obj + 4) = *(float*)(*(int*)(obj + 0x28) + 4);
                    *(undefined*)(state + 0x3a) = 1;
                }
                else
                {
                    placement = *(int*)(obj + 0x5c);
                    *(float*)(obj + 4) =
                        (*(float*)(placement + 8) / *(float*)(placement + 4)) *
                        (lbl_803E37C8 / *(float*)(placement + 0x10)) *
                        *(float*)(*(int*)(obj + 0x28) + 4);
                }
            }
            break;
        case 1:
            val = ObjHits_GetPriorityHit((int)obj, (undefined4*)0x0, (int*)0x0, (uint*)0x0);
            if ((val != 0) ||
                ((*(short*)(placement + 0x26) != -1 &&
                    (bitVal = GameBit_Get((int)*(short*)(placement + 0x26)), bitVal != 0))))
            {
                state = *(int*)(obj + 0x5c);
                placement = 0;
                do
                {
                    (*gPartfxInterface)->spawnObject(obj, 0x55a, NULL, 2, -1, NULL);
                    placement = placement + 1;
                }
                while (placement < 8);
                if (*(void**)(obj + 0x2a) != 0)
                {
                    ObjHits_DisableObject((int)obj);
                }
                *(byte*)(state + 0x5a) = *(byte*)(state + 0x5a) | 2;
                *(float*)(state + 8) = timeDelta;
                *(undefined*)(state + 0x3a) = 5;
            }
            else
            {
                if (frac > ((GroundBaddieState*)state)->baddie.posX)
                {
                    placement = 0;
                    do
                    {
                        (*gPartfxInterface)->spawnObject(obj, 0x55a, NULL, 2, -1, NULL);
                        placement = placement + 1;
                    }
                    while (placement < 8);
                    *(undefined*)(state + 0x3a) = 2;
                }
                else
                {
                    placement = (*(int (**)(void*))(*gSHthorntailAnimationInterface + 0x24))(msgExtra);
                    if (placement != 0)
                    {
                        FUN_8002fc3c(lbl_803E3804, timeDelta);
                    }
                    else
                    {
                        FUN_8002fc3c(lbl_803E3808, timeDelta);
                    }
                }
            }
            break;
        case 2:
            if (frac > ((GroundBaddieState*)state)->baddie.posY)
            {
                val = *(int*)(obj + 0x5c);
                wordPtr2 = (undefined4*)FUN_80039520((int)obj, 0);
                *wordPtr2 = 0;
                *(float*)(val + 0x24) = lbl_803E37C8;
                *(float*)(obj + 4) = *(float*)(*(int*)(obj + 0x28) + 4);
                FUN_80017a78((int)obj, 1);
                *(undefined*)(state + 0x3a) = 3;
            }
            else
            {
                val = *(int*)(obj + 0x5c);
                fa = *(float*)(val + 8);
                fb = -(*(float*)(val + 4) * *(float*)(val + 0x14) - fa) /
                (*(float*)(val + 4) *
                    (*(float*)(val + 0x18) - *(float*)(val + 0x14)));
                fa = fa * fa * fa * fa;
                state = (int)((fa * fa) / *(float*)(val + 0x54));
                wordPtr = (int*)FUN_80039520((int)obj, 0);
                *wordPtr = 0x100 - state;
                *(float*)(val + 0x24) = lbl_803E37D0 * fb + lbl_803E37CC;
                *(float*)(obj + 4) = *(float*)(*(int*)(obj + 0x28) + 4) * *(float*)(val + 0x24);
                FUN_80017a78((int)obj, 1);
            }
            state = ObjHits_GetPriorityHit((int)obj, (undefined4*)0x0, (int*)0x0, (uint*)0x0);
            if ((state != 0) ||
                ((*(short*)(placement + 0x26) != -1 &&
                    (bitVal = GameBit_Get((int)*(short*)(placement + 0x26)), bitVal != 0))))
            {
                FUN_8017db40((uint)obj, 1);
            }
            break;
        case 3:
            *(float*)(state + 8) = fb - timeDelta;
            if (frac > ((GroundBaddieState*)state)->baddie.posZ)
            {
                FUN_8017db40((uint)obj, 0);
            }
            else
            {
                state = ObjHits_GetPriorityHit((int)obj, (undefined4*)0x0, (int*)0x0, (uint*)0x0);
                if ((state != 0) ||
                    ((*(short*)(placement + 0x26) != -1 &&
                        (bitVal = GameBit_Get((int)*(short*)(placement + 0x26)), bitVal != 0))))
                {
                    FUN_8017db40((uint)obj, 2);
                }
            }
            break;
        case 4:
            if (frac > *(float*)(state + 0x20))
            {
                *(undefined*)(state + 0x3a) = 6;
                *(float*)(state + 8) = timeDelta;
            }
            else
            {
                placement = 0;
                val = 0;
                fd = lbl_803E37D4;
                do
                {
                    f32 t = *(float*)(state + 0xc);
                    if (placement != 0) break;
                    fb = t * (((GroundBaddieState*)state)->baddie.velZ + ((GroundBaddieState*)state)->baddie.velY);
                    fc = t * fb + (*(float*)(state + 0x44) * t + *(float*)(state + 0x2c));
                    if (*(float*)(state + 0x28) <= fd)
                    {
                        placement = FUN_8017e15c(fc, obj, state);
                    }
                    else
                    {
                        placement = FUN_8017e3c0(fc, obj, state);
                    }
                    val = val + 1;
                }
                while ((val == 100) || (val != 0x66));
                if (lbl_803E37D4 != *(float*)(state + 0x30))
                {
                    fb = *(float*)(state + 0xc) / *(float*)(state + 0x50);
                    *obj = (f32) * (s16*)(state + 0x48) * fb;
                    obj[1] = (f32) * (s16*)(state + 0x4a) * fb;
                    obj[2] = (f32) * (s16*)(state + 0x4c) * fb;
                }
                wordPtr = (int*)FUN_80039520((int)obj, 0);
                *wordPtr = (int)(lbl_803E380C * frac);
                FUN_8017de58((uint)obj);
            }
            break;
        case 5:
            if (lbl_803E3810 < fb)
            {
                placement = *(int*)(obj + 0x5c);
                if (((GameObject*)obj)->anim.flags & 0x2000)
                {
                    Obj_FreeObject((int)obj);
                }
                else
                {
                    if (*(void**)(obj + 0x2a) != 0)
                    {
                        ObjHits_DisableObject((int)obj);
                    }
                    *(byte*)(placement + 0x5a) = *(byte*)(placement + 0x5a) | 2;
                }
            }
            break;
        case 6:
            frac = lbl_803E3814;
            if (fb > frac)
            {
                placement = *(int*)(obj + 0x5c);
                if (((GameObject*)obj)->anim.flags & 0x2000)
                {
                    Obj_FreeObject((int)obj);
                }
                else
                {
                    if (*(void**)(obj + 0x2a) != 0)
                    {
                        ObjHits_DisableObject((int)obj);
                    }
                    *(byte*)(placement + 0x5a) = *(byte*)(placement + 0x5a) | 2;
                }
            }
            else
            {
                placement = (int)(lbl_803E3818 * fb / frac);
                *(char*)(obj + 0x1b) = -1 - (char)placement;
                FUN_8017de58((uint)obj);
            }
        }
    }
switchD_8017e864_caseD_7:
    return;
}

/*
 * --INFO--
 *
 * Function: appleontree_init
 * EN v1.0 Address: 0x8017E964
 * EN v1.0 Size: 684b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void appleontree_init(int obj, int def)
{
    int state;
    f32 zeroScale;
    f32 timeScale;
    f32 progress;
    int eventBit;
    int* texture;

    state = *(int*)&((GameObject*)obj)->extra;

    ((CrackAnimState*)state)->unk0 = ((AppleontreeObjectDef*)def)->unk18;
    ((CrackAnimState*)state)->duration = (f32)((AppleontreeObjectDef*)def)->duration;
    ((CrackAnimState*)state)->elapsed = (f32)((AppleontreeObjectDef*)def)->elapsed;
    {
        f32 scale = lbl_803E3828;
        ((CrackAnimState*)state)->stageEnd0 = (f32)((AppleontreeObjectDef*)def)->unk20 / scale;
        ((CrackAnimState*)state)->stageEnd1 = ((CrackAnimState*)state)->stageEnd0 + (f32)((AppleontreeObjectDef*)def)->
            unk21 / scale;
        ((CrackAnimState*)state)->stageEnd2 = ((CrackAnimState*)state)->stageEnd1 + (f32)((AppleontreeObjectDef*)def)->
            unk22 / scale;
        ((CrackAnimState*)state)->stageEnd3 = ((CrackAnimState*)state)->stageEnd2 + (f32)((AppleontreeObjectDef*)def)->
            unk23 / scale;
        ((CrackAnimState*)state)->unk20 = (f32)((AppleontreeObjectDef*)def)->unk24 / scale;
        ((CrackAnimState*)state)->unk28 = (f32)((AppleontreeObjectDef*)def)->unk25 / scale;
        ((CrackAnimState*)state)->unk28 = ((CrackAnimState*)state)->unk28 * lbl_803E37DC;
        ((CrackAnimState*)state)->unk24 = lbl_803E37C8;
        ((CrackAnimState*)state)->unk38 = 0;
        zeroScale = lbl_803E37D4;
        ((CrackAnimState*)state)->unk3C = zeroScale;
        ((CrackAnimState*)state)->unk40 = lbl_803E382C;
        ((CrackAnimState*)state)->unk44 = zeroScale;

        timeScale = ((CrackAnimState*)state)->duration * ((CrackAnimState*)state)->stageEnd2;
        timeScale *= timeScale;
        timeScale *= timeScale;
        ((CrackAnimState*)state)->unk54 = (timeScale * timeScale) * lbl_803E3830;

        ((GameObject*)obj)->anim.rotX = (s16)randomGetRange(-0x8000, 0x7fff);
        ((GameObject*)obj)->anim.rootMotionScale = lbl_803E3834;
        Obj_SetActiveModelIndex(obj, 0);

        eventBit = ((AppleontreeObjectDef*)def)->unk26;
        if ((eventBit != -1) && (GameBit_Get(eventBit) != 0))
        {
            ((CrackAnimState*)state)->elapsed = lbl_803E3838;
            ((CrackAnimState*)state)->stage = 6;
        }
        else
        {
            progress = ((CrackAnimState*)state)->elapsed / ((CrackAnimState*)state)->duration;
            if (progress < ((CrackAnimState*)state)->stageEnd0)
            {
                ((CrackAnimState*)state)->stage = 0;
            }
            else if (progress < ((CrackAnimState*)state)->stageEnd1)
            {
                ((GameObject*)obj)->anim.rootMotionScale = *(f32*)(*(int*)&((GameObject*)obj)->anim.modelInstance + 4);
                ((CrackAnimState*)state)->stage = 1;
            }
            else if (progress < ((CrackAnimState*)state)->stageEnd2)
            {
                ((CrackAnimState*)state)->stage = 2;
            }
            else
            {
                state = *(int*)&((GameObject*)obj)->extra;
                texture = objFindTexture(obj, 0, 0);
                *texture = 0;
                ((CrackAnimState*)state)->unk24 = lbl_803E37C8;
                ((GameObject*)obj)->anim.rootMotionScale = *(f32*)(*(int*)&((GameObject*)obj)->anim.modelInstance + 4);
                Obj_SetActiveModelIndex(obj, 1);
                ((CrackAnimState*)state)->stage = 3;
            }
        }

        ObjMsg_AllocQueue(obj, 2);
    }
}

/* Trivial 4b 0-arg blr leaves. */
void dll_FC_free_nop(void);

/* 8b "li r3, N; blr" returners. */
int dll_FC_getExtraSize_ret_8(void);
int dll_FC_getObjectTypeId(void);

/* render-with-objRenderFn_8003b8f4 pattern. */
extern f32 lbl_803E3848;

void dll_FC_render(int p1, int p2, int p3, int p4, int p5, s8 visible);

extern void dll_FC_initialise_nop(void);
extern void dll_FC_release_nop(void);
extern void dll_FC_init(int obj, int objDef);
extern void dll_FC_update(int obj);
extern void dll_FC_hitDetect(int* obj);

extern void objRenderFn_80041018(int* obj);

void dll_FC_hitDetect(int* obj);

ObjectDescriptor gDllFCObjDescriptor = {
    0, 0, 0, OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)dll_FC_initialise_nop,
    (ObjectDescriptorCallback)dll_FC_release_nop,
    0,
    (ObjectDescriptorCallback)dll_FC_init,
    (ObjectDescriptorCallback)dll_FC_update,
    (ObjectDescriptorCallback)dll_FC_hitDetect,
    (ObjectDescriptorCallback)dll_FC_render,
    (ObjectDescriptorCallback)dll_FC_free_nop,
    (ObjectDescriptorCallback)dll_FC_getObjectTypeId,
    dll_FC_getExtraSize_ret_8,
};
