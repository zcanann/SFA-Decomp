#include "main/dll/drexplodable_types.h"
#include "main/obj_placement.h"
#include "main/game_object.h"
#include "main/objhits.h"

extern u32 randomGetRange(int min, int max);
extern void* FUN_80017aa4();
extern undefined4 FUN_80017ae4();
extern uint FUN_80017ae8();
extern undefined4 ObjGroup_AddObject();
extern undefined4 ObjMsg_AllocQueue();
extern int FUN_8005af70();
extern int FUN_8005b398();
extern uint FUN_80060058();
extern int FUN_800600c4();
extern int FUN_800600e4();
extern undefined4 FUN_8007f6e4();

extern undefined4* DAT_803dd740;
extern f64 DOUBLE_803e4f98;
extern f64 DOUBLE_803e4ff8;
extern f32 lbl_803E4F58;
extern f32 lbl_803E4FE8;
extern f32 lbl_803E4FEC;
extern f32 lbl_803E4FF0;
extern f32 lbl_803E4FF4;

#pragma scheduling on
#pragma peephole on
void fn_blasted_init_v11_unused(int param_1, int param_2)
{
    int extra;
    ObjHitsPriorityState* hitState;

    extra = *(int*)&((GameObject*)param_1)->extra;
    hitState = (ObjHitsPriorityState*)((GameObject*)param_1)->anim.hitReactState;
    *(byte*)(extra + 7) = *(byte*)(extra + 7) | 2;
    (**(code**)(*DAT_803dd740 + 4))(param_1, extra, 5);
    ObjGroup_AddObject(param_1, 0x19);
    ObjGroup_AddObject(param_1, 0x16);
    ObjMsg_AllocQueue(param_1, 8);
    ((GameObject*)param_1)->unkF8 = 0;
    *(undefined2*)(extra + 0x44) = 0;
    *(undefined2*)(extra + 0x46) = 0;
    *(undefined*)(extra + 0x15) = 0;
    *(undefined2*)(extra + 0x3c) = 0;
    *(undefined*)(extra + 0x16) = 0;
    *(undefined*)(extra + 0x17) = 0;
    *(undefined*)(extra + 0x3e) = 0;
    *(undefined4*)(extra + 0x40) = 0;
    *(float*)(extra + 0x30) = lbl_803E4F58;
    *(undefined*)(extra + 0x49) = 0;
    FUN_8007f6e4((undefined4*)(extra + 0x18));
    FUN_8007f6e4((undefined4*)(extra + 0x1c));
    *(byte*)(extra + 0x49) = *(byte*)(extra + 0x49) | 1;
    *(byte*)(extra + 0x48) =
        (*(char*)(param_2 + 0x19) < '\x01') << 7 | *(byte*)(extra + 0x48) & 0x7f;
    *(byte*)(extra + 0x48) = (*(short*)(param_2 + 0x1c) != 0) << 6 | *(byte*)(extra + 0x48) & 0xbf;
    ObjHits_EnableObject(param_1);
    *(float*)(extra + 0x2c) =
        (float)((double)CONCAT44(0x43300000, (int)hitState->primaryRadius ^ 0x80000000) - DOUBLE_803e4f98);
    *(byte*)(extra + 0x4a) = *(byte*)(extra + 0x4a) & 0xdf;
    *(float*)(extra + 0x38) = lbl_803E4F58;
    *(undefined4*)(extra + 0x10) = 0;
    (**(code**)(*DAT_803dd740 + 0x2c))(extra, 1);
    if (hitState != NULL)
    {
        hitState->trackContactMask = 1;
    }
    if (((GameObject*)param_1)->anim.seqId == 0x754)
    {
        *(byte*)(extra + 0x4a) = *(byte*)(extra + 0x4a) & 0xfb | 4;
    }
    return;
}

undefined4 FUN_801a2cb8(int param_1, uint param_2)
{
    int block;
    undefined4 result;
    uint id;
    int group;
    int entry;
    int j;
    int i;

    block = FUN_8005b398((double)((GameObject*)param_1)->anim.localPosX,
                         (double)((GameObject*)param_1)->anim.localPosY);
    block = FUN_8005af70(block);
    if ((block == 0) || ((*(ushort*)(block + 4) & 8) == 0))
    {
        result = 0;
    }
    else
    {
        for (i = 0; i < (int)(uint) * (ushort*)(block + 0x9a); i = i + 1)
        {
            entry = FUN_800600c4(block, i);
            id = FUN_80060058(entry);
            if (param_2 == id)
            {
                *(uint*)(entry + 0x10) = *(uint*)(entry + 0x10) | 3;
            }
        }
        for (i = 0; i < (int)(uint) * (byte*)(block + 0xa2); i = i + 1)
        {
            group = FUN_800600e4(block, i);
            entry = group;
            for (j = 0; j < (int)(uint) * (byte*)(group + 0x41); j = j + 1)
            {
                if (*(byte*)(entry + 0x29) == param_2)
                {
                    *(uint*)(group + 0x3c) = *(uint*)(group + 0x3c) | 2;
                }
                entry = entry + 8;
            }
        }
        result = 1;
    }
    return result;
}

undefined4
FUN_801a32d4(undefined8 param_1, undefined8 param_2, double param_3, undefined8 param_4,
             undefined8 param_5, undefined8 param_6, undefined8 param_7, undefined8 param_8, int param_9,
             undefined2 param_10, int param_11, undefined param_12, undefined4 param_13,
             undefined4 param_14, undefined4 param_15, undefined4 param_16)
{
    float scale;
    uint enabled;
    undefined4 result;
    undefined2* setup;
    double bias;

    enabled = FUN_80017ae8();
    if ((enabled & 0xff) == 0)
    {
        result = 0;
    }
    else
    {
        setup = FUN_80017aa4(0x44, param_10);
        *setup = param_10;
        *(undefined*)(setup + 2) = 2;
        *(undefined*)(setup + 3) = 0xff;
        *(undefined*)((int)setup + 5) = 1;
        *(undefined*)((int)setup + 7) = 0xff;
        *(undefined4*)(setup + 4) = *(undefined4*)&((GameObject*)param_9)->anim.localPosX;
        *(undefined4*)(setup + 6) = *(undefined4*)&((GameObject*)param_9)->anim.localPosY;
        *(undefined4*)(setup + 8) = *(undefined4*)&((GameObject*)param_9)->anim.localPosZ;
        scale = lbl_803E4FE8;
        setup[0x10] = (short)(int)(lbl_803E4FE8 * *(float*)(param_11 + 0x40));
        setup[0x11] = (short)(int)(scale * *(float*)(param_11 + 0x44));
        setup[0x12] = (short)(int)(scale * *(float*)(param_11 + 0x48));
        setup[0xd] = *(undefined2*)(param_11 + 0x68);
        setup[0xe] = *(undefined2*)(param_11 + 0x66);
        setup[0xf] = *(undefined2*)(param_11 + 100);
        bias = DOUBLE_803e4ff8;
        setup[0x16] = (short)(int)(*(float*)(param_11 + 0x1c) *
            (float)((double)CONCAT44(0x43300000, (uint) * (byte*)(param_11 + 0x6d))
                - DOUBLE_803e4ff8));
        setup[0x17] = (short)(int)(*(float*)(param_11 + 0x20) *
            (float)((double)CONCAT44(0x43300000, (uint) * (byte*)(param_11 + 0x6d))
                - bias));
        setup[0x18] = (short)(int)(*(float*)(param_11 + 0x24) *
            (float)((double)CONCAT44(0x43300000, (uint) * (byte*)(param_11 + 0x6d))
                - bias));
        scale = lbl_803E4FEC;
        setup[0x19] = (short)(int)(lbl_803E4FEC * *(float*)(param_11 + 0x28));
        setup[0x1b] = (short)(int)(scale * *(float*)(param_11 + 0x30));
        setup[0x1a] = (short)(int)(scale * *(float*)(param_11 + 0x2c));
        scale = lbl_803E4FF0;
        setup[0x13] = (short)(int)(lbl_803E4FF0 * *(float*)(param_11 + 0x34));
        setup[0x14] = (short)(int)(scale * *(float*)(param_11 + 0x38));
        setup[0x15] = (short)(int)(scale * *(float*)(param_11 + 0x3c));
        *(undefined*)(setup + 0xc) = param_12;
        bias = (double)lbl_803E4FF4;
        scale = ((GameObject*)param_9)->anim.rootMotionScale;
        *(char*)((int)setup + 0x3d) =
            (char)(int)(bias * (double)(float)((double)scale /
                (double)*(float*)(*(int*)&((GameObject*)param_9)->anim.modelInstance + 4)));
        setup[0x1c] = (short)*(undefined4*)(param_11 + 0x5c);
        setup[0x1d] = (short)(int)*(float*)(param_11 + 0x58);
        result = FUN_80017ae4((double)scale, bias, param_3, param_4, param_5, param_6, param_7, param_8, setup,
                             5, ((GameObject*)param_9)->anim.mapEventSlot, 0xffffffff, (uint*)0x0, param_14, param_15,
                             param_16);
    }
    return result;
}

void explodable_render(void)
{
}

void cfforcefield_free(void);

/* 8b "li r3, N; blr" returners. */

typedef struct ExplodablePlacement
{
    u8 pad0[0x1A - 0x0];
    s16 rotX;
    s16 rotY;
    s16 rotZ;
    s16 unk20;
    s16 unk22;
    s16 unk24;
    u8 pad26[0x2C - 0x26];
    s16 unk2C;
    s16 unk2E;
    s16 unk30;
    u8 pad32[0x38 - 0x32];
    u16 unk38;
    u8 pad3A[0x3E - 0x3A];
    s16 unk3E;
    s16 activateGameBit;
    u8 pad42[0x48 - 0x42];
} ExplodablePlacement;

STATIC_ASSERT(sizeof(DrExplodableChunk) == 0x70);

STATIC_ASSERT(offsetof(DrExplodableState, children) == 0x690);
STATIC_ASSERT(sizeof(DrExplodableState) == 0x6e8);

int explodable_getExtraSize(void) { return 0x6e8; }
int cfforcefield_getExtraSize(void);

extern void Obj_FreeObject(int obj);
#pragma scheduling off
#pragma peephole off
void explodable_free(int obj, int flag)
{
    int state;
    int i = -1;
    int p;
    void* o;

    state = *(int*)&((GameObject*)obj)->extra;
    ObjGroup_RemoveObject(obj, 0x21);
    if (flag == 0)
    {
        p = state - 4;
        while (p += 4, ++i < 15)
        {
            o = *(void* *)&((DrExplodableState*)p)->children[0];
            if (o != NULL)
            {
                Obj_FreeObject((int)o);
            }
        }
    }
}


extern void fn_801A2E80(int obj, int def, int p3, int state);

void explodable_update(int obj)
{
    int p;
    int def;
    int i;
    int state;
    int r;
    int o;

    state = *(int*)&((GameObject*)obj)->extra;
    def = *(int*)&((GameObject*)obj)->anim.placementData;
    if (((DrExplodableState*)state)->phase6E4 != 2)
    {
        if (((DrExplodableState*)state)->phase6E4 == 0)
        {
            if ((u32)GameBit_Get(((ExplodablePlacement*)def)->activateGameBit) != 0)
            {
                fn_801A2E80(obj, def, 0, state);
                if (((DrExplodableState*)state)->unk6D0 != 0)
                {
                    Sfx_PlayFromObject(obj, ((DrExplodableState*)state)->unk6D0 & 0xffff);
                }
                ((DrExplodableState*)state)->phase6E4 = 1;
                ((GameObject*)obj)->anim.alpha = 0;
            }
            else
            {
                return;
            }
        }
        else
        {
            i = 0;
            p = state;
            do
            {
                o = *(int*)(p + 0x690);
                if ((void*)o != NULL)
                {
                    r = (*(code*)(*(int*)*(int*)(o + 0x68) + 0x20))(o);
                    switch (r)
                    {
                    case 2:
                        GameBit_Set(((ExplodablePlacement*)def)->unk3E, 1);
                        Obj_FreeObject(*(int*)(p + 0x690));
                        *(int*)(p + 0x690) = 0;
                        break;
                    case 0:
                        GameBit_Set(((ExplodablePlacement*)def)->unk3E, 1);
                        if ((((DrExplodableState*)state)->flags6CC & (1 << i)) == 0)
                        {
                            ((DrExplodableState*)state)->flags6CC |= 1 << i;
                        }
                        break;
                    }
                }
                p += 4;
                i++;
            }
            while (i < 0xf);
        }
    }
}

typedef struct
{
    int key;
    int objType;
    int sfx;
    u8 mode;
    u8 flags;
    u8 pad[2];
} GasVentTableEntry;

extern GasVentTableEntry lbl_80322DA0[];
extern f32 lbl_803E435C;

void explodable_init(int obj, int setup)
{
    int state = *(int*)&((GameObject*)obj)->extra;
    int base;
    GasVentTableEntry* e;
    u32 c1;

    ObjGroup_AddObject(obj, 0x21);
    state = *(int*)&((GameObject*)obj)->extra;
    c1 = *(u8*)(setup + 0x18);
    if (c1 == 0)
    {
        c1 = 1;
    }
    ((DrExplodableState*)state)->count6D4 = c1;
    *(int*)&((DrExplodableState*)state)->flags6CC = 0;
    ((DrExplodableState*)state)->children[0] = 0;
    ((DrExplodableState*)state)->children[1] = 0;
    ((DrExplodableState*)state)->children[2] = 0;
    ((DrExplodableState*)state)->children[3] = 0;
    ((DrExplodableState*)state)->children[4] = 0;
    ((DrExplodableState*)state)->children[5] = 0;
    ((DrExplodableState*)state)->children[6] = 0;
    ((DrExplodableState*)state)->children[7] = 0;
    ((DrExplodableState*)state)->children[8] = 0;
    ((DrExplodableState*)state)->children[9] = 0;
    ((DrExplodableState*)state)->children[10] = 0;
    ((DrExplodableState*)state)->children[11] = 0;
    ((DrExplodableState*)state)->children[12] = 0;
    ((DrExplodableState*)state)->children[13] = 0;
    ((DrExplodableState*)state)->children[14] = 0;
    ((GameObject*)obj)->anim.rotX = *(s16*)(setup + 0x1a);
    ((GameObject*)obj)->anim.rotY = *(s16*)(setup + 0x1c);
    ((GameObject*)obj)->anim.rotZ = *(s16*)(setup + 0x1e);
    if ((u32)GameBit_Get(*(s16*)(setup + 0x3e)) != 0)
    {
        ((DrExplodableState*)state)->phase6E4 = 2;
    }
    for (base = 0; base < 16; base++)
    {
        if (((GameObject*)obj)->anim.seqId == lbl_80322DA0[base].key)
        {
            ((DrExplodableState*)state)->unk6E5 = base;
            break;
        }
    }
    if (*(s8*)(setup + 0x3d) == 0)
    {
        *(u8*)(setup + 0x3d) = 0x14;
    }
    ((GameObject*)obj)->anim.rootMotionScale =
        ((GameObject*)obj)->anim.modelInstance->rootMotionScaleBase * (f32)(int) * (s8*)(setup + 0x3d) / lbl_803E435C;
    e = lbl_80322DA0;
    if ((e[((DrExplodableState*)state)->unk6E5].flags & 1) != 0)
    {
        ((GameObject*)obj)->objectFlags |= 0x4000;
    }
}

extern u8 Obj_IsLoadingLocked(void);
extern int Obj_AllocObjectSetup(int a, int b);
extern int Obj_SetupObject(int setup, int a, int b, int c, int d);
extern f32 lbl_803E4350;
extern f32 lbl_803E4354;
extern f32 lbl_803E4358;

int fn_801A2BDC(int p1, int p2, int p3, int p4)
{
    int s;
    f32 f1;
    DrExplodableChunk* c = (DrExplodableChunk*)p3;

    if (Obj_IsLoadingLocked() == 0)
    {
        return 0;
    }
    s = Obj_AllocObjectSetup(0x44, p2);
    *(s16*)(s + 0) = (s16)p2;
    *(u8*)(s + 4) = 2;
    *(u8*)(s + 6) = 0xff;
    *(u8*)(s + 5) = 1;
    *(u8*)(s + 7) = 0xff;
    *(f32*)(s + 8) = ((GameObject*)p1)->anim.localPosX;
    *(f32*)(s + 0xc) = ((GameObject*)p1)->anim.localPosY;
    *(f32*)(s + 0x10) = ((GameObject*)p1)->anim.localPosZ;
    f1 = lbl_803E4350;
    *(u16*)(s + 0x20) = lbl_803E4350 * c->velX;
    *(u16*)(s + 0x22) = f1 * c->velY;
    *(u16*)(s + 0x24) = f1 * c->velZ;
    *(s16*)(s + 0x1a) = c->unk68;
    *(s16*)(s + 0x1c) = c->unk66;
    *(s16*)(s + 0x1e) = c->unk64;
    *(u16*)(s + 0x2c) = c->spinX * (f32)(u32)
    c->spinScale;
    *(u16*)(s + 0x2e) = c->spinY * (f32)(u32)
    c->spinScale;
    *(u16*)(s + 0x30) = c->spinZ * (f32)(u32)
    c->spinScale;
    f1 = lbl_803E4354;
    *(u16*)(s + 0x32) = lbl_803E4354 * c->unk28;
    *(u16*)(s + 0x36) = f1 * c->unk30;
    *(u16*)(s + 0x34) = f1 * c->unk2C;
    f1 = lbl_803E4358;
    *(u16*)(s + 0x26) = lbl_803E4358 * c->unk34;
    *(u16*)(s + 0x28) = f1 * c->unk38;
    *(u16*)(s + 0x2a) = f1 * c->unk3C;
    *(u8*)(s + 0x18) = p4;
    *(s8*)(s + 0x3d) = (s8)(int)(
        lbl_803E435C * (((GameObject*)p1)->anim.rootMotionScale / *(f32*)(*(int*)&((GameObject*)p1)->anim.modelInstance
            + 4)));
    *(u16*)(s + 0x38) = c->unk5C;
    *(u16*)(s + 0x3a) = (int)c->height;
    return Obj_SetupObject(s, 5, ((GameObject*)p1)->anim.mapEventSlot, -1, 0);
}

extern void fn_801A30C0(int obj, int slot, int def);
extern void Model_GetVertexPosition(int model, int i, f32* out);
extern f32 lbl_803E4368;
extern f32 lbl_803E436C;

void fn_801A2E80(int obj, int def, int p3, int state)
{
    int i15;
    int i14;
    int i8;
    int i13;
    int objType;
    u8 entMode;
    int j;
    int model;
    GasVentTableEntry* e;
    f32 z;
    struct
    {
        f32 v[3];
        f32 acc[3];
    } s;

    e = (GasVentTableEntry*)lbl_80322DA0;
    objType = e[((DrExplodableState*)state)->unk6E5].objType;
    ((DrExplodableState*)state)->unk6D0 = e[((DrExplodableState*)state)->unk6E5].sfx;
    entMode = e[((DrExplodableState*)state)->unk6E5].mode;
    if (objType != -1)
    {
        i13 = 0;
        i15 = state;
        i14 = 0;
        i8 = state;
        for (; i13 < ((DrExplodableState*)state)->count6D4; i13++)
        {
            *(u8*)(state + i13 + 0x6d5) = 1;
            *(u8*)(i15 + 0x6d) = entMode;
            if (p3 == 0)
            {
                z = lbl_803E4368;
                *(f32*)(i15 + 4) = z;
                *(f32*)(i15 + 8) = z;
                *(f32*)(i15 + 0xc) = z;
                model = *(int*)(*(int*)(*(int*)&((GameObject*)obj)->anim.banks + i14));
                s.acc[0] = z;
                s.acc[1] = z;
                s.acc[2] = z;
                for (j = 0; j < *(u16*)(model + 0xe4); j++)
                {
                    Model_GetVertexPosition(model, j, s.v);
                    s.acc[0] = s.v[0] + s.acc[0];
                    s.acc[1] = s.v[1] + s.acc[1];
                    s.acc[2] = s.v[2] + s.acc[2];
                }
                *(f32*)(i15 + 4) = s.acc[0] * ((z = lbl_803E436C) / (f32)(u32) * (u16*)(model + 0xe4));
                *(f32*)(i15 + 8) = s.acc[1] * (z / (f32)(u32) * (u16*)(model + 0xe4));
                *(f32*)(i15 + 0xc) = s.acc[2] * (z / (f32)(u32) * (u16*)(model + 0xe4));
            }
            *(f32*)(i15 + 0x10) = *(f32*)(i15 + 4);
            *(f32*)(i15 + 0x14) = *(f32*)(i15 + 8);
            *(f32*)(i15 + 0x18) = *(f32*)(i15 + 0xc);
            fn_801A30C0(obj, i15, def);
            *(u8*)(i15 + 0x6b) = 0xff;
            *(u8*)(i15 + 0x6a) = (u32)GameBit_Get(*(s16*)(def + 0x3e)) != 0 ? 2 : 0;
            *(int*)(i8 + 0x690) = fn_801A2BDC(obj, objType, i15, i13);
            i15 += 0x70;
            i14 += 4;
            i8 += 4;
        }
        ((DrExplodableState*)state)->phase6E4 = ((u32)GameBit_Get(*(s16*)(def + 0x3e)) != 0) ? 1 : 0;
    }
}

extern void vecRotateZXY(s16 * rot, f32 * vec);
extern f32 sqrtf(f32 x);
extern void normalize(f32 * x, f32 * y, f32 * z);
extern f32 lbl_803E4370;
extern f32 lbl_803E4374;
extern f32 lbl_803E4378;
extern f32 lbl_803E437C;
extern f32 lbl_803E4380;

void fn_801A30C0(int obj, int slot, int def)
{
    f32 dx;
    f32 dy;
    f32 dz;
    f32 mag;
    f32 scale;
    int max2;
    DrExplodableChunk* c = (DrExplodableChunk*)slot;
    int max;

    vecRotateZXY((s16*)(def + 0x1a), &c->offX);
    c->posX = c->offX * ((GameObject*)obj)->anim.rootMotionScale + ((ObjPlacement*)def)->posX;
    c->posY = c->offY * ((GameObject*)obj)->anim.rootMotionScale + ((ObjPlacement*)def)->posY;
    c->posZ = c->offZ * ((GameObject*)obj)->anim.rootMotionScale + ((ObjPlacement*)def)->posZ;
    c->unk68 = *(s16*)(def + 0x1a);
    c->unk66 = *(s16*)(def + 0x1c);
    c->unk64 = *(s16*)(def + 0x1e);
    dx = c->offX - (f32) * (s16*)(def + 0x20);
    dy = c->offY - (f32) * (s16*)(def + 0x22);
    dz = c->offZ - (f32) * (s16*)(def + 0x24);
    mag = sqrtf(dz * dz + (dx * dx + dy * dy));
    if (mag != lbl_803E4368)
    {
        scale = (f32) * (s16*)(def + 0x2c) / (lbl_803E4370 * mag);
        if (dx != lbl_803E4368 || dy != lbl_803E4368 || dz != lbl_803E4368)
        {
            normalize(&dx, &dy, &dz);
        }
        c->velX = dx * scale;
        c->velY = dy * scale;
        c->velZ = dz * scale;
        max = (int)(lbl_803E4374 * (lbl_803E4378 + scale));
        c->spinX = (f32)(int)
        randomGetRange(0, max) / lbl_803E437C;
        c->spinY = (f32)(int)
        randomGetRange(0, max) / lbl_803E437C;
        c->spinZ = (f32)(int)
        randomGetRange(0, max) / lbl_803E437C;
        scale = (f32) * (s16*)(def + 0x30) / lbl_803E4358;
        if (((GameObject*)obj)->anim.velocityX > lbl_803E4368)
        {
            c->launchFlags |= 1;
        }
        if (((GameObject*)obj)->anim.velocityZ > lbl_803E4368)
        {
            c->launchFlags |= 2;
        }
        if (c->spinX > lbl_803E4368)
        {
            c->launchFlags |= 4;
        }
        if (c->spinY > lbl_803E4368)
        {
            c->launchFlags |= 8;
        }
        if (c->spinZ > lbl_803E4368)
        {
            c->launchFlags |= 0x10;
        }
        max2 = (int)(lbl_803E4374 * (lbl_803E4378 + scale));
        c->unk28 = (f32)(int)
        randomGetRange(0, max2) / lbl_803E4374;
        c->unk2C = (f32)(int)
        randomGetRange(0, max2) / lbl_803E4374;
        c->unk30 = (f32)(int)
        randomGetRange(0, max2) / lbl_803E4374;
        c->unk34 = dx * scale;
        c->unk38 = dy * scale - lbl_803E4380;
        c->unk3C = dz * scale;
        {
            int height = *(s16*)(def + 0x2e);
            if (height != 0)
            {
                c->height = (f32)height;
            }
        }
        *(u32*)&c->unk5C = *(u16*)(def + 0x38);
        if (*(u16*)(def + 0x38) != 0)
        {
            c->launchDelay = (int)(*(u16*)(def + 0x38) * (randomGetRange(0, 100) + 100)) / 200;
        }
        else
        {
            c->launchDelay = -1;
        }
    }
}
