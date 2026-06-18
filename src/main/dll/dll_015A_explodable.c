/*
 * explodable (DLL 0x15A) - a destructible scenery prop that shatters into
 * up to 15 physics fragments (chunks) when its activate game bit is set.
 *
 * explodable_init seeds the fragment chunk array (DrExplodableChunk[15]) and
 * looks up the prop's break recipe (object type / sfx / mode flags) from the
 * gas-vent table lbl_80322DA0, keyed on the object's seqId. If the activate
 * bit is already set at load time the prop starts pre-exploded (phase 2).
 *
 * explodable_update drives the phase machine:
 *   phase 0: wait for the activate game bit, then build the fragments
 *            (explodable_buildFragments), play the break sfx and go invisible (phase 1).
 *   phase 1: poll each spawned fragment object's vtable status (slot +0x20);
 *            free finished fragments and raise the prop's done game bit.
 *   phase 2: already broken, nothing to do.
 *
 * explodable_computeFragmentLaunch computes a fragment's launch offset/velocity/spin from the
 * placement def and random spread; explodable_spawnFragmentObject spawns the fragment object.
 */
#include "main/dll/dll_015A_explodable.h"
#include "main/obj_placement.h"
#include "main/game_object.h"

extern u32 randomGetRange(int min, int max);

/* object group this prop registers its fragments under */
#define EXPLODABLE_OBJ_GROUP 0x21
/* fragment object vtable slot returning its lifecycle status */
#define FRAGMENT_VTABLE_STATUS 0x20

void explodable_render(void)
{
}

STATIC_ASSERT(sizeof(DrExplodableChunk) == 0x70);

STATIC_ASSERT(offsetof(DrExplodableState, children) == 0x690);
STATIC_ASSERT(sizeof(DrExplodableState) == 0x6e8);

int explodable_getExtraSize(void) { return 0x6e8; }

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
    ObjGroup_RemoveObject(obj, EXPLODABLE_OBJ_GROUP);
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
#pragma reset

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
                explodable_buildFragments(obj, def, 0, state);
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
                    r = (*(code*)(*(int*)*(int*)(o + 0x68) + FRAGMENT_VTABLE_STATUS))(o);
                    switch (r)
                    {
                    case 2:
                        GameBit_Set(((ExplodablePlacement*)def)->doneGameBit, 1);
                        Obj_FreeObject(*(int*)(p + 0x690));
                        *(int*)(p + 0x690) = 0;
                        break;
                    case 0:
                        GameBit_Set(((ExplodablePlacement*)def)->doneGameBit, 1);
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

extern GasVentTableEntry lbl_80322DA0[];
extern f32 lbl_803E435C;

void explodable_init(int obj, int setup)
{
    int state = *(int*)&((GameObject*)obj)->extra;
    int base;
    GasVentTableEntry* e;
    u32 count;

    ObjGroup_AddObject(obj, EXPLODABLE_OBJ_GROUP);
    state = *(int*)&((GameObject*)obj)->extra;
    count = *(u8*)(setup + 0x18);
    if (count == 0)
    {
        count = 1;
    }
    ((DrExplodableState*)state)->count6D4 = count;
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
    if ((u32)GameBit_Get(((ExplodablePlacement*)setup)->doneGameBit) != 0)
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
    if (((ExplodablePlacement*)setup)->scaleParam == 0)
    {
        ((ExplodablePlacement*)setup)->scaleParam = 0x14;
    }
    ((GameObject*)obj)->anim.rootMotionScale =
        ((GameObject*)obj)->anim.modelInstance->rootMotionScaleBase * (f32)(int)((ExplodablePlacement*)setup)->scaleParam / lbl_803E435C;
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

int explodable_spawnFragmentObject(int obj, int objType, int chunkSrc, int fragmentIndex)
{
    ExplodableFragmentSetup* s;
    f32 f1;
    DrExplodableChunk* c = (DrExplodableChunk*)chunkSrc;

    if (Obj_IsLoadingLocked() == 0)
    {
        return 0;
    }
    s = (ExplodableFragmentSetup*)Obj_AllocObjectSetup(0x44, objType);
    s->seqId = (s16)objType;
    s->unk04 = 2;
    s->unk06 = 0xff;
    s->unk05 = 1;
    s->unk07 = 0xff;
    s->posX = ((GameObject*)obj)->anim.localPosX;
    s->posY = ((GameObject*)obj)->anim.localPosY;
    s->posZ = ((GameObject*)obj)->anim.localPosZ;
    f1 = lbl_803E4350;
    s->velX = lbl_803E4350 * c->velX;
    s->velY = f1 * c->velY;
    s->velZ = f1 * c->velZ;
    s->rotX = c->rotX;
    s->rotY = c->rotY;
    s->rotZ = c->rotZ;
    s->spinX = c->spinX * (f32)(u32)
    c->spinScale;
    s->spinY = c->spinY * (f32)(u32)
    c->spinScale;
    s->spinZ = c->spinZ * (f32)(u32)
    c->spinScale;
    f1 = lbl_803E4354;
    s->unk32 = lbl_803E4354 * c->unk28;
    s->unk36 = f1 * c->unk30;
    s->unk34 = f1 * c->unk2C;
    f1 = lbl_803E4358;
    s->unk26 = lbl_803E4358 * c->unk34;
    s->unk28 = f1 * c->unk38;
    s->unk2A = f1 * c->unk3C;
    s->fragmentIndex = fragmentIndex;
    s->scale = (s8)(int)(
        lbl_803E435C * (((GameObject*)obj)->anim.rootMotionScale / *(f32*)(*(int*)&((GameObject*)obj)->anim.modelInstance
            + 4)));
    s->unk38 = c->unk5C;
    s->height = (int)c->height;
    return Obj_SetupObject((int)s, 5, ((GameObject*)obj)->anim.mapEventSlot, -1, 0);
}

extern void Model_GetVertexPosition(int model, int i, f32* out);
extern f32 lbl_803E4368;
extern f32 lbl_803E436C;

void explodable_buildFragments(int obj, int def, int skipCentroid, int state)
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
            if (skipCentroid == 0)
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
            explodable_computeFragmentLaunch(obj, i15, def);
            *(u8*)(i15 + 0x6b) = 0xff;
            *(u8*)(i15 + 0x6a) = (u32)GameBit_Get(((ExplodablePlacement*)def)->doneGameBit) != 0 ? 2 : 0;
            *(int*)(i8 + 0x690) = explodable_spawnFragmentObject(obj, objType, i15, i13);
            i15 += 0x70;
            i14 += 4;
            i8 += 4;
        }
        ((DrExplodableState*)state)->phase6E4 = ((u32)GameBit_Get(((ExplodablePlacement*)def)->doneGameBit) != 0) ? 1 : 0;
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

void explodable_computeFragmentLaunch(int obj, int chunkSlot, int def)
{
    f32 dx;
    f32 dy;
    f32 dz;
    f32 mag;
    f32 scale;
    int max2;
    DrExplodableChunk* c = (DrExplodableChunk*)chunkSlot;
    int max;

    vecRotateZXY((s16*)(def + 0x1a), &c->offX);
    c->posX = c->offX * ((GameObject*)obj)->anim.rootMotionScale + ((ExplodablePlacement*)def)->base.posX;
    c->posY = c->offY * ((GameObject*)obj)->anim.rootMotionScale + ((ExplodablePlacement*)def)->base.posY;
    c->posZ = c->offZ * ((GameObject*)obj)->anim.rootMotionScale + ((ExplodablePlacement*)def)->base.posZ;
    c->rotX = *(s16*)(def + 0x1a);
    c->rotY = *(s16*)(def + 0x1c);
    c->rotZ = *(s16*)(def + 0x1e);
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
