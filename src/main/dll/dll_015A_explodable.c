/*
 * explodable (DLL 0x15A) - a destructible scenery prop that shatters into
 * up to 15 physics fragments (chunks) when its activate game bit is set.
 *
 * explodable_init seeds the fragment chunk array (DrExplodableChunk[15]) and
 * looks up the prop's break recipe (object type / sfx / mode flags) from the
 * gas-vent table gExplodableBreakRecipeTable, keyed on the object's seqId. If the activate
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
#include "main/object_descriptor.h"
#include "main/dll/dll_015A_explodable.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/math_api.h"
#include "main/vecmath.h"
#include "main/game_object.h"
#include "main/object.h"
#include "main/object_api.h"
#include "main/model.h"
#include "track/intersect_api.h"
#include "main/dll/dll_0166_exploded.h"
#include "main/dll/IM/IMspacecraft.h"
#include "main/dll/MMP/dll_017E_mmplevelcontrol.h"

STATIC_ASSERT(sizeof(DrExplodableChunk) == 0x70);

STATIC_ASSERT(offsetof(DrExplodableState, children) == 0x690);
STATIC_ASSERT(sizeof(DrExplodableState) == 0x6e8);

#define EXPLODABLE_OBJFLAG_HIDDEN 0x4000

/* object group this prop registers its fragments under */
#define EXPLODABLE_OBJ_GROUP 0x21
/* fragment object vtable slot returning its lifecycle status */
#define FRAGMENT_VTABLE_STATUS 0x20

/* DrExplodableState.phase6E4 progression (see file header) */
#define EXPLODABLE_PHASE_WAIT     0 /* wait for the activate game bit */
#define EXPLODABLE_PHASE_BREAKING 1 /* fragments spawned; poll their status */
#define EXPLODABLE_PHASE_BROKEN   2 /* already broken, nothing to do */

extern GasVentTableEntry gExplodableBreakRecipeTable[];


int explodable_spawnFragmentObject(GameObject* obj, int objType, int chunkSrc, int fragmentIndex)
{
    ExplodableFragmentSetup* s;
    f32 f1;
    DrExplodableChunk* c = (DrExplodableChunk*)chunkSrc;

    if (Obj_IsLoadingLocked() == 0)
    {
        return 0;
    }
    s = (ExplodableFragmentSetup*)Obj_AllocObjectSetup(0x44, objType);
    s->seqId = objType;
    s->colorR = 2;
    s->colorB = 0xff;
    s->colorG = 1;
    s->colorA = 0xff;
    s->posX = obj->anim.localPosX;
    s->posY = obj->anim.localPosY;
    s->posZ = obj->anim.localPosZ;
    f1 = 100.0f;
    s->velX = 100.0f * c->velX;
    s->velY = f1 * c->velY;
    s->velZ = f1 * c->velZ;
    s->rotX = c->rotX;
    s->rotY = c->rotY;
    s->rotZ = c->rotZ;
    s->spinX = c->spinX * (f32)(u32)c->spinScale;
    s->spinY = c->spinY * (f32)(u32)c->spinScale;
    s->spinZ = c->spinZ * (f32)(u32)c->spinScale;
    f1 = 10.0f;
    s->spin2X = 10.0f * c->spin2X;
    s->spin2Z = f1 * c->spin2Z;
    s->spin2Y = f1 * c->spin2Y;
    f1 = 1000.0f;
    s->vel2X = 1000.0f * c->vel2X;
    s->vel2Y = f1 * c->vel2Y;
    s->vel2Z = f1 * c->vel2Z;
    s->fragmentIndex = fragmentIndex;
    s->scale = (s8)(int)(20.0f * (obj->anim.rootMotionScale / obj->anim.modelInstance->rootMotionScaleBase));
    s->launchDelayBase = c->launchDelayBase;
    s->height = (int)c->height;
    return (int)Obj_SetupObject((ObjPlacement*)s, 5, obj->anim.mapEventSlot, -1, NULL);
}

void explodable_buildFragments(GameObject* obj, int def, int skipCentroid, int state)
{
    DrExplodableChunk* c;
    int i14;
    int i8;
    int i13;
    int objType;
    u8 entMode;
    int vertexIdx;
    ModelFileHeader* model;
    GasVentTableEntry* e;
    f32 zero;
    DrExplodableState* st = (DrExplodableState*)state;
    struct
    {
        f32 v[3];
        f32 acc[3];
    } s;

    e = (GasVentTableEntry*)gExplodableBreakRecipeTable;
    objType = e[st->recipeIndex].objType;
    st->breakSfx = e[st->recipeIndex].sfx;
    entMode = e[st->recipeIndex].mode;
    if (objType != -1)
    {
        i13 = 0;
        c = (DrExplodableChunk*)state;
        i14 = 0;
        i8 = state;
        for (; i13 < st->count6D4; i13++)
        {
            *(u8*)(state + i13 + offsetof(DrExplodableState, spawnedFlags)) = 1;
            c->spinScale = entMode;
            if (skipCentroid == 0)
            {
                zero = 0.0f;
                c->centroidX = zero;
                c->centroidY = zero;
                c->centroidZ = zero;
                model = (ModelFileHeader*)*(int*)(*(int*)(*(int*)&(obj)->anim.banks + i14));
                s.acc[0] = zero;
                s.acc[1] = zero;
                s.acc[2] = zero;
                for (vertexIdx = 0; vertexIdx < model->vertexCount; vertexIdx++)
                {
                    Model_GetVertexPosition(model, vertexIdx, s.v);
                    s.acc[0] = s.v[0] + s.acc[0];
                    s.acc[1] = s.v[1] + s.acc[1];
                    s.acc[2] = s.v[2] + s.acc[2];
                }
                c->centroidX = s.acc[0] * ((zero = 1.0f) / (f32)(u32)model->vertexCount);
                c->centroidY = s.acc[1] * (zero / (f32)(u32)model->vertexCount);
                c->centroidZ = s.acc[2] * (zero / (f32)(u32)model->vertexCount);
            }
            c->offX = c->centroidX;
            c->offY = c->centroidY;
            c->offZ = c->centroidZ;
            explodable_computeFragmentLaunch(obj, (int)c, def);
            c->unk6B = 0xff;
            c->gameBitMode = (u32)mainGetBit(((ExplodablePlacement*)def)->doneGameBit) != 0 ? 2 : 0;
            ((DrExplodableState*)i8)->children[0] = (GameObject*)explodable_spawnFragmentObject(obj, objType, (int)c, i13);
            c++;
            i14 += 4;
            i8 += 4;
        }
        st->phase6E4 = ((u32)mainGetBit(((ExplodablePlacement*)def)->doneGameBit) != 0)
                                                    ? EXPLODABLE_PHASE_BREAKING
                                                    : EXPLODABLE_PHASE_WAIT;
    }
}

void explodable_computeFragmentLaunch(GameObject* obj, int chunkSlot, int def)
{
    f32 dx;
    f32 dy;
    f32 dz;
    f32 mag;
    f32 scale;
    int max2;
    DrExplodableChunk* c = (DrExplodableChunk*)chunkSlot;
    int max;
    ExplodablePlacement* d = (ExplodablePlacement*)def;
    f32 zero = 0.0f;

    vecRotateZXY((s16*)(def + 0x1a), &c->offX);
    c->posX = c->offX * obj->anim.rootMotionScale + d->base.posX;
    c->posY = c->offY * obj->anim.rootMotionScale + d->base.posY;
    c->posZ = c->offZ * obj->anim.rootMotionScale + d->base.posZ;
    c->rotX = d->rotX;
    c->rotY = d->rotY;
    c->rotZ = d->rotZ;
    dx = c->offX - (f32)d->originX;
    dy = c->offY - (f32)d->originY;
    dz = c->offZ - (f32)d->originZ;
    mag = sqrtf(dz * dz + (dx * dx + dy * dy));
    if (mag != zero)
    {
        scale = (f32)d->launchForce / (5.0f * mag);
        if (dx != zero || dy != zero || dz != zero)
        {
            normalize(&dx, &dy, &dz);
        }
        c->velX = dx * scale;
        c->velY = dy * scale;
        c->velZ = dz * scale;
        max = (int)(200.0f * (0.5f + scale));
        c->spinX = (f32)(int)randomGetRange(0, max) / 50.0f;
        c->spinY = (f32)(int)randomGetRange(0, max) / 50.0f;
        c->spinZ = (f32)(int)randomGetRange(0, max) / 50.0f;
        scale = (f32)d->launchScale2 / 1000.0f;
        if (obj->anim.velocityX > 0.0f)
        {
            c->launchFlags |= 1;
        }
        if (obj->anim.velocityZ > 0.0f)
        {
            c->launchFlags |= 2;
        }
        if (c->spinX > 0.0f)
        {
            c->launchFlags |= 4;
        }
        if (c->spinY > 0.0f)
        {
            c->launchFlags |= 8;
        }
        if (c->spinZ > 0.0f)
        {
            c->launchFlags |= 0x10;
        }
        max2 = (int)(200.0f * (0.5f + scale));
        c->spin2X = (f32)(int)randomGetRange(0, max2) / 200.0f;
        c->spin2Y = (f32)(int)randomGetRange(0, max2) / 200.0f;
        c->spin2Z = (f32)(int)randomGetRange(0, max2) / 200.0f;
        c->vel2X = dx * scale;
        c->vel2Y = dy * scale - 0.07f;
        c->vel2Z = dz * scale;
        {
            int height = d->fragmentHeight;
            if (height != 0)
            {
                c->height = height;
            }
        }
        *(u32*)&c->launchDelayBase = d->launchDelayBase;
        if (d->launchDelayBase != 0)
        {
            c->launchDelay = (int)(d->launchDelayBase * (randomGetRange(0, 100) + 100)) / 200;
        }
        else
        {
            c->launchDelay = -1;
        }
    }
}

int explodable_getExtraSize(void)
{
    return 0x6e8;
}

void explodable_free(GameObject* obj, int flag)
{
    int state;
    int i = -1;
    int slotPtr;
    GameObject* child;

    state = *(int*)&(obj)->extra;
    ObjGroup_RemoveObject(obj, EXPLODABLE_OBJ_GROUP);
    if (flag == 0)
    {
        slotPtr = state - 4;
        while (slotPtr += 4, ++i < 15)
        {
            child = ((DrExplodableState*)slotPtr)->children[0];
            if (child != NULL)
            {
                Obj_FreeObject(child);
            }
        }
    }
}

void explodable_render(void)
{
}

void explodable_update(GameObject* obj)
{
    int slotPtr;
    int def;
    int i;
    int state;
    int status;
    int fragObj;
    DrExplodableState* s;
    ExplodablePlacement* d;

    state = *(int*)&(obj)->extra;
    def = *(int*)&(obj)->anim.placementData;
    s = (DrExplodableState*)state;
    d = (ExplodablePlacement*)def;
    if (s->phase6E4 != EXPLODABLE_PHASE_BROKEN)
    {
        if (s->phase6E4 == EXPLODABLE_PHASE_WAIT)
        {
            if ((u32)mainGetBit(d->activateGameBit) != 0)
            {
                explodable_buildFragments(obj, def, 0, state);
                if (s->breakSfx != 0)
                {
                    Sfx_PlayFromObject(obj, s->breakSfx & 0xffff);
                }
                s->phase6E4 = EXPLODABLE_PHASE_BREAKING;
                (obj)->anim.alpha = 0;
            }
            else
            {
                return;
            }
        }
        else
        {
            i = 0;
            slotPtr = state;
            do
            {
                fragObj = (int)((DrExplodableState*)slotPtr)->children[0];
                if ((void*)fragObj != NULL)
                {
                    status = (*(VtableFn*)(*(int*)*(int*)(fragObj + 0x68) + FRAGMENT_VTABLE_STATUS))(fragObj);
                    switch (status)
                    {
                    case 2:
                        mainSetBits(d->doneGameBit, 1);
                        Obj_FreeObject(((DrExplodableState*)slotPtr)->children[0]);
                        ((DrExplodableState*)slotPtr)->children[0] = NULL;
                        break;
                    case 0:
                        mainSetBits(d->doneGameBit, 1);
                        if ((s->flags6CC & (1 << i)) == 0)
                        {
                            s->flags6CC |= 1 << i;
                        }
                        break;
                    }
                }
                slotPtr += 4;
                i++;
            } while (i < 0xf);
        }
    }
}

void explodable_init(GameObject* obj, int setup)
{
    int state = *(int*)&(obj)->extra;
    int base;
    GasVentTableEntry* e;
    u32 count;
    DrExplodableState* st;
    ExplodablePlacement* su = (ExplodablePlacement*)setup;

    ObjGroup_AddObject(obj, EXPLODABLE_OBJ_GROUP);
    state = *(int*)&(obj)->extra;
    st = (DrExplodableState*)state;
    count = su->fragmentCount;
    if (count == 0)
    {
        count = 1;
    }
    st->count6D4 = count;
    *(int*)&st->flags6CC = 0;
    st->children[0] = 0;
    st->children[1] = 0;
    st->children[2] = 0;
    st->children[3] = 0;
    st->children[4] = 0;
    st->children[5] = 0;
    st->children[6] = 0;
    st->children[7] = 0;
    st->children[8] = 0;
    st->children[9] = 0;
    st->children[10] = 0;
    st->children[11] = 0;
    st->children[12] = 0;
    st->children[13] = 0;
    st->children[14] = 0;
    (obj)->anim.rotX = su->rotX;
    (obj)->anim.rotY = su->rotY;
    (obj)->anim.rotZ = su->rotZ;
    if ((u32)mainGetBit(su->doneGameBit) != 0)
    {
        st->phase6E4 = EXPLODABLE_PHASE_BROKEN;
    }
    for (base = 0; base < 16; base++)
    {
        if ((obj)->anim.seqId == gExplodableBreakRecipeTable[base].key)
        {
            st->recipeIndex = base;
            break;
        }
    }
    if (su->scaleParam == 0)
    {
        su->scaleParam = 0x14;
    }
    (obj)->anim.rootMotionScale = (obj)->anim.modelInstance->rootMotionScaleBase *
                                  (f32)(int)su->scaleParam / 20.0f;
    e = gExplodableBreakRecipeTable;
    if ((e[st->recipeIndex].flags & 1) != 0)
    {
        (obj)->objectFlags |= EXPLODABLE_OBJFLAG_HIDDEN;
    }
}


GasVentTableEntry gExplodableBreakRecipeTable[16] = {
    {124, 876, 216, 1, 0, {0, 0}},    {2098, 2099, 705, 50, 0, {0, 0}}, {147, 1408, 0, 100, 0, {0, 0}},
    {176, 903, 0, 100, 0, {0, 0}},    {677, 933, 0, 20, 0, {0, 0}},     {1257, 1258, 216, 1, 0, {0, 0}},
    {1078, 1079, 705, 50, 0, {0, 0}}, {125, 126, 705, 50, 0, {0, 0}},   {127, 129, 0, 10, 0, {0, 0}},
    {1399, 1401, 216, 50, 0, {0, 0}}, {255, 254, 0, 10, 1, {0, 0}},     {1531, 1532, 705, 50, 0, {0, 0}},
    {1910, 1911, 705, 50, 0, {0, 0}}, {1938, 1937, 705, 50, 0, {0, 0}}, {1190, 1201, 705, 50, 0, {0, 0}},
    {2071, 2072, 705, 50, 0, {0, 0}},
};

ObjectDescriptor gExplodableObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    0,
    0,
    0,
    (ObjectDescriptorCallback)explodable_init,
    (ObjectDescriptorCallback)explodable_update,
    0,
    (ObjectDescriptorCallback)explodable_render,
    (ObjectDescriptorCallback)explodable_free,
    0,
    explodable_getExtraSize,
};
