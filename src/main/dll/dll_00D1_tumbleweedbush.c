/*
 * tumbleweedbush (DLL 0x00D1) - a destructible bush/cluster object that
 * spawns and manages a small array of detachable "piece" sub-objects.
 *
 * init seeds rotation from placement bytes, scales the capsule hitbox by
 * the placement rootMotionScale, and - keyed on anim.seqId - selects a
 * piece count (3) and a piece-offset template row in gTumbleweedBushPieceOffsetTable,
 * rotating each offset into world space.
 *
 * update polls a priority hit; on a hit (other than seqId 0x4ba) it spawns
 * a hit emitter, plays SFXsc_gethit04 and triggers each live piece's vtable
 * +0x28 callback. When the player comes within triggerRadius it repeatedly
 * calls fn_801631C8 to spawn sibling objects, and it prunes pieces whose
 * vtable +0x20 query reports >1.
 *
 * fn_801631C8 picks a sibling seqId from the bush seqId (0x28d->0x39d sun-
 * gated, 0x3fd->0x3fb, 0x4b9->0x4ba, 0x4be->0x4c1), finds a free piece
 * slot, caps the live sibling count at 7, and allocates/positions a new
 * sibling. fn_80163990 (called by tumbleweed) advances a detached piece's
 * gravity/spin. findNearestActive/setScale are shared piece helpers used
 * by sibling DLLs.
 */
#include "main/audio/sfx_ids.h"
#include "main/game_object.h"
#include "main/dll/dll_00D1_tumbleweedbush.h"
#include "main/obj_placement.h"
#include "main/sky_interface.h"
#include "main/sfa_shared_decls.h"

typedef struct TumbleweedBushState
{
    f32 scale;
    u8 pad04[4];
    u16 triggerRadius;
    u8 pad0A[2];
    void* pieceObjects[4];
    f32 pieceOffsets[3][3];
    u8 pad40[0x4c - 0x40];
    u8 variant;
    u8 pad4D[3];
    u8 pieceCount;
    u8 pad51[3];
} TumbleweedBushState;

extern u32 ObjHitbox_SetCapsuleBounds();

extern f32 timeDelta;
extern f32 lbl_803E2F48;
extern f32 lbl_803E2F4C;
extern f32 lbl_803E2F50;
extern f32 lbl_803E2F54;
extern u8 gTumbleweedBushPieceOffsetTable[];
extern void vecRotateZXY(void* obj, void* p);
extern void* memcpy(void* dst, const void* src, int n);
extern u8 gTumbleweedBushHitCooldownState;
extern void* Obj_GetPlayerObject(void);

extern int Sfx_PlayFromObject(int* obj, int sfx);
extern float sqrtf(float x);
extern f32 lbl_803E2F44;
extern void objRenderFn_8003b8f4(f32);
extern void* ObjGroup_GetObjects(int type, int* outCount);
extern f32 vec3f_distanceSquared(f32* a, f32* b);
extern f32 gTumbleweedBushNearestInitDist;
extern u8 Obj_IsLoadingLocked(void);
extern void* Obj_AllocObjectSetup(int size, int b);
extern int* Obj_SetupObject(int* obj, int a, int b, int c, void* d);
extern void* ObjList_GetObjects(int* outA, int* outB);
extern f32 lbl_803E2F40;
extern int fn_80065684(int a, f32 b, f32 val, f32 d, f32* out, int e);
extern f32 lbl_803E2F5C;
extern f32 lbl_803E2F60;
extern f32 lbl_803E2F64;
extern f32 lbl_803E2F68;

void tumbleweedbush_free(void)
{
}

void tumbleweedbush_hitDetect(void)
{
}

void tumbleweedbush_release(void)
{
}

void tumbleweedbush_initialise(void)
{
}

void tumbleweedbush_init(u8* obj, u8* params, int param3)
{
    u8* sub;
    f32 t;
    int idx;
    u8* pieceSlot;
    u8* pe;
    u8* pieceOffset;
    int i;

    sub = ((GameObject*)obj)->extra;
    *(f32*)sub = lbl_803E2F48;
    ((TumbleweedBushState*)sub)->triggerRadius = (u16)(params[0x1b] * 2);
    sub[0x4c] = params[0x23];
    ((GameObject*)obj)->anim.rotZ = (s16)((params[0x18] - 0x7f) << 7);
    ((GameObject*)obj)->anim.rotY = (s16)((params[0x19] - 0x7f) << 7);
    ((GameObject*)obj)->anim.rotX = (s16)(params[0x1a] << 8);
    ((GameObject*)obj)->anim.rootMotionScale = *(f32*)(params + 0x1c);
    t = ((GameObject*)obj)->anim.rootMotionScale;
    ObjHitbox_SetCapsuleBounds(obj,
                               (s32)(lbl_803E2F4C * t),
                               (s32)(lbl_803E2F50 * t),
                               (s32)(lbl_803E2F54 * t));
    switch (((GameObject*)obj)->anim.seqId)
    {
    case TUMBLEWEEDBUSH_SEQ_A:
    case TUMBLEWEEDBUSH_SEQ_C:
    case TUMBLEWEEDBUSH_SEQ_D:
        sub[0x50] = 3;
        idx = 0;
        break;
    case TUMBLEWEEDBUSH_SEQ_B:
        sub[0x50] = 3;
        idx = 1;
        break;
    }
    if (param3 == 0)
    {
        i = 0;
        pieceSlot = sub;
        pe = gTumbleweedBushPieceOffsetTable + idx * 0x30;
        pieceOffset = sub;
        for (; i < sub[0x50]; i++)
        {
            *(int*)(pieceSlot + 0xc) = 0;
            memcpy(pieceOffset + 0x1c, pe, 0xc);
            *(f32*)(pieceOffset + 0x1c) = *(f32*)(pieceOffset + 0x1c) * ((GameObject*)obj)->anim.rootMotionScale;
            *(f32*)(pieceOffset + 0x20) = *(f32*)(pieceOffset + 0x20) * ((GameObject*)obj)->anim.rootMotionScale;
            *(f32*)(pieceOffset + 0x24) = *(f32*)(pieceOffset + 0x24) * ((GameObject*)obj)->anim.rootMotionScale;
            vecRotateZXY(obj, pieceOffset + 0x1c);
            pieceSlot += 4;
            pe += 0xc;
            pieceOffset += 0xc;
        }
    }
}

int tumbleweedbush_getExtraSize(void) { return 0x54; }
int tumbleweedbush_getObjectTypeId(void) { return 0x0; }

#pragma optimization_level 2
void tumbleweedbush_update(int* obj)
{
    TumbleweedBushState* state;
    int* player;
    f32 hitExtra[3];
    f32 sunTime;
    int hit0;
    f32 dx, dy, d;
    int j;
    int nullVal;
    int** slot;
    int i;

    state = ((GameObject*)obj)->extra;
    player = Obj_GetPlayerObject();
    if (ObjHits_PollPriorityHitWithCooldown(obj, &gTumbleweedBushHitCooldownState, &hit0, hitExtra) != 0)
    {
        if (((GameObject*)hit0)->anim.seqId != TUMBLEWEEDBUSH_SIBLING_C)
        {
            objfx_spawnHitEmitterAtPos(hitExtra, 8, 0xff, 0xff, 0x78);
            Sfx_PlayFromObject(obj, SFXsc_gethit04);
            for (i = 0; (u8)i < state->pieceCount; i++)
            {
                slot = (int**)&state->pieceObjects[(u8)i];
                if (*slot != NULL)
                {
                    if (((GameObject*)obj)->anim.seqId == TUMBLEWEEDBUSH_SEQ_A)
                    {
                        if ((*gSkyInterface)->getSunPosition(&sunTime) == 0) continue;
                    }
                    ((void(*)(int*))*(int*)(*(int*)(*(int*)&((GameObject*)*slot)->anim.dll) + 0x28))(*slot);
                }
            }
        }
    }
    dx = ((GameObject*)obj)->anim.localPosX - ((GameObject*)player)->anim.localPosX;
    dy = ((GameObject*)obj)->anim.localPosZ - ((GameObject*)player)->anim.localPosZ;
    d = sqrtf(dx * dx + dy * dy);
    if ((u16)(s32)d < state->triggerRadius)
    {
        while ((s8)fn_801631C8(obj) != -1)
        {
        }
    }
    for (nullVal = j = 0; (u8)j < state->pieceCount; j++)
    {
        slot = (int**)&state->pieceObjects[(u8)j];
        if (*slot != NULL)
        {
            if (((int(*)(int*))*(int*)(*(int*)(*(int*)&((GameObject*)*slot)->anim.dll) + 0x20))(*slot) > 1)
            {
                *slot = (int*)nullVal;
            }
        }
    }
}

#pragma optimization_level reset
void fn_80163980(int* obj)
{
    u8 v = 0x7;
    *((u8*)(int*)((GameObject*)obj)->extra + 0x278) = v;
}

void tumbleweedbush_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0) objRenderFn_8003b8f4(lbl_803E2F44);
}

void* tumbleweedbush_findNearestActive(f32* p_pos)
{
    int count;
    void** list;
    f32 bestDist;
    int i;
    void* bestObj;
    bestDist = gTumbleweedBushNearestInitDist;
    bestObj = NULL;
    {
        void** tmp = ObjGroup_GetObjects(0x31, &count);
        i = 0;
        list = tmp;
    }
    while (i < count)
    {
        if (((GameObject*)*list)->anim.seqId == TUMBLEWEEDBUSH_SIBLING_B)
        {
            if (((u8*)((GameObject*)*list)->extra)[0x278] > 1)
            {
                f32 d = vec3f_distanceSquared(&((GameObject*)*list)->anim.worldPosX, p_pos);
                if (d < bestDist)
                {
                    bestDist = d;
                    bestObj = *list;
                }
            }
        }
        list = (void**)((char*)list + 4);
        i++;
    }
    return bestObj;
}

void tumbleweedbush_setScale(u8* obj, void* match)
{
    TumbleweedBushState* state;
    int i;
    state = ((GameObject*)obj)->extra;
    i = 0;
    while (i < state->pieceCount)
    {
        if (state->pieceObjects[i] == match)
        {
            state->pieceObjects[i] = NULL;
        }
        i++;
    }
}

s8 fn_801631C8(int* obj)
{
    u8* state;
    u8* p4c;
    int siblingType;
    int idx;
    int outCount;
    f32 sunTime;
    int freeSlot;
    u8* scan;
    int** list;
    int count;
    int* newObj;

    state = ((GameObject*)obj)->extra;
    p4c = *(u8**)&((GameObject*)obj)->anim.placementData;
    switch (((GameObject*)obj)->anim.seqId)
    {
    case TUMBLEWEEDBUSH_SEQ_A:
        if ((*gSkyInterface)->getSunPosition(&sunTime) == 0)
            return -1;
        siblingType = TUMBLEWEEDBUSH_SIBLING_A;
        break;
    case TUMBLEWEEDBUSH_SEQ_B:
        siblingType = TUMBLEWEEDBUSH_SIBLING_B;
        break;
    case TUMBLEWEEDBUSH_SEQ_C:
        siblingType = TUMBLEWEEDBUSH_SIBLING_C;
        break;
    case TUMBLEWEEDBUSH_SEQ_D:
        siblingType = TUMBLEWEEDBUSH_SIBLING_D;
        break;
    }

    idx = 0;
    freeSlot = -1;
    scan = state;
    while (idx < (int)(u8)state[0x50] && freeSlot == -1)
    {
        if (*(void**)(scan + 0xc) == NULL) freeSlot = idx;
        scan += 4;
        idx++;
    }
    if (freeSlot == -1) return -1;

    list = ObjList_GetObjects(&idx, &outCount);
    count = 0;
    while (idx < outCount)
    {
        int j = *(int*)&idx;
        idx = j + 1;
        if (siblingType == ((GameObject*)list[j])->anim.seqId) count++;
    }
    if (count >= 7) return -1;
    if (Obj_IsLoadingLocked() == 0) return -1;

    newObj = Obj_AllocObjectSetup(0x20, siblingType);
    ((ObjPlacement*)newObj)->posX =
        ((GameObject*)obj)->anim.localPosX + ((TumbleweedBushState*)state)->pieceOffsets[freeSlot][0];
    ((ObjPlacement*)newObj)->posY =
        ((GameObject*)obj)->anim.localPosY + ((TumbleweedBushState*)state)->pieceOffsets[freeSlot][1];
    *(f32*)&((ObjDef*)newObj)->jointData =
        ((GameObject*)obj)->anim.localPosZ + ((TumbleweedBushState*)state)->pieceOffsets[freeSlot][2];
    ((ObjPlacement*)newObj)->color[0] = p4c[4];
    ((ObjPlacement*)newObj)->color[1] = p4c[5];
    ((ObjPlacement*)newObj)->color[2] = p4c[6];
    ((ObjPlacement*)newObj)->color[3] = p4c[7];
    *(f32*)((char*)newObj + 0x1c) = lbl_803E2F40;

    if ((state[0x4c] & 1) != 0)
    {
        switch (((ObjPlacement*)((GameObject*)obj)->anim.placementData)->mapId)
        {
        case 0x292c:
            if (*(u16*)(state + 0x4e) == 6)
            {
                *((u8*)newObj + 0x1b) = 1;
                list = ObjList_GetObjects(&idx, &outCount);
                while (idx < outCount)
                {
                    int* child = list[idx];
                    if (((GameObject*)child)->anim.seqId == 0x27f)
                    {
                        ((ObjPlacement*)newObj)->posX = ((GameObject*)child)->anim.localPosX;
                        ((ObjPlacement*)newObj)->posY = *(f32*)((char*)list[idx] + 0x10);
                        *(f32*)&((ObjDef*)newObj)->jointData = *(f32*)((char*)list[idx] + 0x14);
                        idx = outCount;
                    }
                    idx++;
                }
            }
            break;
        }
    }

    {
        int* setup = Obj_SetupObject(newObj, 5, ((GameObject*)obj)->anim.mapEventSlot, -1,
                                     ((GameObject*)obj)->anim.parent);
        u8* slotBase = state + 0xc;
        *(int**)(slotBase + freeSlot * 4) = setup;
        {
            int* spawned = *(int**)(slotBase + freeSlot * 4);
            ((void(*)(int*, f64, f64))*(int*)(*(int*)(*(int*)((char*)spawned + 0x68)) + 0x24))(
                spawned,
                (f64)((GameObject*)obj)->anim.localPosX, (f64)((GameObject*)obj)->anim.localPosZ);
        }
    }
    *(u16*)(state + 0x4e) += 1;
    return freeSlot;
}

void fn_80163990(int* piece, u8* state)
{
    f32 gh;

    ((GameObject*)piece)->anim.velocityX = ((GameObject*)piece)->anim.velocityX / lbl_803E2F5C;
    if (fn_80065684((int)piece, ((GameObject*)piece)->anim.localPosX, ((GameObject*)piece)->anim.localPosY,
                    ((GameObject*)piece)->anim.localPosZ, &gh, 0) != 0)
    {
        if (gh > lbl_803E2F60)
        {
            ((GameObject*)piece)->anim.velocityY = ((GameObject*)piece)->anim.velocityY + lbl_803E2F64 * timeDelta;
        }
        else
        {
            ((GameObject*)piece)->anim.localPosY = ((GameObject*)piece)->anim.localPosY - (gh - lbl_803E2F60);
            ((GameObject*)piece)->anim.velocityY = lbl_803E2F68;
        }
    }
    ((GameObject*)piece)->anim.velocityZ = ((GameObject*)piece)->anim.velocityZ / lbl_803E2F5C;

    *(s16*)(state + 0x27c) = (s16)(*(s16*)(state + 0x27c) / 100);
    *(s16*)(state + 0x27e) = (s16)(*(s16*)(state + 0x27e) / 100);
    *(s16*)(state + 0x280) = (s16)(*(s16*)(state + 0x280) / 100);

    ((GameObject*)piece)->anim.localPosX = ((GameObject*)piece)->anim.localPosX + ((GameObject*)piece)->anim.velocityX *
        timeDelta;
    ((GameObject*)piece)->anim.localPosY = ((GameObject*)piece)->anim.localPosY + ((GameObject*)piece)->anim.velocityY *
        timeDelta;
    ((GameObject*)piece)->anim.localPosZ = ((GameObject*)piece)->anim.localPosZ + ((GameObject*)piece)->anim.velocityZ *
        timeDelta;

    ((GameObject*)piece)->anim.rotZ =
        (f32)(int) * (s16*)(state + 0x27c) * timeDelta + (f32)(int)((GameObject*)piece)->anim.rotZ;
    ((GameObject*)piece)->anim.rotY =
        (f32)(int) * (s16*)(state + 0x27e) * timeDelta + (f32)(int)((GameObject*)piece)->anim.rotY;
    ((GameObject*)piece)->anim.rotX =
        (f32)(int) * (s16*)(state + 0x280) * timeDelta + (f32)(int)((GameObject*)piece)->anim.rotX;
}

ObjectDescriptor11WithPadding gTumbleWeedBushObjDescriptor = {
    {
        0,
        0,
        0,
        OBJECT_DESCRIPTOR_FLAGS_11_SLOTS,
        (ObjectDescriptorCallback)tumbleweedbush_initialise,
        (ObjectDescriptorCallback)tumbleweedbush_release,
        0,
        (ObjectDescriptorCallback)tumbleweedbush_init,
        (ObjectDescriptorCallback)tumbleweedbush_update,
        (ObjectDescriptorCallback)tumbleweedbush_hitDetect,
        (ObjectDescriptorCallback)tumbleweedbush_render,
        (ObjectDescriptorCallback)tumbleweedbush_free,
        (ObjectDescriptorCallback)tumbleweedbush_getObjectTypeId,
        tumbleweedbush_getExtraSize,
        (ObjectDescriptorCallback)tumbleweedbush_setScale,
    },
    0,
};

u8 gTumbleweedBushPieceOffsetTable[] =
{
    0xC1, 0xB0, 0x00, 0x00, 0x42, 0x60, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x42, 0xBE, 0x00, 0x00, 0x42, 0x58, 0x00, 0x00,
    0x41, 0x90, 0x00, 0x00, 0x42, 0xB4, 0x00, 0x00, 0xC1, 0x40, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0xC1, 0xB0, 0x00, 0x00, 0x42, 0x60, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x42, 0xA0, 0x00, 0x00, 0x42, 0x58, 0x00, 0x00,
    0x41, 0x90, 0x00, 0x00, 0x42, 0xB4, 0x00, 0x00, 0xC1, 0x40, 0x00, 0x00,
    0xC2, 0x70, 0x00, 0x00, 0x42, 0xB0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};
