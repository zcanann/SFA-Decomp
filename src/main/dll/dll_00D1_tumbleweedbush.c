#include "main/audio/sfx_ids.h"
#include "main/game_object.h"
#include "main/dll/dll_00D1_tumbleweedbush.h"
#include "main/sky_interface.h"

typedef struct TumbleweedbushState
{
    u8 pad0[0x8 - 0x0];
    u16 unk8;
    u8 padA[0x54 - 0xA];
} TumbleweedbushState;

extern undefined4 ObjHitbox_SetCapsuleBounds();
extern void* ObjGroup_GetObjects();
extern int ObjHits_PollPriorityHitWithCooldown();
extern undefined4 FUN_8003b818();

/* Actual cannonclaw_update is 188b -- trigger-once cannon-arm awakener.
 * The 668b "Ghidra body" was misattributed; replaced with the right one. */
extern f32 timeDelta;

#pragma scheduling on
#pragma peephole on
extern f32 lbl_803E2F48;
extern f32 lbl_803E2F4C;
extern f32 lbl_803E2F50;
extern f32 lbl_803E2F54;
extern u8 lbl_803201E8[];
extern void vecRotateZXY(void* obj, void* p);
extern void* memcpy(void* dst, const void* src, int n);
extern u8 lbl_803DDA80;
extern void* Obj_GetPlayerObject(void);
extern void objfx_spawnHitEmitterAtPos(f32* p, int a, int b, int c, int d);
extern int Sfx_PlayFromObject(int* obj, int sfx);
extern s8 fn_801631C8(int* obj);
extern float sqrtf(float x);
extern f32 lbl_803E2F44;
extern void objRenderFn_8003b8f4(f32);
extern void* ObjGroup_GetObjects(int type, int* outCount);
extern f32 vec3f_distanceSquared(f32 * p1, f32 * p2);
extern f32 lbl_803E2F58;
extern u8 Obj_IsLoadingLocked(void);
extern int* Obj_AllocObjectSetup(int size, int type);
extern int* Obj_SetupObject(int* obj, int a, int b, int c, void* d);
extern int** ObjList_GetObjects(int* idx, int* count);
extern f32 lbl_803E2F40;
extern int fn_80065684(int obj, f32 a, f32 b, f32 c, f32* out, int flag);
extern f32 lbl_803E2F5C;
extern f32 lbl_803E2F60;
extern f32 lbl_803E2F64;
extern f32 lbl_803E2F68;

void FUN_801638bc(int param_1, int param_2, int param_3, int param_4, int param_5, s8 visible)
{
    if (visible != 0)
    {
        FUN_8003b818(param_1);
    }
    return;
}

void cannonclaw_release(void);

#pragma scheduling off
#pragma peephole off
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
    u8* p4;
    u8* pe;
    u8* p12;
    int i;

    sub = ((GameObject*)obj)->extra;
    *(f32*)sub = lbl_803E2F48;
    ((TumbleweedbushState*)sub)->unk8 = (u16)(params[0x1b] * 2);
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
    case 0x28d:
    case 0x4b9:
    case 0x4be:
        sub[0x50] = 3;
        idx = 0;
        break;
    case 0x3fd:
        sub[0x50] = 3;
        idx = 1;
        break;
    }
    if (param3 == 0)
    {
        i = 0;
        p4 = sub;
        pe = lbl_803201E8 + idx * 0x30;
        p12 = sub;
        for (; i < (int)sub[0x50]; i++)
        {
            *(int*)(p4 + 0xc) = 0;
            memcpy(p12 + 0x1c, pe, 0xc);
            *(f32*)(p12 + 0x1c) = *(f32*)(p12 + 0x1c) * ((GameObject*)obj)->anim.rootMotionScale;
            *(f32*)(p12 + 0x20) = *(f32*)(p12 + 0x20) * ((GameObject*)obj)->anim.rootMotionScale;
            *(f32*)(p12 + 0x24) = *(f32*)(p12 + 0x24) * ((GameObject*)obj)->anim.rootMotionScale;
            vecRotateZXY(obj, p12 + 0x1c);
            p4 += 4;
            pe += 0xc;
            p12 += 0xc;
        }
    }
}

int tumbleweedbush_getExtraSize(void) { return 0x54; }
int tumbleweedbush_getObjectTypeId(void) { return 0x0; }

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
    player = (int*)Obj_GetPlayerObject();
    if (ObjHits_PollPriorityHitWithCooldown(obj, &lbl_803DDA80, &hit0, hitExtra) != 0)
    {
        if (((GameObject*)hit0)->anim.seqId != 0x4ba)
        {
            objfx_spawnHitEmitterAtPos(hitExtra, 8, 0xff, 0xff, 0x78);
            Sfx_PlayFromObject(obj, SFXsc_gethit04);
            for (i = 0; (u8)i < state->pieceCount; i++)
            {
                slot = (int**)&state->pieceObjects[(u8)i];
                if (*slot != NULL)
                {
                    if (((GameObject*)obj)->anim.seqId == 0x28d)
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
    if ((u16)(s32)d < state->triggerRadius
    )
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
    *((u8*)((int**)obj)[0xb8 / 4] + 0x278) = v;
}

void tumbleweedbush_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0) objRenderFn_8003b8f4(lbl_803E2F44);
}

void cannonclaw_init(s16* dst, void* src);

/* tumbleweedbush_findNearestActive: scan all type-0x31 objects, pick the closest one whose
 * obj->_46 == 0x3fb and obj->_b8->_278 > 1 (by vec3f_distanceSquared from
 * the supplied position vector). Returns NULL if no match. */

void* tumbleweedbush_findNearestActive(f32* p_pos)
{
    int count;
    void** list;
    f32 bestDist;
    int i;
    void* bestObj;
    bestDist = lbl_803E2F58;
    bestObj = NULL;
    {
        void** tmp = (void**)ObjGroup_GetObjects(0x31, &count);
        i = 0;
        list = tmp;
    }
    while (i < count)
    {
        if (((GameObject*)*list)->anim.seqId == 0x3fb)
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

/* tumbleweedbush_setScale: scan the sub-array at obj->_b8 (sub[0x50] entries
 * of 4 bytes each), zeroing every slot whose +0xc word matches `match`. */
void tumbleweedbush_setScale(u8* obj, void* match)
{
    TumbleweedBushState* state;
    int i;
    state = ((GameObject*)obj)->extra;
    i = 0;
    while (i < (int)state->pieceCount)
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
    case 0x28d:
        if ((*gSkyInterface)->getSunPosition(&sunTime) == 0)
            return -1;
        siblingType = 0x39d;
        break;
    case 0x3fd:
        siblingType = 0x3fb;
        break;
    case 0x4b9:
        siblingType = 0x4ba;
        break;
    case 0x4be:
        siblingType = 0x4c1;
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
        int j = idx;
        idx = j + 1;
        if (siblingType == ((GameObject*)list[j])->anim.seqId) count++;
    }
    if (count >= 7) return -1;
    if (Obj_IsLoadingLocked() == 0) return -1;

    newObj = Obj_AllocObjectSetup(0x20, siblingType);
    *(f32*)((char*)newObj + 0x8) =
        ((GameObject*)obj)->anim.localPosX + *(f32*)(state + freeSlot * 12 + 0x1c);
    *(f32*)((char*)newObj + 0xc) =
        ((GameObject*)obj)->anim.localPosY + *(f32*)(state + freeSlot * 12 + 0x20);
    *(f32*)&((ObjDef*)newObj)->jointData =
        ((GameObject*)obj)->anim.localPosZ + *(f32*)(state + freeSlot * 12 + 0x24);
    *((u8*)newObj + 4) = p4c[4];
    *((u8*)newObj + 5) = p4c[5];
    *((u8*)newObj + 6) = p4c[6];
    *((u8*)newObj + 7) = p4c[7];
    *(f32*)((char*)newObj + 0x1c) = lbl_803E2F40;

    if ((state[0x4c] & 1) != 0
        && *(int*)(*(int*)&((GameObject*)obj)->anim.placementData + 0x14) == 0x292c
        && *(u16*)(state + 0x4e) == 6)
    {
        *((u8*)newObj + 0x1b) = 1;
        list = ObjList_GetObjects(&idx, &outCount);
        while (idx < outCount)
        {
            int* child = list[idx];
            if (((GameObject*)child)->anim.seqId == 0x27f)
            {
                *(f32*)((char*)newObj + 0x8) = ((GameObject*)child)->anim.localPosX;
                *(f32*)((char*)newObj + 0xc) = *(f32*)((char*)list[idx] + 0x10);
                *(f32*)&((ObjDef*)newObj)->jointData = *(f32*)((char*)list[idx] + 0x14);
                idx = outCount;
            }
            idx++;
        }
    }

    {
        int* setup = Obj_SetupObject(newObj, 5, ((GameObject*)obj)->anim.mapEventSlot, -1,
                                     ((GameObject*)obj)->anim.parent);
        u8* slotBase = state + freeSlot * 4;
        *(int**)(slotBase + 0xc) = setup;
        ((void(*)(f64, f64))*(int*)(*(int*)(*(int*)((char*)*(int**)(slotBase + 0xc) + 0x68)) + 0x24))(
            (f64)((GameObject*)obj)->anim.localPosX, (f64)((GameObject*)obj)->anim.localPosZ);
    }
    *(u16*)(state + 0x4e) += 1;
    return (s8)freeSlot;
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
