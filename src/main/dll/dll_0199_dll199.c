/* DLL 0x199 - NW shrine level controller / dll199 objects [801CA9C0-801CAD80) */
#include "main/dll/dll197state_struct.h"
#include "main/dll/dll199state_struct.h"
#include "main/effect_interfaces.h"
#include "main/game_object.h"
#include "main/objseq.h"
#include "main/dll/dimmagicbridge.h"
#include "main/mapEventTypes.h"
#include "main/resource.h"
#include "main/gamebits.h"
#include "main/sfa_shared_decls.h"
#include "main/object_descriptor.h"

#define PAD_BUTTON_A 0x100
#define PAD_BUTTON_B 0x200

extern void objRenderFn_8003b8f4(f32);
extern f32 lbl_803E5158;
extern int getEnvfxAct(int a, int b, u16 idx, int d);
extern ModgfxInterface** gModgfxInterface;

extern int return0_8005669C(int p);
extern int lbl_803DB610;
extern u32 lbl_803DDBD8;
extern int ObjMsg_Pop(int obj, int* msgOut, int* paramOut, int* flagsOut);
extern char* ObjGroup_FindNearestObject(int group, char* from, f32* distInOut);
extern void Obj_FreeObject(char* obj);
extern f32 Vec_distance(f32* a, f32* b);
extern u8 framesThisStep;
extern f32 lbl_803E515C;
extern f32 lbl_803E5160;
extern f32 lbl_803E5164;
extern f32 lbl_803E5168;
extern f32 lbl_803E516C;
extern f32 lbl_803E5170;
extern f32 lbl_803E5174;
extern void ObjMsg_AllocQueue(int obj, int n);

void dll_199_hitDetect(void)
{
}

int dll_199_getExtraSize(void) { return 0x14; }
int dll_199_getObjectTypeId(void) { return 0x0; }

void dll_199_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0) objRenderFn_8003b8f4(lbl_803E5158);
}

void dll_199_free(int* obj)
{
    extern void* gTitleMenuControlInterface;
    (*gModgfxInterface)->detachSource(obj);
    ((void(*)(int, int))((void**)*(void**)gTitleMenuControlInterface)[14])(3, 0);
    ((void(*)(int, int))((void**)*(void**)gTitleMenuControlInterface)[14])(2, 0);
}

void dll_199_initialise(void);
void dll_199_release(void);
void dll_199_init(int obj, int def);
void dll_199_update(int obj);

ObjectDescriptor dll_199 = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)dll_199_initialise,
    (ObjectDescriptorCallback)dll_199_release,
    0,
    (ObjectDescriptorCallback)dll_199_init,
    (ObjectDescriptorCallback)dll_199_update,
    (ObjectDescriptorCallback)dll_199_hitDetect,
    (ObjectDescriptorCallback)dll_199_render,
    (ObjectDescriptorCallback)dll_199_free,
    (ObjectDescriptorCallback)dll_199_getObjectTypeId,
    dll_199_getExtraSize,
};

int dll_199_SeqFn(int obj, int p2, ObjAnimUpdateState* animUpdate)
{
    extern void* gTitleMenuControlInterface;
    u8* st;
    int i;
    u8 eventId;

    st = ((GameObject*)obj)->extra;
    animUpdate->activeHitVolumePair = -1;
    animUpdate->sequenceEventActive = 0;
    if (((Dll197State*)st)->scrollVel != 0)
    {
        ((Dll197State*)st)->scrollPos += ((Dll197State*)st)->scrollVel;
        if (((Dll197State*)st)->scrollPos <= 1 && ((Dll197State*)st)->scrollVel <= 0)
        {
            ((Dll197State*)st)->scrollPos = 1;
            ((Dll197State*)st)->scrollVel = 0;
        }
        else if (((Dll197State*)st)->scrollPos >= 0x46 && ((Dll197State*)st)->scrollVel >= 0)
        {
            ((Dll197State*)st)->scrollPos = 0x46;
            ((Dll197State*)st)->scrollVel = 0;
        }
        (**(void (**)(int, int))(*(int*)gTitleMenuControlInterface + 0x38))(3, ((Dll197State*)st)->scrollPos & 0xff);
    }
    for (i = 0; i < animUpdate->eventCount; i++)
    {
        eventId = animUpdate->eventIds[i];
        if (eventId != 0)
        switch (eventId)
        {
        case 0xb:
            ((Dll197State*)st)->menuState = 7;
            break;
        case 1:
            getEnvfxAct(obj, obj, 0xc3, 0);
            break;
        case 2:
            if (lbl_803DB610 == -1)
            {
                getEnvfxAct(obj, obj, 0x14, 0);
            }
            else
            {
                getEnvfxAct(obj, obj, (u16)lbl_803DB610, 0);
            }
            break;
        case 3:
            ((Dll197State*)st)->unk10 = 1;
            break;
        case 4:
            ((Dll197State*)st)->menuState = 4;
            ((Dll197State*)st)->unk10 = 2;
            GameBit_Set(0x129, 1);
            GameBit_Set(0x1cf, 0);
            GameBit_Set(0x126, 1);
            ((Dll197State*)st)->scrollVel = -3;
            break;
        case 5:
            ((Dll197State*)st)->unk10 = 3;
            ((Dll197State*)st)->scrollVel = -3;
            GameBit_Set(0x129, 1);
            break;
        case 6:
            GameBit_Set(0x1cf, 1);
            break;
        case 7:
            GameBit_Set(0x1cf, 0);
            ((Dll197State*)st)->scrollVel = -3;
            break;
        case 9:
            GameBit_Set(0x128, 1);
            if (lbl_803DDBD8 == 0)
            {
                lbl_803DDBD8 = return0_8005669C(1);
            }
            break;
        case 8:
            GameBit_Set(0x127, 1);
            break;
        case 10:
            ((Dll197State*)st)->scrollPos = 100;
            (**(void (**)(int, int, int, int, int))(*(int*)gTitleMenuControlInterface + 0x18))(
                3, 0x2d, 0x50, ((Dll197State*)st)->scrollPos & 0xff, 0);
            break;
        }
        animUpdate->eventIds[i] = 0;
    }
    switch ((int)((Dll197State*)st)->menuState)
    {
    case 7:
        if ((getButtonsHeld(0) & PAD_BUTTON_A) != 0u)
        {
            (*gObjectTriggerInterface)->endSequence(animUpdate->sequenceSlot);
            ((Dll197State*)st)->menuState = 8;
            ((Dll197State*)st)->unk2 = 0;
        }
        else if ((getButtonsHeld(0) & PAD_BUTTON_B) != 0u)
        {
            (*gObjectTriggerInterface)->endSequence(animUpdate->sequenceSlot);
            ((Dll197State*)st)->menuState = 7;
            ((Dll197State*)st)->unk2 = 0;
        }
        break;
    }
    return 0;
}

typedef struct Dll199ObjectDef
{
    u8 pad0[0x1A - 0x0];
    s16 initStateOverride; /* 0x1A: if >0, high byte (>>8) overrides the object's initial state (default 10) */
    u8 pad1C[0x20 - 0x1C];
} Dll199ObjectDef;

void dll_199_update(int obj)
{
    extern int* gTitleMenuControlInterface;
    extern void* Obj_GetPlayerObject(void);
    short* state;
    char* player;
    int queue;
    char* found;
    f32 dist;
    int flags;
    int msg;
    int param;
    f32 dz;
    u32 n;
    int delta;

    state = ((GameObject*)obj)->extra;
    player = Obj_GetPlayerObject();
    dist = lbl_803E515C;
    ((GameObject*)obj)->anim.worldPosX = ((GameObject*)obj)->anim.localPosX;
    ((GameObject*)obj)->anim.worldPosY = ((GameObject*)obj)->anim.localPosY;
    ((GameObject*)obj)->anim.worldPosZ = ((GameObject*)obj)->anim.localPosZ;
    queue = *(int*)&((GameObject*)obj)->extra;
    flags = 0;
    while (ObjMsg_Pop(obj, &msg, &param, &flags) != 0)
    {
        switch (msg)
        {
        case 0x30005:
            *(s16*)(queue + 6) = -3;
            break;
        case 0x30006:
            *(s16*)(queue + 6) = 0x10;
            break;
        }
    }
    GameBit_Set(0x127, 1);
    delta = state[3];
    if (delta != 0)
    {
        state[2] += (s16)delta;
        if (state[2] <= 0xc)
        {
            state[2] = 0xc;
            state[3] = 0;
        }
        else if (state[2] >= 0x46)
        {
            state[2] = 0x46;
            state[3] = 0;
        }
        (**(void (**)(int, int))(*gTitleMenuControlInterface + 0x38))(2, state[2] & 0xff);
    }
    delta = state[5];
    if (delta != 0)
    {
        state[4] += (s16)delta;
        if ((state[4] <= 1) && (state[5] <= 0))
        {
            state[4] = 1;
            state[5] = 0;
        }
        else if ((state[4] >= 0x46) && (state[5] >= 0))
        {
            state[4] = 0x46;
            state[5] = 0;
        }
        (**(void (**)(int, int))(*gTitleMenuControlInterface + 0x38))(3, state[4] & 0xff);
    }
    if (state[1] > 0)
    {
        state[1] -= framesThisStep;
        if (state[1] <= 0)
        {
            state[1] = 0;
            if (((Dll199State*)state)->triggered == 0)
            {
                (**(void (**)(int, int, int, int, int))(*gTitleMenuControlInterface +
                    0x18))(3, 0x2c, 0x50, state[4], 0);
                ((Dll199State*)state)->triggered = 1;
            }
        }
    }
    else
    {
        found = ObjGroup_FindNearestObject(0xe, player, &dist);
        if ((found != 0) && (dist < lbl_803E5160) && (dist > lbl_803E5164))
        {
            dz = ((GameObject*)found)->anim.localPosZ - ((GameObject*)player)->anim.localPosZ;
            if (dz <= lbl_803E5168)
            {
                if (dz < lbl_803E5168)
                {
                    dz = dz * lbl_803E516C;
                }
                if (state[4] != 0x1e)
                {
                    state[4] = 0x1e;
                }
                n = (int)((f32)state[4] * ((dz - lbl_803E5164) / lbl_803E5170));
                if ((s16)n < 1)
                {
                    n = 1;
                }
                (**(void (**)(int, int))(*gTitleMenuControlInterface + 0x38))(3, n & 0xff);
                n = (int)((f32)state[2] * ((lbl_803E5170 - (dz - lbl_803E5164)) / *(f32*)&lbl_803E5170));
                if ((s16)n < 1)
                {
                    n = 1;
                }
                (**(void (**)(int, int))(*gTitleMenuControlInterface + 0x38))(2, n & 0xff);
            }
        }
        switch (((Dll199State*)state)->phase)
        {
        case 0:
            if ((GameBit_Get(0x5b5) == 0) && (GameBit_Get(0x594) != 0))
            {
                GameBit_Set(0x5b5, 1);
            }
            GameBit_Set(0x5b9, 0);
            if (Vec_distance((f32*)(obj + 0x18), (f32*)(player + 0x18)) < state[0])
            {
                ((Dll199State*)state)->phase = 1;
                GameBit_Set(0x129, 0);
                (*gObjectTriggerInterface)->runSequence(0, (void*)obj, 0xffffffff);
                {
                    int* res = Resource_Acquire(0x83, 1);
                    (**(void (**)(int, int, int, int, int, int))(*res + 4))(obj, 0, 0, 1, 0xffffffff, 0);
                    Resource_Release(res);
                }
                {
                    int* res = Resource_Acquire(0x84, 1);
                    (**(void (**)(int, int, int, int, int, int))(*res + 4))(obj, 0, 0, 1, 0xffffffff, 0);
                    Resource_Release(res);
                }
                GameBit_Set(0x126, 0);
                (*gModgfxInterface)->releaseHandle(state + 6);
            }
            break;
        case 1:
            if (((Dll199State*)state)->unk10 == 1)
            {
                ((Dll199State*)state)->phase = 2;
                state[1] = 0xa0;
            }
            break;
        case 2:
            if ((((Dll199State*)state)->unlockCount == 0) && (GameBit_Get(0x1cd) == 0))
            {
                GameBit_Set(0x1cd, 1);
            }
            if (GameBit_Get(0x5b2) != 0)
            {
                ((Dll199State*)state)->unlockCount += 1;
                state[1] = 100;
                if (((Dll199State*)state)->unlockCount == 1)
                {
                    (*gObjectTriggerInterface)->runSequence(3, (void*)obj, 0xffffffff);
                }
            }
            break;
        case 7:
            (*gObjectTriggerInterface)->runSequence(5, (void*)obj, 0xffffffff);
            ((Dll199State*)state)->phase = 3;
            state[1] = 0;
            state[5] = -3;
            break;
        case 8:
            (*gObjectTriggerInterface)->runSequence(4, (void*)obj, 0xffffffff);
            ((Dll199State*)state)->phase = 6;
            state[1] = 0;
            state[5] = -3;
            break;
        case 6:
            (**(void (**)(int, int, int, int, int))(*gTitleMenuControlInterface + 0x18))(
                3, 0x35, 0x50, state[4] & 0xff, 0);
            state[5] = 1;
            (*gObjectTriggerInterface)->runSequence(2, (void*)obj, 0xffffffff);
            dist = lbl_803E5174;
            found = ObjGroup_FindNearestObject(3, (char*)obj, &dist);
            if (found != 0)
            {
                Obj_FreeObject(found);
            }
            ((Dll199State*)state)->phase = 0;
            state[1] = 400;
            GameBit_Set(0x129, 1);
            GameBit_Set(0x126, 1);
            GameBit_Set(0x127, 1);
            GameBit_Set(0x5b2, 0);
            GameBit_Set(0x5b9, 1);
            {
                int* res = Resource_Acquire(0x6a, 1);
                state[6] = (**(short (**)(int, int, int, int, int, int))(*res + 4))(obj, 0, 0, 0x402, 0xffffffff, 0);
                Resource_Release(res);
            }
            GameBit_Set(0x1cd, 0);
            ((Dll199State*)state)->unlockCount = 0;
            ((Dll199State*)state)->unk10 = 0;
            break;
        case 3:
            dist = lbl_803E5174;
            found = ObjGroup_FindNearestObject(3, (char*)obj, &dist);
            if (found != 0)
            {
                Obj_FreeObject(found);
            }
            if (GameBit_Get(0x1ce) != 0)
            {
                state[4] = 1;
                (**(void (**)(int, int, int, int, int))(*gTitleMenuControlInterface + 0x18))(
                    3, 0x2c, 0x50, state[4] & 0xff, 0);
                state[5] = 1;
                GameBit_Set(0x129, 1);
                ((Dll199State*)state)->phase = 5;
            }
            else
            {
                GameBit_Set(0x126, 0);
                (**(void (**)(int, int, int, int, int))(*gTitleMenuControlInterface + 0x18))(
                    3, 0x2a, 0x50, state[4] & 0xff, 0);
                state[5] = 1;
                (*gObjectTriggerInterface)->runSequence(1, (void*)obj, 0xffffffff);
            }
            break;
        case 4:
            if (GameBit_Get(0xfd) == 0)
            {
                GameBit_Set(0xfd, 1);
            }
            GameBit_Set(0x1cf, 0);
            GameBit_Set(0x127, 0);
            ((Dll199State*)state)->phase = 5;
            (**(void (**)(int, int, int, int, int))(*gTitleMenuControlInterface + 0x18))(
                3, 0x2c, 0x50, state[4] & 0xff, 0);
            GameBit_Set(0x1ce, 1);
            (*gMapEventInterface)->setMapAct(0xb, 6);
            break;
        }
    }
}

void dll_199_init(int obj, int def)
{
    extern int* gTitleMenuControlInterface;
    short* state;
    int* res;
    short id;

    state = ((GameObject*)obj)->extra;
    ((GameObject*)obj)->anim.rotX = 0;
    *state = 10;
    if (((Dll199ObjectDef*)def)->initStateOverride > 0)
    {
        *state = ((Dll199ObjectDef*)def)->initStateOverride >> 8;
    }
    ((Dll199State*)state)->phase = 0;
    ((Dll199State*)state)->unk10 = 0;
    state[1] = 0;
    ((Dll199State*)state)->unlockCount = 0;
    ((GameObject*)obj)->animEventCallback = dll_199_SeqFn;
    ObjMsg_AllocQueue(obj, 4);
    GameBit_Set(0x129, 1);
    GameBit_Set(0x1cf, 0);
    GameBit_Set(0x126, 1);
    GameBit_Set(0x127, 1);
    GameBit_Set(0x1cd, 0);
    GameBit_Set(0x1e7, 0);
    state[2] = 0xc;
    state[4] = 0x1e;
    state[1] = 200;
    (**(void (**)(int, int, int, int, int))(*gTitleMenuControlInterface + 0x18))(2, 0x2b, 0x50, 1, 0);
    state[3] = 0;
    state[5] = 0;
    ((Dll199State*)state)->triggered = 0;
    res = Resource_Acquire(0x6a, 1);
    id = (**(short (**)(int, int, int, int, int, int))(*res + 4))(obj, 0, 0, 0x402, 0xffffffff, 0);
    state[6] = id;
    Resource_Release(res);
}

void dll_199_release(void)
{
}

void dll_199_initialise(void)
{
}
