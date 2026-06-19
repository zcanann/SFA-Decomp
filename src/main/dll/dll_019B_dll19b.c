/* DLL 0x019B — torch / fire-effect objects [801CBA98-801CBD88) */
#include "main/dll/torch1CD.h"
#include "main/dll/dll19cstate_struct.h"
#include "main/game_object.h"
#include "main/dll/torch1cd_state.h"
#include "main/dll_000A_expgfx.h"
#include "main/objseq.h"
#include "main/resource.h"

extern int getEnvfxAct(int a, int b, u16 idx, int d);
extern void* return0_8005669C(int);

extern int lbl_803DB610;
extern void* lbl_803DDBE0;

extern f32 lbl_803E5188;
extern void objRenderFn_8003b8f4(f32);
extern ModgfxInterface** gModgfxInterface;
extern void ObjMsg_AllocQueue(void* obj, int capacity);
extern int Obj_GetPlayerObject(void);
extern int ObjGroup_FindNearestObject(int group, u32 obj, float* maxDistance);
extern int ObjMsg_Pop(int obj, int* msg, int* a, int* b);
extern u32 GameBit_Get(int eventId);
extern f32 Vec_distance(f32* a, f32* b);
extern void fn_80296B78(int obj, int a);
extern void fn_80137948(char* fmt, ...);
extern char sShrineTimeFormat[];
extern f32 lbl_803E518C;
extern f32 lbl_803E5190;
extern f32 lbl_803E5194;
extern f32 lbl_803E5198;
extern f32 lbl_803E519C;
extern f32 lbl_803E51A0;
extern f32 timeDelta;
extern u8 framesThisStep;

int dll_19B_SeqFn(int obj, int unused, ObjAnimUpdateState* animUpdate)
{
    extern int* gTitleMenuControlInterface;
    extern void GameBit_Set(int eventId, int value);
    int state;
    int i;

    state = *(int*)&((GameObject*)obj)->extra;
    animUpdate->hitVolumePair = -1;
    animUpdate->sequenceEventActive = 0;

    if (((Torch1CDState*)state)->flameFrameVel != 0)
    {
        ((Torch1CDState*)state)->flameFrame += ((Torch1CDState*)state)->flameFrameVel;
        if (((Torch1CDState*)state)->flameFrame <= 1 && ((Torch1CDState*)state)->flameFrameVel <= 0)
        {
            ((Torch1CDState*)state)->flameFrame = 1;
            ((Torch1CDState*)state)->flameFrameVel = 0;
        }
        else if (((Torch1CDState*)state)->flameFrame >= 0x46 && ((Torch1CDState*)state)->flameFrameVel >= 0)
        {
            ((Torch1CDState*)state)->flameFrame = 0x46;
            ((Torch1CDState*)state)->flameFrameVel = 0;
        }
        ((void (**)(int, u8))*gTitleMenuControlInterface)[0x38 / 4](3, (u8)((Torch1CDState*)state)->flameFrame);
    }

    for (i = 0; i < animUpdate->eventCount; i++)
    {
        u8 cmd = animUpdate->eventIds[i];
        if (cmd != 0)
        {
            switch (cmd)
            {
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
                    getEnvfxAct(obj, obj, lbl_803DB610 & 0xffff, 0);
                }
                break;
            case 3:
                ((Torch1CDState*)state)->unk14 = 1;
                break;
            case 4:
                ((Torch1CDState*)state)->unk13 = 4;
                ((Torch1CDState*)state)->unk14 = 2;
                GameBit_Set(0x129, 1);
                GameBit_Set(0x1d2, 0);
                GameBit_Set(0x126, 1);
                ((Torch1CDState*)state)->flameFrameVel = -3;
                break;
            case 5:
                ((Torch1CDState*)state)->unk13 = 6;
                ((Torch1CDState*)state)->unk14 = 3;
                ((Torch1CDState*)state)->flameFrameVel = -3;
                GameBit_Set(0x129, 1);
                break;
            case 6:
                GameBit_Set(0x1d2, 1);
                break;
            case 7:
                GameBit_Set(0x1d2, 0);
                ((Torch1CDState*)state)->flameFrameVel = -3;
                break;
            case 8:
                GameBit_Set(0x128, 1);
                if (lbl_803DDBE0 == NULL)
                {
                    lbl_803DDBE0 = return0_8005669C(1);
                }
                break;
            case 9:
                GameBit_Set(0x127, 1);
                break;
            case 0xb:
                ((Torch1CDState*)state)->flameFrame = 100;
                ((void (**)(int, int, int, u8, int))*gTitleMenuControlInterface)[0x18 / 4]
                    (3, 0x2d, 0x50, (u8)((Torch1CDState*)state)->flameFrame, 0);
                break;
            }
        }
        animUpdate->eventIds[i] = 0;
    }
    return 0;
}

void dll_19B_hitDetect(void)
{
}

int dll_19B_getExtraSize(void) { return 0x18; }
int dll_19B_getObjectTypeId(void) { return 0x0; }

void dll_19B_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0) objRenderFn_8003b8f4(lbl_803E5188);
}

void dll_19B_free(int* obj)
{
    (*gModgfxInterface)->detachSource(obj);
}

typedef struct Dll19BState
{
    u8 pad0[0x12 - 0x0];
    u8 unk12;
    u8 unk13;
    u8 unk14;
    u8 pad15[0x16 - 0x15];
    u8 unk16;
    u8 pad17[0x18 - 0x17];
} Dll19BState;

void dll_19B_update(int obj)
{
    extern void* gTitleMenuControlInterface;
    extern void GameBit_Set(int eventId, int value);
    s16* st;
    int player;
    int near;
    s16* st2;
    int v;
    f32 dy;
    f32 dist;
    int unk16;
    int msg;
    int unk8;

    st = ((GameObject*)obj)->extra;
    player = Obj_GetPlayerObject();
    dist = lbl_803E518C;
    st2 = ((GameObject*)obj)->extra;
    unk16 = 0;
    while (ObjMsg_Pop(obj, &msg, &unk8, &unk16) != 0)
    {
        switch (msg)
        {
        case 0x30005:
            st2[3] = -3;
            break;
        case 0x30006:
            st2[3] = 0x10;
            break;
        }
    }
    GameBit_Set(0x127, 1);
    if ((v = st[3]) != 0)
    {
        st[2] += (s16)v;
        if (st[2] <= 12)
        {
            st[2] = 12;
            st[3] = 0;
        }
        else if (st[2] >= 70)
        {
            st[2] = 70;
            st[3] = 0;
        }
        (*(void (**)(int, int))(*(int*)gTitleMenuControlInterface + 0x38))(2, st[2] & 0xff);
    }
    if ((v = st[5]) != 0)
    {
        st[4] += (s16)v;
        if (st[4] <= 1 && st[5] <= 0)
        {
            st[4] = 1;
            st[5] = 0;
        }
        else if (st[4] >= 70 && st[5] >= 0)
        {
            st[4] = 70;
            st[5] = 0;
        }
        (*(void (**)(int, int))(*(int*)gTitleMenuControlInterface + 0x38))(3, st[4] & 0xff);
    }
    if (st[1] > 0)
    {
        st[1] -= framesThisStep;
        if (st[1] <= 0)
        {
            st[1] = 0;
            if (((Dll19BState*)st)->unk16 == 0)
            {
                (*(void (**)(int, int, int, int, int))(*(int*)gTitleMenuControlInterface + 0x18))(
                    3, 0x2c, 0x50, st[4], 0);
                ((Dll19BState*)st)->unk16 = 1;
            }
        }
    }
    else
    {
        near = ObjGroup_FindNearestObject(0xe, player, &dist);
        if ((u32)near != 0 && dist < lbl_803E5190 && dist > lbl_803E5194)
        {
            dy = ((GameObject*)near)->anim.localPosZ - ((GameObject*)player)->anim.localPosZ;
            if (dy <= lbl_803E5198)
            {
                if (dy < lbl_803E5198)
                {
                    dy = dy * lbl_803E519C;
                }
                if (st[4] != 30)
                {
                    st[4] = 30;
                }
                v = (int)((f32)st[4] * ((dy - lbl_803E5194) / lbl_803E51A0));
                if ((s16)v < 1)
                {
                    v = 1;
                }
                (*(void (**)(int, int))(*(int*)gTitleMenuControlInterface + 0x38))(3, v & 0xff);
                v = (int)((f32)st[2] * ((lbl_803E51A0 - (dy - lbl_803E5194)) / *(f32*)&lbl_803E51A0));
                if ((s16)v < 1)
                {
                    v = 1;
                }
                (*(void (**)(int, int))(*(int*)gTitleMenuControlInterface + 0x38))(2, v & 0xff);
            }
        }
        switch (((Dll19BState*)st)->unk13)
        {
        case 0:
            if (Vec_distance(&((GameObject*)obj)->anim.worldPosX, (f32*)(player + 0x18)) < st[0])
            {
                ((Dll19BState*)st)->unk13 = 1;
                GameBit_Set(0x129, 0);
                (*gObjectTriggerInterface)->runSequence(0, (void*)obj, -1);
                {
                    void* handle = Resource_Acquire(0x83, 1);
                    (*(s16 (**)(int, int, int, int, int, int))(*(int*)handle + 4))(obj, 1, 0, 1, -1, 0);
                    Resource_Release(handle);
                }
                {
                    void* handle = Resource_Acquire(0x84, 1);
                    (*(s16 (**)(int, int, int, int, int, int))(*(int*)handle + 4))(obj, 0, 0, 1, -1, 0);
                    Resource_Release(handle);
                }
                GameBit_Set(0x126, 0);
                (*gModgfxInterface)->releaseHandle(st + 6);
            }
            break;
        case 1:
            if (((Dll19BState*)st)->unk14 == 1)
            {
                ((Dll19BState*)st)->unk13 = 2;
                st[1] = 160;
            }
            break;
        case 2:
            if (((Dll19BState*)st)->unk12 == 0 && GameBit_Get(0x1d3) == 0)
            {
                GameBit_Set(0x1d3, 1);
            }
            if ((u32)GameBit_Get(0x1d8) != 0)
            {
                ((Dll19BState*)st)->unk12 += 1;
                GameBit_Set(0x1d8, 0);
            }
            st[7] -= (s16)timeDelta;
            fn_80137948(sShrineTimeFormat, st[7]);
            if (st[7] <= 0)
            {
                GameBit_Set(0x1d4, 1);
                (*gObjectTriggerInterface)->runSequence(2, (void*)obj, -1);
                st[1] = 10;
                ((Dll19BState*)st)->unk13 = 6;
                (*(void (**)(int, int, int, int, int))(*(int*)gTitleMenuControlInterface + 0x18))(
                    3, 0x35, 0x50, st[4] & 0xff, 0);
                st[5] = 1;
                GameBit_Set(0x1d3, 0);
            }
            else if (((Dll19BState*)st)->unk12 == 1)
            {
                ((Dll19BState*)st)->unk13 = 3;
                st[1] = 200;
                st[5] = -3;
            }
            break;
        case 3:
            if ((u32)GameBit_Get(0x1d1) != 0)
            {
                st[4] = 1;
                (*(void (**)(int, int, int, int, int))(*(int*)gTitleMenuControlInterface + 0x18))(
                    3, 0x2c, 0x50, st[4] & 0xff, 0);
                st[5] = 1;
                GameBit_Set(0x129, 1);
                ((Dll19BState*)st)->unk13 = 5;
            }
            else
            {
                fn_80296B78(player, -1);
                GameBit_Set(0x126, 0);
                (*(void (**)(int, int, int, int, int))(*(int*)gTitleMenuControlInterface + 0x18))(
                    3, 0x2a, 0x50, st[4] & 0xff, 0);
                st[5] = 1;
                (*gObjectTriggerInterface)->runSequence(1, (void*)obj, -1);
                ((Dll19BState*)st)->unk13 = 4;
            }
            break;
        case 4:
            if ((u32)GameBit_Get(0xfd) == 0)
            {
                GameBit_Set(0xfd, 1);
            }
            GameBit_Set(0x1d2, 0);
            GameBit_Set(0x127, 0);
            ((Dll19BState*)st)->unk13 = 5;
            (*(void (**)(int, int, int, int, int))(*(int*)gTitleMenuControlInterface + 0x18))(
                3, 0x2c, 0x50, st[4] & 0xff, 0);
            break;
        case 6:
            ((Dll19BState*)st)->unk13 = 0;
            ((Dll19BState*)st)->unk14 = 0;
            st[1] = 400;
            GameBit_Set(0x129, 1);
            GameBit_Set(0x126, 1);
            GameBit_Set(0x127, 1);
            {
                void* handle = Resource_Acquire(0x6a, 1);
                st[6] = (*(s16 (**)(int, int, int, int, int, int))(*(int*)handle + 4))(obj, 2, 0, 0x402, -1, 0);
                Resource_Release(handle);
            }
            GameBit_Set(0x1d8, 0);
            ((Dll19BState*)st)->unk12 = 0;
            st[7] = 4000;
            GameBit_Set(0x1d4, 0);
            break;
        }
    }
}

void dll_19B_release(void)
{
}

void dll_19B_initialise(void)
{
}

void dll_19C_free(void);

void dll_19B_init(u8* obj, u8* params)
{
    extern void* gTitleMenuControlInterface;
    extern void GameBit_Set(int eventId, int value);
    register u8* sub;
    void* res;

    sub = ((GameObject*)obj)->extra;
    ((GameObject*)obj)->anim.rotX = 0;
    *(s16*)sub = 0xa;
    if (*(s16*)(params + 0x1a) > 0)
    {
        *(s16*)sub = (s16)(*(s16*)(params + 0x1a) >> 8);
    }
    sub[0x13] = 0;
    sub[0x14] = 0;
    ((Dll19CState*)sub)->unk2 = 0;
    sub[0x12] = 0;
    ((GameObject*)obj)->animEventCallback = dll_19B_SeqFn;
    ObjMsg_AllocQueue(obj, 4);
    GameBit_Set(0x129, 1);
    GameBit_Set(0x1d2, 0);
    GameBit_Set(0x126, 1);
    GameBit_Set(0x127, 1);
    GameBit_Set(0x2d, 1);
    GameBit_Set(0x40, 1);
    GameBit_Set(0x1d7, 1);
    GameBit_Set(0x1d8, 0);
    ((Dll19CState*)sub)->unk4 = 0xc;
    *(s16*)(sub + 8) = 0x1e;
    ((Dll19CState*)sub)->unk2 = 0xc8;
    ((void(*)(int, int, int, int, int))((void**)*(void**)gTitleMenuControlInterface)[6])(2, 0x2b, 0x50, 1, 0);
    ((Dll19CState*)sub)->unk6 = 0;
    *(s16*)(sub + 0xa) = 0;
    sub[0x16] = 0;
    *(s16*)(sub + 0x10) = 0xc8;
    *(s16*)(sub + 0xe) = 0xfa0;
    res = Resource_Acquire(0x6a, 1);
    *(s16*)(sub + 0xc) = ((s16(*)(u8*, int, int, int, int, int))((void**)*(int*)res)[1])(obj, 1, 0, 0x402, -1, 0);
    Resource_Release(res);
    ((GameObject*)obj)->anim.worldPosX = ((GameObject*)obj)->anim.localPosX;
    ((GameObject*)obj)->anim.worldPosY = ((GameObject*)obj)->anim.localPosY;
    ((GameObject*)obj)->anim.worldPosZ = ((GameObject*)obj)->anim.localPosZ;
}

/*
 * Function: dll_19C_init
 * EN v1.0 Address: 0x801CC950
 * EN v1.0 Size: 64b
 */
void dll_19C_init(int obj, u8* initData);

/*
 * Function: dll_19D_free
 * EN v1.0 Address: 0x801CC9A8
 * EN v1.0 Size: 132b
 */

/*
 * Function: dll_19D_init
 * EN v1.0 Address: 0x801CCECC
 * EN v1.0 Size: 208b
 */

/*
 * Function: dll_19D_hitDetect
 * EN v1.0 Address: 0x801CCA30
 * EN v1.0 Size: 276b
 */

/*
 * Function: dll_19D_update
 * EN v1.0 Address: 0x801CCB44
 * EN v1.0 Size: 904b
 */
