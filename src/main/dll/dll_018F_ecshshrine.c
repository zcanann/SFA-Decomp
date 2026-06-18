/*
 * DLL 0x18F - ECSH shrine animated object controller.
 *
 * Drives the floating shrine object at the EarthWalker/Cape Shrine: a
 * bobbing model that orbits/wobbles toward the player (fn_801C5990) and
 * fades with distance, plus its anim-event callback (fn_801C5CE4) which
 * reacts to torch signals, sets camera vars, and toggles the model light.
 *
 * ecsh_shrine_update is the main state machine: it runs a six-slot rune
 * puzzle whose working set lives in a shared scratch buffer (EcshPuzzleState
 * at lbl_80326208 - color floats plus current/next rune arrays that are
 * rotated/swapped per round), and sequences the screen transitions, object
 * sequences and looping SFX as the puzzle advances through its phases.
 * Several render/query helpers (modelMtxFn, func0E, render2, func0B,
 * setScale) read the active instance through the lbl_803DDBC4 singleton.
 *
 * The DLL owns a cluster of GameBits set on init/free/transition (0xefa,
 * 0xcbb, 0xa7f, 0xb9d, 0x129, 0x143, ...) and a torch GameBit (0x58b).
 */
#include "main/game_object.h"
#include "main/dll/mmshrineanimobj_struct.h"
#include "main/objseq.h"

#include "main/dll/mmshrine/ecsh_shrine_state.h"
#include "main/game_ui_interface.h"
#include "main/screen_transition.h"

typedef struct EcshIntPair
{
    int a;
    int b;
} EcshIntPair;

extern u32 randomGetRange(int min, int max);
extern f32 Vec_xzDistance(f32 * a, f32 * b);
extern f32 mathSinf(f32 x);
extern f32 timeDelta;
extern f32 lbl_803E4F90;
extern f32 lbl_803E4F94;
extern f32 lbl_803E4F98;
extern f32 lbl_803E4F9C;
extern f32 lbl_803E4FA0;
extern f32 lbl_803E4FA4;
extern f32 lbl_803E4FA8;
extern f32 lbl_803E4FAC;
extern f32 lbl_803E4FB0;
extern f32 lbl_803E4FB4;
extern f32 lbl_803E4FB8;
extern f32 lbl_803E4FC8;
extern f32 lbl_803E4FCC;
extern f32 lbl_803E4FD0;
extern f32 lbl_803E4FD4;
extern f32 lbl_803E4FD8;
extern f32 lbl_803E4FDC;
extern f32 lbl_803E4FE0;
extern f32 lbl_803E4FE4;
extern f32 lbl_803E4FE8;
extern f32 lbl_803E4FEC;
extern f32 lbl_803E4FF0;
extern int lbl_803DDBC0;
extern EcshIntPair lbl_803E8470;
extern s16 lbl_80326238[];

extern u32 GameBit_Get(u32 bit);
extern void Music_Trigger(int trackId, int restart);
extern void ModelLightStruct_free(void* p);
extern int objCreateLight(int a, int b);
extern void skyFn_80088c94(int a, int b);
extern void getEnvfxAct(s16* obj, int* target, int id, int p);
extern int objIsCurModelNotZero(int* player);
extern void fn_80295CF4(int* player, int a);
extern void SCGameBitLatch_Update(u8* latch, int mask, int a, int b, int bit, int c);
extern void SCGameBitLatch_UpdateInverted(u8* latch, int mask, int a, int b, int bit, int c);
extern void audioStopByMask(int mask);
extern int objGetAnimStateFlags(int* player, int flags);
extern void Sfx_KeepAliveLoopedObjectSound(s16* obj, int sfxId);
extern void Sfx_PlayFromObject(s16* obj, int sfxId);
extern void ObjGroup_RemoveObject(int obj, int group);
extern void ObjGroup_AddObject(void* obj, int group);
extern int ObjMsg_Pop(void* obj, int* msg, int* a, int* b);
extern void ObjMsg_AllocQueue(void* obj, int capacity);

typedef struct MmShrineAnimState
{
    int light;
    u8 pad04[0x24];
    s16 orbitA;
    s16 orbitB;
    s16 orbitC;
    u8 pad2E[0x2];
    u8 hasTorchSignal;
} MmShrineAnimState;

typedef struct MmShrineAnimEvents
{
    u8 pad00[0x56];
    u8 eventStatus;
    u8 pad57[0x19];
    s16 eventModel;
    u8 pad72[0xF];
    u8 events[10];
    u8 eventCount;
} MmShrineAnimEvents;

#pragma scheduling off
#pragma peephole off
void fn_801C5990(MmShrineAnimObj* obj)
{
    extern s16 getAngle(f32 deltaX, f32 deltaZ); /* #57 */
    extern void* Obj_GetPlayerObject(void); /* #57 */
    u8* config;
    MmShrineAnimState* state;
    void* player;
    f32 trigA;
    f32 trigB;
    f32 distance;
    s32 angleDelta;
    ObjAnimEventList animEvents;

    config = obj->config;
    state = (MmShrineAnimState*)obj->state;
    player = Obj_GetPlayerObject();

    if ((obj->flags & 0x4000) != 0)
    {
        obj->yaw = 0;
        obj->posY = *(f32*)(config + 0xC);
        return;
    }

    state->orbitA = (s16)(state->orbitA + (s32)(lbl_803E4F90 * timeDelta));
    state->orbitB = (s16)(state->orbitB + (s32)(lbl_803E4F94 * timeDelta));
    state->orbitC = (s16)(state->orbitC + (s32)(lbl_803E4F98 * timeDelta));

    obj->posY = lbl_803E4F9C +
    (*(f32*)(config + 0xC) +
        mathSinf((lbl_803E4FA0 * (f32)state->orbitA) / lbl_803E4FA4));

    trigA = mathSinf((lbl_803E4FA0 * (f32)state->orbitB) / lbl_803E4FA4);
    trigB = mathSinf((lbl_803E4FA0 * (f32)state->orbitA) / lbl_803E4FA4);
    trigB = trigB + trigA;
    obj->roll = lbl_803E4FA8 * trigB;

    trigA = mathSinf((lbl_803E4FA0 * (f32)state->orbitC) / lbl_803E4FA4);
    trigB = mathSinf((lbl_803E4FA0 * (f32)state->orbitA) / lbl_803E4FA4);
    trigB = trigB + trigA;
    obj->pitch = lbl_803E4FA8 * trigB;

    ((ObjAnimAdvanceObjectFirstF32Fn)ObjAnim_AdvanceCurrentMove)((int)obj, lbl_803E4FAC, timeDelta,
                                                                 &animEvents);

    if (player != NULL)
    {
        angleDelta = (u16)getAngle(obj->posX - ((GameObject*)player)->anim.worldPosX,
                                   obj->posZ - ((GameObject*)player)->anim.worldPosZ) -
            (u16)obj->yaw;
        if (angleDelta > 0x8000)
        {
            angleDelta -= 0xFFFF;
        }
        if (angleDelta < -0x8000)
        {
            angleDelta += 0xFFFF;
        }

        obj->yaw = (s16)(*(s16*)(int)&obj->yaw + (s32)(((f32)angleDelta * timeDelta) / lbl_803E4FB0));
        distance = Vec_xzDistance((f32*)((int)&obj->posX), (f32*)((int)player + 0x18));
        if (distance <= lbl_803E4FB4)
        {
            obj->fadeAlpha = (u8)(s32)(lbl_803E4FB8 * (distance / lbl_803E4FB4));
        }
        else
        {
            obj->fadeAlpha = 0xFF;
        }
    }
}

int fn_801C5CE4(void* objArg, int unused, void* eventListArg)
{
    extern void fn_80296518(void* obj, int arg, int enable); /* #57 */
    extern void modelLightStruct_setEnabled(int light, int mode, f32 value); /* #57 */
    extern void* Obj_GetPlayerObject(void); /* #57 */
    extern void GameBit_Set(int eventId, int value); /* #57 */
    MmShrineAnimObj* obj;
    MmShrineAnimState* state;
    MmShrineAnimEvents* eventList;
    void* player;
    int i;
    u8 event;

    (void)unused;
    obj = (MmShrineAnimObj*)objArg;
    eventList = (MmShrineAnimEvents*)eventListArg;
    state = (MmShrineAnimState*)obj->state;
    player = Obj_GetPlayerObject();
    eventList->eventModel = -1;
    eventList->eventStatus = 0;

    for (i = 0; i < eventList->eventCount; i++)
    {
        event = eventList->events[i];
        if (event != 0)
        {
            switch (event)
            {
            case 3:
                state->hasTorchSignal = 1;
                break;
            case 7:
                fn_80296518(player, 8, 1);
                GameBit_Set(0x143, 1);
                GameBit_Set(0xBA8, 1);
                break;
            case 13:
                (*gObjectTriggerInterface)->setCamVars(0x48, 100, 0, 0x50);
                break;
            case 14:
                obj->flags |= 0x4000;
                if ((void*)state->light != NULL)
                {
                    modelLightStruct_setEnabled(state->light, 0, lbl_803E4FC8);
                }
                break;
            case 15:
                obj->flags &= ~0x4000;
                if ((void*)state->light != NULL)
                {
                    modelLightStruct_setEnabled(state->light, 0, lbl_803E4FC8);
                }
                break;
            }
        }
        eventList->events[i] = 0;
    }

    return 0;
}

void ecsh_shrine_modelMtxFn(int* p1, u8* p2)
{
    extern int lbl_803DDBC4; /* type varies per fn for coloring - #57 */
    int* obj = (int*)lbl_803DDBC4;
    int* inner;
    if (obj == NULL) return;
    inner = ((GameObject*)obj)->extra;
    *p2 = ((EcshShrineState*)inner)->unk2E;
    *p1 = ((EcshShrineState*)inner)->unk24;
}

void ecsh_shrine_func0E(u8 v)
{
    extern int lbl_803DDBC4; /* #57 */
    int* obj = (int*)lbl_803DDBC4;
    int* inner;
    if (obj == NULL) return;
    inner = ((GameObject*)obj)->extra;
    if ((u32)(u8)v == ((EcshShrineState*)inner)->unk2E)
    {
        ((EcshShrineState*)inner)->unk26 = 1;
    }
    else
    {
        ((EcshShrineState*)inner)->unk26 = 0;
    }
}

typedef struct EcshRenderPair
{
    f32 a;
    f32 b;
} EcshRenderPair;

void ecsh_shrine_render2(u8 idx, f32 a, f32 b)
{
    extern EcshRenderPair lbl_80326208[]; /* #57 */
    extern int lbl_803DDBC4; /* #57 */
    int v;
    if ((int*)lbl_803DDBC4 == NULL) return;
    v = lbl_80326238[(u32)idx];
    lbl_80326208[v].a = a;
    lbl_80326208[v].b = b;
}

void ecsh_shrine_func0B(u8 idx, f32* out1, f32* out2)
{
    extern u8 lbl_80326208[]; /* #57 */
    extern void* lbl_803DDBC4; /* #57 */
    int j;
    if (lbl_803DDBC4 == NULL) return;
    j = lbl_80326238[idx];
    *out1 = *(f32*)((char*)lbl_80326208 + j * 8);
    j = lbl_80326238[idx];
    *out2 = *(f32*)((char*)lbl_80326208 + j * 8 + 4);
}

void ecsh_shrine_setScale(s16* out)
{
    extern void* lbl_803DDBC4; /* #57 */
    int* obj = (int*)lbl_803DDBC4;
    int* state;
    if (obj == NULL) return;
    state = ((GameObject*)obj)->extra;
    *out = *(s16*)((char*)state + 0x20);
}

int ecsh_shrine_getExtraSize(void)
{
    return 0x38;
}

int ecsh_shrine_getObjectTypeId(void)
{
    return 0;
}

void ecsh_shrine_hitDetect(void)
{
}

void ecsh_shrine_render(int obj, int p2, int p3, int p4, int p5, s8 visible)
{
    extern void objParticleFn_80099d84(int obj, f32 a, int kind, f32 b, int h); /* #57 */
    extern void objRenderFn_8003b8f4(int p1, int p2, int p3, int p4, int p5, f32 scale); /* #57 */
    extern void modelLightStruct_setEnabled(int handle, int flag, f32 v); /* #57 */
    void** inner = ((GameObject*)obj)->extra;
    if (visible == 0)
    {
        if (*inner != NULL)
        {
            modelLightStruct_setEnabled((int)*inner, 0, lbl_803E4FC8);
        }
        return;
    }
    if (*inner != NULL)
    {
        modelLightStruct_setEnabled((int)*inner, 1, lbl_803E4FC8);
    }
    objRenderFn_8003b8f4(obj, p2, p3, p4, p5, lbl_803E4FC8);
    objParticleFn_80099d84(obj, lbl_803E4FC8, 7, *(f32*)&lbl_803E4FC8, (int)*inner);
}

void ecsh_shrine_free(int* obj)
{
    extern void GameBit_Set(int eventId, int value); /* #57 */
    int* inner = ((GameObject*)obj)->extra;
    Music_Trigger(0xd8, 0);
    Music_Trigger(0xd9, 0);
    Music_Trigger(0x08, 0);
    Music_Trigger(0x0d, 0);
    if (*(void**)inner != NULL)
    {
        ModelLightStruct_free(*(void**)inner);
        *(void**)inner = NULL;
    }
    ObjGroup_RemoveObject((int)obj, 0xb);
    GameBit_Set(0xefa, 0);
    GameBit_Set(0xcbb, 1);
    GameBit_Set(0xa7f, 1);
}

typedef struct EcshPuzzleState
{
    f32 f[12]; /* 0x00 */
    s16 cur[6]; /* 0x30 */
    s16 next[7]; /* 0x3c */
} EcshPuzzleState;

#pragma opt_strength_reduction off
void ecsh_shrine_update(s16* obj)
{
    extern int* Obj_GetPlayerObject(void); /* #57 */
    extern void fn_801C5990(s16 * obj); /* #57 */
    extern u8 lbl_80326208[]; /* #57 */
    extern void GameBit_Set(int bit, int value); /* #57 */
    f32 t[2];
    int msgC;
    int msgA;
    int msgB;
    EcshPuzzleState* ps;
    u8* sub;
    int* player;
    u8 gv;
    int pick;
    int n;
    s16 sc;
    f32 z;
    f32 fv;

    ps = (EcshPuzzleState*)lbl_80326208;
    sub = ((GameObject*)obj)->extra;
    player = Obj_GetPlayerObject();
    *(EcshIntPair*)&t[0] = *(EcshIntPair*)&lbl_803E8470;
    if (sub[0x32] == 0)
    {
        gv = GameBit_Get(0x58b);
        sub[0x32] = gv;
        if (sub[0x32] != 0)
        {
            (*gGameUIInterface)->showNpcDialogue(0x285, 0x14, 0x8c, 1);
        }
    }
    if (((GameObject*)obj)->unkF4 != 0)
    {
        ((GameObject*)obj)->unkF4 = ((GameObject*)obj)->unkF4 - 1;
        if (((GameObject*)obj)->unkF4 == 0)
        {
            skyFn_80088c94(7, 1);
            getEnvfxAct(obj, player, 0x221, 0);
            getEnvfxAct(obj, player, 0x220, 0);
            getEnvfxAct(obj, player, 0x222, 0);
        }
    }
    fn_801C5990(obj);
    if (player != NULL && objIsCurModelNotZero(player) == 0)
    {
        fn_80295CF4(player, 0);
    }
    msgC = 0;
    while (ObjMsg_Pop(obj, &msgA, &msgB, &msgC) != 0)
    {
    }
    SCGameBitLatch_Update(sub + 0x34, 2, -1, -1, 0xb9d, 0xd);
    SCGameBitLatch_UpdateInverted(sub + 0x34, 1, -1, -1, 0xcbb, 8);
    SCGameBitLatch_Update(sub + 0x34, 0x10, -1, -1, 0xcbb, 0xc4);
    if (((EcshShrineState*)sub)->unk8 > (z = *(f32*)&lbl_803E4FCC))
    {
        ((EcshShrineState*)sub)->unk8 = ((EcshShrineState*)sub)->unk8 - timeDelta;
        if (((EcshShrineState*)sub)->unk8 <= z)
        {
            ((EcshShrineState*)sub)->unk8 = z;
        }
    }
    else
    {
        switch (sub[0x2f])
        {
        case 0:
            ((GameObject*)obj)->anim.flags &= ~OBJANIM_FLAG_HIDDEN;
            fv = *(f32*)(sub + 0x10) - timeDelta;
            *(f32*)(sub + 0x10) = fv;
            if (fv <= z)
            {
                Sfx_PlayFromObject(obj, 0x343);
                *(f32*)(sub + 0x10) = (f32)(int)
                randomGetRange(500, 1000);
            }
            if ((*(u8*)&((GameObject*)obj)->anim.resetHitboxMode & 1) != 0)
            {
                sub[0x2f] = 1;
                GameBit_Set(0x129, 0);
                (*gObjectTriggerInterface)->runSequence(0, obj, -1);
                Music_Trigger(0xd8, 1);
                {
                    f32 fz = lbl_803E4FCC;
                    ps->f[0] = fz;
                    ps->f[1] = fz;
                    ps->f[2] = fz;
                    ps->f[3] = fz;
                    ps->f[4] = fz;
                    ps->f[5] = fz;
                    ps->f[6] = fz;
                    ps->f[7] = fz;
                    ps->f[8] = fz;
                    ps->f[9] = fz;
                    ps->f[10] = fz;
                    ps->f[11] = fz;
                }
                ps->cur[0] = ps->next[0];
                ps->cur[1] = ps->next[1];
                ps->cur[2] = ps->next[2];
                ps->cur[3] = ps->next[3];
                ps->cur[4] = ps->next[4];
                ps->cur[5] = ps->next[5];
                ps->next[0] = ps->next[6];
            }
            break;
        case 1:
            if (sub[0x30] == 1)
            {
                sub[0x2f] = 2;
                ((EcshShrineState*)sub)->unk8 = lbl_803E4FD0;
                ((EcshShrineState*)sub)->unk24 = 6;
                Sfx_PlayFromObject(obj, 0x16f);
                ((EcshShrineState*)sub)->unk4 = lbl_803E4FCC;
                GameBit_Set(0xb9d, 1);
                (*gScreenTransitionInterface)->step(0x78, 1);
            }
            ((GameObject*)obj)->anim.flags |= OBJANIM_FLAG_HIDDEN;
            break;
        case 2:
            sub[0x2f] = 3;
            ((EcshShrineState*)sub)->unk8 = lbl_803E4FD4;
            ((EcshShrineState*)sub)->unk24 = 8;
            ((EcshShrineState*)sub)->unk4 = lbl_803E4FD8;
            ((EcshShrineState*)sub)->unk22 = 5;
            gv = randomGetRange(0, 5);
            sub[0x2e] = gv;
            (*gObjectTriggerInterface)->runSequence(2, obj, -1);
            break;
        case 3:
        case 4:
        case 5:
            if (((EcshShrineState*)sub)->unk4 > (fv = lbl_803E4FCC))
            {
                if (((EcshShrineState*)sub)->unk24 == 1 && sub[0x31] == 0
                    && ((EcshShrineState*)sub)->unk4 < *(f32*)(sub + 0x14))
                {
                    if ((int)randomGetRange(0, 10) > 7)
                    {
                        Sfx_PlayFromObject(obj, 0x345);
                    }
                    sub[0x31] = 1;
                }
                ((EcshShrineState*)sub)->unk4 = ((EcshShrineState*)sub)->unk4 - timeDelta;
                if (((EcshShrineState*)sub)->unk4 < lbl_803E4FCC)
                {
                    ((EcshShrineState*)sub)->unk4 = *(f32*)&lbl_803E4FCC;
                }
            }
            else
            {
                switch (((EcshShrineState*)sub)->unk24)
                {
                case 8:
                    ((EcshShrineState*)sub)->unk24 = 2;
                    ((EcshShrineState*)sub)->unk4 = lbl_803E4FD8;
                    ((EcshShrineState*)sub)->unk8 = lbl_803E4FDC;
                    break;
                case 9:
                    ((EcshShrineState*)sub)->unk24 = 8;
                    ((EcshShrineState*)sub)->unk4 = lbl_803E4FD8;
                    ((EcshShrineState*)sub)->unk8 = lbl_803E4FDC;
                    break;
                case 7:
                    ((EcshShrineState*)sub)->unk24 = 3;
                    ((EcshShrineState*)sub)->unk4 = lbl_803E4FD8;
                    ((EcshShrineState*)sub)->unk8 = lbl_803E4FDC;
                    break;
                case 2:
                    ((EcshShrineState*)sub)->unk22 -= 1;
                    if (((EcshShrineState*)sub)->unk22 <= 0)
                    {
                        Sfx_PlayFromObject(0, 0x3a8);
                        ((EcshShrineState*)sub)->unk24 = 5;
                        if (sub[0x2f] == 3)
                        {
                            *(f32*)(sub + 0xc) = lbl_803E4FA8;
                        }
                        else if (sub[0x2f] == 4)
                        {
                            *(f32*)(sub + 0xc) = lbl_803E4FA8;
                        }
                        else
                        {
                            *(f32*)(sub + 0xc) = lbl_803E4FA8;
                        }
                    }
                    else
                    {
                        sub[0x31] = 0;
                        *(f32*)(sub + 0x14) = (f32)(int)
                        randomGetRange(0x28, 0x3c);
                        Sfx_PlayFromObject(obj, 0x344);
                        ((EcshShrineState*)sub)->unk24 = 0;
                        ((EcshShrineState*)sub)->unk4 = lbl_803E4FE0;
                        if (sub[0x2f] == 3)
                        {
                            pick = randomGetRange(0, 1);
                        }
                        else if (sub[0x2f] == 4)
                        {
                            pick = randomGetRange(0, 5);
                        }
                        else
                        {
                            pick = randomGetRange(0, 7);
                        }
                        if (pick == 0)
                        {
                            for (n = 0; n < 6; n++)
                            {
                                ps->cur[n] += 1;
                                if (ps->cur[n] > 5)
                                {
                                    ps->cur[n] = 0;
                                }
                            }
                        }
                        else if (pick == 1)
                        {
                            for (n = 0; n < 6; n++)
                            {
                                ps->cur[n] -= 1;
                                if (ps->cur[n] < 0)
                                {
                                    ps->cur[n] = 5;
                                }
                            }
                        }
                        else if (pick == 2)
                        {
                            sc = ps->cur[0];
                            ps->cur[0] = ps->cur[2];
                            ps->cur[2] = ps->cur[4];
                            ps->cur[4] = sc;
                        }
                        else if (pick == 3)
                        {
                            sc = ps->cur[4];
                            ps->cur[4] = ps->cur[0];
                            ps->cur[0] = ps->cur[2];
                            ps->cur[2] = sc;
                        }
                        else if (pick == 4)
                        {
                            sc = ps->cur[1];
                            ps->cur[1] = ps->cur[3];
                            ps->cur[3] = ps->cur[5];
                            ps->cur[5] = sc;
                        }
                        else if (pick == 5)
                        {
                            sc = ps->cur[5];
                            ps->cur[5] = ps->cur[1];
                            ps->cur[1] = ps->cur[3];
                            ps->cur[3] = sc;
                        }
                        else if (pick == 6)
                        {
                            t[0] = ps->f[2];
                            t[1] = ps->f[3];
                            ps->f[2] = ps->f[4];
                            ps->f[3] = ps->f[5];
                            ps->f[4] = ps->f[8];
                            ps->f[5] = ps->f[9];
                            ps->f[8] = ps->f[10];
                            ps->f[9] = ps->f[11];
                            ps->f[10] = t[0];
                            ps->f[11] = t[1];
                        }
                        else if (pick == 7)
                        {
                            t[0] = ps->f[10];
                            t[1] = ps->f[11];
                            ps->f[10] = ps->f[8];
                            ps->f[11] = ps->f[9];
                            ps->f[8] = ps->f[4];
                            ps->f[9] = ps->f[5];
                            ps->f[4] = ps->f[2];
                            ps->f[5] = ps->f[3];
                            ps->f[2] = t[0];
                            ps->f[3] = t[1];
                        }
                    }
                    break;
                case 0:
                    ((EcshShrineState*)sub)->unk24 = 1;
                    ((EcshShrineState*)sub)->unk4 = lbl_803E4FE4;
                    break;
                case 1:
                    ((EcshShrineState*)sub)->unk24 = 4;
                    ((EcshShrineState*)sub)->unk4 = fv;
                    break;
                case 4:
                    ((EcshShrineState*)sub)->unk24 = 2;
                    ((EcshShrineState*)sub)->unk4 = fv;
                    break;
                case 5:
                    Sfx_KeepAliveLoopedObjectSound(0, 0x3a8);
                    if (((EcshShrineState*)sub)->unk26 == 0)
                    {
                        (*gScreenTransitionInterface)->start(0x1e, 1);
                        ((EcshShrineState*)sub)->unk8 = lbl_803E4FE8;
                        ((EcshShrineState*)sub)->unk24 = 7;
                        Sfx_PlayFromObject(obj, 0x16f);
                        sub[0x2f] = 10;
                    }
                    else if (((EcshShrineState*)sub)->unk26 == 1)
                    {
                        if (sub[0x2f] == 3)
                        {
                            gv = randomGetRange(0, 5);
                            sub[0x2e] = gv;
                            sub[0x2f] = 4;
                            ((EcshShrineState*)sub)->unk24 = 9;
                            ((EcshShrineState*)sub)->unk8 = lbl_803E4FEC;
                            ((EcshShrineState*)sub)->unk4 = lbl_803E4FB0;
                            ((EcshShrineState*)sub)->unk22 = 7;
                            ((EcshShrineState*)sub)->unk26 = -1;
                            Sfx_PlayFromObject(obj, 0x170);
                            (*gObjectTriggerInterface)->runSequence(2, obj, -1);
                        }
                        else if (sub[0x2f] == 4)
                        {
                            gv = randomGetRange(0, 5);
                            sub[0x2e] = gv;
                            sub[0x2f] = 5;
                            ((EcshShrineState*)sub)->unk24 = 9;
                            ((EcshShrineState*)sub)->unk8 = lbl_803E4FEC;
                            ((EcshShrineState*)sub)->unk4 = lbl_803E4FB0;
                            ((EcshShrineState*)sub)->unk22 = 9;
                            ((EcshShrineState*)sub)->unk26 = -1;
                            Sfx_PlayFromObject(obj, 0x170);
                            (*gObjectTriggerInterface)->runSequence(2, obj, -1);
                        }
                        else
                        {
                            ((EcshShrineState*)sub)->unk8 = lbl_803E4FE8;
                            (*gScreenTransitionInterface)->start(0x1e, 1);
                            sub[0x2f] = 6;
                            ((EcshShrineState*)sub)->unk24 = 3;
                            ((EcshShrineState*)sub)->unk26 = 0;
                            ((EcshShrineState*)sub)->unk24 = 7;
                            Sfx_PlayFromObject(obj, 0x7e);
                            Sfx_PlayFromObject(obj, 0x16f);
                        }
                    }
                    else
                    {
                        *(f32*)(sub + 0xc) = *(f32*)(sub + 0xc) - timeDelta;
                        if (*(f32*)(sub + 0xc) <= lbl_803E4FCC)
                        {
                            sub[0x2f] = 10;
                            (*gScreenTransitionInterface)->start(0x1e, 1);
                            ((EcshShrineState*)sub)->unk8 = lbl_803E4FE8;
                            ((EcshShrineState*)sub)->unk24 = 7;
                            Sfx_PlayFromObject(obj, 0x16f);
                        }
                    }
                    break;
                }
            }
            break;
        case 10:
            GameBit_Set(0xa6f, 1);
            sub[0x2f] = 8;
            break;
        case 6:
            GameBit_Set(0xb9d, 0);
            audioStopByMask(3);
            if (objGetAnimStateFlags(player, 8) != 0)
            {
                GameBit_Set(0x129, 1);
                sub[0x2f] = 7;
            }
            else
            {
                sub[0x2f] = 7;
                (*gObjectTriggerInterface)->runSequence(1, obj, -1);
            }
            break;
        case 7:
            GameBit_Set(0x129, 0);
            sub[0x2f] = 8;
            break;
        case 8:
            sub[0x2f] = 0;
            ((EcshShrineState*)sub)->unk4 = z;
            ((EcshShrineState*)sub)->unk20 = 0;
            ((EcshShrineState*)sub)->unk22 = 0;
            ((EcshShrineState*)sub)->unk24 = 0;
            ((EcshShrineState*)sub)->unk26 = -1;
            sub[0x2e] = 0;
            sub[0x30] = 0;
            ((EcshShrineState*)sub)->unk8 = lbl_803E4FF0;
            GameBit_Set(0x129, 1);
            GameBit_Set(0xb9d, 0);
            GameBit_Set(0xa6d, 0);
            GameBit_Set(0xa6f, 0);
            GameBit_Set(0xa70, 0);
            GameBit_Set(0x143, 0);
            sub[0x30] = 0;
            ((EcshShrineState*)sub)->unk26 = -1;
            break;
        }
    }
}
#pragma opt_strength_reduction reset

void ecsh_shrine_release(void)
{
}

void ecsh_shrine_initialise(void)
{
}

void ecsh_shrine_init(s16* obj, s8* def)
{
    extern s16* lbl_803DDBC4; /* #57 */
    extern void GameBit_Set(int bit, int value); /* #57 */
    int* sub = ((GameObject*)obj)->extra;
    u8 gv;
    lbl_803DDBC0 = 0;
    lbl_803DDBC4 = 0;
    *obj = (s16)((s32)def[0x18] << 8);
    ((EcshShrineState*)sub)->unk2F = 0;
    ((EcshShrineState*)sub)->unk30 = 0;
    ((EcshShrineState*)sub)->unk4 = lbl_803E4FCC;
    ((EcshShrineState*)sub)->unk20 = 0;
    ((EcshShrineState*)sub)->unk22 = 0;
    ((EcshShrineState*)sub)->unk24 = 0;
    ((EcshShrineState*)sub)->unk26 = -1;
    ((EcshShrineState*)sub)->unk2E = 0;
    ((EcshShrineState*)sub)->unk34 = 0;
    ((GameObject*)obj)->animEventCallback = (void*)fn_801C5CE4;
    ObjMsg_AllocQueue(obj, 4);
    GameBit_Set(0xba5, 1);
    GameBit_Set(0x129, 1);
    GameBit_Set(0x143, 0);
    ((EcshShrineState*)sub)->unk18 = 0xc;
    ((EcshShrineState*)sub)->unk1C = 0x1e;
    ((EcshShrineState*)sub)->unk8 = lbl_803E4FD0;
    ((EcshShrineState*)sub)->unk1A = 0;
    ((EcshShrineState*)sub)->unk1E = 0;
    gv = GameBit_Get(0x58b);
    ((EcshShrineState*)sub)->unk32 = gv;
    lbl_803DDBC4 = obj;
    ObjGroup_AddObject(obj, 0xb);
    ((GameObject*)obj)->unkF4 = 1;
    if (*(void**)sub == NULL)
    {
        *(int*)sub = objCreateLight(0, 1);
    }
    GameBit_Set(0xefa, 1);
}
