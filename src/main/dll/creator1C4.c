/* === moved from main/dll/mmshrine/shrine1C2.c [801C70F0-801C7724) (TU re-split, docs/boundary_audit.md) === */
#include "main/audio/sfx_ids.h"
#include "main/game_ui_interface.h"
#include "main/obj_placement.h"
#include "main/game_object.h"
#include "main/objanim.h"
#include "main/mapEventTypes.h"
#include "main/dll/mmshrine/shrine1C2.h"
#include "main/dll/mmshrine/torch1C1.h"
#include "main/objseq.h"
#include "main/resource.h"
#include "main/screen_transition.h"

#include "main/dll/mmshrine/ecsh_shrine_state.h"


extern undefined4 FUN_80006824();
extern undefined4 FUN_80006b0c();
extern undefined4 FUN_80006b14();
extern uint FUN_80017690();
extern u32 randomGetRange(int min, int max);
extern undefined4 FUN_80017830();
extern int FUN_80017ae4();
extern uint FUN_80017ae8();
extern undefined8 ObjGroup_RemoveObject();
extern undefined4 ObjGroup_AddObject();
extern int ObjMsg_Pop();
extern undefined4 ObjMsg_AllocQueue();

extern undefined4 DAT_803dc070;

/*
 * --INFO--
 *
 * Function: ecsh_shrine_update
 * EN v1.0 Address: 0x801C60B8
 * EN v1.0 Size: 3360b
 * EN v1.1 Address: 0x801C666C
 * EN v1.1 Size: 3104b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
extern void skyFn_80088c94(int a, int b);
extern void fn_801C5990(s16 * obj);
extern int objIsCurModelNotZero(int* player);
extern void fn_80295CF4(int* player, int a);
extern void audioStopByMask(int mask);
extern void Sfx_KeepAliveLoopedObjectSound(s16* obj, int sfxId);
extern ObjectTriggerInterface** gObjectTriggerInterface;
extern ScreenTransitionInterface** gScreenTransitionInterface;
extern u8 lbl_80326208[];
extern int lbl_803E8470;
extern f32 timeDelta;
extern f32 lbl_803E4FA8;
extern f32 lbl_803E4FB0;
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

typedef struct EcshPuzzleState
{
    f32 f[12]; /* 0x00 */
    s16 cur[6]; /* 0x30 */
    s16 next[7]; /* 0x3c */
} EcshPuzzleState;

typedef struct EcshIntPair
{
    int a;
    int b;
} EcshIntPair;

#pragma opt_strength_reduction off
#pragma opt_strength_reduction reset


/*
 * --INFO--
 *
 * Function: FUN_801c6e04
 * EN v1.0 Address: 0x801C6E04
 * EN v1.0 Size: 704b
 * EN v1.1 Address: 0x801C7408
 * EN v1.1 Size: 668b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */


/* Trivial 4b 0-arg blr leaves. */


void ecsh_creator_free(void);

void ecsh_creator_hitDetect(void);

void ecsh_creator_release(void);

void ecsh_creator_initialise(void);

void gpsh_shrine_hitDetect(void)
{
}

/* 8b "li r3, N; blr" returners. */
int ecsh_creator_getExtraSize(void);
int ecsh_creator_getObjectTypeId(void);
int gpsh_shrine_getExtraSize(void) { return 0x18; }
int gpsh_shrine_getObjectTypeId(void) { return 0x0; }

extern void ModelLightStruct_free(void* light);
extern void gameTimerStop(void);
extern void modelLightStruct_setEnabled(void* light, int enabled, f32 scale);
extern void objRenderFn_8003b8f4(f32);
extern void objParticleFn_80099d84(void* obj, f32 scale, int type, f32 extraScale, void* light);
extern f32 lbl_803E5038;

void gpsh_shrine_free(int* obj)
{
    extern void Music_Trigger(int id, int restart); /* #57 */
    extern void GameBit_Set(int bit, int value); /* #57 */
    extern int GameBit_Get(int bit); /* #57 */
    void** state = ((GameObject*)obj)->extra;
    void* light = state[0];

    if (light != NULL)
    {
        ModelLightStruct_free(light);
        state[0] = NULL;
    }
    gameTimerStop();
    ObjGroup_RemoveObject(obj, 0xb);
    Music_Trigger(0xd8, 0);
    Music_Trigger(0xd9, 0);
    Music_Trigger(8, 0);
    Music_Trigger(0xb, 0);
    GameBit_Set(0xefa, 0);
    GameBit_Set(0xcbb, GameBit_Get(0xc91) == 0);
}

void gpsh_shrine_render(void* obj, int p2, int p3, int p4, int p5, s8 visible)
{
    void** state = ((GameObject*)obj)->extra;

    if (visible == 0)
    {
        void* light = state[0];
        if (light != NULL)
        {
            modelLightStruct_setEnabled(light, 0, lbl_803E5038);
        }
    }
    else
    {
        void* light = state[0];
        if (light != NULL)
        {
            modelLightStruct_setEnabled(light, 1, lbl_803E5038);
        }
        ((void (*)(void*, int, int, int, int, f32))objRenderFn_8003b8f4)(obj, p2, p3, p4, p5, lbl_803E5038);
        objParticleFn_80099d84(obj, lbl_803E5038, 7, *(f32*)&lbl_803E5038, state[0]);
    }
}

/* render-with-objRenderFn_8003b8f4 pattern. */
extern f32 lbl_803E4FF8;

void ecsh_creator_render(int p1, int p2, int p3, int p4, int p5, s8 visible);

void ecsh_creator_init(s16* obj, s8* def);

extern void fn_80296518(int* player, int a, int b);
extern int fn_801C5CE4(void* objArg, int unused, void* eventListArg);
extern int lbl_803DDBC0;
extern s16* lbl_803DDBC4;

typedef struct EcshShrineByte15
{
    u8 flag : 1;
    u8 rest : 7;
} EcshShrineByte15;

int gpsh_shrine_SeqFn(int* obj, int unused, ObjAnimUpdateState* animUpdate)
{
    extern void GameBit_Set(int bit, int value); /* #57 */
    extern int* Obj_GetPlayerObject(void); /* #57 */
    u8* sub;
    int* player;
    int i;
    u8 ev;
    void* light;

    sub = ((GameObject*)obj)->extra;
    player = Obj_GetPlayerObject();
    animUpdate->activeHitVolumePair = -1;
    animUpdate->sequenceEventActive = 0;
    for (i = 0; i < animUpdate->eventCount; i++)
    {
        ev = animUpdate->eventIds[i];
        if (ev != 0)
        {
            switch (ev)
            {
            case 3:
                ((EcshShrineByte15*)(sub + 0x15))->flag = 1;
                break;
            case 7:
                fn_80296518(player, 0x80, 1);
                GameBit_Set(0x12b, 1);
                GameBit_Set(0xc85, 1);
                (*gMapEventInterface)->setMode(0xb, 5);
                break;
            case 14:
                ((GameObject*)obj)->anim.flags |= OBJANIM_FLAG_HIDDEN;
                light = *(void**)sub;
                if (light != NULL)
                {
                    modelLightStruct_setEnabled(light, 0, lbl_803E5038);
                }
                break;
            case 15:
                ((GameObject*)obj)->anim.flags &= ~OBJANIM_FLAG_HIDDEN;
                light = *(void**)sub;
                if (light != NULL)
                {
                    modelLightStruct_setEnabled(light, 0, lbl_803E5038);
                }
                break;
            }
        }
        animUpdate->eventIds[i] = 0;
    }
    return 0;
}


extern u8* mmAlloc(int size, int tag, int p);
extern u8 Obj_IsLoadingLocked(void);
extern u8 framesThisStep;

void ecsh_creator_update(s16* obj);

extern int getAngle(f32 dx, f32 dz);
extern f32 Vec_xzDistance(f32 * a, f32 * b);
extern f32 lbl_803E5000;
extern f32 lbl_803E5004;
extern f32 lbl_803E5008;
extern f32 lbl_803E500C;
extern f32 lbl_803E5010;
extern f32 lbl_803E5014;
extern f32 lbl_803E5018;
extern f32 lbl_803E501C;
extern f32 lbl_803E5020;
extern f32 lbl_803E5024;
extern f32 lbl_803E5028;
extern f32 mathSinf(f32 angle);

void fn_801C70F0(s16* obj)
{
    extern int* Obj_GetPlayerObject(void); /* #57 */
    u8 buf[32];
    u8* def;
    u8* sub;
    int* player;
    int diff;
    f32 c1;
    f32 c2;
    f32 dist;

    def = *(u8**)&((GameObject*)obj)->anim.placementData;
    sub = ((GameObject*)obj)->extra;
    player = Obj_GetPlayerObject();
    if ((((GameObject*)obj)->anim.flags & OBJANIM_FLAG_HIDDEN) != 0)
    {
        *obj = 0;
        ((GameObject*)obj)->anim.localPosY = ((ObjPlacement*)def)->posY;
    }
    else
    {
        *(s16*)(sub + 0xc) = (s16)(*(s16*)(sub + 0xc) + (int)(lbl_803E5000 * timeDelta));
        *(s16*)(sub + 0xe) = (s16)(*(s16*)(sub + 0xe) + (int)(lbl_803E5004 * timeDelta));
        *(s16*)(sub + 0x10) = (s16)(*(s16*)(sub + 0x10) + (int)(lbl_803E5008 * timeDelta));
        ((GameObject*)obj)->anim.localPosY =
            lbl_803E500C + (((ObjPlacement*)def)->posY
                + mathSinf((lbl_803E5010 * (f32) * (s16*)(sub + 0xc)) / lbl_803E5014));
        c1 = mathSinf((lbl_803E5010 * (f32) * (s16*)(sub + 0xe)) / lbl_803E5014);
        c2 = mathSinf((lbl_803E5010 * (f32) * (s16*)(sub + 0xc)) / lbl_803E5014);
        c2 = c2 + c1;
        ((GameObject*)obj)->anim.rotZ = lbl_803E5018 * c2;
        c1 = mathSinf((lbl_803E5010 * (f32) * (s16*)(sub + 0x10)) / lbl_803E5014);
        c2 = mathSinf((lbl_803E5010 * (f32) * (s16*)(sub + 0xc)) / lbl_803E5014);
        c2 = c2 + c1;
        ((GameObject*)obj)->anim.rotY = lbl_803E5018 * c2;
        ((ObjAnimAdvanceObjectFirstF32Fn)ObjAnim_AdvanceCurrentMove)((int)obj, lbl_803E501C, timeDelta,
                                                                     (ObjAnimEventList*)buf);
        if (player != NULL)
        {
            diff = (getAngle(((f32*)obj)[6] - ((f32*)player)[6],
                             ((f32*)obj)[8] - ((f32*)player)[8]) & 0xffff)
                - (*obj & 0xffff);
            if (diff > 0x8000)
            {
                diff = diff - 0xffff;
            }
            if (diff < -0x8000)
            {
                diff = diff + 0xffff;
            }
            *obj = (s16)(*(s16*)(int)obj + (int)(((f32)diff * timeDelta) / lbl_803E5020));
            dist = Vec_xzDistance((f32*)((int)obj + 0x18), (f32*)((int)player + 0x18));
            if (dist <= lbl_803E5024)
            {
                ((GameObject*)obj)->anim.alpha = (u8)(int)(lbl_803E5028 * (dist / lbl_803E5024));
            }
            else
            {
                ((GameObject*)obj)->anim.alpha = 0xff;
            }
        }
    }
}

#include "main/audio/sfx_ids.h"
#include "main/obj_placement.h"
#include "main/effect_interfaces.h"
#include "main/expgfx.h"
#include "main/game_object.h"
#include "main/dll/creator1C4.h"
#include "main/mapEventTypes.h"
#include "main/objseq.h"
#include "main/screen_transition.h"

typedef struct GpshObjcreatorState
{
    u8 pad0[0x4 - 0x0];
    u8 unk4;
    u8 pad5[0x8 - 0x5];
} GpshObjcreatorState;


typedef struct GpshObjcreatorObjectDef
{
    u8 pad0[0x18 - 0x0];
    s8 unk18;
    u8 pad19[0x1A - 0x19];
    s16 unk1A;
    u8 pad1C[0x1E - 0x1C];
    s8 unk1E;
    u8 pad1F[0x20 - 0x1F];
} GpshObjcreatorObjectDef;


typedef struct GpshShrineState
{
    u8 pad0[0x4 - 0x0];
    f32 unk4;
    f32 unk8;
    u8 padC[0x12 - 0xC];
    u8 unk12;
    u8 pad13[0x14 - 0x13];
    u8 unk14;
    u8 pad15[0x18 - 0x15];
} GpshShrineState;


extern undefined8 FUN_80006728();
extern undefined4 FUN_80006770();
extern undefined4 FUN_800067c0();
extern byte FUN_80006b44();
extern undefined4 FUN_80006b4c();
extern undefined4 FUN_80006b50();
extern undefined4 FUN_80006b54();
extern undefined4 FUN_80017698();
extern int FUN_80017a98();
extern undefined4 FUN_80017ac8();
extern void* ObjGroup_GetObjects();
extern undefined4 FUN_80042b9c();
extern int FUN_80044404();
extern undefined8 FUN_80080f28();
extern undefined4 SH_LevelControl_runBloopEvent();
extern undefined4 FUN_801d8480();
extern undefined4 FUN_80286834();
extern undefined4 FUN_80286880();
extern uint FUN_80294cd0();

extern f64 DOUBLE_803e5cc8;
extern f32 lbl_803DC074;
extern f32 lbl_803E5CD4;
extern f32 lbl_803E5CD8;

/*
 * --INFO--
 *
 * Function: gpsh_shrine_update
 * EN v1.0 Address: 0x801C7724
 * EN v1.0 Size: 2520b
 * EN v1.1 Address: 0x801C7CD8
 * EN v1.1 Size: 2124b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
typedef struct
{
    u8 b80 : 1;
    u8 b40 : 1;
    u8 b20 : 1;
    u8 b10 : 1;
    u8 b08 : 1;
    u8 b04 : 1;
    u8 b02 : 1;
    u8 b01 : 1;
} GpshShrineFlags;

extern int mapGetDirIdx(int a);
extern int unlockLevel(int a, int b, int c);
extern void gameTimerInit(int a, int b);
extern void timerSetToCountUp(void);
extern int isGameTimerDisabled(void);
extern int Obj_FreeObject(int obj);
extern f32 lbl_803E503C;
extern f32 lbl_803E5040;

void gpsh_shrine_update(int obj)
{
    extern int Music_Trigger(int id, int value); /* #57 */
    extern int objGetAnimStateFlags(int obj, int flag); /* #57 */
    extern void SCGameBitLatch_UpdateInverted(int state, int a, int b, int c, int d, int e); /* #57 */
    extern void SCGameBitLatch_Update(int state, int a, int b, int c, int d, int e); /* #57 */
    extern void fn_801C70F0(int obj); /* #57 */
    extern int getEnvfxAct(int obj, int player, int id, int p); /* #57 */
    extern void Sfx_PlayFromObject(int obj, int sfx); /* #57 */
    extern int GameBit_Set(int bit, int val); /* #57 */
    extern u32 GameBit_Get(int bit); /* #57 */
    extern void* Obj_GetPlayerObject(void); /* #57 */
    int count;
    int data = *(int*)&((GameObject*)obj)->extra;
    char* player = Obj_GetPlayerObject();
    u8 b149;
    u8 b14c;
    u8 b14d;
    u8 b14e;
    u8 b14a;
    u8 b14b;
    int* objs;
    f32 t;
    f32 k;

    count = 0;
    if (player != NULL)
    {
        b149 = GameBit_Get(0x149);
        b14c = GameBit_Get(0x14c);
        b14d = GameBit_Get(0x14d);
        b14e = GameBit_Get(0x14e);
        b14a = GameBit_Get(0x14a);
        b14b = GameBit_Get(0x14b);
        if (b149 == 0 || b14c == 0 || b14d == 0 || b14e == 0 || b14a == 0 || b14b == 0)
        {
            if (!((GpshShrineFlags*)((char*)data + 0x15))->b40 && b149 != 0)
            {
                ((GpshShrineFlags*)((char*)data + 0x15))->b40 = 1;
                Sfx_PlayFromObject(0, SFXsp_lf_mutter4);
            }
            else if (!((GpshShrineFlags*)((char*)data + 0x15))->b20 && b14c != 0)
            {
                ((GpshShrineFlags*)((char*)data + 0x15))->b20 = 1;
                Sfx_PlayFromObject(0, SFXsp_lf_mutter4);
            }
            else if (!((GpshShrineFlags*)((char*)data + 0x15))->b10 && b14d != 0)
            {
                ((GpshShrineFlags*)((char*)data + 0x15))->b10 = 1;
                Sfx_PlayFromObject(0, SFXsp_lf_mutter4);
            }
            else if (!((GpshShrineFlags*)((char*)data + 0x15))->b08 && b14e != 0)
            {
                ((GpshShrineFlags*)((char*)data + 0x15))->b08 = 1;
                Sfx_PlayFromObject(0, SFXsp_lf_mutter4);
            }
            else if (!((GpshShrineFlags*)((char*)data + 0x15))->b04 && b14a != 0)
            {
                ((GpshShrineFlags*)((char*)data + 0x15))->b04 = 1;
                Sfx_PlayFromObject(0, SFXsp_lf_mutter4);
            }
            else if (!((GpshShrineFlags*)((char*)data + 0x15))->b02 && b14b != 0)
            {
                ((GpshShrineFlags*)((char*)data + 0x15))->b02 = 1;
                Sfx_PlayFromObject(0, SFXsp_lf_mutter4);
            }
        }
        if (((GameObject*)obj)->unkF4 != 0)
        {
            ((GameObject*)obj)->unkF4 -= 1;
            if (((GameObject*)obj)->unkF4 == 0)
            {
                skyFn_80088c94(7, 1);
                getEnvfxAct(obj, (int)player, 0xcc, 0);
                getEnvfxAct(obj, (int)player, 0xcd, 0);
                getEnvfxAct(obj, (int)player, 0x222, 0);
            }
        }
        fn_801C70F0(obj);
        unlockLevel(mapGetDirIdx(0x22), 1, 0);
        SCGameBitLatch_Update(data + 0x13, 2, -1, -1, 0xdd2, 0xb);
        SCGameBitLatch_UpdateInverted(data + 0x13, 1, -1, -1, 0xcbb, 8);
        SCGameBitLatch_Update(data + 0x13, 4, -1, -1, 0xcbb, 0xc4);
        if (((GpshShrineState*)data)->unk4 > (k = lbl_803E503C))
        {
            ((GpshShrineState*)data)->unk4 -= timeDelta;
            if (((GpshShrineState*)data)->unk4 <= k)
            {
                ((GpshShrineState*)data)->unk4 = k;
            }
        }
        else
        {
            switch (((GpshShrineState*)data)->unk14)
            {
            case 0:
                ((GameObject*)obj)->anim.flags &= ~OBJANIM_FLAG_HIDDEN;
                t = ((GpshShrineState*)data)->unk8 - timeDelta;
                ((GpshShrineState*)data)->unk8 = t;
                if (t <= k)
                {
                    Sfx_PlayFromObject(obj, 0x343);
                    ((GpshShrineState*)data)->unk8 = (f32)(int)
                    randomGetRange(500, 1000);
                }
                if (*(u8*)&((GameObject*)obj)->anim.resetHitboxMode & 1)
                {
                    ((GpshShrineState*)data)->unk14 = 5;
                    GameBit_Set(0x129, 0);
                    GameBit_Set(0x5af, 0);
                    GameBit_Set(0xdd2, 1);
                    (*gObjectTriggerInterface)->runSequence(0, (void*)obj, -1);
                    Music_Trigger(0xd8, 1);
                }
                break;
            case 5:
                ((GpshShrineState*)data)->unk4 = lbl_803E5040;
                (*gScreenTransitionInterface)->step(0x1e, 1);
                ((GpshShrineState*)data)->unk14 = 1;
                ((GameObject*)obj)->anim.flags |= OBJANIM_FLAG_HIDDEN;
                break;
            case 1:
                if (((GpshShrineFlags*)((char*)data + 0x15))->b80 == 1)
                {
                    GameBit_Set(0x148, 1);
                    ((GpshShrineState*)data)->unk14 = 2;
                    gameTimerInit(0x1d, 0x4e);
                    timerSetToCountUp();
                }
                break;
            case 2:
                ((GpshShrineState*)data)->unk12 = 0;
                if (GameBit_Get(0x149))
                {
                    ((GpshShrineState*)data)->unk12 += 1;
                }
                if (GameBit_Get(0x14b))
                {
                    ((GpshShrineState*)data)->unk12 += 1;
                }
                if (GameBit_Get(0x14e))
                {
                    ((GpshShrineState*)data)->unk12 += 1;
                }
                if (GameBit_Get(0x14d))
                {
                    ((GpshShrineState*)data)->unk12 += 1;
                }
                if (GameBit_Get(0x14c))
                {
                    ((GpshShrineState*)data)->unk12 += 1;
                }
                if (GameBit_Get(0x14a))
                {
                    ((GpshShrineState*)data)->unk12 += 1;
                }
                if (((GpshShrineState*)data)->unk12 == 6)
                {
                    ((GpshShrineState*)data)->unk14 = 6;
                    gameTimerStop();
                    GameBit_Set(0xdd2, 0);
                    ((GpshShrineState*)data)->unk4 = lbl_803E5040;
                    (*gScreenTransitionInterface)->start(0x1e, 1);
                    Sfx_PlayFromObject(0, SFXmn_sml_trex_fstep);
                }
                else if (isGameTimerDisabled())
                {
                    ((GpshShrineState*)data)->unk14 = 7;
                    objs = (int*)ObjGroup_GetObjects(0x10, &count);
                    for (; count != 0; count--)
                    {
                        Obj_FreeObject(objs[count - 1]);
                    }
                    ((GpshShrineState*)data)->unk4 = lbl_803E5040;
                    (*gScreenTransitionInterface)->start(0x1e, 1);
                }
                else
                {
                    ((GpshShrineState*)data)->unk12 = 0;
                }
                break;
            case 7:
                ((GpshShrineState*)data)->unk14 = 4;
                GameBit_Set(0xdd2, 0);
                GameBit_Set(0xe37, 1);
                break;
            case 6:
                ((GpshShrineState*)data)->unk14 = 3;
                break;
            case 3:
                if (objGetAnimStateFlags((int)player, 0x80))
                {
                    GameBit_Set(0x129, 1);
                    ((GpshShrineState*)data)->unk14 = 4;
                }
                else
                {
                    audioStopByMask(3);
                    (*gObjectTriggerInterface)->runSequence(1, (void*)obj, -1);
                    ((GpshShrineState*)data)->unk14 = 4;
                    GameBit_Set(0x36a, 0);
                    (*gMapEventInterface)->setAnimEvent(0xd, 0, 1);
                    (*gMapEventInterface)->setAnimEvent(0xd, 1, 1);
                    (*gMapEventInterface)->setAnimEvent(0xd, 5, 1);
                    (*gMapEventInterface)->setAnimEvent(0xd, 10, 1);
                    (*gMapEventInterface)->setAnimEvent(0xd, 0xb, 1);
                    GameBit_Set(0xc91, 1);
                    GameBit_Set(0xe05, 0);
                }
                break;
            case 4:
                ((GpshShrineState*)data)->unk14 = 0;
                ((GpshShrineFlags*)((char*)data + 0x15))->b80 = 0;
                GameBit_Set(0xdd2, 0);
                GameBit_Set(0x129, 1);
                GameBit_Set(0x149, 0);
                GameBit_Set(0x14c, 0);
                GameBit_Set(0x14d, 0);
                GameBit_Set(0x14e, 0);
                GameBit_Set(0x14a, 0);
                GameBit_Set(0x14b, 0);
                GameBit_Set(0x14b, 0);
                GameBit_Set(0x5af, 1);
                GameBit_Set(0x148, 0);
                GameBit_Set(0xe37, 0);
                GameBit_Set(0xe3a, 0);
                ((GpshShrineFlags*)((char*)data + 0x15))->b40 = 0;
                ((GpshShrineFlags*)((char*)data + 0x15))->b20 = 0;
                ((GpshShrineFlags*)((char*)data + 0x15))->b10 = 0;
                ((GpshShrineFlags*)((char*)data + 0x15))->b08 = 0;
                ((GpshShrineFlags*)((char*)data + 0x15))->b04 = 0;
                ((GpshShrineFlags*)((char*)data + 0x15))->b02 = 0;
                break;
            }
        }
    }
}


void gpsh_shrine_init(int* obj, int* def)
{
    extern int GameBit_Set(int bit, int val); /* #57 */
    extern void* objCreateLight(int obj, int kind); /* #57 */
    u8* state;

    state = ((GameObject*)obj)->extra;
    *(s16*)obj = 0;
    ((GameObject*)obj)->animEventCallback = (void*)gpsh_shrine_SeqFn;
    ((GameObject*)obj)->anim.worldPosX = ((GameObject*)obj)->anim.localPosX;
    ((GameObject*)obj)->anim.worldPosY = ((GameObject*)obj)->anim.localPosY;
    ((GameObject*)obj)->anim.worldPosZ = ((GameObject*)obj)->anim.localPosZ;
    state[0x14] = 0;
    ((GpshShrineFlags*)(state + 0x15))->b80 = 0;
    GameBit_Set(0x129, 1);
    GameBit_Set(0x12b, 0);
    GameBit_Set(0x149, 0);
    GameBit_Set(0x14c, 0);
    GameBit_Set(0x14d, 0);
    GameBit_Set(0x14e, 0);
    GameBit_Set(0x14a, 0);
    GameBit_Set(0x14b, 0);
    ((GameObject*)obj)->unkF4 = 1;
    if (*(void**)state == NULL)
    {
        *(void**)state = objCreateLight(0, 1);
    }
    GameBit_Set(0xea1, 1);
    GameBit_Set(0xefa, 1);
}

/* Trivial 4b 0-arg blr leaves. */
void gpsh_shrine_release(void)
{
}

void gpsh_shrine_initialise(void)
{
}

void gpsh_objcreator_free(void)
{
}

void gpsh_objcreator_hitDetect(void)
{
}

void gpsh_objcreator_release(void)
{
}

void gpsh_objcreator_initialise(void)
{
}

extern void hitDetectFn_80097070(int* obj, f32 e, int a, int b, int c, int d);
extern void Sfx_PlayFromObjectLimited(int obj, int sfx, int v);
extern void* Obj_AllocObjectSetup(int size, int type);
extern f32 lbl_803E504C;
extern f32 lbl_803E5050;
extern f32 lbl_803E5054;
extern s16 lbl_803263B8[];

void gpsh_objcreator_update(int* obj)
{
    extern int* Obj_SetupObject(void* setup, int a, int b, int c, void* d); /* #57 */
    extern u32 GameBit_Get(int bit); /* #57 */
    u8* sub;
    void* setup;

    sub = ((GameObject*)obj)->extra;
    if (GameBit_Get(0x5af) != 0)
    {
        ((GameObject*)obj)->unkF8 = 0;
        ((GpshShrineFlags*)(sub + 5))->b80 = 0;
        *(u8*)((char*)obj + 0x37) = 0xff;
        ((GameObject*)obj)->anim.alpha = 0xff;
    }
    if (((GpshShrineFlags*)(sub + 5))->b80) return;
    if (((GameObject*)obj)->unkF8 == 0)
    {
        if (GameBit_Get(0x148) != 0)
        {
            *(f32*)sub = lbl_803E504C;
            ((GameObject*)obj)->unkF8 = 1;
        }
    }
    if ((u8)Obj_IsLoadingLocked() == 0) return;
    if (*(f32*)sub == lbl_803E5050) return;
    *(f32*)sub = *(f32*)sub - timeDelta;
    hitDetectFn_80097070(obj, lbl_803E5054, 2, 1, 1, 0);
    if (*(f32*)sub <= lbl_803E5050)
    {
        Sfx_PlayFromObjectLimited(0, SFXwp_swtst1_c, 1);
        setup = Obj_AllocObjectSetup(0x24, sub[4] + 0x1f4);
        ((GpshShrineFlags*)(sub + 5))->b80 = 1;
        *(u8*)((char*)setup + 7) = 0xff;
        *(u8*)((char*)setup + 4) = 0x20;
        *(u8*)((char*)setup + 5) = 2;
        ((ObjPlacement*)setup)->posX = ((GameObject*)obj)->anim.localPosX;
        ((ObjPlacement*)setup)->posY = ((GameObject*)obj)->anim.localPosY;
        ((ObjPlacement*)setup)->posZ = ((GameObject*)obj)->anim.localPosZ;
        *(s16*)setup = (s16)(sub[4] + 0x1f4);
        *(u8*)((char*)setup + 0x18) = (u8)((s32) * (s16*)obj >> 8);
        *(s16*)((char*)setup + 0x1a) = lbl_803263B8[sub[4]];
        Obj_SetupObject(setup, 5, ((GameObject*)obj)->anim.mapEventSlot, -1, *(void**)&((GameObject*)obj)->anim.parent);
    }
}

void gpsh_scene_free(void)
{
}

void gpsh_scene_hitDetect(void)
{
}

void gpsh_scene_update(void)
{
}

void gpsh_scene_release(void)
{
}

void gpsh_scene_initialise(void)
{
}

void ecsh_cup_hitDetect(void);

/* 8b "li r3, N; blr" returners. */
int gpsh_objcreator_getExtraSize(void) { return 0x8; }
int gpsh_objcreator_getObjectTypeId(void) { return 0x0; }
int gpsh_scene_getExtraSize(void) { return 0x0; }
int gpsh_scene_getObjectTypeId(void) { return 0x0; }
int ecsh_cup_getExtraSize(void);
int ecsh_cup_getObjectTypeId(void);

/* render-with-objRenderFn_8003b8f4 pattern. */
extern f32 lbl_803E5048;
extern f32 lbl_803E5058;
extern f32 lbl_803E5060;

void gpsh_objcreator_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0) objRenderFn_8003b8f4(lbl_803E5048);
}

void gpsh_scene_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0) objRenderFn_8003b8f4(lbl_803E5058);
}

void ecsh_cup_render(int p1, int p2, int p3, int p4, int p5, s8 visible);

void ecsh_cup_free(int* obj);

void gpsh_scene_init(int* obj, int* def)
{
    *(s16*)obj = (s16)((s32) * (s8*)((char*)def + 0x18) << 8);
    ((GameObject*)obj)->anim.worldPosX = ((GameObject*)obj)->anim.localPosX;
    ((GameObject*)obj)->anim.worldPosY = ((GameObject*)obj)->anim.localPosY;
    ((GameObject*)obj)->anim.worldPosZ = ((GameObject*)obj)->anim.localPosZ;
    *(u8*)&((GameObject*)obj)->anim.resetHitboxMode = (u8)(*(u8*)&((GameObject*)obj)->anim.resetHitboxMode | 8);
}

void gpsh_objcreator_init(int* obj, int* def)
{
    register u32 zero;
    register int* state;
    state = ((GameObject*)obj)->extra;
    *(s16*)obj = (s16)((s32)((GpshObjcreatorObjectDef*)def)->unk1E << 8);
    zero = 0;
    ((GameObject*)obj)->unkF8 = zero;
    ((GpshObjcreatorState*)state)->unk4 = (u8)((GpshObjcreatorObjectDef*)def)->unk1A;
    ((GpshShrineFlags*)((char*)state + 5))->b80 = 0;
    *(u8*)((char*)obj + 0x37) = 0xff;
    ((GameObject*)obj)->anim.alpha = 0xff;
}
