/* DLL 0x0192 — GPS-H shrine objects [801C70F0-801C7724) */
#include "main/obj_placement.h"
#include "main/vecmath_distance_api.h"
#include "main/audio/music_api.h"
#include "main/object_render_legacy.h"
#include "main/object_api.h"
#include "main/vecmath.h"
#include "main/render.h"
#include "main/dll/gpshshrineflags_struct.h"
#include "main/dll/dll_0195_dbshshrine.h"
#include "main/game_object.h"
#include "main/object.h"
#include "main/obj_group.h"
#include "main/frame_timing.h"
#include "main/mapEventTypes.h"
#include "main/objseq.h"
#include "main/screen_transition.h"
#include "main/audio/sfx_ids.h"
#include "main/dll/creator1C4.h"
#include "main/gamebits.h"
#include "main/audio/sfx.h"
#include "main/audio/audio_control_api.h"
#include "main/model_engine.h"
#include "main/model_light.h"
#include "main/map_load.h"
#include "main/pi_dolphin_api.h"
#include "main/sky_api.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/math_api.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/audio/music_trigger_ids.h"
#include "main/gamebit_ids.h"

/* env-effect ids fired when the shrine intro countdown expires (index-style; roles opaque) */
#define GPSH_SHRINE_ENVFX_A 0xcc
#define GPSH_SHRINE_ENVFX_B 0xcd
#define GPSH_SHRINE_ENVFX_C 0x222

extern void gpsh_scene_getExtraSize(void);
extern void ecsh_cup_getExtraSize(void);

extern void gpsh_scene_getObjectTypeId(void);
extern void ecsh_cup_getObjectTypeId(void);

extern void gpsh_scene_free(void);
extern void ecsh_cup_free(void);

extern void gpsh_scene_render(void);
extern void ecsh_cup_render(void);

extern void gpsh_scene_hitDetect(void);
extern void ecsh_cup_hitDetect(void);
extern void DBSH_Symbol_getExtraSize(void);

extern void gpsh_scene_update(void);
extern void ecsh_cup_update(void);
extern void DBSH_Symbol_free(void);

extern void gpsh_scene_init(void);
extern void ecsh_cup_init(void);
extern void DBSH_Symbol_render(void);

extern void gpsh_scene_release(void);
extern void ecsh_cup_release(void);
extern void DBSH_Symbol_update(GameObject *);

extern void gpsh_scene_initialise(void);
extern void ecsh_cup_initialise(void);
extern void DBSH_Symbol_init(void);

#define GPSHSHRINE_OBJGROUP 0xb
#define GPSHSHRINE_MAP_SHRINE 0xb
#define GPSHSHRINE_SPAWNED_OBJGROUP 0x10 /* puzzle-spawned objects, freed on completion */


extern void objParticleFn_80099d84(void* obj, f32 scale, int type, f32 extraScale, void* light);
extern f32 lbl_803E5038;
extern void objSetAnimStateFlags(int* player, int a, int b);
extern f32 lbl_803E5000;
extern f32 lbl_803E5004;
extern f32 lbl_803E5008;
extern f32 lbl_803E500C;
extern f32 gGpShShrinePi;
extern f32 gGpShShrineAngleHalfRange;
extern f32 lbl_803E5018;
extern f32 lbl_803E501C;
extern f32 lbl_803E5020;
extern f32 gGpShShrineAlphaFadeDistance;
extern f32 lbl_803E5028;






extern f32 lbl_803E503C;
extern f32 lbl_803E5040;

void gpsh_shrine_hitDetect(void)
{
}

int gpsh_shrine_getExtraSize(void) { return 0x18; }
int gpsh_shrine_getObjectTypeId(void) { return 0x0; }

void gpsh_shrine_free(int* obj)
{
    void** state = ((GameObject*)obj)->extra;
    void* light = state[0];

    if (light != NULL)
    {
        ModelLightStruct_free((ModelLightStruct*)light);
        state[0] = NULL;
    }
    gameTimerStop();
    ObjGroup_RemoveObject((int)obj, GPSHSHRINE_OBJGROUP);
    Music_Trigger(MUSICTRIG_DIM_Snow, 0);
    Music_Trigger(MUSICTRIG_CC_Visit1, 0);
    Music_Trigger(MUSICTRIG_vfp_walkabout, 0);
    Music_Trigger(MUSICTRIG_krazoa_tunnel_2, 0);
    mainSetBits(GAMEBIT_ECSH_InShrine, 0);
    mainSetBits(GAMEBIT_SHRINE_MUSIC_LOCK, mainGetBit(0xc91) == 0);
}

void gpsh_shrine_render(GameObject *obj, int p2, int p3, int p4, int p5, s8 visible)
{
    void** state = (obj)->extra;

    if (visible == 0)
    {
        void* light = state[0];
        if (light != NULL)
        {
            modelLightStruct_setEnabled((ModelLightStruct*)light, 0, lbl_803E5038);
        }
    }
    else
    {
        void* light = state[0];
        if (light != NULL)
        {
            modelLightStruct_setEnabled((ModelLightStruct*)light, 1, lbl_803E5038);
        }
        ((void (*)(void*, int, int, int, int, f32))objRenderModelAndHitVolumes)(obj, p2, p3, p4, p5, lbl_803E5038);
        objParticleFn_80099d84(obj, lbl_803E5038, 7, *(f32*)&lbl_803E5038, state[0]);
    }
}

typedef struct GpshShrineState
{
    ModelLightStruct* light;
    f32 timer;
    f32 sfxTimer;
    s16 anglePhase[3];
    u8 solvedCount;
    u8 pad13[0x14 - 0x13];
    u8 puzzleState;
    u8 activatedFlag : 1;
    u8 flagRest : 7;
    u8 pad16[0x18 - 0x16];
} GpshShrineState;

STATIC_ASSERT(sizeof(GpshShrineState) == 0x18);
STATIC_ASSERT(offsetof(GpshShrineState, timer) == 0x04);
STATIC_ASSERT(offsetof(GpshShrineState, sfxTimer) == 0x08);
STATIC_ASSERT(offsetof(GpshShrineState, anglePhase) == 0x0C);
STATIC_ASSERT(offsetof(GpshShrineState, solvedCount) == 0x12);
STATIC_ASSERT(offsetof(GpshShrineState, puzzleState) == 0x14);

int GPSH_Shrine_SeqFn(int* obj, int unused, ObjAnimUpdateState* animUpdate)
{
    GpshShrineState* sub;
    GameObject* player;
    int i;
    u8 ev;
    ModelLightStruct* light;

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
                sub->activatedFlag = 1;
                break;
            case 7:
                objSetAnimStateFlags((int*)player, 0x80, 1);
                mainSetBits(0x12b, 1);
                mainSetBits(GAMEBIT_ITEM_Spirit5_Got, 1);
                (*gMapEventInterface)->setMapAct(GPSHSHRINE_MAP_SHRINE, 5);
                break;
            case 14:
                ((GameObject*)obj)->anim.flags |= OBJANIM_FLAG_HIDDEN;
                light = sub->light;
                if (light != NULL)
                {
                    modelLightStruct_setEnabled(light, 0, lbl_803E5038);
                }
                break;
            case 15:
                ((GameObject*)obj)->anim.flags &= ~OBJANIM_FLAG_HIDDEN;
                light = sub->light;
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

void fn_801C70F0(s16* obj)
{
    u8 buf[32];
    u8* def;
    GpshShrineState* sub;
    GameObject* player;
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
        sub->anglePhase[0] = (s16)(sub->anglePhase[0] + (int)(lbl_803E5000 * timeDelta));
        sub->anglePhase[1] = (s16)(sub->anglePhase[1] + (int)(lbl_803E5004 * timeDelta));
        sub->anglePhase[2] = (s16)(sub->anglePhase[2] + (int)(lbl_803E5008 * timeDelta));
        ((GameObject*)obj)->anim.localPosY =
            lbl_803E500C + (((ObjPlacement*)def)->posY
                + mathSinf((gGpShShrinePi * (f32)sub->anglePhase[0]) / gGpShShrineAngleHalfRange));
        c1 = mathSinf((gGpShShrinePi * (f32)sub->anglePhase[1]) / gGpShShrineAngleHalfRange);
        c2 = mathSinf((gGpShShrinePi * (f32)sub->anglePhase[0]) / gGpShShrineAngleHalfRange);
        c2 = c2 + c1;
        ((GameObject*)obj)->anim.rotZ = lbl_803E5018 * c2;
        c1 = mathSinf((gGpShShrinePi * (f32)sub->anglePhase[2]) / gGpShShrineAngleHalfRange);
        c2 = mathSinf((gGpShShrinePi * (f32)sub->anglePhase[0]) / gGpShShrineAngleHalfRange);
        c2 = c2 + c1;
        ((GameObject*)obj)->anim.rotY = lbl_803E5018 * c2;
        ObjAnim_AdvanceCurrentMove((int)obj, lbl_803E501C, timeDelta,
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
            if (dist <= gGpShShrineAlphaFadeDistance)
            {
                ((GameObject*)obj)->anim.alpha = (u8)(int)(lbl_803E5028 * (dist / gGpShShrineAlphaFadeDistance));
            }
            else
            {
                ((GameObject*)obj)->anim.alpha = 0xff;
            }
        }
    }
}

void gpsh_shrine_update(GameObject *obj)
{
    extern int objGetAnimStateFlags(int obj, int flag);
    extern void SCGameBitLatch_UpdateInverted(int state, int a, int b, int c, int d, int e);
    extern void SCGameBitLatch_Update(int state, int a, int b, int c, int d, int e);
    extern void fn_801C70F0(int obj);
    int count;
    int data = *(int*)&(obj)->extra;
    GameObject* player = Obj_GetPlayerObject();
    u8 b149;
    u8 b14c;
    u8 b14d;
    u8 b14e;
    u8 b14a;
    u8 b14b;
    int* objs;
    f32 idleSfxTimer;
    f32 k;

    count = 0;
    if (player != NULL)
    {
        b149 = mainGetBit(0x149);
        b14c = mainGetBit(0x14c);
        b14d = mainGetBit(0x14d);
        b14e = mainGetBit(0x14e);
        b14a = mainGetBit(0x14a);
        b14b = mainGetBit(0x14b);
        if (b149 == 0 || b14c == 0 || b14d == 0 || b14e == 0 || b14a == 0 || b14b == 0)
        {
            if (!((GpshShrineFlags*)((char*)data + 0x15))->b40 && b149 != 0)
            {
                ((GpshShrineFlags*)((char*)data + 0x15))->b40 = 1;
                Sfx_PlayFromObject(0, SFXTRIG_menuups16k);
            }
            else if (!((GpshShrineFlags*)((char*)data + 0x15))->b20 && b14c != 0)
            {
                ((GpshShrineFlags*)((char*)data + 0x15))->b20 = 1;
                Sfx_PlayFromObject(0, SFXTRIG_menuups16k);
            }
            else if (!((GpshShrineFlags*)((char*)data + 0x15))->b10 && b14d != 0)
            {
                ((GpshShrineFlags*)((char*)data + 0x15))->b10 = 1;
                Sfx_PlayFromObject(0, SFXTRIG_menuups16k);
            }
            else if (!((GpshShrineFlags*)((char*)data + 0x15))->b08 && b14e != 0)
            {
                ((GpshShrineFlags*)((char*)data + 0x15))->b08 = 1;
                Sfx_PlayFromObject(0, SFXTRIG_menuups16k);
            }
            else if (!((GpshShrineFlags*)((char*)data + 0x15))->b04 && b14a != 0)
            {
                ((GpshShrineFlags*)((char*)data + 0x15))->b04 = 1;
                Sfx_PlayFromObject(0, SFXTRIG_menuups16k);
            }
            else if (!((GpshShrineFlags*)((char*)data + 0x15))->b02 && b14b != 0)
            {
                ((GpshShrineFlags*)((char*)data + 0x15))->b02 = 1;
                Sfx_PlayFromObject(0, SFXTRIG_menuups16k);
            }
        }
        if ((obj)->unkF4 != 0)
        {
            (obj)->unkF4 -= 1;
            if ((obj)->unkF4 == 0)
            {
                skyFn_80088c94(7, 1);
                getEnvfxActInt((int)obj, (int)player, GPSH_SHRINE_ENVFX_A, 0);
                getEnvfxActInt((int)obj, (int)player, GPSH_SHRINE_ENVFX_B, 0);
                getEnvfxActInt((int)obj, (int)player, GPSH_SHRINE_ENVFX_C, 0);
            }
        }
        fn_801C70F0((int)obj);
        unlockLevel(mapGetDirIdx(0x22), 1, 0);
        SCGameBitLatch_Update(data + 0x13, 2, -1, -1, 0xdd2, 0xb);
        SCGameBitLatch_UpdateInverted(data + 0x13, 1, -1, -1, 0xcbb, 8);
        SCGameBitLatch_Update(data + 0x13, 4, -1, -1, 0xcbb, 0xc4);
        if (((GpshShrineState*)data)->timer > (k = lbl_803E503C))
        {
            ((GpshShrineState*)data)->timer -= timeDelta;
            if (((GpshShrineState*)data)->timer <= k)
            {
                ((GpshShrineState*)data)->timer = k;
            }
        }
        else
        {
            switch (((GpshShrineState*)data)->puzzleState)
            {
            case 0:
                (obj)->anim.flags &= ~OBJANIM_FLAG_HIDDEN;
                idleSfxTimer = ((GpshShrineState*)data)->sfxTimer - timeDelta;
                ((GpshShrineState*)data)->sfxTimer = idleSfxTimer;
                if (idleSfxTimer <= k)
                {
                    Sfx_PlayFromObject((int)obj, SFXTRIG_spirit_voice);
                    ((GpshShrineState*)data)->sfxTimer = (f32)(int)
                    randomGetRange(500, 1000);
                }
                if (*(u8*)&(obj)->anim.resetHitboxMode & INTERACT_FLAG_ACTIVATED)
                {
                    ((GpshShrineState*)data)->puzzleState = 5;
                    mainSetBits(GAMEBIT_WM_EnteredKrazoaTest1_0129, 0);
                    mainSetBits(0x5af, 0);
                    mainSetBits(GAMEBIT_GPSH_TestKnowledgeRunning, 1);
                    (*gObjectTriggerInterface)->runSequence(0, (void*)obj, -1);
                    Music_Trigger(MUSICTRIG_DIM_Snow, 1);
                }
                break;
            case 5:
                ((GpshShrineState*)data)->timer = lbl_803E5040;
                (*gScreenTransitionInterface)->step(0x1e, 1);
                ((GpshShrineState*)data)->puzzleState = 1;
                (obj)->anim.flags |= OBJANIM_FLAG_HIDDEN;
                break;
            case 1:
                if (((GpshShrineFlags*)((char*)data + 0x15))->b80 == 1)
                {
                    mainSetBits(0x148, 1);
                    ((GpshShrineState*)data)->puzzleState = 2;
                    gameTimerInit(0x1d, 0x4e);
                    timerSetToCountUp();
                }
                break;
            case 2:
                ((GpshShrineState*)data)->solvedCount = 0;
                if (mainGetBit(0x149))
                {
                    ((GpshShrineState*)data)->solvedCount += 1;
                }
                if (mainGetBit(0x14b))
                {
                    ((GpshShrineState*)data)->solvedCount += 1;
                }
                if (mainGetBit(0x14e))
                {
                    ((GpshShrineState*)data)->solvedCount += 1;
                }
                if (mainGetBit(0x14d))
                {
                    ((GpshShrineState*)data)->solvedCount += 1;
                }
                if (mainGetBit(0x14c))
                {
                    ((GpshShrineState*)data)->solvedCount += 1;
                }
                if (mainGetBit(0x14a))
                {
                    ((GpshShrineState*)data)->solvedCount += 1;
                }
                if (((GpshShrineState*)data)->solvedCount == 6)
                {
                    ((GpshShrineState*)data)->puzzleState = 6;
                    gameTimerStop();
                    mainSetBits(GAMEBIT_GPSH_TestKnowledgeRunning, 0);
                    ((GpshShrineState*)data)->timer = lbl_803E5040;
                    (*gScreenTransitionInterface)->start(0x1e, 1);
                    Sfx_PlayFromObject(0, SFXTRIG_mpick1_b);
                }
                else if (isGameTimerDisabled())
                {
                    ((GpshShrineState*)data)->puzzleState = 7;
                    objs = (int*)ObjGroup_GetObjects(GPSHSHRINE_SPAWNED_OBJGROUP, &count);
                    for (; count != 0; count--)
                    {
                        Obj_FreeObject((GameObject*)objs[count - 1]);
                    }
                    ((GpshShrineState*)data)->timer = lbl_803E5040;
                    (*gScreenTransitionInterface)->start(0x1e, 1);
                }
                else
                {
                    ((GpshShrineState*)data)->solvedCount = 0;
                }
                break;
            case 7:
                ((GpshShrineState*)data)->puzzleState = 4;
                mainSetBits(GAMEBIT_GPSH_TestKnowledgeRunning, 0);
                mainSetBits(0xe37, 1);
                break;
            case 6:
                ((GpshShrineState*)data)->puzzleState = 3;
                break;
            case 3:
                if (objGetAnimStateFlags((int)player, 0x80))
                {
                    mainSetBits(GAMEBIT_WM_EnteredKrazoaTest1_0129, 1);
                    ((GpshShrineState*)data)->puzzleState = 4;
                }
                else
                {
                    audioStopByMask(3);
                    (*gObjectTriggerInterface)->runSequence(1, (void*)obj, -1);
                    ((GpshShrineState*)data)->puzzleState = 4;
                    mainSetBits(GAMEBIT_WC_ObjGroups, 0);
                    (*gMapEventInterface)->setObjGroupStatus(0xd, 0, 1);
                    (*gMapEventInterface)->setObjGroupStatus(0xd, 1, 1);
                    (*gMapEventInterface)->setObjGroupStatus(0xd, 5, 1);
                    (*gMapEventInterface)->setObjGroupStatus(0xd, 10, 1);
                    (*gMapEventInterface)->setObjGroupStatus(0xd, GPSHSHRINE_OBJGROUP, 1);
                    mainSetBits(0xc91, 1);
                    mainSetBits(GAMEBIT_WC_MagicCaveRelated0E05, 0);
                }
                break;
            case 4:
                ((GpshShrineState*)data)->puzzleState = 0;
                ((GpshShrineFlags*)((char*)data + 0x15))->b80 = 0;
                mainSetBits(GAMEBIT_GPSH_TestKnowledgeRunning, 0);
                mainSetBits(GAMEBIT_WM_EnteredKrazoaTest1_0129, 1);
                mainSetBits(0x149, 0);
                mainSetBits(0x14c, 0);
                mainSetBits(0x14d, 0);
                mainSetBits(0x14e, 0);
                mainSetBits(0x14a, 0);
                mainSetBits(0x14b, 0);
                mainSetBits(0x14b, 0);
                mainSetBits(0x5af, 1);
                mainSetBits(0x148, 0);
                mainSetBits(0xe37, 0);
                mainSetBits(0xe3a, 0);
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
    u8* state;

    state = ((GameObject*)obj)->extra;
    ((GameObject*)obj)->anim.rotX = 0;
    ((GameObject*)obj)->animEventCallback = GPSH_Shrine_SeqFn;
    ((GameObject*)obj)->anim.worldPosX = ((GameObject*)obj)->anim.localPosX;
    ((GameObject*)obj)->anim.worldPosY = ((GameObject*)obj)->anim.localPosY;
    ((GameObject*)obj)->anim.worldPosZ = ((GameObject*)obj)->anim.localPosZ;
    state[0x14] = 0;
    ((GpshShrineFlags*)(state + 0x15))->b80 = 0;
    mainSetBits(GAMEBIT_WM_EnteredKrazoaTest1_0129, 1);
    mainSetBits(0x12b, 0);
    mainSetBits(0x149, 0);
    mainSetBits(0x14c, 0);
    mainSetBits(0x14d, 0);
    mainSetBits(0x14e, 0);
    mainSetBits(0x14a, 0);
    mainSetBits(0x14b, 0);
    ((GameObject*)obj)->unkF4 = 1;
    if (*(void**)state == NULL)
    {
        *(void**)state = objCreateLight(0, 1);
    }
    mainSetBits(GAMEBIT_WC_EnteredShrine, 1);
    mainSetBits(GAMEBIT_ECSH_InShrine, 1);
}

void gpsh_shrine_release(void)
{
}

void gpsh_shrine_initialise(void)
{
}

/* descriptor/ptr table auto 0x803263b8-0x803264e0 */
u32 lbl_803263B8[3] = { 0x00280028, 0x00300030, 0x002d002d };
u32 gGPSH_ObjCreatorObjDescriptor[15] = { 0x00000000, 0x00000000, 0x00000000, 0x00090000, (u32)gpsh_objcreator_initialise, (u32)gpsh_objcreator_release, 0x00000000, (u32)gpsh_objcreator_init, (u32)gpsh_objcreator_update, (u32)gpsh_objcreator_hitDetect, (u32)gpsh_objcreator_render, (u32)gpsh_objcreator_free, (u32)gpsh_objcreator_getObjectTypeId, (u32)gpsh_objcreator_getExtraSize, 0x00000000 };
u32 gGPSH_SceneObjDescriptor[14] = { 0x00000000, 0x00000000, 0x00000000, 0x00090000, (u32)gpsh_scene_initialise, (u32)gpsh_scene_release, 0x00000000, (u32)gpsh_scene_init, (u32)gpsh_scene_update, (u32)gpsh_scene_hitDetect, (u32)gpsh_scene_render, (u32)gpsh_scene_free, (u32)gpsh_scene_getObjectTypeId, (u32)gpsh_scene_getExtraSize };
u32 gECSH_CupObjDescriptor[14] = { 0x00000000, 0x00000000, 0x00000000, 0x00090000, (u32)ecsh_cup_initialise, (u32)ecsh_cup_release, 0x00000000, (u32)ecsh_cup_init, (u32)ecsh_cup_update, (u32)ecsh_cup_hitDetect, (u32)ecsh_cup_render, (u32)ecsh_cup_free, (u32)ecsh_cup_getObjectTypeId, (u32)ecsh_cup_getExtraSize };
u32 gDBSH_ShrineObjDescriptor[14] = { 0x00000000, 0x00000000, 0x00000000, 0x00090000, (u32)dbsh_shrine_initialise, (u32)dbsh_shrine_release, 0x00000000, (u32)dbsh_shrine_init, (u32)dbsh_shrine_update, (u32)dbsh_shrine_hitDetect, (u32)dbsh_shrine_render, (u32)dbsh_shrine_free, (u32)dbsh_shrine_getObjectTypeId, (u32)dbsh_shrine_getExtraSize };
u32 gDBSH_SymbolObjDescriptor[14] = { 0x00000000, 0x00000000, 0x00000000, 0x00090000, 0x00000000, 0x00000000, 0x00000000, (u32)DBSH_Symbol_init, (u32)DBSH_Symbol_update, 0x00000000, (u32)DBSH_Symbol_render, (u32)DBSH_Symbol_free, 0x00000000, (u32)DBSH_Symbol_getExtraSize };
