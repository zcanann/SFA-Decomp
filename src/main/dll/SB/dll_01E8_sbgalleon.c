/*
 * SB_Galleon (DLL 0x1E8) - General Scales' flying galleon, the centrepiece
 * of the game's prologue. ("SB" is the retail map name "ShipBattle"; the
 * ROM ships this level as the map dir ShipBattle/ and every handler here is
 * a retail SB_* object.) Krystal, riding her Cloudrunner (SB_Cloudrunner),
 * chases the galleon through the sky and shoots out its deck guns
 * (SB_ShipGun) and propellers (SB_Propeller); she then lands on the deck for
 * the game's first on-foot section, talks to the caged baby Cloudrunner Kyte
 * (SB_CageKyte), and goes after a golden key behind the deck door
 * (SB_DeckDoor). Returning to Kyte, the closing cutscene cuts in before the
 * key can be used: Scales storms out of the cabin, grabs Krystal by the
 * throat and hurls her overboard - her Cloudrunner catches her and carries
 * her on to Krazoa Palace, where the key actually fits a door.
 *
 * This object is both the galleon and the driver of that closing cutscene's
 * camera/encounter state machine: SB_Galleon_animEventCallback consumes the
 * sequence events (damage-phase toggle, water spray, sky lighting, the
 * on-screen gameText subtitle) while SB_Galleon_update steps the camera
 * state and hands per-phase work to the DBprotection.c handlers
 * (fn_801DFA28, DBprotection_updateShield) that run on the same object.
 *
 * The per-object extra block is SBGalleonState (sbgalleon_state.h), shared
 * with those DBprotection handlers. Handlers register through the standard
 * ObjectDescriptor slots (init/update/hitDetect/render/free/getExtraSize).
 */
#include "main/dll/sbshipheadstate_struct.h"
#include "main/dll/sbpropellerstate_struct.h"
#include "main/audio/sfx_ids.h"
#include "main/effect_interfaces.h"
#include "main/mapEventTypes.h"
#include "main/objseq.h"
#include "main/objlib.h"
#include "main/dll/DB/DBstealerworm.h"
#include "main/dll/DB/sbgalleon_state.h"
#include "main/gamebits.h"
#include "main/texture.h"
#include "main/dll/SB/dll_01E9_sbpropeller.h"

#define SBGALLEON_OBJGROUP 3

STATIC_ASSERT(sizeof(SBPropellerState) == 0x10);

STATIC_ASSERT(sizeof(SBShipHeadState) == 0x10);

extern u32 getLActions();
extern void DBprotection_storeHomePosition(int obj);
extern void Sfx_PlayFromObject(int obj, int sfxId);
extern void Music_Trigger(int id, int arg);
extern const f32 lbl_803E56CC;
extern void Sfx_StopFromObject(int obj, int sfxId);

extern void gameTextSetColor(u8 r, u8 g, u8 b, u8 a);
extern void gameTextShow(int a);
extern f32 lbl_803E57F4;
extern f32 lbl_803E57F8;
extern f32 lbl_803E5790;
extern f32 timeDelta;
extern void setDrawLights(int v);
extern void skySetOverrideLightColorEnabled(u8 enabled);
extern void skySetOverrideLightColor(u8 red, u8 green, u8 blue);
extern void skyFn_80089710(int flags, int enabled, int startComplete);
extern f32 fn_8008ED88(void);
extern void skyFn_800895e0(int idx, int r, int g, int b, int a, int b2);
extern void fn_80089510(int idx, int r, int g, int b);
extern void fn_80089578(int idx, int r, int g, int b);
extern void skySetOverrideLightDirectionEnabled(u8 enabled);
extern void skySetOverrideLightDirection(f32 x, f32 y, f32 z, f32 intensity);
extern void skyFn_800894a8(int flags, f32 x, f32 y, f32 z);
extern int* Obj_GetActiveModel(int obj);
extern int ObjModel_GetRenderOp(int model, int idx);
extern f32 gSbGalleonSkyLightVecs[12];
extern u8 lbl_803DC078[4];
extern u8 gSbGalleonSkyColorBEnd[4];
extern u8 gSbGalleonSkyColorAStart[4];
extern u8 gSbGalleonSkyColorAEnd[4];
extern u8 gSbGalleonSkyColorCStart[4];
extern u8 gSbGalleonSkyColorCEnd[4];
extern f32 lbl_803DDC24;
extern f32 lbl_803DDC28;
extern u8 lbl_803DDC2D;
extern u8 gSbGalleonSkyColorC[3];
extern u8 gSbGalleonSkyColorB[3];
extern u8 gSbGalleonSkyColorA[3];
extern f32 lbl_803E57A4;
extern f32 lbl_803E57B4;
extern f32 lbl_803E57E0;
extern f32 lbl_803E57F0;
extern f32 lbl_803E5724;
extern u8 framesThisStep;
extern u32 gSbGalleon;
extern void objRenderFn_8003b8f4(int obj, int p2, int p3, int p4, int p5, f32 scale);
extern f32 lbl_803E57FC;
extern f32 lbl_803E5800;
extern f32 lbl_803E5804;
extern f32 lbl_803E5808;
extern f32 lbl_803E5738;
extern f32 lbl_803E56F0;
extern f32 lbl_803E56C8;
extern int mapGetDirIdx(int idx);
extern int lockLevel(s32 val, int idx);
extern void fn_801DFA28(int obj);
extern void DBprotection_updateShield(int obj);
extern void SCGameBitLatch_Update(u8* latch, int mask, int a, int b, int bit, int c);
extern void objSetSlot(void* obj, int slot);
extern int gSbGalleonSkyTexA;
extern int gSbGalleonSkyTexB;
extern f32 lbl_803E580C;

/* Sequence-event opcodes consumed by SB_Galleon_animEventCallback. */
enum SbGalleonSeqEvent
{
    SBGALLEON_SEQEV_TOGGLE_DAMAGE_PHASE_1 = 2,  /* toggle damagePhase to 1 */
    SBGALLEON_SEQEV_SPRAY_ON = 3,
    SBGALLEON_SEQEV_SPRAY_OFF = 4,
    SBGALLEON_SEQEV_TOGGLE_DAMAGE_PHASE_2 = 5,  /* toggle damagePhase to 2 */
    SBGALLEON_SEQEV_SFX_ON = 6,
    SBGALLEON_SEQEV_SFX_OFF = 7,
    SBGALLEON_SEQEV_TOGGLE_DAMAGE_PHASE_8 = 8,  /* toggle damagePhase to 8 */
    SBGALLEON_SEQEV_SKY_ON = 9,
    SBGALLEON_SEQEV_SKY_OFF = 10,
    SBGALLEON_SEQEV_SPLASH_SFX = 0xb,
    SBGALLEON_SEQEV_MUSIC = 0xc,
    SBGALLEON_SEQEV_TEXT = 0xd
};

/* SBGalleonState.cameraState - protection-spirit encounter state machine
   stepped in SB_Galleon_update. */
enum SbGalleonCameraState
{
    SBGALLEON_CAM_APPROACH = 0,
    SBGALLEON_CAM_START_INTRO = 1,
    SBGALLEON_CAM_SHIELD = 2,
    SBGALLEON_CAM_END = 3,
    SBGALLEON_CAM_DONE = 4
};

#define SBGALLEON_FX_SPRAY 0x7aa         /* water-spray particle fx */
#define SBGALLEON_FX_WANDER 0xa3         /* wandering particle fx */
#define SBGALLEON_ROMLIST_LINKED 0xf7    /* romlist type of the linked spray actor */
#define SBGALLEON_GAMETEXT 0x4b1         /* on-screen gameText id */
#define SBGALLEON_GAMEBIT_INTRO 0x75     /* gates the intro map-event setup */
#define SBGALLEON_GAMEBIT_DEFEATED 0xac8 /* set on free */
#define SBGALLEON_SFX_SPLASH 0x143
#define SBGALLEON_SFX_SPRAY 0x2c6
#define SBGALLEON_MUSIC_INTRO 0xa3
#define SBGALLEON_MAP_PALACE 0xb         /* map-event/dir id this boss locks */
#define SBGALLEON_SKY_LIGHT_SLOT 7       /* sky override light slot fn_801E1588 drives */

int SB_Galleon_animEventCallback(int obj, int unused, ObjAnimUpdateState* animUpdate)
{
    SBGalleonState* state = (SBGalleonState*)((GameObject*)obj)->extra;
    int i;
    ((GameObject*)obj)->anim.mapEventSlot = -1;
    fn_801E1588(obj, (int)state);
    {
        f32 z = lbl_803E56CC;
        state->moveScale = lbl_803E56CC;
        state->swayX = z;
        state->swayY = z;
        state->swayZ = z;
    }
    animUpdate->freeCallback = (ObjAnimSequenceFreeCallback)DBprotection_storeHomePosition;
    for (i = 0; i < animUpdate->eventCount; i++)
    {
        switch (animUpdate->eventIds[i])
        {
        case SBGALLEON_SEQEV_TOGGLE_DAMAGE_PHASE_1:
            if (state->damagePhase == 1)
            {
                state->damagePhase = 0;
            }
            else
            {
                state->damagePhase = 1;
            }
            break;
        case SBGALLEON_SEQEV_SPRAY_ON:
            {
                int start;
                int end;
                int* arr = ObjList_GetObjects(&start, &end);
                for (i = start; i < end; i++)
                {
                    if (((GameObject*)arr[i])->anim.seqId == SBGALLEON_ROMLIST_LINKED)
                    {
                        state->linkedActor = arr[i];
                        i = end;
                    }
                }
                state->sprayActive = 1;
                break;
            }
        case SBGALLEON_SEQEV_SPRAY_OFF:
            state->sprayActive = 0;
            break;
        case SBGALLEON_SEQEV_TOGGLE_DAMAGE_PHASE_2:
            if (state->damagePhase == 2)
            {
                state->damagePhase = 0;
            }
            else
            {
                state->damagePhase = 2;
            }
            break;
        case SBGALLEON_SEQEV_SFX_ON:
            Sfx_PlayFromObject(obj, SBGALLEON_SFX_SPLASH);
            break;
        case SBGALLEON_SEQEV_SFX_OFF:
            Sfx_StopFromObject(obj, SBGALLEON_SFX_SPLASH);
            break;
        case SBGALLEON_SEQEV_TOGGLE_DAMAGE_PHASE_8:
            if (state->damagePhase == 8)
            {
                state->damagePhase = 1;
            }
            else
            {
                state->damagePhase = 8;
            }
            break;
        case SBGALLEON_SEQEV_SKY_ON:
            state->skyFlag = 1;
            break;
        case SBGALLEON_SEQEV_SKY_OFF:
            state->skyFlag = 0;
            break;
        case SBGALLEON_SEQEV_SPLASH_SFX:
            Sfx_PlayFromObject(fn_801E2570(), SBGALLEON_SFX_SPRAY);
            break;
        case SBGALLEON_SEQEV_MUSIC:
            state->musicIdB = SBGALLEON_MUSIC_INTRO;
            Music_Trigger(state->musicIdB, 1);
            Music_Trigger(state->musicIdA, 0);
            break;
        case SBGALLEON_SEQEV_TEXT:
            state->textTimer = lbl_803E57F8;
            state->textRising = 1;
            state->textAlpha = lbl_803E56CC;
            break;
        }
    }
    if (state->textTimer >= lbl_803E56CC)
    {
        state->textTimer = state->textTimer - timeDelta;
        if (state->textTimer < lbl_803E56CC)
        {
            state->textTimer = lbl_803E56CC;
            state->textRising = 0;
        }
    }
    if (state->textRising != 0)
    {
        state->textAlpha = lbl_803E5790 * timeDelta + state->textAlpha;
    }
    else
    {
        state->textAlpha = -(lbl_803E5790 * timeDelta - state->textAlpha);
    }
    {
        f32 v = state->textAlpha;
        state->textAlpha =
            (v < lbl_803E56CC) ? lbl_803E56CC : ((v > lbl_803E57F4) ? lbl_803E57F4 : v);
    }
    if (state->textAlpha > lbl_803E56CC)
    {
        gameTextSetColor(0xff, 0xff, 0xff, state->textAlpha);
        gameTextShow(SBGALLEON_GAMETEXT);
    }
    state->posX = ((GameObject*)obj)->anim.localPosX;
    state->posY = ((GameObject*)obj)->anim.localPosY;
    state->posZ = ((GameObject*)obj)->anim.localPosZ;
    animUpdate->hitVolumePair = animUpdate->activeHitVolumePair;
    animUpdate->sequenceEventActive = 0;
    return 0;
}

typedef struct
{
    f32 x, y, z;
} SkyVec3;

void fn_801E1588(int obj, int state)
{
    int* model;
    int i;
    int rop;
    SkyVec3 a;
    SkyVec3 b;
    SkyVec3 c;
    SkyVec3 d;
    a = ((SkyVec3*)gSbGalleonSkyLightVecs)[0];
    b = ((SkyVec3*)gSbGalleonSkyLightVecs)[1];
    c = ((SkyVec3*)gSbGalleonSkyLightVecs)[2];
    d = ((SkyVec3*)gSbGalleonSkyLightVecs)[3];
    setDrawLights(0);
    skySetOverrideLightColorEnabled(1);
    skySetOverrideLightColor(0x29, 0x4b, 0xa9);
    skyFn_80089710(SBGALLEON_SKY_LIGHT_SLOT, 1, 0);
    if (fn_8008ED88() > *(f32*)&lbl_803E56CC)
    {
        lbl_803DDC24 = lbl_803E57A4;
        lbl_803DDC28 = lbl_803E57A4;
    }
    {
        f32 t = -(lbl_803E57B4 * timeDelta - lbl_803DDC28);
        lbl_803DDC28 = t;
        if (t < lbl_803E56CC)
        {
            lbl_803DDC28 = lbl_803E56CC;
        }
    }
    {
        int v0 = gSbGalleonSkyColorAStart[0];
        gSbGalleonSkyColorA[0] = v0 + lbl_803DDC28 * (f32)(gSbGalleonSkyColorAEnd[0] - v0);
    }
    {
        int v1 = gSbGalleonSkyColorAStart[1];
        gSbGalleonSkyColorA[1] = v1 + lbl_803DDC28 * (f32)(gSbGalleonSkyColorAEnd[1] - v1);
    }
    {
        int v2 = gSbGalleonSkyColorAStart[2];
        gSbGalleonSkyColorA[2] = v2 + lbl_803DDC28 * (f32)(gSbGalleonSkyColorAEnd[2] - v2);
    }
    skyFn_800895e0(SBGALLEON_SKY_LIGHT_SLOT, *(volatile u8*)&gSbGalleonSkyColorA[0], *(volatile u8*)&gSbGalleonSkyColorA[1], *(volatile u8*)&gSbGalleonSkyColorA[2], 0x40, 0x40);
    {
        int v0 = lbl_803DC078[0];
        gSbGalleonSkyColorB[0] = v0 + lbl_803DDC28 * (f32)(gSbGalleonSkyColorBEnd[0] - v0);
    }
    {
        int v1 = lbl_803DC078[1];
        gSbGalleonSkyColorB[1] = v1 + lbl_803DDC28 * (f32)(gSbGalleonSkyColorBEnd[1] - v1);
    }
    {
        int v2 = lbl_803DC078[2];
        gSbGalleonSkyColorB[2] = v2 + lbl_803DDC28 * (f32)(gSbGalleonSkyColorBEnd[2] - v2);
    }
    fn_80089510(SBGALLEON_SKY_LIGHT_SLOT, *(volatile u8*)&gSbGalleonSkyColorB[0], *(volatile u8*)&gSbGalleonSkyColorB[1], *(volatile u8*)&gSbGalleonSkyColorB[2]);
    {
        int v0 = gSbGalleonSkyColorCStart[0];
        gSbGalleonSkyColorC[0] = v0 + lbl_803DDC28 * (f32)(gSbGalleonSkyColorCEnd[0] - v0);
    }
    {
        int v1 = gSbGalleonSkyColorCStart[1];
        gSbGalleonSkyColorC[1] = v1 + lbl_803DDC28 * (f32)(gSbGalleonSkyColorCEnd[1] - v1);
    }
    {
        int v2 = gSbGalleonSkyColorCStart[2];
        gSbGalleonSkyColorC[2] = v2 + lbl_803DDC28 * (f32)(gSbGalleonSkyColorCEnd[2] - v2);
    }
    fn_80089578(SBGALLEON_SKY_LIGHT_SLOT, *(volatile u8*)&gSbGalleonSkyColorC[0], *(volatile u8*)&gSbGalleonSkyColorC[1], *(volatile u8*)&gSbGalleonSkyColorC[2]);
    lbl_803DDC2D = lbl_803DDC28 * lbl_803E57E0 + lbl_803E57F0;
    skySetOverrideLightDirectionEnabled(1);
    skySetOverrideLightDirection(lbl_803DDC28 * (d.x - c.x) + c.x,
                                 lbl_803DDC28 * (d.y - c.y) + c.y,
                                 lbl_803DDC28 * (d.z - c.z) + c.z, lbl_803E5724);
    if (((SBGalleonState*)state)->skyFlag == 0)
    {
        skyFn_800894a8(SBGALLEON_SKY_LIGHT_SLOT, a.x, a.y, a.z);
    }
    else
    {
        skyFn_800894a8(SBGALLEON_SKY_LIGHT_SLOT, b.x, b.y, b.z);
    }
    model = Obj_GetActiveModel(obj);
    i = 0;
    {
        f32 scale = lbl_803E57F4;
        for (; i < *(u8*)(*model + 0xf8); i++)
        {
            rop = ObjModel_GetRenderOp(*model, i);
            if (*(u8*)(rop + 0x29) == 1)
            {
                *(u8*)(rop + 0xc) = scale * lbl_803DDC28;
            }
        }
    }
}

void SB_Galleon_release(void)
{
}

void SB_Galleon_initialise(void)
{
}

int SB_Galleon_getExtraSize(void) { return sizeof(SBGalleonState); }
int SB_Galleon_getObjectTypeId(void) { return 0x0; }

u32 getSbGalleon(void) { return gSbGalleon; }

u8 SB_Galleon_getDamagePhase(int* obj) { return ((SBGalleonState*)((GameObject*)obj)->extra)->damagePhase; }

s32 SB_Galleon_getStage(int* obj) { return ((SBGalleonState*)((GameObject*)obj)->extra)->stage; }

/*
 * Galleon DLL vtable slot SB_GALLEON_VTBL_ON_GUN_DESTROYED: a destructible part
 * (gun / propeller blade / ship head, via their *_update) reports its destruction
 * here. Advances the fight -- bumps `stage`, or `phaseCounter` while phase == 1.
 * (Was mis-named SB_Galleon_setScale; it performs no scaling.)
 */
int SB_Galleon_onPartDestroyed(GameObject* obj)
{
    SBGalleonState* state = (SBGalleonState*)obj->extra;
    int phase = state->phase;
    if (phase != 1)
    {
        if (phase >= 2)
        {
            Sfx_PlayFromObject((int)obj, SFXen_diallp_c);
        }
        state->stage += 1;
        return 1;
    }
    {
        int pattern;
        if ((pattern = (s8)state->flightPattern) == 0 || pattern == 1 || pattern == 2)
        {
            state->phaseCounter += 1;
            return 1;
        }
    }
    return 0;
}

void SB_Galleon_render(GameObject* obj, int p2, int p3, int p4, int p5, s8 visible)
{
    SBGalleonState* state = (SBGalleonState*)obj->extra;
    struct
    {
        u8 pad[6];
        u16 mode;
        f32 unused;
        f32 a;
        f32 b;
        f32 c;
    } stk;
    if (visible != 0)
    {
        if ((s8)state->cameraState < 2)
        {
            stk.mode = state->wanderA;
            stk.c = lbl_803E57FC;
            stk.b = lbl_803E5800;
            stk.a = lbl_803E5804;
            (*gPartfxInterface)->spawnObject((void*)obj, SBGALLEON_FX_WANDER, stk.pad, 2, -1, NULL);
            stk.mode = state->wanderB;
            stk.a = lbl_803E5808;
            (*gPartfxInterface)->spawnObject((void*)obj, SBGALLEON_FX_WANDER, stk.pad, 2, -1, NULL);
        }
        ((void (*)(int, int, int, int, int, f32))objRenderFn_8003b8f4)((int)obj, p2, p3, p4, p5, lbl_803E57A4);
    }
}

void SB_Galleon_hitDetect(GameObject* obj)
{
    SBGalleonState* state = (SBGalleonState*)obj->extra;
    u8 i;
    struct
    {
        u8 pad[6];
        u16 mode;
        f32 a;
        f32 b;
        f32 c;
        f32 d;
    } stk;
    if (state->sprayActive != 0 && *(void**)&state->linkedActor != NULL)
    {
        stk.a = lbl_803E5738;
        stk.mode = 0xc0a;
        stk.b = lbl_803E56CC;
        stk.c = lbl_803E56F0;
        stk.d = lbl_803E56C8;
        for (i = 0; i < framesThisStep; i++)
        {
            (*gPartfxInterface)->spawnObject(
                (void*)state->linkedActor, SBGALLEON_FX_SPRAY, stk.pad, 2, -1, 0);
        }
    }
}

void SB_Galleon_update(GameObject* obj)
{
    SBGalleonState* state = (SBGalleonState*)obj->extra;
    obj->anim.mapEventSlot = state->mapLayer;
    fn_801E1588((int)obj, (int)state);
    if (GameBit_Get(SBGALLEON_GAMEBIT_INTRO) == 0)
    {
        (*gMapEventInterface)->setMapAct(SBGALLEON_MAP_PALACE, 1);
        (*gMapEventInterface)->setObjGroupStatus(SBGALLEON_MAP_PALACE, 0, 1);
        (*gMapEventInterface)->setObjGroupStatus(SBGALLEON_MAP_PALACE, 1, 1);
        (*gMapEventInterface)->setObjGroupStatus(SBGALLEON_MAP_PALACE, 5, 1);
        lockLevel(mapGetDirIdx(SBGALLEON_MAP_PALACE), 0);
        if ((u8)(*gMapEventInterface)->getObjGroupStatus(*(u8*)((char*)obj + 0x34), 1) == 0)
        {
            (*gMapEventInterface)->setObjGroupStatus(*(u8*)((char*)obj + 0x34), 1, 1);
        }
        obj->unkF4 = 0;
    }
    else
    {
        if ((state->musicLatch == 0) && ((s8)state->cameraState > 0))
        {
            state->musicLatch = 1;
        }
        switch ((s8)state->cameraState)
        {
        case SBGALLEON_CAM_APPROACH:
            fn_801DFA28((int)obj);
            break;
        case SBGALLEON_CAM_START_INTRO:
            (*gObjectTriggerInterface)->runSequence(3, obj, -1);
            state->cameraState = SBGALLEON_CAM_SHIELD;
            break;
        case SBGALLEON_CAM_SHIELD:
            DBprotection_updateShield((int)obj);
            break;
        case SBGALLEON_CAM_END:
            (*gMapEventInterface)->setMapAct(SBGALLEON_MAP_PALACE, 1);
            obj->anim.mapEventSlot = -1;
            (*gObjectTriggerInterface)->runSequence(2, obj, -1);
            state->cameraState = SBGALLEON_CAM_DONE;
            break;
        }
        SCGameBitLatch_Update(state->gameBitLatch, 1, -1, -1, 0xa71, 0xa4);
    }
}

void SB_Galleon_init(GameObject* obj)
{
    SBGalleonState* state = (SBGalleonState*)obj->extra;
    ObjHitsPriorityState* hitState;
    gSbGalleon = (u32)obj;
    ObjGroup_AddObject((u32)obj, SBGALLEON_OBJGROUP);
    objSetSlot(obj, 0x5a);
    obj->animEventCallback = SB_Galleon_animEventCallback;
    state->posX = obj->anim.localPosX;
    state->posY = obj->anim.localPosY;
    state->posZ = obj->anim.localPosZ;
    state->sweepDir = 1;
    state->timer26 = 0xf0;
    state->phaseTimer = 0xf0;
    state->damagePhase = 0;
    state->headingLatch = 200;
    state->envfxActs[2] = 0x89;
    state->envfxActs[3] = 0x95;
    state->envfxActs[4] = 0x86;
    state->envfxActs[5] = 0x88;
    state->envfxActs[0] = 0x87;
    state->envfxActs[1] = 0x97;
    state->mapLayer = obj->anim.mapEventSlot;
    obj->anim.rotX = 0x4000;
    obj->anim.rotY = 0;
    obj->anim.rotZ = 0;
    gSbGalleonSkyTexA = (int)textureLoadAsset(0x16d);
    gSbGalleonSkyTexB = (int)textureLoadAsset(0x89);
    state->unk84 = 100;
    (*gMapEventInterface)->setMapAct(obj->anim.mapEventSlot, 1);
    getLActions(obj, obj, 0x58, 0, 0, 0);
    state->wanderTimerA = lbl_803E56CC;
    state->wanderTimerB = lbl_803E580C;
    hitState = (ObjHitsPriorityState*)obj->anim.hitReactState;
    hitState->flags |= 0x1800;
    setDrawLights(0);
    state->musicIdA = 0x92;
    state->musicIdB = 0x91;
    Music_Trigger(state->musicIdB, 1);
}

void SB_Galleon_free(GameObject* obj, int p2)
{
    SBGalleonState* state = (SBGalleonState*)obj->extra;
    if ((void*)gSbGalleonSkyTexA != NULL)
    {
        textureFree((void*)gSbGalleonSkyTexA);
        gSbGalleonSkyTexA = 0;
    }
    if ((void*)gSbGalleonSkyTexB != NULL)
    {
        textureFree((void*)gSbGalleonSkyTexB);
        gSbGalleonSkyTexB = 0;
    }
    ObjGroup_RemoveObject((u32)obj, SBGALLEON_OBJGROUP);
    if (state->musicLatch != 0 && p2 == 0)
    {
        state->musicLatch = 0;
    }
    gSbGalleon = 0;
    Music_Trigger(state->musicIdB, 0);
    Music_Trigger(state->musicIdA, 0);
    GameBit_Set(SBGALLEON_GAMEBIT_DEFEATED, 1);
}

int SB_Galleon_getPhase(int* obj)
{
    int phase;
    SBGalleonState* state = (SBGalleonState*)((GameObject*)obj)->extra;
    int pattern;
    phase = (u8)state->phase;
    if ((s8)phase == 0)
    {
        if (state->timer26 > 0) return -2;
    }
    if ((s8)phase == 1)
    {
        if ((pattern = (s8)state->flightPattern) == 2 || pattern == 3 || pattern == 5) return -1;
    }
    return (s8)phase;
}

int SB_Galleon_func0E(int* obj)
{
    SBGalleonState* state = (SBGalleonState*)((GameObject*)obj)->extra;
    if ((s8)(u8)state->phase == 1)
    {
        int wrapped;
        if ((s8)(u8)state->phaseCounter >= 5) wrapped = (s8)(u8)state->phaseCounter - 5;
        else wrapped = (s8)(u8)state->phaseCounter;
        return (6 - wrapped) * 0x5a;
    }
    return 0x640;
}
