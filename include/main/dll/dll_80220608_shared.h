#ifndef MAIN_DLL_DLL_80220608_SHARED_H
#define MAIN_DLL_DLL_80220608_SHARED_H

#include "ghidra_import.h"
#include "main/audio/sfx.h"
#include "main/camera_interface.h"
#include "main/effect_interfaces.h"
#include "main/dll_000A_expgfx.h"
#include "main/gamebits.h"
#include "main/game_ui_interface.h"
#include "main/mapEventTypes.h"
#include "main/obj_placement.h"
#include "main/objanim.h"
#include "main/objanim_internal.h"
#include "main/objfx.h"
#include "main/objHitReact.h"
#include "main/objseq.h"
#include "main/objanim_update.h"
#include "main/objtexture.h"
#include "main/resource.h"
#include "main/sky_interface.h"
#include "main/dll/path_control_interface.h"
#include "main/dll/curve_walker.h"
#include "main/dll/rom_curve_interface.h"
#include "main/screen_transition.h"
#include "main/dll/cnthitobjec_state.h"

/* Pattern wrappers. */
extern u8 framesThisStep;
extern int lbl_803DC380;
extern f32 lbl_803E6BB0;
extern void mm_free(void *ptr);
extern void Obj_FreeObject(int obj);
extern f32 lbl_803E6BC8;
extern void cloudClearOverridePosition(int obj);
extern void objRenderFn_8003b8f4(int obj, int p2, int p3, int p4, int p5, f32 scale);
extern void ObjGroup_RemoveObject(int obj, int group);
extern void ObjGroup_AddObject(int obj, int group);
extern f32 lbl_803E6C20;
extern int lbl_803DC398;
extern void storeZeroToFloatParam(void *timer);
extern void s16toFloat(void *timer, int duration);
extern void gunpowderbarrel_clearHeldState(int obj);
extern f32 lbl_803E6CE0;
extern void dll_2E_func06(int obj, int state, int flags);
extern int seqFn_800394a0(void);
extern void fn_8003AAE0(int obj, int seq, int hitId, int p4, int p5);
extern f32 lbl_803E6D38;
extern f32 lbl_803E6D54;
extern f32 lbl_803E6DA0;
extern f32 lbl_803E6DE0;
extern f32 lbl_803E6DF0;
extern f32 lbl_803E6E00;
extern f32 lbl_803E6DFC;
extern f32 lbl_803E6E10;
extern f32 lbl_803E6E14;
extern f32 lbl_803E6E18;
extern f32 lbl_803E6E20;
extern f32 lbl_803E6E24;
extern f32 timeDelta;
extern int isGameTimerDisabled(void);
extern int randomGetRange(int min, int max);
extern void ObjHitbox_SetStateIndex(int obj, int hitbox, int stateIndex);
extern int Obj_GetActiveModel(int obj);
extern void ObjModel_SetPostRenderCallback(int model, void *callback);
extern void objRenderFn_80041018(int obj);
extern void postRenderSetAlphaBlendState(void);


typedef struct DrEnergyDiscState {
    u8 activated : 1;
} DrEnergyDiscState;




typedef struct DrLightBeaFlags {
    u8 bit80 : 1;
    u8 bit40 : 1;
    u8 pad : 6;
} DrLightBeaFlags;









typedef struct DrBarrelGrFlags {
    u8 bit80 : 1;
    u8 bit40 : 1;
    u8 pad : 6;
} DrBarrelGrFlags;



extern void dll_2E_func03(int obj, int p2);
extern void characterDoEyeAnims(int obj, int p2);
extern void buttonDisable(int a, int b);
extern ObjHitReactEntry gEarthWalkerHitReactEntries[];
extern f32 gEarthWalkerMoveStartProgress;
extern f32 gEarthWalkerAnimAdvanceRate;

typedef struct EarthWalkerState {
    u8 pad000[0x600];
    u8 animPhase;
    u8 pad601[0x610 - 0x601];
    u8 hitTriggerId;
    u8 moveLibFlags611; /* 0x611: moveLib flag byte, OR-set with bit 2 at init */
    u8 pad612[0x624 - 0x612];
    u8 eyeAnimState[0x654 - 0x624];
    f32 hitReactStepScale;
    u8 interactionState;
    u8 flags;
    u8 hitReactState;
    u8 encounterType;
    s8 lastTriggeredState;
    u8 pad65D[0x660 - 0x65D];
} EarthWalkerState;

STATIC_ASSERT(sizeof(EarthWalkerState) == 0x660);
STATIC_ASSERT(offsetof(EarthWalkerState, animPhase) == 0x600);
STATIC_ASSERT(offsetof(EarthWalkerState, hitTriggerId) == 0x610);
STATIC_ASSERT(offsetof(EarthWalkerState, eyeAnimState) == 0x624);
STATIC_ASSERT(offsetof(EarthWalkerState, hitReactStepScale) == 0x654);
STATIC_ASSERT(offsetof(EarthWalkerState, interactionState) == 0x658);
STATIC_ASSERT(offsetof(EarthWalkerState, flags) == 0x659);
STATIC_ASSERT(offsetof(EarthWalkerState, hitReactState) == 0x65A);
STATIC_ASSERT(offsetof(EarthWalkerState, encounterType) == 0x65B);
STATIC_ASSERT(offsetof(EarthWalkerState, lastTriggeredState) == 0x65C);

typedef struct EarthWalkerObject {
    union {
        ObjAnimComponent anim;
        struct {
            s16 facingAngle;
            u8 pad02[0xA0 - 0x02];
            s16 currentMove;
            u8 padA2[0xAC - 0xA2];
            s8 mapEventId;
            u8 padAD[0xAF - 0xAD];
            u8 statusFlags;
        };
    };
    u8 padB0[0xB8 - sizeof(ObjAnimComponent)];
    EarthWalkerState *state;
    void *animEventCallback;
} EarthWalkerObject;

STATIC_ASSERT(offsetof(EarthWalkerObject, anim) == 0x00);
STATIC_ASSERT(offsetof(EarthWalkerObject, facingAngle) == 0x00);
STATIC_ASSERT(offsetof(EarthWalkerObject, currentMove) == offsetof(ObjAnimComponent, currentMove));
STATIC_ASSERT(offsetof(EarthWalkerObject, mapEventId) == offsetof(ObjAnimComponent, mapEventSlot));
STATIC_ASSERT(offsetof(EarthWalkerObject, statusFlags) == offsetof(ObjAnimComponent, resetHitboxFlags));
STATIC_ASSERT(offsetof(EarthWalkerObject, state) == 0xB8);
STATIC_ASSERT(offsetof(EarthWalkerObject, animEventCallback) == 0xBC);


extern f32 gBouncyCrateTriggerSearchRadius;
extern f32 lbl_803E6D24;
extern f32 gBouncyCrateNearDistance;
extern f32 lbl_803E6D2C;
extern f32 gBouncyCrateFarDistance;
extern f32 lbl_803E6D34;
extern f32 gBouncyCrateGravity;
extern f32 gBouncyCrateRestitution;


typedef struct {
    u8 phase : 3;
    u8 sfxActive : 1;
    u8 pad : 4;
} PushBlockFlags;

typedef struct WCLevelContInterface WCLevelContInterface;

typedef struct WCLevelContInterface {
    u8 pad00[0x20];
    void (*tileAToWorldPos)(int obj, int tileX, int tileY, f32 *outX, f32 *outZ,
                            WCLevelContInterface *iface);
    void (*worldPosToTileA)(int obj, f32 x, f32 z, s16 *outTileX, s16 *outTileY,
                            WCLevelContInterface *iface);
    void (*setTileA)(int value, int tileX, int tileY, WCLevelContInterface *iface);
    int (*getTileA)(int tileX, int tileY, WCLevelContInterface *iface);
    void (*getInitialTileXYA)(int value, s16 *outTileX, s16 *outTileY,
                              WCLevelContInterface *iface);
    void (*getSolvedTileXYA)(int value, s16 *outTileX, s16 *outTileY,
                             WCLevelContInterface *iface);
    u8 (*traceMoveA)(int obj, int tileX, int tileY, f32 *outX, f32 *outZ, int dx,
                      int dy, WCLevelContInterface *iface);
    void (*tileBToWorldPos)(int obj, int tileX, int tileY, f32 *outX, f32 *outZ,
                            WCLevelContInterface *iface);
    void (*worldPosToTileB)(int obj, f32 x, f32 z, s16 *outTileX, s16 *outTileY,
                            WCLevelContInterface *iface);
    void (*setTileB)(int value, int tileX, int tileY, WCLevelContInterface *iface);
    int (*getTileB)(int tileX, int tileY, WCLevelContInterface *iface);
    void (*getInitialTileXYB)(int value, s16 *outTileX, s16 *outTileY,
                              WCLevelContInterface *iface);
    void (*getSolvedTileXYB)(int value, s16 *outTileX, s16 *outTileY,
                             WCLevelContInterface *iface);
    u8 (*traceMoveB)(int obj, int tileX, int tileY, f32 *outX, f32 *outZ, int dx,
                      int dy, WCLevelContInterface *iface);
} WCLevelContInterface;

STATIC_ASSERT(offsetof(WCLevelContInterface, tileAToWorldPos) == 0x20);
STATIC_ASSERT(offsetof(WCLevelContInterface, worldPosToTileA) == 0x24);
STATIC_ASSERT(offsetof(WCLevelContInterface, setTileA) == 0x28);
STATIC_ASSERT(offsetof(WCLevelContInterface, getTileA) == 0x2C);
STATIC_ASSERT(offsetof(WCLevelContInterface, getInitialTileXYA) == 0x30);
STATIC_ASSERT(offsetof(WCLevelContInterface, getSolvedTileXYA) == 0x34);
STATIC_ASSERT(offsetof(WCLevelContInterface, traceMoveA) == 0x38);
STATIC_ASSERT(offsetof(WCLevelContInterface, tileBToWorldPos) == 0x3C);
STATIC_ASSERT(offsetof(WCLevelContInterface, worldPosToTileB) == 0x40);
STATIC_ASSERT(offsetof(WCLevelContInterface, setTileB) == 0x44);
STATIC_ASSERT(offsetof(WCLevelContInterface, getTileB) == 0x48);
STATIC_ASSERT(offsetof(WCLevelContInterface, getInitialTileXYB) == 0x4C);
STATIC_ASSERT(offsetof(WCLevelContInterface, getSolvedTileXYB) == 0x50);
STATIC_ASSERT(offsetof(WCLevelContInterface, traceMoveB) == 0x54);

extern u8 fn_80296414(int player, int obj, int dir);
extern int wcblock_isPlayerAwayFromStoredCell(int obj, int state, int player);
extern int Obj_GetPlayerObject(void);
extern int ObjGroup_FindNearestObject(int group, int obj, f32 *out);
extern void objMove(int obj, f32 vx, f32 vy, f32 vz);
extern f32 sqrtf(f32 x);
extern f32 mathSinf(f32 x);
extern void objfx_spawnBoxBurst(void *obj, u8 idx, u8 kind, u8 mode, u8 chance, void *origin,
                                int flags, f32 f8val, f32 mulX, f32 mulY, f32 mulZ);
extern void ObjHits_DisableObject(u32 obj);
extern void ObjHits_EnableObject(u32 obj);
extern int gameBitIncrement(int id);
extern f32 gWcPushBlockControllerSearchRange;
extern f32 lbl_803E6D5C;
extern f32 lbl_803E6D60;
extern f32 lbl_803E6D64;
extern f32 lbl_803E6D68;
extern f32 lbl_803E6D6C;
extern f32 lbl_803E6D70;
extern f32 gWcPushBlockSlideSfxMaxVolume;
extern f32 lbl_803E6D78;
extern f32 gWcPushBlockMaxSlideSpeed;
extern f32 gWcPushBlockSlideAccel;
extern f32 gWcPushBlockMinSlideSpeed;
extern f32 gWcPushBlockBobAngleSpeed;
extern f32 gWcPushBlockBobAmplitude;
extern f32 gWcPushBlockPi;
extern f32 gWcPushBlockAngleScale;

extern u8 lbl_8032B0C8[][8];
extern u8 lbl_8032B088[][8];
extern u8 lbl_8032B048[][8];
extern u8 lbl_8032B008[][8];
extern u8 lbl_803AD298[][8];
extern u8 lbl_803AD2D8[][8];
extern f32 lbl_803E6DB0;
extern f32 lbl_803E6DB4;
extern f32 lbl_803E6DB8;
extern f32 lbl_803E6DBC;
extern f32 lbl_803E6DC0;
extern f32 lbl_803E6DD0;
extern f32 lbl_803E6DD4;
extern f32 lbl_803E6DD8;
extern void mapGetBlockOriginForPos(f32 x, f32 y, f32 z, f32 *outX, f32 *outZ);
extern void gameTimerStop(void);
extern u8 gameTimerIsRunning(void);
extern void Music_Trigger(int id, int p2);
extern void SCGameBitLatch_Update(int state, int a, int b, int c, int d, int e);
extern const f32 lbl_803E6DA8;
typedef struct WcLevelControlState WcLevelControlState;
extern void wcpushblock_updateLevelControlState(int obj, WcLevelControlState *state);
extern void fn_802251B4(int obj, WcLevelControlState *state);
extern void getEnvfxActImmediately(int a, int b, int c, int d);
extern void skyFn_80088e54(int a, f32 b);
extern int wcpushblock_levelControlTriggerCallback(int obj, int unused, ObjAnimUpdateState *animUpdate);
extern void *memcpy(void *dst, const void *src, u32 n);



#pragma dont_inline on
#pragma dont_inline reset
typedef struct {
    u8 b80 : 1;
    u8 b40 : 1;
    u8 b20 : 1;
    u8 b18 : 2;
    u8 b07 : 3;
} WclevelcontFlags;

/* WcLevelControlState.completionFlags: one-shot latches for each WC sub-puzzle.
 * 0x1/0x2 are transient (trigger-fired / event-active); the rest mirror gamebits. */
#define WCLEVELCTL_FLAG_TRIGGERED    0x1   /* trigger callback fired this frame */
#define WCLEVELCTL_FLAG_EVENT_ACTIVE 0x2   /* event running; update pass skips */
#define WCLEVELCTL_FLAG_PUZZLE_A     0x4   /* gamebit 0x7f9 solved */
#define WCLEVELCTL_FLAG_PUZZLE_B     0x8   /* gamebit 0x7fa solved */
#define WCLEVELCTL_FLAG_TILE_A       0x10  /* gamebit 0x812: tile-A set solved */
#define WCLEVELCTL_FLAG_TILE_B       0x20  /* gamebit 0x813: tile-B set solved */
#define WCLEVELCTL_FLAG_TREX         0x40  /* gamebit 0x2a5: trex timer challenge */
#define WCLEVELCTL_FLAG_SWITCHES     0x80  /* gamebit 0x205: three-switch puzzle */
#define WCLEVELCTL_FLAG_FINAL        0x100 /* gamebit 0xbcf: final event */
#define WCLEVELCTL_FLAG_EXTRA        0x200 /* gamebit 0xcac */

typedef struct WcLevelControlState {
    f32 eventTimer;
    f32 tileBResetTimer;
    f32 tileAResetTimer;
    u8 mode;
    u8 previousMode;
    u8 pad0E[0x10 - 0x0E];
    u32 gameBitLatch;
    WclevelcontFlags dialogueFlags;
    u8 pad15;
    u16 thorntailMusicId;
    u16 ambientMusicId;
    u16 completionFlags;
} WcLevelControlState;

STATIC_ASSERT(sizeof(WclevelcontFlags) == 1);
STATIC_ASSERT(sizeof(WcLevelControlState) == 0x1C);
STATIC_ASSERT(offsetof(WcLevelControlState, eventTimer) == 0x00);
STATIC_ASSERT(offsetof(WcLevelControlState, tileBResetTimer) == 0x04);
STATIC_ASSERT(offsetof(WcLevelControlState, tileAResetTimer) == 0x08);
STATIC_ASSERT(offsetof(WcLevelControlState, mode) == 0x0C);
STATIC_ASSERT(offsetof(WcLevelControlState, previousMode) == 0x0D);
STATIC_ASSERT(offsetof(WcLevelControlState, gameBitLatch) == 0x10);
STATIC_ASSERT(offsetof(WcLevelControlState, dialogueFlags) == 0x14);
STATIC_ASSERT(offsetof(WcLevelControlState, thorntailMusicId) == 0x16);
STATIC_ASSERT(offsetof(WcLevelControlState, ambientMusicId) == 0x18);
STATIC_ASSERT(offsetof(WcLevelControlState, completionFlags) == 0x1A);

extern void gameTimerInit(int a, int b);
extern void timerSetToCountUp(void);
extern f32 gWcPushBlockTileResetTime;










extern int getTrickyObject(void);
extern int fn_80138F84(int tricky);
extern int trickyFn_80138f14(int tricky);
extern f32 lbl_803E6DE4;
extern f32 lbl_803E6DE8;



extern f32 lbl_803E6DF4;
extern f32 lbl_803E6DF8;



extern void fn_80137948(void *fmt, ...);
extern char sWCPressuresActivateFormat[];
extern f32 lbl_803E6E04;



extern int objPosToMapBlockIdx(f32 x, f32 y, f32 z);
extern u8 *mapGetBlock(int idx);
extern int fn_8006070C(int block, int index);
extern void mapTextureOverrideSetValue(int a, int b, int c);
extern f32 lbl_803E6E58;
#pragma dont_inline on
#pragma dont_inline reset
extern s16 gWcTempleDiaGameBitsA;
extern s16 gWcTempleDiaGameBitsB;
extern f32 gWcTempleDiaTargetSpeedTableA[];
extern f32 gWcTempleDiaTargetSpeedTableB[];
extern f32 gWcTempleDiaSpeedLerpRate;
int wctempledia_interactCallback(int obj, int p2, ObjAnimUpdateState *animUpdate);
extern f32 lbl_803E6E5C;
extern f32 lbl_803E6E60;
extern f32 lbl_803E6E64;
extern f32 lbl_803E6E68;

extern f32 lbl_803E6E90;
#pragma dont_inline on
#pragma dont_inline reset

extern int ObjModel_GetCurrentVertexCoords(int model, int idx);
extern int ObjModel_GetBaseVertexCoords(int model, int idx);
extern void ObjHits_DisableObject(u32 obj);
extern int wctemplebri_interactCallback(int obj, int p2, ObjAnimUpdateState *animUpdate);
extern f32 lbl_803E6E70;
extern f32 lbl_803E6E74;
extern f32 lbl_803E6E78;
extern f32 lbl_803E6E7C;

extern f32 PSVECDistance(void *a, void *b);
extern f32 lbl_803E6E94;


extern f32 lbl_803E6E98;
extern f32 lbl_803E6E2C;
extern f32 lbl_803E72E8;
extern void ModelLightStruct_free(void *light);
extern void queueGlowRender(void *light);
extern int gWaterFlowPhaseDriver;
extern f32 gWaterFlowIdlePhase;
extern f32 gWaterFlowFlowPhase;
extern f32 lbl_803E72B0;


extern int fn_80065640(void);
extern void fn_80065574(int a, int b, int c);
extern f32 lbl_803E6E9C;
extern f32 lbl_803E6EA0;
extern f32 lbl_803E6EA4;
extern f32 lbl_803E6EA8;
extern f32 lbl_803E6EAC;
extern f32 lbl_803E6EB0;
extern f32 lbl_803E6EB4;
extern f32 lbl_803E6EB8;
extern f32 lbl_803E6EBC;


extern f32 lbl_803E6E28;
extern f32 lbl_803E6E30;
extern f32 lbl_803E6E34;
extern void modelLightStruct_updateGlowAlpha(void *light);

extern f32 lbl_803E6E3C;
extern f32 lbl_803E6E40;
extern void *objCreateLight(int obj, int kind);
extern void modelLightStruct_setLightKind(void *light, int v);
extern void modelLightStruct_setupGlow(void *light, u16 a, u8 b, u8 c, u8 d, u8 e, f32 f);
extern void modelLightStruct_setGlowProjectionRadius(void *light, f32 v);


extern int fn_802969F0(int player);
extern f32 Camera_GetFovY(void);
extern void modelLightStruct_setEnabled(void *light, int flag, f32 val);
extern f32 lbl_803E6E38;


extern f32 gWaterFlowScaleDivisor;
extern void waterflowwe_calcCurrentVector(int obj, f32 *vx, f32 *vz);
extern int getAngle(f32 dx, f32 dz);
extern f32 gWaterFlowIdlePhaseRate;
extern f32 gWaterFlowFlowPhaseRate;

int suntemple_interactCallback(int obj, int p2, ObjAnimUpdateState *animUpdate);

extern f32 lbl_802C25D8[];
extern int getCurMapLayer(void);

typedef struct { f32 x, y, z; } SunVec3;



extern void buttonDisable(int a, int b);




extern void objMove(int obj, f32 vx, f32 vy, f32 vz);
extern int lbl_803DDD90;
extern int lbl_803DDD94;
extern f32 lbl_803E7118;
extern f32 lbl_803E711C;
extern f32 lbl_803E7120;
extern f32 lbl_803E7124;






extern f32 lbl_803E7138;
extern const f32 lbl_803E713C;




typedef void ModelLight;
typedef struct PointLightVec { f32 x, y, z; } PointLightVec;

#define MODEL_LIGHT_KIND_POINT 2
#define MODEL_LIGHT_KIND_DIRECTIONAL 4
#define MODEL_LIGHT_KIND_PROJECTED 8

#define LGT_POINTLIGHT_GROUP 0x35

extern f32 lbl_802C25F8[];
extern f32 lbl_803E7230;
extern f32 lbl_803E7234;
extern f32 lbl_803E7240;
extern void ModelLightStruct_free(ModelLight *light);
extern void modelLightStruct_setEnabled(ModelLight *light, int flag, f32 val);
extern void queueGlowRender(ModelLight *light);
extern void getAmbientColor(int id, u8 *r, u8 *g, u8 *b);
extern void modelLightStruct_setDiffuseColor(ModelLight *light, u8 r, u8 g, u8 b, int a);
extern void modelLightStruct_setDiffuseTargetColor(ModelLight *light, u8 r, u8 g, u8 b, int a);
extern void modelLightStruct_updateGlowAlpha(ModelLight *light);
extern ModelLight *objCreateLight(int obj, int kind);
extern void modelLightStruct_setLightKind(ModelLight *light, int v);
extern void objSetEventName(ModelLight *light, int name);
extern void modelLightStruct_setPosition(ModelLight *light, f32 x, f32 y, f32 z);
extern void modelLightStruct_setDistanceAttenuation(ModelLight *light, f32 near, f32 far);
extern void modelLightStruct_setSpotAttenuation(ModelLight *light, f32 v, int x);
extern void modelLightStruct_startColorFade(ModelLight *light, int a, s16 b);
extern void modelLightStruct_setDirection(ModelLight *light, f32 x, f32 y, f32 z);
extern void Obj_SetActiveModelIndex(int obj, int index);
extern void modelLightStruct_setupGlow(ModelLight *light, u16 a, u8 b, u8 c, u8 d, u8 e, f32 f);
extern void modelLightStruct_setGlowProjectionRadius(ModelLight *light, f32 v);
extern void modelLightStruct_setAffectsAabbLightSelection(ModelLight *light, int v);
extern void modelLightStruct_setSelectionPriority(ModelLight *light, u8 v);


#pragma dont_inline on
#pragma dont_inline reset







extern f32 lbl_802C2608[];
extern f32 lbl_803E7250;
extern f32 lbl_803E7254;
extern struct DirectionalLightObjDescriptorLayout gDirectionalLightObjDescriptor;
extern int getButtonsJustPressed(int controller);
extern void fn_80137948(void *fmt, ...);









extern f32 lbl_802C2618[];
extern f32 lbl_803E7270;
extern f32 lbl_803E7274;
extern f32 lbl_803E7260;
extern void textureFree(void *tex);
extern void *textureLoadAsset(int id);
extern void modelLightStruct_setProjectedLightChannelPreference(ModelLight *light, int v);
extern void modelLightStruct_setProjectionTexture(ModelLight *light, void *tex);
extern void modelLightStruct_setupOrthoProjection(ModelLight *light, f32 a, f32 b, f32 c, f32 d, f32 e, f32 f);
extern void modelLightStruct_setupPerspectiveProjection(ModelLight *light, f32 a, f32 b);
extern void modelLightStruct_setProjectionTevModes(ModelLight *light, int a, int b);
extern void modelLightStruct_setProjectionNearZ(ModelLight *light, f32 v);
extern void modelLightStruct_setProjectionFarZ(ModelLight *light, f32 v);







extern int *ObjGroup_GetObjects(int group, int *count);
extern f32 Vec_distance(int a, int b);





typedef struct TimerFlags {
    u8 expired : 1;
    u8 manual : 1;
    u8 flag20 : 1;
    u8 pad : 5;
} TimerFlags;

extern f32 lbl_803E7408;
extern f32 lbl_803E7418;
extern f32 lbl_803E7424;
extern void modelLightStruct_freeSlot(int p);
extern void gameTimerStop(void);
extern int fn_80080150(int state);
extern void gameTimerInit(int a, int b);
extern void timerSetToCountUp(void);










extern int timerCountDown(void *timer);
extern int modelLightStruct_createPointLight(int obj, int a, int b, int c, int d);
extern f32 lbl_803DC418;
extern f32 lbl_803DC41C;
extern f32 lbl_803E741C;
extern f32 lbl_803E7420;


extern void set_hudNumber_803db278(int n);







typedef struct VortexFlags {
    u8 active : 1;
    u8 pad : 7;
} VortexFlags;

typedef struct VortexState {
    f32 alpha;
    f32 particleTimer;
    f32 alphaScale[3];
    f32 radiusScale[3];
    s16 angles[3];
    VortexFlags flags;
    u8 pad27;
} VortexState;

typedef struct VortexSetup {
    ObjPlacement base;
    u8 pad18[2];
    s16 radiusParam;
    s16 reverseTextureScroll;
    s16 invertGameBit;
    s16 activeGameBit;
    u8 pad22[0x24 - 0x22];
} VortexSetup;

STATIC_ASSERT(sizeof(VortexState) == 0x28);
STATIC_ASSERT(offsetof(VortexState, alphaScale) == 0x08);
STATIC_ASSERT(offsetof(VortexState, radiusScale) == 0x14);
STATIC_ASSERT(offsetof(VortexState, angles) == 0x20);
STATIC_ASSERT(offsetof(VortexState, flags) == 0x26);
STATIC_ASSERT(sizeof(VortexSetup) == 0x24);
STATIC_ASSERT(offsetof(VortexSetup, radiusParam) == 0x1a);
STATIC_ASSERT(offsetof(VortexSetup, reverseTextureScroll) == 0x1c);
STATIC_ASSERT(offsetof(VortexSetup, invertGameBit) == 0x1e);
STATIC_ASSERT(offsetof(VortexSetup, activeGameBit) == 0x20);

extern f32 lbl_803E73E0;
extern const f32 lbl_803E73D0;
extern f32 lbl_803E73D4;
extern f32 lbl_803E73D8;
extern f32 gVortexRadiusParamScale;
extern f32 lbl_803E73E4;
extern f32 lbl_803E73E8;
extern f32 lbl_803E73EC;
extern double lbl_803E73F0;
extern double lbl_803E73F8;
extern f32 gVortexAlphaFadeSpeed;




extern s16 gVortexAngleSpeed83D[4];
extern s16 gVortexAngleSpeedDefault[4];
extern s16 gVortexAngleSpeed835[2];
extern s16 gVortexRotZTable[2];
extern f32 gVortexScaleParams[];
extern f32 gVortexRadiusScaleInit[2];
extern f32 gVortexAlphaScaleInit835[2];
extern f32 gVortexAlphaScaleInit838[2];
extern f32 lbl_803E7404;
extern int getHudHiddenFrameCount(void);




extern int modelLightStruct_getActiveState(void *light);
extern f32 lbl_803E70B0;






typedef struct RingFlags {
    u8 bit80 : 1;
    u8 bit40 : 1;
    u8 bit20 : 1;
    u8 bit10 : 1;
    u8 pad : 4;
} RingFlags;

typedef struct RingState {
    u8 mode;
    u8 route;
    u16 linkId;
    f32 pullHeight;
    f32 origX;
    f32 origY;
    f32 arwingYOffset;
    RingFlags flags;
    u8 phase;
    u8 pad16[2];
    f32 pullTimer;
    u8 pad1C[4];
    void *light;
} RingState;

STATIC_ASSERT(sizeof(RingFlags) == 0x1);
STATIC_ASSERT(sizeof(RingState) == 0x24);
STATIC_ASSERT(offsetof(RingState, route) == 0x01);
STATIC_ASSERT(offsetof(RingState, linkId) == 0x02);
STATIC_ASSERT(offsetof(RingState, pullHeight) == 0x04);
STATIC_ASSERT(offsetof(RingState, origX) == 0x08);
STATIC_ASSERT(offsetof(RingState, origY) == 0x0C);
STATIC_ASSERT(offsetof(RingState, arwingYOffset) == 0x10);
STATIC_ASSERT(offsetof(RingState, flags) == 0x14);
STATIC_ASSERT(offsetof(RingState, phase) == 0x15);
STATIC_ASSERT(offsetof(RingState, pullTimer) == 0x18);
STATIC_ASSERT(offsetof(RingState, light) == 0x20);

/*
 * Placement/setup record the map loader hands to ring_init/ring_update.
 * Embeds the common ObjPlacement head, then the ring's class-specific
 * fields (setup+0x18..+0x20) read in ring_init and ring_update.
 */
typedef struct RingPlacement {
    ObjPlacement base;     /* 0x00: common placement head */
    s8 modeFlag;           /* 0x18 */
    u8 route;              /* 0x19 */
    s16 linkId;            /* 0x1A */
    s16 pullHeight;        /* 0x1C */
    u8 pad1E[2];           /* 0x1E */
    s16 activateBit;       /* 0x20 */
} RingPlacement;

STATIC_ASSERT(offsetof(RingPlacement, modeFlag) == 0x18);
STATIC_ASSERT(offsetof(RingPlacement, route) == 0x19);
STATIC_ASSERT(offsetof(RingPlacement, linkId) == 0x1A);
STATIC_ASSERT(offsetof(RingPlacement, pullHeight) == 0x1C);
STATIC_ASSERT(offsetof(RingPlacement, activateBit) == 0x20);

extern f32 lbl_803E70C4;
extern f32 lbl_803E70D8;

typedef struct CntHitFlags {
    u8 disabled : 1;
    u8 pad : 7;
} CntHitFlags;

extern f32 lbl_803E7430;
extern void spawnExplosion(int obj, f32 v, int a, int b, int c, int d, int e, int f, int g);
extern void ObjHits_DisableObject(u32 obj);
extern void ObjHits_EnableObject(u32 obj);
extern void ObjHitbox_SetSphereRadius(int obj, int radius);





extern int lbl_8032BEF8[];
extern u8 lbl_803DC42C;
extern int lbl_803DC428;
extern void ObjHits_ClearSourceMask(int obj, int sourceMask);
extern int arrayIndexOf(int array, int count, int value);
extern int ObjHits_GetPriorityHit(int obj, int *outHitObject, int *outSphereIndex,
                                  u32 *outHitVolume);
extern void Obj_SetModelColorFadeRecursive(int obj, int r, int g, int b, int a, int frames);








extern void objfx_spawnMaskedHitEffect(int obj, int a, int b, f32 c, int d, int e);
extern void hitDetectFn_80097070(int obj, int a, int b, f32 c, int d, int e);
extern void objfx_spawnBoxBurst(void *obj, u8 idx, u8 kind, u8 mode, u8 chance, void *origin,
                                int flags, f32 f8val, f32 mulX, f32 mulY, f32 mulZ);
extern void objfx_spawnDirectionalBurst(int obj, int a, int b, int c, f32 e, f32 f, int g, int h, int i);
extern void objfx_spawnArcedBurst(int obj, int enabled, f32 radius, int particleKind,
                                   int particleId, int lifetime, f32 scaleX, f32 scaleY,
                                   f32 scaleZ, void *args, int arg9);



extern f32 lbl_803E7338;
extern f32 lbl_803E733C;
extern f32 lbl_803E7340;
extern int ObjHits_PollPriorityHitEffectWithCooldown(int obj, u32 hitFxMode, u32 colorR,
                                                     u32 colorG, u32 colorB, u32 sfxId,
                                                     float *cooldown);




extern void *lbl_803DDD98;
extern f32 lbl_803DDD9C;
extern f32 lbl_803DDDA0;
extern f32 lbl_803E7288;
extern f32 lbl_803E728C;
extern f32 lbl_803E7290;
extern f32 lbl_803E7294;
extern f32 lbl_803E7298;









extern f32 lbl_803E7078;
extern f32 lbl_803E7150;









extern f32 lbl_803E7218;
extern f32 lbl_803E7100;
extern f32 lbl_803E71E4;
extern f32 lbl_803E704C;
extern void ObjHits_MarkObjectPositionDirty(int obj);





















#pragma dont_inline on
#pragma dont_inline reset


/* Arwing family (untouched: arwarwing, arwarwinggu, arwingandrossstuff, arwlevelcon, arwsquadron). */
extern int gArwing;
extern f32 lbl_803E701C;
extern f32 lbl_803E7058;
extern f32 lbl_803E70E0;
extern f32 lbl_803E7188;
extern void arwingHudSetVisible(int mode);
extern void fn_80125D04(void);
extern void setIsOvercast(int value);
extern void Music_Trigger(int id, int p2);

#pragma dont_inline on
#pragma dont_inline reset


#pragma dont_inline on
#pragma dont_inline reset


extern int getArwing(void);
extern int ObjHits_GetPriorityHit(int obj, int *outHitObject, int *outSphereIndex,
                                  u32 *outHitVolume);
extern void spawnExplosion(int obj, f32 v, int a, int b, int c, int d, int e, int f, int g);
extern int getAngle(f32 dx, f32 dz);
extern f32 mathCosf(f32 x);
extern void doRumble(f32 v);
extern void PSVECNormalize(void *src, void *dst);
extern void C_VECHalfAngle(void *out, void *a, void *b);
extern void projectileParticleFxFn_80099660(int obj, f32 p2, int p3);
extern f32 lbl_803E7008;
extern f32 lbl_803E7014;
extern f32 lbl_803E7028;
extern f32 lbl_803E702C;
extern f32 gArwingAndrossPi;
extern f32 gArwingAndrossBinAngScale;
extern f32 lbl_803E7038;
extern f32 lbl_803E703C;



#pragma dont_inline on
#pragma dont_inline reset

extern f32 lbl_803E7008;
extern f32 lbl_803E70EC;
extern f32 lbl_803E70F0;
extern f32 lbl_803E70F4;
extern void ObjHits_SetTargetMask(int obj, u8 targetMask);
extern void setMatrixFromObjectPos(void *mtx, void *src);
extern void Matrix_TransformPoint(void *mtx, f32 x, f32 y, f32 z, f32 *ox, f32 *oy, f32 *oz);
extern void gameTextFn_80125ba4(int id);
extern void pauseMenuCreateHeads(void);

typedef struct ArwProjPosSrc {
    s16 rot[3];
    f32 scale;
    f32 pos[3];
} ArwProjPosSrc;

#pragma dont_inline on
#pragma dont_inline reset


int arwlevelcon_ringEventCallback(int obj, int p2, int data);



extern f32 lbl_803E6ED0;
extern f32 lbl_803E6EE8;
extern f32 lbl_803E6EFC;
extern f32 lbl_803E6F00;
extern f32 lbl_803E6F5C;
extern f32 lbl_803E6FF4;
extern f32 lbl_803E6FF8;
extern f32 playerMapOffsetX;
extern f32 playerMapOffsetZ;
extern f32 mathSinf(f32 x);
extern void Obj_BuildWorldTransformMatrix(int obj, void *mtx, int p3);
extern void PSMTXMultVec(void *mtx, void *src, void *dst);
extern void fn_8008020C(int rx, int ry, int rz, f32 x, f32 y, f32 z, f32 p7);



extern f32 lbl_803E7028;
extern f32 lbl_803E705C;
extern f32 lbl_803E7060;
extern f32 lbl_803DC3D0;
extern f32 lbl_803DC3D4;
extern f32 lbl_803DC3D8;
extern void objMove(int obj, f32 vx, f32 vy, f32 vz);
extern void ObjHits_SetHitVolumeSlot(u32 obj, int hitVolume, int hitType, int sourceSlot);
extern void projectileParticleFxFn_80099660(int obj, f32 p2, int p3);
extern int ObjModel_GetTexture(int p1, int p2);
extern void fn_800541A4(int p1, int p2);
extern void textureAnimFn_80053f2c(int p1, int p2, int p3);



extern f32 lbl_803E70E4;
extern f32 lbl_803E70E8;
extern void skyFn_80089710(int p1, u8 p2, int p3);
extern void skyFn_800895e0(int p1, int p2, int p3, int p4, int p5, int p6);
extern void skyFn_800894a8(int p1, f32 p2, f32 p3, f32 p4);
extern void getEnvfxAct(int p1, int p2, int p3, int p4);
extern void setDrawLights(int value);
extern int AudioStream_IsPreparing(void);
extern void AudioStream_StartPrepared(void);
extern void AudioStream_Play(int stream, void (*cb)(void));
extern int mapBlockFn_800592e4(void);
extern int arwarwing_getRequiredRingCount(int arwing);
extern int arwarwing_getCollectedRingCount(int arwing);


extern f32 lbl_803E7154;
typedef struct ARWGeneratorState {
    f32 spawnTimer;
} ARWGeneratorState;

typedef struct ARWGeneratorSetup {
    u8 pad00[0x18];
    u16 spawnInterval;
    u16 projectileSpeed;
    s8 velocityX;
    s8 velocityY;
    s8 velocityZ;
    u8 pad1F[3];
    u8 spreadX;
    u8 spreadY;
    u8 spreadZ;
    u8 spawnMode;
} ARWGeneratorSetup;

STATIC_ASSERT(sizeof(ARWGeneratorState) == 0x4);
STATIC_ASSERT(offsetof(ARWGeneratorSetup, spawnInterval) == 0x18);
STATIC_ASSERT(offsetof(ARWGeneratorSetup, projectileSpeed) == 0x1A);
STATIC_ASSERT(offsetof(ARWGeneratorSetup, velocityX) == 0x1C);
STATIC_ASSERT(offsetof(ARWGeneratorSetup, spreadX) == 0x22);
STATIC_ASSERT(offsetof(ARWGeneratorSetup, spawnMode) == 0x25);

extern void fn_802317A8(int obj, ARWGeneratorState *state, ARWGeneratorSetup *setup);
extern void fn_802315EC(int obj, ARWGeneratorState *state, ARWGeneratorSetup *setup);


extern void fn_8006CB24(int obj);
extern void Rcp_DisableDistortionFilter(void);
extern void lightningRender(void *p);
extern f32 lbl_803E74DC;
extern f32 lbl_803E75B0;
extern f32 lbl_803E7600;

#pragma dont_inline on
#pragma dont_inline reset


extern int ObjList_FindObjectById(int id);
extern void androsshand_handleDamage(int obj, int hand);
extern void androsshand_spawnShot(int p1, int p2, int p3);
extern f32 lbl_803E75AC;
extern f32 gAndrossHandMoveAnimSpeeds[];
extern f32 lbl_803DC4F0;
extern f32 lbl_803DC4F4;
extern f32 lbl_803DC4F8;
extern int lbl_803DC4FC;
extern int lbl_803DC500;
extern int lbl_803DC504;
extern f32 lbl_803E75B4;
extern f32 gAndrossHandPi;
extern f32 gAndrossHandHalfAngleScale;
extern f32 lbl_803E75C0;
extern f32 lbl_803E75C4;
extern f32 lbl_803E75C8;
extern double lbl_803E75D0;
extern f32 lbl_803E75D8;
extern f32 lbl_803E75DC;
extern f32 lbl_803E75E0;
extern double lbl_803E75E8;
extern f32 lbl_803E75F0;
extern f32 lbl_803E75F4;
extern f32 lbl_803E75F8;



extern void fn_8006CB50(void);
extern void unlockLevel(int a, int b, int c);
extern int ObjModel_GetRenderOp(int model, int idx);
extern f32 gAndrossAlpha255;
extern f32 lbl_803E74D4;
extern f32 gAndrossSpringDamping;
extern f32 gAndrossInitAnimSpeed;
extern f32 gAndrossInitSpawnCooldown;
extern f32 gAndrossSpringStiffness;







extern int ObjHits_GetPriorityHit(int obj, int *outHitObject, int *outSphereIndex,
                                  u32 *outHitVolume);
extern void ObjPath_GetPointWorldPosition(int obj, int idx, f32 *x, f32 *y, f32 *z, int p6);
extern void DIMexplosionFn_8009a96c(int obj, f32 a, f32 b, f32 c, f32 d, int e, int f,
                                    int g, int h, int i, int j, int k);
extern int lbl_803DC508;
extern f32 lbl_803E75A8;


extern f32 lbl_803E75AC;
extern f32 gAndrossHandMoveAnimSpeeds[];




extern int ObjList_FindObjectById(int id);
extern void androssligh_updateBeam(int obj, int state);


extern void *Camera_GetViewMatrix(void);
extern void *Camera_GetInverseViewRotationMatrix(void);
extern void *lightningCreate(f32 *pos, f32 *dir, f32 a, f32 b, u16 angle, int c, int d);
extern void PSVECScale(void *dst, void *src, f32 scale);
extern void PSVECAdd(int p1, int p2, int p3);
extern f32 lbl_803DC518;
extern f32 lbl_803DC51C;
extern f32 lbl_803DC520;
extern f32 lbl_803DC524;
extern f32 lbl_803DC528;
extern f32 lbl_803DC52C;
extern f32 lbl_803E7608;
extern f32 lbl_803E760C;

extern void Obj_SetModelColorFadeRecursive(int obj, int r, int g, int b, int a, int frames);


extern f32 lbl_803E7480;
extern int gf_levelcon_handleScriptEvents(int obj, int eventId, ObjAnimUpdateState *animUpdate);
extern void gf_levelcon_findLinkedObjects(int obj);
extern int loadMapAndParent(int mapId);
extern void mapUnload(int a, int b);
extern int mapGetDirIdx(int mapId);
extern void warpToMap(int map, int p2);
extern void loadUiDll(int id);
extern void creditsStart(void);
extern void gameTextShow(int id);
extern f32 lbl_803E7460;
extern f32 lbl_803E7464;
extern f32 lbl_803E7468;
extern f32 lbl_803E746C;
extern f32 lbl_803E7470;
extern f32 lbl_803E7474;
extern f32 lbl_803E7478;
extern f32 lbl_803E747C;
extern f32 lbl_803E7484;
extern f32 lbl_803E7488;
extern f32 lbl_803E748C;
extern f32 timeDelta;




extern f32 lbl_803E745C;
extern int mclightning_handleScriptEvents(int obj, int unused, ObjAnimUpdateState *animUpdate);
extern f32 lbl_803E7440;

extern void *lightningCreate(f32 *pos, f32 *dir, f32 a, f32 b, u16 angle, int c, int d);
extern f32 lbl_803E7450;
extern f32 lbl_803E7454;
extern f32 lbl_803E7458;


extern f32 lbl_803E738C;
extern int cmbsrc_update(int obj);


extern void modelLightStruct_setSpecularColor(void *light, u8 r, u8 g, u8 b, int a);
extern f32 lbl_803E7360;
extern f32 lbl_803E7364;
extern f32 lbl_803E7368;
extern f32 lbl_803E736C;
extern f32 lbl_803E7370;
extern f32 lbl_803E7374;
extern f32 lbl_803E7384;
extern u8 gCmbsrcColorCycleIndexTable[8];
extern u8 gCmbsrcColorSoundIdTable[];
extern u8 gCmbsrcColorRgbTable[];
extern f32 lbl_803E7378;
extern f32 lbl_803E737C;
extern f32 lbl_803E7380;
extern f32 lbl_803E7388;
extern f32 lbl_803E738C;
extern f32 lbl_803E7390;
extern f32 lbl_803E7394;
extern f32 lbl_803E7398;
extern int Camera_GetCurrentViewSlot(void);
extern f32 interpolate(f32 a, f32 b, f32 c);
extern void objfx_spawnLightPulse(int obj, f32 brightness, int b, int c, int d, f32 e, int f);
extern void fn_80098B18(int obj, f32 brightness, int b, int c, int d, void *vec);
extern void lightSetField4D(void *light, int v);
extern void ObjHits_SyncObjectPositionIfDirty(u32 obj);
extern f32 gCmbsrcColorRadiusScaleTable[];
extern f32 lbl_803E73A8;
extern f32 lbl_803E73AC;
extern f32 lbl_803E73B0;
extern f32 lbl_803E73B4;
extern f32 lbl_803E73B8;
extern f32 lbl_803E73BC;
extern f32 lbl_803E73C0;

#pragma dont_inline on






#pragma dont_inline reset

extern void fn_8003B608(int r, int g, int b);
extern u8 Obj_IsLoadingLocked(void);
extern int Obj_AllocObjectSetup(int a, int b);
extern int Obj_SetupObject(int newObj, int a, int b, int c, int d);
extern const f32 lbl_803E72F8;
extern const f32 lbl_803E7308;
extern void ObjHitbox_SetCapsuleBounds(int obj, int radius, int a, int b);
extern void vecRotateZXY(int obj, f32 *vec);
extern void objfx_spawnRandomBurst(int obj, int mode, int p3, void *vec, f32 f, int flag);
extern int ObjHits_GetPriorityHitWithPosition(int obj, int *outHitObject, int *outSphereIndex,
                                              u32 *outHitVolume, float *outHitPosX,
                                              float *outHitPosY, float *outHitPosZ);
extern int ObjHits_RecordObjectHit(int obj, int hitObj, char priority, u8 hitVolume,
                                   u8 sphereIndex);
extern int Obj_GetPlayerObject(void);
extern f32 sqrtf(f32 x);
extern f32 gTreeEffectColors[];
extern const f32 lbl_803E730C;
extern const f32 lbl_803E7310;
extern const f32 lbl_803E7314;
extern const f32 lbl_803E7318;
extern const f32 lbl_803E731C;
extern const f32 lbl_803E7320;
extern const f32 lbl_803E7324;
extern const f32 gTreeScaleByteNormalizer;
extern const f32 lbl_803E732C;

#pragma dont_inline on




#pragma dont_inline reset

extern int *ObjList_GetObjects(int *startIndex, int *objectCount);


extern int *gPlayerInterface;
extern int Curve_AdvanceAlongPath(RomCurveWalker *curve, f32 val);
extern int getAngle(f32 dx, f32 dz);
extern f32 oneOverTimeDelta;
extern f32 Vec_xzDistance(int a, int b);
extern void characterDoEyeAnims(int obj, int p2);
extern void doNothing_80062A50(int obj, f32 x, f32 y, f32 z);
extern void dll_2E_func03(int obj, int p2);
extern void dll_2E_func05(int obj, int p2, int p3, int p4, int p5);
extern void dll_2E_func09(int p1, void *p2, void *p3, int p4);
extern int gDll28BMoveBlendDataA[];
extern int gDll28BMoveBlendDataB[];
extern void *gDll28BSubstateHandlers[];
extern void *gDll28BStateHandlers[];
extern f32 gWcEarthWalkerFarPlayerDistance;
extern f32 gWcEarthWalkerNearPlayerDistance;
extern f32 gWcEarthWalkerIdleTimerThreshold;
extern f32 gWcEarthWalkerCurveAdvanceStep;
extern f32 gWcEarthWalkerApproachPlayerDistance;
extern f32 gWcEarthWalkerChaseMoveSpeed;
extern f32 gWcEarthWalkerWalkMoveSpeed;
extern f32 lbl_803E6D18;
extern f32 gDll28BCurveInitParam;

typedef struct Blob16 { int a, b, c, d; } Blob16;
typedef struct ObjXform {
    s16 rx, ry, rz;
    f32 scale;
    f32 x, y, z;
} ObjXform;












extern int dll_2E_func07(int obj, int p2, int state, int p4, int p5);
extern void dll_2E_setLookAtMaxDistance(int state, f32 a);
extern void getEnvfxActImmediately(int a, int b, int c, int d);
extern int gEarthWalkerMoveBlendData;
extern f32 gEarthWalkerLookAtMaxDistance;



extern int Obj_IsObjectAlive(int obj);
extern int Obj_GetPlayerObject(void);
extern f32 lbl_803E6C24;
extern f32 lbl_803E6C28;
extern f32 lbl_803E6C2C;
extern f32 lbl_803E6C30;
extern f32 lbl_803E6C34;


extern ModgfxInterface **gModgfxInterface;
extern void *lbl_803DDD80;




extern void PSVECAdd(int p1, int p2, int p3);
typedef struct Vec12 { int a, b, c; } Vec12;







#pragma dont_inline on
#pragma dont_inline reset

#pragma dont_inline on







#pragma dont_inline on



#pragma dont_inline reset



#pragma dont_inline reset

extern int gameBitIncrement(int id);
extern f32 lbl_803E70A0;
extern f32 gArwBombCollHitToleranceY;
extern f32 gArwBombCollHitRadiusSq;
extern f32 gArwBombCollPlaneHitRadius;




extern f32 lbl_803E6ECC;

#pragma dont_inline on
#pragma dont_inline reset

extern f32 lbl_803E6ED0;
extern f32 lbl_803E6EFC;
extern f32 lbl_803E6F00;
extern f32 mathSinf(f32 x);
extern void PSVECScale(void *dst, void *src, f32 scale);
extern void PSVECSubtract(void *a, void *b, void *ab);



extern f32 lbl_803E6F08;
extern f32 lbl_803E6F0C;
extern f32 lbl_803E6F10;
extern f32 lbl_803E6F14;
extern f32 lbl_803E6F18;
extern f32 lbl_803E6F1C;
extern f32 lbl_803E6F20;


extern void warpToMap(int map, int p2);

#pragma dont_inline on
#pragma dont_inline reset

extern void lightSetFieldBC_8001db14(void *light, int v);
extern f32 lbl_803E700C;
extern f32 lbl_803E7010;
extern f32 lbl_803E7014;
extern f32 lbl_803E7018;

#pragma dont_inline on
#pragma dont_inline reset

extern f32 lbl_803E721C;
extern f32 lbl_803E7220;


extern void modelLightStruct_getDiffuseColor(void *light, u8 *a, u8 *b, u8 *c, u8 *d);
extern void modelLightStruct_setGlowColor(void *light, u8 r, u8 g, u8 b, int e);
extern f32 lbl_803E71D8;
extern f32 lbl_803E71DC;
extern f32 lbl_803E71E0;
extern f32 gArwProximityTauntDistance;
extern f32 gArwProximityActivateDistance;
extern f32 lbl_803E71F0;
extern f32 lbl_803E71F4;
extern f32 lbl_803E71F8;
extern f32 gArwProximityFadeInRate;
extern f32 gArwProximityWarningDistance;


extern f32 lbl_803E71A8;


extern void *Camera_GetInverseViewMatrix(void);
extern f32 lbl_803E7104;
extern f32 lbl_803E7108;
extern f32 lbl_803E710C;


extern void arwarwing_spawnLaserShot(int obj, int state, int a, int b, int c);
extern f32 gArwingFireTimerReset;


extern f32 lbl_803E6F34;
extern f32 gArwingExplodeModeTime;
extern f32 lbl_803E6F28;
extern f32 lbl_803E6F6C;
extern f32 lbl_803E6EF8;
extern f32 lbl_803E6FFC;
extern f32 lbl_803E7000;
extern void unlockLevel(int a, int b, int c);
extern int mapGetDirIdx(int mapId);
extern void lockLevel(int idx, int p2);
extern void warpToMap(int map, int p2);
extern void spawnExplosion(int obj, f32 v, int a, int b, int c, int d, int e, int f, int g);



#pragma dont_inline on

#pragma dont_inline reset

#pragma dont_inline on
#pragma dont_inline reset



extern int ObjTrigger_IsSet(int obj);
extern void hudFn_8011f38c(int arg);
extern int fn_80296A9C(int player, int p2);
extern int fn_802966CC(void);
extern void staffSetGlow(int staff, int p2, int p3);











extern f32 mathCosf(f32 x);
extern f32 lbl_803E6BF0;
extern f32 lbl_803E6BF4;
extern f32 lbl_803E6BF8;





extern int objModelGetVecFn_800395d8(int model, int idx);
extern f32 fn_802945E0(f32 ratio);
extern double lbl_803E6F48;
extern double lbl_803E6F50;
extern f32 lbl_803E6F58;
extern f32 lbl_803E6F60;
extern f32 lbl_803E6F64;
extern f32 lbl_803E6F68;
extern f32 lbl_803E6F38;
extern f32 lbl_803E6EF8;
void fn_8022F270(int obj, int p2);




extern void ObjLink_AttachChild(int obj, int child, int p3);
extern f32 lbl_803E6F2C;
extern f32 lbl_803E6F34;
extern f32 lbl_803E6F70;
extern f32 lbl_803E6F74;
extern f32 lbl_803E6F78;
extern f32 lbl_803E6F7C;
extern f32 lbl_803E6F80;
extern f32 lbl_803E6F84;
extern f32 lbl_803E6F88;
extern f32 lbl_803E6F8C;
extern f32 lbl_803E6F90;
extern f32 lbl_803E6F94;
extern f32 lbl_803E6F98;
extern f32 lbl_803E6F9C;
extern f32 lbl_803E6FA0;
extern f32 lbl_803E6FA4;
extern f32 lbl_803E6FA8;
extern f32 lbl_803E6FAC;
extern f32 lbl_803E6FB0;
extern f32 lbl_803E6FB4;
extern f32 lbl_803E6FB8;
extern f32 lbl_803E6FBC;
extern f32 gArwingEscortSearchRadius;
extern f32 lbl_803E6FC4;
extern f32 lbl_803E6FC8;
extern f32 lbl_803E6FCC;
extern f32 lbl_803E6FD0;
extern f32 lbl_803E6FD4;
extern f32 lbl_803E6FD8;
extern f32 lbl_803E6FDC;
extern f32 lbl_803E6FE0;
extern f32 lbl_803E6FE4;
extern f32 lbl_803E6FE8;
extern f32 lbl_803E6FEC;
extern f32 lbl_803E6FF0;
extern f32 lbl_803E6EF0;
extern f32 lbl_803E6EF4;


extern f32 lbl_803E707C;
extern f32 gArwBombCollActivateDistanceZ;
extern f32 gArwBombCollAlphaFadeRate;
extern f32 gArwBombCollSpinRate;
extern f32 lbl_803E708C;

typedef struct {
    u8 b80 : 1;
    u8 b40 : 1;
} ArwBombFlags;

typedef struct ARWBombCollState {
    f32 lifetime;
    ArwBombFlags flags;
    u8 pad05[3];
} ARWBombCollState;

STATIC_ASSERT(sizeof(ArwBombFlags) == 0x1);
STATIC_ASSERT(sizeof(ARWBombCollState) == 0x8);
STATIC_ASSERT(offsetof(ARWBombCollState, flags) == 0x04);


extern int lbl_803E7160;
extern f32 lbl_803E716C;
extern f32 lbl_803E7170;
extern f32 lbl_803E71C0;
extern f32 lbl_803E71C4;
extern f32 lbl_803E71C8;
extern f32 lbl_803E71CC;
extern f32 lbl_803E71D0;
extern f32 lbl_803E71D4;
void arwsquadron_applyCommandParams(int p1, int p2);

typedef struct {
    u8 b80 : 1;
    u8 b40 : 1;
    u8 b20 : 1;
    u8 b10 : 1;
} SquadFlags;




#pragma dont_inline on
#pragma dont_inline reset
#pragma dont_inline on
#pragma dont_inline reset

extern f32 lbl_803E7140;


extern f32 lbl_803E7044;
#pragma dont_inline on
#pragma dont_inline reset

extern int loadObjectAtObject(int obj);

#pragma dont_inline on
#pragma dont_inline reset

extern int ObjList_FindNearestObjectByDefNo(int obj, int defNo, f32 *maxDistanceSq);
extern f32 lbl_803E7490;

#pragma dont_inline on
#pragma dont_inline reset

extern int lbl_803DC4E8;


extern f32 lbl_803E74AC;
extern f32 lbl_803E74B0;
extern f32 lbl_803E74D4;
extern f32 lbl_803E74D8;



extern int lbl_803DC4D8;
extern int lbl_803DC4DC;
extern int lbl_803DC4E0;
extern f32 lbl_803DC4E4;
extern int gGfLevelConProjectilePitch;
extern int lbl_803DDDC0;
extern s16 gGfLevelConProjectileYaw;
extern s16 lbl_803DDDC6;
extern f32 lbl_803E74A0;
extern f32 lbl_803E74A4;
extern f32 lbl_803E74A8;



extern f32 lbl_803DC4C0;
extern f32 gAndrossArwingVelDamp;


extern u8 lbl_803DC4C8;


extern f32 WCBLOCK_PLAYER_CELL_MARGIN;


extern f32 lbl_803E6ECC;
extern f32 lbl_803E6ED0;
extern f32 lbl_803E6F5C;
extern f32 lbl_803E6F64;
extern f32 lbl_803E6F70;
extern f32 lbl_803E6F74;
extern f32 lbl_803E6F78;
extern f32 lbl_803E6F7C;
extern f32 lbl_803E6F80;
extern f32 lbl_803E6F84;
extern f32 lbl_803E6F88;
extern f32 lbl_803E6F8C;
extern f32 lbl_803E6F90;
extern f32 lbl_803E6F94;
extern f32 lbl_803E6F98;
extern f32 lbl_803E6F9C;
extern f32 lbl_803E6FA0;
extern f32 lbl_803E6FA4;
extern f32 lbl_803E6FA8;
extern f32 lbl_803E6FAC;
extern f32 lbl_803E6FB0;
extern f32 lbl_803E6FB4;
extern f32 lbl_803E6FB8;
extern f32 lbl_803E6FBC;


extern f32 lbl_803E7040;
extern f32 lbl_803E7048;


extern f32 lbl_803E6EF0;
extern f32 lbl_803E6EF4;

#pragma dont_inline on
#pragma dont_inline reset

extern f32 gArwingExplodeModeTime;
extern f32 lbl_803E6F28;
extern f32 lbl_803E6F2C;
extern f32 lbl_803E6F30;
extern f32 lbl_803E6F34;
extern f32 lbl_803E6F38;
extern f32 lbl_803E6F3C;
extern f32 lbl_803E6F40;


extern int objGetFlagsE5_2(int obj);
extern int mapGetDirIdx(int mapId);
extern void lockLevel(int idx, int p2);
extern int loadMapAndParent(int mapId);


extern int gAndrossHandShotPitch;
extern int lbl_803DC50C;
extern int lbl_803DC510;


extern void mapUnload(int a, int b);
extern void setLoadedFileFlags_blocks1(void);
extern void clearLoadedFileFlags_blocks1(void);
extern void registerNewScore(int a, int b, int c, int d);
extern u8 gArwingCourseMapIds[8];
typedef struct { u8 scoreFlag : 1; } Arw339Flags;


typedef struct { int a; int b; u16 c; } ArwInitCfg;
extern ArwInitCfg gArwingInitConfig;
extern int gArwingPathSetupData[];
extern int sArwingPathName[];


extern f32 PSVECMag(f32 *v);
extern void PSVECNormalize(void *src, void *dst);
extern void PSVECCrossProduct(f32 *a, f32 *b, f32 *out);
extern f32 PSVECDotProduct(f32 *a, f32 *b);
extern void PSMTXRotAxisRad(f32 *mtx, f32 *axis, f32 angle);
extern void PSMTXMultVecSR(f32 *mtx, f32 *in, f32 *out);
extern f32 fn_80291FF4(f32 x);
extern f32 lbl_803E6C38;
extern f32 lbl_803E6C6C;
extern f32 lbl_803E6C70;
extern f32 lbl_803E6C74;


extern f32 gBarrelGenPi;
extern f32 gBarrelGenAngleHalfRange;
extern f32 lbl_803E6C78;
extern f32 lbl_803E6C7C;
extern f32 lbl_803E6C80;

#pragma dont_inline on
#pragma dont_inline reset

#pragma dont_inline reset

typedef struct {
    u8 f80 : 1;
    u8 f40 : 1;
    u8 f20 : 1;
    u8 f10 : 1;
    u8 f08 : 1;
    u8 : 3;
} SquadCmdFlags;
extern f32 lbl_803E716C;
extern f32 lbl_803E7170;

#pragma dont_inline on

extern void Obj_SmoothTurnAnglesTowardVelocity(int a, int b, int c, f32 d, f32 e);
extern f32 lbl_803E7168;
extern f32 lbl_803E719C;
extern f32 lbl_803E71A0;
extern f32 lbl_803E71A4;



extern void ObjPath_GetPointLocalPosition(int obj, int idx, f32 *x, f32 *y, f32 *z);

typedef struct {
    s16 s0, s2, s4, s6;
    f32 f8;
    f32 fx, fy, fz;
} SquadPfx;


extern f32 lbl_803E71AC;
extern f32 lbl_803E71B0;
extern f32 lbl_803E71B4;


extern void setMatrixFromObjectTransposed(void *transform, f32 *mtx);
extern f32 lbl_803E718C;
extern f32 lbl_803E7190;
extern f32 gArwingSquadronPi;
extern f32 gArwingSquadronSwayPhaseToAngleDiv;


extern f32 lbl_803E7164;
extern f32 lbl_803E71B8;
extern f32 lbl_803E71BC;


extern f32 lbl_803E6C68;

typedef struct DrMusicContFlags {
    u8 b_state : 1;
    u8 pad8_lo : 1;
    u8 b_e30 : 1;
    u8 b_e31 : 1;
    u8 b_e32 : 1;
    u8 b_e33 : 1;
    u8 b_e9c : 1;
    u8 b_e38 : 1;
    u8 b_e3c : 1;
    u8 b_e3d : 1;
    u8 b_e3e : 1;
    u8 b_e39 : 1;
    u8 b_9e0 : 1;
    u8 b_9e1 : 1;
    u8 b_9e2 : 1;
    u8 b_9e7 : 1;
} DrMusicContFlags;


extern void cloudSetOverridePosition(int obj, f32 a, f32 b, f32 c);
extern void getEnvfxActImmediately(int a, int b, int c, int d);
extern void skyFn_80088e54(int a, f32 b);
extern void SCGameBitLatch_Update(int state, int a, int b, int c, int d, int e);
extern void SCGameBitLatch_UpdateInverted(int state, int a, int b, int c, int d, int e);
extern f32 gDrMusicControlCloudOverridePosX;
extern f32 gDrMusicControlCloudOverridePosY;
extern f32 gDrMusicControlCloudOverridePosZ;
extern f32 lbl_803E6BD8;
extern f32 gDrMusicControlStingerTimerDuration;
extern f32 gDrMusicControlRestartPointX;
extern f32 gDrMusicControlRestartPointY;
extern f32 gDrMusicControlRestartPointZ;


extern f32 lbl_803E6CA4;
extern f32 lbl_803E6CD0;


extern int gunpowderbarrel_isHeld(int obj);
extern int gunpowderbarrel_canBeGrabbed(int obj);
extern void gunpowderbarrel_addThrowVelocity(int obj, void *vec);
extern void gunpowderbarrel_setHeldState(int obj);
extern int timerCountDown(void *timer);
extern void PSVECNormalize(void *src, void *dst);
extern void PSVECScale(void *dst, void *src, f32 scale);
extern f32 PSVECDistance(void *a, void *b);
extern int Obj_UpdateRomCurveFollowVelocity(int obj, int p2, f32 a, f32 b, f32 c, int p6);
extern int voxmaps_traceWorldLine(void *p1, void *p2);
extern void PSVECSubtract(void *a, void *b, void *ab);
extern int ObjGroup_FindNearestObject(int group, int obj, f32 *out);
extern f32 lbl_803E6CA0;
extern f32 lbl_803E6CA8;
extern f32 gDrBarrelGenGrabRange;
extern f32 lbl_803E6CB4;
extern f32 gDrBarrelGenCarrySpeedScale;
extern f32 lbl_803E6CBC;
extern f32 lbl_803E6CC0;
extern f32 lbl_803DC3B0;
extern f32 gDrBarrelGenGrabYOffset;


extern void PSVECSubtract(void *a, void *b, void *ab);
extern int ObjGroup_FindNearestObject(int group, int obj, f32 *out);
extern f32 lbl_803E6CA0;
extern f32 lbl_803E6CA8;
extern f32 lbl_803E6CAC;

typedef struct DrBarrelGrRenderParams {
    s16 a;
    s16 b;
    s16 c;
    f32 d;
} DrBarrelGrRenderParams;


extern int dll_2E_func0A(int a, void *out);
extern void *lightningCreate(f32 *pos, f32 *dir, f32 a, f32 b, u16 angle, int c, int d);
extern f32 lbl_803E6BB8;
extern f32 lbl_803E6BBC;
extern f32 lbl_803E6BC0;


extern void *fn_802972A8(void);
extern void setAButtonIcon(int icon);
extern void objfx_spawnArcedBurst(int obj, int enabled, f32 radius, int particleKind,
                                   int particleId, int lifetime, f32 scaleX, f32 scaleY,
                                   f32 scaleZ, void *args, int arg9);
extern f32 lbl_803E6C08;
extern f32 lbl_803E6C0C;
extern f32 lbl_803E6C10;
extern f32 lbl_803E6C14;
extern f32 lbl_803E6C18;
extern f32 lbl_803E6C1C;


extern void voxmaps_worldToGrid(void *world, void *grid);
extern int voxmaps_traceLine(void *from, void *to, void *out, int p4, int p5);
extern f32 lbl_803E6C58;

extern void mm_free_(void *ptr);
extern f32 lbl_803E6C3C;
extern f32 lbl_803E6C40;
extern f32 lbl_803E6C44;
extern f32 lbl_803DC3A0;
extern f32 lbl_803DC3A4;
extern f32 lbl_803DC3A8;
extern u16 lbl_803DC3AC;


extern f32 lbl_803E6C5C;
extern f32 gBarrelGenAngleWrapNeg;
extern f32 gBarrelGenAngleWrapPos;
extern f32 gBarrelGenAngleWrapThreshold;
extern f32 gBarrelGenTurnRateClampMin;
extern f32 gBarrelGenTurnRateClampMax;
extern f32 lbl_803E6C98;




extern void voxmaps_gridToWorld(void *grid, void *out);


extern f32 lbl_803E70A0;
extern f32 lbl_803E70B4;
extern f32 lbl_803E70B8;
extern f32 lbl_803E70BC;
extern f32 lbl_803E70C0;
extern f32 lbl_803E70C4;
extern f32 lbl_803E70C8;
extern f32 lbl_803E70CC;
extern int getArwing(void);
extern int Obj_GetPlayerObject(void);
extern void PSMTXMultVecSR(f32 *mtx, f32 *in, f32 *out);
extern f32 mathCosf(f32 x);
extern f32 mathSinf(f32 x);

typedef struct {
    /* 0x0 */ int f0;
    /* 0x4 */ int f4;
    /* 0x8 */ int f8;
    /* 0xc */ int fc;
    /* 0x10 */ int f10;
    /* 0x14 */ f32 f14;
} RingTable;
extern RingTable lbl_8032B720[];


extern f32 lbl_803E6EC8;
extern f32 lbl_803E6ED4;
extern f32 lbl_803E6ED8;
extern void debugPrintSetColor(int r, int g, int b, int a);
extern int padGetStickX(int controller);
extern int padGetStickY(int controller);
extern int padGetRTrigger(int controller);
extern int padGetLTrigger(int controller);
extern int getButtonsJustPressedIfNotBusy(int controller);
extern int getButtonsHeld(int controller);
extern f32 lbl_8032B4A8[];


extern f32 lbl_803E6EF8;

/* Forward declarations for graduated functions (split from placeholder_80220608). */
int drenergydisc_getExtraSize(void);
int drenergydisc_getObjectTypeId(void);
void drenergydisc_free(void);
void drenergydisc_render(void);
void drenergydisc_hitDetect(void);
void drenergydisc_update(int obj);
void drenergydisc_init(u8 *obj, u8 *setup);
void drenergydisc_release(void);
void drenergydisc_initialise(void);
int drlightbea_getExtraSize(void);
int drlightbea_getObjectTypeId(void);
void drlightbea_free(int obj);
void drlightbea_hitDetect(void);
void drlightbea_update(int obj);
void drlightbea_init(int obj);
void drlightbea_release(void);
void drlightbea_initialise(void);
int drmusiccont_getExtraSize(void);
int drmusiccont_getObjectTypeId(void);
void drmusiccont_free(int obj);
void drmusiccont_render(int obj, int p2, int p3, int p4, int p5, s8 visible);
void drmusiccont_hitDetect(void);
void drmusiccont_release(void);
void drmusiccont_initialise(void);
int drcloudper_getExtraSize(void);
int drcloudper_getObjectTypeId(void);
void drcloudper_free(int obj);
void drcloudper_render(void);
void drcloudper_hitDetect(void);
void drcloudper_update(void);
void drcloudper_release(void);
void drcloudper_initialise(void);
int drearthcal_setScale(void);
int drearthcal_getExtraSize(void);
int drearthcal_getObjectTypeId(void);
void drearthcal_free(void);
void drearthcal_render(void);
void drearthcal_hitDetect(void);
void drearthcal_init(int obj, int setup);
void drearthcal_release(void);
void drearthcal_initialise(void);
int barrelgener_getLinkId(int obj);
void barrelgener_queueObjectRelease(int obj, int queuedObj, int releaseFrame);
int barrelgener_getExtraSize(void);
int barrelgener_getObjectTypeId(void);
void barrelgener_free(int obj);
void barrelgener_render(int obj, int p2, int p3, int p4, int p5, s8 visible);
void barrelgener_hitDetect(void);
void barrelgener_init(int obj);
void barrelgener_release(void);
void barrelgener_initialise(void);
int drbarrelgr_getExtraSize(void);
int drbarrelgr_getObjectTypeId(void);
void drbarrelgr_free(int obj);
void drbarrelgr_hitDetect(void);
void drbarrelgr_release(void);
void drbarrelgr_initialise(void);
int earthwalker_getExtraSize(void);
int earthwalker_getObjectTypeId(void);
void earthwalker_free(void);
void earthwalker_render(int obj, int p2, int p3, int p4, int p5, s8 visible);
void earthwalker_hitDetect(int obj);
void earthwalker_release(void);
void earthwalker_initialise(void);
void earthwalker_update(int obj);
int wcbouncycra_getExtraSize(void);
int wcbouncycra_getObjectTypeId(void);
void wcbouncycra_free(void);
void wcbouncycra_render(int obj, int p2, int p3, int p4, int p5, s8 visible);
void wcbouncycra_hitDetect(void);
void wcbouncycra_update(int obj);
void wcbouncycra_init(int obj, int setup);
void wcbouncycra_release(void);
void wcbouncycra_initialise(void);
int wcpushblock_getExtraSize(void);
int wcpushblock_getObjectTypeId(int obj);
void wcpushblock_free(void);
void wcpushblock_render(int obj, int p2, int p3, int p4, int p5, s8 visible);
void wcpushblock_hitDetect(void);
void wcpushblock_init(int obj, int setup);
void wcpushblock_release(void);
void wcpushblock_initialise(void);
void wcpushblock_update(int obj);
void wclevelcont_func16(s16 value, s16 *outRow, s16 *outCol);
void wclevelcont_func15(s16 value, s16 *outRow, s16 *outCol);
int wclevelcont_func14(s16 i, s16 j);
void wclevelcont_func13(int value, s16 i, s16 j);
void wclevelcont_func12(int obj, f32 px, f32 pz, s16 *outRow, s16 *outCol);
void wclevelcont_func11(int obj, s16 col, s16 row, f32 *outXp, f32 *outZp);
void wclevelcont_func0F(s16 value, s16 *outRow, s16 *outCol);
void wclevelcont_func0E(s16 value, s16 *outRow, s16 *outCol);
int wclevelcont_render2(s16 i, s16 j);
void wclevelcont_modelMtxFn(int value, s16 i, s16 j);
void wclevelcont_func0B(int obj, f32 px, f32 pz, s16 *outRow, s16 *outCol);
void wclevelcont_setScale(int obj, s16 col, s16 row, f32 *outXp, f32 *outZp);
int wclevelcont_getExtraSize(void);
int wclevelcont_getObjectTypeId(void);
void wclevelcont_free(int obj);
void wclevelcont_render(int obj, int p2, int p3, int p4, int p5, s8 visible);
void wclevelcont_hitDetect(void);
void wclevelcont_syncProgressBits(int state);
void wclevelcont_update(int obj);
void fn_802251B4(int obj, WcLevelControlState *state);
int wclevelcont_func10(int obj, s16 a, s16 b, f32 *outX, f32 *outZ, int dx, int dy);
void wcpushblock_updateLevelControlState(int obj, WcLevelControlState *state);
int wcpushblock_levelControlTriggerCallback(int obj, int unused, ObjAnimUpdateState *animUpdate);
int fn_80225D2C(int obj, s16 a, s16 b, f32 *outX, f32 *outZ, int dx, int dy);
void wclevelcont_init(int obj);
void wclevelcont_release(void);
void wclevelcont_initialise(void);
int wcbeacon_aButtonCallback(int obj);
int wcbeacon_getExtraSize(void);
int wcbeacon_getObjectTypeId(int obj);
void wcbeacon_render(int obj, int p2, int p3, int p4, int p5, s8 visible);
void wcbeacon_init(u8 *obj, u8 *setup);
void wcbeacon_update(int obj);
int wctile_getExtraSize(void);
int wctile_getObjectTypeId(int obj);
void wctile_free(void);
void wctile_render(int obj, int p2, int p3, int p4, int p5, s8 visible);
void wctile_hitDetect(void);
void wctile_init(u8 *obj, u8 *setup);
void wctile_release(void);
void wctile_initialise(void);
void wctile_update(int obj);
int wcpressures_getExtraSize(void);
int wcpressures_tileStateCallback(int obj, int unused, ObjAnimUpdateState *animUpdate);
int wcpressures_getObjectTypeId(int obj);
void wcpressures_free(int obj);
void wcpressures_render(int obj, int p2, int p3, int p4, int p5, s8 visible);
void wcpressures_hitDetect(void);
void wcpressures_update(int obj);
void wcpressures_init(u8 *obj, u8 *setup);
void wcpressures_release(void);
void wcpressures_initialise(void);
int wctrexstatu_interactCallback(int obj, int unused, ObjAnimUpdateState *animUpdate);
int wctrexstatu_getExtraSize(void);
int wctrexstatu_getObjectTypeId(int obj);
void wctrexstatu_free(void);
void wctrexstatu_render(int obj, int p2, int p3, int p4, int p5, s8 visible);
void wctrexstatu_hitDetect(u8 *obj);
void wctrexstatu_update(void);
void wctrexstatu_init(int obj, int setup, int fromLoad);
void wctrexstatu_release(void);
void wctrexstatu_initialise(void);
void wctempledia_syncPartVisibility(int obj, u8 mask);
int wctempledia_getExtraSize(void);
int wctempledia_getObjectTypeId(void);
void wctempledia_free(void);
void wctempledia_render(int obj, int p2, int p3, int p4, int p5, s8 visible);
void wctempledia_hitDetect(void);
int wctempledia_interactCallback(int obj, int p2, ObjAnimUpdateState *animUpdate);
void wctempledia_update(int obj);
void wctempledia_init(int obj, int setup);
void wctempledia_release(void);
void wctempledia_initialise(void);
void wctemplebri_updateModelWarp(int obj, int p2);
int wctemplebri_getExtraSize(void);
int wctemplebri_getObjectTypeId(int obj);
void wctemplebri_free(void);
void wctemplebri_render(int obj, int p2, int p3, int p4, int p5, s8 visible);
void wctemplebri_hitDetect(void);
void wctemplebri_release(void);
void wctemplebri_initialise(void);
int wctemplebri_interactCallback(int obj, int p2, ObjAnimUpdateState *animUpdate);
void wctemplebri_update(int obj);
void wctemplebri_init(int obj, int initData);
int wcfloortile_getExtraSize(void);
int wcfloortile_getObjectTypeId(void);
void wcfloortile_free(void);
void wcfloortile_render(int obj, int p2, int p3, int p4, int p5, s8 visible);
void wcfloortile_hitDetect(void);
void wcfloortile_init(int obj);
void wcfloortile_release(void);
void wcfloortile_initialise(void);
void wcfloortile_update(int obj);
int wcapertures_getExtraSize(void);
int wcapertures_getObjectTypeId(int obj);
void wcapertures_free(int obj);
void wcapertures_render(int obj, int p2, int p3, int p4, int p5, s8 visible);
void wcapertures_hitDetect(int obj);
void wcapertures_release(void);
void wcapertures_initialise(void);
int wcapertures_interactCallback(int obj, int p2, ObjAnimUpdateState *animUpdate);
void wcapertures_init(int obj, int initData);
void wcapertures_update(int obj);
int waterflowwe_getExtraSize(void);
int waterflowwe_getObjectTypeId(void);
void waterflowwe_init(int obj, u8 *setup);
void waterflowwe_free(int obj);
void waterflowwe_render(int obj, int p2, int p3, int p4, int p5, s8 visible);
void waterflowwe_hitDetect(void);
void waterflowwe_update(int obj);
void waterflowwe_release(void);
void waterflowwe_initialise(void);
int suntemple_getExtraSize(void);
int suntemple_getObjectTypeId(void);
void suntemple_free(void);
void suntemple_render(int obj, int p2, int p3, int p4, int p5, s8 visible);
void suntemple_hitDetect(int obj);
int suntemple_interactCallback(int obj, int p2, ObjAnimUpdateState *animUpdate);
void suntemple_init(u8 *obj, u8 *setup);
void suntemple_update(int obj);
void suntemple_release(void);
void suntemple_initialise(void);
int wctemple_getExtraSize(void);
int wctemple_getObjectTypeId(void);
void wctemple_free(void);
void wctemple_render(int obj, int p2, int p3, int p4, int p5, s8 visible);
void wctemple_hitDetect(void);
void wctemple_update(int obj);
void wctemple_init(int obj, int setup);
void wctemple_release(void);
void wctemple_initialise(void);
int dll_28B_substateHandler0(void);
int dll_28B_stateHandler0(void);
int dll_28B_getExtraSize(void);
int dll_28B_getObjectTypeId(void);
void dll_28B_hitDetect_nop(void);
void dll_28B_release_nop(void);
int dll_299_getExtraSize_ret_2(void);
int dll_299_getObjectTypeId(void);
void dll_299_render_nop(void);
void dll_299_hitDetect_nop(void);
void dll_299_release_nop(void);
void dll_299_initialise_nop(void);
int Dummy29E_getExtraSize(void);
int Dummy29E_getObjectTypeId(void);
void Dummy29E_free(void);
void Dummy29E_render(void);
void Dummy29E_hitDetect(void);
void Dummy29E_update(void);
void Dummy29E_init(void);
void Dummy29E_release(void);
void Dummy29E_initialise(void);
int dll_2A3_getExtraSize_ret_12(void);
int dll_2A3_getObjectTypeId(void);
void dll_2A3_release_nop(void);
void dll_2A3_initialise_nop(void);
int dll_2A4_getExtraSize_ret_12(void);
int dll_2A4_getObjectTypeId(void);
void dll_2A4_free_nop(void);
void dll_2A4_hitDetect_nop(void);
void dll_2A4_release_nop(void);
void dll_2A4_initialise_nop(void);
void dll_2A3_free(void);
void dll_2A3_render(int obj, int p2, int p3, int p4, int p5);
void dll_2A3_hitDetect(void);
void dll_2A3_update(int obj);
void dll_2A3_init(int obj);
void dll_2A4_render(int obj, int p2, int p3, int p4, int p5);
void dll_2A4_update(int obj);
void dll_2A4_init(int obj);
int pointlight_getExtraSize(void);
int pointlight_getObjectTypeId(void);
void pointlight_setEffectState(int obj, int enabled);
void pointlight_free(int obj);
void pointlight_render(int obj);
void pointlight_hitDetect(void);
void pointlight_update(int obj);
void pointlight_init(int obj, int setup);
void pointlight_release(void);
void pointlight_initialise(void);
int directionallight_getExtraSize(void);
int directionallight_getObjectTypeId(void);
void directionallight_free(int obj);
void directionallight_hitDetect(void);
void directionallight_render(int obj, int p2, int p3, int p4, int p5, f32 scale);
void directionallight_debugEdit(int obj, int state);
void directionallight_init(int obj, int setup);
void directionallight_update(int obj);
void directionallight_release(void);
void directionallight_initialise(void);
int projectedlight_getExtraSize(void);
int projectedlight_getObjectTypeId(void);
void projectedlight_free(int obj);
void projectedlight_hitDetect(void);
void projectedlight_render(void);
void projectedlight_update(int obj);
void projectedlight_init(int obj, int setup);
void projectedlight_release(void);
void projectedlight_initialise(void);
int controllight_getExtraSize(void);
int controllight_getObjectTypeId(void);
void controllight_free(void);
void controllight_hitDetect(void);
void controllight_render(void);
void controllight_init(int obj, int setup);
void controllight_update(int obj);
void controllight_release(void);
void controllight_initialise(void);
int timer_getExtraSize(void);
void timer_free(int obj);
int timer_hasExpired(int obj);
int timer_isEffectMode(int obj);
void timer_clearManualFlags(int obj);
void timer_forceStart(int obj);
void timer_addDuration(int obj, int duration);
void timer_render(int obj, int p2, int p3, int p4, int p5, f32 scale);
void timer_init(int obj, int setup);
void timer_update(int obj);
int cntcounter_getExtraSize(void);
int cntcounter_getObjectTypeId(void);
void cntcounter_free(int obj);
void cntcounter_hitDetect(void);
void cntcounter_render(void);
void cntcounter_init(int obj);
void cntcounter_update(int obj);
void cntcounter_release(void);
void cntcounter_initialise(void);
int vortex_getExtraSize(void);
int vortex_getObjectTypeId(void);
void vortex_free(int obj);
void vortex_hitDetect(void);
void vortex_init(int obj, int initData);
void vortex_update(int obj);
void vortex_release(void);
void vortex_initialise(void);
int ring_getExtraSize(void);
int ring_getObjectTypeId(void);
void ring_free(int obj);
void ring_hitDetect(void);
void ring_render(int obj, int p2, int p3, int p4, int p5, f32 scale);
void ring_release(void);
void ring_initialise(void);
void ring_init(int obj, int setup);
int cnthitobjec_getExtraSize(void);
int cnthitobjec_getObjectTypeId(void);
void cnthitobjec_free(void);
void cnthitobjec_release(void);
void cnthitobjec_initialise(void);
void cnthitobjec_render(int obj, int p2, int p3, int p4, int p5, f32 scale);
int cnthitobjec_emitHitEvents(int obj, int p2, int p3);
void cnthitobjec_hitDetect(int obj);
void cnthitobjec_init(int obj, int setup);
void cnthitobjec_update(int obj);
int dustmotesou_getExtraSize(void);
int dustmotesou_getObjectTypeId(void);
void dustmotesou_free(int obj);
void dustmotesou_hitDetect(void);
void dustmotesou_init(int obj, int setup);
void dustmotesou_update(int obj);
void dustmotesou_release(void);
void dustmotesou_initialise(void);
int brokenpipe_getExtraSize(void);
void brokenpipe_init(int obj, int setup);
void brokenpipe_update(int obj);
int softbody_getExtraSize(void);
int softbody_getObjectTypeId(void);
void softbody_free(int obj);
void softbody_render(int obj, int p2, int p3, int p4, int p5, s8 visible);
void softbody_hitDetect(void);
void softbody_init(int obj, int setup);
void softbody_release(void);
void softbody_initialise(void);
void softbody_update(int obj);
int arwbombcoll_getExtraSize(void);
int arwbombcoll_getObjectTypeId(void);
void arwbombcoll_free(void);
void arwbombcoll_hitDetect(void);
void arwbombcoll_render(int obj, int p2, int p3, int p4, int p5, f32 scale);
void arwbombcoll_init(int obj, int setup);
void arwbombcoll_release(void);
void arwbombcoll_initialise(void);
int arwgenerato_getExtraSize(void);
int arwgenerato_getObjectTypeId(void);
void arwgenerato_free(void);
void arwgenerato_hitDetect(void);
void arwgenerato_render(int obj, int p2, int p3, int p4, int p5, f32 scale);
void arwgenerato_init(int obj, int setup);
void arwgenerato_release(void);
void arwgenerato_initialise(void);
int arwblocker_getBlockState(int obj);
int arwblocker_getExtraSize(void);
int arwblocker_getObjectTypeId(void);
void arwblocker_free(void);
void arwblocker_hitDetect(void);
void arwblocker_render(int obj, int p2, int p3, int p4, int p5, f32 scale);
void arwblocker_init(int obj, int setup);
void arwblocker_release(void);
void arwblocker_initialise(void);
int arwspeedstr_getExtraSize(void);
int arwspeedstr_getObjectTypeId(void);
void arwspeedstr_free(void);
void arwspeedstr_hitDetect(void);
void arwspeedstr_render(int obj, int p2, int p3, int p4, int p5, f32 scale);
void arwspeedstr_init(int obj, int setup);
void arwspeedstr_release(void);
void arwspeedstr_initialise(void);
int arwproximit_getExtraSize(void);
int arwproximit_getObjectTypeId(void);
void arwproximit_free(int obj);
void arwproximit_hitDetect(void);
void arwproximit_render(int obj, int p2, int p3, int p4, int p5, f32 scale);
void arwproximit_init(int obj, int setup, int p3);
void arwproximit_release(void);
void arwproximit_initialise(void);
int arwarwingbo_getExtraSize(void);
int arwarwingbo_getObjectTypeId(void);
void arwarwingbo_free(int obj);
void arwarwingbo_hitDetect(void);
void arwarwingbo_render(int obj, int p2, int p3, int p4, int p5, s8 visible);
void arwarwingbo_init(int obj, int setup);
void arwarwingbo_setActiveVisible(int obj, u8 active, u8 visible);
void arwarwingbo_release(void);
void arwarwingbo_initialise(void);
int getArwing(void);
int arwarwing_getExtraSize(void);
int arwarwing_getObjectTypeId(void);
void arwarwing_free(int obj);
void arwarwing_release(void);
void arwarwing_initialise(void);
int arwarwinggu_getExtraSize(int obj);
int arwarwinggu_getObjectTypeId(void);
void arwarwinggu_free(void);
void arwarwinggu_render(void);
void arwarwinggu_hitDetect(void);
void arwarwinggu_init(int obj);
void arwarwinggu_setActiveVisible(int obj, u8 active, u8 visible);
void arwarwinggu_release(void);
void arwarwinggu_initialise(void);
int arwingandrossstuff_getExtraSize(void);
int arwingandrossstuff_getObjectTypeId(void);
void arwingandrossstuff_free(int obj);
void arwingandrossstuff_render(int obj, int p2, int p3, int p4, int p5, s8 visible);
void arwingandrossstuff_release(void);
void arwingandrossstuff_initialise(void);
void arwingandrossstuff_hitDetect(int obj);
int arwlevelcon_getExtraSize(void);
int arwlevelcon_getObjectTypeId(void);
void arwlevelcon_free(void);
void arwlevelcon_render(int obj, int p2, int p3, int p4, int p5);
void arwlevelcon_hitDetect(void);
void arwlevelcon_commitRingChoice(int obj);
void arwlevelcon_release(void);
void arwlevelcon_initialise(void);
int arwsquadron_getExtraSize(void);
int arwsquadron_getObjectTypeId(void);
void arwsquadron_free(void);
void arwsquadron_render(int obj, int p2, int p3, int p4, int p5);
void arwsquadron_hitDetect(void);
void arwprojectile_setLifetime(int obj, int lifetime);
void arwprojectile_placeForward(int obj, f32 dist);
void arwingandrossstuff_init(int obj, u8 *setup);
void arwlevelcon_init(int obj, u8 *setup);
int arwlevelcon_ringEventCallback(int obj, int p2, int data);
void arwarwing_render(int obj, int p2, int p3, int p4, int p5);
void arwarwing_hitDetect(int obj);
void arwarwinggu_update(int obj);
void arwingandrossstuff_update(int obj);
void arwlevelcon_update(int obj);
void arwgenerato_update(int obj);
int andross_getExtraSize(void);
int andross_getObjectTypeId(void);
void andross_free(int obj);
void andross_hitDetect(void);
void andross_render(int obj, int p2, int p3, int p4, int p5);
void andross_setPartSignal(int obj, int signal);
int androsshand_getExtraSize(void);
int androsshand_getObjectTypeId(void);
void androsshand_free(void);
void androsshand_render(int obj, int p2, int p3, int p4, int p5);
void androsshand_update(int obj);
int androssligh_getExtraSize(void);
int androssligh_getObjectTypeId(void);
void androssligh_free(void);
void androssligh_render(int obj);
void androssligh_setState(int obj, int newState, u8 force);
int andross_updateModelAlpha(int obj);
void andross_init(int obj, u8 *setup);
int androssbrain_getExtraSize(void);
int androssbrain_getObjectTypeId(void);
void androssbrain_free(void);
void androssbrain_render(int obj, int p2, int p3, int p4, int p5);
void androsshand_hitDetect(void);
void androssligh_hitDetect(void);
void androssbrain_hitDetect(void);
void androsshand_setState(int obj, int newState, u8 force);
void androssbrain_setState(int obj, int newState, u8 force);
void androsshand_handleDamage(int obj, int hand);
void androssligh_init(void);
void androssbrain_init(int obj);
void androsshand_init(int obj, u8 *setup);
void androssligh_update(int obj);
void androssligh_updateBeam(int obj, int beam);
void androssbrain_update(int obj);
int gf_levelcon_handleScriptEvents(int obj, int eventId, ObjAnimUpdateState *animUpdate);
int gf_levelcon_getExtraSize(void);
int gf_levelcon_getObjectTypeId(void);
void gf_levelcon_hitDetect(void);
void gf_levelcon_initialise(void);
void gf_levelcon_release(void);
void gf_levelcon_free(void);
void gf_levelcon_update(int obj);
void gf_levelcon_render(int obj, int p2, int p3, int p4, int p5, s8 visible);
void gf_levelcon_init(int obj);
int tree_getExtraSize(void);
int mclightning_handleScriptEvents(int obj, int unused, ObjAnimUpdateState *animUpdate);
int mclightning_getExtraSize(void);
void mclightning_free(int obj);
void mclightning_update(int obj);
void mclightning_init(int obj, u8 *setup);
void mclightning_render(int obj, int p2, int p3, int p4, int p5, f32 scale);
int cmbsrc_getExtraSize(void);
int cmbsrc_getObjectTypeId(void);
void cmbsrc_initialise(void);
void cmbsrc_release(void);
int cmbsrc_updateAndReturnZero(int obj);
int cmbsrc_getColorIndex(int obj);
void cmbsrc_setExternalActive(int obj, u8 active);
void cmbsrc_free(int obj);
void cmbsrc_render(int obj, int p2, int p3, int p4, int p5, s8 visible);
int cmbsrc_shouldActivate(int obj, int state, int setup);
int cmbsrc_shouldDeactivate(int obj, int state, int setup);
void cmbsrc_hitDetect(int obj);
int cmbsrc_cycleColor(int obj, int state);
void cmbsrc_updateVisuals(int obj, int state);
int cmbsrc_update(int obj);
void cmbsrc_init(int obj, u8 *setup);
void tree_spawnAmbientEffect(int obj, int p2, s8 index);
void tree_updateAmbientEffects(int obj, int p2);
void tree_render(int obj, int p2, int p3, int p4, int p5, s8 visible);
void tree_init(int obj, u8 *setup);
void tree_update(int obj);
void gf_levelcon_findLinkedObjects(int obj);
void dll_28B_free(int obj);
void dll_28B_render(int obj, int p2, int p3, int p4, int p5, s8 visible);
int dll_28B_substateHandler3(int obj, int ai);
int dll_28B_substateHandler2(int obj, int ai);
int dll_28B_substateHandler1(int obj, int ai);
int dll_28B_stateHandler3(int obj, int ai);
int dll_28B_stateHandler2(int obj, int ai);
int dll_28B_stateHandler1(int obj, int ai);
void dll_28B_update(int obj);
void dll_28B_init(int obj);
void dll_28B_initialise(void);
int earthwalker_animEventCallback(int obj, int unused, ObjAnimUpdateState *animUpdate, int shouldAdvanceMove);
void earthwalker_init(int obj, int setup);
void barrelgener_update(int obj);
void dll_299_free(int obj);
void dll_299_update(int obj);
void dll_299_init(int obj, int setup);
void arwarwing_setFlightHalfWidth(int arwing, f32 width);
int arwarwing_getRotY(int arwing);
void arwarwing_setRotY(int arwing, int rotY);
void arwarwing_getVelocity(int out, int arwing);
void arwarwing_setVelocity(int arwing, int in);
void arwarwing_addVelocity(int arwing, int in);
void arwarwing_clearActiveBomb(int arwing);
int arwarwing_getRequiredRingCount(int arwing);
int arwarwing_getCollectedRingCount(int arwing);
void arwarwing_addScore(int arwing, u8 amount);
int arwarwing_getScore(int arwing);
int arwarwing_getBombCount(int arwing);
int arwarwing_getMaxShield(int arwing);
int arwarwing_getShield(int arwing);
int arwarwing_incrementPickup6DACount(int arwing);
int arwarwing_incrementPickup6DBCount(int arwing);
int arwarwing_incrementPickup6D9Count(int arwing);
int arwarwing_incrementPickup6D8Count(int arwing);
int arwarwing_incrementCollectedRingCount(int arwing);
void arwarwing_addMaxShield(int arwing, int p2);
void arwarwing_addShield(int arwing, int p2);
void arwbombcoll_updateMovingAxis(int obj, RingState *state);
void arwbombcoll_handleArwingHit(int obj, RingState *state, int arwing);
int arwbombcoll_checkArwingCollision(int obj, RingState *state, int arwing);
void arwarwing_clampToFlightBounds(int obj, int state);
void arwarwing_updateFlightPhysics(int obj, int state);
void arwarwing_updateBombFire(int obj, int state);
void arwarwing_emitDamageEffects(int obj, int state);
void arwarwing_warpByCourse(int obj);
void arwprojectile_createLinkedEffect(int obj, u8 enable);
void arwblocker_update(int obj);
void arwproximit_update(int obj);
void arwsquadron_spawnProjectile(int obj, int pathIdx, int angle, u8 flag);
void arwspeedstr_update(int obj);
void arwarwing_updateWeaponFire(int obj, int state);
void arwarwing_update(int obj);
void arwarwing_spawnLaserShot(int obj, int state, int side, int level, int linkEffect);
void arwarwing_addBomb(int arwing);
void arwarwing_upgradeLaserLevel(int arwing);
int arwarwing_isExplodingOrWarping(int arwing);
int arwarwing_isBarrelRolling(int arwing);
int arwarwing_isDead(int arwing);
int mcupgrade_SeqFn(int obj, int unused, CntHitObjectAnimEvent *event);
int mcupgradema_SeqFn(int obj, int unused, ObjAnimUpdateState *animUpdate);
int mcstaffeffe_SeqFn(int obj, int unused, ObjAnimUpdateState *animUpdate);
void mcupgrade_update(int obj);
void mcupgrade_init(int obj);
void mcupgradema_update(int obj);
void mcupgradema_init(int obj);
void mcstaffeffe_render(int obj);
void mcstaffeffe_update(void);
void mcstaffeffe_init(int obj, int setup);
int drcloudper_setScale(int obj);
int drcloudper_selectActiveCloud(int obj);
void drcloudper_init(int obj, int setup);
void arwarwing_updateRollAndEngine(int obj, int state);
void fn_8022F270(int obj, int p2);
void arwarwing_clearAimSnapshot(int obj);
void arwarwing_initAttachments(int obj, int state);
void arwbombcoll_update(int obj);
void arwsquadron_init(int obj, int setup);
void fn_80231058(int obj, int src);
void fn_8023137C(int obj, f32* src);
void fn_8022ED74(int obj, int v);
void fn_8022F558(int obj, int v);
void fn_80231028(int obj, int v);
void fn_8023134C(int obj, int v);
void fn_802315EC(int obj, ARWGeneratorState *state, ARWGeneratorSetup *setup);
void fn_802317A8(int obj, ARWGeneratorState *state, ARWGeneratorSetup *setup);
void fn_8022F27C(int obj);
void fn_8022ECE0(int obj, f32 param);
void arwarwing_spawnBomb(int obj, int state, int side);
void fn_80239DD8(int p1, int p2);
void fn_80239EAC(int p1, int p2);
void fn_8023A168(int p1, int p2);
void fn_8023A87C(int p1, int p2);
void fn_8023A268(int p1, int p2, int p3);
void fn_80239FCC(int p1, int p2);
int fn_8023A6A4(int p1, f32 a, f32 b, f32 c);
void fn_8023A3E4(int p1, int p2);
int wcblock_isPlayerAwayFromStoredCell(int obj, int state, int player);
void arwarwing_resetFlightState(int obj);
void arwarwingbo_update(int obj);
void arwarwing_updateThrusters(int obj, int state);
void arwarwing_handlePathDamage(int obj, int state);
void arwarwing_handleObjectDamage(int obj, int state);
void androsshand_spawnShot(int obj, int hand, int p3);
int arwarwing_SeqFn(int obj, int unused, ObjAnimUpdateState *animUpdate);
void arwarwing_init(int obj);
void Obj_SteerVelocityTowardVector(int out, f32 *v1, f32 *v2, f32 a, f32 b, f32 c);
int Obj_UpdateRomCurveFollowVelocity(int p1, int p2, f32 a, f32 b, f32 c, int flag);
int Obj_UpdateRomCurveFollowVelocityIndexed(int p1, int p2, f32 a, f32 b, f32 c, int flag, int *p6);
void arwsquadron_applyCommandParams(int p1, int p2);
void arwsquadron_followPath(int p1, int p2);
void arwsquadron_updateVolley(int p1, int p2, int p3);
void arwsquadron_emitEffects(int p1, int p2);
void arwsquadron_handleDamage(int obj, int state);
void arwsquadron_followLeader(int p1, int p2);
void arwsquadron_update(int obj);
void Obj_SpawnHitLightAndFade(int obj, f32 *p2);
void drmusiccont_init(int obj);
void drmusiccont_update(int obj);
void drbarrelgr_init(int obj, int setup);
void drbarrelgr_update(int obj);
void drbarrelgr_render(int obj, int p2, int p3, int p4, int p5);
void drlightbea_render(int obj, int p2, int p3, int p4, int p5);
void drearthcal_update(int obj);
int Obj_UpdateLightningCluster(int obj, void **entries, int count, f32 intensity, void **light);
void Obj_SmoothTurnAnglesTowardVelocity(int a, int b, int c, f32 d, f32 e);
int Obj_PredictInterceptPoint(int obj, f32 dt, int p3, int p4);
int voxmaps_traceWorldLine(void *p1, void *p2);
void voxmaps_traceScaledVectorEnd(f32 *p1, void *p2, f32 *p3, f32 scale);
void ring_update(int obj);
void arwarwing_readControls(int obj, int state);
void arwarwing_updateBarrelRoll(int obj, int state);

#endif
