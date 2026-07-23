#define BADDIE_MOVE_STATUS_SIGNED

#include "main/dll/modgfx_interface.h"
#include "main/dll/partfx_interface.h"
#include "main/obj_placement.h"
#include "main/model_engine.h"
#include "main/model_engine_ui_api.h"
#include "main/object.h"
#include "main/dll/dll_80136a40.h"
#include "main/debug.h"
#include "main/render_envfx_api.h"
#include "main/game_object.h"
#include "main/model.h"
#include "main/maketex_api.h"
#include "main/objprint_api.h"
#include "main/objprint_character_api.h"
#include "main/objprint_render_api.h"
#include "main/dll/objfx_api.h"
#include "main/dll/player_api.h"
#include "main/dll/player_spirit_api.h"
#include "main/dll/player_state_api.h"
#include "main/dll/player_motion_api.h"
#include "main/dll/dll_00E5_shield_api.h"
#include "main/dll/dll_000D_playershadow.h"
#include "main/dll/dll_01B5_lightfoot.h"
#include "main/dll/DB/DBprotection.h"
#include "main/dll/SB/dll_01E8_sbgalleon.h"
#include "main/dll/dll_00E2_staff_api.h"
#include "main/dll/CF/staffactivated_helpers.h"
#include "main/dll/viewfinder.h"
#include "main/sky_api.h"
#include "main/object_render.h"
#include "main/dll/dll_0015_curves.h"
#include "track/intersect_api.h"
#include "main/track_dolphin_api.h"
#include "main/track_bbox_api.h"
#include "main/vecmath_distance_api.h"

#include "main/object_api.h"
#include "main/curve_eval.h"
#include "main/objhits.h"
#include "main/audio/sfx_ids.h"
#include "main/audio/stream_api.h"
#include "main/audio/sfx_keep_alive_api.h"
#include "main/audio/sfx_object_query_api.h"
#include "main/audio/sfx_play_legacy_api.h"
#include "main/audio/sfx_position_api.h"
#include "main/audio/sfx_stop_object_api.h"
#include "main/audio/music_api.h"
#include "main/gameloop_api.h"
#include "main/dll/dll_0000_gameui_api.h"
#include "main/lightmap_api.h"
#include "main/newshadows_audio_api.h"
#include "main/objfx.h"
#include "main/screen_transition.h"
#include "main/object_transform.h"
#include "ghidra_import.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/math_api.h"
#include "main/objseq_api.h"
#include "main/shader_api.h"
#include "main/pi_dolphin_api.h"
#include "main/dll/player_state.h"
#include "main/dll/baddie_control_interface.h"
#include "main/dll/boneparticleeffect_interface.h"
#include "main/camera_interface.h"
#include "main/camera.h"
#include "main/dll/rom_curve_interface.h"
#include "main/dll/waterfx_interface.h"

#include "main/game_ui_interface.h"
#include "main/mapEventTypes.h"
#include "main/mm.h"
#include "main/objanim.h"
#include "main/objanim_update.h"
#include "main/objtexture.h"
#include "main/objseq.h"
#include "main/dll/player_motion.h"
#include "main/dll/player_objects.h"
#include "main/dll/player_status.h"
#include "main/dll/player_target.h"
#include "main/resource.h"
#include "main/sky_interface.h"
#include "main/vecmath.h"
#include "main/dll/path_control_interface.h"
#include "main/frame_timing.h"
#include "main/byte_flags.h"
#include "main/pad.h"
#include "dolphin/mtx/mtx_legacy.h"
#include "dolphin/gx/GXPixel.h"
#include "dolphin/gx/GXTransform.h"
#include "string.h"
#include "main/dll/dll_002F_carryable.h"
#include "main/dll/dll_0104_smallbasket.h"
#define FEAR_TEST_METER_POSITION_INT
#include "main/dll/dll_0000_gameui.h"
#undef FEAR_TEST_METER_POSITION_INT
#include "main/dll/dll_00C9_enemy.h"
#include "main/obj_group.h"
#include "main/obj_link.h"
#include "main/obj_message.h"
#include "main/obj_path.h"
#include "main/obj_query.h"
#include "main/player_eye_anim.h"
#include "main/dll/dll_029B_arwingandrossstuff.h"
#include "main/dll/player.h"
#include "main/dll/tricky_api.h"
#include "main/gamebits.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/audio/music_trigger_ids.h"
#include "main/gamebit_ids.h"
#include "main/player_control_interface.h"
#include "main/sky.h"

#undef BADDIE_MOVE_STATUS_SIGNED


void playerUpdateTail(int unused1, int* unused2, f32* vec, int unused3, int mode, f32 angle);
void playerDoTailAnims(int obj, void* statep);
void playerUpdatePathEffectCountdown(GameObject* obj, int inner);
int playerStopRidingObject(GameObject* obj);
void playerSetHaveSpell(GameObject* obj, int spell, int set);
int fn_80297498(void);
int playerState41(GameObject* obj, int state, f32 fv);
int playerState40(int p1, int obj);
int playerState3F(int obj, int state);
int playerStateNop3E(void);
void fn_8029782C(GameObject* obj);
int playerState3D(int obj, int state, f32 fv);
int playerState3C(GameObject* obj, int state, f32 fv);
int playerState3B(GameObject* obj, int state, f32 fv);
int playerState3A(GameObject* obj, int state, f32 fv);
int playerState39(GameObject* obj, int state, f32 fv);
int playerState38(GameObject* obj, int state, f32 fv);
int playerState37(GameObject* obj, int state);
void fn_802985AC(GameObject* obj);
int playerStateSuperQuake(GameObject* obj, int state, f32 fv);
void fn_80298924(int obj);
int playerState35(GameObject* obj, int state);
int playerState34(GameObject* obj, int state);
int playerStateStaffLiftRock(int obj, int state, f32 fv);
void fn_802994A4(GameObject* obj);
int playerStateStaffBoost(GameObject* obj, int state, f32 fv);
int playerState31(GameObject* obj, int p2);
int playerState30(GameObject* obj, int state, f32 fv);
void fn_8029A420(GameObject* obj);
void fn_8029A4A8(GameObject* obj, int p2);
int playerStateFireLaser(int obj, int state, f32 fv);
int playerStateShootFireball(GameObject* obj, int state, f32 fv);
int playerStateTryCastSpell(GameObject* obj, int state, f32 fv);
int playerStateStopAimStaff(int obj, int state, f32 fv);
int playerStateStartAimStaff(GameObject* obj, int state, f32 fv);
int playerState29(GameObject* obj, int state);
int playerState28(GameObject* obj, int state, f32 fv);
void fn_8029BC08(GameObject* obj);
int playerState27(GameObject* obj, int state, f32 fv);
void fn_8029C8C8(GameObject* obj, int p2);
int playerState25(int obj, int state, f32 fv);
int playerState24(GameObject* obj, int state, f32 fv);
int playerState23(GameObject* obj, int state, f32 fv);
int playerState22(GameObject* obj, int state);
int playerState21(int obj, int state, f32 fv);
int playerState20(GameObject* obj, int state, f32 fv);
int playerState1F(GameObject* obj, int state, f32 fv);
int playerState1E(int obj, int state, f32 fv);
void fn_8029DAE0(GameObject* obj, int* p2);
int playerState1C(GameObject* obj, int state);
int playerState1B(GameObject* obj, int state, f32 fv);
int playerStateOnCloudRunner(GameObject* obj, int state);
int playerState19(GameObject* obj, int state);
void fn_8029F67C(GameObject* obj);
int playerStateOnBike(GameObject* obj, int state);
int playerState17(int p1, int state);
int playerStateMountBike(GameObject* obj, int state, f32 fv);
void fn_8029FFD0(GameObject* obj, int p2);
void objUpdateHitboxPos(int obj);
int playerStateClimbDownFromWall(GameObject* obj, int state);
int playerStateClimbUpFromWall(GameObject* obj, int state);
int playerStateClimbOntoWall(GameObject* obj, int state);
void playerPlayClimbingSound(GameObject* obj, int p2);
int playerState11(GameObject* obj, int state);
int playerStateSlideDownLadder(GameObject* obj, int state, f32 fv);
int playerStateClimbOntoLadder(GameObject* obj, int state, f32 fv);
int playerState0D(GameObject* obj, int p2);
int playerState0B(GameObject* obj, int state);
int playerStateGrabLedge(GameObject* obj, int state);
int playerState09(GameObject* obj, int state);
void fn_802A49A8(GameObject* obj);
int playerStateThrowing(GameObject* obj, int state);
void fn_802A4B4C(GameObject* obj);
int playerState06(GameObject* obj, int state);
int playerState05(GameObject* obj, int state);
int playerState04(int obj, int state, f32 fv);
int playerStateIceSpell(int obj, int state, f32 fv);
void fn_802A514C(GameObject* obj, int state);
int playerState00(int obj, int state);
s16 fn_802A71E0(int obj, int baseMoveId, int blendMoveId, int* blendAnchor, int* blendPlane,
                f32 samplePhase, f32 moveStepScale, int axis, int flags);
void fn_802A81B8(GameObject* obj, int state, f32* out);
int fn_802A8680(int p1, int p2, void* src, f32* vec, int out, int flag);
int fn_802A8EE4(int a, int b, void* c, int d, f32* e, f32 distance);
void fn_802A93F4(GameObject* obj, int p2, int p3);
void playerCastIceSpell(GameObject* unused);
int fn_802A97D0(GameObject* obj, int p2);
int playerCanCastPortalOpenSpell(GameObject* obj, int p2);
int playerCanCastQuakeSpell(GameObject* obj, int p2);
int playerCanCastBlasterSpell(GameObject* obj, int p2, int p3);
int playerIsBlasterSpellAvailable(GameObject* obj, int p2, int p3);
void fn_802A9D0C(int p1, int p2, int p3, int p4, int p5, int p6, int p7, int p8);
void fn_802AA014(GameObject* obj, int state, f32 aimInputZ, f32 zero);
void fn_802AA2B0(int obj, int state, f32 unused, f32 yoff);
void staffShootFireball(GameObject* obj, int p2, f32 unused);
void objDoTeleportAnim(GameObject* obj);
void playerDie(GameObject* obj);
void fn_802AABE4(int obj);
void playerDrawTeleportAnim(GameObject* obj);
void fn_802AAF80(GameObject* obj, int inner, int a, int b, int c);
int fn_802AB1D0(GameObject* obj);
void playerCastSpell(int a, int b, int c);
void fn_802AB5A4(GameObject* obj, int p2, int flags);
void playerCalcWaterCurrent(f32* outX, f32* outZ, f32 p3, int player);
int fn_802ABAE8(GameObject* obj, int state, int inner, f32 fv);
void fn_802ABFBC(GameObject* obj, int state, PlayerState* inner);
void fn_802AC32C(int p1, int p2, int p3);
void playerSetMovingAnims(int p1, int obj);
int fn_802ADC08(GameObject* obj, int inner, int p3);
void fn_802ADE80(GameObject* obj, int inner, int state);
int fn_802AE480(GameObject* obj, int inner, int state);
void fn_802AE650(GameObject* obj, int state, int p3);
void fn_802AE83C(int obj, int inner, int state);
void fn_802AE9C8(GameObject* obj, int inner, int state);
void fn_802AED2C(GameObject* obj, int state, int p3);
void staffAnimate(int obj, void* state, f32 dt);
void playerProcessQueuedItemCommand(GameObject* obj, int state);
void playerRunActiveSpells(GameObject* obj, int state);
void fn_802B066C(GameObject* obj, int state);
void playerStaffInit(GameObject* obj, int state);
void playerDoEyeAnims(GameObject* obj, int state);
int fn_80295A04(GameObject* obj, int sel);
void fn_802B18BC(GameObject* obj, int state, f32 fv);
void playerDoControls(GameObject* obj, int state, f32 fv);
void fn_802B1E5C(GameObject* obj, int state, int cfg, f32 dt);
void fn_802B4A9C(GameObject* obj, int inner, int inner2);
void playerAnimate(GameObject* obj, int state, f32 fv);
void fn_802B4ED8(GameObject* obj, int p2, int mode);
void playerInitFuncPtrs(void);

static inline ObjHitsPriorityState* Player_GetObjHitsState(GameObject* obj)
{
    return (ObjHitsPriorityState*)obj->anim.hitReactState;
}

typedef struct
{
    int a[6];
} UiMsgBlock;

static inline u32 playerLoadPendingHitBits(char* p)
{
    return *(u32*)p;
}

extern u8 lbl_803DC6A8[8];
extern u8 lbl_803DC6B0[2];
extern f32 lbl_803E8164;
extern const int lbl_802C2C50[6];

#define PLAYER_OBJGROUP 0x25
#define PAD_BUTTON_A  0x100

int playerStateClimbLedge(int obj, int state, f32 fv);
int player_SeqFn(int obj, int obj2, ObjSeqState* seq, int endFlag);

void playerUpdateWhileTimeStopped(int obj)
{
    PlayerState* inner = ((GameObject*)obj)->extra;
    f32 v = inner->cutsceneTimer;
    f32 zero = lbl_803E7EA4;
    if (v > zero)
    {
        inner->cutsceneTimer = v - lbl_803E7EE0;
        v = inner->cutsceneTimer;
        if (v <= zero)
        {
            cutsceneEnterExit(0, 0);
            inner->cutsceneEnded = 1;
        }
        else if (lbl_803E7EF0 == v)
        {
            cutsceneEnterExit(1, 0);
            setTimeStop(0xfd);
        }
    }
}

void playerUpdate(GameObject* obj)
{
    int inner = *(int*)&obj->extra;
    int cam = (int)Camera_GetCurrentViewSlot();
    f32 zero;
    f32 six;
    f32 t = ((PlayerState*)inner)->cutsceneTimer;
    if (t >= (six = lbl_803E7EF0))
    {
        if (t > (zero = lbl_803E7EA4))
        {
            ((PlayerState*)inner)->cutsceneTimer = t - lbl_803E7EE0;
            if (((PlayerState*)inner)->cutsceneTimer <= zero)
            {
                cutsceneEnterExit(0, 0);
                ((PlayerState*)inner)->cutsceneEnded = 1;
            }
            else if (six == ((PlayerState*)inner)->cutsceneTimer)
            {
                cutsceneEnterExit(1, 0);
                setTimeStop(0xfd);
            }
        }
    }
    else
    {
        if (getCurUiDll() == 4 || (*(u32*)&((PlayerState*)inner)->flags360 & 0x200000) != 0)
        {
            return;
        }
        if (((ByteFlags*)((char*)inner + 0x3f3))->b08 != 0)
        {
            setBButtonIcon(10);
        }
        if (obj->anim.parent == NULL && *(void**)((char*)inner + 0x7f0) == NULL &&
            isInBounds(obj->anim.localPosX, obj->anim.localPosZ) == 0)
        {
            *(int*)&((PlayerState*)inner)->baddie.targetObj = 0;
            ((PlayerState*)inner)->unk7EC = 0;
            (*gCameraInterface)->setTarget(0);
            {
                f32 z = lbl_803E7EA4;
                ((PlayerState*)inner)->baddie.animSpeedC = z;
                ((PlayerState*)inner)->baddie.animSpeedB = z;
                ((PlayerState*)inner)->baddie.animSpeedA = z;
                obj->anim.velocityX = z;
                obj->anim.velocityY = z;
                obj->anim.velocityZ = z;
            }
            fn_802AB5A4(obj, inner, 0xff);
        }
        else
        {
            f32 dt;
            f32 ym;
            int i;
            int v;
            u8 hov;
            u8* bits;
            UiMsgBlock m;
            ((PlayerState*)inner)->curAnimId = (*gCameraInterface)->getMode();
            if (((PlayerState*)inner)->curAnimId == 0x44 && ((PlayerState*)inner)->baddie.controlMode != 1)
            {
                (*gPlayerInterface)->setState(obj, (void*)inner, 1);
                {
                    f32 z = lbl_803E7EA4;
                    ((PlayerState*)inner)->baddie.animSpeedC = z;
                    ((PlayerState*)inner)->baddie.animSpeedB = z;
                    ((PlayerState*)inner)->baddie.animSpeedA = z;
                    obj->anim.velocityX = z;
                    obj->anim.velocityY = z;
                    obj->anim.velocityZ = z;
                }
                *(int*)&((PlayerState*)inner)->baddie.unk304 = (int)fn_802A514C;
            }
            ((void (*)(GameObject*, int, int))playerItemGetAnimFn)(obj, inner, inner);
            fn_802B4A9C(obj, inner, inner);
            playerStaffInit(obj, inner);
            if ((u32)gPlayerEggObject == 0 && Obj_IsLoadingLocked() != 0)
            {
                gPlayerEggObject = (int)Obj_SetupObject(Obj_AllocObjectSetup(0x18, 0x66a), 4, -1, -1,
                                                        obj->anim.parent);
                ObjLink_AttachChild(obj, (GameObject*)gPlayerEggObject, 3);
            }
            if ((u32)gPlayerEggObject != 0)
            {
                *(int*)&((GameObject*)gPlayerEggObject)->anim.parent = *(int*)&obj->anim.parent;
                if (((PlayerState*)inner)->characterId == 0)
                {
                    *(s16*)(gPlayerEggObject + 6) = *(s16*)(gPlayerEggObject + 6) | 0x4000;
                }
            }
            if (gPlayerStaffObject == NULL && Obj_IsLoadingLocked() != 0)
            {
                gPlayerStaffObject = (GameObject*)Obj_SetupObject(Obj_AllocObjectSetup(0x24, 0x773), 5, -1, -1,
                                                                  obj->anim.parent);
            }
            if (gPlayerStaffObject != NULL)
            {
                ObjPath_GetPointWorldPosition((GameObject*)obj, 4, (void*)&gPlayerStaffObject->anim.localPosX,
                                              (void*)&gPlayerStaffObject->anim.localPosY,
                                              (void*)&gPlayerStaffObject->anim.localPosZ, 0);
            }
            if (*(s16**)&obj->anim.parent != NULL)
            {
                v = (**(s16**)&obj->anim.parent & 0xffffU) - ((0x8000U - *(s16*)cam) & 0xffff);
                if (v > 0x8000)
                {
                    v -= 0xffff;
                }
                if (v < -0x8000)
                {
                    v += 0xffff;
                }
                ((PlayerState*)inner)->baddie.cameraYaw = (s16)(v + 0x8000);
            }
            else
            {
                ((PlayerState*)inner)->baddie.cameraYaw = *(s16*)cam;
            }
            ((PlayerState*)inner)->probeHitDist = lbl_803E8164;
            ((PlayerState*)inner)->cameraFlags = 0;
            *(int*)((char*)inner + 0x310) = 0;
            bits = (u8*)inner;
            for (i = 0; i < ((PlayerState*)inner)->queuedBitCount; i++)
            {
                u32 acc = playerLoadPendingHitBits((char*)inner + 0x310);
                *(u32*)((char*)inner + 0x310) = acc | (1 << bits[i + 0x8b9]);
            }
            *(u32*)&((PlayerState*)inner)->flags360 &= 0xfffff4ff;
            dt = *(f32*)&timeDelta;
            playerDoControls(obj, inner, dt);
            playerAnimate(obj, inner, dt);
            ((void (*)(GameObject*, int, f32))staffAnimate)(obj, inner, dt);
            fn_802B1E5C(obj, inner, inner, dt);
            fn_802B1BF8(obj, inner, inner, dt);
            {
                f32 t = obj->anim.velocityX;
                obj->anim.velocityX =
                    (t < lbl_803E801C) ? lbl_803E801C : ((t > lbl_803E7F10) ? lbl_803E7F10 : t);
                t = obj->anim.velocityY;
                obj->anim.velocityY =
                    (t < lbl_803E811C) ? lbl_803E811C : ((t > lbl_803E80E4) ? lbl_803E80E4 : t);
                t = obj->anim.velocityZ;
                obj->anim.velocityZ =
                    (t < lbl_803E801C) ? lbl_803E801C : ((t > lbl_803E7F10) ? lbl_803E7F10 : t);
            }
            ym = obj->anim.velocityY * dt;
            if (ym > lbl_803E7ED8)
            {
                ym = lbl_803E7ED8;
            }
            objMove((GameObject*)obj, obj->anim.velocityX * dt, ym, obj->anim.velocityZ * dt);
            *(s16*)obj = ((PlayerState*)inner)->targetYaw;
            m = *(UiMsgBlock*)lbl_802C2C50;
            (*gGameUIInterface)->isOneOfItemsBeingUsed((s32*)&m, 6);
            playerDoEyeAnims(obj, inner);
            {
                if ((((PlayerState*)inner)->stepEventTimer -= framesThisStep) < 0)
                {
                    ((PlayerState*)inner)->stepEventTimer = lbl_803DC6A8[((PlayerState*)inner)->gaitStepLevel];
                    ((PlayerState*)inner)->stepDustCount = lbl_803DC6B0[((PlayerState*)inner)->gaitStepLevel];
                }
            }
            fn_802B066C(obj, inner);
            if (((PlayerState*)inner)->teleportAnimActive == 1)
            {
                ((PlayerState*)inner)->teleportAnimProgress =
                    ((PlayerState*)inner)->teleportAnimRate * timeDelta + ((PlayerState*)inner)->teleportAnimProgress;
                if (((PlayerState*)inner)->teleportAnimProgress >= lbl_803E80C4)
                {
                    ((PlayerState*)inner)->teleportAnimProgress = lbl_803E80C4;
                    ((PlayerState*)inner)->teleportAnimRate = lbl_803E7EA4;
                }
                else if (((PlayerState*)inner)->teleportAnimProgress <= lbl_803E7EA4)
                {
                    ((PlayerState*)inner)->teleportAnimProgress = lbl_803E7EA4;
                    ((PlayerState*)inner)->teleportAnimRate = lbl_803E7F14;
                }
            }
            ((void (*)(GameObject*, int, int))fn_802AFB0C)(obj, inner, inner);
            if (((PlayerState*)inner)->heldObj != NULL &&
                Obj_IsObjectAlive((GameObject*)((PlayerState*)inner)->heldObj) == 0)
            {
                ((PlayerState*)inner)->isHoldingObject = 0;
                {
                    GameObject* held = (GameObject*)((PlayerState*)inner)->heldObj;
                    if (held != NULL)
                    {
                        s16 typ = held->anim.seqId;
                        if (typ == 0x3cf || typ == 0x662)
                        {
                            objThrowFn_80182504((GameObject*)held);
                        }
                        else
                        {
                            objSaveFn_800ea774(held);
                        }
                        *(s16*)((char*)((PlayerState*)inner)->heldObj + 0x6) =
                            *(s16*)((char*)((PlayerState*)inner)->heldObj + 0x6) & ~0x4000;
                        *(int*)((char*)((PlayerState*)inner)->heldObj + 0xf8) = 0;
                        ((PlayerState*)inner)->heldObj = 0;
                    }
                }
            }
            if ((*(u8*)(*(int*)&obj->extra + 0xc4) & 0x40) != 0)
            {
                v = (int)-(lbl_803E80E4 * timeDelta - (f32)(u32) * (u8*)((char*)obj + 0xf1));
            }
            else
            {
                v = (int)(lbl_803E80E4 * timeDelta + (f32)(u32) * (u8*)((char*)obj + 0xf1));
            }
            if (v < (u8)getSkyColorFn_80088e30(2))
            {
                v = (u8)getSkyColorFn_80088e30(2);
            }
            else if (v > 0xff)
            {
                v = 0xff;
            }
            *(u8*)((char*)obj + 0xf1) = (u8)v;
            playerRunActiveSpells(obj, inner);
            playerProcessQueuedItemCommand(obj, inner);
            if (((ByteFlags*)((char*)inner + 0x3f3))->b20 != 0 && (*gScreenTransitionInterface)->isFinished() != 0)
            {
                (*gMapEventInterface)->gotoRestartPoint();
            }
            if (((ByteFlags*)((char*)inner + 0x3f3))->b20 == 0 && (*(int*)((char*)inner + 0x310) & 1) != 0)
            {
                int po = (int)obj;
                if (Sfx_IsPlayingFromObject(
                        po, (u16)(((PlayerState*)inner)->characterId == 0 ? SFXTRIG_jump2 : SFXTRIG_sa_climb02)) == 0)
                {
                    Sfx_PlayFromObject(
                        0, (u16)(((PlayerState*)inner)->characterId == 0 ? SFXTRIG_jump2 : SFXTRIG_sa_climb02));
                }
                ((ByteFlags*)((char*)inner + 0x3f3))->b20 = 1;
                (*gScreenTransitionInterface)->start(0x1e, 1);
                Pause_ResetMenuFrameCounter();
            }
            if (gPlayerPathObject != 0 && ((ByteFlags*)((char*)inner + 0x3f4))->b40 != 0)
            {
                ((GameObject*)gPlayerPathObject)->objectFlags = ((GameObject*)gPlayerPathObject)->objectFlags & ~7;
                if (((PlayerState*)inner)->staffGrown == 0)
                {
                    ((GameObject*)gPlayerPathObject)->objectFlags = ((GameObject*)gPlayerPathObject)->objectFlags | 2;
                }
            }
            hov = ((ByteFlags*)((char*)inner + 0x3f4))->b40;
            if (hov != 0)
            {
                if (((PlayerState*)inner)->staffGrown != 0)
                {
                    setAButtonIcon(1);
                }
                else
                {
                    int ok;
                    if (((PlayerState*)inner)->heldObj != NULL || hov == 0 ||
                        ((ByteFlags*)((char*)inner + 0x3f0))->b20 != 0 ||
                        ((ByteFlags*)((char*)inner + 0x3f0))->b10 != 0)
                    {
                        ok = 0;
                    }
                    else
                    {
                        ok = 1;
                    }
                    if (ok)
                    {
                        setAButtonIcon(0xb);
                    }
                }
                if (((PlayerState*)inner)->staffGrown != 0)
                {
                    setBButtonIcon(0xc);
                }
            }
            (*gCameraInterface)->func1C(((PlayerState*)inner)->cameraFlags);
            ((PlayerState*)inner)->isHoldingObject = 0;
            ((PlayerState*)inner)->queuedBitCount = 0;
            *(s16*)obj = ((PlayerState*)inner)->targetYaw;
            objAudioFn_8006edcc((GameObject*)obj, *(int*)&((PlayerState*)inner)->baddie.eventFlags,
                                ((PlayerState*)inner)->animSoundId, (void*)(inner + 0x3c4), (void*)(inner + 4),
                                ((PlayerState*)inner)->baddie.animSpeedA, lbl_803E7EE0);
        }
    }
}

void objLoadPlayerFromSave(int obj)
{
    char* base = (char*)lbl_80332EC0;
    int off;
    int inner = *(int*)&((GameObject*)obj)->extra;
    int i;
    f32 fz;
    int me;
    u8* pathState;

    lbl_803DE459 = 0;
    ObjGroup_AddObject((int)obj, 0);
    ObjGroup_AddObject((int)obj, PLAYER_OBJGROUP);
    objSetSlot((GameObject*)obj, 0x3c);
    ObjMsg_AllocQueue((void*)obj, 0x14);
    ((GameObject*)obj)->animEventCallback = (void*)player_SeqFn;
    *(int*)&((GameObject*)obj)->anim.placementData = 0;
    ((PlayerState*)inner)->heldObj = 0;
    ((PlayerState*)inner)->playerStatus = (int)(*gMapEventInterface)->getCurCharacterState();
    *(u16*)&((PlayerState*)inner)->characterId = (*gMapEventInterface)->getCurChar();
    Obj_SetActiveModelIndex((GameObject*)obj, ((PlayerState*)inner)->characterId);
    me = (int)(*gMapEventInterface)->getCurCharPos();
    ((GameObject*)obj)->anim.rotX = (s16)(*(s8*)((char*)me + 0xc) << 8);
    ((PlayerState*)inner)->targetYaw = ((GameObject*)obj)->anim.rotX;
    ((PlayerState*)inner)->yaw = ((GameObject*)obj)->anim.rotX;
    ((PlayerState*)inner)->lastInputHeading = ((GameObject*)obj)->anim.rotX;
    fz = lbl_803E7EE0;
    ((PlayerState*)inner)->timeScale = fz;
    ((PlayerState*)inner)->queuedItemCommand = -1;
    ((PlayerState*)inner)->animState = -1;
    ((PlayerState*)inner)->targetAnimSpeed = fz;
    ((PlayerState*)inner)->yawSmoothScale = fz;
    ((PlayerState*)inner)->velSmoothRateBase = lbl_803E8144;
    ((ByteFlags*)((char*)inner + 0x3f1))->b01 = 1;
    ((PlayerState*)inner)->idleDelayTimer = lbl_803E7FA4;
    ((PlayerState*)inner)->walkAnimSoundId = 3;
    ((PlayerState*)inner)->runAnimSoundId = 4;
    ((PlayerState*)inner)->footstepSoundId = 5;
    ((PlayerState*)inner)->altAnimSoundId = 6;
    ((PlayerState*)inner)->animSoundId = ((PlayerState*)inner)->walkAnimSoundId;
    ((PlayerState*)inner)->unk8BF = 0;
    (*gPlayerInterface)->init((void*)obj, (void*)inner, 0x42, 1);
    *(int*)((char*)inner + 0x27c) = inner + 0x6f0;
    pathState = (u8*)&((PlayerState*)inner)->baddie + 4;
    (*gPathControlInterface)->init(pathState, 1, 0x400a7, 1);
    (*gPathControlInterface)->setLocalPointCollision(pathState, 1, base + 0x130, &lbl_803DC6C0, 1);
    (*gPathControlInterface)->setup(pathState, 2, base + 0x118, &lbl_803DC6B8, &lbl_803DC6A4);
    pathState[0x258] = 0x64;
    fn_802AB5A4((GameObject*)obj, inner, 0xff);
    Player_GetObjHitsState((GameObject*)(obj))->trackContactMask = 0x29;
    ((GameObject*)obj)->anim.alpha = 0xff;
    if (((GameObject*)obj)->anim.modelState != NULL)
    {
        ((GameObject*)obj)->anim.modelState->flags |= 0x4008;
    }
    (*(void (*)(GameUIInterface*))(*(int*)((char*)*gGameUIInterface + 0x14)))(*gGameUIInterface);
    *(int*)&gPlayerChildObject = (off = 0);
    ((ByteFlags*)((char*)inner + 0x3f4))->b40 = 1;
    ((PlayerState*)inner)->moveAnimTable = (int)(base + 0x190);
    ((PlayerState*)inner)->moveSlots = (int)(base + 0x854);
    ((PlayerState*)inner)->moveSlotCount = 0x1c;
    ((PlayerState*)inner)->paramCurve0 = (int)(base + 0x450);
    ((PlayerState*)inner)->unk8D0 = 0x29;
    ((PlayerState*)inner)->paramCurve1 = (int)(base + 0x4f4);
    ((PlayerState*)inner)->unk8D1 = 0x29;
    ((PlayerState*)inner)->paramCurve2 = (int)(base + 0x598);
    ((PlayerState*)inner)->unk8D2 = 0x2e;
    ((PlayerState*)inner)->paramCurve3 = (int)(base + 0x650);
    ((PlayerState*)inner)->unk8D3 = 0x29;
    ((PlayerState*)inner)->paramCurve4 = (int)(base + 0x6f4);
    ((PlayerState*)inner)->unk8D4 = 0x2e;
    ((PlayerState*)inner)->curveSpeedScale = lbl_803E7ED8;
    for (i = 0; i < ((PlayerState*)inner)->moveSlotCount; i++)
    {
        int da;
        *(int*)(((PlayerState*)inner)->moveSlots + off + 0x64) = (int)mmAlloc(0x800, 0x1a, 0);
        da = ((PlayerState*)inner)->moveSlots + off;
        objGetWeaponDa((u8*)obj, ((GameObject*)obj)->anim.seqId, (ObjWeaponDaTable*)(da + 0x60),
                       ((s16*)(base + 0x7fc))[*(s16*)((char*)da + 0x2)], 0);
        off += 0xb0;
    }
    fn_802AABE4(obj);
    gPlayerSelectedItem = GAMEBIT_STAFF_ABILITY_FIRE_BLASTER;
    gPlayerEggObject = 0;
    base += 0x1b94;
    for (i = 0; (u32)i < 0xb; i++)
    {
        if (mainGetBit(*(s16*)base) != 0)
        {
            ((PlayerState*)inner)->staffUnlockedFlags = (u8)(((PlayerState*)inner)->staffUnlockedFlags | (1 << i));
        }
        base += 2;
    }
    if (((PlayerState*)inner)->characterId == 0)
    {
        ((PlayerState*)inner)->pathBearingEyeY = lbl_803E8168;
        ((PlayerState*)inner)->characterHeightOffset = lbl_803E816C;
    }
    else
    {
        ((PlayerState*)inner)->pathBearingEyeY = lbl_803E8170;
        ((PlayerState*)inner)->characterHeightOffset = lbl_803E8174;
    }
    gPlayerModelChain = (int)ObjModelChain_Alloc(&gPlayerModelChainConfig, 1);
    *(int*)((char*)obj + 0x108) = (int)playerDoTailAnims;
    if (gPlayerPendingHealth != 0)
    {
        int v = gPlayerPendingHealth;
        int hi;
        PlayerState* in1;
        PlayerState* in2;
        in1 = (PlayerState*)((GameObject*)obj)->extra;
        if (v < 0)
        {
            v = 0;
        }
        else if (v > 0x50)
        {
            v = 0x50;
        }
        *(s8*)(in1->playerStatus + 1) = (s8)v;
        v = gPlayerPendingHealth;
        in2 = (PlayerState*)((GameObject*)obj)->extra;
        if (v < 0)
        {
            v = 0;
        }
        else
        {
            hi = *(s8*)(in2->playerStatus + 1);
            if (v > hi)
            {
                v = hi;
            }
        }
        *(s8*)(in2->playerStatus + 0) = (s8)v;
        gPlayerPendingHealth = 0;
    }
    gPlayerHeldObject = 0;
}

void playerInitFuncPtrsEntry(void)
{
    playerInitFuncPtrs();
}

void playerInitFuncPtrs(void)
{
    int* p = gPlayerStateHandlers;
    p[0] = (int)playerState00;
    p[1] = (int)playerStateIdle;
    p[2] = (int)playerStateMoving;
    p[3] = (int)playerStateIceSpell;
    p[4] = (int)playerState04;
    p[5] = (int)playerState05;
    p[6] = (int)playerState06;
    p[7] = (int)playerStateThrowing;
    p[8] = (int)playerState08;
    p[9] = (int)playerState09;
    p[10] = (int)playerStateGrabLedge;
    p[11] = (int)playerState0B;
    p[12] = (int)playerStateClimbLedge;
    p[13] = (int)playerState0D;
    p[14] = (int)playerStateClimbOntoLadder;
    p[15] = (int)playerStateOnLadder;
    p[16] = (int)playerStateSlideDownLadder;
    p[17] = (int)playerState11;
    p[18] = (int)playerStateClimbOntoWall;
    p[19] = (int)playerStateClimbWall;
    p[20] = (int)playerStateClimbUpFromWall;
    p[21] = (int)playerStateClimbDownFromWall;
    p[22] = (int)playerStateMountBike;
    p[23] = (int)playerState17;
    p[24] = (int)playerStateOnBike;
    p[25] = (int)playerState19;
    p[26] = (int)playerStateOnCloudRunner;
    p[27] = (int)playerState1B;
    p[28] = (int)playerState1C;
    p[29] = (int)playerState1D;
    p[30] = (int)playerState1E;
    p[31] = (int)playerState1F;
    p[32] = (int)playerState20;
    p[33] = (int)playerState21;
    p[34] = (int)playerState22;
    p[35] = (int)playerState23;
    p[36] = (int)playerState24;
    p[37] = (int)playerState25;
    p[38] = (int)playerStateAttack;
    p[39] = (int)playerState27;
    p[40] = (int)playerState28;
    p[41] = (int)playerState29;
    p[42] = (int)playerStateStartAimStaff;
    p[43] = (int)playerStateStopAimStaff;
    p[44] = (int)playerStateAimStaff;
    p[45] = (int)playerStateTryCastSpell;
    p[46] = (int)playerStateShootFireball;
    p[47] = (int)playerStateFireLaser;
    p[48] = (int)playerState30;
    p[49] = (int)playerState31;
    p[50] = (int)playerStateStaffBoost;
    p[51] = (int)playerStateStaffLiftRock;
    p[52] = (int)playerState34;
    p[53] = (int)playerState35;
    p[54] = (int)playerStateSuperQuake;
    p[55] = (int)playerState37;
    p[56] = (int)playerState38;
    p[57] = (int)playerState39;
    p[58] = (int)playerState3A;
    p[59] = (int)playerState3B;
    p[60] = (int)playerState3C;
    p[61] = (int)playerState3D;
    p[62] = (int)playerStateNop3E;
    p[63] = (int)playerState3F;
    p[64] = (int)playerState40;
    p[65] = (int)playerState41;
    gPlayerDefaultStateHandler = (int)fn_80297498;
}

int Lightfoot_UpdateProximityInteractionState(int obj, int state)
{
    PlayerState* inner = ((GameObject*)obj)->extra;
    if (((PlayerState*)state)->baddie.targetObj != NULL)
    {
        if (*(u16*)((char*)*(int*)((char*)inner + 0x40c) + 0x22) < inner->proximityRange)
        {
            if (*(s8*)&((PlayerState*)state)->baddie.moveJustStartedB != 0 ||
                *(s8*)&((PlayerState*)state)->baddie.moveDone != 0 || ((PlayerState*)state)->baddie.controlMode == 0)
            {
                (*gPlayerInterface)->setState((void*)obj, (void*)state, 4);
            }
        }
        else if (*(s8*)&((PlayerState*)state)->baddie.moveJustStartedB != 0 ||
                 *(s8*)&((PlayerState*)state)->baddie.moveDone != 0)
        {
            (*gPlayerInterface)->setState((void*)obj, (void*)state, 0);
        }
    }
    return 0;
}

int Lightfoot_UpdateCompletionInteraction(int obj, int state)
{
    int data = *(int*)&((GameObject*)obj)->anim.placementData;
    int inner = *(int*)&((GameObject*)obj)->extra;
    int a4 = *(int*)((char*)inner + 0x40c);
    if (*(s8*)&((PlayerState*)state)->baddie.moveJustStartedB != 0 ||
        *(s8*)&((PlayerState*)state)->baddie.moveDone != 0)
    {
        if (mainGetBit(*(s16*)((char*)data + 0x1c)) != 0)
        {
            *(u8*)((char*)inner + 0x404) |= 1;
        }
        if ((*(u8*)((char*)inner + 0x404) & 1) != 0)
        {
            if (((PlayerState*)state)->baddie.controlMode != 3)
            {
                *(u8*)((char*)a4 + 0x2c) = 4;
                (*gPlayerInterface)->setState((void*)obj, (void*)state, 3);
            }
            if (*(u8*)((char*)a4 + 0x2c) != 0)
            {
                *(u8*)((char*)a4 + 0x2c) -= 1;
                if (*(u8*)((char*)a4 + 0x2c) == 0)
                {
                    mainSetBits(*(s16*)((char*)data + 0x1a), 1);
                    mainSetBits(*(s16*)((char*)data + 0x30), 0);
                    ((GameObject*)obj)->anim.alpha = 0;
                    ((GameObject*)obj)->anim.flags |= OBJANIM_FLAG_HIDDEN;
                    *(f32*)((char*)a4 + 0x8) = lbl_803E8178;
                    *(f32*)((char*)a4 + 0x10) = lbl_803E817C;
                }
            }
        }
        else
        {
            if (((PlayerState*)state)->baddie.controlMode != 1)
            {
                if (mainGetBit(*(s16*)((char*)data + 0x30)) != 0)
                {
                    (*gPlayerInterface)->setState((void*)obj, (void*)state, 1);
                }
            }
        }
    }
    return 0;
}

int Lightfoot_UpdateChallengeGateInteraction(int obj, int state)
{
    int inner = *(int*)&((GameObject*)obj)->extra;
    int r4c;
    int sub;
    int v;

    if (((PlayerState*)state)->baddie.targetObj != NULL)
    {
        sub = *(int*)((char*)inner + 0x40c);
        v = (s16) * (u16*)((char*)sub + 0x20);
        if (v < 0)
        {
            v = -v;
        }
        if ((u16)v < 0x1770)
        {
            r4c = *(int*)&((GameObject*)obj)->anim.placementData;
            *(u8*)&((GameObject*)obj)->anim.resetHitboxMode &= ~INTERACT_FLAG_DISABLED;
            switch (*(int*)((char*)r4c + 0x14))
            {
            case 0x46a51:
                if (mainGetBit(0xc52))
                {
                    *(u8*)&((GameObject*)obj)->anim.resetHitboxMode |= INTERACT_FLAG_DISABLED;
                }
                break;
            case 0x46a55:
                if (mainGetBit(GAMEBIT_LV_ChallengeGate2Complete))
                {
                    *(u8*)&((GameObject*)obj)->anim.resetHitboxMode |= INTERACT_FLAG_DISABLED;
                }
                break;
            case 0x49928:
                if (mainGetBit(GAMEBIT_SC_ChallengeGate3Complete))
                {
                    *(u8*)&((GameObject*)obj)->anim.resetHitboxMode |= INTERACT_FLAG_DISABLED;
                }
                break;
            }
            if ((*(u8*)&((GameObject*)obj)->anim.resetHitboxMode & INTERACT_FLAG_ACTIVATED) != 0)
            {
                buttonDisable(0, PAD_BUTTON_A);
                switch (*(int*)((char*)r4c + 0x14))
                {
                case 0x46a51:
                    if (mainGetBit(0xc38) != 0 && mainGetBit(0xc39) != 0 && mainGetBit(0xc3a) != 0)
                    {
                        if (mainGetBit(0xc52) == 0)
                        {
                            mainSetBits(0xc52, 1);
                            (*gObjectTriggerInterface)->runSequence(3, (void*)obj, -1);
                            *(u8*)((char*)sub + 0x2e) = 1;
                            *(u8*)&((GameObject*)obj)->anim.resetHitboxMode |= INTERACT_FLAG_DISABLED;
                        }
                    }
                    else
                    {
                        (*gObjectTriggerInterface)->runSequence(2, (void*)obj, -1);
                    }
                    break;
                case 0x46a55:
                    if (mainGetBit(0xc3b) != 0 && mainGetBit(0xc3c) != 0 && mainGetBit(0xc3d) != 0)
                    {
                        if (mainGetBit(GAMEBIT_LV_ChallengeGate2Complete) == 0)
                        {
                            mainSetBits(GAMEBIT_LV_ChallengeGate2Complete, 1);
                            (*gObjectTriggerInterface)->runSequence(5, (void*)obj, -1);
                            *(u8*)((char*)sub + 0x2e) = 1;
                            *(u8*)&((GameObject*)obj)->anim.resetHitboxMode |= INTERACT_FLAG_DISABLED;
                        }
                    }
                    else
                    {
                        (*gObjectTriggerInterface)->runSequence(4, (void*)obj, -1);
                    }
                    break;
                case 0x49928:
                    if (mainGetBit(0xc3e) != 0 && mainGetBit(0xc3f) != 0 && mainGetBit(0xc40) != 0)
                    {
                        if (mainGetBit(GAMEBIT_SC_ChallengeGate3Complete) == 0)
                        {
                            mainSetBits(GAMEBIT_SC_ChallengeGate3Complete, 1);
                            (*gObjectTriggerInterface)->runSequence(7, (void*)obj, -1);
                            *(u8*)((char*)sub + 0x2e) = 1;
                            *(u8*)&((GameObject*)obj)->anim.resetHitboxMode |= INTERACT_FLAG_DISABLED;
                        }
                    }
                    else
                    {
                        (*gObjectTriggerInterface)->runSequence(6, (void*)obj, -1);
                    }
                    break;
                }
            }
        }
        else
        {
            *(u8*)&((GameObject*)obj)->anim.resetHitboxMode |= INTERACT_FLAG_DISABLED;
        }
        if (*(s8*)&((PlayerState*)state)->baddie.moveJustStartedB != 0 ||
            *(s8*)&((PlayerState*)state)->baddie.moveDone != 0)
        {
            (*gPlayerInterface)->setState((void*)obj, (void*)state, 0);
        }
    }
    return 0;
}

int Lightfoot_UpdateWanderSteering(GameObject* obj, int state, f32 fv)
{
    PlayerState* inner = obj->extra;
    int sub = *(int*)((char*)inner + 0x40c);
    if (((PlayerState*)sub)->baddie.posX <= lbl_803E8180)
    {
        Sfx_PlayFromObject((int)obj, SFXTRIG_htop_hurry1);
        ((PlayerState*)sub)->baddie.posX = (f32)randomGetRange(0x78, 0xb4);
    }
    ((PlayerState*)state)->baddie.moveSpeed =
        lbl_803E8184 * (lbl_803E8188 - (f32)(u16) * (u16*)((char*)sub + 0x22) / (f32)(u16)inner->proximityRange);
    if (((PlayerState*)state)->baddie.moveSpeed < *(f32*)&lbl_803E818C)
    {
        ((PlayerState*)state)->baddie.moveSpeed = lbl_803E818C;
    }
    if (*(s8*)&((PlayerState*)state)->baddie.moveJustStartedA != 0 ||
        *(s8*)&((PlayerState*)state)->baddie.moveDone != 0)
    {
        u8 r;
        if (*(u8*)((char*)sub + 0x2c) != 0)
        {
            *(u8*)((char*)sub + 0x2c) -= 1;
        }
        else
        {
            r = (*gBaddieControlInterface)
                    ->getClearDirectionMask(obj, (void*)state, lbl_803E8190);
            if ((r & 1) == 0)
            {
                if (r & 4)
                {
                    obj->anim.rotX += 0x7ff8;
                    *(u8*)((char*)sub + 0x2c) = 3;
                }
                else if (r & 2)
                {
                    obj->anim.rotX -= 0x3ffc;
                    *(u8*)((char*)sub + 0x2c) = 3;
                }
                else if (r & 8)
                {
                    obj->anim.rotX += 0x3ffc;
                    *(u8*)((char*)sub + 0x2c) = 3;
                }
            }
        }
        ObjAnim_SetCurrentMove((int)obj, 0x14, lbl_803E8180, 0);
    }
    if (*(u8*)((char*)sub + 0x2c) == 0)
    {
        {
            f32 t = (f32)(s32)((u16) * (u16*)((char*)sub + 0x20) - 0x7fff) * timeDelta;
            obj->anim.rotX += (s16)(t * lbl_803E8194);
        }
    }
    (*gPlayerInterface)->updateAnimRootMotion(obj, (void*)state, fv, 1);
    return 0;
}

int Lightfoot_UpdateRandomTurn(int obj, int state, f32 fv)
{
    int inner = *(int*)&((GameObject*)obj)->extra;
    if (*(s8*)&((PlayerState*)state)->baddie.moveJustStartedA != 0)
    {
        Sfx_PlayFromObject(obj, *(u16*)((char*)*(int*)((char*)inner + 0x40c) + 0x2a));
        if (randomGetRange(0, 1) != 0)
        {
            ((GameObject*)obj)->anim.rotX += 0x8AA9;
        }
        else
        {
            ((GameObject*)obj)->anim.rotX -= 0x8AA9;
        }
        ObjAnim_SetCurrentMove(obj, 0x23, lbl_803E8180, 0);
    }
    ((PlayerState*)state)->baddie.moveSpeed = lbl_803E81A8;
    (*gPlayerInterface)->updateAnimRootMotion((void*)obj, (void*)state, fv, 1);
    return 0;
}

int Lightfoot_UpdateTargetAnimationCycle(GameObject* obj, int state, f32 fv)
{
    int inner = *(int*)&obj->extra;
    int a4 = *(int*)((char*)inner + 0x40c);
    void* p = ((PlayerState*)state)->baddie.targetObj;
    if (p != NULL)
    {
        fn_8003B0D0(obj, (GameObject*)p, (CharacterEyeAnimState*)(inner + 0x3ac), 0x19);
    }
    if (*(s8*)&((PlayerState*)state)->baddie.moveDone != 0 ||
        *(s8*)&((PlayerState*)state)->baddie.moveJustStartedA != 0)
    {
        int q = *(int*)&obj->anim.placementData;
        obj->anim.localPosX = *(f32*)((char*)q + 0x8);
        obj->anim.localPosZ = *(f32*)((char*)q + 0x10);
        *(u16*)((char*)a4 + 0x24) += 1;
        if (gPlayerMoveTableC[*(u16*)((char*)a4 + 0x24)] == -1)
        {
            *(u16*)((char*)a4 + 0x24) = 0;
        }
        ObjAnim_SetCurrentMove((int)obj, gPlayerMoveTableC[*(u16*)((char*)a4 + 0x24)], lbl_803E8180, 0);
    }
    ((PlayerState*)state)->baddie.moveSpeed = gPlayerMoveSpeedTable[*(u16*)((char*)a4 + 0x24)];
    (*gPlayerInterface)->updateAnimRootMotion(obj, (void*)state, fv, 1);
    return 0;
}

typedef struct LightfootButtonTimingState
{
    u8 pad00[0x18];
    u16 phase;
    u16 previousPhase2;
    u16 previousPhase;
    u8 pad1E[0x24 - 0x1E];
    u16 animationIndex;
    u8 pad26[0x2D - 0x26];
    u8 difficulty;
} LightfootButtonTimingState;
STATIC_ASSERT(offsetof(LightfootButtonTimingState, phase) == 0x18);
STATIC_ASSERT(offsetof(LightfootButtonTimingState, animationIndex) == 0x24);
STATIC_ASSERT(offsetof(LightfootButtonTimingState, difficulty) == 0x2D);

typedef struct LightfootChallengePlacement
{
    ObjPlacement base;
    u8 pad18[2];
    s16 completionGameBit;
    u8 pad1C[0x30 - 0x1C];
    s16 activeGameBit;
} LightfootChallengePlacement;
STATIC_ASSERT(offsetof(LightfootChallengePlacement, completionGameBit) == 0x1A);
STATIC_ASSERT(offsetof(LightfootChallengePlacement, activeGameBit) == 0x30);

int Lightfoot_UpdateButtonTimingChallenge(GameObject* obj, int state, f32 fv)
{
    LightfootChallengePlacement* placement;
    EmitCtrlTbl* controls = (EmitCtrlTbl*)lbl_80334EE8;
    GroundBaddieState* actor = obj->extra;
    LightfootButtonTimingState* challenge = actor->control;
    BaddieState* playerState = (BaddieState*)state;
    GameObject* target = playerState->targetObj;
    if (target != NULL)
    {
        fn_8003B0D0(obj, target, (CharacterEyeAnimState*)actor->eyeAnimState, 0x19);
    }
    if (obj->userData2 == 0)
    {
        challenge->previousPhase2 = challenge->previousPhase;
        challenge->previousPhase = challenge->phase;
        challenge->phase += (u16)(lbl_803E81AC * timeDelta);
    }
    if (challenge->animationIndex < 4)
    {
        int meterPosition =
            (s16)(lbl_803E81B0 * mathSinf(gPlayerPi2 * (f32)challenge->phase / lbl_803E81B8));
        u16 successRange = (int)(lbl_803E81B0 * controls->scales[challenge->difficulty]);
        if (obj->userData2 == 0)
        {
            if ((s16)challenge->phase * (s16)challenge->previousPhase < 0)
            {
                Sfx_PlayFromObject(0, SFXTRIG_lockon3_off);
            }
        }
        setAButtonIcon(6);
        fearTestMeterSetRange(0x60, (u8)successRange, meterPosition);
        if ((getButtonsJustPressed(0) & 0x100) && obj->userData2 == 0)
        {
            int distanceFromCenter = meterPosition < 0 ? -meterPosition : meterPosition;
            if (distanceFromCenter <= successRange)
            {
                Sfx_PlayFromObject(0, SFXTRIG_menuups16k);
                obj->userData2 = 2;
            }
            else
            {
                Sfx_PlayFromObject(0, SFXTRIG_lowoxy_beep);
                obj->userData2 = 3;
            }
            fearTestMeterSetFadeIn(0);
        }
    }
    else
    {
        fearTestMeterSetFadeIn(0);
    }
    if (playerState->moveDone != 0 || playerState->moveJustStartedA != 0)
    {
        if (playerState->moveJustStartedA != 0)
        {
            int index;
            u16* gameBit;
            challenge->difficulty = 0;
            for (index = 0, gameBit = controls->bits; index < 8; gameBit++, index++)
            {
                if (mainGetBit(*gameBit) != 0)
                {
                    challenge->difficulty += 1;
                }
            }
            challenge->phase = (u16)randomGetRange(0, 0xffff);
            challenge->previousPhase = challenge->phase;
            challenge->previousPhase2 = challenge->previousPhase;
            fearTestMeterSetRange(
                0x60, (u8)(int)(lbl_803E81BC * controls->scales[challenge->difficulty]),
                (int)(lbl_803E81B0 * mathSinf(gPlayerPi2 * (f32)challenge->phase / lbl_803E81B8)));
            fearTestMeterSetFadeIn(1);
            setAButtonIcon(6);
        }
        placement = (LightfootChallengePlacement*)obj->anim.placementData;
        if (playerState->moveJustStartedA != 0)
        {
            challenge->animationIndex = 0;
            obj->anim.localPosX = placement->base.posX;
            obj->anim.localPosZ = placement->base.posZ;
        }
        else
        {
            challenge->animationIndex += 1;
        }
        if (controls->anims[challenge->animationIndex] == -1)
        {
            challenge->animationIndex = 0;
            obj->anim.localPosX = placement->base.posX;
            obj->anim.localPosZ = placement->base.posZ;
            mainSetBits(placement->completionGameBit, 1);
            mainSetBits(placement->activeGameBit, 0);
            return 3;
        }
        ObjAnim_SetCurrentMove((int)obj, controls->anims[challenge->animationIndex], lbl_803E8180, 0);
    }
    playerState->moveSpeed = controls->blends[challenge->animationIndex];
    (*gPlayerInterface)->updateAnimRootMotion(obj, (void*)state, fv, 1);
    return 0;
}

int Lightfoot_UpdateAnimationCycle(GameObject* obj, int state, f32 fv)
{
    int inner = *(int*)&obj->extra;
    void* p = ((PlayerState*)state)->baddie.targetObj;
    int a4;
    s16* moves;
    f32* blends;
    if (p != NULL)
    {
        fn_8003B0D0(obj, (GameObject*)p, (CharacterEyeAnimState*)(inner + 0x3ac), 0x19);
    }
    a4 = *(int*)((char*)inner + 0x40c);
    moves = *(s16**)((char*)a4 + 0);
    blends = *(f32**)((char*)a4 + 4);
    if (*(s8*)&((PlayerState*)state)->baddie.moveJustStartedA != 0 ||
        *(s8*)&((PlayerState*)state)->baddie.moveDone != 0)
    {
        *(u8*)((char*)a4 + 0x2c) = 0;
        *(u16*)((char*)a4 + 0x24) += 1;
        if (moves[*(u16*)((char*)a4 + 0x24)] == -1)
        {
            *(u16*)((char*)a4 + 0x24) = 0;
        }
        if (*(s8*)&((PlayerState*)state)->baddie.moveJustStartedA != 0)
        {
            obj->anim.currentMoveProgress = (f32)randomGetRange(0, 0x63) / lbl_803E817C;
            ObjAnim_SetCurrentMove((int)obj, moves[*(u16*)((char*)a4 + 0x24)], obj->anim.currentMoveProgress,
                                   0);
        }
        else
        {
            ObjAnim_SetCurrentMove((int)obj, moves[*(u16*)((char*)a4 + 0x24)], lbl_803E8180, 0);
        }
    }
    ((PlayerState*)state)->baddie.moveSpeed = blends[*(u16*)((char*)a4 + 0x24)];
    (*gPlayerInterface)->updateAnimRootMotion(obj, (void*)state, fv, 0);
    return 0;
}

void Lightfoot_RecordCompletedChallengeTargetHit(GameObject* obj, int inner, int animState)
{
    int idx;

    if (*(u8*)((char*)animState + 0x2e) == 0)
        return;
    if ((*(u16*)((char*)inner + 0x400) & 2) == 0)
        return;

    idx = *(int*)&obj->anim.placementData;
    if (*(u32*)((char*)idx + 0x14) == 0x46A51 && mainGetBit(0xc49) == 0)
    {
        mainSetBits(0xc49, 1);
    }
    else if (*(u32*)((char*)idx + 0x14) == 0x46A55 && mainGetBit(0xc4a) == 0)
    {
        mainSetBits(0xc4a, 1);
    }
    else if (*(u32*)((char*)idx + 0x14) == 0x49928 && mainGetBit(0xc4b) == 0)
    {
        mainSetBits(0xc4b, 1);
    }
    *(u8*)((char*)animState + 0x2e) = 0;
}

void Lightfoot_UpdatePlayerInteraction(int obj, int inner, int state);
void Lightfoot_ProcessHitResponseFlags(int obj, int inner);

/*
 * Mask passed to hitDetectFn_80065e50 / hitDetectFn_800691c0 to pick what a
 * collision query tests. Low byte = behaviour flags; the high bits select the
 * map-surface type (consumed by mapLoadBlocksFn_800685cc).
 */
void Lightfoot_ProcessHitResponseFlags(int obj, int inner)
{
    if (*(int*)&((PlayerState*)inner)->baddie.eventFlags & 4)
    {
        *(int*)&((PlayerState*)inner)->baddie.eventFlags &= ~4;
        Sfx_PlayFromObject(obj, SFXTRIG_sc_spotfox02);
    }
    if (*(int*)&((PlayerState*)inner)->baddie.eventFlags & 2)
    {
        *(int*)&((PlayerState*)inner)->baddie.eventFlags &= ~2;
        Sfx_PlayFromObject(obj, SFXTRIG_sc_spotfox02);
    }
    if (*(int*)&((PlayerState*)inner)->baddie.eventFlags & 1)
    {
        *(int*)&((PlayerState*)inner)->baddie.eventFlags &= ~1;
        if (randomGetRange(0, 2) == 0)
        {
            Sfx_PlayFromObject(obj, SFXTRIG_skeep_mumb4);
        }
    }
    if (*(int*)&((PlayerState*)inner)->baddie.eventFlags & 0x80)
    {
        *(int*)&((PlayerState*)inner)->baddie.eventFlags &= ~0x80;
        Sfx_PlayFromObject(obj, SFXTRIG_wp_swdtest322);
    }
    if (*(int*)&((PlayerState*)inner)->baddie.eventFlags & 0x200)
    {
        *(int*)&((PlayerState*)inner)->baddie.eventFlags &= ~0x200;
        Sfx_PlayFromObject(obj, SFXTRIG_sk_trwhin3);
    }
    if (*(int*)&((PlayerState*)inner)->baddie.eventFlags & 0x40)
    {
        *(int*)&((PlayerState*)inner)->baddie.eventFlags &= ~0x40;
        Sfx_PlayFromObject(obj, SFXTRIG_wp_swdtest322_135);
    }
    if (*(int*)&((PlayerState*)inner)->baddie.eventFlags & 0x800)
    {
        *(int*)&((PlayerState*)inner)->baddie.eventFlags &= ~0x800;
        ObjHits_RecordObjectHit(Obj_GetPlayerObject(), (GameObject*)obj, 0x19, 2, 1);
        Sfx_PlayFromObject(obj, SFXTRIG_wp_simp1_c);
        CameraShake_Start(lbl_803E81CC, lbl_803E81D0, lbl_803E81D4);
        doRumble(lbl_803E81D8);
    }
}

void Lightfoot_ResetScriptedPosition(GameObject* obj)
{
    switch (*(int*)((char*)*(int*)&obj->anim.placementData + 0x14))
    {
    case 0x34316:
        obj->anim.worldPosX = lbl_803E81DC;
        obj->anim.worldPosY = lbl_803E81E0;
        obj->anim.worldPosZ = lbl_803E81E4;
        obj->anim.rotX = 0x2565;
        break;
    case 0x33E3C:
        obj->anim.worldPosX = lbl_803E81E8;
        obj->anim.worldPosY = lbl_803E81EC;
        obj->anim.worldPosZ = lbl_803E81F0;
        obj->anim.rotX = 0x1c42;
        break;
    case 0x33E34:
        obj->anim.worldPosX = lbl_803E81F4;
        obj->anim.worldPosY = lbl_803E81EC;
        obj->anim.worldPosZ = lbl_803E81F8;
        obj->anim.rotX = 0x1d00;
        break;
    case 0x45C47:
        obj->anim.worldPosX = lbl_803E81FC;
        obj->anim.worldPosY = lbl_803E81E0;
        obj->anim.worldPosZ = lbl_803E8200;
        obj->anim.rotX = 0x32c1;
        break;
    case 0x460B6:
        obj->anim.worldPosX = lbl_803E8204;
        obj->anim.worldPosY = lbl_803E81E0;
        obj->anim.worldPosZ = lbl_803E8208;
        obj->anim.rotX = 0x119f;
        break;
    }
}

void Lightfoot_UpdateAttachedChild(GameObject* obj, int inner)
{
    int animState = *(int*)((char*)inner + 0x40c);
    GameObject* child;
    ObjPlacement* setup;

    if (*(s16*)((char*)animState + 0x26) == *(s16*)((char*)animState + 0x28))
        return;
    if (obj->anim.alpha == 0)
        return;

    child = obj->childObjs[0];
    if (child != NULL)
    {
        ObjLink_DetachChild(obj, child);
        Obj_FreeObject(child);
    }
    if (Obj_IsLoadingLocked())
    {
        if (*(s16*)((char*)animState + 0x28) > 0)
        {
            setup = Obj_AllocObjectSetup(0x20, *(s16*)((char*)animState + 0x28));
            child = Obj_SetupObject(setup, 4, obj->anim.mapEventSlot, -1, obj->anim.parent);
            ObjLink_AttachChild(obj, child, 0);
            *(s16*)((char*)animState + 0x26) = *(s16*)((char*)animState + 0x28);
        }
    }
    else
    {
        *(s16*)((char*)animState + 0x26) = 0;
    }
}

void Lightfoot_UpdatePlayerInteraction(int obj, int inner, int state)
{
    int p = *(int*)((char*)inner + 0x40c);
    int sub = *(int*)&((GameObject*)obj)->anim.placementData;
    int mode;
    int v;

    (*gBaddieControlInterface)
        ->getTargetGeometry((GameObject*)obj, Obj_GetPlayerObject(), 0x10, (u16*)((char*)p + 0x1e),
                            (u16*)((char*)p + 0x20), (u16*)((char*)p + 0x22));
    ((PlayerState*)state)->baddie.targetDistance = (f32)(u32) * (u16*)((int)p + 0x22);
    mode = ((GameObject*)obj)->userData2;
    if (mode == 2)
    {
        (*gObjectTriggerInterface)->runSequence(0, (void*)obj, -1);
        ((GameObject*)obj)->userData2 = 1;
    }
    else if (mode == 3)
    {
        (*gObjectTriggerInterface)->runSequence(1, (void*)obj, -1);
        ((GameObject*)obj)->userData2 = 1;
    }
    else
    {
        characterDoEyeAnims((GameObject*)obj, (void*)(inner + 0x3ac));
        ((PlayerState*)state)->baddie.targetObj = Obj_GetPlayerObject();
        v = *(int*)&((PlayerState*)sub)->baddie.posX;
        if (v >= 0x49942 || v < 0x4993f)
        {
            (*gBaddieControlInterface)
                ->updateGravity((GameObject*)obj, (void*)state, lbl_803E820C, 1);
        }
        ((PlayerState*)inner)->pendingParentObj = *(int*)&((GameObject*)obj)->pendingParentObj;
        *(int*)&((GameObject*)obj)->pendingParentObj = 0;
        (*gPlayerInterface)->update((void*)obj, (void*)state, timeDelta, timeDelta, lbl_803DB0DC, lbl_803DB0D0);
        *(int*)&((GameObject*)obj)->pendingParentObj = ((PlayerState*)inner)->pendingParentObj;
        Lightfoot_ProcessHitResponseFlags(obj, inner);
    }
}

int Lightfoot_SeqFn(GameObject* obj, int unused, ObjAnimUpdateState* animUpdate)
{
    int inner = *(int*)&obj->extra;
    int placement = *(int*)&obj->anim.placementData;
    int timerRec;
    int mode;
    u8 i;
    u8 j;
    f32 scale;
    f32 zero;
    f32 fv;
    f32 snd[3];
    f32 arr[6];

    timerRec = *(int*)((char*)inner + 0x40c);
    fv = *(f32*)((char*)timerRec + 0x10);
    if (fv != (zero = lbl_803E8180))
    {
        *(f32*)((char*)timerRec + 0x10) = fv - timeDelta;
        if (*(f32*)((char*)timerRec + 0x10) <= zero)
        {
            Obj_FreeObject((GameObject*)obj);
        }
    }
    for (i = 0; i < animUpdate->eventCount; i++)
    {
        switch (animUpdate->eventIds[i])
        {
        case 1:
            *(u8*)((char*)inner + 0x404) = *(u8*)((char*)inner + 0x404) | 1;
            mainSetBits(*(s16*)((char*)placement + 0x1c), 1);
            arr[3] = lbl_803E8180;
            arr[4] = lbl_803E81C4;
            arr[5] = lbl_803E8180;
            j = 0x19;
            scale = lbl_803E8210;
            for (; j != 0; j--)
            {
                fn_80098B18(obj, scale * obj->anim.rootMotionScale, 3, 0, 0, arr);
            }
            break;
        }
    }
    if (*(s16*)((char*)placement + 0x1a) == 0x64c)
    {
        Lightfoot_UpdatePlayerInteraction((int)obj, inner, inner);
        if ((*(u8*)((char*)inner + 0x404) & 1) != 0 && (obj->objectFlags & OBJECT_OBJFLAG_RENDERED) != 0)
        {
            timerRec = *(int*)((char*)inner + 0x40c);
            *(f32*)((char*)timerRec + 0xc) = *(f32*)((char*)timerRec + 0xc) - timeDelta;
            if (*(f32*)((char*)timerRec + 0xc) <= lbl_803E8180)
            {
                mode = 3;
                *(f32*)((char*)timerRec + 0xc) = *(f32*)((char*)timerRec + 0xc) + lbl_803E81C0;
            }
            else
            {
                mode = 0;
            }
            snd[0] = lbl_803E8180;
            snd[1] = lbl_803E81C4;
            snd[2] = lbl_803E8180;
            Sfx_KeepAliveLoopedObjectSound((int)obj, SFXTRIG_foot_metal_scuff_455);
            fn_80098B18(obj, lbl_803E81C8 * obj->anim.rootMotionScale, 3, mode, 0, snd);
        }
    }
    *(u16*)((char*)inner + 0x400) = *(u16*)((char*)inner + 0x400) | 2;
    return 0;
}
