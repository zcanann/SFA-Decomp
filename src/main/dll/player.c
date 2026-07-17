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
#include "main/dll/player_motion_api.h"
#include "main/dll/dll_00E5_shield_api.h"
#include "main/dll/dll_01B5_lightfoot.h"
#include "main/dll/dll_00E2_staff_api.h"
#include "main/dll/CF/staffactivated_helpers.h"
#include "main/dll/viewfinder.h"
#include "main/sky_api.h"
#include "main/object_render_legacy.h"
#include "main/dll/dll_0015_curves.h"
#include "track/intersect_api.h"
#include "main/track_dolphin_api.h"
#include "main/track_bbox_api.h"
#include "main/vecmath_distance_api.h"

#define ObjHits_SyncObjectPositionIfDirtyLegacy(obj)                                                             \
    ((void (*)(u32))ObjHits_SyncObjectPositionIfDirty)((u32)(obj))
#define ObjGroup_FindNearestObjectLegacy(group, obj, distance) \
    ((int (*)())ObjGroup_FindNearestObject)((group), (obj), (distance))
#define ObjModel_SampleJointTransformLegacy(model, animState, frameSource, phase, rootMotionScale, outPosition, outRotation) \
    ((void (*)(int, int, int, f32, f32, void*, void*))ObjModel_SampleJointTransform)( \
        (model), (animState), (frameSource), (phase), (rootMotionScale), (outPosition), (outRotation))

typedef s16 (*PlayerBlendEventLegacyFn)(int obj, int a, int b, int* p6, int* p7, f32 e, f32 f, int n, int flags);
typedef void (*PSVECScaleLegacyFn)(f32 scale, f32* src, f32* dst);

#define fn_802A71E0Legacy ((PlayerBlendEventLegacyFn)fn_802A71E0)
#define PSVECScaleLegacy  ((PSVECScaleLegacyFn)PSVECScale)
#include "main/object_api.h"
#include "main/curve_eval.h"
#include "main/objhits.h"
#include "main/audio/sfx_ids.h"
#include "main/audio/stream_api.h"
#include "main/audio/sfx_legacy.h"
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

#define Waterfx_SpawnSimpleRippleLegacy(interface, x, y, z, sourceId, radius) \
    ((void (*)(f32, f32, f32, s16, f32))(interface)->spawnSimpleRipple)(      \
        (x), (y), (z), (sourceId), (radius))
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

/* forward declarations for graduated functions */
void playerUpdateTail(int a, int b, f32* vec, int c, int mode, f32 angle);
void playerDoTailAnims(int obj, void* statep);
void playerUpdatePathEffectCountdown(GameObject* obj, int inner);
int playerStopRidingObject(GameObject* obj);
void fn_802960E4(void);
void fn_802961FC(int a, u8 type);
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
int playerStateFireLaser(int obj, int state);
int playerStateShootFireball(GameObject* obj, int state, f32 fv);
int playerStateTryCastSpell(GameObject* obj, int state, f32 fv);
int playerStateStopAimStaff(int obj, int state);
int playerStateStartAimStaff(GameObject* obj, int state);
int playerState29(GameObject* obj, int state);
int playerState28(GameObject* obj, int state, f32 fv);
void fn_8029BC08(GameObject* obj);
int playerState27(GameObject* obj, int state, f32 fv);
void fn_8029C8C8(GameObject* obj, int p2);
int playerState25(int obj, int state);
int playerState24(GameObject* obj, int state, f32 fv);
int playerState23(GameObject* obj, int state, f32 fv);
int playerState22(GameObject* obj, int state);
int playerState21(int obj, int state, f32 fv);
int playerState20(GameObject* obj, int state, f32 fv);
int playerState1F(GameObject* obj, int state, f32 fv);
int playerState1E(int obj, int state);
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
int fn_802A71E0(int obj, int a, int b, int* p6, int* p7, f32 e, f32 f, int n, int flags);
void fn_802A81B8(GameObject* obj, int state, f32* out);
int fn_802A8350(int obj, int p4, int src, int dst, int flag);
int fn_802A8680(int p1, int p2, int src, int vec, int out, int flag);
int fn_802A8EE4(int a, int b, int c, int d, int e);
void fn_802A93F4(GameObject* obj, int p2, int p3);
void playerCastIceSpell(void);
int fn_802A97D0(GameObject* obj, int p2);
int playerCanCastPortalOpenSpell(GameObject* obj, int p2);
int playerCanCastQuakeSpell(GameObject* obj, int p2);
int playerCanCastBlasterSpell(GameObject* obj, int p2, int p3);
int playerIsBlasterSpellAvailable(GameObject* obj, int p2, int p3);
void fn_802A9D0C(int p1, int p2, int p3, int p4, int p5, int p6, int p7, int p8);
void fn_802AA014(GameObject* obj);
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
void playerCalcWaterCurrent(f32* outX, f32* outZ, int player);
int fn_802ABAE8(GameObject* obj, int state, int inner, f32 fv);
void fn_802ABFBC(GameObject* obj, int state, PlayerState* inner);
void fn_802AC32C(int p1, int p2, int p3);
void playerSetMovingAnims(int p1, int obj);
int fn_802ADC08(GameObject* obj, int inner, int p3);
void fn_802ADE80(GameObject* obj, int inner, int state);
int fn_802AE480(GameObject* obj, int inner, int state);
void fn_802AE650(GameObject* obj, int state, int p3);
void fn_802AE83C(int obj, int inner);
void fn_802AE9C8(GameObject* obj, int inner, int state);
void fn_802AED2C(GameObject* obj, int state, int p3);
void staffAnimate(int obj, int state);
void playerProcessQueuedItemCommand(GameObject* obj, int state);
void playerRunActiveSpells(GameObject* obj, int state);
void fn_802B066C(GameObject* obj, int state);
void playerStaffInit(GameObject* obj, int state);
void playerDoEyeAnims(GameObject* obj, int state);
void fn_802B18BC(GameObject* obj, int state, f32 fv);
void playerDoControls(GameObject* obj, int state, f32 fv);
void fn_802B1E5C(GameObject* obj, int state, int cfg, f32 dt);
void fn_802B2DA4(void);
void fn_802B4A9C(int obj, int inner, int inner2);
void playerAnimate(int obj, int state, f32 fv);
void fn_802B4DE0(GameObject* obj);
void fn_802B4ED8(GameObject* obj, int p2, int mode);
void playerUpdateWhileTimeStopped(int obj);
void objLoadPlayerFromSave(int obj);
void playerInitFuncPtrsEntry(int obj);
void playerInitFuncPtrs(int obj);
#define LANTERNFIREFLY_OBJGROUP  0x30 /* DLL 0x10C lanternfirefly */
typedef struct
{
    int a;
    int b;
} IntPair2;

s8 playerCheckIfClimbingOntoWall(int obj, int state, int state2, void* out, f32 fv, u32 mask);
int fn_802AD2F4(GameObject* obj, int inner, int state);
int fn_802AC7DC(int obj, int state, int inner, f32 fv);


void playerUpdateTail(int a, int b, f32* vec, int c, int mode, f32 angle)
{
    f32 mtx1[12];
    f32 mtx2[12];

    switch (gPlayerSubState)
    {
    case 0:
        lbl_803DC670 = lbl_803E7E80;
        lbl_803DC674 = lbl_803E7E84;
        lbl_803DC678 = lbl_803E7E88;
        break;
    case 1:
        lbl_803DC670 = lbl_803E7E80;
        lbl_803DC674 = lbl_803E7E84;
        lbl_803DC678 = lbl_803E7E88;
        PSMTXRotRad(mtx1, 0x79, lbl_803E7E8C * fn_802943F4(lbl_803E7E90 * angle - lbl_803E7E94 * (f32)mode));
        PSMTXMultVecSR(mtx1, vec, vec);
        break;
    case 4:
        lbl_803DC670 = lbl_803E7E98;
        lbl_803DC674 = lbl_803E7E84;
        lbl_803DC678 = lbl_803E7E88;
        PSMTXRotRad(mtx1, 0x79, lbl_803E7E8C * fn_802943F4(lbl_803E7E90 * angle - lbl_803E7E94 * (f32)mode));
        PSMTXMultVecSR(mtx1, vec, vec);
        break;
    case 5:
        lbl_803DC670 = lbl_803E7E9C;
        lbl_803DC674 = lbl_803E7E84;
        lbl_803DC678 = lbl_803E7E88;
        PSMTXRotRad(mtx1, 0x79, lbl_803E7E8C * fn_802943F4(lbl_803E7E90 * angle - lbl_803E7E94 * (f32)mode));
        PSMTXMultVecSR(mtx1, vec, vec);
        break;
    case 2:
        lbl_803DC670 = lbl_803E7EA0;
        lbl_803DC674 = lbl_803E7EA4;
        lbl_803DC678 = lbl_803E7EA8;
        PSMTXRotRad(mtx1, 0x79, lbl_803E7EAC * fn_802943F4(lbl_803E7E98 * angle));
        PSMTXRotRad(mtx2, 0x78, lbl_803E7EB0);
        PSMTXConcat(mtx2, mtx1, mtx1);
        PSMTXMultVecSR(mtx1, vec, vec);
        break;
    case 3:
        lbl_803DC670 = lbl_803E7E80;
        lbl_803DC674 = lbl_803E7E84;
        lbl_803DC678 = lbl_803E7E88;
        PSMTXRotRad(mtx1, 0x79, lbl_803E7EB4 * fn_802943F4(lbl_803E7EB4 * angle - lbl_803E7EB8 * (f32)mode));
        if (mode == 1)
        {
            PSMTXRotRad(mtx2, 0x78, lbl_803E7EBC);
            PSMTXConcat(mtx2, mtx1, mtx1);
        }
        PSMTXMultVecSR(mtx1, vec, vec);
        break;
    }
}

void playerDoTailAnims(int obj, void* statep)
{
    int* state = (int*)statep;
    int v = *state;
    if ((void*)gPlayerModelChain != NULL)
    {
        ObjModelChain_SetOrigin((ObjModelChain*)gPlayerModelChain, lbl_803DC670, lbl_803DC674, lbl_803DC678);
        playerTailFn_80026b3c(state, v, gPlayerModelChain, playerUpdateTail);
    }
}
#pragma dont_inline on
void playerUpdatePathEffectCountdown(GameObject* obj, int inner)
{
    f32 outvec[3];
    struct
    {
        u8 pad[0xc];
        f32 x;
        f32 y;
        f32 z;
    } buf;
    f32 mtx[12];
    u8 cnt = ((PlayerState*)inner)->stepDustCount;

    if (cnt != 0)
    {
        if (cnt & 1)
        {
            int t;
            memcpy(mtx, (void*)ObjPath_GetPointModelMtx(obj, 5), 0x30);
            mtx[3] = lbl_803E7EA4;
            mtx[7] = lbl_803E7EA4;
            mtx[11] = lbl_803E7EA4;
            buf.x = lbl_803E7EA4;
            buf.y = lbl_803E7EA4;
            t = ((PlayerState*)inner)->stepDustCount;
            buf.z = lbl_803E7EC8 * (f32)(int)randomGetRange(t + 4, t + 8);
            PSMTXMultVec(mtx, &buf.x, outvec);
            buf.x = lbl_803E7EA4;
            buf.y = lbl_803E7ECC;
            buf.z = lbl_803E7ED0;
            ObjPath_GetPointWorldPosition((GameObject*)obj, 0xa, &buf.x, &buf.y, &buf.z, 1);
            (*gPartfxInterface)->spawnObject((void*)obj, 0x7e5, &buf, 0x200001, -1, outvec);
        }
        ((PlayerState*)inner)->stepDustCount -= 1;
    }
}
#pragma dont_inline reset

static inline ObjModel* Player_GetActiveModel(int obj)
{
    ObjAnimComponent* objAnim = (ObjAnimComponent*)obj;
    return (ObjModel*)objAnim->banks[objAnim->bankIndex];
}

static inline ObjHitsPriorityState* Player_GetObjHitsState(GameObject* obj)
{
    return (ObjHitsPriorityState*)obj->anim.hitReactState;
}
#pragma optimization_level 1
int playerStopRidingObject(GameObject* obj)
{
    PlayerState* inner = obj->extra;
    int sub;

    if ((void*)obj == NULL)
    {
        return 0;
    }
    (*gCameraInterface)->loadTriggeredCamAction(0, 1, 0);
    (*gObjectTriggerInterface)->setCamVars(0x42, 4, 0, 0);

    sub = (int)inner->focusObject;
    if ((void*)sub != NULL)
    {
        (*(void (**)(int, int))((char*)*((GameObject*)sub)->anim.dll + 0x3c))(sub, 0);
        (*gCameraInterface)->setFocus((void*)obj, 0);
        obj->anim.flags &= ~8;
        obj->anim.modelState->flags &= ~0x1000LL;
        inner->focusObject = NULL;
        obj->anim.activeMove = -1;
        (**(void (**)(int, int, int))((char*)(*gPlayerInterface) + 0x14))((int)obj, (int)inner, 1);
        *(int*)&inner->baddie.unk304 = (int)fn_802A514C;
        Music_Trigger(MUSICTRIG_inside_warlock, 0);
        Music_Trigger(MUSICTRIG_drako_2, 0);
        Music_Trigger(MUSICTRIG_starfox_rwing_1_e6, 0);
        Music_Trigger(MUSICTRIG_WLC_Puzzle, 0);
        return 1;
    }
    return 0;
}
#pragma optimization_level reset

void fn_80295918(GameObject* obj, int sel, f32 fval)
{
    int state = *(int*)&obj->extra;
    int iv = (int)fval;
    switch (sel)
    {
    case 1:
    {
        if (((PlayerState*)state)->queuedBitCount < 4)
            *((u8*)((char*)state + 0x8b9) + ((PlayerState*)state)->queuedBitCount++) = (u8)iv;
        break;
    }
    case 6:
        (*(void (*)(int, int, int))(*(int*)((char*)*gPlayerInterface + 0x14)))((int)obj, state, 0x3f);
        break;
    case 5:
        (*(void (*)(int, int, int))(*(int*)((char*)*gPlayerInterface + 0x14)))((int)obj, state, 1);
        *(int*)&((PlayerState*)state)->baddie.unk304 = (int)fn_802A514C;
        break;
    case 10:
        *(u32*)&((PlayerState*)state)->flags360 |= 0x80000LL;
        break;
    case 11:
        *(u32*)&((PlayerState*)state)->flags360 &= ~0x80000LL;
        break;
    }
}

#pragma dont_inline on
int fn_80295A04(GameObject* obj, int sel)
{
    int state = *(int*)&obj->extra;
    switch (sel)
    {
    case 1:
        if ((*(int*)((char*)state + 0x310) & 0x1000) != 0 ||
            (obj->objectFlags & OBJECT_OBJFLAG_PARENT_SLACK) != 0)
            return 0;
        return 1;
    case 2:
        switch (((PlayerState*)state)->baddie.controlMode)
        {
        case 1:
            return 0;
        case 2:
        {
            s16* list;
            s16 key;
            int i;
            i = 0;
            list = *(s16**)((char*)state + 0x3f8);
            key = obj->anim.currentMove;
            while (key != *list && i < 0x14)
            {
                list += 4;
                i += 4;
            }
            return i / 4;
        }
        default:
            return 5;
        }
    case 9:
        return *(s8*)&((PlayerState*)state)->baddie.stateTag == 3;
    case 10:
        return *(u32*)&((PlayerState*)state)->flags360 & 0x200;
    case 11:
        return *(u32*)&((PlayerState*)state)->flags360 & 0x100;
    case 13:
        return ((PlayerState*)state)->baddie.hasTarget == 1;
    case 14:
        return ((PlayerState*)state)->animState;
    case 18:
    {
        void* p = *(void**)((char*)state + 0x7f0);
        if (p != 0)
            return *(s16*)((char*)p + 0x46);
        return 0;
    }
    }
    return 0;
}
#pragma dont_inline reset

void objSetPos(GameObject* obj, f32 f1, f32 f2, f32 f3)
{
    int inner = *(int*)&obj->extra;
    obj->anim.previousWorldPosX = f1;
    obj->anim.previousLocalPosX = f1;
    obj->anim.worldPosX = f1;
    obj->anim.localPosX = f1;
    obj->anim.previousWorldPosY = f2;
    obj->anim.previousLocalPosY = f2;
    obj->anim.worldPosY = f2;
    obj->anim.localPosY = f2;
    obj->anim.previousWorldPosZ = f3;
    obj->anim.previousLocalPosZ = f3;
    obj->anim.worldPosZ = f3;
    obj->anim.localPosZ = f3;
    fn_802AB5A4(obj, inner, 7);
    (*(void (*)(int, int, int))(*(int*)((char*)*gPlayerInterface + 0x14)))((int)obj, inner, 1);
    *(int*)&((PlayerState*)inner)->baddie.unk304 = (int)fn_802A514C;
}

int objIsCurModelNotZero(void* obj)
{
    if (obj != NULL)
    {
        return ((ObjAnimComponent*)obj)->bankIndex != 0;
    }
    return 0;
}

int isTrickyNear(GameObject* obj)
{
    PlayerState* inner = obj->extra;
    return inner->curAnimId != 0x44;
}

int fn_80295C0C(GameObject* obj)
{
    PlayerState* inner = obj->extra;
    return ((inner->flags3F0 >> 1) & 1) == 0;
}

int fn_80295C24(GameObject* obj)
{
    PlayerState* inner = obj->extra;
    return inner->targetSuppressTimer > lbl_803E7EA4;
}

int fn_80295C40(GameObject* obj)
{
    PlayerState* inner = obj->extra;
    return inner->waterDepth > lbl_803E7ED4;
}

int fn_80295C5C(GameObject* obj)
{
    PlayerState* inner = obj->extra;
    return inner->baddie.controlMode == 0x36 && ((ByteFlags*)((char*)inner + 0x3f3))->b10;
}

int fn_80295C88(GameObject* player)
{
    f32 dist = lbl_803E7EDC;
    return ObjGroup_FindNearestObject(LANTERNFIREFLY_OBJGROUP, (int)player, &dist);
}

int fn_80295CBC(GameObject* obj)
{
    PlayerState* inner = obj->extra;
    return inner->baddie.controlMode == 0x13;
}

int playerIsDisguised(GameObject* obj)
{
    PlayerState* inner = obj->extra;
    return (inner->flags3F3 >> 3) & 1;
}

int playerIsPathFollowing(GameObject* player)
{
    PlayerState* inner = player->extra;
    return (inner->flags3F4 >> 6) & 1;
}

void staffToggle(GameObject* obj, int a)
{
    PlayerState* inner = obj->extra;

    if ((void*)gPlayerPathObject == NULL)
    {
        return;
    }
    if (((ByteFlags*)((char*)inner + 0x3f4))->b40 == a)
    {
        return;
    }
    if (a == 0)
    {
        if ((void*)gPlayerPathObject != NULL)
        {
            *(s16*)((char*)gPlayerPathObject + 6) |= 0x4000;
            if ((void*)gPlayerPathObject != NULL && ((ByteFlags*)((char*)inner + 0x3f4))->b40)
            {
                inner->staffActionRequest = 1;
                ((ByteFlags*)((char*)inner + 0x3f4))->b08 = 1;
            }
            mainSetBits(GAMEBIT_ITEM_SuperQuake_Disabled, 1);
            mainSetBits(GAMEBIT_ITEM_Spell0961_Disabled, 1);
            mainSetBits(GAMEBIT_ITEM_SharpClawDisguise_Disabled, 1);
            mainSetBits(GAMEBIT_ITEM_StaffBooster_Disabled, 1);
            mainSetBits(GAMEBIT_ITEM_Spell0965_Disabled, 1);
            mainSetBits(GAMEBIT_ITEM_FireBlaster_Disabled, 1);
            mainSetBits(GAMEBIT_ITEM_PortalSpell_Disabled, 1);
        }
    }
    else
    {
        if ((void*)gPlayerPathObject != NULL)
        {
            if ((void*)gPlayerPathObject != NULL && ((ByteFlags*)((char*)inner + 0x3f4))->b40)
            {
                inner->staffActionRequest = 4;
                ((ByteFlags*)((char*)inner + 0x3f4))->b08 = 1;
            }
            *(s16*)((char*)gPlayerPathObject + 6) &= ~0x4000;
            mainSetBits(GAMEBIT_ITEM_SuperQuake_Disabled, 0);
            mainSetBits(GAMEBIT_ITEM_Spell0961_Disabled, 0);
            mainSetBits(GAMEBIT_ITEM_SharpClawDisguise_Disabled, 0);
            mainSetBits(GAMEBIT_ITEM_StaffBooster_Disabled, 0);
            mainSetBits(GAMEBIT_ITEM_Spell0965_Disabled, 0);
            mainSetBits(GAMEBIT_ITEM_FireBlaster_Disabled, 0);
            mainSetBits(GAMEBIT_ITEM_PortalSpell_Disabled, 0);
        }
    }
    ((ByteFlags*)((char*)inner + 0x3f4))->b40 = a;
}

void playerSetDisguised(GameObject* obj, int mode)
{
    int inner = *(int*)&obj->extra;
    int oldModel;
    int newModel;
    void* tricky;

    objModelGetVecFn_800395d8(obj, 0);
    objModelGetVecFn_800395d8(obj, 9);
    if (mode != 0)
    {
        staffToggle(obj, 0);
        ((ByteFlags*)((char*)inner + 0x3f3))->b08 = 1;
        tricky = getTrickyObject();
        if (tricky != NULL)
        {
            trickyImpress((GameObject*)tricky);
        }
        mainSetBits(GAMEBIT_PlayerIsDisguised, 1);
        Sfx_PlayFromObject((int)obj, SFXTRIG_en_lrope_powerup);
        (*gBoneParticleEffectInterface)->spawnEffect((void*)obj, 0x801, NULL, 0x50, NULL);
        oldModel = (int)Obj_GetActiveModel(obj);
        Obj_SetActiveModelIndex(obj, 2);
        newModel = (int)Obj_GetActiveModel(obj);
        memcpy((void*)*(int*)((char*)newModel + 0x2c), (void*)*(int*)((char*)oldModel + 0x2c), 0x68);
        memcpy((void*)*(int*)((char*)newModel + 0x30), (void*)*(int*)((char*)oldModel + 0x30), 0x68);
        if (mode == 2)
        {
            ((ByteFlags*)((char*)inner + 0x3f4))->b80 = 1;
        }
    }
    else
    {
        staffToggle(obj, 1);
        ((ByteFlags*)((char*)inner + 0x3f3))->b08 = 0;
        ((ByteFlags*)((char*)inner + 0x3f4))->b80 = 0;
        (*gBoneParticleEffectInterface)->spawnEffect((void*)obj, 0x801, NULL, 0x50, NULL);
        oldModel = (int)Obj_GetActiveModel(obj);
        Obj_SetActiveModelIndex(obj, 1);
        newModel = (int)Obj_GetActiveModel(obj);
        memcpy((void*)*(int*)((char*)newModel + 0x2c), (void*)*(int*)((char*)oldModel + 0x2c), 0x68);
        memcpy((void*)*(int*)((char*)newModel + 0x30), (void*)*(int*)((char*)oldModel + 0x30), 0x68);
        mainSetBits(GAMEBIT_PlayerIsDisguised, 0);
        Sfx_PlayFromObject((int)obj, SFXTRIG_en_lrope_powerup);
    }
}

int fn_8029605C(GameObject* obj, f32* p2, f32* p3)
{
    void* inner = obj->extra;
    if (inner == NULL || getCurSeqNoInt() != 0)
    {
        return 0;
    }
    if ((((PlayerState*)inner)->flags360 & 0x400) != 0u)
    {
        *p2 = ((PlayerState*)inner)->aimScreenY;
        *p3 = ((PlayerState*)inner)->aimScreenX;
        return 1;
    }
    return 0;
}

/* the player object's own group (joined at init, left on free) */
#define PLAYER_OBJGROUP 0x25
/* groups owned by other DLLs the player queries */
#define CFGUARDIAN_OBJGROUP      0x16 /* DLL 0x148 cfguardian */
#define BABYCLOUDRUNNER_OBJGROUP 0x20 /* DLL 0x14C babycloudrunner (secondary) */
#define STAFFACTIVATED_OBJ_GROUP 0x41 /* DLL 0x11C staffactivated */
#define MAGICPLANT_OBJGROUP_B    0x3e /* DLL 0xFE magicplant (group B) */

/* GameCube controller button masks (tested against PlayerState.buttons* fields) */
#define PAD_BUTTON_A  0x100
#define PAD_BUTTON_B  0x200
#define PAD_BUTTON_X  0x400
#define PAD_BUTTON_Y  0x800
#define PAD_TRIGGER_L 0x40

void fn_802960E4(void)
{
}

void fn_802960E8(GameObject* player, s16 effectId)
{
    PlayerState* inner = player->extra;
    inner->pendingBoneEffectId = effectId;
}

void fn_802960F4(GameObject* obj, f32** outFxOffsets)
{
    PlayerState* inner = obj->extra;
    if (outFxOffsets == NULL)
    {
        return;
    }
    *outFxOffsets = &inner->fxOffsetX;
}

f32 fn_8029610C(GameObject* obj)
{
    PlayerState* inner = obj->extra;
    return inner->baddie.animSpeedA;
}

int fn_80296118(GameObject* obj)
{
    int inner = *(int*)&obj->extra;
    return *(int*)&((PlayerState*)inner)->baddie.targetObj;
}

void fn_80296124(GameObject* obj, const Vec3f* position, const Vec3s* rotation, int unused)
{
    PlayerState* inner = obj->extra;
    *(u32*)&((PlayerState*)inner)->flags360 &= ~0x4000LL;
    if (position != NULL)
    {
        obj->anim.localPosX = position->x;
        obj->anim.localPosY = position->y;
        obj->anim.localPosZ = position->z;
        *(u32*)&((PlayerState*)inner)->flags360 |= 0x4000LL;
    }
    if (rotation != NULL)
    {
        s16 t = rotation->x;
        obj->anim.rotX = t;
        inner->targetYaw = t;
        inner->yaw = t;
        inner->yaw = inner->targetYaw;
        obj->anim.rotY = rotation->y;
        obj->anim.rotZ = rotation->z;
        *(u32*)&((PlayerState*)inner)->flags360 |= 0x4000LL;
    }
}

void fn_802961A4(GameObject* obj, int* outMove, f32* outChargeLevel)
{
    PlayerState* inner = obj->extra;
    *outMove = obj->anim.currentMove;
    if (inner->baddie.controlMode == 0x26)
    {
        *outChargeLevel = inner->boulderChargeLevel;
    }
    else
    {
        *outChargeLevel = inner->chargeLevel;
    }
}

void objSetXRot(GameObject* obj, int v)
{
    PlayerState* inner = obj->extra;
    obj->anim.rotX = v;
    inner->targetYaw = v;
    inner->yaw = v;
    *(u32*)&((PlayerState*)inner)->flags360 |= PLAYER_FLAG_TELEPORTED;
}

void fn_802961FC(int a, u8 type)
{
    u8 v = type;
    if (type > 2)
    {
        v = 0;
    }
    lbl_803DE459 = v;
}

f32 fn_80296214(GameObject* obj)
{
    PlayerState* inner = obj->extra;
    return inner->verticalVel;
}

void fn_80296220(GameObject* obj, f32 v)
{
    PlayerState* inner = obj->extra;
    inner->verticalVel = v;
}

int Obj_IsParentSlackClear(GameObject* obj)
{
    return (obj->objectFlags & OBJECT_OBJFLAG_PARENT_SLACK) == 0;
}

int fn_80296240(GameObject* obj)
{
    PlayerState* inner = obj->extra;
    ByteFlags* f = (ByteFlags*)((char*)inner + 0x3f0);
    s16 s;
    if (f->b04 || f->b08 || f->b20 || f->b10 || ((ByteFlags*)((char*)inner + 0x3f3))->b08)
    {
        return 0;
    }
    s = inner->baddie.controlMode;
    if (s == 1 || s == 2)
    {
        return 1;
    }
    return 0;
}

int objFn_802962b4(GameObject* obj)
{
    PlayerState* inner = obj->extra;
    ByteFlags* f = (ByteFlags*)((char*)inner + 0x3f0);
    s16 s;
    if (f->b04 || f->b08 || f->b10)
    {
        return 0;
    }
    s = inner->baddie.controlMode;
    if (s == 1 || s == 2)
    {
        return 1;
    }
    return 0;
}

int fn_8029630C(GameObject* obj)
{
    PlayerState* inner = obj->extra;
    return inner->baddie.controlMode != 0x26;
}

int objAnimFn_80296328(GameObject* obj)
{
    PlayerState* inner = ((GameObject*)obj)->extra;
    if (((((GameObject*)obj)->objectFlags & OBJECT_OBJFLAG_PARENT_SLACK) != 0 &&
         ((ByteFlags*)((char*)inner + 0x3f2))->b80 == 0) ||
        ((ByteFlags*)((char*)inner + 0x3f0))->b04 || ((ByteFlags*)((char*)inner + 0x3f0))->b08 ||
        ((ByteFlags*)((char*)inner + 0x3f0))->b20 || *(void**)((char*)inner + 0x7f8) != NULL ||
        ((ByteFlags*)((char*)inner + 0x3f0))->b02)
    {
        return 0;
    }
    if (inner->baddie.controlMode == 1 || inner->baddie.controlMode == 2 || inner->baddie.controlMode == 0x26 ||
        (inner->baddie.controlMode == 0x18 &&
         (mainGetBit(GAMEBIT_NW_SnowHorn03E3) || *(s16*)((char*)inner->focusObject + 0x46) == 0x416)) ||
        inner->baddie.targetObj != NULL)
    {
        return 1;
    }
    return 0;
}

u8 fn_80296414(GameObject* obj, GameObject* otherObj, u8* out)
{
    PlayerState* inner = obj->extra;
    *out = inner->surfaceDir;
    return inner->baddie.controlMode == 0x1c && *(u32*)&inner->contactObject == (u32)otherObj;
}

int playerGetFlags3F0Bit5(GameObject* obj)
{
    PlayerState* inner = obj->extra;
    return (inner->flags3F0 >> 5) & 1;
}

int EmissionController_IsLingering(GameObject* obj)
{
    PlayerState* inner = obj->extra;
    return inner->emissionState;
}

int fn_80296464(GameObject* player)
{
    PlayerState* inner = player->extra;
    return inner->flags360 & 1;
}

void playerSetHaveSpell(GameObject* obj, int spell, int set)
{
    PlayerState* inner = obj->extra;
    if ((u32)spell > 0xb)
    {
        return;
    }
    if (set != 0)
    {
        inner->staffUnlockedFlags |= (1 << spell);
    }
    else
    {
        inner->staffUnlockedFlags &= ~(1 << spell);
    }
    mainSetBits(gPlayerSpellGameBits[spell], set);
}

int playerHasSpell(GameObject* obj, int spell)
{
    PlayerState* inner = obj->extra;
    if ((u32)spell > 0xb)
    {
        return 0;
    }
    return inner->staffUnlockedFlags & (1 << spell);
}

void objSetAnimStateFlags(GameObject* obj, int flag, int set)
{
    PlayerState* inner = obj->extra;
    if (set != 0)
    {
        *(s8*)((char*)inner->playerStatus + 2) |= flag;
    }
    else
    {
        *(s8*)((char*)inner->playerStatus + 2) &= ~flag;
    }
}

int objGetAnimStateFlags(GameObject* obj, int flag)
{
    PlayerState* inner = obj->extra;
    return *(s8*)((char*)inner->playerStatus + 2) & flag;
}

int playerGetTimeScale(GameObject* obj, f32* out)
{
    PlayerState* inner = obj->extra;
    *out = inner->timeScale;
    return inner->unk8C4;
}

int playerSetHeldObject(GameObject* obj, GameObject* heldObj)
{
    PlayerState* inner = obj->extra;
    GameObject* sub;

    if (heldObj != NULL)
    {
        inner->heldObj = heldObj;
        (*(void (*)(int, int, int))(*(int*)((char*)*gPlayerInterface + 0x14)))((int)obj, (int)inner, 5);
        *(int*)&((PlayerState*)inner)->baddie.unk304 = (int)fn_802A4B4C;
    }
    else if (inner->heldObj != NULL)
    {
        inner->isHoldingObject = 0;
        sub = inner->heldObj;
        if (sub != NULL)
        {
            s16 id = sub->anim.seqId;
            if (id == 0x3cf || id == 0x662)
            {
                objThrowFn_80182504(sub);
            }
            else
            {
                objSaveFn_800ea774(sub);
            }
            *(s16*)((char*)inner->heldObj + 6) &= ~0x4000;
            *(int*)((char*)inner->heldObj + 0xf8) = 0;
            inner->heldObj = NULL;
        }
        *(u32*)&((PlayerState*)inner)->flags360 |= PLAYER_FLAG_TELEPORTED;
        (*(void (*)(int, int, int))(*(int*)((char*)*gPlayerInterface + 0x14)))((int)obj, (int)inner, 1);
        *(int*)&((PlayerState*)inner)->baddie.unk304 = (int)fn_802A514C;
    }
    return inner->heldObj != NULL;
}

int fn_8029669C(GameObject* obj)
{
    PlayerState* inner = obj->extra;
    return inner->baddie.controlMode == 7;
}

int fn_802966B4(GameObject* obj)
{
    PlayerState* inner = obj->extra;
    return inner->baddie.controlMode == 6;
}

GameObject* objGetFirstChild(GameObject* obj)
{
    return obj->childObjs[0];
}

int playerGetHeldObject(GameObject* obj, GameObject** outHeldObj)
{
    PlayerState* inner = obj->extra;
    *outHeldObj = inner->heldObj;
    return inner->heldObj != NULL;
}

f32 fn_802966F4(GameObject* obj)
{
    PlayerState* inner = obj->extra;
    return inner->probeHitDist;
}

int objFn_80296700(GameObject* obj)
{
    PlayerState* inner = obj->extra;
    if (inner->staffGrown != 0 && inner->staffActionRequest != 0)
    {
        return 1;
    }
    return 0;
}

void playerPutAwayStaff(GameObject* obj, int mode)
{
    PlayerState* inner = obj->extra;
    if (mode == 0)
    {
        if (gPlayerPathObject == NULL)
            return;
        if (((ByteFlags*)((char*)inner + 0x3f4))->b40 == 0)
            return;
        inner->staffActionRequest = 0;
        ((ByteFlags*)((char*)inner + 0x3f4))->b08 = 0;
    }
    else if (mode == 1)
    {
        if (gPlayerPathObject == NULL)
            return;
        if (((ByteFlags*)((char*)inner + 0x3f4))->b40 == 0)
            return;
        inner->staffActionRequest = 1;
        ((ByteFlags*)((char*)inner + 0x3f4))->b08 = 1;
    }
    else
    {
        if (gPlayerPathObject == NULL)
            return;
        if (((ByteFlags*)((char*)inner + 0x3f4))->b40 == 0)
            return;
        inner->staffActionRequest = 1;
        ((ByteFlags*)((char*)inner + 0x3f4))->b08 = 0;
    }
}

void playerPullOutStaff(GameObject* obj, int mode)
{
    PlayerState* inner = obj->extra;
    if (mode == 0)
    {
        if (gPlayerPathObject == NULL)
            return;
        if (((ByteFlags*)((char*)inner + 0x3f4))->b40 == 0)
            return;
        inner->staffActionRequest = 2;
        ((ByteFlags*)((char*)inner + 0x3f4))->b08 = 0;
    }
    else if (mode == 1)
    {
        if (gPlayerPathObject == NULL)
            return;
        if (((ByteFlags*)((char*)inner + 0x3f4))->b40 == 0)
            return;
        inner->staffActionRequest = 4;
        ((ByteFlags*)((char*)inner + 0x3f4))->b08 = 1;
    }
    else
    {
        if (gPlayerPathObject == NULL)
            return;
        if (((ByteFlags*)((char*)inner + 0x3f4))->b40 == 0)
            return;
        inner->staffActionRequest = 4;
        ((ByteFlags*)((char*)inner + 0x3f4))->b08 = 0;
    }
}

int playerGetMoney(GameObject* player)
{
    PlayerState* inner = player->extra;
    return *(u8*)((char*)inner->playerStatus + 8);
}

void playerAddMoney(GameObject* obj, int amount)
{
    PlayerState* inner = obj->extra;
    int cap;
    int total;
    if (mainGetBit(GAMEBIT_ITEM_200ScarabBag_Got))
    {
        cap = 0xc8;
    }
    else if (mainGetBit(GAMEBIT_ITEM_100ScarabBag_Got))
    {
        cap = 0x64;
    }
    else if (mainGetBit(GAMEBIT_ITEM_50ScarabBag_Got))
    {
        cap = 0x32;
    }
    else
    {
        cap = 0xa;
    }
    total = *(u8*)((char*)inner->playerStatus + 8);
    total += amount;
    if (amount > inner->maxMagicUsed)
    {
        inner->maxMagicUsed = (u8)amount;
    }
    if (total < 0)
    {
        total = 0;
    }
    else if (total > cap)
    {
        total = cap;
    }
    *(u8*)((char*)inner->playerStatus + 8) = (u8)total;
    mainSetBits(GAMEBIT_ITEM_GiveScarabs_Count, total);
}

void fn_8029697C(GameObject* obj, s16* out1, s16* out2)
{
    PlayerState* inner = obj->extra;
    *out1 = lbl_803E7EE4 * inner->aimInputX;
    if (*(void**)((char*)inner + 0x7f0) != NULL)
    {
        *out2 = lbl_803E7EE8 * inner->aimInputZ;
    }
    else
    {
        *out2 = lbl_803E7EEC * inner->aimInputZ;
    }
}

int fn_802969F0(GameObject* obj)
{
    PlayerState* inner = obj->extra;
    if (((ByteFlags*)((char*)inner + 0x3f1))->b01)
    {
        return inner->surfaceType;
    }
    return -1;
}

int playerGetCurMagic(GameObject* player)
{
    PlayerState* inner = player->extra;
    return *(s16*)((char*)inner->playerStatus + 4);
}

void playerAddRemoveMagic(GameObject* obj, int amount)
{
    PlayerState* inner = obj->extra;
    int deref = inner->playerStatus;
    int m = *(s16*)((char*)deref + 4);
    m += amount;
    if (m < 0)
    {
        m = 0;
    }
    else if (m > *(s16*)((char*)deref + 6))
    {
        m = *(s16*)((char*)deref + 6);
    }
    *(s16*)((char*)deref + 4) = (s16)m;
    if (amount > 0)
    {
        Sfx_PlayFromObject(0, SFXTRIG_id_21c);
    }
}

int playerGetMaxMagic(GameObject* obj)
{
    PlayerState* inner = obj->extra;
    return *(s16*)((char*)inner->playerStatus + 6);
}

void fn_80296A9C(GameObject* obj, int delta)
{
    PlayerState* inner = obj->extra;
    int deref = inner->playerStatus;
    int v = *(s16*)((char*)deref + 6) + delta;
    if (v < 0)
    {
        v = 0;
    }
    else if (v > 0x64)
    {
        v = 0x64;
    }
    *(s16*)((char*)deref + 6) = (s16)v;
}

int playerGetMaxHealth(GameObject* obj)
{
    PlayerState* inner = obj->extra;
    return *(s8*)((char*)inner->playerStatus + 1);
}

int playerGetCurHealth(GameObject* obj)
{
    PlayerState* inner = obj->extra;
    return *(s8*)((char*)inner->playerStatus);
}

void playerAddHealth(GameObject* obj, int amount)
{
    PlayerState* inner = obj->extra;
    int h = *(s8*)((char*)inner->playerStatus);
    h += amount;
    if (h < 0)
    {
        h = 0;
    }
    else if (h > *(s8*)((char*)inner->playerStatus + 1))
    {
        h = *(s8*)((char*)inner->playerStatus + 1);
    }
    *(s8*)((char*)inner->playerStatus) = (s8)h;
    if (*(s8*)((char*)inner->playerStatus) <= 0)
    {
        playerDie(obj);
    }
}

void saveSetOverrideHealth(int v)
{
    gPlayerPendingHealth = v;
}

void playerCancelSpell(GameObject* obj, int p2)
{
    playerCastSpell((int)obj, *(int*)&obj->extra, p2);
}

int objGetAnimState80A(GameObject* obj)
{
    void* inner = obj->extra;
    if (inner != NULL)
    {
        return ((PlayerState*)inner)->animState;
    }
    return 0;
}

void fn_80296BBC(GameObject* obj)
{
    int inner = *(int*)&obj->extra;
    *(u32*)&((PlayerState*)inner)->flags360 &= ~PLAYER_FLAG_HITDETECT;
}

void cameraGetPrevPos2(GameObject* obj, f32* x, f32* y, f32* z)
{
    int inner = *(int*)&obj->extra;
    *x = *(f32*)((char*)inner + 0x24);
    *y = *(f32*)((char*)inner + 0x28);
    *z = *(f32*)((char*)inner + 0x2c);
}

void playerLock(GameObject* obj, int lock)
{
    PlayerState* inner = obj->extra;
    if (lock != 0)
    {
        *(u32*)&((PlayerState*)inner)->flags360 |= PLAYER_FLAG_LOCKED;
    }
    else
    {
        *(u32*)&((PlayerState*)inner)->flags360 &= ~PLAYER_FLAG_LOCKED;
    }
}

int playerStatusIsPositive(GameObject* obj)
{
    PlayerState* inner = obj->extra;
    return *(s8*)((char*)inner->playerStatus) > 0;
}

int fn_80296C4C(GameObject* obj)
{
    PlayerState* inner = obj->extra;
    return (inner->flags3F3 >> 1) & 1;
}

int playerIsDead(GameObject* player)
{
    PlayerState* inner = player->extra;
    return (inner->flags3F3 >> 2) & 1;
}

void playerSetIsDead(GameObject* obj, int flag)
{
    int inner = *(int*)&obj->extra;
    ((ByteFlags*)((char*)inner + 0x3f3))->b02 = flag;
}

void playerHeal(GameObject* obj)
{
    PlayerState* inner = obj->extra;
    int deref = inner->playerStatus;
    int v = *(s8*)((char*)deref + 1);
    if (v < 0)
    {
        v = 0;
    }
    else
    {
        int hi = *(s8*)(deref + 1);
        if (v > hi)
        {
            v = hi;
        }
    }
    *(s8*)((char*)*(int*)((char*)inner + 0x35C)) = (s8)v;
    Obj_SetModelColorFadeRecursive(obj, 0x168, 0xc8, 0, 0, 1);
    ((ByteFlags*)((char*)inner + 0x3f3))->b04 = 1;
    inner->knockbackTimer = lbl_803E7EA4;
    inner->moveVariantIndex = 0xff;
}
#pragma opt_propagation off

void fn_80296D20(GameObject* obj, GameObject* parentObj)
{
    int state = (int)((GameObject*)obj)->extra;
    PlayerState* inner = ((GameObject*)obj)->extra;
    short type;

    if (((GameObject*)obj)->anim.parent == parentObj)
    {
        objHitDetectFn_80062e84((GameObject*)obj, NULL, 1);
        type = ((PlayerState*)state)->baddie.controlMode;
        if (type == 0xa || type == 0xc)
        {
            *(int*)((char*)state + 4) &= ~0x100000;
            fn_802AB5A4((GameObject*)obj, (int)inner, 5);
            ((ByteFlags*)((char*)inner + 0x3f0))->b80 = 0;
            ((ByteFlags*)((char*)inner + 0x3f0))->b10 = 0;
            ((ByteFlags*)((char*)inner + 0x3f0))->b08 = 0;
            staffFn_80170380(gPlayerStaffObject, 2);
            ((ByteFlags*)((char*)inner + 0x3f0))->b02 = 0;
            *(u32*)&((PlayerState*)inner)->flags360 |= PLAYER_FLAG_TELEPORTED;
            ObjHits_SyncObjectPositionIfDirtyLegacy((int)obj);
            ((ByteFlags*)((char*)inner + 0x3f0))->b40 = 0;
            ((ByteFlags*)((char*)inner + 0x3f0))->b04 = 1;
            ((ByteFlags*)((char*)inner + 0x3f4))->b10 = 1;
            inner->isHoldingObject = 0;
            if (*(void**)((char*)inner + 0x7f8) != NULL)
            {
                short id = ((GameObject*)inner->heldObj)->anim.seqId;
                if (id == 0x3cf || id == 0x662)
                {
                    objThrowFn_80182504((GameObject*)(inner->heldObj));
                }
                else
                {
                    objSaveFn_800ea774((GameObject*)inner->heldObj);
                }
                *(s16*)((char*)inner->heldObj + 6) &= ~0x4000;
                *(int*)((char*)inner->heldObj + 0xf8) = 0;
                inner->heldObj = 0;
            }
            (*(void (*)(int, int, int))(*(int*)((char*)*gPlayerInterface + 0x14)))((int)obj, state, 2);
            *(int*)&((PlayerState*)state)->baddie.unk304 = (int)fn_802A514C;
        }
    }
}
#pragma opt_propagation reset

void fn_80296EB4(GameObject* obj, int newParent)
{
    int oldParent = *(int*)&obj->anim.parent;
    int a0;
    int a1;
    int a2;
    int a3;
    int a4;
    int a5;
    PlayerState* inner = obj->extra;
    struct
    {
        f32 wp0[3];
        f32 wv[3];
        f32 wp2[3];
        f32 wp[3];
    } s;

    if ((void*)oldParent == (void*)newParent)
    {
        return;
    }
    if ((void*)oldParent != NULL)
    {
        ((void (*)(f32, f32, f32, f32*, f32*, f32*, int))Obj_TransformLocalPointToWorld)(
            obj->anim.localPosX, obj->anim.localPosY, obj->anim.localPosZ,
            &s.wp[0], &s.wp[1], &s.wp[2], oldParent);
        ((void (*)(f32, f32, f32, f32*, f32*, f32*, int))Obj_TransformLocalPointToWorld)(
            obj->anim.previousLocalPosX, obj->anim.previousLocalPosY,
            obj->anim.previousLocalPosZ, &s.wp2[0], &s.wp2[1], &s.wp2[2], oldParent);
        ((void (*)(f32, f32, f32, f32*, f32*, f32*, int))Obj_TransformLocalVectorToWorld)(
            obj->anim.velocityX, lbl_803E7EA4, obj->anim.velocityZ, &s.wv[0], &s.wv[1],
            &s.wv[2], oldParent);
        a0 = Angle_AddWrappedS16(obj->anim.rotX, (s16*)oldParent);
        a1 = Angle_AddWrappedS16(inner->targetYaw, (s16*)oldParent);
        a2 = Angle_AddWrappedS16(inner->yaw, (s16*)oldParent);
        a3 = Angle_AddWrappedS16(inner->prevTargetYaw, (s16*)oldParent);
        a4 = Angle_AddWrappedS16(inner->prevYaw, (s16*)oldParent);
        a5 = Angle_AddWrappedS16(inner->lastInputHeading, (s16*)oldParent);
        ((void (*)(f32, f32, f32, f32*, f32*, f32*, int))Obj_TransformLocalPointToWorld)(
            *(f32*)((char*)inner + 0x118), *(f32*)((char*)inner + 0x11c), *(f32*)((char*)inner + 0x120), &s.wp0[0],
            &s.wp0[1], &s.wp0[2], oldParent);
    }
    else
    {
        s.wp[0] = obj->anim.localPosX;
        s.wp[1] = obj->anim.localPosY;
        s.wp[2] = obj->anim.localPosZ;
        s.wp2[0] = obj->anim.previousLocalPosX;
        s.wp2[1] = obj->anim.previousLocalPosY;
        s.wp2[2] = obj->anim.previousLocalPosZ;
        s.wv[0] = obj->anim.velocityX;
        s.wv[2] = obj->anim.velocityZ;
        a0 = obj->anim.rotX;
        a1 = inner->targetYaw;
        a2 = inner->yaw;
        a3 = inner->prevTargetYaw;
        a4 = inner->prevYaw;
        a5 = inner->lastInputHeading;
        s.wp0[0] = *(f32*)((char*)inner + 0x118);
        s.wp0[1] = *(f32*)((char*)inner + 0x11c);
        s.wp0[2] = *(f32*)((char*)inner + 0x120);
    }
    if ((void*)newParent != NULL)
    {
        Obj_TransformWorldPointToLocal(s.wp[0], s.wp[1], s.wp[2], &obj->anim.localPosX,
                                       &obj->anim.localPosY, &obj->anim.localPosZ,
                                       newParent);
        Obj_TransformWorldPointToLocal(s.wp2[0], s.wp2[1], s.wp2[2], &obj->anim.previousLocalPosX,
                                       &obj->anim.previousLocalPosY,
                                       &obj->anim.previousLocalPosZ, newParent);
        Obj_TransformWorldVectorToLocal(s.wv[0], lbl_803E7EA4, s.wv[2], &obj->anim.velocityX, &s.wv[1],
                                        &obj->anim.velocityZ, newParent);
        obj->anim.rotX = Angle_SubWrappedS16(a0, (s16*)newParent);
        inner->targetYaw = Angle_SubWrappedS16(a1, (s16*)newParent);
        inner->yaw = Angle_SubWrappedS16(a2, (s16*)newParent);
        inner->prevTargetYaw = Angle_SubWrappedS16(a3, (s16*)newParent);
        inner->prevYaw = Angle_SubWrappedS16(a4, (s16*)newParent);
        inner->lastInputHeading = Angle_SubWrappedS16(a5, (s16*)newParent);
        Obj_TransformWorldPointToLocal(s.wp0[0], s.wp0[1], s.wp0[2], (f32*)((char*)inner + 0x118),
                                       (f32*)((char*)inner + 0x11c), (f32*)((char*)inner + 0x120), newParent);
    }
    else
    {
        obj->anim.localPosX = s.wp[0];
        obj->anim.localPosY = s.wp[1];
        obj->anim.localPosZ = s.wp[2];
        obj->anim.previousLocalPosX = s.wp2[0];
        obj->anim.previousLocalPosY = s.wp2[1];
        obj->anim.previousLocalPosZ = s.wp2[2];
        obj->anim.velocityX = s.wv[0];
        obj->anim.velocityZ = s.wv[2];
        obj->anim.rotX = a0;
        inner->targetYaw = a1;
        inner->yaw = a2;
        inner->prevTargetYaw = a3;
        inner->prevYaw = a4;
        inner->lastInputHeading = a5;
        *(f32*)((char*)inner + 0x118) = s.wp0[0];
        *(f32*)((char*)inner + 0x11c) = s.wp0[1];
        *(f32*)((char*)inner + 0x120) = s.wp0[2];
    }
    obj->anim.worldPosX = s.wp[0];
    obj->anim.worldPosY = s.wp[1];
    obj->anim.worldPosZ = s.wp[2];
    obj->anim.previousWorldPosX = s.wp2[0];
    obj->anim.previousWorldPosY = s.wp2[1];
    obj->anim.previousWorldPosZ = s.wp2[2];
    Player_GetObjHitsState(obj)->localPosX = obj->anim.localPosX;
    Player_GetObjHitsState(obj)->localPosY = obj->anim.localPosY;
    Player_GetObjHitsState(obj)->localPosZ = obj->anim.localPosZ;
    Player_GetObjHitsState(obj)->worldPosX = obj->anim.worldPosX;
    Player_GetObjHitsState(obj)->worldPosY = obj->anim.worldPosY;
    Player_GetObjHitsState(obj)->worldPosZ = obj->anim.worldPosZ;
    *(int*)&obj->anim.parent = newParent;
}

void playerSetInCutscene(GameObject* obj)
{
    int inner = *(int*)&obj->extra;
    ((ByteFlags*)((char*)inner + 0x3f2))->b20 = 1;
}

void playerSetCutsceneCameraFlag(GameObject* obj)
{
    int inner = *(int*)&obj->extra;
    ((ByteFlags*)((char*)inner + 0x3f2))->b40 = 1;
}

void playerSetOverrideParentSlack(GameObject* obj)
{
    int inner = *(int*)&obj->extra;
    ((ByteFlags*)((char*)inner + 0x3f2))->b80 = 1;
}

u32 playerGetStateFlag310(GameObject* obj)
{
    int inner = *(int*)&obj->extra;
    return *(int*)((char*)inner + 0x310);
}

GameObject* playerGetFocusObject(GameObject* obj)
{
    PlayerState* inner = obj->extra;
    return inner->focusObject;
}

void fn_802972B4(GameObject* obj, u32* flags, f32* p5, f32* p6, f32* p7, u16* p8)
{
    PlayerState* inner = obj->extra;
    s8 idx;
    u8 mode;
    f32 zero;

    *flags = 0;
    zero = lbl_803E7EA4;
    *p5 = zero;
    *p6 = zero;
    *p7 = zero;
    if (inner->baddie.controlMode == 0x26)
    {
        *flags |= 1;
        idx = inner->hitWindowIndex;
        if (idx != -1)
        {
            *flags |= *(int*)((inner->moveSlots + 8) + (u32)inner->moveSlotIndex * 0xb0 + idx * 4);
            *p6 = *(f32*)((inner->moveSlots + 0x70) + (u32)inner->moveSlotIndex * 0xb0 + inner->hitWindowIndex * 4);
            *p7 = *(f32*)((inner->moveSlots + 0x7c) + (u32)inner->moveSlotIndex * 0xb0 + inner->hitWindowIndex * 4);
            *p5 = *(f32*)((inner->moveSlots + 0x94) + (u32)inner->moveSlotIndex * 0xb0 + inner->hitWindowIndex * 4);
        }
        if (*(u8*)((inner->moveSlots + 0x88) + (u32)inner->moveSlotIndex * 0xb0) & 2)
        {
            if (inner->hitCount < inner->hitCountMax)
            {
                *p7 = *p6 = lbl_803E7EA4;
            }
        }
        if ((*(u8*)((inner->moveSlots + 0x88) + (u32)inner->moveSlotIndex * 0xb0) & 1) &&
            inner->cutsceneTimer >= lbl_803E7EF0)
        {
            *flags |= 0x80;
        }
    }
    mode = inner->attackVariantMode;
    if (mode == 0)
    {
        *flags |= 0x100;
    }
    else if (mode == 1)
    {
        *flags |= 0x200;
    }
    else if (mode == 2)
    {
        *flags |= 0x400;
    }
    if (inner->baddie.controlMode == 0x2e || inner->baddie.controlMode == 0x2f)
    {
        *(u32*)flags &= 0x7dLL;
        *flags |= 2;
    }
    *p8 = 0x78;
}


int fn_80297498(void)
{
    return 0x0;
}

extern f32 lbl_803E8064;
extern f32 lbl_803E8074;
extern f32 lbl_803E8030;
extern f32 lbl_803E8078;
extern f32 lbl_803E807C;
extern f32 lbl_803E8080;


int playerState41(GameObject* obj, int state, f32 fv)
{
    PlayerState* inner = obj->extra;
    inner->probeHitDist = lbl_803E7ED8;
    *(u32*)&((PlayerState*)inner)->flags360 |= 0x2000000LL;
    *(int*)((char*)state + 0) |= 0x200000;
    if (lbl_803E7EA4 == inner->verticalVel)
    {
        void* sub;
        ((ByteFlags*)((char*)inner + 0x3f0))->b80 = 0;
        ((ByteFlags*)((char*)inner + 0x3f0))->b10 = 0;
        ((ByteFlags*)((char*)inner + 0x3f0))->b08 = 0;
        staffFn_80170380(gPlayerStaffObject, 2);
        ((ByteFlags*)((char*)inner + 0x3f0))->b02 = 0;
        *(u32*)&((PlayerState*)inner)->flags360 |= PLAYER_FLAG_TELEPORTED;
        ObjHits_SyncObjectPositionIfDirtyLegacy(obj);
        ((ByteFlags*)((char*)inner + 0x3f0))->b40 = 0;
        ((ByteFlags*)((char*)inner + 0x3f0))->b04 = 1;
        ((ByteFlags*)((char*)inner + 0x3f4))->b10 = 0;
        inner->isHoldingObject = 0;
        sub = *(void**)((char*)inner + 0x7f8);
        if (sub != NULL)
        {
            s16 id = ((GameObject*)sub)->anim.seqId;
            if (id == 0x3cf || id == 0x662)
            {
                objThrowFn_80182504((GameObject*)sub);
            }
            else
            {
                objSaveFn_800ea774((GameObject*)sub);
            }
            *(s16*)((char*)inner->heldObj + 0x6) &= ~0x4000;
            *(int*)((char*)inner->heldObj + 0xf8) = 0;
            inner->heldObj = 0;
        }
        *(int*)&((PlayerState*)state)->baddie.unk308 = (int)fn_802A514C;
        return 3;
    }
    if (*(s8*)&((PlayerState*)state)->baddie.moveJustStartedA != 0)
    {
        ObjAnim_SetCurrentMove((int)obj, 0x12, lbl_803E7EA4, 1);
    }
    {
        f32 v = lbl_803E7EE0 + inner->verticalVel;
        f32 w;
        f32 clamped;
        ObjAnimComponent* o;
        w = v * lbl_803E7E98;
        o = (ObjAnimComponent*)obj;
        clamped = (w < lbl_803E7EA4) ? lbl_803E7EA4 : ((w > lbl_803E7EE0) ? lbl_803E7EE0 : w);
        ObjAnim_SetMoveProgress(lbl_803E7EE0 - clamped, o);
    }
    (*(void (*)(int, int, f32, f32, int))(*(int*)((char*)*gPlayerInterface + 0x44)))((int)obj, state, fv, lbl_803E7EE0,
                                                                              inner->inputHeading);
    ((PlayerState*)state)->baddie.velSmoothTime = lbl_803E7EF4;
    ((PlayerState*)state)->baddie.moveSpeed = lbl_803E7EF8;
    obj->anim.velocityY = inner->verticalVel * fv;
    if (((PlayerState*)state)->baddie.inputMagnitude > lbl_803E7EFC)
    {
        f32 ryaw = (f32)inner->targetYawRate * fv;
        inner->targetYaw = (s16)((f32)(s16)inner->targetYaw + gPlayerDegToBinAngle * (ryaw * lbl_803E7F04));
        inner->yaw = inner->targetYaw;
    }
    fn_802ABAE8(obj, state, (int)inner, lbl_803E7EA4);
    return 0;
}

extern f32 lbl_803E8020;


int playerState40(int p1, int obj)
{
    if (*(s8*)((char*)obj + 0x27a) != 0)
    {
        *(u8*)((char*)obj + 0x357) = 0;
    }
    *(u8*)((char*)obj + 0x357) += 1;
    if (*(s8*)((char*)obj + 0x346) != 0 && *(s8*)((char*)obj + 0x357) > 0x1e)
    {
        *(int*)((char*)obj + 0x308) = (int)fn_802A514C;
        return 2;
    }
    return 0;
}

typedef struct
{
    u8 pad0[0xc];
    f32 fz0;
    f32 fz1;
    u8 pad1[8];
    f32 nx;
    f32 ny;
    f32 nz;
    f32 nw;
    u8 pad2[0x10];
    f32 ga;
    f32 gb;
    u8 pad3[4];
    f32 gt;
    u8 pad4[6];
    s8 flags;
    u8 pad5;
} WallHit;



int playerState3F(int obj, int state)
{
    if (*(s8*)&((PlayerState*)state)->baddie.moveJustStartedA != 0)
    {
        ObjAnim_SetCurrentMove(obj, 0xe, lbl_803E7EA4, 0);
        *(s8*)&((PlayerState*)state)->baddie.moveDone = 0;
    }
    ((PlayerState*)state)->baddie.moveSpeed = lbl_803E7F08;
    if (*(s8*)&((PlayerState*)state)->baddie.moveDone != 0)
    {
        *(int*)&((PlayerState*)state)->baddie.unk308 = 0;
        return 0x41;
    }
    return 0;
}


int playerStateNop3E(void)
{
    return 0x0;
}

extern f32 lbl_803E8090;
extern f32 lbl_803E8094;
extern f32 lbl_803E8098;
extern f32 lbl_803E809C;
extern f32 lbl_803E80A0;
char sNotOnGroundFailureMessage[] = "FAIL ON NOT ON GROUND\n";

int fn_802A87CC(GameObject* obj, char* cam, f32* out, f32* vec, f32 fa, f32 fb);
int player_probeClimbable(GameObject* obj, int p4, int src, int dst, int flag);

void fn_8029782C(GameObject* obj)
{
    PlayerState* inner = obj->extra;
    *(u32*)&((PlayerState*)inner)->flags360 |= PLAYER_FLAG_TELEPORTED;
    ((ByteFlags*)((char*)inner + 0x3f6))->b20 = 0;
}


int playerState3D(int obj, int state, f32 fv)
{
    PlayerState* inner = ((GameObject*)obj)->extra;
    int r;
    f32 k;
    s16 hdr;

    if (*(s8*)&((PlayerState*)state)->baddie.moveJustStartedA != 0)
    {
        ObjAnim_SetCurrentMove(obj, gPlayerMoveSlotTable[*(s16*)((char*)gPlayerMoveSlotData + 0x4d2)], lbl_803E7EA4, 0);
        ((PlayerState*)state)->baddie.moveSpeed = lbl_803E7F0C;
        k = lbl_803E7EA4;
        ((PlayerState*)state)->baddie.animSpeedC = k;
        ((PlayerState*)state)->baddie.animSpeedB = k;
        ((PlayerState*)state)->baddie.animSpeedA = k;
        ((GameObject*)obj)->anim.velocityX = k;
        ((GameObject*)obj)->anim.velocityY = k;
        ((GameObject*)obj)->anim.velocityZ = k;
    }
    r = playerState28((GameObject*)obj, state, fv);
    if (r != 0)
    {
        return r;
    }
    (*(void (*)(int, int, f32, int))(*(int*)((char*)*gPlayerInterface + 0x30)))(obj, state, fv, 0x10);
    hdr = *(s16*)obj;
    inner->yaw = hdr;
    inner->targetYaw = hdr;
    (*(void (*)(int, int, f32, int))(*(int*)((char*)*gPlayerInterface + 0x20)))(obj, state, fv, 1);
    if (*(int*)&((PlayerState*)state)->baddie.eventFlags & 0x200)
    {
        doRumble(lbl_803E7F10);
        Sfx_PlayFromObject(obj, SFXTRIG_rserv1_c);
        inner->pendingFxFlags |= 4;
    }
    if ((((PlayerState*)state)->baddie.moveEventFlags & 1) == 0 &&
        ((GameObject*)obj)->anim.currentMoveProgress > lbl_803E7F14)
    {
        Sfx_PlayFromObject(obj, SFXTRIG_sp_sa_def01);
        ((PlayerState*)state)->baddie.moveEventFlags |= 1;
    }
    if ((((PlayerState*)state)->baddie.moveEventFlags & 2) == 0 &&
        ((GameObject*)obj)->anim.currentMoveProgress > lbl_803E7F18)
    {
        Sfx_PlayFromObject(obj, audioPickSoundEffectIntLegacy(inner->surfaceType, inner->footstepSoundId));
        ((PlayerState*)state)->baddie.moveEventFlags |= 2;
    }
    if (*(s8*)&((PlayerState*)state)->baddie.moveDone != 0)
    {
        *(int*)&((PlayerState*)state)->baddie.unk308 = (int)fn_8029C8C8;
        return 0x25;
    }
    if (((GameObject*)obj)->anim.currentMoveProgress > lbl_803E7F1C)
    {
        if (((PlayerState*)state)->baddie.hasTarget != 1)
        {
            if (gPlayerPathObject != 0 && ((ByteFlags*)((char*)inner + 0x3f4))->b40)
            {
                inner->staffActionRequest = 0;
                ((ByteFlags*)((char*)inner + 0x3f4))->b08 = 0;
            }
            *(int*)&((PlayerState*)state)->baddie.unk308 = (int)fn_802A514C;
            return -1;
        }
        r = playerState30((GameObject*)obj, state, fv);
        if (r != 0)
        {
            return r;
        }
    }
    return 0;
}

int playerState3C(GameObject* obj, int state, f32 fv)
{
    PlayerState* inner = obj->extra;
    int r;
    f32 k;
    s16 hdr;

    if (*(s8*)&((PlayerState*)state)->baddie.moveJustStartedA != 0)
    {
        ObjAnim_SetCurrentMove((int)obj, gPlayerMoveSlotTable[*(s16*)((char*)gPlayerMoveSlotData + 0x422)], lbl_803E7EA4, 0);
        ((PlayerState*)state)->baddie.moveSpeed = lbl_803E7F20;
        k = lbl_803E7EA4;
        ((PlayerState*)state)->baddie.animSpeedC = k;
        ((PlayerState*)state)->baddie.animSpeedB = k;
        ((PlayerState*)state)->baddie.animSpeedA = k;
        obj->anim.velocityX = k;
        obj->anim.velocityY = k;
        obj->anim.velocityZ = k;
    }
    r = playerState28(obj, state, fv);
    if (r != 0)
    {
        return r;
    }
    (*(void (*)(int, int, f32, int))(*(int*)((char*)*gPlayerInterface + 0x30)))((int)obj, state, fv, 0x10);
    hdr = *(s16*)obj;
    inner->yaw = hdr;
    inner->targetYaw = hdr;
    (*(void (*)(int, int, f32, int))(*(int*)((char*)*gPlayerInterface + 0x20)))((int)obj, state, fv, 1);
    if ((((PlayerState*)state)->baddie.moveEventFlags & 1) == 0 &&
        obj->anim.currentMoveProgress > lbl_803E7F14)
    {
        Sfx_PlayFromObject((int)obj, SFXTRIG_sp_sa_def01);
        ((PlayerState*)state)->baddie.moveEventFlags |= 1;
    }
    if ((((PlayerState*)state)->baddie.moveEventFlags & 2) == 0 &&
        obj->anim.currentMoveProgress > lbl_803E7F18)
    {
        Sfx_PlayFromObject((int)obj, SFXTRIG_fox_fightbreath2);
        ((PlayerState*)state)->baddie.moveEventFlags |= 2;
    }
    if (*(s8*)&((PlayerState*)state)->baddie.moveDone != 0)
    {
        *(int*)&((PlayerState*)state)->baddie.unk308 = (int)fn_8029C8C8;
        return 0x25;
    }
    if (obj->anim.currentMoveProgress > lbl_803E7F1C)
    {
        if (((PlayerState*)state)->baddie.hasTarget != 1)
        {
            if (gPlayerPathObject != 0 && ((ByteFlags*)((char*)inner + 0x3f4))->b40)
            {
                inner->staffActionRequest = 0;
                ((ByteFlags*)((char*)inner + 0x3f4))->b08 = 0;
            }
            *(int*)&((PlayerState*)state)->baddie.unk308 = (int)fn_802A514C;
            return -1;
        }
        r = playerState30(obj, state, fv);
        if (r != 0)
        {
            return r;
        }
    }
    return 0;
}

int playerState3B(GameObject* obj, int state, f32 fv)
{
    PlayerState* inner = obj->extra;
    int r;
    f32 k;
    s16 hdr;

    if (*(s8*)&((PlayerState*)state)->baddie.moveJustStartedA != 0)
    {
        ObjAnim_SetCurrentMove((int)obj, gPlayerMoveSlotTable[*(s16*)((char*)gPlayerMoveSlotData + 0x632)], lbl_803E7EA4, 0);
        ((PlayerState*)state)->baddie.moveSpeed = lbl_803E7F24;
        ((PlayerState*)state)->baddie.moveEventFlags = 0;
        k = lbl_803E7EA4;
        ((PlayerState*)state)->baddie.animSpeedC = k;
        ((PlayerState*)state)->baddie.animSpeedB = k;
        ((PlayerState*)state)->baddie.animSpeedA = k;
        obj->anim.velocityX = k;
        obj->anim.velocityY = k;
        obj->anim.velocityZ = k;
    }
    r = playerState28(obj, state, fv);
    if (r != 0)
    {
        return r;
    }
    (*(void (*)(int, int, f32, int))(*(int*)((char*)*gPlayerInterface + 0x30)))((int)obj, state, fv, 1);
    hdr = *(s16*)obj;
    inner->yaw = hdr;
    inner->targetYaw = hdr;
    (*(void (*)(int, int, f32, int))(*(int*)((char*)*gPlayerInterface + 0x20)))((int)obj, state, fv, 2);
    if (*(int*)&((PlayerState*)state)->baddie.eventFlags & 0x200)
    {
        doRumble(lbl_803E7F10);
        Sfx_PlayFromObject((int)obj, SFXTRIG_rserv1_c);
        inner->pendingFxFlags |= 4;
    }
    if ((((PlayerState*)state)->baddie.moveEventFlags & 1) == 0 &&
        obj->anim.currentMoveProgress > lbl_803E7F14)
    {
        Sfx_PlayFromObject((int)obj, SFXTRIG_fox_fightbreath2);
        ((PlayerState*)state)->baddie.moveEventFlags |= 1;
    }
    if (*(s8*)&((PlayerState*)state)->baddie.moveDone != 0)
    {
        *(int*)&((PlayerState*)state)->baddie.unk308 = (int)fn_8029C8C8;
        return 0x25;
    }
    if (obj->anim.currentMoveProgress > lbl_803E7F1C)
    {
        if (((PlayerState*)state)->baddie.hasTarget != 1)
        {
            if (gPlayerPathObject != 0 && ((ByteFlags*)((char*)inner + 0x3f4))->b40)
            {
                inner->staffActionRequest = 0;
                ((ByteFlags*)((char*)inner + 0x3f4))->b08 = 0;
            }
            *(int*)&((PlayerState*)state)->baddie.unk308 = (int)fn_802A514C;
            return -1;
        }
        r = playerState30(obj, state, fv);
        if (r != 0)
        {
            return r;
        }
    }
    return 0;
}

#pragma opt_propagation off
static void playerFreeSpawnedObjects(void** p, int i, int hi)
{
    do
    {
        if (*p != NULL)
        {
            Obj_FreeObject((GameObject*)*p);
            *p = (void*)hi;
        }
        p++;
        i++;
    } while (i < 7);
}
#pragma opt_propagation reset

int playerState3A(GameObject* obj, int state, f32 fv)
{
    PlayerState* inner = obj->extra;
    int r;
    f32 k;
    s16 hdr;

    if (*(s8*)&((PlayerState*)state)->baddie.moveJustStartedA != 0)
    {
        ObjAnim_SetCurrentMove((int)obj, gPlayerMoveSlotTable[*(s16*)((char*)gPlayerMoveSlotData + 0x582)], lbl_803E7EA4, 0);
        ((PlayerState*)state)->baddie.moveSpeed = lbl_803E7F24;
        ((PlayerState*)state)->baddie.moveEventFlags = 0;
        k = lbl_803E7EA4;
        ((PlayerState*)state)->baddie.animSpeedC = k;
        ((PlayerState*)state)->baddie.animSpeedB = k;
        ((PlayerState*)state)->baddie.animSpeedA = k;
        obj->anim.velocityX = k;
        obj->anim.velocityY = k;
        obj->anim.velocityZ = k;
    }
    r = playerState28(obj, state, fv);
    if (r != 0)
    {
        return r;
    }
    (*(void (*)(int, int, f32, int))(*(int*)((char*)*gPlayerInterface + 0x30)))((int)obj, state, fv, 1);
    hdr = *(s16*)obj;
    inner->yaw = hdr;
    inner->targetYaw = hdr;
    (*(void (*)(int, int, f32, int))(*(int*)((char*)*gPlayerInterface + 0x20)))((int)obj, state, fv, 2);
    if (*(int*)&((PlayerState*)state)->baddie.eventFlags & 0x200)
    {
        doRumble(lbl_803E7F10);
        Sfx_PlayFromObject((int)obj, SFXTRIG_rserv1_c);
        inner->pendingFxFlags |= 4;
    }
    if ((((PlayerState*)state)->baddie.moveEventFlags & 1) == 0 &&
        obj->anim.currentMoveProgress > lbl_803E7F14)
    {
        Sfx_PlayFromObject((int)obj, SFXTRIG_fox_fightbreath2);
        ((PlayerState*)state)->baddie.moveEventFlags |= 1;
    }
    if (*(s8*)&((PlayerState*)state)->baddie.moveDone != 0)
    {
        *(int*)&((PlayerState*)state)->baddie.unk308 = (int)fn_8029C8C8;
        return 0x25;
    }
    if (obj->anim.currentMoveProgress > lbl_803E7F1C)
    {
        if (((PlayerState*)state)->baddie.hasTarget != 1)
        {
            if (gPlayerPathObject != 0 && ((ByteFlags*)((char*)inner + 0x3f4))->b40)
            {
                inner->staffActionRequest = 0;
                ((ByteFlags*)((char*)inner + 0x3f4))->b08 = 0;
            }
            *(int*)&((PlayerState*)state)->baddie.unk308 = (int)fn_802A514C;
            return -1;
        }
        r = playerState30(obj, state, fv);
        if (r != 0)
        {
            return r;
        }
    }
    return 0;
}


int playerState39(GameObject* obj, int state, f32 fv)
{
    PlayerState* inner = obj->extra;
    int r;
    f32 k;
    s16 hdr;

    *(u32*)&((PlayerState*)inner)->flags360 |= PLAYER_FLAG_KNOCKBACK;
    if (*(s8*)&((PlayerState*)state)->baddie.moveJustStartedA != 0)
    {
        ((PlayerState*)state)->baddie.moveSpeed = lbl_803E7EF8;
        k = lbl_803E7EA4;
        ((PlayerState*)state)->baddie.animSpeedC = k;
        ((PlayerState*)state)->baddie.animSpeedB = k;
        ((PlayerState*)state)->baddie.animSpeedA = k;
        obj->anim.velocityX = k;
        obj->anim.velocityY = k;
        obj->anim.velocityZ = k;
    }
    r = playerState28(obj, state, fv);
    if (r != 0)
    {
        return r;
    }
    (*(void (*)(int, int, f32, int))(*(int*)((char*)*gPlayerInterface + 0x30)))((int)obj, state, fv, 1);
    hdr = *(s16*)obj;
    inner->yaw = hdr;
    inner->targetYaw = hdr;
    if ((getButtons_80014dd8(0) & 0x20) == 0)
    {
        *(int*)&((PlayerState*)state)->baddie.unk308 = (int)fn_8029C8C8;
        return 0x25;
    }
    if (*(s8*)&((PlayerState*)state)->baddie.moveJustStartedA != 0)
    {
        ((ByteFlags*)((char*)inner + 0x3f6))->b10 = 0;
    }
    if (((ByteFlags*)((char*)inner + 0x3f6))->b10)
    {
        ((PlayerState*)state)->baddie.moveSpeed = lbl_803E7E8C;
        if (obj->anim.currentMove != 0x455)
        {
            doRumble(lbl_803E7ED8);
            ObjAnim_SetCurrentMove((int)obj, 0x455, lbl_803E7EA4, 0);
            ((PlayerState*)state)->baddie.animSpeedA = -inner->animSpeedStart;
        }
        if (*(s8*)&((PlayerState*)state)->baddie.moveDone != 0)
        {
            ((ByteFlags*)((char*)inner + 0x3f6))->b10 = 0;
        }
    }
    else
    {
        ((PlayerState*)state)->baddie.moveSpeed = lbl_803E7EF8;
        if (obj->anim.currentMove != 0x458 &&
            ((int (*)(ObjAnimComponent*))ObjAnim_GetCurrentEventCountdown)((ObjAnimComponent*)obj) == 0)
        {
            ObjAnim_SetCurrentMove((int)obj, 0x458, obj->anim.currentMoveProgress, 0);
            ObjAnim_SetCurrentEventStepFrames((ObjAnimComponent*)obj, 8);
        }
    }
    ((PlayerState*)state)->baddie.animSpeedA =
        ((PlayerState*)state)->baddie.animSpeedA * powfBitEstimate(inner->animSpeedDecay, timeDelta);
    return 0;
}

int playerState38(GameObject* obj, int state, f32 fv)
{
    PlayerState* inner = obj->extra;
    int r;

    if (*(s8*)&((PlayerState*)state)->baddie.moveJustStartedA != 0)
    {
        f32 zero;
        ObjAnim_SetCurrentMove((int)obj, 0xfb, lbl_803E7EA4, 0);
        ((PlayerState*)state)->baddie.moveSpeed = lbl_803E7F28;
        zero = lbl_803E7EA4;
        ((PlayerState*)state)->baddie.animSpeedC = zero;
        ((PlayerState*)state)->baddie.animSpeedB = zero;
        ((PlayerState*)state)->baddie.animSpeedA = zero;
        obj->anim.velocityX = zero;
        obj->anim.velocityY = zero;
        obj->anim.velocityZ = zero;
    }

    r = playerState28(obj, state, fv);
    if (r != 0)
    {
        return r;
    }

    (*(void (*)(int, int, f32, int))(*(int*)((char*)*gPlayerInterface + 0x30)))((int)obj, state, fv, 1);
    inner->targetYaw = inner->yaw = *(s16*)((char*)obj);
    (*(void (*)(int, int, f32, int))(*(int*)((char*)*gPlayerInterface + 0x20)))((int)obj, state, fv, 2);

    if (*(s8*)&((PlayerState*)state)->baddie.moveDone != 0)
    {
        *(int*)&((PlayerState*)state)->baddie.unk308 = (int)fn_8029C8C8;
        return 0x25;
    }
    if (obj->anim.currentMoveProgress > lbl_803E7F2C)
    {
        if (((PlayerState*)state)->baddie.hasTarget != 1)
        {
            if ((void*)gPlayerPathObject != NULL && ((ByteFlags*)((char*)inner + 0x3f4))->b40)
            {
                inner->staffActionRequest = 0;
                ((ByteFlags*)((char*)inner + 0x3f4))->b08 = 0;
            }
            *(int*)&((PlayerState*)state)->baddie.unk308 = (int)fn_802A514C;
            return -1;
        }
        r = playerState30(obj, state, fv);
        if (r != 0)
        {
            return r;
        }
    }
    return 0;
}

int playerState37(GameObject* obj, int state)
{
    int inner = *(int*)&obj->extra;
    u8 v;
    ((ByteFlags*)((char*)inner + 0x3f6))->b20 = 1;
    v = *(u8*)((char*)state + 0x34b);
    if (v == 3)
    {
        *(int*)&((PlayerState*)state)->baddie.unk308 = (int)fn_8029782C;
        return 0x3c;
    }
    if (v == 4)
    {
        *(int*)&((PlayerState*)state)->baddie.unk308 = (int)fn_8029782C;
        return 0x3e;
    }
    if (v == 1)
    {
        *(int*)&((PlayerState*)state)->baddie.unk308 = (int)fn_8029782C;
        return 0x3b;
    }
    *(int*)&((PlayerState*)state)->baddie.unk308 = (int)fn_8029782C;
    return 0x39;
}

void fn_802985AC(GameObject* obj)
{
    PlayerState* inner = obj->extra;
    ((ByteFlags*)((char*)inner + 0x3f4))->b20 = 0;
    inner->buttonHoldTimer = lbl_803E7EA4;
    ((ByteFlags*)((char*)inner + 0x3f3))->b10 = 0;
    inner->animState = -1;
    ObjHits_SyncObjectPositionIfDirtyLegacy(obj);
}

int playerStateSuperQuake(GameObject* obj, int state, f32 fv)
{
    PlayerState* inner = obj->extra;
    f32 f;

    *(int*)state |= 0x200000;
    if (*(s8*)&((PlayerState*)state)->baddie.moveJustStartedA != 0)
    {
        ((ByteFlags*)((char*)inner + 0x3f3))->b10 = 0;
        if (inner->animState == 0xc55)
        {
            ((PlayerState*)inner)->chargeCapacity = 0x14;
        }
        else
        {
            ((PlayerState*)inner)->chargeCapacity = 0xa;
        }
        ObjHits_MarkObjectPositionDirty((ObjAnimComponent*)obj);
    }
    if (((ByteFlags*)((char*)inner + 0x3f0))->b20 == 0 && lbl_803E7EA4 != inner->verticalVel)
    {
        *(int*)&((PlayerState*)state)->baddie.unk308 = 0;
        return 0x42;
    }
    switch (obj->anim.currentMove)
    {
    case 0x84:
        if (*(s8*)&((PlayerState*)state)->baddie.moveDone != 0)
        {
            ObjAnim_SetCurrentMove((int)obj, 0x85, lbl_803E7EA4, 0);
            ((PlayerState*)state)->baddie.moveSpeed = lbl_803E7EFC;
        }
        break;
    case 0x85:
        inner->chargeLevel = inner->chargeLevel + lbl_803E7ED4 * fv / lbl_803E7EF0;
        inner->chargeLevel = lbl_803E7E98 * fv + inner->chargeLevel;
        if (inner->chargeLevel >= (f32)(u32) * (u8*)((char*)inner + 0x41c))
        {
            int amt;
            int r35c;
            int v;
            int hi;
            Sfx_PlayFromObject((int)obj, SFXTRIG_fox_roll2);
            amt = -((PlayerState*)inner)->chargeCapacity;
            r35c = *(int*)((char*)(*(int*)&obj->extra) + 0x35c);
            v = *(s16*)((char*)r35c + 4) + amt;
            if (v < 0)
            {
                v = 0;
            }
            else if (v > (hi = *(s16*)((char*)r35c + 6)))
            {
                v = hi;
            }
            *(s16*)((char*)r35c + 4) = v;
            if (amt > 0)
            {
                Sfx_PlayFromObject(0, SFXTRIG_id_21c);
            }
            ObjAnim_SetCurrentMove((int)obj, 0x86, lbl_803E7EA4, 0);
            ((PlayerState*)state)->baddie.moveSpeed = lbl_803E7EF8;
        }
        break;
    case 0x86:
        if (((ByteFlags*)((char*)inner + 0x3f3))->b10 == 0 &&
            obj->anim.currentMoveProgress > lbl_803E7EFC)
        {
            void* tricky = getTrickyObject();
            if (tricky != NULL)
            {
                trickyImpress((GameObject*)tricky);
            }
            Sfx_PlayFromObject((int)obj, SFXTRIG_staff_boulder_move1);
            superQuakeFn_8016d9fc(&obj->anim.localPosX);
            ((ByteFlags*)((char*)inner + 0x3f3))->b10 = 1;
            doRumble(lbl_803E7F30);
        }
        if (*(s8*)&((PlayerState*)state)->baddie.moveDone != 0)
        {
            *(u32*)&((PlayerState*)inner)->flags360 |= PLAYER_FLAG_TELEPORTED;
            *(int*)&((PlayerState*)state)->baddie.unk308 = (int)fn_802A514C;
            return 2;
        }
        break;
    default:
        Sfx_PlayFromObject((int)obj, SFXTRIG_staff_boulder_drops);
        f = lbl_803E7EA4;
        ((PlayerState*)state)->baddie.animSpeedC = f;
        ((PlayerState*)state)->baddie.animSpeedB = f;
        ((PlayerState*)state)->baddie.animSpeedA = f;
        obj->anim.velocityX = f;
        obj->anim.velocityY = f;
        obj->anim.velocityZ = f;
        ObjAnim_SetCurrentMove((int)obj, 0x84, f, 0);
        ((PlayerState*)state)->baddie.moveSpeed = lbl_803E7F34;
        inner->chargeLevel = lbl_803E7EA4;
        ((ByteFlags*)((char*)inner + 0x3f3))->b10 = 0;
        if (gPlayerPathObject != NULL && ((ByteFlags*)((char*)inner + 0x3f4))->b40)
        {
            inner->staffActionRequest = 4;
            ((ByteFlags*)((char*)inner + 0x3f4))->b08 = 1;
        }
        break;
    }
    return 0;
}

void fn_80298924(int obj)
{
    ObjHits_SyncObjectPositionIfDirtyLegacy(obj);
}

int playerState35(GameObject* obj, int state)
{
    PlayerState* inner = obj->extra;
    f32 f;

    if (*(s8*)&((PlayerState*)state)->baddie.moveJustStartedA != 0)
    {
        ObjHits_MarkObjectPositionDirty((ObjAnimComponent*)obj);
    }
    f = lbl_803E7EA4;
    ((PlayerState*)state)->baddie.animSpeedC = f;
    ((PlayerState*)state)->baddie.animSpeedB = f;
    ((PlayerState*)state)->baddie.animSpeedA = f;
    obj->anim.velocityX = f;
    obj->anim.velocityY = f;
    obj->anim.velocityZ = f;
    setAButtonIcon(0xe);
    setBButtonIcon(0xa);
    switch (obj->anim.currentMove)
    {
    case 0xe0:
        if (obj->anim.currentMoveProgress > lbl_803E7E98 &&
            (((PlayerState*)state)->baddie.moveEventFlags & 1) == 0)
        {
            ((PlayerState*)state)->baddie.moveEventFlags |= 1;
            Sfx_PlayFromObject((int)obj, SFXTRIG_recrate_hit);
        }
        if (*(s8*)&((PlayerState*)state)->baddie.moveDone != 0)
        {
            ObjAnim_SetCurrentMove((int)obj, 0xdf, lbl_803E7EA4, 0);
            ((PlayerState*)state)->baddie.moveSpeed = lbl_803E7F40;
            ((PlayerState*)state)->baddie.moveEventFlags = 0;
        }
        break;
    case 0xde:
        if (obj->anim.currentMoveProgress > lbl_803E7E9C &&
            (((PlayerState*)state)->baddie.moveEventFlags & 1) == 0)
        {
            ((PlayerState*)state)->baddie.moveEventFlags |= 1;
            doRumble(lbl_803E7F10);
            Sfx_PlayFromObject((int)obj, SFXTRIG_staff_rapidfire);
            cfPrisonGuard_setGameBitMirror(gPlayerInteractTarget, 0);
        }
        if (*(s8*)&((PlayerState*)state)->baddie.moveDone != 0)
        {
            ObjAnim_SetCurrentMove((int)obj, 0xe4, lbl_803E7EA4, 0);
            ((PlayerState*)state)->baddie.moveSpeed = lbl_803E7F40;
            Sfx_PlayFromObject((int)obj, SFXTRIG_staff_lever);
        }
        break;
    case 0xe1:
        if (obj->anim.currentMoveProgress > lbl_803E7E98 &&
            (((PlayerState*)state)->baddie.moveEventFlags & 1) == 0)
        {
            ((PlayerState*)state)->baddie.moveEventFlags |= 1;
            Sfx_PlayFromObject((int)obj, SFXTRIG_recrate_hit);
        }
        if (*(s8*)&((PlayerState*)state)->baddie.moveDone != 0)
        {
            ObjAnim_SetCurrentMove((int)obj, 0xde, lbl_803E7EA4, 0);
            ((PlayerState*)state)->baddie.moveSpeed = lbl_803E7F40;
            ((PlayerState*)state)->baddie.moveEventFlags = 0;
        }
        break;
    case 0xdf:
        if (obj->anim.currentMoveProgress > lbl_803E7E9C &&
            (((PlayerState*)state)->baddie.moveEventFlags & 1) == 0)
        {
            ((PlayerState*)state)->baddie.moveEventFlags |= 1;
            doRumble(lbl_803E7F10);
            Sfx_PlayFromObject((int)obj, SFXTRIG_staff_rapidfire);
            cfPrisonGuard_setGameBitMirror(gPlayerInteractTarget, 1);
        }
        if (*(s8*)&((PlayerState*)state)->baddie.moveDone != 0)
        {
            ObjAnim_SetCurrentMove((int)obj, 0xe5, lbl_803E7EA4, 0);
            ((PlayerState*)state)->baddie.moveSpeed = lbl_803E7F40;
            Sfx_PlayFromObject((int)obj, SFXTRIG_staff_lever);
        }
        break;
    case 0xe4:
    case 0xe5:
        if (*(s8*)&((PlayerState*)state)->baddie.moveDone != 0)
        {
            *(u32*)&((PlayerState*)inner)->flags360 |= PLAYER_FLAG_TELEPORTED;
            *(int*)&((PlayerState*)state)->baddie.unk308 = (int)fn_802A514C;
            return 2;
        }
        break;
    default:
        if (cfPrisonGuard_isGameBitMirrorSet(gPlayerInteractTarget) != 0)
        {
            ObjAnim_SetCurrentMove((int)obj, 0xe1, lbl_803E7EA4, 0);
        }
        else
        {
            ObjAnim_SetCurrentMove((int)obj, 0xe0, lbl_803E7EA4, 0);
        }
        staffactivated_calcInteractionTargetXZ(gPlayerInteractTarget, &((GameObject*)obj)->anim.localPosX,
                                               &((GameObject*)obj)->anim.localPosZ);
        ((PlayerState*)state)->baddie.moveSpeed = lbl_803E7F40;
        ((PlayerState*)state)->baddie.moveEventFlags = 0;
        inner->targetYaw = gPlayerInteractTarget->anim.rotX;
        inner->yaw = inner->targetYaw;
        if (gPlayerPathObject != NULL && ((ByteFlags*)((char*)inner + 0x3f4))->b40)
        {
            inner->staffActionRequest = 4;
            ((ByteFlags*)((char*)inner + 0x3f4))->b08 = 1;
        }
        break;
    }
    return 0;
}

int playerState34(GameObject* obj, int state)
{
    PlayerState* inner = obj->extra;
    f32 k;

    if (*(s8*)&((PlayerState*)state)->baddie.moveJustStartedA != 0)
    {
        ObjHits_MarkObjectPositionDirty((ObjAnimComponent*)obj);
    }
    k = lbl_803E7EA4;
    ((PlayerState*)state)->baddie.animSpeedC = k;
    ((PlayerState*)state)->baddie.animSpeedB = k;
    ((PlayerState*)state)->baddie.animSpeedA = k;
    obj->anim.velocityX = k;
    obj->anim.velocityY = k;
    obj->anim.velocityZ = k;

    switch (obj->anim.currentMove)
    {
    case 0xdd:
        if (obj->anim.currentMoveProgress > lbl_803E7F44)
        {
            cfPrisonGuard_setLiftHeight(gPlayerInteractTarget, 0);
        }
        if (obj->anim.currentMoveProgress > lbl_803E7F48 &&
            (((PlayerState*)state)->baddie.moveEventFlags & 1) == 0)
        {
            Sfx_PlayFromObject((int)obj, SFXTRIG_recrate_smash);
            ((PlayerState*)state)->baddie.moveEventFlags |= 1;
        }
        if (*(s8*)&((PlayerState*)state)->baddie.moveDone != 0)
        {
            *(u32*)&((PlayerState*)inner)->flags360 |= PLAYER_FLAG_TELEPORTED;
            *(int*)&((PlayerState*)state)->baddie.unk308 = (int)fn_802A514C;
            return 2;
        }
        break;
    default:
        ObjAnim_SetCurrentMove((int)obj, 0xdd, k, 0);
        staffactivated_calcInteractionTargetXZ(gPlayerInteractTarget, &((GameObject*)obj)->anim.localPosX,
                                               &((GameObject*)obj)->anim.localPosZ);
        ((PlayerState*)state)->baddie.moveSpeed = lbl_803E7EF8;
        ((PlayerState*)state)->baddie.moveEventFlags = 0;
        inner->targetYaw = gPlayerInteractTarget->anim.rotX;
        inner->yaw = inner->targetYaw;
        if ((void*)gPlayerPathObject != NULL && ((ByteFlags*)((char*)inner + 0x3f4))->b40)
        {
            inner->staffActionRequest = 4;
            ((ByteFlags*)((char*)inner + 0x3f4))->b08 = 1;
        }
        break;
    }
    return 0;
}

int playerStateStaffLiftRock(int obj, int state, f32 fv)
{
    PlayerState* inner = ((GameObject*)obj)->extra;
    if (*(s8*)&((PlayerState*)state)->baddie.moveJustStartedA != 0)
    {
        ObjHits_MarkObjectPositionDirty((ObjAnimComponent*)obj);
    }
    setBButtonIcon(0xa);
    {
        f32 zero = lbl_803E7EA4;
        ((PlayerState*)state)->baddie.animSpeedC = zero;
        ((PlayerState*)state)->baddie.animSpeedB = zero;
        ((PlayerState*)state)->baddie.animSpeedA = zero;
        ((GameObject*)obj)->anim.velocityX = zero;
        ((GameObject*)obj)->anim.velocityY = zero;
        ((GameObject*)obj)->anim.velocityZ = zero;
    }
    switch (((GameObject*)obj)->anim.currentMove)
    {
    case 0xab:
        setAButtonIcon(2);
        if (lbl_803DE48C == 0)
        {
            if (((GameObject*)obj)->anim.currentMoveProgress > lbl_803E7E9C)
            {
                Sfx_PlayFromObject(obj, SFXTRIG_staff_rocket_boost);
                lbl_803DE48C = 1;
            }
        }
        if (*(s8*)&((PlayerState*)state)->baddie.moveDone != 0)
        {
            ObjAnim_SetCurrentMove(obj, 0xb1, lbl_803E7EA4, 0);
            ((PlayerState*)state)->baddie.moveSpeed = lbl_803E7EF8;
        }
        break;
    case 0xb1:
    {
        int flags;
        setAButtonIcon(2);
        cfPrisonGuard_setLiftHeight(gPlayerInteractTarget, 0);
        flags = inner->buttonsJustPressed;
        if ((flags & 0x100) != 0)
        {
            buttonDisable(0, PAD_BUTTON_A);
            lbl_803DE488 = lbl_803E7ED8;
            ObjAnim_SetCurrentMove(obj, 0xac, lbl_803E7EA4, 0);
            ((PlayerState*)state)->baddie.moveSpeed = lbl_803E7EA4;
        }
        else if ((flags & 0x200) != 0)
        {
            buttonDisable(0, PAD_BUTTON_B);
            Sfx_PlayFromObject(obj, SFXTRIG_staff_rocket_boost);
            ObjAnim_SetCurrentMove(obj, 0xd1, lbl_803E7EA4, 0);
            ((PlayerState*)state)->baddie.moveSpeed = lbl_803E7F4C;
        }
        break;
    }
    case 0xd1:
        if (*(s8*)&((PlayerState*)state)->baddie.moveDone != 0)
        {
            *(u32*)&((PlayerState*)inner)->flags360 |= PLAYER_FLAG_TELEPORTED;
            *(int*)&((PlayerState*)state)->baddie.unk308 = (int)fn_802A514C;
            return 2;
        }
        break;
    case 0xac:
    {
        int count;
        f32 prog;
        setAButtonIcon(2);
        lbl_803DE488 = lbl_803DE488 - lbl_803E7EE0;
        if ((inner->buttonsJustPressedIfNotBusy & PAD_BUTTON_A) != 0 || getCurSeqNoInt() != 0)
        {
            buttonDisable(0, PAD_BUTTON_A);
            lbl_803DE460 = lbl_803DE460 - fv;
            if (lbl_803DE460 < lbl_803E7EA4)
            {
                Sfx_PlayFromObject(obj, (u16)(inner->characterId == 0 ? SFXTRIG_impact3 : SFXTRIG_literun116));
                lbl_803DE460 = (f32)(int)randomGetRange(0xa, 0x12);
            }
            switch (cfPrisonGuard_getPullRateMode(gPlayerInteractTarget))
            {
            case 2:
                lbl_803DE488 = lbl_803DE488 + lbl_803E7F50;
                break;
            default:
                lbl_803DE488 = lbl_803DE488 + lbl_803E7F54;
                break;
            case 0:
                lbl_803DE488 = lbl_803DE488 + lbl_803E7F58;
                break;
            }
        }
        if (lbl_803DE488 > lbl_803E7F5C)
        {
            lbl_803DE488 = lbl_803E7F5C;
        }
        else if (lbl_803DE488 < lbl_803E7F60)
        {
            lbl_803DE488 = lbl_803E7F60;
        }
        {
            f32 lh = (f32)(int)cfPrisonGuard_getLiftHeight(gPlayerInteractTarget);
            count = (int)(lh + lbl_803DE488);
        }
        if (count <= 0)
        {
            lbl_803DE488 = lbl_803E7EA4;
            count = 0;
            ObjAnim_SetCurrentMove(obj, 0xb1, lbl_803E7EA4, 0);
            ((PlayerState*)state)->baddie.moveSpeed = lbl_803E7EF8;
        }
        else if (count > 0x800)
        {
            count = 0x800;
        }
        prog = (f32)count / lbl_803E7F64;
        if (prog >= lbl_803E7F68)
        {
            staffactivated_spawnMapEventDebris(gPlayerInteractTarget);
            Sfx_PlayFromObject(obj, (u16)(inner->characterId == 0 ? SFXTRIG_impact3 : SFXTRIG_literun116));
            ObjAnim_SetCurrentMove(obj, 0xd0, lbl_803E7EA4, 0);
            ((PlayerState*)state)->baddie.moveSpeed = lbl_803E7F6C;
        }
        else
        {
            ObjAnim_SetMoveProgress(prog + (f32)(int)randomGetRange(-0x64, 0x64) / lbl_803E7F70,
                                    (ObjAnimComponent*)obj);
        }
        cfPrisonGuard_setLiftHeight(gPlayerInteractTarget, count);
        break;
    }
    case 0xd0:
        cfPrisonGuard_setLiftHeight(gPlayerInteractTarget, 0x800);
        if (*(s8*)&((PlayerState*)state)->baddie.moveDone != 0)
        {
            Sfx_PlayFromObject(obj, SFXTRIG_menuups16k);
            ObjAnim_SetCurrentMove(obj, 0xb2, lbl_803E7EA4, 0);
            ((PlayerState*)state)->baddie.moveSpeed = lbl_803E7EF8;
        }
        break;
    case 0xb2:
        cfPrisonGuard_setLiftHeight(gPlayerInteractTarget, 0x800);
        if ((inner->buttonsJustPressed & PAD_BUTTON_B) != 0)
        {
            buttonDisable(0, PAD_BUTTON_B);
            Sfx_PlayFromObject(obj, SFXTRIG_staff_rocket_boost);
            ObjAnim_SetCurrentMove(obj, 0xad, lbl_803E7EA4, 0);
            ((PlayerState*)state)->baddie.moveSpeed = lbl_803E7F4C;
        }
        break;
    case 0xad:
        if (*(s8*)&((PlayerState*)state)->baddie.moveDone != 0)
        {
            *(u32*)&((PlayerState*)inner)->flags360 |= PLAYER_FLAG_TELEPORTED;
            *(int*)&((PlayerState*)state)->baddie.unk308 = (int)fn_802A514C;
            return 2;
        }
        break;
    default:
        ObjAnim_SetCurrentMove(obj, 0xab, lbl_803E7EA4, 0);
        ((PlayerState*)state)->baddie.moveSpeed = lbl_803E7F40;
        staffactivated_calcInteractionTargetXZ(gPlayerInteractTarget,
                                               &((GameObject*)obj)->anim.localPosX,
                                               &((GameObject*)obj)->anim.localPosZ);
        inner->targetYaw = gPlayerInteractTarget->anim.rotX + 0x8000;
        inner->yaw = inner->targetYaw;
        if (gPlayerPathObject != NULL && ((ByteFlags*)((char*)inner + 0x3f4))->b40)
        {
            inner->staffActionRequest = 4;
            ((ByteFlags*)((char*)inner + 0x3f4))->b08 = 1;
        }
        lbl_803DE488 = lbl_803E7EA4;
        lbl_803DE48C = 0;
        lbl_803DE460 = lbl_803E7EA4;
        if (inner->curAnimId != 0x48 && inner->curAnimId != 0x47)
        {
            struct
            {
                s16 a;
                u8 b;
                u8 c;
            } shk;
            shk.a = 0;
            shk.b = 0;
            shk.c = 1;
            (*gCameraInterface)->setMode(0x43, 1, 0, 4, &shk, 0, 0xff);
        }
        break;
    }
    return 0;
}

void fn_802994A4(GameObject* obj)
{
    *(s16*)((char*)*(int*)&obj->extra + 0x80a) = -1;
    ObjHits_SyncObjectPositionIfDirtyLegacy(obj);
}

int playerStateStaffBoost(GameObject* obj, int state, f32 fv)
{
    PlayerState* inner = obj->extra;
    u32 mask;
    s16 item;
    if (*(s8*)&((PlayerState*)state)->baddie.moveJustStartedA != 0)
    {
        ObjHits_MarkObjectPositionDirty((ObjAnimComponent*)obj);
    }
    if ((s16)getYButtonItemLegacy(&item) == 1 && item == 0x957)
    {
        mask = 0x900;
    }
    else
    {
        mask = 0x100;
    }
    *(int*)((char*)state + 0) |= 0x200000;
    switch (obj->anim.currentMove)
    {
    case 0x4:
        if (lbl_803DE48D == 0)
        {
            if (obj->anim.currentMoveProgress > lbl_803E7F74)
            {
                Sfx_PlayFromObject((int)obj, SFXTRIG_staff_quake_powerup);
                lbl_803DE48D = 1;
            }
        }
        if (*(s8*)&((PlayerState*)state)->baddie.moveDone != 0)
        {
            if ((inner->buttonsHeld & mask) != 0)
            {
                Sfx_PlayFromObject((int)obj, SFXTRIG_staff_quake_strike);
                ObjAnim_SetCurrentMove((int)obj, 0x87, lbl_803E7EA4, 0);
                ((PlayerState*)state)->baddie.moveSpeed = lbl_803E7EF8;
            }
            else
            {
                ObjAnim_SetCurrentMove((int)obj, 0x43, lbl_803E7EA4, 0);
                ((PlayerState*)state)->baddie.moveSpeed = lbl_803E7F78;
            }
        }
        break;
    case 0x87:
        if ((inner->buttonsHeld & mask) != 0 &&
            inner->chargeLevel <=
                (f32) * (s16*)((char*)*(int*)((char*)*(int*)&obj->extra + 0x35c) + 0x4))
        {
            ((PlayerState*)state)->baddie.moveSpeed = lbl_803E7F20 * fv + ((PlayerState*)state)->baddie.moveSpeed;
            if (((PlayerState*)state)->baddie.moveSpeed > lbl_803E7F6C)
            {
                ((PlayerState*)state)->baddie.moveSpeed = *(f32*)&lbl_803E7F6C;
            }
            inner->chargeLevel = lbl_803E7F7C * fv + inner->chargeLevel;
            inner->chargeLevel = lbl_803E7E98 * fv + inner->chargeLevel;
            if (inner->chargeLevel >= lbl_803E7ED8)
            {
                int sub;
                int v;
                inner->chargeLevel = lbl_803E7EA4;
                sub = *(int*)((char*)*(int*)&obj->extra + 0x35c);
                v = *(s16*)((char*)sub + 0x4) - 0xa;
                if (v < 0)
                {
                    v = 0;
                }
                else if (v > *(s16*)((char*)sub + 0x6))
                {
                    v = *(s16*)((char*)sub + 0x6);
                }
                *(s16*)((char*)sub + 0x4) = v;
                Sfx_PlayFromObject((int)obj, SFXTRIG_staff_boulder_move2);
                ObjAnim_SetCurrentMove((int)obj, 0x88, lbl_803E7EA4, 0);
                ((PlayerState*)state)->baddie.moveSpeed = lbl_803E7F6C;
            }
        }
        else
        {
            ObjAnim_SetCurrentMove((int)obj, 0x43, lbl_803E7EA4, 0);
            ((PlayerState*)state)->baddie.moveSpeed = lbl_803E7F78;
        }
        break;
    case 0x43:
        if ((inner->buttonsHeld & mask) != 0)
        {
            Sfx_PlayFromObject((int)obj, SFXTRIG_staff_quake_strike);
            ObjAnim_SetCurrentMove((int)obj, 0x87, lbl_803E7EA4, 0);
            ((PlayerState*)state)->baddie.moveSpeed = lbl_803E7EF8;
        }
        else if ((inner->buttonsJustPressed & PAD_BUTTON_B) != 0)
        {
            buttonDisable(0, PAD_BUTTON_B);
            ObjAnim_SetCurrentMove((int)obj, 0x44, lbl_803E7EA4, 0);
            ((PlayerState*)state)->baddie.moveSpeed = lbl_803E7F80;
        }
        break;
    case 0x44:
        if (*(s8*)&((PlayerState*)state)->baddie.moveDone != 0)
        {
            *(u32*)&((PlayerState*)inner)->flags360 |= PLAYER_FLAG_TELEPORTED;
            obj->anim.velocityY = lbl_803E7EA4;
            inner->animState = -1;
            *(int*)&((PlayerState*)state)->baddie.unk308 = (int)fn_802A514C;
            return 2;
        }
        break;
    case 0x88:
        obj->anim.velocityY = lbl_803E7F6C * fv + obj->anim.velocityY;
        if (*(s8*)&((PlayerState*)state)->baddie.moveDone != 0)
        {
            void* t = getTrickyObject();
            if (t != NULL)
            {
                trickyImpress((GameObject*)t);
            }
            ObjAnim_SetCurrentMove((int)obj, 0x7f, lbl_803E7EA4, 0);
            ((PlayerState*)state)->baddie.moveSpeed = lbl_803E7EB4;
        }
        break;
    case 0x7f:
        obj->anim.velocityY = lbl_803E7EFC * fv + obj->anim.velocityY;
        if (obj->anim.velocityY > lbl_803E7F10)
        {
            obj->anim.velocityY = *(f32*)&lbl_803E7F10;
        }
        if (obj->anim.localPosY > lbl_803DE490)
        {
            ObjAnim_SetCurrentMove((int)obj, 0x80, lbl_803E7EA4, 0);
            ((PlayerState*)state)->baddie.moveSpeed = lbl_803E7F84;
        }
        break;
    case 0x80:
    {
        f32 p;
        obj->anim.velocityY = obj->anim.velocityY - lbl_803E7F88 * fv;
        p = powfBitEstimate(lbl_803E7F90, fv);
        obj->anim.velocityY = obj->anim.velocityY * p;
        (*(void (*)(int, int, f32, int))(*(int*)((char*)*gPlayerInterface + 0x20)))((int)obj, state, fv, 1);
        if (*(s8*)&((PlayerState*)state)->baddie.moveDone != 0)
        {
            *(u32*)&((PlayerState*)inner)->flags360 |= PLAYER_FLAG_TELEPORTED;
            obj->anim.velocityY = lbl_803E7EA4;
            inner->animState = -1;
            *(int*)&((PlayerState*)state)->baddie.unk308 = (int)fn_802A514C;
            return 2;
        }
        break;
    }
    default:
    {
        f32 fromVec[3];
        f32 toVec[3];
        u8 hitBuf[0x58];
        f32 zero = lbl_803E7EA4;
        ((PlayerState*)state)->baddie.animSpeedC = zero;
        ((PlayerState*)state)->baddie.animSpeedB = zero;
        ((PlayerState*)state)->baddie.animSpeedA = zero;
        obj->anim.velocityX = zero;
        obj->anim.velocityY = zero;
        obj->anim.velocityZ = zero;
        ObjAnim_SetCurrentMove((int)obj, 0x4, zero, 0);
        ((PlayerState*)state)->baddie.moveSpeed = lbl_803E7F84;
        lbl_803DE494 = obj->anim.localPosY;
        inner->targetYaw = gPlayerInteractTarget->anim.rotX;
        inner->yaw = inner->targetYaw;
        staffactivated_calcInteractionTargetXZ(gPlayerInteractTarget, &((GameObject*)obj)->anim.localPosX,
                                               &((GameObject*)obj)->anim.localPosZ);
        fn_802AB5A4(obj, (int)inner, 7);
        *(int*)((char*)state + 0x4) |= 0x8000000;
        fromVec[0] = obj->anim.localPosX;
        fromVec[1] = lbl_803E7ED8 + obj->anim.localPosY;
        fromVec[2] = obj->anim.localPosZ;
        toVec[0] = fromVec[0] - lbl_803E7F5C * mathSinf(gPlayerPi * (f32)(int)inner->targetYaw / lbl_803E7F98);
        toVec[1] = fromVec[1];
        toVec[2] = fromVec[2] - lbl_803E7F5C * mathCosf(gPlayerPi * (f32)(int)inner->targetYaw / lbl_803E7F98);
        if (objBboxFn_800640cc(fromVec, toVec, lbl_803E7EA4, 3, (TrackBBoxHit*)hitBuf, obj, 1, 1, 0xff, 0) != 0)
        {
            lbl_803DE490 = *(f32*)(hitBuf + 0x3c) - lbl_803E7F30;
        }
        else
        {
            lbl_803DE490 = lbl_803E7F5C + obj->anim.localPosY;
        }
        lbl_803DE48D = 0;
        if (gPlayerPathObject != NULL && ((ByteFlags*)((char*)inner + 0x3f4))->b40)
        {
            inner->staffActionRequest = 4;
            ((ByteFlags*)((char*)inner + 0x3f4))->b08 = 1;
        }
        inner->chargeLevel = lbl_803E7EA4;
        if (inner->curAnimId != 0x48 && inner->curAnimId != 0x47)
        {
            struct
            {
                s16 a;
                u8 b;
                u8 c;
            } shk;
            shk.a = 0;
            shk.b = 0;
            shk.c = 1;
            (*gCameraInterface)->setMode(0x43, 1, 0, 4, &shk, 0, 0xff);
        }
        break;
    }
    }
    return 0;
}

int playerState31(GameObject* obj, int p2)
{
    PlayerState* inner = obj->extra;
    u8 state30 = 0x1a;
    u8 state29 = 0x1a;
    void* near;
    f32 dist;
    f32 dir[3];
    f32 cosv;
    f32 sinv;
    f32 fz;
    dist = lbl_803E7F5C;
    near = (void*)ObjGroup_FindNearestObjectLegacy(MAGICPLANT_OBJGROUP_B, obj, &dist);
    ((ByteFlags*)((char*)inner + 0x3f4))->b20 = 1;
    fz = lbl_803E7EA4;
    inner->buttonHoldTimer = fz;
    if (near != 0)
    {
        dir[0] = *(f32*)((char*)near + 0xc) - obj->anim.localPosX;
        dir[1] = *(f32*)((char*)near + 0x10) - obj->anim.localPosY;
        dir[2] = *(f32*)((char*)near + 0x14) - obj->anim.localPosZ;
        dir[1] = fz;
        Vec3_Normalize(dir);
        cosv = mathSinf(gPlayerPi * (f32)inner->targetYaw / lbl_803E7F98);
        sinv = mathCosf(gPlayerPi * (f32)inner->targetYaw / lbl_803E7F98);
        switch (*(u8*)(*(int*)((char*)near + 0x50) + 0x75))
        {
        case 3:
            if (dir[2] * cosv - dir[0] * sinv > lbl_803E7EA4)
            {
                state29 = 0x1a;
            }
            state30 = state29;
            break;
        case 2:
            state29 = 0x1a;
            break;
        case 1:
            state30 ^= state29;
            state29 ^= state30;
            state30 ^= state29;
            break;
        case 0:
        default:
            inner->altMoveToggle = (u8)(inner->altMoveToggle ^ 1);
            if (inner->altMoveToggle != 0)
            {
                state29 = 0x1a;
            }
            break;
        }
    }
    else
    {
        inner->altMoveToggle = (u8)(inner->altMoveToggle ^ 1);
        if (inner->altMoveToggle != 0)
        {
            state29 = 0x1a;
        }
    }
    if (*(u8*)((char*)p2 + 0x34b) == 2 && ((PlayerState*)p2)->baddie.inputMagnitude > lbl_803E7EAC)
    {
        ObjAnim_SetCurrentMove((int)obj, gPlayerMoveSlotTable[((s16*)((char*)inner->moveSlots + 2))[(u8)state30 * 88]],
                               lbl_803E7EA4, 0);
        inner->moveSlotIndex = state30;
        *(int*)&((PlayerState*)p2)->baddie.unk308 = (int)fn_8029BC08;
        return 0x27;
    }
    ObjAnim_SetCurrentMove((int)obj, gPlayerMoveSlotTable[((s16*)((char*)inner->moveSlots + 2))[(u8)state29 * 88]],
                           lbl_803E7EA4, 0);
    inner->moveSlotIndex = state29;
    *(int*)&((PlayerState*)p2)->baddie.unk308 = (int)fn_8029BC08;
    return 0x27;
}
#pragma opt_propagation off
int playerState30(GameObject* obj, int state, f32 fv)
{
    PlayerState* inner = obj->extra;
    int h[1];
    struct
    {
        u8 pad[6];
        u16 mode;
        f32 scale;
        f32 x;
        f32 y;
        f32 z;
    } pfx;
    f32 timer;

    if (lbl_803DE42C != 0)
    {
        Sfx_KeepAliveLoopedObjectSoundIntLegacy((int)obj, SFXTRIG_whit3_c);
        timer = inner->stateTimer - timeDelta;
        inner->stateTimer = timer;
        if (timer <= lbl_803E7EA4)
        {
            int sub = *(int*)((char*)*(int*)&obj->extra + 0x35c);
            int v = *(s16*)((char*)sub + 0x4) - 1;
            if (v < 0)
            {
                v = 0;
            }
            else if (v > *(s16*)((char*)sub + 0x6))
            {
                v = *(s16*)((char*)sub + 0x6);
            }
            *(s16*)((char*)sub + 0x4) = v;
            inner->stateTimer = lbl_803E7F58;
        }
        ObjPath_GetPointWorldPosition(gPlayerPathObject, 5, &pfx.x, &pfx.y, &pfx.z, 0);
        pfx.scale = lbl_803E7F9C;
        h[0] = 0x200000;
        pfx.mode = 0;
        (*gPartfxInterface)->spawnObject((void*)gPlayerPathObject, 0x7f5, &pfx, h[0] + 1, -1, NULL);
        pfx.mode = 1;
        (*gPartfxInterface)->spawnObject((void*)gPlayerPathObject, 0x7f5, &pfx, h[0] + 1, -1, NULL);
        if ((inner->buttonsHeld & gPlayerHeldButtonMask) == 0 ||
            *(s16*)((char*)*(int*)((char*)*(int*)&obj->extra + 0x35c) + 0x4) == 0 || getCurSeqNoInt() != 0)
        {
            int z[2];
            void** p[1];
            z[0] = 0;
            lbl_803DE42C = z[0];
            z[1] = lbl_803DE42C;
            p[0] = gPlayerSpawnedObjects;
            do
            {
                if (*p[0] != NULL)
                {
                    Obj_FreeObject((GameObject*)*p[0]);
                    *p[0] = NULL;
                }
                p[0]++;
                z[1]++;
            } while (z[1] < 7);
            if (gPlayerResource != NULL)
            {
                Resource_Release(gPlayerResource);
                gPlayerResource = NULL;
            }
        }
    }
    if (inner->deferredItemCommand != -1 || (*(int*)&((PlayerState*)state)->baddie.unk31C & 0x800) != 0)
    {
        int r = playerStateTryCastSpell(obj, state, fv);
        if (r != 0)
        {
            return r;
        }
        inner->deferredItemCommand = -1;
    }
    if ((*(int*)&((PlayerState*)state)->baddie.unk31C & 0x400) != 0)
    {
        u8 sel = *(u8*)((char*)state + 0x34b);
        if (sel == 1)
        {
            inner->moveSlotIndex = 8;
            ObjAnim_SetCurrentMove(
                (int)obj, gPlayerMoveSlotTable[*(s16*)((inner->moveSlots + 2) + (u32)inner->moveSlotIndex * 0xb0)],
                lbl_803E7EA4, 0);
            *(int*)&((PlayerState*)state)->baddie.unk308 = (int)fn_8029BC08;
            return 0x27;
        }
        if (sel == 3)
        {
            inner->moveSlotIndex = 9;
            ObjAnim_SetCurrentMove(
                (int)obj, gPlayerMoveSlotTable[*(s16*)((inner->moveSlots + 2) + (u32)inner->moveSlotIndex * 0xb0)],
                lbl_803E7EA4, 0);
            *(int*)&((PlayerState*)state)->baddie.unk308 = (int)fn_8029BC08;
            return 0x27;
        }
        if (sel == 4)
        {
            inner->moveSlotIndex = 7;
            ObjAnim_SetCurrentMove(
                (int)obj, gPlayerMoveSlotTable[*(s16*)((inner->moveSlots + 2) + (u32)inner->moveSlotIndex * 0xb0)],
                lbl_803E7EA4, 0);
            *(int*)&((PlayerState*)state)->baddie.unk308 = (int)fn_8029BC08;
            return 0x27;
        }
        if (sel == 2)
        {
            inner->moveSlotIndex = 6;
            ObjAnim_SetCurrentMove(
                (int)obj, gPlayerMoveSlotTable[*(s16*)((inner->moveSlots + 2) + (u32)inner->moveSlotIndex * 0xb0)],
                lbl_803E7EA4, 0);
            *(int*)&((PlayerState*)state)->baddie.unk308 = (int)fn_8029BC08;
            return 0x27;
        }
        inner->moveSlotIndex = 5;
        ObjAnim_SetCurrentMove((int)obj,
                               gPlayerMoveSlotTable[*(s16*)((inner->moveSlots + 2) + (u32)inner->moveSlotIndex * 0xb0)],
                               lbl_803E7EA4, 0);
        *(int*)&((PlayerState*)state)->baddie.unk308 = (int)fn_8029BC08;
        return 0x27;
    }
    if ((*(int*)&((PlayerState*)state)->baddie.unk31C & 0x100) != 0)
    {
        if (*(u8*)((char*)state + 0x34b) == 2 && ((PlayerState*)state)->baddie.inputMagnitude > lbl_803E7EAC)
        {
            inner->moveSlotIndex = 1;
            ObjAnim_SetCurrentMove(
                (int)obj, gPlayerMoveSlotTable[*(s16*)((inner->moveSlots + 2) + (u32)inner->moveSlotIndex * 0xb0)],
                lbl_803E7EA4, 0);
            *(int*)&((PlayerState*)state)->baddie.unk308 = (int)fn_8029BC08;
            return 0x27;
        }
        if (*(u8*)((char*)state + 0x34b) == 3 && ((PlayerState*)state)->baddie.inputMagnitude > lbl_803E7EAC)
        {
            inner->moveSlotIndex = 4;
            ObjAnim_SetCurrentMove(
                (int)obj, gPlayerMoveSlotTable[*(s16*)((inner->moveSlots + 2) + (u32)inner->moveSlotIndex * 0xb0)],
                lbl_803E7EA4, 0);
            *(int*)&((PlayerState*)state)->baddie.unk308 = (int)fn_8029BC08;
            return 0x27;
        }
        if (*(u8*)((char*)state + 0x34b) == 1 && ((PlayerState*)state)->baddie.inputMagnitude > lbl_803E7EAC)
        {
            inner->moveSlotIndex = 3;
            ObjAnim_SetCurrentMove(
                (int)obj, gPlayerMoveSlotTable[*(s16*)((inner->moveSlots + 2) + (u32)inner->moveSlotIndex * 0xb0)],
                lbl_803E7EA4, 0);
            *(int*)&((PlayerState*)state)->baddie.unk308 = (int)fn_8029BC08;
            return 0x27;
        }
        if (*(u8*)((char*)state + 0x34b) == 4 && ((PlayerState*)state)->baddie.inputMagnitude > lbl_803E7EAC)
        {
            inner->moveSlotIndex = 2;
            ObjAnim_SetCurrentMove(
                (int)obj, gPlayerMoveSlotTable[*(s16*)((inner->moveSlots + 2) + (u32)inner->moveSlotIndex * 0xb0)],
                lbl_803E7EA4, 0);
            *(int*)&((PlayerState*)state)->baddie.unk308 = (int)fn_8029BC08;
            return 0x27;
        }
        inner->moveSlotIndex = 0;
        ObjAnim_SetCurrentMove((int)obj,
                               gPlayerMoveSlotTable[*(s16*)((inner->moveSlots + 2) + (u32)inner->moveSlotIndex * 0xb0)],
                               lbl_803E7EA4, 0);
        *(int*)&((PlayerState*)state)->baddie.unk308 = (int)fn_8029BC08;
        return 0x27;
    }
    return 0;
}
#pragma opt_propagation reset

void fn_8029A420(GameObject* obj)
{
    PlayerState* inner = obj->extra;
    if (inner->curAnimId != 0x42 && getCurSeqNoInt() == 0)
    {
        (*gCameraInterface)->setMode(0x42, 0, 1, 0, NULL, 0x3c, 0xfe);
    }
    ((ByteFlags*)((char*)inner + 0x3f6))->b40 = 0;
    inner->animState = -1;
}

void fn_8029A4A8(GameObject* obj, int p2)
{
    int z[2];
    PlayerState* inner = obj->extra;
    int sel = ((PlayerState*)p2)->baddie.controlMode;

    if (sel == 0x2a)
        return;
    if (sel == 0x2e)
        return;
    if (sel == 0x2f)
        return;
    if (sel == 0x2c)
        return;

    *(u32*)&((PlayerState*)inner)->flags360 |= PLAYER_FLAG_TELEPORTED;
    inner->animState = -1;
    *(u32*)&((PlayerState*)inner)->flags360 &= ~0x2000400LL;

    if (((PlayerState*)p2)->baddie.controlMode != 0x2b)
    {
        if (inner->curAnimId != 0x42 && getCurSeqNoInt() == 0)
        {
            (*gCameraInterface)->setMode(0x42, 0, 1, 0, NULL, 0x3c, 0xfe);
        }
        ((ByteFlags*)((char*)inner + 0x3f6))->b40 = 0;
    }

    z[0] = 0;
    lbl_803DE42C = z[0];
    for (z[1] = z[0]; z[1] < 7; z[1]++)
    {
        if (gPlayerSpawnedObjects[z[1]] != NULL)
        {
            Obj_FreeObject((GameObject*)gPlayerSpawnedObjects[z[1]]);
            gPlayerSpawnedObjects[z[1]] = NULL;
        }
    }
    if (gPlayerResource != NULL)
    {
        Resource_Release(gPlayerResource);
        gPlayerResource = NULL;
    }
}
#pragma opt_propagation off

int playerStateFireLaser(int obj, int state)
{
    PlayerState* inner = ((GameObject*)obj)->extra;
    int r = ((int (*)(int, int, int))fn_802AC7DC)(obj, state, (int)inner);
    if (r != 0)
    {
        return r;
    }
    setAButtonIcon(6);
    setBButtonIcon(0xa);
    if (*(s8*)&((PlayerState*)state)->baddie.moveJustStartedA != 0)
    {
        int p = *(int*)((char*)*(int*)&((GameObject*)obj)->extra + 0x35c);
        int val = *(s16*)((char*)p + 4);
        if (val < 0)
        {
            val = 0;
        }
        else
        {
            int hi = *(s16*)((char*)p + 6);
            if (val > hi)
            {
                val = hi;
            }
        }
        *(s16*)((char*)p + 4) = (s16)val;
        lbl_803DE45C = lbl_803E7F30;
    }
    if (lbl_803E7F30 == lbl_803DE45C || lbl_803E7FA0 == lbl_803DE45C || lbl_803E7FA4 == lbl_803DE45C)
    {
        fn_802AA2B0(obj, state, inner->aimInputZ, (f32)randomGetRange(-0xc8, 0xc8) / lbl_803E7F5C);
    }
    lbl_803DE45C = lbl_803DE45C - lbl_803E7EE0;
    if (lbl_803DE45C < lbl_803E7EA4)
    {
        *(int*)&((PlayerState*)state)->baddie.unk308 = (int)fn_8029A4A8;
        return 0x2d;
    }
    if (((PlayerState*)state)->baddie.targetObj == NULL)
    {
        if ((inner->buttonsJustPressed & PAD_BUTTON_B) != 0 || inner->curAnimId != 0x52)
        {
            *(int*)&((PlayerState*)state)->baddie.unk308 = (int)fn_8029A420;
            return 0x2c;
        }
    }
    return 0;
}

typedef struct
{
    u8 pad[0x1ba8];
    int moveA[4];
    int moveB[4];
    int moveC[4];
    f32 spdD[4];
    f32 spdE[4];
} HeadMoveTable;

typedef struct
{
    int a;
    int b;
} ColPair;

extern ColPair lbl_803E7E78;
extern f32 lbl_803E7FDC;
extern f32 lbl_803E7FE0;
extern f32 lbl_803E7FE4;

int playerStateShootFireball(GameObject* obj, int state, f32 fv)
{
    PlayerState* inner = obj->extra;
    int r;
    int h[1];
    f32 timer;
    struct
    {
        u8 pad[6];
        u16 mode;
        f32 scale;
        f32 x;
        f32 y;
        f32 z;
    } pfx2;
    struct
    {
        u8 pad[6];
        u16 mode;
        f32 scale;
        f32 x;
        f32 y;
        f32 z;
    } pfx;

    if (((PlayerState*)state)->baddie.targetObj == NULL)
    {
        f32 z = lbl_803E7EA4;
        ((PlayerState*)state)->baddie.animSpeedC = z;
        ((PlayerState*)state)->baddie.animSpeedB = z;
        ((PlayerState*)state)->baddie.animSpeedA = z;
        obj->anim.velocityX = z;
        obj->anim.velocityY = z;
        obj->anim.velocityZ = z;
    }
    r = ((int (*)(int, int, int))fn_802AC7DC)((int)obj, state, (int)inner);
    if (r != 0)
    {
        return r;
    }
    setAButtonIcon(6);
    setBButtonIcon(0xa);
    if (lbl_803DE42C != 0)
    {
        Sfx_KeepAliveLoopedObjectSoundIntLegacy((int)obj, SFXTRIG_whit3_c);
        timer = inner->stateTimer - timeDelta;
        inner->stateTimer = timer;
        if (timer <= lbl_803E7EA4)
        {
            int sub = *(int*)((char*)*(int*)&obj->extra + 0x35c);
            int v = *(s16*)((char*)sub + 0x4) - 1;
            if (v < 0)
            {
                v = 0;
            }
            else if (v > *(s16*)((char*)sub + 0x6))
            {
                v = *(s16*)((char*)sub + 0x6);
            }
            *(s16*)((char*)sub + 0x4) = v;
            inner->stateTimer = lbl_803E7F58;
        }
        ObjPath_GetPointWorldPosition(gPlayerPathObject, 5, &pfx.x, &pfx.y, &pfx.z, 0);
        pfx.scale = lbl_803E7F9C;
        h[0] = 0x200000;
        pfx.mode = 0;
        (*gPartfxInterface)->spawnObject((void*)gPlayerPathObject, 0x7f5, &pfx, h[0] + 1, -1, NULL);
        pfx.mode = 1;
        (*gPartfxInterface)->spawnObject((void*)gPlayerPathObject, 0x7f5, &pfx, h[0] + 1, -1, NULL);
        if ((((PlayerState*)inner)->buttonsHeld & gPlayerHeldButtonMask) == 0 ||
            *(s16*)((char*)*(int*)((char*)*(int*)&obj->extra + 0x35c) + 0x4) == 0 || getCurSeqNoInt() != 0)
        {
            int z[2];
            void** p[1];
            z[1] = z[0] = lbl_803DE42C = 0;
            p[0] = gPlayerSpawnedObjects;
            do
            {
                if (*p[0] != NULL)
                {
                    Obj_FreeObject((GameObject*)*p[0]);
                    *p[0] = NULL;
                }
                p[0]++;
                z[1]++;
            } while (z[1] < 7);
            if (gPlayerResource != NULL)
            {
                Resource_Release(gPlayerResource);
                gPlayerResource = NULL;
            }
        }
    }
    switch (obj->anim.currentMove)
    {
    case 0x43f:
        if (((PlayerState*)state)->baddie.targetObj == NULL)
        {
            int res;
            int half;
            int low;
            f32 b;
            f32 a;
            f32 k;
            *(u32*)&((PlayerState*)inner)->flags360 &= ~PLAYER_FLAG_AIM_READY;
            a = inner->aimInputZ;
            b = inner->aimInputX;
            res = getScreenResolution();
            half = res >> 17;
            low = (res & 0xffff) >> 1;
            inner->aimScreenY = (k = lbl_803E7E98) * (b * (f32)(int)low) + (f32)(int)low;
            if (a < lbl_803E7EA4)
            {
                inner->aimScreenX = k * (a * (f32)(int)half) + (f32)(int)half;
            }
            else
            {
                inner->aimScreenX = lbl_803E7F44 * (a * (f32)(int)half) + (f32)(int)half;
            }
            *(u32*)&((PlayerState*)inner)->flags360 |= PLAYER_FLAG_AIM_READY;
            if (*(s8*)&((PlayerState*)state)->baddie.moveDone != 0)
            {
                *(int*)&((PlayerState*)state)->baddie.unk308 = (int)fn_8029A4A8;
                return 0x2d;
            }
        }
        break;
    default:
    {
        int i;
        int sub;
        int v;
        ObjPath_GetPointWorldPosition(gPlayerPathObject, 0, &pfx2.x, &pfx2.y, &pfx2.z, 0);
        for (i = 0; i < 0x28; i++)
        {
            (*gPartfxInterface)->spawnObject((void*)gPlayerPathObject, 0x3ed, &pfx2, 0x200001, -1, NULL);
        }
        sub = *(int*)((char*)*(int*)&obj->extra + 0x35c);
        v = *(s16*)((char*)sub + 0x4) - 2;
        if (v < 0)
        {
            v = 0;
        }
        else if (v > *(s16*)((char*)sub + 0x6))
        {
            v = *(s16*)((char*)sub + 0x6);
        }
        *(s16*)((char*)sub + 0x4) = v;
        staffShootFireball(obj, state, inner->aimInputZ);
        if (((PlayerState*)state)->baddie.targetObj == NULL)
        {
            *(int*)&((PlayerState*)state)->baddie.unk308 = (int)fn_8029A4A8;
            return 0x2d;
        }
        else
        {
            lbl_803DE460 = lbl_803E7EA4;
            lbl_803DE464 = lbl_803E7EA4;
        }
    }
    break;
    }
    if (((PlayerState*)state)->baddie.targetObj == NULL)
    {
        if ((((PlayerState*)inner)->buttonsJustPressed & PAD_BUTTON_B) != 0 || inner->curAnimId != 0x52)
        {
            *(int*)&((PlayerState*)state)->baddie.unk308 = (int)fn_8029A420;
            return 0x2c;
        }
    }
    return 0;
}


int playerStateTryCastSpell(GameObject* obj, int state, f32 fv)
{
    PlayerState* inner = obj->extra;
    int h[1];
    f32 timer;
    struct
    {
        u8 pad[6];
        u16 mode;
        f32 scale;
        f32 x;
        f32 y;
        f32 z;
    } pfx;

    if (lbl_803DE42C != 0)
    {
        Sfx_KeepAliveLoopedObjectSoundIntLegacy((int)obj, SFXTRIG_whit3_c);
        timer = inner->stateTimer - timeDelta;
        inner->stateTimer = timer;
        if (timer <= lbl_803E7EA4)
        {
            int sub = *(int*)((char*)*(int*)&obj->extra + 0x35c);
            int v = *(s16*)((char*)sub + 0x4) - 1;
            if (v < 0)
            {
                v = 0;
            }
            else if (v > *(s16*)((char*)sub + 0x6))
            {
                v = *(s16*)((char*)sub + 0x6);
            }
            *(s16*)((char*)sub + 0x4) = v;
            inner->stateTimer = lbl_803E7F58;
        }
        ObjPath_GetPointWorldPosition(gPlayerPathObject, 5, &pfx.x, &pfx.y, &pfx.z, 0);
        pfx.scale = lbl_803E7F9C;
        h[0] = 0x200000;
        pfx.mode = 0;
        (*gPartfxInterface)->spawnObject((void*)gPlayerPathObject, 0x7f5, &pfx, h[0] + 1, -1, NULL);
        pfx.mode = 1;
        (*gPartfxInterface)->spawnObject((void*)gPlayerPathObject, 0x7f5, &pfx, h[0] + 1, -1, NULL);
        if ((inner->buttonsHeld & gPlayerHeldButtonMask) == 0 ||
            *(s16*)((char*)*(int*)((char*)*(int*)&obj->extra + 0x35c) + 0x4) == 0 || getCurSeqNoInt() != 0)
        {
            int z[2];
            void** p[1];
            inner->animState = -1;
            z[0] = lbl_803DE42C = z[1] = 0;
            p[0] = gPlayerSpawnedObjects;
            do
            {
                if (*p[0] != NULL)
                {
                    Obj_FreeObject((GameObject*)*p[0]);
                    *p[0] = NULL;
                }
                p[0]++;
                z[0]++;
            } while (z[0] < 7);
            if (gPlayerResource != NULL)
            {
                Resource_Release(gPlayerResource);
                gPlayerResource = NULL;
            }
        }
    }
    else if (inner->deferredItemCommand != -1 || (inner->buttonsJustPressed & PAD_BUTTON_Y) != 0)
    {
        int yitem;
        u16 b28;
        s16 item;
        if (inner->buttonsJustPressed & PAD_BUTTON_Y)
        {
            yitem = getYButtonItemLegacy(&item);
            b28 = 0x800;
        }
        else
        {
            yitem = 0;
            item = inner->deferredItemCommand;
            b28 = 0x100;
        }
        if (inner->deferredItemCommand != -1 ||
            (yitem == 1 && (item == GAMEBIT_STAFF_ABILITY_FIRE_BLASTER || item == GAMEBIT_STAFF_ABILITY_FREEZE_BLAST)))
        {
            buttonDisable(0, 0x900);
            ((PlayerState*)inner)->buttonsJustPressed = inner->buttonsJustPressed & ~0x900;
            gPlayerSelectedItem = item;
            if (item != inner->animState)
            {
                playerCastSpell((int)obj, (int)inner, item);
            }
            switch (gPlayerSelectedItem)
            {
            case GAMEBIT_STAFF_ABILITY_FIRE_BLASTER:
            {
                int sub = *(int*)((char*)*(int*)&obj->extra + 0x35c);
                if (*(s16*)((char*)sub + 0x4) >= 2)
                {
                    int r = playerStateShootFireball(obj, state, fv);
                    if (r != 0)
                    {
                        return r;
                    }
                }
                else
                {
                    Sfx_PlayFromObject(0, SFXTRIG_id_10a);
                }
                break;
            }
            case 0x958:
            {
                int sub = *(int*)((char*)*(int*)&obj->extra + 0x35c);
                if (*(s16*)((char*)sub + 0x4) >= 0)
                {
                    int r = ((int (*)(int, int, f32))playerStateFireLaser)((int)obj, state, fv);
                    if (r != 0)
                    {
                        return r;
                    }
                }
                else
                {
                    Sfx_PlayFromObject(0, SFXTRIG_id_10a);
                }
                break;
            }
            case GAMEBIT_STAFF_ABILITY_FREEZE_BLAST:
            {
                int sub = *(int*)((char*)*(int*)&obj->extra + 0x35c);
                if (*(s16*)((char*)sub + 0x4) >= 1)
                {
                    int sub2;
                    int v;
                    ((void (*)(int))playerCastIceSpell)((int)obj);
                    gPlayerHeldButtonMask = b28;
                    lbl_803DE42C = 1;
                    lbl_803DE430 = lbl_803E7EA4;
                    inner->stateTimer = lbl_803E7F58;
                    sub2 = *(int*)((char*)*(int*)&obj->extra + 0x35c);
                    v = *(s16*)((char*)sub2 + 0x4) - 1;
                    if (v < 0)
                    {
                        v = 0;
                    }
                    else if (v > *(s16*)((char*)sub2 + 0x6))
                    {
                        v = *(s16*)((char*)sub2 + 0x6);
                    }
                    *(s16*)((char*)sub2 + 0x4) = v;
                }
                break;
            }
            }
        }
    }
    inner->animState = -1;
    return 0;
}
int playerStateAimStaff(int obj, int state)
{
    PlayerState* inner = ((GameObject*)obj)->extra;
    int r;
    f32 spin;
    struct
    {
        u8 pad[6];
        u16 mode;
        f32 scale;
        f32 x;
        f32 y;
        f32 z;
    } pfx;

    r = ((int (*)(int, int, int))fn_802AC7DC)(obj, state, (int)inner);
    if (r != 0)
    {
        return r;
    }
    {
        f32 z = lbl_803E7EA4;
        ((PlayerState*)state)->baddie.animSpeedC = z;
        ((PlayerState*)state)->baddie.animSpeedB = z;
        ((PlayerState*)state)->baddie.animSpeedA = z;
        ((GameObject*)obj)->anim.velocityX = z;
        ((GameObject*)obj)->anim.velocityY = z;
        ((GameObject*)obj)->anim.velocityZ = z;
    }
    *(u32*)&((PlayerState*)inner)->flags360 |= 0x2000000LL;
    setAButtonIcon(6);
    setBButtonIcon(0xa);
    switch (((GameObject*)obj)->anim.currentMove)
    {
    case 0x43e:
    {
        f32 t;
        f32 c;
        f32 a;
        t = ((PlayerState*)state)->baddie.moveInputZ / lbl_803E7FA8;
        c = (t < lbl_803E7ECC) ? lbl_803E7ECC : ((t > lbl_803E7EE0) ? lbl_803E7EE0 : t);
        inner->aimInputZ = inner->aimInputZ + interpolate(c - inner->aimInputZ, lbl_803E7EFC, timeDelta);
        t = ((PlayerState*)state)->baddie.moveInputX / lbl_803E7FA8;
        c = (t < lbl_803E7ECC) ? lbl_803E7ECC : ((t > lbl_803E7EE0) ? lbl_803E7EE0 : t);
        inner->aimInputX = inner->aimInputX + interpolate(c - inner->aimInputX, lbl_803E7EFC, timeDelta);
        if ((t = inner->aimInputX) > lbl_803E7EA4)
        {
            spin = t - lbl_803E7EA0;
            if (spin < lbl_803E7EA4)
            {
                spin = lbl_803E7EA4;
            }
        }
        else
        {
            spin = lbl_803E7EA0 + t;
            if (spin > lbl_803E7EA4)
            {
                spin = lbl_803E7EA4;
            }
        }
        a = inner->aimInputZ;
        if (a > *(f32*)&lbl_803E7EA4)
        {
            Object_ObjAnimSetSecondaryBlendMove((ObjAnimComponent*)obj, 0x441, (int)(lbl_803E7FAC * a));
        }
        else
        {
            Object_ObjAnimSetSecondaryBlendMove((ObjAnimComponent*)obj, 0x440, (int)(lbl_803E7FAC * -a));
        }
        inner->bodyLeanHalf = lbl_803E7FB0 * inner->aimInputX;
        objModelGetVecFn_800395d8((GameObject*)(obj), 9);
        *(u32*)&((PlayerState*)inner)->flags360 &= ~PLAYER_FLAG_AIM_READY;
        if (gPlayerSelectedItem == GAMEBIT_STAFF_ABILITY_FIRE_BLASTER)
        {
            f32 bv;
            f32 av;
            int res;
            int half;
            int low;
            f32 k;
            av = inner->aimInputZ;
            bv = inner->aimInputX;
            res = getScreenResolution();
            half = res >> 17;
            low = (res & 0xffff) >> 1;
            inner->aimScreenY = (k = lbl_803E7E98) * (bv * (f32)(int)low) + (f32)(int)low;
            if (av < lbl_803E7EA4)
            {
                inner->aimScreenX = k * (av * (f32)(int)half) + (f32)(int)half;
            }
            else
            {
                inner->aimScreenX = lbl_803E7F44 * (av * (f32)(int)half) + (f32)(int)half;
            }
            *(u32*)&((PlayerState*)inner)->flags360 |= PLAYER_FLAG_AIM_READY;
        }
        if (lbl_803DE42C != 0)
        {
            f32 x;
            int h[1];
            Sfx_KeepAliveLoopedObjectSoundIntLegacy(obj, SFXTRIG_whit3_c);
            x = inner->stateTimer - timeDelta;
            inner->stateTimer = x;
            if (x <= lbl_803E7EA4)
            {
                int sub = *(int*)((char*)*(int*)&((GameObject*)obj)->extra + 0x35c);
                int v = *(s16*)((char*)sub + 0x4) - 1;
                if (v < 0)
                {
                    v = 0;
                }
                else if (v > *(s16*)((char*)sub + 0x6))
                {
                    v = *(s16*)((char*)sub + 0x6);
                }
                *(s16*)((char*)sub + 0x4) = v;
                inner->stateTimer = lbl_803E7F58;
            }
            ObjPath_GetPointWorldPosition(gPlayerPathObject, 5, &pfx.x, &pfx.y, &pfx.z, 0);
            pfx.scale = lbl_803E7F9C;
            h[0] = 0x200000;
            pfx.mode = 0;
            (*gPartfxInterface)->spawnObject((void*)gPlayerPathObject, 0x7f5, &pfx, h[0] + 1, -1, NULL);
            pfx.mode = 1;
            (*gPartfxInterface)->spawnObject((void*)gPlayerPathObject, 0x7f5, &pfx, h[0] + 1, -1, NULL);
            if ((inner->buttonsHeld & gPlayerHeldButtonMask) == 0 ||
                *(s16*)((char*)*(int*)((char*)*(int*)&((GameObject*)obj)->extra + 0x35c) + 0x4) == 0 ||
                getCurSeqNoInt() != 0)
            {
                int z[2];
                void** p[1];
                z[1] = lbl_803DE42C = z[0] = 0;
                p[0] = gPlayerSpawnedObjects;
                do
                {
                    if (*p[0] != NULL)
                    {
                        Obj_FreeObject((GameObject*)*p[0]);
                        *p[0] = NULL;
                    }
                    p[0]++;
                    z[1]++;
                } while (z[1] < 7);
                if (gPlayerResource != NULL)
                {
                    Resource_Release(gPlayerResource);
                    gPlayerResource = NULL;
                }
            }
        }
        else if ((inner->buttonsJustPressed & 0x900) != 0)
        {
            int yitem;
            u16 b28;
            s16 item;
            if (inner->buttonsJustPressed & PAD_BUTTON_Y)
            {
            yitem = getYButtonItemLegacy(&item);
                b28 = 0x800;
            }
            else
            {
                yitem = 0;
                item = gPlayerSelectedItem;
                b28 = 0x100;
            }
            if ((inner->buttonsJustPressed & PAD_BUTTON_A) != 0 ||
                (yitem == 1 &&
                 (item == GAMEBIT_STAFF_ABILITY_FIRE_BLASTER || item == GAMEBIT_STAFF_ABILITY_FREEZE_BLAST)))
            {
                buttonDisable(0, 0x900);
                inner->buttonsJustPressed = inner->buttonsJustPressed & ~0x900;
                gPlayerSelectedItem = item;
                if (item != inner->animState)
                {
                    playerCastSpell(obj, (int)inner, item);
                }
                switch (gPlayerSelectedItem)
                {
                case GAMEBIT_STAFF_ABILITY_FIRE_BLASTER:
                {
                    int sub = *(int*)((char*)*(int*)&((GameObject*)obj)->extra + 0x35c);
                    if (*(s16*)((char*)sub + 0x4) >= 2)
                    {
                        *(int*)&((PlayerState*)state)->baddie.unk308 = (int)fn_8029A4A8;
                        return 0x2f;
                    }
                    Sfx_PlayFromObject(0, SFXTRIG_staff_swipes_long);
                    break;
                }
                case 0x958:
                {
                    int sub = *(int*)((char*)*(int*)&((GameObject*)obj)->extra + 0x35c);
                    if (*(s16*)((char*)sub + 0x4) >= 0)
                    {
                        *(int*)&((PlayerState*)state)->baddie.unk308 = (int)fn_8029A4A8;
                        return 0x30;
                    }
                    Sfx_PlayFromObject(0, SFXTRIG_staff_swipes_long);
                    break;
                }
                case GAMEBIT_STAFF_ABILITY_FREEZE_BLAST:
                {
                    int sub = *(int*)((char*)*(int*)&((GameObject*)obj)->extra + 0x35c);
                    if (*(s16*)((char*)sub + 0x4) >= 1)
                    {
                        int sub2;
                        int v;
                        ((void (*)(int))playerCastIceSpell)(obj);
                        gPlayerHeldButtonMask = b28;
                        lbl_803DE42C = 1;
                        lbl_803DE430 = lbl_803E7EA4;
                        inner->stateTimer = lbl_803E7F58;
                        sub2 = *(int*)((char*)*(int*)&((GameObject*)obj)->extra + 0x35c);
                        v = *(s16*)((char*)sub2 + 0x4) - 1;
                        if (v < 0)
                        {
                            v = 0;
                        }
                        else if (v > *(s16*)((char*)sub2 + 0x6))
                        {
                            v = *(s16*)((char*)sub2 + 0x6);
                        }
                        *(s16*)((char*)sub2 + 0x4) = v;
                        break;
                    }
                    Sfx_PlayFromObject(0, SFXTRIG_staff_swipes_long);
                    break;
                }
                }
            }
        }
        inner->targetYaw = lbl_803E7FB4 * spin + (f32)(int)inner->targetYaw;
        {
            s16 v = inner->targetYaw;
            inner->yaw = v;
            ((GameObject*)obj)->anim.rotX = v;
        }
        break;
    }
    default:
        ObjAnim_SetCurrentMove(obj, 0x43e, lbl_803E7EA4, 0);
        ((PlayerState*)state)->baddie.moveSpeed = lbl_803E7F34;
        lbl_803DE42C = 0;
        lbl_803DE430 = lbl_803E7EA4;
        break;
    }
    if ((inner->buttonsJustPressed & PAD_BUTTON_B) != 0 || inner->curAnimId != 0x52)
    {
        *(u32*)&((PlayerState*)inner)->flags360 &= ~0x2000000LL;
        *(int*)&((PlayerState*)state)->baddie.unk308 = (int)fn_8029A420;
        return 0x2c;
    }
    return 0;
}

extern void objAudioFn_8006edcc();

extern u8 lbl_803DC6A8[8];
extern u8 lbl_803DC6B0[2];
extern int lbl_802C2C50[];
extern f32 lbl_803E8164;

typedef struct
{
    int a[6];
} UiMsgBlock;

static inline u32 playerLoadPendingHitBits(char* p)
{
    return *(u32*)p;
}
#pragma opt_propagation reset

int playerStateStopAimStaff(int obj, int state)
{
    PlayerState* inner = ((GameObject*)obj)->extra;
    int r = ((int (*)(int, int, int))fn_802AC7DC)(obj, state, (int)inner);
    if (r != 0)
    {
        return r;
    }
    if (((GameObject*)obj)->anim.currentMove != 0x449)
    {
        u8 c;
        ObjAnim_SetCurrentMove(obj, 0x449, lbl_803E7EA4, 0);
        ((PlayerState*)state)->baddie.moveSpeed = lbl_803E7F4C;
        Sfx_PlayFromObject(obj, SFXTRIG_staff_swipes_short);
        c = inner->curAnimId;
        if (c != 0x42 && c != 0x4c)
        {
            (*gCameraInterface)->setMode(0x42, 0, 1, 0, NULL, 0x3c, 0xfe);
        }
    }
    if (*(s8*)&((PlayerState*)state)->baddie.moveDone != 0)
    {
        *(int*)&((PlayerState*)state)->baddie.unk308 = (int)fn_802A514C;
        return -1;
    }
    return 0;
}
#pragma opt_propagation off

int playerStateStartAimStaff(GameObject* obj, int state)
{
    PlayerState* inner = obj->extra;
    int r = ((int (*)(int, int, int))fn_802AC7DC)((int)obj, state, (int)inner);
    u32 b;
    if (r != 0)
    {
        return r;
    }
    {
        f32 z = lbl_803E7EA4;
        ((PlayerState*)state)->baddie.animSpeedC = z;
        ((PlayerState*)state)->baddie.animSpeedB = z;
        ((PlayerState*)state)->baddie.animSpeedA = z;
        obj->anim.velocityX = z;
        obj->anim.velocityY = z;
        obj->anim.velocityZ = z;
    }
    setAButtonIcon(6);
    setBButtonIcon(0xa);
    switch (obj->anim.currentMove)
    {
    case 0x43d:
        if (*(s8*)&((PlayerState*)state)->baddie.moveDone != 0)
        {
            *(int*)&((PlayerState*)state)->baddie.unk308 = (int)fn_8029A4A8;
            return 0x2d;
        }
        break;
    case 0x448:
        if (obj->anim.currentMoveProgress > lbl_803E7E9C)
        {
            if (inner->staffGrown == 0)
            {
                Sfx_PlayFromObject((int)obj, SFXTRIG_wp_swddirt16);
                if (gPlayerPathObject != NULL)
                {
                    b = (((PlayerState*)inner)->flags3F4 >> 6) & 1;
                    if (b != 0)
                    {
                        inner->staffActionRequest = 2;
                        ((ByteFlags*)((char*)inner + 0x3f4))->b08 = 0;
                    }
                }
            }
        }
        if (*(s8*)&((PlayerState*)state)->baddie.moveDone != 0)
        {
            *(int*)&((PlayerState*)state)->baddie.unk308 = (int)fn_8029A4A8;
            return 0x2d;
        }
        break;
    default:
    {
        f32 z;
        ObjAnim_SetCurrentMove((int)obj, 0x43d, lbl_803E7EA4, 0);
        ((PlayerState*)state)->baddie.moveSpeed = lbl_803E7F4C;
        if (gPlayerPathObject != NULL)
        {
            b = (((PlayerState*)inner)->flags3F4 >> 6) & 1;
            if (b != 0)
            {
                inner->staffActionRequest = 4;
                ((ByteFlags*)((char*)inner + 0x3f4))->b08 = 1;
            }
        }
        z = lbl_803E7EA4;
        lbl_803DE460 = z;
        lbl_803DE464 = z;
        inner->aimInputZ = z;
        inner->aimInputX = z;
        break;
    }
    }
    if ((inner->buttonsJustPressed & PAD_BUTTON_B) != 0 || inner->curAnimId != 0x52)
    {
        buttonDisable(0, PAD_BUTTON_B);
        *(int*)&((PlayerState*)state)->baddie.unk308 = (int)fn_8029A420;
        return 0x2c;
    }
    return 0;
}
#pragma opt_propagation reset

int playerState29(GameObject* obj, int state)
{
    PlayerState* inner = obj->extra;
    u32 b;
    if ((*(int*)&((PlayerState*)state)->baddie.unk31C & 0x100) != 0)
    {
        b = (((PlayerState*)inner)->flags3F4 >> 6) & 1;
        if (b != 0)
        {
            if (gPlayerPathObject != NULL && b != 0)
            {
                inner->staffActionRequest = 4;
                ((ByteFlags*)((char*)inner + 0x3f4))->b08 = 1;
            }
            *(int*)&((PlayerState*)state)->baddie.unk308 = 0;
            return 0x32;
        }
    }
    return 0;
}

typedef struct
{
    u8 pad[0x88];
    u8 flags;
    u8 pad2[0x1f];
    u8 valsA[3];
    u8 valsB[5];
} HitDesc;

extern int getSbGalleon(void);
extern int DBprotection_getCameraState(void);
extern f32 lbl_803E8160;


int playerState28(GameObject* obj, int state, f32 fv)
{
    PlayerState* inner = obj->extra;
    int v;

    if (((PlayerState*)state)->baddie.hasTarget != 1 && ((PlayerState*)state)->baddie.controlMode != 0x26)
    {
        if (gPlayerPathObject != NULL && ((ByteFlags*)((char*)inner + 0x3f4))->b40)
        {
            inner->staffActionRequest = 0;
            ((ByteFlags*)((char*)inner + 0x3f4))->b08 = 0;
        }
        *(int*)&((PlayerState*)state)->baddie.unk308 = (int)fn_802A514C;
        return 2;
    }
    v = ((int (*)(int, int, int, f32))fn_802AC7DC)((int)obj, state, (int)inner, fv);
    if (v != 0)
    {
        if (gPlayerPathObject != NULL && ((ByteFlags*)((char*)inner + 0x3f4))->b40)
        {
            inner->staffActionRequest = 1;
            ((ByteFlags*)((char*)inner + 0x3f4))->b08 = 1;
        }
        *(int*)&((PlayerState*)state)->baddie.targetObj = 0;
        ((PlayerState*)state)->baddie.hasTarget = 0;
        (*gCameraInterface)->setTarget(0);
        return v;
    }
    if (((PlayerState*)state)->baddie.controlMode == 0x26 || ((ByteFlags*)((char*)inner + 0x3f6))->b20)
    {
        return 0;
    }
    if (((PlayerState*)state)->baddie.controlMode != 0x39)
    {
        if ((getButtons_80014dd8(0) & 0x20) != 0)
        {
            ((ByteFlags*)((char*)inner + 0x3f6))->b20 = 1;
            *(int*)&((PlayerState*)state)->baddie.unk308 = (int)fn_8029782C;
            return 0x3a;
        }
    }
    if (((PlayerState*)state)->baddie.controlMode == 0x39)
    {
        return 0;
    }
    if ((*(int*)&((PlayerState*)state)->baddie.unk31C & 0x100) && gPlayerPathObject != NULL &&
        ((ByteFlags*)((char*)inner + 0x3f4))->b40)
    {
        inner->staffActionRequest = 4;
        ((ByteFlags*)((char*)inner + 0x3f4))->b08 = 1;
    }
    v = playerState30(obj, state, fv);
    if (v != 0)
        return v;
    return 0;
}

typedef struct
{
    s16 rx, ry, rz;
    f32 scale;
    f32 x, y, z;
} HitFxDesc;

typedef struct
{
    int a, b, c, d;
} ColQuad;

typedef struct
{
    u8 knock : 3;
    u8 low : 5;
} KnockBits;

typedef struct
{
    f32 x, y, z;
} VecXYZ;

void fn_8029BC08(GameObject* obj)
{
    Player_GetObjHitsState(obj)->objectHitMask = 0;
    if (((GameObject*)gPlayerPathObject)->anim.classId == 0x2d)
    {
        objSetAnimField48to0((GameObject*)gPlayerPathObject);
    }
    gPlayerSubState = 1;
}

#pragma opt_loop_invariants off
static inline void Player_ApplyStatusDamage(GameObject* obj, int param)
{
    int in2 = *(int*)&obj->extra;
    s8* pc = *(s8**)((char*)in2 + 0x35c);
    int v = pc[0];
    v -= param;
    if (v < 0)
    {
        v = 0;
    }
    else if (v > pc[1])
    {
        v = pc[1];
    }
    pc[0] = (s8)v;
    if (**(s8**)((char*)in2 + 0x35c) <= 0)
    {
        playerDie(obj);
    }
}
#pragma opt_loop_invariants reset

int playerState27(GameObject* obj, int state, f32 fv)
{
    PlayerState* inner = obj->extra;

    if (*(s8*)&((PlayerState*)state)->baddie.moveJustStartedA != 0)
    {
        if (lbl_803DE459 == 0)
        {
            lbl_803DE459 = 1;
        }
        else if (lbl_803DE459 > 2)
        {
            lbl_803DE459 = 2;
        }
        ((PlayerState*)state)->baddie.moveSpeed = (&lbl_803DC690)[lbl_803DE459 - 1];
        ObjAnim_SetCurrentMove((int)obj, (&lbl_803DC688)[lbl_803DE459 - 1], lbl_803E7EA4, 0);
        lbl_803DE459 = 0;
    }
    if (*(s8*)&((PlayerState*)state)->baddie.moveDone != 0)
    {
        Player_GetObjHitsState(obj)->suppressOutgoingHits = 0;
        if (((PlayerState*)state)->baddie.targetObj != NULL)
        {
            *(int*)&((PlayerState*)state)->baddie.unk308 = (int)fn_8029C8C8;
            return 0x25;
        }
        ((ByteFlags*)((char*)inner + 0x3f1))->b80 = 1;
        *(u32*)&((PlayerState*)inner)->flags360 |= PLAYER_FLAG_TELEPORTED;
        *(int*)&((PlayerState*)state)->baddie.unk308 = (int)fn_802A514C;
        return 2;
    }
    (*(void (*)(int, int, f32, int))(*(int*)((char*)*gPlayerInterface + 0x20)))((int)obj, state, fv, 1);
    return 0;
}

extern f32 lbl_803E7FB8;

int playerStateAttack(GameObject* obj, int state, f32 fv)
{
    int r;
    u8 changed;
    int path;
    PlayerState* inner = obj->extra;
    f32 amt;

    r = playerState28(obj, state, fv);
    if (r != 0)
    {
        return r;
    }
    path = (int)gPlayerPathObject;
    *(s8*)&((PlayerState*)state)->baddie.stateTag = 1;
    gPlayerSubState = 5;
    if (*(s8*)&((PlayerState*)state)->baddie.moveJustStartedA == 0)
    {
        if (lbl_803DE459 != 0)
        {
            doRumble(10.0f);
            *(int*)&((PlayerState*)state)->baddie.unk308 = 0;
            return 0x28;
        }
        changed = 0;
        if (((PlayerState*)state)->baddie.moveSpeed > 0.0f)
        {
            if ((*(int*)&((PlayerState*)state)->baddie.eventFlags & 0x200) != 0)
            {
                doRumble(5.0f);
                Sfx_PlayFromObject((int)obj, SFXTRIG_rserv1_c);
                inner->pendingFxFlags = inner->pendingFxFlags | 4;
            }
            if ((*(int*)&((PlayerState*)state)->baddie.eventFlags & 0x400) != 0)
            {
                doRumble(5.0f);
                Sfx_PlayFromObject((int)obj, SFXTRIG_rserv1_c);
                inner->pendingFxFlags = inner->pendingFxFlags | 4;
            }
            if ((((PlayerState*)state)->baddie.moveEventFlags & 1) == 0 &&
                obj->anim.currentMoveProgress >
                    *(f32*)((inner->moveSlots + 0x50) + (u32)inner->moveSlotIndex * 0xb0))
            {
                u16 sfx;
                if (inner->characterId == 0)
                {
                    sfx = 0x2de;
                }
                else
                {
                    sfx = 0x1c;
                }
                Sfx_PlayFromObject((int)obj, sfx);
                ((PlayerState*)state)->baddie.moveEventFlags = ((PlayerState*)state)->baddie.moveEventFlags | 1;
            }
            if ((((PlayerState*)state)->baddie.moveEventFlags & 2) == 0 &&
                obj->anim.currentMoveProgress >
                    *(f32*)((inner->moveSlots + 0x54) + (u32)inner->moveSlotIndex * 0xb0))
            {
                Sfx_PlayFromObject((int)obj, SFXTRIG_sswsh);
                ((PlayerState*)state)->baddie.moveEventFlags = ((PlayerState*)state)->baddie.moveEventFlags | 2;
            }
        }
        {
            int slot = inner->moveSlots + (u32)inner->moveSlotIndex * 0xb0;
            if (*(s8*)(slot + 0x15) >= 0)
            {
                if (obj->anim.currentMoveProgress > *(f32*)(slot + 0x28))
                {
                    *(u8*)((char*)state + 0x34a) = *(u8*)((char*)state + 0x34a) | 2;
                    if (*(u8*)((inner->moveSlots + 0x6c) + (u32)inner->moveSlotIndex * 0xb0) != 0u)
                    {
                        *(u8*)((char*)state + 0x34a) = *(u8*)((char*)state + 0x34a) | 4;
                        inner->moveChainIndex = 0;
                    }
                }
                if (obj->anim.currentMoveProgress >
                    *(f32*)((inner->moveSlots + 0x20) + (u32)inner->moveSlotIndex * 0xb0))
                {
                    *(u8*)((char*)state + 0x34a) = *(u8*)((char*)state + 0x34a) | 1;
                }
                if (obj->anim.currentMoveProgress >
                    *(f32*)((inner->moveSlots + 0x24) + (u32)inner->moveSlotIndex * 0xb0))
                {
                    *(u8*)((char*)state + 0x34a) = *(u8*)((char*)state + 0x34a) & ~1;
                }
                if ((*(int*)&((PlayerState*)state)->baddie.unk31C & 0x100) != 0 &&
                    (*(u8*)((char*)state + 0x34a) & 1) != 0)
                {
                    *(u8*)((char*)state + 0x34a) = *(u8*)((char*)state + 0x34a) | 4;
                    *(int*)&((PlayerState*)state)->baddie.unk31C =
                        *(int*)&((PlayerState*)state)->baddie.unk31C & ~0x100;
                    buttonDisable(0, PAD_BUTTON_A);
                    inner->moveChainIndex = *(u8*)((char*)state + 0x34b);
                }
                if ((*(u8*)((char*)state + 0x34a) & 4) != 0 && (*(u8*)((char*)state + 0x34a) & 2) != 0)
                {
                    f32 v = (f32)(u8)fn_8014C4D8((GameObject*)((PlayerState*)state)->baddie.targetObj);
                    int slot2 = inner->moveSlots + (u32)inner->moveSlotIndex * 0xb0;
                    if (v >= *(f32*)(slot2 + 0x8c))
                    {
                        inner->moveSlotIndex = *(u8*)((slot2 + 0x15) + (u32)inner->moveChainIndex);
                    }
                    else
                    {
                        inner->moveSlotIndex = *(u8*)(slot2 + 0x90);
                    }
                    changed = 1;
                }
            }
        }
    }
    else
    {
        lbl_803DE459 = 0;
        changed = 1;
        *(u32*)&inner->flags360 &= ~0x40LL;
        Player_GetObjHitsState(obj)->suppressOutgoingHits = 0;
        {
            f32 z = 0.0f;
            inner->hitTimer = z;
            inner->hitCount = 0;
            inner->lastHitObject = 0;
            *(u8*)&inner->activeHitWindow = 0xff;
            ((PlayerState*)state)->baddie.animSpeedC = z;
            ((PlayerState*)state)->baddie.animSpeedB = z;
            ((PlayerState*)state)->baddie.animSpeedA = z;
            obj->anim.velocityX = z;
            obj->anim.velocityY = z;
            obj->anim.velocityZ = z;
        }
    }
    if (((PlayerState*)state)->baddie.targetObj != NULL)
    {
        if (inner->moveSlotIndex >= 5 && inner->moveSlotIndex <= 9)
        {
            amt = (f32)inner->targetObjectBearing;
        }
        else
        {
            amt = (f32)inner->targetObjectBearing / 12.0f;
        }
        inner->targetYaw = (f32)(int)inner->targetYaw + amt;
        inner->yaw = inner->targetYaw;
    }
    else if (*(s8*)&((PlayerState*)state)->baddie.moveJustStartedA != 0 && inner->cameraTargetObject != NULL &&
             inner->targetObjModelType == 1)
    {
        if (inner->targetObjectBearingAbs < 0x4000)
        {
            amt = (f32)inner->targetObjectBearing;
        }
        inner->targetYaw = (f32)(int)inner->targetYaw + amt;
        inner->yaw = inner->targetYaw;
    }
    else if (*(s8*)&((PlayerState*)state)->baddie.moveJustStartedA != 0)
    {
        s16 v = inner->inputHeading;
        inner->targetYaw = v;
        inner->yaw = v;
    }
    if (changed != 0)
    {
        *(int*)&obj->anim.weaponDaTable = (inner->moveSlots + (u32)inner->moveSlotIndex * 0xb0) + 0x60;
        if (obj->anim.currentMove !=
            gPlayerMoveSlotTable[*(s16*)((inner->moveSlots + (u32)inner->moveSlotIndex * 0xb0) + 0x2)])
        {
            ObjAnim_SetCurrentMove(
                (int)obj, gPlayerMoveSlotTable[*(s16*)((inner->moveSlots + (u32)inner->moveSlotIndex * 0xb0) + 0x2)],
                *(f32*)((inner->moveSlots + (u32)inner->moveSlotIndex * 0xb0) + 0x68), 0);
            ObjAnim_SetCurrentEventStepFrames((ObjAnimComponent*)obj, 2);
        }
        *(u8*)((char*)state + 0x34a) = *(u8*)((char*)state + 0x34a) & ~0xef;
        ((PlayerState*)state)->baddie.moveSpeed = *(f32*)((inner->moveSlots + 0x1c) + (u32)inner->moveSlotIndex * 0xb0);
        inner->unk824 = ((PlayerState*)state)->baddie.moveSpeed;
        inner->cutsceneEnded = 0;
        ((PlayerState*)state)->baddie.animSpeedB = 0.0f;
        ((PlayerState*)state)->baddie.moveEventFlags = 0;
        if (((PlayerState*)state)->baddie.targetObj != NULL)
        {
            if (inner->moveSlotIndex >= 5 && inner->moveSlotIndex <= 9)
            {
                (*(void (*)(int, int, f32, int))(*(int*)((char*)*gPlayerInterface + 0x30)))((int)obj, state, fv, 1);
            }
            else
            {
                (*(void (*)(int, int, f32, int))(*(int*)((char*)*gPlayerInterface + 0x30)))((int)obj, state, fv, 2);
            }
            {
                s16 v = obj->anim.rotX;
                inner->yaw = v;
                inner->targetYaw = v;
            }
        }
        if (obj->anim.hitReactState != NULL)
        {
            Player_GetObjHitsState(obj)->suppressOutgoingHits = 0;
        }
        inner->activeHitWindow = -1;
        if (*(s16*)((char*)path + 0x44) == 0x2d)
        {
            objSetAnimField48to0((GameObject*)path);
            (*(void (*)(int, int)) * (int*)(*(int*)(*(int*)((char*)path + 0x68)) + 0x38))(
                path, *(u8*)((inner->moveSlots + 0x5c) + (u32)inner->moveSlotIndex * 0xb0));
            (*(void (*)(int, f32, f32)) * (int*)(*(int*)(*(int*)((char*)path + 0x68)) + 0x4c))(
                path, *(f32*)((inner->moveSlots + 0x48) + (u32)inner->moveSlotIndex * 0xb0),
                *(f32*)((inner->moveSlots + 0x4c) + (u32)inner->moveSlotIndex * 0xb0));
        }
        {
            f32 z = 0.0f;
            inner->boulderChargeLevel = z;
            inner->hitTimer = z;
            inner->hitCount = 0;
            inner->lastHitObject = 0;
        }
    }
    Player_GetObjHitsState(obj)->hitVolumePriority = 0xb;
    *(u8*)&Player_GetObjHitsState(obj)->hitVolumeId =
        *(u8*)((inner->moveSlots + 0x14) + (u32)inner->moveSlotIndex * 0xb0);
    {
        int slot = inner->moveSlots + (u32)inner->moveSlotIndex * 0xb0;
        f32 t = *(f32*)(slot + 0xa0);
        if (t >= 0.0f)
        {
            if (obj->anim.currentMoveProgress > t &&
                obj->anim.currentMoveProgress < *(f32*)(slot + 0xa4))
            {
                if (0.0f == inner->boulderChargeLevel)
                {
                    Sfx_PlayFromObject((int)obj, SFXTRIG_staff_boulder_drops);
                }
                inner->boulderChargeLevel = 2.0f * timeDelta + inner->boulderChargeLevel;
                if (inner->boulderChargeLevel > 60.0f)
                {
                    inner->boulderChargeLevel = 60.0f;
                }
            }
            else
            {
                inner->boulderChargeLevel = 0.0f;
            }
        }
    }
    if ((*(u8*)((inner->moveSlots + 0x88) + (u32)inner->moveSlotIndex * 0xb0) & 2) != 0 &&
        *(void**)&inner->lastHitObject != NULL)
    {
        if (inner->hitCount < inner->hitCountMax)
        {
            f32 t = inner->hitTimer - 1.0f;
            inner->hitTimer = t;
            if (t <= 0.0f)
            {
                ((void (*)(int, int, int, int, int))ObjHits_RecordObjectHit)(inner->lastHitObject, (int)obj, 0xb, 1, 0);
                (*(u8*)&((PlayerState*)inner)->hitCount)++;
                inner->hitTimer = (f32)(u8)inner->hitInterval;
            }
        }
        else
        {
            inner->lastHitObject = 0;
        }
    }
    {
        int off;
        int i;
        off = 0;
        Player_GetObjHitsState(obj)->objectHitMask = 0;
        for (i = 0; i != 3; i++)
        {
            if (obj->anim.currentMoveProgress >=
                    *(f32*)((inner->moveSlots + (u32)inner->moveSlotIndex * 0xb0 + off) + 0x30) &&
                obj->anim.currentMoveProgress <=
                    *(f32*)((inner->moveSlots + (u32)inner->moveSlotIndex * 0xb0 + off) + 0x3c))
            {
                if ((s8)Player_GetObjHitsState(obj)->suppressOutgoingHits == 0)
                {
                    int bits;
                    switch (*(s8*)((char*)(inner->moveSlots + (u32)inner->moveSlotIndex * 0xb0 + 0x5d) + i))
                    {
                    case -1:
                        bits = 0;
                        break;
                    case 0:
                        bits = 0xc;
                        break;
                    case 1:
                        bits = 3;
                        break;
                    case 4:
                        bits = 0xf;
                        break;
                    case 2:
                        bits = 0x100000;
                        break;
                    case 3:
                        bits = 0x10000;
                        break;
                    default:
                        bits = 0;
                        break;
                    }
                    Player_GetObjHitsState(obj)->objectHitMask = bits;
                }
                if (i != inner->activeHitWindow)
                {
                    Player_GetObjHitsState(obj)->suppressOutgoingHits = 0;
                    inner->activeHitWindow = (s8)i;
                    inner->hitCount = 0;
                    inner->hitTimer = 0.0f;
                    inner->lastHitObject = 0;
                }
                break;
            }
            off += 4;
        }
    }
    (*(void (*)(int, int, f32, int))(*(int*)((char*)*gPlayerInterface + 0x20)))((int)obj, state, fv, 3);
    if (*(s8*)&((PlayerState*)state)->baddie.moveDone != 0)
    {
        Player_GetObjHitsState(obj)->suppressOutgoingHits = 0;
        if (((PlayerState*)state)->baddie.targetObj != NULL)
        {
            *(int*)&((PlayerState*)state)->baddie.unk308 = (int)fn_8029C8C8;
            return 0x25;
        }
        ((struct {
             u8 hi : 1;
             u8 lo : 7;
         }*)&inner->flags3F1)
            ->hi = 1;
        *(u32*)&inner->flags360 |= PLAYER_FLAG_TELEPORTED;
        *(int*)&((PlayerState*)state)->baddie.unk308 = (int)fn_802A514C;
        return 2;
    }
    if (obj->anim.currentMoveProgress >=
        *(f32*)((inner->moveSlots + 0x2c) + (u32)inner->moveSlotIndex * 0xb0))
    {
        if (((PlayerState*)state)->baddie.targetObj != NULL)
        {
            if ((*(int*)&((PlayerState*)state)->baddie.unk31C & 0x100) != 0)
            {
                Player_GetObjHitsState(obj)->suppressOutgoingHits = 0;
                inner->activeHitWindow = -1;
                (*(void (*)(int, int, f32, int))(*(int*)((char*)*gPlayerInterface + 0x30)))((int)obj, state, fv, 2);
                {
                    s16 v = obj->anim.rotX;
                    inner->yaw = v;
                    inner->targetYaw = v;
                }
                *(int*)&((PlayerState*)state)->baddie.unk308 = 0;
                return 0x31;
            }
        }
        else if ((*(int*)&((PlayerState*)state)->baddie.unk31C & 0x100) != 0 &&
                 ((PlayerState*)state)->baddie.inputMagnitude > 0.3f)
        {
            inner->targetYaw = inner->targetYaw + inner->targetYawRate * 0xb6;
            inner->yaw = inner->targetYaw;
            inner->targetYawRateSigned = 0;
            inner->targetYawRate = 0;
            inner->yawRateSigned = 0;
            inner->yawRate = 0;
            *(int*)&((PlayerState*)state)->baddie.unk308 = 0;
            return 0x32;
        }
    }
    return 0;
}

void fn_8029C8C8(GameObject* obj, int p2)
{
    PlayerState* inner = obj->extra;
    if (((PlayerState*)p2)->baddie.inputMagnitude < lbl_803E7F6C)
    {
        s16 h = obj->anim.rotX;
        inner->yaw = h;
        inner->targetYaw = h;
        inner->lastInputHeading = h;
        ((PlayerState*)p2)->baddie.inputMagnitude = lbl_803E7EA4;
    }
    else
    {
        int t = inner->inputHeading;
        inner->lastInputHeading = t;
        inner->yaw = (s16)t;
        inner->yawRate = 0;
        inner->yawRateSigned = 0;
    }
    gPlayerSubState = 1;
    if (((PlayerState*)p2)->baddie.controlMode != 0x24 && ((PlayerState*)p2)->baddie.controlMode != 0x25 &&
        lbl_803DE42C != 0)
    {
        int z[2];
        inner->animState = -1;
        z[0] = 0;
        lbl_803DE42C = z[0];
        for (z[1] = z[0]; z[1] < 7; z[1]++)
        {
            if (gPlayerSpawnedObjects[z[1]] != NULL)
            {
                Obj_FreeObject((GameObject*)gPlayerSpawnedObjects[z[1]]);
                gPlayerSpawnedObjects[z[1]] = NULL;
            }
        }
        if (gPlayerResource != NULL)
        {
            Resource_Release(gPlayerResource);
            gPlayerResource = NULL;
        }
    }
}
#pragma opt_propagation off

int playerState25(int obj, int state)
{
    PlayerState* inner = ((GameObject*)obj)->extra;
    f32 ratio, c, s, vx, t0, curveOut;
    f32 vy;
    int r;

    if (*(s8*)&((PlayerState*)state)->baddie.moveJustStartedA != 0)
    {
        gPlayerSubState = 5;
    }
    r = ((int (*)(int, int))playerState28)(obj, state);
    if (r != 0)
    {
        return r;
    }
    {
        f32 x = (((PlayerState*)state)->baddie.inputMagnitude - lbl_803E7F14) / lbl_803E7F2C;
        ratio = (x < lbl_803E7EA4) ? lbl_803E7EA4 : ((x > lbl_803E7EE0) ? lbl_803E7EE0 : x);
    }
    {
        f32 ang = gPlayerPi * (f32)(int)inner->inputHeading / lbl_803E7F98;
        vx = ratio * -mathSinf(ang);
        vx = inner->maxSpeed * vx;
    }
    {
        f32 ang = gPlayerPi * (f32)(int)inner->inputHeading / lbl_803E7F98;
        vy = inner->maxSpeed * (ratio * -mathCosf(ang));
    }
    {
        f32 a = interpolate(vx - inner->smoothVelX, lbl_803E7F44, timeDelta);
        f32 b = interpolate(vy - inner->smoothVelZ, lbl_803E7F44, timeDelta);
        inner->smoothVelX += a;
        inner->smoothVelZ += b;
    }
    ((PlayerState*)state)->baddie.animSpeedC =
        sqrtf(inner->smoothVelX * inner->smoothVelX + inner->smoothVelZ * inner->smoothVelZ);
    {
        f32 v = ((PlayerState*)state)->baddie.animSpeedC;
        f32 lo = *(f32*)inner->moveParams;
        ((PlayerState*)state)->baddie.animSpeedC =
            (((PlayerState*)state)->baddie.animSpeedC < lo)
                ? lo
                : ((v > inner->maxSpeed) ? inner->maxSpeed : ((PlayerState*)state)->baddie.animSpeedC);
    }
    {
        f32 ang = gPlayerPi * (f32)inner->targetYaw / lbl_803E7F98;
        c = mathSinf(ang);
    }
    {
        f32 ang = gPlayerPi * (f32)inner->targetYaw / lbl_803E7F98;
        s = mathCosf(ang);
    }
    {
        f32 cc = inner->smoothVelZ;
        f32 c8 = inner->smoothVelX;
        ((PlayerState*)state)->baddie.animSpeedA +=
            interpolate(-cc * s - c8 * c - ((PlayerState*)state)->baddie.animSpeedA, inner->targetAnimSpeed, timeDelta);
        ((PlayerState*)state)->baddie.animSpeedB +=
            interpolate(c8 * s - cc * c - ((PlayerState*)state)->baddie.animSpeedB, inner->targetAnimSpeed, timeDelta);
    }
    t0 = ((GameObject*)obj)->anim.currentMoveProgress;
    {
        u8 phase = *(u8*)&((PlayerState*)inner)->gaitLevel;
        int idx = (u8)((s8)phase >> 1);
        if (((PlayerState*)state)->baddie.animSpeedC < gPlayerAnimSpeedThresholds[idx])
        {
            if ((s8)phase == 4)
            {
                if (((PlayerState*)state)->baddie.inputMagnitude < lbl_803E7F14)
                {
                    *(int*)&((PlayerState*)state)->baddie.unk308 = (int)fn_8029C8C8;
                    return 0x25;
                }
            }
            else
            {
                *(u8*)&((PlayerState*)inner)->gaitLevel -= 4;
            }
        }
        else
        {
            if (((PlayerState*)state)->baddie.animSpeedC >= gPlayerAnimSpeedThresholds[idx + 1] && (s8)phase < 8)
            {
                if ((s8)phase == 0)
                {
                    t0 = lbl_803E7EA4;
                }
                if (((PlayerState*)state)->baddie.animSpeedC < inner->maxSpeed)
                {
                    *(u8*)&((PlayerState*)inner)->gaitLevel += 4;
                }
            }
        }
    }
    {
        f32 ax;
        f32 az = ((PlayerState*)state)->baddie.animSpeedB;
        if (az < lbl_803E7EA4)
        {
            az = -az;
        }
        ax = ((PlayerState*)state)->baddie.animSpeedA;
        if (ax < *(f32*)&lbl_803E7EA4)
        {
            ax = -ax;
        }
        if (((int (*)(int, f32, f32*))ObjAnim_SampleRootCurvePhase)(obj, ((PlayerState*)state)->baddie.animSpeedC,
                                                                    &curveOut) != 0)
        {
            ((PlayerState*)state)->baddie.moveSpeed = curveOut;
        }
        if (ax > az)
        {
            if (((PlayerState*)state)->baddie.animSpeedA < lbl_803E7EA4)
            {
                ((PlayerState*)state)->baddie.moveSpeed = -((PlayerState*)state)->baddie.moveSpeed;
            }
            if (((GameObject*)obj)->anim.currentMove != gPlayerMoveTableB[inner->gaitLevel])
            {
                if (((int (*)(int))ObjAnim_GetCurrentEventCountdown)(obj) == 0)
                {
                    ObjAnim_SetCurrentMove(obj, gPlayerMoveTableB[inner->gaitLevel], t0, 0);
                    if (*(s8*)&((PlayerState*)state)->baddie.moveJustStartedA == 0)
                    {
                        ((void (*)(int, int))ObjAnim_SetCurrentEventStepFrames)(obj, 0xc);
                    }
                }
            }
        }
        else
        {
            if (((PlayerState*)state)->baddie.animSpeedB >= lbl_803E7EA4)
            {
                ((PlayerState*)state)->baddie.moveSpeed = -((PlayerState*)state)->baddie.moveSpeed;
            }
            if (((GameObject*)obj)->anim.currentMove != (gPlayerMoveTableB + 2)[inner->gaitLevel])
            {
                if (((int (*)(int))ObjAnim_GetCurrentEventCountdown)(obj) == 0)
                {
                    ObjAnim_SetCurrentMove(obj, (gPlayerMoveTableB + 2)[inner->gaitLevel], t0, 0);
                    if (*(s8*)&((PlayerState*)state)->baddie.moveJustStartedA == 0)
                    {
                        ((void (*)(int, int))ObjAnim_SetCurrentEventStepFrames)(obj, 0xc);
                    }
                }
            }
        }
    }
    inner->targetYaw = (s16)(inner->targetYaw + (int)((f32)(int)inner->targetObjectBearing / lbl_803E7FC0));
    inner->yaw = inner->targetYaw;
    *(u32*)&((PlayerState*)inner)->flags360 |= 0x2000000LL;
    fn_802ABFBC((GameObject*)obj, state, inner);
    return 0;
}
#pragma opt_propagation reset
int playerState24(GameObject* obj, int state, f32 fv)
{
    PlayerState* inner = obj->extra;
    f32 t, ang, vx, vy, dx, dy;
    f32 zero = lbl_803E7EA4;
    int r;

    ((PlayerState*)state)->baddie.animSpeedA = zero;
    ((PlayerState*)state)->baddie.animSpeedB = zero;
    if (*(s8*)&((PlayerState*)state)->baddie.moveJustStartedA != 0)
    {
        inner->maxSpeed = lbl_803E7FC4;
        *(u8*)&((PlayerState*)inner)->gaitLevel = 0;
        inner->smoothVelX = zero;
        inner->smoothVelZ = zero;
        ((PlayerState*)state)->baddie.moveSpeed = lbl_803E7F84;
        ((PlayerState*)state)->baddie.animSpeedC = zero;
        gPlayerSubState = 5;
    }

    r = playerState28(obj, state, fv);
    if (r != 0)
    {
        return r;
    }

    t = (((PlayerState*)state)->baddie.inputMagnitude - lbl_803E7F14) / lbl_803E7F2C;
    ang = (t < lbl_803E7EA4) ? lbl_803E7EA4 : ((t > lbl_803E7EE0) ? lbl_803E7EE0 : t);
    vx = inner->maxSpeed * (ang * -mathSinf(gPlayerPi * (f32)inner->inputHeading / lbl_803E7F98));
    vy = inner->maxSpeed * (ang * -mathCosf(gPlayerPi * (f32)inner->inputHeading / lbl_803E7F98));
    dx = interpolate(vx - inner->smoothVelX, lbl_803E7F44, timeDelta);
    dy = interpolate(vy - inner->smoothVelZ, lbl_803E7F44, timeDelta);
    inner->smoothVelX += dx;
    inner->smoothVelZ += dy;
    ((PlayerState*)state)->baddie.animSpeedC =
        sqrtf(inner->smoothVelX * inner->smoothVelX + inner->smoothVelZ * inner->smoothVelZ);
    ((PlayerState*)state)->baddie.animSpeedC =
        (((PlayerState*)state)->baddie.animSpeedC < lbl_803E7EA4)
            ? lbl_803E7EA4
            : ((((PlayerState*)state)->baddie.animSpeedC > inner->maxSpeed) ? inner->maxSpeed
                                                                            : ((PlayerState*)state)->baddie.animSpeedC);

    if (*(f32*)&((PlayerState*)state)->baddie.trackedObj >= lbl_803E7FC8 &&
        ((PlayerState*)state)->baddie.inputMagnitude >= lbl_803E7FC8 &&
        ((PlayerState*)state)->baddie.animSpeedC >= gPlayerAnimSpeedThresholds[1])
    {
        *(int*)&((PlayerState*)state)->baddie.unk308 = (int)fn_8029C8C8;
        return 0x26;
    }

    if (obj->anim.currentMove != 0x8c)
    {
        ObjAnim_SetCurrentMove((int)obj, 0x8c, lbl_803E7EA4, 0);
        if (((PlayerState*)state)->baddie.prevControlMode == 0x39)
        {
            ObjAnim_SetCurrentEventStepFrames((ObjAnimComponent*)obj, 8);
        }
        ((PlayerState*)state)->baddie.moveSpeed = lbl_803E7F84;
    }

    inner->targetYaw += (int)((f32)inner->targetObjectBearing / lbl_803E7FC0);
    inner->yaw = inner->targetYaw;
    *(u32*)&((PlayerState*)inner)->flags360 |= 0x2000000LL;
    fn_802ABFBC(obj, state, inner);
    return 0;
}

int playerState23(GameObject* obj, int state, f32 fv)
{
    MoveTable* mt = (MoveTable*)lbl_80332EC0;
    PlayerState* inner = obj->extra;
    u32 flags;
    int idx;

    ((PlayerState*)state)->baddie.stateTag = 3;
    if (*(s8*)&((PlayerState*)state)->baddie.moveJustStartedA != 0)
    {
        if (((PlayerState*)state)->baddie.targetObj != NULL && (inner->flags884 & 1))
        {
            doRumble(lbl_803E7ED8);
            flags = inner->flags884;
            if (flags & 2)
            {
                idx = 3;
            }
            else if (flags & 4)
            {
                idx = 1;
            }
            else if (flags & 8)
            {
                idx = 2;
            }
            else
            {
                idx = 3;
            }
            ObjAnim_SetCurrentMove((int)obj, mt->moves[idx], mt->blend[idx], 0);
            ((PlayerState*)state)->baddie.moveSpeed = mt->angles[idx];
            ((PlayerState*)state)->baddie.animSpeedA = -inner->animSpeedStart;
        }
        else
        {
            ObjAnim_SetCurrentMove((int)obj, mt->moves[inner->moveVariantIndex], lbl_803E7EA4, 0);
            ((PlayerState*)state)->baddie.moveSpeed = mt->angles[inner->moveVariantIndex];
        }
    }
    if (((PlayerState*)state)->baddie.targetObj != NULL)
    {
        inner->targetYaw = inner->targetYaw + (int)((f32)inner->targetObjectBearing / lbl_803E7FC0);
        inner->yaw = inner->targetYaw;
    }
    ((PlayerState*)state)->baddie.animSpeedA =
        ((PlayerState*)state)->baddie.animSpeedA * powfBitEstimate(inner->animSpeedDecay, fv);
    (*(void (*)(int, int, f32, int))(*(int*)((char*)*gPlayerInterface + 0x20)))((int)obj, state, fv, 2);
    if (*(s8*)&((PlayerState*)state)->baddie.moveDone != 0)
    {
        *(int*)&((PlayerState*)state)->baddie.unk308 = (int)fn_802A514C;
        return 2;
    }
    return 0;
}

int playerState22(GameObject* obj, int state)
{
    PlayerState* inner = obj->extra;
    ((PlayerState*)state)->baddie.stateTag = 3;
    if (*(s8*)((char*)inner->playerStatus) > 0)
    {
        ObjAnim_SetCurrentMove((int)obj, 0xc8, lbl_803E7EA4, 0);
        *(int*)&((PlayerState*)state)->baddie.unk308 = 0;
        return -0x21;
    }
    return 0;
}

int playerState21(int obj, int state, f32 fv)
{
    PlayerState* inner = ((GameObject*)obj)->extra;
    u16 sfxId;
    int d;

    switch (((GameObject*)obj)->anim.currentMove)
    {
    case 0x450:
        ((PlayerState*)state)->baddie.moveSpeed = lbl_803E7FCC;
        if (((GameObject*)obj)->anim.velocityY < lbl_803E7EE0 && ((ByteFlags*)((char*)inner + 0x3f1))->b01)
        {
            if (inner->characterId == 0)
            {
                sfxId = 0x2d2;
            }
            else
            {
                sfxId = 0x214;
            }
            Sfx_PlayFromObject(obj, sfxId);
            ObjAnim_SetCurrentMove(obj, 0xc6, lbl_803E7EA4, 0);
        }
        if (((GameObject*)obj)->anim.velocityX * ((GameObject*)obj)->anim.velocityX +
                ((GameObject*)obj)->anim.velocityZ * ((GameObject*)obj)->anim.velocityZ >
            lbl_803E7EE0)
        {
            d = getAngle(((GameObject*)obj)->anim.velocityX, ((GameObject*)obj)->anim.velocityZ) & 0xffff;
            d -= (u16) * (s16*)((char*)inner + 0x478);
            if (d > 0x8000)
            {
                d -= 0xffff;
            }
            if (d < -0x8000)
            {
                d += 0xffff;
            }
            ((PlayerState*)inner)->targetYaw += (d * (int)fv >> 3);
            inner->yaw = ((PlayerState*)inner)->targetYaw;
        }
        break;
    case 0xc4:
        ((PlayerState*)state)->baddie.moveSpeed = lbl_803E7F6C;
        if (((GameObject*)obj)->anim.velocityY < lbl_803E7EE0 && ((ByteFlags*)((char*)inner + 0x3f1))->b01)
        {
            if (inner->characterId == 0)
            {
                sfxId = 0x2d2;
            }
            else
            {
                sfxId = 0x214;
            }
            Sfx_PlayFromObject(obj, sfxId);
            ObjAnim_SetCurrentMove(obj, 0xc6, lbl_803E7EA4, 0);
        }
        if (((GameObject*)obj)->anim.velocityX * ((GameObject*)obj)->anim.velocityX +
                ((GameObject*)obj)->anim.velocityZ * ((GameObject*)obj)->anim.velocityZ >
            lbl_803E7EE0)
        {
            d = getAngle(((GameObject*)obj)->anim.velocityX, ((GameObject*)obj)->anim.velocityZ) & 0xffff;
            d -= (u16) * (s16*)((char*)inner + 0x478);
            if (d > 0x8000)
            {
                d -= 0xffff;
            }
            if (d < -0x8000)
            {
                d += 0xffff;
            }
            ((PlayerState*)inner)->targetYaw += (d * (int)fv >> 3);
            inner->yaw = ((PlayerState*)inner)->targetYaw;
        }
        break;
    case 0xc6:
        ((PlayerState*)state)->baddie.moveSpeed = lbl_803E7F6C;
        if (*(s8*)&((PlayerState*)state)->baddie.moveDone != 0)
        {
            ObjAnim_SetCurrentMove(obj, 0xc8, lbl_803E7EA4, 0);
        }
        ((GameObject*)obj)->anim.velocityZ = ((GameObject*)obj)->anim.velocityX = lbl_803E7EA4;
        break;
    case 0xc8:
        ((PlayerState*)state)->baddie.moveSpeed = lbl_803E7EF8;
        if (*(s8*)&((PlayerState*)state)->baddie.moveDone != 0)
        {
            *(u32*)&((PlayerState*)inner)->flags360 |= PLAYER_FLAG_TELEPORTED;
            *(int*)&((PlayerState*)state)->baddie.unk308 = (int)fn_802A514C;
            return -1;
        }
        break;
    default:
        ObjAnim_SetCurrentMove(obj, 0xc4, lbl_803E7EA4, 0);
        break;
    }
    *(s8*)((char*)state + 0x34c) |= 2;
    ((GameObject*)obj)->anim.velocityX = ((GameObject*)obj)->anim.velocityX * powfBitEstimate(lbl_803E7FD0, fv);
    ((GameObject*)obj)->anim.velocityZ = ((GameObject*)obj)->anim.velocityZ * powfBitEstimate(lbl_803E7FD0, fv);
    return 0;
}

int playerState20(GameObject* obj, int state, f32 fv)
{
    ((PlayerState*)state)->baddie.stateTag = 3;
    if (*(s8*)&((PlayerState*)state)->baddie.moveJustStartedA != 0)
    {
        ObjAnim_SetCurrentMove((int)obj, 0x44c, lbl_803E7EA4, 0);
        ((PlayerState*)state)->baddie.moveSpeed = lbl_803E7FD4;
    }
    switch (obj->anim.currentMove)
    {
    case 0x44c:
        if (*(s8*)&((PlayerState*)state)->baddie.moveDone != 0)
        {
            ObjAnim_SetCurrentMove((int)obj, 0x44d, lbl_803E7EA4, 0);
            ((PlayerState*)state)->baddie.moveSpeed = lbl_803E7FCC;
        }
        break;
    case 0x44d:
        if (*(s8*)&((PlayerState*)state)->baddie.moveDone != 0)
        {
            *(int*)&((PlayerState*)state)->baddie.unk308 = (int)fn_802A514C;
            return 2;
        }
        break;
    }
    (*(void (*)(int, int, f32, int))(*(int*)((char*)*gPlayerInterface + 0x20)))((int)obj, state, fv, 1);
    return 0;
}

int playerState1F(GameObject* obj, int state, f32 fv)
{
    PlayerState* inner = obj->extra;
    int hit;

    ((PlayerState*)state)->baddie.stateTag = 3;
    if (*(s8*)&((PlayerState*)state)->baddie.moveJustStartedA != 0)
    {
        if (ObjHits_GetPriorityHit(obj, &hit, 0, 0))
        {
            inner->targetYaw = (s16)getAngle(-*(f32*)((char*)hit + 0x24), -*(f32*)((char*)hit + 0x2c));
            inner->yaw = inner->targetYaw;
        }
        ObjAnim_SetCurrentMove((int)obj, 0x407, lbl_803E7EA4, 0);
        ((PlayerState*)state)->baddie.moveSpeed = lbl_803E7F34;
    }
    switch (obj->anim.currentMove)
    {
    case 0x407:
        if (*(s8*)&((PlayerState*)state)->baddie.moveDone != 0)
        {
            ObjAnim_SetCurrentMove((int)obj, 0x408, lbl_803E7EA4, 0);
            ((PlayerState*)state)->baddie.moveSpeed = lbl_803E7FCC;
        }
        break;
    case 0x408:
        if (*(s8*)&((PlayerState*)state)->baddie.moveDone != 0)
        {
            *(int*)&((PlayerState*)state)->baddie.unk308 = (int)fn_802A514C;
            return 2;
        }
        break;
    }
    (*(void (*)(int, int, f32, int))(*(int*)((char*)*gPlayerInterface + 0x20)))((int)obj, state, fv, 1);
    return 0;
}

int playerState1E(int obj, int state)
{
    ((PlayerState*)state)->baddie.stateTag = 3;
    ((PlayerState*)state)->baddie.moveSpeed = lbl_803E7FD8;
    ((PlayerState*)state)->baddie.animSpeedA = lbl_803E7EA4;
    (*(void (*)(int, int, int))(*(int*)((char*)*gPlayerInterface + 0x20)))(obj, state, 2);
    if (*(s8*)&((PlayerState*)state)->baddie.moveDone != 0)
    {
        *(int*)&((PlayerState*)state)->baddie.unk308 = (int)fn_802A514C;
        return 2;
    }
    return 0;
}

void fn_8029DAE0(GameObject* obj, int* p2)
{
    PlayerState* inner = obj->extra;
    u8 c;
    *p2 &= ~0x4000;
    c = inner->curAnimId;
    if (c != 0x48 && c != 0x47 && getCurSeqNoInt() == 0)
    {
        (*gCameraInterface)->setMode(0x42, 0, 1, 0, NULL, 0x3c, 0xfe);
    }
    ObjHits_SyncObjectPositionIfDirtyLegacy(obj);
}
#pragma opt_common_subs off
int playerState1D(int obj, PlayerState* state, f32 fv)
{
    HeadMoveTable* tbl = (HeadMoveTable*)lbl_80332EC0;
    int prev;
    int* tblB;
    GameObject* self = (GameObject*)obj;
    PlayerState* inner = self->extra;
    int sub;
    int nextMove = -1;
    int doXform = 1;
    int camCall = 0;
    f32 t;
    f32 t2;
    f32 xc;
    f32 yc;
    f32 xT;
    f32 yT;
    f32 yOut;
    ColPair col;

    col = lbl_803E7E78;
    setAButtonIcon(0xf);
    if (*(s8*)&state->baddie.moveJustStartedA != 0)
    {
        ((ByteFlags*)((char*)inner + 0x3f3))->b01 = ((ByteFlags*)((char*)inner + 0x3f3))->b08;
        state->baddie.stateId = 0x1d;
        inner->stateHandler = (int)fn_8029DAE0;
    }
    if (*(s8*)&state->baddie.moveJustStartedA != 0)
    {
        if (gPlayerPathObject != 0 && ((ByteFlags*)((char*)inner + 0x3f4))->b40 != 0)
        {
            inner->staffActionRequest = 1;
            ((ByteFlags*)((char*)inner + 0x3f4))->b08 = 1;
        }
        if (inner->curAnimId != 0x48 && inner->curAnimId != 0x47)
        {
            cameraSetInterpMode(2);
            (*gCameraInterface)->setMode(0x52, 1, 0, 8, &col, 0x1e, 0xff);
        }
        inner->stickDirection = 0;
        inner->latchedStickDir = 0;
        inner->targetYaw = getAngle(inner->surfaceNormalX, inner->surfaceNormalZ);
        {
            s16 ang = inner->targetYaw;
            inner->yaw = ang;
            self->anim.rotX = ang;
        }
        ((ByteFlags*)((char*)inner + 0x3f2))->b01 = 1;
        ObjAnim_SetCurrentMove(obj, 0x5f, lbl_803E7EA4, 0);
        ObjAnim_SetCurrentEventStepFrames((ObjAnimComponent*)obj, 8);
        state->baddie.moveSpeed = lbl_803E7EF8;
        {
            f32 z = lbl_803E7EA4;
            inner->stickTargetX = z;
            inner->stickTargetY = z;
        }
        ((ByteFlags*)((char*)inner + 0x3f3))->b80 = 0;
        ObjHits_MarkObjectPositionDirty((ObjAnimComponent*)obj);
    }
    inner->aimInputZ = lbl_803E7F2C;
    {
        f32 z = lbl_803E7EA4;
        inner->aimInputX = z;
        state->baddie.animSpeedA = z;
        state->baddie.animSpeedB = z;
    }
    sub = inner->contactObject;
    switch (self->anim.currentMove)
    {
    case 0x5f:
        if ((*(int*)&state->baddie.unk318 & 0x100) == 0)
        {
            *(u32*)&inner->flags360 |= PLAYER_FLAG_TELEPORTED;
            *(int*)&state->baddie.unk308 = (int)fn_802A514C;
            return 2;
        }
        break;
    case 0x4d:
    case 0x4e:
    case 0x5a:
    case 0x65:
        if (*(s8*)&state->baddie.moveDone != 0)
        {
            *(u32*)&inner->flags360 |= PLAYER_FLAG_TELEPORTED;
            *(int*)&state->baddie.unk308 = (int)fn_802A514C;
            return 2;
        }
        camCall = 1;
        doXform = 0;
        break;
    }
    prev = *(u8*)&inner->stickDirection;
    t = (f32)padGetStickXS8(0) / lbl_803E7FA8;
    xc = (t < lbl_803E7ECC) ? lbl_803E7ECC : ((t > lbl_803E7EE0) ? lbl_803E7EE0 : t);
    t2 = (f32)padGetStickYS8(0) / lbl_803E7FA8;
    yc = (t2 < lbl_803E7ECC) ? lbl_803E7ECC : ((t2 > lbl_803E7EE0) ? lbl_803E7EE0 : t2);
    if (((ByteFlags*)((char*)inner + 0x3f3))->b80 == 0)
    {
        if (yc > lbl_803E7F14)
        {
            xT = lbl_803E7FDC - lbl_803E7F48 * yc;
            inner->stickTargetY = yT = lbl_803E7EA4;
            inner->stickDirection = 1;
        }
        else if (yc < lbl_803E7FE0)
        {
            xT = lbl_803E7F6C - lbl_803E7F48 * yc;
            inner->stickTargetY = yT = lbl_803E7EA4;
            inner->stickDirection = 2;
        }
        else if (xc > lbl_803E7F14)
        {
            inner->stickTargetX = xT = lbl_803E7EA4;
            yT = lbl_803E7EAC * xc + lbl_803E7F6C;
            inner->stickDirection = 3;
        }
        else if (xc < lbl_803E7FE0)
        {
            inner->stickTargetX = xT = lbl_803E7EA4;
            yT = lbl_803E7EAC * xc + lbl_803E7FDC;
            inner->stickDirection = 4;
        }
        else
        {
            if (inner->stickTargetX <= lbl_803E7F6C && inner->stickTargetX >= lbl_803E7FDC &&
                inner->stickTargetY <= lbl_803E7F6C && inner->stickTargetY >= lbl_803E7FDC)
            {
                inner->stickDirection = 0;
                nextMove = 0x5f;
                state->baddie.moveSpeed = lbl_803E7EF8;
            }
            xT = lbl_803E7EA4;
            yT = lbl_803E7EA4;
        }
        {
            f32 k = lbl_803E7EFC;
            inner->stickTargetX = k * (xT - inner->stickTargetX) + inner->stickTargetX;
            inner->stickTargetY = k * (yT - inner->stickTargetY) + inner->stickTargetY;
        }
    }
    if (((ByteFlags*)((char*)inner + 0x3f3))->b80 == 0 &&
        ((*(int*)&state->baddie.unk318 & 0x100) == 0 || inner->stickEdgeLatch != 0 ||
         (((ByteFlags*)((char*)inner + 0x3f1))->b01 == 0 && *(f32*)((char*)state + 0x1b0) >= lbl_803E7F58)))
    {
        if (inner->stickDirection != 0)
        {
            ObjAnim_SetCurrentMove(obj, tbl->moveA[inner->stickDirection], lbl_803E7E98, 0);
            state->baddie.moveSpeed = lbl_803E7F20;
        }
        else
        {
            *(u32*)&inner->flags360 |= PLAYER_FLAG_TELEPORTED;
            *(int*)&state->baddie.unk308 = (int)fn_802A514C;
            return 2;
        }
        inner->stickDirection = 0;
        ((ByteFlags*)((char*)inner + 0x3f3))->b80 = 1;
    }
    if (((ByteFlags*)((char*)inner + 0x3f3))->b80 == 0)
    {
        if (inner->stickDirection != 0)
        {
            gPlayerSfxTimerD = gPlayerSfxTimerD - framesThisStep;
            if (gPlayerSfxTimerD <= 0)
            {
                gPlayerSfxTimerD = randomGetRange(0xb4, 0xf0);
                Sfx_PlayFromObject(obj, SFXTRIG_literun116);
            }
            *(u32*)&inner->flags360 |= 0x200LL;
            if (inner->stickDirection != (u8)prev || *(s8*)&inner->latchedStickDir == 0)
            {
                ((ByteFlags*)((char*)inner + 0x3f2))->b01 = 1;
                inner->latchedStickDir = 0;
            }
            else if (inner->stickDirection == *(s8*)&inner->latchedStickDir)
            {
                if (((ByteFlags*)((char*)inner + 0x3f3))->b08 != 0 && ((ByteFlags*)((char*)inner + 0x3f3))->b01 == 0)
                {
                    ((ByteFlags*)((char*)inner + 0x3f2))->b01 = 1;
                    inner->latchedStickDir = 0;
                }
                else
                {
                    ((ByteFlags*)((char*)inner + 0x3f2))->b01 = 0;
                }
            }
            if (((ByteFlags*)((char*)inner + 0x3f2))->b01 != 0)
            {
                state->baddie.moveSpeed =
                    lbl_803E7EF8 * state->baddie.inputMagnitude + tbl->spdD[inner->stickDirection];
                nextMove = tbl->moveC[inner->stickDirection];
            }
            else
            {
                if (self->anim.currentMove != (tblB = tbl->moveB)[inner->stickDirection] ||
                    self->anim.currentMoveProgress >= lbl_803E7FE4)
                {
                    state->baddie.moveSpeed =
                        lbl_803E7F78 * ((f32)randomGetRange(0, 100) / lbl_803E7F5C) + tbl->spdE[inner->stickDirection];
                }
                nextMove = tblB[inner->stickDirection];
            }
        }
        {
            u8 res;
            s8 direction = inner->stickDirection;
            f32 a;
            f32 b;
            if (direction == 0)
            {
                a = lbl_803E7EA4;
                b = lbl_803E7EA4;
            }
            else
            {
                a = inner->stickTargetX;
                b = inner->stickTargetY;
            }
            res = (*(u8 (*)(int, int, int, f32, f32))(*(int*)(*(int*)(*(int*)((char*)sub + 0x68)) + 0x20)))(
                sub, obj, direction, a, b);
            if (res == 1)
            {
                inner->latchedStickDir = 1;
            }
            else if (res == 2)
            {
                inner->latchedStickDir = 2;
            }
            else if (res == 3)
            {
                inner->latchedStickDir = 4;
            }
            else if (res == 4)
            {
                inner->latchedStickDir = 3;
            }
            else if (res == 5)
            {
                inner->stickEdgeLatch = 1;
            }
            else
            {
                inner->latchedStickDir = 0;
            }
        }
    }
    if (nextMove != -1 && self->anim.currentMove != nextMove &&
        ((int (*)(ObjAnimComponent*))ObjAnim_GetCurrentEventCountdown)((ObjAnimComponent*)obj) == 0)
    {
        ObjAnim_SetCurrentMove(obj, nextMove, lbl_803E7EA4, 0);
        ObjAnim_SetCurrentEventStepFrames((ObjAnimComponent*)obj, 0xa);
    }
    if (camCall != 0)
    {
        (*(void (*)(int, int, f32, int))(*(int*)((char*)*gPlayerInterface + 0x20)))(obj, (int)state, fv, 3);
    }
    if (doXform != 0)
    {
        ((void (*)(f32, f32, f32, void*, f32*, void*, int))Obj_TransformLocalPointToWorld)(
            inner->contactPointX, inner->contactPointY, inner->contactPointZ, (void*)(obj + 0xc), &yOut,
            (void*)(obj + 0x14), sub);
        {
            f32 k = lbl_803E7FB8;
            self->anim.localPosX = k * inner->surfaceNormalX + self->anim.localPosX;
            self->anim.localPosZ = k * inner->surfaceNormalZ + self->anim.localPosZ;
        }
    }
    ((ByteFlags*)((char*)inner + 0x3f3))->b01 = ((ByteFlags*)((char*)inner + 0x3f3))->b08;
    return 0;
}
#pragma opt_common_subs reset

int playerState1C(GameObject* obj, int state)
{
    PlayerState* inner = obj->extra;
    f32 k;
    f32 a, b;
    u8 s1, s2;

    if (*(s8*)&((PlayerState*)state)->baddie.moveJustStartedA != 0)
    {
        *(s16*)((char*)state + 0x278) = 0x1c;
        inner->stateHandler = 0;
    }
    k = lbl_803E7EA4;
    ((PlayerState*)state)->baddie.animSpeedC = k;
    ((PlayerState*)state)->baddie.animSpeedB = k;
    ((PlayerState*)state)->baddie.animSpeedA = k;
    obj->anim.velocityX = k;
    obj->anim.velocityY = k;
    obj->anim.velocityZ = k;
    if (*(s8*)&((PlayerState*)state)->baddie.moveJustStartedA != 0)
    {
        s1 = 0;
        a = inner->surfaceNormalX;
        if (a < k)
        {
            s1 = 1;
            a = -a;
        }
        s2 = 0;
        b = inner->surfaceNormalZ;
        if (b < lbl_803E7EA4)
        {
            s2 = 1;
            b = -b;
        }
        if (a > b)
        {
            if (s1)
            {
                inner->surfaceDir = 0;
            }
            else
            {
                inner->surfaceDir = 1;
            }
        }
        else
        {
            if (s2)
            {
                inner->surfaceDir = 2;
            }
            else
            {
                inner->surfaceDir = 3;
            }
        }
        ObjAnim_SetCurrentMove((int)obj, 0x57, lbl_803E7EA4, 0);
        ((PlayerState*)state)->baddie.moveSpeed = lbl_803E7FE8;
        Sfx_PlayFromObject((int)obj, (u16)(inner->characterId == 0 ? SFXTRIG_impact3 : SFXTRIG_literun116));
    }
    if (*(s8*)&((PlayerState*)state)->baddie.moveDone != 0)
    {
        *(int*)&((PlayerState*)state)->baddie.unk308 = (int)fn_802A514C;
        return -1;
    }
    return 0;
}


int playerState1B(GameObject* obj, int state, f32 fv)
{
    PlayerState* inner = obj->extra;
    int curveId;
    int camArg = 0;
    f32 vec[3];
    if (*(s8*)&((PlayerState*)state)->baddie.moveJustStartedA != 0)
    {
        *(s16*)((char*)state + 0x278) = 0x1b;
        inner->stateHandler = (int)objUpdateHitboxPos;
        ObjHits_MarkObjectPositionDirty((ObjAnimComponent*)obj);
    }
    {
        int in2 = *(int*)&obj->extra;
        *(int*)((char*)in2 + 0x360) &= ~2LL;
        *(u32*)((char*)in2 + 0x360) |= 0x2000LL;
    }
    *(int*)((char*)state + 0x4) |= 0x100000;
    {
        f32 zero = lbl_803E7EA4;
        ((PlayerState*)state)->baddie.animSpeedA = zero;
        ((PlayerState*)state)->baddie.animSpeedB = zero;
        *(int*)((char*)state + 0) |= 0x200000;
        obj->anim.velocityX = zero;
        obj->anim.velocityZ = zero;
        ((PlayerState*)state)->baddie.physicsActive = 0;
        obj->anim.velocityY = zero;
    }
    switch (obj->anim.currentMove)
    {
    case 0x76:
    case 0x40d:
    {
        int active;
        int atDest;
        f32 amt = ((PlayerState*)state)->baddie.moveInputZ / lbl_803E7FA8;
        f32 clamped;
        f32 sp;
        f32 spd;
        if (amt < lbl_803E7EA4)
        {
            amt = -amt;
        }
        clamped = (amt < lbl_803E7EFC) ? lbl_803E7EFC : ((amt > lbl_803E7EE0) ? lbl_803E7EE0 : amt);
        sp = ((PlayerState*)state)->baddie.moveInputZ;
        if (sp > lbl_803E7EE0)
        {
            spd = lbl_803E7F44 * clamped;
            active = 1;
        }
        else if (sp < lbl_803E7ECC)
        {
            spd = lbl_803E7F44 * -clamped;
            active = 1;
        }
        else
        {
            spd = 0.0f;
            active = 0;
        }
        if (active != 0)
        {
            gPlayerSfxTimerC = gPlayerSfxTimerC - framesThisStep;
            if (gPlayerSfxTimerC <= 0)
            {
                gPlayerSfxTimerC = randomGetRange(0x1e, 0x2d);
                Sfx_PlayFromObject(0, SFXTRIG_foot_ladder3);
            }
        }
        ((PlayerState*)state)->baddie.animSpeedC =
            ((PlayerState*)state)->baddie.animSpeedC +
            interpolate(spd - ((PlayerState*)state)->baddie.animSpeedC, lbl_803E7EFC, timeDelta);
        inner->traveledDistance = ((PlayerState*)state)->baddie.animSpeedC * timeDelta + inner->traveledDistance;
        {
            f32 ph = ((PlayerState*)state)->baddie.animSpeedC;
            if (ph < lbl_803E7EF8 && ph > lbl_803E7FEC)
            {
                f32 zeroPh = lbl_803E7EA4;
                ((PlayerState*)state)->baddie.animSpeedC = zeroPh;
                if (obj->anim.currentMove != 0x76)
                {
                    ObjAnim_SetCurrentMove((int)obj, 0x76, zeroPh, 0);
                }
                ((PlayerState*)state)->baddie.moveSpeed = lbl_803E7F78;
            }
            else
            {
                if (obj->anim.currentMove != 0x40d)
                {
                    ObjAnim_SetCurrentMove((int)obj, 0x40d, lbl_803E7EA4, 0);
                }
                ((int (*)(int, f32, f32*))ObjAnim_SampleRootCurvePhase)((int)obj, ((PlayerState*)state)->baddie.animSpeedC,
                                                                        (f32*)((char*)state + 0x2a0));
            }
        }
        atDest = inner->traveledDistance > inner->travelTargetDistance || inner->traveledDistance < lbl_803E7EA4;
        if (atDest)
        {
            u8 anim;
            ObjAnim_SetCurrentMove((int)obj, 0x40f, lbl_803E7EA4, 0);
            anim = inner->curAnimId;
            if (anim != 0x48 && anim != 0x47)
            {
                camArg = inner->traveledDistance < lbl_803E7EA4 ? 0 : 1;
                (*(void (*)(int*))(*(int*)((char*)*gCameraInterface + 0x60)))(&camArg);
            }
        }
        else
        {
            inner->targetYaw = (s16)getAngle(-*(f32*)((char*)inner + 0x634), -inner->travelDirZ);
            inner->yaw = inner->targetYaw;
            obj->anim.rotY = 0;
        }
        break;
    }
    case 0x40f:
        ((PlayerState*)state)->baddie.moveSpeed = lbl_803E7F34;
        (*(void (*)(int, int, f32, int))(*(int*)((char*)*gPlayerInterface + 0x20)))((int)obj, state, fv, 1);
        if (*(s8*)&((PlayerState*)state)->baddie.moveDone != 0)
        {
            u8 anim = inner->curAnimId;
            if (anim != 0x48 && anim != 0x47)
            {
                (*gCameraInterface)->setMode(0x42, 1, 1, 0, NULL, 0, 0xff);
            }
            *(u32*)&((PlayerState*)inner)->flags360 |= PLAYER_FLAG_TELEPORTED;
            *(int*)&((PlayerState*)state)->baddie.unk308 = (int)fn_802A514C;
            return 2;
        }
        break;
    case 0x40e:
        ((PlayerState*)state)->baddie.moveSpeed = lbl_803E7F34;
        (*(void (*)(int, int, f32, int))(*(int*)((char*)*gPlayerInterface + 0x20)))((int)obj, state, fv, 1);
        inner->targetYaw = (s16)getAngle(inner->hitNormalX, inner->hitNormalZ);
        inner->yaw = inner->targetYaw;
        sqrtf(inner->hitNormalX * inner->hitNormalX + inner->hitNormalZ * inner->hitNormalZ);
        obj->anim.rotY = 0;
        if (*(s8*)&((PlayerState*)state)->baddie.moveDone != 0)
        {
            ObjAnim_SetCurrentMove((int)obj, 0x40d, lbl_803E7EA4, 0);
        }
        break;
    default:
    {
        int found;
        curveId = 0x1f;
        found = ((int (*)(f32, f32, f32, int*, int, int))(*gRomCurveInterface)->find)(
            obj->anim.localPosX, obj->anim.localPosY, obj->anim.localPosZ,
            &curveId, 1, 0);
        if (found != -1)
        {
            int pt = (int)(*gRomCurveInterface)->getById(found);
            int pt2;
            *(f32*)((int)inner + 0x61c) = ((ObjHitVolumeRuntimeTransform*)pt)->jointZ;
            inner->curveStartY = ((ObjHitVolumeRuntimeTransform*)pt)->centerX;
            inner->curveStartZ = ((ObjHitVolumeRuntimeTransform*)pt)->centerY;
            obj->anim.localPosX = ((ObjHitVolumeRuntimeTransform*)pt)->jointZ;
            obj->anim.localPosY = ((ObjHitVolumeRuntimeTransform*)pt)->centerX;
            obj->anim.localPosZ = ((ObjHitVolumeRuntimeTransform*)pt)->centerY;
            inner->targetYaw = (s16)getAngle(inner->hitNormalX, inner->hitNormalZ);
            inner->yaw = inner->targetYaw;
            sqrtf(inner->hitNormalX * inner->hitNormalX + inner->hitNormalZ * inner->hitNormalZ);
            obj->anim.rotY = 0;
            found = ((int (*)(int, int))(*gRomCurveInterface)->slot54)(pt, -1);
            if (found == -1)
            {
                found = ((int (*)(int, int))(*gRomCurveInterface)->slot60)(pt, -1);
            }
            pt2 = (int)(*gRomCurveInterface)->getById(found);
            *(f32*)((int)inner + 0x628) = *(f32*)((char*)pt2 + 0x8);
            inner->curveEndY = *(f32*)((char*)pt2 + 0xc);
            inner->curveEndZ = *(f32*)((char*)pt2 + 0x10);
            inner->traveledDistance = lbl_803E7EA4;
            PSVECSubtract((f32*)((char*)inner + 0x628), (f32*)((char*)inner + 0x61c), vec);
            inner->travelTargetDistance = PSVECMag(vec);
            PSVECNormalize(vec, (f32*)((char*)inner + 0x634));
        }
        ObjAnim_SetCurrentMove((int)obj, 0x40e, lbl_803E7EA4, 0);
        {
            u8 anim = inner->curAnimId;
            if (anim != 0x48 && anim != 0x47)
            {
                (*gCameraInterface)->setMode(0x50, 1, 0, 0, NULL, 0x28, 0xff);
            }
        }
        ((PlayerState*)state)->baddie.animSpeedC = lbl_803E7EA4;
        break;
    }
    }
    PSVECScale((f32*)((char*)inner + 0x634), vec, inner->traveledDistance);
    PSVECAdd((f32*)((char*)inner + 0x61c), vec, &obj->anim.localPosX);
    fn_802AB5A4(obj, (int)inner, 7);
    return 0;
}

int playerStateOnCloudRunner(GameObject* obj, int state)
{
    PlayerState* inner = obj->extra;
    void* sub;
    f32 v7b8, v7bc;
    f32 k;
    int res, halfW, halfH;

    *(u32*)&inner->flags360 &= ~PLAYER_FLAG_HITDETECT;
    ObjHits_EnableObject(obj);
    sub = *(void**)((char*)inner + 0x7f0);
    if (sub == NULL)
    {
        f32 z = lbl_803E7EA4;
        ((PlayerState*)state)->baddie.animSpeedC = z;
        ((PlayerState*)state)->baddie.animSpeedB = z;
        ((PlayerState*)state)->baddie.animSpeedA = z;
        obj->anim.velocityX = z;
        obj->anim.velocityY = z;
        obj->anim.velocityZ = z;
        ObjHits_EnableObject(obj);
    }
    else
    {
        if (*(s16*)((char*)sub + 0x46) != 0x714)
        {
            ObjHits_DisableObject(obj);
        }
    }
    if (*(s8*)&((PlayerState*)state)->baddie.moveJustStartedA != 0)
    {
        f32 z = lbl_803E7EA4;
        inner->aimInputX = z;
        inner->aimInputZ = z;
        (*gCameraInterface)->setMode(0x53, 1, sub != NULL ? 0x12 : -2, 0, NULL, 0, 0xff);
        ObjAnim_SetCurrentMove((int)obj, 0x43e, lbl_803E7EA4, 0);
        ((PlayerState*)state)->baddie.moveSpeed = lbl_803E7F34;
        inner->actionCooldown = lbl_803E7EA4;
        if (gPlayerPathObject != NULL)
        {
            if (((ByteFlags*)((char*)inner + 0x3f4))->b40 != 0)
            {
                inner->staffActionRequest = 4;
                ((ByteFlags*)((char*)inner + 0x3f4))->b08 = 1;
            }
        }
    }
    if (obj->anim.alpha > 1)
    {
        obj->anim.alpha = 1;
    }
    inner->actionCooldown = inner->actionCooldown - timeDelta;
    if (inner->actionCooldown < lbl_803E7EA4)
    {
        inner->actionCooldown = *(f32*)&lbl_803E7EA4;
    }
    if ((inner->buttonsJustPressed & PAD_BUTTON_A) != 0)
    {
        if (inner->actionCooldown <= lbl_803E7EA4)
        {
            buttonDisable(0, PAD_BUTTON_A);
            ((void (*)(int, int, f32, f32))fn_802AA014)((int)obj, state, inner->aimInputZ, lbl_803E7EA4);
            inner->actionCooldown = lbl_803E7F10;
        }
    }
    {
        f32 x = ((PlayerState*)state)->baddie.moveInputZ / lbl_803E7FA8;
        f32 c;
        void* hit;
        c = (x < lbl_803E7FF0) ? lbl_803E7FF0 : ((x > lbl_803E7FC4) ? lbl_803E7FC4 : x);
        hit = *(void**)((char*)inner + 0x7f0);
        if (hit != NULL && *(s16*)((char*)hit + 0x46) == 0x484)
        {
            c = c + lbl_803DC6E0;
        }
        if (hit == NULL)
        {
            c = c + lbl_803DC6E4;
        }
        inner->aimInputZ += interpolate(c - inner->aimInputZ, lbl_803DC6D4, timeDelta);
    }
    {
        f32 x = ((PlayerState*)state)->baddie.moveInputX / lbl_803E7FA8;
        f32 c;
        c = (x < lbl_803E7ECC) ? lbl_803E7ECC : ((x > lbl_803E7EE0) ? lbl_803E7EE0 : x);
        inner->aimInputX += interpolate(c - inner->aimInputX, lbl_803DC6D8, timeDelta);
    }
    {
        f32 d = inner->aimInputX;
        if (d > lbl_803E7EA4)
        {
            d = d - lbl_803E7EA0;
            if (d < lbl_803E7EA4)
            {
                d = lbl_803E7EA4;
            }
        }
        else
        {
            d = lbl_803E7EA0 + d;
            if (d > lbl_803E7EA4)
            {
                d = lbl_803E7EA4;
            }
        }
        {
            f32 p = lbl_803E7FB4 * d;
            inner->targetYaw = (s16)(p * lbl_803DC6DC + (f32)inner->targetYaw);
        }
        inner->yaw = inner->targetYaw;
    }
    if (inner->aimInputZ > lbl_803E7EA4)
    {
        Object_ObjAnimSetSecondaryBlendMove((ObjAnimComponent*)obj, 0x441, (int)(lbl_803E7FAC * inner->aimInputZ));
    }
    else
    {
        Object_ObjAnimSetSecondaryBlendMove((ObjAnimComponent*)obj, 0x440, (int)(lbl_803E7FAC * -inner->aimInputZ));
    }
    inner->headPitch = (f32)inner->headPitch * powfBitEstimate(lbl_803E7FF4, timeDelta);
    inner->headYaw = (f32)inner->headYaw * powfBitEstimate(lbl_803E7F1C, timeDelta);
    inner->bodyLeanHalf = lbl_803E7FB0 * inner->aimInputX;
    inner->bodyLeanAngle = (s16)(inner->bodyLeanHalf >> 1);
    *(u32*)&inner->flags360 &= ~PLAYER_FLAG_AIM_READY;
    v7bc = inner->aimInputZ;
    v7b8 = inner->aimInputX;
    res = getScreenResolution();
    halfW = res >> 17;
    halfH = (int)(u16)res >> 1;
    inner->aimScreenY = (k = lbl_803E7E98) * (v7b8 * (f32)halfH) + (f32)halfH;
    if (v7bc < lbl_803E7EA4)
    {
        inner->aimScreenX = k * (v7bc * (f32)halfW) + (f32)halfW;
    }
    else
    {
        inner->aimScreenX = lbl_803E7F44 * (v7bc * (f32)halfW) + (f32)halfW;
    }
    *(u32*)&((PlayerState*)inner)->flags360 |= PLAYER_FLAG_AIM_READY;
    return 0;
}


int playerState19(GameObject* obj, int state)
{
    PlayerState* inner = obj->extra;
    int sub = (int)inner->focusObject;
    void* vec;
    int kind;
    ObjModel* joint;
    int n;
    f32 t;
    f32 pos1[3];
    f32 pos2[3];
    s16 ang[3];
    f32 localPt;
    f32 cam[3];

    if (*(s8*)&((PlayerState*)state)->baddie.moveJustStartedA != 0)
    {
        *(s16*)((char*)state + 0x278) = 0x19;
        inner->stateHandler = 0;
    }
    {
        int inner2 = *(int*)&obj->extra;
        *(int*)((char*)inner2 + 0x360) &= ~0x2LL;
        *(int*)((char*)inner2 + 0x360) |= 0x2000;
    }
    *(int*)((char*)state + 0x4) |= 0x100000;
    {
        f32 z = lbl_803E7EA4;
        ((PlayerState*)state)->baddie.animSpeedA = z;
        ((PlayerState*)state)->baddie.animSpeedB = z;
        *(int*)((char*)state + 0x0) |= 0x200000;
        obj->anim.velocityX = z;
        obj->anim.velocityZ = z;
    }
    ((PlayerState*)state)->baddie.physicsActive = 0;
    ObjHits_DisableObject(obj);
    obj->anim.velocityY = lbl_803E7EA4;
    if (*(s8*)&((PlayerState*)state)->baddie.moveJustStartedA != 0)
    {
        (*(void (*)(int, void*, void*, void*))(*(int*)(*(int*)*(int*)((char*)sub + 0x68) + 0x28)))(
            sub, (char*)obj + 0xc, (char*)obj + 0x10, (char*)obj + 0x14);
        switch (*(s16*)((char*)sub + 0x46))
        {
        case 0x38c:
        case 0x72:
            (*gCameraInterface)->setMode(0x42, 0, 1, 0, NULL, 0x64, 0xff);
            break;
        default:
            (*gCameraInterface)->loadTriggeredCamAction(0, 1, 0);
            break;
        }
        kind = (*(int (*)(int))(*(int*)(*(int*)*(int*)((char*)sub + 0x68) + 0x30)))(sub);
        (*(void (*)(int, int))(*(int*)(*(int*)*(int*)((char*)sub + 0x68) + 0x3c)))(sub, 3);
        switch (kind)
        {
        case 1:
            n = 8;
            break;
        case 2:
        default:
            n = 9;
            break;
        }
        inner->targetYaw = *(s16*)((char*)sub + 0x0);
        inner->yaw = inner->targetYaw;
        obj->anim.rotY = 0;
        obj->anim.rotZ = 0;
        ObjAnim_SetCurrentMove((int)obj, ((s16*)inner->moveSequence)[n], lbl_803E7EA4, 1);
        joint = Player_GetActiveModel((int)obj);
        ObjModel_SampleJointTransform(joint, 0, 0, lbl_803E7EA4, obj->anim.rootMotionScale, pos1, ang);
        ObjModel_SampleJointTransform(joint, 0, 0, lbl_803E7EE0, obj->anim.rootMotionScale, pos2, ang);
        ang[0] = inner->targetYaw;
        ang[1] = 0;
        ang[2] = 0;
        vecRotateZXY(ang, pos2);
        pos2[0] = pos2[0] + obj->anim.localPosX;
        pos2[2] = pos2[2] + obj->anim.localPosZ;
        obj->anim.localPosY -= pos1[1];
        t = (*gPathControlInterface)
                ->sampleHeight((void*)obj, pos2[0], obj->anim.localPosY, pos2[2], lbl_803E7FA4);
        inner->warpStartX = pos2[0];
        inner->warpStartY = t;
        inner->warpStartZ = pos2[2];
        inner->warpDeltaY = obj->anim.localPosY - t;
        inner->warpKind = (u8)kind;
        obj->anim.flags &= ~0x8;
        obj->anim.activeMove = -1;
        ((PlayerState*)state)->baddie.moveSpeed = lbl_803E7FE8;
    }
    t = lbl_803E7EE0 - obj->anim.currentMoveProgress;
    obj->anim.localPosY = inner->warpDeltaY * t + inner->warpStartY;
    vec = objModelGetVecFn_800395d8(obj, 5);
    if (vec != NULL)
    {
        *(s16*)vec = (f32) * (s16*)((char*)sub + 0x2) * t;
        *(s16*)((char*)vec + 0x4) = (f32) * (s16*)((char*)sub + 0x4) * t;
    }
    (*(void (*)(int, f32*, f32*, f32*))(*(int*)(*(int*)*(int*)((char*)sub + 0x68) + 0x34)))(sub, &cam[0], &cam[1],
                                                                                            &cam[2]);
    {
        f32 w = obj->anim.currentMoveProgress;
        f32 cx = w * (inner->warpStartX - cam[0]) + cam[0];
        f32 cy = w * (inner->warpStartY - cam[1]) + cam[1];
        f32 cz = w * (inner->warpStartZ - cam[2]) + cam[2];
        (*gCameraInterface)->overridePos(cx, cy, cz);
    }
    if (*(s8*)&((PlayerState*)state)->baddie.moveJustStartedA == 0 &&
        *(s8*)&((PlayerState*)state)->baddie.moveDone != 0)
    {
        if (vec != NULL)
        {
            *(s16*)vec = 0;
            *(s16*)((char*)vec + 0x4) = 0;
        }
        obj->anim.modelState->flags &= ~(long long)OBJ_MODEL_STATE_SHADOW_FADE_OUT;
        obj->anim.worldPosX = inner->savedPosX;
        obj->anim.worldPosZ = inner->savedPosZ;
        if (obj->anim.parent != NULL)
        {
            obj->anim.worldPosX += playerMapOffsetX;
            obj->anim.worldPosZ += playerMapOffsetZ;
        }
        Obj_TransformWorldPointToLocal(obj->anim.worldPosX, lbl_803E7EA4,
                                       obj->anim.worldPosZ, &obj->anim.localPosX,
                                       &localPt, &obj->anim.localPosZ,
                                       (int)obj->anim.parent);
        if (inner->warpKind == 1)
        {
            inner->targetYaw += 0x4000;
            inner->yaw = inner->targetYaw;
        }
        else
        {
            inner->targetYaw -= 0x4000;
            inner->yaw = inner->targetYaw;
        }
        ObjAnim_SetCurrentMove((int)obj, 0, lbl_803E7EA4, 1);
        ((void (*)(int, int, int, int))ObjAnim_WriteStateWord)((int)obj, OBJANIM_STATE_INDEX_CURRENT,
                                                               OBJANIM_STATE_WORD_EVENT_COUNTDOWN, 0);
        (*(void (*)(int, int))(*(int*)(*(int*)*(int*)((char*)sub + 0x68) + 0x3c)))(sub, 0);
        fn_802AB5A4(obj, (int)inner, 7);
        ObjHits_EnableObject(obj);
        inner->focusObject = NULL;
        *(int*)&((PlayerState*)state)->baddie.unk308 = (int)fn_802A514C;
        return 2;
    }
    return 0;
}

void fn_8029F67C(GameObject* obj)
{
    ObjModelState* modelState = obj->anim.modelState;
    s16* v;
    modelState->flags &= 0xFFFFEFFFLL;
    obj->anim.flags &= ~0x8;
    obj->anim.activeMove = -1;
    v = objModelGetVecFn_800395d8(obj, 9);
    if (v != NULL)
    {
        v[0] = 0;
        v[1] = 0;
        v[2] = 0;
    }
}

int playerStateOnBike(GameObject* obj, int state)
{
    PlayerState* inner = obj->extra;
    void* sub;
    f32 out;
    f32 a;
    int b;
    f32 c;
    int d;
    f32 ret;
    int blend;
    (*(void (*)(int))(*(int*)((char*)*gCameraInterface + 0x68)))(2);
    ((PlayerState*)state)->baddie.physicsActive = 0;
    *(int*)((char*)state + 0x4) |= 0x100000;
    *(u32*)&((PlayerState*)inner)->flags360 &= ~PLAYER_FLAG_HITDETECT;
    ObjHits_DisableObject(obj);
    sub = *(void**)((char*)inner + 0x7f0);
    if (sub == NULL)
    {
        obj->anim.activeMove = -1;
        return 0;
    }
    if (*(s8*)&((PlayerState*)state)->baddie.moveJustStartedA != 0)
    {
        if (*(void**)((char*)inner + 0x6e8) == NULL)
        {
            inner->moveSequence = (int)lbl_803332B0;
        }
        ObjAnim_SetCurrentMove((int)obj, *(s16*)(inner->moveSequence + 0x2), lbl_803E7EA4, 0);
        ObjAnim_AdvanceCurrentMove((int)obj, lbl_803E7EA4, *(f32*)&lbl_803E7EA4, NULL);
    }
    if ((inner->moveSequenceFlags & 0x4) != 0)
    {
        ((void (*)(ObjAnimComponent*, f32))ObjAnim_SetMoveProgress)((ObjAnimComponent*)obj, *(f32*)((char*)sub + 0x98));
        ((PlayerState*)state)->baddie.moveSpeed = lbl_803E7EA4;
    }
    else
    {
        ret = (*(f32 (*)(int, f32*))(*(int*)((char*)*(int*)*(int*)((char*)sub + 0x68) + 0x44)))((int)sub, &out);
        if (out <= lbl_803E7EE0)
        {
            ((PlayerState*)state)->baddie.moveSpeed = out;
        }
        else
        {
            ((PlayerState*)state)->baddie.moveSpeed = lbl_803E7F6C * ret + lbl_803E7EF8;
        }
    }
    if ((inner->moveSequenceFlags & 0x1) != 0)
    {
        (*(void (*)(int, f32*, int*))(*(int*)((char*)*(int*)*(int*)((char*)sub + 0x68) + 0x40)))((int)sub, &a, &b);
        blend = (int)(lbl_803E7FAC * a);
        if (blend < 0)
        {
            blend = -blend;
        }
        if (b != 0)
        {
            Object_ObjAnimSetSecondaryBlendMove((ObjAnimComponent*)obj, *(s16*)(inner->moveSequence + 0xa), blend);
        }
        else
        {
            Object_ObjAnimSetSecondaryBlendMove((ObjAnimComponent*)obj, *(s16*)(inner->moveSequence + 0x8), blend);
        }
    }
    else if ((inner->moveSequenceFlags & 0x8) != 0)
    {
        (*(void (*)(int, f32*, int*))(*(int*)((char*)*(int*)*(int*)((char*)sub + 0x68) + 0x40)))((int)sub, &c, &d);
        *(u32*)&((PlayerState*)inner)->flags360 |= 0x2000000LL;
        inner->headYaw = (s16)d;
        inner->bodyLeanAngle = (s16)c;
        inner->bodyLeanHalf = inner->bodyLeanAngle / 2;
        inner->headPitch = inner->bodyLeanAngle / 2;
    }
    if ((inner->moveSequenceFlags & 0x1) != 0)
    {
        ObjAnim_WriteStateWord((ObjAnimComponent*)obj, OBJANIM_STATE_INDEX_CURRENT, OBJANIM_STATE_WORD_PREV_EVENT_STATE,
                               0);
        ObjAnim_WriteStateWord((ObjAnimComponent*)obj, OBJANIM_STATE_INDEX_ACTIVE, OBJANIM_STATE_WORD_PREV_EVENT_STATE,
                               0);
    }
    if ((*(int (*)(int, int))(*(int*)((char*)*(int*)*(int*)((char*)sub + 0x68) + 0x2c)))((int)sub, (int)obj) != 0)
    {
        *(int*)&((PlayerState*)state)->baddie.unk308 = 0;
        return 0x1a;
    }
    return 0;
}

int playerState17(int p1, int state)
{
    if (mainGetBit(GAMEBIT_LV_EscapedFromPole))
    {
        *(int*)&((PlayerState*)state)->baddie.unk308 = (int)fn_802A514C;
        return -1;
    }
    return 0;
}
#pragma opt_propagation off

int playerStateMountBike(GameObject* obj, int state, f32 fv)
{
    char* base = (char*)lbl_80332EC0;
    PlayerState* inner = obj->extra;
    int sub = (int)inner->focusObject;
    ObjModel* joint;
    f32 j0[3];
    f32 j1[3];
    f32 wpos[3];

    {
        u32 m;
        u32 f2 = *(u32*)&inner->flags360;
        m = ~0x2;
        *(u32*)&inner->flags360 = f2 & m;
    }
    inner->flags360 |= 0x2000;
    *(int*)((char*)state + 0x4) |= 0x100000;
    {
        f32 z = lbl_803E7EA4;
        ((PlayerState*)state)->baddie.animSpeedA = z;
        ((PlayerState*)state)->baddie.animSpeedB = z;
        *(int*)((char*)state + 0x0) |= 0x200000;
        obj->anim.velocityX = z;
        obj->anim.velocityZ = z;
    }
    *(s8*)&((PlayerState*)state)->baddie.physicsActive = 0;
    if (*(s8*)&((PlayerState*)state)->baddie.moveJustStartedA != 0)
    {
        *(s16*)((char*)state + 0x278) = 0x16;
        inner->stateHandler = 0;
    }
    ObjHits_DisableObject(obj);
    obj->anim.velocityY = lbl_803E7EA4;
    if (*(s8*)&((PlayerState*)state)->baddie.moveJustStartedA != 0)
    {
        int sel;
        f32 scratch[2];

        if (gPlayerPathObject != NULL && ((ByteFlags*)((char*)inner + 0x3f4))->b40 != 0)
        {
            inner->staffActionRequest = 1;
            ((ByteFlags*)((char*)inner + 0x3f4))->b08 = 1;
        }
        switch (*(s16*)((char*)sub + 0x46))
        {
        case 0x72:
            inner->moveSequence = (int)(base + 0x3f0);
            inner->moveSequenceFlags = 3;
            if (coordsToMapCell(obj->anim.localPosX, obj->anim.localPosZ) == 0x13)
            {
                mainSetBits(0xf0a, 1);
            }
            (*gCameraInterface)->setMode(0x45, 1, 0, 0, NULL, 0, 0xff);
            break;
        case 0x38c:
            inner->moveSequence = (int)(base + 0x3f0);
            inner->moveSequenceFlags = 3;
            (*gCameraInterface)->setFocus((void*)sub, 0);
            (*gCameraInterface)->setMode(0x45, 1, 0, 0, NULL, 0, 0xff);
            break;
        case 0x419:
            inner->moveSequence = (int)(base + 0x420);
            (*gCameraInterface)->setMode(0x53, 1, 0, 0, NULL, 0x2d, 0xff);
            break;
        case 0x416:
            inner->moveSequence = (int)(base + 0x438);
            inner->moveSequenceFlags = 8;
            (*gCameraInterface)->setFocus((void*)sub, 0);
            (*gCameraInterface)->loadTriggeredCamAction(0, 0x69, 0);
            break;
        case 0x8c:
            inner->moveSequence = (int)(base + 0x408);
            inner->moveSequenceFlags = 4;
            break;
        default:
            inner->moveSequence = (int)(base + 0x420);
            inner->moveSequenceFlags = 4;
            (*gCameraInterface)->loadTriggeredCamAction(0, 0x1d, 0);
            break;
        }
        {
            int t = (*(int (*)(int))(*(int*)(*(int*)(*(int*)((char*)sub + 0x68)) + 0x24)))(sub);
            (*(void (*)(int, int))(*(int*)(*(int*)(*(int*)((char*)sub + 0x68)) + 0x3c)))(sub, 1);
            switch (t)
            {
            case 1:
                sel = 6;
                break;
            case 2:
            default:
                sel = 7;
                break;
            }
        }
        inner->targetYaw = *(s16*)((char*)sub + 0x0);
        inner->yaw = inner->targetYaw;
        ObjAnim_SetCurrentMove((int)obj, ((s16*)inner->moveSequence)[sel], lbl_803E7EA4, 4);
        joint = Player_GetActiveModel((int)obj);
        ObjModel_SampleJointTransformLegacy((int)joint, 0, 0, lbl_803E7EA4, obj->anim.rootMotionScale, j0, scratch);
        ObjModel_SampleJointTransformLegacy((int)joint, 0, 0, lbl_803E7EE0, obj->anim.rootMotionScale, j1, scratch);
        (*(void (*)(int, void*, void*, void*))(*(int*)(*(int*)(*(int*)((char*)sub + 0x68)) + 0x28)))(
            sub, &wpos[0], &wpos[1], &wpos[2]);
        wpos[0] = wpos[0] - obj->anim.localPosX;
        wpos[1] = wpos[1] - obj->anim.localPosY;
        wpos[2] = wpos[2] - obj->anim.localPosZ;
        inner->warpStartX = obj->anim.localPosX;
        inner->warpStartY = obj->anim.localPosY;
        inner->warpStartZ = obj->anim.localPosZ;
        inner->warpDeltaX = wpos[0];
        inner->warpDeltaY = wpos[1] - j1[1];
        inner->warpDeltaZ = wpos[2];
        obj->anim.flags |= 8;
        obj->anim.modelState->flags |= OBJ_MODEL_STATE_SHADOW_FADE_OUT;
        obj->anim.modelState->shadowAlphaStep = 0;
        ((PlayerState*)state)->baddie.moveSpeed = lbl_803E7FD8;
    }
    {
        obj->anim.localPosX =
            obj->anim.currentMoveProgress * inner->warpDeltaX + inner->warpStartX;
        obj->anim.localPosY =
            obj->anim.currentMoveProgress * inner->warpDeltaY + inner->warpStartY;
        obj->anim.localPosZ =
            obj->anim.currentMoveProgress * inner->warpDeltaZ + inner->warpStartZ;
        (*(void (*)(int, void*, void*, void*))(*(int*)(*(int*)(*(int*)((char*)sub + 0x68)) + 0x34)))(
            sub, &wpos[0], &wpos[1], &wpos[2]);
        (*gCameraInterface)
            ->overridePos(
                obj->anim.currentMoveProgress * (wpos[0] - inner->warpStartX) + inner->warpStartX,
                obj->anim.currentMoveProgress * (wpos[1] - inner->warpStartY) + inner->warpStartY,
                obj->anim.currentMoveProgress * (wpos[2] - inner->warpStartZ) + inner->warpStartZ);
    }
    if (*(s8*)&((PlayerState*)state)->baddie.moveJustStartedA == 0 &&
        *(s8*)&((PlayerState*)state)->baddie.moveDone != 0)
    {
        ObjAnim_SetCurrentMove((int)obj, *(s16*)inner->moveSequence, lbl_803E7EA4, 1);
        (*(void (*)(int, int))(*(int*)(*(int*)(*(int*)((char*)sub + 0x68)) + 0x3c)))(sub, 2);
        if (arrayIndexOf((int*)(base + 0x160), 4, *(s16*)((char*)sub + 0x46)) != -1)
        {
            *(int*)&((PlayerState*)state)->baddie.unk308 = (int)fn_8029F67C;
            return 0x1b;
        }
        *(int*)&((PlayerState*)state)->baddie.unk308 = (int)fn_8029F67C;
        return 0x19;
    }
    return 0;
}
#pragma opt_propagation reset

void fn_8029FFD0(GameObject* obj, int p2)
{
    PlayerState* inner = obj->extra;
    s16 v = ((PlayerState*)p2)->baddie.controlMode;
    if (v != 0x15 && v != 0x14 && v != 0x12 && v != 0x13 && v != 0xe && v != 0xf && v != 0x10)
    {
        u8 c = inner->curAnimId;
        if (c != 0x48 && c != 0x47 && c != 0x42 && getCurSeqNoInt() == 0)
        {
            (*gCameraInterface)->setMode(0x42, 0, 1, 0, NULL, 0, 0xff);
            inner->curAnimId = 0x42;
        }
        *(u32*)&((PlayerState*)inner)->flags360 |= PLAYER_FLAG_TELEPORTED;
        ObjHits_SyncObjectPositionIfDirtyLegacy(obj);
    }
    obj->anim.activeMove = -1;
}


void objUpdateHitboxPos(int obj)
{
    ObjHits_SyncObjectPositionIfDirtyLegacy(obj);
}

int playerStateClimbDownFromWall(GameObject* obj, int state)
{
    PlayerState* inner = obj->extra;
    f32 fz;
    f32 obj98;
    f32 t1, t2, t3;
    f32 outY;
    playerPlayClimbingSound(obj, state);
    if (*(s8*)&((PlayerState*)state)->baddie.moveJustStartedA != 0)
    {
        u8 ic;
        ObjModel* model;
        s16 buf2[3];
        f32 buf1[3];
        ObjHits_MarkObjectPositionDirty((ObjAnimComponent*)obj);
        ic = inner->curAnimId;
        if (ic != 0x48 && ic != 0x47)
        {
            (*gCameraInterface)->setMode(0x42, 0, 1, 0, NULL, 0x3c, 0xff);
        }
        ObjAnim_SetCurrentMove((int)obj, lbl_80332F48[0x13], lbl_803E7EA4, 1);
        Object_ObjAnimSetSecondaryBlendMove((ObjAnimComponent*)obj, lbl_80332F48[0x14], 0);
        ((PlayerState*)state)->baddie.moveSpeed = lbl_803E7F34;
        model = Player_GetActiveModel((int)obj);
        ObjModel_SampleJointTransform(model, 0, 0, lbl_803E7EE0, obj->anim.rootMotionScale, buf1, buf2);
        inner->moveOffsetX = inner->groundNormalX * buf1[2];
        inner->moveOffsetZ = inner->groundNormalZ * buf1[2];
        obj->anim.localPosY = inner->spanBottomY;
        *(s16*)((char*)state + 0x278) = 0x15;
        inner->stateHandler = (int)fn_8029FFD0;
    }
    {
        int ex = *(int*)&obj->extra;
        *(u32*)((char*)ex + 0x360) &= ~2LL;
        *(u32*)((char*)ex + 0x360) |= 0x2000LL;
    }
    *(int*)((char*)state + 4) |= 0x100000;
    fz = lbl_803E7EA4;
    ((PlayerState*)state)->baddie.animSpeedA = fz;
    ((PlayerState*)state)->baddie.animSpeedB = fz;
    *(int*)((char*)state + 0) |= 0x200000;
    obj->anim.velocityX = fz;
    obj->anim.velocityZ = fz;
    *(int*)((char*)state + 4) |= 0x8000000;
    obj->anim.velocityY = fz;
    ObjAnim_WriteStateWord((ObjAnimComponent*)obj, OBJANIM_STATE_INDEX_CURRENT, OBJANIM_STATE_WORD_EVENT_STATE,
                           inner->animEventState);
    if ((*(int*)&((PlayerState*)state)->baddie.eventFlags & 0x200) != 0)
    {
        doRumble(lbl_803E7F10);
    }
    obj98 = obj->anim.currentMoveProgress;
    if (obj98 > lbl_803E7F68)
    {
        obj->anim.worldPosX = inner->savedPosX;
        obj->anim.worldPosZ = inner->savedPosZ;
        if (*(void**)&obj->anim.parent != NULL)
        {
            obj->anim.worldPosX = obj->anim.worldPosX + playerMapOffsetX;
            obj->anim.worldPosZ = obj->anim.worldPosZ + playerMapOffsetZ;
        }
        Obj_TransformWorldPointToLocal(obj->anim.worldPosX, lbl_803E7EA4,
                                       obj->anim.worldPosZ, &obj->anim.localPosX, &outY,
                                       &obj->anim.localPosZ, *(int*)&obj->anim.parent);
        fn_802AB5A4(obj, (int)inner, 5);
        ObjAnim_SetCurrentMove((int)obj, *(s16*)inner->moveAnimTable, lbl_803E7EA4, 1);
        *(u32*)&((PlayerState*)inner)->flags360 |= PLAYER_FLAG_TELEPORTED;
        *(int*)&((PlayerState*)state)->baddie.unk308 = (int)fn_802A514C;
        return -1;
    }
    t1 = inner->moveOffsetX * obj98 + obj->anim.localPosX;
    t2 = obj->anim.localPosY - inner->moveOffsetY * (lbl_803E7EE0 - obj98);
    t3 = inner->moveOffsetZ * obj98 + obj->anim.localPosZ;
    (*gCameraInterface)->overridePos(t1, t2, t3);
    fn_802AB5A4(obj, (int)inner, 5);
    return 0;
}

int playerStateClimbUpFromWall(GameObject* obj, int state)
{
    PlayerState* inner = obj->extra;
    f32 fz;
    f32 obj98;
    f32 t1, t2, t3;
    f32 outY;
    playerPlayClimbingSound(obj, state);
    if (*(s8*)&((PlayerState*)state)->baddie.moveJustStartedA != 0)
    {
        u8 ic;
        ObjModel* model;
        s16 buf2[3];
        f32 buf1[3];
        ObjHits_MarkObjectPositionDirty((ObjAnimComponent*)obj);
        ic = inner->curAnimId;
        if (ic != 0x48 && ic != 0x47)
        {
            (*gCameraInterface)->setMode(0x42, 0, 1, 0, NULL, 0x3c, 0xff);
        }
        ObjAnim_SetCurrentMove((int)obj, lbl_80332F48[0x11], lbl_803E7EA4, 1);
        Object_ObjAnimSetSecondaryBlendMove((ObjAnimComponent*)obj, lbl_80332F48[0x12], 0);
        ((PlayerState*)state)->baddie.moveSpeed = lbl_803E7F84;
        model = Player_GetActiveModel((int)obj);
        ObjModel_SampleJointTransform(model, 0, 0, lbl_803E7EE0, obj->anim.rootMotionScale, buf1, buf2);
        inner->moveOffsetX = inner->groundNormalX * buf1[2];
        inner->moveOffsetZ = inner->groundNormalZ * buf1[2];
        obj->anim.localPosY = inner->spanTopY;
        *(s16*)((char*)state + 0x278) = 0x14;
        inner->stateHandler = (int)fn_8029FFD0;
    }
    {
        int ex = *(int*)&obj->extra;
        *(u32*)((char*)ex + 0x360) &= ~2LL;
        *(u32*)((char*)ex + 0x360) |= 0x2000LL;
    }
    *(int*)((char*)state + 4) |= 0x100000;
    fz = lbl_803E7EA4;
    ((PlayerState*)state)->baddie.animSpeedA = fz;
    ((PlayerState*)state)->baddie.animSpeedB = fz;
    *(int*)((char*)state + 0) |= 0x200000;
    obj->anim.velocityX = fz;
    obj->anim.velocityZ = fz;
    *(int*)((char*)state + 4) |= 0x8000000;
    obj->anim.velocityY = fz;
    ObjAnim_WriteStateWord((ObjAnimComponent*)obj, OBJANIM_STATE_INDEX_CURRENT, OBJANIM_STATE_WORD_EVENT_STATE,
                           inner->animEventState);
    obj98 = obj->anim.currentMoveProgress;
    if (obj98 > lbl_803E7F68)
    {
        obj->anim.worldPosX = inner->savedPosX;
        obj->anim.worldPosZ = inner->savedPosZ;
        if (*(void**)&obj->anim.parent != NULL)
        {
            obj->anim.worldPosX = obj->anim.worldPosX + playerMapOffsetX;
            obj->anim.worldPosZ = obj->anim.worldPosZ + playerMapOffsetZ;
        }
        Obj_TransformWorldPointToLocal(obj->anim.worldPosX, lbl_803E7EA4,
                                       obj->anim.worldPosZ, &obj->anim.localPosX, &outY,
                                       &obj->anim.localPosZ, *(int*)&obj->anim.parent);
        fn_802AB5A4(obj, (int)inner, 5);
        ObjAnim_SetCurrentMove((int)obj, *(s16*)inner->moveAnimTable, lbl_803E7EA4, 1);
        *(u32*)&((PlayerState*)inner)->flags360 |= PLAYER_FLAG_TELEPORTED;
        *(int*)&((PlayerState*)state)->baddie.unk308 = (int)fn_802A514C;
        return -1;
    }
    t1 = inner->moveOffsetX * obj98 + obj->anim.localPosX;
    t2 = obj->anim.localPosY - inner->moveOffsetY * (lbl_803E7EE0 - obj98);
    t3 = inner->moveOffsetZ * obj98 + obj->anim.localPosZ;
    (*gCameraInterface)->overridePos(t1, t2, t3);
    fn_802AB5A4(obj, (int)inner, 5);
    return 0;
}

#pragma opt_common_subs off
int playerStateClimbWall(GameObject* obj, int state)
{
    int mask;
    ObjModel* jt;
    register int inner;
    int b6;
    int b7;
    int b8;
    int b9;
    int dir;
    s16 i;
    f32 oldSpd;
    f32 dx;
    f32 dy;
    f32 ph;
    WallHit hit;
    f32 out1[3];
    f32 pnt[3];
    f32 dst[3];
    s16 tmp[3];

    inner = *(int*)&obj->extra;
    if (*(s8*)&((PlayerState*)state)->baddie.moveJustStartedA != 0)
    {
        gPlayerCurrentMoveId = 0x10;
        ObjHits_MarkObjectPositionDirty((ObjAnimComponent*)obj);
    }
    {
        int base = *(int*)&obj->extra;
        *(int*)((char*)base + 0x360) &= ~0x2LL;
        *(u32*)((char*)base + 0x360) |= 0x2000LL;
    }
    *(u32*)((char*)state + 4) |= 0x100000;
    {
        f32 z = lbl_803E7EA4;
        ((PlayerState*)state)->baddie.animSpeedA = z;
        ((PlayerState*)state)->baddie.animSpeedB = z;
        *(u32*)state |= 0x200000;
        obj->anim.velocityX = z;
        obj->anim.velocityZ = z;
        *(u32*)((char*)state + 4) |= 0x8000000;
        obj->anim.velocityY = z;
    }
    jt = Player_GetActiveModel((int)obj);
    ph = ((PlayerState*)state)->baddie.moveSpeed;
    gPlayerPrevMoveId = gPlayerCurrentMoveId;
    switch ((s16)gPlayerCurrentMoveId)
    {
    case 0x10:
        if (obj->anim.currentMove == 0x66)
        {
            ((PlayerState*)inner)->moveAltToggle = 0;
            gPlayerCurrentMoveId = 0x16;
        }
        else
        {
            ((PlayerState*)inner)->moveAltToggle = 1;
            gPlayerCurrentMoveId = 0x15;
        }
        obj->anim.localPosY = ((PlayerState*)inner)->savedPosY;
        ph = 0.006f;
    case 0x15:
    case 0x16:
    {
        f32 z = 0.0f;
        ((PlayerState*)inner)->moveOffsetX = z;
        ((PlayerState*)inner)->moveOffsetY = z;
        ((PlayerState*)inner)->moveOffsetZ = z;
    }
        playerPlayClimbingSound(obj, state);
        if (((PlayerState*)state)->baddie.inputMagnitude <= 0.1f)
        {
            goto store_ph;
        }
        oldSpd = obj->anim.currentMoveProgress;
        obj->anim.currentMoveProgress = 1.0f;
    default:
        if (1.0f == obj->anim.currentMoveProgress)
        {
            pnt[0] = -(30.0f * ((PlayerState*)inner)->groundNormalX - ((PlayerState*)inner)->savedPosX);
            pnt[1] = ((PlayerState*)inner)->savedPosY;
            pnt[2] = -(30.0f * ((PlayerState*)inner)->groundNormalZ - ((PlayerState*)inner)->savedPosZ);
            {
                int r = objBboxFn_800640cc((f32*)((char*)inner + 0x768), pnt, 0.0f, 3,
                                           (TrackBBoxHit*)&hit, obj, 1, 3, 0xff, 0);
                if (r != 0)
                {
                    obj->anim.localPosX = pnt[0];
                    obj->anim.localPosZ = pnt[2];
                    {
                        f32 ga = hit.ga;
                        ((PlayerState*)inner)->spanTopY = hit.gt * (hit.gb - ga) + ga;
                    }
                    {
                        f32 fz0 = hit.fz0;
                        ((PlayerState*)inner)->spanBottomY = hit.gt * (hit.fz1 - fz0) + fz0;
                    }
                    ((PlayerState*)inner)->groundNormalX = hit.nx;
                    ((PlayerState*)inner)->groundNormalY = hit.ny;
                    ((PlayerState*)inner)->groundNormalZ = hit.nz;
                    ((PlayerState*)inner)->groundNormalW = hit.nw;
                    ((PlayerState*)inner)->slopeTangentX = -hit.nz;
                    ((PlayerState*)inner)->slopeTangentY = 0.0f;
                    ((PlayerState*)inner)->slopeTangentZ = hit.nx;
                    ((PlayerState*)inner)->slopePlaneD = -(pnt[2] * ((PlayerState*)inner)->slopeTangentZ +
                                                           (pnt[0] * ((PlayerState*)inner)->slopeTangentX +
                                                            pnt[1] * ((PlayerState*)inner)->slopeTangentY));
                    ((PlayerState*)inner)->targetYaw =
                        (s16)getAngle(((PlayerState*)inner)->groundNormalX, ((PlayerState*)inner)->groundNormalZ);
                    ((PlayerState*)inner)->yaw = ((PlayerState*)inner)->targetYaw;
                    {
                        int hf = hit.flags;
                        if ((hf & 4) != 0)
                        {
                            dir = 0;
                        }
                        else if ((hf & 8) != 0)
                        {
                            dir = 1;
                        }
                        else if ((hf & 2) != 0)
                        {
                            dir = 2;
                        }
                        else
                        {
                            dir = 3;
                        }
                    }
                }
                else
                {
                    dir = 2;
                }
            }
            if (gPlayerCurrentMoveId != 0x15 && gPlayerCurrentMoveId != 0x16)
            {
                obj->anim.localPosY = ((PlayerState*)inner)->savedPosY;
            }
            if (((PlayerState*)state)->baddie.inputMagnitude > 0.1f)
            {
                gPlayerCurrentMoveId =
                    ((getAngle(((PlayerState*)state)->baddie.moveInputX, -((PlayerState*)state)->baddie.moveInputZ) &
                      0xffff) +
                         0x1000 >>
                     13) &
                    7;
                gPlayerPrevMoveId = -1;
                if ((s16)gPlayerCurrentMoveId == 4 || (s16)gPlayerCurrentMoveId == 0)
                {
                    ((PlayerState*)inner)->moveAltToggle ^= 1;
                }
                b6 = 0;
                b7 = 0;
                b8 = 0;
                b9 = 0;
                switch (gPlayerCurrentMoveId)
                {
                case 4:
                    b6 = 1;
                    break;
                case 0:
                    b7 = 1;
                    break;
                case 6:
                    b8 = 1;
                    break;
                case 2:
                    b9 = 1;
                    break;
                case 3:
                    b6 = 1;
                    b9 = 1;
                    break;
                case 5:
                    b6 = 1;
                    b8 = 1;
                    break;
                case 1:
                    b7 = 1;
                    b9 = 1;
                    break;
                case 7:
                    b7 = 1;
                    b8 = 1;
                    break;
                }
                if (((PlayerState*)inner)->moveAltToggle != 0)
                {
                    gPlayerCurrentMoveId += 8;
                }
                if (b6 != 0)
                {
                    f32 fv = ((PlayerState*)inner)->spanTopY - ((PlayerState*)inner)->savedPosY;
                    f32 lo = lbl_803DAF88[12];
                    f32 hi;
                    if (lo < 0.0f)
                    {
                        lo = -lo;
                    }
                    hi = lbl_803DAF88[13];
                    if (hi < 0.0f)
                    {
                        hi = -hi;
                    }
                    if (fv < hi && (dir == 0 || dir == 3))
                    {
                        f32 frac = (fv - lo) / (hi - lo);
                        f32 m = (frac < 0.0f) ? 0.0f : ((frac > 1.0f) ? 1.0f : frac);
                        ((PlayerState*)inner)->animEventState = (s16)(16384.0f * m);
                        ((PlayerState*)inner)->moveOffsetY = m;
                        *(int*)&((PlayerState*)state)->baddie.unk308 = (int)fn_8029FFD0;
                        return 0x15;
                    }
                }
                else if (b7 != 0)
                {
                    f32 fv = ((PlayerState*)inner)->savedPosY - ((PlayerState*)inner)->spanBottomY;
                    f32 lo = lbl_803DAF88[14];
                    f32 hi;
                    if (lo < 0.0f)
                    {
                        lo = -lo;
                    }
                    hi = lbl_803DAF88[15];
                    if (hi < 0.0f)
                    {
                        hi = -hi;
                    }
                    if (fv < hi && (dir == 1 || dir == 3))
                    {
                        f32 frac = (fv - lo) / (hi - lo);
                        f32 m = (frac < 0.0f) ? 0.0f : ((frac > 1.0f) ? 1.0f : frac);
                        ((PlayerState*)inner)->animEventState = (s16)(16384.0f * m);
                        ((PlayerState*)inner)->moveOffsetY = m;
                        *(int*)&((PlayerState*)state)->baddie.unk308 = (int)fn_8029FFD0;
                        return 0x16;
                    }
                }
                ((int (*)(int, int, f32, int))Object_ObjAnimSetMove)((int)obj, lbl_80332F48[gPlayerCurrentMoveId], 0.0f, 1);
                ObjModel_SampleJointTransform(jt, 1, 0, 1.0f, obj->anim.rootMotionScale, out1, tmp);
                obj->anim.activeMove = -1;
                ((PlayerState*)inner)->moveOffsetX = ((PlayerState*)inner)->slopeTangentX * -out1[0];
                ((PlayerState*)inner)->moveOffsetY = out1[1];
                ((PlayerState*)inner)->moveOffsetZ = ((PlayerState*)inner)->slopeTangentZ * -out1[0];
                if (b6 == 0 && b7 == 0)
                {
                    ((PlayerState*)inner)->moveOffsetY = 0.0f;
                }
                if (b8 == 0 && b9 == 0)
                {
                    f32 z = 0.0f;
                    ((PlayerState*)inner)->moveOffsetX = z;
                    ((PlayerState*)inner)->moveOffsetZ = z;
                }
                mask = 0;
                if (out1[0] < 0.0f)
                {
                    dx = 7.0f * ((PlayerState*)inner)->slopeTangentX;
                    dy = 7.0f * ((PlayerState*)inner)->slopeTangentZ;
                }
                else
                {
                    dx = 7.0f * -((PlayerState*)inner)->slopeTangentX;
                    dy = 7.0f * -((PlayerState*)inner)->slopeTangentZ;
                }
                if (b6 != 0 || b7 != 0)
                {
                    pnt[1] = ((PlayerState*)inner)->savedPosY + out1[1];
                    if (out1[1] < 0.0f)
                    {
                        pnt[1] = pnt[1] - 11.0f;
                    }
                    else
                    {
                        pnt[1] += 11.0f;
                    }
                    for (i = 0, ph = 30.0f; i < 2; i++)
                    {
                        if (i != 0)
                        {
                            pnt[0] = ((PlayerState*)inner)->savedPosX + dx;
                            pnt[2] = ((PlayerState*)inner)->savedPosZ + dy;
                        }
                        else
                        {
                            pnt[0] = ((PlayerState*)inner)->savedPosX - dx;
                            pnt[2] = ((PlayerState*)inner)->savedPosZ - dy;
                        }
                        dst[0] = -(ph * ((PlayerState*)inner)->groundNormalX - pnt[0]);
                        dst[1] = pnt[1];
                        dst[2] = -(ph * ((PlayerState*)inner)->groundNormalZ - pnt[2]);
                        if (objBboxFn_800640cc(pnt, dst, 0.0f, 3, NULL, obj, 1, 3, 0xff, 0) != 0)
                        {
                            mask = mask | 1 << i;
                        }
                    }
                }
                else
                {
                    mask |= 3;
                }
                if (b8 != 0 || b9 != 0)
                {
                    pnt[0] = dx + (((PlayerState*)inner)->savedPosX + ((PlayerState*)inner)->moveOffsetX);
                    pnt[2] = dy + (((PlayerState*)inner)->savedPosZ + ((PlayerState*)inner)->moveOffsetZ);
                    for (i = 0, dy = 30.0f; i < 2; i++)
                    {
                        if (i != 0)
                        {
                            pnt[1] = 11.0f + ((PlayerState*)inner)->savedPosY;
                        }
                        else
                        {
                            pnt[1] = ((PlayerState*)inner)->savedPosY - 11.0f;
                        }
                        dst[0] = -(dy * ((PlayerState*)inner)->groundNormalX - pnt[0]);
                        dst[1] = pnt[1];
                        dst[2] = -(dy * ((PlayerState*)inner)->groundNormalZ - pnt[2]);
                        if (objBboxFn_800640cc(pnt, dst, 0.0f, 3, NULL, obj, 1, 3, 0xff, 0) != 0)
                        {
                            mask = mask | 1 << (i + 2);
                        }
                    }
                }
                else
                {
                    mask |= 0xc;
                }
                ph = 0.02f;
                if (mask != 0xf)
                {
                    {
                        f32 z = 0.0f;
                        ((PlayerState*)inner)->moveOffsetX = z;
                        ((PlayerState*)inner)->moveOffsetY = z;
                        ((PlayerState*)inner)->moveOffsetZ = z;
                    }
                    {
                        int st2 = (s16)gPlayerCurrentMoveId;
                        if (st2 == 4 || st2 == 0 || ((st2 == 0xc) | (st2 == 8)) != 0)
                        {
                            ((PlayerState*)inner)->moveAltToggle ^= 1;
                        }
                    }
                    {
                        s16 ns;
                        if (((PlayerState*)inner)->moveAltToggle != 0)
                        {
                            ns = 0x15;
                        }
                        else
                        {
                            ns = 0x16;
                        }
                        gPlayerCurrentMoveId = ns;
                    }
                    if (obj->anim.currentMove == lbl_80332F48[21] ||
                        obj->anim.currentMove == lbl_80332F48[22])
                    {
                        gPlayerPrevMoveId = *(s16*)&gPlayerCurrentMoveId;
                        obj->anim.currentMoveProgress = oldSpd;
                    }
                    ph = 0.006f;
                }
            }
            else
            {
                obj->anim.localPosY = ((PlayerState*)inner)->savedPosY;
                {
                    s16 ns;
                    if (((PlayerState*)inner)->moveAltToggle != 0)
                    {
                        ns = 0x15;
                    }
                    else
                    {
                        ns = 0x16;
                    }
                    gPlayerCurrentMoveId = ns;
                }
                ph = 0.006f;
            }
        }
        if (gPlayerCurrentMoveId != 0x15 && gPlayerCurrentMoveId != 0x16)
        {
            f32 v = ((PlayerState*)state)->baddie.inputMagnitude;
            if (ph < 0.0f)
            {
                ph = -(0.003999997f * v + 0.034f);
            }
            else if (ph > 0.0f)
            {
                ph = 0.003999997f * v + 0.034f;
            }
        }
        playerPlayClimbingSound(obj, state);
        break;
    }
store_ph:
    ((PlayerState*)state)->baddie.moveSpeed = ph;
    {
        s16 cur;
        if (gPlayerPrevMoveId != (cur = gPlayerCurrentMoveId))
        {
            ObjAnim_SetCurrentMove((int)obj, lbl_80332F48[cur], 0.0f, 1);
        }
    }
    {
        f32 sp = obj->anim.currentMoveProgress;
        (*gCameraInterface)
            ->overridePos(((PlayerState*)inner)->moveOffsetX * sp + obj->anim.localPosX,
                          ((PlayerState*)inner)->moveOffsetY * sp + obj->anim.localPosY,
                          ((PlayerState*)inner)->moveOffsetZ * sp + obj->anim.localPosZ);
    }
    fn_802AB5A4(obj, inner, 5);
    return 0;
}

#pragma opt_common_subs reset

int playerStateClimbOntoWall(GameObject* obj, int state)
{
    PlayerState* inner = obj->extra;
    PlayerState* in0 = obj->extra;
    int flag549;
    f32 fz;
    s16* tbl;
    int flags;
    ObjModel* model;
    u8 ic;
    f32 buf1[3];
    s16 buf2[3];
    f32 pos[2];
    *(u32*)&in0->flags360 &= ~PLAYER_FLAG_HITDETECT;
    *(u32*)&in0->flags360 |= PLAYER_FLAG_NO_POS_VELOCITY;
    *(int*)((char*)state + 0x4) |= 0x100000;
    fz = lbl_803E7EA4;
    ((PlayerState*)state)->baddie.animSpeedA = fz;
    ((PlayerState*)state)->baddie.animSpeedB = fz;
    *(int*)((char*)state + 0x0) |= 0x200000;
    obj->anim.velocityX = fz;
    obj->anim.velocityZ = fz;
    *(int*)((char*)state + 0x4) |= 0x8000000;
    obj->anim.velocityY = fz;
    if (*(s8*)&((PlayerState*)state)->baddie.moveJustStartedA != 0)
    {
        *(s16*)((char*)state + 0x278) = 0x12;
        inner->stateHandler = (int)fn_8029FFD0;
        if (gPlayerPathObject != NULL)
        {
            if (((ByteFlags*)((char*)inner + 0x3f4))->b40)
            {
                inner->staffActionRequest = 1;
                ((ByteFlags*)((char*)inner + 0x3f4))->b08 = 1;
            }
        }
        ObjHits_MarkObjectPositionDirty((ObjAnimComponent*)obj);
    }
    flag549 = inner->climbMoveVariant;
    if (flag549 != 0)
    {
        ((PlayerState*)state)->baddie.moveSpeed = lbl_803E7EF8;
    }
    else
    {
        ((PlayerState*)state)->baddie.moveSpeed = lbl_803E8008;
    }
    playerPlayClimbingSound(obj, state);
    if (*(s8*)&((PlayerState*)state)->baddie.moveJustStartedA != 0)
    {
        f32 zero = lbl_803E7EA4;
        ((PlayerState*)state)->baddie.animSpeedA = zero;
        ((PlayerState*)state)->baddie.animSpeedB = zero;
        inner->targetYaw = (s16)getAngle(*(f32*)((int)inner + 0x56c), inner->groundNormalZ);
        inner->yaw = inner->targetYaw;
        obj->anim.localPosX = inner->climbStartPosX;
        obj->anim.localPosZ = inner->climbStartPosZ;
        if (flag549 != 0)
        {
            tbl = &lbl_803DC69C;
        }
        else
        {
            tbl = &lbl_803DC698;
        }
        flags = 0x25;
        if (flag549 != 0)
        {
            flags |= 0x40;
        }
        {
            inner->animEventState =
                fn_802A71E0Legacy((int)obj, tbl[0], tbl[1], (int*)((char*)inner + 0x598),
                                  (int*)((char*)inner + 0x56c), lbl_803E7EA4, *(f32*)&lbl_803E7EA4, 2, (u8)flags);
        }
        model = Player_GetActiveModel((int)obj);
        ObjModel_SampleJointTransform(model, 0, 0, lbl_803E7EE0, obj->anim.rootMotionScale, buf1, buf2);
        fz = lbl_803E7EA4;
        inner->moveOffsetX = fz;
        inner->moveOffsetY = buf1[1];
        inner->moveOffsetZ = fz;
        pos[0] = inner->spanTopY;
        pos[1] = inner->spanBottomY;
        ic = inner->curAnimId;
        if (ic != 0x48 && ic != 0x47)
        {
            (*gCameraInterface)->setMode(0x4b, 1, 1, 8, pos, 0, 0);
        }
    }
    else
    {
        if (obj->anim.currentMoveProgress >= lbl_803E7EE0)
        {
            *(int*)&((PlayerState*)state)->baddie.unk308 = (int)fn_8029FFD0;
            return 0x14;
        }
    }
    ObjAnim_WriteStateWord((ObjAnimComponent*)obj, OBJANIM_STATE_INDEX_CURRENT, OBJANIM_STATE_WORD_EVENT_STATE,
                           inner->animEventState);
    (*gCameraInterface)
        ->overridePos(obj->anim.localPosX,
                      inner->moveOffsetY * obj->anim.currentMoveProgress +
                          obj->anim.localPosY,
                      obj->anim.localPosZ);
    fn_802AB5A4(obj, (int)inner, 5);
    return 0;
}

void playerPlayClimbingSound(GameObject* obj, int p2)
{
    PlayerState* inner = obj->extra;
    int cell;
    int t;
    int sfx;

    if (*(int*)&((PlayerState*)p2)->baddie.eventFlags & 1)
    {
        cell = coordsToMapCell(obj->anim.localPosX, obj->anim.localPosZ);
        if (cell == 0x12)
        {
            Sfx_PlayFromObject((int)obj, SFXTRIG_mv_ropecreak22);
        }
        else
        {
            Sfx_PlayFromObject((int)obj, SFXTRIG_foot);
        }
    }
    if (gPlayerSfxTimerB > 0)
    {
        t = gPlayerSfxTimerB - framesThisStep;
        gPlayerSfxTimerB = t;
        if (t < 0)
            gPlayerSfxTimerB = 0;
    }
    if (*(int*)&((PlayerState*)p2)->baddie.eventFlags & 0x80)
    {
        if (gPlayerSfxTimerB == 0)
        {
            if (randomGetRange(1, 0x64) < 0x46)
            {
                if (inner->characterId == 0)
                {
                    sfx = 0x398;
                }
                else
                {
                    sfx = 0x25;
                }
                Sfx_PlayFromObject((int)obj, (u16)sfx);
                gPlayerSfxTimerB = 0x3c;
            }
        }
    }
}

int playerState11(GameObject* obj, int state)
{
    int inner = *(int*)&obj->extra;
    f32 k;
    f32 pos[2];

    *(u32*)&((PlayerState*)inner)->flags360 &= ~PLAYER_FLAG_HITDETECT;
    *(u32*)&((PlayerState*)inner)->flags360 |= PLAYER_FLAG_NO_POS_VELOCITY;
    *(int*)((char*)state + 0x4) |= 0x100000;
    k = lbl_803E7EA4;
    ((PlayerState*)state)->baddie.animSpeedA = k;
    ((PlayerState*)state)->baddie.animSpeedB = k;
    *(int*)state |= 0x200000;
    obj->anim.velocityX = k;
    obj->anim.velocityZ = k;
    *(int*)((char*)state + 0x4) |= 0x8000000;
    obj->anim.velocityY = k;
    if (*(s8*)&((PlayerState*)state)->baddie.moveJustStartedA != 0 && gPlayerPathObject != 0 &&
        ((ByteFlags*)((char*)inner + 0x3f4))->b40)
    {
        ((PlayerState*)inner)->staffActionRequest = 1;
        ((ByteFlags*)((char*)inner + 0x3f4))->b08 = 1;
    }
    switch (obj->anim.currentMove)
    {
    case 0x41a:
        if (*(s8*)&((PlayerState*)state)->baddie.moveDone != 0)
        {
            fn_802AB5A4(obj, inner + 4, 5);
            *(int*)&((PlayerState*)state)->baddie.unk308 = (int)fn_8029FFD0;
            return -0x13;
        }
        break;
    default:
    {
        pos[0] = ((PlayerState*)inner)->spanTopY;
        pos[1] = ((PlayerState*)inner)->spanBottomY;
        if (((PlayerState*)inner)->curAnimId != 0x48 && ((PlayerState*)inner)->curAnimId != 0x47)
        {
            (*gCameraInterface)->setMode(0x4b, 1, 1, 8, pos, 0, 0xff);
        }
        ObjAnim_SetCurrentMove((int)obj, 0x41a, lbl_803E7EA4, 1);
        ((PlayerState*)inner)->targetYaw =
            getAngle(((PlayerState*)inner)->groundNormalX, ((PlayerState*)inner)->groundNormalZ);
        ((PlayerState*)inner)->yaw = ((PlayerState*)inner)->targetYaw;
        obj->anim.localPosX = ((PlayerState*)inner)->climbStartPosX;
        obj->anim.localPosY = ((PlayerState*)inner)->savedPosY;
        obj->anim.localPosZ = ((PlayerState*)inner)->climbStartPosZ;
        ((PlayerState*)state)->baddie.moveSpeed = lbl_803E800C;
        break;
    }
    }
    fn_802AB5A4(obj, inner + 4, 5);
    return 0;
}

int playerStateSlideDownLadder(GameObject* obj, int state, f32 fv)
{
    PlayerState* inner = obj->extra;
    if (*(s8*)&((PlayerState*)state)->baddie.moveJustStartedA != 0)
    {
        ObjHits_MarkObjectPositionDirty((ObjAnimComponent*)obj);
        lbl_803DE498 = lbl_803E7EA4;
        ObjAnim_SetCurrentMove((int)obj, 0x35, lbl_803E7EA4, 1);
        ((PlayerState*)state)->baddie.moveSpeed = lbl_803E7F20;
        inner->moveStartPosY = obj->anim.localPosY;
        obj->anim.localPosY = inner->savedPosY;
        fn_802AB5A4(obj, (int)inner, 5);
    }
    if (inner->waterDepth > lbl_803E7FA0)
    {
        fn_802AB5A4(obj, (int)inner, 5);
        ((void (*)(int, int, int))fn_802AE83C)((int)obj, (int)inner, state);
        *(int*)&((PlayerState*)state)->baddie.unk308 = (int)fn_802A514C;
        return 2;
    }
    *(int*)((char*)state + 0x4) |= 0x100000;
    *(int*)((char*)state + 0x4) |= 0x8000000;
    *(int*)((char*)state + 0) |= 0x200000;
    switch (obj->anim.currentMove)
    {
    case 0x35:
        if (*(s8*)&((PlayerState*)state)->baddie.moveDone != 0)
        {
            ObjAnim_SetCurrentMove((int)obj, 0x36, lbl_803E7EA4, 0);
            ((PlayerState*)state)->baddie.moveSpeed = lbl_803E7F20;
        }
    case 0x36:
    {
        f32 f30 = lbl_803E7ED8 * -lbl_803DE498;
        f32 f3;
        if ((*(int*)&((PlayerState*)state)->baddie.eventFlags & 1) != 0)
        {
            Sfx_PlayFromObject((int)obj, SFXTRIG_mv_dive4_c);
        }
        f3 = obj->anim.localPosY - (lbl_803E8010 + inner->climbBaseY);
        if (f3 < lbl_803E7EA4)
        {
            f3 = lbl_803E7EA4;
        }
        if (f3 < f30)
        {
            f32 ed4 = lbl_803E7ED4;
            f32 base = ed4 * (lbl_803DE498 * lbl_803DE498 / (ed4 * f30));
            obj->anim.velocityY = -sqrtf(base * f3);
            if (obj->anim.velocityY >= lbl_803E7FEC)
            {
                u8 anim = inner->curAnimId;
                f32 v4ec;
                if (anim != 0x48 && anim != 0x47 && anim != 0x42)
                {
                    (*gCameraInterface)->setMode(0x42, 0, 1, 0, NULL, 0, 0xff);
                    inner->curAnimId = 0x42;
                }
                inner->moveStartPosY = obj->anim.localPosY;
                v4ec = inner->climbBaseY;
                obj->anim.worldPosY = v4ec;
                obj->anim.localPosY = v4ec;
                if (((ByteFlags*)((char*)inner + 0x547))->b80)
                {
                    ObjAnim_SetCurrentMove((int)obj, 0x37, lbl_803E7EA4, 1);
                    ((PlayerState*)state)->baddie.moveSpeed = lbl_803E7FCC;
                    obj->anim.velocityY = lbl_803E7EA4;
                }
                else
                {
                    f32 zero = lbl_803E7EA4;
                    void* sub;
                    ((PlayerState*)state)->baddie.animSpeedC = zero;
                    ((PlayerState*)state)->baddie.animSpeedB = zero;
                    ((PlayerState*)state)->baddie.animSpeedA = zero;
                    obj->anim.velocityX = zero;
                    obj->anim.velocityY = zero;
                    obj->anim.velocityZ = zero;
                    fn_802AB5A4(obj, (int)inner, 5);
                    ((ByteFlags*)((char*)inner + 0x3f0))->b80 = 0;
                    ((ByteFlags*)((char*)inner + 0x3f0))->b10 = 0;
                    ((ByteFlags*)((char*)inner + 0x3f0))->b08 = 0;
                    staffFn_80170380(gPlayerStaffObject, 2);
                    ((ByteFlags*)((char*)inner + 0x3f0))->b02 = 0;
                    *(u32*)&((PlayerState*)inner)->flags360 |= PLAYER_FLAG_TELEPORTED;
                    ObjHits_SyncObjectPositionIfDirtyLegacy(obj);
                    ((ByteFlags*)((char*)inner + 0x3f0))->b40 = 0;
                    ((ByteFlags*)((char*)inner + 0x3f0))->b04 = 1;
                    ((ByteFlags*)((char*)inner + 0x3f4))->b10 = 1;
                    inner->isHoldingObject = 0;
                    sub = *(void**)((char*)inner + 0x7f8);
                    if (sub != NULL)
                    {
                        s16 id = ((GameObject*)sub)->anim.seqId;
                        if (id == 0x3cf || id == 0x662)
                        {
                            objThrowFn_80182504((GameObject*)sub);
                        }
                        else
                        {
                            objSaveFn_800ea774((GameObject*)sub);
                        }
                        *(s16*)((char*)inner->heldObj + 0x6) &= ~0x4000;
                        *(int*)((char*)inner->heldObj + 0xf8) = 0;
                        inner->heldObj = 0;
                    }
                    *(int*)&((PlayerState*)state)->baddie.unk308 = (int)fn_802A514C;
                    return 3;
                }
            }
        }
        else
        {
            if (obj->anim.velocityY > lbl_803E8014)
            {
                obj->anim.velocityY = obj->anim.velocityY - lbl_803E7F6C * fv;
            }
            if (obj->anim.velocityY < *(f32*)&lbl_803E8014)
            {
                obj->anim.velocityY = lbl_803E8014;
            }
            if (obj->anim.velocityY < lbl_803DE498)
            {
                lbl_803DE498 = obj->anim.velocityY;
            }
        }
    }
    break;
    case 0x37:
        if ((*(int*)&((PlayerState*)state)->baddie.eventFlags & 1) != 0)
        {
            int snd = audioPickSoundEffectIntLegacy(inner->surfaceType, inner->footstepSoundId);
            Sfx_PlayFromObject((int)obj, snd);
            doRumble(lbl_803E7F10);
            if (inner->waterDepth > lbl_803E7EA4)
            {
                (*gWaterfxInterface)
                    ->spawnSplashBurst((void*)obj, obj->anim.localPosX,
                                       obj->anim.localPosY, obj->anim.localPosZ,
                                       lbl_803E8018);
            }
        }
        if (*(s8*)&((PlayerState*)state)->baddie.moveDone != 0)
        {
            f32 local;
            obj->anim.worldPosX = inner->savedPosX;
            obj->anim.worldPosZ = inner->savedPosZ;
            if (obj->anim.parent != NULL)
            {
                obj->anim.worldPosX += playerMapOffsetX;
                obj->anim.worldPosZ += playerMapOffsetZ;
            }
            Obj_TransformWorldPointToLocal(obj->anim.worldPosX, lbl_803E7EA4,
                                           obj->anim.worldPosZ, &obj->anim.localPosX,
                                           &local, &obj->anim.localPosZ,
                                           *(int*)&obj->anim.parent);
            fn_802AB5A4(obj, (int)inner, 5);
            ObjAnim_SetCurrentMove((int)obj, *(s16*)(inner->moveAnimTable), lbl_803E7EA4, 1);
            *(u32*)&((PlayerState*)inner)->flags360 |= PLAYER_FLAG_TELEPORTED;
            *(int*)&((PlayerState*)state)->baddie.unk308 = (int)fn_802A514C;
            return 2;
        }
        break;
    }
    {
        f32 w;
        f32 py;
        f32 cx = obj->anim.localPosX;
        f32 cy;
        f32 cz = obj->anim.localPosZ;
        f32 czOut = cz;
        switch (obj->anim.currentMove)
        {
        case 0x35:
            cy = obj->anim.currentMoveProgress *
                     (obj->anim.localPosY - inner->moveStartPosY) +
                 inner->moveStartPosY;
            break;
        case 0x37:
        {
            w = obj->anim.currentMoveProgress;
            cx = w * (inner->savedPosX - cx) + cx;
            py = obj->anim.localPosY;
            cy = (lbl_803E7EE0 - w) * (inner->moveStartPosY - py) + py;
            czOut = w * (inner->savedPosZ - cz) + cz;
        }
        break;
        default:
            cy = obj->anim.localPosY;
            break;
        }
        (*gCameraInterface)->overridePos(cx, cy, czOut);
    }
    fn_802AB5A4(obj, (int)inner, 5);
    return 0;
}
int playerStateOnLadder(int obj, int state)
{
    ObjModel* jt;
    int inner;
    f32 t;
    f32 spd;
    f32 ph;
    f32 buf1[3];
    f32 buf2[3];
    s16 tmp[3];
    f32 outY;

    inner = *(int*)&((GameObject*)obj)->extra;
    if (*(s8*)&((PlayerState*)state)->baddie.moveJustStartedA != 0)
    {
        ObjHits_MarkObjectPositionDirty((ObjAnimComponent*)obj);
        if (gPlayerPathObject != 0 && ((u32) * (u8*)((char*)inner + 0x3f4) >> 6 & 1) != 0)
        {
            ((PlayerState*)inner)->staffActionRequest = 1;
            ((ByteFlags*)((char*)inner + 0x3f4))->b08 = 1;
        }
        if (((GameObject*)obj)->anim.currentMove == lbl_80332F2C[8] ||
            ((GameObject*)obj)->anim.currentMove == lbl_80332F2C[12])
        {
            gPlayerCurrentMoveId = 8;
        }
        else
        {
            gPlayerCurrentMoveId = 9;
        }
    }
    if (((PlayerState*)inner)->climbStep > 3)
    {
        setAButtonIcon(0x1a);
    }
    else
    {
        setAButtonIcon(0x1c);
    }
    {
        int base = *(int*)&((GameObject*)obj)->extra;
        *(u32*)((char*)base + 0x360) &= ~0x2LL;
        *(u32*)((char*)base + 0x360) |= 0x2000LL;
    }
    *(u32*)((char*)state + 4) |= 0x100000;
    {
        f32 z = lbl_803E7EA4;
        ((PlayerState*)state)->baddie.animSpeedA = z;
        ((PlayerState*)state)->baddie.animSpeedB = z;
        *(u32*)state |= 0x200000;
        ((GameObject*)obj)->anim.velocityX = z;
        ((GameObject*)obj)->anim.velocityZ = z;
        *(u32*)((char*)state + 4) |= 0x8000000;
        if (((PlayerState*)inner)->waterDepth > lbl_803E7FA0)
        {
            fn_802AB5A4((GameObject*)obj, inner, 5);
            ((void (*)(int, int, int))fn_802AE83C)(obj, inner, state);
            *(int*)&((PlayerState*)state)->baddie.unk308 = (int)fn_802A514C;
            return 2;
        }
        ((GameObject*)obj)->anim.velocityY = z;
        {
            f32 mag = ((PlayerState*)state)->baddie.moveInputZ / lbl_803E7FA8;
            if (mag < z)
            {
                mag = -mag;
            }
            t = (mag < lbl_803E7EFC) ? lbl_803E7EFC : ((mag > lbl_803E7EE0) ? lbl_803E7EE0 : mag);
        }
    }
    jt = Player_GetActiveModel(obj);
    spd = lbl_803E7EA4;
    ph = ((PlayerState*)state)->baddie.moveSpeed;
    gPlayerPrevMoveId = gPlayerCurrentMoveId;
    if ((*(int*)&((PlayerState*)state)->baddie.eventFlags & 1) != 0)
    {
        switch (((PlayerState*)inner)->footstepSurface)
        {
        case 4:
            Sfx_PlayFromObject(obj, SFXTRIG_foot_33a);
            break;
        default:
            Sfx_PlayFromObject(obj, SFXTRIG_foot_var);
            break;
        }
    }
    switch ((s16)gPlayerCurrentMoveId)
    {
    case 8:
    case 9:
    case 12:
    case 13:
        ((GameObject*)obj)->anim.localPosY = ((PlayerState*)inner)->climbTargetY;
        ((GameObject*)obj)->anim.activeMove = -1;
        ((PlayerState*)inner)->climbingUp = 0;
        ((PlayerState*)inner)->climbStartY = ((PlayerState*)inner)->climbTargetY;
        ph = spd = lbl_803E7EA4;
        if ((gPlayerCurrentMoveId & 1) != 0)
        {
            gPlayerCurrentMoveId = 1;
        }
        else
        {
            gPlayerCurrentMoveId = 0;
        }
        goto finish;
    case 6:
    case 7:
        if ((*(int*)&((PlayerState*)state)->baddie.eventFlags & 0x80) != 0)
        {
            Sfx_PlayFromObject(obj, SFXTRIG_foot);
            if (((PlayerState*)inner)->characterId == 0)
            {
                Sfx_PlayFromObject(obj, SFXTRIG_jump3);
            }
        }
        if (*(s8*)&((PlayerState*)state)->baddie.moveDone != 0)
        {
            ((GameObject*)obj)->anim.localPosY = ((PlayerState*)inner)->climbEndLocalY;
        }
        else
        {
            ObjModel_SampleJointTransform(jt, 0, 0, lbl_803E7EA4, ((GameObject*)obj)->anim.rootMotionScale, buf1, tmp);
            ObjModel_SampleJointTransform(jt, 0, 0, lbl_803E7EE0, ((GameObject*)obj)->anim.rootMotionScale, buf2, tmp);
            ((GameObject*)obj)->anim.localPosY = ((GameObject*)obj)->anim.currentMoveProgress *
                                                     ((lbl_803DE43C - (buf2[1] - buf1[1])) - (lbl_803DE438 + buf1[1])) +
                                                 lbl_803DE438;
        }
    case 10:
    case 11:
        if ((*(int*)&((PlayerState*)state)->baddie.eventFlags & 0x200) != 0)
        {
            doRumble(lbl_803E7F10);
            if (((PlayerState*)inner)->waterDepth > lbl_803E7EA4)
            {
                (*gWaterfxInterface)
                    ->spawnSplashBurst((void*)obj, ((GameObject*)obj)->anim.localPosX,
                                       ((GameObject*)obj)->anim.localPosY, ((GameObject*)obj)->anim.localPosZ,
                                       lbl_803E8018);
            }
        }
        if (*(s8*)&((PlayerState*)state)->baddie.moveDone != 0)
        {
            ((GameObject*)obj)->anim.worldPosX = ((PlayerState*)inner)->savedPosX;
            ((GameObject*)obj)->anim.worldPosZ = ((PlayerState*)inner)->savedPosZ;
            if (((GameObject*)obj)->anim.parent != NULL)
            {
                ((GameObject*)obj)->anim.worldPosX = ((GameObject*)obj)->anim.worldPosX + playerMapOffsetX;
                ((GameObject*)obj)->anim.worldPosZ = ((GameObject*)obj)->anim.worldPosZ + playerMapOffsetZ;
            }
            ((void (*)(f32, f32, f32, f32*, f32*, f32*, int))Obj_TransformWorldPointToLocal)(
                ((GameObject*)obj)->anim.worldPosX, lbl_803E7EA4, ((GameObject*)obj)->anim.worldPosZ,
                &((GameObject*)obj)->anim.localPosX, &outY, &((GameObject*)obj)->anim.localPosZ,
                *(int*)&((GameObject*)obj)->anim.parent);
            if (gPlayerCurrentMoveId == 6 || gPlayerCurrentMoveId == 7)
            {
                fn_802AB5A4((GameObject*)obj, inner, 7);
            }
            else
            {
                fn_802AB5A4((GameObject*)obj, inner, 5);
            }
            ObjAnim_SetCurrentMove(obj, **(s16**)((char*)inner + 0x3f8), lbl_803E7EA4, 1);
            *(u32*)&((PlayerState*)inner)->flags360 |= PLAYER_FLAG_TELEPORTED;
            *(int*)&((PlayerState*)state)->baddie.unk308 = (int)fn_802A514C;
            return 2;
        }
        goto finish;
    case 4:
    case 5:
        if (((PlayerState*)state)->baddie.moveInputZ > lbl_803E7F10)
        {
            ((void (*)(int, f32))ObjAnim_SetMoveProgress)(obj, lbl_803E7EA4);
        }
        else if (((PlayerState*)state)->baddie.moveInputZ < lbl_803E801C)
        {
            ((void (*)(int, f32))ObjAnim_SetMoveProgress)(obj, lbl_803E7EA4);
        }
        else
        {
            if ((*(int*)&((PlayerState*)state)->baddie.unk31C & 0x100) != 0 && ((PlayerState*)inner)->climbStep > 3)
            {
                *(int*)&((PlayerState*)state)->baddie.unk308 = (int)fn_8029FFD0;
                return -0x10;
            }
            goto finish;
        }
    default:
        if ((*(int*)&((PlayerState*)state)->baddie.eventFlags & 0x80) != 0)
        {
            Sfx_PlayFromObject(obj, SFXTRIG_foot_var);
        }
        if ((*(int*)&((PlayerState*)state)->baddie.unk31C & 0x100) != 0 && ((PlayerState*)inner)->climbStep > 3)
        {
            *(int*)&((PlayerState*)state)->baddie.unk308 = (int)fn_8029FFD0;
            return -0x10;
        }
        if (lbl_803E7EE0 == ((GameObject*)obj)->anim.currentMoveProgress)
        {
            if (((PlayerState*)state)->baddie.moveInputZ < lbl_803E801C)
            {
                ((PlayerState*)inner)->climbingUp = 0;
                ph = -(lbl_803E7EF8 * t + lbl_803E7F20);
                if ((s16)gPlayerCurrentMoveId <= 1)
                {
                    gPlayerCurrentMoveId += 2;
                    spd = lbl_803E7F68;
                }
            }
            else
            {
                *(u8*)&((PlayerState*)inner)->climbStep += 1;
                ((PlayerState*)inner)->climbingUp = 1;
                ph = lbl_803E7EA4;
                if ((s16)gPlayerCurrentMoveId <= 1)
                {
                    gPlayerCurrentMoveId ^= 1;
                    spd = ph;
                }
                ((PlayerState*)inner)->climbStartY =
                    ((GameObject*)obj)->anim.localPosY + ((PlayerState*)inner)->moveStartPosY;
                ((PlayerState*)inner)->climbTargetY =
                    (f32) * (s8*)((char*)inner + 0x4e4) * ((PlayerState*)inner)->climbStepHeight +
                    ((PlayerState*)inner)->climbBaseY;
                ((GameObject*)obj)->anim.localPosY = ((PlayerState*)inner)->climbStartY;
            }
        }
        {
            f32 z2 = lbl_803E7EA4;
            if (z2 == ((GameObject*)obj)->anim.currentMoveProgress)
            {
                if (((PlayerState*)state)->baddie.moveInputZ > lbl_803E7F10)
                {
                    ((PlayerState*)inner)->climbingUp = 1;
                    if ((int)((PlayerState*)inner)->climbStep >= ((PlayerState*)inner)->climbStepCount - 3)
                    {
                        spd = z2;
                        ph = lbl_803E8020;
                        {
                            s16 ns;
                            if ((gPlayerCurrentMoveId & 1) != 0)
                            {
                                ns = 7;
                            }
                            else
                            {
                                ns = 6;
                            }
                            gPlayerCurrentMoveId = ns;
                        }
                        lbl_803DE438 = ((GameObject*)obj)->anim.localPosY;
                        lbl_803DE43C = ((PlayerState*)inner)->climbEndLocalY + lbl_803DAF88[0];
                        if (((PlayerState*)inner)->curAnimId != 0x48 && ((PlayerState*)inner)->curAnimId != 0x47)
                        {
                            (*gCameraInterface)->setMode(0x42, 0, 1, 0, NULL, 0x1e, 0xff);
                        }
                        goto finish;
                    }
                    spd = z2;
                    ph = lbl_803E7F84 * t + lbl_803E7F20;
                    if ((s16)gPlayerCurrentMoveId > 1)
                    {
                        if ((gPlayerCurrentMoveId & 1) != 0)
                        {
                            gPlayerCurrentMoveId = 1;
                        }
                        else
                        {
                            gPlayerCurrentMoveId = 0;
                        }
                    }
                }
                else if (((PlayerState*)state)->baddie.moveInputZ < lbl_803E801C)
                {
                    *(u8*)&((PlayerState*)inner)->climbStep -= 1;
                    ((PlayerState*)inner)->climbingUp = 0;
                    if (((PlayerState*)inner)->climbStep < 1)
                    {
                        if (((PlayerState*)inner)->curAnimId != 0x48 && ((PlayerState*)inner)->curAnimId != 0x47 &&
                            ((PlayerState*)inner)->curAnimId != 0x42)
                        {
                            (*gCameraInterface)->setMode(0x42, 0, 1, 0, NULL, 0x1e, 0xff);
                            ((PlayerState*)inner)->curAnimId = 0x42;
                        }
                        if (((u32) * (u8*)((char*)inner + 0x547) >> 7 & 1) != 0)
                        {
                            spd = lbl_803E7EA4;
                            ph = lbl_803E7FE8;
                            {
                                s16 ns;
                                if ((gPlayerCurrentMoveId & 1) != 0)
                                {
                                    ns = 0xb;
                                }
                                else
                                {
                                    ns = 0xa;
                                }
                                gPlayerCurrentMoveId = ns;
                            }
                            ((GameObject*)obj)->anim.localPosY = ((PlayerState*)inner)->climbBaseY;
                            goto finish;
                        }
                        else
                        {
                            {
                                f32 z3 = lbl_803E7EA4;
                                ((PlayerState*)state)->baddie.animSpeedC = z3;
                                ((PlayerState*)state)->baddie.animSpeedB = z3;
                                ((PlayerState*)state)->baddie.animSpeedA = z3;
                                ((GameObject*)obj)->anim.velocityX = z3;
                                ((GameObject*)obj)->anim.velocityY = z3;
                                ((GameObject*)obj)->anim.velocityZ = z3;
                            }
                            ((ByteFlags*)((char*)inner + 0x3f0))->b80 = 0;
                            ((ByteFlags*)((char*)inner + 0x3f0))->b10 = 0;
                            ((ByteFlags*)((char*)inner + 0x3f0))->b08 = 0;
                            staffFn_80170380(gPlayerStaffObject, 2);
                            ((ByteFlags*)((char*)inner + 0x3f0))->b02 = 0;
                            *(u32*)&((PlayerState*)inner)->flags360 |= PLAYER_FLAG_TELEPORTED;
                            ObjHits_SyncObjectPositionIfDirtyLegacy(obj);
                            ((ByteFlags*)((char*)inner + 0x3f0))->b40 = 0;
                            ((ByteFlags*)((char*)inner + 0x3f0))->b04 = 1;
                            ((ByteFlags*)((char*)inner + 0x3f4))->b10 = 1;
                            ((PlayerState*)inner)->isHoldingObject = 0;
                            if (*(void**)((char*)inner + 0x7f8) != NULL)
                            {
                                if (((GameObject*)((PlayerState*)inner)->heldObj)->anim.seqId == 0x3cf ||
                                    ((GameObject*)((PlayerState*)inner)->heldObj)->anim.seqId == 0x662)
                                {
                                    objThrowFn_80182504((GameObject*)(((PlayerState*)inner)->heldObj));
                                }
                                else
                                {
                                    objSaveFn_800ea774((GameObject*)((PlayerState*)inner)->heldObj);
                                }
                                *(s16*)((char*)((PlayerState*)inner)->heldObj + 6) =
                                    *(s16*)((char*)((PlayerState*)inner)->heldObj + 6) & ~0x4000;
                                *(int*)((char*)((PlayerState*)inner)->heldObj + 0xf8) = 0;
                                ((PlayerState*)inner)->heldObj = 0;
                            }
                            fn_802AB5A4((GameObject*)obj, inner, 5);
                            *(int*)&((PlayerState*)state)->baddie.unk308 = (int)fn_802A514C;
                            return 3;
                        }
                    }
                    else
                    {
                        spd = lbl_803E7F68;
                        ph = -(lbl_803E7EF8 * t + lbl_803E7F20);
                        {
                            s16 ns;
                            if ((gPlayerCurrentMoveId & 1) != 0)
                            {
                                ns = 2;
                            }
                            else
                            {
                                ns = 3;
                            }
                            gPlayerCurrentMoveId = ns;
                        }
                        ((PlayerState*)inner)->climbTargetY =
                            (f32) * (s8*)((char*)inner + 0x4e4) * ((PlayerState*)inner)->climbStepHeight +
                            ((PlayerState*)inner)->climbBaseY;
                        {
                            f32 y2 = ((GameObject*)obj)->anim.localPosY - ((PlayerState*)inner)->moveStartPosY;
                            ((PlayerState*)inner)->climbStartY = y2;
                            ((GameObject*)obj)->anim.localPosY = y2;
                        }
                        goto vel_join;
                    }
                }
                else
                {
                    if (((int (*)(ObjAnimComponent*))ObjAnim_GetCurrentEventCountdown)((ObjAnimComponent*)obj) != 0)
                    {
                        goto vel_join;
                    }
                    spd = lbl_803E7EA4;
                    ph = lbl_803E7EF8;
                    if ((gPlayerCurrentMoveId & 1) != 0 && gPlayerCurrentMoveId != 5)
                    {
                        gPlayerCurrentMoveId = 5;
                    }
                    else if ((gPlayerCurrentMoveId & 1) == 0 && gPlayerCurrentMoveId != 4)
                    {
                        gPlayerCurrentMoveId = 4;
                    }
                    goto finish;
                }
            }
        }
    vel_join:
        if (ph < lbl_803E7EA4)
        {
            ph = -(lbl_803E7EF8 * t + lbl_803E7F20);
        }
        else if (ph > lbl_803E7EA4)
        {
            ph = lbl_803E7F84 * t + lbl_803E7F20;
        }
        if (*(s8*)&((PlayerState*)inner)->climbingUp != 0)
        {
            ((GameObject*)obj)->anim.localPosY =
                ((GameObject*)obj)->anim.currentMoveProgress *
                    (((PlayerState*)inner)->climbTargetY - ((PlayerState*)inner)->climbStartY) +
                ((PlayerState*)inner)->climbStartY;
        }
        else
        {
            ((GameObject*)obj)->anim.localPosY =
                (lbl_803E7EE0 - ((GameObject*)obj)->anim.currentMoveProgress) *
                    (((PlayerState*)inner)->climbTargetY - ((PlayerState*)inner)->climbStartY) +
                ((PlayerState*)inner)->climbStartY;
        }
        break;
    }
finish:
    ((PlayerState*)state)->baddie.moveSpeed = ph;
    if (gPlayerPrevMoveId != gPlayerCurrentMoveId)
    {
        ObjAnim_SetCurrentMove(obj, lbl_80332F2C[gPlayerCurrentMoveId], spd, 1);
        if ((s16)gPlayerCurrentMoveId <= 1 && ((PlayerState*)inner)->climbSampleDone == 0)
        {
            ObjModel_SampleJointTransform(jt, 0, 0, lbl_803E7EA4, ((GameObject*)obj)->anim.rootMotionScale, buf1, tmp);
            ObjModel_SampleJointTransform(jt, 0, 0, lbl_803E7EE0, ((GameObject*)obj)->anim.rootMotionScale, buf2, tmp);
            ((PlayerState*)inner)->moveStartPosY = buf2[1] - buf1[1];
            *(u8*)&((PlayerState*)inner)->climbSampleDone = 1;
        }
    }
    {
        f32 w;
        f32 py;
        f32 x = ((GameObject*)obj)->anim.localPosX;
        f32 y;
        f32 zz = ((GameObject*)obj)->anim.localPosZ;
        f32 zzOut = zz;
        switch ((s16)gPlayerCurrentMoveId)
        {
        case 0:
        case 1:
        case 2:
        case 3:
            y = ((GameObject*)obj)->anim.currentMoveProgress *
                    (((f32)(((PlayerState*)inner)->climbStep + 1) * ((PlayerState*)inner)->climbStepHeight +
                      ((PlayerState*)inner)->climbBaseY) -
                     ((GameObject*)obj)->anim.localPosY) +
                ((GameObject*)obj)->anim.localPosY;
            break;
        case 10:
        case 11:
            w = ((GameObject*)obj)->anim.currentMoveProgress;
            x = w * (((PlayerState*)inner)->savedPosX - x) + x;
            py = ((GameObject*)obj)->anim.localPosY;
            y = (lbl_803E7EE0 - w) * (((PlayerState*)inner)->climbTargetY - py) + py;
            zzOut = w * (((PlayerState*)inner)->savedPosZ - zz) + zz;
            break;
        case 6:
        case 7:
            w = ((GameObject*)obj)->anim.currentMoveProgress;
            x = w * (((PlayerState*)inner)->savedPosX - x) + x;
            y = w * (((PlayerState*)inner)->climbEndLocalY - ((GameObject*)obj)->anim.localPosY) +
                ((GameObject*)obj)->anim.localPosY;
            zzOut = w * (((PlayerState*)inner)->savedPosZ - zz) + zz;
            break;
        default:
            y = ((GameObject*)obj)->anim.localPosY;
            break;
        }
        (*gCameraInterface)->overridePos(x, y, zzOut);
    }
    fn_802AB5A4((GameObject*)obj, inner, 5);
    return 0;
}
#pragma opt_propagation off

int playerStateClimbOntoLadder(GameObject* obj, int state, f32 fv)
{
    int flag;
    PlayerState* innerV = obj->extra;
    PlayerState* inner = obj->extra;

    *(u32*)&((PlayerState*)innerV)->flags360 &= ~PLAYER_FLAG_HITDETECT;
    *(u32*)&((PlayerState*)innerV)->flags360 |= PLAYER_FLAG_NO_POS_VELOCITY;
    *(int*)((char*)state + 0x4) |= 0x100000;
    {
        f32 z = lbl_803E7EA4;
        ((PlayerState*)state)->baddie.animSpeedA = z;
        ((PlayerState*)state)->baddie.animSpeedB = z;
        *(int*)((char*)state + 0x0) |= 0x200000;
        obj->anim.velocityX = z;
        obj->anim.velocityZ = z;
        *(int*)((char*)state + 0x4) |= 0x8000000;
        obj->anim.velocityY = z;
    }
    flag = innerV->climbStep != 1;
    if (flag)
    {
        ((PlayerState*)state)->baddie.moveSpeed = lbl_803E7EF8;
    }
    else
    {
        ((PlayerState*)state)->baddie.moveSpeed = lbl_803E8024;
    }
    if ((*(int*)&((PlayerState*)state)->baddie.eventFlags & 0x80) != 0)
    {
        int o = (int)obj;
        u16 sfxId = inner->characterId == 0 ? 0x398 : 0x1d;
        Sfx_PlayFromObject(o, sfxId);
    }
    if ((*(int*)&((PlayerState*)state)->baddie.eventFlags & 1) != 0)
    {
        switch (inner->footstepSurface)
        {
        case 4:
            Sfx_PlayFromObject((int)obj, SFXTRIG_foot_33a);
            break;
        default:
            Sfx_PlayFromObject((int)obj, SFXTRIG_foot_var);
            break;
        }
    }
    if (*(s8*)&((PlayerState*)state)->baddie.moveJustStartedA != 0)
    {
        s16* tbl;
        int sel;
        f32 jp[3];
        struct
        {
            f32 vx;
            f32 sp1c;
            f32 vy;
            f32 vz;
        } vb;
        ObjHits_MarkObjectPositionDirty((ObjAnimComponent*)obj);
        if (gPlayerPathObject != NULL && ((ByteFlags*)((char*)inner + 0x3f4))->b40 != 0)
        {
            inner->staffActionRequest = 1;
            ((ByteFlags*)((char*)inner + 0x3f4))->b08 = 1;
        }
        {
            f32 z = lbl_803E7EA4;
            ((PlayerState*)state)->baddie.animSpeedA = z;
            ((PlayerState*)state)->baddie.animSpeedB = z;
            *(s16*)((char*)state + 0x278) = 0xe;
            inner->stateHandler = (int)fn_8029FFD0;
            vb.sp1c = z;
        }
        if (flag)
        {
            vb.vx = -inner->moveDirX;
            vb.vy = -inner->moveDirY;
            vb.vz = -inner->moveDirZ;
        }
        else
        {
            vb.vx = inner->moveDirX;
            vb.vy = inner->moveDirY;
            vb.vz = inner->moveDirZ;
        }
        {
            int delta = (u16)getAngle(vb.vx, vb.vy) - inner->targetYaw;
            if (delta > 0x8000)
            {
                delta -= 0xffff;
            }
            if (delta < -0x8000)
            {
                delta += 0xffff;
            }
            inner->targetYaw += delta;
            inner->yaw = inner->targetYaw;
        }
        inner->savedLocalPosX = obj->anim.localPosX;
        inner->savedLocalPosZ = obj->anim.localPosZ;
        obj->anim.localPosX = inner->moveStartPosX;
        obj->anim.localPosZ = inner->moveStartPosZ;
        sel = inner->unk4FC >= *(f32*)&lbl_803E7EA4 ? 0 : 4;
        if (flag)
        {
            tbl = lbl_80332F88;
        }
        else
        {
            tbl = lbl_80332F78;
        }
        inner->eventCountdown =
            fn_802A71E0Legacy((int)obj, tbl[sel], tbl[sel + 2], (int*)inner->blendAnchor, (int*)&vb.vx,
                              lbl_803E7EA4, ((PlayerState*)state)->baddie.moveSpeed, 2, 9);
        {
            int f9 = 0x34;
            if (flag)
            {
                f9 |= 0x40;
            }
            fn_802A71E0Legacy((int)obj, tbl[sel], tbl[sel + 1], (int*)inner->blendAnchor, (int*)inner->pad51C,
                              lbl_803E7EA4, ((PlayerState*)state)->baddie.moveSpeed, 0, (u8)f9);
        }
        fn_802A71E0Legacy((int)obj, tbl[sel + 2], tbl[sel + 3], (int*)inner->blendAnchor, (int*)inner->pad51C,
                          lbl_803E7EA4, ((PlayerState*)state)->baddie.moveSpeed, 0, 0x1a);
        inner->climbTargetY = inner->climbStepHeight * (f32)(int)inner->climbStep + inner->climbBaseY;
        inner->climbStartY = obj->anim.localPosY;
        {
            ObjModel* joint = Player_GetActiveModel((int)obj);
            s16 scratch[3];
            f32 camBuf[2];
            ObjModel_SampleJointTransform(joint, 0, 0, lbl_803E7EE0, obj->anim.rootMotionScale, jp,
                                          scratch);
            lbl_803DE438 = obj->anim.localPosY + jp[1];
            lbl_803DE43C = inner->climbTargetY + lbl_803DAF88[1];
            camBuf[0] = inner->climbEndLocalY;
            camBuf[1] = inner->climbBaseY;
            if (inner->curAnimId != 0x48 && inner->curAnimId != 0x47)
            {
                (*gCameraInterface)->setMode(0x4b, 1, 1, 8, camBuf, 0, 0);
            }
        }
    }
    else
    {
        if (obj->anim.currentMoveProgress > lbl_803E7FF4)
        {
            ((int (*)(int, f32, f32, int))Object_ObjAnimAdvanceMove)((int)obj, ((PlayerState*)state)->baddie.moveSpeed, fv,
                                                                     0);
            *(int*)&((PlayerState*)state)->baddie.unk308 = (int)fn_8029FFD0;
            return 0x10;
        }
    }
    {
        f32 mp = obj->anim.currentMoveProgress;
        if (mp >= lbl_803E7F18)
        {
            f32 g = lbl_803E8028 * (lbl_803E802C * mp - lbl_803E7F18);
            f32 c;
            c = (g < lbl_803E7EA4) ? lbl_803E7EA4 : ((g > lbl_803E7EE0) ? lbl_803E7EE0 : g);
            obj->anim.localPosY = c * (lbl_803DE43C - lbl_803DE438) + inner->climbStartY;
        }
    }
    ((void (*)(int, int, int, int))ObjAnim_WriteStateWord)((int)obj, OBJANIM_STATE_INDEX_CURRENT,
                                                           OBJANIM_STATE_WORD_PREV_EVENT_STATE, 0);
    ((void (*)(int, int, int, int))ObjAnim_WriteStateWord)((int)obj, OBJANIM_STATE_INDEX_ACTIVE,
                                                           OBJANIM_STATE_WORD_PREV_EVENT_STATE, 0);
    ((void (*)(int, int, int, int))ObjAnim_WriteStateWord)((int)obj, OBJANIM_STATE_INDEX_ACTIVE,
                                                           OBJANIM_STATE_WORD_EVENT_COUNTDOWN, inner->eventCountdown);
    ((int (*)(int, f32, f32, int))Object_ObjAnimAdvanceMove)((int)obj, ((PlayerState*)state)->baddie.moveSpeed, fv, 0);
    (*gCameraInterface)
        ->overridePos(obj->anim.localPosX,
                      obj->anim.currentMoveProgress *
                              (inner->climbTargetY - obj->anim.localPosY) +
                          obj->anim.localPosY,
                      obj->anim.localPosZ);
    fn_802AB5A4(obj, (int)inner, 5);
    return 0;
}
#pragma opt_propagation reset

int playerState0D(GameObject* obj, int targetState)
{
    PlayerState* inner = obj->extra;
    f32 fz;
    *(u32*)&((PlayerState*)inner)->flags360 &= ~PLAYER_FLAG_HITDETECT;
    *(u32*)&((PlayerState*)inner)->flags360 |= PLAYER_FLAG_NO_POS_VELOCITY;
    *(int*)((char*)targetState + 4) |= 0x100000;
    fz = lbl_803E7EA4;
    ((PlayerState*)targetState)->baddie.animSpeedA = fz;
    ((PlayerState*)targetState)->baddie.animSpeedB = fz;
    *(int*)((char*)targetState + 0) |= 0x200000;
    obj->anim.velocityX = fz;
    obj->anim.velocityZ = fz;
    return 0;
}

extern f32 lbl_803E8034;
extern f32 lbl_803E803C;

int playerStateClimbLedge(int obj, int state, f32 fv)
{
    int inner = *(int*)&((GameObject*)obj)->extra;
    f32 diff = ((PlayerState*)inner)->leapTargetY - ((PlayerState*)inner)->characterHeightOffset;
    f32 blend;
    f32 z;
    f32 t;

    if (*(s8*)&((PlayerState*)state)->baddie.moveJustStartedA != 0)
    {
        *(s16*)((char*)state + 0x278) = 0xc;
        ((PlayerState*)inner)->stateHandler = 0;
        ((GameObject*)obj)->anim.velocityY = lbl_803E7EA4;
    }
    z = lbl_803E7EA4;
    ((PlayerState*)inner)->probeHitDist = z;
    {
        int in2 = *(int*)&((GameObject*)obj)->extra;
        *(u32*)((char*)in2 + 0x360) &= ~2LL;
        *(u32*)((char*)in2 + 0x360) |= 0x2000LL;
    }
    *(u32*)((char*)state + 4) |= 0x100000;
    ((PlayerState*)state)->baddie.animSpeedA = z;
    ((PlayerState*)state)->baddie.animSpeedB = z;
    *(u32*)state |= 0x200000;
    ((GameObject*)obj)->anim.velocityX = z;
    ((GameObject*)obj)->anim.velocityZ = z;
    *(u32*)((char*)state + 4) |= 0x8000000;
    gPlayerPrevMoveId = gPlayerCurrentMoveId;
    switch (gPlayerCurrentMoveId)
    {
    case 0:
        t = (((GameObject*)obj)->anim.localPosY - ((PlayerState*)inner)->moveStartY) /
            (diff - ((PlayerState*)inner)->moveStartY);
        ((GameObject*)obj)->anim.localPosX =
            t * (((PlayerState*)inner)->moveEnd2X - ((PlayerState*)inner)->moveStartX) +
            ((PlayerState*)inner)->moveStartX;
        ((GameObject*)obj)->anim.localPosZ =
            t * (((PlayerState*)inner)->moveEnd2Z - ((PlayerState*)inner)->moveStartZ) +
            ((PlayerState*)inner)->moveStartZ;
        (*(void (*)(int, int, int))(*(int*)((char*)*gPlayerInterface + 0x20)))(obj, state, 0x14);
        ((GameObject*)obj)->anim.localPosY =
            *(f32*)((char*)state + 0x2b4) * timeDelta + ((GameObject*)obj)->anim.localPosY;
        if (*(s8*)&((PlayerState*)state)->baddie.moveDone != 0)
        {
            f32 d2;
            f32 v;
            gPlayerCurrentMoveId = 2;
            blend = lbl_803E7EF8;
            v = (5.0f + diff) - ((GameObject*)obj)->anim.localPosY;
            v = lbl_803E8030 * -v;
            if (v >= lbl_803E7EA4)
            {
                ((GameObject*)obj)->anim.velocityY = sqrtf(v);
            }
            else
            {
                ((GameObject*)obj)->anim.velocityY = lbl_803E7EA4;
            }
            Sfx_PlayFromObject(obj,
                               (u16)(((PlayerState*)inner)->characterId == 0 ? SFXTRIG_foxcom_var : SFXTRIG_sa_def));
        }
        break;
    case 2:
        if (((GameObject*)obj)->anim.localPosY >= diff)
        {
            gPlayerCurrentMoveId = 3;
            blend = lbl_803E800C;
            ((GameObject*)obj)->anim.velocityY = z;
            ((GameObject*)obj)->anim.localPosX = ((PlayerState*)inner)->moveEnd2X;
            ((GameObject*)obj)->anim.localPosY = diff;
            ((GameObject*)obj)->anim.localPosZ = ((PlayerState*)inner)->moveEnd2Z;
        }
        else
        {
            ((GameObject*)obj)->anim.velocityY = lbl_803E7E88 * fv + ((GameObject*)obj)->anim.velocityY;
            t = (((GameObject*)obj)->anim.localPosY - ((PlayerState*)inner)->moveStartY) /
                (diff - ((PlayerState*)inner)->moveStartY);
            ((GameObject*)obj)->anim.localPosX =
                t * (((PlayerState*)inner)->moveEnd2X - ((PlayerState*)inner)->moveStartX) +
                ((PlayerState*)inner)->moveStartX;
            ((GameObject*)obj)->anim.localPosZ =
                t * (((PlayerState*)inner)->moveEnd2Z - ((PlayerState*)inner)->moveStartZ) +
                ((PlayerState*)inner)->moveStartZ;
        }
        break;
    case 3:
        ((PlayerState*)inner)->moveStartX = ((GameObject*)obj)->anim.localPosX;
        ((PlayerState*)inner)->moveStartY = ((GameObject*)obj)->anim.localPosY;
        ((PlayerState*)inner)->moveStartZ = ((GameObject*)obj)->anim.localPosZ;
        if (((GameObject*)obj)->anim.currentMoveProgress > lbl_803E7F48)
        {
            if (((PlayerState*)state)->baddie.moveInputZ > lbl_803E7F10)
            {
                gPlayerCurrentMoveId = 5;
                blend = lbl_803E8024;
                Sfx_PlayFromObject(obj,
                                   (u16)(((PlayerState*)inner)->characterId == 0 ? SFXTRIG_jump3 : SFXTRIG_sabrepush));
                if (((PlayerState*)inner)->unk608 == 5)
                {
                    Sfx_PlayFromObject(obj, SFXTRIG_fox_swimstroke222);
                }
            }
            else if (((PlayerState*)state)->baddie.moveInputZ < lbl_803E801C)
            {
                ((PlayerState*)inner)->launchYaw = *(s16*)obj;
                gPlayerCurrentMoveId = 7;
                blend = lbl_803E8034;
                ((GameObject*)obj)->anim.velocityY = z;
            }
            else if (*(s8*)&((PlayerState*)state)->baddie.moveDone != 0)
            {
                gPlayerCurrentMoveId = 6;
                blend = lbl_803E8038;
            }
        }
        break;
    case 6:
        ((PlayerState*)inner)->moveStartX = ((GameObject*)obj)->anim.localPosX;
        ((PlayerState*)inner)->moveStartY = ((GameObject*)obj)->anim.localPosY;
        ((PlayerState*)inner)->moveStartZ = ((GameObject*)obj)->anim.localPosZ;
        if (((PlayerState*)state)->baddie.moveInputZ > lbl_803E7F10)
        {
            gPlayerCurrentMoveId = 5;
            blend = lbl_803E8024;
            Sfx_PlayFromObject(obj, (u16)(((PlayerState*)inner)->characterId == 0 ? SFXTRIG_jump3 : SFXTRIG_sabrepush));
            if (((PlayerState*)inner)->unk608 == 5)
            {
                Sfx_PlayFromObject(obj, SFXTRIG_fox_swimstroke222);
            }
        }
        else if (((PlayerState*)state)->baddie.moveInputZ < lbl_803E801C)
        {
            ((PlayerState*)inner)->launchYaw = *(s16*)obj;
            gPlayerCurrentMoveId = 7;
            blend = lbl_803E8034;
            ((GameObject*)obj)->anim.velocityY = z;
        }
        break;
    case 7:
    {
        f32 y2 =
            ((PlayerState*)inner)->launchDirZ * (lbl_803E7E98 + lbl_803DC6C0) + ((PlayerState*)inner)->launchAnchorZ;
        s16 ang;
        ((GameObject*)obj)->anim.localPosX = ((GameObject*)obj)->anim.currentMoveProgress *
                                                 ((((PlayerState*)inner)->launchDirX * (lbl_803E7E98 + lbl_803DC6C0) +
                                                   ((PlayerState*)inner)->launchAnchorX) -
                                                  ((PlayerState*)inner)->moveStartX) +
                                             ((PlayerState*)inner)->moveStartX;
        ((GameObject*)obj)->anim.localPosZ =
            ((GameObject*)obj)->anim.currentMoveProgress * (y2 - ((PlayerState*)inner)->moveStartZ) +
            ((PlayerState*)inner)->moveStartZ;
        ((GameObject*)obj)->anim.velocityY = -(lbl_803E7F6C * timeDelta - ((GameObject*)obj)->anim.velocityY);
        ang = -(lbl_803E7F98 * ((GameObject*)obj)->anim.currentMoveProgress - (f32)((PlayerState*)inner)->launchYaw);
        ((PlayerState*)inner)->yaw = ang;
        ((PlayerState*)inner)->targetYaw = ang;
        if (*(s8*)&((PlayerState*)state)->baddie.moveDone != 0)
        {
            ((PlayerState*)state)->baddie.animSpeedC = z;
            ((PlayerState*)state)->baddie.animSpeedA = z;
            ((PlayerState*)state)->baddie.animSpeedB = z;
            ((GameObject*)obj)->anim.velocityX = z;
            ((GameObject*)obj)->anim.velocityZ = z;
            *(u32*)((char*)state + 4) &= ~0x100000;
            fn_802AB5A4((GameObject*)obj, inner, 5);
            ((ByteFlags*)((char*)inner + 0x3f0))->b80 = 0;
            ((ByteFlags*)((char*)inner + 0x3f0))->b10 = 0;
            ((ByteFlags*)((char*)inner + 0x3f0))->b08 = 0;
            staffFn_80170380(gPlayerStaffObject, 2);
            ((ByteFlags*)((char*)inner + 0x3f0))->b02 = 0;
            *(u32*)&((PlayerState*)inner)->flags360 |= PLAYER_FLAG_TELEPORTED;
            ObjHits_SyncObjectPositionIfDirtyLegacy(obj);
            ((ByteFlags*)((char*)inner + 0x3f0))->b40 = 0;
            ((ByteFlags*)((char*)inner + 0x3f0))->b04 = 1;
            ((ByteFlags*)((char*)inner + 0x3f4))->b10 = 1;
            ((PlayerState*)inner)->isHoldingObject = 0;
            if (*(void**)((char*)inner + 0x7f8) != NULL)
            {
                s16 typ = ((GameObject*)((PlayerState*)inner)->heldObj)->anim.seqId;
                if (typ == 0x3cf || typ == 0x662)
                {
                    objThrowFn_80182504((GameObject*)(((PlayerState*)inner)->heldObj));
                }
                else
                {
                    objSaveFn_800ea774((GameObject*)((PlayerState*)inner)->heldObj);
                }
                *(s16*)((char*)((PlayerState*)inner)->heldObj + 0x6) =
                    *(s16*)((char*)((PlayerState*)inner)->heldObj + 0x6) & ~0x4000;
                *(int*)((char*)((PlayerState*)inner)->heldObj + 0xf8) = 0;
                ((PlayerState*)inner)->heldObj = 0;
            }
            *(int*)&((PlayerState*)state)->baddie.unk308 = (int)fn_802A514C;
            return 3;
        }
        break;
    }
    case 5:
        t = ((GameObject*)obj)->anim.currentMoveProgress / lbl_803E7F68;
        z = (t < z) ? z : ((t > lbl_803E7EE0) ? lbl_803E7EE0 : t);
        ((GameObject*)obj)->anim.localPosX = z * (((PlayerState*)inner)->moveEndX - ((PlayerState*)inner)->moveStartX) +
                                             ((PlayerState*)inner)->moveStartX;
        ((GameObject*)obj)->anim.localPosY = z * (((PlayerState*)inner)->moveEndY - ((PlayerState*)inner)->moveStartY) +
                                             ((PlayerState*)inner)->moveStartY;
        ((GameObject*)obj)->anim.localPosZ = z * (((PlayerState*)inner)->moveEndZ - ((PlayerState*)inner)->moveStartZ) +
                                             ((PlayerState*)inner)->moveStartZ;
        if (((GameObject*)obj)->anim.currentMoveProgress > lbl_803E7F68)
        {
            *(u32*)((char*)state + 4) &= ~0x100000;
            fn_802AB5A4((GameObject*)obj, inner, 5);
            *(u32*)&((PlayerState*)inner)->flags360 |= PLAYER_FLAG_TELEPORTED;
            *(int*)&((PlayerState*)state)->baddie.unk308 = (int)fn_802A514C;
            return 2;
        }
        break;
    default:
        gPlayerCurrentMoveId = 0;
        gPlayerPrevMoveId = 0;
        ((PlayerState*)state)->baddie.moveSpeed = lbl_803E803C;
        ObjAnim_SetCurrentMove(obj, lbl_80332EF0[gPlayerCurrentMoveId], lbl_803E7EA4, 0);
        ObjAnim_SetCurrentEventStepFrames((ObjAnimComponent*)obj, 10);
        {
            s16 ang = getAngle(((PlayerState*)inner)->launchDirX, ((PlayerState*)inner)->launchDirZ);
            ((PlayerState*)inner)->yaw = ang;
            ((PlayerState*)inner)->targetYaw = ang;
        }
        ((GameObject*)obj)->anim.velocityY = lbl_803E7EA4;
        ((void (*)(f32, f32, f32, void*, void*, void*, int))Obj_TransformWorldPointToLocal)(
            ((GameObject*)obj)->anim.worldPosX, ((GameObject*)obj)->anim.worldPosY, ((GameObject*)obj)->anim.worldPosZ,
            (void*)(obj + 0xc), (void*)(obj + 0x10), (void*)(obj + 0x14), *(int*)&((GameObject*)obj)->anim.parent);
        objHitDetectFn_80062e84((GameObject*)obj, ((PlayerState*)inner)->groundObject, 1);
        ((PlayerState*)inner)->moveStartX = ((GameObject*)obj)->anim.localPosX;
        ((PlayerState*)inner)->moveStartY = ((GameObject*)obj)->anim.localPosY;
        ((PlayerState*)inner)->moveStartZ = ((GameObject*)obj)->anim.localPosZ;
        {
            char* xf = *(char**)((char*)inner + 0x4c4);
            if (xf != NULL)
            {
                ((void (*)(f32, f32, f32, void*, void*, void*, char*))Obj_TransformWorldPointToLocal)(
                    ((PlayerState*)inner)->launchAnchorX, ((PlayerState*)inner)->launchAnchorY,
                    ((PlayerState*)inner)->launchAnchorZ, (void*)(inner + 0x5d4), (void*)(inner + 0x5d8),
                    (void*)(inner + 0x5dc), xf);
                ((void (*)(f32, f32, f32, void*, void*, void*, int))Obj_TransformWorldPointToLocal)(
                    ((PlayerState*)inner)->moveEndX, ((PlayerState*)inner)->moveEndY, ((PlayerState*)inner)->moveEndZ,
                    (void*)(inner + 0x5ec), (void*)(inner + 0x5f0), (void*)(inner + 0x5f4),
                    (int)((PlayerState*)inner)->groundObject);
                ((void (*)(f32, f32, f32, void*, void*, void*, int))Obj_TransformWorldPointToLocal)(
                    ((PlayerState*)inner)->moveEnd2X, ((PlayerState*)inner)->moveEnd2Y,
                    ((PlayerState*)inner)->moveEnd2Z, (void*)(inner + 0x5f8), (void*)(inner + 0x5fc),
                    (void*)(inner + 0x600), (int)((PlayerState*)inner)->groundObject);
                ((PlayerState*)inner)->leapTargetY =
                    ((PlayerState*)inner)->leapTargetY - ((PlayerState*)inner)->groundObject->anim.localPosY;
                ((PlayerState*)inner)->leapBaseY =
                    ((PlayerState*)inner)->leapBaseY - ((PlayerState*)inner)->groundObject->anim.localPosY;
                ((PlayerState*)inner)->unk609 = 0;
            }
        }
        break;
    }
    if (gPlayerPrevMoveId != gPlayerCurrentMoveId)
    {
        ObjAnim_SetCurrentMove(obj, lbl_80332EF0[gPlayerCurrentMoveId], lbl_803E7EA4, 0);
        ((PlayerState*)state)->baddie.moveSpeed = blend;
    }
    fn_802AB5A4((GameObject*)obj, inner, 5);
    return 0;
}

int playerState0B(GameObject* obj, int state)
{
    PlayerState* inner = obj->extra;
    f32 fz;
    *(u32*)&((PlayerState*)inner)->flags360 &= ~PLAYER_FLAG_HITDETECT;
    *(u32*)&((PlayerState*)inner)->flags360 |= PLAYER_FLAG_NO_POS_VELOCITY;
    *(int*)((char*)state + 4) |= 0x100000;
    fz = lbl_803E7EA4;
    ((PlayerState*)state)->baddie.animSpeedA = fz;
    ((PlayerState*)state)->baddie.animSpeedB = fz;
    *(int*)((char*)state + 0) |= 0x200000;
    obj->anim.velocityX = fz;
    obj->anim.velocityZ = fz;
    *(int*)((char*)state + 4) |= 0x8000000;
    obj->anim.velocityY = fz;
    *(int*)((char*)state + 0) |= 0x200000;
    switch (gPlayerCurrentMoveId)
    {
    case 0x12:
    case 0x1a:
        if (*(int*)&((PlayerState*)state)->baddie.eventFlags & 1)
        {
            Sfx_PlayFromObject((int)obj, (u16)(inner->characterId == 0 ? SFXTRIG_jump3 : SFXTRIG_sabrepush));
        }
        if ((((u32)inner->flags3F0 >> 5) & 1) || gPlayerCurrentMoveId == 0x1a)
        {
            if (*(int*)&((PlayerState*)state)->baddie.eventFlags & 0x80)
            {
                Sfx_PlayFromObject((int)obj, SFXTRIG_fox_swimstroke222);
            }
        }
    case 0xe:
    case 0x16:
        if (*(s8*)&((PlayerState*)state)->baddie.moveDone != 0)
        {
            *(int*)((char*)state + 4) &= ~0x100000;
            fn_802AB5A4(obj, (int)inner, 5);
            *(u32*)&((PlayerState*)inner)->flags360 |= PLAYER_FLAG_TELEPORTED;
            *(int*)&((PlayerState*)state)->baddie.unk308 = (int)fn_802A514C;
            return 2;
        }
        break;
    default:
    {
        f32 lo;
        f32 hi;
        f32 t;
        f32 r;
        f32 v;
        if (inner->unk606 == 0x10)
        {
            gPlayerCurrentMoveId = 0x1a;
            lo = lbl_803E8040;
            hi = lbl_803E8044;
            ((PlayerState*)state)->baddie.moveSpeed = lbl_803E7F28;
        }
        else if ((v = inner->leapSpeed) >= lbl_803E8040)
        {
            gPlayerCurrentMoveId = 0xe;
            lo = lbl_803E8040;
            hi = lbl_803E7F30;
            ((PlayerState*)state)->baddie.moveSpeed = lbl_803E7F0C;
        }
        else if (v >= *(f32*)&lbl_803E8048)
        {
            gPlayerCurrentMoveId = 0x16;
            lo = lbl_803E8048;
            hi = lbl_803E8040;
            ((PlayerState*)state)->baddie.moveSpeed = lbl_803E804C;
        }
        else
        {
            gPlayerCurrentMoveId = 0x12;
            lo = lbl_803E8018;
            hi = lbl_803E8048;
            ((PlayerState*)state)->baddie.moveSpeed = lbl_803E804C;
        }
        t = (inner->leapSpeed - lo) / (hi - lo);
        t = t * lbl_803E7FAC;
        r = (t < lbl_803E7EA4) ? lbl_803E7EA4 : ((t > lbl_803E7FAC) ? lbl_803E7FAC : t);
        inner->secondaryBlendAmount = (s16)r;
        ObjAnim_SetCurrentMove((int)obj, lbl_80332EF0[gPlayerCurrentMoveId], lbl_803E7EA4, 0);
        ObjAnim_SetCurrentEventStepFrames((ObjAnimComponent*)obj, 0xa);
        inner->targetYaw = inner->yaw = (s16)getAngle(inner->launchDirX, inner->launchDirZ);
        Obj_TransformWorldPointToLocal(obj->anim.worldPosX, obj->anim.worldPosY,
                                       obj->anim.worldPosZ, (f32*)((char*)obj + 0xc),
                                       (f32*)((char*)obj + 0x10), (f32*)((char*)obj + 0x14),
                                       *(int*)&obj->anim.parent);
        objHitDetectFn_80062e84(obj, inner->groundObject, 1);
        inner->moveStartX = obj->anim.localPosX;
        inner->moveStartY = obj->anim.localPosY;
        inner->moveStartZ = obj->anim.localPosZ;
        if (*(void**)((char*)inner + 0x4c4) != NULL)
        {
            Obj_TransformWorldPointToLocal(*(f32*)((int)inner + 0x5d4), *(f32*)((int)inner + 0x5d8),
                                           *(f32*)((int)inner + 0x5dc), (f32*)((char*)inner + 0x5d4),
                                           (f32*)((char*)inner + 0x5d8), (f32*)((char*)inner + 0x5dc),
                                           (u32)inner->groundObject);
            Obj_TransformWorldPointToLocal(*(f32*)((int)inner + 0x5ec), *(f32*)((int)inner + 0x5f0),
                                           *(f32*)((int)inner + 0x5f4), (f32*)((char*)inner + 0x5ec),
                                           (f32*)((char*)inner + 0x5f0), (f32*)((char*)inner + 0x5f4),
                                           (u32)inner->groundObject);
            Obj_TransformWorldPointToLocal(*(f32*)((int)inner + 0x5f8), *(f32*)((int)inner + 0x5fc),
                                           *(f32*)((int)inner + 0x600), (f32*)((char*)inner + 0x5f8),
                                           (f32*)((char*)inner + 0x5fc), (f32*)((char*)inner + 0x600),
                                           (u32)inner->groundObject);
            inner->leapTargetY = inner->leapTargetY - inner->groundObject->anim.localPosY;
            inner->leapBaseY = inner->leapBaseY - inner->groundObject->anim.localPosY;
            inner->unk609 = 0;
        }
        break;
    }
    }
    obj->anim.localPosX =
        obj->anim.currentMoveProgress * (((PlayerState*)inner)->moveEndX - inner->moveStartX) +
        inner->moveStartX;
    obj->anim.localPosY =
        obj->anim.currentMoveProgress * (((PlayerState*)inner)->moveEndY - inner->moveStartY) +
        inner->moveStartY;
    obj->anim.localPosZ =
        obj->anim.currentMoveProgress * (((PlayerState*)inner)->moveEndZ - inner->moveStartZ) +
        inner->moveStartZ;
    Object_ObjAnimSetSecondaryBlendMove((ObjAnimComponent*)obj, lbl_80332EF0[gPlayerCurrentMoveId + 2],
                                        inner->secondaryBlendAmount);
    fn_802AB5A4(obj, (int)inner, 5);
    return 0;
}


int playerStateGrabLedge(GameObject* obj, int state)
{
    int inner = *(int*)&obj->extra;
    f32 fz;
    if (*(s8*)&((PlayerState*)state)->baddie.moveJustStartedA != 0)
    {
        void* sub;
        Sfx_PlayFromObject((int)obj,
                           (u16)(((PlayerState*)inner)->characterId == 0 ? SFXTRIG_foxcom_heel : SFXTRIG_sa_def01));
        *(s16*)((char*)state + 0x278) = 0xa;
        ((PlayerState*)inner)->stateHandler = 0;
        ((PlayerState*)inner)->isHoldingObject = 0;
        sub = *(void**)((char*)inner + 0x7f8);
        if (sub != NULL)
        {
            s16 id = ((GameObject*)sub)->anim.seqId;
            if (id == 0x3cf || id == 0x662)
            {
                objThrowFn_80182504((GameObject*)sub);
            }
            else
            {
                objSaveFn_800ea774((GameObject*)sub);
            }
            *(s16*)((char*)((PlayerState*)inner)->heldObj + 0x6) &= ~0x4000;
            *(int*)((char*)((PlayerState*)inner)->heldObj + 0xf8) = 0;
            ((PlayerState*)inner)->heldObj = 0;
        }
    }
    fz = lbl_803E7EA4;
    ((PlayerState*)inner)->probeHitDist = fz;
    {
        int e = *(int*)&obj->extra;
        *(u32*)((char*)e + 0x360) &= ~2LL;
        *(u32*)((char*)e + 0x360) |= 0x2000LL;
    }
    *(int*)((char*)state + 4) |= 0x100000;
    ((PlayerState*)state)->baddie.animSpeedA = fz;
    ((PlayerState*)state)->baddie.animSpeedB = fz;
    *(int*)((char*)state + 0) |= 0x200000;
    obj->anim.velocityX = fz;
    obj->anim.velocityZ = fz;
    *(int*)((char*)state + 4) |= 0x8000000;
    obj->anim.velocityY = fz;
    switch (obj->anim.currentMove)
    {
    case 0xd:
    case 0x22:
    {
        f32 c;
        f32 d = obj->anim.currentMoveProgress / lbl_803E7F44;
        c = (d < lbl_803E7EA4) ? lbl_803E7EA4 : ((d > lbl_803E7EE0) ? lbl_803E7EE0 : d);
        obj->anim.localPosX =
            c * (((PlayerState*)inner)->moveEnd2X - ((PlayerState*)inner)->moveStartX) +
            ((PlayerState*)inner)->moveStartX;
        obj->anim.localPosY =
            ((PlayerState*)inner)->moveStartY -
            obj->anim.currentMoveProgress *
                (((PlayerState*)inner)->moveStartY -
                 (((PlayerState*)inner)->leapTargetY - ((PlayerState*)inner)->characterHeightOffset));
        obj->anim.localPosZ =
            c * (((PlayerState*)inner)->moveEnd2Z - ((PlayerState*)inner)->moveStartZ) +
            ((PlayerState*)inner)->moveStartZ;
        if (*(s8*)&((PlayerState*)state)->baddie.moveDone != 0)
        {
            ObjAnim_SetCurrentMove((int)obj, lbl_80332EF0[6], lbl_803E7EA4, 0);
            ((PlayerState*)state)->baddie.moveSpeed = lbl_803E8038;
            gPlayerCurrentMoveId = 6;
            fn_802AB5A4(obj, inner + 4, 5);
            *(int*)&((PlayerState*)state)->baddie.unk308 = 0;
            return 0xd;
        }
        break;
    }
    default:
    {
        int m;
        int d = (u16)getAngle(((PlayerState*)inner)->launchDirX, ((PlayerState*)inner)->launchDirZ) -
                ((PlayerState*)inner)->targetYaw;
        if (d > 0x8000)
        {
            d -= 0xffff;
        }
        if (d < -0x8000)
        {
            d += 0xffff;
        }
        m = ((PlayerState*)inner)->unk607 == 1 ? 0xb : 0xa;
        ((PlayerState*)inner)->targetYaw += d;
        ((PlayerState*)inner)->yaw = ((PlayerState*)inner)->targetYaw;
        Obj_TransformWorldPointToLocal(obj->anim.worldPosX, obj->anim.worldPosY,
                                       obj->anim.worldPosZ, (f32*)((char*)obj + 0xc),
                                       (f32*)((char*)obj + 0x10), (f32*)((char*)obj + 0x14),
                                       *(int*)&obj->anim.parent);
        objHitDetectFn_80062e84(obj, ((PlayerState*)inner)->groundObject, 1);
        ((PlayerState*)inner)->moveStartX = obj->anim.localPosX;
        ((PlayerState*)inner)->moveStartY = obj->anim.localPosY;
        ((PlayerState*)inner)->moveStartZ = obj->anim.localPosZ;
        ObjAnim_SetCurrentMove((int)obj, lbl_80332EF0[m], lbl_803E7EA4, 4);
        ((PlayerState*)state)->baddie.moveSpeed = lbl_803E7F34;
        if (((PlayerState*)inner)->curAnimId != 0x48 && ((PlayerState*)inner)->curAnimId != 0x47)
        {
            struct
            {
                s16 a;
                u8 b;
                u8 c;
            } shk;
            shk.a = 0;
            shk.b = 0;
            shk.c = 1;
            (*gCameraInterface)->setMode(0x43, 1, 0, 4, &shk, 0, 0xff);
        }
        if (*(void**)((char*)inner + 0x4c4) != NULL)
        {
            Obj_TransformWorldPointToLocal(*(f32*)((int)inner + 0x5d4), *(f32*)((int)inner + 0x5d8),
                                           *(f32*)((int)inner + 0x5dc), (f32*)((char*)inner + 0x5d4),
                                           (f32*)((char*)inner + 0x5d8), (f32*)((char*)inner + 0x5dc),
                                           (u32)((PlayerState*)inner)->groundObject);
            Obj_TransformWorldPointToLocal(*(f32*)((int)inner + 0x5ec), *(f32*)((int)inner + 0x5f0),
                                           *(f32*)((int)inner + 0x5f4), (f32*)((char*)inner + 0x5ec),
                                           (f32*)((char*)inner + 0x5f0), (f32*)((char*)inner + 0x5f4),
                                           (u32)((PlayerState*)inner)->groundObject);
            Obj_TransformWorldPointToLocal(*(f32*)((int)inner + 0x5f8), *(f32*)((int)inner + 0x5fc),
                                           *(f32*)((int)inner + 0x600), (f32*)((char*)inner + 0x5f8),
                                           (f32*)((char*)inner + 0x5fc), (f32*)((char*)inner + 0x600),
                                           (u32)((PlayerState*)inner)->groundObject);
            ((PlayerState*)inner)->leapTargetY =
                ((PlayerState*)inner)->leapTargetY - ((PlayerState*)inner)->groundObject->anim.localPosY;
            ((PlayerState*)inner)->leapBaseY =
                ((PlayerState*)inner)->leapBaseY - ((PlayerState*)inner)->groundObject->anim.localPosY;
            ((PlayerState*)inner)->unk609 = 0;
        }
        break;
    }
    }
    ((PlayerState*)inner)->cameraFlags |= 4;
    fn_802AB5A4(obj, inner + 4, 5);
    return 0;
}

int playerState09(GameObject* obj, int state)
{
    int inner = *(int*)&obj->extra;
    f32 fz;
    int flagsBase;
    if (*(s8*)&((PlayerState*)state)->baddie.moveJustStartedA != 0)
    {
        *(s16*)((char*)state + 0x278) = 9;
        ((PlayerState*)inner)->stateHandler = 0;
    }
    flagsBase = *(int*)&obj->extra;
    *(u32*)((char*)flagsBase + 0x360) &= ~2LL;
    *(u32*)((char*)flagsBase + 0x360) |= 0x2000LL;
    *(int*)((char*)state + 4) |= 0x100000;
    fz = lbl_803E7EA4;
    ((PlayerState*)state)->baddie.animSpeedA = fz;
    ((PlayerState*)state)->baddie.animSpeedB = fz;
    *(int*)((char*)state + 0) |= 0x200000;
    obj->anim.velocityX = fz;
    obj->anim.velocityZ = fz;
    *(int*)((char*)state + 4) |= 0x8000000;
    obj->anim.velocityY = fz;
    switch (obj->anim.currentMove)
    {
    case 0x419:
        if (*(s8*)&((PlayerState*)state)->baddie.moveDone != 0)
        {
            ObjAnim_SetCurrentMove((int)obj, lbl_80332EF0[6], fz, 0);
            gPlayerCurrentMoveId = 6;
            ((PlayerState*)state)->baddie.moveSpeed = lbl_803E8038;
            fn_802AB5A4(obj, inner + 4, 5);
            *(int*)&((PlayerState*)state)->baddie.unk308 = 0;
            return 0xd;
        }
        break;
    default:
    {
        f32 k;
        ObjAnim_SetCurrentMove((int)obj, 0x419, fz, 1);
        ((PlayerState*)state)->baddie.moveSpeed = lbl_803E7E90;
        ((PlayerState*)inner)->targetYaw =
            (s16)getAngle(((PlayerState*)inner)->launchDirX, ((PlayerState*)inner)->launchDirZ);
        ((PlayerState*)inner)->yaw = ((PlayerState*)inner)->targetYaw;
        k = lbl_803E7F10;
        obj->anim.worldPosX = k * ((PlayerState*)inner)->launchDirX + *(f32*)((int)inner + 0x5d4);
        obj->anim.worldPosY =
            ((PlayerState*)inner)->leapTargetY - ((PlayerState*)inner)->characterHeightOffset;
        obj->anim.worldPosZ = k * ((PlayerState*)inner)->launchDirZ + *(f32*)((int)inner + 0x5dc);
        Obj_TransformWorldPointToLocal(obj->anim.worldPosX, obj->anim.worldPosY,
                                       obj->anim.worldPosZ, &obj->anim.localPosX,
                                       &obj->anim.localPosY, &obj->anim.localPosZ,
                                       *(int*)&obj->anim.parent);
        objHitDetectFn_80062e84(obj, ((PlayerState*)inner)->groundObject, 1);
        if (*(void**)((char*)inner + 0x4c4) != NULL)
        {
            Obj_TransformWorldPointToLocal(*(f32*)((int)inner + 0x5d4), *(f32*)((int)inner + 0x5d8),
                                           *(f32*)((int)inner + 0x5dc), (f32*)((char*)inner + 0x5d4),
                                           (f32*)((char*)inner + 0x5d8), (f32*)((char*)inner + 0x5dc),
                                           (u32)((PlayerState*)inner)->groundObject);
            Obj_TransformWorldPointToLocal(*(f32*)((int)inner + 0x5ec), *(f32*)((int)inner + 0x5f0),
                                           *(f32*)((int)inner + 0x5f4), (f32*)((char*)inner + 0x5ec),
                                           (f32*)((char*)inner + 0x5f0), (f32*)((char*)inner + 0x5f4),
                                           (u32)((PlayerState*)inner)->groundObject);
            Obj_TransformWorldPointToLocal(*(f32*)((int)inner + 0x5f8), *(f32*)((int)inner + 0x5fc),
                                           *(f32*)((int)inner + 0x600), (f32*)((char*)inner + 0x5f8),
                                           (f32*)((char*)inner + 0x5fc), (f32*)((char*)inner + 0x600),
                                           (u32)((PlayerState*)inner)->groundObject);
            ((PlayerState*)inner)->leapTargetY =
                ((PlayerState*)inner)->leapTargetY - ((PlayerState*)inner)->groundObject->anim.localPosY;
            ((PlayerState*)inner)->leapBaseY =
                ((PlayerState*)inner)->leapBaseY - ((PlayerState*)inner)->groundObject->anim.localPosY;
            ((PlayerState*)inner)->unk609 = 0;
        }
        break;
    }
    }
    fn_802AB5A4(obj, inner + 4, 5);
    return 0;
}

#pragma opt_propagation off

extern f32 lbl_803E8054;

int playerState08(GameObject* obj, int state, f32 fv)
{
    PlayerState* inner = obj->extra;
    int c;
    int i;
    int* list;
    u8 buf[64];
    f32 dist;
    int cnt41;
    int cnt20;
    int cnt30;

    dist = lbl_803E8050;
    if (inner->curAnimId == 0x44)
    {
        goto ui_block;
    }
    if (*(void**)((char*)inner + 0x7f8) != NULL)
    {
        c = ((s8 (*)(int, int, int, void*, int))playerCheckIfClimbingOntoWall)((int)obj, (int)inner, state, buf, 0x22);
    }
    else
    {
        c = ((s8 (*)(int, int, int, void*, int))playerCheckIfClimbingOntoWall)((int)obj, (int)inner, state, buf, -0x141);
    }
    if ((s8)c == -1)
    {
        inner->climbProbeResult = -1;
        inner->climbProbeStableCount = 0;
    }
    else if ((s8)c == inner->climbProbeResult)
    {
        if (++inner->climbProbeStableCount > 200)
        {
            inner->climbProbeStableCount = 200;
        }
    }
    else
    {
        inner->climbProbeResult = c;
        inner->climbProbeStableCount = 0;
    }
    switch (inner->climbProbeResult)
    {
    case 0:
        if (((ByteFlags*)((char*)inner + 0x3f1))->b01)
        {
            *(int*)&((PlayerState*)state)->baddie.unk308 = (int)fn_8029FFD0;
            return 0xf;
        }
        goto deflt;
    case 9:
        if (((ByteFlags*)((char*)inner + 0x3f1))->b01)
        {
            *(int*)&((PlayerState*)state)->baddie.unk308 = (int)fn_8029FFD0;
            return 0x13;
        }
        goto deflt;
    case 4:
        gPlayerCurrentMoveId = -1;
        *(int*)&((PlayerState*)state)->baddie.unk308 = 0;
        return 0xd;
    case 5:
        if (*(void**)((char*)inner + 0x7f8) == NULL)
        {
            gPlayerCurrentMoveId = -1;
            *(int*)&((PlayerState*)state)->baddie.unk308 = 0;
            return 0xc;
        }
        goto deflt;
    case 6:
        *(int*)&((PlayerState*)state)->baddie.unk308 = (int)fn_8029DAE0;
        return -0x1d;
    case 0xd:
        *(int*)&((PlayerState*)state)->baddie.unk308 = 0;
        return 0x1d;
    case 7:
        fn_802AE9C8(obj, (int)inner, state);
        return 0;
    case 8:
        *(int*)&((PlayerState*)state)->baddie.unk308 = 0;
        return 0xb;
    case 0xb:
        *(int*)&((PlayerState*)state)->baddie.unk308 = (int)objUpdateHitboxPos;
        return 0x1c;
    case 10:
        *(int*)&((PlayerState*)state)->baddie.unk308 = 0;
        return 0x17;
    default:
    deflt:
        if (*(void**)((char*)inner + 0x7f8) == NULL && ((ByteFlags*)((char*)inner + 0x3f4))->b40)
        {
            list = (int*)ObjGroup_GetObjects(STAFFACTIVATED_OBJ_GROUP, &cnt41);
            for (i = 0; i < cnt41; i++)
            {
                int o = *list;
                gPlayerInteractTarget = (GameObject*)o;
                if ((*(u8*)((char*)o + 0xaf) & 4) != 0 && (*(u8*)((char*)o + 0xaf) & 0x10) == 0)
                {
                    switch ((u8)objGetByteParam1C(gPlayerInteractTarget))
                    {
                    case 2:
                        setAButtonIcon(2);
                        if ((*(int*)&((PlayerState*)state)->baddie.unk31C & 0x100) != 0)
                        {
                            buttonDisable(0, PAD_BUTTON_A);
                            *(int*)&((PlayerState*)state)->baddie.unk308 = (int)fn_80298924;
                            return 0x34;
                        }
                        break;
                    case 4:
                    case 5:
                        setAButtonIcon(0xe);
                        if ((*(int*)&((PlayerState*)state)->baddie.unk31C & 0x100) != 0)
                        {
                            buttonDisable(0, PAD_BUTTON_A);
                            *(int*)&((PlayerState*)state)->baddie.unk308 = (int)fn_80298924;
                            return 0x36;
                        }
                        break;
                    case 3:
                        setAButtonIcon(2);
                        if ((*(int*)&((PlayerState*)state)->baddie.unk31C & 0x100) != 0)
                        {
                            buttonDisable(0, PAD_BUTTON_A);
                            *(int*)&((PlayerState*)state)->baddie.unk308 = (int)fn_80298924;
                            return 0x35;
                        }
                        break;
                    case 0:
                        break;
                    }
                }
                list++;
            }
        }
    ui_block:
        ((void (*)(int, int*))ObjGroup_GetObjects)(BABYCLOUDRUNNER_OBJGROUP, &cnt20);
        mainSetBits(GAMEBIT_ITEM_Flute_Disabled, !cnt20);
        if ((*gGameUIInterface)->isCurrentTriggerClear() != 0)
        {
            if ((*gGameUIInterface)->isEventReady(0x1ee) != 0)
            {
                char* found;
                s16* def = NULL;
                buttonDisable(0, PAD_BUTTON_A);
                found = ((char* (*)(int, int, f32*))ObjGroup_FindNearestObject)(0xf, (int)obj, &dist);
                if (found != NULL)
                {
                    def = *(s16**)((char*)found + 0x4c);
                }
                if (def != NULL && *def == 0x860 && (*(u8*)((char*)found + 0xaf) & 4) != 0)
                {
                    mainSetBits(GAMEBIT_ITEM_DinoHorn_3F1, 1);
                    mainSetBits(GAMEBIT_ITEM_DinoHorn_3D8, 1);
                    mainSetBits(GAMEBIT_ITEM_DinoHorn_651, 1);
                }
                return 0;
            }
            if ((*gGameUIInterface)->isEventReady(0x953) != 0 && gPlayerChildObject == NULL)
            {
                GameObject* player;
                void* att;
                buttonDisable(0, PAD_BUTTON_A);
                if (gPlayerPathObject != NULL && ((ByteFlags*)((char*)inner + 0x3f4))->b40)
                {
                    inner->staffActionRequest = 1;
                    ((ByteFlags*)((char*)inner + 0x3f4))->b08 = 1;
                }
                player = Obj_GetPlayerObject();
                if (Obj_IsLoadingLocked() == 0)
                {
                    att = NULL;
                }
                else
                {
                    ObjPlacement* setup = Obj_AllocObjectSetup(0x24, 0x62d);
                    setup->objectId = 0x62d;
                    setup->color[0] = 2;
                    setup->color[2] = 0xff;
                    setup->color[1] = 1;
                    setup->color[3] = 0xff;
                    setup->posX = player->anim.localPosX;
                    setup->posY = player->anim.localPosY;
                    setup->posZ = player->anim.localPosZ;
                    att = Obj_SetupObject(setup, 4, player->anim.mapEventSlot, -1, player->anim.parent);
                    gPlayerChildObject = att;
                }
                ((void (*)(int, void*, int))ObjLink_AttachChild)((int)obj, att, 1);
                (*gObjectTriggerInterface)->runSequence(0xd, (void*)obj, -1);
            }
        }
        if (inner->curAnimId != 0x44 && (*gGameUIInterface)->isCurrentTriggerClear() != 0 &&
            (*gGameUIInterface)->isEventReady(0x13e) != 0 &&
            (((void (*)(int, int*))ObjGroup_GetObjects)(LANTERNFIREFLY_OBJGROUP, &cnt30), cnt30 == 0))
        {
            gameBitDecrement(0x13d);
            if (Obj_IsLoadingLocked() != 0)
            {
                ObjPlacement* setup = Obj_AllocObjectSetup(0x24, 0x43b);
                setup->objectId = 0x43b;
                setup->size = 9;
                setup->color[0] = 2;
                setup->color[2] = 0xff;
                setup->color[1] = 1;
                setup->color[3] = 0xff;
                setup->posX = obj->anim.localPosX;
                setup->posY = lbl_803E7F58 + obj->anim.localPosY;
                setup->posZ = obj->anim.localPosZ;
                *(u8*)((char*)setup + 0x19) = 1;
                Obj_SetupObject(setup, 5, -1, -1, obj->anim.parent);
            }
            (*(void (*)(void))(*(int*)((char*)*gGameUIInterface + 0x10)))();
            return 0;
        }
        {
            if (*(u8*)&((PlayerState*)inner)->staffGrown != 0)
            {
                int r2;
                if ((*(int*)&((PlayerState*)state)->baddie.unk31C & 0x200) != 0 && gPlayerPathObject != NULL &&
                    ((ByteFlags*)((char*)inner + 0x3f4))->b40)
                {
                    inner->staffActionRequest = 0;
                    ((ByteFlags*)((char*)inner + 0x3f4))->b08 = 0;
                }
                {
                    int in2 = *(int*)&obj->extra;
                    u8 b;
                    if ((*(int*)&((PlayerState*)state)->baddie.unk31C & 0x100) != 0 &&
                        (b = ((ByteFlags*)((char*)in2 + 0x3f4))->b40, b != 0))
                    {
                        if (gPlayerPathObject != NULL && b != 0)
                        {
                            *(u8*)((char*)in2 + 0x8b4) = 4;
                            ((ByteFlags*)((char*)in2 + 0x3f4))->b08 = 1;
                        }
                        *(int*)&((PlayerState*)state)->baddie.unk308 = 0;
                        r2 = 0x32;
                    }
                    else
                    {
                        r2 = 0;
                    }
                    if (r2 != 0)
                    {
                        return r2;
                    }
                }
            }
            else
            {
                if ((*(int*)&((PlayerState*)state)->baddie.unk31C & 0x100) != 0)
                {
                    int ok2;
                    if (*(void**)((char*)inner + 0x7f8) != NULL || !((ByteFlags*)((char*)inner + 0x3f4))->b40 ||
                        ((ByteFlags*)((char*)inner + 0x3f0))->b20 || ((ByteFlags*)((char*)inner + 0x3f0))->b10)
                    {
                        ok2 = 0;
                    }
                    else
                    {
                        ok2 = 1;
                    }
                    if (ok2 != 0)
                    {
                        if (((PlayerState*)inner)->staffActionRequest == 2 ||
                            (inner->cameraTargetObject != NULL && inner->targetObjectDist < lbl_803E8054 &&
                             inner->targetObjectBearingAbs < 0x4000 && ((PlayerState*)inner)->targetObjModelType == 1))
                        {
                            if (gPlayerPathObject != NULL && ((ByteFlags*)((char*)inner + 0x3f4))->b40)
                            {
                                inner->staffActionRequest = 4;
                                ((ByteFlags*)((char*)inner + 0x3f4))->b08 = 1;
                            }
                            *(int*)&((PlayerState*)state)->baddie.unk308 = 0;
                            return 0x32;
                        }
                        if (gPlayerPathObject != NULL && ((ByteFlags*)((char*)inner + 0x3f4))->b40)
                        {
                            inner->staffActionRequest = 2;
                            ((ByteFlags*)((char*)inner + 0x3f4))->b08 = 0;
                        }
                    }
                }
            }
            return 0;
        }
    }
}

#pragma opt_propagation reset

void fn_802A49A8(GameObject* obj)
{
    PlayerState* inner = obj->extra;
    inner->moveParams = (int)lbl_80333250;
    inner->moveAnimTable = (int)gPlayerMoveTableA;
}

int playerStateThrowing(GameObject* obj, int state)
{
    PlayerState* inner = obj->extra;
    f32 k;

    if (*(s8*)&((PlayerState*)state)->baddie.moveJustStartedA != 0)
    {
        if (*(void**)((char*)inner + 0x7f8) != NULL)
        {
            ObjHits_MarkObjectPositionDirty((ObjAnimComponent*)inner->heldObj);
        }
        ObjAnim_SetCurrentMove((int)obj, 0x443, lbl_803E7EAC, 0);
        *(s16*)((char*)state + 0x278) = 1;
        inner->stateHandler = (int)fn_802A514C;
    }
    k = lbl_803E7EA4;
    ((PlayerState*)state)->baddie.animSpeedC = k;
    ((PlayerState*)state)->baddie.animSpeedB = k;
    ((PlayerState*)state)->baddie.animSpeedA = k;
    obj->anim.velocityX = k;
    obj->anim.velocityY = k;
    obj->anim.velocityZ = k;
    ((PlayerState*)state)->baddie.moveSpeed = lbl_803E8058;

    if (*(int*)&((PlayerState*)state)->baddie.eventFlags & 1)
    {
        Sfx_PlayFromObject((int)obj, (u16)(inner->characterId == 0 ? SFXTRIG_foxcom_decoy : SFXTRIG_sa_jump02));
    }

    if (*(void**)((char*)inner + 0x7f8) == NULL && *(s8*)&((PlayerState*)state)->baddie.moveDone != 0)
    {
        *(int*)&((PlayerState*)state)->baddie.unk308 = (int)fn_802A514C;
        return 2;
    }
    if (*(void**)((char*)inner + 0x7f8) != NULL && obj->anim.currentMoveProgress > lbl_803E7E9C)
    {
        inner->isHoldingObject = 0;
        if (*(void**)((char*)inner + 0x7f8) != NULL)
        {
            GameObject* s2 = inner->heldObj;
            s16 id = s2->anim.seqId;
            if (id == 0x3cf || id == 0x662)
            {
                objThrowFn_80182504(s2);
            }
            else
            {
                objSaveFn_800ea774(s2);
            }
            *(s16*)((char*)inner->heldObj + 6) &= ~0x4000;
            *(int*)((char*)inner->heldObj + 0xf8) = 0;
            inner->heldObj = 0;
        }
    }
    return 0;
}

void fn_802A4B4C(GameObject* obj)
{
    PlayerState* inner = obj->extra;
    void* p = *(void**)((char*)inner + 0x7f8);
    if (p != NULL)
    {
        ((GameObject*)p)->unkF8 = 1;
    }
    *(u32*)&((PlayerState*)inner)->flags360 |= PLAYER_FLAG_TELEPORTED;
}

int playerState06(GameObject* obj, int state)
{
    PlayerState* inner = obj->extra;
    GameObject* sub;

    if (*(s8*)&((PlayerState*)state)->baddie.moveJustStartedA != 0)
    {
        ObjAnim_SetCurrentMove((int)obj, 0x447, lbl_803E7EA4, 0);
        *(s16*)((char*)state + 0x278) = 1;
        inner->stateHandler = (int)fn_802A514C;
    }
    if ((*(int*)&((PlayerState*)state)->baddie.eventFlags & 1) && (sub = inner->heldObj) != NULL)
    {
        switch (sub->anim.seqId)
        {
        case 0x6d:
        case 0x754:
            Sfx_PlayFromObject((int)obj, SFXTRIG_barrel_putdown_31f);
            break;
        case 0x1f4:
        case 0x1f5:
        case 0x1f6:
        case 0x1f7:
        case 0x1f8:
        case 0x1f9:
        case 0x519:
            Sfx_PlayFromObject((int)obj, SFXTRIG_weetinkoneshot);
            break;
        default:
            Sfx_PlayFromObject((int)obj, SFXTRIG_vineclimb116);
            break;
        }
    }
    ((PlayerState*)state)->baddie.animSpeedA = lbl_803E7EA4;
    ((PlayerState*)state)->baddie.moveSpeed = lbl_803E7F40;

    sub = inner->heldObj;
    if (sub == NULL && *(s8*)&((PlayerState*)state)->baddie.moveDone != 0)
    {
        *(u32*)&((PlayerState*)inner)->flags360 |= PLAYER_FLAG_TELEPORTED;
        *(int*)&((PlayerState*)state)->baddie.unk308 = (int)fn_802A514C;
        return 2;
    }
    if (sub != NULL && obj->anim.currentMoveProgress > lbl_803E7F48)
    {
        inner->isHoldingObject = 0;
        if (*(void**)((char*)inner + 0x7f8) != NULL)
        {
            GameObject* s2 = inner->heldObj;
            s16 id = s2->anim.seqId;
            if (id == 0x3cf || id == 0x662)
            {
                objThrowFn_80182504(s2);
            }
            else
            {
                objSaveFn_800ea774(s2);
            }
            *(s16*)((char*)inner->heldObj + 6) &= ~0x4000;
            *(int*)((char*)inner->heldObj + 0xf8) = 0;
            inner->heldObj = 0;
        }
    }
    return 0;
}

int playerState05(GameObject* obj, int state)
{
    PlayerState* inner = obj->extra;
    ((PlayerState*)state)->baddie.animSpeedB = lbl_803E7EA4;
    if (*(s8*)&((PlayerState*)state)->baddie.moveJustStartedA != 0)
    {
        if (gPlayerPathObject != NULL)
        {
            if (((ByteFlags*)((char*)inner + 0x3f4))->b40)
            {
                inner->staffActionRequest = 1;
                ((ByteFlags*)((char*)inner + 0x3f4))->b08 = 1;
            }
        }
        *(s16*)((char*)state + 0x278) = 1;
        inner->stateHandler = (int)fn_802A514C;
    }
    switch (obj->anim.currentMove)
    {
    case 5:
    {
        void* sub;
        ((PlayerState*)state)->baddie.moveSpeed = lbl_803E7F40;
        ((PlayerState*)state)->baddie.animSpeedA = lbl_803E7EA4;
        sub = *(void**)((char*)inner + 0x7f8);
        if (sub != NULL)
        {
            f32 amt;
            if (obj->anim.currentMoveProgress > lbl_803E7E98)
            {
                ((GameObject*)sub)->unkF8 = 1;
            }
            amt = interpolate((f32)inner->targetObjectBearing, lbl_803E805C, timeDelta);
            inner->targetYaw = (f32)inner->targetYaw + amt;
            inner->yaw = inner->targetYaw;
        }
        if (obj->anim.currentMoveProgress > lbl_803E7F2C)
        {
            inner->moveAnimTable = (int)lbl_80333110;
            ObjAnim_SetCurrentMove((int)obj, *(s16*)inner->moveAnimTable, lbl_803E7EA4, 0);
            *(u32*)&((PlayerState*)inner)->flags360 |= PLAYER_FLAG_TELEPORTED;
            *(int*)&((PlayerState*)state)->baddie.unk308 = (int)fn_802A514C;
            return 2;
        }
        break;
    }
    default:
    {
        void* sub = *(void**)((char*)inner + 0x7f8);
        if (sub != NULL && ((GameObject*)sub)->anim.seqId == 0x112)
        {
            inner->moveAnimTable = (int)lbl_80333110;
            *(int*)((char*)inner->heldObj + 0xf8) = 1;
            ObjAnim_SetCurrentMove((int)obj, *(s16*)inner->moveAnimTable, lbl_803E7EA4, 0);
            *(u32*)&((PlayerState*)inner)->flags360 |= PLAYER_FLAG_TELEPORTED;
            *(int*)&((PlayerState*)state)->baddie.unk308 = (int)fn_802A514C;
            return 2;
        }
        else
        {
            ObjAnim_SetCurrentMove((int)obj, 5, lbl_803E7EA4, 0);
        }
        break;
    }
    }
    if (*(int*)&((PlayerState*)state)->baddie.eventFlags & 1)
    {
        u16 snd;
        if (inner->characterId == 0)
        {
            snd = 0x320;
        }
        else
        {
            snd = 0x3c1;
        }
        Sfx_PlayFromObject((int)obj, snd);
    }
    return 0;
}

int playerState04(int obj, int state, f32 fv)
{
    if (*(s8*)&((PlayerState*)state)->baddie.moveJustStartedA != 0)
    {
        ObjAnim_SetCurrentMove(obj, 0x92, lbl_803E7EA4, 0);
        ((PlayerState*)state)->baddie.moveSpeed = lbl_803E8060;
    }
    (*(void (*)(int, int, f32, int))(*(int*)((char*)*gPlayerInterface + 0x20)))(obj, state, fv, 3);
    if (*(s8*)&((PlayerState*)state)->baddie.moveDone != 0)
    {
        *(int*)&((PlayerState*)state)->baddie.unk308 = (int)fn_802A514C;
        return 2;
    }
    return 0;
}

int playerStateIceSpell(int obj, int state, f32 fv)
{
    if (*(s8*)&((PlayerState*)state)->baddie.moveJustStartedA != 0)
    {
        ObjAnim_SetCurrentMove(obj, 0x8e, lbl_803E7EA4, 0);
        ((PlayerState*)state)->baddie.moveSpeed = lbl_803E8060;
    }
    (*(void (*)(int, int, f32, int))(*(int*)((char*)*gPlayerInterface + 0x20)))(obj, state, fv, 3);
    if (*(s8*)&((PlayerState*)state)->baddie.moveDone != 0)
    {
        void** p;
        int z[2];
        z[0] = 0;
        lbl_803DE42C = z[0];
        z[1] = z[0];
        p = gPlayerSpawnedObjects;
        for (; z[1] < 7; z[1]++)
        {
            if (p[z[1]] != NULL)
            {
                Obj_FreeObject((GameObject*)p[z[1]]);
                p[z[1]] = NULL;
            }
        }
        if (gPlayerResource != NULL)
        {
            Resource_Release(gPlayerResource);
            gPlayerResource = NULL;
        }
        showDeathMenu();
    }
    return 0;
}


void fn_802A514C(GameObject* obj, int state)
{
    PlayerState* inner = obj->extra;
    ((ByteFlags*)((char*)inner + 0x3f1))->b80 = 0;
    {
        s16 mode = ((PlayerState*)state)->baddie.controlMode;
        if (mode != 2 && mode != 1 && mode != 5 && mode != 7 && mode != 6)
        {
            void* sub;
            inner->isHoldingObject = 0;
            sub = *(void**)((char*)inner + 0x7f8);
            if (sub != NULL)
            {
                s16 id = ((GameObject*)sub)->anim.seqId;
                if (id == 0x3cf || id == 0x662)
                {
                    objThrowFn_80182504((GameObject*)sub);
                }
                else
                {
                    objSaveFn_800ea774((GameObject*)sub);
                }
                *(s16*)((char*)inner->heldObj + 0x6) &= ~0x4000;
                *(int*)((char*)inner->heldObj + 0xf8) = 0;
                inner->heldObj = 0;
            }
        }
    }
    {
        s16 mode = ((PlayerState*)state)->baddie.controlMode;
        if (mode != 2 && mode != 1)
        {
            ((ByteFlags*)((char*)inner + 0x3f0))->b10 = 0;
            ((ByteFlags*)((char*)inner + 0x3f0))->b80 = 0;
            ((ByteFlags*)((char*)inner + 0x3f0))->b40 = 0;
            ((ByteFlags*)((char*)inner + 0x3f0))->b08 = 0;
            ((ByteFlags*)((char*)inner + 0x3f0))->b04 = 0;
            inner->staffHoldFrames = 0;
            ((ByteFlags*)((char*)inner + 0x3f0))->b20 = 0;
            if (((ByteFlags*)((char*)inner + 0x3f1))->b20)
            {
                s16 t = obj->anim.rotX;
                inner->yaw = t;
                inner->targetYaw = t;
                inner->lastInputHeading = t;
                inner->baddie.animSpeedB = lbl_803E7EA4;
            }
            ((ByteFlags*)((char*)inner + 0x3f1))->b20 = 0;
            if (((ByteFlags*)((char*)inner + 0x3f1))->b10)
            {
                u8 anim = inner->curAnimId;
                if (anim != 0x48 && anim != 0x47 && getCurSeqNoInt() == 0)
                {
                    (*gCameraInterface)->setMode(0x42, 0, 1, 0, NULL, 0x1e, 0xff);
                    ((ByteFlags*)((char*)inner + 0x3f1))->b10 = 0;
                }
            }
            *(u32*)&((PlayerState*)inner)->flags360 &= ~0x2000000LL;
        }
    }
    if (((PlayerState*)state)->baddie.controlMode != 2)
    {
        staffFn_80170380(gPlayerStaffObject, 2);
        ((ByteFlags*)((char*)inner + 0x3f0))->b02 = 0;
        *(u32*)&((PlayerState*)inner)->flags360 |= PLAYER_FLAG_TELEPORTED;
        ObjHits_SyncObjectPositionIfDirtyLegacy(obj);
    }
    gPlayerSubState = 1;
}
#pragma opt_propagation off
int playerStateMoving(int obj, int state)
{
    int inner;
    int dir;
    f32 t;
    f32 spd;
    f32 ya;

    inner = *(int*)&((GameObject*)obj)->extra;
    ((ByteFlags*)((char*)inner + 0x3f1))->b02 = 0;
    ((ByteFlags*)((char*)inner + 0x3f1))->b04 = 0;
    ((ByteFlags*)((char*)inner + 0x3f1))->b08 = 0;
    ((ByteFlags*)((char*)inner + 0x3f2))->b10 = 0;
    if (*(s8*)&((PlayerState*)state)->baddie.moveJustStartedA != 0)
    {
        *(u32*)&((PlayerState*)inner)->flags360 |= 0x2000000LL;
        ((ByteFlags*)((char*)inner + 0x3f0))->b80 = 0;
        ((ByteFlags*)((char*)inner + 0x3f0))->b40 = 0;
        ((ByteFlags*)((char*)inner + 0x3f3))->b40 = 0;
        *(u8*)&((PlayerState*)inner)->gaitLevel = 0;
        ((PlayerState*)inner)->unk81E = 0;
        ((ByteFlags*)((char*)inner + 0x3f2))->b10 = 1;
    }
    {
        int r = ((int (*)(int, int, int))fn_802AC7DC)(obj, state, inner);
        if (r != 0)
        {
            return r;
        }
    }
    playerSetMovingAnims(obj, inner);
    {
        u32 fl = *(u8*)((char*)inner + 0x3f0);
        if ((fl >> 5 & 1) != 0)
        {
            *(u32*)state |= 0x200000;
            *(u32*)&((PlayerState*)inner)->flags360 |= PLAYER_FLAG_NO_POS_VELOCITY;
            *(u32*)&((PlayerState*)inner)->flags360 |= 0x2000000LL;
            *(s16*)((char*)state + 0x278) = 2;
            ((PlayerState*)inner)->stateHandler = (int)fn_802A514C;
            if (((u32) * (u8*)((char*)inner + 0x3f1) >> 5 & 1) != 0)
            {
                ((PlayerState*)inner)->maxSpeed = lbl_803E7F2C;
            }
            else
            {
                ((PlayerState*)inner)->maxSpeed = lbl_803E8064;
            }
        }
        else if (((u32) * (u8*)((char*)inner + 0x3f1) >> 5 & 1) != 0)
        {
            *(u32*)&((PlayerState*)inner)->flags360 |= 0x2000000LL;
            *(u32*)state |= 0x800000;
            *(s16*)((char*)state + 0x278) = 0;
            ((PlayerState*)inner)->maxSpeed = lbl_803E7ED4;
        }
        else if ((fl >> 3 & 1) != 0 || (fl >> 2 & 1) != 0)
        {
            *(u32*)state |= 0x200000;
            *(u32*)&((PlayerState*)inner)->flags360 |= 0x2000000LL;
            ((PlayerState*)inner)->maxSpeed = lbl_803E8068;
        }
        else
        {
            *(u32*)&((PlayerState*)inner)->flags360 |= 0x2000000LL;
            *(u32*)state |= 0x800000;
            *(s16*)((char*)state + 0x278) = 0;
            ((PlayerState*)inner)->maxSpeed = lbl_803E806C;
        }
    }
    if (*(s8*)&((PlayerState*)state)->baddie.moveJustStartedA != 0)
    {
        if (((u32) * (u8*)((char*)inner + 0x3f1) >> 5 & 1) == 0 && ((u32) * (u8*)((char*)inner + 0x3f0) >> 2 & 1) == 0)
        {
            ((PlayerState*)inner)->yaw = ((PlayerState*)inner)->yaw + ((PlayerState*)inner)->yawRate * 0xb6;
        }
        ((PlayerState*)inner)->yawRateSigned = 0;
        ((PlayerState*)inner)->yawRate = 0;
    }
    {
        t = ((((PlayerState*)state)->baddie.inputMagnitude - lbl_803E7F14) / lbl_803E7F2C < lbl_803E7EA4)
                ? lbl_803E7EA4
                : (((((PlayerState*)state)->baddie.inputMagnitude - lbl_803E7F14) / lbl_803E7F2C > lbl_803E7EE0)
                       ? lbl_803E7EE0
                       : (((PlayerState*)state)->baddie.inputMagnitude - lbl_803E7F14) / lbl_803E7F2C);
    }
    ((PlayerState*)inner)->currentSpeed =
        (((PlayerState*)inner)->maxSpeed - lbl_803E7F6C) * (t * ((PlayerState*)inner)->speedScale);
    {
        u32 fl = *(u8*)((char*)inner + 0x3f0);
        if ((fl >> 6 & 1) != 0)
        {
            *(u32*)&((PlayerState*)inner)->flags360 |= PLAYER_FLAG_HEADING_LOCK;
            ((PlayerState*)state)->baddie.moveSpeed = lbl_803E8070;
            {
                s16 cd = (s16)(lbl_803E7F98 * ((GameObject*)obj)->anim.currentMoveProgress +
                               (f32) * (int*)((char*)inner + 0x858));
                ((PlayerState*)inner)->targetYaw = cd;
                ((PlayerState*)inner)->lastInputHeading = cd;
            }
            if (*(s8*)&((PlayerState*)state)->baddie.moveDone != 0)
            {
                ((ByteFlags*)((char*)inner + 0x3f0))->b40 = 0;
                {
                    int a = ((PlayerState*)inner)->yaw;
                    ((PlayerState*)inner)->targetYaw = a;
                    ((PlayerState*)inner)->lastInputHeading = a;
                }
                *(u8*)&((PlayerState*)inner)->gaitLevel = 0xc;
                ((ByteFlags*)((char*)inner + 0x3f1))->b04 = 1;
                ((ByteFlags*)((char*)inner + 0x3f1))->b08 = 1;
            }
            ((PlayerState*)state)->baddie.animSpeedC =
                ((PlayerState*)inner)->unk844 * timeDelta + ((PlayerState*)state)->baddie.animSpeedC;
            ((PlayerState*)inner)->currentSpeed = lbl_803E7EA4;
            if (((GameObject*)obj)->anim.currentMoveProgress > lbl_803E7EFC &&
                ((GameObject*)obj)->anim.currentMoveProgress < lbl_803E8074)
            {
                ((PlayerState*)inner)->pendingFxFlags |= 8;
            }
        }
        else if ((fl >> 4 & 1) != 0)
        {
            fn_802AE650((GameObject*)obj, inner, state);
        }
        else if ((fl >> 7 & 1) != 0)
        {
            int r = fn_802AE480((GameObject*)obj, inner, state);
            if (r != 0)
            {
                *(int*)&((PlayerState*)state)->baddie.unk308 = (int)fn_802A514C;
                return 2;
            }
        }
        else if ((fl >> 1 & 1) != 0)
        {
            int leave;
            *(u32*)&((PlayerState*)inner)->flags360 |= PLAYER_FLAG_KNOCKBACK;
            {
                f32 z = 0.0f;
                ((PlayerState*)state)->baddie.animSpeedC = z;
                ((PlayerState*)state)->baddie.animSpeedC = z;
                ((PlayerState*)state)->baddie.animSpeedB = z;
                ((PlayerState*)state)->baddie.animSpeedA = z;
                ((GameObject*)obj)->anim.velocityX = z;
                ((GameObject*)obj)->anim.velocityY = z;
                ((GameObject*)obj)->anim.velocityZ = z;
                {
                    f32 w = 20.0f;
                    ((PlayerState*)inner)->targetYawSmoothRate = w;
                    ((PlayerState*)inner)->targetYawRateLimit = z;
                    ((PlayerState*)inner)->yawSmoothRate = w;
                    ((PlayerState*)inner)->yawRateLimit = z;
                    ((PlayerState*)inner)->currentSpeed = z;
                }
            }
            if ((getButtons_80014dd8(0) & 0x20) == 0)
            {
                goto sit;
            }
            {
                u32 fl2;
                int stay;
                if (((u32) * (u8*)((char*)inner + 0x3f4) >> 6 & 1) != 0 &&
                    ((fl2 = *(u8*)((char*)inner + 0x3f0)) >> 5 & 1) == 0 && (fl2 >> 3 & 1) == 0 &&
                    (fl2 >> 2 & 1) == 0 && ((PlayerState*)inner)->curAnimId != 0x44 &&
                    *(void**)((char*)inner + 0x7f8) == NULL && ((PlayerState*)inner)->baddie.targetObj == NULL &&
                    ((u32) * (u8*)((char*)inner + 0x3f6) >> 6 & 1) == 0 &&
                    ((PlayerState*)inner)->baddie.controlMode != 0x26 &&
                    (((GameObject*)obj)->objectFlags & OBJECT_OBJFLAG_PARENT_SLACK) == 0 &&
                    ((PlayerState*)inner)->idleDelayTimer == lbl_803E7EA4)
                {
                    stay = 1;
                }
                else
                {
                    stay = 0;
                }
                if (!stay)
                {
                sit:
                    if (gPlayerPathObject != 0 && ((u32) * (u8*)((char*)inner + 0x3f4) >> 6 & 1) != 0)
                    {
                        ((PlayerState*)inner)->staffActionRequest = 1;
                        ((ByteFlags*)((char*)inner + 0x3f4))->b08 = 1;
                    }
                    staffFn_80170380(gPlayerStaffObject, 2);
                    ((ByteFlags*)((char*)inner + 0x3f0))->b02 = 0;
                    *(u32*)&((PlayerState*)inner)->flags360 |= PLAYER_FLAG_TELEPORTED;
                    ObjHits_SyncObjectPositionIfDirtyLegacy(obj);
                    leave = 1;
                }
                else
                {
                    leave = 0;
                }
            }
            if (leave)
            {
                *(int*)&((PlayerState*)state)->baddie.unk308 = (int)fn_802A514C;
                return 2;
            }
        }
        else if ((fl >> 5 & 1) != 0)
        {
            fn_802ADE80((GameObject*)obj, inner, state);
        }
        else if ((fl >> 3 & 1) != 0)
        {
            fn_802ADC08((GameObject*)obj, inner, state);
        }
        else if ((fl >> 2 & 1) != 0)
        {
            int r = fn_802AD2F4((GameObject*)obj, inner, state);
            if (r != 0)
            {
                *(int*)&((PlayerState*)state)->baddie.unk308 = (int)fn_802A514C;
                return 2;
            }
        }
    }
    {
        int calm;
        {
            u32 fl = *(u8*)((char*)inner + 0x3f0);
            if ((fl >> 5 & 1) == 0 && (fl >> 6 & 1) == 0 && (fl >> 4 & 1) == 0 && (fl >> 2 & 1) == 0 &&
                (fl >> 3 & 1) == 0 && (fl >> 1 & 1) == 0 && *(void**)((char*)inner + 0x7f8) == NULL &&
                ((PlayerState*)inner)->curAnimId != 0x44)
            {
                calm = 1;
            }
            else
            {
                calm = 0;
            }
        }
        if (calm && (((PlayerState*)inner)->buttonsJustPressed & PAD_BUTTON_X) != 0)
        {
            fn_802AED2C((GameObject*)obj, inner, state);
        }
    }
    {
        int ok;
        {
            u32 fl = *(u8*)((char*)inner + 0x3f0);
            if ((fl >> 5 & 1) == 0 && (fl >> 6 & 1) == 0 && (fl >> 7 & 1) == 0 && (fl >> 4 & 1) == 0 &&
                (fl >> 2 & 1) == 0 && (fl >> 3 & 1) == 0 && ((u32) * (u8*)((char*)inner + 0x3f1) >> 5 & 1) == 0)
            {
                ok = 1;
            }
            else
            {
                ok = 0;
            }
        }
        if (ok && ((PlayerState*)state)->baddie.animSpeedC > lbl_803E7EAC + *(f32*)(((PlayerState*)inner)->moveParams + 0x14) &&
            (((PlayerState*)inner)->inputMagnitude < lbl_803E8030 || ((PlayerState*)inner)->yawRateSigned >= 0x96))
        {
            ((PlayerState*)inner)->pendingFxFlags |= 8;
            ((ByteFlags*)((char*)inner + 0x3f0))->b80 = 1;
            ((PlayerState*)inner)->animSoundId = ((PlayerState*)inner)->altAnimSoundId;
            *(u32*)&((PlayerState*)inner)->flags360 |= PLAYER_FLAG_HEADING_LOCK;
            ((PlayerState*)inner)->unk844 = ((PlayerState*)state)->baddie.animSpeedA;
            ObjAnim_SetCurrentMove(obj, *(s16*)(((PlayerState*)inner)->moveAnimTable + 0x3c), lbl_803E7EA4, 0);
        }
    }
    {
        u32 fl = *(u8*)((char*)inner + 0x3f0);
        if ((fl >> 7 & 1) == 0 && (fl >> 6 & 1) == 0 && ((u32) * (u8*)((char*)inner + 0x3f1) >> 5 & 1) == 0)
        {
            if (((PlayerState*)inner)->yawRateSigned < 0x96)
            {
                f32 d = interpolate((f32) * (int*)((char*)inner + 0x47c),
                                    lbl_803E7EE0 / ((PlayerState*)inner)->targetYawSmoothRate, timeDelta);
                {
                    f32 m =
                        timeDelta * (((PlayerState*)inner)->targetYawRateLimit * ((PlayerState*)inner)->leanCurveScale);
                    d = (d > m) ? m : d;
                }
                if (((PlayerState*)inner)->targetYawRate < 0)
                {
                    d = -d;
                }
                ((PlayerState*)inner)->targetYaw =
                    (s16)(gPlayerDegToBinAngle * d + (f32) * (s16*)((char*)inner + 0x478));
            }
            if (((PlayerState*)inner)->yawRateSigned < 0x96)
            {
                f32 d = interpolate((f32) * (int*)((char*)inner + 0x488), lbl_803E7EE0 / ((PlayerState*)inner)->yawSmoothRate,
                                    timeDelta);
                {
                    f32 m = ((PlayerState*)inner)->yawRateLimit * timeDelta;
                    d = (d > m) ? m : d;
                }
                if (((PlayerState*)inner)->yawRate < 0)
                {
                    d = -d;
                }
                ((PlayerState*)inner)->yaw = (s16)(gPlayerDegToBinAngle * d + (f32) * (s16*)((char*)inner + 0x484));
            }
            else
            {
                u32 fl3 = *(u8*)((char*)inner + 0x3f0);
                if ((fl3 >> 3 & 1) == 0 && (fl3 >> 2 & 1) == 0 && (fl3 >> 4 & 1) == 0 &&
                    ((PlayerState*)state)->baddie.animSpeedC <= *(f32*)(((PlayerState*)inner)->moveParams + 4) &&
                    ((PlayerState*)state)->baddie.animSpeedA <= *(f32*)(((PlayerState*)inner)->moveParams + 0xc))
                {
                    ((PlayerState*)inner)->yaw = ((PlayerState*)inner)->yaw + ((PlayerState*)inner)->yawRate * 0xb6;
                }
            }
        }
    }
    {
        u32 fl;
        u32 fl1 = ((PlayerState*)inner)->flags3F1;
        if ((fl1 >> 5 & 1) != 0)
        {
            spd = ((PlayerState*)inner)->maxSpeed *
                  (t * -mathSinf((gPlayerPi * (f32) * (int*)((char*)inner + 0x474)) / lbl_803E7F98));
            ya = ((PlayerState*)inner)->maxSpeed *
                 (t * -mathCosf((gPlayerPi * (f32) * (int*)((char*)inner + 0x474)) / lbl_803E7F98));
            t = interpolate(spd - ((PlayerState*)inner)->smoothVelX, ((PlayerState*)inner)->velSmoothRate, timeDelta);
            {
                f32 dy = interpolate(ya - ((PlayerState*)inner)->smoothVelZ, ((PlayerState*)inner)->velSmoothRate,
                                     timeDelta);
                ((PlayerState*)inner)->smoothVelX = ((PlayerState*)inner)->smoothVelX + t;
                ((PlayerState*)inner)->smoothVelZ = ((PlayerState*)inner)->smoothVelZ + dy;
            }
            ((PlayerState*)state)->baddie.animSpeedC =
                sqrtf(((PlayerState*)inner)->smoothVelX * ((PlayerState*)inner)->smoothVelX +
                      ((PlayerState*)inner)->smoothVelZ * ((PlayerState*)inner)->smoothVelZ);
            {
                ((PlayerState*)state)->baddie.animSpeedC =
                    (((PlayerState*)state)->baddie.animSpeedC < **(f32**)((char*)inner + 0x400))
                        ? **(f32**)((char*)inner + 0x400)
                        : ((((PlayerState*)state)->baddie.animSpeedC > ((PlayerState*)inner)->maxSpeed)
                               ? ((PlayerState*)inner)->maxSpeed
                               : ((PlayerState*)state)->baddie.animSpeedC);
            }
            t = mathSinf((gPlayerPi * (f32) * (s16*)((char*)inner + 0x478)) / lbl_803E7F98);
            {
                f32 sn = mathCosf((gPlayerPi * (f32) * (s16*)((char*)inner + 0x478)) / lbl_803E7F98);
                f32 nx = -((PlayerState*)inner)->smoothVelZ * sn - ((PlayerState*)inner)->smoothVelX * t;
                ya = ((PlayerState*)inner)->smoothVelX * sn - ((PlayerState*)inner)->smoothVelZ * t;
                ((PlayerState*)state)->baddie.animSpeedA =
                    ((PlayerState*)state)->baddie.animSpeedA +
                    interpolate(nx - ((PlayerState*)state)->baddie.animSpeedA, ((PlayerState*)inner)->targetAnimSpeed,
                                timeDelta);
                ((PlayerState*)state)->baddie.animSpeedB =
                    ((PlayerState*)state)->baddie.animSpeedB +
                    interpolate(ya - ((PlayerState*)state)->baddie.animSpeedB, ((PlayerState*)inner)->targetAnimSpeed,
                                timeDelta);
            }
            spd = ((PlayerState*)state)->baddie.animSpeedB;
            spd = (spd < lbl_803E7EA4) ? -spd : spd;
            t = ((PlayerState*)state)->baddie.animSpeedA;
            t = (t < *(f32*)&lbl_803E7EA4) ? -t : t;
            {
                int r = ((int (*)(int, f32, f32*))ObjAnim_SampleRootCurvePhase)(
                    obj, ((PlayerState*)state)->baddie.animSpeedC, (f32*)(state + 0x2a0));
                if (r == 0)
                {
                    ((PlayerState*)state)->baddie.moveSpeed = lbl_803E7F78;
                }
            }
            if (((u32) * (u8*)((char*)inner + 0x3f0) >> 5 & 1) != 0)
            {
                ((PlayerState*)state)->baddie.moveSpeed = ((PlayerState*)state)->baddie.moveSpeed * lbl_803E7E98;
            }
            if (t > spd)
            {
                if (((PlayerState*)state)->baddie.animSpeedA < lbl_803E7EA4)
                {
                    dir = 1;
                }
                else
                {
                    dir = 0;
                }
            }
            else if (((PlayerState*)state)->baddie.animSpeedB >= lbl_803E7EA4)
            {
                dir = 3;
            }
            else
            {
                dir = 2;
            }
        }
        else
        {
            fl = *(u8*)((char*)inner + 0x3f0);
            if ((fl >> 6 & 1) == 0 && (fl1 >> 2 & 1) == 0 && (fl >> 4 & 1) == 0 && (fl1 >> 1 & 1) == 0 &&
                (fl >> 3 & 1) == 0 && (fl >> 2 & 1) == 0 && (fl >> 1 & 1) == 0)
            {
                f32 d = interpolate(((PlayerState*)inner)->currentSpeed - ((PlayerState*)state)->baddie.animSpeedC,
                                    ((PlayerState*)inner)->velSmoothRate, timeDelta);
                d = (d < lbl_803E7EA8 * timeDelta) ? lbl_803E7EA8 * timeDelta : ((d > lbl_803E7EFC * timeDelta) ? lbl_803E7EFC * timeDelta : d);
                if (((PlayerState*)inner)->yawRateSigned >= 0x96 && d > lbl_803E7EA4)
                {
                    d = lbl_803E7ED4 * -d;
                }
                ((PlayerState*)state)->baddie.animSpeedC = ((PlayerState*)state)->baddie.animSpeedC + d;
                {
                    ((PlayerState*)state)->baddie.animSpeedC =
                        (((PlayerState*)state)->baddie.animSpeedC < **(f32**)((char*)inner + 0x400))
                            ? **(f32**)((char*)inner + 0x400)
                            : ((((PlayerState*)state)->baddie.animSpeedC > ((PlayerState*)inner)->maxSpeed)
                                   ? ((PlayerState*)inner)->maxSpeed
                                   : ((PlayerState*)state)->baddie.animSpeedC);
                }
                ((PlayerState*)state)->baddie.animSpeedB = lbl_803E7EA4;
            }
            else if (((ByteFlags*)((char*)inner + 0x3f0))->b08 != 0 ||
                     ((ByteFlags*)((char*)inner + 0x3f0))->b04 != 0)
            {
                t = ((PlayerState*)inner)->currentSpeed *
                    -mathSinf((gPlayerPi * (gPlayerDegToBinAngle * (f32) * (int*)((char*)inner + 0x48c))) / lbl_803E7F98);
                ya = ((PlayerState*)inner)->currentSpeed *
                     mathCosf((gPlayerPi * (gPlayerDegToBinAngle * (f32) * (int*)((char*)inner + 0x48c))) / lbl_803E7F98);
                if (((u32) * (u8*)((char*)inner + 0x3f0) >> 2 & 1) != 0)
                {
                    ((PlayerState*)state)->baddie.animSpeedC =
                        ((PlayerState*)state)->baddie.animSpeedC * powfBitEstimate(lbl_803E7F90, timeDelta);
                }
                else
                {
                    ((PlayerState*)state)->baddie.animSpeedC =
                        -(lbl_803E7F20 * timeDelta - ((PlayerState*)state)->baddie.animSpeedC);
                }
                {
                    f32 v2 = lbl_803E7E8C * ya;
                    f32 m = (v2 < lbl_803E8078) ? lbl_803E8078 : ((v2 > lbl_803E807C) ? lbl_803E807C : v2);
                    ((PlayerState*)state)->baddie.animSpeedC = m * timeDelta + ((PlayerState*)state)->baddie.animSpeedC;
                }
                {
                    f32 v = ((PlayerState*)state)->baddie.animSpeedC;
                    ((PlayerState*)state)->baddie.animSpeedC =
                        (v < lbl_803E8080)
                            ? lbl_803E8080
                            : ((v > lbl_803E7EFC + ((PlayerState*)inner)->maxSpeed) ? lbl_803E7EFC + ((PlayerState*)inner)->maxSpeed
                                                                            : v);
                }
                t = t * lbl_803E7F74;
                ((PlayerState*)state)->baddie.animSpeedB =
                    ((PlayerState*)state)->baddie.animSpeedB +
                    interpolate(t - ((PlayerState*)state)->baddie.animSpeedB, lbl_803E807C, timeDelta);
            }
            else
            {
                f32 lim;
                f32 v;
                v = ((PlayerState*)state)->baddie.animSpeedC;
                lim = ((PlayerState*)inner)->maxSpeed;
                ((PlayerState*)state)->baddie.animSpeedC = (v < -lim) ? -lim : ((v > lim) ? lim : v);
            }
            {
                if (((u32) * (u8*)((char*)inner + 0x3f0) >> 4 & 1) == 0 &&
                    ((u32) * (u8*)((char*)inner + 0x3f1) >> 1 & 1) == 0 &&
                    ((u32) * (u8*)((char*)inner + 0x3f0) >> 1 & 1) == 0)
                {
                    ((PlayerState*)state)->baddie.animSpeedA =
                        ((PlayerState*)state)->baddie.animSpeedA +
                        interpolate(((PlayerState*)state)->baddie.animSpeedC - ((PlayerState*)state)->baddie.animSpeedA,
                                    ((PlayerState*)inner)->targetAnimSpeed, timeDelta);
                }
            }
            dir = 0;
        }
    }
    {
        u32 fl = *(u8*)((char*)inner + 0x3f0);
        if ((fl >> 7 & 1) == 0 && (fl >> 6 & 1) == 0 && (fl >> 4 & 1) == 0 && (fl >> 2 & 1) == 0 &&
            (fl >> 3 & 1) == 0 && (fl >> 1 & 1) == 0)
        {
            int step;
            int locked;
            locked = 0;
            if (((u32) * (u8*)((char*)inner + 0x3f1) >> 3 & 1) != 0)
            {
                locked = 1;
                spd = lbl_803E7EA4;
            }
            else
            {
                spd = ((GameObject*)obj)->anim.currentMoveProgress;
            }
            step = ((PlayerState*)inner)->gaitLevel / 4 * 2;
            ((PlayerState*)inner)->gaitStepLevel = (step >> 1) + 1;
            if (((PlayerState*)inner)->gaitStepLevel > 4)
            {
                ((PlayerState*)inner)->gaitStepLevel = 4;
            }
            {
                u8 c;
                if (((PlayerState*)inner)->gaitStepLevel > 3)
                {
                    c = ((PlayerState*)inner)->runAnimSoundId;
                }
                else
                {
                    c = ((PlayerState*)inner)->walkAnimSoundId;
                }
                ((PlayerState*)inner)->animSoundId = c;
            }
            {
                f32 v = ((PlayerState*)state)->baddie.animSpeedC;
                f32* tb = (f32*)((PlayerState*)inner)->moveParams;
                if (v < tb[step])
                {
                    if (((PlayerState*)inner)->gaitLevel == 4)
                    {
                        if (((PlayerState*)state)->baddie.animSpeedA < tb[4] &&
                            ((PlayerState*)state)->baddie.inputMagnitude < lbl_803E7F14)
                        {
                            *(int*)&((PlayerState*)state)->baddie.unk308 = (int)fn_802A514C;
                            return 2;
                        }
                    }
                    else
                    {
                        *(u8*)&((PlayerState*)inner)->gaitLevel -= 4;
                    }
                }
                else if (v >= tb[step + 1])
                {
                    int cc = ((PlayerState*)inner)->gaitLevel;
                    if (cc < 0x14)
                    {
                        if (cc == 0)
                        {
                            spd = lbl_803E7EA4;
                        }
                        if (v < ((PlayerState*)inner)->maxSpeed)
                        {
                            *(u8*)&((PlayerState*)inner)->gaitLevel += 4;
                        }
                    }
                }
            }
            if (locked != 0 || *(void**)((char*)inner + 0x3fc) != *(void**)((char*)inner + 0x3f8) ||
                ((GameObject*)obj)->anim.currentMove !=
                    *(s16*)(((PlayerState*)inner)->moveAnimTable + (((PlayerState*)inner)->gaitLevel + dir) * 2))
            {
                if (((int (*)(ObjAnimComponent*))ObjAnim_GetCurrentEventCountdown)((ObjAnimComponent*)obj) == 0 ||
                    ((u32) * (u8*)((char*)inner + 0x3f2) >> 4 & 1) != 0)
                {
                    ObjAnim_SetCurrentMove(
                        obj,
                        *(s16*)(((PlayerState*)inner)->moveAnimTable + (((PlayerState*)inner)->gaitLevel + dir) * 2),
                        spd, 0);
                    if (((u32) * (u8*)((char*)inner + 0x3f1) >> 5 & 1) != 0 &&
                        *(s8*)&((PlayerState*)state)->baddie.moveJustStartedA == 0)
                    {
                        ObjAnim_SetCurrentEventStepFrames((ObjAnimComponent*)obj, 0xc);
                    }
                }
            }
        }
    }
    {
        f32 v = (f32)((PlayerState*)state)->baddie.spawnRotY / lbl_803E7EE8;
        t = (v < (t = lbl_803E7ECC)) ? t : ((v > (t = lbl_803E7EE0)) ? t : v);
    }
    {
        f32 ad = t;
        int pos;
        if (t > lbl_803E7EA4)
        {
            pos = 1;
        }
        else
        {
            pos = 0;
        }
        if (t < *(f32*)&lbl_803E7EA4)
        {
            ad = -t;
        }
        if (((u32) * (u8*)((char*)inner + 0x3f1) >> 5 & 1) == 0)
        {
            u32 fl = *(u8*)((char*)inner + 0x3f0);
            if ((fl >> 7 & 1) == 0 && (fl >> 6 & 1) == 0 && (fl >> 4 & 1) == 0 && (fl >> 2 & 1) == 0 &&
                (fl >> 3 & 1) == 0 && (fl >> 1 & 1) == 0)
            {
                if ((fl >> 5 & 1) == 0)
                {
                    Object_ObjAnimSetSecondaryBlendMove((ObjAnimComponent*)obj,
                                                        *(s16*)(((PlayerState*)inner)->moveAnimTable + 2 +
                                                                (((PlayerState*)inner)->gaitLevel + pos) * 2),
                                                        (int)(lbl_803E7FAC * ad));
                }
                {
                    int r = ((int (*)(int, f32, f32*))ObjAnim_SampleRootCurvePhase)(
                        obj, ((PlayerState*)state)->baddie.animSpeedC, (f32*)(state + 0x2a0));
                    if (r == 0)
                    {
                        ((PlayerState*)state)->baddie.moveSpeed = lbl_803E7F78;
                    }
                }
            }
        }
    }
    fn_802ABAE8((GameObject*)obj, state, inner, t);
    return 0;
}
#pragma opt_propagation reset

extern f32 lbl_803E8084;
extern f32 lbl_803E8088;

int playerStateIdle(int obj, int state, f32 fv)
{
    char* tbl;
    int inner;
    int move;
    f32 t;
    f32 v;
    int calm;

    tbl = (char*)lbl_80332EC0;
    inner = *(int*)&((GameObject*)obj)->extra;
    if (*(s8*)&((PlayerState*)state)->baddie.moveJustStartedA != 0)
    {
        if (((PlayerState*)state)->baddie.prevControlMode != 0x24 &&
            ((PlayerState*)state)->baddie.prevControlMode != 0x25)
        {
            ((PlayerState*)state)->baddie.animSpeedC = lbl_803E7EA4;
        }
        else if (((ByteFlags*)((char*)inner + 0x3f1))->b20 == 0)
        {
            int a = ((PlayerState*)inner)->inputHeading;
            ((PlayerState*)inner)->lastInputHeading = a;
            ((PlayerState*)inner)->yaw = a;
            ((PlayerState*)inner)->yawRate = 0;
            ((PlayerState*)inner)->yawRateSigned = 0;
        }
        else
        {
            f32 z = lbl_803E7EA4;
            ((PlayerState*)inner)->smoothVelX = z;
            ((PlayerState*)inner)->smoothVelZ = z;
        }
        ((PlayerState*)inner)->idleHoldTimer = lbl_803E7EA4;
        ((PlayerState*)inner)->idleWaitTimer = randomGetRange(800, 0x44c);
    }
    ((PlayerState*)state)->baddie.animSpeedA =
        ((PlayerState*)state)->baddie.animSpeedA -
        interpolate(((PlayerState*)state)->baddie.animSpeedA, ((PlayerState*)inner)->targetAnimSpeed, timeDelta);
    if (((PlayerState*)state)->baddie.animSpeedA <= *(f32*)(tbl + 0x398))
    {
        ((PlayerState*)state)->baddie.animSpeedA = lbl_803E7EA4;
    }
    {
        f32 z = lbl_803E7EA4;
        ((PlayerState*)state)->baddie.animSpeedB = z;
        ((GameObject*)obj)->anim.velocityX = z;
        ((GameObject*)obj)->anim.velocityZ = z;
    }
    {
        int r = ((int (*)(int, int, int, f32))fn_802AC7DC)(obj, state, inner, fv);
        if (r != 0)
        {
            return r;
        }
    }
    if (*(f32*)&((PlayerState*)state)->baddie.trackedObj >= lbl_803E7FC8 &&
        ((PlayerState*)state)->baddie.inputMagnitude >= lbl_803E7FC8 &&
        ((PlayerState*)state)->baddie.animSpeedC >= *(f32*)(((PlayerState*)inner)->moveParams + 4))
    {
        *(int*)&((PlayerState*)state)->baddie.unk308 = (int)fn_802A514C;
        return 3;
    }
    playerSetMovingAnims(obj, inner);
    if (*(s16**)((char*)inner + 0x3f8) == (s16*)(tbl + 0x190))
    {
        if (((PlayerState*)inner)->idleHoldTimer >= lbl_803E7FBC && **(s8**)&((PlayerState*)inner)->playerStatus <= 4)
        {
            move = 0x5d;
            fv = lbl_803E7F78;
            if (RandomTimer_UpdateRangeTrigger((void*)(inner + 0x3ec), lbl_803E7ED4, lbl_803E7F10) != 0)
            {
                Sfx_PlayFromObject(obj, SFXTRIG_fox_452);
            }
            goto picked;
        }
        {
            move = **(s16**)((char*)inner + 0x3f8);
            fv = lbl_803E7F78;
            if (((PlayerState*)inner)->idleWaitTimer <= 0)
            {
                if (((PlayerState*)inner)->curAnimId != 0x44)
                {
                    u32 i = ((PlayerState*)inner)->stopMoveIndex;
                    move = gPlayerStopMoves[i];
                    if (((PlayerState*)inner)->characterId == 0)
                    {
                        fv = ((f32*)(tbl + 0x170))[i];
                    }
                    else
                    {
                        fv = ((f32*)(tbl + 0x180))[i];
                    }
                    ((PlayerState*)inner)->stopMoveIndex += 1;
                    ((PlayerState*)inner)->stopMoveIndex = (u8)(((PlayerState*)inner)->stopMoveIndex % 3);
                }
                ((PlayerState*)inner)->idleWaitTimer = randomGetRange(800, 0x44c);
            }
        }
    picked:
        if (((GameObject*)obj)->anim.currentMove == **(s16**)((char*)inner + 0x3f8))
        {
            ((PlayerState*)inner)->idleHoldTimer = ((PlayerState*)inner)->idleHoldTimer + timeDelta;
            v = ((PlayerState*)inner)->idleHoldTimer;
            ((PlayerState*)inner)->idleHoldTimer =
                (v < lbl_803E7EA4) ? lbl_803E7EA4 : ((v > lbl_803E7FBC) ? lbl_803E7FBC : v);
            *(u16*)&((PlayerState*)inner)->idleWaitTimer = (f32) * (s16*)((char*)inner + 0x812) - timeDelta;
            {
                int cd = ((PlayerState*)inner)->idleWaitTimer;
                if (cd < 0)
                {
                    cd = 0;
                }
                else if (cd > 0x44c)
                {
                    cd = 0x44c;
                }
                ((PlayerState*)inner)->idleWaitTimer = (s16)cd;
            }
        }
        else
        {
            if (((GameObject*)obj)->anim.currentMove != 0x5d)
            {
                ((PlayerState*)inner)->idleHoldTimer = lbl_803E7EA4;
            }
            ((PlayerState*)inner)->idleWaitTimer = randomGetRange(800, 0x44c);
        }
    }
    else
    {
        move = **(s16**)((char*)inner + 0x3f8);
        fv = lbl_803E7F78;
    }
    if (((ByteFlags*)((char*)inner + 0x3f0))->b20 != 0)
    {
        *(u32*)state |= 0x200000;
        *(u32*)&((PlayerState*)inner)->flags360 &= ~0x2000000LL;
        *(s16*)((char*)state + 0x278) = 1;
        ((PlayerState*)inner)->stateHandler = (int)fn_802A514C;
        if (((ByteFlags*)((char*)inner + 0x3f1))->b20 != 0)
        {
            ((PlayerState*)inner)->maxSpeed = lbl_803E7F2C;
        }
        else
        {
            ((PlayerState*)inner)->maxSpeed = lbl_803E8064;
        }
    }
    else
    {
        if (((ByteFlags*)((char*)inner + 0x3f1))->b20 != 0)
        {
            *(u32*)&((PlayerState*)inner)->flags360 |= 0x2000000LL;
            *(s16*)((char*)state + 0x278) = 0;
            ((PlayerState*)inner)->maxSpeed = lbl_803E7ED4;
        }
        else
        {
            *(u32*)&((PlayerState*)inner)->flags360 |= 0x2000000LL;
            *(s16*)((char*)state + 0x278) = 0;
            ((PlayerState*)inner)->maxSpeed = lbl_803E806C;
        }
    }
    {
        f32 frac = (((PlayerState*)state)->baddie.inputMagnitude - lbl_803E7F14) / lbl_803E7F2C;
        t = (frac < lbl_803E7EA4) ? lbl_803E7EA4 : ((frac > lbl_803E7EE0) ? lbl_803E7EE0 : frac);
    }
    ((PlayerState*)inner)->currentSpeed =
        (((PlayerState*)inner)->maxSpeed - lbl_803E7F6C) * (t * ((PlayerState*)inner)->speedScale);
    if (((ByteFlags*)((char*)inner + 0x3f0))->b20 != 0)
    {
        fn_802ADE80((GameObject*)obj, inner, state);
    }
    {
        u32 fl = ((PlayerState*)inner)->flags3F0;
        if ((fl >> 5 & 1) == 0 && (fl >> 6 & 1) == 0 && (fl >> 4 & 1) == 0 && (fl >> 2 & 1) == 0 &&
            (fl >> 3 & 1) == 0 && (fl >> 1 & 1) == 0 && *(void**)((char*)inner + 0x7f8) == NULL &&
            ((PlayerState*)inner)->curAnimId != 0x44)
        {
            calm = 1;
        }
        else
        {
            calm = 0;
        }
    }
    if (calm && (((PlayerState*)inner)->buttonsJustPressed & PAD_BUTTON_X) != 0)
    {
        fn_802AED2C((GameObject*)obj, inner, state);
        *(int*)&((PlayerState*)state)->baddie.unk308 = (int)fn_802A514C;
        return 3;
    }
    if (((ByteFlags*)((char*)inner + 0x3f1))->b20 == 0)
    {
        ((PlayerState*)state)->baddie.animSpeedC =
            ((PlayerState*)state)->baddie.animSpeedC +
            interpolate(((PlayerState*)inner)->currentSpeed - ((PlayerState*)state)->baddie.animSpeedC,
                        ((PlayerState*)inner)->velSmoothRate, timeDelta);
    }
    if (*(s8*)&((PlayerState*)state)->baddie.moveJustStartedA != 0)
    {
        ((PlayerState*)inner)->targetYawRateSigned = 0;
        ((PlayerState*)inner)->targetYawRate = 0;
        ((PlayerState*)inner)->yawRateSigned = 0;
        ((PlayerState*)inner)->yawRate = 0;
        ((PlayerState*)inner)->animSoundId = ((PlayerState*)inner)->walkAnimSoundId;
        ((PlayerState*)inner)->gaitStepLevel = 0;
        ((PlayerState*)state)->baddie.velSmoothTime = lbl_803E8018;
        ((PlayerState*)state)->baddie.moveSpeed = lbl_803E8084;
        if (((ByteFlags*)((char*)inner + 0x3f0))->b20 == 0 && ((ByteFlags*)((char*)inner + 0x3f1))->b20 == 0)
        {
            if (((PlayerState*)state)->baddie.prevControlMode == 2)
            {
                int mA;
                int mB;
                if (((GameObject*)obj)->anim.currentMove !=
                        (mA = *(s16*)(((PlayerState*)inner)->moveAnimTable + 0x30)) &&
                    (mB = *(s16*)(((PlayerState*)inner)->moveAnimTable + 0x32),
                     ((GameObject*)obj)->anim.currentMove != mB) &&
                    ((ByteFlags*)((char*)inner + 0x3f3))->b40 == 0)
                {
                    if (((GameObject*)obj)->anim.currentMoveProgress <= lbl_803E7E98)
                    {
                        ObjAnim_SetCurrentMove(obj, mA, lbl_803E7EA4, 0);
                    }
                    else
                    {
                        ObjAnim_SetCurrentMove(obj, mB, lbl_803E7EA4, 0);
                    }
                }
                ((PlayerState*)state)->baddie.moveSpeed = lbl_803E8088;
            }
            else if (((GameObject*)obj)->anim.currentMove != move)
            {
                ObjAnim_SetCurrentMove(obj, move, lbl_803E7EA4, 0);
                ((PlayerState*)state)->baddie.moveSpeed = fv;
            }
        }
        else if (((GameObject*)obj)->anim.currentMove != move)
        {
            ObjAnim_SetCurrentMove(obj, move, lbl_803E7EA4, 0);
            ((PlayerState*)state)->baddie.moveSpeed = fv;
        }
    }
    if (((GameObject*)obj)->anim.currentMove == *(s16*)(((PlayerState*)inner)->moveAnimTable + 0x30) ||
        ((GameObject*)obj)->anim.currentMove == *(s16*)(((PlayerState*)inner)->moveAnimTable + 0x32))
    {
        if (*(s8*)&((PlayerState*)state)->baddie.moveDone != 0 &&
            ((int (*)(int))ObjAnim_GetCurrentEventCountdown)(obj) == 0)
        {
            ObjAnim_SetCurrentMove(obj, move, lbl_803E7EA4, 0);
            ((PlayerState*)state)->baddie.moveSpeed = fv;
        }
    }
    else if (((ByteFlags*)((char*)inner + 0x3f0))->b20 == 0 && ((ByteFlags*)((char*)inner + 0x3f1))->b20 == 0 &&
             ((PlayerState*)inner)->targetYawRateSigned > 5)
    {
        if (((GameObject*)obj)->anim.currentMove != *(s16*)(((PlayerState*)inner)->moveAnimTable + 0x3e) &&
            ((int (*)(int))ObjAnim_GetCurrentEventCountdown)(obj) == 0)
        {
            ObjAnim_SetCurrentMove(obj, *(s16*)(((PlayerState*)inner)->moveAnimTable + 0x3e), lbl_803E7EA4, 0);
            ((PlayerState*)state)->baddie.moveSpeed = lbl_803E7E90;
        }
    }
    else if (((GameObject*)obj)->anim.currentMove != move && ((int (*)(int))ObjAnim_GetCurrentEventCountdown)(obj) == 0)
    {
        s16 cur = ((GameObject*)obj)->anim.currentMove;
        if (cur == gPlayerStopMoves[0] || cur == gPlayerStopMoves[1] || cur == gPlayerStopMoves[2] ||
            cur == gPlayerStopMoves[3])
        {
            if (*(s8*)&((PlayerState*)state)->baddie.moveDone != 0)
            {
                ObjAnim_SetCurrentMove(obj, move, lbl_803E7EA4, 0);
                ((PlayerState*)state)->baddie.moveSpeed = fv;
            }
        }
        else
        {
            ObjAnim_SetCurrentMove(obj, move, lbl_803E7EA4, 0);
            ((PlayerState*)state)->baddie.moveSpeed = fv;
            if (move == 0x5d)
            {
                ((void (*)(int, int))ObjAnim_SetCurrentEventStepFrames)(obj, 0x1e);
            }
        }
    }
    if (((ByteFlags*)((char*)inner + 0x3f1))->b20 == 0)
    {
        f32 step;
        f32 lim;
        step = interpolate((f32) * (int*)((char*)inner + 0x47c),
                           lbl_803E7EE0 / ((PlayerState*)inner)->targetYawSmoothRate, timeDelta);
        lim = timeDelta * (((PlayerState*)inner)->targetYawRateLimit * ((PlayerState*)inner)->leanCurveScale);
        step = (step < lim) ? step : lim;
        if (((PlayerState*)inner)->targetYawRate < 0)
        {
            step = -step;
        }
        *(u16*)&((PlayerState*)inner)->targetYaw = gPlayerDegToBinAngle * step + (f32) * (s16*)((char*)inner + 0x478);
        step = interpolate((f32) * (int*)((char*)inner + 0x488), lbl_803E7EE0 / ((PlayerState*)inner)->yawSmoothRate,
                           timeDelta);
        lim = ((PlayerState*)inner)->yawRateLimit * timeDelta;
        step = (step < lim) ? step : lim;
        if (((PlayerState*)inner)->yawRate < 0)
        {
            step = -step;
        }
        *(u16*)&((PlayerState*)inner)->yaw = gPlayerDegToBinAngle * step + (f32) * (s16*)((char*)inner + 0x484);
    }
    else
    {
        f32 vx;
        f32 vz;
        f32 c;
        c = mathSinf((gPlayerPi * (f32) * (int*)((char*)inner + 0x474)) / lbl_803E7F98);
        vx = t * -c;
        vx = ((PlayerState*)inner)->maxSpeed * vx;
        c = mathCosf((gPlayerPi * (f32) * (int*)((char*)inner + 0x474)) / lbl_803E7F98);
        vz = t * -c;
        vz = ((PlayerState*)inner)->maxSpeed * vz;
        vx = interpolate(vx - ((PlayerState*)inner)->smoothVelX, ((PlayerState*)inner)->velSmoothRate, timeDelta);
        vz = interpolate(vz - ((PlayerState*)inner)->smoothVelZ, ((PlayerState*)inner)->velSmoothRate, timeDelta);
        ((PlayerState*)inner)->smoothVelX = ((PlayerState*)inner)->smoothVelX + vx;
        ((PlayerState*)inner)->smoothVelZ = ((PlayerState*)inner)->smoothVelZ + vz;
        ((PlayerState*)state)->baddie.animSpeedC =
            sqrtf(((PlayerState*)inner)->smoothVelX * ((PlayerState*)inner)->smoothVelX +
                  ((PlayerState*)inner)->smoothVelZ * ((PlayerState*)inner)->smoothVelZ);
        ((PlayerState*)state)->baddie.animSpeedC =
            (((PlayerState*)state)->baddie.animSpeedC < lbl_803E7EA4)
                ? lbl_803E7EA4
                : ((((PlayerState*)state)->baddie.animSpeedC > ((PlayerState*)inner)->maxSpeed)
                       ? ((PlayerState*)inner)->maxSpeed
                       : ((PlayerState*)state)->baddie.animSpeedC);
    }
    if (((ByteFlags*)((char*)inner + 0x3f0))->b20 == 0)
    {
        fn_802AC32C(obj, state, inner);
    }
    return 0;
}

int playerState00(int obj, int state)
{
    if (mainGetBit(GAMEBIT_CF_DoStandUpAnim))
    {
        mainSetBits(GAMEBIT_CF_DoStandUpAnim, 0);
        (*gObjectTriggerInterface)->runSequence(0x10, (void*)obj, -1);
    }
    *(int*)&((PlayerState*)state)->baddie.unk308 = (int)fn_802A514C;
    return 2;
}

int fn_802A71E0(int obj, int a, int b, int* p6, int* p7, f32 e, f32 f, int n, int flags)
{
    ObjModel* model;
    int uf;
    u8 mf;
    int sel;
    int off;
    f32* q;
    int blend;
    f32 v1, v2, t;
    f32 buf1[3];
    s16 buf2[3];
    model = Player_GetActiveModel(obj);
    mf = 0;
    uf = (u8)flags;
    if (uf & 0x2)
    {
        mf |= 0x2;
    }
    if (uf & 0x40)
    {
        mf |= 0x4;
    }
    if (uf & 0x10)
    {
        mf |= 0x8;
    }
    if (uf & 0x20)
    {
        mf |= 0x1;
    }
    sel = uf & 0x4;
    if (sel != 0)
    {
        ((int (*)(int, int, u8, f32))ObjAnim_SetCurrentMove)(obj, a, mf, lbl_803E7EA4);
        ObjAnim_AdvanceCurrentMove((int)obj, f, lbl_803E7EA4, NULL);
        ObjModel_SampleJointTransform(model, 0, 0, e, ((GameObject*)obj)->anim.rootMotionScale, buf1, buf2);
    }
    else
    {
        ((int (*)(int, int, u8, f32))Object_ObjAnimSetMove)(obj, a, mf, lbl_803E7EA4);
        ((int (*)(int, f32, f32, int))Object_ObjAnimAdvanceMove)(obj, f, lbl_803E7EA4, 0);
        ObjModel_SampleJointTransform(model, 1, 0, e, ((GameObject*)obj)->anim.rootMotionScale, buf1, buf2);
    }
    off = (u8)n << 2;
    q = buf1;
    v1 = *(f32*)((char*)q + off);
    if (v1 < lbl_803E7EA4)
    {
        v1 = -v1;
    }
    if (sel != 0)
    {
        Object_ObjAnimSetSecondaryBlendMove((ObjAnimComponent*)obj, b, 0);
        ObjModel_SampleJointTransform(model, 0, 2, e, ((GameObject*)obj)->anim.rootMotionScale, buf1, buf2);
    }
    else
    {
        Object_ObjAnimSetPrimaryBlendMove((ObjAnimComponent*)obj, b, 0);
        ObjModel_SampleJointTransform(model, 1, 2, e, ((GameObject*)obj)->anim.rootMotionScale, buf1, buf2);
    }
    v2 = *(f32*)((char*)q + off);
    if (v2 < 0.0f)
    {
        v2 = -v2;
    }
    t = *(f32*)((char*)p7 + 0xc) +
        (*(f32*)((char*)p6 + 0x0) * *(f32*)((char*)p7 + 0x0) + *(f32*)((char*)p6 + 0x8) * *(f32*)((char*)p7 + 0x8));
    if (t < 0.0f)
    {
        t = -t;
    }
    t = (t - v1) / (v2 - v1);
    if (uf & 0x1)
    {
        if (t < 0.0f)
        {
            t = 0.0f;
        }
    }
    else
    {
        if (t < 0.0f)
        {
            t = -t;
        }
    }
    if (t > lbl_803E7EE0)
    {
        t = lbl_803E7EE0;
    }
    blend = (int)(lbl_803E7FAC * t);
    if (sel != 0)
    {
        Object_ObjAnimSetSecondaryBlendMove((ObjAnimComponent*)obj, b, (s16)blend);
    }
    else
    {
        Object_ObjAnimSetPrimaryBlendMove((ObjAnimComponent*)obj, b, (s16)blend);
    }
    return blend;
}

/* Number of directional sweep probes (parallel dirs[13]/dirMasks[13] tables). */
#define PLAYER_SWEEP_DIR_COUNT 13

s8 playerCheckIfClimbingOntoWall(int obj, int state, int state2, void* out, f32 fv, u32 mask)
{
    typedef struct
    {
        int hitObj;
        f32 minX;
        f32 maxX;
        f32 minY;
        f32 maxY;
        f32 minZ;
        f32 maxZ;
        f32 nx;
        f32 ny;
        f32 nz;
        f32 nw;
        u8 padA[0xc];
        f32 g38;
        f32 g3c;
        f32 g40;
        f32 dist;
        u8 padB[9];
        s8 kind;
        u8 padC[2];
    } SweepHit;
    f32* dir;
    int objCount;
    f32 nearDist;
    f32 rot[3];
    f32 vec[3];
    f32 start[3];
    f32 end[3];
    f32 sc1[3];
    f32* sc1p = sc1;
    f32 sc0[3];
    f32* sc0p = sc0;
    s8 dirs[13] = {0xb, 4, 6, 0xa, 0xa, 3, 3, 2, 0xe, 0x10, 0x12, 0x13, 5};
    u16 dirMasks[13] = {1, 2, 4, 8, 8, 0x10, 0x10, 0x40, 0x80, 0x100, 1, 0x20, 0xffff};
    struct
    {
        u8 pad[2];
        u16 mode;
        u8 pad2[4];
        f32 scale;
        f32 x;
        f32 y;
        f32 z;
    } pfx;
    SweepHit buf;
    u8 useAlt;
    f32 hd;
    f32 dp;
    int i;
    s8 ok;
    f32 ang;
    f32 lo;
    int k;
    s8 flagB;
    s8 flagA;
    u8 hit;
    int ai;

    ai = (u16)getAngle(((PlayerState*)state2)->baddie.moveInputX, -((PlayerState*)state2)->baddie.moveInputZ) -
         ((PlayerState*)state2)->baddie.cameraYaw;
    ang = (gPlayerPi * (f32)ai) / lbl_803E7F98;
    rot[0] = -mathSinf(ang);
    rot[1] = lbl_803E7EA4;
    rot[2] = -mathCosf(ang);
    fn_802A81B8((GameObject*)(obj), state, vec);
    sc1p[0] = lbl_803E808C * rot[0];
    sc1p[1] = lbl_803E808C * rot[1];
    sc1p[2] = lbl_803E808C * rot[2];
    sc0p[0] = lbl_803E808C * vec[0];
    sc0p[1] = lbl_803E808C * vec[1];
    sc0p[2] = lbl_803E808C * vec[2];
    *(u32*)&((PlayerState*)state)->flags360 &= ~PLAYER_FLAG_LEDGE_DETECTED;
    for (i = 0; i < PLAYER_SWEEP_DIR_COUNT; i++)
    {
        if ((mask & dirMasks[i]) == 0)
        {
            continue;
        }
        ok = 0;
        useAlt = 0;
        flagB = 1;
        flagA = 0;
        switch (i)
        {
        case 1:
        case 7:
        case 12:
        {
            u8 b;
            s16 v = ((PlayerState*)state2)->baddie.controlMode;
            if (v == 0xc)
            {
                continue;
            }
            if ((u16)(v - 9) <= 2)
            {
                continue;
            }
            b = ((PlayerState*)state)->flags3F0;
            if ((u32)b >> 3 & 1)
            {
                continue;
            }
            if ((u32)b >> 2 & 1)
            {
                continue;
            }
            flagB = 0;
            flagA = 1;
            ok = 1;
            break;
        }
        case 0:
        case 10:
            if (((u32) * (u8*)(state + 0x3f1) & 1) == 0)
            {
                logPrintf(sNotOnGroundFailureMessage);
                continue;
            }
            ok = 1;
            break;
        case 3:
        case 5:
        {
            u8 b = ((PlayerState*)state)->flags3F0;
            if ((u32)b >> 3 & 1 || (u32)b >> 2 & 1)
            {
                ok = 1;
            }
            useAlt = 1;
            break;
        }
        case 2:
        {
            u8 b2;
            if (((u32) * (u8*)(state + 0x3f1) & 1) == 0)
            {
                u8 b = ((PlayerState*)state)->flags3F0;
                if (((u32)b >> 3 & 1) == 0 && ((u32)b >> 2 & 1) == 0)
                {
                    continue;
                }
            }
            b2 = ((PlayerState*)state)->flags3F0;
            if ((u32)b2 >> 3 & 1 || (u32)b2 >> 2 & 1)
            {
                ok = 1;
            }
            break;
        }
        case 4:
        case 6:
        {
            u8 b2;
            if (((u32) * (u8*)(state + 0x3f1) & 1) == 0)
            {
                u8 b = ((PlayerState*)state)->flags3F0;
                if (((u32)b >> 3 & 1) == 0 && ((u32)b >> 2 & 1) == 0)
                {
                    continue;
                }
            }
            b2 = ((PlayerState*)state)->flags3F0;
            if ((u32)b2 >> 3 & 1 || (u32)b2 >> 2 & 1)
            {
                ok = 1;
            }
            break;
        }
        case 11:
            flagB = 0;
            ok = 1;
            break;
        }
        if (ok == 0)
        {
            if (*(f32*)(state2 + 0x298) < lbl_803E7EFC)
            {
                continue;
            }
        }
        if (useAlt == 0)
        {
            if (ok == 0)
            {
                end[0] = ((GameObject*)obj)->anim.localPosX + sc1p[0];
                end[1] = ((GameObject*)obj)->anim.localPosY + sc1p[1];
                end[2] = ((GameObject*)obj)->anim.localPosZ + sc1p[2];
                dir = rot;
            }
            else
            {
                end[0] = ((GameObject*)obj)->anim.localPosX + sc0p[0];
                end[1] = ((GameObject*)obj)->anim.localPosY + sc0p[1];
                end[2] = ((GameObject*)obj)->anim.localPosZ + sc0p[2];
                dir = vec;
            }
            start[0] = ((GameObject*)obj)->anim.localPosX;
            start[1] = ((GameObject*)obj)->anim.localPosY;
            start[2] = ((GameObject*)obj)->anim.localPosZ;
        }
        else
        {
            if (ok == 0)
            {
                start[0] = ((GameObject*)obj)->anim.localPosX + sc1p[0];
                start[1] = ((GameObject*)obj)->anim.localPosY + sc1p[1];
                start[2] = ((GameObject*)obj)->anim.localPosZ + sc1p[2];
                dir = rot;
            }
            else
            {
                start[0] = ((GameObject*)obj)->anim.localPosX + sc0p[0];
                start[1] = ((GameObject*)obj)->anim.localPosY + sc0p[1];
                start[2] = ((GameObject*)obj)->anim.localPosZ + sc0p[2];
                dir = vec;
            }
            end[0] = ((GameObject*)obj)->anim.localPosX;
            end[1] = ((GameObject*)obj)->anim.localPosY;
            end[2] = ((GameObject*)obj)->anim.localPosZ;
        }
        hit = objBboxFn_800640cc(start, end, lbl_803E7EA4, 3, (TrackBBoxHit*)&buf, (GameObject*)obj, 1, dirs[i],
                                0xff, 10);
        if (flagA != 0 && hit != 0)
        {
            ((PlayerState*)state)->probeHitDist = buf.dist;
        }
        if (flagB != 0 && hit != 0)
        {
            dp = buf.nx * dir[0] + buf.ny * dir[1] + buf.nz * dir[2];
            switch (i)
            {
            case 3:
            case 5:
                if (((GameObject*)obj)->anim.localPosY < lbl_803E7F10 + buf.minY &&
                    ((GameObject*)obj)->anim.localPosY < lbl_803E7F10 + buf.maxY)
                {
                    hit = 0;
                }
                break;
            case 2:
            case 4:
            case 6:
                if (((u32) * (u8*)(state + 0x3f1) & 1) != 0)
                {
                    if (dp > lbl_803E8090 || (((GameObject*)obj)->anim.localPosY > buf.g3c - lbl_803E7ED8 &&
                                              ((GameObject*)obj)->anim.localPosY > buf.g40 - lbl_803E7ED8))
                    {
                        hit = 0;
                    }
                }
                else
                {
                    if (dp > lbl_803E8094)
                    {
                        hit = 0;
                    }
                }
                break;
            case 0:
            case 10:
                break;
            default:
                if (dp > lbl_803E8090)
                {
                    hit = 0;
                }
            }
        }
        if (flagB != 0 && hit != 0)
        {
            if (useAlt == 0)
            {
                start[0] = ((GameObject*)obj)->anim.localPosX;
                start[1] = ((GameObject*)obj)->anim.localPosY;
                start[2] = ((GameObject*)obj)->anim.localPosZ;
                end[0] = -(lbl_803E808C * buf.nx - ((GameObject*)obj)->anim.localPosX);
                end[1] = ((GameObject*)obj)->anim.localPosY;
                end[2] = -(lbl_803E808C * buf.nz - ((GameObject*)obj)->anim.localPosZ);
            }
            else
            {
                start[0] = lbl_803E808C * buf.nx + ((GameObject*)obj)->anim.localPosX;
                start[1] = ((GameObject*)obj)->anim.localPosY;
                start[2] = lbl_803E808C * buf.nz + ((GameObject*)obj)->anim.localPosZ;
                end[0] = ((GameObject*)obj)->anim.localPosX;
                end[1] = ((GameObject*)obj)->anim.localPosY;
                end[2] = ((GameObject*)obj)->anim.localPosZ;
            }
            hit = objBboxFn_800640cc(start, end, lbl_803E7EA4, 3, (TrackBBoxHit*)&buf, (GameObject*)obj, 1,
                                    dirs[i], 0xff, 10);
        }
        if (hit == 0)
        {
            continue;
        }
        hd = buf.dist;
        if (useAlt != 0)
        {
            hd = lbl_803E808C - hd;
        }
        switch (i)
        {
        case 0:
        {
            int t = buf.hitObj;
            if ((u32)t == 0)
            {
                continue;
            }
            if ((*(int (*)(int)) * (int*)((char*)*(int*)*(int*)(t + 0x68) + 0x2c))(t) != 0 &&
                *(f32*)(state2 + 0x298) > lbl_803E7EFC && hd <= lbl_803E7ED4 + lbl_803DC6C0)
            {
                switch (
                    ((int (*)(int, int, void*, int, f32*, f32))fn_802A8EE4)(obj, state, &buf, state + 0x5a8, end, hd))
                {
                case 2:
                    return 4;
                case 3:
                    return 5;
                }
            }
            if (!(hd < lbl_803E7FA4))
            {
                continue;
            }
            if (*(u8*)(t + 0xaf) & 8)
            {
                continue;
            }
            *(u32*)&((PlayerState*)state)->flags360 |= PLAYER_FLAG_LEDGE_DETECTED;
            if ((*(int*)&((PlayerState*)state2)->baddie.unk31C & 0x100) == 0)
            {
                continue;
            }
            ((PlayerState*)state)->surfaceNormalX = buf.nx;
            ((PlayerState*)state)->surfaceNormalY = buf.ny;
            ((PlayerState*)state)->surfaceNormalZ = buf.nz;
            ((PlayerState*)state)->surfaceNormalW = buf.g38;
            *(u8*)&((PlayerState*)state)->stickEdgeLatch = 0;
            if ((u32)buf.hitObj != 0)
            {
                Obj_TransformWorldPointToLocal(end[0], end[1], end[2], (f32*)(state + 0x664), (f32*)(state + 0x668),
                                               (f32*)(state + 0x66c), buf.hitObj);
                ((PlayerState*)state)->contactObject = buf.hitObj;
            }
            else
            {
                *(f32*)(state + 0x664) = end[0];
                *(f32*)(state + 0x668) = end[1];
                *(f32*)(state + 0x66c) = end[2];
                ((PlayerState*)state)->contactObject = 0;
            }
            return 6;
        }
        case 10:
            if (!(hd < lbl_803E8098))
            {
                continue;
            }
            if ((*(int*)&((PlayerState*)state2)->baddie.unk31C & 0x100) == 0)
            {
                continue;
            }
            ((PlayerState*)state)->surfaceNormalX = buf.nx;
            ((PlayerState*)state)->surfaceNormalY = buf.ny;
            ((PlayerState*)state)->surfaceNormalZ = buf.nz;
            ((PlayerState*)state)->surfaceNormalW = buf.g38;
            *(u8*)&((PlayerState*)state)->stickEdgeLatch = 0;
            if ((u32)buf.hitObj != 0)
            {
                Obj_TransformWorldPointToLocal(end[0], end[1], end[2], (f32*)(state + 0x664), (f32*)(state + 0x668),
                                               (f32*)(state + 0x66c), buf.hitObj);
                ((PlayerState*)state)->contactObject = buf.hitObj;
            }
            else
            {
                *(f32*)(state + 0x664) = end[0];
                *(f32*)(state + 0x668) = end[1];
                *(f32*)(state + 0x66c) = end[2];
                ((PlayerState*)state)->contactObject = 0;
            }
            return 0xd;
        case 3:
        case 4:
            if (!(hd <= lbl_803E7F58))
            {
                continue;
            }
            if (((int (*)(int, int, void*, int, int))player_probeClimbable)(obj, state, &buf, state + 0x4e4, i == 3) ==
                0)
            {
                continue;
            }
            return 0;
        case 5:
        case 6:
            if (!(hd <= lbl_803E7EE0 + lbl_803DC6C0))
            {
                continue;
            }
            if (((int (*)(int, int, void*, f32*, int, int))fn_802A8680)(obj, state, &buf, end, state + 0x548, i == 5) ==
                0)
            {
                continue;
            }
            return 9;
        case 1:
        case 7:
        case 12:
            if (!(hd < lbl_803E7F58))
            {
                continue;
            }
            switch (fn_802A87CC((GameObject*)obj, (char*)&buf, (f32*)(state + 0x5a8), end, hd, fv))
            {
            case 4:
                return 8;
            case 5:
                return 7;
            }
            break;
        case 2:
        case 9:
            if (!(hd <= lbl_803E7EE0 + lbl_803DC6C0))
            {
                continue;
            }
            switch (((int (*)(int, int, void*, int, f32*, f32))fn_802A8EE4)(obj, state, &buf, state + 0x5a8, end, hd))
            {
            case 2:
                return 4;
            case 3:
                return 5;
            case 6:
                return 0xc;
            }
            break;
        case 8:
        {
            s8 ok2;
            int t8;
            if (!(hd <= lbl_803E7EE0 + lbl_803DC6C0))
            {
                continue;
            }
            nearDist = lbl_803E808C;
            t8 = ObjGroup_FindNearestObject(0x23, (int)obj, &nearDist);
            ok2 = 1;
            if ((u32)t8 != 0)
            {
                if ((*(u8 (*)(int)) * (int*)((char*)*(int*)*(int*)(t8 + 0x68) + 0x24))(t8) == 0)
                {
                    ok2 = 0;
                }
            }
            if (ok2 == 0)
            {
                continue;
            }
            ((PlayerState*)state)->hitNormalX = buf.nx;
            ((PlayerState*)state)->hitNormalY = buf.ny;
            ((PlayerState*)state)->hitNormalZ = buf.nz;
            ((PlayerState*)state)->hitNormalW = buf.nw;
            return 0xb;
        }
        case 11:
            if (!(hd < lbl_803E809C))
            {
                continue;
            }
            if (buf.kind == 0xd)
            {
                if (!(((PlayerState*)state2)->baddie.animSpeedA > lbl_803E80A0))
                {
                    continue;
                }
                if (((PlayerState*)state)->particleBurstCooldown <= lbl_803E7EA4)
                {
                    for (k = 0; k < 0x4b; k++)
                    {
                        lo = buf.minX;
                        pfx.x = lo + (buf.maxX - lo) * (f32)randomGetRange(0, 100) / lbl_803E7F5C;
                        lo = buf.minY;
                        pfx.y = lo + (buf.g3c - lo) * (f32)randomGetRange(0, 100) / lbl_803E7F5C;
                        lo = buf.minZ;
                        pfx.z = lo + (buf.maxZ - lo) * (f32)randomGetRange(0, 100) / lbl_803E7F5C;
                        pfx.scale = lbl_803E7EE0;
                        pfx.mode = 0x3c;
                        (*gPartfxInterface)->spawnObject((void*)obj, 0x804, &pfx, 0x200001, -1, NULL);
                    }
                    ((PlayerState*)state)->particleBurstCooldown = lbl_803E7F30;
                }
            }
            else
            {
                ObjPath_GetPointWorldPosition((GameObject*)obj, 0xb, &pfx.x, &pfx.y, &pfx.z, 0);
                ((void (*)(int, int, int, int, int, f32, f32, f32))ObjHits_RecordPositionHit)(obj, 0, 8, 1, -1, pfx.x,
                                                                                              pfx.y, pfx.z);
            }
            break;
        }
    }
    if ((*(int*)&((PlayerState*)state2)->baddie.unk31C & 0x100) != 0 && (mask & 0x200) != 0)
    {
        int* objs = (int*)ObjGroup_GetObjects(10, &objCount);
        int k2;
        for (k2 = 0; k2 < objCount; k2++)
        {
            int cur = *objs;
            if ((*(int (*)(int, int)) * (int*)((char*)*(int*)*(int*)(cur + 0x68) + 0x20))(cur, obj) != 0)
            {
                ((PlayerState*)state)->focusObject = (GameObject*)cur;
                return 0xa;
            }
            objs++;
        }
    }
    return -1;
}
#pragma opt_propagation off

void fn_802A81B8(GameObject* obj, int state, f32* out)
{
    f32 mag;
    u32 flag = (((PlayerState*)state)->flags3F1 >> 5) & 1;

    if (flag != 0 || ((PlayerState*)state)->baddie.targetObj != NULL)
    {
        out[0] = obj->anim.velocityX;
        out[1] = lbl_803E7EA4;
        out[2] = obj->anim.velocityZ;
        mag = PSVECMag(out);
        if (mag > lbl_803E7EA4)
        {
            PSVECScaleLegacy(lbl_803E7EE0 / mag, out, out);
        }
        else
        {
            out[0] = -mathSinf(gPlayerPi * (f32)((PlayerState*)state)->targetYaw / lbl_803E7F98);
            out[1] = lbl_803E7EA4;
            out[2] = -mathCosf(gPlayerPi * (f32)((PlayerState*)state)->targetYaw / lbl_803E7F98);
        }
    }
    else
    {
        out[0] = -mathSinf(gPlayerPi * (f32)((PlayerState*)state)->targetYaw / lbl_803E7F98);
        out[1] = lbl_803E7EA4;
        out[2] = -mathCosf(gPlayerPi * (f32)((PlayerState*)state)->targetYaw / lbl_803E7F98);
    }
}
#pragma opt_propagation reset

/*
 * Probe for a climbable map surface (a HITQUERY_CLIMB_SURFACE collision hit) and,
 * if one is found near the player, seed the climb state at `dst` (PlayerState's
 * climb block: climbStepCount = surface height / step size, climbStepHeight,
 * climbStep) and return 1; return 0 when no ladder is in range. Called per
 * candidate direction from the player move handler.
 */
enum HitQueryMask
{
    HITQUERY_TEST_OBJECT_HITBOXES = 0x01,  /* also test reset-object hitboxes, not just map triangles */
    HITQUERY_REUSE_TRIANGLE_BUFFER = 0x10, /* reuse the loaded map-triangle buffer (skip block reload) */
    HITQUERY_SKIP_CULLED_OBJECTS = 0x80,   /* skip objects whose modelInstance flag 0x01000000 is set */
    /* Composite the player's ladder/climb probe issues: a climb-typed map
     * surface, map triangles only (no 0x01 -> no object hitboxes). Live-verified
     * in Dolphin as the query that detects a ladder and seeds the climb state. */
    HITQUERY_CLIMB_SURFACE = 0x204,
};

int player_probeClimbable(GameObject* obj, int p4, int src, int dst, int flag)
{
    TrackGroundHit** hits;
    f32 pos[3];
    f32 y;
    f32 minDist;
    int best;
    int i;
    int count;
    TrackGroundHit* chosen;
    f32 zero;

    *(u8*)((char*)dst + 3) = 0;
    ((ByteFlags*)((char*)dst + 0x63))->b80 = 1;
    if ((*(s8*)((char*)src + 0x52) & 0x08) == 0)
    {
        ((ByteFlags*)((char*)dst + 0x63))->b80 = 0;
    }

    {
        f32 s4 = *(f32*)((char*)src + 0x4);
        f32 t = 0.5f;
        *(f32*)((char*)dst + 0x48) = s4 + t * (*(f32*)((char*)src + 0x8) - s4);
        *(f32*)((char*)dst + 0x4c) = *(f32*)((char*)src + 0xc);
        *(f32*)((char*)dst + 0x50) =
            *(f32*)((char*)src + 0x14) + t * (*(f32*)((char*)src + 0x18) - *(f32*)((char*)src + 0x14));
    }

    if (flag != 0)
    {
        *(f32*)((char*)dst + 0x28) = -*(f32*)((char*)src + 0x1c);
        *(f32*)((char*)dst + 0x2c) = -*(f32*)((char*)src + 0x20);
        *(f32*)((char*)dst + 0x30) = -*(f32*)((char*)src + 0x24);
        *(f32*)((char*)dst + 0x34) = -*(f32*)((char*)src + 0x28);
    }
    else
    {
        *(f32*)((char*)dst + 0x28) = *(f32*)((char*)src + 0x1c);
        *(f32*)((char*)dst + 0x2c) = *(f32*)((char*)src + 0x20);
        *(f32*)((char*)dst + 0x30) = *(f32*)((char*)src + 0x24);
        *(f32*)((char*)dst + 0x34) = *(f32*)((char*)src + 0x28);
    }

    *(f32*)((char*)dst + 0x38) = -*(f32*)((char*)src + 0x24);
    *(f32*)((char*)dst + 0x3c) = zero = 0.0f;
    *(f32*)((char*)dst + 0x40) = *(f32*)((int)src + 0x1c);
    *(f32*)((char*)dst + 0x44) = -(*(f32*)((char*)dst + 0x48) * *(f32*)((char*)dst + 0x38) +
                                   *(f32*)((char*)dst + 0x4c) * *(f32*)((char*)dst + 0x3c) +
                                   *(f32*)((char*)dst + 0x50) * *(f32*)((char*)dst + 0x40));

    *(f32*)((char*)dst + 0x54) = *(f32*)((char*)p4 + 0x768);
    *(f32*)((char*)dst + 0x58) = zero;
    *(f32*)((char*)dst + 0x5c) = *(f32*)((char*)p4 + 0x770);
    *(f32*)((char*)dst + 0x18) = *(f32*)((char*)dst + 0x54) * *(f32*)((char*)dst + 0x38) +
                                 *(f32*)((char*)dst + 0x58) * *(f32*)((char*)dst + 0x3c) +
                                 *(f32*)((char*)dst + 0x5c) * *(f32*)((char*)dst + 0x40) + *(f32*)((char*)dst + 0x44);

    *(s8*)((char*)dst + 0x62) = (s8)(int)*(s8*)((char*)src + 0x53);

    if (*(f32*)((char*)dst + 0x18) > -9.0f && *(f32*)((char*)dst + 0x18) < 9.0f)
    {
        *(f32*)((char*)dst + 0x8) = *(f32*)((char*)src + 0xc);
        PSVECScale((f32*)((char*)src + 0x1c), pos, -(&lbl_803DC6B8)[1]);
        PSVECAdd((f32*)((int)dst + 0x48), pos, pos);
        y = *(f32*)((char*)src + 0x3c);
        pos[1] = y;
        count = hitDetectFn_80065e50(obj, pos[0], y, pos[2], &hits, 0, HITQUERY_CLIMB_SURFACE);

        minDist = 10000.0f;
        best = -1;
        for (i = 0; i < count; i++)
        {
            TrackGroundHit* entry = hits[i];
            if (entry->normalY > 0.707f)
            {
                f32 d = pos[1] - entry->height;
                if (d < 0.0f)
                {
                    d = -d;
                }
                if (d < minDist)
                {
                    minDist = d;
                    best = i;
                }
            }
        }

        chosen = hits[best];
        *(f32*)((char*)dst + 0x4) = chosen->height;
        *(s8*)((char*)dst + 0x1) = (s8)(s32)((2.2f + (*(f32*)((char*)src + 0x3c) - *(f32*)((char*)dst + 0x8))) / 8.8f);
        *(f32*)((char*)dst + 0xc) =
            (*(f32*)((char*)src + 0x3c) - *(f32*)((char*)dst + 0x8)) / (f32) * (s8*)((char*)dst + 0x1);

        if (obj->anim.localPosY > *(f32*)((char*)dst + 0x4) - 10.0f)
        {
            *(s8*)((char*)dst + 0x0) = *(u8*)((char*)dst + 0x1) - 3;
        }
        else
        {
            *(s8*)((char*)dst + 0x0) = 1;
        }
        return 1;
    }
    return 0;
}

int fn_802A8680(int p1, int p2, int src, int vec, int out, int flag)
{
    f32 p48;
    f32 m44;
    f32 d1;
    f32 m4c;
    f32 nx;
    f32 ny;
    f32 d2;
    f32 c38;
    *(f32*)((char*)out + 0x44) = *(f32*)((char*)vec + 0x0);
    *(f32*)((char*)out + 0x48) = *(f32*)((char*)src + 0xc);
    *(f32*)((char*)out + 0x4c) = *(f32*)((char*)vec + 0x8);
    *(f32*)((char*)out + 0x50) = ((PlayerState*)p2)->savedPosX;
    *(f32*)((char*)out + 0x54) = lbl_803E7EA4;
    *(f32*)((char*)out + 0x58) = ((PlayerState*)p2)->savedPosZ;
    if (flag != 0)
    {
        *(u8*)((char*)out + 0x1) = 1;
    }
    else
    {
        *(u8*)((char*)out + 0x1) = 0;
    }
    *(f32*)((char*)out + 0x24) = *(f32*)((char*)src + 0x1c);
    *(f32*)((char*)out + 0x28) = *(f32*)((char*)src + 0x20);
    *(f32*)((char*)out + 0x2c) = *(f32*)((char*)src + 0x24);
    *(f32*)((char*)out + 0x30) = *(f32*)((char*)src + 0x28);
    *(f32*)((char*)out + 0x34) = -*(f32*)((char*)src + 0x24);
    c38 = lbl_803E7EA4;
    *(f32*)((char*)out + 0x38) = c38;
    *(f32*)((char*)out + 0x3c) = *(f32*)((char*)src + 0x1c);
    *(f32*)((char*)out + 0x40) = -(*(f32*)((char*)out + 0x44) * *(f32*)((char*)out + 0x34) +
                                   *(f32*)((char*)out + 0x48) * *(f32*)((char*)out + 0x38) +
                                   *(f32*)((char*)out + 0x4c) * *(f32*)((char*)out + 0x3c));
    nx = -*(f32*)((char*)out + 0x2c);
    ny = *(f32*)((char*)out + 0x24);
    d1 = -(nx * *(f32*)((char*)src + 0x4) + ny * *(f32*)((char*)src + 0x14)) +
         (ny * (m4c = *(f32*)((char*)out + 0x4c)) +
          (nx * (m44 = *(f32*)((char*)out + 0x44)) + (p48 = c38 * *(f32*)((char*)out + 0x48))));
    nx = -nx;
    ny = -ny;
    d2 = -(nx * *(f32*)((char*)src + 0x8) + ny * *(f32*)((char*)src + 0x18)) + (ny * m4c + (nx * m44 + p48));
    if (d1 > lbl_803E80BC && d2 > lbl_803E80BC)
    {
        *(f32*)((char*)out + 0x8) = *(f32*)((char*)src + 0xc);
        *(f32*)((char*)out + 0x4) = *(f32*)((char*)src + 0x3c);
        *(s8*)((char*)out + 0x2) = (int)*(s8*)((char*)src + 0x53);
        return 1;
    }
    return 0;
}
#pragma opt_loop_invariants off
#pragma opt_propagation off
int fn_802A87CC(GameObject* obj, char* cam, f32* out, f32* vec, f32 fa, f32 fb)
{
    f32* pl;
    f32* dp;
    char* cp;
    f32* px2;
    f32* py2;
    f32* pz2;
    int inner;
    f32* b6b8;
    s8 mode;
    int wallHit;
    int tris;
    int verts;
    void* parent;

    f32 x2;
    f32 x1;
    f32 z2;
    f32 z1;
    f32 y2;
    f32 y1;
    TrackGroundHit** list;
    f32 planes[8];
    struct
    {
        f32 x;
        f32 y;
        f32 z;
    } probe;
    f32 dists[2];

    mode = 0;
    inner = *(int*)&obj->extra;
    if (fa <= ((PlayerState*)inner)->baddie.animSpeedA * fb || fa <= 3.5f)
    {
        s8 st = *(s8*)((char*)cam + 0x50);
        if (st == 2 || st == 0x11)
        {
            mode = 4;
        }
        else if (((PlayerState*)inner)->baddie.animSpeedA >= 1.2530199f)
        {
            mode = 5;
        }
        else if (st != 4)
        {
            mode = 4;
        }
    }
    out[7] = ((GameObject*)cam)->anim.worldPosY;
    out[8] = ((GameObject*)cam)->anim.worldPosZ;
    out[9] = ((GameObject*)cam)->anim.velocityX;
    out[7] = -out[7];
    out[8] = -out[8];
    out[9] = -out[9];
    out[10] = -((GameObject*)cam)->anim.velocityY;
    out[0xb] = vec[0];
    out[0xc] = vec[1];
    out[0xd] = vec[2];
    parent = *(void**)cam;
    if (mode == 4)
    {
        f32 thresh;
        int i;
        int j;
        int j8;
        wallHit = 0;
        if (parent != NULL)
        {
            tris = *(int*)((char*)*(int*)((char*)parent + 0x50) + 0x34);
            verts = *(int*)((char*)*(int*)((char*)parent + 0x50) + 0x3c);
        }
        else
        {
            tris = lbl_803DCF34;
            verts = (int)lbl_803DCF38;
        }
        planes[0] = out[9];
        planes[1] = 0.0f;
        planes[2] = -out[7];
        planes[3] = -(planes[0] * *(f32*)((char*)cam + 0x4) + planes[2] * ((GameObject*)cam)->anim.localPosZ);
        planes[4] = -planes[0];
        planes[5] = 0.0f;
        planes[6] = -planes[2];
        planes[7] =
            -(planes[4] * ((GameObject*)cam)->anim.rootMotionScale + planes[6] * ((GameObject*)cam)->anim.worldPosX);
        i = 0;
        pl = planes;
        dp = dists;
        cp = cam;
        b6b8 = &lbl_803DC6B8;
        px2 = &x2;
        py2 = &y2;
        pz2 = &z2;
        thresh = 0.5f;
        do
        {
            f32 dot = ((f32 (*)(f32*, f32*))PSVECDotProduct)(pl, vec);
            *dp = pl[3] + dot;
            if (*dp < thresh + b6b8[1])
            {
                int tri;
                if (*(s16*)(cp + 0x4c) > -1)
                {
                    tri = tris + *(s16*)(cp + 0x4c) * 0x10;
                }
                else
                {
                    tri = 0;
                }
                if ((void*)tri != NULL && ((*(s8*)(tri + 3) & 0x3f) == 5 || (*(s8*)(tri + 3) & 0x3f) == 2))
                {
                    j = *(s16*)(tri + 4) * 0xc;
                    x1 = *(f32*)(verts + j);
                    y1 = 0.0f;
                    j8 = j + 8;
                    z1 = *(f32*)(verts + j8);
                    j = *(s16*)(tri + 6) * 0xc;
                    x2 = *(f32*)(verts + j);
                    y2 = 0.0f;
                    j8 = j + 8;
                    z2 = *(f32*)(verts + j8);
                    if (parent != NULL)
                    {
                        ((void (*)(f32*, f32*, f32*, void*))Obj_TransformLocalPointToWorld)(&x1, &y1, &z1, parent);
                        ((void (*)(f32, f32, f32, f32*, f32*, f32*, void*))Obj_TransformLocalPointToWorld)(
                            x2, y2, z2, px2, py2, pz2, parent);
                    }
                    {
                        f32 dz = z2 - z1;
                        f32 dx = x1 - x2;
                        f32 inv = 1.0f / sqrtf(dz * dz + dx * dx);
                        dz = dz * inv;
                        dx = dx * inv;
                        if (dz * out[7] + dx * out[9] < 0.5f)
                        {
                            wallHit = 1;
                        }
                    }
                }
                else
                {
                    wallHit = 1;
                }
            }
            pl += 4;
            dp++;
            cp += 2;
            i++;
        } while (i < 2);
        if (dists[0] < dists[1])
        {
            *(u8*)((char*)out + 0x5f) = 0;
        }
        else
        {
            *(u8*)((char*)out + 0x5f) = 1;
        }
        if (wallHit != 0)
        {
            out[0xb] = out[0xb] + ((0.5f + b6b8[1]) - dists[*(u8*)((char*)out + 0x5f)]) *
                                      planes[(u32) * (u8*)((char*)out + 0x5f) * 4];
            out[0xd] = out[0xd] + ((0.5f + b6b8[1]) - dists[*(u8*)((char*)out + 0x5f)]) *
                                      planes[(u32) * (u8*)((char*)out + 0x5f) * 4 + 2];
        }
        out[0x11] = -(out[7] * (0.5f + lbl_803DC6C0) - out[0xb]);
        out[0x13] = -(out[9] * (0.5f + lbl_803DC6C0) - out[0xd]);
        {
            f32 f = 5.0f;
            out[0x14] = f * out[7] + out[0xb];
            out[0x16] = f * out[9] + out[0xd];
        }
        out[1] = ((GameObject*)cam)->anim.localPosX +
                 *(f32*)((char*)cam + 0x48) * (((GameObject*)cam)->anim.localPosY - ((GameObject*)cam)->anim.localPosX);
        probe.x = out[0x14];
        probe.y = out[1];
        probe.z = out[0x16];
        ((void (*)(f32*, f32*, f32*, int))Obj_TransformLocalPointToWorld)(&probe.x, &probe.y, &probe.z,
                                                                          *(int*)&obj->anim.parent);
        {
            int cnt = hitDetectFn_80065e50(obj, probe.x, probe.y, probe.z, &list, 0, 0x201);
            if (cnt != 0)
            {
                TrackGroundHit** pp;
                f32 best = 10000.0f;
                f32 best2 = best;
                int bi = -1;
                int i2 = 0;
                pp = list;
                for (; cnt > 0; cnt--)
                {
                    f32 dy = probe.y - (*pp)->height;
                    if (dy >= 0.0f && (best < 0.0f || dy < best))
                    {
                        best = dy;
                        bi = i2;
                    }
                    if ((*pp)->normalY > 0.707f && dy >= 0.0f && (best2 < 0.0f || dy < best2))
                    {
                        best2 = dy;
                    }
                    pp++;
                    i2++;
                }
                if (best < 40.0f && bi != -1 && list[bi]->normalY <= 0.707f && list[bi]->normalY > 0.175f)
                {
                    return 0;
                }
                if (best2 < 40.0f)
                {
                    return 0;
                }
            }
        }
        probe.x = out[0x11];
        probe.y = out[1];
        probe.z = out[0x13];
        ((void (*)(f32*, f32*, f32*, int))Obj_TransformLocalPointToWorld)(&probe.x, &probe.y, &probe.z,
                                                                          *(int*)&obj->anim.parent);
        if (((int (*)(int, f32, f32, f32, f32*, int))hitDetectFn_800658a4)((int)obj, probe.x, probe.y, probe.z, out + 0x12,
                                                                           0x205) == 0)
        {
            out[0x12] = out[1] - out[0x12];
        }
        else
        {
            out[0x12] = out[1];
        }
        out[2] = ((GameObject*)cam)->anim.localPosX;
        out[0] = out[1] - out[2];
        *(u8*)((char*)out + 0x5e) = *(u8*)((char*)cam + 0x50);
        *(u8*)((char*)out + 0x60) = *(u8*)((char*)cam + 0x53);
        if (obj->anim.parent != NULL)
        {
            ((void (*)(f32, f32, f32, f32*, f32*, f32*))Obj_TransformLocalPointToWorld)(
                out[0xb], out[0xc], out[0xd], out + 0xb, out + 0xc, out + 0xd);
            ((void (*)(f32, f32, f32, f32*, f32*, f32*, int))Obj_TransformLocalPointToWorld)(
                out[0x11], out[0x12], out[0x13], out + 0x11, out + 0x12, out + 0x13,
                *(int*)&obj->anim.parent);
            ((void (*)(f32, f32, f32, f32*, f32*, f32*, int))Obj_TransformLocalPointToWorld)(
                out[0x14], out[0x15], out[0x16], out + 0x14, out + 0x15, out + 0x16,
                *(int*)&obj->anim.parent);
            ((PlayerState*)inner)->leapTargetY =
                ((PlayerState*)inner)->leapTargetY + *(f32*)(*(int*)&obj->anim.parent + 0x10);
            ((PlayerState*)inner)->leapBaseY =
                ((PlayerState*)inner)->leapBaseY + *(f32*)(*(int*)&obj->anim.parent + 0x10);
        }
        *(u8*)((char*)out + 0x61) = 1;
        if (parent != NULL && (((ObjAnimComponent*)parent)->modelInstance->flags & 0x8000) == 0)
        {
            *(void**)((char*)inner + 0x4c4) = parent;
        }
        else
        {
            ((PlayerState*)inner)->groundObject = NULL;
        }
    }
    else
    {
        ((PlayerState*)inner)->groundObject = NULL;
    }
    return mode;
}
#pragma opt_loop_invariants reset
#pragma peephole off
int fn_802A8EE4(int a, int b, int c, int d, int e)
{
    EmitPlane* pl;
    char* cp;
    f32* b6b8;
    f32* pbx;
    f32* pby;
    f32* pbz;
    int tbl1, tbl2;
    void* hit;
    int i;
    int j;
    int k;
    f32 bx, ax, bz, az, by, ay;
    f32 threshold;
    EmitPlane planes[2];

    ((PlayerState*)b)->groundObject = NULL;
    *(f32*)((char*)d + 0x1c) = *(f32*)((char*)c + 0x1c);
    *(f32*)((char*)d + 0x20) = *(f32*)((char*)c + 0x20);
    *(f32*)((char*)d + 0x24) = *(f32*)((char*)c + 0x24);
    *(f32*)((char*)d + 0x28) = *(f32*)((char*)c + 0x28);
    *(u8*)((char*)d + 0x60) = *(u8*)((char*)c + 0x53);
    hit = *(void**)((char*)c + 0x0);
    if (hit != NULL)
    {
        tbl1 = *(int*)((char*)*(int*)((char*)hit + 0x50) + 0x34);
        tbl2 = *(int*)((char*)*(int*)((char*)hit + 0x50) + 0x3c);
    }
    else
    {
        tbl1 = lbl_803DCF34;
        tbl2 = (int)lbl_803DCF38;
    }
    planes[0].nx = -*(f32*)((char*)d + 0x24);
    planes[0].ny = lbl_803E7EA4;
    planes[0].nz = *(f32*)((char*)d + 0x1c);
    planes[0].d = -(planes[0].nx * *(f32*)((char*)c + 0x4) + planes[0].nz * *(f32*)((char*)c + 0x14));
    planes[1].nx = -planes[0].nx;
    planes[1].ny = lbl_803E7EA4;
    planes[1].nz = -planes[0].nz;
    planes[1].d = -(planes[1].nx * *(f32*)((char*)c + 0x8) + planes[1].nz * *(f32*)((char*)c + 0x18));
    i = 0;
    pl = planes;
    cp = (char*)c;
    b6b8 = &lbl_803DC6B8;
    pbx = &bx;
    pby = &by;
    pbz = &bz;
    threshold = lbl_803E7E98;
    do
    {
        f32 dot = ((f32 (*)(void*, void*))PSVECDotProduct)(pl, (void*)e);
        if (pl->d + dot < threshold + b6b8[1])
        {
            void* face;
            if (*(s16*)(cp + 0x4c) > -1)
            {
                face = (void*)(tbl1 + *(s16*)(cp + 0x4c) * 0x10);
            }
            else
            {
                face = NULL;
            }
            if (face != NULL &&
                (((s8) * (s8*)((char*)face + 0x3) & 0x3f) == 6 || ((s8) * (s8*)((char*)face + 0x3) & 0x3f) == 0x10))
            {
                j = *(s16*)((char*)face + 0x4) * 0xc;
                ax = *(f32*)(tbl2 + j);
                ay = lbl_803E7EA4;
                k = j + 8;
                az = *(f32*)(tbl2 + k);
                j = *(s16*)((char*)face + 0x6) * 0xc;
                bx = *(f32*)(tbl2 + j);
                by = lbl_803E7EA4;
                k = j + 8;
                bz = *(f32*)(tbl2 + k);
                if (hit != NULL)
                {
                    ((void (*)(f32, f32, f32, f32*, f32*, f32*, void*))Obj_TransformLocalPointToWorld)(ax, ay, az, &ax,
                                                                                                       &ay, &az, hit);
                    ((void (*)(f32, f32, f32, f32*, f32*, f32*, void*))Obj_TransformLocalPointToWorld)(bx, by, bz, pbx,
                                                                                                       pby, pbz, hit);
                }
                {
                    f32 dz = bz - az;
                    f32 dx = ax - bx;
                    f32 scale = lbl_803E7EE0 / sqrtf(dz * dz + dx * dx);
                    dz = dz * scale;
                    dx = dx * scale;
                    if (dz * *(f32*)((char*)d + 0x1c) + dx * *(f32*)((char*)d + 0x24) < lbl_803E7E98)
                    {
                        return 0;
                    }
                }
            }
            else
            {
                return 0;
            }
        }
        pl++;
        cp += 2;
        i++;
    } while (i < 2);
    *(f32*)((char*)d + 0x2c) = *(f32*)((char*)e + 0x0);
    *(f32*)((char*)d + 0x30) = *(f32*)((char*)e + 0x4);
    *(f32*)((char*)d + 0x34) = *(f32*)((char*)e + 0x8);
    {
        f32 e2;
        f32 e3;
        *(f32*)((char*)d + 0x44) =
            -(*(f32*)((char*)d + 0x1c) * ((e2 = lbl_803E7E98) + (e3 = lbl_803DC6C0)) - *(f32*)((char*)d + 0x2c));
        *(f32*)((char*)d + 0x4c) = -(*(f32*)((char*)d + 0x24) * (e2 + lbl_803DC6C0) - *(f32*)((char*)d + 0x34));
    }
    {
        f32 f = lbl_803E7F10;
        *(f32*)((char*)d + 0x50) = f * *(f32*)((char*)d + 0x1c) + *(f32*)((char*)d + 0x2c);
        *(f32*)((char*)d + 0x58) = f * *(f32*)((char*)d + 0x24) + *(f32*)((char*)d + 0x34);
    }
    *(f32*)((char*)d + 0x38) = ((PlayerState*)b)->savedPosX;
    *(f32*)((char*)d + 0x3c) = lbl_803E7EA4;
    *(f32*)((char*)d + 0x40) = ((PlayerState*)b)->savedPosZ;
    *(f32*)((char*)d + 0x4) =
        *(f32*)((char*)c + 0x48) * (*(f32*)((char*)c + 0x40) - *(f32*)((char*)c + 0x3c)) + *(f32*)((char*)c + 0x3c);
    *(u8*)((char*)d + 0x5e) = *(u8*)((char*)c + 0x50);
    *(u8*)((char*)d + 0x61) = 1;
    if (((int (*)(int, f32, f32, f32, char*, int))hitDetectFn_800658a4)(
            a, *(f32*)((char*)d + 0x44), *(f32*)((char*)d + 0x4), *(f32*)((char*)d + 0x4c), (char*)d + 0x48, 0x205) ==
        0)
    {
        *(f32*)((int)d + 0x48) = *(f32*)((char*)d + 0x4) - *(f32*)((int)d + 0x48);
    }
    else
    {
        return 0;
    }
    if ((s8) * (s8*)((char*)c + 0x50) != 0x10)
    {
        *(f32*)((char*)d + 0x8) = ((GameObject*)a)->anim.previousLocalPosY;
        *(f32*)((char*)d + 0x0) = *(f32*)((char*)d + 0x4) - *(f32*)((char*)d + 0x8);
        if ((((PlayerState*)b)->flags3F1 & 1) != 0u)
        {
            if (hit != NULL && (((ObjAnimComponent*)hit)->modelInstance->flags & 0x8000) == 0)
            {
                ((PlayerState*)b)->groundObject = (GameObject*)hit;
            }
            if (*(f32*)((char*)d + 0x0) <= lbl_803E80C8)
            {
                if (*(f32*)((char*)d + 0x0) > lbl_803E80C4)
                {
                    return 2;
                }
            }
            if (*(f32*)((char*)d + 0x0) <= lbl_803E80C4 && *(f32*)((char*)d + 0x0) >= lbl_803E8018)
            {
                return 3;
            }
        }
        else
        {
            f32 q;
            q = *(f32*)((char*)c + 0x48) * (*(f32*)((char*)c + 0x10) - *(f32*)((char*)c + 0xc)) +
                *(f32*)((char*)c + 0xc);
            q = *(f32*)((char*)d + 0x4) - q;
            if (*(f32*)((char*)d + 0x0) >= lbl_803E7ED8 && *(f32*)((char*)d + 0x0) <= lbl_803E7FBC && q >= lbl_803E80C4)
            {
                if (hit != NULL && (((ObjAnimComponent*)hit)->modelInstance->flags & 0x8000) == 0)
                {
                    ((PlayerState*)b)->groundObject = (GameObject*)hit;
                }
                return 6;
            }
        }
    }
    else
    {
        *(f32*)((char*)d + 0x8) = ((GameObject*)a)->anim.localPosY;
        *(f32*)((char*)d + 0x0) = *(f32*)((char*)d + 0x4) - *(f32*)((char*)d + 0x8);
        if (*(f32*)((char*)d + 0x0) >= lbl_803E8044)
        {
            return 0;
        }
        if (hit != NULL && (((ObjAnimComponent*)hit)->modelInstance->flags & 0x8000) == 0)
        {
            ((PlayerState*)b)->groundObject = (GameObject*)hit;
        }
        return 3;
    }
    return 0;
}
#pragma opt_propagation reset
#pragma peephole reset

void fn_802A93F4(GameObject* obj, int p2, int p3)
{
    PlayerState* inner = obj->extra;
    f32 dist;
    void* found;
    s16* vec;
    ObjTextureRuntimeSlot* tex;
    dist = lbl_803E80CC;
    obj->anim.rootMotionScale = lbl_803E7EE0;
    viewFinderSetZoom(Camera_GetFovY());
    obj->objectFlags &= ~OBJECT_OBJFLAG_PARENT_SLACK;
    obj->anim.alpha = 0xff;
    ((ByteFlags*)((char*)inner + 0x3f2))->b80 = 0;
    if (((ByteFlags*)((char*)inner + 0x3f2))->b40)
    {
        inner->targetSuppressTimer = lbl_803E7FBC;
    }
    ((ByteFlags*)((char*)inner + 0x3f2))->b40 = 0;
    ((ByteFlags*)((char*)inner + 0x3f2))->b20 = 0;
    ((ByteFlags*)((char*)inner + 0x3f4))->b80 = 0;
    ObjHits_EnableObject(obj);
    obj->anim.velocityY = lbl_803E7EA4;
    if ((*(s16*)((char*)p3 + 0x6e) & 1) != 0)
    {
        fn_802AB5A4(obj, (int)inner, 7);
    }
    ObjModelChain_SetEnabled((ObjModelChain*)gPlayerModelChain, 1);
    inner->unk8C4 = 2;
    if (gPlayerChildObject != NULL)
    {
        found = (void*)ObjGroup_FindNearestObject(BABYCLOUDRUNNER_OBJGROUP, (int)obj, &dist);
        if (found != NULL)
        {
            (*(void (*)(void*))(*(int*)((char*)*(int*)*(int*)((char*)found + 0x68) + 0x24)))(found);
        }
        ObjLink_DetachChild(obj, (int)gPlayerChildObject);
        Obj_FreeObject((GameObject*)gPlayerChildObject);
        gPlayerChildObject = NULL;
    }
    *(u32*)&((PlayerState*)inner)->flags360 |= PLAYER_FLAG_TELEPORTED;
    inner->interactObject = 0;
    ((ByteFlags*)((char*)inner + 0x3f0))->b10 = 0;
    ((ByteFlags*)((char*)inner + 0x3f0))->b08 = 0;
    ((ByteFlags*)((char*)inner + 0x3f0))->b04 = 0;
    inner->staffHoldFrames = 0;
    ((ByteFlags*)((char*)inner + 0x3f0))->b80 = 0;
    ((ByteFlags*)((char*)inner + 0x3f0))->b40 = 0;
    ((ByteFlags*)((char*)inner + 0x3f0))->b20 = 0;
    inner->animState = -1;
    ((ByteFlags*)((char*)inner + 0x3f6))->b40 = 0;
    staffFn_80170380(gPlayerStaffObject, 2);
    ((ByteFlags*)((char*)inner + 0x3f0))->b02 = 0;
    *(u32*)&((PlayerState*)inner)->flags360 |= PLAYER_FLAG_TELEPORTED;
    ObjHits_SyncObjectPositionIfDirtyLegacy(obj);
    inner->waterDepth = lbl_803E7EA4;
    inner->waterSurfaceY = lbl_803E80D0;
    inner->idleDelayTimer = lbl_803E7FA4;
    inner->baddie.physicsActive = 1;
    *(int*)((char*)inner + 0x4) &= ~0x100000;
    *(int*)((char*)inner + 0x4) |= 0x8000000;
    if (*(s8*)(*(int*)((char*)*(int*)&obj->extra + 0x35c)) <= 0)
    {
        (*(void (*)(int, int, int))(*(int*)((char*)*gPlayerInterface + 0x14)))((int)obj, (int)inner, 3);
        *(int*)&((PlayerState*)inner)->baddie.unk304 = 0;
    }
    vec = (s16*)objModelGetVecFn_800395d8(obj, 1);
    if (vec != NULL)
    {
        vec[0] = 0;
        vec[1] = 0;
        vec[2] = 0;
    }
    ObjModel_ClearBlendChannels(Obj_GetActiveModel(obj));
    tex = objFindTexture(obj, 1, 0);
    tex->offsetS = 0;
    tex->offsetT = 0;
    tex = objFindTexture(obj, 0, 0);
    tex->offsetS = 0;
    tex->offsetT = 0;
}

void playerCastIceSpell(void)
{
    ObjPlacement* setup;
    s8 i;

    if (!Obj_IsLoadingLocked())
        return;
    for (i = 0; i < 7; i++)
    {
        if (gPlayerSpawnedObjects[i] == NULL)
        {
            setup = Obj_AllocObjectSetup(0x24, 0x4ec);
            ObjPath_GetPointWorldPosition(gPlayerPathObject, 0, &setup->posX, &setup->posY, &setup->posZ, 0);
            setup->color[0] = 2;
            setup->color[1] = 1;
            setup->color[2] = 0xff;
            setup->color[3] = 0xff;
            *(s16*)((char*)setup + 0x1a) = (s16)(i * 3);
            *(s16*)((char*)setup + 0x1c) = 0;
            gPlayerSpawnedObjects[i] = Obj_SetupObject(setup, 5, -1, -1, NULL);
        }
    }
}
#pragma dont_inline on
int fn_802A97D0(GameObject* obj, int p2)
{
    PlayerState* inner = obj->extra;
    void* slot;
    u8 af;
    u8 c;
    s16 sel = ((PlayerState*)p2)->baddie.controlMode;

    if (!((sel != 1 && sel != 2 && sel != 0x26) || !mainGetBit(GAMEBIT_STAFF_ABILITY_STAFF_BOOSTER) ||
          (slot = inner->cameraTargetObject) == NULL || *(s16*)((char*)slot + 0x46) != 0x64f ||
          ((af = *(u8*)((char*)slot + 0xaf)) & 4) == 0 || (af & 0x18) != 0 ||
          ((PlayerState*)p2)->baddie.targetObj != NULL || (c = inner->curAnimId) == 0x48 || c == 0x47 || c == 0x44 ||
          *(void**)((char*)inner + 0x7f8) != NULL || ((ByteFlags*)((char*)inner + 0x3f0))->b20 ||
          ((ByteFlags*)((char*)inner + 0x3f0))->b04 || ((ByteFlags*)((char*)inner + 0x3f0))->b08 ||
          ((ByteFlags*)((char*)inner + 0x3f4))->b40 == 0 ||
          *(s16*)((char*)*(int*)((char*)*(int*)&obj->extra + 0x35c) + 4) < 0xa))
    {
        return 1;
    }
    return 0;
}
int playerCanCastPortalOpenSpell(GameObject* obj, int p2)
{
    PlayerState* inner = obj->extra;
    s16 sel = ((PlayerState*)p2)->baddie.controlMode;

    if (sel == 1 || sel == 2)
    {
        void* slot = inner->cameraTargetObject;
        u8 af;
        u8 c;
        if (slot == NULL || *(s16*)((char*)slot + 0x46) != 0x414 || ((af = *(u8*)((char*)slot + 0xaf)) & 4) == 0 ||
            (af & 0x18) != 0)
        {
            return 0;
        }
        if (((PlayerState*)p2)->baddie.targetObj != NULL || (c = inner->curAnimId) == 0x48 || c == 0x47 || c == 0x44 ||
            *(void**)((char*)inner + 0x7f8) != NULL || ((ByteFlags*)((char*)inner + 0x3f0))->b20 ||
            ((ByteFlags*)((char*)inner + 0x3f0))->b04 || ((ByteFlags*)((char*)inner + 0x3f0))->b08 ||
            ((ByteFlags*)((char*)inner + 0x3f4))->b40 == 0 || *(s16*)((char*)inner->playerStatus + 4) < 0x14 ||
            !mainGetBit(GAMEBIT_STAFF_ABILITY_OPEN_PORTAL))
        {
            return 0;
        }
        return 1;
    }
    return 0;
}
int playerCanCastQuakeSpell(GameObject* obj, int p2)
{
    PlayerState* inner = obj->extra;
    int threshold;
    if (mainGetBit(GAMEBIT_STAFF_ABILITY_SUPER_QUAKE))
    {
        threshold = 0x14;
    }
    else
    {
        threshold = 0xa;
    }
    if (mainGetBit(GAMEBIT_STAFF_ABILITY_GROUND_QUAKE) == 0 ||
        *(s16*)((char*)*(int*)((char*)*(int*)&obj->extra + 0x35c) + 4) < threshold || inner->curAnimId == 0x44 ||
        *(void**)((char*)inner + 0x7f8) != NULL || ((ByteFlags*)((char*)inner + 0x3f0))->b20 ||
        ((ByteFlags*)((char*)inner + 0x3f0))->b04 || ((ByteFlags*)((char*)inner + 0x3f0))->b08 ||
        ((ByteFlags*)((char*)inner + 0x3f4))->b40 == 0)
    {
        return 0;
    }
    {
        s16 v;
        if ((v = ((PlayerState*)p2)->baddie.controlMode) == 1 || v == 2 || v == 0x25 || v == 0x24)
        {
            return 1;
        }
    }
    return 0;
}
int playerCanCastBlasterSpell(GameObject* obj, int p2, int p3)
{
    PlayerState* inner = obj->extra;
    u8 c;
    int v;
    if ((c = inner->curAnimId) == 0x48 || c == 0x47 || c == 0x44 || *(void**)((char*)inner + 0x7f8) != NULL ||
        ((ByteFlags*)((char*)inner + 0x3f0))->b20 || ((ByteFlags*)((char*)inner + 0x3f0))->b04 ||
        ((ByteFlags*)((char*)inner + 0x3f0))->b08 || ((ByteFlags*)((char*)inner + 0x3f4))->b40 == 0)
    {
        return 0;
    }
    if (p3 == GAMEBIT_STAFF_ABILITY_FIRE_BLASTER)
    {
        if (*(s16*)((char*)inner->playerStatus + 4) < 2)
            return 0;
    }
    else
    {
        if (*(s16*)((char*)inner->playerStatus + 4) < 1)
            return 0;
    }
    if ((v = ((PlayerState*)p2)->baddie.controlMode) == 1 || v == 2 || v == 0x2a || v == 0x2c || (u16)(v - 0x2e) <= 1 ||
        v == 0x2d)
    {
        return 1;
    }
    return 0;
}

int playerIsBlasterSpellAvailable(GameObject* obj, int p2, int p3)
{
    PlayerState* inner = obj->extra;
    u8 c;
    int v;
    if ((c = inner->curAnimId) == 0x48 || c == 0x47 || c == 0x44 || *(void**)((char*)inner + 0x7f8) != NULL ||
        ((ByteFlags*)((char*)inner + 0x3f0))->b20 || ((ByteFlags*)((char*)inner + 0x3f0))->b04 ||
        ((ByteFlags*)((char*)inner + 0x3f0))->b08 || ((ByteFlags*)((char*)inner + 0x3f4))->b40 == 0)
    {
        return 0;
    }
    if (p3 == GAMEBIT_STAFF_ABILITY_FIRE_BLASTER)
    {
        if (*(s16*)((char*)inner->playerStatus + 4) < 2)
            return 0;
    }
    else
    {
        if (*(s16*)((char*)inner->playerStatus + 4) < 1)
            return 0;
    }
    if ((v = ((PlayerState*)p2)->baddie.controlMode) == 1 || v == 2 || (u16)(v - 0x24) <= 1 || (u16)(v - 0x2a) <= 2 ||
        (u16)(v - 0x2e) <= 1 || v == 0x2d)
    {
        return 1;
    }
    return 0;
}
#pragma dont_inline reset

void fn_802A9D0C(int p1, int p2, int p3, int p4, int p5, int p6, int p7, int p8)
{
    void* vec;
    s16 v;
    f32 a, b, c;
    int d, e, flag;
    s16 angle;
    int clamped;
    int inner;
    if (p8 != 0)
    {
        vec = (void*)objModelGetVecFn_800395d8((GameObject*)(p1), 0);
        if (vec != NULL)
        {
            v = *(s16*)((char*)vec + 0x2);
            if (v > 0)
            {
                *(s16*)((char*)vec + 0x2) -= (s16)(lbl_803E8050 * timeDelta);
                if (*(s16*)((char*)vec + 0x2) < 0)
                {
                    *(s16*)((char*)vec + 0x2) = 0;
                }
            }
            else
            {
                *(s16*)((char*)vec + 0x2) += (s16)(lbl_803E8050 * timeDelta);
                if (*(s16*)((char*)vec + 0x2) > 0)
                {
                    *(s16*)((char*)vec + 0x2) = 0;
                }
            }
        }
        (*(void (*)(int, int, int, int, int, int))(*(int*)((char*)*(int*)*(int*)((char*)p3 + 0x68) + 0x10)))(
            p3, p4, p5, p6, p7, -1);
        ((GameObject*)p1)->anim.previousWorldPosX = ((GameObject*)p1)->anim.worldPosX;
        ((GameObject*)p1)->anim.previousWorldPosY = ((GameObject*)p1)->anim.worldPosY;
        ((GameObject*)p1)->anim.previousWorldPosZ = ((GameObject*)p1)->anim.worldPosZ;
        ((GameObject*)p1)->anim.previousLocalPosX = ((GameObject*)p1)->anim.localPosX;
        ((GameObject*)p1)->anim.previousLocalPosY = ((GameObject*)p1)->anim.localPosY;
        ((GameObject*)p1)->anim.previousLocalPosZ = ((GameObject*)p1)->anim.localPosZ;
    }
    (*(void (*)(int, f32*, f32*, f32*))(*(int*)((char*)*(int*)*(int*)((char*)p3 + 0x68) + 0x28)))(p3, &a, &b, &c);
    ((GameObject*)p1)->anim.localPosX = a;
    ((GameObject*)p1)->anim.localPosY = b;
    ((GameObject*)p1)->anim.localPosZ = c;
    inner = *(int*)&((GameObject*)p1)->extra;
    if (((PlayerState*)inner)->baddie.controlMode != 0x18 &&
        (((GameObject*)p1)->objectFlags & OBJECT_OBJFLAG_PARENT_SLACK) == 0)
    {
        flag = 1;
        (*(void (*)(int, int, int*))(*(int*)((char*)*(int*)*(int*)((char*)p3 + 0x68) + 0x54)))(p3, 2, &d);
        angle = (s16)(((PlayerState*)p2)->targetYaw - (u16)d);
        if (angle > 0x8000)
        {
            angle = angle - 0xFFFF;
        }
        if (angle < -0x8000)
        {
            angle = angle + 0xFFFF;
        }
        (*(void (*)(int, int, int*))(*(int*)((char*)*(int*)*(int*)((char*)p3 + 0x68) + 0x54)))(p3, 3, &e);
        clamped = (angle < (s16)-e) ? (s16)-e : ((angle > (s16)e) ? (s16)e : angle);
        ((PlayerState*)p2)->targetYaw = (s16)d + clamped;
        (*(void (*)(int, int, int*))(*(int*)((char*)*(int*)*(int*)((char*)p3 + 0x68) + 0x54)))(p3, 4, &flag);
        if (flag != 0)
        {
            ((GameObject*)p1)->anim.rotY = ((GameObject*)p3)->anim.rotY;
            ((GameObject*)p1)->anim.rotZ = ((GameObject*)p3)->anim.rotZ;
        }
    }
    else
    {
        ((GameObject*)p1)->anim.rotY = ((GameObject*)p3)->anim.rotY;
        ((GameObject*)p1)->anim.rotZ = ((GameObject*)p3)->anim.rotZ;
        ((PlayerState*)p2)->targetYaw = ((GameObject*)p3)->anim.rotX;
    }
    v = ((PlayerState*)p2)->targetYaw;
    ((PlayerState*)p2)->yaw = v;
    ((GameObject*)p1)->anim.rotX = v;
    ((GameObject*)p1)->anim.worldPosX = ((GameObject*)p1)->anim.localPosX;
    ((GameObject*)p1)->anim.worldPosY = ((GameObject*)p1)->anim.localPosY;
    ((GameObject*)p1)->anim.worldPosZ = ((GameObject*)p1)->anim.localPosZ;
    ((GameObject*)p1)->anim.velocityX = *(f32*)((char*)p3 + 0x24);
    ((GameObject*)p1)->anim.velocityY = *(f32*)((char*)p3 + 0x28);
    ((GameObject*)p1)->anim.velocityZ = *(f32*)((char*)p3 + 0x2c);
    fn_802AB5A4((GameObject*)p1, p2, 7);
}

void fn_802AA014(GameObject* obj)
{
    void* o;
    int slot;
    PlayerState* inner;
    ObjPlacement* setup;

    inner = obj->extra;
    slot = (int)Camera_GetCurrentViewSlot();
    if (Obj_IsLoadingLocked())
    {
        f32 v[3];

        setup = (ObjPlacement*)Obj_AllocObjectSetup(0x24, 0x14b);
        *(u8*)((char*)setup + 4) = 2;
        *(u8*)((char*)setup + 5) = 1;
        *(u8*)((char*)setup + 6) = 0xff;
        *(u8*)((char*)setup + 7) = 0xff;
        setup->posX = *(f32*)((char*)slot + 0xc);
        setup->posY = *(f32*)((char*)slot + 0x10);
        setup->posZ = *(f32*)((char*)slot + 0x14);
        Sfx_PlayFromObject((int)obj, SFXTRIG_staff_rocket_hitdirt);
        o = Obj_SetupObject(setup, 5, -1, -1, NULL);
        if (o != NULL)
        {
            f32 fov, ycomp, cot, aspect, xcomp, len;
            f32 scale;
            f32 mix;
            f32 t;
            int res, h2, hw;

            *(s16*)((char*)o + 6) |= 0x2000;
            res = getScreenResolution();
            hw = res >> 17;
            *(s16*)((char*)o + 0) = *(s16*)((char*)slot + 0);
            t = Camera_GetFovY();
            t *= lbl_803E80D4;
            fov = (gPlayerPi * t) / lbl_803E7F98;
            cot = mathSinf(fov);
            cot = lbl_803E7F5C * (cot / mathCosf(fov));
            aspect = Camera_GetAspectRatio();
            h2 = (u16)res >> 1;
            t = (inner->aimScreenY - (f32)h2) / (f32)h2;
            t *= aspect;
            ycomp = cot * -t;
            xcomp = cot * ((inner->aimScreenX - (f32)hw) / (f32)hw);
            len = sqrtf(lbl_803E80AC + (ycomp * ycomp + xcomp * xcomp));
            v[0] = ycomp / len;
            v[1] = xcomp / len;
            v[2] = lbl_803E7F5C / len;
            Matrix_TransformVector(fn_8000E814(), v, v);
            *(f32*)((char*)o + 0x24) = v[0] * (scale = lbl_803E80D8);
            *(f32*)((char*)o + 0x28) = v[1] * scale;
            *(f32*)((char*)o + 0x2c) = v[2] * scale;
            mix = lbl_803E7ED4;
            *(f32*)((char*)o + 0xc) = *(f32*)((char*)o + 0x18) =
                mix * *(f32*)((char*)o + 0x24) + *(f32*)((char*)slot + 0xc);
            *(f32*)((char*)o + 0x10) = *(f32*)((char*)o + 0x1c) =
                mix * *(f32*)((char*)o + 0x28) + *(f32*)((char*)slot + 0x10);
            *(f32*)((char*)o + 0x14) = *(f32*)((char*)o + 0x20) =
                mix * *(f32*)((char*)o + 0x2c) + *(f32*)((char*)slot + 0x14);
            *(s16*)((char*)o + 2) = *(s16*)((char*)slot + 2) / 2;
            *(s16*)((char*)o + 0) = -*(s16*)((char*)slot + 0);
            *(int*)((char*)o + 0xf4) = 0x64;
        }
    }
}

#pragma opt_propagation off
void fn_802AA2B0(int obj, int state, f32 unused, f32 yoff)
{
    int slot = 1;
    ObjPlacement* setup;
    f32 x1, y1, z1, x0, y0, z0;
    f32 dx, dy, dz, len;

    Camera_GetCurrentViewSlot();
    if (Obj_IsLoadingLocked() != 0)
    {
        Sfx_PlayFromObject(0, SFXTRIG_staff_rocket_hitdirt);
        setup = Obj_AllocObjectSetup(0x24, 0x655);
        setup->color[0] = 2;
        setup->color[1] = 1;
        setup->color[2] = 0xff;
        setup->color[3] = 0xff;
        ObjPath_GetPointWorldPosition((GameObject*)gPlayerPathObject, 0, &x0, &y0, &z0, 0);
        setup->posX = x0 + yoff;
        setup->posY = y0 + yoff;
        setup->posZ = z0 + yoff;
        setup = (ObjPlacement*)Obj_SetupObject(setup, 5, -1, -1, NULL);
        if (setup != NULL)
        {
            ObjPath_GetPointWorldPosition((GameObject*)gPlayerPathObject, 0, &x0, &y0, &z0, 0);
            ObjPath_GetPointWorldPosition((GameObject*)gPlayerPathObject, 1, &x1, &y1, &z1, 0);
            dx = x0 - x1;
            dy = y0 - y1;
            dz = z0 - z1;
            len = sqrtf(dx * dx + dy * dy + dz * dz);
            dx = dx / len;
            dy = dy / len;
            dz = dz / len;
            *(s16*)setup = (s16)getAngle(dx, dz);
            setup->unk02 = (s16)(-getAngle(dy, sqrtf(dx * dx + dz * dz)));
            setup->posX = setup->posX * lbl_803E7EF0;
            arwprojectile_placeForward((GameObject*)setup, lbl_803E7ED8);
            arwprojectile_setLifetime((GameObject*)setup, 0x32);
            if (slot == 1)
            {
                arwprojectile_createLinkedEffect((GameObject*)setup, 1);
            }
        }
    }
}
#pragma opt_propagation reset

void staffShootFireball(GameObject* obj, int state, f32 unused)
{
    int spawned = 0;
    PlayerState* inner = obj->extra;
    GameObject* fb;
    int slot;
    ObjPlacement* setup;
    f32 vec[3];
    MatrixTransform v;
    f32 mtx[16];

    slot = (int)Camera_GetCurrentViewSlot();
    if (Obj_IsLoadingLocked())
    {
        Sfx_PlayFromObject((int)obj, SFXTRIG_wp_hitpos_6_20a);
        setup = Obj_AllocObjectSetup(0x24, 0x14b);
        *(u8*)((char*)setup + 0x4) = 2;
        *(u8*)((char*)setup + 0x5) = 1;
        *(u8*)((char*)setup + 0x6) = 0xff;
        *(u8*)((char*)setup + 0x7) = 0xff;
        if (((PlayerState*)state)->baddie.targetObj != NULL)
        {
            ObjPath_GetPointWorldPosition(gPlayerPathObject, 0, (f32*)((char*)setup + 0x8), (f32*)((char*)setup + 0xc),
                                          (f32*)((char*)setup + 0x10), 0);
        }
        else
        {
            ((ObjPlacement*)setup)->posX = *(f32*)((char*)slot + 0xc);
            ((ObjPlacement*)setup)->posY = *(f32*)((char*)slot + 0x10);
            ((ObjPlacement*)setup)->posZ = *(f32*)((char*)slot + 0x14);
        }
        *(s8*)((char*)setup + 0x19) = (s8)(*(int (*)(void*))(
            *(int*)((char*)*(int*)(*(int*)((char*)gPlayerPathObject + 0x68)) + 0x44)))(gPlayerPathObject);
        if (((PlayerState*)state)->baddie.targetObj == NULL)
        {
            *(s16*)((char*)setup + 0x1a) = 1;
        }
        fb = Obj_SetupObject(setup, 5, -1, -1, NULL);
        if (fb == NULL)
        {
            return;
        }
        fb->anim.flags = fb->anim.flags | 0x2000;
        if (((PlayerState*)state)->baddie.targetObj != NULL)
        {
            ObjHitVolumeRuntimeTransform* pt;
            GameObject* target;
            f32 dx;
            f32 dz;
            f32 dy;
            target = *(GameObject**)&((PlayerState*)state)->baddie.targetObj;
            spawned = (int)target;
            pt = &target->anim.hitVolumeTransforms[target->hitVolumeIndex];
            dx = pt->jointX - ((GameObject*)gPlayerPathObject)->anim.localPosX;
            dy = pt->jointY - ((GameObject*)gPlayerPathObject)->anim.localPosY;
            dz = pt->jointZ - ((GameObject*)gPlayerPathObject)->anim.localPosZ;
            v.x = 0.0f;
            v.y = 0.0f;
            v.z = 0.0f;
            v.scale = 1.0f;
            v.rotX = inner->targetYaw;
            v.rotY = (s16)getAngle(dy, sqrtf(dx * dx + dz * dz));
            v.rotZ = 0;
            if (obj->anim.parent != NULL)
            {
                v.rotX = v.rotX + *(s16*)(*(int*)&obj->anim.parent);
            }
            setMatrixFromObjectPos(mtx, &v);
            Matrix_TransformPoint(mtx, 0.0f, 0.0f, -10.0f, &fb->anim.velocityX, &fb->anim.velocityY,
                                  &fb->anim.velocityZ);
            fb->anim.worldPosX = fb->anim.localPosX;
            fb->anim.worldPosY = fb->anim.localPosY;
            fb->anim.worldPosZ = fb->anim.localPosZ;
            fb->anim.rotX = inner->targetYaw;
            fb->anim.rotY = *(s16*)((char*)slot + 0x2) / 2;
        }
        else
        {
            int res = getScreenResolution();
            int half = res >> 17;
            f32 fov;
            f32 cot;
            f32 fx;
            f32 mag;
            fb->anim.rotX = *(s16*)((char*)slot + 0x0);
            fov = Camera_GetFovY();
            fov *= 91.022f;
            fov = gPlayerPi * fov / 32768.0f;
            {
                f32 sn = mathSinf(fov);
                cot = 100.0f * (sn / mathCosf(fov));
            }
            fx = cot * -((inner->aimScreenY - (f32)(int)((res & 0xffff) >> 1)) / (f32)(int)((res & 0xffff) >> 1) *
                         Camera_GetAspectRatio());
            cot = cot * ((inner->aimScreenX - (f32)half) / (f32)half);
            mag = sqrtf(10000.0f + (fx * fx + cot * cot));
            vec[0] = fx / mag;
            vec[1] = cot / mag;
            vec[2] = 100.0f / mag;
            Matrix_TransformVector(fn_8000E814(), vec, vec);
            fb->anim.velocityX = -10.0f * vec[0];
            fb->anim.velocityY = -10.0f * vec[1];
            fb->anim.velocityZ = -10.0f * vec[2];
            fb->anim.localPosX = fb->anim.worldPosX = 2.0f * fb->anim.velocityX + *(f32*)((char*)slot + 0xc);
            fb->anim.localPosY = fb->anim.worldPosY = 2.0f * fb->anim.velocityY + *(f32*)((char*)slot + 0x10);
            fb->anim.localPosZ = fb->anim.worldPosZ = 2.0f * fb->anim.velocityZ + *(f32*)((char*)slot + 0x14);
            fb->anim.rotY = *(s16*)((char*)slot + 0x2) / 2;
            fb->anim.rotX = -*(s16*)((char*)slot + 0x0);
        }
        *(int*)((char*)fb + 0xf4) = 0x5f;
        *(int*)((char*)fb + 0xf8) = spawned;
    }
}

#pragma dont_inline on
#pragma opt_propagation off
void objDoTeleportAnim(GameObject* obj)
{
    PlayerState* inner = obj->extra;
    struct
    {
        u8 pad[0xc];
        f32 x;
        f32 y;
        f32 z;
    } buf;
    f32 dy;
    f32 base = lbl_803E80C4;
    int i;

    dy = base - inner->teleportAnimProgress;
    buf.y = dy;
    if (lbl_803DE478 < lbl_803E80D8)
    {
        inner->teleportAnimActive = 0;
        return;
    }
    if (dy <= lbl_803E7EA4)
    {
        lbl_803DE478 = lbl_803DE478 - lbl_803E7F14 * timeDelta;
        return;
    }
    lbl_803DE478 = base;
    buf.y = dy + obj->anim.localPosY;
    {
        for (i = 0; i < 10; i++)
        {
            buf.x = obj->anim.localPosX + (f32)randomGetRange(-0x64, 0x64) / lbl_803E7ED8;
            buf.z = obj->anim.localPosZ + (f32)randomGetRange(-0x64, 0x64) / lbl_803E7ED8;
            (*gPartfxInterface)->spawnObject((void*)obj, randomGetRange(0, 2) + 0x3f4, &buf, 1, -1, NULL);
            (*gPartfxInterface)->spawnObject((void*)obj, randomGetRange(0, 2) + 0x3f7, &buf, 1, -1, NULL);
        }
    }
}
#pragma dont_inline reset
#pragma opt_propagation reset

void playerDie(GameObject* obj)
{
    PlayerState* inner = obj->extra;
    ObjPlacement* setup;
    int variant;
    int z[2];
    cutsceneFadeInOut(1);
    setTimeStop(0xff);
    setPendingMapLoad(1);
    if ((u32)obj != 0)
    {
        variant = ((ObjAnimComponent*)obj)->bankIndex != 0;
    }
    else
    {
        variant = 0;
    }
    if (variant != 0)
    {
        setup = Obj_AllocObjectSetup(0x20, 0x882);
    }
    else
    {
        setup = Obj_AllocObjectSetup(0x20, 0x887);
    }
    ((ObjPlacement*)setup)->posX = obj->anim.localPosX;
    ((ObjPlacement*)setup)->posY = obj->anim.localPosY;
    ((ObjPlacement*)setup)->posZ = obj->anim.localPosZ;
    inner->spawnedObject = (int)Obj_SetupObject(setup, 5, -1, -1, NULL);
    ((ByteFlags*)((char*)inner + 0x3f3))->b04 = 0;
    ((ByteFlags*)((char*)inner + 0x3f3))->b02 = 1;
    z[0] = 0;
    lbl_803DE42C = z[0];
    for (z[1] = z[0]; z[1] < 7; z[1]++)
    {
        if (gPlayerSpawnedObjects[z[1]] != NULL)
        {
            Obj_FreeObject((GameObject*)gPlayerSpawnedObjects[z[1]]);
            gPlayerSpawnedObjects[z[1]] = NULL;
        }
    }
    if (gPlayerResource != NULL)
    {
        Resource_Release(gPlayerResource);
        gPlayerResource = NULL;
    }
    *(u32*)&((PlayerState*)inner)->flags360 &= ~PLAYER_FLAG_AIM_READY;
    AudioStream_StopCurrent();
    AudioStream_Play(0x51e0, AudioStream_StartPrepared);
}
#pragma opt_propagation off
#pragma dont_inline on
void fn_802AABE4(int obj)
{
    s16* movp;
    f32* outp;
    ObjModel* model;
    short i;
    s16 out2[3];
    f32 out1[5];

    model = (ObjModel*)((ObjAnimComponent*)obj)->banks[((ObjAnimComponent*)obj)->bankIndex];

    ObjAnim_SetCurrentMove(obj, *(s16*)((PlayerState*)((GameObject*)obj)->extra)->moveAnimTable, lbl_803E7EA4, 0);
    ObjModel_SampleJointTransform(model, 0, 0, lbl_803E7EA4, ((GameObject*)obj)->anim.rootMotionScale, out1, out2);
    lbl_803DAF88[0] = out1[1];

    ObjAnim_SetCurrentMove(obj, lbl_80332F2C[0], lbl_803E7EA4, 0);
    ObjModel_SampleJointTransform(model, 0, 0, lbl_803E7EA4, ((GameObject*)obj)->anim.rootMotionScale, out1, out2);
    lbl_803DAF88[1] = out1[1];

    i = 12;
    movp = (s16*)((char*)lbl_80332F48 + 0x22);
    outp = &lbl_803DAF88[i];
    for (; i <= 15; i++)
    {
        ObjAnim_SetCurrentMove(obj, *movp, lbl_803E7EA4, 0);
        ObjModel_SampleJointTransform(model, 0, 0, lbl_803E7EA4, ((GameObject*)obj)->anim.rootMotionScale, out1, out2);
        *outp = out1[1];
        movp++;
        outp++;
    }
    ObjAnim_WriteStateWord((ObjAnimComponent*)obj, OBJANIM_STATE_INDEX_CURRENT, OBJANIM_STATE_WORD_EVENT_COUNTDOWN, 0);
}
#pragma dont_inline reset
#pragma opt_propagation reset

void playerDrawTeleportAnim(GameObject* obj)
{
    int state = *(int*)&obj->extra;
    u8* vp = gPlayerHudVtxBuf;
    u8* p = vp;
    int i;
    f32 height;
    f32 v;
    struct
    {
        s16 rx, ry, rz, pad;
        f32 scale;
        f32 px, py, pz;
    } xf;
    f32 mtx[16];

    height = ((PlayerState*)state)->teleportAnimProgress;
    setTextColor(0, 0xff, 0xff, 0xff, 0x80);
    textureSetupFn_800799c0();
    textRenderSetupFn_800795e8();
    textRenderSetupFn_80079804();
    fn_80078740();
    GXSetColorUpdate(0);

    i = 0;
    for (; i < 8; i++)
    {
        v = lbl_803E7FA4 * (lbl_803E80C4 - height);
        if (i < 4)
        {
            *(s16*)(p + 2) = 0x320;
        }
        else
        {
            *(s16*)(p + 2) = v;
        }
        if (i < 4)
        {
            *(s16*)(p + 0) = (lbl_803E7FA4 * lbl_802C2BF0[i * 3 + 0]);
            *(s16*)(p + 4) = (lbl_803E7FA4 * lbl_802C2BF0[i * 3 + 2]);
        }
        else
        {
            *(s16*)(p + 0) = (lbl_803E7FA4 * lbl_802C2BF0[i * 3 + 0]);
            *(s16*)(p + 4) = (lbl_803E7FA4 * lbl_802C2BF0[i * 3 + 2]);
        }
        p[0xc] = 0xff;
        p[0xd] = 0;
        p[0xe] = 0;
        p[0xf] = 0x40;
        p += 0x10;
    }

    xf.px = obj->anim.localPosX - playerMapOffsetX;
    xf.py = obj->anim.localPosY;
    xf.pz = obj->anim.localPosZ - playerMapOffsetZ;
    xf.rx = ((PlayerState*)state)->targetYaw;
    xf.ry = 0;
    xf.rz = 0;
    xf.scale = lbl_803E7F6C;
    setMatrixFromObjectTransposed(&xf, mtx);
    PSMTXConcat(Camera_GetViewMatrix(), mtx, mtx);
    GXLoadPosMtxImm((const f32(*)[4])mtx, 0);
    drawFn_8005cf8c((int)vp, lbl_802C2B30, 0xc);

    if (((PlayerState*)state)->teleportAnimProgress >= lbl_803E80E0)
    {
        int t = obj->anim.alpha - (framesThisStep << 2);
        if (t < 0)
        {
            t = 0;
        }
        obj->anim.alpha = t;
    }
    GXSetColorUpdate(1);
}

#pragma dont_inline on
void fn_802AAF80(GameObject* obj, int inner, int a, int b, int c)
{
    int v;
    if (gPlayerPathObject != NULL && (((u32)((PlayerState*)inner)->flags3F4 >> 6) & 1) != 0)
    {
        (*gModgfxInterface)->renderEffects((void*)a, b, c, 1, gPlayerPathObject);
    }
    if (((PlayerState*)inner)->pendingBoneEffectId != 0)
    {
        (*gBoneParticleEffectInterface)
            ->spawnEffect((void*)obj, ((PlayerState*)inner)->pendingBoneEffectId, NULL, 0x64, NULL);
    }
    ((PlayerState*)inner)->pendingBoneEffectId = 0;
    if (((PlayerState*)inner)->teleportAnimActive == 1)
    {
        objDoTeleportAnim(obj);
    }
    if ((*gSkyInterface)->getBlendStateBit20(2) != 0)
    {
        playerUpdatePathEffectCountdown(obj, inner);
    }
    v = ((PlayerState*)inner)->flags360;
    if ((v & 0x60000u) != 0)
    {
        ((PartFxSpawnParams*)gPlayerPartFxParams)->posX = obj->anim.localPosX;
        ((PartFxSpawnParams*)gPlayerPartFxParams)->posY = obj->anim.localPosY;
        ((PartFxSpawnParams*)gPlayerPartFxParams)->posZ = obj->anim.localPosZ;
        if ((v & 0x40000u) != 0)
        {
            (*gPartfxInterface)->spawnObject((void*)obj, 0x427, gPlayerPartFxParams, 0x200001, -1, NULL);
            (*gPartfxInterface)->spawnObject((void*)obj, 0x427, gPlayerPartFxParams, 0x200001, -1, NULL);
            (*gPartfxInterface)->spawnObject((void*)obj, 0x427, gPlayerPartFxParams, 0x200001, -1, NULL);
        }
        if ((((PlayerState*)inner)->flags360 & 0x20000u) != 0)
        {
            (*gWaterfxInterface)
                ->spawnSplashBurst((void*)obj, obj->anim.localPosX,
                                   (obj->anim.localPosY + ((PlayerState*)inner)->waterDepth) -
                                       lbl_803E7F10,
                                   obj->anim.localPosZ, lbl_803E7FFC);
            (*gWaterfxInterface)->spawnRipple(
                obj->anim.localPosX,
                obj->anim.localPosY + ((PlayerState*)inner)->waterDepth,
                obj->anim.localPosZ, 0, lbl_803E80E4, 2);
            *(u32*)&((PlayerState*)inner)->flags360 &= ~PLAYER_FLAG_WATER_SPLASH_PENDING;
        }
    }
}
#pragma dont_inline reset
#pragma opt_strength_reduction off
int fn_802AB1D0(GameObject* obj)
{
    GameObject* cur;
    u32* objs;
    GameObject* best;
    int count;
    int i;
    f32 dist;
    f32 bestDist;
    f32 scale;
    s16 yaw;
    void* held;

    if (obj->objectFlags & OBJECT_OBJFLAG_PARENT_SLACK)
    {
        return 0;
    }
    held = *(void**)((char*)*(int*)&obj->extra + 0x2d0);
    if (held != NULL)
    {
        return (int)held;
    }
    best = NULL;
    objs = ObjGroup_GetObjects(8, &count);
    i = 0;
    bestDist = lbl_803E7EA4;
    for (; i < count;)
    {
        cur = (GameObject*)objs[i++];
        if ((cur->anim.classId == 0x1c || cur->anim.classId == 0x2a) && cur->anim.alpha == 0xff)
        {
            f32 dx = cur->anim.worldPosX - obj->anim.worldPosX;
            f32 dy = cur->anim.worldPosY - obj->anim.worldPosY;
            f32 dz = cur->anim.worldPosZ - obj->anim.worldPosZ;
            dist = dx * dx + dy * dy + dz * dz;
            if (dist < lbl_803E80E8)
            {
                if (dist <= lbl_803E7EA4)
                {
                    scale = (f32)cur->anim.modelInstance->group8RegistrationCount;
                    if (scale <= lbl_803E7EA4)
                    {
                        scale = lbl_803E7EE0;
                    }
                    dist = sqrtf(dist) / scale;
                }
                yaw = Obj_GetYawDeltaToObject(obj, cur, 0);
                if (yaw < 0x5555 && yaw > -0x5555)
                {
                    if (dist < bestDist || lbl_803E7EA4 == bestDist)
                    {
                        bestDist = dist;
                        best = cur;
                    }
                }
            }
        }
    }
    return (int)best;
}
#pragma opt_strength_reduction reset

void playerCastSpell(int a, int b, int c)
{
    switch (c)
    {
    case GAMEBIT_STAFF_ABILITY_FIRE_BLASTER:
        gPlayerSelectedItem = GAMEBIT_STAFF_ABILITY_FIRE_BLASTER;
        break;
    case 0x958:
        gPlayerSelectedItem = 0x958;
        break;
    case GAMEBIT_STAFF_ABILITY_FREEZE_BLAST:
        gPlayerSelectedItem = GAMEBIT_STAFF_ABILITY_FREEZE_BLAST;
        break;
    case GAMEBIT_STAFF_ABILITY_STAFF_BOOSTER:
        gPlayerInteractTarget = ((PlayerState*)b)->cameraTargetObject;
        (*(void (*)(int, int, int))(*(int*)((char*)*gPlayerInterface + 0x14)))(a, b, 0x32);
        *(int*)&((PlayerState*)b)->baddie.unk304 = (int)fn_802994A4;
        break;
    case 0x107:
    case 0xc55:
        (*(void (*)(int, int, int))(*(int*)((char*)*gPlayerInterface + 0x14)))(a, b, 0x36);
        *(int*)&((PlayerState*)b)->baddie.unk304 = (int)fn_802985AC;
        break;
    case 0x40:
        ((PlayerState*)b)->stateTimer = lbl_803E7EDC;
        {
            int sub = *(int*)((char*)((GameObject*)a)->extra + 0x35c);
            int v = *(s16*)((char*)sub + 0x4) - 0xa;
            if (v < 0)
            {
                v = 0;
            }
            else if (v > *(s16*)((char*)sub + 0x6))
            {
                v = *(s16*)((char*)sub + 0x6);
            }
            *(s16*)((char*)sub + 0x4) = v;
        }
        playerSetDisguised((GameObject*)a, 1);
        Sfx_PlayFromObject(a, SFXTRIG_dn_boar1_c_209);
        break;
    case 0x5bd:
        c = -1;
        {
            int sub = *(int*)((char*)((GameObject*)a)->extra + 0x35c);
            int v = *(s16*)((char*)sub + 0x4) - 0x14;
            if (v < 0)
            {
                v = 0;
            }
            else if (v > *(s16*)((char*)sub + 0x6))
            {
                v = *(s16*)((char*)sub + 0x6);
            }
            *(s16*)((char*)sub + 0x4) = v;
        }
        {
            void* cam = (void*)(*gCameraInterface)->getTarget();
            if (cam != NULL)
            {
                s16 id = ((GameObject*)cam)->anim.seqId;
                if (id == 0x414 || id == 0x4a9)
                {
                    c = 0x5bd;
                    getAngle(((GameObject*)cam)->anim.hitVolumeTransforms->jointX - ((GameObject*)a)->anim.localPosX,
                             ((GameObject*)cam)->anim.hitVolumeTransforms->jointZ - ((GameObject*)a)->anim.localPosZ);
                }
            }
        }
        break;
    }
    ((PlayerState*)b)->animState = c;
}
#pragma dont_inline on
void fn_802AB5A4(GameObject* obj, int p2, int flags)
{
    u8 f = (u8)flags;
    char* q = (char*)p2 + 4;
    if (f & 1)
    {
        curves_updateLocalPointTransforms((int)obj, (CurvesCollisionState*)q);
    }
    if (f & 2)
    {
        curves_preparePointCollisionFrame((int)obj, (CurvesCollisionState*)((char*)(int)p2 + 4));
        *(f32*)(q + 0x20) = obj->anim.worldPosX;
        *(f32*)(q + 0x24) = lbl_803E80EC + obj->anim.worldPosY;
        *(f32*)(q + 0x28) = obj->anim.worldPosZ;
    }
    if (f & 4)
    {
        ((ObjHitsPriorityState*)obj->anim.hitReactState)->localPosX = obj->anim.localPosX;
        ((ObjHitsPriorityState*)obj->anim.hitReactState)->localPosY = obj->anim.localPosY;
        ((ObjHitsPriorityState*)obj->anim.hitReactState)->localPosZ = obj->anim.localPosZ;
        ((ObjHitsPriorityState*)obj->anim.hitReactState)->worldPosX = obj->anim.worldPosX;
        ((ObjHitsPriorityState*)obj->anim.hitReactState)->worldPosY = obj->anim.worldPosY;
        ((ObjHitsPriorityState*)obj->anim.hitReactState)->worldPosZ = obj->anim.worldPosZ;
    }
}

#pragma dont_inline reset

void playerCalcWaterCurrent(f32* outX, f32* outZ, int player)
{
    int any;
    PlayerState* inner = ((GameObject*)player)->extra;
    f32 sumC;
    f32 sumS;
    f32 ratio;
    f32 angle;
    int* objs;
    int n;
    int i;

    sumC = sumS = lbl_803E7EA4;
    objs = (int*)ObjGroup_GetObjects(0x14, &n);
    any = 0;
    for (i = 0; i < n; i++)
    {
        int o = objs[i];
        if (*(u8*)((char*)*(int*)((char*)o + 0x4c) + 0x1a) & 2)
        {
            f32 dy;
            any = 1;
            dy = *(f32*)((char*)o + 0x10) - ((GameObject*)player)->anim.localPosY;
            if (dy <= 200.0f && dy >= -200.0f)
            {
                f32 dx = *(f32*)((char*)o + 0xc) - ((GameObject*)player)->anim.localPosX;
                f32 dz = *(f32*)((char*)o + 0x14) - ((GameObject*)player)->anim.localPosZ;
                f32 dist = sqrtf(dx * dx + dz * dz);
                f32 thresh = 1.5f * (f32)(u32) * (u8*)((char*)*(int*)((char*)o + 0x4c) + 0x19);
                if (dist < thresh)
                {
                    ratio = 0.0f;
                    if (thresh > 0.0f)
                    {
                        ratio = (thresh - dist) / thresh;
                    }
                    ratio = ratio * (10.0f * *(f32*)((char*)o + 0x8));
                    sumC = ratio * mathSinf(3.1415927f * (f32)(int)*(s16*)((char*)o + 0) / 32768.0f) + sumC;
                    sumS = ratio * mathCosf(3.1415927f * (f32)(int)*(s16*)((char*)o + 0) / 32768.0f) + sumS;
                }
            }
        }
    }
    objs = (int*)ObjGroup_GetObjects(0x50, &n);
    for (i = 0; i < n; i++)
    {
        int o = objs[i];
        f32 strength = (f32)(u32) * (u8*)((char*)*(int*)((char*)o + 0x4c) + 0x32) / 10.0f;
        f32 dy;
        any = 1;
        dy = *(f32*)((char*)o + 0x10) - ((GameObject*)player)->anim.localPosY;
        if (dy <= 200.0f && dy >= -200.0f)
        {
            f32 dx = *(f32*)((char*)o + 0xc) - ((GameObject*)player)->anim.localPosX;
            f32 dz = *(f32*)((char*)o + 0x14) - ((GameObject*)player)->anim.localPosZ;
            int a22 = (s16)(getAngle(dx, dz) + 0x84d0);
            f32 dist = sqrtf(dx * dx + dz * dz);
            f32 thresh = (f32)(int)(*(u8*)((char*)*(int*)((char*)o + 0x4c) + 0x29) << 3);
            if (dist < thresh)
            {
                ratio = lbl_803E7EA4;
                if (thresh > lbl_803E7EA4)
                {
                    ratio = (thresh - dist) / thresh;
                }
                ratio = ratio * strength;
                angle = 3.1415927f * (f32)(int)a22 / 32768.0f;
                sumC = ratio * mathSinf(angle) + sumC;
                sumS = ratio * mathCosf(angle) + sumS;
            }
        }
    }
    if (any)
    {
        f32 mag;
        f32 k;
        sumC = sumC / (f32)(int)any;
        sumS = sumS / (f32)(int)any;
        k = lbl_803E7F6C;
        inner->avoidVelX = inner->avoidVelX - k * sumC;
        inner->avoidVelZ = inner->avoidVelZ - k * sumS;
        {
            f32 k;
            inner->avoidVelX = inner->avoidVelX * (k = lbl_803E7F68);
            inner->avoidVelZ = inner->avoidVelZ * k;
        }
        mag = sqrtf(inner->avoidVelX * inner->avoidVelX + inner->avoidVelZ * inner->avoidVelZ);
        if (mag > lbl_803E7F1C)
        {
            f32 s = lbl_803E7F1C / mag;
            inner->avoidVelX = inner->avoidVelX * s;
            inner->avoidVelZ = inner->avoidVelZ * s;
        }
        *outX = inner->avoidVelX * timeDelta;
        *outZ = inner->avoidVelZ * timeDelta;
    }
    else
    {
        *outX = 0.0f;
        *outZ = 0.0f;
    }
}
#pragma opt_common_subs off
int fn_802ABAE8(GameObject* obj, int state, int inner, f32 fv)
{
    int d = ((PlayerState*)inner)->targetYaw - (u16)((PlayerState*)inner)->prevTargetYaw;
    int near;
    int g;
    if (d > 0x8000)
        d -= 0xffff;
    if (d < -0x8000)
        d += 0xffff;
    if ((((u32)((PlayerState*)inner)->flags3F1 >> 5) & 1) || (((u32)((PlayerState*)inner)->flags3F0 >> 4) & 1))
    {
        d = 0;
    }
    {
        f32 f2 = lbl_803E7E98 * (((PlayerState*)state)->baddie.animSpeedC - lbl_803E7E9C) + lbl_803E7EE0;
        if (f2 < lbl_803E7EA4)
        {
            f2 = lbl_803E7EA4;
        }
        d = (int)((f32)(int)d * (lbl_803E7FC4 * f2));
        d = (d < -0xccc) ? -0xccc : ((d > 0xccc) ? 0xccc : d);
    }
    d -= (u16)((PlayerState*)inner)->headPitch;
    if (d > 0x8000)
        d = d - 0xffff;
    if (d < -0x8000)
        d = d + 0xffff;
    ((PlayerState*)inner)->headPitch =
        (f32)(int)((PlayerState*)inner)->headPitch + interpolate((f32)(int)d, lbl_803E7EB4, timeDelta);
    near = fn_802AB1D0(obj);
    if ((u32)near != 0 && (((u32)((PlayerState*)inner)->flags3F0 >> 7) & 1) == 0 &&
        (((u32)((PlayerState*)inner)->flags3F0 >> 6) & 1) == 0 &&
        (((u32)((PlayerState*)inner)->flags3F0 >> 4) & 1) == 0 &&
        (((u32)((PlayerState*)inner)->flags3F0 >> 5) & 1) == 0)
    {
        int gd = (u16)getAngle(-(*(f32*)((char*)near + 0xc) - obj->anim.localPosX),
                               -(*(f32*)((char*)near + 0x14) - obj->anim.localPosZ)) -
                 (u16)((PlayerState*)inner)->targetYaw;
        f32 t;
        f32 f5;
        if (gd > 0x8000)
            gd -= 0xffff;
        if (gd < -0x8000)
            gd += 0xffff;
        t = lbl_803E7EE0 - (((PlayerState*)state)->baddie.animSpeedC - lbl_803E7E9C) /
                               (((PlayerState*)inner)->maxSpeed - lbl_803E7E9C);
        f5 = lbl_803E80C4 * ((t < *(f32*)&lbl_803E7EA4) ? lbl_803E7EA4 : ((t > lbl_803E7EE0) ? lbl_803E7EE0 : t)) +
             lbl_803E80F4;
        g = (int)(((f32)(int)gd < lbl_803E80F8 * -f5)
                      ? lbl_803E80F8 * -f5
                      : (((f32)(int)gd > lbl_803E80F8 * f5) ? lbl_803E80F8 * f5 : (f32)(int)gd));
    }
    else
    {
        g = 0;
    }
    {
        int r0;
        int h;
        if (!((((u32)((PlayerState*)inner)->flags3F1 >> 5) & 1) || (((u32)((PlayerState*)inner)->flags3F0 >> 4) & 1)))
        {
            r0 = ((PlayerState*)inner)->targetYawRate;
        }
        else
        {
            r0 = 0;
        }
        if (r0 < -0x28)
        {
            r0 = -0x28;
        }
        else if (r0 > 0x28)
        {
            r0 = 0x28;
        }
        h = g + r0 * 0xb6;
        if (h < -0x3ffc)
        {
            h = -0x3ffc;
        }
        else if (h > 0x3ffc)
        {
            h = 0x3ffc;
        }
        h = h - (u16)((PlayerState*)inner)->bodyLeanAngle;
        if (h > 0x8000)
            h -= 0xffff;
        if (h < -0x8000)
            h += 0xffff;
        h = (int)((f32)(int)h * lbl_803E7EB4);
        if (h < -0x16c)
        {
            h = -0x16c;
        }
        else if (h > 0x16c)
        {
            h = 0x16c;
        }
        ((PlayerState*)inner)->bodyLeanAngle = (f32)(int)h * timeDelta + (f32)(int)*(s16*)((int)inner + 0x4D4);
        ((PlayerState*)inner)->bodyLeanHalf = ((PlayerState*)inner)->bodyLeanAngle / 2;
    }
    {
        int k = (int)(lbl_803E80F8 * (lbl_803E7ED8 * -fv));
        k -= (u16)((PlayerState*)inner)->headYaw;
        if (k > 0x8000)
            k -= 0xffff;
        if (k < -0x8000)
            k += 0xffff;
        ((PlayerState*)inner)->headYaw = *(s16*)((int)inner + 0x4D6) + k;
    }
}
#pragma opt_common_subs reset
#pragma opt_propagation off

void fn_802ABFBC(GameObject* obj, int state, PlayerState* inner)
{
    f32 x1, y1, z1;
    f32 pos[3];
    GameObject* sub;

    inner->headPitch *= powfBitEstimate(lbl_803E7FF4, timeDelta);
    sub = inner->cameraTargetObject;
    if (sub != NULL && sub->anim.modelInstance->unk58 != 0)
    {
        ObjPath_GetPointWorldPosition((GameObject*)obj, 5, &x1, &y1, &z1, 0);
        if (objModelGetVecFn_800395d8((GameObject*)sub, 0) != 0)
        {
            objPosFn_80039510((GameObject*)sub, 0, pos);
        }
        else
        {
            pos[0] = sub->anim.localPosX;
            pos[1] = sub->anim.localPosY;
            pos[2] = sub->anim.localPosZ;
        }

        {
            f32 dx = pos[0] - x1;
            f32 dy = pos[1] - y1;
            f32 dz = pos[2] - z1;

            int d = getAngle(-dy, sqrtf(dx * dx + dz * dz)) & 0xffff;
            d -= (u16)inner->headYaw;
            if (d > 0x8000)
                d = d - 0xffff;
            if (d < -0x8000)
                d = d + 0xffff;
            d *= lbl_803E7EB4;
            inner->headYaw += d * timeDelta;

            d = getAngle(-dx, -dz) & 0xffff;
            d -= (u16)inner->targetYaw;

            if (d > 0x8000)
                d = d - 0xffff;
            if (d < -0x8000)
                d = d + 0xffff;

            d = (d < -0x1c70) ? -0x1c70 : ((d > 0x1c70) ? 0x1c70 : d);
            d -= (u16)inner->bodyLeanAngle;

            if (d > 0x8000)
                d = d - 0xffff;
            if (d < -0x8000)
                d = d + 0xffff;

            d *= lbl_803E7EB4;
            inner->bodyLeanAngle += d * timeDelta;
            inner->bodyLeanHalf = inner->bodyLeanAngle / 2;
        }
    }
    else
    {
        inner->headYaw *= powfBitEstimate(lbl_803E7F1C, timeDelta);
    }
}
#pragma opt_propagation reset

void fn_802AC32C(int p1, int p2, int p3)
{
    void* near;
    int angle1;
    int angle2;

    near = (void*)fn_802AB1D0((GameObject*)p1);
    if (near != NULL && ((ByteFlags*)((char*)p3 + 0x3f0))->b80 == 0 && ((ByteFlags*)((char*)p3 + 0x3f0))->b40 == 0)
    {
        f32 ratio;
        f32 clamped;
        f32 f5;

        if (--*(s16*)&((PlayerState*)p3)->lookAtTimer <= 0)
        {
            *(s16*)&((PlayerState*)p3)->lookAtTimer = (s16)randomGetRange(0x78, 0xf0);
            *(s16*)&((PlayerState*)p3)->lookAtRandOffset = (s16)randomGetRange(0, 0x28);
        }
        angle1 = getAngle(-(*(f32*)((char*)near + 0xc) - ((GameObject*)p1)->anim.localPosX),
                          -(*(f32*)((char*)near + 0x14) - ((GameObject*)p1)->anim.localPosZ)) &
                 0xffff;
        angle1 -= (u16)((PlayerState*)p3)->targetYaw;
        if (angle1 > 0x8000)
        {
            angle1 = angle1 - 0xFFFF;
        }
        if (angle1 < -0x8000)
        {
            angle1 = angle1 + 0xFFFF;
        }
        ratio = lbl_803E7EE0 -
                (((PlayerState*)p2)->baddie.animSpeedC - lbl_803E7E9C) / (((PlayerState*)p3)->maxSpeed - *(f32*)&lbl_803E7E9C);
        f5 = lbl_803E80C4;
        clamped = (ratio < lbl_803E7EA4) ? lbl_803E7EA4 : ((ratio > lbl_803E7EE0) ? lbl_803E7EE0 : ratio);
        f5 = f5 * clamped + lbl_803E80F4;
        angle1 = ((f32)angle1 < lbl_803E80F8 * -f5)
                     ? lbl_803E80F8 * -f5
                     : (((f32)angle1 > lbl_803E80F8 * f5) ? lbl_803E80F8 * f5 : (f32)angle1);
    }
    else
    {
        angle1 = 0;
        *(s16*)&((PlayerState*)p3)->lookAtTimer = angle1;
    }

    {
        int v480;
        if (((ByteFlags*)((char*)p3 + 0x3f1))->b20)
        {
            v480 = 0;
        }
        else
        {
            v480 = ((PlayerState*)p3)->targetYawRate;
        }
        v480 = (v480 < -0x28) ? -0x28 : ((v480 > 0x28) ? 0x28 : v480);
        angle1 += v480 * 0xb6;
    }
    angle1 = (angle1 < -0x3ffc) ? -0x3ffc : ((angle1 > 0x3ffc) ? 0x3ffc : angle1);
    angle1 -= (u16)((PlayerState*)p3)->bodyLeanAngle;
    if (angle1 > 0x8000)
    {
        angle1 = angle1 - 0xFFFF;
    }
    if (angle1 < -0x8000)
    {
        angle1 = angle1 + 0xFFFF;
    }
    angle1 *= lbl_803E7EB4;
    angle1 = (angle1 < -0x16c) ? -0x16c : ((angle1 > 0x16c) ? 0x16c : angle1);
    ((PlayerState*)p3)->bodyLeanAngle += angle1 * timeDelta;
    ((PlayerState*)p3)->bodyLeanHalf = (s16)(((PlayerState*)p3)->bodyLeanAngle / 2);

    angle2 = ((PlayerState*)p3)->targetYaw - (u16)((PlayerState*)p3)->prevTargetYaw;
    if (angle2 > 0x8000)
    {
        angle2 = angle2 - 0xFFFF;
    }
    if (angle2 < -0x8000)
    {
        angle2 = angle2 + 0xFFFF;
    }
    if (((ByteFlags*)((char*)p3 + 0x3f1))->b20)
    {
        angle2 = 0;
    }
    {
        f32 f2 = lbl_803E7E98 * (((PlayerState*)p2)->baddie.animSpeedC - lbl_803E7E9C) + lbl_803E7EE0;
        if (f2 < lbl_803E7EA4)
        {
            f2 = lbl_803E7EA4;
        }
        angle2 = (int)((f32)angle2 * (lbl_803E7FC4 * f2));
    }
    angle2 = (angle2 < -0xccc) ? -0xccc : ((angle2 > 0xccc) ? 0xccc : angle2);
    angle2 -= (u16)((PlayerState*)p3)->headPitch;
    if (angle2 > 0x8000)
    {
        angle2 = angle2 - 0xFFFF;
    }
    if (angle2 < -0x8000)
    {
        angle2 = angle2 + 0xFFFF;
    }
    ((PlayerState*)p3)->headPitch =
        (f32)((PlayerState*)p3)->headPitch + interpolate((f32)angle2, lbl_803E7EB4, timeDelta);
    ((PlayerState*)p3)->headYaw = (f32)((PlayerState*)p3)->headYaw * powfBitEstimate(lbl_803E7F1C, timeDelta);
}
#pragma opt_propagation off

extern int lbl_803E7E70;
extern f32 lbl_803E80FC;
extern f32 lbl_803E8100;

int fn_802AC7DC(int obj, int state, int inner, f32 fv)
{
    int r;
    int ok;
    IntPair2 camp;
    MatrixTransform pos;
    u8 buf[52];
    f32 mtx[16];
    f32 dummy;

    camp = *(IntPair2*)&lbl_803E7E70;
    if (((PlayerState*)inner)->curAnimId != 0x48 && ((PlayerState*)inner)->curAnimId != 0x47 &&
        !((ByteFlags*)((char*)inner + 0x3f0))->b04 && !((ByteFlags*)((char*)inner + 0x3f0))->b08 &&
        *(void**)((char*)inner + 0x7f8) == NULL && !((ByteFlags*)((char*)inner + 0x3f0))->b02 &&
        ((PlayerState*)inner)->baddie.targetObj == NULL && !((ByteFlags*)((char*)inner + 0x3f6))->b40 &&
        ((PlayerState*)inner)->baddie.controlMode != 0x26)
    {
        ok = 1;
    }
    else
    {
        ok = 0;
    }
    if (ok != 0 && (((PlayerState*)inner)->buttonsHeld & PAD_TRIGGER_L) != 0 && getCurSeqNoInt() == 0)
    {
        if (!((ByteFlags*)((char*)inner + 0x3f1))->b20 && !((ByteFlags*)((char*)inner + 0x3f0))->b10)
        {
            f32 b;
            f32 a;
            a = ((PlayerState*)state)->baddie.animSpeedB;
            b = ((PlayerState*)state)->baddie.animSpeedA;
            pos.rotX = ((PlayerState*)inner)->yaw;
            pos.rotY = 0;
            pos.rotZ = 0;
            pos.scale = lbl_803E7EE0;
            pos.x = lbl_803E7EA4;
            pos.y = lbl_803E7EA4;
            pos.z = lbl_803E7EA4;
            setMatrixFromObjectPos(mtx, &pos);
            Matrix_TransformPoint(mtx, a, lbl_803E7EA4, -b, (f32*)((char*)inner + 0x4c8), &dummy,
                                  (f32*)((char*)inner + 0x4cc));
            ((ByteFlags*)((char*)inner + 0x3f0))->b80 = 0;
            ((ByteFlags*)((char*)inner + 0x3f0))->b40 = 0;
            ((ByteFlags*)((char*)inner + 0x3f0))->b10 = 0;
            ((ByteFlags*)((char*)inner + 0x3f1))->b08 = 1;
            {
                s16 v = ((PlayerState*)inner)->targetYaw;
                ((PlayerState*)inner)->yaw = v;
                ((GameObject*)obj)->anim.rotX = v;
            }
            ((ByteFlags*)((char*)inner + 0x3f1))->b20 = 1;
            {
                f32 z = lbl_803E7EA4;
                ((PlayerState*)inner)->aimInputZ = z;
                ((PlayerState*)inner)->aimInputX = z;
            }
        }
        if (!((ByteFlags*)((char*)inner + 0x3f1))->b10)
        {
            cameraSetInterpMode(2);
            (*gCameraInterface)->setMode(0x52, 1, 0, 8, &camp, 0x1e, 0xff);
            if (gPlayerFrameCounter - gPlayerLastSfxFrame > 2)
            {
                Sfx_PlayFromObject(obj, SFXTRIG_headcam_in);
            }
            gPlayerLastSfxFrame = gPlayerFrameCounter;
            ((ByteFlags*)((char*)inner + 0x3f1))->b10 = 1;
        }
    }
    else
    {
        if (((ByteFlags*)((char*)inner + 0x3f1))->b20)
        {
            s16 v = ((GameObject*)obj)->anim.rotX;
            ((PlayerState*)inner)->yaw = v;
            ((PlayerState*)inner)->targetYaw = v;
            ((PlayerState*)inner)->lastInputHeading = v;
            ((PlayerState*)inner)->baddie.animSpeedB = lbl_803E7EA4;
        }
        ((ByteFlags*)((char*)inner + 0x3f1))->b20 = 0;
        if (((ByteFlags*)((char*)inner + 0x3f1))->b10 && ((PlayerState*)inner)->curAnimId != 0x48 &&
            ((PlayerState*)inner)->curAnimId != 0x47 && getCurSeqNoInt() == 0)
        {
            (*gCameraInterface)->setMode(0x42, 0, 1, 0, NULL, 0x1e, 0xff);
            ((ByteFlags*)((char*)inner + 0x3f1))->b10 = 0;
        }
    }
    gPlayerFrameCounter = gPlayerFrameCounter + 1;
    if (!((ByteFlags*)((char*)inner + 0x3f0))->b20 && ((PlayerState*)inner)->waterDepth > lbl_803E7FA0 &&
        *(f32*)((char*)state + 0x1b0) < lbl_803E80FC)
    {
        ((void (*)(int, int, int))fn_802AE83C)(obj, inner, state);
        return 0;
    }
    {
        if (!((ByteFlags*)((char*)inner + 0x3f0))->b20 && !((ByteFlags*)((char*)inner + 0x3f0))->b08 &&
            !((ByteFlags*)((char*)inner + 0x3f0))->b04)
        {
            if (((ByteFlags*)((char*)inner + 0x3f1))->b01 || *(f32*)((char*)state + 0x1b0) < lbl_803E7F58)
            {
                ((PlayerState*)inner)->staffHoldFrames = 0;
            }
            else
            {
                ((PlayerState*)inner)->staffHoldFrames += 1;
            }
            ((PlayerState*)inner)->staffHoldFrames =
                (((PlayerState*)inner)->staffHoldFrames > 10) ? 10 : ((PlayerState*)inner)->staffHoldFrames;
            if (((PlayerState*)inner)->staffHoldFrames > 2)
            {
                ((ByteFlags*)((char*)inner + 0x3f0))->b80 = 0;
                ((ByteFlags*)((char*)inner + 0x3f0))->b10 = 0;
                ((ByteFlags*)((char*)inner + 0x3f0))->b08 = 0;
                staffFn_80170380(gPlayerStaffObject, 2);
                ((ByteFlags*)((char*)inner + 0x3f0))->b02 = 0;
                *(u32*)&((PlayerState*)inner)->flags360 |= PLAYER_FLAG_TELEPORTED;
                ((void (*)(int))ObjHits_SyncObjectPositionIfDirty)(obj);
                ((ByteFlags*)((char*)inner + 0x3f0))->b40 = 0;
                ((ByteFlags*)((char*)inner + 0x3f0))->b04 = 1;
                ((ByteFlags*)((char*)inner + 0x3f4))->b10 = 0;
                ((PlayerState*)inner)->isHoldingObject = 0;
                if (*(void**)((char*)inner + 0x7f8) != NULL)
                {
                    s16 t = ((GameObject*)((PlayerState*)inner)->heldObj)->anim.seqId;
                    if (t == 0x3cf || t == 0x662)
                    {
                        objThrowFn_80182504((GameObject*)(((PlayerState*)inner)->heldObj));
                    }
                    else
                    {
                        objSaveFn_800ea774((GameObject*)((PlayerState*)inner)->heldObj);
                    }
                    *(s16*)((char*)((PlayerState*)inner)->heldObj + 0x6) =
                        *(s16*)((char*)((PlayerState*)inner)->heldObj + 0x6) & ~0x4000;
                    *(int*)((char*)((PlayerState*)inner)->heldObj + 0xf8) = 0;
                    ((PlayerState*)inner)->heldObj = 0;
                }
                *(int*)&((PlayerState*)state)->baddie.unk308 = (int)fn_802A514C;
                return 3;
            }
        }
        if (!((ByteFlags*)((char*)inner + 0x3f0))->b20 && lbl_803E7EA4 != ((PlayerState*)inner)->verticalVel)
        {
            *(int*)&((PlayerState*)state)->baddie.unk308 = 0;
            return 0x42;
        }
        if (!((ByteFlags*)((char*)inner + 0x3f0))->b20 && !((ByteFlags*)((char*)inner + 0x3f0))->b08 &&
            !((ByteFlags*)((char*)inner + 0x3f0))->b04 && ((PlayerState*)inner)->baddie.targetObj == NULL &&
            !((ByteFlags*)((char*)inner + 0x3f6))->b40 && ((PlayerState*)inner)->baddie.controlMode != 0x26)
        {
            ok = 1;
        }
        else
        {
            ok = 0;
        }
        if (ok != 0 && *(void**)((char*)inner + 0x7f8) != NULL && ((PlayerState*)inner)->isHoldingObject == 0)
        {
            if ((*(int*)((char*)state + 0x310) & 0x4000) != 0)
            {
                *(int*)&((PlayerState*)state)->baddie.unk308 = (int)fn_802A49A8;
                return 7;
            }
            *(int*)&((PlayerState*)state)->baddie.unk308 = (int)fn_802A49A8;
            return 8;
        }
        if (!((ByteFlags*)((char*)inner + 0x3f0))->b20 && !((ByteFlags*)((char*)inner + 0x3f0))->b08 &&
            !((ByteFlags*)((char*)inner + 0x3f0))->b04 && !((ByteFlags*)((char*)inner + 0x3f0))->b02 &&
            ((PlayerState*)inner)->baddie.targetObj == NULL && !((ByteFlags*)((char*)inner + 0x3f6))->b40 &&
            ((PlayerState*)inner)->baddie.controlMode != 0x26)
        {
            ok = 1;
        }
        else
        {
            ok = 0;
        }
        if (ok != 0)
        {
            r = ((int (*)(int, int, f32))playerState08)(obj, state, fv);
            if (r != 0)
            {
                return r;
            }
        }
        if (((PlayerState*)state)->baddie.targetObj != NULL)
        {
            s16 t = ((PlayerState*)state)->baddie.controlMode;
            if (t != 0x24 && t != 0x25 && t != 0x26 && !((ByteFlags*)((char*)inner + 0x3f6))->b20 &&
                *(u8*)&((PlayerState*)state)->baddie.hasTarget == 1)
            {
                *(int*)&((PlayerState*)state)->baddie.unk308 = (int)fn_8029C8C8;
                return 0x25;
            }
        }
        {
            int btn = getButtons_80014dd8(0);
            if ((btn & 0x20) != 0)
            {
                if (((ByteFlags*)((char*)inner + 0x3f4))->b40 && !((ByteFlags*)((char*)inner + 0x3f0))->b20 &&
                    !((ByteFlags*)((char*)inner + 0x3f0))->b08 && !((ByteFlags*)((char*)inner + 0x3f0))->b04 &&
                    ((PlayerState*)inner)->curAnimId != 0x44 && *(void**)((char*)inner + 0x7f8) == NULL &&
                    ((PlayerState*)inner)->baddie.targetObj == NULL && !((ByteFlags*)((char*)inner + 0x3f6))->b40 &&
                    ((PlayerState*)inner)->baddie.controlMode != 0x26 &&
                    (((GameObject*)obj)->objectFlags & OBJECT_OBJFLAG_PARENT_SLACK) == 0 &&
                    ((PlayerState*)inner)->idleDelayTimer == lbl_803E7EA4)
                {
                    ok = 1;
                }
                else
                {
                    ok = 0;
                }
                if (ok != 0 && !((ByteFlags*)((char*)inner + 0x3f0))->b02)
                {
                    staffFn_80170380(gPlayerStaffObject, 1);
                    ObjAnim_SetCurrentMove(obj, 0x4f, ((GameObject*)obj)->anim.currentMoveProgress, 0);
                    ObjAnim_SetCurrentEventStepFrames((ObjAnimComponent*)obj, 8);
                    if (gPlayerPathObject != NULL && ((ByteFlags*)((char*)inner + 0x3f4))->b40)
                    {
                        ((PlayerState*)inner)->staffActionRequest = 4;
                        ((ByteFlags*)((char*)inner + 0x3f4))->b08 = 1;
                    }
                    ((PlayerState*)state)->baddie.moveSpeed = lbl_803E7EF8;
                    ((ByteFlags*)((char*)inner + 0x3f0))->b10 = 0;
                    ((ByteFlags*)((char*)inner + 0x3f0))->b40 = 0;
                    ((ByteFlags*)((char*)inner + 0x3f0))->b80 = 0;
                    ((ByteFlags*)((char*)inner + 0x3f0))->b08 = 0;
                    ((ByteFlags*)((char*)inner + 0x3f0))->b04 = 0;
                    ((PlayerState*)inner)->staffHoldFrames = 0;
                    ((ByteFlags*)((char*)inner + 0x3f0))->b02 = 1;
                    ((PlayerState*)inner)->isHoldingObject = 0;
                    if (*(void**)((char*)inner + 0x7f8) != NULL)
                    {
                        s16 t = ((GameObject*)((PlayerState*)inner)->heldObj)->anim.seqId;
                        if (t == 0x3cf || t == 0x662)
                        {
                            objThrowFn_80182504((GameObject*)(((PlayerState*)inner)->heldObj));
                        }
                        else
                        {
                            objSaveFn_800ea774((GameObject*)((PlayerState*)inner)->heldObj);
                        }
                        *(s16*)((char*)((PlayerState*)inner)->heldObj + 0x6) =
                            *(s16*)((char*)((PlayerState*)inner)->heldObj + 0x6) & ~0x4000;
                        *(int*)((char*)((PlayerState*)inner)->heldObj + 0xf8) = 0;
                        ((PlayerState*)inner)->heldObj = 0;
                    }
                    ObjHits_MarkObjectPositionDirty((ObjAnimComponent*)obj);
                    *(int*)&((PlayerState*)state)->baddie.unk308 = (int)fn_802A514C;
                    return 3;
                }
            }
        }
        if (((ByteFlags*)((char*)inner + 0x3f0))->b08 || ((ByteFlags*)((char*)inner + 0x3f0))->b04)
        {
            r = ((int (*)(int, int, int, void*, f32, u32))playerCheckIfClimbingOntoWall)(obj, inner, state, buf, fv,
                                                                                         0x14);
            if (r == 0xc)
            {
                *(int*)&((PlayerState*)state)->baddie.unk308 = 0;
                return 10;
            }
            if (r == 9)
            {
                f32 mid;
                f32 lo;
                f32 hi = ((PlayerState*)inner)->spanTopY - lbl_803E7F10;
                mid = lbl_803E8100 + ((GameObject*)obj)->anim.localPosY;
                lo = lbl_803E7F30 + ((PlayerState*)inner)->spanBottomY;
                if (mid >= lo && mid <= hi)
                {
                    doRumble(lbl_803E7ED8);
                    *(int*)&((PlayerState*)state)->baddie.unk308 = (int)fn_8029FFD0;
                    return 0x12;
                }
            }
        }
        if (((ByteFlags*)((char*)inner + 0x3f0))->b20)
        {
            r = ((int (*)(int, int, int, void*, f32, u32))playerCheckIfClimbingOntoWall)(obj, inner, state, buf,
                                                                                         lbl_803E7EE0, 0x100);
            if (r == 5)
            {
                gPlayerCurrentMoveId = -1;
                *(int*)&((PlayerState*)state)->baddie.unk308 = 0;
                return 0xc;
            }
            if (((PlayerState*)inner)->waterDepth < lbl_803E7FC0 && ((ByteFlags*)((char*)inner + 0x3f1))->b01)
            {
                ((ByteFlags*)((char*)inner + 0x3f0))->b20 = 0;
            }
        }
        return 0;
    }
}
#pragma opt_propagation reset

void playerSetMovingAnims(int p1, int obj)
{
    char* t = (char*)lbl_80332EC0;
    *(int*)((char*)obj + 0x3fc) = *(int*)((char*)obj + 0x3f8);
    if (((ByteFlags*)((char*)obj + 0x3f0))->b20)
    {
        if (((ByteFlags*)((char*)obj + 0x3f1))->b20)
        {
            *(int*)((char*)obj + 0x3f8) = (int)(t + 0x310);
            *(int*)((char*)obj + 0x400) = (int)(t + 0xd8);
        }
        else
        {
            *(int*)((char*)obj + 0x3f8) = (int)(t + 0x210);
            *(int*)((char*)obj + 0x400) = (int)(t + 0xd8);
        }
    }
    else if (*(void**)((char*)obj + 0x7f8) != NULL)
    {
        *(int*)((char*)obj + 0x3f8) = (int)(t + 0x250);
        *(int*)((char*)obj + 0x400) = (int)(t + 0x390);
    }
    else if (((ByteFlags*)((char*)obj + 0x3f1))->b20)
    {
        if (*(u8*)((char*)obj + 0x8b3) != 0)
        {
            *(int*)((char*)obj + 0x3f8) = (int)(t + 0x290);
            *(int*)((char*)obj + 0x400) = (int)(t + 0x390);
        }
        else
        {
            *(int*)((char*)obj + 0x3f8) = (int)(t + 0x2d0);
            *(int*)((char*)obj + 0x400) = (int)(t + 0x390);
        }
    }
    else if (*(u8*)((char*)obj + 0x8b3) != 0)
    {
        *(int*)((char*)obj + 0x3f8) = (int)(t + 0x1d0);
        *(int*)((char*)obj + 0x400) = (int)(t + 0x390);
    }
    else
    {
        *(int*)((char*)obj + 0x3f8) = (int)(t + 0x190);
        *(int*)((char*)obj + 0x400) = (int)(t + 0x390);
    }
}

extern f32 lbl_803E8104;
extern f32 lbl_803E8108;
extern f32 lbl_803E810C;
extern f32 lbl_803E8110;

int fn_802AD2F4(GameObject* obj, int inner, int state)
{
    f32 hdiff;
    int sfx;
    f32 v[6];
    char* p35c;
    PlayerState* ps;
    obj->anim.velocityY = -((lbl_803E7EFC * timeDelta) - obj->anim.velocityY);
    p35c = ((char*)inner) + 0x35c;
    switch (obj->anim.currentMove)
    {
    case 0xa:

    case 0x54:

    case 0x90:
        ((PlayerState*)inner)->emissionState = 2;
        break;

    case 0x13:
    {
        f32 zz = lbl_803E7EA4;
        ((PlayerState*)state)->baddie.animSpeedB = zz;
        obj->anim.velocityY = zz;
    }
        if (obj->anim.currentMoveProgress >= (lbl_803E7F10 * ((PlayerState*)state)->baddie.moveSpeed))
        {
            ((ByteFlags*)(((char*)inner) + 0x3f2))->b08 = 0;
        }
        else if ((((PlayerState*)inner)->fallSeverity >= 2) && (((ByteFlags*)(((char*)inner) + 0x3f2))->b04 == 0))
        {
            s8 hv;
            Camera_EnableViewYOffset();
            CameraShake_SetAllMagnitudes(lbl_803E7ED8);
            ObjPath_GetPointWorldPosition((GameObject*)obj, 0xb, &v[3], &v[4], &v[5], 0);
            if (((PlayerState*)inner)->surfaceType == 0x1a)
            {
                hv = 0x14;
            }
            else
            {
                hv = 2;
            }
            ObjHits_RecordPositionHit(obj, 0, hv, 1, 0, v[3], v[4], v[5]);
            ((ByteFlags*)(((char*)inner) + 0x3f2))->b04 = 1;
        }
        if ((*((s8*)(&((PlayerState*)state)->baddie.moveDone))) != 0)
        {
            ((ByteFlags*)(((char*)inner) + 0x3f0))->b04 = 0;
            ((ByteFlags*)(((char*)inner) + 0x3f3))->b40 = 1;
            ((PlayerState*)inner)->staffHoldFrames = 0;
            return 1;
        }
        if (((PlayerState*)inner)->fallSeverity >= 2)
        {
            ((PlayerState*)inner)->emissionState = 4;
        }
        else
        {
            ((PlayerState*)inner)->emissionState = 3;
        }
        break;

    case 0xb:
    {
        f32 zz = lbl_803E7EA4;
        ((PlayerState*)state)->baddie.animSpeedB = zz;
        if ((*((s8*)(&((PlayerState*)state)->baddie.moveDone))) != 0)
        {
            if ((*(*((s8**)p35c))) > 0)
            {
                ObjAnim_SetCurrentMove((int)obj, 0xc, zz, 0);
                ((PlayerState*)state)->baddie.moveSpeed = lbl_803E8038;
            }
            else
            {
                ((ByteFlags*)(((char*)inner) + 0x3f0))->b04 = 0;
                ((PlayerState*)inner)->staffHoldFrames = 0;
                playerDie(obj);
            }
        }
        (*((void (*)(int, int, f32, int))(*((int*)((char*)(*gPlayerInterface) + 0x20)))))((int)obj, state, timeDelta, 2);
        ((PlayerState*)inner)->emissionState = 4;
        break;
    }

    case 0xc:
        if ((((*((int*)(&((PlayerState*)state)->baddie.eventFlags))) & 1) != 0) &&
            (((PlayerState*)inner)->characterId != 0))
        {
            Sfx_PlayFromObject((int)obj, SFXTRIG_fox_bigfallgrunt2);
            Sfx_PlayFromObject((int)obj, SFXTRIG_foot_ladder2);
        }
        if ((*((s8*)(&((PlayerState*)state)->baddie.moveDone))) != 0)
        {
            ((ByteFlags*)(((char*)inner) + 0x3f0))->b04 = 0;
            ((ByteFlags*)(((char*)inner) + 0x3f3))->b40 = 1;
            ((PlayerState*)inner)->staffHoldFrames = 0;
            return 1;
        }
        (*((void (*)(int, int, f32, int))(*((int*)((char*)(*gPlayerInterface) + 0x20)))))((int)obj, state, timeDelta, 2);
        ((PlayerState*)inner)->emissionState = 4;
        break;

    default:
        ObjAnim_SetCurrentMove((int)obj, 0x54, lbl_803E7EA4, 0);
        ObjAnim_SetCurrentEventStepFrames((ObjAnimComponent*)obj, 0x14);
        ((PlayerState*)state)->baddie.moveSpeed = lbl_803E7F6C;
        ((PlayerState*)inner)->emissionState = 2;
        ((PlayerState*)inner)->fallSeverity = 0;
        ((ByteFlags*)(((char*)inner) + 0x3f0))->b01 = 0;
        ((ByteFlags*)(((char*)inner) + 0x3f2))->b08 = 0;
        ((ByteFlags*)(((char*)inner) + 0x3f2))->b04 = 0;
        ((ByteFlags*)(((char*)inner) + 0x3f2))->b02 = 0;
        ((PlayerState*)inner)->prevWorldPosY = obj->anim.worldPosY;
        break;
    }

    ps = (PlayerState*)inner;
    hdiff = ((PlayerState*)inner)->prevWorldPosY - obj->anim.worldPosY;
    if ((((ByteFlags*)(((char*)inner) + 0x3f1))->b01 != 0) && (((ByteFlags*)(((char*)inner) + 0x3f0))->b01 == 0))
    {
        ((ByteFlags*)(((char*)inner) + 0x3f0))->b01 = 1;
        sfx = audioPickSoundEffectIntLegacy(ps->surfaceType, ps->footstepSoundId);
        if (hdiff > lbl_803E8104)
        {
            s8 hv;
            doRumble(lbl_803E7FA4);
            Camera_EnableViewYOffset();
            CameraShake_SetAllMagnitudes(lbl_803E7F58);
            ObjAnim_SetCurrentMove((int)obj, 0xb, lbl_803E7EA4, 0);
            ((PlayerState*)state)->baddie.moveSpeed = lbl_803E7F34;
            Sfx_PlayFromObject((int)obj, SFXTRIG_foot_crawl2);
            Sfx_PlayFromObject((int)obj, SFXTRIG_watery_bubble);
            ObjPath_GetPointWorldPosition((GameObject*)obj, 0xb, &v[3], &v[4], &v[5], 0);
            if (ps->surfaceType == 0x1a)
            {
                hv = 0x14;
            }
            else
            {
                hv = 2;
            }
            ObjHits_RecordPositionHit(obj, 0, hv, 2, 0, v[3], v[4], v[5]);
            ((ByteFlags*)(((char*)inner) + 0x3f2))->b08 = 0;
            if (ps->waterDepth > lbl_803E7FC4)
            {
                Sfx_PlayFromObject((int)obj, SFXTRIG_foot_run_jingle3);
            }
        }
        else if (hdiff > lbl_803E8108)
        {
            doRumble(lbl_803E7ED8);
            ObjAnim_SetCurrentMove((int)obj, 0x13, lbl_803E7EA4, 0);
            ((PlayerState*)state)->baddie.moveSpeed = lbl_803E800C;
            Sfx_PlayFromObject((int)obj, sfx);
            Sfx_StopFromObjectIntLegacy((int)obj,
                                        (u16)((ps->characterId == 0) ? (SFXTRIG_jump2) : (SFXTRIG_sa_climb02)));
            ((ByteFlags*)(((char*)inner) + 0x3f2))->b08 = 1;
            if (ps->waterDepth > lbl_803E7FC4)
            {
                Sfx_PlayFromObject((int)obj, SFXTRIG_foot_run_jingle3_429);
            }
        }
        else if (hdiff > lbl_803E810C)
        {
            doRumble(lbl_803E7ED8);
            ObjAnim_SetCurrentMove((int)obj, 0x13, lbl_803E7EA4, 0);
            ((PlayerState*)state)->baddie.moveSpeed = lbl_803E800C;
            Sfx_PlayFromObject((int)obj, sfx);
            Sfx_PlayFromObject(
                (int)obj, (u16)((((PlayerState*)inner)->characterId == 0) ? (SFXTRIG_panting2) : (SFXTRIG_sa_jump03_var)));
            ((ByteFlags*)(((char*)inner) + 0x3f2))->b08 = 1;
            if (((PlayerState*)inner)->waterDepth > lbl_803E7FC4)
            {
                Sfx_PlayFromObject((int)obj, SFXTRIG_foot_run_jingle3_42a);
            }
        }
        else
        {
            doRumble(lbl_803E7F10);
            Sfx_PlayFromObject(0, sfx);
            ((ByteFlags*)(((char*)inner) + 0x3f0))->b04 = 0;
            ((PlayerState*)inner)->staffHoldFrames = 0;
            ((ByteFlags*)(((char*)inner) + 0x3f1))->b08 = 1;
            ((ByteFlags*)(((char*)inner) + 0x3f2))->b10 = 1;
            ((ByteFlags*)(((char*)inner) + 0x3f2))->b08 = 1;
            if (((PlayerState*)inner)->waterDepth > lbl_803E7FC4)
            {
                Sfx_PlayFromObject((int)obj, SFXTRIG_foot_run_jingle3_42b);
            }
        }
        if (hdiff > lbl_803E810C)
        {
            f32 z2 = lbl_803E7EA4;
            ((PlayerState*)state)->baddie.animSpeedC = z2;
            ((PlayerState*)state)->baddie.animSpeedA = z2;
        }
        ((PlayerState*)state)->baddie.animSpeedB = lbl_803E7EA4;
    }
    if (((ByteFlags*)(((char*)inner) + 0x3f0))->b01 == 0)
    {
        if ((*((f32*)(((char*)state) + 0x1b0))) < lbl_803E80C4)
        {
            ((ByteFlags*)(((char*)inner) + 0x3f2))->b08 = 1;
        }
        if ((hdiff > lbl_803E8104) && (ps->fallSeverity < 3))
        {
            ObjAnim_SetCurrentMove((int)obj, 0xa, lbl_803E7EA4, 0);
            ObjAnim_SetCurrentEventStepFrames((ObjAnimComponent*)obj, 0x19);
            ((PlayerState*)state)->baddie.moveSpeed = lbl_803E7EF8;
            ps->fallSeverity = 3;
            ((ByteFlags*)(((char*)inner) + 0x3f2))->b08 = 0;
        }
        else if ((hdiff > lbl_803E8108) && (ps->fallSeverity < 2))
        {
            if (Sfx_IsPlayingFromObjectIntU16Legacy(
                    0, (u16)((((PlayerState*)inner)->characterId == 0) ? (SFXTRIG_jump2) : (SFXTRIG_sa_climb02))) == 0)
            {
                Sfx_PlayFromObject((int)obj, (u16)((ps->characterId == 0) ? (SFXTRIG_jump2) : (SFXTRIG_sa_climb02)));
            }
            ((PlayerState*)inner)->fallSeverity = 2;
        }
        else if ((hdiff > lbl_803E810C) && (((PlayerState*)inner)->fallSeverity < 1))
        {
            ObjAnim_SetCurrentMove((int)obj, 0x90, lbl_803E7EA4, 0);
            ObjAnim_SetCurrentEventStepFrames((ObjAnimComponent*)obj, 0x19);
            ((PlayerState*)state)->baddie.moveSpeed = lbl_803E7EFC;
            ((PlayerState*)inner)->fallSeverity = 1;
        }
    }
    if ((((ByteFlags*)(((char*)inner) + 0x3f2))->b08 != 0) &&
        ((((PlayerState*)inner)->buttonsJustPressed & 0x400) != 0))
    {
        ((ByteFlags*)(((char*)inner) + 0x3f2))->b02 = 1;
        ((PlayerState*)inner)->buttonsJustPressed = ps->buttonsJustPressed & (~0x400);
    }
    if (((((ByteFlags*)(((char*)inner) + 0x3f0))->b01 != 0) && (((ByteFlags*)(((char*)inner) + 0x3f2))->b02 != 0)) &&
        (ps->fallSeverity < 3))
    {
        fn_802AED2C(obj, inner, state);
        ((ByteFlags*)(((char*)inner) + 0x3f0))->b04 = 0;
        ps->staffHoldFrames = 0;
    }
    if ((ps->fallSeverity == 0) && (((ByteFlags*)(((char*)inner) + 0x3f4))->b10 == 0))
    {
        f32 b;
        f32 a;
        f32 c;
        ps->targetYawSmoothRate = (a = lbl_803E7FBC);
        ps->targetYawRateLimit = (b = lbl_803E7E98);
        ps->yawSmoothRate = a;
        ps->yawRateLimit = b;
        c = lbl_803E7F14;
        ps->targetAnimSpeed = c;
        ps->currentSpeed = ps->currentSpeed * c;
    }
    else
    {
        f32 a;
        f32 b;
        ps->targetYawSmoothRate = (a = lbl_803E7FBC);
        ps->targetYawRateLimit = (b = lbl_803E7EA4);
        ps->yawSmoothRate = a;
        ps->yawRateLimit = b;
        ps->targetAnimSpeed = b;
        ps->currentSpeed = ps->currentSpeed * b;
    }
    ps->currentSpeed = (ps->currentSpeed < lbl_803E8110)
                           ? (lbl_803E8110)
                           : ((ps->currentSpeed > ps->maxSpeed) ? (ps->maxSpeed) : (ps->currentSpeed));
    if (ps->curAnimId == 0x4b)
    {
        (*gCameraInterface)->setMode(0x42, 0, 1, 0, (void*)0, 0, 0xff);
        ps->curAnimId = 0x42;
    }
    return 0;
}


int fn_802ADC08(GameObject* obj, int inner, int p3)
{
    obj->anim.velocityY = obj->anim.velocityY - lbl_803DC67C * timeDelta;
    if (((PlayerState*)inner)->fallFrames > 5 && ((ByteFlags*)((char*)inner + 0x3f1))->b01)
    {
        u16 snd;
        doRumble(lbl_803E7F10);
        Sfx_PlayFromObject((int)obj, (u16)audioPickSoundEffectIntLegacy(((PlayerState*)inner)->surfaceType,
                                                                        ((PlayerState*)inner)->footstepSoundId));
        if (((PlayerState*)inner)->characterId == 0)
        {
            snd = 0x2cf;
        }
        else
        {
            snd = 0x25;
        }
        Sfx_PlayFromObject((int)obj, snd);
        ((ByteFlags*)((char*)inner + 0x3f0))->b08 = 0;
        ((ByteFlags*)((char*)inner + 0x3f1))->b08 = 1;
        ((ByteFlags*)((char*)inner + 0x3f2))->b10 = 1;
    }
    if (obj->anim.worldPosY <= ((PlayerState*)inner)->fallThresholdY ||
        ((*(s8*)((char*)p3 + 0x264) & 2) && (*(s8*)((char*)p3 + 0x264) & 0x20) == 0) || *(u8*)((char*)p3 + 0x262) != 0)
    {
        void* sub;
        ((ByteFlags*)((char*)inner + 0x3f0))->b80 = 0;
        ((ByteFlags*)((char*)inner + 0x3f0))->b10 = 0;
        ((ByteFlags*)((char*)inner + 0x3f0))->b08 = 0;
        staffFn_80170380(gPlayerStaffObject, 2);
        ((ByteFlags*)((char*)inner + 0x3f0))->b02 = 0;
        *(u32*)&((PlayerState*)inner)->flags360 |= PLAYER_FLAG_TELEPORTED;
        ObjHits_SyncObjectPositionIfDirtyLegacy(obj);
        ((ByteFlags*)((char*)inner + 0x3f0))->b40 = 0;
        ((ByteFlags*)((char*)inner + 0x3f0))->b04 = 1;
        ((ByteFlags*)((char*)inner + 0x3f4))->b10 = 0;
        ((PlayerState*)inner)->isHoldingObject = 0;
        sub = *(void**)((char*)inner + 0x7f8);
        if (sub != NULL)
        {
            s16 id = ((GameObject*)sub)->anim.seqId;
            if (id == 0x3cf || id == 0x662)
            {
                objThrowFn_80182504((GameObject*)sub);
            }
            else
            {
                objSaveFn_800ea774((GameObject*)sub);
            }
            *(s16*)((char*)((PlayerState*)inner)->heldObj + 0x6) &= ~0x4000;
            *(int*)((char*)((PlayerState*)inner)->heldObj + 0xf8) = 0;
            ((PlayerState*)inner)->heldObj = 0;
        }
    }
    ((PlayerState*)inner)->fallFrames += 1;
    {
        u32 v = ((PlayerState*)inner)->fallFrames;
        if (v > 0xa)
            v = 0xa;
        ((PlayerState*)inner)->fallFrames = v;
    }
    ((PlayerState*)inner)->emissionState = 1;
    {
        f32 f4, c4;
        ((PlayerState*)inner)->targetYawSmoothRate = (c4 = lbl_803E80C4);
        ((PlayerState*)inner)->targetYawRateLimit = (f4 = lbl_803E7FF4);
        ((PlayerState*)inner)->yawSmoothRate = c4;
        ((PlayerState*)inner)->yawRateLimit = f4;
    }
    ((PlayerState*)inner)->targetAnimSpeed = lbl_803DC684;
    {
        ((PlayerState*)inner)->currentSpeed =
            (((PlayerState*)inner)->currentSpeed < lbl_803E7EA4)
                ? lbl_803E7EA4
                : ((((PlayerState*)inner)->currentSpeed > ((PlayerState*)inner)->maxSpeed)
                       ? ((PlayerState*)inner)->maxSpeed
                       : ((PlayerState*)inner)->currentSpeed);
    }
    return 0;
}

void fn_802ADE80(GameObject* obj, int inner, int state)
{
    f32 t[3];
    f32 waterX;
    f32 waterZ;
    MatrixTransform v;
    struct
    {
        u8 pad[6];
        u16 mode;
        f32 scale;
        f32 x;
        f32 y;
        f32 z;
    } pfx;
    f32 mtx[16];
    f32 angle;
    f32 d;
    f32 accel;
    f32 vel;
    f32 cosv;
    f32 sinv;
    f32 a;
    int playEffect;
    u8 loopCount;
    int i;

    angle = ((PlayerState*)inner)->waterSurfaceY;
    angle = angle + mathSinf(gPlayerPi * (f32)(u32) * (u16*)((char*)inner + 0x89c) / lbl_803E7F98);
    *(s16*)&((PlayerState*)inner)->unk89C = lbl_803E8114 * timeDelta + (f32)(u32) * (u16*)((char*)inner + 0x89c);
    {
        d = angle - obj->anim.localPosY;
        if (d > 25.0f)
        {
            d = 25.0f;
        }
        accel = d / lbl_803E7FA0;
        accel = accel * lbl_803E8118;
        obj->anim.velocityY = accel * timeDelta + obj->anim.velocityY;
    }
    obj->anim.velocityY = obj->anim.velocityY - 0.1f * timeDelta;
    obj->anim.velocityY = obj->anim.velocityY * powfBitEstimate(lbl_803E7FD0, timeDelta);
    {
        vel = obj->anim.velocityY;
        obj->anim.velocityY = (vel < -4.0f) ? -4.0f : ((vel > 1.4f) ? 1.4f : vel);
    }
    ((void (*)(f32*, f32*, f32, int))playerCalcWaterCurrent)(&waterX, &waterZ, lbl_803E7EE0, (int)obj);
    {
        cosv = mathSinf(gPlayerPi * (f32) * (s16*)((char*)inner + 0x478) / lbl_803E7F98);
        sinv = mathCosf(gPlayerPi * (f32) * (s16*)((char*)inner + 0x478) / lbl_803E7F98);
        a = -waterZ * sinv - waterX * cosv;
        ((PlayerState*)inner)->waterCurrentVelB +=
            timeDelta * (0.1f * ((waterX * sinv - waterZ * cosv) - ((PlayerState*)inner)->waterCurrentVelB));
        ((PlayerState*)inner)->waterCurrentVelA += timeDelta * (0.1f * (a - ((PlayerState*)inner)->waterCurrentVelA));
    }
    playEffect = 0;
    if (((PlayerState*)state)->baddie.controlMode == 1)
    {
        if ((*(int*)&((PlayerState*)state)->baddie.eventFlags & 0x200) != 0)
        {
            ((void (*)(int, f32, f32, f32, int))Sfx_PlayAtPositionFromObject)((int)obj, obj->anim.localPosX,
                                                                              ((PlayerState*)inner)->waterSurfaceY,
                                                                              obj->anim.localPosZ, 0xe);
        }
        if (((PlayerState*)inner)->waterDepth < lbl_803E7FA0 &&
            (*(int*)&((PlayerState*)state)->baddie.eventFlags & 0x200) != 0)
        {
            t[0] = (f32)randomGetRange(-0x14, 0x14) / lbl_803E7ED8;
            t[2] = (f32)randomGetRange(-0x14, 0x14) / lbl_803E7ED8;
            playEffect = 1;
        }
    }
    else
    {
        if ((*(int*)&((PlayerState*)state)->baddie.eventFlags & 1) != 0)
        {
            ((void (*)(int, f32, f32, f32, int))Sfx_PlayAtPositionFromObject)((int)obj, obj->anim.localPosX,
                                                                              ((PlayerState*)inner)->waterSurfaceY,
                                                                              obj->anim.localPosZ, 0xf);
        }
        if (((PlayerState*)inner)->waterDepth < lbl_803E7FA0 &&
            (*(int*)&((PlayerState*)state)->baddie.eventFlags & 0x200) != 0)
        {
            s8 c;
            t[0] = (f32)randomGetRange(-0x14, 0x14) / lbl_803E7ED8;
            c = ((PlayerState*)inner)->gaitLevel;
            if (c <= 8)
            {
                t[2] = lbl_803E8124;
            }
            else if (c <= 0xc)
            {
                t[2] = lbl_803E8124;
            }
            else
            {
                t[2] = lbl_803E8124;
            }
            playEffect = 1;
        }
    }
    if (playEffect != 0)
    {
        v.x = obj->anim.localPosX;
        v.y = lbl_803E7EA4;
        v.z = obj->anim.localPosZ;
        v.rotX = ((PlayerState*)inner)->targetYaw;
        v.rotY = 0;
        v.rotZ = 0;
        v.scale = lbl_803E7EE0;
        setMatrixFromObjectPos(mtx, &v);
        Matrix_TransformPoint(mtx, t[0], lbl_803E7EA4, t[2], &t[0], &t[1], &t[2]);
        (*gWaterfxInterface)->spawnRipple(
            t[0], ((PlayerState*)inner)->waterSurfaceY, t[2], 0, lbl_803E7EA4, 5);
        if (((PlayerState*)inner)->waterDepth > lbl_803E8128 && ((PlayerState*)state)->baddie.animSpeedC > lbl_803E7E9C)
        {
            u16 ang = ((PlayerState*)inner)->targetYaw -
                      getAngle(((PlayerState*)state)->baddie.animSpeedB, ((PlayerState*)state)->baddie.animSpeedA);
            Waterfx_SpawnSimpleRippleLegacy((*gWaterfxInterface), t[0],
                                            ((PlayerState*)inner)->waterSurfaceY, t[2], ang, lbl_803E7EA4);
        }
    }
    ObjPath_GetPointWorldPosition((GameObject*)obj, 0x13, &v.x, &v.y, &v.z, 0);
    loopCount = (((PlayerState*)inner)->waterSurfaceY - v.y > lbl_803E7F10) ? 1 : 0;
    for (i = 0; i < loopCount; i++)
    {
        pfx.x = v.x + (f32)randomGetRange(-0x64, 0x64) / 20.0f;
        pfx.y = v.y + (f32)randomGetRange(-0x64, 0x64) / 50.0f;
        pfx.z = v.z + (f32)randomGetRange(-0x64, 0x64) / 20.0f;
        pfx.scale = ((PlayerState*)inner)->waterSurfaceY - pfx.y;
        if (pfx.scale > 0.0f)
        {
            (*gPartfxInterface)->spawnObject((void*)obj, 0x202, &pfx, 0x200001, -1, NULL);
        }
    }
}

int fn_802AE480(GameObject* obj, int inner, int state)
{
    f32 h;
    f32 lim;

    *(u32*)&((PlayerState*)inner)->flags360 |= PLAYER_FLAG_HEADING_LOCK;
    ((PlayerState*)state)->baddie.moveSpeed = lbl_803E7F20;
    h = obj->anim.currentMoveProgress;
    if (h > lbl_803E7EFC && h < lbl_803E7F44 &&
        ((PlayerState*)state)->baddie.animSpeedC >
            *(f32*)((char*)((PlayerState*)inner)->moveParams + 0x1c) - lbl_803E7E9C &&
        ((PlayerState*)state)->baddie.inputMagnitude > lbl_803E7F2C && ((PlayerState*)inner)->yawRateSigned >= 0x96)
    {
        ((ByteFlags*)((char*)inner + 0x3f0))->b40 = 1;
        ((ByteFlags*)((char*)inner + 0x3f0))->b80 = 0;
        ((PlayerState*)inner)->animSoundId = ((PlayerState*)inner)->altAnimSoundId;
        ((PlayerState*)state)->baddie.moveSpeed = lbl_803E8070;
        ObjAnim_SetCurrentMove((int)obj, *(s16*)((char*)((PlayerState*)inner)->moveAnimTable + 0x3a), lbl_803E7EA4, 0);
        ObjAnim_SetCurrentEventStepFrames((ObjAnimComponent*)obj, 0x10);
        ((PlayerState*)inner)->unk858 = ((PlayerState*)inner)->yaw;
        ((PlayerState*)inner)->unk844 = (lbl_803E7F14 + (*(f32*)((char*)((PlayerState*)inner)->moveParams + 0x14) +
                                                         ((PlayerState*)state)->baddie.animSpeedC)) /
                                        lbl_803E7F30;
        ((PlayerState*)inner)->targetYaw = ((PlayerState*)inner)->yaw;
        ((PlayerState*)inner)->yaw += 0x8000;
        ((PlayerState*)state)->baddie.animSpeedC = -((PlayerState*)state)->baddie.animSpeedC;
        ((PlayerState*)state)->baddie.animSpeedA = -((PlayerState*)state)->baddie.animSpeedA;
    }
    if (((ByteFlags*)((char*)inner + 0x3f0))->b80)
    {
        if (((PlayerState*)state)->baddie.animSpeedC <=
                (lim = *(f32*)((char*)((PlayerState*)inner)->moveParams + 0x10)) &&
            ((PlayerState*)state)->baddie.animSpeedA <= lim)
        {
            ((PlayerState*)inner)->lastInputHeading = ((PlayerState*)inner)->yaw;
            ((ByteFlags*)((char*)inner + 0x3f0))->b40 = 0;
            ((ByteFlags*)((char*)inner + 0x3f0))->b80 = 0;
            return 1;
        }
        ((PlayerState*)inner)->currentSpeed = lbl_803E7EA4;
        ((PlayerState*)inner)->velSmoothRate = ((PlayerState*)inner)->velSmoothRateBase;
    }
    return 0;
}

extern int lbl_803E7E68;
extern int lbl_803E7E6C;


void fn_802AE650(GameObject* obj, int state, int p3)
{
    f32 v;
    u32 b;
    f32 ee0;

    (*(void (*)(int, int, f32, int))(*(int*)((char*)*gPlayerInterface + 0x20)))((int)obj, p3, timeDelta, 1);
    if (obj->anim.currentMoveProgress >=
        (ee0 = lbl_803E7EE0) - lbl_803E7F50 * ((PlayerState*)p3)->baddie.moveSpeed)
    {
        ((PlayerState*)p3)->baddie.animSpeedA =
            ((PlayerState*)state)->unk844 * ((lbl_803E7F14 + *(f32*)((char*)((PlayerState*)state)->moveParams + 0x14)) -
                                             ((PlayerState*)p3)->baddie.animSpeedA) +
            *(f32*)&((PlayerState*)p3)->baddie.animSpeedA;
        ((PlayerState*)p3)->baddie.animSpeedC = ((PlayerState*)p3)->baddie.animSpeedA;
        ((PlayerState*)state)->unk844 = lbl_803E7EFC * timeDelta + ((PlayerState*)state)->unk844;
        v = ((PlayerState*)state)->unk844;
        ((PlayerState*)state)->unk844 = (v < lbl_803E7EA4) ? lbl_803E7EA4 : ((v > ee0) ? ee0 : v);
    }
    if ((*(int*)&((PlayerState*)p3)->baddie.eventFlags & 0x200) != 0)
    {
        doRumble(lbl_803E7F10);
        Sfx_PlayFromObject((int)obj, SFXTRIG_rserv1_c);
        ((PlayerState*)state)->pendingFxFlags |= 4;
    }
    {
        f32 fa4 = lbl_803E7FA4;
        ((PlayerState*)state)->targetYawSmoothRate = fa4;
        ((PlayerState*)state)->yawSmoothRate = fa4;
    }
    b = (((PlayerState*)state)->flags3F1 >> 4) & 1;
    if (b != 0)
    {
        f32 ea4 = lbl_803E7EA4;
        ((PlayerState*)state)->targetYawRateLimit = ea4;
        ((PlayerState*)state)->yawRateLimit = ea4;
    }
    else
    {
        f32 ed4 = lbl_803E7ED4;
        ((PlayerState*)state)->targetYawRateLimit = ed4;
        ((PlayerState*)state)->yawRateLimit = ed4;
    }
    ((PlayerState*)state)->knockbackDrainRate = lbl_803E80E4;
    if (obj->anim.currentMoveProgress >= lbl_803E7EE0)
    {
        short tmp;
        ((ByteFlags*)((char*)state + 0x3f0))->b10 = 0;
        gPlayerSubState = 1;
        ((ByteFlags*)((char*)state + 0x3f1))->b02 = 1;
        ((ByteFlags*)((char*)state + 0x3f1))->b08 = 1;
        *(u8*)&((PlayerState*)state)->gaitLevel = 0xc;
        tmp = ((PlayerState*)state)->yaw;
        ((PlayerState*)state)->targetYaw = tmp;
        ((PlayerState*)state)->lastInputHeading = tmp;
        ObjAnim_SetCurrentMove((int)obj, ((s16*)gPlayerMoveTableA)[(s8) * (u8*)((char*)state + 0x8cc)], lbl_803E7EA4, 0);
        ObjAnim_SetCurrentEventStepFrames((ObjAnimComponent*)obj, 1);
    }
}



void fn_802AE83C(int obj, int inner)
{
    GameObject* sub;
    f32 z;

    ((ByteFlags*)((char*)inner + 0x3f1))->b40 = 0;
    ((ByteFlags*)((char*)inner + 0x3f0))->b40 = 0;
    ((ByteFlags*)((char*)inner + 0x3f0))->b80 = 0;
    ((ByteFlags*)((char*)inner + 0x3f0))->b08 = 0;
    ((ByteFlags*)((char*)inner + 0x3f0))->b04 = 0;
    ((PlayerState*)inner)->staffHoldFrames = 0;
    ((ByteFlags*)((char*)inner + 0x3f0))->b20 = 1;
    ((ByteFlags*)((char*)inner + 0x3f0))->b10 = 0;
    z = lbl_803E7EA4;
    ((PlayerState*)inner)->waterCurrentVelB = z;
    ((PlayerState*)inner)->waterCurrentVelA = z;
    Sfx_StopFromObjectIntLegacy(
        obj, (u16)(((PlayerState*)inner)->characterId == 0 ? SFXTRIG_jump2 : SFXTRIG_sa_climb02));

    if ((void*)gPlayerPathObject != NULL && ((ByteFlags*)((char*)inner + 0x3f4))->b40)
    {
        ((PlayerState*)inner)->staffActionRequest = 1;
        ((ByteFlags*)((char*)inner + 0x3f4))->b08 = 1;
    }
    ((PlayerState*)inner)->isHoldingObject = 0;
    sub = ((PlayerState*)inner)->heldObj;
    if (sub != NULL)
    {
        s16 id = sub->anim.seqId;
        if (id == 0x3cf || id == 0x662)
        {
            objThrowFn_80182504(sub);
        }
        else
        {
            objSaveFn_800ea774(sub);
        }
        *(s16*)((char*)((PlayerState*)inner)->heldObj + 6) &= ~0x4000;
        *(int*)((char*)((PlayerState*)inner)->heldObj + 0xf8) = 0;
        ((PlayerState*)inner)->heldObj = 0;
    }
    if (((GameObject*)obj)->anim.velocityY < lbl_803E812C)
    {
        Sfx_PlayFromObject(obj, SFXTRIG_mv_curtainopen16_212);
        (*gWaterfxInterface)
            ->spawnSplashBurst((void*)obj, ((GameObject*)obj)->anim.localPosX, ((GameObject*)obj)->anim.localPosY,
                               ((GameObject*)obj)->anim.localPosZ, lbl_803E7ED8);
    }
}



void fn_802AE9C8(GameObject* obj, int inner, int state)
{
    if (obj->anim.currentMoveProgress > lbl_803E7E98)
    {
        ObjAnim_SetCurrentMove((int)obj, 0x91, lbl_803E7EA4, 0);
    }
    else
    {
        ObjAnim_SetCurrentMove((int)obj, 0x12, lbl_803E7EA4, 0);
    }
    ObjAnim_SetCurrentEventStepFrames((ObjAnimComponent*)obj, 0xf);

    ((PlayerState*)inner)->maxSpeed = lbl_803E8068;
    ((PlayerState*)inner)->currentSpeed = lbl_803E7EA0 * (lbl_803E806C * ((PlayerState*)state)->baddie.inputMagnitude) +
                                          lbl_803E7EB4 * ((PlayerState*)state)->baddie.animSpeedC;
    ((PlayerState*)inner)->currentSpeed = (((PlayerState*)inner)->currentSpeed < lbl_803E7F18)
                                              ? lbl_803E7F18
                                              : ((((PlayerState*)inner)->currentSpeed > ((PlayerState*)inner)->maxSpeed)
                                                     ? ((PlayerState*)inner)->maxSpeed
                                                     : ((PlayerState*)inner)->currentSpeed);
    {
        f32 a = ((PlayerState*)inner)->currentSpeed;
        ((PlayerState*)state)->baddie.animSpeedA = a;
        ((PlayerState*)state)->baddie.animSpeedC = a;
    }

    obj->anim.velocityY = ((PlayerState*)state)->baddie.animSpeedA / lbl_803E8068;
    {
        f32 v = obj->anim.velocityY;
        f32 clamped;
        if (v < lbl_803E7EA4)
        {
            clamped = lbl_803E7EA4;
        }
        else if (v > lbl_803E7EE0)
        {
            clamped = lbl_803E7EE0;
        }
        else
        {
            clamped = v;
        }
        obj->anim.velocityY = clamped;
    }
    obj->anim.velocityY = obj->anim.velocityY * lbl_803DC680;
    obj->anim.velocityY =
        (obj->anim.velocityY < lbl_803E7E98)
            ? lbl_803E7E98
            : ((obj->anim.velocityY > lbl_803DC680) ? lbl_803DC680 : obj->anim.velocityY);
    ((PlayerState*)state)->baddie.moveSpeed = lbl_803E7EE0 / (lbl_803E7ED4 * lbl_803DC680 / lbl_803DC67C);
    ((PlayerState*)inner)->groundRefY = obj->anim.worldPosY;
    ((PlayerState*)inner)->fallThresholdY = obj->anim.worldPosY - lbl_803E7ED8;

    ((ByteFlags*)((char*)inner + 0x3f0))->b08 = 1;
    ((ByteFlags*)((char*)inner + 0x3f0))->b04 = 0;
    ((PlayerState*)inner)->staffHoldFrames = 0;
    ((ByteFlags*)((char*)inner + 0x3f0))->b10 = 0;
    ((ByteFlags*)((char*)inner + 0x3f0))->b80 = 0;
    staffFn_80170380(gPlayerStaffObject, 2);
    ((ByteFlags*)((char*)inner + 0x3f0))->b02 = 0;
    *(u32*)&((PlayerState*)inner)->flags360 |= PLAYER_FLAG_TELEPORTED;
    ObjHits_SyncObjectPositionIfDirtyLegacy(obj);
    if (((ByteFlags*)((char*)inner + 0x3f0))->b40)
    {
        ((PlayerState*)inner)->yaw += -0x8000;
    }
    ((ByteFlags*)((char*)inner + 0x3f0))->b40 = 0;
    ((ByteFlags*)((char*)inner + 0x3f1))->b01 = 0;
    ((PlayerState*)inner)->fallFrames = 0;
    if (((ByteFlags*)((char*)inner + 0x3f1))->b20)
    {
        int t = *(s16*)obj;
        ((PlayerState*)inner)->yaw = t;
        ((PlayerState*)inner)->targetYaw = t;
        ((PlayerState*)inner)->lastInputHeading = t;
        ((PlayerState*)inner)->baddie.animSpeedB = lbl_803E7EA4;
    }
    ((ByteFlags*)((char*)inner + 0x3f1))->b20 = 0;
    if (((ByteFlags*)((char*)inner + 0x3f1))->b10 && ((PlayerState*)inner)->curAnimId != 0x48 &&
        ((PlayerState*)inner)->curAnimId != 0x47 && getCurSeqNoInt() == 0)
    {
        (*gCameraInterface)->setMode(0x42, 0, 1, 0, NULL, 0x1e, 0xff);
        ((ByteFlags*)((char*)inner + 0x3f1))->b10 = 0;
    }
    {
        u16 sfxId;
        if (((PlayerState*)inner)->characterId == 0)
        {
            sfxId = 0x2d7;
        }
        else
        {
            sfxId = 0x2d6;
        }
        Sfx_PlayFromObject((int)obj, sfxId);
    }
    ((PlayerState*)inner)->isHoldingObject = 0;
    {
        void* sub = *(void**)((char*)inner + 0x7f8);
        if (sub != NULL)
        {
            s16 id = ((GameObject*)sub)->anim.seqId;
            if (id == 0x3cf || id == 0x662)
            {
                objThrowFn_80182504((GameObject*)sub);
            }
            else
            {
                objSaveFn_800ea774((GameObject*)sub);
            }
            *(s16*)((char*)((PlayerState*)inner)->heldObj + 0x6) &= ~0x4000;
            *(int*)((char*)((PlayerState*)inner)->heldObj + 0xf8) = 0;
            ((PlayerState*)inner)->heldObj = 0;
        }
    }
}


void fn_802AED2C(GameObject* obj, int state, int p3)
{
    u16 sound;
    u32 b;

    if (((PlayerState*)state)->staffGrown != 0)
    {
        ObjAnim_SetCurrentMove((int)obj, 0x47f, lbl_803E7EA4, 0);
    }
    else
    {
        ObjAnim_SetCurrentMove((int)obj, 0x47b, lbl_803E7EA4, 0);
    }
    ((PlayerState*)p3)->baddie.moveSpeed = lbl_803E7F20;
    ((PlayerState*)state)->targetYaw = ((PlayerState*)state)->yaw;
    ((PlayerState*)state)->unk844 = lbl_803E7EA4;
    ((ByteFlags*)((char*)state + 0x3f0))->b10 = 1;
    ((ByteFlags*)((char*)state + 0x3f0))->b80 = 0;
    staffFn_80170380(gPlayerStaffObject, 2);
    ((ByteFlags*)((char*)state + 0x3f0))->b02 = 0;
    *(u32*)&((PlayerState*)state)->flags360 |= PLAYER_FLAG_TELEPORTED;
    ObjHits_SyncObjectPositionIfDirtyLegacy(obj);
    ((ByteFlags*)((char*)state + 0x3f0))->b08 = 0;
    ((ByteFlags*)((char*)state + 0x3f0))->b04 = 0;
    ((PlayerState*)state)->staffHoldFrames = 0;
    ((ByteFlags*)((char*)state + 0x3f0))->b40 = 0;
    ((PlayerState*)state)->yawRateSigned = 0;
    ((PlayerState*)state)->targetYawRateSigned = 0;
    ((PlayerState*)state)->yawRate = 0;
    ((PlayerState*)state)->targetYawRate = 0;
    gPlayerSubState = 4;
    ((PlayerState*)state)->isHoldingObject = 0;
    if (*(void**)((char*)state + 0x7f8) != NULL)
    {
        short id = ((GameObject*)((PlayerState*)state)->heldObj)->anim.seqId;
        if (id == 0x3cf || id == 0x662)
        {
            objThrowFn_80182504((GameObject*)(((PlayerState*)state)->heldObj));
        }
        else
        {
            objSaveFn_800ea774((GameObject*)((PlayerState*)state)->heldObj);
        }
        *(s16*)((char*)((PlayerState*)state)->heldObj + 6) &= ~0x4000;
        *(int*)((char*)((PlayerState*)state)->heldObj + 0xf8) = 0;
        ((PlayerState*)state)->heldObj = 0;
    }
    b = (((PlayerState*)state)->flags3F1 >> 5) & 1;
    if (b != 0)
    {
        short t = obj->anim.rotX;
        ((PlayerState*)state)->yaw = t;
        ((PlayerState*)state)->targetYaw = t;
        ((PlayerState*)state)->lastInputHeading = t;
        ((PlayerState*)state)->baddie.animSpeedB = lbl_803E7EA4;
    }
    ((ByteFlags*)((char*)state + 0x3f1))->b20 = 0;
    if (((PlayerState*)state)->waterDepth > lbl_803E7EE0)
    {
        if (((PlayerState*)state)->characterId == 0)
        {
            sound = 0x427;
        }
        else
        {
            sound = 0x427;
        }
        Sfx_PlayFromObject((int)obj, sound);
    }
    else
    {
        if (((PlayerState*)state)->characterId == 0)
        {
            sound = 0x3ce;
        }
        else
        {
            sound = 0x2e;
        }
        Sfx_PlayFromObject((int)obj, sound);
    }
}

void staffAnimate(int obj, int state)
{
    int prevChanged;
    int changed;
    int model;
    f32 f31;
    void* p;

    model = *(int*)((char*)Obj_GetActiveModel((GameObject*)obj) + 0x30);
    prevChanged = 0;

    if (*(s16*)&((PlayerState*)state)->staffAnimState != 3)
    {
        u8 b = ((PlayerState*)state)->staffActionRequest;
        if (b == 1)
        {
            staffDoGrowShrinkAnim((GameObject*)gPlayerPathObject, 0, ((ByteFlags*)((char*)state + 0x3f4))->b08, 0);
            ((PlayerState*)state)->staffGrown = 0;
            if (*(s16*)&((PlayerState*)state)->staffAnimState != 0 &&
                *(s16*)&((PlayerState*)state)->staffAnimState != 0xf)
            {
                *(s16*)&((PlayerState*)state)->staffAnimState = 3;
            }
        }
        else if (b == 4)
        {
            staffDoGrowShrinkAnim((GameObject*)gPlayerPathObject, 1, ((ByteFlags*)((char*)state + 0x3f4))->b08, 0);
            ((PlayerState*)state)->staffGrown = 1;
            if (*(s16*)&((PlayerState*)state)->staffAnimState != 0 &&
                *(s16*)&((PlayerState*)state)->staffAnimState != 0xf)
            {
                *(s16*)&((PlayerState*)state)->staffAnimState = 3;
            }
        }
    }

    f31 = -lbl_803E7F20;
    do
    {
        changed = 0;
        switch (*(s16*)&((PlayerState*)state)->staffAnimState)
        {
        case 2:
            if (prevChanged != 0)
            {
                ((int (*)(int, int, f32, int))Object_ObjAnimSetMove)(obj, ((GameObject*)obj)->anim.currentMove,
                                                                     ((GameObject*)obj)->anim.currentMoveProgress, 0);
                p = *(void**)((char*)state + 0x4b8);
                if (p != NULL && (*(s16*)((char*)p + 0x44) == 0x1c || *(s16*)((char*)p + 0x44) == 0x2a))
                {
                    ((int (*)(int, int, f32, int))Object_ObjAnimSetMove)(obj, 0x82, lbl_803E7EA4, 0);
                }
                else
                {
                    ((int (*)(int, int, f32, int))Object_ObjAnimSetMove)(obj, 0x8d, lbl_803E7EA4, 0);
                }
                ObjAnim_SetCurrentEventStepFrames((ObjAnimComponent*)obj, 0xc);
            }
            if (((GameObject*)obj)->anim.activeMoveProgress >= lbl_803E8130)
            {
                ((PlayerState*)state)->staffGrown = 1;
            }
            if (((GameObject*)obj)->anim.activeMoveProgress >= lbl_803E7F1C)
            {
                staffDoGrowShrinkAnim((GameObject*)gPlayerPathObject, 1, 0, 0);
                *(s16*)&((PlayerState*)state)->staffAnimState = 3;
                changed = 1;
            }
            else
            {
                ((int (*)(int, f32, f32, int))Object_ObjAnimAdvanceMove)(obj, lbl_803E7F20, lbl_803E7EE0, 0);
            }
            break;
        case 1:
            if (prevChanged != 0)
            {
                ((int (*)(int, int, f32, int))Object_ObjAnimSetMove)(obj, ((GameObject*)obj)->anim.currentMove,
                                                                     ((GameObject*)obj)->anim.currentMoveProgress, 0);
                p = *(void**)((char*)state + 0x4b8);
                if (p != NULL && (*(s16*)((char*)p + 0x44) == 0x1c || *(s16*)((char*)p + 0x44) == 0x2a))
                {
                    ((int (*)(int, int, f32, int))Object_ObjAnimSetMove)(obj, 0x82, lbl_803E7F68, 0);
                }
                else
                {
                    ((int (*)(int, int, f32, int))Object_ObjAnimSetMove)(obj, 0x8d, lbl_803E7F68, 0);
                }
                ObjAnim_SetCurrentEventStepFrames((ObjAnimComponent*)obj, 0xc);
            }
            if (((GameObject*)obj)->anim.activeMoveProgress <= lbl_803E8130)
            {
                ((PlayerState*)state)->staffGrown = 0;
            }
            if (((GameObject*)obj)->anim.activeMoveProgress <= lbl_803E7EB4)
            {
                *(s16*)&((PlayerState*)state)->staffAnimState = 3;
                changed = 1;
            }
            else
            {
                ((int (*)(int, f32, f32, int))Object_ObjAnimAdvanceMove)(obj, f31, lbl_803E7EE0, 0);
            }
            break;
        case 0xf:
            if (prevChanged != 0)
            {
                ((int (*)(int, int, f32, int))Object_ObjAnimSetMove)(obj, ((GameObject*)obj)->anim.currentMove,
                                                                     ((GameObject*)obj)->anim.currentMoveProgress, 0);
                ((int (*)(int, int, f32, int))Object_ObjAnimSetMove)(
                    obj, lbl_8033366C[((PlayerState*)state)->moveVariantIndex], lbl_803E7EA4, 0);
                ObjAnim_SetCurrentEventStepFrames((ObjAnimComponent*)obj, 0xc);
            }
            if (((GameObject*)obj)->anim.activeMoveProgress >= lbl_803E7EE0)
            {
                goto set806_3;
            }
            else
            {
                int ok;
                ByteFlags* bf = (ByteFlags*)((char*)state + 0x3f0);
                if (bf->b10 || bf->b04 || bf->b08 || bf->b20 || ((PlayerState*)state)->baddie.controlMode == 0x36)
                {
                    ok = 0;
                }
                else
                {
                    s16 t = ((PlayerState*)state)->baddie.controlMode;
                    if ((u16)(t - 1) <= 1 || (u16)(t - 0x24) <= 1 || ((PlayerState*)state)->baddie.targetObj != NULL)
                    {
                        ok = 1;
                    }
                    else
                    {
                        ok = 0;
                    }
                }
                if (!ok)
                {
                set806_3:
                    *(s16*)&((PlayerState*)state)->staffAnimState = 3;
                    ((PlayerState*)state)->moveVariantIndex = 0xff;
                    changed = 1;
                }
                else
                {
                    ((int (*)(int, f32, f32, int))Object_ObjAnimAdvanceMove)(
                        obj, lbl_8033369C[((PlayerState*)state)->moveVariantIndex], timeDelta, 0);
                }
            }
            break;
        case 3:
            if (((GameObject*)obj)->anim.activeMove != ((GameObject*)obj)->anim.currentMove)
            {
                ((int (*)(int, int, f32, int))Object_ObjAnimSetMove)(obj, ((GameObject*)obj)->anim.currentMove,
                                                                     ((GameObject*)obj)->anim.currentMoveProgress, 0);
            }
            if (*(u16*)((char*)model + 0x58) == 0)
            {
                ((GameObject*)obj)->anim.activeMove = -1;
                *(s16*)&((PlayerState*)state)->staffAnimState = 0;
            }
            else
            {
                ((int (*)(int, f32, f32, int))Object_ObjAnimAdvanceMove)(obj, lbl_803E7EA4, timeDelta, 0);
                ((int (*)(ObjAnimComponent*, f32))Object_ObjAnimSetMoveProgress)(
                    (ObjAnimComponent*)obj, ((GameObject*)obj)->anim.currentMoveProgress);
            }
            break;
        default:
            if (((PlayerState*)state)->staffGrown != 0)
            {
                if (((PlayerState*)state)->staffActionRequest == 0)
                {
                    staffDoGrowShrinkAnim((GameObject*)gPlayerPathObject, 0, 0, 0);
                    *(s16*)&((PlayerState*)state)->staffAnimState = 1;
                    changed = 1;
                }
            }
            else if (((PlayerState*)state)->staffActionRequest == 2)
            {
                *(s16*)&((PlayerState*)state)->staffAnimState = 2;
                changed = 1;
            }
            if (((PlayerState*)state)->moveVariantIndex == 5 || ((PlayerState*)state)->moveVariantIndex == 7)
            {
                *(s16*)&((PlayerState*)state)->staffAnimState = 0xf;
                changed = 1;
            }
            break;
        }
        prevChanged = changed;
    } while (changed != 0);
}

void playerProcessQueuedItemCommand(GameObject* obj, int state)
{
    u8 noMatch;
    s16 cmd;
    s16 item;

    if (((PlayerState*)state)->buttonsJustPressed & PAD_BUTTON_Y)
    {
        int yButtonItemResult;
        if (((PlayerState*)state)->buttonsJustPressed & PAD_BUTTON_Y)
        {
            yButtonItemResult = getYButtonItemLegacy(&item);
        }
        if (yButtonItemResult == 1)
        {
            buttonDisable(0, PAD_BUTTON_Y);
            ((PlayerState*)state)->buttonsJustPressed &= ~PAD_BUTTON_Y;
            ((PlayerState*)state)->queuedItemCommand = item;
        }
    }

    cmd = ((PlayerState*)state)->queuedItemCommand;
    if (cmd != -1 && cmd != ((PlayerState*)state)->animState && getCurSeqNoInt() == 0)
    {
        s16 sel = ((PlayerState*)state)->queuedItemCommand;
        noMatch = 0;
        switch (sel)
        {
        case GAMEBIT_STAFF_ABILITY_FIRE_BLASTER:
        case 0x958:
        case GAMEBIT_STAFF_ABILITY_FREEZE_BLAST:
            if (playerCanCastBlasterSpell(obj, state, sel) != 0)
            {
                ByteFlags* f1 = (ByteFlags*)((char*)state + 0x3f1);
                u8 c8;
                if (((PlayerState*)state)->baddie.targetObj != NULL)
                {
                    break;
                }
                c8 = ((PlayerState*)state)->curAnimId;
                if (c8 == 0x49)
                {
                    break;
                }
                if (c8 == 0x52 && !f1->b20 && !f1->b10 && ((PlayerState*)state)->baddie.controlMode != 0x1d)
                {
                    break;
                }
                if (f1->b20)
                {
                    s16 v = obj->anim.rotX;
                    ((PlayerState*)state)->yaw = v;
                    ((PlayerState*)state)->targetYaw = v;
                    ((PlayerState*)state)->lastInputHeading = v;
                    ((PlayerState*)state)->baddie.animSpeedB = lbl_803E7EA4;
                }
                f1->b20 = 0;
                if (f1->b10)
                {
                    u8 c = ((PlayerState*)state)->curAnimId;
                    if (c != 0x48 && c != 0x47 && getCurSeqNoInt() == 0)
                    {
                        (*gCameraInterface)->setMode(0x42, 0, 1, 0, NULL, 0x1e, 0xff);
                        f1->b10 = 0;
                    }
                }
                cameraSetInterpMode(2);
                (*gCameraInterface)->setMode(0x52, 1, 0, 0, NULL, 0x2d, 0xff);
                ((ByteFlags*)((char*)state + 0x3f6))->b40 = 1;
                (*(void (*)(int, int, int))(*(int*)((char*)*gPlayerInterface + 0x14)))((int)obj, state, 0x2a);
                *(int*)&((PlayerState*)state)->baddie.unk304 = (int)fn_8029A4A8;
                playerCastSpell((int)obj, state, ((PlayerState*)state)->queuedItemCommand);
            }
            else
            {
                noMatch = 1;
            }
            break;
        case 0x957:
            if (fn_802A97D0(obj, state) != 0)
            {
                playerCastSpell((int)obj, state, ((PlayerState*)state)->queuedItemCommand);
            }
            else
            {
                noMatch = 1;
            }
            break;
        case 0x107:
        case 0xc55:
            if (playerCanCastQuakeSpell(obj, state) != 0)
            {
                playerCastSpell((int)obj, state, ((PlayerState*)state)->queuedItemCommand);
            }
            else
            {
                noMatch = 1;
            }
            break;
        case 0x40:
        {
            PlayerState* inner = obj->extra;
            int ok;
            if (((PlayerState*)state)->baddie.targetObj != NULL || *(s16*)((char*)inner->playerStatus + 4) < 0xa ||
                ((ByteFlags*)((char*)inner + 0x3f3))->b08)
            {
                ok = 0;
            }
            else if (((PlayerState*)state)->baddie.controlMode == 1 || ((PlayerState*)state)->baddie.controlMode == 2)
            {
                ok = 1;
            }
            else
            {
                ok = 0;
            }
            if (ok && !((ByteFlags*)((char*)state + 0x3f3))->b08)
            {
                playerCastSpell((int)obj, state, sel);
            }
            else
            {
                noMatch = 1;
            }
            break;
        }
        case 0x5bd:
            if (playerCanCastPortalOpenSpell(obj, state) != 0)
            {
                playerCastSpell((int)obj, state, ((PlayerState*)state)->queuedItemCommand);
            }
            else
            {
                noMatch = 1;
            }
            break;
        default:
            playerCastSpell((int)obj, state, sel);
            break;
        }
        if (noMatch)
        {
            Sfx_PlayFromObject(0, SFXTRIG_id_10a);
        }
    }

    ((PlayerState*)state)->queuedItemCommand = -1;
}

void playerRunActiveSpells(GameObject* obj, int state)
{
    int inner;
    u8 result;
    void** p;
    int z[2];
    int v;
    if (playerIsBlasterSpellAvailable(obj, state, GAMEBIT_STAFF_ABILITY_FIRE_BLASTER) != 0)
    {
        mainSetBits(GAMEBIT_ITEM_Spell0965_Disabled, 0);
        mainSetBits(GAMEBIT_ITEM_FireBlaster_Disabled, 0);
    }
    else
    {
        mainSetBits(GAMEBIT_ITEM_Spell0965_Disabled, 1);
        mainSetBits(GAMEBIT_ITEM_FireBlaster_Disabled, 1);
    }
    if (playerIsBlasterSpellAvailable(obj, state, GAMEBIT_STAFF_ABILITY_FREEZE_BLAST) != 0)
    {
        mainSetBits(GAMEBIT_ITEM_Spell0961_Disabled, 0);
    }
    else
    {
        mainSetBits(GAMEBIT_ITEM_Spell0961_Disabled, 1);
    }
    inner = *(int*)&obj->extra;
    if (((PlayerState*)state)->baddie.targetObj != NULL || *(s16*)(((PlayerState*)inner)->playerStatus + 4) < 0xa ||
        ((ByteFlags*)((char*)inner + 0x3f3))->b08 != 0)
    {
        result = 0;
    }
    else if (((PlayerState*)state)->baddie.controlMode == 1 || ((PlayerState*)state)->baddie.controlMode == 2)
    {
        result = 1;
    }
    else
    {
        result = 0;
    }
    if (result != 0)
    {
        mainSetBits(GAMEBIT_ITEM_SharpClawDisguise_Disabled, 0);
    }
    else
    {
        mainSetBits(GAMEBIT_ITEM_SharpClawDisguise_Disabled, 1);
    }
    if (playerCanCastPortalOpenSpell(obj, state) != 0)
    {
        mainSetBits(GAMEBIT_ITEM_PortalSpell_Disabled, 0);
    }
    else
    {
        mainSetBits(GAMEBIT_ITEM_PortalSpell_Disabled, 1);
    }
    if (fn_802A97D0(obj, state) != 0)
    {
        mainSetBits(GAMEBIT_ITEM_StaffBooster_Disabled, 0);
    }
    else
    {
        mainSetBits(GAMEBIT_ITEM_StaffBooster_Disabled, 1);
    }
    if (playerCanCastQuakeSpell(obj, state) != 0)
    {
        mainSetBits(GAMEBIT_ITEM_SuperQuake_Disabled, 0);
    }
    else
    {
        mainSetBits(GAMEBIT_ITEM_SuperQuake_Disabled, 1);
    }
    switch (((PlayerState*)state)->animState)
    {
    case GAMEBIT_STAFF_ABILITY_FIRE_BLASTER:
        break;
    case GAMEBIT_STAFF_ABILITY_SHARPCLAW_DISGUISE:
        if ((((u32 (*)(int))getButtonsJustPressed)(0) & 0x200) != 0 && ((ByteFlags*)((char*)state + 0x3f3))->b08 != 0 &&
            ((PlayerState*)state)->curAnimId != 0x44)
        {
            playerSetDisguised(obj, 0);
            ((PlayerState*)state)->animState = -1;
            ((PlayerState*)state)->queuedItemCommand = -1;
            buttonDisable(0, PAD_BUTTON_B);
        }
        ((PlayerState*)state)->stateTimer = ((PlayerState*)state)->stateTimer - timeDelta;
        if (((PlayerState*)state)->stateTimer <= lbl_803E7EA4)
        {
            if (*(s16*)((char*)*(int*)((char*)*(int*)&obj->extra + 0x35c) + 4) < 0)
            {
                v = 0;
            }
            else if (*(s16*)((char*)*(int*)((char*)*(int*)&obj->extra + 0x35c) + 4) >
                     *(s16*)((char*)*(int*)((char*)*(int*)&obj->extra + 0x35c) + 6))
            {
                v = *(s16*)((char*)*(int*)((char*)*(int*)&obj->extra + 0x35c) + 6);
            }
            else
            {
                v = *(s16*)((char*)*(int*)((char*)*(int*)&obj->extra + 0x35c) + 4);
            }
            *(s16*)((char*)*(int*)((char*)*(int*)&obj->extra + 0x35c) + 4) = v;
            ((PlayerState*)state)->stateTimer = lbl_803E7EDC;
        }
        break;
    case GAMEBIT_STAFF_ABILITY_FREEZE_BLAST:
        if (lbl_803DE42C != 0 && getCurSeqNoInt() != 0)
        {
            ((PlayerState*)state)->animState = -1;
            z[0] = 0;
            lbl_803DE42C = z[0];
            z[1] = z[0];
            p = gPlayerSpawnedObjects;
            for (; z[1] < 7; z[1]++)
            {
                if (p[z[1]] != NULL)
                {
                    Obj_FreeObject((GameObject*)p[z[1]]);
                    p[z[1]] = NULL;
                }
            }
            if (gPlayerResource != NULL)
            {
                Resource_Release(gPlayerResource);
                gPlayerResource = NULL;
            }
        }
        break;
    }
}


extern int lbl_802C2C68[];
extern f32 lbl_803E8134;

void fn_802AFB0C(int obj, int inner, int state)
{
    int orig;
    int work;
    int newAnim;
    int keepKnock;
    int knockKind;
    int canCounter;
    int anim;
    HitFxDesc desc;
    VecXYZ pos;
    u8 buf[12];
    ColQuad col;
    int surfIdx;
    int damage;
    char* hitObj;

    col = *(ColQuad*)lbl_802C2C68;
    knockKind = 0;
    if (*(f32*)(*(int*)&((GameObject*)obj)->extra + 0x838) > lbl_803E7ED8)
    {
        ((PlayerState*)inner)->knockbackTimer = lbl_803E7EA4;
    }
    if (gPlayerSfxTimerA > 0)
    {
        gPlayerSfxTimerA = gPlayerSfxTimerA - framesThisStep;
        if (gPlayerSfxTimerA < 0)
        {
            gPlayerSfxTimerA = 0;
        }
    }
    work = ObjHits_GetPriorityHitWithPosition((GameObject*)(obj), (int*)&hitObj, &surfIdx, (u32*)&damage, &pos.x,
                                              &pos.y, &pos.z);
    orig = work;
    if (**(s8**)&((PlayerState*)inner)->playerStatus <= 0)
    {
        **(s8**)&((PlayerState*)inner)->playerStatus = 1;
    }
    if ((*(int (*)(int))ObjHits_IsObjectEnabled)(obj) == 0 || objGetFlagsE5_2((u8*)obj) != 0 ||
        ((ByteFlags*)((char*)inner + 0x3f3))->b20 != 0 ||
        (((GameObject*)obj)->objectFlags & OBJECT_OBJFLAG_PARENT_SLACK))
    {
        return;
    }
    if (*(void**)((char*)inner + 0x7f0) != NULL && work != 0)
    {
        work = 0x15;
    }
    keepKnock = 1;
    if (work != 0)
    {
        if (surfIdx != -1)
        {
            pos.x = pos.x + playerMapOffsetX;
            pos.z = pos.z + playerMapOffsetZ;
        }
        if (*(s16*)((char*)state + 0x278) != 0)
        {
            work = 0x1b;
        }
        if (*(s8*)&((PlayerState*)state)->baddie.stateTag == 3 && *(s8*)((char*)state + 0x34f) <= work)
        {
            return;
        }
        *(s8*)((char*)state + 0x34f) = work;
        ((GameObject*)obj)->anim.activeMove = -1;
        newAnim = -1;
        {
            u32 fl = ((PlayerState*)inner)->flags3F0;
            if ((fl >> 4 & 1) != 0 || (fl >> 2 & 1) != 0 || (fl >> 3 & 1) != 0 || (fl >> 5 & 1) != 0 ||
                (anim = ((PlayerState*)state)->baddie.controlMode) == 0x36)
            {
                canCounter = 0;
            }
            else if ((u16)(anim - 1) <= 1 || (u16)(anim - 0x24) <= 1 || ((PlayerState*)state)->baddie.targetObj != NULL)
            {
                canCounter = 1;
            }
            else
            {
                canCounter = 0;
            }
        }
        switch (work)
        {
        case 0xb:
            if (canCounter && ((PlayerState*)state)->baddie.targetObj != NULL)
            {
                ((PlayerState*)inner)->moveVariantIndex = 2;
                newAnim = 0x23;
                ((PlayerState*)inner)->stateHandler = 0;
            }
            break;
        case 7:
        case 8:
        case 9:
            if (canCounter && ((PlayerState*)state)->baddie.targetObj != NULL)
            {
                ((PlayerState*)inner)->moveVariantIndex = 3;
                newAnim = 0x23;
                ((PlayerState*)inner)->stateHandler = 0;
            }
            break;
        case 0xc:
            if (canCounter && ((PlayerState*)state)->baddie.targetObj != NULL)
            {
                ((PlayerState*)inner)->moveVariantIndex = 1;
                newAnim = 0x23;
                ((PlayerState*)inner)->stateHandler = 0;
            }
            break;
        case 0xa:
            if (canCounter && ((PlayerState*)state)->baddie.targetObj != NULL)
            {
                ((PlayerState*)inner)->moveVariantIndex = 3;
                newAnim = 0x23;
                ((PlayerState*)inner)->stateHandler = 0;
            }
            break;
        case 4:
            if (canCounter)
            {
                newAnim = 0x1f;
                ((PlayerState*)inner)->stateHandler = 0;
            }
            break;
        case 1:
            damage = **(s8**)&((PlayerState*)inner)->playerStatus;
            break;
        case 0x15:
            switch (((PlayerState*)inner)->focusObject->anim.seqId)
            {
            case 0x714:
                Camera_EnableViewYOffset();
                CameraShake_SetAllMagnitudes(lbl_803E7EE0);
                break;
            }
            break;
        case 0x16:
            if (((ByteFlags*)((char*)inner + 0x3f0))->b02 == 0)
            {
                keepKnock = 0;
            }
            if (canCounter && ((PlayerState*)state)->baddie.targetObj == NULL)
            {
                ((PlayerState*)inner)->moveVariantIndex = 5;
            }
            break;
        case 0x19:
            Camera_EnableViewYOffset();
            CameraShake_SetAllMagnitudes(lbl_803E7EE0);
            break;
        case 0x1b:
            newAnim = *(s16*)((char*)state + 0x278);
            break;
        case 0x14:
        case 0x1a:
        case 0x1f:
            if (((PlayerState*)inner)->knockbackTimer <= lbl_803E7EA4)
            {
                knockKind = 1;
            }
            if (((ByteFlags*)((char*)inner + 0x3f0))->b02 == 0)
            {
                keepKnock = 0;
            }
            if (canCounter && ((PlayerState*)state)->baddie.targetObj == NULL)
            {
                ((PlayerState*)inner)->moveVariantIndex = 5;
            }
            break;
        case 0x1e:
            if (((ByteFlags*)((char*)inner + 0x3f3))->b08 == 0)
            {
                knockKind = 2;
                if (((ByteFlags*)((char*)inner + 0x3f0))->b02 == 0)
                {
                    keepKnock = 0;
                }
                if (canCounter && ((PlayerState*)state)->baddie.targetObj == NULL)
                {
                    ((PlayerState*)inner)->moveVariantIndex = 5;
                }
                break;
            }
            return;
        case 2:
        case 5:
        case 0x12:
        case 0x17:
        case 0x18:
            break;
        default:
            if (canCounter && ((PlayerState*)state)->baddie.targetObj != NULL)
            {
                ((PlayerState*)inner)->moveVariantIndex = 0;
                newAnim = 0x23;
                ((PlayerState*)inner)->stateHandler = 0;
            }
            break;
        }
        if ((*(u32*)&((PlayerState*)inner)->flags360 & 0x800) == 0 && knockKind != 0)
        {
            ((PlayerState*)inner)->knockbackTimer = lbl_803E7EDC;
            ((PlayerState*)inner)->knockbackHitTimer = lbl_803E8050;
            ((PlayerState*)inner)->knockbackDrainRate = lbl_803E7EE0;
            ((KnockBits*)((char*)inner + 0x7a8))->knock = (u8)knockKind;
        }
        if ((*(u32*)&((PlayerState*)inner)->flags360 & 0x800) != 0 && keepKnock != 0)
        {
            damage = 0;
            ((ByteFlags*)((char*)inner + 0x3f6))->b10 = 1;
            if (hitObj != NULL && ((GameObject*)hitObj)->anim.seqId != 0x2c5)
            {
                if (gPlayerSfxTimerA == 0)
                {
                    Sfx_PlayFromObject(
                        obj, (u16)(((PlayerState*)inner)->characterId == 0 ? SFXTRIG_pole1_c : SFXTRIG_wp_pole1_c));
                }
                gPlayerSfxTimerA = 6;
            }
            if (gPlayerStepSfxTimer == 0)
            {
                char* pt = *(char* volatile*)((char*)Player_GetActiveModel(obj) + 0x50);
                desc.x = playerMapOffsetX + *(f32*)(pt + surfIdx * 0x10 + 4);
                desc.y = *(f32*)(pt + surfIdx * 0x10 + 8);
                desc.z = playerMapOffsetZ + *(f32*)(pt + surfIdx * 0x10 + 0xc);
                (*gPartfxInterface)->spawnObject((void*)obj, 0x328, &desc, 0x200001, -1, NULL);
                desc.x -= ((GameObject*)obj)->anim.worldPosX;
                desc.y -= ((GameObject*)obj)->anim.worldPosY;
                desc.z -= ((GameObject*)obj)->anim.worldPosZ;
                if (gPlayerResource == NULL)
                {
                    gPlayerResource = Resource_Acquire(0x5a, 1);
                }
                col.b += randomGetRange(0, 0x9b);
                col.c += randomGetRange(0, 0x9b);
                desc.scale = lbl_803E7EE0;
                desc.rx = 0;
                desc.ry = 0;
                desc.rz = 0;
                (**(void (**)(int, int, void*, int, int, ColQuad*))((char*)*(int**)gPlayerResource + 0x4))(
                    obj, 0, &desc, 1, -1, &col);
                if (gPlayerResource != NULL)
                {
                    Resource_Release(gPlayerResource);
                }
                gPlayerResource = NULL;
                gPlayerStepSfxTimer = 10;
                return;
            }
            else
            {
                gPlayerStepSfxTimer = gPlayerStepSfxTimer - 1;
                return;
            }
        }
        if (damage != 0)
        {
            {
                int v;
                int hb = *(int*)&((GameObject*)obj)->extra;
                s8* hp = *(s8**)((char*)hb + 0x35c);
                v = *hp - damage;
                if (v < 0)
                {
                    v = 0;
                }
                else
                {
                    int hi = hp[1];
                    if (v > hi)
                    {
                        v = hi;
                    }
                }
                *hp = v;
                if (**(s8**)((char*)hb + 0x35c) <= 0)
                {
                    playerDie((GameObject*)obj);
                }
            }
            gPlayerStepSfxTimer = 0;
            if (hitObj != NULL)
            {
                switch (((GameObject*)hitObj)->anim.seqId)
                {
                case 0x11:
                case 0x33:
                case 0x13a:
                case 0x5b7:
                case 0x5b8:
                case 0x5b9:
                case 0x5e1:
                    Sfx_PlayFromObject((int)hitObj, SFXTRIG_snort);
                    break;
                case 0x5f9:
                case 0x5fa:
                case 0x5fe:
                    Sfx_PlayFromObject((int)hitObj, SFXTRIG_swd);
                    break;
                case 0x2c5:
                    Sfx_PlayFromObject((int)hitObj, SFXTRIG_wp_crtsmsh6);
                    break;
                case 0x709:
                    Sfx_PlayFromObject((int)hitObj, SFXTRIG_wp_fball2_c);
                    break;
                case 0x458:
                case 0x842:
                    Sfx_PlayFromObject((int)hitObj, SFXTRIG_baddie_mika_death);
                    break;
                }
            }
            switch (orig)
            {
            case 0x16:
                if (hitObj != NULL &&
                    (((GameObject*)hitObj)->anim.seqId == 0x613 || ((GameObject*)hitObj)->anim.seqId == 0x70f))
                {
                    Sfx_PlayFromObject(
                        obj, (u16)(((PlayerState*)inner)->characterId == 0 ? SFXTRIG_foxcom : SFXTRIG_sabrepush163));
                }
                else
                {
                    Sfx_PlayFromObject(obj, SFXTRIG_watery_bubble3);
                }
                break;
            case 0x14:
            case 0x1f:
                Sfx_PlayFromObject(
                    obj, (u16)(((PlayerState*)inner)->characterId == 0 ? SFXTRIG_foxcom : SFXTRIG_sabrepush163));
                Sfx_PlayFromObject(obj, SFXTRIG_en_cvdrip1c_393);
                if (Sfx_IsPlayingFromObjectIntU16Legacy(obj, SFXTRIG_foot_metal_scuff) == 0)
                {
                    Sfx_PlayFromObject(obj, SFXTRIG_foot_metal_scuff);
                }
                if (**(s8**)&((PlayerState*)inner)->playerStatus > 0)
                {
                    objLightFn_8009a1dc((void*)obj, lbl_803E8024, buf, 6, 0);
                }
                break;
            case 0x1c:
                Sfx_PlayFromObject(obj, SFXTRIG_fox_var);
                if (**(s8**)&((PlayerState*)inner)->playerStatus > 0)
                {
                    objLightFn_8009a1dc((void*)obj, lbl_803E8024, buf, 8, 0);
                }
                break;
            default:
                Sfx_PlayFromObject(
                    obj, (u16)(((PlayerState*)inner)->characterId == 0 ? SFXTRIG_foxcom : SFXTRIG_sabrepush163));
                if (hitObj != NULL)
                {
                    switch (((GameObject*)hitObj)->anim.seqId)
                    {
                    case 0x33:
                        Sfx_PlayFromObject(obj, SFXTRIG_snort);
                        if (**(s8**)&((PlayerState*)inner)->playerStatus > 0)
                        {
                            objLightFn_8009a1dc((void*)obj, lbl_803E8024, buf, 5, 0);
                        }
                        break;
                    case 0x7c8:
                        if (**(s8**)&((PlayerState*)inner)->playerStatus > 0)
                        {
                            objLightFn_8009a1dc((void*)obj, lbl_803E8024, buf, 8, 0);
                        }
                        break;
                    default:
                        if (**(s8**)&((PlayerState*)inner)->playerStatus > 0)
                        {
                            objLightFn_8009a1dc((void*)obj, lbl_803E8024, buf, 5, 0);
                        }
                        break;
                    }
                }
                else
                {
                    if (**(s8**)&((PlayerState*)inner)->playerStatus > 0)
                    {
                        objLightFn_8009a1dc((void*)obj, lbl_803E8024, buf, 5, 0);
                    }
                }
                break;
            }
            if (**(s8**)&((PlayerState*)inner)->playerStatus > 0)
            {
                Obj_SetModelColorFadeRecursive((GameObject*)obj, 0xb4, 200, 0, 0, 1);
            }
            if (((PlayerState*)state)->baddie.controlMode == 0x1a)
            {
                fn_8009A8C8((GameObject*)obj, lbl_803E8134);
            }
            ((PlayerState*)inner)->idleHoldTimer = lbl_803E7EA4;
            ((PlayerState*)inner)->idleWaitTimer = randomGetRange(800, 0x44c);
            ((PlayerState*)inner)->isHoldingObject = 0;
            if (*(void**)((char*)inner + 0x7f8) != NULL)
            {
                s16 t = ((GameObject*)((PlayerState*)inner)->heldObj)->anim.seqId;
                if (t == 0x3cf || t == 0x662)
                {
                    objThrowFn_80182504((GameObject*)(((PlayerState*)inner)->heldObj));
                }
                else
                {
                    objSaveFn_800ea774((GameObject*)((PlayerState*)inner)->heldObj);
                }
                *(s16*)((char*)((PlayerState*)inner)->heldObj + 6) =
                    *(s16*)((char*)((PlayerState*)inner)->heldObj + 6) & ~0x4000;
                *(int*)((char*)((PlayerState*)inner)->heldObj + 0xf8) = 0;
                ((PlayerState*)inner)->heldObj = 0;
            }
            if (newAnim != -1 && ((PlayerState*)state)->baddie.controlMode != newAnim &&
                **(s8**)&((PlayerState*)inner)->playerStatus > 0)
            {
                (*(void (*)(int, int, int))(*(int*)((char*)*gPlayerInterface + 0x14)))(obj, state, newAnim);
                *(int*)&((PlayerState*)state)->baddie.unk304 = ((PlayerState*)inner)->stateHandler;
            }
        }
        else
        {
            gPlayerStepSfxTimer = 0;
        }
    }
    else
    {
        gPlayerStepSfxTimer = 0;
    }
}

void fn_802B066C(GameObject* obj, int state)
{
    f32 v;
    f32 posWork[6];
    f32 zero;

    if (((PlayerState*)state)->surfaceType == 0x1a)
    {
        return;
    }
    if (((ByteFlags*)((char*)state + 0x3f0))->b10 == 0)
    {
        v = sqrtf(obj->anim.velocityZ * obj->anim.velocityZ +
                  (obj->anim.velocityX * obj->anim.velocityX +
                   obj->anim.velocityY * obj->anim.velocityY));
        ((PlayerState*)state)->knockbackDrainRate = v;
        v = ((PlayerState*)state)->knockbackDrainRate;
        ((PlayerState*)state)->knockbackDrainRate =
            (v < lbl_803E7EE0) ? lbl_803E7EE0 : ((v > lbl_803E8138) ? lbl_803E8138 : v);
    }
    ((PlayerState*)state)->knockbackTimer =
        ((PlayerState*)state)->knockbackTimer - timeDelta * ((PlayerState*)state)->knockbackDrainRate;
    if (((PlayerState*)state)->knockbackTimer <= (zero = lbl_803E7EA4))
    {
        if (Sfx_IsPlayingFromObjectIntU16Legacy((int)obj, SFXTRIG_foot_metal_scuff))
        {
            Sfx_StopFromObjectIntLegacy((int)obj, SFXTRIG_foot_metal_scuff);
            Sfx_PlayFromObject((int)obj, SFXTRIG_foot_metal_land);
        }
        ((PlayerState*)state)->knockbackTimer = lbl_803E7EA4;
        return;
    }
    ((PlayerState*)state)->knockbackHitTimer = ((PlayerState*)state)->knockbackHitTimer - timeDelta;
    if (((PlayerState*)state)->knockbackHitTimer <= zero)
    {
        ObjPath_GetPointWorldPosition((GameObject*)obj, 0xb, &posWork[3], &posWork[4], &posWork[5], 0);
        ObjHits_RecordPositionHit(obj, 0, 0x1f, 1, -1, posWork[3], posWork[4], posWork[5]);
        ((PlayerState*)state)->knockbackHitTimer = lbl_803E8050;
    }
}

void playerStaffInit(GameObject* obj, int state)
{
    GameObject* child;
    int b;

    if (gPlayerPathObject == NULL && Obj_IsLoadingLocked())
    {
        child = Obj_SetupObject(Obj_AllocObjectSetup(0x18, 0x69), 4, -1, -1, obj->anim.parent);
        gPlayerPathObject = child;
        ObjLink_AttachChild((int)obj, (int)child, 2);
    }
    if (gPlayerPathObject != NULL)
    {
        *(int*)&((GameObject*)gPlayerPathObject)->anim.parent = *(int*)&obj->anim.parent;
    }

    ((PlayerState*)state)->chargeLevel -= lbl_803E7E98 * timeDelta;
    if (((PlayerState*)state)->chargeLevel < *(f32*)&lbl_803E7EA4)
    {
        ((PlayerState*)state)->chargeLevel = lbl_803E7EA4;
    }
    ((PlayerState*)state)->boulderChargeLevel -= lbl_803E7E98 * timeDelta;
    if (((PlayerState*)state)->boulderChargeLevel < *(f32*)&lbl_803E7EA4)
    {
        ((PlayerState*)state)->boulderChargeLevel = lbl_803E7EA4;
    }

    fn_8011F34C((u8)(int)((PlayerState*)state)->chargeLevel);

    if ((u32)obj != 0)
    {
        b = (((ObjAnimComponent*)obj)->bankIndex != 0);
    }
    else
    {
        b = 0;
    }
    if (b == 0 && mainGetBit(GAMEBIT_ITEM_Staff_Got))
    {
        staffToggle(obj, 0);
    }
}


void playerDoEyeAnims(GameObject* obj, int state)
{
    s16* vec9 = objModelGetVecFn_800395d8(obj, 9);
    s16* vec0 = objModelGetVecFn_800395d8(obj, 0);
    u8 doBlink = 0;
    PlayerState* inner = obj->extra;
    f32 f31v;
    f32 f30v;

    if ((s8) * (s8*)(((PlayerState*)state)->playerStatus) > 0)
    {
        characterDoEyeAnimsState(obj, state + 0x364);
    }
    else
    {
        ObjTextureRuntimeSlot* t5 = objFindTexture(obj, 5, 0);
        ObjTextureRuntimeSlot* t4 = objFindTexture(obj, 4, 0);
        if (t5 != NULL)
        {
            t5->textureId = 0x200;
        }
        if (t4 != NULL)
        {
            t4->textureId = 0x200;
        }
    }
    if ((((PlayerState*)state)->flags360 & 0x2000000u) == 0)
    {
        ((PlayerState*)state)->headPitch =
            (f32)((PlayerState*)state)->headPitch * powfBitEstimate(lbl_803E7FF4, timeDelta);
        ((PlayerState*)state)->headYaw = (f32)((PlayerState*)state)->headYaw * powfBitEstimate(lbl_803E7F1C, timeDelta);
        ((PlayerState*)state)->bodyLeanAngle =
            (f32)((PlayerState*)state)->bodyLeanAngle * powfBitEstimate(lbl_803E7F1C, timeDelta);
        ((PlayerState*)state)->bodyLeanHalf =
            (f32)((PlayerState*)state)->bodyLeanHalf * powfBitEstimate(lbl_803E7F1C, timeDelta);
    }
    if (((ByteFlags*)((char*)state + 0x3f0))->b20)
    {
        f31v = inner->baddie.animSpeedC / *(f32*)((char*)(((PlayerState*)state)->moveParams) + 0x18);
        f31v = (f31v < lbl_803E7EA4) ? lbl_803E7EA4 : ((f31v > lbl_803E7EE0) ? lbl_803E7EE0 : f31v);
        f30v = lbl_803E7EE0 - f31v;
    }
    if (vec9 != NULL)
    {
        if (((ByteFlags*)((char*)state + 0x3f0))->b20)
        {
            f32 k = lbl_803E7E98;
            vec9[2] =
                k * ((f32)((PlayerState*)state)->headPitch * f30v + (f32)((PlayerState*)state)->bodyLeanHalf * f31v);
            vec9[1] =
                k * ((f32)((PlayerState*)state)->bodyLeanHalf * f30v + (f32)((PlayerState*)state)->headPitch * f31v);
        }
        else
        {
            vec9[2] = ((PlayerState*)state)->headPitch;
            vec9[1] = ((PlayerState*)state)->bodyLeanHalf;
        }
    }
    if (vec0 != NULL)
    {
        vec0[0] = -((PlayerState*)state)->headYaw;
        if (((ByteFlags*)((char*)state + 0x3f0))->b20)
        {
            int h4 = ((PlayerState*)state)->bodyLeanAngle / 2;
            int h0 = -(((PlayerState*)state)->headPitch / 2);
            f32 k = lbl_803E7E98;
            vec0[1] = k * ((f32)h4 * f30v + (f32)h0 * f31v);
            vec0[2] = k * ((f32)h0 * f30v + (f32)h4 * f31v);
        }
        else
        {
            vec0[1] = ((PlayerState*)state)->bodyLeanAngle / 2;
            vec0[2] = -(((PlayerState*)state)->headPitch / 2);
        }
    }
    if (!((ByteFlags*)((char*)state + 0x3f0))->b20)
    {
        obj->anim.rotZ = ((PlayerState*)state)->headPitch / 4;
    }
    else
    {
        obj->anim.rotZ = (f32)obj->anim.rotZ * powfBitEstimate(lbl_803E7FF4, timeDelta);
    }
    {
        int e;
        if (((PlayerState*)state)->baddie.controlMode == 1)
        {
            e = 1;
        }
        else
        {
            e = 0;
        }
        ((void (*)(int, int, u16))playerEyeAnimFn_80038988)((int)obj, state + 0x364, e);
    }
    if ((obj->objectFlags & OBJECT_OBJFLAG_PARENT_SLACK) == 0)
    {
        if (((ByteFlags*)((char*)state + 0x3f1))->b20)
        {
            gPlayerSubState = 5;
        }
        else
        {
            if (fn_80295A04(obj, 2) == 0 && (s8) * (s8*)(((PlayerState*)state)->playerStatus) > 4 &&
                gPlayerSubState == 1 && randomGetRange(0, 0x12c) == 1)
            {
                gPlayerSubState = 2;
                doBlink = 1;
            }
            if (doBlink == 0 && gPlayerSubState == 2 && randomGetRange(0, 5) == 1)
            {
                gPlayerSubState = 1;
            }
        }
        {
            s16* vec1 = objModelGetVecFn_800395d8(obj, 1);
            if (vec1 != NULL)
            {
                vec1[0] = 0x1c2;
                vec1[1] = 0;
                vec1[2] = 0;
            }
        }
    }
}


void fn_802B0EA4(GameObject* obj, int inner, int state)
{
    int d;
    char* cam;
    f32 dx;
    f32 dz;
    f32 spd;
    f32 t;
    f32 u;
    int idx;
    f32 one;
    f32 v;

    if ((*(u32*)&((PlayerState*)inner)->flags360 & 0x800000) != 0)
    {
        s16 a = *(s16*)obj;
        ((PlayerState*)inner)->yaw = a;
        ((PlayerState*)inner)->targetYaw = a;
        ((PlayerState*)inner)->lastInputHeading = a;
        ((PlayerState*)state)->baddie.inputMagnitude = lbl_803E7EA4;
    }
    *(f32*)&((PlayerState*)state)->baddie.trackedObj = ((PlayerState*)state)->baddie.inputMagnitude;
    ((PlayerState*)inner)->prevYaw = ((PlayerState*)inner)->yaw;
    ((PlayerState*)inner)->prevTargetYaw = ((PlayerState*)inner)->targetYaw;
    ((PlayerState*)state)->baddie.inputMagnitude =
        sqrtf(((PlayerState*)state)->baddie.moveInputX * ((PlayerState*)state)->baddie.moveInputX +
              ((PlayerState*)state)->baddie.moveInputZ * ((PlayerState*)state)->baddie.moveInputZ);
    if (((PlayerState*)state)->baddie.inputMagnitude > lbl_803E7FA8)
    {
        ((PlayerState*)state)->baddie.inputMagnitude = *(f32*)&lbl_803E7FA8;
    }
    ((PlayerState*)state)->baddie.inputMagnitude = ((PlayerState*)state)->baddie.inputMagnitude / lbl_803E7FA8;
    ((PlayerState*)inner)->inputMagnitude =
        ((PlayerState*)state)->baddie.inputMagnitude - *(f32*)&((PlayerState*)state)->baddie.trackedObj;
    if (((PlayerState*)state)->baddie.inputMagnitude < lbl_803E7F6C)
    {
        ((PlayerState*)state)->baddie.inputMagnitude = lbl_803E7EA4;
        ((PlayerState*)inner)->inputHeading = ((PlayerState*)inner)->lastInputHeading;
    }
    else
    {
        ((PlayerState*)inner)->inputHeading =
            getAngle(((PlayerState*)state)->baddie.moveInputX, -((PlayerState*)state)->baddie.moveInputZ) & 0xffff;
        ((PlayerState*)inner)->inputHeading =
            ((PlayerState*)inner)->inputHeading - ((PlayerState*)state)->baddie.cameraYaw;
        if ((*(u32*)&((PlayerState*)inner)->flags360 & 0x1000000) == 0)
        {
            ((PlayerState*)inner)->lastInputHeading = ((PlayerState*)inner)->inputHeading;
        }
    }
    d = ((PlayerState*)inner)->inputHeading - (u16)((PlayerState*)inner)->yaw;
    if (d > 0x8000)
    {
        d = d - 0xffff;
    }
    if (d < -0x8000)
    {
        d = d + 0xffff;
    }
    ((PlayerState*)inner)->yawRate = (int)((f32)d / gPlayerDegToBinAngle);
    if (((PlayerState*)inner)->turnDeadzoneScale != lbl_803E7EA4)
    {
        f32 dead = ((PlayerState*)inner)->turnDeadzoneScale * ((PlayerState*)state)->baddie.animSpeedA;
        if ((f32)((PlayerState*)inner)->yawRate < dead && (f32)((PlayerState*)inner)->yawRate > -dead)
        {
            ((PlayerState*)inner)->yawRate = 0;
        }
    }
    if (d < 0)
    {
        ((PlayerState*)inner)->yawRateSigned = -((PlayerState*)inner)->yawRate;
    }
    else
    {
        ((PlayerState*)inner)->yawRateSigned = ((PlayerState*)inner)->yawRate;
    }
    if (((PlayerState*)state)->baddie.inputMagnitude < lbl_803E7F6C)
    {
        *(u8*)((char*)state + 0x34b) = 0;
    }
    else
    {
        d = d + 0xa000;
        if (d < 0)
        {
            d = d + 0xffff;
        }
        if (d > 0xffff)
        {
            d = d - 0xffff;
        }
        *(u8*)((char*)state + 0x34b) = (u8)(4 - d / 0x4000);
    }
    d = ((PlayerState*)inner)->inputHeading - (u16)((PlayerState*)inner)->targetYaw;
    if (d > 0x8000)
    {
        d = d - 0xffff;
    }
    if (d < -0x8000)
    {
        d = d + 0xffff;
    }
    ((PlayerState*)inner)->targetYawRate = (int)((f32)d / gPlayerDegToBinAngle);
    if (((PlayerState*)inner)->turnDeadzoneScale != lbl_803E7EA4)
    {
        f32 dead = ((PlayerState*)inner)->turnDeadzoneScale * ((PlayerState*)state)->baddie.animSpeedA;
        if ((f32)((PlayerState*)inner)->targetYawRate < dead && (f32)((PlayerState*)inner)->targetYawRate > -dead)
        {
            ((PlayerState*)inner)->targetYawRate = 0;
        }
    }
    if (d < 0)
    {
        ((PlayerState*)inner)->targetYawRateSigned = -((PlayerState*)inner)->targetYawRate;
    }
    else
    {
        ((PlayerState*)inner)->targetYawRateSigned = ((PlayerState*)inner)->targetYawRate;
    }
    d = ((PlayerState*)inner)->inputHeading - (u16)((PlayerState*)inner)->bodyLeanAngle;
    if (d > 0x8000)
    {
        d = d - 0xffff;
    }
    if (d < -0x8000)
    {
        d = d + 0xffff;
    }
    ((PlayerState*)inner)->bodyLeanRate = (int)((f32)d / gPlayerDegToBinAngle);
    if (d < 0)
    {
        ((PlayerState*)inner)->bodyLeanRateSigned = -((PlayerState*)inner)->bodyLeanRate;
    }
    else
    {
        ((PlayerState*)inner)->bodyLeanRateSigned = ((PlayerState*)inner)->bodyLeanRate;
    }
    *(int*)&((PlayerState*)inner)->cameraTargetObject = (*gCameraInterface)->getTarget();
    cam = *(char**)((char*)inner + 0x4b8);
    if (cam != NULL)
    {
        dx = ((GameObject*)cam)->anim.localPosX - obj->anim.localPosX;
        dz = ((GameObject*)cam)->anim.localPosZ - obj->anim.localPosZ;
        ((PlayerState*)inner)->targetObjectYaw = getAngle(-dx, -dz) & 0xffff;
        ((PlayerState*)inner)->targetObjectDist = sqrtf(dx * dx + dz * dz);
        ((PlayerState*)inner)->targetObjModelType =
            *(u8*)(*(int*)(*(int*)&((GameObject*)cam)->anim.modelInstance + 0x40) + 0x10) & 0xf;
    }
    d = ((PlayerState*)inner)->targetObjectYaw - (u16)((PlayerState*)inner)->targetYaw;
    if (d > 0x8000)
    {
        d = d - 0xffff;
    }
    if (d < -0x8000)
    {
        d = d + 0xffff;
    }
    ((PlayerState*)inner)->targetObjectBearing = (int)(f32)d;
    if (d < 0)
    {
        ((PlayerState*)inner)->targetObjectBearingAbs = -((PlayerState*)inner)->targetObjectBearing;
    }
    else
    {
        ((PlayerState*)inner)->targetObjectBearingAbs = ((PlayerState*)inner)->targetObjectBearing;
    }
    if (((ByteFlags*)((char*)inner + 0x3f1))->b20 != 0)
    {
        spd = sqrtf(((PlayerState*)state)->baddie.animSpeedA * ((PlayerState*)state)->baddie.animSpeedA +
                    ((PlayerState*)state)->baddie.animSpeedB * ((PlayerState*)state)->baddie.animSpeedB);
        t = ((t = lbl_803E7EA4), spd < t) ? t : ((spd > (t = ((PlayerState*)inner)->maxSpeed)) ? t : spd);
        if (lbl_803E7EE0 == ((PlayerState*)inner)->targetAnimSpeed)
        {
            ((PlayerState*)inner)->velSmoothRate = lbl_803E7F44;
        }
        else
        {
            u = t * ((PlayerState*)inner)->curveSpeedScale;
            idx = (int)u;
            ((PlayerState*)inner)->velSmoothRate =
                lbl_803E7EE0 /
                Curve_EvalCatmullRomValuesFirst(((PlayerState*)inner)->paramCurve0 + (idx + 1) * 4,
                                                u - (f32)idx, 0);
        }
    }
    else
    {
        spd = ((PlayerState*)state)->baddie.animSpeedA;
        t = (spd < (t = lbl_803E7EA4)) ? t : ((spd > (t = ((PlayerState*)inner)->maxSpeed)) ? t : spd);
        u = t * ((PlayerState*)inner)->curveSpeedScale;
        idx = (int)u;
        ((PlayerState*)inner)->velSmoothRate =
            lbl_803E7EE0 / Curve_EvalCatmullRomValuesFirst(((PlayerState*)inner)->paramCurve0 + (idx + 1) * 4,
                                                          u - (f32)idx, 0);
    }
    u = t * ((PlayerState*)inner)->curveSpeedScale;
    idx = (int)u;
    ((PlayerState*)inner)->targetYawSmoothRate =
        Curve_EvalCatmullRomValuesFirst(((PlayerState*)inner)->paramCurve1 + (idx + 1) * 4, u - (f32)idx, 0);
    u = t * ((PlayerState*)inner)->curveSpeedScale;
    idx = (int)u;
    ((PlayerState*)inner)->targetYawRateLimit =
        Curve_EvalCatmullRomValuesFirst(((PlayerState*)inner)->paramCurve2 + (idx + 1) * 4, u - (f32)idx, 0);
    u = t * ((PlayerState*)inner)->curveSpeedScale;
    idx = (int)u;
    ((PlayerState*)inner)->yawSmoothRate =
        Curve_EvalCatmullRomValuesFirst(((PlayerState*)inner)->paramCurve3 + (idx + 1) * 4, u - (f32)idx, 0);
    u = t * ((PlayerState*)inner)->curveSpeedScale;
    idx = (int)u;
    ((PlayerState*)inner)->yawRateLimit =
        Curve_EvalCatmullRomValuesFirst(((PlayerState*)inner)->paramCurve4 + (idx + 1) * 4, u - (f32)idx, 0);
    if (((ByteFlags*)((char*)inner + 0x3f0))->b20 != 0)
    {
        f32 k;
        ((PlayerState*)inner)->targetYawSmoothRate = ((PlayerState*)inner)->targetYawSmoothRate * (k = lbl_803E80E4);
        ((PlayerState*)inner)->yawSmoothRate = ((PlayerState*)inner)->yawSmoothRate * k;
        ((PlayerState*)inner)->velSmoothRate = ((PlayerState*)inner)->velSmoothRate * lbl_803E7F44;
    }
    else
    {
        if (lbl_803E7EE0 != ((PlayerState*)inner)->yawSmoothScale)
        {
            f32 base = *(f32*)(((PlayerState*)inner)->moveParams + 0x10);
            f32 frac = (((PlayerState*)state)->baddie.animSpeedA - base) / (((PlayerState*)inner)->maxSpeed - base);
            f32 v430 = ((PlayerState*)inner)->yawSmoothRate;
            f32 diff = ((PlayerState*)inner)->yawSmoothScale - lbl_803E7EE0;
            ((PlayerState*)inner)->yawSmoothRate =
                v430 * (diff * ((frac < lbl_803E7EA4) ? lbl_803E7EA4 : ((frac > lbl_803E7EE0) ? lbl_803E7EE0 : frac)) +
                        *(f32*)&lbl_803E7EE0);
        }
    }
    if (*(void**)((char*)inner + 0x464) != NULL)
    {
        int n = ((PlayerState*)inner)->targetYawRateSigned;
        ((PlayerState*)inner)->leanCurveScale =
            Curve_EvalCatmullRomValuesFirst(((PlayerState*)inner)->leanCurve + (n / 5 + 1) * 4,
                                            (f32)(n % 5) / lbl_803E7F10, 0);
    }
    else
    {
        ((PlayerState*)inner)->leanCurveScale = lbl_803E7EE0;
    }
    one = lbl_803E7EE0;
    ((PlayerState*)inner)->leanCurveScale = one;
    if (((ByteFlags*)((char*)inner + 0x3f0))->b20 == 0 && ((PlayerState*)inner)->waterDepth > (v = lbl_803E7EA4))
    {
        ((PlayerState*)inner)->speedScale = (((PlayerState*)inner)->waterDepth - lbl_803E7FFC) / lbl_803E8098;
        if (!(((PlayerState*)inner)->speedScale < v))
        {
            v = (((PlayerState*)inner)->speedScale > one) ? one : ((PlayerState*)inner)->speedScale;
        }
        ((PlayerState*)inner)->speedScale = v;
        ((PlayerState*)inner)->speedScale = -(lbl_803E7E98 * ((PlayerState*)inner)->speedScale - lbl_803E7EE0);
    }
    else
    {
        if (((PlayerState*)state)->baddie.spawnRotY > 0)
        {
            ((PlayerState*)inner)->speedScale = (f32)((PlayerState*)state)->baddie.spawnRotY / lbl_803E7EE8;
            v = ((PlayerState*)inner)->speedScale;
            ((PlayerState*)inner)->speedScale =
                (v < lbl_803E7EA4) ? lbl_803E7EA4 : ((v > lbl_803E7EE0) ? lbl_803E7EE0 : v);
            ((PlayerState*)inner)->speedScale = -(lbl_803E7EAC * ((PlayerState*)inner)->speedScale - lbl_803E7EE0);
        }
        else
        {
            ((PlayerState*)inner)->speedScale = lbl_803E7EE0;
        }
    }
    if (*(void**)((char*)inner + 0x7f8) != NULL)
    {
        ((PlayerState*)inner)->speedScale = ((PlayerState*)inner)->speedScale - lbl_803E7EFC;
    }
    v = ((PlayerState*)inner)->speedScale;
    t = (v < lbl_803E7E98) ? lbl_803E7E98 : ((v > lbl_803E7EE0) ? lbl_803E7EE0 : v);
    ((PlayerState*)inner)->speedScale = t;
    *(u32*)&((PlayerState*)inner)->flags360 &= ~0x1800000LL;
}
#pragma dont_inline on
void fn_802B18BC(GameObject* obj, int state, f32 fv)
{
    f32 v;

    if ((((PlayerState*)state)->buttonsHeld & PAD_BUTTON_A) && playerCanCastQuakeSpell(obj, state))
    {
        ((ByteFlags*)((char*)state + 0x3f4))->b20 = 1;
        ((PlayerState*)state)->buttonHoldTimer += fv;
        v = ((PlayerState*)state)->buttonHoldTimer;
        ((PlayerState*)state)->buttonHoldTimer =
            (v < lbl_803E7EA4) ? lbl_803E7EA4 : ((v > lbl_803E813C) ? lbl_803E813C : v);
    }
    else
    {
        ((ByteFlags*)((char*)state + 0x3f4))->b20 = 0;
        ((PlayerState*)state)->buttonHoldTimer = lbl_803E7EA4;
    }

    ((PlayerState*)state)->rumbleCooldown -= fv;
    if (((PlayerState*)state)->rumbleCooldown < lbl_803E7EA4)
    {
        ((PlayerState*)state)->rumbleCooldown = *(f32*)&lbl_803E7EA4;
    }
    ((PlayerState*)state)->particleBurstCooldown -= fv;
    if (((PlayerState*)state)->particleBurstCooldown < lbl_803E7EA4)
    {
        ((PlayerState*)state)->particleBurstCooldown = *(f32*)&lbl_803E7EA4;
    }
    ((PlayerState*)state)->targetSuppressTimer -= fv;
    if (((PlayerState*)state)->targetSuppressTimer < lbl_803E7EA4)
    {
        ((PlayerState*)state)->targetSuppressTimer = *(f32*)&lbl_803E7EA4;
    }
    ((PlayerState*)state)->idleDelayTimer -= fv;
    if (((PlayerState*)state)->idleDelayTimer < lbl_803E7EA4)
    {
        ((PlayerState*)state)->idleDelayTimer = *(f32*)&lbl_803E7EA4;
    }
}

#pragma dont_inline reset

void playerDoControls(GameObject* obj, int state, f32 fv)
{
    u8 c;

    ((PlayerState*)state)->stickX = 0;
    ((PlayerState*)state)->stickY = 0;
    ((PlayerState*)state)->buttonsHeld = 0;
    ((PlayerState*)state)->buttonsJustPressed = 0;
    ((PlayerState*)state)->buttonsJustPressedIfNotBusy = 0;
    if ((((PlayerState*)state)->flags360 & 0x200000) == 0u && ((PlayerState*)state)->characterId != -1 &&
        (c = ((PlayerState*)state)->curAnimId) != 0x44 && c != 0x4e)
    {
        ((PlayerState*)state)->stickX = padGetStickXS8(0);
        ((PlayerState*)state)->stickY = padGetStickYS8(0);
        ((PlayerState*)state)->buttonsHeld = (u16)getButtonsHeld(0);
        ((PlayerState*)state)->buttonsJustPressed = (u16)getButtonsJustPressed(0);
        ((PlayerState*)state)->buttonsJustPressedIfNotBusy = (u16)getButtonsJustPressedIfNotBusy(0);
    }
    ((PlayerState*)state)->stickXf = (f32) * (int*)((char*)state + 0x6d0);
    ((PlayerState*)state)->stickYf = (f32) * (int*)((char*)state + 0x6d4);
    fn_802B18BC(obj, state, fv);
}

void fn_802B1B28(GameObject* obj, f32 fv)
{
    f32 x, y, z;
    f32 v;

    v = obj->anim.velocityX;
    obj->anim.velocityX = (v < lbl_803E801C) ? lbl_803E801C : ((v > lbl_803E7F10) ? lbl_803E7F10 : v);

    v = obj->anim.velocityY;
    obj->anim.velocityY = (v < lbl_803E811C) ? lbl_803E811C : ((v > lbl_803E80E4) ? lbl_803E80E4 : v);

    v = obj->anim.velocityZ;
    obj->anim.velocityZ = (v < lbl_803E801C) ? lbl_803E801C : ((v > lbl_803E7F10) ? lbl_803E7F10 : v);

    y = obj->anim.velocityY * fv;
    if (y > lbl_803E7ED8)
    {
        y = lbl_803E7ED8;
    }
    x = obj->anim.velocityX * fv;
    z = obj->anim.velocityZ * fv;
    objMove((GameObject*)obj, x, y, z);
}

void fn_802B1BF8(EmitObj* a, int b, int state)
{
    MatrixTransform v;
    f32 mtx[16];
    f32 oy;
    f32 f31v;
    f32 f30v;
    s8 flags = *(s8*)((char*)state + 0x34c);

    if ((flags & 2) == 0 && (flags & 1) == 0)
    {
        f31v = ((PlayerState*)state)->baddie.animSpeedA;
        f30v = ((PlayerState*)state)->baddie.animSpeedB;
        if (((ByteFlags*)((char*)b + 0x3f0))->b20)
        {
            f31v = f31v + ((PlayerState*)b)->waterCurrentVelA;
            f30v = f30v + ((PlayerState*)b)->waterCurrentVelB;
        }
        v.rotX = ((PlayerState*)b)->yaw;
        v.rotY = 0;
        v.rotZ = 0;
        v.scale = lbl_803E7EE0;
        v.x = lbl_803E7EA4;
        v.y = lbl_803E7EA4;
        v.z = lbl_803E7EA4;
        setMatrixFromObjectPos(mtx, &v);
        Matrix_TransformPoint(mtx, f30v, lbl_803E7EA4, -f31v, &a->x, &oy, &a->z);
        a->x = a->x + ((PlayerState*)b)->pushVelX;
        a->z = a->z + ((PlayerState*)b)->pushVelZ;
    }
    else
    {
        int cosI = (int)mathSinf(gPlayerPi * (f32) * (s16*)((char*)b + 0x484) / lbl_803E7F98);
        int sinI = (int)mathCosf(gPlayerPi * (f32) * (s16*)((char*)b + 0x484) / lbl_803E7F98);
        ((PlayerState*)state)->baddie.animSpeedB = a->x * (f32)sinI - a->z * (f32)cosI;
        ((PlayerState*)state)->baddie.animSpeedA = -a->z * (f32)sinI - a->x * (f32)cosI;
    }

    if ((*(int*)((char*)state) & 0x200000) == 0)
    {
        a->y = a->y * powfBitEstimate(lbl_803E8140, timeDelta);
        a->y = a->y - ((PlayerState*)state)->baddie.gravity * timeDelta;
    }
}

void fn_802B1E5C(GameObject* obj, int state, int cfg, f32 dt)
{
    u32 b;
    void* found;
    int iv;
    f32 fv2;
    f32 clamp;
    f32 velMag;
    f32 damp;
    f32 r;
    f32 pos[3];
    f32 queryParams[4];
    TrackGroundHit** nearList;
    f32 pushX;
    f32 pushZ;

    found = 0;
    {
        f32 z = lbl_803E7EE0;
        ((PlayerState*)state)->targetAnimSpeed = z;
        ((PlayerState*)state)->yawSmoothScale = z;
    }
    ((PlayerState*)state)->velSmoothRateBase = lbl_803E8144;
    ((PlayerState*)state)->surfaceType = 0;
    b = ((PlayerState*)state)->flags3F0 >> 5 & 1;
    if (b == 0 || (b != 0 && lbl_803E80D0 != *(f32*)((char*)cfg + 0x1c0)))
    {
        ((PlayerState*)state)->waterSurfaceY = *(f32*)((char*)cfg + 0x1c0);
    }
    if (lbl_803E80D0 != ((PlayerState*)state)->waterSurfaceY)
    {
        ((PlayerState*)state)->waterDepth = ((PlayerState*)state)->waterSurfaceY - obj->anim.worldPosY;
    }
    else
    {
        ((PlayerState*)state)->waterDepth = lbl_803E7EA4;
    }
    ((ByteFlags*)((char*)state + 0x3f1))->b01 = 0;
    clamp = lbl_803E7EA4;
    pushX = lbl_803E7EA4;
    pushZ = lbl_803E7EA4;
    if ((*(s8*)((char*)cfg + 0x264) & 0x10) != 0)
    {
        ((ByteFlags*)((char*)state + 0x3f1))->b01 = 1;
        ((PlayerState*)state)->surfaceType = *(u8*)((char*)cfg + 0xbc);
        switch (((PlayerState*)state)->surfaceType)
        {
        case SURFACE_ICE:
            ((PlayerState*)state)->targetAnimSpeed = lbl_803E8148;
            ((PlayerState*)state)->yawSmoothScale = lbl_803E814C;
            ((PlayerState*)state)->velSmoothRateBase = lbl_803E8118;
            break;
        case SURFACE_SNOW:
            fv2 = lbl_803E7EE0;
            ((PlayerState*)state)->targetAnimSpeed = fv2;
            ((PlayerState*)state)->yawSmoothScale = fv2;
            ((PlayerState*)state)->velSmoothRateBase = lbl_803E7F6C;
            break;
        case 6:
            if ((*(s16*)&((PlayerState*)state)->hitIntervalTimer -= dt) <= 0)
            {
                *(s16*)&((PlayerState*)state)->hitIntervalTimer = 0x3c;
                ObjHits_RecordObjectHit((int)obj, 0, 0x14, 2, 0);
            }
            break;
        case SURFACE_CONVEYOR:
            queryParams[0] = lbl_803E8150;
            found = (void*)ObjGroup_FindNearestObject(CFGUARDIAN_OBJGROUP, (int)obj, queryParams);
            if (found != 0)
            {
                (*(void (*)(f32, int, int, f32*, f32*))(*(int*)(*(int*)(*(int*)((char*)found + 0x68)) + 0x20)))(
                    lbl_803E7EE0, (int)found, (int)obj, &pushX, &pushZ);
            }
            break;
        case SURFACE_LAVA:
            if ((*(s16*)&((PlayerState*)state)->hitIntervalTimer -= dt) <= 0)
            {
                *(s16*)&((PlayerState*)state)->hitIntervalTimer = 0x3c;
                ObjPath_GetPointWorldPosition((GameObject*)obj, 0xb, &pos[0], &pos[1], &pos[2], 0);
                ((void (*)(int, int, int, int, int, f32, f32, f32))ObjHits_RecordPositionHit)(
                    (int)obj, 0, 0x14, 2, 0xffffffff, pos[0], pos[1], pos[2]);
            }
            break;
        case SURFACE_INSTANT_DEATH:
            ObjHits_RecordObjectHit((int)obj, 0, 1, 0, 0);
            break;
        case 28:
            if (mainGetBit(0x21) == 0)
            {
                ((PlayerState*)state)->periodicHitTimer += dt;
                if (0x78 < ((PlayerState*)state)->periodicHitTimer)
                {
                    ((PlayerState*)state)->periodicHitTimer -= 0x78;
                    ObjPath_GetPointWorldPosition((GameObject*)obj, 0xb, &pos[0], &pos[1], &pos[2], 0);
                    ((void (*)(int, int, int, int, int, f32, f32, f32))ObjHits_RecordPositionHit)(
                        (int)obj, 0, 0x16, 2, 0xffffffff, pos[0], pos[1], pos[2]);
                }
            }
            break;
        case 32:
            if (((PlayerState*)cfg)->baddie.animSpeedA > lbl_803E7E98)
            {
                fv2 = lbl_803E7F6C + ((PlayerState*)state)->sinkOffsetY;
                ((PlayerState*)state)->sinkOffsetY = (fv2 < clamp) ? fv2 : clamp;
            }
            else
            {
                ((PlayerState*)state)->sinkOffsetY = -(lbl_803E7E90 * dt - ((PlayerState*)state)->sinkOffsetY);
                if (lbl_803DE440 > clamp)
                {
                    lbl_803DE440 = lbl_803DE440 - dt;
                }
                else
                {
                    Sfx_PlayFromObject((int)obj, SFXTRIG_dn_boar1_c_208);
                    lbl_803DE440 = (f32)(int)randomGetRange(0x27, 0x3c);
                }
            }
            iv = hitDetectFn_80065e50(obj, obj->anim.localPosX, obj->anim.localPosY,
                                      obj->anim.localPosZ, &nearList, 0, 0x20);
            velMag = -((PlayerState*)state)->sinkOffsetY;
            if (1 < iv &&
                (velMag = velMag + (nearList[0]->height - nearList[iv - 1]->height), velMag > lbl_803E7FA0))
            {
                int inner = *(int*)&obj->extra;
                s8* p = *(s8**)&((PlayerState*)inner)->playerStatus;
                int n = *p - 1;
                if (n < 0)
                {
                    n = 0;
                }
                else if (n > p[1])
                {
                    n = p[1];
                }
                *p = (s8)n;
                if (**(s8**)&((PlayerState*)inner)->playerStatus <= 0)
                {
                    playerDie(obj);
                }
            }
            break;
        case 31:
            mainSetBits(0x643, 1);
            break;
        default:
            *(s16*)&((PlayerState*)state)->hitIntervalTimer = 0;
            if (((PlayerState*)state)->sinkOffsetY < *(f32*)&lbl_803E7EA4)
            {
                fv2 = lbl_803E7EFC * ((PlayerState*)cfg)->baddie.animSpeedA + ((PlayerState*)state)->sinkOffsetY;
                ((PlayerState*)state)->sinkOffsetY = (fv2 < *(f32*)&lbl_803E7EA4) ? fv2 : *(f32*)&lbl_803E7EA4;
                velMag = -((PlayerState*)state)->sinkOffsetY;
            }
            break;
        }
        if (velMag != lbl_803E7EA4)
        {
            damp = lbl_803E7F14;
            r = -(lbl_803E7F6C * velMag - lbl_803E7EE0);
            damp = (damp > r) ? damp : r;
            obj->anim.velocityX = obj->anim.velocityX * powfBitEstimate(damp, dt);
            obj->anim.velocityZ = obj->anim.velocityZ * powfBitEstimate(damp, dt);
        }
    }
    r = interpolate(pushX - ((PlayerState*)state)->pushVelX, lbl_803E7FCC, timeDelta);
    ((PlayerState*)state)->pushVelX = ((PlayerState*)state)->pushVelX + r;
    r = interpolate(pushZ - ((PlayerState*)state)->pushVelZ, lbl_803E7FCC, timeDelta);
    ((PlayerState*)state)->pushVelZ = ((PlayerState*)state)->pushVelZ + r;
    if (found == 0)
    {
        ((PlayerState*)state)->pushVelX = ((PlayerState*)state)->pushVelX * powfBitEstimate(lbl_803E7FF4, timeDelta);
        ((PlayerState*)state)->pushVelZ = ((PlayerState*)state)->pushVelZ * powfBitEstimate(lbl_803E7FF4, timeDelta);
    }
    if (((PlayerState*)state)->pushVelX > lbl_803E7FEC && ((PlayerState*)state)->pushVelX < lbl_803E7EF8)
    {
        ((PlayerState*)state)->pushVelX = lbl_803E7EA4;
    }
    if (((PlayerState*)state)->pushVelZ > lbl_803E7FEC && ((PlayerState*)state)->pushVelZ < lbl_803E7EF8)
    {
        ((PlayerState*)state)->pushVelZ = lbl_803E7EA4;
    }
}
#pragma opt_loop_invariants off

void playerItemGetAnimFn(int obj, int inner, int state)
{
    int p;
    int param = 0;
    int msg;

    while (ObjMsg_Pop((void*)obj, (u32*)&msg, (u32*)&p, (u32*)&param) != 0)
    {
        switch (msg)
        {
        case 0x80002:
            ((PlayerState*)inner)->queuedItemCommand = (s16)param;
            if (((PlayerState*)state)->baddie.targetObj != NULL &&
                (param == GAMEBIT_STAFF_ABILITY_FIRE_BLASTER || param == GAMEBIT_STAFF_ABILITY_FREEZE_BLAST))
            {
                ((PlayerState*)inner)->deferredItemCommand = (s16)param;
                ((PlayerState*)inner)->queuedItemCommand = -1;
            }
            break;
        case 0x60003:
        {
            f32 dz;
            f32 dx;
            f32 d;
            f32 zz;
            dx = *(f32*)(p + 0xc) - ((GameObject*)obj)->anim.localPosX;
            dz = ((PlayerState*)p)->baddie.posX - ((GameObject*)obj)->anim.localPosZ;
            zz = dz * dz;
            d = sqrtf(zz + dx * dx);
            if (d > 1.0f)
            {
                dx = dx / d;
                dz = dz / d;
            }
            {
                f32 spd = 2.5f;
                ((GameObject*)obj)->anim.velocityX = spd * dx;
                ((GameObject*)obj)->anim.velocityZ = spd * dz;
                ((GameObject*)obj)->anim.velocityY = spd;
            }
            (*(void (*)(int, int, int))(*(int*)((char*)*gPlayerInterface + 0x14)))(obj, state, 0x21);
            *(int*)&((PlayerState*)state)->baddie.unk304 = 0;
            Player_ApplyStatusDamage((GameObject*)obj, param);
            ((PlayerState*)inner)->isHoldingObject = 0;
            if (*(void**)((char*)inner + 0x7f8) != NULL)
            {
                s16 typ = ((GameObject*)((PlayerState*)inner)->heldObj)->anim.seqId;
                if (typ == 0x3cf || typ == 0x662)
                {
                    objThrowFn_80182504((GameObject*)(((PlayerState*)inner)->heldObj));
                }
                else
                {
                    objSaveFn_800ea774((GameObject*)((PlayerState*)inner)->heldObj);
                }
                *(s16*)((char*)((PlayerState*)inner)->heldObj + 0x6) =
                    *(s16*)((char*)((PlayerState*)inner)->heldObj + 0x6) & ~0x4000;
                *(int*)((char*)((PlayerState*)inner)->heldObj + 0xf8) = 0;
                ((PlayerState*)inner)->heldObj = 0;
            }
            break;
        }
        case 0x60004:
        {
            f32 dz;
            f32 dx = *(f32*)(p + 0xc) - ((GameObject*)obj)->anim.localPosX;
            f32 d;
            dz = ((PlayerState*)p)->baddie.posX - ((GameObject*)obj)->anim.localPosZ;
            d = sqrtf(dx * dx + dz * dz);
            if (d > 1.0f)
            {
                dx = dx / d;
                dz = dz / d;
            }
            {
                f32 spd = 2.5f;
                ((GameObject*)obj)->anim.velocityX = spd * -dx;
                ((GameObject*)obj)->anim.velocityZ = spd * -dz;
                ((GameObject*)obj)->anim.velocityY = spd;
            }
            (*(void (*)(int, int, int))(*(int*)((char*)*gPlayerInterface + 0x14)))(obj, state, 0x21);
            *(int*)&((PlayerState*)state)->baddie.unk304 = 0;
            Player_ApplyStatusDamage((GameObject*)obj, param);
            ((PlayerState*)inner)->isHoldingObject = 0;
            if (*(void**)((char*)inner + 0x7f8) != NULL)
            {
                s16 typ = ((GameObject*)((PlayerState*)inner)->heldObj)->anim.seqId;
                if (typ == 0x3cf || typ == 0x662)
                {
                    objThrowFn_80182504((GameObject*)(((PlayerState*)inner)->heldObj));
                }
                else
                {
                    objSaveFn_800ea774((GameObject*)((PlayerState*)inner)->heldObj);
                }
                *(s16*)((char*)((PlayerState*)inner)->heldObj + 0x6) =
                    *(s16*)((char*)((PlayerState*)inner)->heldObj + 0x6) & ~0x4000;
                *(int*)((char*)((PlayerState*)inner)->heldObj + 0xf8) = 0;
                ((PlayerState*)inner)->heldObj = 0;
            }
            Sfx_PlayFromObject(obj,
                               (u16)(((PlayerState*)inner)->characterId == 0 ? SFXTRIG_foxcom : SFXTRIG_sabrepush163));
            break;
        }
        case 0x60005:
        {
            f32 dz;
            f32 dx = *(f32*)(p + 0xc) - ((GameObject*)obj)->anim.localPosX;
            f32 d;
            dz = ((PlayerState*)p)->baddie.posX - ((GameObject*)obj)->anim.localPosZ;
            d = sqrtf(dx * dx + dz * dz);
            if (d > 1.0f)
            {
                dx = dx / d;
                dz = dz / d;
            }
            {
                f32 spd = 2.5f;
                ((GameObject*)obj)->anim.velocityX = spd * -dx;
                ((GameObject*)obj)->anim.velocityZ = spd * -dz;
                ((GameObject*)obj)->anim.velocityY = spd;
            }
            (*(void (*)(int, int, int))(*(int*)((char*)*gPlayerInterface + 0x14)))(obj, state, 0x21);
            *(int*)&((PlayerState*)state)->baddie.unk304 = 0;
            ObjAnim_SetCurrentMove(obj, 0x450, 0.0f, 0);
            Player_ApplyStatusDamage((GameObject*)obj, param);
            ((PlayerState*)inner)->isHoldingObject = 0;
            if (*(void**)((char*)inner + 0x7f8) != NULL)
            {
                s16 typ = ((GameObject*)((PlayerState*)inner)->heldObj)->anim.seqId;
                if (typ == 0x3cf || typ == 0x662)
                {
                    objThrowFn_80182504((GameObject*)(((PlayerState*)inner)->heldObj));
                }
                else
                {
                    objSaveFn_800ea774((GameObject*)((PlayerState*)inner)->heldObj);
                }
                *(s16*)((char*)((PlayerState*)inner)->heldObj + 0x6) =
                    *(s16*)((char*)((PlayerState*)inner)->heldObj + 0x6) & ~0x4000;
                *(int*)((char*)((PlayerState*)inner)->heldObj + 0xf8) = 0;
                ((PlayerState*)inner)->heldObj = 0;
            }
            break;
        }
        case 0x7000a:
        {
            void* t;
            s16 bit;
            ((PlayerState*)inner)->triggerGameBitPtr = param;
            t = *(void**)(p + 0x64);
            if (t != NULL)
            {
                *(u32*)((char*)t + 0x30) &= ~0x4LL;
            }
            bit = **(s16**)((char*)inner + 0x8dc);
            if (bit > 0)
            {
                if (mainGetBit(bit) != 0)
                {
                    ObjMsg_SendToObject((void*)p, 0x7000b, (void*)obj, 0);
                    break;
                }
                else
                {
                    f32 k;
                    f32 lim;
                    f32 r = *(f32*)(p + 8) / *(f32*)(*(int*)(p + 0x50) + 4);
                    lim = 30.0f;
                    k = 0.99f;
                    while (r * (((GameObject*)obj)->anim.hitboxScale * ((GameObject*)obj)->anim.rootMotionScale) > lim)
                    {
                        *(f32*)(p + 8) = *(f32*)(p + 8) * k;
                        r = *(f32*)(p + 8) / *(f32*)(*(int*)(p + 0x50) + 4);
                    }
                    mainSetBits(**(s16**)((char*)inner + 0x8dc), 1);
                    (*gObjectTriggerInterface)->setObjects(*(s16*)(p + 0x46), 0, 0);
                    (*gObjectTriggerInterface)->runSequence(0, (void*)obj, -1);
                }
            }
            else
            {
                f32 k;
                f32 lim;
                f32 r = *(f32*)(p + 8) / *(f32*)(*(int*)(p + 0x50) + 4);
                lim = 30.0f;
                k = 0.99f;
                while (r * (((GameObject*)obj)->anim.hitboxScale * ((GameObject*)obj)->anim.rootMotionScale) > lim)
                {
                    *(f32*)(p + 8) = *(f32*)(p + 8) * k;
                    r = *(f32*)(p + 8) / *(f32*)(*(int*)(p + 0x50) + 4);
                }
                (*gObjectTriggerInterface)->setObjects(*(s16*)(p + 0x46), 0, 0);
                (*gObjectTriggerInterface)->runSequence(0, (void*)obj, -1);
            }
            ((PlayerState*)inner)->interactObject = p;
            ((PlayerState*)inner)->unk688 = *(s16*)(((PlayerState*)inner)->triggerGameBitPtr + 2);
            t = *(void**)(((PlayerState*)inner)->interactObject + 0x64);
            if (t != NULL)
            {
                *(int*)((char*)t + 0x30) = 0x1000;
            }
            if (gPlayerPathObject != 0 && ((ByteFlags*)((char*)inner + 0x3f4))->b40 != 0)
            {
                ((PlayerState*)inner)->staffActionRequest = 1;
                ((ByteFlags*)((char*)inner + 0x3f4))->b08 = 1;
            }
            break;
        }
        case 0x100008:
            ((PlayerState*)inner)->isHoldingObject = 1;
            if ((void*)((PlayerState*)inner)->heldObj == NULL)
            {
                int* mdl;
                ((PlayerState*)inner)->heldObj = (GameObject*)p;
                mdl = (int*)Obj_GetActiveModel(((PlayerState*)inner)->heldObj);
                if (mdl != NULL && (void*)*mdl != NULL && (*(u16*)(*mdl + 2) & 0x8000) == 0)
                {
                    *(u8*)((char*)((PlayerState*)inner)->heldObj + 0xf2) = *(u8*)((char*)obj + 0xf2);
                }
                ((PlayerState*)inner)->unk7FC = (f32)(param >> 0x10) / 10.0f;
                (*(void (*)(int, int, int))(*(int*)((char*)*gPlayerInterface + 0x14)))(obj, state, 5);
                *(int*)&((PlayerState*)state)->baddie.unk304 = (int)fn_802A4B4C;
                if (gPlayerPathObject != 0 && ((ByteFlags*)((char*)inner + 0x3f4))->b40 != 0)
                {
                    ((PlayerState*)inner)->staffActionRequest = 1;
                    ((ByteFlags*)((char*)inner + 0x3f4))->b08 = 1;
                }
            }
            break;
        case 0x100010:
            ((PlayerState*)inner)->isHoldingObject = 1;
            if ((void*)((PlayerState*)inner)->heldObj == NULL)
            {
                int* mdl;
                ((PlayerState*)inner)->heldObj = (GameObject*)p;
                mdl = (int*)Obj_GetActiveModel(((PlayerState*)inner)->heldObj);
                if (mdl != NULL && (void*)*mdl != NULL && (*(u16*)(*mdl + 2) & 0x8000) == 0)
                {
                    *(u8*)((char*)((PlayerState*)inner)->heldObj + 0xf2) = *(u8*)((char*)obj + 0xf2);
                }
                ((PlayerState*)inner)->unk7FC = (f32)(param >> 0x10);
                (*(void (*)(int, int, int))(*(int*)((char*)*gPlayerInterface + 0x14)))(obj, state, 5);
                *(int*)&((PlayerState*)state)->baddie.unk304 = (int)fn_802A4B4C;
                if (gPlayerPathObject != 0 && ((ByteFlags*)((char*)inner + 0x3f4))->b40 != 0)
                {
                    ((PlayerState*)inner)->staffActionRequest = 1;
                    ((ByteFlags*)((char*)inner + 0x3f4))->b08 = 1;
                }
            }
            break;
        }
    }
}
#pragma opt_loop_invariants reset
#pragma opt_propagation off
#pragma inline_max_size(7)
int player_SeqFn(int obj, int obj2, ObjSeqState* seq, int endFlag)
{
    int ctrl;
    register int va;
    int vb;
    int tbl;
    int mapVal;
    int result;
    register PlayerState* inner;
    u8 found;
    f32 npos[3];
    f32 pz;
    f32 py;
    f32 px;
    int objCount;
    f32 nearArg;

    tbl = (int)lbl_80332EC0;
    ctrl = *(int*)&((GameObject*)obj2)->anim.placementData;
    inner = ((GameObject*)obj)->extra;
    result = 0;
    va = (int)objModelGetVecFn_800395d8((GameObject*)(obj), 0);
    vb = (int)objModelGetVecFn_800395d8((GameObject*)(obj), 9);
    seq->freeCallback = (ObjAnimSequenceFreeCallback)fn_802A93F4;
    if (gPlayerStaffObject != NULL)
    {
        staffFn_80170380(gPlayerStaffObject, 0);
    }
    playerStaffInit((GameObject*)obj, (int)inner);
    if (*(void**)&gPlayerEggObject == NULL && Obj_IsLoadingLocked() != 0)
    {
        ObjLink_AttachChild(obj,
                            gPlayerEggObject = (int)Obj_SetupObject(Obj_AllocObjectSetup(0x18, 0x66a), 4, -1, -1,
                                                                    ((GameObject*)obj)->anim.parent),
                            3);
    }
    if (*(void**)&gPlayerEggObject != NULL)
    {
        *(int*)&((GameObject*)gPlayerEggObject)->anim.parent = *(int*)&((GameObject*)obj)->anim.parent;
        if (inner->characterId == 0)
        {
            *(s16*)(gPlayerEggObject + 6) |= 0x4000;
        }
    }
    if (gPlayerStaffObject == NULL && Obj_IsLoadingLocked() != 0)
    {
        gPlayerStaffObject =
            (GameObject*)Obj_SetupObject(Obj_AllocObjectSetup(0x24, 0x773), 5, -1, -1, ((GameObject*)obj)->anim.parent);
    }
    if (gPlayerStaffObject != NULL)
    {
        ObjPath_GetPointWorldPosition((GameObject*)obj, 4, &gPlayerStaffObject->anim.localPosX,
                                      &gPlayerStaffObject->anim.localPosY, &gPlayerStaffObject->anim.localPosZ, 0);
    }
    if ((((u32) * (u8*)((char*)inner + 0x3f3) >> 3 & 1) != 0 || inner->animState == 0x40) &&
        ((u32) * (u8*)((char*)inner + 0x3f4) >> 7 & 1) == 0)
    {
        playerSetDisguised((GameObject*)obj, 0);
        inner->animState = -1;
    }
    ObjHits_DisableObject(obj);
    *(u32*)&inner->flags360 &= ~PLAYER_FLAG_HITDETECT;
    if ((s8)seq->movementState != 0)
    {
        s8 c;
        *(u32*)&inner->flags360 &= ~PLAYER_FLAG_AIM_READY;
        {
            f32 fz = 0.0f;
            inner->knockbackTimer = fz;
            inner->knockbackHitTimer = fz;
        }
        if (((u32) * (u8*)((char*)inner + 0x3f2) >> 7 & 1) == 0)
        {
            if (gPlayerPathObject != NULL && ((u32) * (u8*)((char*)inner + 0x3f4) >> 6 & 1) != 0)
            {
                inner->staffActionRequest = 1;
                ((ByteFlags*)((char*)inner + 0x3f4))->b08 = 1;
            }
            inner->isHoldingObject = 0;
            {
                GameObject* p = inner->heldObj;
                if (p != NULL)
                {
                    s16 sp = p->anim.seqId;
                    if (sp == 0x3cf || sp == 0x662)
                    {
                        objThrowFn_80182504(p);
                    }
                    else
                    {
                        objSaveFn_800ea774(p);
                    }
                    *(s16*)((char*)inner->heldObj + 6) &= ~0x4000;
                    *(int*)((char*)inner->heldObj + 0xf8) = 0;
                    inner->heldObj = 0;
                }
            }
        }
        if (*(s8*)(ctrl + 0x20) == 0 || (c = (s8)seq->movementState) == 3 || c == 2)
        {
            seq->flags = seq->savedFlags;
            if ((s8)seq->movementState != 2)
            {
                seq->posOffsetScale = 1.0f;
                seq->posOffsetX = ((GameObject*)obj)->anim.localPosX - ((GameObject*)obj2)->anim.localPosX;
                seq->posOffsetY = ((GameObject*)obj)->anim.localPosY - ((GameObject*)obj2)->anim.localPosY;
                seq->posOffsetZ = ((GameObject*)obj)->anim.localPosZ - ((PlayerState*)obj2)->baddie.posX;
                seq->rotOffsetX = inner->targetYaw - (u16) * (s16*)obj2;
                if (seq->rotOffsetX > 0x8000)
                {
                    seq->rotOffsetX = seq->rotOffsetX - 0xffff;
                }
                if (seq->rotOffsetX < -0x8000)
                {
                    seq->rotOffsetX = seq->rotOffsetX + 0xffff;
                }
                seq->rotOffsetY = ((GameObject*)obj)->anim.rotY - (u16) * (s16*)((char*)obj2 + 2);
                if (seq->rotOffsetY > 0x8000)
                {
                    seq->rotOffsetY = seq->rotOffsetY - 0xffff;
                }
                if (seq->rotOffsetY < -0x8000)
                {
                    seq->rotOffsetY = seq->rotOffsetY + 0xffff;
                }
                seq->rotOffsetZ = (u16) * (s16*)((char*)obj2 + 4) - (u16)((GameObject*)obj)->anim.rotZ;
                if (seq->rotOffsetZ > 0x8000)
                {
                    seq->rotOffsetZ = seq->rotOffsetZ - 0xffff;
                }
                if (seq->rotOffsetZ < -0x8000)
                {
                    seq->rotOffsetZ = seq->rotOffsetZ + 0xffff;
                }
                seq->movementState = 2;
            }
            seq->posOffsetScale = -(seq->posOffsetDecay * timeDelta - seq->posOffsetScale);
            if (seq->posOffsetScale <= 0.0f)
            {
                seq->movementState = 0;
            }
            ((GameObject*)obj)->anim.activeMove = -1;
            inner->bodyLeanHalf = 0;
            inner->headPitch = 0;
            inner->bodyLeanAngle = 0;
            inner->headYaw = 0;
        }
        else if (c == 4)
        {
            f32 dz;
            f32 dy;
            f32 dx;
            int d;
            seq->flags &= ~0x4c;
            seq->savedFlags &= ~0x48;
            obj2 = (int)getFocusedNpc();
            if (objModelGetVecFn_800395d8((GameObject*)(obj2), 0) != 0)
            {
                objPosFn_80039510((GameObject*)(obj2), 0, npos);
            }
            else
            {
                ObjHitVolumeRuntimeTransform* pv = ((GameObject*)obj2)->anim.hitVolumeTransforms;
                if (pv == NULL)
                {
                    npos[0] = ((GameObject*)obj2)->anim.worldPosX;
                    npos[1] = ((GameObject*)obj2)->anim.worldPosY;
                    npos[2] = ((GameObject*)obj2)->anim.worldPosZ;
                }
                else
                {
                    npos[0] = pv->jointX;
                    npos[1] = pv->jointY;
                    npos[2] = pv->jointZ;
                }
            }
            ObjPath_GetPointWorldPosition((GameObject*)obj, 5, &px, &py, &pz, 0);
            dx = ((GameObject*)obj)->anim.worldPosX - npos[0];
            dy = (((PlayerState*)inner)->pathBearingEyeY + ((GameObject*)obj)->anim.worldPosY) - npos[1];
            dz = ((GameObject*)obj)->anim.worldPosZ - npos[2];
            {
                s16 ang = (s16)getAngle(dx, dz);
                lbl_803DE4B0 = ang;
                d = ang - (u16) * (s16*)((char*)inner + 0x478);
            }
            if (d > 0x8000)
            {
                d -= 0xffff;
            }
            if (d < -0x8000)
            {
                d += 0xffff;
            }
            *(s16*)((char*)inner + 0x4d8) = -*(s16*)(va + 2);
            *(s16*)((char*)inner + 0x4dc) = -*(s16*)va;
            if (d >= 0)
            {
                if (d > 0x2aaa)
                {
                    ((PlayerState*)inner)->bodyLeanAimDelta = -0x2aaa;
                    ((PlayerState*)inner)->aimTurnYaw = d - 0x2aaa;
                }
                else
                {
                    ((PlayerState*)inner)->bodyLeanAimDelta = -d;
                    ((PlayerState*)inner)->aimTurnYaw = 0;
                }
            }
            else if (d < -0x2aaa)
            {
                ((PlayerState*)inner)->bodyLeanAimDelta = 0x2aaa;
                ((PlayerState*)inner)->aimTurnYaw = d + 0x2aaa;
            }
            else
            {
                ((PlayerState*)inner)->bodyLeanAimDelta = -d;
                ((PlayerState*)inner)->aimTurnYaw = 0;
            }
            ((PlayerState*)inner)->headYawAimDelta = (s16)getAngle(dy, sqrtf(dx * dx + dz * dz));
            {
                int v = ((PlayerState*)inner)->headYawAimDelta;
                if (v < -0x1000)
                {
                    v = -0x1000;
                }
                else if (v > 0x1000)
                {
                    v = 0x1000;
                }
                ((PlayerState*)inner)->headYawAimDelta = v;
            }
            seq->rotOffsetZ = 0;
            seq->posOffsetScale = 0.0f;
            seq->posOffsetDecay = 0.033333335f;
            seq->movementState = 5;
            {
                int mv;
                if (*(u32*)&((PlayerState*)inner)->heldObj != 0)
                {
                    mv = 8;
                }
                else
                {
                    mv = 0;
                }
                if (((GameObject*)obj)->anim.currentMove != mv)
                {
                    ObjAnim_SetCurrentMove(obj, mv, 0.0f, 0);
                    ObjAnim_SetCurrentEventStepFrames((ObjAnimComponent*)obj, 1);
                }
            }
            ObjAnim_AdvanceCurrentMove((int)obj, 0.005f, timeDelta, 0);
            result = 1;
        }
        else if (c == 5)
        {
            seq->flags &= ~0x4c;
            seq->savedFlags &= ~0x48;
            ObjHits_EnableObject(obj);
            if (seq->posOffsetScale >= 1.0f && (*gCameraInterface)->isZooming() == 0)
            {
                ((PlayerState*)inner)->bodyLeanHalf = 0;
                ((PlayerState*)inner)->headPitch = 0;
                if ((s8)endFlag == 0)
                {
                    seq->movementState = 0;
                }
                else
                {
                    seq->movementState = 6;
                }
                if (((PlayerState*)inner)->focusObject != NULL)
                {
                    (**(void (**)(int, int, int))((char*)(*gPlayerInterface) + 0x14))(obj, (int)inner, 0x18);
                    *(void (**)(int))((char*)inner + 0x304) = (void (*)(int))fn_8029F67C;
                }
                else
                {
                    (**(void (**)(int, int, int))((char*)(*gPlayerInterface) + 0x14))(obj, (int)inner, 1);
                    *(void (**)(int, int))((char*)inner + 0x304) = (void (*)(int, int))fn_802A514C;
                    ((PlayerState*)inner)->baddie.prevControlMode = 1;
                }
            }
            else
            {
                f32 prev = seq->posOffsetScale;
                f32 one;
                int dd;
                seq->posOffsetScale = seq->posOffsetDecay * timeDelta + prev;
                if (seq->posOffsetScale > 1.0f)
                {
                    seq->posOffsetScale = 1.0f;
                }
                prev = seq->posOffsetScale - prev;
                ((PlayerState*)inner)->targetYaw += (s16)(prev * (f32) * (s16*)((char*)inner + 0x4e0));
                *(s16*)obj = ((PlayerState*)inner)->yaw = ((PlayerState*)inner)->targetYaw;
                dd = *(s16*)((char*)inner + 0x4d8) - (u16) * (s16*)((char*)inner + 0x4da);
                if (dd > 0x8000)
                {
                    dd = dd - 0xffff;
                }
                if (dd < -0x8000)
                {
                    dd = dd + 0xffff;
                }
                *(s16*)(va + 2) = (s16)((f32)dd * seq->posOffsetScale + (f32) * (s16*)((char*)inner + 0x4d8));
                dd = *(s16*)((char*)inner + 0x4dc) - (u16) * (s16*)((char*)inner + 0x4de);
                if (dd > 0x8000)
                {
                    dd = dd - 0xffff;
                }
                if (dd < -0x8000)
                {
                    dd = dd + 0xffff;
                }
                *(s16*)va = (s16)((f32)dd * seq->posOffsetScale + (f32) * (s16*)((char*)inner + 0x4dc));
                *(s16*)(vb + 2) = (s16)((f32) * (s16*)((char*)inner + 0x4d2) * ((one = 1.0f) - seq->posOffsetScale));
                *(s16*)(vb + 4) = (s16)((f32) * (s16*)((char*)inner + 0x4d0) * (one - seq->posOffsetScale));
                ((GameObject*)obj)->anim.rotZ = *(s16*)(vb + 4) / 4;
                ((PlayerState*)inner)->bodyLeanAngle = *(s16*)(va + 2);
                ((PlayerState*)inner)->headYaw = -*(s16*)va;
            }
            ObjAnim_AdvanceCurrentMove((int)obj, 0.005f, timeDelta, 0);
            result = 1;
        }
        else if (c == 6)
        {
            seq->flags &= ~0x4c;
            seq->savedFlags &= ~0x48;
            ObjHits_EnableObject(obj);
            if ((s8)endFlag == 0)
            {
                seq->movementState = 0;
            }
            ObjAnim_AdvanceCurrentMove((int)obj, 0.005f, timeDelta, 0);
            result = 0;
        }
        else
        {
            f32 dx2;
            f32 dz2;
            f32 dist;
            f32 d2;
            if (c != 1)
            {
                seq->posOffsetX = ((GameObject*)obj)->anim.localPosX;
                seq->posOffsetY = ((GameObject*)obj)->anim.localPosY;
                seq->posOffsetZ = ((GameObject*)obj)->anim.localPosZ;
                lbl_803DE468 = 10000.0f;
                lbl_803DE46C = 0;
            }
            result = 1;
            seq->flags = 0;
            seq->movementState = 1;
            {
                f32 ax = seq->posOffsetX - ((GameObject*)obj)->anim.localPosX;
                f32 az = seq->posOffsetZ - ((GameObject*)obj)->anim.localPosZ;
                dist = sqrtf(ax * ax + az * az);
            }
            dx2 = ((GameObject*)obj2)->anim.localPosX - seq->posOffsetX;
            dz2 = ((PlayerState*)obj2)->baddie.posX - seq->posOffsetZ;
            d2 = sqrtf(dx2 * dx2 + dz2 * dz2);
            if (dist <= lbl_803DE468)
            {
                lbl_803DE46C += 1;
            }
            if (dist >= d2 || lbl_803DE46C > 5)
            {
                int dd3 = ((PlayerState*)inner)->targetYaw - (u16) * (s16*)obj2;
                if (dd3 > 0x8000)
                {
                    dd3 -= 0xffff;
                }
                if (dd3 < -0x8000)
                {
                    dd3 += 0xffff;
                }
                if (dd3 > 0x4000)
                {
                    dd3 = 0x4000;
                }
                if (dd3 < -0x4000)
                {
                    dd3 = -0x4000;
                }
                ((PlayerState*)inner)->targetYaw -= (dd3 * framesThisStep) >> 3;
                ((PlayerState*)inner)->yaw = ((PlayerState*)inner)->targetYaw;
                if (lbl_803DE46C > 6)
                {
                    dd3 = 0;
                }
                if (dd3 < 0x100 && dd3 > -0x100)
                {
                    seq->flags = seq->savedFlags;
                    seq->movementState = 0;
                    seq->prevFrame = seq->curFrame - 1;
                    ((GameObject*)obj)->anim.activeMove = -1;
                    result = 0;
                }
                else
                {
                    f32 fz3 = 0.0f;
                    ((PlayerState*)inner)->baddie.moveInputX = fz3;
                    ((PlayerState*)inner)->baddie.moveInputZ = fz3;
                    (**(void (**)(int))((char*)(*gPlayerInterface) + 0x10))(obj2);
                    *(int*)&((PlayerState*)inner)->baddie.unk31C = 0;
                    *(int*)&((PlayerState*)inner)->baddie.unk318 = 0;
                    ((GameObject*)obj)->unkF4 = 0;
                    ((PlayerState*)inner)->baddie.cameraYaw = 0;
                    ((PlayerState*)inner)->baddie.physicsActive = 1;
                    *(u32*)((char*)inner + 4) = *(u32*)((char*)inner + 4) & ~0x100000;
                    ((PlayerState*)inner)->emissionState = 0;
                    fn_802B0EA4((GameObject*)(obj), (int)inner, (int)inner);
                    (**(void (**)(f32, int, int, f32, void*, void*))((char*)(*gPlayerInterface) + 8))(
                        timeDelta, obj, (int)inner, timeDelta, gPlayerStateHandlers, &gPlayerDefaultStateHandler);
                }
            }
            else
            {
                dx2 = dx2 / d2;
                dz2 = dz2 / d2;
                {
                    f32 k = 40.0f;
                    ((PlayerState*)inner)->baddie.moveInputX = k * -dx2;
                    ((PlayerState*)inner)->baddie.moveInputZ = k * dz2;
                }
                ((GameObject*)obj)->anim.localPosX = dist * dx2 + seq->posOffsetX;
                ((GameObject*)obj)->anim.localPosZ = dist * dz2 + seq->posOffsetZ;
                (**(void (**)(int))((char*)(*gPlayerInterface) + 0x10))(obj2);
                *(int*)&((PlayerState*)inner)->baddie.unk31C = 0;
                *(int*)&((PlayerState*)inner)->baddie.unk318 = 0;
                ((GameObject*)obj)->unkF4 = 0;
                ((PlayerState*)inner)->baddie.cameraYaw = 0;
                ((PlayerState*)inner)->baddie.physicsActive = 1;
                *(u32*)((char*)inner + 4) = *(u32*)((char*)inner + 4) & ~0x100000;
                ((PlayerState*)inner)->emissionState = 0;
                fn_802B0EA4((GameObject*)(obj), (int)inner, (int)inner);
                (**(void (**)(f32, int, int, f32, void*, void*))((char*)(*gPlayerInterface) + 8))(
                    timeDelta, obj, (int)inner, timeDelta, gPlayerStateHandlers, &gPlayerDefaultStateHandler);
            }
            lbl_803DE468 = dist;
        }
        if ((s8)seq->movementState == 0)
        {
            (**(void (**)(int, int, int))((char*)(*gPlayerInterface) + 0x14))(obj, (int)inner, 1);
            *(void (**)(int, int))((char*)inner + 0x304) = (void (*)(int, int))fn_802A514C;
            ((PlayerState*)inner)->baddie.prevControlMode = 1;
        }
    }
    else
    {
        seq->flags |= seq->savedFlags & ~0x400;
        *(u8*)((char*)inner + 0x34c) = 0;
        {
            f32 fz2 = 0.0f;
            ((PlayerState*)inner)->baddie.moveInputX = fz2;
            ((PlayerState*)inner)->baddie.moveInputZ = fz2;
        }
        ((PlayerState*)inner)->baddie.cameraYaw = 0;
        *(int*)&((PlayerState*)inner)->baddie.unk31C = 0;
        *(int*)&((PlayerState*)inner)->baddie.unk318 = 0;
        if (seq->flags & 1)
        {
            *(u32*)((char*)inner + 4) |= 0x100000;
            ((PlayerState*)inner)->baddie.physicsActive = 0;
        }
        for (vb = 0; vb < seq->eventCount; vb++)
        {
            switch (seq->eventIds[vb])
            {
            case 3:
            {
                f32 best;
                obj2 = (int)ObjGroup_GetObjects(10, &objCount);
                found = 0;
                best = 10000.0f;
                for (endFlag = 0; endFlag < objCount; endFlag++)
                {
                    va = *(int*)obj2;
                    if ((u32)va != 0 && arrayIndexOf((int*)(tbl + 0x13c), 9, *(s16*)(va + 0x46)) != -1)
                    {
                        f32 dsq = vec3f_distanceSquared((f32*)(va + 0x18), (f32*)(obj + 0x18));
                        if (dsq < best || found == 0)
                        {
                            best = dsq;
                            ((PlayerState*)inner)->focusObject = (GameObject*)va;
                            found = 1;
                        }
                    }
                    obj2 += 4;
                }
                if (found != 0)
                {
                    ((PlayerState*)inner)->unk6A4 = 1.0f;
                    ((PlayerState*)inner)->unk6A8 = ((PlayerState*)inner)->savedPosX;
                    ((PlayerState*)inner)->unk6AC = ((PlayerState*)inner)->savedPosY;
                    ((PlayerState*)inner)->unk6B0 = ((PlayerState*)inner)->savedPosZ;
                    va = (int)((PlayerState*)inner)->focusObject;
                    (*(void (*)(int, int)) * (int*)((char*)*(int*)(*(int*)(va + 0x68)) + 0x3c))(va, 2);
                    ((GameObject*)obj)->anim.flags |= 8;
                    ((GameObject*)obj)->anim.modelState->flags |= OBJ_MODEL_STATE_SHADOW_FADE_OUT;
                    ((GameObject*)obj)->anim.modelState->shadowAlphaStep = 0;
                    seq->flags &= ~4;
                    switch (*(s16*)(va + 0x46))
                    {
                    case 0x72:
                    case 0x38c:
                        Music_Trigger(MUSICTRIG_drako_2, 1);
                        mainSetBits(0xc1f, 0);
                        ((PlayerState*)inner)->moveSequence = tbl + 0x3f0;
                        ((PlayerState*)inner)->moveSequenceFlags = 3;
                        ObjAnim_SetCurrentMove(obj, 0x17, 0.0f, 1);
                        break;
                    case 0x8c:
                        ((PlayerState*)inner)->moveSequence = tbl + 0x408;
                        ((PlayerState*)inner)->moveSequenceFlags = 4;
                        ObjAnim_SetCurrentMove(obj, 0x7b, 0.0f, 1);
                        if ((u32)getSbGalleon() != 0)
                        {
                            (*gCameraInterface)->setFocus((void*)va, 0);
                            (*gObjectTriggerInterface)->setCamVars(0x4a, 1, 0, 0x78);
                        }
                        break;
                    case 0x416:
                        Music_Trigger(MUSICTRIG_WLC_Puzzle, 1);
                        ((PlayerState*)inner)->moveSequence = tbl + 0x438;
                        ((PlayerState*)inner)->moveSequenceFlags = 8;
                        ObjAnim_SetCurrentMove(obj, *(s16*)(tbl + 0x438), 0.0f, 1);
                        break;
                    case 0x419:
                        Music_Trigger(MUSICTRIG_starfox_rwing_1_e6, 1);
                        ((PlayerState*)inner)->moveSequence = tbl + 0x408;
                        ((PlayerState*)inner)->moveSequenceFlags = 4;
                        ObjAnim_SetCurrentMove(obj, 0x7b, 0.0f, 1);
                        break;
                    case 0x484:
                        Music_Trigger(MUSICTRIG_starfox_rwing_1_e6, 1);
                        ((PlayerState*)inner)->moveSequence = tbl + 0x420;
                        ((PlayerState*)inner)->moveSequenceFlags = 4;
                        ObjAnim_SetCurrentMove(obj, 0xf8, 0.0f, 1);
                        break;
                    default:
                        Music_Trigger(MUSICTRIG_inside_warlock, 1);
                    case 0x714:
                        ((PlayerState*)inner)->moveSequence = tbl + 0x420;
                        ((PlayerState*)inner)->moveSequenceFlags = 4;
                        ObjAnim_SetCurrentMove(obj, 0xf8, 0.0f, 1);
                    }
                    if (arrayIndexOf((int*)(tbl + 0x160), 4, *(s16*)(va + 0x46)) != -1)
                    {
                        (**(void (**)(int, int, int))((char*)(*gPlayerInterface) + 0x14))(obj, (int)inner, 0x1a);
                        *(void (**)(int))((char*)inner + 0x304) = (void (*)(int))fn_8029F67C;
                    }
                    else
                    {
                        (**(void (**)(int, int, int))((char*)(*gPlayerInterface) + 0x14))(obj, (int)inner, 0x18);
                        *(void (**)(int))((char*)inner + 0x304) = (void (*)(int))fn_8029F67C;
                    }
                }
                break;
            }
            case 2:
                if (playerStopRidingObject((GameObject*)obj) != 0)
                {
                    seq->flags |= 4;
                }
                break;
            case 4:
                obj2 = (int)((PlayerState*)inner)->focusObject;
                (*gCameraInterface)->setFocus((void*)obj2, 0);
                (*gObjectTriggerInterface)->setCamVars(0x45, 0, 0, 0);
                ((PlayerState*)inner)->moveSequence = 0;
                if ((u32)obj2 != 0 && ((GameObject*)obj2)->anim.seqId == 0x22)
                {
                    (**(void (**)(int, int, int))((char*)(*gPlayerInterface) + 0x14))(obj, (int)inner, 0x16);
                    *(int*)&((PlayerState*)inner)->baddie.unk304 = 0;
                }
                else
                {
                    (**(void (**)(int, int, int))((char*)(*gPlayerInterface) + 0x14))(obj, (int)inner, 0x18);
                    *(void (**)(int))((char*)inner + 0x304) = (void (*)(int))fn_8029F67C;
                }
                break;
            case 0xb:
            {
                int gb = (int)((PlayerState*)inner)->focusObject;
                if ((u32)gb != 0 && *(s16*)(gb + 0x46) == 0x416)
                {
                    (*gCameraInterface)->setFocus((void*)gb, 0);
                    (*gCameraInterface)->loadTriggeredCamAction(0, 0x69, 0);
                    (*gObjectTriggerInterface)->setCamVars(0x42, 4, 0, 0);
                }
                else if ((u32)gb != 0 && arrayIndexOf((int*)(tbl + 0x160), 4, *(s16*)(gb + 0x46)) != -1)
                {
                    (*gObjectTriggerInterface)->setCamVars(0x53, 0, 0, 0);
                }
                else
                {
                    (*gCameraInterface)->loadTriggeredCamAction(0, 0x1d, 0);
                    (*gObjectTriggerInterface)->setCamVars(0x42, 4, 0, 0);
                }
                break;
            }
            case 6:
                (*gObjectTriggerInterface)->setCamVars(0x44, 0, 0, 0);
                (**(void (**)(int, int, int))((char*)(*gPlayerInterface) + 0x14))(obj, (int)inner, 0x17);
                *(int*)&((PlayerState*)inner)->baddie.unk304 = 0;
                break;
            case 7:
                seq->flags &= ~3;
                obj2 = *(int*)&((GameObject*)obj)->extra;
                (**(void (**)(int, int, int))((char*)(*gPlayerInterface) + 0x14))(obj, obj2, 0x3e);
                *(int*)&((PlayerState*)obj2)->baddie.unk304 = 0;
                *(u32*)(obj2 + 0x360) |= 1LL;
                ((GameObject*)obj)->anim.flags |= 8;
                break;
            case 8:
            {
                seq->flags = seq->savedFlags;
                obj2 = *(int*)&((GameObject*)obj)->extra;
                (**(void (**)(int, int, int))((char*)(*gPlayerInterface) + 0x14))(obj, obj2, 1);
                *(void (**)(int, int))(obj2 + 0x304) = (void (*)(int, int))fn_802A514C;
                *(u32*)((char*)obj2 + 0x360) &= ~0x1LL;
                ((GameObject*)obj)->anim.flags &= ~8;
                break;
            }
            case 0xa:
                if (gPlayerPathObject != NULL && ((u32) * (u8*)((char*)inner + 0x3f4) >> 6 & 1) != 0)
                {
                    ((PlayerState*)inner)->staffActionRequest = 2;
                    ((ByteFlags*)((char*)inner + 0x3f4))->b08 = 0;
                }
                break;
            case 0x18:
                if (gPlayerPathObject != NULL && ((u32) * (u8*)((char*)inner + 0x3f4) >> 6 & 1) != 0)
                {
                    ((PlayerState*)inner)->staffActionRequest = 0;
                    ((ByteFlags*)((char*)inner + 0x3f4))->b08 = 0;
                }
                break;
            case 0xd:
            {
                f32 spd;
                f32 dy2;
                f32 sp3;
                (*gObjectTriggerInterface)
                    ->setObjects(*(s16*)(*(int*)&((GameObject*)obj)->ownerObj + 0x46),
                                 *(int*)&((GameObject*)obj)->ownerObj, 0);
                {
                    int prt = *(int*)&((GameObject*)obj)->ownerObj;
                    obj2 = (int)((GameObject*)prt)->extra;
                    if (*(u32*)&((GameObject*)prt)->anim.hitReactState != 0)
                    {
                        spd = (f32) * (s16*)(*(int*)&((GameObject*)prt)->anim.hitReactState + 0x5a);
                    }
                    else
                    {
                        spd = ((GameObject*)prt)->anim.hitboxScale * ((GameObject*)prt)->anim.rootMotionScale;
                    }
                    dy2 = (((GameObject*)prt)->anim.hitVolumeTransforms->jointY - ((GameObject*)prt)->anim.localPosY) -
                          29.0f;
                }
                sp3 = spd * -mathCosf(gPlayerPi * (f32) * (s16*)(obj2 + 0x478) / 32768.0f);
                (*gObjectTriggerInterface)
                    ->setOverridePos(spd * -mathSinf(gPlayerPi * (f32) * (s16*)(obj2 + 0x478) / 32768.0f), dy2, sp3);
                (*gObjectTriggerInterface)->runSequence(((GameObject*)obj)->unkF4, (void*)obj, -1);
                break;
            }
            case 0xf:
                objHitDetectFn_80062e84((GameObject*)obj, NULL, 1);
                break;
            case 0x10:
            {
                int t;
                nearArg = 400.0f;
                t = ObjGroup_FindNearestObject(6, (int)obj, &nearArg);
                if ((u32)t != 0)
                {
                    objHitDetectFn_80062e84((GameObject*)obj, (GameObject*)t, 1);
                }
                break;
            }
            case 0x17:
                va = *(int*)&((GameObject*)obj)->extra;
                if (*(u32*)(va + 0x7f8) != 0)
                {
                    *(u8*)(va + 0x800) = 0;
                    {
                        int p17 = *(int*)(va + 0x7f8);
                        if ((u32)p17 != 0)
                        {
                            s16 sp17 = *(s16*)(p17 + 0x46);
                            if (sp17 == 0x3cf || sp17 == 0x662)
                            {
                                objThrowFn_80182504((GameObject*)(p17));
                            }
                            else
                            {
                                objSaveFn_800ea774((GameObject*)p17);
                            }
                            *(s16*)(*(int*)(va + 0x7f8) + 6) &= ~0x4000;
                            *(int*)(*(int*)(va + 0x7f8) + 0xf8) = 0;
                            *(int*)(va + 0x7f8) = 0;
                        }
                    }
                    *(u32*)((char*)va + 0x360) |= 0x800000LL;
                    (**(void (**)(int, int, int))((char*)(*gPlayerInterface) + 0x14))(obj, va, 1);
                    *(void (**)(int, int))(va + 0x304) = (void (*)(int, int))fn_802A514C;
                }
                break;
            case 0x14:
            {
                *(u32*)&((PlayerState*)inner)->flags360 |= 0x40000LL;
                break;
            }
            case 0x15:
            {
                *(u32*)&((PlayerState*)inner)->flags360 &= ~0x40000LL;
                break;
            }
            case 0x16:
            {
                *(u32*)&((PlayerState*)inner)->flags360 |= PLAYER_FLAG_WATER_SPLASH_PENDING;
                break;
            }
            case 0x12:
            {
                *(u32*)&((PlayerState*)inner)->flags360 |= 0x8000LL;
                break;
            }
            case 0x13:
                loadUiDll(1);
                break;
            case 0x19:
                (*gMapEventInterface)->gotoRestartPoint();
                break;
            case 0x1c:
                staffToggle((GameObject*)(obj), 0);
                break;
            case 0x1d:
                (**(void (**)(int, int, int))((char*)(*gPlayerInterface) + 0x14))(obj, (int)inner, 0x1a);
                *(void (**)(int))((char*)inner + 0x304) = (void (*)(int))fn_8029F67C;
                break;
            case 0x1e:
                (**(void (**)(int, int, int))((char*)(*gPlayerInterface) + 0x14))(obj, (int)inner, 1);
                *(void (**)(int, int))((char*)inner + 0x304) = (void (*)(int, int))fn_802A514C;
                break;
            case 0x1f:
                __set_debug_bba((u8*)gPlayerModelChain);
                ObjModelChain_SetEnabled((ObjModelChain*)gPlayerModelChain, 1);
                break;
            case 0x20:
                ObjModelChain_SetEnabled((ObjModelChain*)gPlayerModelChain, 0);
                break;
            case 0x21:
                gPlayerSubState = 2;
                break;
            case 0x22:
                gPlayerSubState = 1;
                break;
            case 0x1a:
                if (*(u32*)&((PlayerState*)inner)->interactObject != 0)
                {
                    int p1a = *(int*)(((PlayerState*)inner)->interactObject + 0x50);
                    int snd = *(s16*)(p1a + 0x7a);
                    if (snd > -1)
                    {
                        (*gGameUIInterface)->showNpcDialogue(snd, 0x154, 300, 0);
                    }
                    else
                    {
                        (*gGameUIInterface)->showNpcDialogue(*(s16*)(p1a + 0x7c), 0x154, 300, 0);
                    }
                }
                break;
            case 1:
                if (*(u32*)&((PlayerState*)inner)->interactObject != 0)
                {
            ObjMsg_SendToObject((void*)((PlayerState*)inner)->interactObject, 0x7000b, (void*)obj, 0);
                    ((PlayerState*)inner)->interactObject = 0;
                }
                break;
            case 0x25:
                ((PlayerState*)inner)->pendingFxFlags ^= 1;
                break;
            case 0x26:
                ((PlayerState*)inner)->pendingFxFlags ^= 2;
                break;
            case 0x27:
                hudFn_8011f38c(1);
                break;
            case 0x28:
            {
                int h;
                switch (coordsToMapCell(((GameObject*)obj)->anim.localPosX, ((GameObject*)obj)->anim.localPosZ))
                {
                case 0x13:
                    mapVal = 0x10;
                    break;
                case 0xc:
                    mapVal = 0x14;
                    break;
                case 0xd:
                    mapVal = 0x18;
                    break;
                case 2:
                    mapVal = 0x1c;
                    break;
                }
                h = *(int*)&((GameObject*)obj)->extra;
                if ((s8) * (s8*)(*(int*)(h + 0x35c) + 1) <= mapVal - 4)
                {
                    int vv = mapVal;
                    if (mapVal < 0)
                    {
                        vv = 0;
                    }
                    else if (mapVal > 0x50)
                    {
                        vv = 0x50;
                    }
                    *(s8*)(*(int*)(h + 0x35c) + 1) = vv;
                    vv = mapVal;
                    h = *(int*)&((GameObject*)obj)->extra;
                    if (mapVal < 0)
                    {
                        vv = 0;
                    }
                    else
                    {
                        s8 cur2 = *(s8*)(*(int*)(h + 0x35c) + 1);
                        if (mapVal > cur2)
                        {
                            vv = cur2;
                        }
                    }
                    *(s8*)(*(int*)(h + 0x35c)) = vv;
                }
                break;
            }
            case 0x29:
                hudFn_8011f38c(0);
                break;
            case 0x2a:
                if ((*gMapEventInterface)->getMapAct(0xb) == 7)
                {
                    getEnvfxActImmediatelyVoid(obj, obj, 0x1fb, 0);
                    getEnvfxActImmediatelyVoid(obj, obj, 0x1ff, 0);
                    getEnvfxActImmediatelyVoid(obj, obj, 0x249, 0);
                    getEnvfxActImmediatelyVoid(obj, obj, 0x1fd, 0);
                }
                else
                {
                    getEnvfxActImmediatelyVoid(obj, obj, 0x217, 0);
                    getEnvfxActImmediatelyVoid(obj, obj, 0x216, 0);
                    getEnvfxActImmediatelyVoid(obj, obj, 0x22e, 0);
                    getEnvfxActImmediatelyVoid(obj, obj, 0x218, 0);
                    getEnvfxActImmediatelyVoid(obj, obj, 0x84, 0);
                    getEnvfxActImmediatelyVoid(obj, obj, 0x8a, 0);
                }
                ((void (*)(int, f32))skyFn_80088e54)(0, 0.0f);
                break;
            case 0x2d:
                Rcp_SetSpiritVisionEnabled(1);
                break;
            case 0x2e:
                Rcp_SetSpiritVisionEnabled(0);
                break;
            case 0x2b:
            {
                register u32 m;
                m = ((GameObject*)obj)->anim.modelState->flags;
                m &= ~OBJ_MODEL_STATE_SHADOW_VISIBLE;
                ((GameObject*)obj)->anim.modelState->flags = m;
                break;
            }
            case 0x2c:
                ((GameObject*)obj)->anim.modelState->flags |= OBJ_MODEL_STATE_SHADOW_VISIBLE;
                break;
            case 0x31:
                viewFinderSetZoomTo50();
                break;
            case 0x32:
                viewFinderSetZoom(Camera_GetFovY());
                break;
            }
        }
        if (*(int*)(*(int*)&((GameObject*)obj)->extra + 0x360) & 1)
        {
            seq->flags &= ~3;
        }
    }
    if (lbl_803DE458 != 0)
    {
        seq->sequenceControlFlags |= OBJSEQ_CONTROL_SET_LATCH_A;
        lbl_803DE458 = 0;
    }
    {
        int g = (int)((PlayerState*)inner)->focusObject;
        if ((u32)g != 0 && (*(int (*)(int)) * (int*)((char*)*(int*)(*(int*)(g + 0x68)) + 0x38))(g) == 2)
        {
            seq->flags &= ~3;
        }
    }
    if (((u32) * (u8*)((char*)inner + 0x3f2) >> 6 & 1) != 0)
    {
        characterDoEyeAnimsState((GameObject*)obj, (char*)inner + 0x364);
    }
    if (gPlayerSubState == 2)
    {
        gPlayerSubState = 1;
    }
    if (((GameObject*)gPlayerPathObject)->anim.classId == 0x2d)
    {
        ((void (*)(void))objSetAnimField48to0)();
    }
    ((void (*)(int, int, f32))staffAnimate)(obj, (int)inner, timeDelta);
    if (gPlayerPathObject != NULL && ((u32) * (u8*)((char*)inner + 0x3f4) >> 6 & 1) != 0)
    {
        ((GameObject*)gPlayerPathObject)->objectFlags &= ~7;
        if (((PlayerState*)inner)->staffGrown == 0)
        {
            ((GameObject*)gPlayerPathObject)->objectFlags |= 2;
        }
    }
    *(u32*)&((PlayerState*)inner)->flags360 |= PLAYER_FLAG_TELEPORTED;
    ((void (*)(int, int, int, int, int, f32, f32))objAudioFn_8006ef38)(
        obj, (int)&seq->animEvents, ((PlayerState*)inner)->animSoundId, (int)((char*)inner + 0x3c4),
        (int)((char*)inner + 4), ((PlayerState*)inner)->baddie.animSpeedA, 1.0f);
    return result;
}

void fn_802B4A9C(int obj, int inner, int inner2)
{
    int* target = (int*)(*gCameraInterface)->getOverrideTarget();
    u32 v = (((PlayerState*)inner)->flags3F4 >> 6) & 1;

    if (v != 0)
    {
        if ((*(u32*)&((PlayerState*)inner)->flags360 & 0x10) != 0)
        {
            if (gPlayerPathObject != NULL && v != 0)
            {
                ((PlayerState*)inner)->staffActionRequest = 2;
                ((ByteFlags*)((char*)inner + 0x3f4))->b08 = 0;
            }
            ((PlayerState*)inner2)->baddie.hasTarget = 1;
            if (target != NULL)
            {
                *(int**)&((PlayerState*)inner2)->baddie.targetObj = target;
            }
            else
            {
                f32 dist = lbl_803E8150;
                *(int*)&((PlayerState*)inner2)->baddie.targetObj = ObjGroup_FindNearestObject(3, (int)obj, &dist);
            }
        }
        else
        {
            if (target != NULL)
            {
                if (*(int**)&((PlayerState*)inner2)->baddie.targetObj != target)
                {
                    ((PlayerState*)inner2)->baddie.hasTarget = 0;
                    if ((((GameObject*)target)->anim.hitVolumeBounds->flags & 0xf) == 1)
                    {
                        if (gPlayerPathObject != NULL)
                        {
                            u32 targetFlag = (((PlayerState*)inner)->flags3F4 >> 6) & 1;
                            if (targetFlag != 0)
                            {
                                ((PlayerState*)inner)->staffActionRequest = 2;
                                ((ByteFlags*)((char*)inner + 0x3f4))->b08 = 0;
                            }
                        }
                        ((PlayerState*)inner2)->baddie.hasTarget = 1;
                    }
                }
                *(int**)&((PlayerState*)inner2)->baddie.targetObj = target;
            }
            else
            {
                *(int*)&((PlayerState*)inner2)->baddie.targetObj = 0;
                ((PlayerState*)inner2)->baddie.hasTarget = 0;
            }
        }
        if (*(int**)&((PlayerState*)inner2)->baddie.targetObj != NULL)
        {
            fn_8014C540((GameObject*)((PlayerState*)inner2)->baddie.targetObj, (int*)&((PlayerState*)inner)->flags884,
                        &((PlayerState*)inner)->animSpeedDecay, &((PlayerState*)inner)->animSpeedStart);
        }
        else
        {
            ((PlayerState*)inner)->deferredItemCommand = -1;
        }
    }
}
#pragma inline_max_size reset
#pragma opt_propagation reset

void playerAnimate(int obj, int state, f32 fv)
{
    u8 buf[0x40];

    ((PlayerState*)state)->baddie.gravity = lbl_803E7EB4;
    ((PlayerState*)state)->baddie.moveInputX = ((PlayerState*)state)->stickXf;
    ((PlayerState*)state)->baddie.moveInputZ = ((PlayerState*)state)->stickYf;
    *(int*)&((PlayerState*)state)->baddie.unk31C = ((PlayerState*)state)->buttonsJustPressed;
    *(int*)&((PlayerState*)state)->baddie.unk318 = ((PlayerState*)state)->buttonsHeld;
    Player_GetObjHitsState((GameObject*)(obj))->hitVolumePriority = 0;
    Player_GetObjHitsState((GameObject*)(obj))->hitVolumeId = 0;
    Player_GetObjHitsState((GameObject*)(obj))->objectPairPriority = 0;
    Player_GetObjHitsState((GameObject*)(obj))->objectPairHitVolume = 0;
    ((PlayerState*)state)->baddie.physicsActive = 1;
    *(u32*)((char*)state + 0x4) &= ~0x8100000;
    playerShadowFn_80062a30((GameObject*)obj);
    ((PlayerState*)state)->emissionState = 0;
    *(u32*)&((PlayerState*)state)->flags360 &= ~PLAYER_FLAG_NO_POS_VELOCITY;
    *(int*)state |= 0x1000000;
    fn_802B0EA4((GameObject*)(obj), state, state);
    if (playerCheckIfClimbingOntoWall(obj, state, state, buf, fv, 0x60) == 8)
    {
        *(int*)&((PlayerState*)state)->baddie.targetObj = 0;
        ((PlayerState*)state)->baddie.hasTarget = 0;
        (*gCameraInterface)->setTarget(0);
        if (gPlayerPathObject != 0 && ((ByteFlags*)((char*)state + 0x3f4))->b40)
        {
            ((PlayerState*)state)->staffActionRequest = 1;
            ((ByteFlags*)((char*)state + 0x3f4))->b08 = 1;
        }
        (*(void (*)(int, int, int))(*(int*)((char*)*gPlayerInterface + 0x14)))(obj, state, 0xa);
        *(int*)&((PlayerState*)state)->baddie.unk304 = 0;
    }
    (*(void (*)(int, int, f32, f32, int*, int*))(*(int*)((char*)*gPlayerInterface + 0x8)))(
        obj, state, fv, fv, gPlayerStateHandlers, &gPlayerDefaultStateHandler);
    *(int*)state &= ~0x1000000;
}

void fn_802B4DE0(GameObject* obj)
{
    int off;
    int i;
    PlayerState* inner = obj->extra;

    if ((u32)gPlayerEggObject != 0)
    {
        Obj_FreeObject((GameObject*)gPlayerEggObject);
        ObjLink_DetachChild(obj, gPlayerEggObject);
        gPlayerEggObject = 0;
    }
    if (gPlayerPathObject != NULL)
    {
        Obj_FreeObject((GameObject*)gPlayerPathObject);
        ObjLink_DetachChild(obj, (int)gPlayerPathObject);
        gPlayerPathObject = NULL;
    }
    if (gPlayerStaffObject != NULL)
    {
        gPlayerStaffObject = NULL;
    }
    for (i = 0, off = 0; i < inner->moveSlotCount; i++)
    {
        int e = *(int*)(inner->moveSlots + off + 0x64);
        if ((u32)e != 0)
            mm_free((void*)e);
        off += 0xb0;
    }
    ObjGroup_RemoveObject((int)obj, 0);
    ObjGroup_RemoveObject((int)obj, PLAYER_OBJGROUP);
    ObjModelChain_Free((ObjModelChain*)gPlayerModelChain);
}
#pragma opt_propagation off

void fn_802B4ED8(GameObject* obj, int p2, int mode)
{
    PlayerState* inner = obj->extra;
    f32 sx, sy, sz;
    u32 v;
    u32 m;

    if ((s8)p2 != -1)
    {
        if ((*(u32*)&((PlayerState*)inner)->flags360 & 0x4001) != 0)
        {
            return;
        }
    }
    v = (inner->flags3F3 >> 3) & 1;
    if (v != 0)
    {
        return;
    }
    if ((u32)obj->anim.alpha < 2)
    {
        return;
    }
    if (*(void**)((char*)inner + 0x7f0) != NULL)
    {
        if ((obj->objectFlags & OBJECT_OBJFLAG_PARENT_SLACK) != 0 ||
            arrayIndexOf((int*)&lbl_803DC6C4, 2, inner->baddie.controlMode) != -1)
        {
            int p = (int)inner->focusObject;
            (*(void (*)(int, f32))(*(int*)((char*)*(int*)*(int*)((char*)p + 0x68) + 0x50)))(
                p, obj->anim.modelInstance->rootMotionScaleBase);
        }
    }
    if ((*(u32*)&((PlayerState*)inner)->flags360 & 0x8000000) != 0)
    {
        sx = obj->anim.localPosX;
        sy = obj->anim.localPosY;
        sz = obj->anim.localPosZ;
        obj->anim.localPosX = obj->anim.modelState->overrideWorldPosX;
        obj->anim.localPosY = obj->anim.modelState->overrideWorldPosY;
        obj->anim.localPosZ = obj->anim.modelState->overrideWorldPosZ;
        obj->anim.modelState->overrideWorldPosX = sx;
        obj->anim.modelState->overrideWorldPosY = sy;
        obj->anim.modelState->overrideWorldPosZ = sz;
    }
    obj->anim.localPosY = obj->anim.localPosY + inner->sinkOffsetY;
    m = (u32)(mode & 0xff);
    if (m == 1)
    {
        objRenderFuzz((int*)obj);
    }
    else if (m == 2)
    {
        objRenderFn_800413d4((int*)obj);
    }
    else if (m == 4)
    {
        fuzzRenderFn_800412dc((int*)obj);
    }
    objSetMtxFn_800412d4(0);
    obj->anim.localPosY = obj->anim.localPosY - inner->sinkOffsetY;
    if ((*(u32*)&((PlayerState*)inner)->flags360 & 0x8000000) != 0)
    {
        obj->anim.modelState->overrideWorldPosX = obj->anim.localPosX;
        obj->anim.modelState->overrideWorldPosY = obj->anim.localPosY;
        obj->anim.modelState->overrideWorldPosZ = obj->anim.localPosZ;
        obj->anim.localPosX = sx;
        obj->anim.localPosY = sy;
        obj->anim.localPosZ = sz;
    }
}
void playerRender(int obj, int a, int b, int c, int d, s8 flag)
{
    int in2;
    int inner = *(int*)&((GameObject*)obj)->extra;
    f32 sx;
    f32 sy;
    f32 sz;
    f32 qz;
    f32 qy;
    f32 qx;
    f32 pz;
    f32 py;
    f32 px;
    int tbl[2];
    struct
    {
        u16 mode;
        u8 pad[6];
        f32 scale;
        f32 x;
        f32 y;
        f32 z;
    } pfx;
    f32 vel[3];

    if (flag == -1 || (*(u32*)&((PlayerState*)inner)->flags360 & 0x4001) == 0)
    {
        if (*(void**)((char*)inner + 0x7f0) != NULL &&
            ((((GameObject*)obj)->objectFlags & OBJECT_OBJFLAG_PARENT_SLACK) != 0 ||
             arrayIndexOf((int*)&lbl_803DC6C4, 2, ((PlayerState*)inner)->baddie.controlMode) != -1))
        {
            fn_802A9D0C(obj, inner, (int)((PlayerState*)inner)->focusObject, a, b, c, d, 1);
        }
        if (((PlayerState*)inner)->teleportAnimActive == 1)
        {
            playerDrawTeleportAnim((GameObject*)(obj));
        }
        (*(void (*)(int))(*(int*)(*gPlayerShadowInterface + 0x8)))(obj);
        if (*(void**)((char*)inner + 0x7f0) != NULL &&
            ((((GameObject*)obj)->objectFlags & OBJECT_OBJFLAG_PARENT_SLACK) != 0 ||
             arrayIndexOf((int*)&lbl_803DC6C4, 2, ((PlayerState*)inner)->baddie.controlMode) != -1))
        {
            {
                char* held = (char*)((PlayerState*)inner)->focusObject;
                ObjDef* mi = ((GameObject*)obj)->anim.modelInstance;
                (*(void (*)(char*, f32)) * (int*)(*(int*)(*(int*)(held + 0x68)) + 0x50))(held, mi->rootMotionScaleBase);
            }
        }
        if ((*(u32*)&((PlayerState*)inner)->flags360 & 0x8000000) != 0)
        {
            sx = ((GameObject*)obj)->anim.localPosX;
            sy = ((GameObject*)obj)->anim.localPosY;
            sz = ((GameObject*)obj)->anim.localPosZ;
            ((GameObject*)obj)->anim.localPosX = ((GameObject*)obj)->anim.modelState->overrideWorldPosX;
            ((GameObject*)obj)->anim.localPosY = ((GameObject*)obj)->anim.modelState->overrideWorldPosY;
            ((GameObject*)obj)->anim.localPosZ = ((GameObject*)obj)->anim.modelState->overrideWorldPosZ;
        }
        ((GameObject*)obj)->anim.localPosY = ((GameObject*)obj)->anim.localPosY + ((PlayerState*)inner)->sinkOffsetY;
        ((void (*)(int, int, int, int, int, f32))objRenderModelAndHitVolumes)(obj, a, b, c, d, lbl_803E7EE0);
        ((GameObject*)obj)->anim.localPosY = ((GameObject*)obj)->anim.localPosY - ((PlayerState*)inner)->sinkOffsetY;
        if ((*(u32*)&((PlayerState*)inner)->flags360 & 0x8000000) != 0)
        {
            ((GameObject*)obj)->anim.localPosX = sx;
            ((GameObject*)obj)->anim.localPosY = sy;
            ((GameObject*)obj)->anim.localPosZ = sz;
        }
        if (flag != 0)
        {
            fn_802AAF80((GameObject*)obj, inner, a, b, c);
        }
        ((void (*)(int, int, int, int))ObjPath_GetPointWorldPositionArray)(obj, 6, 2, inner + 0x3c4);
        ObjPath_GetPointWorldPosition((GameObject*)obj, 0xb, (f32*)((char*)inner + 0x768), (f32*)((char*)inner + 0x76c),
                                      (f32*)((char*)inner + 0x770), 0);
        if (((int (*)(int, int))playerHasKrazoaSpirit)(1, 0) != 0)
        {
            if ((void*)gPlayerHeldObject == NULL)
            {
                int i;
                ModelFileHeader* m = Obj_GetActiveModel((GameObject*)obj)->file;
                for (i = 0; i < m->renderOpCount; i++)
                {
                    ModelRenderOp* op = ObjModel_GetRenderOp(m, i);
                    if (op->mode == 2)
                    {
                        Shader_getLayer(op, 1);
                        gPlayerHeldObject = (int)op;
                        op->flags |= 0x100000LL;
                        break;
                    }
                }
            }
        }
        else if ((void*)gPlayerHeldObject != NULL)
        {
            *(u32*)((char*)gPlayerHeldObject + 0x3c) &= ~0x100000LL;
            {
                int zero = 0;
                gPlayerHeldObject = zero;
            }
        }
        {
            in2 = *(int*)&((GameObject*)obj)->extra;
            if (*(void**)((char*)in2 + 0x7f8) != NULL && *(int*)((char*)*(int*)((char*)in2 + 0x7f8) + 0xf8) == 1)
            {
                ObjPath_GetPointWorldPosition((GameObject*)obj, 8, &px, &py, &pz, 0);
                ObjPath_GetPointWorldPosition((GameObject*)obj, 9, &qx, &qy, &qz, 0);
                px = lbl_803E7E98 * (px + qx);
                py = lbl_803E7E98 * (py + qy);
                pz = lbl_803E7E98 * (pz + qz);
                if (*(s16*)((char*)*(int*)((char*)in2 + 0x7f8) + 0x46) == 0x112)
                {
                    py = py + lbl_803E7ED4;
                }
                *(f32*)((char*)*(int*)((char*)in2 + 0x7f8) + 0xc) = *(f32*)((char*)*(int*)((char*)in2 + 0x7f8) + 0x18) =
                    px;
                *(f32*)((char*)*(int*)((char*)in2 + 0x7f8) + 0x10) =
                    *(f32*)((char*)*(int*)((char*)in2 + 0x7f8) + 0x1c) = py;
                *(f32*)((char*)*(int*)((char*)in2 + 0x7f8) + 0x14) =
                    *(f32*)((char*)*(int*)((char*)in2 + 0x7f8) + 0x20) = pz;
                if (*(s16**)&((GameObject*)obj)->anim.parent != NULL)
                {
                    *(s16*)*(int*)((char*)in2 + 0x7f8) =
                        **(s16**)&((GameObject*)obj)->anim.parent + ((GameObject*)obj)->anim.rotX;
                }
                else
                {
                    *(s16*)*(int*)((char*)in2 + 0x7f8) = *(s16*)((char*)in2 + 0x478);
                }
                (*(void (*)(int, int, int, int, int, int)) *
                 (int*)(*(int*)(*(int*)((char*)*(int*)((char*)in2 + 0x7f8) + 0x68)) + 0x10))(
                    *(int*)((char*)in2 + 0x7f8), 0, 0, 0, 0, -1);
            }
        }
        if (((PlayerState*)inner)->knockbackTimer > lbl_803E7EA4 || (((PlayerState*)inner)->pendingFxFlags & 2) != 0)
        {
            {
                int t1;
                int t0;
                t0 = lbl_803E7E68;
                t1 = lbl_803E7E6C;
                tbl[0] = t0;
                tbl[1] = t1;
            }
            objParticleFn_80099d84((GameObject*)obj, lbl_803E7E9C,
                                   tbl[((((PlayerState*)inner)->knockKindBits >> 5) & 7) - 1] & 0xff,
                                   lbl_803E7EE0, NULL);
        }
        if ((((PlayerState*)inner)->pendingFxFlags & 1) != 0)
        {
            objParticleFn_80099d84((GameObject*)obj, lbl_803E7E9C, 8, lbl_803E7EE0, NULL);
        }
        if (((PlayerState*)inner)->waterDepth > lbl_803E7EA4)
        {
            if ((((PlayerState*)inner)->pendingFxFlags & 4) != 0)
            {
                *(u32*)&((PlayerState*)inner)->flags360 |= PLAYER_FLAG_WATER_SPLASH_PENDING;
                ((PlayerState*)inner)->pendingFxFlags = ((PlayerState*)inner)->pendingFxFlags & ~0x4;
            }
        }
        else
        {
            if (gPlayerSurfacePfxModeTable[((PlayerState*)inner)->surfaceType] == 6 ||
                gPlayerSurfacePfxModeTable[((PlayerState*)inner)->surfaceType] == 3)
            {
                if ((((PlayerState*)inner)->pendingFxFlags & 8) != 0)
                {
                    u8 n;
                    vel[0] = lbl_803E7F6C * ((GameObject*)obj)->anim.velocityX;
                    vel[1] = lbl_803E7F6C * ((GameObject*)obj)->anim.velocityY;
                    vel[2] = lbl_803E7F6C * ((GameObject*)obj)->anim.velocityZ;
                    pfx.x = *(f32*)&lbl_803E8018 * ((GameObject*)obj)->anim.velocityX + ((PlayerState*)inner)->fxOffsetX;
                    pfx.y = lbl_803E8018 * ((GameObject*)obj)->anim.velocityY + ((PlayerState*)inner)->fxOffsetY;
                    pfx.z = lbl_803E8018 * ((GameObject*)obj)->anim.velocityZ + ((PlayerState*)inner)->fxOffsetZ;
                    pfx.scale = lbl_803E7F18;
                    pfx.mode = gPlayerSurfacePfxModeTable[((PlayerState*)inner)->surfaceType];
                    for (n = 5; n != 0; n--)
                    {
                        (*gPartfxInterface)->spawnObject((void*)obj, 0x7e6, &pfx, 0x200001, -1, vel);
                    }
                    pfx.x = lbl_803E8018 * ((GameObject*)obj)->anim.velocityX + ((PlayerState*)inner)->fxOffset2X;
                    pfx.y = lbl_803E8018 * ((GameObject*)obj)->anim.velocityY + ((PlayerState*)inner)->fxOffset2Y;
                    pfx.z = lbl_803E8018 * ((GameObject*)obj)->anim.velocityZ + ((PlayerState*)inner)->fxOffset2Z;
                    pfx.scale = lbl_803E7F18;
                    pfx.mode = gPlayerSurfacePfxModeTable[((PlayerState*)inner)->surfaceType];
                    for (n = 5; n != 0; n--)
                    {
                        (*gPartfxInterface)->spawnObject((void*)obj, 0x7e6, &pfx, 0x200001, -1, vel);
                    }
                    ((PlayerState*)inner)->pendingFxFlags = ((PlayerState*)inner)->pendingFxFlags & ~0x8;
                }
                if ((((PlayerState*)inner)->pendingFxFlags & 4) != 0)
                {
                    u8 n2;
                    vel[0] = lbl_803E7F44 * ((GameObject*)obj)->anim.velocityX;
                    vel[1] = lbl_803E7F44 * ((GameObject*)obj)->anim.velocityY;
                    vel[2] = lbl_803E7F44 * ((GameObject*)obj)->anim.velocityZ;
                    pfx.x = ((GameObject*)obj)->anim.worldPosX;
                    pfx.y = lbl_803E7F10 + ((GameObject*)obj)->anim.worldPosY;
                    pfx.z = ((GameObject*)obj)->anim.worldPosZ;
                    pfx.scale = lbl_803E7EE0;
                    pfx.mode = gPlayerSurfacePfxModeTable[((PlayerState*)inner)->surfaceType];
                    for (n2 = 0; n2 < 10; n2++)
                    {
                        (*gPartfxInterface)->spawnObject((void*)obj, 0x7e6, &pfx, 0x200001, -1, vel);
                    }
                    ((PlayerState*)inner)->pendingFxFlags = ((PlayerState*)inner)->pendingFxFlags & ~0x4;
                }
            }
        }
    }
}
void playerDoHitDetection(int obj)
{
    int inner = *(int*)&((GameObject*)obj)->extra;
    f32 dt = timeDelta;
    f32 spd;
    int sub;
    int desc;
    HitDesc* hd;
    u32 fl;
    f32 x;
    f32 y;
    f32 z;

    *(u32*)&((PlayerState*)inner)->flags360 &= ~PLAYER_FLAG_WORLDPOS_OVERRIDE;
    if (((ByteFlags*)((char*)inner + 0x3f2))->b20 != 0 &&
        (((GameObject*)obj)->objectFlags & OBJECT_OBJFLAG_PARENT_SLACK) != 0)
    {
        u8 zero = 0;
        ((PlayerState*)inner)->baddie.physicsActive = zero;
    }
    (*gPathControlInterface)->update((void*)obj, (void*)(inner + 4), timeDelta);
    (*gPathControlInterface)->apply((void*)obj, (void*)(inner + 4));
    (*gPathControlInterface)->advance((void*)obj, (void*)(inner + 4), timeDelta);
    ObjModelChain_AdvancePhase((ObjModelChain*)gPlayerModelChain);
    if (!(((PlayerState*)inner)->cutsceneTimer >= lbl_803E7EF0))
    {
        (*(void (*)(int, int, void*))(*(int*)((char*)*gPlayerInterface + 0xc)))(obj, inner, gPlayerStateHandlers);
        if (*(s8*)&((PlayerState*)inner)->baddie.stateTag == 1)
        {
            if (gPlayerPathObject != 0 && ((ByteFlags*)((char*)inner + 0x3f4))->b40 != 0 &&
                (*(void**)((sub = *(int*)((char*)gPlayerPathObject + 0x54)) + 0x50) != NULL ||
                 (*(s8*)(sub + 0xad) != 0 && *(s8*)(sub + 0xac) != 0xe)))
            {
                {
                    u8 one = 1;
                    Player_GetObjHitsState((GameObject*)(obj))->suppressOutgoingHits = one;
                }
                ((PlayerState*)inner)->boulderChargeLevel = lbl_803E7EA4;
                *(u8*)&((PlayerState*)inner)->hitWindowIndex = *(u8*)&((PlayerState*)inner)->activeHitWindow;
                {
                    hd = (HitDesc*)((PlayerState*)inner)->moveSlots + (u32)((PlayerState*)inner)->moveSlotIndex;
                    if ((hd->flags & 1) != 0)
                    {
                        ((PlayerState*)inner)->cutsceneTimer = lbl_803E80A8;
                    }
                    hd = (HitDesc*)((PlayerState*)inner)->moveSlots + (u32)((PlayerState*)inner)->moveSlotIndex;
                    if ((hd->flags & 2) != 0)
                    {
                        ((PlayerState*)inner)->hitInterval = hd->valsA[((PlayerState*)inner)->activeHitWindow];
                        hd = (HitDesc*)((PlayerState*)inner)->moveSlots + (u32)((PlayerState*)inner)->moveSlotIndex;
                        hd = (HitDesc*)((u8*)hd + ((PlayerState*)inner)->activeHitWindow);
                        ((PlayerState*)inner)->hitCountMax = hd->valsB[0];
                        ((PlayerState*)inner)->hitTimer = (f32)(u32)((PlayerState*)inner)->hitInterval;
                        ((PlayerState*)inner)->hitCount += 1;
                        ((PlayerState*)inner)->lastHitObject = *(int*)(sub + 0x50);
                    }
                }
                {
                    hd = *(HitDesc**)(sub + 0x50);
                    if (hd != NULL)
                    {
                        if ((((GameObject*)hd)->anim.modelInstance->effectFlags & 4) != 0)
                        {
                            doRumble(lbl_803E7ED8);
                        }
                        if ((((GameObject*)hd)->anim.modelInstance->effectFlags & 8) != 0)
                        {
                            lbl_803DE459 = 1;
                        }
                    }
                    else if (*(s8*)(sub + 0xad) != 0)
                    {
                        doRumble(lbl_803E7ED8);
                        lbl_803DE459 = 1;
                    }
                }
                {
                    u8 c = ((PlayerState*)inner)->moveSlotIndex;
                    if (c == 0xf)
                    {
                        ((PlayerState*)inner)->attackVariantMode = 1;
                    }
                    else if (c == 0x1b)
                    {
                        ((PlayerState*)inner)->attackVariantMode = 2;
                    }
                    else if (c == 0x11)
                    {
                        ((PlayerState*)inner)->attackVariantMode = 0;
                    }
                    else
                    {
                        ((PlayerState*)inner)->attackVariantMode = 1;
                    }
                }
            }
            if (Player_GetObjHitsState((GameObject*)(obj))->lastHitObject != 0)
            {
                Player_GetObjHitsState((GameObject*)(obj))->suppressOutgoingHits = 1;
                ((PlayerState*)inner)->boulderChargeLevel = lbl_803E7EA4;
                *(u8*)&((PlayerState*)inner)->hitWindowIndex = *(u8*)&((PlayerState*)inner)->activeHitWindow;
                {
                    hd = (HitDesc*)((PlayerState*)inner)->moveSlots + (u32)((PlayerState*)inner)->moveSlotIndex;
                    if ((hd->flags & 1) != 0)
                    {
                        ((PlayerState*)inner)->cutsceneTimer = lbl_803E80A8;
                    }
                    hd = (HitDesc*)((PlayerState*)inner)->moveSlots + (u32)((PlayerState*)inner)->moveSlotIndex;
                    if ((hd->flags & 2) != 0)
                    {
                        ((PlayerState*)inner)->hitInterval = hd->valsA[((PlayerState*)inner)->activeHitWindow];
                        hd = (HitDesc*)((PlayerState*)inner)->moveSlots + (u32)((PlayerState*)inner)->moveSlotIndex;
                        hd = (HitDesc*)((u8*)hd + ((PlayerState*)inner)->activeHitWindow);
                        ((PlayerState*)inner)->hitCountMax = hd->valsB[0];
                        ((PlayerState*)inner)->hitTimer = (f32)(u32)((PlayerState*)inner)->hitInterval;
                        ((PlayerState*)inner)->hitCount += 1;
                        ((PlayerState*)inner)->lastHitObject =
                            Player_GetObjHitsState((GameObject*)(obj))->lastHitObject;
                    }
                }
            }
        }
        if ((*(u32*)&((PlayerState*)inner)->flags360 & 2) != 0)
        {
            void* h = *(void**)((char*)inner + 0xdc);
            if (h != NULL &&
                ((fl = ((ObjAnimComponent*)h)->modelInstance->flags) & OBJMODEL_FLAG_SKIP_RESET_UPDATE) != 0 &&
                (fl & 0x8000) == 0)
            {
                objHitDetectFn_80062e84((GameObject*)obj, (GameObject*)h, 1);
            }
            else if (((GameObject*)obj)->anim.parent != NULL && h == NULL)
            {
                objHitDetectFn_80062e84((GameObject*)obj, NULL, 1);
            }
        }
        *(u32*)&((PlayerState*)inner)->flags360 |= PLAYER_FLAG_HITDETECT;
        if (((PlayerState*)inner)->focusObject != NULL &&
            ((((GameObject*)obj)->objectFlags & OBJECT_OBJFLAG_PARENT_SLACK) != 0 ||
             arrayIndexOf((int*)&lbl_803DC6C4, 2, ((PlayerState*)inner)->baddie.controlMode) != -1))
        {
            (*(void (*)(int, f32*, f32*, f32*))(*(int*)(*(int*)(*(int*)((int)((PlayerState*)inner)->focusObject + 0x68)) +
                                                        0x34)))((int)((PlayerState*)inner)->focusObject, &x, &y, &z);
            (*gCameraInterface)->overridePos(x, y, z);
            fn_802A9D0C(obj, inner, (int)((PlayerState*)inner)->focusObject, 0, 0, 0, 0, 0);
        }
        if (*(s8*)&((PlayerState*)inner)->baddie.physicsActive == 1 && (*(int*)((char*)inner + 4) & 0x100000) == 0)
        {
            if ((*(u32*)&((PlayerState*)inner)->flags360 & 0x2000) == 0 && (*(s8*)((char*)inner + 0x264) & 0x33) != 0)
            {
                ((GameObject*)obj)->anim.velocityY =
                    (((GameObject*)obj)->anim.worldPosY - ((GameObject*)obj)->anim.previousWorldPosY) / dt;
                if (((GameObject*)obj)->anim.velocityY < *(f32*)&lbl_803E811C)
                {
                    ((GameObject*)obj)->anim.velocityY = lbl_803E811C;
                }
                if (((GameObject*)obj)->anim.velocityY > *(f32*)&lbl_803E7EA4)
                {
                    ((GameObject*)obj)->anim.velocityY = lbl_803E7EA4;
                }
            }
            if ((*(int*)inner & 0x800000) != 0 && lbl_803E7EA4 == ((PlayerState*)inner)->pushVelX &&
                lbl_803E7EA4 == ((PlayerState*)inner)->pushVelZ)
            {
                spd = sqrtf(((GameObject*)obj)->anim.velocityX * ((GameObject*)obj)->anim.velocityX +
                            ((GameObject*)obj)->anim.velocityZ * ((GameObject*)obj)->anim.velocityZ);
                if (((GameObject*)obj)->anim.parent != NULL)
                {
                    ((GameObject*)obj)->anim.velocityX =
                        (((GameObject*)obj)->anim.localPosX - ((GameObject*)obj)->anim.previousLocalPosX) / dt;
                    ((GameObject*)obj)->anim.velocityZ =
                        (((GameObject*)obj)->anim.localPosZ - ((GameObject*)obj)->anim.previousLocalPosZ) / dt;
                }
                else
                {
                    ((GameObject*)obj)->anim.velocityX =
                        (((GameObject*)obj)->anim.worldPosX - ((GameObject*)obj)->anim.previousWorldPosX) / dt;
                    ((GameObject*)obj)->anim.velocityZ =
                        (((GameObject*)obj)->anim.worldPosZ - ((GameObject*)obj)->anim.previousWorldPosZ) / dt;
                }
                if (((*(s8*)((char*)inner + 0x264) & 2) != 0 && (*(s8*)((char*)inner + 0x264) & 0x20) == 0) ||
                    *(u8*)((char*)inner + 0x262) != 0 || (Player_GetObjHitsState((GameObject*)(obj))->flags & 8) != 0)
                {
                    if (((PlayerState*)inner)->rumbleCooldown <= lbl_803E7EA4 &&
                        ((PlayerState*)inner)->baddie.animSpeedA > lbl_803E8160)
                    {
                        doRumble(lbl_803E7F10);
                        ((PlayerState*)inner)->rumbleCooldown = lbl_803E7F30;
                        Sfx_PlayFromObject(obj, SFXTRIG_foot_run_jingle4);
                    }
                    dt = mathSinf((gPlayerPi * (f32)((PlayerState*)inner)->yaw) / lbl_803E7F98);
                    {
                        f32 s = mathCosf((gPlayerPi * (f32)((PlayerState*)inner)->yaw) / lbl_803E7F98);
                        ((PlayerState*)inner)->baddie.animSpeedA =
                            -((GameObject*)obj)->anim.velocityZ * s - ((GameObject*)obj)->anim.velocityX * dt;
                    }
                    ((PlayerState*)inner)->baddie.animSpeedA = ((PlayerState*)inner)->baddie.animSpeedA * lbl_803E7FC4;
                    {
                        f32 c = ((PlayerState*)inner)->baddie.animSpeedA;
                        f32 lo = lbl_803E8110 * ((PlayerState*)inner)->baddie.inputMagnitude;
                        ((PlayerState*)inner)->baddie.animSpeedA =
                            (c < lo) ? lo
                                     : ((c > ((PlayerState*)inner)->maxSpeed) ? ((PlayerState*)inner)->maxSpeed : c);
                    }
                    {
                        f32 c = ((PlayerState*)inner)->baddie.animSpeedA;
                        ((PlayerState*)inner)->baddie.animSpeedA =
                            (c < lbl_803E7EA4) ? lbl_803E7EA4 : ((c > spd) ? spd : c);
                    }
                    if (((ByteFlags*)((char*)inner + 0x3f0))->b40 == 0)
                    {
                        ((PlayerState*)inner)->baddie.animSpeedC = ((PlayerState*)inner)->baddie.animSpeedA;
                    }
                }
                *(u32*)inner &= ~0x800000;
            }
        }
        if ((((GameObject*)obj)->objectFlags & OBJECT_OBJFLAG_PARENT_SLACK) == 0)
        {
            *(s16*)obj = ((PlayerState*)inner)->targetYaw;
        }
        {
            void* g = (void*)getSbGalleon();
            if (g != NULL && DBprotection_getCameraState() == 2)
            {
                ((GameObject*)obj)->anim.modelState->overrideWorldPosX =
                    ((GameObject*)obj)->anim.localPosX - *(f32*)((char*)g + 0xc);
                ((GameObject*)obj)->anim.modelState->overrideWorldPosY =
                    ((GameObject*)obj)->anim.localPosY - *(f32*)((char*)g + 0x10);
                ((GameObject*)obj)->anim.modelState->overrideWorldPosZ =
                    ((GameObject*)obj)->anim.localPosZ - *(f32*)((char*)g + 0x14);
                vecRotateZXY((void*)g, &((GameObject*)obj)->anim.modelState->overrideWorldPosX);
                ((GameObject*)obj)->anim.modelState->overrideWorldPosX =
                    ((GameObject*)obj)->anim.modelState->overrideWorldPosX + *(f32*)((char*)g + 0xc);
                ((GameObject*)obj)->anim.modelState->overrideWorldPosY =
                    ((GameObject*)obj)->anim.modelState->overrideWorldPosY + *(f32*)((char*)g + 0x10);
                ((GameObject*)obj)->anim.modelState->overrideWorldPosZ =
                    ((GameObject*)obj)->anim.modelState->overrideWorldPosZ + *(f32*)((char*)g + 0x14);
                ((GameObject*)obj)->anim.modelState->flags |= 0x2020;
                ((GameObject*)obj)->anim.rotZ = *(s16*)((char*)g + 4);
                *(u32*)&((PlayerState*)inner)->flags360 |= PLAYER_FLAG_WORLDPOS_OVERRIDE;
            }
        }
        *(u32*)&((PlayerState*)inner)->flags360 &= ~0x400000LL;
    }
}
#pragma opt_propagation reset

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
#pragma opt_common_subs off
#pragma opt_propagation off
#pragma inline_max_size(7)

void playerUpdate(GameObject* obj)
{
    int inner = *(int*)&obj->extra;
    int cam = (int)Camera_GetCurrentViewSlot();
    if (((PlayerState*)inner)->cutsceneTimer >= 6.0f)
    {
        if (((PlayerState*)inner)->cutsceneTimer > 0.0f)
        {
            ((PlayerState*)inner)->cutsceneTimer -= 1.0f;
            if (((PlayerState*)inner)->cutsceneTimer <= 0.0f)
            {
                cutsceneEnterExit(0, 0);
                ((PlayerState*)inner)->cutsceneEnded = 1;
            }
            else if (((PlayerState*)inner)->cutsceneTimer == 6.0f)
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
            UiMsgBlock m;
            ((PlayerState*)inner)->curAnimId = (*gCameraInterface)->getMode();
            if (((PlayerState*)inner)->curAnimId == 0x44 && ((PlayerState*)inner)->baddie.controlMode != 1)
            {
                (*(void (*)(int, int, int))(*(int*)((char*)*gPlayerInterface + 0x14)))((int)obj, inner, 1);
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
            playerItemGetAnimFn((int)obj, inner, inner);
            fn_802B4A9C((int)obj, inner, inner);
            playerStaffInit(obj, inner);
            if ((u32)gPlayerEggObject == 0 && Obj_IsLoadingLocked() != 0)
            {
                gPlayerEggObject = (int)Obj_SetupObject(Obj_AllocObjectSetup(0x18, 0x66a), 4, -1, -1,
                                                        obj->anim.parent);
                ObjLink_AttachChild((int)obj, gPlayerEggObject, 3);
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
            for (i = 0; i < ((PlayerState*)inner)->queuedBitCount; i++)
            {
                u32 acc = playerLoadPendingHitBits((char*)inner + 0x310);
                int idx = i + 0x8b9;
                *(u32*)((char*)inner + 0x310) = acc | (1 << *(u8*)((char*)inner + idx));
            }
            *(u32*)&((PlayerState*)inner)->flags360 &= 0xfffff4ff;
            dt = timeDelta;
            playerDoControls(obj, inner, dt);
            playerAnimate((int)obj, inner, dt);
            ((void (*)(int, int, f32))staffAnimate)((int)obj, inner, dt);
            fn_802B1E5C(obj, inner, inner, dt);
            fn_802B1BF8TimeLegacy((int)obj, inner, inner, dt);
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
            fn_802AFB0C((int)obj, inner, inner);
            if (*(void**)((char*)inner + 0x7f8) != NULL &&
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
                if (Sfx_IsPlayingFromObjectIntU16Legacy(
                        (int)obj, (u16)(((PlayerState*)inner)->characterId == 0 ? SFXTRIG_jump2 : SFXTRIG_sa_climb02)) == 0)
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
                    if (*(void**)((char*)inner + 0x7f8) != NULL || hov == 0 ||
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
            (*(void (*)(int))(*(int*)((char*)*gCameraInterface + 0x68)))(((PlayerState*)inner)->cameraFlags);
            ((PlayerState*)inner)->isHoldingObject = 0;
            ((PlayerState*)inner)->queuedBitCount = 0;
            *(s16*)obj = ((PlayerState*)inner)->targetYaw;
            objAudioFn_8006edcc(obj, *(int*)&((PlayerState*)inner)->baddie.eventFlags,
                                ((PlayerState*)inner)->animSoundId, (void*)(inner + 0x3c4), (void*)(inner + 4),
                                ((PlayerState*)inner)->baddie.animSpeedA, lbl_803E7EE0);
        }
    }
}
#pragma inline_max_size reset
#pragma opt_common_subs reset
#pragma opt_propagation reset

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
    (*(void (*)(int, int, int, int))(*(int*)((char*)*gPlayerInterface + 0x4)))(obj, inner, 0x42, 1);
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

void playerInitFuncPtrsEntry(int obj)
{
    playerInitFuncPtrs(obj);
}

void playerInitFuncPtrs(int obj)
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
                (*(void (*)(int, int, int))(*(int*)((char*)*gPlayerInterface + 0x14)))(obj, state, 4);
            }
        }
        else if (*(s8*)&((PlayerState*)state)->baddie.moveJustStartedB != 0 ||
                 *(s8*)&((PlayerState*)state)->baddie.moveDone != 0)
        {
            (*(void (*)(int, int, int))(*(int*)((char*)*gPlayerInterface + 0x14)))(obj, state, 0);
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
                (*(void (*)(int, int, int))(*(int*)((char*)*gPlayerInterface + 0x14)))(obj, state, 3);
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
                    (*(void (*)(int, int, int))(*(int*)((char*)*gPlayerInterface + 0x14)))(obj, state, 1);
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
            (*(void (*)(int, int, int))(*(int*)((char*)*gPlayerInterface + 0x14)))(obj, state, 0);
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
            r = (*(u8 (*)(int, int, f32))(*(int*)(*gBaddieControlInterface + 0x18)))((int)obj, state, lbl_803E8190);
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
    (*(void (*)(int, int, f32, int))(*(int*)((char*)*gPlayerInterface + 0x20)))((int)obj, state, fv, 1);
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
    (*(void (*)(int, int, f32, int))(*(int*)((char*)*gPlayerInterface + 0x20)))(obj, state, fv, 1);
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
    (*(void (*)(int, int, f32, int))(*(int*)((char*)*gPlayerInterface + 0x20)))((int)obj, state, fv, 1);
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

typedef void (*LightfootPlayerUpdateFn)(GameObject* obj, int state, f32 timeDelta, int flags);

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
    if (obj->unkF8 == 0)
    {
        challenge->previousPhase2 = challenge->previousPhase;
        challenge->previousPhase = challenge->phase;
        challenge->phase += (u16)(lbl_803E81AC * timeDelta);
    }
    if (challenge->animationIndex < 4)
    {
        int meterPosition =
            (s16)(lbl_803E81B0 * mathSinf(gPlayerPi2 * (f32)challenge->phase / lbl_803E81B8));
        int successRange = (int)(lbl_803E81B0 * controls->scales[challenge->difficulty]);
        if (obj->unkF8 == 0)
        {
            if ((s16)challenge->phase * (s16)challenge->previousPhase < 0)
            {
                Sfx_PlayFromObject(0, SFXTRIG_lockon3_off);
            }
        }
        setAButtonIcon(6);
        fearTestMeterSetRange(0x60, (u8)successRange, meterPosition);
        if ((getButtonsJustPressed(0) & 0x100) && obj->unkF8 == 0)
        {
            int distanceFromCenter = meterPosition < 0 ? -meterPosition : meterPosition;
            if (distanceFromCenter <= successRange)
            {
                Sfx_PlayFromObject(0, SFXTRIG_menuups16k);
                obj->unkF8 = 2;
            }
            else
            {
                Sfx_PlayFromObject(0, SFXTRIG_lowoxy_beep);
                obj->unkF8 = 3;
            }
            fn_8011F6D4(0);
        }
    }
    else
    {
        fn_8011F6D4(0);
    }
    if (*(s8*)&playerState->moveDone != 0 || *(s8*)&playerState->moveJustStartedA != 0)
    {
        if (*(s8*)&playerState->moveJustStartedA != 0)
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
            fn_8011F6D4(1);
            setAButtonIcon(6);
        }
        placement = (LightfootChallengePlacement*)obj->anim.placementData;
        if (*(s8*)&playerState->moveJustStartedA != 0)
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
    ((LightfootPlayerUpdateFn)(*gPlayerInterface)->updateAnimRootMotion)(obj, state, fv, 1);
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
    (*(void (*)(int, int, f32, int))(*(int*)((char*)*gPlayerInterface + 0x20)))((int)obj, state, fv, 0);
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
        ObjHits_RecordObjectHit(Obj_GetPlayerObject(), obj, 0x19, 2, 1);
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
        ObjLink_DetachChild(obj, (int)child);
        Obj_FreeObject(child);
    }
    if (Obj_IsLoadingLocked())
    {
        if (*(s16*)((char*)animState + 0x28) > 0)
        {
            setup = Obj_AllocObjectSetup(0x20, *(s16*)((char*)animState + 0x28));
            child = Obj_SetupObject(setup, 4, obj->anim.mapEventSlot, -1, obj->anim.parent);
            ObjLink_AttachChild((int)obj, (int)child, 0);
            *(s16*)((char*)animState + 0x26) = *(s16*)((char*)animState + 0x28);
        }
    }
    else
    {
        *(s16*)((char*)animState + 0x26) = 0;
    }
}

/*
 * Mask passed to hitDetectFn_80065e50 / hitDetectFn_800691c0 to pick what a
 * collision query tests. Low byte = behaviour flags (decoded from
 * hitDetectFn_800691c0); the high bits select the map-surface type (consumed by
 * mapLoadBlocksFn_800685cc; per-type meanings not yet decoded). Only the climb
 * mask is meaning-confirmed so far (live-verified ladder probe); the others are
 * left as raw literals at their call sites until traced.
 */
#pragma dont_inline on
void Lightfoot_UpdatePlayerInteraction(int obj, int inner, int state)
{
    int p = *(int*)((char*)inner + 0x40c);
    int sub = *(int*)&((GameObject*)obj)->anim.placementData;
    int mode;
    int v;

    (*(void (*)(int, int, int, void*, void*, void*))(*(int*)(*gBaddieControlInterface + 0x14)))(
        obj, (int)Obj_GetPlayerObject(), 0x10, (char*)p + 0x1e, (char*)p + 0x20, (char*)p + 0x22);
    ((PlayerState*)state)->baddie.targetDistance = (f32)(u32) * (u16*)((int)p + 0x22);
    mode = ((GameObject*)obj)->unkF8;
    if (mode == 2)
    {
        (*gObjectTriggerInterface)->runSequence(0, (void*)obj, -1);
        ((GameObject*)obj)->unkF8 = 1;
    }
    else if (mode == 3)
    {
        (*gObjectTriggerInterface)->runSequence(1, (void*)obj, -1);
        ((GameObject*)obj)->unkF8 = 1;
    }
    else
    {
        characterDoEyeAnimsState((GameObject*)obj, inner + 0x3ac);
        ((PlayerState*)state)->baddie.targetObj = Obj_GetPlayerObject();
        v = *(int*)&((PlayerState*)sub)->baddie.posX;
        if (v >= 0x49942 || v < 0x4993f)
        {
            (*(void (*)(int, int, f32, int))(*(int*)(*gBaddieControlInterface + 0x2c)))(obj, state, lbl_803E820C, 1);
        }
        ((PlayerState*)inner)->pendingParentObj = *(int*)&((GameObject*)obj)->pendingParentObj;
        *(int*)&((GameObject*)obj)->pendingParentObj = 0;
        (*(void (*)(int, int, f32, f32, void*, void*))(*(int*)((char*)*gPlayerInterface + 0x8)))(
            obj, state, timeDelta, timeDelta, lbl_803DB0DC, lbl_803DB0D0);
        *(int*)&((GameObject*)obj)->pendingParentObj = ((PlayerState*)inner)->pendingParentObj;
        Lightfoot_ProcessHitResponseFlags(obj, inner);
    }
}
#pragma dont_inline reset
#pragma opt_loop_invariants off
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
                ((void (*)(int, f32, int, int, int, void*))fn_80098B18)(
                    (int)obj, scale * obj->anim.rootMotionScale, 3, 0, 0, arr);
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
            Sfx_KeepAliveLoopedObjectSoundIntLegacy((int)obj, SFXTRIG_foot_metal_scuff_455);
            ((void (*)(int, f32, int, int, int, void*))fn_80098B18)(
                (int)obj, lbl_803E81C8 * obj->anim.rootMotionScale, 3, mode, 0, snd);
        }
    }
    *(u16*)((char*)inner + 0x400) = *(u16*)((char*)inner + 0x400) | 2;
    return 0;
}

PlayerModelChainEntry lbl_803DC660 = {lbl_80332EC0, 5};
PlayerModelChainEntry* gPlayerModelChainConfig = &lbl_803DC660;

s16 gPlayerMoveSlotData[2464] = {
    0,      0,      0,      210,    0,      20,     0,      20,     0,      20,     266,    2570,   2570,   0,
    15564,  -13107, 0,      0,      16128,  0,      16128,  0,      16230,  26214,  16035,  -10486, -16512, 0,
    -16512, 0,      16087,  2621,   -16512, 0,      -16512, 0,      0,      0,      16256,  0,      15948,  -13107,
    16051,  13107,  0,      0,      0,      0,      0,      0,      0,      0,      0,      0,      0,      0,
    16256,  0,      0,      0,      0,      0,      16230,  26214,  0,      0,      0,      0,      0,      0,
    0,      0,      2560,   0,      15820,  -13107, 15820,  -13107, 0,      0,      -16512, 0,      0,      0,
    0,      0,      0,      0,      256,    16,     0,      210,    0,      4,      0,      4,      0,      4,
    274,    4626,   4626,   0,      15564,  -13107, 0,      0,      16128,  0,      16128,  0,      16230,  26214,
    16035,  -10486, -16512, 0,      -16512, 0,      16087,  2621,   -16512, 0,      -16512, 0,      0,      0,
    16256,  0,      15948,  -13107, 16051,  13107,  0,      0,      1,      257,    0,      0,      0,      0,
    0,      0,      0,      0,      16204,  -13107, 0,      0,      0,      0,      16230,  26214,  0,      0,
    0,      0,      0,      0,      0,      0,      0,      0,      15820,  -13107, 15820,  -13107, 0,      0,
    -16512, 0,      0,      0,      0,      0,      0,      0,      512,    27,     0,      210,    0,      0,
    0,      0,      0,      0,      277,    5397,   5397,   0,      15564,  -13107, 0,      0,      16153,  -26214,
    16153,  -26214, 16230,  26214,  16087,  2621,   -16512, 0,      -16512, 0,      16133,  7864,   -16512, 0,
    -16512, 0,      0,      0,      16256,  0,      15948,  -13107, 16051,  13107,  0,      0,      1,      0,
    0,      0,      0,      0,      0,      0,      0,      0,      16256,  0,      0,      0,      0,      0,
    16230,  26214,  0,      0,      0,      0,      0,      0,      0,      0,      0,      0,      15820,  -13107,
    0,      0,      0,      0,      -16512, 0,      0,      0,      0,      0,      0,      0,      768,    33,
    0,      210,    0,      16,     0,      4,      0,      4,      270,    3598,   3598,   0,      15564,  -13107,
    0,      0,      16153,  -26214, 16153,  -26214, 16204,  -13107, 16051,  13107,  -16512, 0,      -16512, 0,
    16102,  26214,  -16512, 0,      -16512, 0,      0,      0,      16256,  0,      15948,  -13107, 16051,  13107,
    0,      0,      0,      0,      0,      0,      0,      0,      0,      0,      0,      0,      0,      0,
    0,      0,      0,      0,      16230,  26214,  0,      0,      0,      0,      0,      0,      0,      0,
    0,      0,      15820,  -13107, 0,      0,      0,      0,      -16512, 0,      0,      0,      0,      0,
    0,      0,      1024,   31,     0,      210,    0,      8,      0,      4,      0,      4,      270,    3598,
    3598,   0,      15564,  -13107, 0,      0,      16153,  -26214, 16153,  -26214, 16204,  -13107, 16051,  13107,
    -16512, 0,      -16512, 0,      16102,  26214,  -16512, 0,      -16512, 0,      0,      0,      16256,  0,
    15948,  -13107, 16051,  13107,  0,      0,      1,      0,      0,      0,      0,      0,      0,      0,
    0,      0,      0,      0,      0,      0,      0,      0,      16230,  26214,  0,      0,      0,      0,
    0,      0,      0,      0,      0,      0,      15820,  -13107, 0,      0,      0,      0,      -16512, 0,
    0,      0,      0,      0,      0,      0,      1280,   17,     0,      210,    0,      4,      0,      4,
    0,      4,      511,    -1,     -1,     0,      15564,  -13107, 0,      0,      16128,  0,      16128,  0,
    16128,  0,      -16512, 0,      -16512, 0,      -16512, 0,      -16512, 0,      -16512, 0,      -16512, 0,
    0,      0,      0,      0,      15948,  -13107, 16051,  13107,  0,      0,      0,      0,      0,      0,
    0,      0,      0,      0,      0,      0,      0,      0,      0,      0,      0,      0,      0,      0,
    0,      0,      0,      0,      0,      0,      0,      0,      0,      0,      0,      0,      0,      0,
    0,      0,      -16512, 0,      0,      0,      0,      0,      0,      0,      1536,   19,     0,      210,
    0,      4,      0,      4,      0,      4,      272,    3344,   3344,   0,      15605,  -15729, 0,      0,
    16256,  0,      16128,  0,      16128,  0,      -16512, 0,      -16512, 0,      -16512, 0,      -16512, 0,
    -16512, 0,      -16512, 0,      0,      0,      0,      0,      15948,  -13107, 16051,  13107,  0,      0,
    0,      0,      0,      0,      0,      0,      0,      0,      0,      0,      0,      0,      0,      0,
    0,      0,      0,      0,      0,      0,      0,      0,      0,      0,      0,      0,      0,      0,
    0,      0,      0,      0,      0,      0,      -16512, 0,      0,      0,      0,      0,      0,      0,
    1792,   20,     0,      210,    0,      4,      0,      4,      0,      4,      511,    -1,     -1,     0,
    15564,  -13107, 0,      0,      16256,  0,      16128,  0,      16128,  0,      -16512, 0,      -16512, 0,
    -16512, 0,      -16512, 0,      -16512, 0,      -16512, 0,      0,      0,      0,      0,      15948,  -13107,
    16051,  13107,  0,      0,      0,      0,      0,      0,      0,      0,      0,      0,      0,      0,
    0,      0,      0,      0,      0,      0,      0,      0,      0,      0,      0,      0,      0,      0,
    0,      0,      0,      0,      0,      0,      0,      0,      0,      0,      -16512, 0,      0,      0,
    0,      0,      0,      0,      2048,   17,     0,      210,    0,      4,      0,      4,      0,      4,
    269,    3341,   3341,   0,      15564,  -13107, 0,      0,      16192,  0,      16192,  0,      16204,  -13107,
    -16512, 0,      -16512, 0,      -16512, 0,      -16512, 0,      -16512, 0,      -16512, 0,      0,      0,
    0,      0,      15948,  -13107, 16051,  13107,  0,      0,      0,      0,      0,      0,      0,      0,
    0,      0,      0,      0,      0,      0,      0,      0,      0,      0,      0,      0,      0,      0,
    0,      0,      0,      0,      0,      0,      3328,   0,      15820,  -13107, 0,      0,      0,      0,
    -16512, 0,      0,      0,      0,      0,      0,      0,      2304,   18,     0,      210,    0,      4,
    0,      4,      0,      4,      269,    3341,   3341,   0,      15564,  -13107, 0,      0,      16192,  0,
    16192,  0,      16204,  -13107, -16512, 0,      -16512, 0,      -16512, 0,      -16512, 0,      -16512, 0,
    -16512, 0,      0,      0,      0,      0,      15948,  -13107, 16051,  13107,  0,      0,      0,      0,
    0,      0,      0,      0,      0,      0,      0,      0,      0,      0,      0,      0,      0,      0,
    0,      0,      0,      0,      0,      0,      0,      0,      0,      0,      3328,   0,      15820,  -13107,
    0,      0,      0,      0,      -16512, 0,      0,      0,      0,      0,      0,      0,      2560,   22,
    0,      210,    0,      12,     0,      0,      0,      0,      268,    3086,   3091,   0,      15564,  -13107,
    0,      0,      16128,  0,      16128,  0,      16230,  26214,  16035,  -10486, -16512, 0,      -16512, 0,
    16087,  2621,   -16512, 0,      -16512, 0,      0,      0,      16256,  0,      15948,  -13107, 16051,  13107,
    0,      0,      1,      257,    0,      0,      0,      0,      0,      0,      0,      0,      16256,  0,
    0,      0,      0,      0,      16230,  26214,  0,      0,      0,      0,      0,      0,      16268,  -13107,
    2816,   0,      15820,  -13107, 0,      0,      0,      0,      -16512, 0,      0,      0,      0,      0,
    0,      0,      2816,   21,     0,      210,    0,      20,     0,      0,      0,      0,      266,    2570,
    2570,   0,      15564,  -13107, 0,      0,      16128,  0,      16128,  0,      16230,  26214,  16035,  -10486,
    -16512, 0,      -16512, 0,      16087,  2621,   -16512, 0,      -16512, 0,      0,      0,      16256,  0,
    15948,  -13107, 16051,  13107,  0,      0,      0,      0,      0,      0,      0,      0,      0,      0,
    0,      0,      16256,  0,      0,      0,      0,      0,      16230,  26214,  0,      0,      0,      0,
    0,      0,      0,      0,      2560,   0,      15820,  -13107, 0,      0,      0,      0,      -16512, 0,
    0,      0,      0,      0,      0,      0,      3072,   11,     0,      210,    0,      12,     0,      12,
    0,      0,      271,    3855,   3855,   0,      15477,  -15729, 0,      0,      16128,  0,      16128,  0,
    16230,  26214,  15948,  -13107, 16056,  20972,  -16512, 0,      16025,  -26214, 16097,  18350,  -16512, 0,
    0,      0,      16102,  26214,  15948,  -13107, 16051,  13107,  0,      0,      2,      768,    0,      0,
    0,      0,      0,      0,      0,      0,      16256,  0,      16448,  0,      0,      0,      16230,  26214,
    16230,  26214,  0,      0,      256,    0,      0,      0,      0,      0,      15820,  -13107, 15948,  -13107,
    0,      0,      -16512, 0,      0,      0,      0,      0,      0,      0,      3328,   7,      0,      210,
    0,      0,      0,      0,      0,      0,      511,    -1,     -1,     0,      15651,  -10486, 0,      0,
    16256,  0,      16128,  0,      16230,  26214,  16035,  -10486, -16512, 0,      -16512, 0,      16133,  7864,
    -16512, 0,      -16512, 0,      0,      0,      16222,  -18350, 15948,  -13107, 16051,  13107,  0,      0,
    2,      0,      0,      0,      0,      0,      0,      0,      0,      0,      0,      0,      0,      0,
    0,      0,      0,      0,      0,      0,      0,      0,      0,      0,      0,      0,      0,      0,
    16025,  -26214, 0,      0,      0,      0,      -16512, 0,      0,      0,      0,      0,      0,      0,
    3584,   9,      0,      210,    0,      20,     0,      12,     0,      0,      283,    6939,   6939,   0,
    15523,  -10486, 0,      0,      16256,  0,      16204,  -13107, 16204,  -13107, 15948,  -13107, 16161,  18350,
    -16512, 0,      16010,  15729,  16179,  13107,  -16512, 0,      0,      0,      16256,  0,      15948,  -13107,
    16051,  13107,  0,      0,      1,      257,    0,      0,      0,      0,      0,      0,      0,      0,
    16416,  0,      16384,  0,      0,      0,      16230,  26214,  16230,  26214,  0,      0,      0,      0,
    0,      0,      0,      0,      15948,  -13107, 15948,  -13107, 0,      0,      -16512, 0,      0,      0,
    0,      0,      0,      0,      3840,   15,     0,      210,    0,      20,     0,      0,      0,      0,
    511,    -1,     -1,     0,      15477,  -15729, 0,      0,      16256,  0,      16128,  0,      16128,  0,
    16076,  -13107, -16512, 0,      -16512, 0,      16128,  0,      -16512, 0,      -16512, 0,      0,      0,
    16166,  26214,  15948,  -13107, 16051,  13107,  0,      0,      3,      0,      0,      0,      0,      0,
    0,      0,      0,      0,      16672,  0,      0,      0,      0,      0,      16215,  2621,   0,      0,
    0,      0,      256,    0,      0,      0,      0,      0,      16025,  -26214, 0,      0,      0,      0,
    -16512, 0,      0,      0,      0,      0,      0,      0,      4096,   28,     0,      210,    0,      4,
    0,      4,      0,      0,      279,    5911,   5911,   0,      15499,  17302,  0,      0,      16153,  -26214,
    16153,  -26214, 16256,  0,      16066,  -28836, -16512, 0,      -16512, 0,      16097,  18350,  -16512, 0,
    -16512, 0,      0,      0,      16256,  0,      16051,  13107,  16087,  2621,   0,      0,      1,      256,
    0,      0,      0,      0,      0,      0,      0,      0,      16384,  0,      0,      0,      0,      0,
    16230,  26214,  0,      0,      0,      0,      256,    0,      0,      0,      0,      0,      15948,  -13107,
    0,      0,      0,      0,      -16512, 0,      0,      0,      0,      0,      0,      0,      4352,   30,
    0,      210,    0,      20,     0,      0,      0,      0,      511,    -1,     -1,     0,      15363,  4719,
    0,      0,      16256,  0,      16128,  0,      16128,  0,      16161,  18350,  -16512, 0,      -16512, 0,
    16179,  13107,  -16512, 0,      -16512, 0,      0,      0,      16256,  0,      15948,  -13107, 16051,  13107,
    0,      0,      1,      0,      0,      0,      0,      0,      0,      0,      0,      0,      16672,  0,
    0,      0,      0,      0,      16215,  2621,   0,      0,      0,      0,      256,    0,      0,      0,
    -256,   0,      16025,  -26214, 0,      0,      0,      0,      15897,  -26214, 16128,  0,      0,      0,
    0,      0,      4608,   34,     0,      210,    0,      0,      0,      0,      0,      0,      268,    3086,
    3091,   0,      15540,  14680,  0,      0,      16128,  0,      16128,  0,      16230,  26214,  16035,  -10486,
    -16512, 0,      -16512, 0,      16076,  -13107, -16512, 0,      -16512, 0,      0,      0,      16256,  0,
    15948,  -13107, 16051,  13107,  0,      0,      1,      0,      0,      0,      0,      0,      0,      0,
    0,      0,      16204,  -13107, 0,      0,      0,      0,      16230,  26214,  0,      0,      0,      0,
    0,      0,      16268,  -13107, 5120,   0,      15820,  -13107, 0,      0,      0,      0,      -16512, 0,
    0,      0,      0,      0,      0,      0,      4864,   12,     0,      210,    0,      0,      0,      4,
    0,      8,      273,    4369,   4369,   0,      15395,  -10486, 16128,  0,      16230,  26214,  16230,  26214,
    16230,  26214,  15897,  -26214, 16087,  2621,   16174,  5243,   16000,  0,      16128,  0,      16192,  0,
    0,      0,      16256,  0,      15948,  -13107, 16051,  13107,  0,      0,      4,      1028,   0,      0,
    0,      0,      0,      0,      0,      0,      16256,  0,      16256,  0,      0,      0,      16230,  26214,
    16230,  26214,  16230,  26214,  512,    0,      0,      0,      0,      0,      15820,  -13107, 15820,  -13107,
    15948,  -13107, -16512, 0,      0,      0,      1285,   3075,   770,    0,      5120,   16,     0,      210,
    0,      4,      0,      4,      0,      4,      274,    4626,   4626,   0,      15564,  -13107, 0,      0,
    16128,  0,      16128,  0,      16230,  26214,  16035,  -10486, -16512, 0,      -16512, 0,      16087,  2621,
    -16512, 0,      -16512, 0,      0,      0,      16256,  0,      15948,  -13107, 16051,  13107,  0,      0,
    1,      257,    0,      0,      0,      0,      0,      0,      0,      0,      16204,  -13107, 0,      0,
    0,      0,      16230,  26214,  0,      0,      0,      0,      0,      0,      0,      0,      4608,   0,
    15820,  -13107, 15820,  -13107, 0,      0,      -16512, 0,      0,      0,      0,      0,      0,      0,
    5376,   16,     0,      210,    0,      4,      0,      4,      0,      4,      268,    3086,   3091,   0,
    15564,  -13107, 0,      0,      16128,  0,      16128,  0,      16230,  26214,  16035,  -10486, -16512, 0,
    -16512, 0,      16087,  2621,   -16512, 0,      -16512, 0,      0,      0,      16256,  0,      15948,  -13107,
    16051,  13107,  0,      0,      1,      257,    0,      0,      0,      0,      0,      0,      0,      0,
    16204,  -13107, 0,      0,      0,      0,      16230,  26214,  0,      0,      0,      0,      0,      0,
    16268,  -13107, 5632,   0,      15820,  -13107, 15820,  -13107, 0,      0,      -16512, 0,      0,      0,
    0,      0,      0,      0,      5632,   34,     0,      210,    0,      0,      0,      0,      0,      0,
    277,    5397,   5397,   0,      15564,  -13107, 0,      0,      16153,  -26214, 16153,  -26214, 16230,  26214,
    16087,  2621,   -16512, 0,      -16512, 0,      16133,  7864,   -16512, 0,      -16512, 0,      0,      0,
    16256,  0,      15948,  -13107, 16051,  13107,  0,      0,      1,      0,      0,      0,      0,      0,
    0,      0,      0,      0,      16204,  -13107, 0,      0,      0,      0,      16230,  26214,  0,      0,
    0,      0,      0,      0,      16268,  -13107, 5376,   0,      15820,  -13107, 0,      0,      0,      0,
    -16512, 0,      0,      0,      0,      0,      0,      0,      5888,   13,     0,      210,    0,      16,
    0,      4,      0,      4,      511,    -1,     -1,     0,      15395,  -10486, 0,      0,      16204,  -13107,
    16204,  -13107, 16204,  -13107, 16133,  7864,   -16512, 0,      -16512, 0,      16158,  -18350, -16512, 0,
    -16512, 0,      0,      0,      16256,  0,      15948,  -13107, 16051,  13107,  0,      0,      1,      257,
    0,      0,      0,      0,      0,      0,      256,    0,      16204,  -13107, 0,      0,      0,      0,
    16230,  26214,  0,      0,      0,      0,      0,      0,      0,      0,      0,      0,      15948,  -13107,
    15820,  -13107, 0,      0,      -16512, 0,      0,      0,      0,      0,      0,      0,      6144,   40,
    0,      210,    0,      16,     0,      4,      0,      4,      511,    -1,     -1,     0,      15395,  -10486,
    0,      0,      16128,  0,      16128,  0,      16230,  26214,  16035,  -10486, -16512, 0,      -16512, 0,
    16087,  2621,   -16512, 0,      -16512, 0,      0,      0,      16256,  0,      15948,  -13107, 16051,  13107,
    0,      0,      3,      257,    0,      0,      0,      0,      0,      0,      0,      0,      16204,  -13107,
    0,      0,      0,      0,      16230,  26214,  0,      0,      0,      0,      0,      0,      0,      0,
    0,      0,      15948,  -13107, 15820,  -13107, 0,      0,      -16512, 0,      0,      0,      0,      0,
    0,      0,      6400,   0,      0,      210,    0,      20,     0,      20,     0,      20,     511,    -1,
    -1,     0,      15564,  -13107, 0,      0,      16128,  0,      16128,  0,      16230,  26214,  16035,  -10486,
    -16512, 0,      -16512, 0,      16087,  2621,   -16512, 0,      -16512, 0,      0,      0,      16256,  0,
    15948,  -13107, 16051,  13107,  0,      0,      0,      0,      0,      0,      0,      0,      0,      0,
    0,      0,      16256,  0,      0,      0,      0,      0,      16230,  26214,  0,      0,      0,      0,
    0,      0,      0,      0,      -256,   0,      15820,  -13107, 15820,  -13107, 0,      0,      -16512, 0,
    0,      0,      0,      0,      0,      0,      6656,   42,     0,      210,    0,      4,      0,      4,
    0,      4,      511,    -1,     -1,     0,      15564,  -13107, 0,      0,      16128,  0,      16128,  0,
    16230,  26214,  16051,  13107,  -16512, 0,      -16512, 0,      16102,  26214,  -16512, 0,      -16512, 0,
    0,      0,      16256,  0,      15948,  -13107, 16051,  13107,  0,      0,      1,      257,    0,      0,
    0,      0,      0,      0,      0,      0,      16204,  -13107, 0,      0,      0,      0,      16230,  26214,
    0,      0,      0,      0,      0,      0,      0,      0,      -256,   0,      15820,  -13107, 15820,  -13107,
    0,      0,      -16512, 0,      0,      0,      0,      0,      0,      0,      6912,   41,     0,      210,
    0,      4,      0,      4,      0,      4,      511,    -1,     -1,     0,      15395,  -10486, 0,      0,
    16204,  -13107, 16204,  -13107, 16204,  -13107, 16133,  7864,   -16512, 0,      -16512, 0,      16158,  -18350,
    -16512, 0,      -16512, 0,      0,      0,      16256,  0,      15948,  -13107, 16051,  13107,  0,      0,
    1,      257,    0,      0,      0,      0,      0,      0,      256,    0,      16204,  -13107, 0,      0,
    0,      0,      16230,  26214,  0,      0,      0,      0,      0,      0,      0,      0,      0,      0,
    16025,  -26214, 15820,  -13107, 0,      0,      -16512, 0,      0,      0,      0,      0,      0,      0,
};

f32 gPlayerAnimSpeedThresholds[36] = {
    0.005f,     0.1f,      0.08f,     0.55f,     0.53f,      2.3993998f, 0.0f,      0.0f,       0.0f,
    0.0f,       17.0f,     0.0f,      0.0f,      5.0f,       0.0f,       1.6e-43f,  1.272e-42f, 5.59e-43f,
    1.466e-42f, 1.47e-42f, 1.96e-43f, 1.62e-42f, 1.469e-42f, 2.539e-42f, 1.62e-42f, 1.47e-42f,  1.469e-42f,
    2.539e-42f, 0.002f,    0.003f,    0.0015f,   0.008f,     0.0022f,    0.002f,    0.0015f,    0.008f,
};

int gPlayerMoveTableA[48] = {
    0,        0,        1441824,  2031638,  1441824,  2031638,  131194,   7929858,  196644,   2293763,
    196611,   196611,   1966149,  0,        231,      15073512, 1072,     70255664, 70321203, 70386737,
    70321203, 70386737, 69010463, 69075997, 70911036, 70976570, 70911036, 70976570, 1966149,  0,
    231,      15859944, 68355091, 68355091, 4980812,  4980812,  4980812,  4980812,  7536755,  7536755,
    7602292,  7602292,  7602292,  7602292,  68355091, 68355091, 68355091, 68355091,
};

s16 gPlayerSpellGameBits[52] = {
    45,     64,    471,    1469,  1486,   1532,  1911,   2391,  2392,  263,   3157,  0,      0,
    77,     0,     101,    0,     90,     0,     78,     0,     1024,  0,     1033,  0,      75,
    0,      74,    0,      1025,  0,      99,    0,      73,    0,     72,    15523, -10486, 15523,
    -10486, 15564, -13107, 15564, -13107, 15428, -25690, 15333, 24642, 15379, 29884, 15379,  29884,
};

/* .data tables (reconstructed to match player.o; typed per header externs) */
s16 lbl_80333110[128] = {8,    8,    8,    8,    7,    7,    7,    7,    7,    7,    7,    7,    1051, 1051, 1051, 1051,
                         1051, 1051, 1051, 1051, 1051, 1051, 1051, 1051, 1093, 1093, 1457, 1090, 1092, 235,  234,  8,
                         140,  140,  140,  140,  147,  148,  149,  150,  147,  148,  149,  150,  147,  148,  149,  150,
                         147,  148,  149,  150,  147,  148,  149,  150,  1093, 1093, 1457, 1090, 1092, 235,  234,  8,
                         91,   91,   91,   91,   214,  215,  216,  217,  214,  215,  216,  217,  214,  215,  216,  217,
                         214,  215,  216,  217,  214,  215,  216,  217,  1093, 1093, 1457, 1090, 1092, 235,  234,  8,
                         1043, 1043, 1043, 1043, 218,  219,  131,  220,  218,  219,  131,  220,  218,  219,  131,  220,
                         218,  219,  131,  220,  218,  219,  131,  220,  1093, 1093, 1457, 1090, 1092, 235,  234,  8};
s16 gPlayerMoveTableB[14] = {140, 140, 140, 140, 147, 148, 149, 150, 147, 148, 149, 150, 140, 0};
u8 gPlayerSurfacePfxModeTable[36] = {0, 1, 2, 3, 0, 0, 0, 0, 0, 3, 0, 0, 0, 7, 5, 0, 0, 0,
                                     0, 0, 0, 3, 5, 0, 4, 6, 0, 7, 0, 0, 0, 0, 8, 0, 9, 0};
int lbl_80333250[24] = {1000593162, 1040744395, 1037723154, 1060652576, 1060205294, 1067475701, 1067252061, 1072843067,
                        1072619427, 1075417028, 1075333142, 1075417028, 1000593162, 1011129254, 1008981770, 1048911544,
                        1047233823, 1051931443, 1050253722, 1057300152, 1056964608, 1060320051, 1059984507, 1060320051};
s16 lbl_803332B0[478] = {
    23,    201,    24,    25,     26,    193,    195,   194,    205,   206,    -1,    -1,     123,   123,
    123,   123,    123,   123,    123,   123,    123,   123,    -1,    -1,     248,   248,    248,   248,
    248,   248,    246,   247,    249,   250,    -1,    -1,     252,   252,    252,   252,    252,   252,
    252,   252,    252,   252,    -1,    -1,     16704, 0,      16704, 0,      16704, 0,      16704, 0,
    16704, 0,      16704, 0,      16704, 0,      16704, 0,      16704, 0,      16704, 0,      16704, 0,
    16704, 0,      16704, 0,      16704, 0,      16704, 0,      16704, 0,      16704, 0,      16704, 0,
    16720, 0,      16736, 0,      16752, 0,      16768, 0,      16768, 0,      16768, 0,      16768, 0,
    16832, 0,      16832, 0,      16896, 0,      16896, 0,      16896, 0,      16896, 0,      16896, 0,
    16896, 0,      16896, 0,      16896, 0,      16896, 0,      16896, 0,      16896, 0,      16896, 0,
    16896, 0,      16896, 0,      16640, 0,      16640, 0,      16544, 0,      16544, 0,      16544, 0,
    16544, 0,      16544, 0,      16544, 0,      16544, 0,      16544, 0,      16544, 0,      16544, 0,
    16544, 0,      16544, 0,      16544, 0,      16544, 0,      16544, 0,      16544, 0,      16544, 0,
    16544, 0,      16544, 0,      16544, 0,      16544, 0,      16544, 0,      16544, 0,      16544, 0,
    16544, 0,      16544, 0,      16544, 0,      16544, 0,      16544, 0,      16544, 0,      16544, 0,
    16544, 0,      16544, 0,      16544, 0,      16544, 0,      16544, 0,      16544, 0,      16544, 0,
    16544, 0,      16736, 0,      16736, 0,      16736, 0,      16736, 0,      16736, 0,      16736, 0,
    16736, 0,      16736, 0,      16736, 0,      16736, 0,      16736, 0,      16736, 0,      16736, 0,
    16720, 0,      16704, 0,      16688, 0,      16672, 0,      16665, -26214, 16640, 0,      16614, 26214,
    16601, -26214, 16601, -26214, 16601, -26214, 16601, -26214, 16601, -26214, 16601, -26214, 16601, -26214,
    16601, -26214, 16601, -26214, 16601, -26214, 16601, -26214, 16601, -26214, 16601, -26214, 16601, -26214,
    16601, -26214, 16601, -26214, 16601, -26214, 16601, -26214, 16601, -26214, 16601, -26214, 16601, -26214,
    16601, -26214, 16601, -26214, 16601, -26214, 16601, -26214, 16601, -26214, 16640, 0,      16640, 0,
    16544, 0,      16544, 0,      16544, 0,      16544, 0,      16544, 0,      16544, 0,      16544, 0,
    16544, 0,      16544, 0,      16544, 0,      16544, 0,      16544, 0,      16544, 0,      16544, 0,
    16544, 0,      16544, 0,      16544, 0,      16544, 0,      16544, 0,      16544, 0,      16544, 0,
    16544, 0,      16544, 0,      16544, 0,      16544, 0,      16544, 0,      16544, 0,      16544, 0,
    16544, 0,      16544, 0,      16544, 0,      16544, 0,      16544, 0,      16544, 0,      16544, 0,
    16544, 0,      16544, 0,      16544, 0,      16544, 0,      16736, 0,      16736, 0,      16736, 0,
    16736, 0,      16736, 0,      16736, 0,      16736, 0,      16736, 0,      16736, 0,      16736, 0,
    16736, 0,      16736, 0,      16736, 0,      16720, 0,      16704, 0,      16688, 0,      16672, 0,
    16665, -26214, 16640, 0,      16614, 26214,  16601, -26214, 16601, -26214, 16601, -26214, 16601, -26214,
    16601, -26214, 16601, -26214, 16601, -26214, 16601, -26214, 16601, -26214, 16601, -26214, 16601, -26214,
    16601, -26214, 16601, -26214, 16601, -26214, 16601, -26214, 16601, -26214, 16601, -26214, 16601, -26214,
    16601, -26214, 16601, -26214, 16601, -26214, 16601, -26214, 16601, -26214, 16601, -26214, 16601, -26214,
    16601, -26214};
s16 lbl_8033366C[24] = {168,   167,    166,   165,    92,    1071,   92,    21,     15692, -13107, 15692, -13107,
                        15692, -13107, 15692, -13107, 15692, -13107, 15820, -13107, 15692, -13107, 0,     0};
f32 lbl_8033369C[8] = {0.01f, 0.02f, 0.02f, 0.015f, 0.015f, 0.01f, 0.02f, 0.005f};
s16 gPlayerMoveSlotTable[44] = {1113, 1114, 0,    0,    0,    0,   0,    1120, 0,    1122, 0,    1124, 1125, 1126, 0,
                                1128, 1129, 151,  152,  153,  154, 1130, 1131, 1109, 0,    0,    1112, 1132, 1133, 1134,
                                1135, 1136, 1137, 1138, 1139, 0,   0,    0,    0,    0,    1145, 1152, 1129, 0};

int gPlayerStateHandlers[66];
f32 lbl_803DAF88[16];
u8 gPlayerHudVtxBuf[0x80];
f32 gPlayerPartFxParams[6];

void* jumptable_80334ABC[12] = {
    (void*)((u8*)fn_80295918 + 0xD8),
    (void*)((u8*)fn_80295918 + 0x40),
    (void*)((u8*)fn_80295918 + 0xD8),
    (void*)((u8*)fn_80295918 + 0xD8),
    (void*)((u8*)fn_80295918 + 0xD8),
    (void*)((u8*)fn_80295918 + 0x84),
    (void*)((u8*)fn_80295918 + 0x64),
    (void*)((u8*)fn_80295918 + 0xD8),
    (void*)((u8*)fn_80295918 + 0xD8),
    (void*)((u8*)fn_80295918 + 0xD8),
    (void*)((u8*)fn_80295918 + 0xB0),
    (void*)((u8*)fn_80295918 + 0xC4),
};
void* jumptable_80334AEC[19] = {
    (void*)((u8*)fn_80295A04 + 0x120),
    (void*)((u8*)fn_80295A04 + 0x24),
    (void*)((u8*)fn_80295A04 + 0x54),
    (void*)((u8*)fn_80295A04 + 0x120),
    (void*)((u8*)fn_80295A04 + 0x120),
    (void*)((u8*)fn_80295A04 + 0x120),
    (void*)((u8*)fn_80295A04 + 0x120),
    (void*)((u8*)fn_80295A04 + 0x120),
    (void*)((u8*)fn_80295A04 + 0x120),
    (void*)((u8*)fn_80295A04 + 0xB8),
    (void*)((u8*)fn_80295A04 + 0xD0),
    (void*)((u8*)fn_80295A04 + 0xDC),
    (void*)((u8*)fn_80295A04 + 0x120),
    (void*)((u8*)fn_80295A04 + 0xE8),
    (void*)((u8*)fn_80295A04 + 0xFC),
    (void*)((u8*)fn_80295A04 + 0x120),
    (void*)((u8*)fn_80295A04 + 0x120),
    (void*)((u8*)fn_80295A04 + 0x120),
    (void*)((u8*)fn_80295A04 + 0x104),
};
void* jumptable_80334B38[25] = {
    (void*)((u8*)playerState1D + 0x220),
    (void*)((u8*)playerState1D + 0x220),
    (void*)((u8*)playerState1D + 0x25C),
    (void*)((u8*)playerState1D + 0x25C),
    (void*)((u8*)playerState1D + 0x25C),
    (void*)((u8*)playerState1D + 0x25C),
    (void*)((u8*)playerState1D + 0x25C),
    (void*)((u8*)playerState1D + 0x25C),
    (void*)((u8*)playerState1D + 0x25C),
    (void*)((u8*)playerState1D + 0x25C),
    (void*)((u8*)playerState1D + 0x25C),
    (void*)((u8*)playerState1D + 0x25C),
    (void*)((u8*)playerState1D + 0x25C),
    (void*)((u8*)playerState1D + 0x220),
    (void*)((u8*)playerState1D + 0x25C),
    (void*)((u8*)playerState1D + 0x25C),
    (void*)((u8*)playerState1D + 0x25C),
    (void*)((u8*)playerState1D + 0x25C),
    (void*)((u8*)playerState1D + 0x1EC),
    (void*)((u8*)playerState1D + 0x25C),
    (void*)((u8*)playerState1D + 0x25C),
    (void*)((u8*)playerState1D + 0x25C),
    (void*)((u8*)playerState1D + 0x25C),
    (void*)((u8*)playerState1D + 0x25C),
    (void*)((u8*)playerState1D + 0x220),
};
void* jumptable_80334B9C[8] = {
    (void*)((u8*)playerStateClimbWall + 0x3AC),
    (void*)((u8*)playerStateClimbWall + 0x3DC),
    (void*)((u8*)playerStateClimbWall + 0x3BC),
    (void*)((u8*)playerStateClimbWall + 0x3C4),
    (void*)((u8*)playerStateClimbWall + 0x3A4),
    (void*)((u8*)playerStateClimbWall + 0x3D0),
    (void*)((u8*)playerStateClimbWall + 0x3B4),
    (void*)((u8*)playerStateClimbWall + 0x3E8),
};
void* jumptable_80334BBC[8] = {
    (void*)((u8*)playerStateClimbLedge + 0xEC),
    (void*)((u8*)playerStateClimbLedge + 0x654),
    (void*)((u8*)playerStateClimbLedge + 0x1DC),
    (void*)((u8*)playerStateClimbLedge + 0x264),
    (void*)((u8*)playerStateClimbLedge + 0x654),
    (void*)((u8*)playerStateClimbLedge + 0x59C),
    (void*)((u8*)playerStateClimbLedge + 0x330),
    (void*)((u8*)playerStateClimbLedge + 0x3CC),
};
void* jumptable_80334BDC[13] = {
    (void*)((u8*)playerState0B + 0x11C),
    (void*)((u8*)playerState0B + 0x16C),
    (void*)((u8*)playerState0B + 0x16C),
    (void*)((u8*)playerState0B + 0x16C),
    (void*)((u8*)playerState0B + 0xB0),
    (void*)((u8*)playerState0B + 0x16C),
    (void*)((u8*)playerState0B + 0x16C),
    (void*)((u8*)playerState0B + 0x16C),
    (void*)((u8*)playerState0B + 0x11C),
    (void*)((u8*)playerState0B + 0x16C),
    (void*)((u8*)playerState0B + 0x16C),
    (void*)((u8*)playerState0B + 0x16C),
    (void*)((u8*)playerState0B + 0xB0),
};
void* jumptable_80334C10[14] = {
    (void*)((u8*)playerState08 + 0xFC),
    (void*)((u8*)playerState08 + 0x1F0),
    (void*)((u8*)playerState08 + 0x1F0),
    (void*)((u8*)playerState08 + 0x1F0),
    (void*)((u8*)playerState08 + 0x144),
    (void*)((u8*)playerState08 + 0x15C),
    (void*)((u8*)playerState08 + 0x180),
    (void*)((u8*)playerState08 + 0x1A4),
    (void*)((u8*)playerState08 + 0x1BC),
    (void*)((u8*)playerState08 + 0x120),
    (void*)((u8*)playerState08 + 0x1E0),
    (void*)((u8*)playerState08 + 0x1CC),
    (void*)((u8*)playerState08 + 0x1F0),
    (void*)((u8*)playerState08 + 0x194),
};
void* jumptable_80334C60[13] = {
    (void*)((u8*)playerCheckIfClimbingOntoWall + 0x6D4),
    (void*)((u8*)playerCheckIfClimbingOntoWall + 0x94C),
    (void*)((u8*)playerCheckIfClimbingOntoWall + 0x99C),
    (void*)((u8*)playerCheckIfClimbingOntoWall + 0x8C0),
    (void*)((u8*)playerCheckIfClimbingOntoWall + 0x8C0),
    (void*)((u8*)playerCheckIfClimbingOntoWall + 0x900),
    (void*)((u8*)playerCheckIfClimbingOntoWall + 0x900),
    (void*)((u8*)playerCheckIfClimbingOntoWall + 0x94C),
    (void*)((u8*)playerCheckIfClimbingOntoWall + 0xA0C),
    (void*)((u8*)playerCheckIfClimbingOntoWall + 0x99C),
    (void*)((u8*)playerCheckIfClimbingOntoWall + 0x824),
    (void*)((u8*)playerCheckIfClimbingOntoWall + 0xAA0),
    (void*)((u8*)playerCheckIfClimbingOntoWall + 0x94C),
};
void* jumptable_80334C94[11] = {
    (void*)((u8*)playerCheckIfClimbingOntoWall + 0x5C4),
    (void*)((u8*)playerCheckIfClimbingOntoWall + 0x5B4),
    (void*)((u8*)playerCheckIfClimbingOntoWall + 0x554),
    (void*)((u8*)playerCheckIfClimbingOntoWall + 0x524),
    (void*)((u8*)playerCheckIfClimbingOntoWall + 0x554),
    (void*)((u8*)playerCheckIfClimbingOntoWall + 0x524),
    (void*)((u8*)playerCheckIfClimbingOntoWall + 0x554),
    (void*)((u8*)playerCheckIfClimbingOntoWall + 0x5B4),
    (void*)((u8*)playerCheckIfClimbingOntoWall + 0x5B4),
    (void*)((u8*)playerCheckIfClimbingOntoWall + 0x5B4),
    (void*)((u8*)playerCheckIfClimbingOntoWall + 0x5C4),
};
void* jumptable_80334CC0[13] = {
    (void*)((u8*)playerCheckIfClimbingOntoWall + 0x234),
    (void*)((u8*)playerCheckIfClimbingOntoWall + 0x1EC),
    (void*)((u8*)playerCheckIfClimbingOntoWall + 0x288),
    (void*)((u8*)playerCheckIfClimbingOntoWall + 0x260),
    (void*)((u8*)playerCheckIfClimbingOntoWall + 0x2D8),
    (void*)((u8*)playerCheckIfClimbingOntoWall + 0x260),
    (void*)((u8*)playerCheckIfClimbingOntoWall + 0x2D8),
    (void*)((u8*)playerCheckIfClimbingOntoWall + 0x1EC),
    (void*)((u8*)playerCheckIfClimbingOntoWall + 0x330),
    (void*)((u8*)playerCheckIfClimbingOntoWall + 0x330),
    (void*)((u8*)playerCheckIfClimbingOntoWall + 0x234),
    (void*)((u8*)playerCheckIfClimbingOntoWall + 0x328),
    (void*)((u8*)playerCheckIfClimbingOntoWall + 0x1EC),
};
void* jumptable_80334CF4[12] = {
    (void*)((u8*)fn_802AFB0C + 0x854),
    (void*)((u8*)fn_802AFB0C + 0x910),
    (void*)((u8*)fn_802AFB0C + 0x7FC),
    (void*)((u8*)fn_802AFB0C + 0x910),
    (void*)((u8*)fn_802AFB0C + 0x910),
    (void*)((u8*)fn_802AFB0C + 0x910),
    (void*)((u8*)fn_802AFB0C + 0x910),
    (void*)((u8*)fn_802AFB0C + 0x910),
    (void*)((u8*)fn_802AFB0C + 0x8D4),
    (void*)((u8*)fn_802AFB0C + 0x910),
    (void*)((u8*)fn_802AFB0C + 0x910),
    (void*)((u8*)fn_802AFB0C + 0x854),
};
void* jumptable_80334D24[32] = {
    (void*)((u8*)fn_802AFB0C + 0x430),
    (void*)((u8*)fn_802AFB0C + 0x314),
    (void*)((u8*)fn_802AFB0C + 0x454),
    (void*)((u8*)fn_802AFB0C + 0x430),
    (void*)((u8*)fn_802AFB0C + 0x2FC),
    (void*)((u8*)fn_802AFB0C + 0x454),
    (void*)((u8*)fn_802AFB0C + 0x430),
    (void*)((u8*)fn_802AFB0C + 0x278),
    (void*)((u8*)fn_802AFB0C + 0x278),
    (void*)((u8*)fn_802AFB0C + 0x278),
    (void*)((u8*)fn_802AFB0C + 0x2D0),
    (void*)((u8*)fn_802AFB0C + 0x24C),
    (void*)((u8*)fn_802AFB0C + 0x2A4),
    (void*)((u8*)fn_802AFB0C + 0x430),
    (void*)((u8*)fn_802AFB0C + 0x430),
    (void*)((u8*)fn_802AFB0C + 0x430),
    (void*)((u8*)fn_802AFB0C + 0x430),
    (void*)((u8*)fn_802AFB0C + 0x430),
    (void*)((u8*)fn_802AFB0C + 0x454),
    (void*)((u8*)fn_802AFB0C + 0x430),
    (void*)((u8*)fn_802AFB0C + 0x398),
    (void*)((u8*)fn_802AFB0C + 0x328),
    (void*)((u8*)fn_802AFB0C + 0x34C),
    (void*)((u8*)fn_802AFB0C + 0x454),
    (void*)((u8*)fn_802AFB0C + 0x454),
    (void*)((u8*)fn_802AFB0C + 0x380),
    (void*)((u8*)fn_802AFB0C + 0x398),
    (void*)((u8*)fn_802AFB0C + 0x390),
    (void*)((u8*)fn_802AFB0C + 0x430),
    (void*)((u8*)fn_802AFB0C + 0x430),
    (void*)((u8*)fn_802AFB0C + 0x3E4),
    (void*)((u8*)fn_802AFB0C + 0x398),
};
void* jumptable_80334DA4[30] = {
    (void*)((u8*)fn_802B1E5C + 0x13C),
    (void*)((u8*)fn_802B1E5C + 0x4A8),
    (void*)((u8*)fn_802B1E5C + 0x4A8),
    (void*)((u8*)fn_802B1E5C + 0x154),
    (void*)((u8*)fn_802B1E5C + 0x4A8),
    (void*)((u8*)fn_802B1E5C + 0x290),
    (void*)((u8*)fn_802B1E5C + 0x4A8),
    (void*)((u8*)fn_802B1E5C + 0x4A8),
    (void*)((u8*)fn_802B1E5C + 0x4A8),
    (void*)((u8*)fn_802B1E5C + 0x4A8),
    (void*)((u8*)fn_802B1E5C + 0x120),
    (void*)((u8*)fn_802B1E5C + 0x4A8),
    (void*)((u8*)fn_802B1E5C + 0x4A8),
    (void*)((u8*)fn_802B1E5C + 0x4A8),
    (void*)((u8*)fn_802B1E5C + 0x4A8),
    (void*)((u8*)fn_802B1E5C + 0x4A8),
    (void*)((u8*)fn_802B1E5C + 0x4A8),
    (void*)((u8*)fn_802B1E5C + 0x4A8),
    (void*)((u8*)fn_802B1E5C + 0x4A8),
    (void*)((u8*)fn_802B1E5C + 0x4A8),
    (void*)((u8*)fn_802B1E5C + 0x4A8),
    (void*)((u8*)fn_802B1E5C + 0x4A8),
    (void*)((u8*)fn_802B1E5C + 0x4A8),
    (void*)((u8*)fn_802B1E5C + 0x204),
    (void*)((u8*)fn_802B1E5C + 0x4A8),
    (void*)((u8*)fn_802B1E5C + 0x2AC),
    (void*)((u8*)fn_802B1E5C + 0x1B8),
    (void*)((u8*)fn_802B1E5C + 0x4A8),
    (void*)((u8*)fn_802B1E5C + 0x498),
    (void*)((u8*)fn_802B1E5C + 0x344),
};
void* jumptable_80334E1C[51] = {
    (void*)((u8*)player_SeqFn + 0x1B64),
    (void*)((u8*)player_SeqFn + 0x18C4),
    (void*)((u8*)player_SeqFn + 0x11AC),
    (void*)((u8*)player_SeqFn + 0xE50),
    (void*)((u8*)player_SeqFn + 0x11D0),
    (void*)((u8*)player_SeqFn + 0x1B64),
    (void*)((u8*)player_SeqFn + 0x1398),
    (void*)((u8*)player_SeqFn + 0x13E8),
    (void*)((u8*)player_SeqFn + 0x1444),
    (void*)((u8*)player_SeqFn + 0x1B64),
    (void*)((u8*)player_SeqFn + 0x14A0),
    (void*)((u8*)player_SeqFn + 0x128C),
    (void*)((u8*)player_SeqFn + 0x1B64),
    (void*)((u8*)player_SeqFn + 0x150C),
    (void*)((u8*)player_SeqFn + 0x1B64),
    (void*)((u8*)player_SeqFn + 0x1640),
    (void*)((u8*)player_SeqFn + 0x1654),
    (void*)((u8*)player_SeqFn + 0x1B64),
    (void*)((u8*)player_SeqFn + 0x1770),
    (void*)((u8*)player_SeqFn + 0x1788),
    (void*)((u8*)player_SeqFn + 0x1730),
    (void*)((u8*)player_SeqFn + 0x1744),
    (void*)((u8*)player_SeqFn + 0x175C),
    (void*)((u8*)player_SeqFn + 0x1688),
    (void*)((u8*)player_SeqFn + 0x14D8),
    (void*)((u8*)player_SeqFn + 0x1794),
    (void*)((u8*)player_SeqFn + 0x185C),
    (void*)((u8*)player_SeqFn + 0x1B64),
    (void*)((u8*)player_SeqFn + 0x17AC),
    (void*)((u8*)player_SeqFn + 0x17BC),
    (void*)((u8*)player_SeqFn + 0x17EC),
    (void*)((u8*)player_SeqFn + 0x181C),
    (void*)((u8*)player_SeqFn + 0x1834),
    (void*)((u8*)player_SeqFn + 0x1844),
    (void*)((u8*)player_SeqFn + 0x1850),
    (void*)((u8*)player_SeqFn + 0x1B64),
    (void*)((u8*)player_SeqFn + 0x1B64),
    (void*)((u8*)player_SeqFn + 0x18F0),
    (void*)((u8*)player_SeqFn + 0x1904),
    (void*)((u8*)player_SeqFn + 0x1918),
    (void*)((u8*)player_SeqFn + 0x1924),
    (void*)((u8*)player_SeqFn + 0x1A04),
    (void*)((u8*)player_SeqFn + 0x1A10),
    (void*)((u8*)player_SeqFn + 0x1B28),
    (void*)((u8*)player_SeqFn + 0x1B40),
    (void*)((u8*)player_SeqFn + 0x1B10),
    (void*)((u8*)player_SeqFn + 0x1B1C),
    (void*)((u8*)player_SeqFn + 0x1B64),
    (void*)((u8*)player_SeqFn + 0x1B64),
    (void*)((u8*)player_SeqFn + 0x1B54),
    (void*)((u8*)player_SeqFn + 0x1B5C),
};
