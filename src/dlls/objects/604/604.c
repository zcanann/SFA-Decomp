/* DLL 604: SnowClaw-family object callbacks. */

#include "dlls/objects/364.h"
#include "dlls/objects/common/vehicle.h"
#include "main/audio/sfx.h"
#include "main/dll/objfx_api.h"
#include "dlls/object_descriptor.h"
#include "main/frame_timing.h"
#include "main/dll/player_api.h"
#include "main/gamebits.h"
#include "main/objtype.h"
#include "main/object_render.h"
#include "sys/objects/lifecycle.h"
#include "sys/objects.h"
#include "main/obj_query.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/objhits.h"
#include "main/objfx.h"
#include "main/objseq.h"
#include "game/objects/object_setup.h"
#include "main/maketex_random_api.h"
#include "main/maketex_sequence_api.h"
#include "main/maketex_timer_api.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/math_api.h"
#include "main/shader_api.h"
#include "main/vecmath.h"
#include "main/obj_link.h"
#include "main/obj_path.h"
#include "dlls/objects/597_SnowBike.h"
#include "main/audio/sfx_play_api.h"

f32 gSnowClawPulseScale = 1.0f;
f32 gSnowClawPulseOffsetY = -15.0f;
int gSnowClawPulseInterval = 3;
f32 gSnowClawMoveStepScaleBase = 0.006f;

/* object group queried to find this object's target */
#define SNOWCLAW_TARGET_OBJGROUP 0x1e
/* drop-bomb child spawned by snowclaw_spawnDropBomb (obj id 0x5ff) */
#define SNOWCLAW_CHILD_OBJ_DROP_BOMB 0x5ff

/* rider-variant seqIds (retail OBJECTS.bin names) */
#define SNOWCLAW_SEQID_IM_SNOWCLAW  0x16d /* "IMSnowClaw" (DLL 0x25C) */
#define SNOWCLAW_SEQID_IM_SNOWCLAW2 0x170 /* "IMSnowClaw2" (DLL 0x25C) */
#define SNOWCLAW_SEQID_CR_SNOWCLAW  0x389 /* "CRSnowClaw" (DLL 0x25C) */

/* gSnowClawDropObjectTable entries, indexed by SnowclawState.dropIndex
   (retail OBJECTS.bin names); index 4 (0x1D) has no retail object entry */
#define SNOWCLAW_DROP_OBJ_SWORD       0x23 /* "sword" (DLL 0xE2) */
#define SNOWCLAW_DROP_OBJ_STAFF       0x69 /* "staff" (DLL 0xE2) */
#define SNOWCLAW_DROP_OBJ_SCWEAPON_T1 0x33 /* "SCweaponT1" */
#define SNOWCLAW_DROP_OBJ_ICEBALL     0x64 /* "IceBall" (DLL 0xCD) */

typedef struct SnowclawPlacement
{
    ObjPlacement base;     /* 0x00 */
    u8 pad18[0x27 - 0x18]; /* 0x18 */
    s8 dropIndex;          /* 0x27 */
} SnowclawPlacement;

typedef struct SnowclawState
{
    GameObject* mount;
    s16* moveTablePtr;
    f32 unk8;
    f32 prevPosX;
    f32 prevPosY;
    f32 prevPosZ;
    f32 posX;
    f32 posY;
    f32 posZ;
    f32 velX;
    f32 velY;
    f32 velZ;
    f32 unk30;
    u8 pad34[0x94 - 0x34];
    s32 pendingMoveId;
    f32 attackTimer;
    s32 attackDelay;
    u8 mountAlpha; /* 0xA0: opacity byte (default 0xff) written to obj+0x37 while mounted */
    u8 hitFlag;
    s8 dropIndex;
    s8 dropIndexApplied;
    s8 health;
    s8 hitCooldown;
    u8 tickCounter;
    u8 padA7[0xA8 - 0xA7];
    u16 moveIdBase;
    union {
        u8 flags;
        struct {
            u8 b0 : 1;
            u8 flag6 : 1;
            u8 rest : 6;
        };
    };
    u8 padAB[0xAC - 0xAB];
    f32 particleAlpha;
} SnowclawState;
STATIC_ASSERT(offsetof(SnowclawState, dropIndex) == 0xA2);
STATIC_ASSERT(offsetof(SnowclawState, health) == 0xA4);
STATIC_ASSERT(offsetof(SnowclawState, moveIdBase) == 0xA8);

typedef struct SnowclawTargetInterface
{
    void* pad00[8];
    int (*setState)(GameObject* target, int state);
    int (*getState)(GameObject* target);
} SnowclawTargetInterface;

STATIC_ASSERT(offsetof(SnowclawTargetInterface, setState) == 0x20);
STATIC_ASSERT(offsetof(SnowclawTargetInterface, getState) == 0x24);

#define SNOWCLAW_MOUNT_INTERFACE(mount)   (*(IMSnowClawMountInterface**)((GameObject*)(mount))->anim.dll)
#define SNOWCLAW_TARGET_INTERFACE(target) (*(SnowclawTargetInterface**)((GameObject*)(target))->anim.dll)

typedef struct SnowClawDropObjectTable
{
    s16 objectIds[5];
} SnowClawDropObjectTable;

typedef struct
{
    u32 w[4];
} SnowClawPulse4;

/* Spawn-setup buffer for the snowclaw drop-bomb child (obj id 0x5ff):
 * ObjPlacement head (pos/color) plus the class-specific aim/launch fields the
 * parent seeds at +0x18 (see the target stb/sth). */
typedef struct SnowClawBombSetup
{
    ObjPlacement head; /* 0x00: pos/color/mapId */
    s8 aimYaw;         /* 0x18 */
    s8 launchMode;   /* 0x19: bomb launch/aim mode (switched on to pick launchAngle: 0=default drop, 1=aim at player) */
    s16 launchAngle; /* 0x1a */
} SnowClawBombSetup;

int gSnowClawDropBombAngle;

s32 gSnowClawMoveTable[12] = {905, 909, 906, 910, 1235, 1236, 365, 364, 368, 367, 1000, 1002};

s32 gSnowClawAttackTimerByRank[4] = {150, 200, 300, 400};

u32 gSnowClawHurtSfxTable[8] = {0x2EF, 0x2EE, 0x2ED, 0x2EC, 0x2EB, 0x0497049C, 0x03A2049C, 0x07D007D1};

const u32 gSnowClawPulseTable[8] = {0, 1, 2, 3, 1, 1, 2, 2};
const SnowClawDropObjectTable gSnowClawDropObjectTable = {
    {SNOWCLAW_DROP_OBJ_SWORD, SNOWCLAW_DROP_OBJ_STAFF, SNOWCLAW_DROP_OBJ_SCWEAPON_T1, SNOWCLAW_DROP_OBJ_ICEBALL,
     0x1D}};

int snowclaw_getExtraSize(void);
int snowclaw_getObjectTypeId(void);
void snowclaw_release(void);
void snowclaw_initialise(void);
void snowclaw_free(GameObject* obj);
void snowclaw_init(GameObject* obj, SnowclawPlacement* placement);
void snowclaw_spawnDropBomb(GameObject* obj, GameObject* owner, int launchMode, int userData1Value);
void snowclaw_updateMountAttack(GameObject* obj, GameObject* mount);
void snowclaw_syncMountTransform(GameObject* obj, GameObject* mount, int p2, int p3, int p4, int p5, int opacity,
                                 int mountAlpha, int enabled);
void snowclaw_render(GameObject* obj, int p2, int p3, int p4, int p5, s8 vis);
void snowclaw_hitDetect(GameObject* obj);
void snowclaw_update(GameObject* obj);
int snowclaw_animEventCallback(GameObject* obj, int a2, ObjSeqState* seq);

ObjectDescriptor gSnowClawObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)snowclaw_initialise,
    (ObjectDescriptorCallback)snowclaw_release,
    0,
    (ObjectDescriptorCallback)snowclaw_init,
    (ObjectDescriptorCallback)snowclaw_update,
    (ObjectDescriptorCallback)snowclaw_hitDetect,
    (ObjectDescriptorCallback)snowclaw_render,
    (ObjectDescriptorCallback)snowclaw_free,
    (ObjectDescriptorCallback)snowclaw_getObjectTypeId,
    (ObjectDescriptorExtraSizeCallback)snowclaw_getExtraSize,
};


void snowclaw_spawnDropBomb(GameObject* obj, GameObject* owner, int launchMode, int userData1Value)
{
    GameObject* player;
    SnowClawBombSetup* setup;
    GameObject* spawned;

    player = Obj_GetPlayerObject();
    if ((u8)Obj_CanSetupObject() != 0)
    {
        setup = (SnowClawBombSetup*)Obj_AllocObjectSetup(0x24, SNOWCLAW_CHILD_OBJ_DROP_BOMB);
        setup->head.objectId = SNOWCLAW_CHILD_OBJ_DROP_BOMB;
        setup->head.color[0] = 2;
        setup->head.color[2] = 0xff;
        setup->head.color[1] = 1;
        setup->head.color[3] = 0xff;
        setup->launchMode = launchMode;
        setup->head.posX = obj->anim.localPosX;
        setup->head.posY = 4.0f + obj->anim.localPosY;
        setup->head.posZ = obj->anim.localPosZ;
        setup->aimYaw =
            (s8)(u8)((((getAngle(player->anim.localPosX - obj->anim.localPosX,
                                 player->anim.localPosZ - obj->anim.localPosZ) &
                        0xffff) >>
                       8) +
                      0x8000) >>
                     8);
        Sfx_PlayFromObject(obj, SFXTRIG_id_2e4);
        switch ((u8)launchMode)
        {
        case 0:
            setup->launchAngle = gSnowClawDropBombAngle;
            break;
        case 1:
            setup->launchAngle =
                (s16)(getAngle(player->anim.localPosX - obj->anim.localPosX,
                               player->anim.localPosZ - obj->anim.localPosZ) +
                      0x8000);
            break;
        }
        spawned = loadObjectAtObject(obj, &setup->head);
        if (spawned != NULL)
        {
            spawned->userData1 = (u8)userData1Value;
            spawned->ownerObj = (void*)owner;
        }
    }
}

void snowclaw_updateMountAttack(GameObject* obj, GameObject* mount)
{
    SnowclawState* inner;
    f32 mountPhase;
    f32 moveStep;
    f32 movePhase;
    int mountFlag;
    int magnitude;
    int turnSign;
    int moveId;
    int delay;

    inner = obj->extra;
    movePhase = SNOWCLAW_MOUNT_INTERFACE(mount)->getNormalizedSpeed(mount, &moveStep);
    moveStep = gSnowClawMoveStepScaleBase + 2.0f * (movePhase * gSnowClawMoveStepScaleBase);
    SNOWCLAW_MOUNT_INTERFACE(mount)->func12(mount, &mountPhase, &mountFlag);
    magnitude = (int)(16384.0f * mountPhase);
    if (magnitude < 0)
    {
        magnitude = -magnitude;
    }

    if (mountFlag != 0 && obj->anim.currentMove == inner->moveIdBase) {
        Object_ObjAnimSetSecondaryBlendMove(&obj->anim, inner->moveIdBase + 1,
                                            magnitude);
    } else {
        Object_ObjAnimSetSecondaryBlendMove(&obj->anim, inner->moveIdBase + 2,
                                            magnitude);
    }

    if (ObjAnim_AdvanceCurrentMove(obj, moveStep, (f32)framesThisStep, NULL) != 0 &&
        obj->anim.currentMove != inner->moveIdBase) {
        inner->unk30 = 0.006f;
        delay = inner->attackDelay;
        if (delay < 1)
        {
            delay = 1;
        }
        else if (delay > 0x190)
        {
            delay = 0x190;
        }
        inner->attackDelay = delay;

        if (randomChanceOneIn(2) == 0)
        {
            ObjAnim_SetCurrentMove(obj, inner->moveIdBase, 0.0f, 0);
        }
        else
        {
            turnSign = (u32)(s16)Obj_GetYawDeltaToObject(obj, Obj_GetPlayerObject(), 0) >> 31;
            if (turnSign == 0)
            {
                inner->unk30 = 0.004f;
                Sfx_PlayFromObject(obj, SFXTRIG_id_2e3);
            }
            else
            {
                inner->unk30 = 0.003f;
                Sfx_PlayFromObject(obj, SFXTRIG_id_2e2);
            }
            if (turnSign != 0)
            {
                moveId = inner->moveIdBase + 4;
            }
            else
            {
                moveId = inner->moveIdBase + 8;
            }
            ObjAnim_SetCurrentMove(obj, moveId, 0.0f, 0);
            inner->attackDelay += 0x64;
        }
    }
}

void snowclaw_syncMountTransform(GameObject* obj, GameObject* mount, int p2, int p3, int p4, int p5, int opacity,
                                 int mountAlpha, int enabled)
{
    f32 newPosX, newPosY, newPosZ;

    if (enabled != 0 && (s8)opacity != 0 && mountAlpha > 0)
    {
        u8 saved = mount->anim.renderAlpha;
        mount->anim.renderAlpha = mountAlpha;
        SNOWCLAW_MOUNT_INTERFACE(mount)->render(mount, p2, p3, p4, p5, -1);
        mount->anim.renderAlpha = saved;
    }
    obj->anim.previousWorldPosX = obj->anim.worldPosX;
    obj->anim.previousWorldPosY = obj->anim.worldPosY;
    obj->anim.previousWorldPosZ = obj->anim.worldPosZ;
    obj->anim.previousLocalPosX = obj->anim.localPosX;
    obj->anim.previousLocalPosY = obj->anim.localPosY;
    obj->anim.previousLocalPosZ = obj->anim.localPosZ;
    SNOWCLAW_MOUNT_INTERFACE(mount)->getPosition(mount, &newPosX, &newPosY, &newPosZ);
    obj->anim.localPosX = newPosX;
    obj->anim.localPosY = newPosY;
    obj->anim.localPosZ = newPosZ;
    obj->anim.rotX = mount->anim.rotX;
    obj->anim.rotY = mount->anim.rotY;
    obj->anim.rotZ = mount->anim.rotZ;
    obj->anim.worldPosX = obj->anim.localPosX;
    obj->anim.worldPosY = obj->anim.localPosY;
    obj->anim.worldPosZ = obj->anim.localPosZ;
    obj->anim.velocityX = mount->anim.velocityX;
    obj->anim.velocityY = mount->anim.velocityY;
    obj->anim.velocityZ = mount->anim.velocityZ;
}

int snowclaw_animEventCallback(GameObject* obj, int a2, ObjSeqState* seq)
{
    GameObject* sub;
    SnowclawState* s;
    int i;
    SnowClawDropObjectTable tbl;
    f32 dist;

    dist = 5000.0f;
    s = obj->extra;
    s->hitFlag = 1;
    ObjHits_DisableObject(obj);
    if (s->mount != NULL)
    {
        ObjHits_DisableObject(s->mount);
    }
    if (obj->seqIndex != -1 && (obj->anim.romDefNo == SNOWCLAW_SEQID_IM_SNOWCLAW || obj->anim.romDefNo == SNOWCLAW_SEQID_IM_SNOWCLAW2) &&
        mainGetBit(GAMEBIT_IM_BikeRelated03A3) != 0)
    {
        (*gObjectTriggerInterface)->endSequence(obj->seqIndex);
        s->particleAlpha = 0.0f;
        return 4;
    }
    obj->anim.flags &= ~OBJANIM_FLAG_HIDDEN;
    sub = s->mount;
    s->mountAlpha = 0xff;
    if (sub != 0)
    {
        s16 animFlags = sub->anim.flags;
        if (animFlags & OBJANIM_FLAG_HIDDEN)
        {
            sub->anim.flags = animFlags & ~OBJANIM_FLAG_HIDDEN;
            SNOWCLAW_MOUNT_INTERFACE(sub)->setRiderMode((GameObject*)sub, 2);
        }
    }
    if (seq->runState == 2)
    {
        seq->sequenceControlFlags |= OBJSEQ_CONTROL_CLEAR_LATCH_A;
    }
    seq->flags = seq->savedFlags;
    for (i = 0; i < seq->eventCount; i++)
    {
        switch (seq->eventIds[i])
        {
        case 3:
            s->dropIndex = -1;
            break;
        case 4:
            if (mainGetBit(0xb7d) != 0)
            {
                seq->sequenceControlFlags |= OBJSEQ_CONTROL_SET_LATCH_A;
            }
            break;
        case 5:
            if (mainGetBit(*s->moveTablePtr) != 0)
            {
                seq->sequenceControlFlags |= OBJSEQ_CONTROL_SET_LATCH_A;
            }
            break;
        case 2:
            if (sub != 0)
            {
                s->unk8 = 1.0f;
                s->prevPosX = s->posX;
                s->prevPosY = s->posY;
                s->prevPosZ = s->posZ;
                SNOWCLAW_MOUNT_INTERFACE(sub)->setRiderMode((GameObject*)sub, 2);
                ObjAnim_SetCurrentMove(obj, s->moveIdBase, 0.0f, 1);
                {
                    ObjModelState* gx = obj->anim.modelState;
                    if (gx != 0)
                    {
                        gx->flags |= OBJ_MODEL_STATE_SHADOW_FADE_OUT;
                    }
                }
                seq->flags &= ~4;
            }
            break;
        case 1:
            sub = s->mount;
            if (sub != 0)
            {
                SNOWCLAW_MOUNT_INTERFACE(sub)->setRiderMode((GameObject*)sub, 0);
                seq->flags |= 4;
            }
            break;
        case 6:
        {
            int* found = (int*)objGetNearestTypeTo(SNOWCLAW_TARGET_OBJGROUP, obj, &dist);
            if (found != 0)
            {
                SNOWCLAW_TARGET_INTERFACE(found)->setState((GameObject*)found, 2);
                s->b0 = 0;
            }
            break;
        }
        case 7:
        {
            int* found = (int*)objGetNearestTypeTo(SNOWCLAW_TARGET_OBJGROUP, obj, &dist);
            if (found != 0)
            {
                SNOWCLAW_TARGET_INTERFACE(found)->setState((GameObject*)found, 0);
                s->b0 = 1;
            }
            break;
        }
        }
        seq->eventIds[i] = 0;
    }
    tbl = gSnowClawDropObjectTable;
    if (s->dropIndex != s->dropIndexApplied)
    {
        if (obj->childObjs[0] != 0)
        {
            Obj_FreeObject((GameObject*)obj->childObjs[0]);
            obj->childObjs[0] = NULL;
            obj->childCount = 0;
        }
        if (s->dropIndex > 0 && (u8)Obj_CanSetupObject() != 0)
        {
            obj->childObjs[0] =
                objSetupObject(Obj_AllocObjectSetup(
                                         0x18, tbl.objectIds[s->dropIndex]), 4,
                                     obj->anim.mapEventSlot, -1, obj->anim.parent);
            obj->childCount = 1;
        }
        s->dropIndexApplied = s->dropIndex;
    }
    if (sub != 0 && SNOWCLAW_MOUNT_INTERFACE(sub)->getRiderMode((GameObject*)sub) == 2)
    {
        seq->flags &= ~3;
    }
    return 0;
}

int snowclaw_getExtraSize(void)
{
    return sizeof(SnowclawState);
}

int snowclaw_getObjectTypeId(void)
{
    return 0x3;
}

void snowclaw_free(GameObject* obj)
{
    if (obj->childObjs[0] != NULL)
    {
        Obj_FreeObject((GameObject*)obj->childObjs[0]);
    }
}

void snowclaw_render(GameObject* obj, int p2, int p3, int p4, int p5, s8 vis)
{
    SnowclawState* s;
    GameObject* mount;
    int found;
    int oldFlag;
    f32 dist;
    GameObject* near;
    f32 zero = 0.0f;

    dist = 5000.0f;
    s = obj->extra;
    mount = s->mount;
    if (obj->anim.alpha < 5) {
        s->particleAlpha = 0.0f;
    }
    found = 0;
    if (s->health >= 0 && mount != NULL)
    {
        if (SNOWCLAW_MOUNT_INTERFACE(mount)->getRiderMode(mount) == 2)
        {
            found = 1;
        }
    }
    if (found != 0)
    {
        obj->anim.flags |= 8;
        vis = objUpdateOpacity(mount);
        snowclaw_syncMountTransform(obj, mount, p2, p3, p4, p5, vis, s->mountAlpha, 1);
    }
    else
    {
        obj->anim.flags &= ~8;
    }
    if (vis != 0 && s->mountAlpha != 0)
    {
        oldFlag = obj->anim.renderAlpha;
        if (found != 0)
        {
            obj->anim.renderAlpha = s->mountAlpha;
        }
        if (obj->childCount == 0 && obj->anim.romDefNo == SNOWCLAW_SEQID_CR_SNOWCLAW && s->b0 != 0) {
            near = objGetNearestTypeTo(SNOWCLAW_TARGET_OBJGROUP, obj, &dist);
            if (near != NULL && SNOWCLAW_TARGET_INTERFACE(near)->getState(near) != 0 &&
                SNOWCLAW_TARGET_INTERFACE(near)->setState(near, 0) != 0)
            {
                ObjLink_AttachChild(obj, near, 0);
            }
        }
        objRenderModelAndHitVolumes(obj, p2, p3, p4, p5, 1.0f);
        ObjPath_GetPointWorldPosition(obj, 1, &s->posX, &s->posY,
                                      &s->posZ, 0);
        obj->anim.renderAlpha = oldFlag;
        if (s->flag6 != 0)
        {
            if (s->particleAlpha != zero)
            {
                s->particleAlpha = 1.0f + (f32)(s32)(0xff - obj->anim.alpha) / 255.0f;
            }
            else
            {
                s->flag6 = 0;
            }
            objDoParticleFx(obj, 1.0f, 3, s->particleAlpha, 0);
        }
    }
}

void snowclaw_hitDetect(GameObject* obj)
{
    SnowclawState* s;
    GameObject* sub;
    GameObject* near;
    GameObject* player;
    f32 dist;
    GameObject* hit;
    s8 hitCooldown;

    s = obj->extra;
    dist = 500.0f;
    sub = s->mount;
    if (sub == NULL)
    {
        return;
    }
    if (ObjHits_GetPriorityHit(sub, &hit, 0, 0) == 0x15 && s->health >= 0)
    {
        ObjHits_RecordObjectHit(sub, hit, 0x15, 1, 0);
        if (s->hitCooldown < 0)
        {
            s->health -= 1;
            Sfx_PlayFromObject(obj, SFXTRIG_en_sbalhis6_f2);
            Sfx_PlayFromObject(obj, SFXTRIG_attack);
            Sfx_PlayFromObject(obj, gSnowClawHurtSfxTable[s->health]);
            s->hitCooldown = 0x14;
            s->attackDelay -= 0x28;
            if (s->health < 0)
            {
                GameObject* sub2;

                spawnExplosion(obj, 60.0f, 1, 1, 1, 1, 0, 1, 0);
                sub2 = s->mount;
                if (sub2 != 0)
                {
                    SNOWCLAW_MOUNT_INTERFACE(sub2)->setRiderMode(sub2, 0);
                }
                if (obj->anim.romDefNo == SNOWCLAW_SEQID_CR_SNOWCLAW)
                {
                    near = objGetNearestTypeTo(SNOWCLAW_TARGET_OBJGROUP, obj, &dist);
                    if (near != 0)
                    {
                        ObjLink_DetachChild(obj, near);
                        SNOWCLAW_TARGET_INTERFACE(near)->setState(near, 2);
                    }
                }
                if (obj->anim.romDefNo == SNOWCLAW_SEQID_IM_SNOWCLAW || obj->anim.romDefNo == SNOWCLAW_SEQID_IM_SNOWCLAW2)
                {
                    (*gObjectTriggerInterface)->runSequence(0, (void*)obj, 1);
                }
                else
                {
                    (*gObjectTriggerInterface)->runSequence(0, (void*)obj, 3);
                }
                s->flag6 = 1;
                s->particleAlpha = 1.0f;
                s->velX =
                    0.1f * mathSinf(3.1415927f * (f32)obj->anim.rotX / 32768.0f);
                s->velY = 0.01f * randomGetRange(0x28, 0x64);
                s->velZ =
                    0.1f * mathCosf(3.1415927f * (f32)obj->anim.rotX / 32768.0f);
                player = playerGetFocusObject(Obj_GetPlayerObject());
                if (player != 0)
                {
                    int* sub3 = player->extra;
                    if (sub3 != 0)
                    {
                        *(f32*)((char*)sub3 + 0x4c4) = 3000.0f;
                    }
                }
            }
            else
            {
                ObjAnim_SetCurrentMove(obj, s->moveIdBase + 9, 0.0f, 0);
                s->unk30 = 0.004f;
            }
        }
    }
    if (s->mount != NULL &&
        SNOWCLAW_MOUNT_INTERFACE(s->mount)->getRiderMode(s->mount) == 2)
    {
        snowclaw_syncMountTransform(obj, s->mount, 0, 0, 0, 0, 0, 0, 0);
    }
    hitCooldown = s->hitCooldown;
    if (hitCooldown >= 0)
    {
        s->hitCooldown = hitCooldown - framesThisStep;
    }
}

void snowclaw_update(GameObject* obj)
{
    SnowclawState* s;
    GameObject** objects;
    int objectCount;
    int i;
    int targetType;
    GameObject* sub;
    int choice;
    int turnSign;
    int pulseIndex;
    s8 healthState;
    const u32* pulseTable;
    u32 pulseTypes[4];
    u32 pulseModes[4];
    u32* pulseType;
    u32* pulseMode;
    f32 pulseVec[3];
    SnowClawDropObjectTable dropTable;
    const SnowClawPulse4* pulseSrc;

    pulseTable = gSnowClawPulseTable;
    s = obj->extra;
    if (((SnowclawState*)obj->extra)->hitFlag != 0 && ((SnowclawState*)obj->extra)->flag6 != 0)
    {
        s->particleAlpha = 0.0f;
    }
    s->hitFlag = 0;
    s->mountAlpha = 0xff;

    healthState = s->health;
    if (healthState < 0)
    {
        if (healthState < -10)
        {
            obj->anim.flags |= OBJANIM_FLAG_HIDDEN;
            s->mount->anim.flags |= OBJANIM_FLAG_HIDDEN;
            ObjHits_DisableObject(obj);
            ObjHits_DisableObject(s->mount);
        }
        else
        {
            s->health -= 1;
        }
        return;
    }

    ObjHits_EnableObject(obj);
    sub = s->mount;
    if (sub != NULL)
    {
        ObjHits_EnableObject(sub);
    }

    dropTable = *(const SnowClawDropObjectTable*)(pulseTable + 8);
    if (s->dropIndex != s->dropIndexApplied)
    {
        if (obj->childObjs[0] != NULL)
        {
            Obj_FreeObject((GameObject*)obj->childObjs[0]);
            obj->childObjs[0] = NULL;
            obj->childCount = 0;
        }
        if (s->dropIndex > 0 && (u8)Obj_CanSetupObject() != 0)
        {
            obj->childObjs[0] =
                objSetupObject(Obj_AllocObjectSetup(
                                         0x18, dropTable.objectIds[s->dropIndex]), 4,
                                     obj->anim.mapEventSlot, -1, obj->anim.parent);
            obj->childCount = 1;
        }
        s->dropIndexApplied = s->dropIndex;
    }

    if (s->mount == NULL)
    {
        objects = objGetAllOfType(VEHICLE_OBJECT_GROUP, &objectCount);
        targetType = seqPairTableLookup(gSnowClawMoveTable, 6, obj->anim.romDefNo);
        for (i = 0; i < objectCount; i++)
        {
            if (objects[i]->anim.romDefNo == targetType)
            {
                s->mount = objects[i];
                i = objectCount;
            }
        }
    }

    if (mainGetBit(*s->moveTablePtr) == 0)
    {
        return;
    }

    sub = s->mount;
    if (sub != 0 && s->health != 0 &&
        obj->anim.currentMove == s->moveIdBase &&
        SnowBike_isAtRankGate(sub) != 0 && timerCountDown(&s->attackTimer) != 0)
    {
        choice = randomGetRange(0, 1);
        s->pendingMoveId = s->moveIdBase + 5;
        turnSign = (u32)(s16)Obj_GetYawDeltaToObject(obj, Obj_GetPlayerObject(), 0) >> 31;
        if (turnSign == 0 || obj->anim.romDefNo == SNOWCLAW_SEQID_CR_SNOWCLAW)
        {
            ObjAnim_SetCurrentMove(obj, s->moveIdBase + 6, 0.0f, 0);
            snowclaw_spawnDropBomb(s->mount, obj, (u8)choice, 2);
        }
        else
        {
            ObjAnim_SetCurrentMove(obj, s->moveIdBase + 5, 0.0f, 0);
            snowclaw_spawnDropBomb(s->mount, obj, (u8)choice, 0);
        }
        s16toFloat(&s->attackTimer,
                   gSnowClawAttackTimerByRank[SnowBike_getRouteRank(s->mount) - 1]);
    }

    sub = s->mount;
    if (sub != NULL)
    {
        snowclaw_updateMountAttack(obj, sub);
    }

    if (randomChanceOneIn(0x12c) != 0)
    {
        Sfx_PlayFromObject(obj, SFXTRIG_id_2e5);
    }

    if (s->health < 4)
    {
        *(SnowClawPulse4*)pulseTypes = *(const SnowClawPulse4*)&pulseTable[0];
        pulseSrc = (const SnowClawPulse4*)&pulseTable[4];
        *(SnowClawPulse4*)pulseModes = *pulseSrc;
        pulseIndex = 3 - s->health;
        i = s->tickCounter++;
        if ((i % gSnowClawPulseInterval) != 0)
        {
            pulseVec[0] = 0.0f;
            pulseVec[1] = gSnowClawPulseOffsetY;
            pulseVec[2] = 0.0f;
            pulseType = &pulseTypes[pulseIndex];
            pulseMode = &pulseModes[pulseIndex];
            objfx_spawnPulseBurst(obj, gSnowClawPulseScale, (u8)*pulseType, (u8)*pulseMode, 0, pulseVec);
        }
    }
}

void snowclaw_init(GameObject* obj, SnowclawPlacement* placement)
{
    u8* table;
    SnowclawState* inner;

    table = (u8*)(int)gSnowClawMoveTable;
    obj->animEventCallback = snowclaw_animEventCallback;
    if (obj->anim.modelState != NULL) {
        obj->anim.modelState->flags |= OBJ_MODEL_STATE_UNREAD_4000;
        obj->anim.modelState->shadowTintA = 0x64;
        obj->anim.modelState->shadowTintB = 0x96;
    }
    inner = obj->extra;
    inner->mount = NULL;
    inner->dropIndex = placement->dropIndex;
    inner->health = 4;
    inner->hitCooldown = -1;
    switch (obj->anim.romDefNo) {
    case 0x16d:
    case 0x170:
    default:
        inner->moveTablePtr = (s16*)(table + 0x58);
        inner->moveIdBase = 0x100;
        break;
    case 0x389:
    case 0x38a:
    case 0x4d3:
        inner->moveTablePtr = (s16*)(table + 0x54);
        inner->moveIdBase = 0x400;
    case 0x3e8:
        inner->moveTablePtr = (s16*)(table + 0x5c);
        inner->moveIdBase = 0x400;
        break;
    }
    inner->tickCounter = 0;
    inner->attackDelay = 0x64;
    inner->unk30 = 0.006f;
    storeZeroToFloatParam(&inner->attackTimer);
    s16toFloat(&inner->attackTimer, * (int*)(table + 0x3c));
    seqPairTablePrepare((u8*)(int)gSnowClawMoveTable, 6);
    gSnowClawDropBombAngle = 0x96;
    inner->b0 = 0;
}

void snowclaw_release(void)
{
}

void snowclaw_initialise(void)
{
}
