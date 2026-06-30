#include "main/obj_placement.h"
#include "main/game_object.h"
#include "main/audio/sfx_ids.h"
#include "main/objfx.h"
#include "main/screen_transition.h"
#include "main/dll/player_80295318_shared.h"
#include "main/dll/player_state.h"
#include "main/dll/player.h"
#include "main/dll/DIM/dll_802B9780_shared.h"

void fn_802960E4(void)
{
}

int fn_80297498(void) { return 0x0; }

int fn_80297824(void) { return 0x0; }

static inline int* Player_GetActiveModel(int obj)
{
    ObjAnimComponent* objAnim = (ObjAnimComponent*)obj;
    return (int*)objAnim->banks[objAnim->bankIndex];
}

static inline ObjHitsPriorityState* Player_GetObjHitsState(int obj)
{
    return (ObjHitsPriorityState*)((GameObject*)obj)->anim.hitReactState;
}

int fn_80295CE4(int obj)
{
    PlayerState* inner = ((GameObject*)obj)->extra;
    return (inner->flags3F4 >> 6) & 1;
}

void fn_802960E8(void* playerObj, s16 effectId)
{
    PlayerState* inner = ((GameObject*)playerObj)->extra;
    inner->pendingBoneEffectId = effectId;
}

void fn_802960F4(int obj, int* out)
{
    int inner = *(int*)&((GameObject*)obj)->extra;
    if (out == NULL)
    {
        return;
    }
    *out = (int)((char*)inner + 0x3c4);
}

f32 fn_8029610C(int obj)
{
    PlayerState* inner = ((GameObject*)obj)->extra;
    return inner->baddie.animSpeedA;
}

int fn_80296118(int obj)
{
    int inner = *(int*)&((GameObject*)obj)->extra;
    return *(int*)&((PlayerState*)inner)->baddie.targetObj;
}

f32 fn_80296214(int obj)
{
    PlayerState* inner = ((GameObject*)obj)->extra;
    return inner->verticalVel;
}

void fn_80296220(int obj, f32 v)
{
    PlayerState* inner = ((GameObject*)obj)->extra;
    inner->verticalVel = v;
}

int fn_8029622C(int obj)
{
    return (((GameObject*)obj)->objectFlags & 0x1000) == 0;
}

int fn_80296448(int obj)
{
    PlayerState* inner = ((GameObject*)obj)->extra;
    return (inner->flags3F0 >> 5) & 1;
}

int fn_80296464(int obj)
{
    PlayerState* inner = ((GameObject*)obj)->extra;
    return inner->flags360 & 1;
}

int fn_80295BF0(int obj)
{
    PlayerState* inner = ((GameObject*)obj)->extra;
    return inner->curAnimId != 0x44;
}

int fn_80295C0C(int obj)
{
    PlayerState* inner = ((GameObject*)obj)->extra;
    return ((inner->flags3F0 >> 1) & 1) == 0;
}

int fn_80295C24(int obj)
{
    PlayerState* inner = ((GameObject*)obj)->extra;
    return inner->targetSuppressTimer > lbl_803E7EA4;
}

int fn_80295C40(int obj)
{
    PlayerState* inner = ((GameObject*)obj)->extra;
    return inner->waterDepth > lbl_803E7ED4;
}

int fn_80295CBC(int obj)
{
    PlayerState* inner = ((GameObject*)obj)->extra;
    return inner->baddie.controlMode == 0x13;
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

int fn_8029630C(int obj)
{
    PlayerState* inner = ((GameObject*)obj)->extra;
    return inner->baddie.controlMode != 0x26;
}

int fn_8029669C(int obj)
{
    PlayerState* inner = ((GameObject*)obj)->extra;
    return inner->baddie.controlMode == 7;
}

int fn_802966B4(int obj)
{
    PlayerState* inner = ((GameObject*)obj)->extra;
    return inner->baddie.controlMode == 6;
}

void fn_80296BBC(int obj)
{
    int inner = *(int*)&((GameObject*)obj)->extra;
    *(u32*)&((PlayerState*)inner)->flags360 &= ~2LL;
}

void fn_80296C6C(int obj, int flag)
{
    int inner = *(int*)&((GameObject*)obj)->extra;
    ((ByteFlags*)((char*)inner + 0x3f3))->b02 = flag;
}

void fn_80297254(int obj)
{
    int inner = *(int*)&((GameObject*)obj)->extra;
    ((ByteFlags*)((char*)inner + 0x3f2))->b20 = 1;
}

void fn_8029726C(int obj)
{
    int inner = *(int*)&((GameObject*)obj)->extra;
    ((ByteFlags*)((char*)inner + 0x3f2))->b40 = 1;
}

void fn_80297284(int obj)
{
    int inner = *(int*)&((GameObject*)obj)->extra;
    ((ByteFlags*)((char*)inner + 0x3f2))->b80 = 1;
}

int fn_802966CC(int obj)
{
    return *(int*)&((GameObject*)obj)->childObjs[0];
}

void fn_80296B70(int v)
{
    gPlayerPendingHealth = v;
}

f32 fn_802966F4(int obj)
{
    PlayerState* inner = ((GameObject*)obj)->extra;
    return inner->probeHitDist;
}

int fn_802972A8(int obj)
{
    PlayerState* inner = ((GameObject*)obj)->extra;
    return inner->focusObject;
}

int EmissionController_IsLingering(int obj)
{
    PlayerState* inner = ((GameObject*)obj)->extra;
    return inner->emissionState;
}

u32 playerGetStateFlag310(int obj)
{
    int inner = *(int*)&((GameObject*)obj)->extra;
    return *(int*)((char*)inner + 0x310);
}

int fn_80296A14(int obj)
{
    PlayerState* inner = ((GameObject*)obj)->extra;
    return *(s16*)((char*)inner->playerStatus + 4);
}

int fn_80296A8C(int obj)
{
    PlayerState* inner = ((GameObject*)obj)->extra;
    return *(s16*)((char*)inner->playerStatus + 6);
}

int fn_80296C4C(int obj)
{
    PlayerState* inner = ((GameObject*)obj)->extra;
    return (inner->flags3F3 >> 1) & 1;
}

int fn_80296C5C(int obj)
{
    PlayerState* inner = ((GameObject*)obj)->extra;
    return (inner->flags3F3 >> 2) & 1;
}

int fn_8029656C(int obj, f32* out)
{
    PlayerState* inner = ((GameObject*)obj)->extra;
    *out = inner->unk77C;
    return inner->unk8C4;
}

int fn_80296AD4(int obj)
{
    PlayerState* inner = ((GameObject*)obj)->extra;
    return *(s8*)((char*)inner->playerStatus + 1);
}

int fn_80296AE8(int obj)
{
    PlayerState* inner = ((GameObject*)obj)->extra;
    return *(s8*)((char*)inner->playerStatus);
}

int playerGetMoney(void* player)
{
    PlayerState* inner = ((GameObject*)player)->extra;
    return *(u8*)((char*)inner->playerStatus + 8);
}

int playerIsDisguised(int obj)
{
    PlayerState* inner = ((GameObject*)obj)->extra;
    return (inner->flags3F3 >> 3) & 1;
}

int objGetAnimStateFlags(int obj, int flag)
{
    PlayerState* inner = ((GameObject*)obj)->extra;
    return *(s8*)((char*)inner->playerStatus + 2) & flag;
}

int objGetAnimState80A(void* obj)
{
    void* inner = ((GameObject*)obj)->extra;
    if (inner != NULL)
    {
        return ((PlayerState*)inner)->animState;
    }
    return 0;
}

void cameraGetPrevPos2(int obj, f32* x, f32* y, f32* z)
{
    int inner = *(int*)&((GameObject*)obj)->extra;
    *x = *(f32*)((char*)inner + 0x24);
    *y = *(f32*)((char*)inner + 0x28);
    *z = *(f32*)((char*)inner + 0x2c);
}

int fn_802966D4(int obj, int* out)
{
    PlayerState* inner = ((GameObject*)obj)->extra;
    *out = inner->heldObj;
    return inner->heldObj != 0;
}

int fn_80296C2C(int obj)
{
    PlayerState* inner = ((GameObject*)obj)->extra;
    return *(s8*)((char*)inner->playerStatus) > 0;
}

void fn_80298924(int obj)
{
    ObjHits_SyncObjectPositionIfDirty(obj);
}

void fn_802A00C0(int obj)
{
    ObjHits_SyncObjectPositionIfDirty(obj);
}

void fn_802A49A8(int obj)
{
    PlayerState* inner = ((GameObject*)obj)->extra;
    inner->moveParams = (int)lbl_80333250;
    inner->moveAnimTable = (int)gPlayerMoveTableA;
}

void fn_802B6F48(int obj)
{
    playerInitFuncPtrs(obj);
}

int fn_802969F0(int obj)
{
    PlayerState* inner = ((GameObject*)obj)->extra;
    if (((ByteFlags*)((char*)inner + 0x3f1))->b01)
    {
        return inner->surfaceType;
    }
    return -1;
}

void fn_802961D4(int obj, int v)
{
    PlayerState* inner = ((GameObject*)obj)->extra;
    ((GameObject*)obj)->anim.rotX = v;
    inner->targetYaw = v;
    inner->yaw = v;
    *(u32*)&((PlayerState*)inner)->flags360 |= 0x800000LL;
}

void fn_80296B78(int obj, int p2)
{
    fn_802AB38C(obj, *(int*)&((GameObject*)obj)->extra, p2);
}

int fn_802974A0(int obj, int state, f32 fv)
{
    PlayerState* inner = ((GameObject*)obj)->extra;
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
        *(u32*)&((PlayerState*)inner)->flags360 |= 0x800000LL;
        ObjHits_SyncObjectPositionIfDirty(obj);
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
                objThrowFn_80182504((int)sub);
            }
            else
            {
                objSaveFn_800ea774((int)sub);
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
        ObjAnim_SetCurrentMove(obj, 0x12, lbl_803E7EA4, 1);
    }
    {
        f32 v = lbl_803E7EE0 + inner->verticalVel;
        f32 w;
        f32 clamped;
        w = v * lbl_803E7E98;
        clamped = (w < lbl_803E7EA4) ? lbl_803E7EA4 : ((w > lbl_803E7EE0) ? lbl_803E7EE0 : w);
        ObjAnim_SetMoveProgress(lbl_803E7EE0 - clamped, (ObjAnimComponent*)obj);
    }
    (*(void (*)(int, int, f32, f32, int))(*(int*)(*gPlayerInterface + 0x44)))(
        obj, state, fv, lbl_803E7EE0, inner->inputHeading);
    ((PlayerState*)state)->baddie.velSmoothTime = lbl_803E7EF4;
    ((PlayerState*)state)->baddie.moveSpeed = lbl_803E7EF8;
    ((GameObject*)obj)->anim.velocityY = inner->verticalVel * fv;
    if (((PlayerState*)state)->baddie.inputMagnitude > lbl_803E7EFC)
    {
        f32 ryaw = (f32)inner->targetYawRate * fv;
        inner->targetYaw =
            (s16)((f32)(s16)inner->targetYaw +
                  gPlayerDegToBinAngle * (ryaw * lbl_803E7F04));
        inner->yaw = inner->targetYaw;
    }
    fn_802ABAE8(obj, state, (int)inner, lbl_803E7EA4);
    return 0;
}

void fn_8029782C(int obj)
{
    PlayerState* inner = ((GameObject*)obj)->extra;
    *(u32*)&((PlayerState*)inner)->flags360 |= 0x800000LL;
    ((ByteFlags*)((char*)inner + 0x3f6))->b20 = 0;
}

int objIsCurModelNotZero(void* obj)
{
    if (obj != NULL)
    {
        return ((ObjAnimComponent*)obj)->bankIndex != 0;
    }
    return 0;
}

int playerHasSpell(int obj, int spell)
{
    PlayerState* inner = ((GameObject*)obj)->extra;
    if ((u32)spell > 0xb)
    {
        return 0;
    }
    return inner->staffUnlockedFlags & (1 << spell);
}

int fn_80295C5C(int obj)
{
    PlayerState* inner = ((GameObject*)obj)->extra;
    return inner->baddie.controlMode == 0x36 &&
        ((ByteFlags*)((char*)inner + 0x3f3))->b10;
}

int objFn_80296700(int obj)
{
    PlayerState* inner = ((GameObject*)obj)->extra;
    if (inner->staffGrown != 0 && inner->staffActionRequest != 0)
    {
        return 1;
    }
    return 0;
}

void fn_802961A4(int obj, int* out1, f32* out2)
{
    PlayerState* inner = ((GameObject*)obj)->extra;
    *out1 = ((GameObject*)obj)->anim.currentMove;
    if (inner->baddie.controlMode == 0x26)
    {
        *out2 = inner->unk7D8;
    }
    else
    {
        *out2 = inner->chargeLevel;
    }
}

void playerLock(int obj, int lock)
{
    PlayerState* inner = ((GameObject*)obj)->extra;
    if (lock != 0)
    {
        *(u32*)&((PlayerState*)inner)->flags360 |= 0x200000LL;
    }
    else
    {
        *(u32*)&((PlayerState*)inner)->flags360 &= ~0x200000LL;
    }
}

void fn_80296A9C(int obj, int delta)
{
    PlayerState* inner = ((GameObject*)obj)->extra;
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

void fn_80296518(int obj, int flag, int set)
{
    PlayerState* inner = ((GameObject*)obj)->extra;
    if (set != 0)
    {
        *(s8*)((char*)inner->playerStatus + 2) |= flag;
    }
    else
    {
        *(s8*)((char*)inner->playerStatus + 2) &= ~flag;
    }
}

u8 fn_80296414(int obj, int otherObj, u8* out)
{
    PlayerState* inner = ((GameObject*)obj)->extra;
    *out = inner->surfaceDir;
    return inner->baddie.controlMode == 0x1c &&
        *(u32*)&((PlayerState*)inner)->contactObject == (u32)otherObj;
}

int fn_80295C88(int obj)
{
    f32 dist = lbl_803E7EDC;
    return ObjGroup_FindNearestObject(0x30, obj, &dist);
}

void fn_8029697C(int obj, s16* out1, s16* out2)
{
    PlayerState* inner = ((GameObject*)obj)->extra;
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

void playerAddHealth(int obj, int amount)
{
    PlayerState* inner = ((GameObject*)obj)->extra;
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

void playerAddRemoveMagic(int obj, int amount)
{
    PlayerState* inner = ((GameObject*)obj)->extra;
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
        Sfx_PlayFromObject(0, SFXmammoth_dirtstep);
    }
}

void fn_802994A4(int obj)
{
    *(s16*)((char*)*(int*)&((GameObject*)obj)->extra + 0x80a) = -1;
    ObjHits_SyncObjectPositionIfDirty(obj);
}

int objFn_802962b4(int obj)
{
    PlayerState* inner = ((GameObject*)obj)->extra;
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

int fn_80296240(int obj)
{
    PlayerState* inner = ((GameObject*)obj)->extra;
    ByteFlags* f = (ByteFlags*)((char*)inner + 0x3f0);
    s16 s;
    if (f->b04 || f->b08 || f->b20 || f->b10 ||
        ((ByteFlags*)((char*)inner + 0x3f3))->b08)
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

void fn_80296474(int obj, int spell, int set)
{
    PlayerState* inner = ((GameObject*)obj)->extra;
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
    GameBit_Set(gPlayerSpellGameBits[spell], set);
}

void fn_802A4B4C(int obj)
{
    PlayerState* inner = ((GameObject*)obj)->extra;
    void* p = *(void**)((char*)inner + 0x7f8);
    if (p != NULL)
    {
        ((GameObject*)p)->unkF8 = 1;
    }
    *(u32*)&((PlayerState*)inner)->flags360 |= 0x800000LL;
}

void fn_802985AC(int obj)
{
    PlayerState* inner = ((GameObject*)obj)->extra;
    ((ByteFlags*)((char*)inner + 0x3f4))->b20 = 0;
    inner->buttonHoldTimer = lbl_803E7EA4;
    ((ByteFlags*)((char*)inner + 0x3f3))->b10 = 0;
    inner->animState = -1;
    ObjHits_SyncObjectPositionIfDirty(obj);
}

int fn_8029F9D4(int p1, int state)
{
    if (GameBit_Get(0x2d0))
    {
        *(int*)&((PlayerState*)state)->baddie.unk308 = (int)fn_802A514C;
        return -1;
    }
    return 0;
}

int fn_80297748(int p1, int obj)
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

int fn_8029852C(int obj, int state)
{
    int inner = *(int*)&((GameObject*)obj)->extra;
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

int fn_802A2E8C(int obj, int targetState)
{
    PlayerState* inner = ((GameObject*)obj)->extra;
    f32 fz;
    *(u32*)&((PlayerState*)inner)->flags360 &= ~2LL;
    *(u32*)&((PlayerState*)inner)->flags360 |= 0x2000LL;
    *(int*)((char*)targetState + 4) |= 0x100000;
    fz = lbl_803E7EA4;
    ((PlayerState*)targetState)->baddie.animSpeedA = fz;
    ((PlayerState*)targetState)->baddie.animSpeedB = fz;
    *(int*)((char*)targetState + 0) |= 0x200000;
    ((GameObject*)obj)->anim.velocityX = fz;
    ((GameObject*)obj)->anim.velocityZ = fz;
    return 0;
}

int fn_802A3F24(int obj, int state)
{
    int inner = *(int*)&((GameObject*)obj)->extra;
    f32 fz;
    int flagsBase;
    if (*(s8*)&((PlayerState*)state)->baddie.moveJustStartedA != 0)
    {
        *(s16*)((char*)state + 0x278) = 9;
        ((PlayerState*)inner)->stateHandler = 0;
    }
    flagsBase = *(int*)&((GameObject*)obj)->extra;
    *(u32*)((char*)flagsBase + 0x360) &= ~2LL;
    *(u32*)((char*)flagsBase + 0x360) |= 0x2000LL;
    *(int*)((char*)state + 4) |= 0x100000;
    fz = lbl_803E7EA4;
    ((PlayerState*)state)->baddie.animSpeedA = fz;
    ((PlayerState*)state)->baddie.animSpeedB = fz;
    *(int*)((char*)state + 0) |= 0x200000;
    ((GameObject*)obj)->anim.velocityX = fz;
    ((GameObject*)obj)->anim.velocityZ = fz;
    *(int*)((char*)state + 4) |= 0x8000000;
    ((GameObject*)obj)->anim.velocityY = fz;
    switch (((GameObject*)obj)->anim.currentMove)
    {
    case 0x419:
        if (*(s8*)&((PlayerState*)state)->baddie.moveDone != 0)
        {
            ObjAnim_SetCurrentMove(obj, lbl_80332EF0[6], fz, 0);
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
        ObjAnim_SetCurrentMove(obj, 0x419, fz, 1);
        ((PlayerState*)state)->baddie.moveSpeed = lbl_803E7E90;
        ((PlayerState*)inner)->targetYaw =
            (s16)getAngle(((PlayerState*)inner)->unk5C4, ((PlayerState*)inner)->unk5CC);
        ((PlayerState*)inner)->yaw = ((PlayerState*)inner)->targetYaw;
        k = lbl_803E7F10;
        ((GameObject*)obj)->anim.worldPosX =
            k * ((PlayerState*)inner)->unk5C4 + *(f32*)((int)inner + 0x5d4);
        ((GameObject*)obj)->anim.worldPosY =
            ((PlayerState*)inner)->unk5AC - ((PlayerState*)inner)->unk874;
        ((GameObject*)obj)->anim.worldPosZ =
            k * ((PlayerState*)inner)->unk5CC + *(f32*)((int)inner + 0x5dc);
        Obj_TransformWorldPointToLocal(((GameObject*)obj)->anim.worldPosX, ((GameObject*)obj)->anim.worldPosY,
                                       ((GameObject*)obj)->anim.worldPosZ, &((GameObject*)obj)->anim.localPosX,
                                       &((GameObject*)obj)->anim.localPosY, &((GameObject*)obj)->anim.localPosZ,
                                       *(int*)&((GameObject*)obj)->anim.parent);
        objHitDetectFn_80062e84(obj, ((PlayerState*)inner)->groundObject, 1);
        if (*(void**)((char*)inner + 0x4c4) != NULL)
        {
            Obj_TransformWorldPointToLocal(*(f32*)((int)inner + 0x5d4), *(f32*)((int)inner + 0x5d8),
                                           *(f32*)((int)inner + 0x5dc), (f32*)((char*)inner + 0x5d4),
                                           (f32*)((char*)inner + 0x5d8), (f32*)((char*)inner + 0x5dc),
                                           ((PlayerState*)inner)->groundObject);
            Obj_TransformWorldPointToLocal(*(f32*)((int)inner + 0x5ec), *(f32*)((int)inner + 0x5f0),
                                           *(f32*)((int)inner + 0x5f4), (f32*)((char*)inner + 0x5ec),
                                           (f32*)((char*)inner + 0x5f0), (f32*)((char*)inner + 0x5f4),
                                           ((PlayerState*)inner)->groundObject);
            Obj_TransformWorldPointToLocal(*(f32*)((int)inner + 0x5f8), *(f32*)((int)inner + 0x5fc),
                                           *(f32*)((int)inner + 0x600), (f32*)((char*)inner + 0x5f8),
                                           (f32*)((char*)inner + 0x5fc), (f32*)((char*)inner + 0x600),
                                           ((PlayerState*)inner)->groundObject);
            ((PlayerState*)inner)->unk5AC =
                ((PlayerState*)inner)->unk5AC - *(f32*)((char*)((PlayerState*)inner)->groundObject + 0x10);
            ((PlayerState*)inner)->unk5B0 =
                ((PlayerState*)inner)->unk5B0 - *(f32*)((char*)((PlayerState*)inner)->groundObject + 0x10);
            ((PlayerState*)inner)->unk609 = 0;
        }
        break;
    }
    }
    fn_802AB5A4(obj, inner + 4, 5);
    return 0;
}

int fn_802A36EC(int obj, int state)
{
    PlayerState* inner = ((GameObject*)obj)->extra;
    f32 fz;
    *(u32*)&((PlayerState*)inner)->flags360 &= ~2LL;
    *(u32*)&((PlayerState*)inner)->flags360 |= 0x2000LL;
    *(int*)((char*)state + 4) |= 0x100000;
    fz = lbl_803E7EA4;
    ((PlayerState*)state)->baddie.animSpeedA = fz;
    ((PlayerState*)state)->baddie.animSpeedB = fz;
    *(int*)((char*)state + 0) |= 0x200000;
    ((GameObject*)obj)->anim.velocityX = fz;
    ((GameObject*)obj)->anim.velocityZ = fz;
    *(int*)((char*)state + 4) |= 0x8000000;
    ((GameObject*)obj)->anim.velocityY = fz;
    *(int*)((char*)state + 0) |= 0x200000;
    switch (gPlayerCurrentMoveId)
    {
    case 0x12:
    case 0x1a:
        if (*(int*)&((PlayerState*)state)->baddie.eventFlags & 1)
        {
            Sfx_PlayFromObject(
                obj, (u16)(inner->characterId == 0 ? 0x398 : 0x1d));
        }
        if ((((u32)inner->flags3F0 >> 5) & 1) || gPlayerCurrentMoveId == 0x1a)
        {
            if (*(int*)&((PlayerState*)state)->baddie.eventFlags & 0x80)
            {
                Sfx_PlayFromObject(obj, SFXen_littletink22);
            }
        }
    case 0xe:
    case 0x16:
        if (*(s8*)&((PlayerState*)state)->baddie.moveDone != 0)
        {
            *(int*)((char*)state + 4) &= ~0x100000;
            fn_802AB5A4(obj, (int)inner, 5);
            *(u32*)&((PlayerState*)inner)->flags360 |= 0x800000LL;
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
            if (inner->unk606 == 0x10)
            {
                gPlayerCurrentMoveId = 0x1a;
                lo = lbl_803E8040;
                hi = lbl_803E8044;
                ((PlayerState*)state)->baddie.moveSpeed = lbl_803E7F28;
            }
            else if (inner->unk5A8 >= lbl_803E8040)
            {
                gPlayerCurrentMoveId = 0xe;
                lo = lbl_803E8040;
                hi = lbl_803E7F30;
                ((PlayerState*)state)->baddie.moveSpeed = lbl_803E7F0C;
            }
            else if (inner->unk5A8 >= lbl_803E8048)
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
            t = (inner->unk5A8 - lo) / (hi - lo);
            t = t * lbl_803E7FAC;
            r = (t < lbl_803E7EA4) ? lbl_803E7EA4 : ((t > lbl_803E7FAC) ? lbl_803E7FAC : t);
            inner->unk604 = (s16)r;
            ObjAnim_SetCurrentMove(obj, lbl_80332EF0[gPlayerCurrentMoveId], lbl_803E7EA4, 0);
            ObjAnim_SetCurrentEventStepFrames((ObjAnimComponent*)obj, 0xa);
            inner->targetYaw = inner->yaw =
                (s16)getAngle(inner->unk5C4, inner->unk5CC);
            Obj_TransformWorldPointToLocal(((GameObject*)obj)->anim.worldPosX, ((GameObject*)obj)->anim.worldPosY,
                                           ((GameObject*)obj)->anim.worldPosZ, (f32*)((char*)obj + 0xc),
                                           (f32*)((char*)obj + 0x10), (f32*)((char*)obj + 0x14),
                                           *(int*)&((GameObject*)obj)->anim.parent);
            objHitDetectFn_80062e84(obj, inner->groundObject, 1);
            inner->moveStartX = ((GameObject*)obj)->anim.localPosX;
            inner->moveStartY = ((GameObject*)obj)->anim.localPosY;
            inner->moveStartZ = ((GameObject*)obj)->anim.localPosZ;
            if (*(void**)((char*)inner + 0x4c4) != NULL)
            {
                Obj_TransformWorldPointToLocal(*(f32*)((int)inner + 0x5d4), *(f32*)((int)inner + 0x5d8),
                                               *(f32*)((int)inner + 0x5dc), (f32*)((char*)inner + 0x5d4),
                                               (f32*)((char*)inner + 0x5d8), (f32*)((char*)inner + 0x5dc),
                                               inner->groundObject);
                Obj_TransformWorldPointToLocal(*(f32*)((int)inner + 0x5ec), *(f32*)((int)inner + 0x5f0),
                                               *(f32*)((int)inner + 0x5f4), (f32*)((char*)inner + 0x5ec),
                                               (f32*)((char*)inner + 0x5f0), (f32*)((char*)inner + 0x5f4),
                                               inner->groundObject);
                Obj_TransformWorldPointToLocal(*(f32*)((int)inner + 0x5f8), *(f32*)((int)inner + 0x5fc),
                                               *(f32*)((int)inner + 0x600), (f32*)((char*)inner + 0x5f8),
                                               (f32*)((char*)inner + 0x5fc), (f32*)((char*)inner + 0x600),
                                               inner->groundObject);
                inner->unk5AC =
                    inner->unk5AC - *(f32*)((char*)inner->groundObject + 0x10);
                inner->unk5B0 =
                    inner->unk5B0 - *(f32*)((char*)inner->groundObject + 0x10);
                inner->unk609 = 0;
            }
            break;
        }
    }
    ((GameObject*)obj)->anim.localPosX =
        ((GameObject*)obj)->anim.currentMoveProgress *
        (((PlayerState*)inner)->moveEndX - inner->moveStartX) +
        inner->moveStartX;
    ((GameObject*)obj)->anim.localPosY =
        ((GameObject*)obj)->anim.currentMoveProgress *
        (((PlayerState*)inner)->moveEndY - inner->moveStartY) +
        inner->moveStartY;
    ((GameObject*)obj)->anim.localPosZ =
        ((GameObject*)obj)->anim.currentMoveProgress *
        (((PlayerState*)inner)->moveEndZ - inner->moveStartZ) +
        inner->moveStartZ;
    Object_ObjAnimSetSecondaryBlendMove(
        (ObjAnimComponent*)obj, lbl_80332EF0[gPlayerCurrentMoveId + 2], inner->unk604);
    fn_802AB5A4(obj, (int)inner, 5);
    return 0;
}

int fn_802A3B04(int obj, int state)
{
    int inner = *(int*)&((GameObject*)obj)->extra;
    f32 fz;
    if (*(s8*)&((PlayerState*)state)->baddie.moveJustStartedA != 0)
    {
        void* sub;
        Sfx_PlayFromObject(obj, (u16)(((PlayerState*)inner)->characterId == 0 ? 0x2cb : 0x29));
        *(s16*)((char*)state + 0x278) = 0xa;
        ((PlayerState*)inner)->stateHandler = 0;
        ((PlayerState*)inner)->isHoldingObject = 0;
        sub = *(void**)((char*)inner + 0x7f8);
        if (sub != NULL)
        {
            s16 id = ((GameObject*)sub)->anim.seqId;
            if (id == 0x3cf || id == 0x662)
            {
                objThrowFn_80182504((int)sub);
            }
            else
            {
                objSaveFn_800ea774((int)sub);
            }
            *(s16*)((char*)((PlayerState*)inner)->heldObj + 0x6) &= ~0x4000;
            *(int*)((char*)((PlayerState*)inner)->heldObj + 0xf8) = 0;
            ((PlayerState*)inner)->heldObj = 0;
        }
    }
    fz = lbl_803E7EA4;
    ((PlayerState*)inner)->probeHitDist = fz;
    {
        int e = *(int*)&((GameObject*)obj)->extra;
        *(u32*)((char*)e + 0x360) &= ~2LL;
        *(u32*)((char*)e + 0x360) |= 0x2000LL;
    }
    *(int*)((char*)state + 4) |= 0x100000;
    ((PlayerState*)state)->baddie.animSpeedA = fz;
    ((PlayerState*)state)->baddie.animSpeedB = fz;
    *(int*)((char*)state + 0) |= 0x200000;
    ((GameObject*)obj)->anim.velocityX = fz;
    ((GameObject*)obj)->anim.velocityZ = fz;
    *(int*)((char*)state + 4) |= 0x8000000;
    ((GameObject*)obj)->anim.velocityY = fz;
    switch (((GameObject*)obj)->anim.currentMove)
    {
    case 0xd:
    case 0x22:
    {
        f32 c;
        f32 d = ((GameObject*)obj)->anim.currentMoveProgress / lbl_803E7F44;
        c = (d < lbl_803E7EA4) ? lbl_803E7EA4 : ((d > lbl_803E7EE0) ? lbl_803E7EE0 : d);
        ((GameObject*)obj)->anim.localPosX =
            c * (((PlayerState*)inner)->moveEnd2X - ((PlayerState*)inner)->moveStartX) +
            ((PlayerState*)inner)->moveStartX;
        ((GameObject*)obj)->anim.localPosY =
            ((PlayerState*)inner)->moveStartY -
            ((GameObject*)obj)->anim.currentMoveProgress *
            (((PlayerState*)inner)->moveStartY -
                (((PlayerState*)inner)->unk5AC - ((PlayerState*)inner)->unk874));
        ((GameObject*)obj)->anim.localPosZ =
            c * (((PlayerState*)inner)->moveEnd2Z - ((PlayerState*)inner)->moveStartZ) +
            ((PlayerState*)inner)->moveStartZ;
        if (*(s8*)&((PlayerState*)state)->baddie.moveDone != 0)
        {
            ObjAnim_SetCurrentMove(obj, lbl_80332EF0[6], lbl_803E7EA4, 0);
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
        int d = (u16)getAngle(((PlayerState*)inner)->unk5C4, ((PlayerState*)inner)->unk5CC) -
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
        Obj_TransformWorldPointToLocal(((GameObject*)obj)->anim.worldPosX, ((GameObject*)obj)->anim.worldPosY,
                                       ((GameObject*)obj)->anim.worldPosZ, (f32*)((char*)obj + 0xc),
                                       (f32*)((char*)obj + 0x10), (f32*)((char*)obj + 0x14),
                                       *(int*)&((GameObject*)obj)->anim.parent);
        objHitDetectFn_80062e84(obj, ((PlayerState*)inner)->groundObject, 1);
        ((PlayerState*)inner)->moveStartX = ((GameObject*)obj)->anim.localPosX;
        ((PlayerState*)inner)->moveStartY = ((GameObject*)obj)->anim.localPosY;
        ((PlayerState*)inner)->moveStartZ = ((GameObject*)obj)->anim.localPosZ;
        ObjAnim_SetCurrentMove(obj, lbl_80332EF0[m], lbl_803E7EA4, 4);
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
            (*gCameraInterface)->setMode(
                0x43, 1, 0, 4, &shk, 0, 0xff);
        }
        if (*(void**)((char*)inner + 0x4c4) != NULL)
        {
            Obj_TransformWorldPointToLocal(*(f32*)((int)inner + 0x5d4), *(f32*)((int)inner + 0x5d8),
                                           *(f32*)((int)inner + 0x5dc), (f32*)((char*)inner + 0x5d4),
                                           (f32*)((char*)inner + 0x5d8), (f32*)((char*)inner + 0x5dc),
                                           ((PlayerState*)inner)->groundObject);
            Obj_TransformWorldPointToLocal(*(f32*)((int)inner + 0x5ec), *(f32*)((int)inner + 0x5f0),
                                           *(f32*)((int)inner + 0x5f4), (f32*)((char*)inner + 0x5ec),
                                           (f32*)((char*)inner + 0x5f0), (f32*)((char*)inner + 0x5f4),
                                           ((PlayerState*)inner)->groundObject);
            Obj_TransformWorldPointToLocal(*(f32*)((int)inner + 0x5f8), *(f32*)((int)inner + 0x5fc),
                                           *(f32*)((int)inner + 0x600), (f32*)((char*)inner + 0x5f8),
                                           (f32*)((char*)inner + 0x5fc), (f32*)((char*)inner + 0x600),
                                           ((PlayerState*)inner)->groundObject);
            ((PlayerState*)inner)->unk5AC =
                ((PlayerState*)inner)->unk5AC - *(f32*)((char*)((PlayerState*)inner)->groundObject + 0x10);
            ((PlayerState*)inner)->unk5B0 =
                ((PlayerState*)inner)->unk5B0 - *(f32*)((char*)((PlayerState*)inner)->groundObject + 0x10);
            ((PlayerState*)inner)->unk609 = 0;
        }
        break;
    }
    }
    ((PlayerState*)inner)->cameraFlags |= 4;
    fn_802AB5A4(obj, inner + 4, 5);
    return 0;
}

void fn_802AA4B0(int obj, int state, f32 unused)
{
    int spawned = 0;
    PlayerState* inner = ((GameObject*)obj)->extra;
    int slot;
    int setup;
    f32 vec[3];
    struct
    {
        s16 angles[4];
        f32 mat[4];
    } v;
    f32 mtx[16];

    slot = Camera_GetCurrentViewSlot();
    if (Obj_IsLoadingLocked())
    {
        Sfx_PlayFromObject(obj, SFXmammoth_attacks);
        setup = Obj_AllocObjectSetup(0x24, 0x14b);
        *(u8*)((char*)setup + 0x4) = 2;
        *(u8*)((char*)setup + 0x5) = 1;
        *(u8*)((char*)setup + 0x6) = 0xff;
        *(u8*)((char*)setup + 0x7) = 0xff;
        if (((PlayerState*)state)->baddie.targetObj != NULL)
        {
            ObjPath_GetPointWorldPosition(gPlayerPathObject, 0, (f32*)((char*)setup + 0x8),
                                          (f32*)((char*)setup + 0xc), (f32*)((char*)setup + 0x10), 0);
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
        setup = Obj_SetupObject(setup, 5, -1, -1, 0);
        if ((void*)setup == NULL)
        {
            return;
        }
        *(s16*)((char*)setup + 0x6) = *(s16*)((char*)setup + 0x6) | 0x2000;
        if (((PlayerState*)state)->baddie.targetObj != NULL)
        {
            int sp = *(int*)&((PlayerState*)state)->baddie.targetObj;
            ObjHitVolumeRuntimeTransform* pt =
                &((GameObject*)sp)->anim.hitVolumeTransforms[((GameObject*)sp)->hitVolumeIndex];
            f32 dx = pt->jointX - ((GameObject*)gPlayerPathObject)->anim.localPosX;
            f32 dy = pt->jointY - ((GameObject*)gPlayerPathObject)->anim.localPosY;
            f32 dz = pt->jointZ - ((GameObject*)gPlayerPathObject)->anim.localPosZ;
            spawned = sp;
            v.mat[1] = lbl_803E7EA4;
            v.mat[2] = lbl_803E7EA4;
            v.mat[3] = lbl_803E7EA4;
            v.mat[0] = lbl_803E7EE0;
            v.angles[0] = inner->targetYaw;
            v.angles[1] = (s16)getAngle(dy, sqrtf(dx * dx + dz * dz));
            v.angles[2] = 0;
            if (((GameObject*)obj)->anim.parent != NULL)
            {
                v.angles[0] = v.angles[0] + *(s16*)(*(int*)&((GameObject*)obj)->anim.parent);
            }
            setMatrixFromObjectPos(mtx, v.angles);
            Matrix_TransformPoint(mtx, lbl_803E7EA4, lbl_803E7EA4, lbl_803E80DC,
                                  (f32*)((char*)setup + 0x24), (f32*)((char*)setup + 0x28),
                                  (f32*)((char*)setup + 0x2c));
            *(f32*)((char*)setup + 0x18) = ((ObjPlacement*)setup)->posY;
            *(f32*)((char*)setup + 0x1c) = ((ObjPlacement*)setup)->posZ;
            *(f32*)((char*)setup + 0x20) = *(f32*)&((ObjPlacement*)setup)->mapId;
            *(s16*)((char*)setup + 0x0) = inner->targetYaw;
            ((ObjPlacement*)setup)->unk02 = *(s16*)((char*)slot + 0x2) / 2;
        }
        else
        {
            int res = getScreenResolution();
            int half = res >> 17;
            f32 fov;
            f32 cot;
            f32 fx;
            f32 mag;
            f32 k;
            f32 m;
            *(s16*)((char*)setup + 0x0) = *(s16*)((char*)slot + 0x0);
            fov = gPlayerPi * (Camera_GetFovY() * lbl_803E80D4) / lbl_803E7F98;
            {
                f32 sn = mathSinf(fov);
                cot = lbl_803E7F5C * (sn / mathCosf(fov));
            }
            fx = cot * -((inner->aimScreenY - (f32)(int)((res & 0xffff) >> 1)) /
                (f32)(int)((res & 0xffff) >> 1) * Camera_GetAspectRatio());
            cot = cot * ((inner->aimScreenX - (f32)half) / (f32)half);
            mag = sqrtf(lbl_803E80AC + (fx * fx + cot * cot));
            vec[0] = fx / mag;
            vec[1] = cot / mag;
            vec[2] = lbl_803E7F5C / mag;
            Matrix_TransformVector(fn_8000E814(), vec, vec);
            m = lbl_803E80DC;
            *(f32*)((char*)setup + 0x24) = m * vec[0];
            *(f32*)((char*)setup + 0x28) = m * vec[1];
            *(f32*)((char*)setup + 0x2c) = m * vec[2];
            k = lbl_803E7ED4;
            *(f32*)((char*)setup + 0x18) = ((ObjPlacement*)setup)->posY =
                k * *(f32*)((char*)setup + 0x24) + *(f32*)((char*)slot + 0xc);
            *(f32*)((char*)setup + 0x1c) = ((ObjPlacement*)setup)->posZ =
                k * *(f32*)((char*)setup + 0x28) + *(f32*)((char*)slot + 0x10);
            *(f32*)((char*)setup + 0x20) = *(f32*)&((ObjPlacement*)setup)->mapId =
                k * *(f32*)((char*)setup + 0x2c) + *(f32*)((char*)slot + 0x14);
            ((ObjPlacement*)setup)->unk02 = *(s16*)((char*)slot + 0x2) / 2;
            *(s16*)((char*)setup + 0x0) = -*(s16*)((char*)slot + 0x0);
        }
        *(int*)((char*)setup + 0xf4) = 0x5f;
        *(int*)((char*)setup + 0xf8) = spawned;
    }
}

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
                f32 thresh =
                    1.5f * (f32)(u32) * (u8*)((char*)*(int*)((char*)o + 0x4c) + 0x19);
                if (dist < thresh)
                {
                    ratio = lbl_803E7EA4;
                    if (thresh > lbl_803E7EA4)
                    {
                        ratio = (thresh - dist) / thresh;
                    }
                    ratio = ratio * (10.0f * *(f32*)((char*)o + 0x8));
                    sumC = ratio * mathSinf(3.1415927f * (f32)(int) * (s16*)((char*)o + 0) /
                            32768.0f) +
                        sumC;
                    sumS = ratio * mathCosf(3.1415927f * (f32)(int) * (s16*)((char*)o + 0) /
                            32768.0f) +
                        sumS;
                }
            }
        }
    }
    objs = (int*)ObjGroup_GetObjects(0x50, &n);
    for (i = 0; i < n; i++)
    {
        int o = objs[i];
        f32 strength =
            (f32)(u32) * (u8*)((char*)*(int*)((char*)o + 0x4c) + 0x32) / 10.0f;
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
                angle = 3.1415927f * (f32)(int)
                a22 / 32768.0f;
                sumC = ratio * mathSinf(angle) + sumC;
                sumS = ratio * mathCosf(angle) + sumS;
            }
        }
    }
    if (any)
    {
        f32 mag;
        sumC = sumC / (f32)(int)
        any;
        sumS = sumS / (f32)(int)
        any;
        inner->avoidVelX =
            inner->avoidVelX - lbl_803E7F6C * sumC;
        inner->avoidVelZ =
            inner->avoidVelZ - lbl_803E7F6C * sumS;
        inner->avoidVelX = inner->avoidVelX * lbl_803E7F68;
        inner->avoidVelZ = inner->avoidVelZ * lbl_803E7F68;
        mag = sqrtf(inner->avoidVelX * inner->avoidVelX +
            inner->avoidVelZ * inner->avoidVelZ);
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
        *outX = lbl_803E7EA4;
        *outZ = lbl_803E7EA4;
    }
}

int fn_8029A76C(int obj, int state, f32 fv)
{
    PlayerState* inner = ((GameObject*)obj)->extra;
    int r;
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
        ((GameObject*)obj)->anim.velocityX = z;
        ((GameObject*)obj)->anim.velocityY = z;
        ((GameObject*)obj)->anim.velocityZ = z;
    }
    r = ((int (*)(int, int, int))fn_802AC7DC)(obj, state, (int)inner);
    if (r != 0)
    {
        return r;
    }
    setAButtonIcon(6);
    setBButtonIcon(0xa);
    if (lbl_803DE42C != 0)
    {
        Sfx_KeepAliveLoopedObjectSound(obj, 0x382);
        timer = inner->stateTimer - timeDelta;
        inner->stateTimer = timer;
        if (timer <= lbl_803E7EA4)
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
        pfx.mode = 0;
        (*gPartfxInterface)->spawnObject(
            (void*)gPlayerPathObject, 0x7f5, &pfx, 0x200001, -1, NULL);
        pfx.mode = 1;
        (*gPartfxInterface)->spawnObject(
            (void*)gPlayerPathObject, 0x7f5, &pfx, 0x200001, -1, NULL);
        if ((((PlayerState*)inner)->buttonsHeld & gPlayerHeldButtonMask) == 0 ||
            *(s16*)((char*)*(int*)((char*)*(int*)&((GameObject*)obj)->extra + 0x35c) + 0x4) == 0 ||
            getCurSeqNo() != 0)
        {
            int i;
            lbl_803DE42C = 0;
            for (i = 0; i < 7; i++)
            {
                if (gPlayerSpawnedObjects[i] != NULL)
                {
                    Obj_FreeObject((int)gPlayerSpawnedObjects[i]);
                    gPlayerSpawnedObjects[i] = NULL;
                }
            }
            if (gPlayerResource != NULL)
            {
                Resource_Release(gPlayerResource);
                gPlayerResource = NULL;
            }
        }
    }
    switch (((GameObject*)obj)->anim.currentMove)
    {
    case 0x43f:
        if (((PlayerState*)state)->baddie.targetObj == NULL)
        {
            int res;
            int half;
            int low;
            f32 b;
            f32 a;
            *(u32*)&((PlayerState*)inner)->flags360 &= ~0x400LL;
            a = inner->aimInputZ;
            b = inner->aimInputX;
            res = getScreenResolution();
            half = res >> 17;
            low = (res & 0xffff) >> 1;
            inner->aimScreenY =
                lbl_803E7E98 * (b * (f32)(int)
            low
            )
            +(f32)(int)
            low;
            if (a < lbl_803E7EA4)
            {
                inner->aimScreenX =
                    lbl_803E7E98 * (a * (f32)(int)
                half
                )
                +(f32)(int)
                half;
            }
            else
            {
                inner->aimScreenX =
                    lbl_803E7F44 * (a * (f32)(int)
                half
                )
                +(f32)(int)
                half;
            }
            *(u32*)&((PlayerState*)inner)->flags360 |= 0x400LL;
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
            (*gPartfxInterface)->spawnObject(
                (void*)gPlayerPathObject, 0x3ed, &pfx2, 0x200001, -1, NULL);
        }
        sub = *(int*)((char*)*(int*)&((GameObject*)obj)->extra + 0x35c);
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
        fn_802AA4B0(obj, state, inner->aimInputZ);
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
        if ((((PlayerState*)inner)->buttonsJustPressed & 0x200) != 0 ||
            inner->curAnimId != 0x52)
        {
            *(int*)&((PlayerState*)state)->baddie.unk308 = (int)fn_8029A420;
            return 0x2c;
        }
    }
    return 0;
}

extern f32 lbl_803E8064;
extern f32 lbl_803E8074;
extern f32 lbl_803E8030;
extern f32 lbl_803E8078;
extern f32 lbl_803E807C;
extern f32 lbl_803E8080;


int fn_802A5384(int obj, int state)
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
    fn_802AD204(obj, inner);
    {
        u32 fl = *(u8*)((char*)inner + 0x3f0);
        if ((fl >> 5 & 1) != 0)
        {
            *(u32*)state |= 0x200000;
            *(u32*)&((PlayerState*)inner)->flags360 |= 0x2000LL;
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
        if (((u32) * (u8*)((char*)inner + 0x3f1) >> 5 & 1) == 0 &&
            ((u32) * (u8*)((char*)inner + 0x3f0) >> 2 & 1) == 0)
        {
            ((PlayerState*)inner)->yaw =
                ((PlayerState*)inner)->yaw + ((PlayerState*)inner)->yawRate * 0xb6;
        }
        ((PlayerState*)inner)->yawRateSigned = 0;
        ((PlayerState*)inner)->yawRate = 0;
    }
    {
        t = ((((PlayerState*)state)->baddie.inputMagnitude - lbl_803E7F14) / lbl_803E7F2C < (t = lbl_803E7EA4))
                ? t
                : (((((PlayerState*)state)->baddie.inputMagnitude - lbl_803E7F14) / lbl_803E7F2C >
                       (t = lbl_803E7EE0))
                       ? t
                       : (((PlayerState*)state)->baddie.inputMagnitude - lbl_803E7F14) / lbl_803E7F2C);
    }
    ((PlayerState*)inner)->currentSpeed =
        (((PlayerState*)inner)->maxSpeed - lbl_803E7F6C) *
        (t * ((PlayerState*)inner)->speedScale);
    {
        u32 fl = *(u8*)((char*)inner + 0x3f0);
        if ((fl >> 6 & 1) != 0)
        {
            *(u32*)&((PlayerState*)inner)->flags360 |= 0x1000000LL;
            ((PlayerState*)state)->baddie.moveSpeed = lbl_803E8070;
            {
                int cd = (int)(lbl_803E7F98 * ((GameObject*)obj)->anim.currentMoveProgress +
                    (f32) * (int*)((char*)inner + 0x858));
                ((PlayerState*)inner)->targetYaw = cd;
                ((PlayerState*)inner)->lastInputHeading = (s16)cd;
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
            fn_802AE650(obj, inner, state);
        }
        else if ((fl >> 7 & 1) != 0)
        {
            int r = fn_802AE480(obj, inner, state);
            if (r != 0)
            {
                *(int*)&((PlayerState*)state)->baddie.unk308 = (int)fn_802A514C;
                return 2;
            }
        }
        else if ((fl >> 1 & 1) != 0)
        {
            int leave;
            *(u32*)&((PlayerState*)inner)->flags360 |= 0x800LL;
            {
                f32 z = lbl_803E7EA4;
                ((PlayerState*)state)->baddie.animSpeedC = z;
                ((PlayerState*)state)->baddie.animSpeedC = z;
                ((PlayerState*)state)->baddie.animSpeedB = z;
                ((PlayerState*)state)->baddie.animSpeedA = z;
                ((GameObject*)obj)->anim.velocityX = z;
                ((GameObject*)obj)->anim.velocityY = z;
                ((GameObject*)obj)->anim.velocityZ = z;
                {
                    f32 w = lbl_803E7FA4;
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
                    ((fl2 = *(u8*)((char*)inner + 0x3f0)) >> 5 & 1) == 0 &&
                    (fl2 >> 3 & 1) == 0 && (fl2 >> 2 & 1) == 0 &&
                    ((PlayerState*)inner)->curAnimId != 0x44 &&
                    *(void**)((char*)inner + 0x7f8) == NULL &&
                    ((PlayerState*)inner)->baddie.targetObj == NULL &&
                    ((u32) * (u8*)((char*)inner + 0x3f6) >> 6 & 1) == 0 &&
                    ((PlayerState*)inner)->baddie.controlMode != 0x26 &&
                    (((GameObject*)obj)->objectFlags & 0x1000) == 0 &&
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
                    if (gPlayerPathObject != 0 &&
                        ((u32) * (u8*)((char*)inner + 0x3f4) >> 6 & 1) != 0)
                    {
                        ((PlayerState*)inner)->staffActionRequest = 1;
                        ((ByteFlags*)((char*)inner + 0x3f4))->b08 = 1;
                    }
                    staffFn_80170380(gPlayerStaffObject, 2);
                    ((ByteFlags*)((char*)inner + 0x3f0))->b02 = 0;
                    *(u32*)&((PlayerState*)inner)->flags360 |= 0x800000LL;
                    ObjHits_SyncObjectPositionIfDirty(obj);
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
            fn_802ADE80(obj, inner, state);
        }
        else if ((fl >> 3 & 1) != 0)
        {
            fn_802ADC08(obj, inner, state);
        }
        else if ((fl >> 2 & 1) != 0)
        {
            int r = fn_802AD2F4(obj, inner, state);
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
            if ((fl >> 5 & 1) == 0 && (fl >> 6 & 1) == 0 && (fl >> 4 & 1) == 0 &&
                (fl >> 2 & 1) == 0 && (fl >> 3 & 1) == 0 && (fl >> 1 & 1) == 0 &&
                *(void**)((char*)inner + 0x7f8) == NULL &&
                ((PlayerState*)inner)->curAnimId != 0x44)
            {
                calm = 1;
            }
            else
            {
                calm = 0;
            }
        }
        if (calm && (((PlayerState*)inner)->buttonsJustPressed & 0x400) != 0)
        {
            fn_802AED2C(obj, inner, state);
        }
    }
    {
        int ok;
        {
            u32 fl = *(u8*)((char*)inner + 0x3f0);
            if ((fl >> 5 & 1) == 0 && (fl >> 6 & 1) == 0 && (fl >> 7 & 1) == 0 &&
                (fl >> 4 & 1) == 0 && (fl >> 2 & 1) == 0 && (fl >> 3 & 1) == 0 &&
                ((u32) * (u8*)((char*)inner + 0x3f1) >> 5 & 1) == 0)
            {
                ok = 1;
            }
            else
            {
                ok = 0;
            }
        }
        if (ok &&
            ((PlayerState*)state)->baddie.animSpeedC >
            lbl_803E7EAC + *(f32*)(((PlayerState*)inner)->moveParams + 0x14) &&
            (((PlayerState*)inner)->inputMagnitude < lbl_803E8030 ||
                ((PlayerState*)inner)->yawRateSigned >= 0x96))
        {
            ((PlayerState*)inner)->pendingFxFlags |= 8;
            ((ByteFlags*)((char*)inner + 0x3f0))->b80 = 1;
            ((PlayerState*)inner)->animSoundId = ((PlayerState*)inner)->altAnimSoundId;
            *(u32*)&((PlayerState*)inner)->flags360 |= 0x1000000LL;
            ((PlayerState*)inner)->unk844 = ((PlayerState*)state)->baddie.animSpeedA;
            ObjAnim_SetCurrentMove(obj,
                                   *(s16*)(((PlayerState*)inner)->moveAnimTable + 0x3c),
                                   lbl_803E7EA4, 0);
        }
    }
    {
        u32 fl = *(u8*)((char*)inner + 0x3f0);
        if ((fl >> 7 & 1) == 0 && (fl >> 6 & 1) == 0 &&
            ((u32) * (u8*)((char*)inner + 0x3f1) >> 5 & 1) == 0)
        {
            if (((PlayerState*)inner)->yawRateSigned < 0x96)
            {
                f32 d = interpolate((f32) * (int*)((char*)inner + 0x47c),
                                    lbl_803E7EE0 / ((PlayerState*)inner)->targetYawSmoothRate,
                                    timeDelta);
                {
                    f32 m = timeDelta *
                        (((PlayerState*)inner)->targetYawRateLimit * ((PlayerState*)inner)->leanCurveScale);
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
                f32 d = interpolate((f32) * (int*)((char*)inner + 0x488),
                                    lbl_803E7EE0 / ((PlayerState*)inner)->yawSmoothRate,
                                    timeDelta);
                {
                    f32 m = ((PlayerState*)inner)->yawRateLimit * timeDelta;
                    d = (d > m) ? m : d;
                }
                if (((PlayerState*)inner)->yawRate < 0)
                {
                    d = -d;
                }
                ((PlayerState*)inner)->yaw =
                    (s16)(gPlayerDegToBinAngle * d + (f32) * (s16*)((char*)inner + 0x484));
            }
            else
            {
                u32 fl3 = *(u8*)((char*)inner + 0x3f0);
                if ((fl3 >> 3 & 1) == 0 && (fl3 >> 2 & 1) == 0 && (fl3 >> 4 & 1) == 0 &&
                    ((PlayerState*)state)->baddie.animSpeedC <=
                    *(f32*)(((PlayerState*)inner)->moveParams + 4) &&
                    ((PlayerState*)state)->baddie.animSpeedA <=
                    *(f32*)(((PlayerState*)inner)->moveParams + 0xc))
                {
                    ((PlayerState*)inner)->yaw =
                        ((PlayerState*)inner)->yaw +
                        ((PlayerState*)inner)->yawRate * 0xb6;
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
            (t * -mathSinf((gPlayerPi * (f32) * (int*)((char*)inner + 0x474)) /
                lbl_803E7F98));
            ya = ((PlayerState*)inner)->maxSpeed *
            (t * -mathCosf((gPlayerPi * (f32) * (int*)((char*)inner + 0x474)) /
                lbl_803E7F98));
            t = interpolate(spd - ((PlayerState*)inner)->smoothVelX,
                            ((PlayerState*)inner)->velSmoothRate, timeDelta);
            {
                f32 dy = interpolate(ya - ((PlayerState*)inner)->smoothVelZ,
                                     ((PlayerState*)inner)->velSmoothRate, timeDelta);
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
                        : ((((PlayerState*)state)->baddie.animSpeedC >
                               ((PlayerState*)inner)->maxSpeed)
                               ? ((PlayerState*)inner)->maxSpeed
                               : ((PlayerState*)state)->baddie.animSpeedC);
            }
            t = mathSinf((gPlayerPi * (f32) * (s16*)((char*)inner + 0x478)) /
                lbl_803E7F98);
            {
                f32 sn = mathCosf((gPlayerPi * (f32) * (s16*)((char*)inner + 0x478)) /
                    lbl_803E7F98);
                f32 negA = -((PlayerState*)inner)->smoothVelZ;
                f32 nx = negA * sn - ((PlayerState*)inner)->smoothVelX * t;
                ya = ((PlayerState*)inner)->smoothVelX * sn -
                    ((PlayerState*)inner)->smoothVelZ * t;
                ((PlayerState*)state)->baddie.animSpeedA =
                    ((PlayerState*)state)->baddie.animSpeedA +
                    interpolate(nx - ((PlayerState*)state)->baddie.animSpeedA,
                                ((PlayerState*)inner)->targetAnimSpeed, timeDelta);
                ((PlayerState*)state)->baddie.animSpeedB =
                    ((PlayerState*)state)->baddie.animSpeedB +
                    interpolate(ya - ((PlayerState*)state)->baddie.animSpeedB,
                                ((PlayerState*)inner)->targetAnimSpeed, timeDelta);
            }
            spd = ((PlayerState*)state)->baddie.animSpeedB;
            spd = (spd < lbl_803E7EA4) ? -spd : spd;
            t = ((PlayerState*)state)->baddie.animSpeedA;
            t = (t < lbl_803E7EA4) ? -t : t;
            {
                int r = ObjAnim_SampleRootCurvePhase(((PlayerState*)state)->baddie.animSpeedC,
                                                     (ObjAnimComponent*)obj,
                                                     (f32*)(state + 0x2a0));
                if (r == 0)
                {
                    ((PlayerState*)state)->baddie.moveSpeed = lbl_803E7F78;
                }
            }
            if (((u32) * (u8*)((char*)inner + 0x3f0) >> 5 & 1) != 0)
            {
                ((PlayerState*)state)->baddie.moveSpeed =
                    ((PlayerState*)state)->baddie.moveSpeed * lbl_803E7E98;
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
            if ((fl >> 6 & 1) == 0 && (fl1 >> 2 & 1) == 0 && (fl >> 4 & 1) == 0 &&
                (fl1 >> 1 & 1) == 0 && (fl >> 3 & 1) == 0 && (fl >> 2 & 1) == 0 &&
                (fl >> 1 & 1) == 0)
            {
                f32 d = interpolate(((PlayerState*)inner)->currentSpeed -
                                    ((PlayerState*)state)->baddie.animSpeedC,
                                    ((PlayerState*)inner)->velSmoothRate, timeDelta);
                f32 m = (d < lbl_803E7EA8 * timeDelta)
                            ? lbl_803E7EA8 * timeDelta
                            : ((d > lbl_803E7EFC * timeDelta) ? lbl_803E7EFC * timeDelta : d);
                if (((PlayerState*)inner)->yawRateSigned >= 0x96 && m > lbl_803E7EA4)
                {
                    m = lbl_803E7ED4 * -m;
                }
                ((PlayerState*)state)->baddie.animSpeedC = ((PlayerState*)state)->baddie.animSpeedC + m;
                {
                    ((PlayerState*)state)->baddie.animSpeedC =
                        (((PlayerState*)state)->baddie.animSpeedC < **(f32**)((char*)inner + 0x400))
                            ? **(f32**)((char*)inner + 0x400)
                            : ((((PlayerState*)state)->baddie.animSpeedC >
                                   ((PlayerState*)inner)->maxSpeed)
                                   ? ((PlayerState*)inner)->maxSpeed
                                   : ((PlayerState*)state)->baddie.animSpeedC);
                }
                ((PlayerState*)state)->baddie.animSpeedB = lbl_803E7EA4;
            }
            else if (((u32) * (u8*)((char*)inner + 0x3f0) >> 3 & 1) != 0 ||
                ((u32) * (u8*)((char*)inner + 0x3f0) >> 2 & 1) != 0)
            {
                t = ((PlayerState*)inner)->currentSpeed *
                    -mathSinf((gPlayerPi *
                            (gPlayerDegToBinAngle * (f32) * (int*)((char*)inner + 0x48c))) /
                        lbl_803E7F98);
                ya = ((PlayerState*)inner)->currentSpeed *
                    mathCosf((gPlayerPi *
                            (gPlayerDegToBinAngle * (f32) * (int*)((char*)inner + 0x48c))) /
                        lbl_803E7F98);
                if (((u32) * (u8*)((char*)inner + 0x3f0) >> 2 & 1) != 0)
                {
                    ((PlayerState*)state)->baddie.animSpeedC =
                        ((PlayerState*)state)->baddie.animSpeedC *
                        powfBitEstimate(lbl_803E7F90, timeDelta);
                }
                else
                {
                    ((PlayerState*)state)->baddie.animSpeedC =
                        -(lbl_803E7F20 * timeDelta - ((PlayerState*)state)->baddie.animSpeedC);
                }
                {
                    f32 v2 = lbl_803E7E8C * ya;
                    f32 m = (v2 < lbl_803E8078)
                                ? lbl_803E8078
                                : ((v2 > lbl_803E807C) ? lbl_803E807C : v2);
                    ((PlayerState*)state)->baddie.animSpeedC =
                        m * timeDelta + ((PlayerState*)state)->baddie.animSpeedC;
                }
                {
                    f32 v = ((PlayerState*)state)->baddie.animSpeedC;
                    ((PlayerState*)state)->baddie.animSpeedC =
                        (v < lbl_803E8080)
                            ? lbl_803E8080
                            : ((v > lbl_803E7EFC + ((PlayerState*)inner)->maxSpeed)
                                   ? lbl_803E7EFC + ((PlayerState*)inner)->maxSpeed
                                   : v);
                }
                t = t * lbl_803E7F74;
                ((PlayerState*)state)->baddie.animSpeedB =
                    ((PlayerState*)state)->baddie.animSpeedB +
                    interpolate(t - ((PlayerState*)state)->baddie.animSpeedB, lbl_803E807C,
                                timeDelta);
            }
            else
            {
                f32 v = ((PlayerState*)state)->baddie.animSpeedC;
                f32 lim = ((PlayerState*)inner)->maxSpeed;
                ((PlayerState*)state)->baddie.animSpeedC =
                    (v < -lim) ? -lim : ((v > lim) ? lim : v);
            }
            {
                if (((u32) * (u8*)((char*)inner + 0x3f0) >> 4 & 1) == 0 &&
                    ((u32) * (u8*)((char*)inner + 0x3f1) >> 1 & 1) == 0 &&
                    ((u32) * (u8*)((char*)inner + 0x3f0) >> 1 & 1) == 0)
                {
                    ((PlayerState*)state)->baddie.animSpeedA =
                        ((PlayerState*)state)->baddie.animSpeedA +
                        interpolate(((PlayerState*)state)->baddie.animSpeedC -
                                    ((PlayerState*)state)->baddie.animSpeedA,
                                    ((PlayerState*)inner)->targetAnimSpeed, timeDelta);
                }
            }
            dir = 0;
        }
    }
    {
        u32 fl = *(u8*)((char*)inner + 0x3f0);
        if ((fl >> 7 & 1) == 0 && (fl >> 6 & 1) == 0 && (fl >> 4 & 1) == 0 &&
            (fl >> 2 & 1) == 0 && (fl >> 3 & 1) == 0 && (fl >> 1 & 1) == 0)
        {
            int locked;
            int step;
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
                int tb = ((PlayerState*)inner)->moveParams;
                if (v < *(f32*)(tb + step * 4))
                {
                    if (((PlayerState*)inner)->gaitLevel == 4)
                    {
                        if (((PlayerState*)state)->baddie.animSpeedA < *(f32*)(tb + 0x10) &&
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
                else if (v >= *(f32*)(tb + step * 4 + 4))
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
            if (locked != 0 ||
                *(void**)((char*)inner + 0x3fc) != *(void**)((char*)inner + 0x3f8) ||
                ((GameObject*)obj)->anim.currentMove !=
                *(s16*)(((PlayerState*)inner)->moveAnimTable +
                    (((PlayerState*)inner)->gaitLevel + dir) * 2))
            {
                if (((int (*)(ObjAnimComponent*))ObjAnim_GetCurrentEventCountdown)((ObjAnimComponent*)obj) == 0 ||
                    ((u32) * (u8*)((char*)inner + 0x3f2) >> 4 & 1) != 0)
                {
                    ObjAnim_SetCurrentMove(obj,
                                           *(s16*)(((PlayerState*)inner)->moveAnimTable +
                                               (((PlayerState*)inner)->gaitLevel + dir) * 2),
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
        if (t < lbl_803E7EA4)
        {
            ad = -t;
        }
        if (((u32) * (u8*)((char*)inner + 0x3f1) >> 5 & 1) == 0)
        {
            u32 fl = *(u8*)((char*)inner + 0x3f0);
            if ((fl >> 7 & 1) == 0 && (fl >> 6 & 1) == 0 && (fl >> 4 & 1) == 0 &&
                (fl >> 2 & 1) == 0 && (fl >> 3 & 1) == 0 && (fl >> 1 & 1) == 0)
            {
                if ((fl >> 5 & 1) == 0)
                {
                    Object_ObjAnimSetSecondaryBlendMove(
                        (ObjAnimComponent*)obj,
                        *(s16*)(((PlayerState*)inner)->moveAnimTable +
                            (((PlayerState*)inner)->gaitLevel + pos) * 2 + 2),
                        (int)(lbl_803E7FAC * ad));
                }
                {
                    int r = ObjAnim_SampleRootCurvePhase(((PlayerState*)state)->baddie.animSpeedC,
                                                         (ObjAnimComponent*)obj,
                                                         (f32*)(state + 0x2a0));
                    if (r == 0)
                    {
                        ((PlayerState*)state)->baddie.moveSpeed = lbl_803E7F78;
                    }
                }
            }
        }
    }
    fn_802ABAE8(obj, state, inner, t);
    return 0;
}

extern s16 gPlayerPrevMoveId;
extern f32 lbl_803E8020;

int fn_802A1CA8(int obj, int state)
{
    int jt;
    int inner;
    f32 t;
    f32 spd;
    f32 ph;
    f32 buf1[3];
    f32 buf2[3];
    f32 tmp[2];
    f32 outY;

    inner = *(int*)&((GameObject*)obj)->extra;
    if (*(s8*)&((PlayerState*)state)->baddie.moveJustStartedA != 0)
    {
        ObjHits_MarkObjectPositionDirty();
        if (gPlayerPathObject != 0 &&
            ((u32) * (u8*)((char*)inner + 0x3f4) >> 6 & 1) != 0)
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
            fn_802AB5A4(obj, inner, 5);
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
    jt = (int)Player_GetActiveModel(obj);
    spd = lbl_803E7EA4;
    ph = ((PlayerState*)state)->baddie.moveSpeed;
    gPlayerPrevMoveId = gPlayerCurrentMoveId;
    if ((*(int*)&((PlayerState*)state)->baddie.eventFlags & 1) != 0)
    {
        switch (((PlayerState*)inner)->unk546)
        {
        case 4:
            Sfx_PlayFromObject(obj, 0x33a);
            break;
        default:
            Sfx_PlayFromObject(obj, 0x11);
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
            Sfx_PlayFromObject(obj, 0x10);
            if (((PlayerState*)inner)->characterId == 0)
            {
                Sfx_PlayFromObject(obj, 0x398);
            }
        }
        if (*(s8*)&((PlayerState*)state)->baddie.moveDone != 0)
        {
            ((GameObject*)obj)->anim.localPosY = ((PlayerState*)inner)->unk4E8;
        }
        else
        {
            ObjModel_SampleJointTransform(jt, 0, 0, lbl_803E7EA4,
                                          ((GameObject*)obj)->anim.rootMotionScale, buf1, tmp);
            ObjModel_SampleJointTransform(jt, 0, 0, lbl_803E7EE0,
                                          ((GameObject*)obj)->anim.rootMotionScale, buf2, tmp);
            ((GameObject*)obj)->anim.localPosY =
                ((GameObject*)obj)->anim.currentMoveProgress *
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
                (*gWaterfxInterface)->spawnSplashBurst(
                    (void*)obj, ((GameObject*)obj)->anim.localPosX,
                    ((GameObject*)obj)->anim.localPosY,
                    ((GameObject*)obj)->anim.localPosZ, lbl_803E8018);
            }
        }
        if (*(s8*)&((PlayerState*)state)->baddie.moveDone != 0)
        {
            ((GameObject*)obj)->anim.worldPosX = ((PlayerState*)inner)->savedPosX;
            ((GameObject*)obj)->anim.worldPosZ = ((PlayerState*)inner)->savedPosZ;
            if (((GameObject*)obj)->anim.parent != NULL)
            {
                ((GameObject*)obj)->anim.worldPosX =
                    ((GameObject*)obj)->anim.worldPosX + playerMapOffsetX;
                ((GameObject*)obj)->anim.worldPosZ =
                    ((GameObject*)obj)->anim.worldPosZ + playerMapOffsetZ;
            }
            ((void (*)(f32, f32, f32, f32*, f32*, f32*, int))Obj_TransformWorldPointToLocal)(
                ((GameObject*)obj)->anim.worldPosX, lbl_803E7EA4, ((GameObject*)obj)->anim.worldPosZ,
                &((GameObject*)obj)->anim.localPosX, &outY, &((GameObject*)obj)->anim.localPosZ,
                *(int*)&((GameObject*)obj)->anim.parent);
            if (gPlayerCurrentMoveId == 6 || gPlayerCurrentMoveId == 7)
            {
                fn_802AB5A4(obj, inner, 7);
            }
            else
            {
                fn_802AB5A4(obj, inner, 5);
            }
            ObjAnim_SetCurrentMove(obj, **(s16**)((char*)inner + 0x3f8),
                                   lbl_803E7EA4, 1);
            *(u32*)&((PlayerState*)inner)->flags360 |= 0x800000LL;
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
            if ((*(int*)&((PlayerState*)state)->baddie.unk31C & 0x100) != 0 &&
                ((PlayerState*)inner)->climbStep > 3)
            {
                *(int*)&((PlayerState*)state)->baddie.unk308 = (int)fn_8029FFD0;
                return -0x10;
            }
            goto finish;
        }
    default:
        if ((*(int*)&((PlayerState*)state)->baddie.eventFlags & 0x80) != 0)
        {
            Sfx_PlayFromObject(obj, 0x11);
        }
        if ((*(int*)&((PlayerState*)state)->baddie.unk31C & 0x100) != 0 &&
            ((PlayerState*)inner)->climbStep > 3)
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
                    if ((int)((PlayerState*)inner)->climbStep >=
                        ((PlayerState*)inner)->climbStepCount - 3)
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
                        lbl_803DE43C = ((PlayerState*)inner)->unk4E8 + lbl_803DAF88[0];
                        if (((PlayerState*)inner)->curAnimId != 0x48 &&
                            ((PlayerState*)inner)->curAnimId != 0x47)
                        {
                            (*gCameraInterface)->setMode(
                                0x42, 0, 1, 0, NULL, 0x1e, 0xff);
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
                        if (((PlayerState*)inner)->curAnimId != 0x48 &&
                            ((PlayerState*)inner)->curAnimId != 0x47 &&
                            ((PlayerState*)inner)->curAnimId != 0x42)
                        {
                            (*gCameraInterface)->setMode(
                                0x42, 0, 1, 0, NULL, 0x1e, 0xff);
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
                            *(u32*)&((PlayerState*)inner)->flags360 |= 0x800000LL;
                            ObjHits_SyncObjectPositionIfDirty(obj);
                            ((ByteFlags*)((char*)inner + 0x3f0))->b40 = 0;
                            ((ByteFlags*)((char*)inner + 0x3f0))->b04 = 1;
                            ((ByteFlags*)((char*)inner + 0x3f4))->b10 = 1;
                            ((PlayerState*)inner)->isHoldingObject = 0;
                            if (*(void**)((char*)inner + 0x7f8) != NULL)
                            {
                                if (((GameObject*)((PlayerState*)inner)->heldObj)->anim.seqId == 0x3cf ||
                                    ((GameObject*)((PlayerState*)inner)->heldObj)->anim.seqId == 0x662)
                                {
                                    objThrowFn_80182504(((PlayerState*)inner)->heldObj);
                                }
                                else
                                {
                                    objSaveFn_800ea774(((PlayerState*)inner)->heldObj);
                                }
                                *(s16*)(((PlayerState*)inner)->heldObj + 6) =
                                    *(s16*)(((PlayerState*)inner)->heldObj + 6) & ~0x4000;
                                *(int*)(((PlayerState*)inner)->heldObj + 0xf8) = 0;
                                ((PlayerState*)inner)->heldObj = 0;
                            }
                            fn_802AB5A4(obj, inner, 5);
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
                            f32 y2 = ((GameObject*)obj)->anim.localPosY -
                                ((PlayerState*)inner)->moveStartPosY;
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
            ObjModel_SampleJointTransform(jt, 0, 0, lbl_803E7EA4,
                                          ((GameObject*)obj)->anim.rootMotionScale, buf1, tmp);
            ObjModel_SampleJointTransform(jt, 0, 0, lbl_803E7EE0,
                                          ((GameObject*)obj)->anim.rootMotionScale, buf2, tmp);
            ((PlayerState*)inner)->moveStartPosY = buf2[1] - buf1[1];
            *(u8*)&((PlayerState*)inner)->climbSampleDone = 1;
        }
    }
    {
        f32 x = ((GameObject*)obj)->anim.localPosX;
        f32 zz = ((GameObject*)obj)->anim.localPosZ;
        f32 y;
        switch ((s16)gPlayerCurrentMoveId)
        {
        case 0:
        case 1:
        case 2:
        case 3:
            y = ((GameObject*)obj)->anim.currentMoveProgress *
                (((f32)(((PlayerState*)inner)->climbStep + 1) *
                        ((PlayerState*)inner)->climbStepHeight +
                        ((PlayerState*)inner)->climbBaseY) -
                    ((GameObject*)obj)->anim.localPosY) +
                ((GameObject*)obj)->anim.localPosY;
            break;
        case 10:
        case 11:
            x = ((GameObject*)obj)->anim.currentMoveProgress * (((PlayerState*)inner)->savedPosX - x) + x;
            y = (lbl_803E7EE0 - ((GameObject*)obj)->anim.currentMoveProgress) *
                (((PlayerState*)inner)->climbTargetY - ((GameObject*)obj)->anim.localPosY) +
                ((GameObject*)obj)->anim.localPosY;
            zz = ((GameObject*)obj)->anim.currentMoveProgress * (((PlayerState*)inner)->savedPosZ - zz) + zz;
            break;
        case 6:
        case 7:
            x = ((GameObject*)obj)->anim.currentMoveProgress * (((PlayerState*)inner)->savedPosX - x) + x;
            y = ((GameObject*)obj)->anim.currentMoveProgress *
                (((PlayerState*)inner)->unk4E8 - ((GameObject*)obj)->anim.localPosY) +
                ((GameObject*)obj)->anim.localPosY;
            zz = ((GameObject*)obj)->anim.currentMoveProgress * (((PlayerState*)inner)->savedPosZ - zz) + zz;
            break;
        default:
            y = ((GameObject*)obj)->anim.localPosY;
            break;
        }
        (*gCameraInterface)->overridePos(x, y, zz);
    }
    fn_802AB5A4(obj, inner, 5);
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

extern f32 lbl_803E7FF8;
extern f32 lbl_803E8000;
extern f32 lbl_803E8004;

int fn_802A0680(int obj, int state)
{
    extern int objBboxFn_800640cc(void* from, void* to, f32 radius, int mode, void* hit, int obj,
                                  int p7, int p8, int p9, int p10);
    int jt;
    int inner;
    int b6;
    int b7;
    int b8;
    int b9;
    int dir;
    int mask;
    s16 i;
    f32 oldSpd;
    f32 dx;
    f32 dy;
    f32 ph;
    WallHit hit;
    f32 out1[3];
    f32 pnt[3];
    f32 dst[3];
    f32 tmp[2];

    inner = *(int*)&((GameObject*)obj)->extra;
    if (*(s8*)&((PlayerState*)state)->baddie.moveJustStartedA != 0)
    {
        gPlayerCurrentMoveId = 0x10;
        ObjHits_MarkObjectPositionDirty();
    }
    {
        int base = *(int*)&((GameObject*)obj)->extra;
        *(int*)((char*)base + 0x360) &= ~0x2LL;
        *(u32*)((char*)base + 0x360) |= 0x2000LL;
    }
    *(u32*)((char*)state + 4) |= 0x100000;
    {
        f32 z = 0.0f;
        ((PlayerState*)state)->baddie.animSpeedA = z;
        ((PlayerState*)state)->baddie.animSpeedB = z;
        *(u32*)state |= 0x200000;
        ((GameObject*)obj)->anim.velocityX = z;
        ((GameObject*)obj)->anim.velocityZ = z;
        *(u32*)((char*)state + 4) |= 0x8000000;
        ((GameObject*)obj)->anim.velocityY = z;
    }
    jt = (int)Player_GetActiveModel(obj);
    ph = ((PlayerState*)state)->baddie.moveSpeed;
    gPlayerPrevMoveId = gPlayerCurrentMoveId;
    switch ((s16)gPlayerCurrentMoveId)
    {
    case 0x10:
        if (((GameObject*)obj)->anim.currentMove == 0x66)
        {
            ((PlayerState*)inner)->moveAltToggle = 0;
            gPlayerCurrentMoveId = 0x16;
        }
        else
        {
            ((PlayerState*)inner)->moveAltToggle = 1;
            gPlayerCurrentMoveId = 0x15;
        }
        ((GameObject*)obj)->anim.localPosY = ((PlayerState*)inner)->savedPosY;
        ph = lbl_803E7FF8;
    case 0x15:
    case 0x16:
        {
            f32 z = 0.0f;
            ((PlayerState*)inner)->moveOffsetX = z;
            ((PlayerState*)inner)->moveOffsetY = z;
            ((PlayerState*)inner)->moveOffsetZ = z;
        }
        fn_802A13F4(obj, state);
        if (((PlayerState*)state)->baddie.inputMagnitude <= lbl_803E7EFC)
        {
            goto store_ph;
        }
        oldSpd = ((GameObject*)obj)->anim.currentMoveProgress;
        ((GameObject*)obj)->anim.currentMoveProgress = 1.0f;
    default:
        if (1.0f == ((GameObject*)obj)->anim.currentMoveProgress)
        {
            pnt[0] = -(lbl_803E7F30 * ((PlayerState*)inner)->groundNormalX -
                ((PlayerState*)inner)->savedPosX);
            pnt[1] = ((PlayerState*)inner)->savedPosY;
            pnt[2] = -(lbl_803E7F30 * ((PlayerState*)inner)->groundNormalZ -
                ((PlayerState*)inner)->savedPosZ);
            {
                int r = objBboxFn_800640cc((void*)((char*)inner + 0x768), pnt, 0.0f, 3,
                                           &hit, obj, 1, 3, 0xff, 0);
                if (r != 0)
                {
                    ((GameObject*)obj)->anim.localPosX = pnt[0];
                    ((GameObject*)obj)->anim.localPosZ = pnt[2];
                    ((PlayerState*)inner)->spanTopY = hit.gt * (hit.gb - hit.ga) + hit.ga;
                    ((PlayerState*)inner)->spanBottomY = hit.gt * (hit.fz1 - hit.fz0) + hit.fz0;
                    ((PlayerState*)inner)->groundNormalX = hit.nx;
                    ((PlayerState*)inner)->groundNormalY = hit.ny;
                    ((PlayerState*)inner)->groundNormalZ = hit.nz;
                    ((PlayerState*)inner)->groundNormalW = hit.nw;
                    ((PlayerState*)inner)->slopeTangentX = -hit.nz;
                    ((PlayerState*)inner)->slopeTangentY = 0.0f;
                    ((PlayerState*)inner)->slopeTangentZ = hit.nx;
                    ((PlayerState*)inner)->slopePlaneD =
                        -(pnt[2] * ((PlayerState*)inner)->slopeTangentZ +
                            (pnt[0] * ((PlayerState*)inner)->slopeTangentX +
                                pnt[1] * ((PlayerState*)inner)->slopeTangentY));
                    ((PlayerState*)inner)->targetYaw =
                        (s16)getAngle(((PlayerState*)inner)->groundNormalX,
                                      ((PlayerState*)inner)->groundNormalZ);
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
                ((GameObject*)obj)->anim.localPosY = ((PlayerState*)inner)->savedPosY;
            }
            if (((PlayerState*)state)->baddie.inputMagnitude > lbl_803E7EFC)
            {
                gPlayerCurrentMoveId =
                ((getAngle(((PlayerState*)state)->baddie.moveInputX,
                           -((PlayerState*)state)->baddie.moveInputZ) & 0xffff) + 0x1000 >> 13) & 7;
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
                        ((PlayerState*)inner)->animEventState = (s16)(lbl_803E7FAC * m);
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
                        ((PlayerState*)inner)->animEventState = (s16)(lbl_803E7FAC * m);
                        ((PlayerState*)inner)->moveOffsetY = m;
                        *(int*)&((PlayerState*)state)->baddie.unk308 = (int)fn_8029FFD0;
                        return 0x16;
                    }
                }
                ((int (*)(int, int, f32, int))Object_ObjAnimSetMove)(
                    obj, lbl_80332F48[gPlayerCurrentMoveId], 0.0f, 1);
                ObjModel_SampleJointTransform(jt, 1, 0, 1.0f,
                                              ((GameObject*)obj)->anim.rootMotionScale, out1, tmp);
                ((GameObject*)obj)->anim.activeMove = -1;
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
                    dx = lbl_803E7FFC * ((PlayerState*)inner)->slopeTangentX;
                    dy = lbl_803E7FFC * ((PlayerState*)inner)->slopeTangentZ;
                }
                else
                {
                    dx = lbl_803E7FFC * -((PlayerState*)inner)->slopeTangentX;
                    dy = lbl_803E7FFC * -((PlayerState*)inner)->slopeTangentZ;
                }
                if (b6 != 0 || b7 != 0)
                {
                    pnt[1] = ((PlayerState*)inner)->savedPosY + out1[1];
                    if (out1[1] < 0.0f)
                    {
                        pnt[1] = pnt[1] - lbl_803E7F50;
                    }
                    else
                    {
                        pnt[1] = pnt[1] + lbl_803E7F50;
                    }
                    for (i = 0, ph = lbl_803E7F30; i < 2; i++)
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
                        if (objBboxFn_800640cc(pnt, dst, 0.0f, 3, 0, obj, 1, 3, 0xff,
                                               0) != 0)
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
                    pnt[0] = dx + (((PlayerState*)inner)->savedPosX +
                        ((PlayerState*)inner)->moveOffsetX);
                    pnt[2] = dy + (((PlayerState*)inner)->savedPosZ +
                        ((PlayerState*)inner)->moveOffsetZ);
                    for (i = 0, dy = lbl_803E7F30; i < 2; i++)
                    {
                        if (i != 0)
                        {
                            pnt[1] = lbl_803E7F50 + ((PlayerState*)inner)->savedPosY;
                        }
                        else
                        {
                            pnt[1] = ((PlayerState*)inner)->savedPosY - lbl_803E7F50;
                        }
                        dst[0] = -(dy * ((PlayerState*)inner)->groundNormalX - pnt[0]);
                        dst[1] = pnt[1];
                        dst[2] = -(dy * ((PlayerState*)inner)->groundNormalZ - pnt[2]);
                        if (objBboxFn_800640cc(pnt, dst, 0.0f, 3, 0, obj, 1, 3, 0xff,
                                               0) != 0)
                        {
                            mask = mask | 1 << (i + 2);
                        }
                    }
                }
                else
                {
                    mask |= 0xc;
                }
                ph = lbl_803E7FCC;
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
                    if (((GameObject*)obj)->anim.currentMove == lbl_80332F48[21] ||
                        ((GameObject*)obj)->anim.currentMove == lbl_80332F48[22])
                    {
                        gPlayerPrevMoveId = *(s16*)&gPlayerCurrentMoveId;
                        ((GameObject*)obj)->anim.currentMoveProgress = oldSpd;
                    }
                    ph = lbl_803E7FF8;
                }
            }
            else
            {
                ((GameObject*)obj)->anim.localPosY = ((PlayerState*)inner)->savedPosY;
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
                ph = lbl_803E7FF8;
            }
        }
        if (gPlayerCurrentMoveId != 0x15 && gPlayerCurrentMoveId != 0x16)
        {
            f32 v = ((PlayerState*)state)->baddie.inputMagnitude;
            if (ph < 0.0f)
            {
                ph = -(lbl_803E8004 * v + lbl_803E8000);
            }
            else if (ph > 0.0f)
            {
                ph = lbl_803E8004 * v + lbl_803E8000;
            }
        }
        fn_802A13F4(obj, state);
        break;
    }
store_ph:
    ((PlayerState*)state)->baddie.moveSpeed = ph;
    if (gPlayerPrevMoveId != gPlayerCurrentMoveId)
    {
        ObjAnim_SetCurrentMove(obj, lbl_80332F48[gPlayerCurrentMoveId], 0.0f, 1);
    }
    {
        f32 sp = ((GameObject*)obj)->anim.currentMoveProgress;
        (*gCameraInterface)->overridePos(
            ((PlayerState*)inner)->moveOffsetX * sp + ((GameObject*)obj)->anim.localPosX,
            ((PlayerState*)inner)->moveOffsetY * sp + ((GameObject*)obj)->anim.localPosY,
            ((PlayerState*)inner)->moveOffsetZ * sp + ((GameObject*)obj)->anim.localPosZ);
    }
    fn_802AB5A4(obj, inner, 5);
    return 0;
}

int player_SeqFn(int obj, int obj2, ObjSeqState* seq, int endFlag)
{
    int ctrl;
    register int va;
    int vb;
    int tbl;
    int mapVal;
    int result;
    register u8* inner;
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
    va = (int)objModelGetVecFn_800395d8(obj, 0);
    vb = (int)objModelGetVecFn_800395d8(obj, 9);
    seq->freeCallback = (ObjAnimSequenceFreeCallback)fn_802A93F4;
    if (*(void**)&gPlayerStaffObject != NULL)
    {
        staffFn_80170380(gPlayerStaffObject, 0);
    }
    fn_802B07D8(obj, (int)inner);
    if (*(void**)&gPlayerEggObject == NULL && Obj_IsLoadingLocked() != 0)
    {
        ObjLink_AttachChild(obj,
                            gPlayerEggObject = Obj_SetupObject(Obj_AllocObjectSetup(0x18, 0x66a), 4, -1,
                                                           -1, *(int*)&((GameObject*)obj)->anim.parent),
                            3);
    }
    if (*(void**)&gPlayerEggObject != NULL)
    {
        *(int*)&((GameObject*)gPlayerEggObject)->anim.parent = *(int*)&((GameObject*)obj)->anim.parent;
        if (((PlayerState*)inner)->characterId == 0)
        {
            *(s16*)(gPlayerEggObject + 6) |= 0x4000;
        }
    }
    if (*(void**)&gPlayerStaffObject == NULL && Obj_IsLoadingLocked() != 0)
    {
        gPlayerStaffObject = Obj_SetupObject(Obj_AllocObjectSetup(0x24, 0x773), 5, -1, -1,
                                       *(int*)&((GameObject*)obj)->anim.parent);
    }
    if (*(void**)&gPlayerStaffObject != NULL)
    {
        ObjPath_GetPointWorldPosition(obj, 4, &((GameObject*)gPlayerStaffObject)->anim.localPosX, &((GameObject*)gPlayerStaffObject)->anim.localPosY,
                                      &((GameObject*)gPlayerStaffObject)->anim.localPosZ, 0);
    }
    if ((((u32) * (u8*)((char*)inner + 0x3f3) >> 3 & 1) != 0 ||
            ((PlayerState*)inner)->animState == 0x40) &&
        ((u32) * (u8*)((char*)inner + 0x3f4) >> 7 & 1) == 0)
    {
        fn_80295E90(obj, 0);
        ((PlayerState*)inner)->animState = -1;
    }
    ObjHits_DisableObject(obj);
    *(u32*)&((PlayerState*)inner)->flags360 &= ~0x2LL;
    if ((s8)seq->movementState != 0)
    {
        s8 c;
        *(u32*)&((PlayerState*)inner)->flags360 &= ~0x400LL;
        {
            f32 fz = lbl_803E7EA4;
            ((PlayerState*)inner)->knockbackTimer = fz;
            ((PlayerState*)inner)->knockbackHitTimer = fz;
        }
        if (((u32) * (u8*)((char*)inner + 0x3f2) >> 7 & 1) == 0)
        {
            if (gPlayerPathObject != NULL && ((u32) * (u8*)((char*)inner + 0x3f4) >> 6 & 1) != 0)
            {
                ((PlayerState*)inner)->staffActionRequest = 1;
                ((ByteFlags*)((char*)inner + 0x3f4))->b08 = 1;
            }
            ((PlayerState*)inner)->isHoldingObject = 0;
            {
                int p = ((PlayerState*)inner)->heldObj;
                if ((u32)p != 0)
                {
                    s16 sp = *(s16*)(p + 0x46);
                    if (sp == 0x3cf || sp == 0x662)
                    {
                        objThrowFn_80182504(p);
                    }
                    else
                    {
                        objSaveFn_800ea774(p);
                    }
                    *(s16*)(((PlayerState*)inner)->heldObj + 6) &= ~0x4000;
                    *(int*)(((PlayerState*)inner)->heldObj + 0xf8) = 0;
                    ((PlayerState*)inner)->heldObj = 0;
                }
            }
        }
        if (*(s8*)(ctrl + 0x20) == 0 || (c = (s8)seq->movementState) == 3 || c == 2)
        {
            seq->flags = seq->unk70;
            if ((s8)seq->movementState != 2)
            {
                seq->posOffsetScale = lbl_803E7EE0;
                seq->posOffsetX = ((GameObject*)obj)->anim.localPosX - ((GameObject*)obj2)->anim.localPosX;
                seq->posOffsetY = ((GameObject*)obj)->anim.localPosY - ((GameObject*)obj2)->anim.localPosY;
                seq->posOffsetZ = ((GameObject*)obj)->anim.localPosZ - ((PlayerState*)obj2)->baddie.posX;
                seq->rotOffsetX = ((PlayerState*)inner)->targetYaw - (u16) * (s16*)obj2;
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
            if (seq->posOffsetScale <= lbl_803E7EA4)
            {
                seq->movementState = 0;
            }
            ((GameObject*)obj)->anim.activeMove = -1;
            ((PlayerState*)inner)->bodyLeanHalf = 0;
            ((PlayerState*)inner)->headPitch = 0;
            ((PlayerState*)inner)->bodyLeanAngle = 0;
            ((PlayerState*)inner)->headYaw = 0;
        }
        else if (c == 4)
        {
            f32 dz;
            f32 dy;
            f32 dx;
            int d;
            seq->flags &= ~0x4c;
            seq->unk70 &= ~0x48;
            obj2 = getFocusedNpc();
            if (objModelGetVecFn_800395d8(obj2, 0) != 0)
            {
                objPosFn_80039510(obj2, 0, npos);
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
            ObjPath_GetPointWorldPosition(obj, 5, (int)&px, (int)&py, (int)&pz, 0);
            dx = ((GameObject*)obj)->anim.worldPosX - npos[0];
            dy = (((PlayerState*)inner)->unk7DC + ((GameObject*)obj)->anim.worldPosY) - npos[1];
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
                    ((PlayerState*)inner)->unk4DA = -0x2aaa;
                    ((PlayerState*)inner)->unk4E0 = d - 0x2aaa;
                }
                else
                {
                    ((PlayerState*)inner)->unk4DA = -d;
                    ((PlayerState*)inner)->unk4E0 = 0;
                }
            }
            else if (d < -0x2aaa)
            {
                ((PlayerState*)inner)->unk4DA = 0x2aaa;
                ((PlayerState*)inner)->unk4E0 = d + 0x2aaa;
            }
            else
            {
                ((PlayerState*)inner)->unk4DA = -d;
                ((PlayerState*)inner)->unk4E0 = 0;
            }
            ((PlayerState*)inner)->unk4DE = (s16)getAngle(dy, sqrtf(dx * dx + dz * dz));
            {
                int v = ((PlayerState*)inner)->unk4DE;
                if (v < -0x1000)
                {
                    v = -0x1000;
                }
                else if (v > 0x1000)
                {
                    v = 0x1000;
                }
                ((PlayerState*)inner)->unk4DE = v;
            }
            seq->rotOffsetZ = 0;
            seq->posOffsetScale = lbl_803E7EA4;
            seq->posOffsetDecay = lbl_803E8154;
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
                    ObjAnim_SetCurrentMove(obj, mv, lbl_803E7EA4, 0);
                    ObjAnim_SetCurrentEventStepFrames((ObjAnimComponent*)obj, 1);
                }
            }
            ((void (*)(int, f32, f32, int))ObjAnim_AdvanceCurrentMove)(obj, lbl_803E7F78, timeDelta, 0);
            result = 1;
        }
        else if (c == 5)
        {
            seq->flags &= ~0x4c;
            seq->unk70 &= ~0x48;
            ObjHits_EnableObject(obj);
            if (seq->posOffsetScale >= lbl_803E7EE0 &&
                (*gCameraInterface)->isZooming() == 0)
            {
                ((PlayerState *)inner)->headYaw = 0;
                ((PlayerState *)inner)->bodyLeanAngle = 0;
                if ((s8)endFlag == 0)
                {
                    seq->movementState = 0;
                }
                else
                {
                    seq->movementState = 6;
                }
                if (*(u32*)&((PlayerState*)inner)->focusObject != 0)
                {
                    (**(void (**)(int, int, int))((char*)(*gPlayerInterface) + 0x14))(obj, (int)inner,
                        0x18);
                    *(void (**)(int))((char*)inner + 0x304) = fn_8029F67C;
                }
                else
                {
                    (**(void (**)(int, int, int))((char*)(*gPlayerInterface) + 0x14))(obj, (int)inner,
                        1);
                    *(void (**)(int, int))((char*)inner + 0x304) = fn_802A514C;
                    ((PlayerState*)inner)->baddie.unk276 = 1;
                }
            }
            else
            {
                f32 prev = seq->posOffsetScale;
                f32 one;
                int dd;
                seq->posOffsetScale = seq->posOffsetDecay * timeDelta + prev;
                if (seq->posOffsetScale > lbl_803E7EE0)
                {
                    seq->posOffsetScale = lbl_803E7EE0;
                }
                prev = seq->posOffsetScale - prev;
                ((PlayerState*)inner)->targetYaw +=
                    (s16)(prev * (f32) * (s16*)((char*)inner + 0x4e0));
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
                *(s16*)(va + 2) = (s16)((f32)dd * seq->posOffsetScale +
                    (f32) * (s16*)((char*)inner + 0x4d8));
                dd = *(s16*)((char*)inner + 0x4dc) - (u16) * (s16*)((char*)inner + 0x4de);
                if (dd > 0x8000)
                {
                    dd = dd - 0xffff;
                }
                if (dd < -0x8000)
                {
                    dd = dd + 0xffff;
                }
                *(s16*)va = (s16)((f32)dd * seq->posOffsetScale +
                    (f32) * (s16*)((char*)inner + 0x4dc));
                *(s16*)(vb + 2) = (s16)((f32) * (s16*)((char*)inner + 0x4d2) *
                    ((one = lbl_803E7EE0) - seq->posOffsetScale));
                *(s16*)(vb + 4) = (s16)((f32) * (s16*)((char*)inner + 0x4d0) *
                    (one - seq->posOffsetScale));
                ((GameObject*)obj)->anim.rotZ = *(s16*)(vb + 4) / 4;
                ((PlayerState*)inner)->bodyLeanAngle = *(s16*)(va + 2);
                ((PlayerState*)inner)->headYaw = -*(s16*)va;
            }
            ((void (*)(int, f32, f32, int))ObjAnim_AdvanceCurrentMove)(obj, lbl_803E7F78, timeDelta, 0);
            result = 1;
        }
        else if (c == 6)
        {
            seq->flags &= ~0x4c;
            seq->unk70 &= ~0x48;
            ObjHits_EnableObject(obj);
            if ((s8)endFlag == 0)
            {
                seq->movementState = 0;
            }
            ((void (*)(int, f32, f32, int))ObjAnim_AdvanceCurrentMove)(obj, lbl_803E7F78, timeDelta, 0);
            result = 0;
        }
        else
        {
            f32 dz2;
            f32 dist;
            f32 dx2;
            f32 d2;
            if (c != 1)
            {
                seq->posOffsetX = ((GameObject*)obj)->anim.localPosX;
                seq->posOffsetY = ((GameObject*)obj)->anim.localPosY;
                seq->posOffsetZ = ((GameObject*)obj)->anim.localPosZ;
                lbl_803DE468 = lbl_803E80AC;
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
                    seq->flags = seq->unk70;
                    seq->movementState = 0;
                    seq->prevFrame = seq->curFrame - 1;
                    ((GameObject*)obj)->anim.activeMove = -1;
                    result = 0;
                }
                else
                {
                    f32 fz3 = lbl_803E7EA4;
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
                    fn_802B0EA4(obj, (int)inner, (int)inner);
                    (**(void (**)(f32, int, int, f32, void*, void*))((char*)(*gPlayerInterface) +
                        8))(
                        timeDelta, obj, (int)inner, timeDelta, gPlayerStateHandlers, &gPlayerDefaultStateHandler);
                }
            }
            else
            {
                dx2 = dx2 / d2;
                dz2 = dz2 / d2;
                {
                    f32 k = lbl_803E80C4;
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
                fn_802B0EA4(obj, (int)inner, (int)inner);
                (**(void (**)(f32, int, int, f32, void*, void*))((char*)(*gPlayerInterface) +
                    8))(timeDelta, obj, (int)inner,
                        timeDelta, gPlayerStateHandlers,
                        &gPlayerDefaultStateHandler);
            }
            lbl_803DE468 = dist;
        }
        if ((s8)seq->movementState == 0)
        {
            (**(void (**)(int, int, int))((char*)(*gPlayerInterface) + 0x14))(obj, (int)inner, 1);
            *(void (**)(int, int))((char*)inner + 0x304) = fn_802A514C;
            ((PlayerState*)inner)->baddie.unk276 = 1;
        }
    }
    else
    {
        seq->flags |= seq->unk70 & ~0x400;
        *(u8*)((char*)inner + 0x34c) = 0;
        {
            f32 fz2 = lbl_803E7EA4;
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
                    best = lbl_803E80AC;
                    for (endFlag = 0; endFlag < objCount; endFlag++)
                    {
                        va = *(int*)obj2;
                        if ((u32)va != 0 && arrayIndexOf((void*)(tbl + 0x13c), 9, *(s16*)(va + 0x46)) != -1)
                        {
                            f32 dsq = vec3f_distanceSquared((void*)(va + 0x18), (void*)(obj + 0x18));
                            if (dsq < best || found == 0)
                            {
                                best = dsq;
                                ((PlayerState*)inner)->focusObject = va;
                                found = 1;
                            }
                        }
                        obj2 += 4;
                    }
                    if (found != 0)
                    {
                        ((PlayerState*)inner)->unk6A4 = lbl_803E7EE0;
                        ((PlayerState*)inner)->unk6A8 = ((PlayerState *)inner)->savedPosY;
                        ((PlayerState*)inner)->unk6AC = ((PlayerState *)inner)->savedPosZ;
                        ((PlayerState*)inner)->unk6B0 = ((PlayerState*)inner)->savedPosZ;
                        va = ((PlayerState*)inner)->focusObject;
                        (*(void (*)(int, int))*(int*)((char*)*(int*)(*(int*)(va + 0x68)) + 0x3c))(
                            va, 2);
                        ((GameObject*)obj)->anim.flags |= 8;
                        ((GameObject*)obj)->anim.modelState->flags |= OBJ_MODEL_STATE_SHADOW_FADE_OUT;
                        ((GameObject*)obj)->anim.modelState->shadowAlphaStep = 0;
                        seq->flags &= ~4;
                        switch (*(s16*)(va + 0x46))
                        {
                        case 0x72:
                        case 0x38c:
                            Music_Trigger(0x97, 1);
                            GameBit_Set(0xc1f, 0);
                            ((PlayerState*)inner)->moveSequence = tbl + 0x3f0;
                            ((PlayerState*)inner)->moveSequenceFlags = 3;
                            ObjAnim_SetCurrentMove(obj, 0x17, lbl_803E7EA4, 1);
                            break;
                        case 0x8c:
                            ((PlayerState*)inner)->moveSequence = tbl + 0x408;
                            ((PlayerState*)inner)->moveSequenceFlags = 4;
                            ObjAnim_SetCurrentMove(obj, 0x7b, lbl_803E7EA4, 1);
                            if ((u32)getSbGalleon() != 0)
                            {
                                (*gCameraInterface)->setFocus((void*)va, 0);
                                (*gObjectTriggerInterface)
                                    ->setCamVars(0x4a, 1, 0, 0x78);
                            }
                            break;
                        case 0x416:
                            Music_Trigger(0xd5, 1);
                            ((PlayerState*)inner)->moveSequence = tbl + 0x438;
                            ((PlayerState*)inner)->moveSequenceFlags = 8;
                            ObjAnim_SetCurrentMove(obj, *(s16*)(tbl + 0x438), lbl_803E7EA4, 1);
                            break;
                        case 0x419:
                            Music_Trigger(0xe6, 1);
                            ((PlayerState*)inner)->moveSequence = tbl + 0x408;
                            ((PlayerState*)inner)->moveSequenceFlags = 4;
                            ObjAnim_SetCurrentMove(obj, 0x7b, lbl_803E7EA4, 1);
                            break;
                        case 0x484:
                            Music_Trigger(0xe6, 1);
                            ((PlayerState*)inner)->moveSequence = tbl + 0x420;
                            ((PlayerState*)inner)->moveSequenceFlags = 4;
                            ObjAnim_SetCurrentMove(obj, 0xf8, lbl_803E7EA4, 1);
                            break;
                        default:
                            Music_Trigger(0x1f, 1);
                        case 0x714:
                            ((PlayerState*)inner)->moveSequence = tbl + 0x420;
                            ((PlayerState*)inner)->moveSequenceFlags = 4;
                            ObjAnim_SetCurrentMove(obj, 0xf8, lbl_803E7EA4, 1);
                        }
                        if (arrayIndexOf((void*)(tbl + 0x160), 4, *(s16*)(va + 0x46)) != -1)
                        {
                            (**(void (**)(int, int, int))((char*)(*gPlayerInterface) + 0x14))(
                                obj, (int)inner, 0x1a);
                            *(void (**)(int))((char*)inner + 0x304) = fn_8029F67C;
                        }
                        else
                        {
                            (**(void (**)(int, int, int))((char*)(*gPlayerInterface) + 0x14))(
                                obj, (int)inner, 0x18);
                            *(void (**)(int))((char*)inner + 0x304) = fn_8029F67C;
                        }
                    }
                    break;
                }
            case 2:
                if (fn_802957B4(obj) != 0)
                {
                    seq->flags |= 4;
                }
                break;
            case 4:
                obj2 = ((PlayerState*)inner)->focusObject;
                (*gCameraInterface)->setFocus((void*)obj2, 0);
                (*gObjectTriggerInterface)->setCamVars(0x45, 0, 0, 0);
                ((PlayerState*)inner)->moveSequence = 0;
                if ((u32)obj2 != 0 && ((GameObject*)obj2)->anim.seqId == 0x22)
                {
                    (**(void (**)(int, int, int))((char*)(*gPlayerInterface) + 0x14))(obj, (int)inner,
                        0x16);
                    *(int*)&((PlayerState*)inner)->baddie.unk304 = 0;
                }
                else
                {
                    (**(void (**)(int, int, int))((char*)(*gPlayerInterface) + 0x14))(obj, (int)inner,
                        0x18);
                    *(void (**)(int))((char*)inner + 0x304) = fn_8029F67C;
                }
                break;
            case 0xb:
                {
                    int gb = ((PlayerState*)inner)->focusObject;
                    if ((u32)gb != 0 && *(s16*)(gb + 0x46) == 0x416)
                    {
                        (*gCameraInterface)->setFocus((void*)gb, 0);
                        (*gCameraInterface)->loadTriggeredCamAction(0, 0x69, 0);
                        (*gObjectTriggerInterface)
                            ->setCamVars(0x42, 4, 0, 0);
                    }
                    else if ((u32)gb != 0 && arrayIndexOf((void*)(tbl + 0x160), 4, *(s16*)(gb + 0x46)) != -1)
                    {
                        (*gObjectTriggerInterface)
                            ->setCamVars(0x53, 0, 0, 0);
                    }
                    else
                    {
                        (*gCameraInterface)->loadTriggeredCamAction(0, 0x1d, 0);
                        (*gObjectTriggerInterface)
                            ->setCamVars(0x42, 4, 0, 0);
                    }
                    break;
                }
            case 6:
                (*gObjectTriggerInterface)->setCamVars(0x44, 0, 0, 0);
                (**(void (**)(int, int, int))((char*)(*gPlayerInterface) + 0x14))(obj, (int)inner,
                    0x17);
                *(int*)&((PlayerState*)inner)->baddie.unk304 = 0;
                break;
            case 7:
                seq->flags &= ~3;
                obj2 = *(int*)&((GameObject*)obj)->extra;
                (**(void (**)(int, int, int))((char*)(*gPlayerInterface) + 0x14))(obj, obj2,
                    0x3e);
                *(int*)&((PlayerState*)obj2)->baddie.unk304 = 0;
                *(u32*)(obj2 + 0x360) |= 1LL;
                ((GameObject*)obj)->anim.flags |= 8;
                break;
            case 8:
                {
                    seq->flags = seq->unk70;
                    obj2 = *(int*)&((GameObject*)obj)->extra;
                    (**(void (**)(int, int, int))((char*)(*gPlayerInterface) + 0x14))(obj, obj2, 1);
                    *(void (**)(int, int))(obj2 + 0x304) = fn_802A514C;
                    *(u32*)((char*)obj2 + 0x360) &= ~0x1LL;
                    ((GameObject*)obj)->anim.flags &= ~8;
                    break;
                }
            case 0xa:
                if (gPlayerPathObject != NULL &&
                    ((u32) * (u8*)((char*)inner + 0x3f4) >> 6 & 1) != 0)
                {
                    ((PlayerState*)inner)->staffActionRequest = 2;
                    ((ByteFlags*)((char*)inner + 0x3f4))->b08 = 0;
                }
                break;
            case 0x18:
                if (gPlayerPathObject != NULL &&
                    ((u32) * (u8*)((char*)inner + 0x3f4) >> 6 & 1) != 0)
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
                    (*gObjectTriggerInterface)->setObjects(
                        *(s16*)(*(int*)&((GameObject*)obj)->ownerObj + 0x46), *(int*)&((GameObject*)obj)->ownerObj,
                        0);
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
                            lbl_803E8158;
                    }
                    sp3 = spd *
                        -mathCosf(gPlayerPi * (f32) * (s16*)(obj2 + 0x478) / lbl_803E7F98);
                    (*gObjectTriggerInterface)->setOverridePos(
                        spd * -mathSinf(gPlayerPi * (f32) * (s16*)(obj2 + 0x478) /
                            lbl_803E7F98),
                        dy2, sp3);
                    (*gObjectTriggerInterface)
                        ->runSequence(((GameObject*)obj)->unkF4, (void*)obj, -1);
                    break;
                }
            case 0xf:
                objHitDetectFn_80062e84(obj, 0, 1);
                break;
            case 0x10:
                {
                    int t;
                    nearArg = lbl_803E815C;
                    t = ObjGroup_FindNearestObject(6, obj, &nearArg);
                    if ((u32)t != 0)
                    {
                        objHitDetectFn_80062e84(obj, t, 1);
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
                                objThrowFn_80182504(p17);
                            }
                            else
                            {
                                objSaveFn_800ea774(p17);
                            }
                            *(s16*)(*(int*)(va + 0x7f8) + 6) &= ~0x4000;
                            *(int*)(*(int*)(va + 0x7f8) + 0xf8) = 0;
                            *(int*)(va + 0x7f8) = 0;
                        }
                    }
                    *(u32*)((char*)va + 0x360) |= 0x800000LL;
                    (**(void (**)(int, int, int))((char*)(*gPlayerInterface) + 0x14))(obj, va,
                        1);
                    *(void (**)(int, int))(va + 0x304) = fn_802A514C;
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
                    *(u32*)&((PlayerState*)inner)->flags360 |= 0x20000LL;
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
                fn_80295CF4(obj, 0);
                break;
            case 0x1d:
                (**(void (**)(int, int, int))((char*)(*gPlayerInterface) + 0x14))(obj, (int)inner,
                    0x1a);
                *(void (**)(int))((char*)inner + 0x304) = fn_8029F67C;
                break;
            case 0x1e:
                (**(void (**)(int, int, int))((char*)(*gPlayerInterface) + 0x14))(obj, (int)inner, 1);
                *(void (**)(int, int))((char*)inner + 0x304) = fn_802A514C;
                break;
            case 0x1f:
                __set_debug_bba(gPlayerModelChain);
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
                        (*gGameUIInterface)->showNpcDialogue(
                            snd, 0x154, 300, 0);
                    }
                    else
                    {
                        (*gGameUIInterface)->showNpcDialogue(
                            *(s16*)(p1a + 0x7c), 0x154, 300, 0);
                    }
                }
                break;
            case 1:
                if (*(u32*)&((PlayerState*)inner)->interactObject != 0)
                {
                    ObjMsg_SendToObject(((PlayerState*)inner)->interactObject, 0x7000b, obj, 0);
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
                    switch (coordsToMapCell(((GameObject*)obj)->anim.localPosX,
                                            ((GameObject*)obj)->anim.localPosZ))
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
                    getEnvfxActImmediately(obj, obj, 0x1fb, 0);
                    getEnvfxActImmediately(obj, obj, 0x1ff, 0);
                    getEnvfxActImmediately(obj, obj, 0x249, 0);
                    getEnvfxActImmediately(obj, obj, 0x1fd, 0);
                }
                else
                {
                    getEnvfxActImmediately(obj, obj, 0x217, 0);
                    getEnvfxActImmediately(obj, obj, 0x216, 0);
                    getEnvfxActImmediately(obj, obj, 0x22e, 0);
                    getEnvfxActImmediately(obj, obj, 0x218, 0);
                    getEnvfxActImmediately(obj, obj, 0x84, 0);
                    getEnvfxActImmediately(obj, obj, 0x8a, 0);
                }
                ((void (*)(int, f32))skyFn_80088e54)(0, lbl_803E7EA4);
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
                    ((GameObject*)obj)->anim.modelState->flags &= ~OBJ_MODEL_STATE_SHADOW_VISIBLE;
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
        int g = ((PlayerState*)inner)->focusObject;
        if ((u32)g != 0 &&
            (*(int (*)(int))*(int*)((char*)*(int*)(*(int*)(g + 0x68)) + 0x38))(g) == 2)
        {
            seq->flags &= ~3;
        }
    }
    if (((u32) * (u8*)((char*)inner + 0x3f2) >> 6 & 1) != 0)
    {
        characterDoEyeAnims(obj, (int)((char*)inner + 0x364));
    }
    if (gPlayerSubState == 2)
    {
        gPlayerSubState = 1;
    }
    if (((GameObject*)gPlayerPathObject)->anim.classId == 0x2d)
    {
        ((void (*)(void))objSetAnimField48to0)();
    }
    ((void (*)(int, int, f32))fn_802AEF34)(obj, (int)inner, timeDelta);
    if (gPlayerPathObject != NULL && ((u32) * (u8*)((char*)inner + 0x3f4) >> 6 & 1) != 0)
    {
        ((GameObject*)gPlayerPathObject)->objectFlags &= ~7;
        if (((PlayerState*)inner)->staffGrown == 0)
        {
            ((GameObject*)gPlayerPathObject)->objectFlags |= 2;
        }
    }
    *(u32*)&((PlayerState*)inner)->flags360 |= 0x800000LL;
    ((void (*)(int, int, int, int, int, f32, f32))objAudioFn_8006ef38)(
        obj, (int)&seq->animEvents, ((PlayerState*)inner)->animSoundId,
        (int)((char*)inner + 0x3c4), (int)((char*)inner + 4),
        ((PlayerState*)inner)->baddie.animSpeedA, lbl_803E7EE0);
    return result;
}

extern f32 lbl_803E8090;
extern f32 lbl_803E8094;
extern f32 lbl_803E8098;
extern f32 lbl_803E809C;
extern f32 lbl_803E80A0;
extern char sNotOnGroundFailureMessage[];

int fn_802A87CC(int obj, char* cam, f32* out, f32* vec, f32 fa, f32 fb);

/* Number of directional sweep probes (parallel dirs[13]/dirMasks[13] tables). */
#define PLAYER_SWEEP_DIR_COUNT 13

s8 fn_802A74A4(int obj, int state, int state2, void* out, f32 fv, u32 mask)
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
    f32 nearDist;
    f32 cEE0;
    int objCount;
    s8 dirs[13] = {0xb, 4, 6, 0xa, 0xa, 3, 3, 2, 0xe, 0x10, 0x12, 0x13, 5};
    volatile f32 sc0[3];
    volatile f32 sc1[3];
    f32 end[3];
    f32 start[3];
    f32 vec[3];
    f32 rot[3];
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
    u16 dirMasks[13] = {1, 2, 4, 8, 8, 0x10, 0x10, 0x40, 0x80, 0x100, 1, 0x20, 0xffff};
    SweepHit buf;
    u8 useAlt;
    f32 hd;
    f32 dp;
    int i;
    s8 ok;
    f32 ang;
    s8 flagB;
    s8 flagA;
    u8 hit;
    f32* dir;

    ang = (gPlayerPi *
            (f32)((u16)getAngle(((PlayerState*)state2)->baddie.moveInputX, -((PlayerState*)state2)->baddie.moveInputZ) -
                ((PlayerState*)state2)->baddie.cameraYaw)) /
        lbl_803E7F98;
    rot[0] = -mathSinf(ang);
    rot[1] = lbl_803E7EA4;
    rot[2] = -mathCosf(ang);
    fn_802A81B8(obj, state, vec);
    sc1[0] = lbl_803E808C * rot[0];
    sc1[1] = lbl_803E808C * rot[1];
    sc1[2] = lbl_803E808C * rot[2];
    sc0[0] = lbl_803E808C * vec[0];
    sc0[1] = lbl_803E808C * vec[1];
    sc0[2] = lbl_803E808C * vec[2];
    *(u32*)&((PlayerState*)state)->flags360 &= ~0x100LL;
    cEE0 = lbl_803E7EE0;
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
                s16 v = ((PlayerState*)state)->baddie.controlMode;
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
                fn_80137948(sNotOnGroundFailureMessage);
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
                end[0] = ((GameObject*)obj)->anim.localPosX + sc1[0];
                end[1] = ((GameObject*)obj)->anim.localPosY + sc1[1];
                end[2] = ((GameObject*)obj)->anim.localPosZ + sc1[2];
                dir = rot;
            }
            else
            {
                end[0] = ((GameObject*)obj)->anim.localPosX + sc0[0];
                end[1] = ((GameObject*)obj)->anim.localPosY + sc0[1];
                end[2] = ((GameObject*)obj)->anim.localPosZ + sc0[2];
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
                start[0] = ((GameObject*)obj)->anim.localPosX + sc1[0];
                start[1] = ((GameObject*)obj)->anim.localPosY + sc1[1];
                start[2] = ((GameObject*)obj)->anim.localPosZ + sc1[2];
                dir = rot;
            }
            else
            {
                start[0] = ((GameObject*)obj)->anim.localPosX + sc0[0];
                start[1] = ((GameObject*)obj)->anim.localPosY + sc0[1];
                start[2] = ((GameObject*)obj)->anim.localPosZ + sc0[2];
                dir = vec;
            }
            end[0] = ((GameObject*)obj)->anim.localPosX;
            end[1] = ((GameObject*)obj)->anim.localPosY;
            end[2] = ((GameObject*)obj)->anim.localPosZ;
        }
        hit = objBboxFn_800640cc(lbl_803E7EA4, start, end, 3, &buf, obj, 1, dirs[i], 0xff, 10);
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
                    if (dp > lbl_803E8090 ||
                        (((GameObject*)obj)->anim.localPosY > buf.g3c - lbl_803E7ED8 &&
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
            hit = objBboxFn_800640cc(lbl_803E7EA4, start, end, 3, &buf, obj, 1, dirs[i], 0xff,
                                     10);
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
                if ((*(int (*)(int))*(int*)((char*)*(int*)(t + 0x68) + 0x2c))(t) != 0 &&
                    *(f32*)(state2 + 0x298) > lbl_803E7EFC &&
                    hd <= lbl_803E7ED4 + lbl_803DC6C0)
                {
                    switch (((int (*)(int, int, void*, int, f32*, f32))fn_802A8EE4)(
                        obj, state, &buf, state + 0x5a8, end, hd))
                    {
                    case 2:
                        return 4;
                    case 3:
                        return 5;
                    }
                }
                if (hd >= lbl_803E7FA4)
                {
                    continue;
                }
                if (*(u8*)(t + 0xaf) & 8)
                {
                    continue;
                }
                *(u32*)&((PlayerState*)state)->flags360 |= 0x100LL;
                if ((*(int*)&((PlayerState*)state2)->baddie.unk31C & 0x100) == 0)
                {
                    continue;
                }
                ((PlayerState*)state)->surfaceNormalX = buf.nx;
                ((PlayerState*)state)->surfaceNormalY = buf.ny;
                ((PlayerState*)state)->surfaceNormalZ = buf.nz;
                ((PlayerState*)state)->unk660 = buf.g38;
                *(u8*)&((PlayerState*)state)->unk681 = 0;
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
            if (hd >= lbl_803E8098)
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
            ((PlayerState*)state)->unk660 = buf.g38;
            *(u8*)&((PlayerState*)state)->unk681 = 0;
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
            if (hd > lbl_803E7F58)
            {
                continue;
            }
            if (player_probeClimbable(obj, state, (int)&buf, state + 0x4e4, i == 3) == 0)
            {
                continue;
            }
            return 0;
        case 5:
        case 6:
            if (hd > cEE0 + lbl_803DC6C0)
            {
                continue;
            }
            if (fn_802A8680(obj, state, (int)&buf, (int)end, state + 0x548, i == 5) == 0)
            {
                continue;
            }
            return 9;
        case 1:
        case 7:
        case 12:
            if (hd >= lbl_803E7F58)
            {
                continue;
            }
            switch (fn_802A87CC(obj, (char*)&buf, (f32*)(state + 0x5a8), end, hd, fv))
            {
            case 4:
                return 8;
            case 5:
                return 7;
            }
            break;
        case 2:
        case 9:
            if (hd > cEE0 + lbl_803DC6C0)
            {
                continue;
            }
            switch (((int (*)(int, int, void*, int, f32*, f32))fn_802A8EE4)(obj, state, &buf,
                                                                            state + 0x5a8, end,
                                                                            hd))
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
                if (hd > cEE0 + lbl_803DC6C0)
                {
                    continue;
                }
                nearDist = lbl_803E808C;
                t8 = ObjGroup_FindNearestObject(0x23, obj, &nearDist);
                ok2 = 1;
                if ((u32)t8 != 0)
                {
                    if ((*(u8 (*)(int))*(int*)((char*)*(int*)(t8 + 0x68) + 0x24))(t8) == 0)
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
            if (hd >= lbl_803E809C)
            {
                continue;
            }
            if (buf.kind == 0xd)
            {
                int k;
                f32 inv;
                if (((PlayerState*)state2)->baddie.animSpeedA <= lbl_803E80A0)
                {
                    continue;
                }
                if (((PlayerState*)state)->particleBurstCooldown <= lbl_803E7EA4)
                {
                    inv = lbl_803E7F5C;
                    for (k = 0; k < 0x4b; k++)
                    {
                        f32 lo;
                        lo = buf.minX;
                        pfx.x = lo + (buf.maxX - lo) * (f32)randomGetRange(0, 100) /
                            inv;
                        lo = buf.minY;
                        pfx.y = lo + (buf.g3c - lo) * (f32)randomGetRange(0, 100) /
                            inv;
                        lo = buf.minZ;
                        pfx.z = lo + (buf.maxZ - lo) * (f32)randomGetRange(0, 100) /
                            inv;
                        pfx.scale = cEE0;
                        pfx.mode = 0x3c;
                        (*gPartfxInterface)->spawnObject((void*)obj, 0x804, &pfx, 0x200001,
                                                         -1, NULL);
                    }
                    ((PlayerState*)state)->particleBurstCooldown = lbl_803E7F30;
                }
            }
            else
            {
                ObjPath_GetPointWorldPosition(obj, 0xb, &pfx.x, &pfx.y, &pfx.z, 0);
                ((void (*)(int, int, int, int, int, f32, f32, f32))ObjHits_RecordPositionHit)(
                    obj, 0, 8, 1, -1, pfx.x, pfx.y, pfx.z);
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
            if ((*(int (*)(int, int))*(int*)((char*)*(int*)(cur + 0x68) + 0x20))(cur, obj) !=
                0)
            {
                ((PlayerState*)state)->focusObject = cur;
                return 0xa;
            }
            objs++;
        }
    }
    return -1;
}

int fn_802ABAE8(int obj, int state, int inner, f32 fv)
{
    int d = ((PlayerState*)inner)->targetYaw - (u16)((PlayerState*)inner)->prevTargetYaw;
    int near;
    int g;
    if (d > 0x8000) d -= 0xffff;
    if (d < -0x8000) d += 0xffff;
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
        d = (int)((f32)(int)
        d * (lbl_803E7FC4 * f2)
        )
        ;
        if (d < -0xccc)
        {
            d = -0xccc;
        }
        else if (d > 0xccc)
        {
            d = 0xccc;
        }
    }
    d -= (u16)((PlayerState*)inner)->headPitch;
    if (d > 0x8000) d -= 0xffff;
    if (d < -0x8000) d += 0xffff;
    ((PlayerState*)inner)->headPitch = (f32)(int)((PlayerState*)inner)->headPitch +
        interpolate((f32)(int)d, lbl_803E7EB4, timeDelta);
    near = fn_802AB1D0(obj);
    if ((u32)near != 0 && (((u32)((PlayerState*)inner)->flags3F0 >> 7) & 1) == 0 &&
        (((u32)((PlayerState*)inner)->flags3F0 >> 6) & 1) == 0 &&
        (((u32)((PlayerState*)inner)->flags3F0 >> 4) & 1) == 0 &&
        (((u32)((PlayerState*)inner)->flags3F0 >> 5) & 1) == 0)
    {
        int gd = (u16)getAngle(-(*(f32*)((char*)near + 0xc) - ((GameObject*)obj)->anim.localPosX),
                               -(*(f32*)((char*)near + 0x14) - ((GameObject*)obj)->anim.localPosZ)) -
            (u16)((PlayerState*)inner)->targetYaw;
        f32 t;
        f32 f5;
        if (gd > 0x8000) gd -= 0xffff;
        if (gd < -0x8000) gd += 0xffff;
        t = lbl_803E7EE0 - (((PlayerState*)state)->baddie.animSpeedC - lbl_803E7E9C) /
            (((PlayerState*)inner)->maxSpeed - lbl_803E7E9C);
        f5 = lbl_803E80C4 * ((t < *(f32*)&lbl_803E7EA4) ? lbl_803E7EA4 : ((t > lbl_803E7EE0) ? lbl_803E7EE0 : t)) +
            lbl_803E80F4;
        g = (int)
        (((f32)(int)
        gd < lbl_803E80F8 * -f5
        )
        ?
        lbl_803E80F8 * -f5
        :
        (((f32)(int)
        gd > lbl_803E80F8 * f5
        )
        ?
        lbl_803E80F8* f5
        :
        (f32)(int)
        gd
        )
        )
        ;
    }
    else
    {
        g = 0;
    }
    {
        int r0;
        int h;
        if (!((((u32)((PlayerState*)inner)->flags3F1 >> 5) & 1) ||
            (((u32)((PlayerState*)inner)->flags3F0 >> 4) & 1)))
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
        if (h > 0x8000) h -= 0xffff;
        if (h < -0x8000) h += 0xffff;
        h = (int)((f32)(int)
        h * lbl_803E7EB4
        )
        ;
        if (h < -0x16c)
        {
            h = -0x16c;
        }
        else if (h > 0x16c)
        {
            h = 0x16c;
        }
        ((PlayerState*)inner)->bodyLeanAngle = (f32)(int)
        h * timeDelta +
            (f32)(int) * (s16*)((int)inner + 0x4D4);
        ((PlayerState*)inner)->bodyLeanHalf = ((PlayerState*)inner)->bodyLeanAngle / 2;
    }
    {
        int k = (int)(lbl_803E80F8 * (lbl_803E7ED8 * -fv));
        k -= (u16)((PlayerState*)inner)->headYaw;
        if (k > 0x8000) k -= 0xffff;
        if (k < -0x8000) k += 0xffff;
        ((PlayerState*)inner)->headYaw = *(s16*)((int)inner + 0x4D6) + k;
    }
}

void fn_80296EB4(int obj, int newParent)
{
    int oldParent = *(int*)&((GameObject*)obj)->anim.parent;
    int a0;
    int a1;
    int a2;
    int a3;
    int a4;
    int a5;
    PlayerState* inner = ((GameObject*)obj)->extra;
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
            ((GameObject*)obj)->anim.localPosX, ((GameObject*)obj)->anim.localPosY,
            ((GameObject*)obj)->anim.localPosZ, &s.wp[0], &s.wp[1], &s.wp[2], oldParent);
        ((void (*)(f32, f32, f32, f32*, f32*, f32*, int))Obj_TransformLocalPointToWorld)(
            ((GameObject*)obj)->anim.previousLocalPosX, ((GameObject*)obj)->anim.previousLocalPosY,
            ((GameObject*)obj)->anim.previousLocalPosZ, &s.wp2[0], &s.wp2[1], &s.wp2[2], oldParent);
        ((void (*)(f32, f32, f32, f32*, f32*, f32*, int))Obj_TransformLocalVectorToWorld)(
            ((GameObject*)obj)->anim.velocityX, lbl_803E7EA4, ((GameObject*)obj)->anim.velocityZ,
            &s.wv[0], &s.wv[1], &s.wv[2], oldParent);
        a0 = Angle_AddWrappedS16(((GameObject*)obj)->anim.rotX, oldParent);
        a1 = Angle_AddWrappedS16(inner->targetYaw, oldParent);
        a2 = Angle_AddWrappedS16(inner->yaw, oldParent);
        a3 = Angle_AddWrappedS16(inner->prevTargetYaw, oldParent);
        a4 = Angle_AddWrappedS16(inner->prevYaw, oldParent);
        a5 = Angle_AddWrappedS16(inner->lastInputHeading, oldParent);
        ((void (*)(f32, f32, f32, f32*, f32*, f32*, int))Obj_TransformLocalPointToWorld)(
            *(f32*)((char*)inner + 0x118), *(f32*)((char*)inner + 0x11c), *(f32*)((char*)inner + 0x120),
            &s.wp0[0], &s.wp0[1], &s.wp0[2], oldParent);
    }
    else
    {
        s.wp[0] = ((GameObject*)obj)->anim.localPosX;
        s.wp[1] = ((GameObject*)obj)->anim.localPosY;
        s.wp[2] = ((GameObject*)obj)->anim.localPosZ;
        s.wp2[0] = ((GameObject*)obj)->anim.previousLocalPosX;
        s.wp2[1] = ((GameObject*)obj)->anim.previousLocalPosY;
        s.wp2[2] = ((GameObject*)obj)->anim.previousLocalPosZ;
        s.wv[0] = ((GameObject*)obj)->anim.velocityX;
        s.wv[2] = ((GameObject*)obj)->anim.velocityZ;
        a0 = ((GameObject*)obj)->anim.rotX;
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
        Obj_TransformWorldPointToLocal(s.wp[0], s.wp[1], s.wp[2], &((GameObject*)obj)->anim.localPosX,
                                       &((GameObject*)obj)->anim.localPosY, &((GameObject*)obj)->anim.localPosZ,
                                       newParent);
        Obj_TransformWorldPointToLocal(s.wp2[0], s.wp2[1], s.wp2[2], &((GameObject*)obj)->anim.previousLocalPosX,
                                       &((GameObject*)obj)->anim.previousLocalPosY,
                                       &((GameObject*)obj)->anim.previousLocalPosZ, newParent);
        Obj_TransformWorldVectorToLocal(s.wv[0], lbl_803E7EA4, s.wv[2], &((GameObject*)obj)->anim.velocityX, &s.wv[1],
                                        &((GameObject*)obj)->anim.velocityZ, newParent);
        ((GameObject*)obj)->anim.rotX = Angle_SubWrappedS16(a0, newParent);
        inner->targetYaw = Angle_SubWrappedS16(a1, newParent);
        inner->yaw = Angle_SubWrappedS16(a2, newParent);
        inner->prevTargetYaw = Angle_SubWrappedS16(a3, newParent);
        inner->prevYaw = Angle_SubWrappedS16(a4, newParent);
        inner->lastInputHeading = Angle_SubWrappedS16(a5, newParent);
        Obj_TransformWorldPointToLocal(s.wp0[0], s.wp0[1], s.wp0[2], (f32*)((char*)inner + 0x118),
                                       (f32*)((char*)inner + 0x11c), (f32*)((char*)inner + 0x120), newParent);
    }
    else
    {
        ((GameObject*)obj)->anim.localPosX = s.wp[0];
        ((GameObject*)obj)->anim.localPosY = s.wp[1];
        ((GameObject*)obj)->anim.localPosZ = s.wp[2];
        ((GameObject*)obj)->anim.previousLocalPosX = s.wp2[0];
        ((GameObject*)obj)->anim.previousLocalPosY = s.wp2[1];
        ((GameObject*)obj)->anim.previousLocalPosZ = s.wp2[2];
        ((GameObject*)obj)->anim.velocityX = s.wv[0];
        ((GameObject*)obj)->anim.velocityZ = s.wv[2];
        ((GameObject*)obj)->anim.rotX = a0;
        inner->targetYaw = a1;
        inner->yaw = a2;
        inner->prevTargetYaw = a3;
        inner->prevYaw = a4;
        inner->lastInputHeading = a5;
        *(f32*)((char*)inner + 0x118) = s.wp0[0];
        *(f32*)((char*)inner + 0x11c) = s.wp0[1];
        *(f32*)((char*)inner + 0x120) = s.wp0[2];
    }
    ((GameObject*)obj)->anim.worldPosX = s.wp[0];
    ((GameObject*)obj)->anim.worldPosY = s.wp[1];
    ((GameObject*)obj)->anim.worldPosZ = s.wp[2];
    ((GameObject*)obj)->anim.previousWorldPosX = s.wp2[0];
    ((GameObject*)obj)->anim.previousWorldPosY = s.wp2[1];
    ((GameObject*)obj)->anim.previousWorldPosZ = s.wp2[2];
    Player_GetObjHitsState(obj)->localPosX = ((GameObject*)obj)->anim.localPosX;
    Player_GetObjHitsState(obj)->localPosY = ((GameObject*)obj)->anim.localPosY;
    Player_GetObjHitsState(obj)->localPosZ = ((GameObject*)obj)->anim.localPosZ;
    Player_GetObjHitsState(obj)->worldPosX = ((GameObject*)obj)->anim.worldPosX;
    Player_GetObjHitsState(obj)->worldPosY = ((GameObject*)obj)->anim.worldPosY;
    Player_GetObjHitsState(obj)->worldPosZ = ((GameObject*)obj)->anim.worldPosZ;
    *(int*)&((GameObject*)obj)->anim.parent = newParent;
}

int fn_802A8680(int p1, int p2, int src, int vec, int out, int flag)
{
    f32 d1;
    f32 d2;
    f32 nx;
    f32 ny;
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
    (ny * *(f32*)((char*)out + 0x4c) +
        (nx * *(f32*)((char*)out + 0x44) + c38 * *(f32*)((char*)out + 0x48)));
    nx = -nx;
    ny = -ny;
    d2 = -(nx * *(f32*)((char*)src + 0x8) + ny * *(f32*)((char*)src + 0x18)) +
    (ny * *(f32*)((char*)out + 0x4c) +
        (nx * *(f32*)((char*)out + 0x44) + c38 * *(f32*)((char*)out + 0x48)));
    if (d1 > lbl_803E80BC && d2 > lbl_803E80BC)
    {
        *(f32*)((char*)out + 0x8) = *(f32*)((char*)src + 0xc);
        *(f32*)((char*)out + 0x4) = *(f32*)((char*)src + 0x3c);
        *(s8*)((char*)out + 0x2) = (int)*(s8*)((char*)src + 0x53);
        return 1;
    }
    return 0;
}

int fn_8029ABD8(int obj, int state, f32 fv)
{
    PlayerState* inner = ((GameObject*)obj)->extra;
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
        Sfx_KeepAliveLoopedObjectSound(obj, 0x382);
        timer = inner->stateTimer - timeDelta;
        inner->stateTimer = timer;
        if (timer <= lbl_803E7EA4)
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
        pfx.mode = 0;
        (*gPartfxInterface)->spawnObject(
            (void*)gPlayerPathObject, 0x7f5, &pfx, 0x200000 + 1, -1, NULL);
        pfx.mode = 1;
        (*gPartfxInterface)->spawnObject(
            (void*)gPlayerPathObject, 0x7f5, &pfx, 0x200000 + 1, -1, NULL);
        if ((inner->buttonsHeld & gPlayerHeldButtonMask) == 0 ||
            *(s16*)((char*)*(int*)((char*)*(int*)&((GameObject*)obj)->extra + 0x35c) + 0x4) == 0 ||
            getCurSeqNo() != 0)
        {
            void** p = gPlayerSpawnedObjects;
            int i;
            inner->animState = -1;
            lbl_803DE42C = 0;
            for (i = 0; i < 7; i++)
            {
                if (p[i] != NULL)
                {
                    Obj_FreeObject((int)p[i]);
                    p[i] = NULL;
                }
            }
            if (gPlayerResource != NULL)
            {
                Resource_Release(gPlayerResource);
                gPlayerResource = NULL;
            }
        }
    }
    else if (inner->deferredItemCommand != -1 || (inner->buttonsJustPressed & 0x800) != 0)
    {
        int yitem;
        u16 b28;
        s16 item;
        if (inner->buttonsJustPressed & 0x800)
        {
            yitem = getYButtonItem(&item);
            b28 = 0x800;
        }
        else
        {
            yitem = 0;
            item = inner->deferredItemCommand;
            b28 = 0x100;
        }
        if (inner->deferredItemCommand != -1 ||
            (yitem == 1 && (item == 0x2d || item == 0x5ce)))
        {
            buttonDisable(0, 0x900);
            ((PlayerState*)inner)->buttonsJustPressed = inner->buttonsJustPressed & ~0x900;
            gPlayerSelectedItem = item;
            if (item != inner->animState)
            {
                fn_802AB38C(obj, (int)inner, item);
            }
            switch (gPlayerSelectedItem)
            {
            case 0x2d:
                {
                    int sub = *(int*)((char*)*(int*)&((GameObject*)obj)->extra + 0x35c);
                    if (*(s16*)((char*)sub + 0x4) >= 2)
                    {
                        int r = fn_8029A76C(obj, state, fv);
                        if (r != 0)
                        {
                            return r;
                        }
                    }
                    else
                    {
                        Sfx_PlayFromObject(0, SFXsp_skeep_mumb1);
                    }
                    break;
                }
            case 0x958:
                {
                    int sub = *(int*)((char*)*(int*)&((GameObject*)obj)->extra + 0x35c);
                    if (*(s16*)((char*)sub + 0x4) >= 0)
                    {
                        int r = ((int (*)(int, int, f32))fn_8029A5E4)(obj, state, fv);
                        if (r != 0)
                        {
                            return r;
                        }
                    }
                    else
                    {
                        Sfx_PlayFromObject(0, SFXsp_skeep_mumb1);
                    }
                    break;
                }
            case 0x5ce:
                {
                    int sub = *(int*)((char*)*(int*)&((GameObject*)obj)->extra + 0x35c);
                    if (*(s16*)((char*)sub + 0x4) >= 1)
                    {
                        int sub2;
                        int v;
                        ((void (*)(int))fn_802A96D8)(obj);
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
                    }
                    break;
                }
            }
        }
    }
    inner->animState = -1;
    return 0;
}

int fn_8029AF9C(int obj, int state)
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
            inner->aimInputZ =
                inner->aimInputZ +
                interpolate(c - inner->aimInputZ, lbl_803E7EFC, timeDelta);
            t = ((PlayerState*)state)->baddie.moveInputX / lbl_803E7FA8;
            c = (t < lbl_803E7ECC) ? lbl_803E7ECC : ((t > lbl_803E7EE0) ? lbl_803E7EE0 : t);
            inner->aimInputX =
                inner->aimInputX +
                interpolate(c - inner->aimInputX, lbl_803E7EFC, timeDelta);
            if (inner->aimInputX > lbl_803E7EA4)
            {
                spin = inner->aimInputX - lbl_803E7EA0;
                if (spin < lbl_803E7EA4)
                {
                    spin = lbl_803E7EA4;
                }
            }
            else
            {
                spin = lbl_803E7EA0 + inner->aimInputX;
                if (spin > lbl_803E7EA4)
                {
                    spin = lbl_803E7EA4;
                }
            }
            a = inner->aimInputZ;
            if (a > lbl_803E7EA4)
            {
                Object_ObjAnimSetSecondaryBlendMove((ObjAnimComponent*)obj, 0x441,
                                                    (int)(lbl_803E7FAC * a));
            }
            else
            {
                Object_ObjAnimSetSecondaryBlendMove((ObjAnimComponent*)obj, 0x440,
                                                    (int)(lbl_803E7FAC * -a));
            }
            inner->bodyLeanHalf = lbl_803E7FB0 * inner->aimInputX;
            objModelGetVecFn_800395d8(obj, 9);
            *(u32*)&((PlayerState*)inner)->flags360 &= ~0x400LL;
            if (gPlayerSelectedItem == 0x2d)
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
                k = lbl_803E7E98;
                inner->aimScreenY =
                    k * (bv * (f32)(int)
                low
                )
                +(f32)(int)
                low;
                if (av < lbl_803E7EA4)
                {
                    inner->aimScreenX =
                        k * (av * (f32)(int)
                    half
                    )
                    +(f32)(int)
                    half;
                }
                else
                {
                    inner->aimScreenX =
                        lbl_803E7F44 * (av * (f32)(int)
                    half
                    )
                    +(f32)(int)
                    half;
                }
                *(u32*)&((PlayerState*)inner)->flags360 |= 0x400LL;
            }
            if (lbl_803DE42C != 0)
            {
                f32 x;
                int hi;
                Sfx_KeepAliveLoopedObjectSound(obj, 0x382);
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
                hi = 0x200000;
                pfx.mode = 0;
                (*gPartfxInterface)->spawnObject(
                    (void*)gPlayerPathObject, 0x7f5, &pfx, hi + 1, -1, NULL);
                pfx.mode = 1;
                (*gPartfxInterface)->spawnObject(
                    (void*)gPlayerPathObject, 0x7f5, &pfx, hi + 1, -1, NULL);
                if ((inner->buttonsHeld & gPlayerHeldButtonMask) == 0 ||
                    *(s16*)((char*)*(int*)((char*)*(int*)&((GameObject*)obj)->extra + 0x35c) + 0x4) == 0 ||
                    getCurSeqNo() != 0)
                {
                    int i;
                    void** p;
                    lbl_803DE42C = 0;
                    i = 0;
                    p = gPlayerSpawnedObjects;
                    for (; i < 7; i++)
                    {
                        if (p[i] != NULL)
                        {
                            Obj_FreeObject((int)p[i]);
                            p[i] = NULL;
                        }
                    }
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
                if (inner->buttonsJustPressed & 0x800)
                {
                    yitem = getYButtonItem(&item);
                    b28 = 0x800;
                }
                else
                {
                    yitem = 0;
                    item = gPlayerSelectedItem;
                    b28 = 0x100;
                }
                if ((inner->buttonsJustPressed & 0x100) != 0 ||
                    (yitem == 1 && (item == 0x2d || item == 0x5ce)))
                {
                    buttonDisable(0, 0x900);
                    inner->buttonsJustPressed = inner->buttonsJustPressed & ~0x900;
                    gPlayerSelectedItem = item;
                    if (item != inner->animState)
                    {
                        fn_802AB38C(obj, (int)inner, item);
                    }
                    switch (gPlayerSelectedItem)
                    {
                    case 0x2d:
                        {
                            int sub = *(int*)((char*)*(int*)&((GameObject*)obj)->extra + 0x35c);
                            if (*(s16*)((char*)sub + 0x4) >= 2)
                            {
                                *(int*)&((PlayerState*)state)->baddie.unk308 = (int)fn_8029A4A8;
                                return 0x2f;
                            }
                            Sfx_PlayFromObject(0, 0x40c);
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
                            Sfx_PlayFromObject(0, 0x40c);
                            break;
                        }
                    case 0x5ce:
                        {
                            int sub = *(int*)((char*)*(int*)&((GameObject*)obj)->extra + 0x35c);
                            if (*(s16*)((char*)sub + 0x4) >= 1)
                            {
                                int sub2;
                                int v;
                                ((void (*)(int))fn_802A96D8)(obj);
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
                            Sfx_PlayFromObject(0, 0x40c);
                            break;
                        }
                    }
                }
            }
            inner->targetYaw =
                lbl_803E7FB4 * spin + (f32)(int)
            inner->targetYaw;
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
    if ((inner->buttonsJustPressed & 0x200) != 0 || inner->curAnimId != 0x52)
    {
        *(u32*)&((PlayerState*)inner)->flags360 &= ~0x2000000LL;
        *(int*)&((PlayerState*)state)->baddie.unk308 = (int)fn_8029A420;
        return 0x2c;
    }
    return 0;
}

extern f32 lbl_803E7FB8;

int fn_8029BDB4(int obj, int state, f32 fv)
{
    int r;
    u8 changed;
    int path;
    PlayerState* inner = ((GameObject*)obj)->extra;
    f32 amt;

    r = fn_8029B9FC(obj, state, fv);
    if (r != 0)
    {
        return r;
    }
    path = (int)gPlayerPathObject;
    *(s8*)&((PlayerState*)state)->baddie.unk34D = 1;
    gPlayerSubState = 5;
    if (*(s8*)&((PlayerState*)state)->baddie.moveJustStartedA == 0)
    {
        if (lbl_803DE459 != 0)
        {
            doRumble(lbl_803E7ED8);
            *(int*)&((PlayerState*)state)->baddie.unk308 = 0;
            return 0x28;
        }
        changed = 0;
        if (((PlayerState*)state)->baddie.moveSpeed > lbl_803E7EA4)
        {
            if ((*(int*)&((PlayerState*)state)->baddie.eventFlags & 0x200) != 0)
            {
                doRumble(lbl_803E7F10);
                Sfx_PlayFromObject(obj, 0x3cd);
                inner->pendingFxFlags = inner->pendingFxFlags | 4;
            }
            if ((*(int*)&((PlayerState*)state)->baddie.eventFlags & 0x400) != 0)
            {
                doRumble(lbl_803E7F10);
                Sfx_PlayFromObject(obj, 0x3cd);
                inner->pendingFxFlags = inner->pendingFxFlags | 4;
            }
            if ((((PlayerState*)state)->baddie.moveEventFlags & 1) == 0 &&
                ((GameObject*)obj)->anim.currentMoveProgress >
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
                Sfx_PlayFromObject(obj, sfx);
                ((PlayerState*)state)->baddie.moveEventFlags = ((PlayerState*)state)->baddie.moveEventFlags | 1;
            }
            if ((((PlayerState*)state)->baddie.moveEventFlags & 2) == 0 &&
                ((GameObject*)obj)->anim.currentMoveProgress >
                *(f32*)((inner->moveSlots + 0x54) + (u32)inner->moveSlotIndex * 0xb0))
            {
                Sfx_PlayFromObject(obj, 0x1a);
                ((PlayerState*)state)->baddie.moveEventFlags = ((PlayerState*)state)->baddie.moveEventFlags | 2;
            }
        }
        {
            int slot = inner->moveSlots + (u32)inner->moveSlotIndex * 0xb0;
            if (*(s8*)(slot + 0x15) >= 0)
            {
                if (((GameObject*)obj)->anim.currentMoveProgress > *(f32*)(slot + 0x28))
                {
                    *(u8*)((char*)state + 0x34a) = *(u8*)((char*)state + 0x34a) | 2;
                    if (*(u8*)((inner->moveSlots + 0x6c) + (u32)inner->moveSlotIndex * 0xb0) != 0u)
                    {
                        *(u8*)((char*)state + 0x34a) = *(u8*)((char*)state + 0x34a) | 4;
                        inner->unk8C0 = 0;
                    }
                }
                if (((GameObject*)obj)->anim.currentMoveProgress >
                    *(f32*)((inner->moveSlots + 0x20) + (u32)inner->moveSlotIndex * 0xb0))
                {
                    *(u8*)((char*)state + 0x34a) = *(u8*)((char*)state + 0x34a) | 1;
                }
                if (((GameObject*)obj)->anim.currentMoveProgress >
                    *(f32*)((inner->moveSlots + 0x24) + (u32)inner->moveSlotIndex * 0xb0))
                {
                    *(u8*)((char*)state + 0x34a) = *(u8*)((char*)state + 0x34a) & ~1;
                }
                if ((*(int*)&((PlayerState*)state)->baddie.unk31C & 0x100) != 0 &&
                    (*(u8*)((char*)state + 0x34a) & 1) != 0)
                {
                    *(u8*)((char*)state + 0x34a) = *(u8*)((char*)state + 0x34a) | 4;
                    *(int*)&((PlayerState*)state)->baddie.unk31C = *(int*)&((PlayerState*)state)->baddie.unk31C & ~
                        0x100;
                    buttonDisable(0, 0x100);
                    inner->unk8C0 = *(u8*)((char*)state + 0x34b);
                }
                if ((*(u8*)((char*)state + 0x34a) & 4) != 0 &&
                    (*(u8*)((char*)state + 0x34a) & 2) != 0)
                {
                    f32 v = (f32)(u8)fn_8014C4D8(*(int*)&((PlayerState*)state)->baddie.targetObj);
                    int slot2 = inner->moveSlots +
                        (u32)inner->moveSlotIndex * 0xb0;
                    if (v >= *(f32*)(slot2 + 0x8c))
                    {
                        inner->moveSlotIndex =
                            *(u8*)((slot2 + 0x15) + (u32)inner->unk8C0);
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
            f32 z = lbl_803E7EA4;
            inner->hitTimer = z;
            inner->hitCount = 0;
            inner->lastHitObject = 0;
            inner->activeHitWindow = -1;
            ((PlayerState*)state)->baddie.animSpeedC = z;
            ((PlayerState*)state)->baddie.animSpeedB = z;
            ((PlayerState*)state)->baddie.animSpeedA = z;
            ((GameObject*)obj)->anim.velocityX = z;
            ((GameObject*)obj)->anim.velocityY = z;
            ((GameObject*)obj)->anim.velocityZ = z;
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
            amt = (f32)inner->targetObjectBearing / lbl_803E7FB8;
        }
        inner->targetYaw = (f32)(int)
        inner->targetYaw + amt;
        inner->yaw = inner->targetYaw;
    }
    else if (*(s8*)&((PlayerState*)state)->baddie.moveJustStartedA != 0 && inner->cameraTargetObject != NULL &&
        inner->unk4B4 == 1)
    {
        if (inner->targetObjectBearingAbs < 0x4000)
        {
            amt = (f32)inner->targetObjectBearing;
        }
        inner->targetYaw = (f32)(int)
        inner->targetYaw + amt;
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
        *(int*)&((GameObject*)obj)->anim.weaponDaTable =
            (inner->moveSlots + (u32)inner->moveSlotIndex * 0xb0) + 0x60;
        if (((GameObject*)obj)->anim.currentMove !=
            gPlayerMoveSlotTable[*(s16*)((inner->moveSlots + (u32)inner->moveSlotIndex * 0xb0) + 0x2)])
        {
            ObjAnim_SetCurrentMove(obj,
                gPlayerMoveSlotTable[*(s16*)((inner->moveSlots + (u32)inner->moveSlotIndex * 0xb0) + 0x2)],
                *(f32*)((inner->moveSlots + (u32)inner->moveSlotIndex * 0xb0) + 0x68), 0);
            ObjAnim_SetCurrentEventStepFrames((ObjAnimComponent*)obj, 2);
        }
        *(u8*)((char*)state + 0x34a) = *(u8*)((char*)state + 0x34a) & ~0xef;
        ((PlayerState*)state)->baddie.moveSpeed = *(f32*)((inner->moveSlots + 0x1c) + (u32)inner->moveSlotIndex * 0xb0);
        inner->unk824 = ((PlayerState*)state)->baddie.moveSpeed;
        inner->cutsceneEnded = 0;
        ((PlayerState*)state)->baddie.animSpeedB = lbl_803E7EA4;
        ((PlayerState*)state)->baddie.moveEventFlags = 0;
        if (((PlayerState*)state)->baddie.targetObj != NULL)
        {
            if (inner->moveSlotIndex >= 5 && inner->moveSlotIndex <= 9)
            {
                (*(void (*)(int, int, f32, int))(*(int*)(*gPlayerInterface + 0x30)))(obj, state, fv, 1);
            }
            else
            {
                (*(void (*)(int, int, f32, int))(*(int*)(*gPlayerInterface + 0x30)))(obj, state, fv, 2);
            }
            {
                s16 v = ((GameObject*)obj)->anim.rotX;
                inner->yaw = v;
                inner->targetYaw = v;
            }
        }
        if (((GameObject*)obj)->anim.hitReactState != NULL)
        {
            Player_GetObjHitsState(obj)->suppressOutgoingHits = 0;
        }
        inner->activeHitWindow = -1;
        if (*(s16*)((char*)path + 0x44) == 0x2d)
        {
            objSetAnimField48to0((int*)path);
            (*(void (*)(int, int))*(int*)(*(int*)(*(int*)((char*)path + 0x68)) + 0x38))(
                path, *(u8*)((inner->moveSlots + 0x5c) + (u32)inner->moveSlotIndex * 0xb0));
            {
                int slot = inner->moveSlots +
                    (u32)inner->moveSlotIndex * 0xb0;
                (*(void (*)(int, f32, f32))*(int*)(*(int*)(*(int*)((char*)path + 0x68)) + 0x4c))(
                    path, *(f32*)(slot + 0x48), *(f32*)(slot + 0x4c));
            }
        }
        {
            f32 z = lbl_803E7EA4;
            inner->unk7D8 = z;
            inner->hitTimer = z;
            inner->hitCount = 0;
            inner->lastHitObject = 0;
        }
    }
    Player_GetObjHitsState(obj)->hitVolumePriority = 0xb;
    Player_GetObjHitsState(obj)->hitVolumeId = *(u8*)((inner->moveSlots + 0x14) + (u32)inner->moveSlotIndex * 0xb0);
    {
        int slot = inner->moveSlots + (u32)inner->moveSlotIndex * 0xb0;
        f32 t = *(f32*)(slot + 0xa0);
        if (t >= lbl_803E7EA4)
        {
            if (((GameObject*)obj)->anim.currentMoveProgress > t &&
                ((GameObject*)obj)->anim.currentMoveProgress < *(f32*)(slot + 0xa4))
            {
                if (lbl_803E7EA4 == inner->unk7D8)
                {
                    Sfx_PlayFromObject(obj, 0x21b);
                }
                inner->unk7D8 =
                    lbl_803E7ED4 * timeDelta + inner->unk7D8;
                if (inner->unk7D8 > *(f32*)&lbl_803E7FBC)
                {
                    inner->unk7D8 = lbl_803E7FBC;
                }
            }
            else
            {
                inner->unk7D8 = lbl_803E7EA4;
            }
        }
    }
    if ((*(u8*)((inner->moveSlots + 0x88) + (u32)inner->moveSlotIndex * 0xb0) &
            2) != 0 &&
        *(void**)&inner->lastHitObject != NULL)
    {
        if (inner->hitCount < inner->hitCountMax)
        {
            f32 t = inner->hitTimer - lbl_803E7EE0;
            inner->hitTimer = t;
            if (t <= lbl_803E7EA4)
            {
                ((void (*)(int, int, int, int, int))ObjHits_RecordObjectHit)(
                    inner->lastHitObject, obj, 0xb, 1, 0);
                *(s8*)&((PlayerState*)inner)->hitCount = *(s8*)&((PlayerState*)inner)->hitCount + 1;
                inner->hitTimer = (f32)(u8)
                inner->hitInterval;
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
            int stride = (u32)inner->moveSlotIndex * 0xb0;
            int base = inner->moveSlots + stride;
            int ent = base + off;
            if (((GameObject*)obj)->anim.currentMoveProgress >= *(f32*)(ent + 0x30) &&
                ((GameObject*)obj)->anim.currentMoveProgress <= *(f32*)(ent + 0x3c))
            {
                if ((s8)Player_GetObjHitsState(obj)->suppressOutgoingHits == 0)
                {
                    int bits;
                    switch (*(s8*)((char*)(base + 0x5d) + i))
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
                    inner->hitTimer = lbl_803E7EA4;
                    inner->lastHitObject = 0;
                }
                break;
            }
            off += 4;
        }
    }
    (*(void (*)(int, int, f32, int))(*(int*)(*gPlayerInterface + 0x20)))(obj, state, fv, 3);
    if (*(s8*)&((PlayerState*)state)->baddie.moveDone != 0)
    {
        Player_GetObjHitsState(obj)->suppressOutgoingHits = 0;
        if (((PlayerState*)state)->baddie.targetObj != NULL)
        {
            *(int*)&((PlayerState*)state)->baddie.unk308 = (int)fn_8029C8C8;
            return 0x25;
        }
        ((struct { u8 hi : 1; u8 lo : 7; }*)&inner->flags3F1)->hi = 1;
        *(u32*)&inner->flags360 |= 0x800000LL;
        *(int*)&((PlayerState*)state)->baddie.unk308 = (int)fn_802A514C;
        return 2;
    }
    if (((GameObject*)obj)->anim.currentMoveProgress >=
        *(f32*)((inner->moveSlots + 0x2c) + (u32)inner->moveSlotIndex * 0xb0))
    {
        if (((PlayerState*)state)->baddie.targetObj != NULL)
        {
            if ((*(int*)&((PlayerState*)state)->baddie.unk31C & 0x100) != 0)
            {
                Player_GetObjHitsState(obj)->suppressOutgoingHits = 0;
                inner->activeHitWindow = -1;
                (*(void (*)(int, int, f32, int))(*(int*)(*gPlayerInterface + 0x30)))(obj, state, fv, 2);
                {
                    s16 v = ((GameObject*)obj)->anim.rotX;
                    inner->yaw = v;
                    inner->targetYaw = v;
                }
                *(int*)&((PlayerState*)state)->baddie.unk308 = 0;
                return 0x31;
            }
        }
        else if ((*(int*)&((PlayerState*)state)->baddie.unk31C & 0x100) != 0 &&
                 ((PlayerState*)state)->baddie.inputMagnitude > lbl_803E7EAC)
        {
            inner->targetYaw =
                inner->targetYaw + inner->targetYawRate * 0xb6;
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

int fn_802977A8(int obj, int state)
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

int fn_8029D454(int obj, int state)
{
    PlayerState* inner = ((GameObject*)obj)->extra;
    ((PlayerState*)state)->baddie.unk34D = 3;
    if (*(s8*)((char*)inner->playerStatus) > 0)
    {
        ObjAnim_SetCurrentMove(obj, 0xc8, lbl_803E7EA4, 0);
        *(int*)&((PlayerState*)state)->baddie.unk308 = 0;
        return -0x21;
    }
    return 0;
}

int fn_8029B994(int obj, int state)
{
    PlayerState* inner = ((GameObject*)obj)->extra;
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

int fn_8029EBCC(int obj, int state)
{
    PlayerState* inner = ((GameObject*)obj)->extra;
    void* sub;
    f32 v7b8, v7bc;
    int res, halfW, halfH;

    *(u32*)&inner->flags360 &= ~2LL;
    ObjHits_EnableObject(obj);
    sub = *(void**)((char*)inner + 0x7f0);
    if (sub == NULL)
    {
        f32 z = lbl_803E7EA4;
        ((PlayerState*)state)->baddie.animSpeedC = z;
        ((PlayerState*)state)->baddie.animSpeedB = z;
        ((PlayerState*)state)->baddie.animSpeedA = z;
        ((GameObject*)obj)->anim.velocityX = z;
        ((GameObject*)obj)->anim.velocityY = z;
        ((GameObject*)obj)->anim.velocityZ = z;
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
        (*gCameraInterface)->setMode(
            0x53, 1, sub != NULL ? 0x12 : -2, 0, NULL, 0, 0xff);
        ObjAnim_SetCurrentMove(obj, 0x43e, lbl_803E7EA4, 0);
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
    if (((GameObject*)obj)->anim.alpha > 1)
    {
        ((GameObject*)obj)->anim.alpha = 1;
    }
    inner->actionCooldown = inner->actionCooldown - timeDelta;
    if (inner->actionCooldown < lbl_803E7EA4)
    {
        inner->actionCooldown = *(f32*)&lbl_803E7EA4;
    }
    if ((inner->buttonsJustPressed & 0x100) != 0)
    {
        if (inner->actionCooldown <= lbl_803E7EA4)
        {
            buttonDisable(0, 0x100);
            ((void (*)(int, int, f32, f32))fn_802AA014)(obj, state, inner->aimInputZ, lbl_803E7EA4);
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
        inner->aimInputZ +=
            interpolate(c - inner->aimInputZ, lbl_803DC6D4, timeDelta);
    }
    {
        f32 x = ((PlayerState*)state)->baddie.moveInputX / lbl_803E7FA8;
        f32 c;
        c = (x < lbl_803E7ECC) ? lbl_803E7ECC : ((x > lbl_803E7EE0) ? lbl_803E7EE0 : x);
        inner->aimInputX +=
            interpolate(c - inner->aimInputX, lbl_803DC6D8, timeDelta);
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
            inner->targetYaw =
                (s16)(p * lbl_803DC6DC + (f32)inner->targetYaw);
        }
        inner->yaw = inner->targetYaw;
    }
    if (inner->aimInputZ > lbl_803E7EA4)
    {
        ((void (*)(int, int, f32, int))Object_ObjAnimSetSecondaryBlendMove)(obj, 0x441, lbl_803E7EA4,
                                                                            (int)(lbl_803E7FAC * inner->aimInputZ));
    }
    else
    {
        ((void (*)(int, int, f32, int))Object_ObjAnimSetSecondaryBlendMove)(obj, 0x440, lbl_803E7FAC,
                                                                            (int)(lbl_803E7FAC * -inner->aimInputZ));
    }
    inner->headPitch =
        (f32)inner->headPitch * powfBitEstimate(lbl_803E7FF4, timeDelta);
    inner->headYaw =
        (f32)inner->headYaw * powfBitEstimate(lbl_803E7F1C, timeDelta);
    inner->bodyLeanHalf = lbl_803E7FB0 * inner->aimInputX;
    inner->bodyLeanAngle = (s16)(inner->bodyLeanHalf >> 1);
    *(u32*)&inner->flags360 &= ~0x400LL;
    v7bc = inner->aimInputZ;
    v7b8 = inner->aimInputX;
    res = getScreenResolution();
    halfW = res >> 17;
    halfH = (int)(u16)res >> 1;
    inner->aimScreenY = lbl_803E7E98 * (v7b8 * (f32)halfH) + (f32)halfH;
    if (v7bc < lbl_803E7EA4)
    {
        inner->aimScreenX = lbl_803E7E98 * (v7bc * (f32)halfW) + (f32)halfW;
    }
    else
    {
        inner->aimScreenX = lbl_803E7F44 * (v7bc * (f32)halfW) + (f32)halfW;
    }
    *(u32*)&((PlayerState*)inner)->flags360 |= 0x400LL;
    return 0;
}

int fn_8029F108(int obj, int state)
{
    PlayerState* inner = ((GameObject*)obj)->extra;
    int sub = inner->focusObject;
    void* vec;
    int kind;
    int joint;
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
        int inner2 = *(int*)&((GameObject*)obj)->extra;
        *(int*)((char*)inner2 + 0x360) &= ~0x2LL;
        *(int*)((char*)inner2 + 0x360) |= 0x2000;
    }
    *(int*)((char*)state + 0x4) |= 0x100000;
    {
        f32 z = lbl_803E7EA4;
        ((PlayerState*)state)->baddie.animSpeedA = z;
        ((PlayerState*)state)->baddie.animSpeedB = z;
        *(int*)((char*)state + 0x0) |= 0x200000;
        ((GameObject*)obj)->anim.velocityX = z;
        ((GameObject*)obj)->anim.velocityZ = z;
    }
    ((PlayerState*)state)->baddie.physicsActive = 0;
    ObjHits_DisableObject(obj);
    ((GameObject*)obj)->anim.velocityY = lbl_803E7EA4;
    if (*(s8*)&((PlayerState*)state)->baddie.moveJustStartedA != 0)
    {
        (*(void (*)(int, void*, void*, void*))(*(int*)(*(int*)*(int*)((char*)sub + 0x68) + 0x28)))(
            sub, (char*)obj + 0xc, (char*)obj + 0x10, (char*)obj + 0x14);
        switch (*(s16*)((char*)sub + 0x46))
        {
        case 0x38c:
        case 0x72:
            (*gCameraInterface)->setMode(
                0x42, 0, 1, 0, NULL, 0x64, 0xff);
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
        ((GameObject*)obj)->anim.rotY = 0;
        ((GameObject*)obj)->anim.rotZ = 0;
        ObjAnim_SetCurrentMove(obj, ((s16*)inner->moveSequence)[n], lbl_803E7EA4, 1);
        joint = (int)Player_GetActiveModel(obj);
        ObjModel_SampleJointTransform(joint, 0, 0, lbl_803E7EA4,
                                      ((GameObject*)obj)->anim.rootMotionScale, pos1, ang);
        ObjModel_SampleJointTransform(joint, 0, 0, lbl_803E7EE0,
                                      ((GameObject*)obj)->anim.rootMotionScale, pos2, ang);
        ang[0] = inner->targetYaw;
        ang[1] = 0;
        ang[2] = 0;
        vecRotateZXY(ang, pos2);
        pos2[0] = pos2[0] + ((GameObject*)obj)->anim.localPosX;
        pos2[2] = pos2[2] + ((GameObject*)obj)->anim.localPosZ;
        ((GameObject*)obj)->anim.localPosY -= pos1[1];
        t = (*gPathControlInterface)->sampleHeight((void*)obj, pos2[0],
                                                   ((GameObject*)obj)->anim.localPosY, pos2[2],
                                                   lbl_803E7FA4);
        inner->warpStartX = pos2[0];
        inner->warpStartY = t;
        inner->warpStartZ = pos2[2];
        inner->warpDeltaY = ((GameObject*)obj)->anim.localPosY - t;
        inner->warpKind = (u8)kind;
        ((GameObject*)obj)->anim.flags &= ~0x8;
        ((GameObject*)obj)->anim.activeMove = -1;
        ((PlayerState*)state)->baddie.moveSpeed = lbl_803E7FE8;
    }
    t = lbl_803E7EE0 - ((GameObject*)obj)->anim.currentMoveProgress;
    ((GameObject*)obj)->anim.localPosY =
        inner->warpDeltaY * t + inner->warpStartY;
    vec = objModelGetVecFn_800395d8(obj, 5);
    if (vec != NULL)
    {
        *(s16*)vec = (f32) * (s16*)((char*)sub + 0x2) * t;
        *(s16*)((char*)vec + 0x4) = (f32) * (s16*)((char*)sub + 0x4) * t;
    }
    (*(void (*)(int, f32*, f32*, f32*))(*(int*)(*(int*)*(int*)((char*)sub + 0x68) + 0x34)))(
        sub, &cam[0], &cam[1], &cam[2]);
    {
        f32 w = ((GameObject*)obj)->anim.currentMoveProgress;
        f32 cx = w * (inner->warpStartX - cam[0]) + cam[0];
        f32 cy = w * (inner->warpStartY - cam[1]) + cam[1];
        f32 cz = w * (inner->warpStartZ - cam[2]) + cam[2];
        (*gCameraInterface)->overridePos(cx, cy, cz);
    }
    if (*(s8*)&((PlayerState*)state)->baddie.moveJustStartedA == 0 && *(s8*)&((PlayerState*)state)->baddie.moveDone !=
        0)
    {
        if (vec != NULL)
        {
            *(s16*)vec = 0;
            *(s16*)((char*)vec + 0x4) = 0;
        }
        ((GameObject*)obj)->anim.modelState->flags &= ~(long long)OBJ_MODEL_STATE_SHADOW_FADE_OUT;
        ((GameObject*)obj)->anim.worldPosX = inner->savedPosX;
        ((GameObject*)obj)->anim.worldPosZ = inner->savedPosZ;
        if (((GameObject*)obj)->anim.parent != NULL)
        {
            ((GameObject*)obj)->anim.worldPosX += playerMapOffsetX;
            ((GameObject*)obj)->anim.worldPosZ += playerMapOffsetZ;
        }
        Obj_TransformWorldPointToLocal(((GameObject*)obj)->anim.worldPosX, lbl_803E7EA4,
                                       ((GameObject*)obj)->anim.worldPosZ,
                                       &((GameObject*)obj)->anim.localPosX, &localPt,
                                       &((GameObject*)obj)->anim.localPosZ,
                                       (int)((GameObject*)obj)->anim.parent);
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
        ObjAnim_SetCurrentMove(obj, 0, lbl_803E7EA4, 1);
        ((void (*)(int, int, int, int))ObjAnim_WriteStateWord)
            (obj, OBJANIM_STATE_INDEX_CURRENT, OBJANIM_STATE_WORD_EVENT_COUNTDOWN, 0);
        (*(void (*)(int, int))(*(int*)(*(int*)*(int*)((char*)sub + 0x68) + 0x3c)))(sub, 0);
        fn_802AB5A4(obj, (int)inner, 7);
        ObjHits_EnableObject(obj);
        inner->focusObject = 0;
        *(int*)&((PlayerState*)state)->baddie.unk308 = (int)fn_802A514C;
        return 2;
    }
    return 0;
}

int fn_8029DA60(int obj, int state)
{
    ((PlayerState*)state)->baddie.unk34D = 3;
    ((PlayerState*)state)->baddie.moveSpeed = lbl_803E7FD8;
    ((PlayerState*)state)->baddie.animSpeedA = lbl_803E7EA4;
    (*(void (*)(int, int, int))(*(int*)(*gPlayerInterface + 0x20)))(obj, state, 2);
    if (*(s8*)&((PlayerState*)state)->baddie.moveDone != 0)
    {
        *(int*)&((PlayerState*)state)->baddie.unk308 = (int)fn_802A514C;
        return 2;
    }
    return 0;
}

int fn_802A7160(int obj, int state)
{
    if (GameBit_Get(0x970))
    {
        GameBit_Set(0x970, 0);
        (*gObjectTriggerInterface)->runSequence(0x10, (void*)obj, -1);
    }
    *(int*)&((PlayerState*)state)->baddie.unk308 = (int)fn_802A514C;
    return 2;
}

void fn_8029BC08(int obj)
{
    Player_GetObjHitsState(obj)->objectHitMask = 0;
    if (((GameObject*)gPlayerPathObject)->anim.classId == 0x2d)
    {
        objSetAnimField48to0((int*)gPlayerPathObject);
    }
    gPlayerSubState = 1;
}

void fn_8029F67C(int obj)
{
    ObjModelState* modelState = ((GameObject*)obj)->anim.modelState;
    s16* v;
    modelState->flags &= 0xFFFFEFFFLL;
    ((GameObject*)obj)->anim.flags &= ~0x8;
    ((GameObject*)obj)->anim.activeMove = -1;
    v = objModelGetVecFn_800395d8(obj, 9);
    if (v != NULL)
    {
        v[0] = 0;
        v[1] = 0;
        v[2] = 0;
    }
}

void fn_80296124(int obj, void* p2, void* p3)
{
    PlayerState* inner = ((GameObject*)obj)->extra;
    *(u32*)&((PlayerState*)inner)->flags360 &= ~0x4000LL;
    if (p2 != NULL)
    {
        ((GameObject*)obj)->anim.localPosX = *(f32*)((char*)p2 + 0);
        ((GameObject*)obj)->anim.localPosY = *(f32*)((char*)p2 + 4);
        ((GameObject*)obj)->anim.localPosZ = *(f32*)((char*)p2 + 8);
        *(u32*)&((PlayerState*)inner)->flags360 |= 0x4000LL;
    }
    if (p3 != NULL)
    {
        s16 t = *(s16*)((char*)p3 + 0);
        ((GameObject*)obj)->anim.rotX = t;
        inner->targetYaw = t;
        inner->yaw = t;
        inner->yaw = inner->targetYaw;
        ((GameObject*)obj)->anim.rotY = *(s16*)((char*)p3 + 2);
        ((GameObject*)obj)->anim.rotZ = *(s16*)((char*)p3 + 4);
        *(u32*)&((PlayerState*)inner)->flags360 |= 0x4000LL;
    }
}

int fn_8029605C(int obj, f32* p2, f32* p3)
{
    void* inner = ((GameObject*)obj)->extra;
    if (inner == NULL || getCurSeqNo() != 0)
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

void fn_8029A420(int obj)
{
    PlayerState* inner = ((GameObject*)obj)->extra;
    if (inner->curAnimId != 0x42 && getCurSeqNo() == 0)
    {
        (*gCameraInterface)->setMode(
            0x42, 0, 1, 0, NULL, 0x3c, 0xfe);
    }
    ((ByteFlags*)((char*)inner + 0x3f6))->b40 = 0;
    inner->animState = -1;
}

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

void fn_8029DAE0(int obj, int* p2)
{
    PlayerState* inner = ((GameObject*)obj)->extra;
    u8 c;
    *p2 &= ~0x4000;
    c = inner->curAnimId;
    if (c != 0x48 && c != 0x47 && getCurSeqNo() == 0)
    {
        (*gCameraInterface)->setMode(
            0x42, 0, 1, 0, NULL, 0x3c, 0xfe);
    }
    ObjHits_SyncObjectPositionIfDirty(obj);
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

extern int gPlayerSfxTimerD;
extern int lbl_803E7E78;
extern f32 lbl_803E7FDC;
extern f32 lbl_803E7FE0;
extern f32 lbl_803E7FE4;

int fn_8029DB70(int obj, int state, f32 fv)
{
    int prev;
    HeadMoveTable* tbl = (HeadMoveTable*)lbl_80332EC0;
    PlayerState* inner = ((GameObject*)obj)->extra;
    int sub;
    int nextMove = -1;
    int doXform = 1;
    int camCall = 0;
    f32 t;
    f32 t2;
    f32 xc;
    f32 yc;
    f32 yT;
    f32 xT;
    f32 yOut;
    ColPair col;

    col = *(ColPair*)&lbl_803E7E78;
    setAButtonIcon(0xf);
    if (*(s8*)&((PlayerState*)state)->baddie.moveJustStartedA != 0)
    {
        ((ByteFlags*)((char*)inner + 0x3f3))->b01 = ((ByteFlags*)((char*)inner + 0x3f3))->b08;
        *(s16*)((char*)state + 0x278) = 0x1d;
        inner->stateHandler = (int)fn_8029DAE0;
    }
    if (*(s8*)&((PlayerState*)state)->baddie.moveJustStartedA != 0)
    {
        if (gPlayerPathObject != 0 && ((ByteFlags*)((char*)inner + 0x3f4))->b40 != 0)
        {
            inner->staffActionRequest = 1;
            ((ByteFlags*)((char*)inner + 0x3f4))->b08 = 1;
        }
        if (inner->curAnimId != 0x48 && inner->curAnimId != 0x47)
        {
            cameraSetInterpMode(2);
            (*gCameraInterface)->setMode(
                0x52, 1, 0, 8, &col, 0x1e, 0xff);
        }
        *(u8*)&((PlayerState*)inner)->stickDirection = 0;
        inner->latchedStickDir = 0;
        inner->targetYaw =
            getAngle(inner->surfaceNormalX, inner->surfaceNormalZ);
        {
            s16 ang = inner->targetYaw;
            inner->yaw = ang;
            *(s16*)obj = ang;
        }
        ((ByteFlags*)((char*)inner + 0x3f2))->b01 = 1;
        ObjAnim_SetCurrentMove(obj, 0x5f, lbl_803E7EA4, 0);
        ObjAnim_SetCurrentEventStepFrames((ObjAnimComponent*)obj, 8);
        ((PlayerState*)state)->baddie.moveSpeed = lbl_803E7EF8;
        {
            f32 z = lbl_803E7EA4;
            inner->unk444 = z;
            inner->unk448 = z;
        }
        ((ByteFlags*)((char*)inner + 0x3f3))->b80 = 0;
        ObjHits_MarkObjectPositionDirty(obj);
    }
    inner->aimInputZ = lbl_803E7F2C;
    {
        f32 z = lbl_803E7EA4;
        inner->aimInputX = z;
        ((PlayerState*)state)->baddie.animSpeedA = z;
        ((PlayerState*)state)->baddie.animSpeedB = z;
    }
    sub = inner->contactObject;
    switch (((GameObject*)obj)->anim.currentMove)
    {
    case 0x5f:
        if ((*(int*)&((PlayerState*)state)->baddie.unk318 & 0x100) == 0)
        {
            *(u32*)&((PlayerState*)inner)->flags360 |= 0x800000LL;
            *(int*)&((PlayerState*)state)->baddie.unk308 = (int)fn_802A514C;
            return 2;
        }
        break;
    case 0x4d:
    case 0x4e:
    case 0x5a:
    case 0x65:
        if (*(s8*)&((PlayerState*)state)->baddie.moveDone != 0)
        {
            *(u32*)&((PlayerState*)inner)->flags360 |= 0x800000LL;
            *(int*)&((PlayerState*)state)->baddie.unk308 = (int)fn_802A514C;
            return 2;
        }
        camCall = 1;
        doXform = 0;
        break;
    }
    prev = *(u8*)&((PlayerState*)inner)->stickDirection;
    t = (f32)padGetStickX(0) / lbl_803E7FA8;
    xc = (t < lbl_803E7ECC) ? lbl_803E7ECC : ((t > lbl_803E7EE0) ? lbl_803E7EE0 : t);
    t2 = (f32)padGetStickY(0) / lbl_803E7FA8;
    yc = (t2 < lbl_803E7ECC) ? lbl_803E7ECC : ((t2 > lbl_803E7EE0) ? lbl_803E7EE0 : t2);
    if (((ByteFlags*)((char*)inner + 0x3f3))->b80 == 0)
    {
        if (yc > lbl_803E7F14)
        {
            xT = -(lbl_803E7F48 * yc - lbl_803E7FDC);
            inner->unk448 = yT = lbl_803E7EA4;
            *(u8*)&((PlayerState*)inner)->stickDirection = 1;
        }
        else if (yc < lbl_803E7FE0)
        {
            xT = -(lbl_803E7F48 * yc - lbl_803E7F6C);
            inner->unk448 = yT = lbl_803E7EA4;
            *(u8*)&((PlayerState*)inner)->stickDirection = 2;
        }
        else if (xc > lbl_803E7F14)
        {
            inner->unk444 = xT = lbl_803E7EA4;
            yT = lbl_803E7EAC * xc + lbl_803E7F6C;
            *(u8*)&((PlayerState*)inner)->stickDirection = 3;
        }
        else if (xc < lbl_803E7FE0)
        {
            inner->unk444 = xT = lbl_803E7EA4;
            yT = lbl_803E7EAC * xc + lbl_803E7FDC;
            *(u8*)&((PlayerState*)inner)->stickDirection = 4;
        }
        else
        {
            if (inner->unk444 <= lbl_803E7F6C &&
                inner->unk444 >= lbl_803E7FDC &&
                inner->unk448 <= lbl_803E7F6C &&
                inner->unk448 >= lbl_803E7FDC)
            {
                *(u8*)&((PlayerState*)inner)->stickDirection = 0;
                nextMove = 0x5f;
                ((PlayerState*)state)->baddie.moveSpeed = lbl_803E7EF8;
            }
            xT = lbl_803E7EA4;
            yT = lbl_803E7EA4;
        }
        {
            f32 k = lbl_803E7EFC;
            inner->unk444 =
                k * (xT - inner->unk444) + inner->unk444;
            inner->unk448 =
                k * (yT - inner->unk448) + inner->unk448;
        }
    }
    if (((ByteFlags*)((char*)inner + 0x3f3))->b80 == 0 &&
        ((*(int*)&((PlayerState*)state)->baddie.unk318 & 0x100) == 0 || inner->unk681 != 0 ||
            (((ByteFlags*)((char*)inner + 0x3f1))->b01 == 0 &&
                *(f32*)((char*)state + 0x1b0) >= lbl_803E7F58)))
    {
        if (inner->stickDirection != 0)
        {
            ObjAnim_SetCurrentMove(obj, tbl->moveA[inner->stickDirection], lbl_803E7E98, 0);
            ((PlayerState*)state)->baddie.moveSpeed = lbl_803E7F20;
        }
        else
        {
            *(u32*)&((PlayerState*)inner)->flags360 |= 0x800000LL;
            *(int*)&((PlayerState*)state)->baddie.unk308 = (int)fn_802A514C;
            return 2;
        }
        *(u8*)&((PlayerState*)inner)->stickDirection = 0;
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
                Sfx_PlayFromObject(obj, 0x2b);
            }
            *(u32*)&((PlayerState*)inner)->flags360 |= 0x200LL;
            if (inner->stickDirection != (u8)prev || *(s8*)&((PlayerState*)inner)->latchedStickDir == 0)
            {
                ((ByteFlags*)((char*)inner + 0x3f2))->b01 = 1;
                inner->latchedStickDir = 0;
            }
            else if (inner->stickDirection == *(s8*)&((PlayerState*)inner)->latchedStickDir)
            {
                if (((ByteFlags*)((char*)inner + 0x3f3))->b08 != 0 &&
                    ((ByteFlags*)((char*)inner + 0x3f3))->b01 == 0)
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
                ((PlayerState*)state)->baddie.moveSpeed =
                    lbl_803E7EF8 * ((PlayerState*)state)->baddie.inputMagnitude +
                    tbl->spdD[inner->stickDirection];
                nextMove = tbl->moveC[inner->stickDirection];
            }
            else
            {
                int* tblB = tbl->moveB;
                if (((GameObject*)obj)->anim.currentMove != tblB[inner->stickDirection] ||
                    ((GameObject*)obj)->anim.currentMoveProgress >= lbl_803E7FE4)
                {
                    ((PlayerState*)state)->baddie.moveSpeed =
                        lbl_803E7F78 * ((f32)randomGetRange(0, 100) / lbl_803E7F5C) +
                        tbl->spdE[inner->stickDirection];
                }
                nextMove = tblB[inner->stickDirection];
            }
        }
        {
            u8 res;
            f32 a;
            f32 b;
            if (inner->stickDirection == 0)
            {
                a = lbl_803E7EA4;
                b = lbl_803E7EA4;
            }
            else
            {
                a = inner->unk444;
                b = inner->unk448;
            }
            res = (*(u8 (*)(int, int, int, f32, f32))(
                *(int*)(*(int*)(*(int*)((char*)sub + 0x68)) + 0x20)))(
                sub, obj, inner->stickDirection, a, b);
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
                *(u8*)&((PlayerState*)inner)->unk681 = 1;
            }
            else
            {
                inner->latchedStickDir = 0;
            }
        }
    }
    if (nextMove != -1 && ((GameObject*)obj)->anim.currentMove != nextMove &&
        ((int (*)(ObjAnimComponent*))ObjAnim_GetCurrentEventCountdown)((ObjAnimComponent*)obj) == 0)
    {
        ObjAnim_SetCurrentMove(obj, nextMove, lbl_803E7EA4, 0);
        ObjAnim_SetCurrentEventStepFrames((ObjAnimComponent*)obj, 0xa);
    }
    if (camCall != 0)
    {
        (*(void (*)(int, int, int, f32))(*(int*)(*gPlayerInterface + 0x20)))(obj, state, 3, fv);
    }
    if (doXform != 0)
    {
        ((void (*)(f32, f32, f32, void*, f32*, void*, int))Obj_TransformLocalPointToWorld)(
            inner->unk664, inner->unk668,
            inner->unk66C, (void*)(obj + 0xc), &yOut, (void*)(obj + 0x14), sub);
        ((GameObject*)obj)->anim.localPosX =
            lbl_803E7FB8 * inner->surfaceNormalX + ((GameObject*)obj)->anim.localPosX;
        ((GameObject*)obj)->anim.localPosZ =
            lbl_803E7FB8 * inner->surfaceNormalZ + ((GameObject*)obj)->anim.localPosZ;
    }
    ((ByteFlags*)((char*)inner + 0x3f3))->b01 = ((ByteFlags*)((char*)inner + 0x3f3))->b08;
    return 0;
}

extern f32 lbl_803E8034;
extern f32 lbl_803E803C;

int fn_802A2EE0(int obj, int state, f32 fv)
{
    int inner = *(int*)&((GameObject*)obj)->extra;
    f32 diff = ((PlayerState*)inner)->unk5AC - ((PlayerState*)inner)->unk874;
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
        (*(void (*)(int, int, int))(*(int*)(*gPlayerInterface + 0x20)))(obj, state, 0x14);
        ((GameObject*)obj)->anim.localPosY =
            *(f32*)((char*)state + 0x2b4) * timeDelta + ((GameObject*)obj)->anim.localPosY;
        if (*(s8*)&((PlayerState*)state)->baddie.moveDone != 0)
        {
            f32 d2;
            f32 v;
            gPlayerCurrentMoveId = 2;
            blend = lbl_803E7EF8;
            d2 = (lbl_803E7F10 + diff) - ((GameObject*)obj)->anim.localPosY;
            v = lbl_803E8030 * -d2;
            if (v >= lbl_803E7EA4)
            {
                ((GameObject*)obj)->anim.velocityY = sqrtf(v);
            }
            else
            {
                ((GameObject*)obj)->anim.velocityY = lbl_803E7EA4;
            }
            Sfx_PlayFromObject(obj,
                               (u16)(((PlayerState*)inner)->characterId == 0 ? 0x2d5 : 0x2d4));
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
            ((GameObject*)obj)->anim.velocityY =
                lbl_803E7E88 * fv + ((GameObject*)obj)->anim.velocityY;
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
                                   (u16)(((PlayerState*)inner)->characterId == 0 ? 0x398 : 0x1d));
                if (((PlayerState*)inner)->unk608 == 5)
                {
                    Sfx_PlayFromObject(obj, 0x2f);
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
            Sfx_PlayFromObject(obj,
                               (u16)(((PlayerState*)inner)->characterId == 0 ? 0x398 : 0x1d));
            if (((PlayerState*)inner)->unk608 == 5)
            {
                Sfx_PlayFromObject(obj, 0x2f);
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
            f32 c5cc = ((PlayerState*)inner)->unk5CC;
            f32 k = lbl_803E7E98 + lbl_803DC6C0;
            f32 c5dc = ((PlayerState*)inner)->unk5DC;
            f32 y2 = c5cc * k + c5dc;
            s16 ang;
            ((GameObject*)obj)->anim.localPosX =
                ((GameObject*)obj)->anim.currentMoveProgress *
                ((((PlayerState*)inner)->unk5C4 * k + ((PlayerState*)inner)->unk5D4) -
                    ((PlayerState*)inner)->moveStartX) +
                ((PlayerState*)inner)->moveStartX;
            ((GameObject*)obj)->anim.localPosZ =
                ((GameObject*)obj)->anim.currentMoveProgress * (y2 - ((PlayerState*)inner)->moveStartZ) +
                ((PlayerState*)inner)->moveStartZ;
            ((GameObject*)obj)->anim.velocityY =
                -(lbl_803E7F6C * timeDelta - ((GameObject*)obj)->anim.velocityY);
            ang = -(lbl_803E7F98 * ((GameObject*)obj)->anim.currentMoveProgress -
                (f32)((PlayerState*)inner)->launchYaw);
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
                fn_802AB5A4(obj, inner, 5);
                ((ByteFlags*)((char*)inner + 0x3f0))->b80 = 0;
                ((ByteFlags*)((char*)inner + 0x3f0))->b10 = 0;
                ((ByteFlags*)((char*)inner + 0x3f0))->b08 = 0;
                staffFn_80170380(gPlayerStaffObject, 2);
                ((ByteFlags*)((char*)inner + 0x3f0))->b02 = 0;
                *(u32*)&((PlayerState*)inner)->flags360 |= 0x800000LL;
                ObjHits_SyncObjectPositionIfDirty(obj);
                ((ByteFlags*)((char*)inner + 0x3f0))->b40 = 0;
                ((ByteFlags*)((char*)inner + 0x3f0))->b04 = 1;
                ((ByteFlags*)((char*)inner + 0x3f4))->b10 = 1;
                ((PlayerState*)inner)->isHoldingObject = 0;
                if (*(void**)((char*)inner + 0x7f8) != NULL)
                {
                    s16 typ = ((GameObject*)((PlayerState*)inner)->heldObj)->anim.seqId;
                    if (typ == 0x3cf || typ == 0x662)
                    {
                        objThrowFn_80182504(((PlayerState*)inner)->heldObj);
                    }
                    else
                    {
                        objSaveFn_800ea774(((PlayerState*)inner)->heldObj);
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
        ((GameObject*)obj)->anim.localPosX =
            z * (((PlayerState*)inner)->moveEndX - ((PlayerState*)inner)->moveStartX) +
            ((PlayerState*)inner)->moveStartX;
        ((GameObject*)obj)->anim.localPosY =
            z * (((PlayerState*)inner)->moveEndY - ((PlayerState*)inner)->moveStartY) +
            ((PlayerState*)inner)->moveStartY;
        ((GameObject*)obj)->anim.localPosZ =
            z * (((PlayerState*)inner)->moveEndZ - ((PlayerState*)inner)->moveStartZ) +
            ((PlayerState*)inner)->moveStartZ;
        if (((GameObject*)obj)->anim.currentMoveProgress > lbl_803E7F68)
        {
            *(u32*)((char*)state + 4) &= ~0x100000;
            fn_802AB5A4(obj, inner, 5);
            *(u32*)&((PlayerState*)inner)->flags360 |= 0x800000LL;
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
            s16 ang =
                getAngle(((PlayerState*)inner)->unk5C4, ((PlayerState*)inner)->unk5CC);
            ((PlayerState*)inner)->yaw = ang;
            ((PlayerState*)inner)->targetYaw = ang;
        }
        ((GameObject*)obj)->anim.velocityY = lbl_803E7EA4;
        ((void (*)(f32, f32, f32, void*, void*, void*, int))Obj_TransformWorldPointToLocal)(
            ((GameObject*)obj)->anim.worldPosX, ((GameObject*)obj)->anim.worldPosY,
            ((GameObject*)obj)->anim.worldPosZ, (void*)(obj + 0xc), (void*)(obj + 0x10),
            (void*)(obj + 0x14), *(int*)&((GameObject*)obj)->anim.parent);
        objHitDetectFn_80062e84(obj, ((PlayerState*)inner)->groundObject, 1);
        ((PlayerState*)inner)->moveStartX = ((GameObject*)obj)->anim.localPosX;
        ((PlayerState*)inner)->moveStartY = ((GameObject*)obj)->anim.localPosY;
        ((PlayerState*)inner)->moveStartZ = ((GameObject*)obj)->anim.localPosZ;
        {
            char* xf = *(char**)((char*)inner + 0x4c4);
            if (xf != NULL)
            {
                ((void (*)(f32, f32, f32, void*, void*, void*, char*))Obj_TransformWorldPointToLocal)(
                    ((PlayerState*)inner)->unk5D4, ((PlayerState*)inner)->unk5D8,
                    ((PlayerState*)inner)->unk5DC, (void*)(inner + 0x5d4),
                    (void*)(inner + 0x5d8), (void*)(inner + 0x5dc), xf);
                ((void (*)(f32, f32, f32, void*, void*, void*, int))Obj_TransformWorldPointToLocal)(
                    ((PlayerState*)inner)->moveEndX, ((PlayerState*)inner)->moveEndY,
                    ((PlayerState*)inner)->moveEndZ, (void*)(inner + 0x5ec),
                    (void*)(inner + 0x5f0), (void*)(inner + 0x5f4),
                    ((PlayerState*)inner)->groundObject);
                ((void (*)(f32, f32, f32, void*, void*, void*, int))Obj_TransformWorldPointToLocal)(
                    ((PlayerState*)inner)->moveEnd2X, ((PlayerState*)inner)->moveEnd2Y,
                    ((PlayerState*)inner)->moveEnd2Z, (void*)(inner + 0x5f8),
                    (void*)(inner + 0x5fc), (void*)(inner + 0x600),
                    ((PlayerState*)inner)->groundObject);
                ((PlayerState*)inner)->unk5AC =
                    ((PlayerState*)inner)->unk5AC -
                    *(f32*)((char*)((PlayerState*)inner)->groundObject + 0x10);
                ((PlayerState*)inner)->unk5B0 =
                    ((PlayerState*)inner)->unk5B0 -
                    *(f32*)((char*)((PlayerState*)inner)->groundObject + 0x10);
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
    fn_802AB5A4(obj, inner, 5);
    return 0;
}



extern f32 lbl_803E8104;
extern f32 lbl_803E8108;
extern f32 lbl_803E810C;
extern f32 lbl_803E8110;

int fn_802AD2F4(int obj, int inner, int state)
{
    f32 hdiff;
    int sfx;
    f32 z;
    f32 y;
    f32 x;

    ((GameObject*)obj)->anim.velocityY =
        -(lbl_803E7EFC * timeDelta - ((GameObject*)obj)->anim.velocityY);
    switch (((GameObject*)obj)->anim.currentMove)
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
            ((GameObject*)obj)->anim.velocityY = zz;
        }
        if (((GameObject*)obj)->anim.currentMoveProgress >= lbl_803E7F10 * ((PlayerState*)state)->baddie.moveSpeed)
        {
            ((ByteFlags*)((char*)inner + 0x3f2))->b08 = 0;
        }
        else if (((PlayerState*)inner)->fallSeverity >= 2 &&
            ((ByteFlags*)((char*)inner + 0x3f2))->b04 == 0)
        {
            s8 hv;
            Camera_EnableViewYOffset();
            CameraShake_SetAllMagnitudes(lbl_803E7ED8);
            ObjPath_GetPointWorldPosition(obj, 0xb, &x, &y, &z, 0);
            if (((PlayerState*)inner)->surfaceType == 0x1a)
            {
                hv = 0x14;
            }
            else
            {
                hv = 2;
            }
            ObjHits_RecordPositionHit(obj, 0, hv, 1, 0, x, y, z);
            ((ByteFlags*)((char*)inner + 0x3f2))->b04 = 1;
        }
        if (*(s8*)&((PlayerState*)state)->baddie.moveDone != 0)
        {
            ((ByteFlags*)((char*)inner + 0x3f0))->b04 = 0;
            ((ByteFlags*)((char*)inner + 0x3f3))->b40 = 1;
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
            if (*(s8*)&((PlayerState*)state)->baddie.moveDone != 0)
            {
                if (**(s8**)((char*)inner + 0x35c) > 0)
                {
                    ObjAnim_SetCurrentMove(obj, 0xc, zz, 0);
                    ((PlayerState*)state)->baddie.moveSpeed = lbl_803E8038;
                }
                else
                {
                    ((ByteFlags*)((char*)inner + 0x3f0))->b04 = 0;
                    ((PlayerState*)inner)->staffHoldFrames = 0;
                    playerDie(obj);
                }
            }
            (*(void (*)(int, int, int, f32))(*(int*)(*gPlayerInterface + 0x20)))(obj, state, 2,
                timeDelta);
            ((PlayerState*)inner)->emissionState = 4;
            break;
        }
    case 0xc:
        if ((*(int*)&((PlayerState*)state)->baddie.eventFlags & 1) != 0 &&
            ((PlayerState*)inner)->characterId != 0)
        {
            Sfx_PlayFromObject(obj, 0x20e);
            Sfx_PlayFromObject(obj, 0x20f);
        }
        if (*(s8*)&((PlayerState*)state)->baddie.moveDone != 0)
        {
            ((ByteFlags*)((char*)inner + 0x3f0))->b04 = 0;
            ((ByteFlags*)((char*)inner + 0x3f3))->b40 = 1;
            ((PlayerState*)inner)->staffHoldFrames = 0;
            return 1;
        }
        (*(void (*)(int, int, int, f32))(*(int*)(*gPlayerInterface + 0x20)))(obj, state, 2,
                                                                             timeDelta);
        ((PlayerState*)inner)->emissionState = 4;
        break;
    default:
        ObjAnim_SetCurrentMove(obj, 0x54, lbl_803E7EA4, 0);
        ObjAnim_SetCurrentEventStepFrames((ObjAnimComponent*)obj, 0x14);
        ((PlayerState*)state)->baddie.moveSpeed = lbl_803E7F6C;
        ((PlayerState*)inner)->emissionState = 2;
        ((PlayerState*)inner)->fallSeverity = 0;
        ((ByteFlags*)((char*)inner + 0x3f0))->b01 = 0;
        ((ByteFlags*)((char*)inner + 0x3f2))->b08 = 0;
        ((ByteFlags*)((char*)inner + 0x3f2))->b04 = 0;
        ((ByteFlags*)((char*)inner + 0x3f2))->b02 = 0;
        ((PlayerState*)inner)->prevWorldPosY = ((GameObject*)obj)->anim.worldPosY;
        break;
    }
    hdiff = ((PlayerState*)inner)->prevWorldPosY - ((GameObject*)obj)->anim.worldPosY;
    if (((ByteFlags*)((char*)inner + 0x3f1))->b01 != 0 &&
        ((ByteFlags*)((char*)inner + 0x3f0))->b01 == 0)
    {
        ((ByteFlags*)((char*)inner + 0x3f0))->b01 = 1;
        sfx = audioPickSoundEffect_8006ed24(((PlayerState*)inner)->surfaceType,
                                            ((PlayerState*)inner)->footstepSoundId);
        if (hdiff > lbl_803E8104)
        {
            s8 hv;
            doRumble(lbl_803E7FA4);
            Camera_EnableViewYOffset();
            CameraShake_SetAllMagnitudes(lbl_803E7F58);
            ObjAnim_SetCurrentMove(obj, 0xb, lbl_803E7EA4, 0);
            ((PlayerState*)state)->baddie.moveSpeed = lbl_803E7F34;
            Sfx_PlayFromObject(obj, 0x20d);
            Sfx_PlayFromObject(obj, 0x28);
            ObjPath_GetPointWorldPosition(obj, 0xb, &x, &y, &z, 0);
            if (((PlayerState*)inner)->surfaceType == 0x1a)
            {
                hv = 0x14;
            }
            else
            {
                hv = 2;
            }
            ObjHits_RecordPositionHit(obj, 0, hv, 2, 0, x, y, z);
            ((ByteFlags*)((char*)inner + 0x3f2))->b08 = 0;
            if (((PlayerState*)inner)->waterDepth > lbl_803E7FC4)
            {
                Sfx_PlayFromObject(obj, 0x428);
            }
        }
        else if (hdiff > lbl_803E8108)
        {
            doRumble(lbl_803E7ED8);
            ObjAnim_SetCurrentMove(obj, 0x13, lbl_803E7EA4, 0);
            ((PlayerState*)state)->baddie.moveSpeed = lbl_803E800C;
            Sfx_PlayFromObject(obj, sfx);
            Sfx_StopFromObject(obj,
                               (u16)(((PlayerState*)inner)->characterId == 0 ? 0x2d0 : 0x26));
            ((ByteFlags*)((char*)inner + 0x3f2))->b08 = 1;
            if (((PlayerState*)inner)->waterDepth > lbl_803E7FC4)
            {
                Sfx_PlayFromObject(obj, 0x429);
            }
        }
        else if (hdiff > lbl_803E810C)
        {
            doRumble(lbl_803E7ED8);
            ObjAnim_SetCurrentMove(obj, 0x13, lbl_803E7EA4, 0);
            ((PlayerState*)state)->baddie.moveSpeed = lbl_803E800C;
            Sfx_PlayFromObject(obj, sfx);
            Sfx_PlayFromObject(obj,
                               (u16)(((PlayerState*)inner)->characterId == 0 ? 0x399 : 0x27));
            ((ByteFlags*)((char*)inner + 0x3f2))->b08 = 1;
            if (((PlayerState*)inner)->waterDepth > lbl_803E7FC4)
            {
                Sfx_PlayFromObject(obj, 0x42a);
            }
        }
        else
        {
            doRumble(lbl_803E7F10);
            Sfx_PlayFromObject(0, sfx);
            ((ByteFlags*)((char*)inner + 0x3f0))->b04 = 0;
            ((PlayerState*)inner)->staffHoldFrames = 0;
            ((ByteFlags*)((char*)inner + 0x3f1))->b08 = 1;
            ((ByteFlags*)((char*)inner + 0x3f2))->b10 = 1;
            ((ByteFlags*)((char*)inner + 0x3f2))->b08 = 1;
            if (((PlayerState*)inner)->waterDepth > lbl_803E7FC4)
            {
                Sfx_PlayFromObject(obj, 0x42b);
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
    if (((ByteFlags*)((char*)inner + 0x3f0))->b01 == 0)
    {
        if (*(f32*)((char*)state + 0x1b0) < lbl_803E80C4)
        {
            ((ByteFlags*)((char*)inner + 0x3f2))->b08 = 1;
        }
        if (hdiff > lbl_803E8104 && ((PlayerState*)inner)->fallSeverity < 3)
        {
            ObjAnim_SetCurrentMove(obj, 0xa, lbl_803E7EA4, 0);
            ObjAnim_SetCurrentEventStepFrames((ObjAnimComponent*)obj, 0x19);
            ((PlayerState*)state)->baddie.moveSpeed = lbl_803E7EF8;
            ((PlayerState*)inner)->fallSeverity = 3;
            ((ByteFlags*)((char*)inner + 0x3f2))->b08 = 0;
        }
        else if (hdiff > lbl_803E8108 && ((PlayerState*)inner)->fallSeverity < 2)
        {
            if (Sfx_IsPlayingFromObject(
                0, (u16)(((PlayerState*)inner)->characterId == 0 ? 0x2d0 : 0x26)) == 0)
            {
                Sfx_PlayFromObject(obj,
                                   (u16)(((PlayerState*)inner)->characterId == 0 ? 0x2d0 : 0x26));
            }
            ((PlayerState*)inner)->fallSeverity = 2;
        }
        else if (hdiff > lbl_803E810C && ((PlayerState*)inner)->fallSeverity < 1)
        {
            ObjAnim_SetCurrentMove(obj, 0x90, lbl_803E7EA4, 0);
            ObjAnim_SetCurrentEventStepFrames((ObjAnimComponent*)obj, 0x19);
            ((PlayerState*)state)->baddie.moveSpeed = lbl_803E7EFC;
            ((PlayerState*)inner)->fallSeverity = 1;
        }
    }
    if (((ByteFlags*)((char*)inner + 0x3f2))->b08 != 0 &&
        (((PlayerState*)inner)->buttonsJustPressed & 0x400) != 0)
    {
        ((ByteFlags*)((char*)inner + 0x3f2))->b02 = 1;
        ((PlayerState*)inner)->buttonsJustPressed = ((PlayerState*)inner)->buttonsJustPressed & ~0x400;
    }
    if (((ByteFlags*)((char*)inner + 0x3f0))->b01 != 0 &&
        ((ByteFlags*)((char*)inner + 0x3f2))->b02 != 0 &&
        ((PlayerState*)inner)->fallSeverity < 3)
    {
        fn_802AED2C(obj, inner, state);
        ((ByteFlags*)((char*)inner + 0x3f0))->b04 = 0;
        ((PlayerState*)inner)->staffHoldFrames = 0;
    }
    if (((PlayerState*)inner)->fallSeverity == 0 &&
        ((ByteFlags*)((char*)inner + 0x3f4))->b10 == 0)
    {
        f32 a = lbl_803E7FBC;
        f32 b = lbl_803E7E98;
        f32 c;
        ((PlayerState*)inner)->targetYawSmoothRate = a;
        ((PlayerState*)inner)->targetYawRateLimit = b;
        ((PlayerState*)inner)->yawSmoothRate = a;
        ((PlayerState*)inner)->yawRateLimit = b;
        c = lbl_803E7F14;
        ((PlayerState*)inner)->targetAnimSpeed = c;
        ((PlayerState*)inner)->currentSpeed = ((PlayerState*)inner)->currentSpeed * c;
    }
    else
    {
        f32 a = lbl_803E7FBC;
        f32 b = lbl_803E7EA4;
        ((PlayerState*)inner)->targetYawSmoothRate = a;
        ((PlayerState*)inner)->targetYawRateLimit = b;
        ((PlayerState*)inner)->yawSmoothRate = a;
        ((PlayerState*)inner)->yawRateLimit = b;
        ((PlayerState*)inner)->targetAnimSpeed = b;
        ((PlayerState*)inner)->currentSpeed = ((PlayerState*)inner)->currentSpeed * b;
    }
    {
        f32 t = ((PlayerState*)inner)->currentSpeed;
        ((PlayerState*)inner)->currentSpeed =
            (t < lbl_803E8110)
                ? lbl_803E8110
                : ((t > ((PlayerState*)inner)->maxSpeed) ? ((PlayerState*)inner)->maxSpeed : t);
    }
    if (((PlayerState*)inner)->curAnimId == 0x4b)
    {
        (*gCameraInterface)->setMode(
            0x42, 0, 1, 0, NULL, 0, 0xff);
        ((PlayerState*)inner)->curAnimId = 0x42;
    }
    return 0;
}

extern int getSkyColorFn_80088e30(int idx);
extern void objAudioFn_8006edcc();
extern int getCurUiDll(void);


extern u8 lbl_803DC6A8[8];
extern u8 lbl_803DC6B0[2];
extern int lbl_802C2C50[];
extern f32 lbl_803E8164;

typedef struct
{
    int a[6];
} UiMsgBlock;

void playerUpdate(int obj)
{
    int inner = *(int*)&((GameObject*)obj)->extra;
    int cam = Camera_GetCurrentViewSlot();
    f32 cd = ((PlayerState*)inner)->cutsceneTimer;
    f32 limit = lbl_803E7EF0;
    if (cd >= limit)
    {
        f32 zero = lbl_803E7EA4;
        if (cd > zero)
        {
            ((PlayerState*)inner)->cutsceneTimer = cd - lbl_803E7EE0;
            if (((PlayerState*)inner)->cutsceneTimer <= zero)
            {
                cutsceneEnterExit(0, 0);
                ((PlayerState*)inner)->cutsceneEnded = 1;
            }
            else if (limit == ((PlayerState*)inner)->cutsceneTimer)
            {
                cutsceneEnterExit(1, 0);
                setTimeStop(0xfd);
            }
        }
    }
    else if (getCurUiDll() != 4)
    {
        if ((*(u32*)&((PlayerState*)inner)->flags360 & 0x200000) != 0)
        {
            return;
        }
        if (((ByteFlags*)((char*)inner + 0x3f3))->b08 != 0)
        {
            setBButtonIcon(10);
        }
        if (((GameObject*)obj)->anim.parent == NULL && *(void**)((char*)inner + 0x7f0) == NULL &&
            isInBounds(((GameObject*)obj)->anim.localPosX, ((GameObject*)obj)->anim.localPosZ) == 0)
        {
            *(int*)&((PlayerState*)inner)->baddie.targetObj = 0;
            ((PlayerState*)inner)->unk7EC = 0;
            (*gCameraInterface)->setTarget(0);
            {
                f32 z = lbl_803E7EA4;
                ((PlayerState*)inner)->baddie.animSpeedC = z;
                ((PlayerState*)inner)->baddie.animSpeedB = z;
                ((PlayerState*)inner)->baddie.animSpeedA = z;
                ((GameObject*)obj)->anim.velocityX = z;
                ((GameObject*)obj)->anim.velocityY = z;
                ((GameObject*)obj)->anim.velocityZ = z;
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
                (*(void (*)(int, int, int))(*(int*)(*gPlayerInterface + 0x14)))(obj, inner, 1);
                {
                    f32 z = lbl_803E7EA4;
                    ((PlayerState*)inner)->baddie.animSpeedC = z;
                    ((PlayerState*)inner)->baddie.animSpeedB = z;
                    ((PlayerState*)inner)->baddie.animSpeedA = z;
                    ((GameObject*)obj)->anim.velocityX = z;
                    ((GameObject*)obj)->anim.velocityY = z;
                    ((GameObject*)obj)->anim.velocityZ = z;
                }
                *(int*)&((PlayerState*)inner)->baddie.unk304 = (int)fn_802A514C;
            }
            fn_802B249C(obj, inner, inner);
            fn_802B4A9C(obj, inner, inner);
            fn_802B07D8(obj, inner);
            if ((u32)gPlayerEggObject == 0 && Obj_IsLoadingLocked() != 0)
            {
                gPlayerEggObject = Obj_SetupObject(Obj_AllocObjectSetup(0x18, 0x66a), 4, -1, -1,
                                               *(int*)&((GameObject*)obj)->anim.parent);
                ObjLink_AttachChild(obj, gPlayerEggObject, 3);
            }
            if ((u32)gPlayerEggObject != 0)
            {
                *(int*)&((GameObject*)gPlayerEggObject)->anim.parent = *(int*)&((GameObject*)obj)->anim.parent;
                if (((PlayerState*)inner)->characterId == 0)
                {
                    *(s16*)(gPlayerEggObject + 6) = *(s16*)(gPlayerEggObject + 6) | 0x4000;
                }
            }
            if ((u32)gPlayerStaffObject == 0 && Obj_IsLoadingLocked() != 0)
            {
                gPlayerStaffObject = Obj_SetupObject(Obj_AllocObjectSetup(0x24, 0x773), 5, -1, -1,
                                               *(int*)&((GameObject*)obj)->anim.parent);
            }
            if ((u32)gPlayerStaffObject != 0)
            {
                ObjPath_GetPointWorldPosition(obj, 4, (void*)(&((GameObject*)gPlayerStaffObject)->anim.localPosX),
                                              (void*)(&((GameObject*)gPlayerStaffObject)->anim.localPosY),
                                              (void*)(&((GameObject*)gPlayerStaffObject)->anim.localPosZ), 0);
            }
            if (*(s16**)&((GameObject*)obj)->anim.parent != NULL)
            {
                v = (**(s16**)&((GameObject*)obj)->anim.parent & 0xffffU) -
                    ((0x8000U - *(s16*)cam) & 0xffff);
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
                int idx = i + 0x8b9;
                *(u32*)((char*)inner + 0x310) |= 1 << *(u8*)((char*)inner + idx);
            }
            *(u32*)&((PlayerState*)inner)->flags360 &= 0xfffff4ff;
            dt = timeDelta;
            fn_802B19F8(obj, inner, dt);
            fn_802B4C18(obj, inner, dt);
            ((void (*)(int, int, f32))fn_802AEF34)(obj, inner, dt);
            fn_802B1E5C(obj, inner, inner, dt);
            ((void (*)(int, int, int, f32))fn_802B1BF8)(obj, inner, inner, dt);
            {
                f32 t = ((GameObject*)obj)->anim.velocityX;
                ((GameObject*)obj)->anim.velocityX =
                    (t < lbl_803E801C)
                        ? lbl_803E801C
                        : ((t > lbl_803E7F10) ? lbl_803E7F10 : t);
                t = ((GameObject*)obj)->anim.velocityY;
                ((GameObject*)obj)->anim.velocityY =
                    (t < lbl_803E811C)
                        ? lbl_803E811C
                        : ((t > lbl_803E80E4) ? lbl_803E80E4 : t);
                t = ((GameObject*)obj)->anim.velocityZ;
                ((GameObject*)obj)->anim.velocityZ =
                    (t < lbl_803E801C)
                        ? lbl_803E801C
                        : ((t > lbl_803E7F10) ? lbl_803E7F10 : t);
            }
            ym = ((GameObject*)obj)->anim.velocityY * dt;
            if (ym > lbl_803E7ED8)
            {
                ym = lbl_803E7ED8;
            }
            objMove(obj, ((GameObject*)obj)->anim.velocityX * dt, ym,
                    ((GameObject*)obj)->anim.velocityZ * dt);
            *(s16*)obj = ((PlayerState*)inner)->targetYaw;
            m = *(UiMsgBlock*)lbl_802C2C50;
            (*gGameUIInterface)->isOneOfItemsBeingUsed((s32*)&m, 6);
            fn_802B0920(obj, inner);
            {
                s16 nv = ((PlayerState*)inner)->stepEventTimer - framesThisStep;
                ((PlayerState*)inner)->stepEventTimer = nv;
                if (nv < 0)
                {
                    ((PlayerState*)inner)->stepEventTimer =
                        lbl_803DC6A8[((PlayerState*)inner)->gaitStepLevel];
                    ((PlayerState*)inner)->stepDustCount =
                        lbl_803DC6B0[((PlayerState*)inner)->gaitStepLevel];
                }
            }
            fn_802B066C(obj, inner);
            if (((PlayerState*)inner)->unk8CA == 1)
            {
                ((PlayerState*)inner)->unk7D0 =
                    ((PlayerState*)inner)->unk7CC * timeDelta + ((PlayerState*)inner)->unk7D0;
                if (((PlayerState*)inner)->unk7D0 >= lbl_803E80C4)
                {
                    ((PlayerState*)inner)->unk7D0 = lbl_803E80C4;
                    ((PlayerState*)inner)->unk7CC = lbl_803E7EA4;
                }
                else if (((PlayerState*)inner)->unk7D0 <= lbl_803E7EA4)
                {
                    ((PlayerState*)inner)->unk7D0 = lbl_803E7EA4;
                    ((PlayerState*)inner)->unk7CC = lbl_803E7F14;
                }
            }
            fn_802AFB0C(obj, inner, inner);
            if (*(void**)((char*)inner + 0x7f8) != NULL &&
                Obj_IsObjectAlive(((PlayerState*)inner)->heldObj) == 0)
            {
                ((PlayerState*)inner)->isHoldingObject = 0;
                if (*(void**)((char*)inner + 0x7f8) != NULL)
                {
                    s16 typ = ((GameObject*)((PlayerState*)inner)->heldObj)->anim.seqId;
                    if (typ == 0x3cf || typ == 0x662)
                    {
                        objThrowFn_80182504(((PlayerState*)inner)->heldObj);
                    }
                    else
                    {
                        objSaveFn_800ea774(((PlayerState*)inner)->heldObj);
                    }
                    *(s16*)((char*)((PlayerState*)inner)->heldObj + 0x6) =
                        *(s16*)((char*)((PlayerState*)inner)->heldObj + 0x6) & ~0x4000;
                    *(int*)((char*)((PlayerState*)inner)->heldObj + 0xf8) = 0;
                    ((PlayerState*)inner)->heldObj = 0;
                }
            }
            if ((*(u8*)(*(int*)&((GameObject*)obj)->extra + 0xc4) & 0x40) != 0)
            {
                v = (int)-(lbl_803E80E4 * timeDelta -
                    (f32)(u32) * (u8*)((char*)obj + 0xf1));
            }
            else
            {
                v = (int)(lbl_803E80E4 * timeDelta +
                    (f32)(u32) * (u8*)((char*)obj + 0xf1));
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
            fn_802AF7F8(obj, inner);
            playerProcessQueuedItemCommand(obj, inner);
            if (((ByteFlags*)((char*)inner + 0x3f3))->b20 != 0 &&
                (*gScreenTransitionInterface)->isFinished() != 0)
            {
                (*gMapEventInterface)->gotoRestartPoint();
            }
            if (((ByteFlags*)((char*)inner + 0x3f3))->b20 == 0 &&
                (*(int*)((char*)inner + 0x310) & 1) != 0)
            {
                if (Sfx_IsPlayingFromObject(
                    obj, (u16)(((PlayerState*)inner)->characterId == 0 ? 0x2d0 : 0x26)) == 0)
                {
                    Sfx_PlayFromObject(
                        0, (u16)(((PlayerState*)inner)->characterId == 0 ? 0x2d0 : 0x26));
                }
                ((ByteFlags*)((char*)inner + 0x3f3))->b20 = 1;
                (*gScreenTransitionInterface)->start(0x1e, 1);
                Pause_ResetMenuFrameCounter();
            }
            if (gPlayerPathObject != 0 && ((ByteFlags*)((char*)inner + 0x3f4))->b40 != 0)
            {
                ((GameObject*)gPlayerPathObject)->objectFlags =
                    ((GameObject*)gPlayerPathObject)->objectFlags & ~7;
                if (((PlayerState*)inner)->staffGrown == 0)
                {
                    ((GameObject*)gPlayerPathObject)->objectFlags =
                        ((GameObject*)gPlayerPathObject)->objectFlags | 2;
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
                    int ok = (*(void**)((char*)inner + 0x7f8) == NULL && hov != 0 &&
                        ((ByteFlags*)((char*)inner + 0x3f0))->b20 == 0 &&
                        ((ByteFlags*)((char*)inner + 0x3f0))->b10 == 0);
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
                                ((PlayerState*)inner)->animSoundId, (void*)(inner + 0x3c4),
                                (void*)(inner + 4), ((PlayerState*)inner)->baddie.animSpeedA,
                                lbl_803E7EE0);
        }
    }
}

extern f32 Curve_EvalCatmullRom(int curve, f32 t, int mode);

void fn_802B0EA4(int obj, int inner, int state)
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
        if ((f32)((PlayerState*)inner)->yawRate < dead &&
            (f32)((PlayerState*)inner)->yawRate > -dead)
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
        if ((f32)((PlayerState*)inner)->targetYawRate < dead &&
            (f32)((PlayerState*)inner)->targetYawRate > -dead)
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
    *(int*)&((PlayerState*)inner)->cameraTargetObject =
        (*gCameraInterface)->getTarget();
    cam = *(char**)((char*)inner + 0x4b8);
    if (cam != NULL)
    {
        dx = ((GameObject*)cam)->anim.localPosX - ((GameObject*)obj)->anim.localPosX;
        dz = ((GameObject*)cam)->anim.localPosZ - ((GameObject*)obj)->anim.localPosZ;
        ((PlayerState*)inner)->targetObjectYaw = getAngle(-dx, -dz) & 0xffff;
        ((PlayerState*)inner)->targetObjectDist = sqrtf(dx * dx + dz * dz);
        ((PlayerState*)inner)->unk4B4 =
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
        t = ((t = lbl_803E7EA4), spd < t)
                ? t
                : ((spd > (t = ((PlayerState*)inner)->maxSpeed)) ? t : spd);
        if (lbl_803E7EE0 == ((PlayerState*)inner)->targetAnimSpeed)
        {
            ((PlayerState*)inner)->velSmoothRate = lbl_803E7F44;
        }
        else
        {
            u = t * ((PlayerState*)inner)->curveSpeedScale;
            idx = (int)u;
            ((PlayerState*)inner)->velSmoothRate =
                lbl_803E7EE0 / Curve_EvalCatmullRom(((PlayerState*)inner)->paramCurve0 + (idx + 1) * 4, u - (f32)idx, 0);
        }
    }
    else
    {
        spd = ((PlayerState*)state)->baddie.animSpeedA;
        t = (spd < (t = lbl_803E7EA4))
                ? t
                : ((spd > (t = ((PlayerState*)inner)->maxSpeed)) ? t : spd);
        u = t * ((PlayerState*)inner)->curveSpeedScale;
        idx = (int)u;
        ((PlayerState*)inner)->velSmoothRate =
            lbl_803E7EE0 / Curve_EvalCatmullRom(((PlayerState*)inner)->paramCurve0 + (idx + 1) * 4, u - (f32)idx, 0);
    }
    u = t * ((PlayerState*)inner)->curveSpeedScale;
    idx = (int)u;
    ((PlayerState*)inner)->targetYawSmoothRate =
        Curve_EvalCatmullRom(((PlayerState*)inner)->paramCurve1 + (idx + 1) * 4, u - (f32)idx, 0);
    u = t * ((PlayerState*)inner)->curveSpeedScale;
    idx = (int)u;
    ((PlayerState*)inner)->targetYawRateLimit =
        Curve_EvalCatmullRom(((PlayerState*)inner)->paramCurve2 + (idx + 1) * 4, u - (f32)idx, 0);
    u = t * ((PlayerState*)inner)->curveSpeedScale;
    idx = (int)u;
    ((PlayerState*)inner)->yawSmoothRate =
        Curve_EvalCatmullRom(((PlayerState*)inner)->paramCurve3 + (idx + 1) * 4, u - (f32)idx, 0);
    u = t * ((PlayerState*)inner)->curveSpeedScale;
    idx = (int)u;
    ((PlayerState*)inner)->yawRateLimit =
        Curve_EvalCatmullRom(((PlayerState*)inner)->paramCurve4 + (idx + 1) * 4, u - (f32)idx, 0);
    if (((ByteFlags*)((char*)inner + 0x3f0))->b20 != 0)
    {
        f32 k;
        ((PlayerState*)inner)->targetYawSmoothRate = ((PlayerState*)inner)->targetYawSmoothRate * (k = lbl_803E80E4);
        ((PlayerState*)inner)->yawSmoothRate = ((PlayerState*)inner)->yawSmoothRate * k;
        ((PlayerState*)inner)->velSmoothRate = ((PlayerState*)inner)->velSmoothRate * lbl_803E7F44;
    }
    else
    {
        if (lbl_803E7EE0 != ((PlayerState*)inner)->unk834)
        {
            f32 base = *(f32*)(((PlayerState*)inner)->moveParams + 0x10);
            f32 frac = (((PlayerState*)state)->baddie.animSpeedA - base) /
                (((PlayerState*)inner)->maxSpeed - base);
            f32 v430 = ((PlayerState*)inner)->yawSmoothRate;
            f32 diff = ((PlayerState*)inner)->unk834 - lbl_803E7EE0;
            ((PlayerState*)inner)->yawSmoothRate =
                v430 * (diff * ((frac < lbl_803E7EA4)
                                    ? lbl_803E7EA4
                                    : ((frac > lbl_803E7EE0) ? lbl_803E7EE0 : frac)) +
                    lbl_803E7EE0);
        }
    }
    if (*(void**)((char*)inner + 0x464) != NULL)
    {
        int n = ((PlayerState*)inner)->targetYawRateSigned;
        ((PlayerState*)inner)->leanCurveScale = Curve_EvalCatmullRom(
            ((PlayerState*)inner)->leanCurve + (n / 5 + 1) * 4, (f32)(n % 5) / lbl_803E7F10, 0);
    }
    else
    {
        ((PlayerState*)inner)->leanCurveScale = lbl_803E7EE0;
    }
    one = lbl_803E7EE0;
    ((PlayerState*)inner)->leanCurveScale = one;
    if (((ByteFlags*)((char*)inner + 0x3f0))->b20 == 0 &&
        ((PlayerState*)inner)->waterDepth > lbl_803E7EA4)
    {
        ((PlayerState*)inner)->speedScale =
            (((PlayerState*)inner)->waterDepth - lbl_803E7FFC) / lbl_803E8098;
        v = ((PlayerState*)inner)->speedScale;
        ((PlayerState*)inner)->speedScale = (v < lbl_803E7EA4) ? lbl_803E7EA4 : ((v > one) ? one : v);
        ((PlayerState*)inner)->speedScale =
            -(lbl_803E7E98 * ((PlayerState*)inner)->speedScale - lbl_803E7EE0);
    }
    else
    {
        if (((PlayerState*)state)->baddie.spawnRotY > 0)
        {
            ((PlayerState*)inner)->speedScale =
                (f32)((PlayerState*)state)->baddie.spawnRotY / lbl_803E7EE8;
            v = ((PlayerState*)inner)->speedScale;
            ((PlayerState*)inner)->speedScale =
                (v < lbl_803E7EA4) ? lbl_803E7EA4 : ((v > lbl_803E7EE0) ? lbl_803E7EE0 : v);
            ((PlayerState*)inner)->speedScale =
                -(lbl_803E7EAC * ((PlayerState*)inner)->speedScale - lbl_803E7EE0);
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

extern s16 gPlayerStopMoves[4];
extern f32 lbl_803E8084;
extern f32 lbl_803E8088;

int fn_802A6694(int obj, int state, f32 fv)
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
        if (((PlayerState*)state)->baddie.unk276 != 0x24 &&
            ((PlayerState*)state)->baddie.unk276 != 0x25)
        {
            ((PlayerState*)state)->baddie.animSpeedC = lbl_803E7EA4;
        }
        else if (((ByteFlags*)((char*)inner + 0x3f1))->b20 == 0)
        {
            int a = ((PlayerState*)inner)->inputHeading;
            ((PlayerState *)inner)->lastInputHeading = a;
            ((PlayerState*)inner)->yaw = a;
            ((PlayerState*)inner)->yawRate = 0;
            ((PlayerState *)inner)->yawRateSigned = 0;
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
        interpolate(((PlayerState*)state)->baddie.animSpeedA, ((PlayerState*)inner)->targetAnimSpeed,
                    timeDelta);
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
        ((PlayerState*)state)->baddie.animSpeedC >= *(f32*)(((PlayerState *)inner)->moveParams + 4))
    {
        *(int*)&((PlayerState*)state)->baddie.unk308 = (int)fn_802A514C;
        return 3;
    }
    fn_802AD204(obj, inner);
    if (*(s16**)((char*)inner + 0x3f8) == (s16*)(tbl + 0x190))
    {
        if (((PlayerState*)inner)->idleHoldTimer >= lbl_803E7FBC &&
            **(s8**)&((PlayerState *)inner)->playerStatus <= 4)
        {
            move = 0x5d;
            fv = lbl_803E7F78;
            if (RandomTimer_UpdateRangeTrigger((void*)(inner + 0x3ec), lbl_803E7ED4, lbl_803E7F10) != 0)
            {
                Sfx_PlayFromObject(obj, 0x452);
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
                    ((PlayerState*)inner)->stopMoveIndex =
                        (u8)(((PlayerState*)inner)->stopMoveIndex % 3);
                }
                ((PlayerState*)inner)->idleWaitTimer = randomGetRange(800, 0x44c);
            }
        }
    picked:
        if (((GameObject*)obj)->anim.currentMove == **(s16**)((char*)inner + 0x3f8))
        {
            ((PlayerState*)inner)->idleHoldTimer =
                ((PlayerState*)inner)->idleHoldTimer + timeDelta;
            v = ((PlayerState*)inner)->idleHoldTimer;
            ((PlayerState*)inner)->idleHoldTimer =
                (v < lbl_803E7EA4) ? lbl_803E7EA4 : ((v > lbl_803E7FBC) ? lbl_803E7FBC : v);
            *(u16*)&((PlayerState*)inner)->idleWaitTimer =
                (f32) * (s16*)((char*)inner + 0x812) - timeDelta;
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
        (((PlayerState*)inner)->maxSpeed - lbl_803E7F6C) *
        (t * ((PlayerState*)inner)->speedScale);
    if (((ByteFlags*)((char*)inner + 0x3f0))->b20 != 0)
    {
        fn_802ADE80(obj, inner, state);
    }
    {
        u32 fl = ((PlayerState*)inner)->flags3F0;
        if ((fl >> 5 & 1) == 0 && (fl >> 6 & 1) == 0 && (fl >> 4 & 1) == 0 &&
            (fl >> 2 & 1) == 0 && (fl >> 3 & 1) == 0 && (fl >> 1 & 1) == 0 &&
            *(void**)((char*)inner + 0x7f8) == NULL &&
            ((PlayerState*)inner)->curAnimId != 0x44)
        {
            calm = 1;
        }
        else
        {
            calm = 0;
        }
    }
    if (calm && (((PlayerState*)inner)->buttonsJustPressed & 0x400) != 0)
    {
        fn_802AED2C(obj, inner, state);
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
        ((PlayerState *)inner)->targetYawRateSigned = 0;
        ((PlayerState*)inner)->targetYawRate = 0;
        ((PlayerState *)inner)->yawRateSigned = 0;
        ((PlayerState*)inner)->yawRate = 0;
        ((PlayerState*)inner)->animSoundId = ((PlayerState*)inner)->walkAnimSoundId;
        ((PlayerState*)inner)->gaitStepLevel = 0;
        ((PlayerState*)state)->baddie.velSmoothTime = lbl_803E8018;
        ((PlayerState*)state)->baddie.moveSpeed = lbl_803E8084;
        if (((ByteFlags*)((char*)inner + 0x3f0))->b20 == 0 &&
            ((ByteFlags*)((char*)inner + 0x3f1))->b20 == 0)
        {
            if (((PlayerState*)state)->baddie.unk276 == 2)
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
    else if (((ByteFlags*)((char*)inner + 0x3f0))->b20 == 0 &&
        ((ByteFlags*)((char*)inner + 0x3f1))->b20 == 0 &&
        ((PlayerState *)inner)->targetYawRateSigned > 5)
    {
        if (((GameObject*)obj)->anim.currentMove !=
            *(s16*)(((PlayerState*)inner)->moveAnimTable + 0x3e) &&
            ((int (*)(int))ObjAnim_GetCurrentEventCountdown)(obj) == 0)
        {
            ObjAnim_SetCurrentMove(obj, *(s16*)(((PlayerState*)inner)->moveAnimTable + 0x3e),
                                   lbl_803E7EA4, 0);
            ((PlayerState*)state)->baddie.moveSpeed = lbl_803E7E90;
        }
    }
    else if (((GameObject*)obj)->anim.currentMove != move &&
        ((int (*)(int))ObjAnim_GetCurrentEventCountdown)(obj) == 0)
    {
        s16 cur = ((GameObject*)obj)->anim.currentMove;
        if (cur == gPlayerStopMoves[0] || cur == gPlayerStopMoves[1] ||
            cur == gPlayerStopMoves[2] || cur == gPlayerStopMoves[3])
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
        *(u16*)&((PlayerState*)inner)->targetYaw =
            gPlayerDegToBinAngle * step + (f32) * (s16*)((char*)inner + 0x478);
        step = interpolate((f32) * (int*)((char*)inner + 0x488),
                           lbl_803E7EE0 / ((PlayerState*)inner)->yawSmoothRate, timeDelta);
        lim = ((PlayerState*)inner)->yawRateLimit * timeDelta;
        step = (step < lim) ? step : lim;
        if (((PlayerState*)inner)->yawRate < 0)
        {
            step = -step;
        }
        *(u16*)&((PlayerState*)inner)->yaw =
            gPlayerDegToBinAngle * step + (f32) * (s16*)((char*)inner + 0x484);
    }
    else
    {
        f32 vx;
        f32 vz;
        f32 c;
        c = mathSinf((gPlayerPi * (f32) * (int*)((char*)inner + 0x474)) /
            lbl_803E7F98);
        vx = t * -c;
        vx = ((PlayerState*)inner)->maxSpeed * vx;
        c = mathCosf((gPlayerPi * (f32) * (int*)((char*)inner + 0x474)) / lbl_803E7F98);
        vz = t * -c;
        vz = ((PlayerState*)inner)->maxSpeed * vz;
        vx = interpolate(vx - ((PlayerState*)inner)->smoothVelX,
                         ((PlayerState*)inner)->velSmoothRate, timeDelta);
        vz = interpolate(vz - ((PlayerState*)inner)->smoothVelZ,
                         ((PlayerState*)inner)->velSmoothRate, timeDelta);
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

void playerDoHitDetection(int obj)
{
    int inner = *(int*)&((GameObject*)obj)->extra;
    f32 dt = timeDelta;
    f32 spd;
    int sub;
    int desc;
    u32 fl;
    f32 x;
    f32 y;
    f32 z;

    *(u32*)&((PlayerState*)inner)->flags360 &= ~0x8000000LL;
    if (((ByteFlags*)((char*)inner + 0x3f2))->b20 != 0 &&
        (((GameObject*)obj)->objectFlags & 0x1000) != 0)
    {
        ((PlayerState*)inner)->baddie.physicsActive = 0;
    }
    (*gPathControlInterface)->update((void*)obj, (void*)(inner + 4), timeDelta);
    (*gPathControlInterface)->apply((void*)obj, (void*)(inner + 4));
    (*gPathControlInterface)->advance((void*)obj, (void*)(inner + 4), timeDelta);
    ObjModelChain_AdvancePhase((ObjModelChain*)gPlayerModelChain);
    if (!(((PlayerState*)inner)->cutsceneTimer >= lbl_803E7EF0))
    {
        (*(void (*)(int, int, void*))(*(int*)(*gPlayerInterface + 0xc)))(obj, inner,
                                                                         gPlayerStateHandlers);
        if (*(s8*)&((PlayerState*)inner)->baddie.unk34D == 1)
        {
            if (gPlayerPathObject != 0 && ((ByteFlags*)((char*)inner + 0x3f4))->b40 != 0 &&
                (*(void**)((sub = *(int*)((char*)gPlayerPathObject + 0x54)) + 0x50) != NULL ||
                    (*(s8*)(sub + 0xad) != 0 && *(s8*)(sub + 0xac) != 0xe)))
            {
                Player_GetObjHitsState(obj)->suppressOutgoingHits = 1;
                ((PlayerState*)inner)->unk7D8 = lbl_803E7EA4;
                *(u8*)&((PlayerState*)inner)->hitWindowIndex = *(u8*)&((PlayerState*)inner)->activeHitWindow;
                if ((((HitDesc*)((PlayerState*)inner)->moveSlots)[
                        (u32)((PlayerState*)inner)->moveSlotIndex].flags & 1) != 0)
                {
                    ((PlayerState*)inner)->cutsceneTimer = lbl_803E80A8;
                }
                if ((((HitDesc*)((PlayerState*)inner)->moveSlots)[
                        (u32)((PlayerState*)inner)->moveSlotIndex].flags & 2) != 0)
                    {
                        ((PlayerState*)inner)->hitInterval =
                            ((HitDesc*)((PlayerState*)inner)->moveSlots)[
                                (u32)((PlayerState*)inner)->moveSlotIndex].valsA[
                                ((PlayerState*)inner)->activeHitWindow];
                        ((PlayerState*)inner)->hitCountMax =
                            ((HitDesc*)((PlayerState*)inner)->moveSlots)[
                                (u32)((PlayerState*)inner)->moveSlotIndex].valsB[
                                ((PlayerState*)inner)->activeHitWindow];
                        ((PlayerState*)inner)->hitTimer =
                            (f32)(u32)((PlayerState*)inner)->hitInterval;
                        ((PlayerState*)inner)->hitCount += 1;
                        ((PlayerState*)inner)->lastHitObject = *(int*)(sub + 0x50);
                    }
                {
                    char* h2 = *(char**)(sub + 0x50);
                    if (h2 != NULL)
                    {
                        if ((((GameObject*)h2)->anim.modelInstance->effectFlags & 4) != 0)
                        {
                            doRumble(lbl_803E7ED8);
                        }
                        if ((((GameObject*)h2)->anim.modelInstance->effectFlags & 8) != 0)
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
                        ((PlayerState*)inner)->unk8C1 = 1;
                    }
                    else if (c == 0x1b)
                    {
                        ((PlayerState*)inner)->unk8C1 = 2;
                    }
                    else if (c == 0x11)
                    {
                        ((PlayerState*)inner)->unk8C1 = 0;
                    }
                    else
                    {
                        ((PlayerState*)inner)->unk8C1 = 1;
                    }
                }
            }
            if (Player_GetObjHitsState(obj)->lastHitObject != 0)
            {
                Player_GetObjHitsState(obj)->suppressOutgoingHits = 1;
                ((PlayerState*)inner)->unk7D8 = lbl_803E7EA4;
                *(u8*)&((PlayerState*)inner)->hitWindowIndex = *(u8*)&((PlayerState*)inner)->activeHitWindow;
                if ((((u8*)(((PlayerState*)inner)->moveSlots +
                        (u32)((PlayerState*)inner)->moveSlotIndex * 0xb0))[0x88] & 1) != 0)
                {
                    ((PlayerState*)inner)->cutsceneTimer = lbl_803E80A8;
                }
                if ((((u8*)(((PlayerState*)inner)->moveSlots +
                        (u32)((PlayerState*)inner)->moveSlotIndex * 0xb0))[0x88] & 2) != 0)
                    {
                        ((PlayerState*)inner)->hitInterval =
                            ((u8*)(((PlayerState*)inner)->moveSlots +
                                (u32)((PlayerState*)inner)->moveSlotIndex * 0xb0) +
                                ((PlayerState*)inner)->activeHitWindow)[0xa8];
                        ((PlayerState*)inner)->hitCountMax =
                            ((u8*)(((PlayerState*)inner)->moveSlots +
                                (u32)((PlayerState*)inner)->moveSlotIndex * 0xb0) +
                                ((PlayerState*)inner)->activeHitWindow)[0xab];
                        ((PlayerState*)inner)->hitTimer =
                            (f32)(u32)((PlayerState*)inner)->hitInterval;
                        ((PlayerState*)inner)->hitCount += 1;
                        ((PlayerState*)inner)->lastHitObject =
                            Player_GetObjHitsState(obj)->lastHitObject;
                    }
            }
        }
        if ((*(u32*)&((PlayerState*)inner)->flags360 & 2) != 0)
        {
            void* h = *(void**)((char*)inner + 0xdc);
            if (h != NULL && ((fl = ((ObjAnimComponent*)h)->modelInstance->flags) & OBJMODEL_FLAG_SKIP_RESET_UPDATE) != 0
                &&
                (fl & 0x8000) == 0)
            {
                objHitDetectFn_80062e84(obj, (int)h, 1);
            }
            else if (((GameObject*)obj)->anim.parent != NULL && h == NULL)
            {
                objHitDetectFn_80062e84(obj, 0, 1);
            }
        }
        *(u32*)&((PlayerState*)inner)->flags360 |= 2LL;
        if ((void*)((PlayerState*)inner)->focusObject != NULL &&
            ((((GameObject*)obj)->objectFlags & 0x1000) != 0 ||
                arrayIndexOf(&lbl_803DC6C4, 2, ((PlayerState*)inner)->baddie.controlMode) != -1))
        {
            (*(void (*)(int, f32*, f32*, f32*))(
                *(int*)(*(int*)(*(int*)(((PlayerState*)inner)->focusObject + 0x68)) + 0x34)))(
                ((PlayerState*)inner)->focusObject, &x, &y, &z);
            (*gCameraInterface)->overridePos(x, y, z);
            fn_802A9D0C(obj, inner, ((PlayerState*)inner)->focusObject, 0, 0, 0, 0, 0);
        }
        if (*(s8*)&((PlayerState*)inner)->baddie.physicsActive == 1 &&
            (*(int*)((char*)inner + 4) & 0x100000) == 0)
        {
            if ((*(u32*)&((PlayerState*)inner)->flags360 & 0x2000) == 0 &&
                (*(s8*)((char*)inner + 0x264) & 0x33) != 0)
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
            if ((*(int*)inner & 0x800000) != 0 &&
                lbl_803E7EA4 == ((PlayerState*)inner)->pushVelX &&
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
                if (((*(s8*)((char*)inner + 0x264) & 2) != 0 &&
                        (*(s8*)((char*)inner + 0x264) & 0x20) == 0) ||
                    *(u8*)((char*)inner + 0x262) != 0 ||
                    (Player_GetObjHitsState(obj)->flags & 8) != 0)
                {
                    if (((PlayerState*)inner)->rumbleCooldown <= lbl_803E7EA4 &&
                        ((PlayerState*)inner)->baddie.animSpeedA > lbl_803E8160)
                    {
                        doRumble(lbl_803E7F10);
                        ((PlayerState*)inner)->rumbleCooldown = lbl_803E7F30;
                        Sfx_PlayFromObject(obj, 0x404);
                    }
                    dt = mathSinf((gPlayerPi * (f32)((PlayerState*)inner)->yaw) /
                        lbl_803E7F98);
                    {
                        f32 s = mathCosf((gPlayerPi * (f32)((PlayerState*)inner)->yaw) /
                            lbl_803E7F98);
                        ((PlayerState*)inner)->baddie.animSpeedA =
                            -((GameObject*)obj)->anim.velocityZ * s -
                            ((GameObject*)obj)->anim.velocityX * dt;
                    }
                    ((PlayerState*)inner)->baddie.animSpeedA =
                        ((PlayerState*)inner)->baddie.animSpeedA * lbl_803E7FC4;
                    {
                        f32 c = ((PlayerState*)inner)->baddie.animSpeedA;
                        f32 lo = lbl_803E8110 * ((PlayerState *)inner)->baddie.inputMagnitude;
                        ((PlayerState*)inner)->baddie.animSpeedA =
                            (c < lo)
                                ? lo
                                : ((c > ((PlayerState*)inner)->maxSpeed)
                                       ? ((PlayerState*)inner)->maxSpeed
                                       : c);
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
        if ((((GameObject*)obj)->objectFlags & 0x1000) == 0)
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
                *(u32*)&((PlayerState*)inner)->flags360 |= 0x8000000LL;
            }
        }
        *(u32*)&((PlayerState*)inner)->flags360 &= 0xffbfffff;
    }
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

extern int objGetFlagsE5_2(int obj);
extern void fn_8009A8C8(int obj, f32 fv);
extern int gPlayerSfxTimerA;
extern int gPlayerStepSfxTimer;
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
    work = ObjHits_GetPriorityHitWithPosition(obj, &hitObj, &surfIdx, &damage, &pos.x, &pos.y, &pos.z);
    orig = work;
    if (**(s8**)&((PlayerState *)inner)->playerStatus <= 0)
    {
        **(s8**)&((PlayerState *)inner)->playerStatus = 1;
    }
    if ((*(int (*)(int))ObjHits_IsObjectEnabled)(obj) == 0 || objGetFlagsE5_2(obj) != 0 ||
        ((ByteFlags*)((char*)inner + 0x3f3))->b20 != 0 ||
        (((GameObject*)obj)->objectFlags & 0x1000))
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
        if (*(s8*)&((PlayerState*)state)->baddie.unk34D == 3 && *(s8*)((char*)state + 0x34f) <= work)
        {
            return;
        }
        *(s8*)((char*)state + 0x34f) = work;
        ((GameObject*)obj)->anim.activeMove = -1;
        newAnim = -1;
        {
            u32 fl = ((PlayerState*)inner)->flags3F0;
            if ((fl >> 4 & 1) != 0 || (fl >> 2 & 1) != 0 || (fl >> 3 & 1) != 0 ||
                (fl >> 5 & 1) != 0 ||
                (anim = ((PlayerState*)state)->baddie.controlMode) == 0x36)
            {
                canCounter = 0;
            }
            else if ((u16)(anim - 1) <= 1 || (u16)(anim - 0x24) <= 1 ||
                ((PlayerState*)state)->baddie.targetObj != NULL)
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
            damage = **(s8**)&((PlayerState *)inner)->playerStatus;
            break;
        case 0x15:
            switch (*(s16*)(((PlayerState*)inner)->focusObject + 0x46))
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
            if (((ByteFlags*)((char*)inner + 0x3f3))->b08 != 0)
            {
                return;
            }
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
                        obj, (u16)(((PlayerState*)inner)->characterId == 0 ? 0x2ce : 0x48c));
                }
                gPlayerSfxTimerA = 6;
            }
            if (gPlayerStepSfxTimer == 0)
            {
                char* pt = *(char**)((char*)Player_GetActiveModel(obj) + 0x50);
                desc.x = playerMapOffsetX + *(f32*)(pt + surfIdx * 0x10 + 4);
                desc.y = *(f32*)(pt + surfIdx * 0x10 + 8);
                desc.z = playerMapOffsetZ + *(f32*)(pt + surfIdx * 0x10 + 0xc);
                (*gPartfxInterface)->spawnObject(
                    (void*)obj, 0x328, &desc, 0x200001, -1, NULL);
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
                    playerDie(obj);
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
                    Sfx_PlayFromObject((int)hitObj, 0x36e);
                    break;
                case 0x5f9:
                case 0x5fa:
                case 0x5fe:
                    Sfx_PlayFromObject((int)hitObj, 0x239);
                    break;
                case 0x2c5:
                    Sfx_PlayFromObject((int)hitObj, 0xd0);
                    break;
                case 0x709:
                    Sfx_PlayFromObject((int)hitObj, 0x486);
                    break;
                case 0x458:
                case 0x842:
                    Sfx_PlayFromObject((int)hitObj, 0x36f);
                    break;
                }
            }
            switch (orig)
            {
            case 0x16:
                if (hitObj != NULL && (((GameObject*)hitObj)->anim.seqId == 0x613 ||
                    ((GameObject*)hitObj)->anim.seqId == 0x70f))
                {
                    Sfx_PlayFromObject(obj,
                                       (u16)(((PlayerState*)inner)->characterId == 0 ? 0x1f : 0x24));
                }
                else
                {
                    Sfx_PlayFromObject(obj, 0x367);
                }
                break;
            case 0x14:
            case 0x1f:
                Sfx_PlayFromObject(obj, (u16)(((PlayerState*)inner)->characterId == 0 ? 0x1f : 0x24));
                Sfx_PlayFromObject(obj, 0x393);
                if (Sfx_IsPlayingFromObject(obj, 0x394) == 0)
                {
                    Sfx_PlayFromObject(obj, 0x394);
                }
                if (**(s8**)&((PlayerState *)inner)->playerStatus > 0)
                {
                    objLightFn_8009a1dc((void*)obj, lbl_803E8024, buf, 6, 0);
                }
                break;
            case 0x1c:
                Sfx_PlayFromObject(obj, 0x318);
                if (**(s8**)&((PlayerState *)inner)->playerStatus > 0)
                {
                    objLightFn_8009a1dc((void*)obj, lbl_803E8024, buf, 8, 0);
                }
                break;
            default:
                Sfx_PlayFromObject(obj, (u16)(((PlayerState*)inner)->characterId == 0 ? 0x1f : 0x24));
                if (hitObj != NULL)
                {
                    switch (((GameObject*)hitObj)->anim.seqId)
                    {
                    case 0x33:
                        Sfx_PlayFromObject(obj, 0x36e);
                        if (**(s8**)&((PlayerState *)inner)->playerStatus > 0)
                        {
                            objLightFn_8009a1dc((void*)obj, lbl_803E8024, buf, 5, 0);
                        }
                        break;
                    case 0x7c8:
                        if (**(s8**)&((PlayerState *)inner)->playerStatus > 0)
                        {
                            objLightFn_8009a1dc((void*)obj, lbl_803E8024, buf, 8, 0);
                        }
                        break;
                    default:
                        if (**(s8**)&((PlayerState *)inner)->playerStatus > 0)
                        {
                            objLightFn_8009a1dc((void*)obj, lbl_803E8024, buf, 5, 0);
                        }
                        break;
                    }
                }
                else
                {
                    if (**(s8**)&((PlayerState *)inner)->playerStatus > 0)
                    {
                        objLightFn_8009a1dc((void*)obj, lbl_803E8024, buf, 5, 0);
                    }
                }
                break;
            }
            if (**(s8**)&((PlayerState *)inner)->playerStatus > 0)
            {
                Obj_SetModelColorFadeRecursive(obj, 0xb4, 200, 0, 0, 1);
            }
            if (((PlayerState*)state)->baddie.controlMode == 0x1a)
            {
                fn_8009A8C8(obj, lbl_803E8134);
            }
            ((PlayerState*)inner)->idleHoldTimer = lbl_803E7EA4;
            ((PlayerState*)inner)->idleWaitTimer = randomGetRange(800, 0x44c);
            ((PlayerState*)inner)->isHoldingObject = 0;
            if (*(void**)((char*)inner + 0x7f8) != NULL)
            {
                s16 t = ((GameObject*)((PlayerState*)inner)->heldObj)->anim.seqId;
                if (t == 0x3cf || t == 0x662)
                {
                    objThrowFn_80182504(((PlayerState*)inner)->heldObj);
                }
                else
                {
                    objSaveFn_800ea774(((PlayerState*)inner)->heldObj);
                }
                *(s16*)(((PlayerState*)inner)->heldObj + 6) =
                    *(s16*)(((PlayerState*)inner)->heldObj + 6) & ~0x4000;
                *(int*)(((PlayerState*)inner)->heldObj + 0xf8) = 0;
                ((PlayerState*)inner)->heldObj = 0;
            }
            if (newAnim != -1 && ((PlayerState*)state)->baddie.controlMode != newAnim &&
                **(s8**)&((PlayerState *)inner)->playerStatus > 0)
            {
                (*(void (*)(int, int, int))(*(int*)(*gPlayerInterface + 0x14)))(obj, state, newAnim);
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

#pragma opt_loop_invariants off
void fn_802B249C(int obj, int inner, int state)
{
    int p;
    int param = 0;
    int msg;

    while (ObjMsg_Pop(obj, &msg, &p, &param) != 0)
    {
        switch (msg)
        {
        case 0x80002:
            ((PlayerState*)inner)->queuedItemCommand = (s16)param;
            if (((PlayerState*)state)->baddie.targetObj != NULL &&
                (param == 0x2d || param == 0x5ce))
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
                if (d > lbl_803E7EE0)
                {
                    dx = dx / d;
                    dz = dz / d;
                }
                {
                    f32 spd = lbl_803E7F9C;
                    ((GameObject*)obj)->anim.velocityX = spd * dx;
                    ((GameObject*)obj)->anim.velocityZ = spd * dz;
                    ((GameObject*)obj)->anim.velocityY = spd;
                }
                (*(void (*)(int, int, int))(*(int*)(*gPlayerInterface + 0x14)))(obj, state, 0x21);
                *(int*)&((PlayerState*)state)->baddie.unk304 = 0;
                {
                    int in2 = *(int*)&((GameObject*)obj)->extra;
                    s8* pc = *(s8**)((char*)in2 + 0x35c);
                    int v = pc[0] - param;
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
                ((PlayerState*)inner)->isHoldingObject = 0;
                if (*(void**)((char*)inner + 0x7f8) != NULL)
                {
                    s16 typ = ((GameObject*)((PlayerState*)inner)->heldObj)->anim.seqId;
                    if (typ == 0x3cf || typ == 0x662)
                    {
                        objThrowFn_80182504(((PlayerState*)inner)->heldObj);
                    }
                    else
                    {
                        objSaveFn_800ea774(((PlayerState*)inner)->heldObj);
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
                f32 dx = *(f32*)(p + 0xc) - ((GameObject*)obj)->anim.localPosX;
                f32 dz = ((PlayerState*)p)->baddie.posX - ((GameObject*)obj)->anim.localPosZ;
                f32 d = sqrtf(dz * dz + dx * dx);
                if (d > lbl_803E7EE0)
                {
                    dx = dx / d;
                    dz = dz / d;
                }
                {
                    f32 spd = lbl_803E7F9C;
                    ((GameObject*)obj)->anim.velocityX = spd * -dx;
                    ((GameObject*)obj)->anim.velocityZ = spd * -dz;
                    ((GameObject*)obj)->anim.velocityY = spd;
                }
                (*(void (*)(int, int, int))(*(int*)(*gPlayerInterface + 0x14)))(obj, state, 0x21);
                *(int*)&((PlayerState*)state)->baddie.unk304 = 0;
                {
                    int in2 = *(int*)&((GameObject*)obj)->extra;
                    s8* pc = *(s8**)((char*)in2 + 0x35c);
                    int v = pc[0] - param;
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
                ((PlayerState*)inner)->isHoldingObject = 0;
                if (*(void**)((char*)inner + 0x7f8) != NULL)
                {
                    s16 typ = ((GameObject*)((PlayerState*)inner)->heldObj)->anim.seqId;
                    if (typ == 0x3cf || typ == 0x662)
                    {
                        objThrowFn_80182504(((PlayerState*)inner)->heldObj);
                    }
                    else
                    {
                        objSaveFn_800ea774(((PlayerState*)inner)->heldObj);
                    }
                    *(s16*)((char*)((PlayerState*)inner)->heldObj + 0x6) =
                        *(s16*)((char*)((PlayerState*)inner)->heldObj + 0x6) & ~0x4000;
                    *(int*)((char*)((PlayerState*)inner)->heldObj + 0xf8) = 0;
                    ((PlayerState*)inner)->heldObj = 0;
                }
                Sfx_PlayFromObject(obj,
                                   (u16)(((PlayerState*)inner)->characterId == 0 ? 0x1f : 0x24));
                break;
            }
        case 0x60005:
            {
                f32 dx = *(f32*)(p + 0xc) - ((GameObject*)obj)->anim.localPosX;
                f32 dz = ((PlayerState*)p)->baddie.posX - ((GameObject*)obj)->anim.localPosZ;
                f32 d = sqrtf(dz * dz + dx * dx);
                if (d > lbl_803E7EE0)
                {
                    dx = dx / d;
                    dz = dz / d;
                }
                {
                    f32 spd = lbl_803E7F9C;
                    ((GameObject*)obj)->anim.velocityX = spd * -dx;
                    ((GameObject*)obj)->anim.velocityZ = spd * -dz;
                    ((GameObject*)obj)->anim.velocityY = spd;
                }
                (*(void (*)(int, int, int))(*(int*)(*gPlayerInterface + 0x14)))(obj, state, 0x21);
                *(int*)&((PlayerState*)state)->baddie.unk304 = 0;
                ObjAnim_SetCurrentMove(obj, 0x450, lbl_803E7EA4, 0);
                {
                    int in2 = *(int*)&((GameObject*)obj)->extra;
                    s8* pc = *(s8**)((char*)in2 + 0x35c);
                    int v = pc[0] - param;
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
                ((PlayerState*)inner)->isHoldingObject = 0;
                if (*(void**)((char*)inner + 0x7f8) != NULL)
                {
                    s16 typ = ((GameObject*)((PlayerState*)inner)->heldObj)->anim.seqId;
                    if (typ == 0x3cf || typ == 0x662)
                    {
                        objThrowFn_80182504(((PlayerState*)inner)->heldObj);
                    }
                    else
                    {
                        objSaveFn_800ea774(((PlayerState*)inner)->heldObj);
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
                ((PlayerState*)inner)->unk8DC = param;
                t = *(void**)(p + 0x64);
                if (t != NULL)
                {
                    *(u32*)((char*)t + 0x30) &= ~0x4LL;
                }
                bit = **(s16**)((char*)inner + 0x8dc);
                if (bit > 0)
                {
                    if (GameBit_Get(bit) != 0)
                    {
                        ObjMsg_SendToObject(p, 0x7000b, obj, 0);
                        break;
                    }
                    else
                    {
                        f32 r = *(f32*)(p + 8) / *(f32*)(*(int*)(p + 0x50) + 4);
                        f32 k = lbl_803E7F68;
                        f32 lim = lbl_803E7F30;
                        while (r * (((GameObject*)obj)->anim.hitboxScale * ((GameObject*)obj)->anim.rootMotionScale) >
                            lim)
                        {
                            *(f32*)(p + 8) = *(f32*)(p + 8) * k;
                            r = *(f32*)(p + 8) / *(f32*)(*(int*)(p + 0x50) + 4);
                        }
                        GameBit_Set(**(s16**)((char*)inner + 0x8dc), 1);
                        (*gObjectTriggerInterface)->setObjects(
                            *(s16*)(p + 0x46), 0, 0);
                        (*gObjectTriggerInterface)->runSequence(0, (void*)obj,
                                                                -1);
                    }
                }
                else
                {
                    f32 r = *(f32*)(p + 8) / *(f32*)(*(int*)(p + 0x50) + 4);
                    f32 k = lbl_803E7F68;
                    f32 lim = lbl_803E7F30;
                    while (r * (((GameObject*)obj)->anim.hitboxScale * ((GameObject*)obj)->anim.rootMotionScale) > lim)
                    {
                        *(f32*)(p + 8) = *(f32*)(p + 8) * k;
                        r = *(f32*)(p + 8) / *(f32*)(*(int*)(p + 0x50) + 4);
                    }
                    (*gObjectTriggerInterface)->setObjects(
                        *(s16*)(p + 0x46), 0, 0);
                    (*gObjectTriggerInterface)->runSequence(0, (void*)obj,
                                                            -1);
                }
                ((PlayerState*)inner)->interactObject = p;
                ((PlayerState*)inner)->unk688 = *(s16*)(((PlayerState*)inner)->unk8DC + 2);
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
                ((PlayerState*)inner)->heldObj = p;
                mdl = (int*)Obj_GetActiveModel(((PlayerState*)inner)->heldObj);
                if (mdl != NULL && (void*)*mdl != NULL && (*(u16*)(*mdl + 2) & 0x8000) == 0)
                {
                    *(u8*)(((PlayerState*)inner)->heldObj + 0xf2) =
                        *(u8*)((char*)obj + 0xf2);
                }
                ((PlayerState*)inner)->unk7FC = (f32)(param >> 0x10) / lbl_803E7ED8;
                (*(void (*)(int, int, int))(*(int*)(*gPlayerInterface + 0x14)))(obj, state, 5);
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
                ((PlayerState*)inner)->heldObj = p;
                mdl = (int*)Obj_GetActiveModel(((PlayerState*)inner)->heldObj);
                if (mdl != NULL && (void*)*mdl != NULL && (*(u16*)(*mdl + 2) & 0x8000) == 0)
                {
                    *(u8*)(((PlayerState*)inner)->heldObj + 0xf2) =
                        *(u8*)((char*)obj + 0xf2);
                }
                ((PlayerState*)inner)->unk7FC = (f32)(param >> 0x10);
                (*(void (*)(int, int, int))(*(int*)(*gPlayerInterface + 0x14)))(obj, state, 5);
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

void fn_80295B2C(int obj, f32 f1, f32 f2, f32 f3)
{
    int inner = *(int*)&((GameObject*)obj)->extra;
    ((GameObject*)obj)->anim.previousWorldPosX = f1;
    ((GameObject*)obj)->anim.previousLocalPosX = f1;
    ((GameObject*)obj)->anim.worldPosX = f1;
    ((GameObject*)obj)->anim.localPosX = f1;
    ((GameObject*)obj)->anim.previousWorldPosY = f2;
    ((GameObject*)obj)->anim.previousLocalPosY = f2;
    ((GameObject*)obj)->anim.worldPosY = f2;
    ((GameObject*)obj)->anim.localPosY = f2;
    ((GameObject*)obj)->anim.previousWorldPosZ = f3;
    ((GameObject*)obj)->anim.previousLocalPosZ = f3;
    ((GameObject*)obj)->anim.worldPosZ = f3;
    ((GameObject*)obj)->anim.localPosZ = f3;
    fn_802AB5A4(obj, inner, 7);
    (*(void (*)(int, int, int))(*(int*)(*gPlayerInterface + 0x14)))(obj, inner, 1);
    *(int*)&((PlayerState*)inner)->baddie.unk304 = (int)fn_802A514C;
}

int fn_802A4F8C(int obj, int state, f32 fv)
{
    if (*(s8*)&((PlayerState*)state)->baddie.moveJustStartedA != 0)
    {
        ObjAnim_SetCurrentMove(obj, 0x92, lbl_803E7EA4, 0);
        ((PlayerState*)state)->baddie.moveSpeed = lbl_803E8060;
    }
    (*(void (*)(int, int, f32, int))(*(int*)(*gPlayerInterface + 0x20)))(obj, state, fv, 3);
    if (*(s8*)&((PlayerState*)state)->baddie.moveDone != 0)
    {
        *(int*)&((PlayerState*)state)->baddie.unk308 = (int)fn_802A514C;
        return 2;
    }
    return 0;
}

void playerAddMoney(int obj, int amount)
{
    PlayerState* inner = ((GameObject*)obj)->extra;
    int cap;
    int total;
    if (GameBit_Get(0x91b))
    {
        cap = 0xc8;
    }
    else if (GameBit_Get(0x91a))
    {
        cap = 0x64;
    }
    else if (GameBit_Get(0x919))
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
    GameBit_Set(0x1be, total);
}

void fn_80296C84(int obj)
{
    PlayerState* inner = ((GameObject*)obj)->extra;
    int deref = inner->playerStatus;
    int v = *(s8*)((char*)deref + 1);
    if (v < 0)
    {
        v = 0;
    }
    else
    {
        int hi = *(s8 volatile*)((char*)deref + 1);
        if (v > hi)
        {
            v = hi;
        }
    }
    *(s8*)((char*)*(int volatile*)((char*)inner + 0x35C)) = (s8)v;
    Obj_SetModelColorFadeRecursive(obj, 0x168, 0xc8, 0, 0, 1);
    ((ByteFlags*)((char*)inner + 0x3f3))->b04 = 1;
    inner->knockbackTimer = lbl_803E7EA4;
    inner->moveVariantIndex = 0xff;
}

void fn_8029672C(int obj, int mode)
{
    PlayerState* inner = ((GameObject*)obj)->extra;
    if (mode == 0)
    {
        if (gPlayerPathObject == NULL) return;
        if (((ByteFlags*)((char*)inner + 0x3f4))->b40 == 0) return;
        inner->staffActionRequest = 0;
        ((ByteFlags*)((char*)inner + 0x3f4))->b08 = 0;
    }
    else if (mode == 1)
    {
        if (gPlayerPathObject == NULL) return;
        if (((ByteFlags*)((char*)inner + 0x3f4))->b40 == 0) return;
        inner->staffActionRequest = 1;
        ((ByteFlags*)((char*)inner + 0x3f4))->b08 = 1;
    }
    else
    {
        if (gPlayerPathObject == NULL) return;
        if (((ByteFlags*)((char*)inner + 0x3f4))->b40 == 0) return;
        inner->staffActionRequest = 1;
        ((ByteFlags*)((char*)inner + 0x3f4))->b08 = 0;
    }
}

void fn_802967E0(int obj, int mode)
{
    PlayerState* inner = ((GameObject*)obj)->extra;
    if (mode == 0)
    {
        if (gPlayerPathObject == NULL) return;
        if (((ByteFlags*)((char*)inner + 0x3f4))->b40 == 0) return;
        inner->staffActionRequest = 2;
        ((ByteFlags*)((char*)inner + 0x3f4))->b08 = 0;
    }
    else if (mode == 1)
    {
        if (gPlayerPathObject == NULL) return;
        if (((ByteFlags*)((char*)inner + 0x3f4))->b40 == 0) return;
        inner->staffActionRequest = 4;
        ((ByteFlags*)((char*)inner + 0x3f4))->b08 = 1;
    }
    else
    {
        if (gPlayerPathObject == NULL) return;
        if (((ByteFlags*)((char*)inner + 0x3f4))->b40 == 0) return;
        inner->staffActionRequest = 4;
        ((ByteFlags*)((char*)inner + 0x3f4))->b08 = 0;
    }
}

int fn_8029B6BC(int obj, int state)
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
        Sfx_PlayFromObject(obj, 0x40b);
        c = inner->curAnimId;
        if (c != 0x42 && c != 0x4c)
        {
            (*gCameraInterface)->setMode(
                0x42, 0, 1, 0, NULL, 0x3c, 0xfe);
        }
    }
    if (*(s8*)&((PlayerState*)state)->baddie.moveDone != 0)
    {
        *(int*)&((PlayerState*)state)->baddie.unk308 = (int)fn_802A514C;
        return -1;
    }
    return 0;
}

int Lightfoot_UpdateProximityInteractionState(int obj, int state)
{
    PlayerState* inner = ((GameObject*)obj)->extra;
    if (((PlayerState*)state)->baddie.targetObj != NULL)
    {
        if (*(u16*)((char*)*(int*)((char*)inner + 0x40c) + 0x22) <
            inner->unk3FE)
        {
            if (*(s8*)&((PlayerState*)state)->baddie.moveJustStartedB != 0 || *(s8*)&((PlayerState*)state)->baddie.
                moveDone != 0 ||
                ((PlayerState*)state)->baddie.controlMode == 0)
            {
                (*(void (*)(int, int, int))(*(int*)(*gPlayerInterface + 0x14)))(obj, state, 4);
            }
        }
        else if (*(s8*)&((PlayerState*)state)->baddie.moveJustStartedB != 0 || *(s8*)&((PlayerState*)state)->baddie.
            moveDone != 0)
        {
            (*(void (*)(int, int, int))(*(int*)(*gPlayerInterface + 0x14)))(obj, state, 0);
        }
    }
    return 0;
}

int fn_802A1114(int obj, int state)
{
    PlayerState* inner = ((GameObject*)obj)->extra;
    PlayerState* in0 = ((GameObject*)obj)->extra;
    int flag549;
    f32 fz;
    s16* tbl;
    int flags;
    int model;
    u8 ic;
    f32 buf1[3];
    f32 buf2[2];
    f32 pos[2];
    *(u32*)&in0->flags360 &= ~2LL;
    *(u32*)&in0->flags360 |= 0x2000LL;
    *(int*)((char*)state + 0x4) |= 0x100000;
    fz = lbl_803E7EA4;
    ((PlayerState*)state)->baddie.animSpeedA = fz;
    ((PlayerState*)state)->baddie.animSpeedB = fz;
    *(int*)((char*)state + 0x0) |= 0x200000;
    ((GameObject*)obj)->anim.velocityX = fz;
    ((GameObject*)obj)->anim.velocityZ = fz;
    *(int*)((char*)state + 0x4) |= 0x8000000;
    ((GameObject*)obj)->anim.velocityY = fz;
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
        ObjHits_MarkObjectPositionDirty(obj);
    }
    flag549 = inner->unk549;
    if (flag549 != 0)
    {
        ((PlayerState*)state)->baddie.moveSpeed = lbl_803E7EF8;
    }
    else
    {
        ((PlayerState*)state)->baddie.moveSpeed = lbl_803E8008;
    }
    fn_802A13F4(obj, state);
    if (*(s8*)&((PlayerState*)state)->baddie.moveJustStartedA != 0)
    {
        f32 zero = lbl_803E7EA4;
        ((PlayerState*)state)->baddie.animSpeedA = zero;
        ((PlayerState*)state)->baddie.animSpeedB = zero;
        inner->targetYaw =
            (s16)getAngle(*(f32*)((int)inner + 0x56c), inner->groundNormalZ);
        inner->yaw = inner->targetYaw;
        ((GameObject*)obj)->anim.localPosX = inner->unk58C;
        ((GameObject*)obj)->anim.localPosZ = inner->unk594;
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
            extern s16 fn_802A71E0(int obj, int a, int b, int* p6, int* p7, f32 e, f32 f, int n, int flags);
            inner->animEventState =
                fn_802A71E0(obj, tbl[0], tbl[1], (int*)((char*)inner + 0x598),
                            (int*)((char*)inner + 0x56c), lbl_803E7EA4, *(f32*)&lbl_803E7EA4, 2, (u8)flags);
        }
        model = (int)Player_GetActiveModel(obj);
        ObjModel_SampleJointTransform(model, 0, 0, lbl_803E7EE0,
                                      ((GameObject*)obj)->anim.rootMotionScale, buf1, buf2);
        fz = lbl_803E7EA4;
        inner->moveOffsetX = fz;
        inner->moveOffsetY = buf1[1];
        inner->moveOffsetZ = fz;
        pos[0] = inner->spanTopY;
        pos[1] = inner->spanBottomY;
        ic = inner->curAnimId;
        if (ic != 0x48 && ic != 0x47)
        {
            (*gCameraInterface)->setMode(
                0x4b, 1, 1, 8, pos, 0, 0);
        }
    }
    else
    {
        if (((GameObject*)obj)->anim.currentMoveProgress >= lbl_803E7EE0)
        {
            *(int*)&((PlayerState*)state)->baddie.unk308 = (int)fn_8029FFD0;
            return 0x14;
        }
    }
    ObjAnim_WriteStateWord((ObjAnimComponent*)obj, OBJANIM_STATE_INDEX_CURRENT,
                           OBJANIM_STATE_WORD_EVENT_STATE, inner->animEventState);
    (*gCameraInterface)->overridePos(
        ((GameObject*)obj)->anim.localPosX,
        inner->moveOffsetY * ((GameObject*)obj)->anim.currentMoveProgress + ((GameObject*)obj)->anim.localPosY,
        ((GameObject*)obj)->anim.localPosZ);
    fn_802AB5A4(obj, (int)inner, 5);
    return 0;
}

int fn_802A71E0(int obj, int a, int b, int* p6, int* p7, f32 e, f32 f, int n, int flags)
{
    int model;
    int uf;
    u8 mf;
    int sel;
    int blend;
    f32 v1, v2, t;
    f32 buf1[3];
    f32 buf2[2];
    model = (int)Player_GetActiveModel(obj);
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
        ObjAnim_SetCurrentMove(obj, a, lbl_803E7EA4, mf);
        ((int (*)(int, f32, f32, void*))ObjAnim_AdvanceCurrentMove)(obj, f, lbl_803E7EA4, NULL);
        ObjModel_SampleJointTransform(model, 0, 0, e, ((GameObject*)obj)->anim.rootMotionScale, buf1, buf2);
    }
    else
    {
        Object_ObjAnimSetMove(lbl_803E7EA4, obj, a, mf);
        Object_ObjAnimAdvanceMove(f, lbl_803E7EA4, obj, NULL);
        ObjModel_SampleJointTransform(model, 1, 0, e, ((GameObject*)obj)->anim.rootMotionScale, buf1, buf2);
    }
    v1 = *(f32*)((char*)buf1 + ((u8)n << 2));
    if (v1 < 0.0f)
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
    v2 = *(f32*)((char*)buf1 + ((u8)n << 2));
    if (v2 < 0.0f)
    {
        v2 = -v2;
    }
    t = *(f32*)((char*)p7 + 0xc) +
    (*(f32*)((char*)p6 + 0x0) * *(f32*)((char*)p7 + 0x0) +
        *(f32*)((char*)p6 + 0x8) * *(f32*)((char*)p7 + 0x8));
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

int fn_8029F6E4(int obj, int state)
{
    PlayerState* inner = ((GameObject*)obj)->extra;
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
    *(u32*)&((PlayerState*)inner)->flags360 &= ~2LL;
    ObjHits_DisableObject(obj);
    sub = *(void**)((char*)inner + 0x7f0);
    if (sub == NULL)
    {
        ((GameObject*)obj)->anim.activeMove = -1;
        return 0;
    }
    if (*(s8*)&((PlayerState*)state)->baddie.moveJustStartedA != 0)
    {
        if (*(void**)((char*)inner + 0x6e8) == NULL)
        {
            inner->moveSequence = (int)lbl_803332B0;
        }
        ObjAnim_SetCurrentMove(obj, *(s16*)(inner->moveSequence + 0x2),
                               lbl_803E7EA4, 0);
        ((int (*)(int, f32, f32, void*))ObjAnim_AdvanceCurrentMove)(obj, lbl_803E7EA4, *(f32*)&lbl_803E7EA4, NULL);
    }
    if ((inner->moveSequenceFlags & 0x4) != 0)
    {
        ((void (*)(ObjAnimComponent*, f32))ObjAnim_SetMoveProgress)((ObjAnimComponent*)obj, *(f32*)((char*)sub + 0x98));
        ((PlayerState*)state)->baddie.moveSpeed = lbl_803E7EA4;
    }
    else
    {
        ret = (*(f32 (*)(int, f32*))(*(int*)((char*)*(int*)*(int*)((char*)sub + 0x68) + 0x44)))(
            (int)sub, &out);
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
        (*(void (*)(int, f32*, int*))(*(int*)((char*)*(int*)*(int*)((char*)sub + 0x68) + 0x40)))(
            (int)sub, &a, &b);
        blend = (int)(lbl_803E7FAC * a);
        if (blend < 0)
        {
            blend = -blend;
        }
        if (b != 0)
        {
            Object_ObjAnimSetSecondaryBlendMove((ObjAnimComponent*)obj,
                                                *(s16*)(inner->moveSequence + 0xa), blend);
        }
        else
        {
            Object_ObjAnimSetSecondaryBlendMove((ObjAnimComponent*)obj,
                                                *(s16*)(inner->moveSequence + 0x8), blend);
        }
    }
    else if ((inner->moveSequenceFlags & 0x8) != 0)
    {
        (*(void (*)(int, f32*, int*))(*(int*)((char*)*(int*)*(int*)((char*)sub + 0x68) + 0x40)))(
            (int)sub, &c, &d);
        *(u32*)&((PlayerState*)inner)->flags360 |= 0x2000000LL;
        inner->headYaw = (s16)d;
        inner->bodyLeanAngle = (s16)c;
        inner->bodyLeanHalf = inner->bodyLeanAngle / 2;
        inner->headPitch = inner->bodyLeanAngle / 2;
    }
    if ((inner->moveSequenceFlags & 0x1) != 0)
    {
        ObjAnim_WriteStateWord((ObjAnimComponent*)obj, OBJANIM_STATE_INDEX_CURRENT,
                               OBJANIM_STATE_WORD_PREV_EVENT_STATE, 0);
        ObjAnim_WriteStateWord((ObjAnimComponent*)obj, OBJANIM_STATE_INDEX_ACTIVE,
                               OBJANIM_STATE_WORD_PREV_EVENT_STATE, 0);
    }
    if ((*(int (*)(int, int))(*(int*)((char*)*(int*)*(int*)((char*)sub + 0x68) + 0x2c)))(
        (int)sub, obj) != 0)
    {
        *(int*)&((PlayerState*)state)->baddie.unk308 = 0;
        return 0x1a;
    }
    return 0;
}

void fn_802A93F4(int obj, int p2, int p3)
{
    PlayerState* inner = ((GameObject*)obj)->extra;
    f32 dist;
    void* found;
    s16* vec;
    ObjTextureRuntimeSlot* tex;
    dist = lbl_803E80CC;
    ((GameObject*)obj)->anim.rootMotionScale = lbl_803E7EE0;
    viewFinderSetZoom(Camera_GetFovY());
    ((GameObject*)obj)->objectFlags &= ~0x1000;
    ((GameObject*)obj)->anim.alpha = 0xff;
    ((ByteFlags*)((char*)inner + 0x3f2))->b80 = 0;
    if (((ByteFlags*)((char*)inner + 0x3f2))->b40)
    {
        inner->targetSuppressTimer = lbl_803E7FBC;
    }
    ((ByteFlags*)((char*)inner + 0x3f2))->b40 = 0;
    ((ByteFlags*)((char*)inner + 0x3f2))->b20 = 0;
    ((ByteFlags*)((char*)inner + 0x3f4))->b80 = 0;
    ObjHits_EnableObject(obj);
    ((GameObject*)obj)->anim.velocityY = lbl_803E7EA4;
    if ((*(s16*)((char*)p3 + 0x6e) & 1) != 0)
    {
        fn_802AB5A4(obj, (int)inner, 7);
    }
    ObjModelChain_SetEnabled((ObjModelChain*)gPlayerModelChain, 1);
    inner->unk8C4 = 2;
    if (gPlayerChildObject != NULL)
    {
        found = (void*)ObjGroup_FindNearestObject(0x20, obj, &dist);
        if (found != NULL)
        {
            (*(void (*)(void*))(*(int*)((char*)*(int*)*(int*)((char*)found + 0x68) + 0x24)))(found);
        }
        ObjLink_DetachChild(obj, (int)gPlayerChildObject);
        Obj_FreeObject((int)gPlayerChildObject);
        gPlayerChildObject = NULL;
    }
    *(u32*)&((PlayerState*)inner)->flags360 |= 0x800000LL;
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
    *(u32*)&((PlayerState*)inner)->flags360 |= 0x800000LL;
    ObjHits_SyncObjectPositionIfDirty(obj);
    inner->waterDepth = lbl_803E7EA4;
    inner->waterSurfaceY = lbl_803E80D0;
    inner->idleDelayTimer = lbl_803E7FA4;
    inner->baddie.physicsActive = 1;
    *(int*)((char*)inner + 0x4) &= ~0x100000;
    *(int*)((char*)inner + 0x4) |= 0x8000000;
    if (*(s8*)(*(int*)((char*)*(int*)&((GameObject*)obj)->extra + 0x35c)) <= 0)
    {
        (*(void (*)(int, int, int))(*(int*)(*gPlayerInterface + 0x14)))(obj, (int)inner, 3);
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
    tex = objFindTexture((void*)obj, 1, 0);
    tex->offsetS = 0;
    tex->offsetT = 0;
    tex = objFindTexture((void*)obj, 0, 0);
    tex->offsetS = 0;
    tex->offsetT = 0;
}

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
        vec = (void*)objModelGetVecFn_800395d8(p1, 0);
        if (vec != NULL)
        {
            v = *(s16*)((char*)vec + 0x2);
            if (v > 0)
            {
                *(s16*)((char*)vec + 0x2) = v - (int)(lbl_803E8050 * timeDelta);
                if (*(s16*)((char*)vec + 0x2) < 0)
                {
                    *(s16*)((char*)vec + 0x2) = 0;
                }
            }
            else
            {
                *(s16*)((char*)vec + 0x2) = v + (int)(lbl_803E8050 * timeDelta);
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
    (*(void (*)(int, f32*, f32*, f32*))(*(int*)((char*)*(int*)*(int*)((char*)p3 + 0x68) + 0x28)))(
        p3, &a, &b, &c);
    ((GameObject*)p1)->anim.localPosX = a;
    ((GameObject*)p1)->anim.localPosY = b;
    ((GameObject*)p1)->anim.localPosZ = c;
    inner = *(int*)&((GameObject*)p1)->extra;
    if (((PlayerState*)inner)->baddie.controlMode != 0x18 && (((GameObject*)p1)->objectFlags & 0x1000) == 0)
    {
        flag = 1;
        (*(void (*)(int, int, int*))(*(int*)((char*)*(int*)*(int*)((char*)p3 + 0x68) + 0x54)))(
            p3, 2, &d);
        angle = (s16)(((PlayerState*)p2)->targetYaw - (u16)d);
        if (angle > 0x8000)
        {
            angle = angle - 0xFFFF;
        }
        if (angle < -0x8000)
        {
            angle = angle + 0xFFFF;
        }
        (*(void (*)(int, int, int*))(*(int*)((char*)*(int*)*(int*)((char*)p3 + 0x68) + 0x54)))(
            p3, 3, &e);
        clamped = (angle < (s16) - e) ? (s16) - e : ((angle > (s16)e) ? (s16)e : angle);
        ((PlayerState*)p2)->targetYaw = (s16)d + clamped;
        (*(void (*)(int, int, int*))(*(int*)((char*)*(int*)*(int*)((char*)p3 + 0x68) + 0x54)))(
            p3, 4, &flag);
        if (flag != 0)
        {
            ((GameObject*)p1)->anim.rotY = *(s16*)((char*)p3 + 0x2);
            ((GameObject*)p1)->anim.rotZ = *(s16*)((char*)p3 + 0x4);
        }
    }
    else
    {
        ((GameObject*)p1)->anim.rotY = *(s16*)((char*)p3 + 0x2);
        ((GameObject*)p1)->anim.rotZ = *(s16*)((char*)p3 + 0x4);
        ((PlayerState*)p2)->targetYaw = *(s16*)((char*)p3 + 0x0);
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
    fn_802AB5A4(p1, p2, 7);
}

int fn_80299E44(int obj, int state, f32 fv)
{
    PlayerState* inner = ((GameObject*)obj)->extra;
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
        Sfx_KeepAliveLoopedObjectSound(obj, 0x382);
        timer = inner->stateTimer - timeDelta;
        inner->stateTimer = timer;
        if (timer <= lbl_803E7EA4)
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
        pfx.mode = 0;
        (*gPartfxInterface)->spawnObject(
            (void*)gPlayerPathObject, 0x7f5, &pfx, 0x200001, -1, NULL);
        pfx.mode = 1;
        (*gPartfxInterface)->spawnObject(
            (void*)gPlayerPathObject, 0x7f5, &pfx, 0x200001, -1, NULL);
        if ((inner->buttonsHeld & gPlayerHeldButtonMask) == 0 ||
            *(s16*)((char*)*(int*)((char*)*(int*)&((GameObject*)obj)->extra + 0x35c) + 0x4) == 0 ||
            getCurSeqNo() != 0)
        {
            int i;
            void** p = gPlayerSpawnedObjects;
            lbl_803DE42C = 0;
            for (i = 0; i < 7; i++)
            {
                if (*p != NULL)
                {
                    Obj_FreeObject((int)*p);
                    *p = NULL;
                }
                p++;
            }
            if (gPlayerResource != NULL)
            {
                Resource_Release(gPlayerResource);
                gPlayerResource = NULL;
            }
        }
    }
    if (inner->deferredItemCommand != -1 || (*(int*)&((PlayerState*)state)->baddie.unk31C & 0x800) != 0)
    {
        int r = fn_8029ABD8(obj, state, fv);
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
                obj,
                gPlayerMoveSlotTable[*(s16*)((inner->moveSlots + 2) + (u32)inner->moveSlotIndex * 0xb0)],
                lbl_803E7EA4, 0);
            *(int*)&((PlayerState*)state)->baddie.unk308 = (int)fn_8029BC08;
            return 0x27;
        }
        if (sel == 3)
        {
            inner->moveSlotIndex = 9;
            ObjAnim_SetCurrentMove(
                obj,
                gPlayerMoveSlotTable[*(s16*)((inner->moveSlots + 2) + (u32)inner->moveSlotIndex * 0xb0)],
                lbl_803E7EA4, 0);
            *(int*)&((PlayerState*)state)->baddie.unk308 = (int)fn_8029BC08;
            return 0x27;
        }
        if (sel == 4)
        {
            inner->moveSlotIndex = 7;
            ObjAnim_SetCurrentMove(
                obj,
                gPlayerMoveSlotTable[*(s16*)((inner->moveSlots + 2) + (u32)inner->moveSlotIndex * 0xb0)],
                lbl_803E7EA4, 0);
            *(int*)&((PlayerState*)state)->baddie.unk308 = (int)fn_8029BC08;
            return 0x27;
        }
        if (sel == 2)
        {
            inner->moveSlotIndex = 6;
            ObjAnim_SetCurrentMove(
                obj,
                gPlayerMoveSlotTable[*(s16*)((inner->moveSlots + 2) + (u32)inner->moveSlotIndex * 0xb0)],
                lbl_803E7EA4, 0);
            *(int*)&((PlayerState*)state)->baddie.unk308 = (int)fn_8029BC08;
            return 0x27;
        }
        inner->moveSlotIndex = 5;
        ObjAnim_SetCurrentMove(
            obj,
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
                obj,
                gPlayerMoveSlotTable[*(s16*)((inner->moveSlots + 2) + (u32)inner->moveSlotIndex * 0xb0)],
                lbl_803E7EA4, 0);
            *(int*)&((PlayerState*)state)->baddie.unk308 = (int)fn_8029BC08;
            return 0x27;
        }
        if (*(u8*)((char*)state + 0x34b) == 3 && ((PlayerState*)state)->baddie.inputMagnitude > lbl_803E7EAC)
        {
            inner->moveSlotIndex = 4;
            ObjAnim_SetCurrentMove(
                obj,
                gPlayerMoveSlotTable[*(s16*)((inner->moveSlots + 2) + (u32)inner->moveSlotIndex * 0xb0)],
                lbl_803E7EA4, 0);
            *(int*)&((PlayerState*)state)->baddie.unk308 = (int)fn_8029BC08;
            return 0x27;
        }
        if (*(u8*)((char*)state + 0x34b) == 1 && ((PlayerState*)state)->baddie.inputMagnitude > lbl_803E7EAC)
        {
            inner->moveSlotIndex = 3;
            ObjAnim_SetCurrentMove(
                obj,
                gPlayerMoveSlotTable[*(s16*)((inner->moveSlots + 2) + (u32)inner->moveSlotIndex * 0xb0)],
                lbl_803E7EA4, 0);
            *(int*)&((PlayerState*)state)->baddie.unk308 = (int)fn_8029BC08;
            return 0x27;
        }
        if (*(u8*)((char*)state + 0x34b) == 4 && ((PlayerState*)state)->baddie.inputMagnitude > lbl_803E7EAC)
        {
            inner->moveSlotIndex = 2;
            ObjAnim_SetCurrentMove(
                obj,
                gPlayerMoveSlotTable[*(s16*)((inner->moveSlots + 2) + (u32)inner->moveSlotIndex * 0xb0)],
                lbl_803E7EA4, 0);
            *(int*)&((PlayerState*)state)->baddie.unk308 = (int)fn_8029BC08;
            return 0x27;
        }
        inner->moveSlotIndex = 0;
        ObjAnim_SetCurrentMove(
            obj,
            gPlayerMoveSlotTable[*(s16*)((inner->moveSlots + 2) + (u32)inner->moveSlotIndex * 0xb0)],
            lbl_803E7EA4, 0);
        *(int*)&((PlayerState*)state)->baddie.unk308 = (int)fn_8029BC08;
        return 0x27;
    }
    return 0;
}

int fn_80299BB0(int obj, int p2)
{
    PlayerState* inner = ((GameObject*)obj)->extra;
    u8 state30 = 0x1a;
    u8 state29 = 0x1a;
    void* near;
    f32 dist;
    f32 dir[3];
    f32 cosv;
    f32 sinv;
    f32 fz;
    dist = lbl_803E7F5C;
    near = (void*)ObjGroup_FindNearestObject(0x3e, obj, &dist);
    ((ByteFlags*)((char*)inner + 0x3f4))->b20 = 1;
    fz = lbl_803E7EA4;
    inner->buttonHoldTimer = fz;
    if (near != 0)
    {
        dir[0] = *(f32*)((char*)near + 0xc) - ((GameObject*)obj)->anim.localPosX;
        dir[1] = *(f32*)((char*)near + 0x10) - ((GameObject*)obj)->anim.localPosY;
        dir[2] = *(f32*)((char*)near + 0x14) - ((GameObject*)obj)->anim.localPosZ;
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
        ObjAnim_SetCurrentMove(
            obj, gPlayerMoveSlotTable[((s16*)((char*)inner->moveSlots + 2))[(u8)state30 * 88]],
            lbl_803E7EA4, 0);
        inner->moveSlotIndex = state30;
        *(int*)&((PlayerState*)p2)->baddie.unk308 = (int)fn_8029BC08;
        return 0x27;
    }
    ObjAnim_SetCurrentMove(
        obj, gPlayerMoveSlotTable[((s16*)((char*)inner->moveSlots + 2))[(u8)state29 * 88]],
        lbl_803E7EA4, 0);
    inner->moveSlotIndex = state29;
    *(int*)&((PlayerState*)p2)->baddie.unk308 = (int)fn_8029BC08;
    return 0x27;
}

#pragma dont_inline on
int fn_802A9B1C(int obj, int p2, int p3)
{
    PlayerState* inner = ((GameObject*)obj)->extra;
    u8 c;
    int v;
    if ((c = inner->curAnimId) == 0x48 || c == 0x47 || c == 0x44 ||
        *(void**)((char*)inner + 0x7f8) != NULL ||
        ((ByteFlags*)((char*)inner + 0x3f0))->b20 ||
        ((ByteFlags*)((char*)inner + 0x3f0))->b04 ||
        ((ByteFlags*)((char*)inner + 0x3f0))->b08 ||
        ((ByteFlags*)((char*)inner + 0x3f4))->b40 == 0)
    {
        return 0;
    }
    if (p3 == 0x2d)
    {
        if (*(s16*)((char*)inner->playerStatus + 4) < 2) return 0;
    }
    else
    {
        if (*(s16*)((char*)inner->playerStatus + 4) < 1) return 0;
    }
    if ((v = ((PlayerState*)p2)->baddie.controlMode) == 1 || v == 2 || v == 0x2a || v == 0x2c || (u16)(v - 0x2e) <= 1 ||
        v == 0x2d)
    {
        return 1;
    }
    return 0;
}
#pragma dont_inline reset

void fn_8029FFD0(int obj, int p2)
{
    PlayerState* inner = ((GameObject*)obj)->extra;
    s16 v = ((PlayerState*)p2)->baddie.controlMode;
    if (v != 0x15 && v != 0x14 && v != 0x12 && v != 0x13 && v != 0xe && v != 0xf && v != 0x10)
    {
        u8 c = inner->curAnimId;
        if (c != 0x48 && c != 0x47 && c != 0x42 && getCurSeqNo() == 0)
        {
            (*gCameraInterface)->setMode(
                0x42, 0, 1, 0, NULL, 0, 0xff);
            inner->curAnimId = 0x42;
        }
        *(u32*)&((PlayerState*)inner)->flags360 |= 0x800000LL;
        ObjHits_SyncObjectPositionIfDirty(obj);
    }
    ((GameObject*)obj)->anim.activeMove = -1;
}

int fn_802A00E0(int obj, int state)
{
    PlayerState* inner = ((GameObject*)obj)->extra;
    f32 fz;
    f32 obj98;
    f32 t1, t2, t3;
    f32 outY;
    fn_802A13F4(obj, state);
    if (*(s8*)&((PlayerState*)state)->baddie.moveJustStartedA != 0)
    {
        u8 ic;
        int model;
        f32 buf2[2];
        f32 buf1[3];
        ObjHits_MarkObjectPositionDirty(obj);
        ic = inner->curAnimId;
        if (ic != 0x48 && ic != 0x47)
        {
            (*gCameraInterface)->setMode(
                0x42, 0, 1, 0, NULL, 0x3c, 0xff);
        }
        ObjAnim_SetCurrentMove(obj, lbl_80332F48[0x13], lbl_803E7EA4, 1);
        Object_ObjAnimSetSecondaryBlendMove((ObjAnimComponent*)obj, lbl_80332F48[0x14], 0);
        ((PlayerState*)state)->baddie.moveSpeed = lbl_803E7F34;
        model = (int)Player_GetActiveModel(obj);
        ObjModel_SampleJointTransform(model, 0, 0, lbl_803E7EE0,
                                      ((GameObject*)obj)->anim.rootMotionScale, buf1, buf2);
        inner->moveOffsetX = inner->groundNormalX * buf1[2];
        inner->moveOffsetZ = inner->groundNormalZ * buf1[2];
        ((GameObject*)obj)->anim.localPosY = inner->spanBottomY;
        *(s16*)((char*)state + 0x278) = 0x15;
        inner->stateHandler = (int)fn_8029FFD0;
    }
    {
        int ex = *(int*)&((GameObject*)obj)->extra;
        *(u32*)((char*)ex + 0x360) &= ~2LL;
        *(u32*)((char*)ex + 0x360) |= 0x2000LL;
    }
    *(int*)((char*)state + 4) |= 0x100000;
    fz = lbl_803E7EA4;
    ((PlayerState*)state)->baddie.animSpeedA = fz;
    ((PlayerState*)state)->baddie.animSpeedB = fz;
    *(int*)((char*)state + 0) |= 0x200000;
    ((GameObject*)obj)->anim.velocityX = fz;
    ((GameObject*)obj)->anim.velocityZ = fz;
    *(int*)((char*)state + 4) |= 0x8000000;
    ((GameObject*)obj)->anim.velocityY = fz;
    ObjAnim_WriteStateWord((ObjAnimComponent*)obj, OBJANIM_STATE_INDEX_CURRENT,
                           OBJANIM_STATE_WORD_EVENT_STATE, inner->animEventState);
    if ((*(int*)&((PlayerState*)state)->baddie.eventFlags & 0x200) != 0)
    {
        doRumble(lbl_803E7F10);
    }
    obj98 = ((GameObject*)obj)->anim.currentMoveProgress;
    if (obj98 > lbl_803E7F68)
    {
        ((GameObject*)obj)->anim.worldPosX = inner->savedPosX;
        ((GameObject*)obj)->anim.worldPosZ = inner->savedPosZ;
        if (*(void**)&((GameObject*)obj)->anim.parent != NULL)
        {
            ((GameObject*)obj)->anim.worldPosX = ((GameObject*)obj)->anim.worldPosX + playerMapOffsetX;
            ((GameObject*)obj)->anim.worldPosZ = ((GameObject*)obj)->anim.worldPosZ + playerMapOffsetZ;
        }
        Obj_TransformWorldPointToLocal(((GameObject*)obj)->anim.worldPosX, lbl_803E7EA4,
                                       ((GameObject*)obj)->anim.worldPosZ, &((GameObject*)obj)->anim.localPosX, &outY,
                                       &((GameObject*)obj)->anim.localPosZ, *(int*)&((GameObject*)obj)->anim.parent);
        fn_802AB5A4(obj, (int)inner, 5);
        ObjAnim_SetCurrentMove(obj,
                               *(s16*)inner->moveAnimTable,
                               lbl_803E7EA4, 1);
        *(u32*)&((PlayerState*)inner)->flags360 |= 0x800000LL;
        *(int*)&((PlayerState*)state)->baddie.unk308 = (int)fn_802A514C;
        return -1;
    }
    t1 = inner->moveOffsetX * obj98 + ((GameObject*)obj)->anim.localPosX;
    t2 = ((GameObject*)obj)->anim.localPosY -
        inner->moveOffsetY * (lbl_803E7EE0 - obj98);
    t3 = inner->moveOffsetZ * obj98 + ((GameObject*)obj)->anim.localPosZ;
    (*gCameraInterface)->overridePos(t1, t2, t3);
    fn_802AB5A4(obj, (int)inner, 5);
    return 0;
}

int fn_802A03BC(int obj, int state)
{
    PlayerState* inner = ((GameObject*)obj)->extra;
    f32 fz;
    f32 obj98;
    f32 t1, t2, t3;
    f32 outY;
    fn_802A13F4(obj, state);
    if (*(s8*)&((PlayerState*)state)->baddie.moveJustStartedA != 0)
    {
        u8 ic;
        int model;
        f32 buf2[2];
        f32 buf1[3];
        ObjHits_MarkObjectPositionDirty(obj);
        ic = inner->curAnimId;
        if (ic != 0x48 && ic != 0x47)
        {
            (*gCameraInterface)->setMode(
                0x42, 0, 1, 0, NULL, 0x3c, 0xff);
        }
        ObjAnim_SetCurrentMove(obj, lbl_80332F48[0x11], lbl_803E7EA4, 1);
        Object_ObjAnimSetSecondaryBlendMove((ObjAnimComponent*)obj, lbl_80332F48[0x12], 0);
        ((PlayerState*)state)->baddie.moveSpeed = lbl_803E7F84;
        model = (int)Player_GetActiveModel(obj);
        ObjModel_SampleJointTransform(model, 0, 0, lbl_803E7EE0,
                                      ((GameObject*)obj)->anim.rootMotionScale, buf1, buf2);
        inner->moveOffsetX = inner->groundNormalX * buf1[2];
        inner->moveOffsetZ = inner->groundNormalZ * buf1[2];
        ((GameObject*)obj)->anim.localPosY = inner->spanTopY;
        *(s16*)((char*)state + 0x278) = 0x14;
        inner->stateHandler = (int)fn_8029FFD0;
    }
    {
        int ex = *(int*)&((GameObject*)obj)->extra;
        *(u32*)((char*)ex + 0x360) &= ~2LL;
        *(u32*)((char*)ex + 0x360) |= 0x2000LL;
    }
    *(int*)((char*)state + 4) |= 0x100000;
    fz = lbl_803E7EA4;
    ((PlayerState*)state)->baddie.animSpeedA = fz;
    ((PlayerState*)state)->baddie.animSpeedB = fz;
    *(int*)((char*)state + 0) |= 0x200000;
    ((GameObject*)obj)->anim.velocityX = fz;
    ((GameObject*)obj)->anim.velocityZ = fz;
    *(int*)((char*)state + 4) |= 0x8000000;
    ((GameObject*)obj)->anim.velocityY = fz;
    ObjAnim_WriteStateWord((ObjAnimComponent*)obj, OBJANIM_STATE_INDEX_CURRENT,
                           OBJANIM_STATE_WORD_EVENT_STATE, inner->animEventState);
    obj98 = ((GameObject*)obj)->anim.currentMoveProgress;
    if (obj98 > lbl_803E7F68)
    {
        ((GameObject*)obj)->anim.worldPosX = inner->savedPosX;
        ((GameObject*)obj)->anim.worldPosZ = inner->savedPosZ;
        if (*(void**)&((GameObject*)obj)->anim.parent != NULL)
        {
            ((GameObject*)obj)->anim.worldPosX = ((GameObject*)obj)->anim.worldPosX + playerMapOffsetX;
            ((GameObject*)obj)->anim.worldPosZ = ((GameObject*)obj)->anim.worldPosZ + playerMapOffsetZ;
        }
        Obj_TransformWorldPointToLocal(((GameObject*)obj)->anim.worldPosX, lbl_803E7EA4,
                                       ((GameObject*)obj)->anim.worldPosZ, &((GameObject*)obj)->anim.localPosX, &outY,
                                       &((GameObject*)obj)->anim.localPosZ, *(int*)&((GameObject*)obj)->anim.parent);
        fn_802AB5A4(obj, (int)inner, 5);
        ObjAnim_SetCurrentMove(obj,
                               *(s16*)inner->moveAnimTable,
                               lbl_803E7EA4, 1);
        *(u32*)&((PlayerState*)inner)->flags360 |= 0x800000LL;
        *(int*)&((PlayerState*)state)->baddie.unk308 = (int)fn_802A514C;
        return -1;
    }
    t1 = inner->moveOffsetX * obj98 + ((GameObject*)obj)->anim.localPosX;
    t2 = ((GameObject*)obj)->anim.localPosY -
        inner->moveOffsetY * (lbl_803E7EE0 - obj98);
    t3 = inner->moveOffsetZ * obj98 + ((GameObject*)obj)->anim.localPosZ;
    (*gCameraInterface)->overridePos(t1, t2, t3);
    fn_802AB5A4(obj, (int)inner, 5);
    return 0;
}

int objAnimFn_80296328(int obj)
{
    PlayerState* inner = ((GameObject*)obj)->extra;
    if (((((GameObject*)obj)->objectFlags & 0x1000) != 0 &&
        ((ByteFlags*)((char*)inner + 0x3f2))->b80 == 0) ||
        ((ByteFlags*)((char*)inner + 0x3f0))->b04 ||
        ((ByteFlags*)((char*)inner + 0x3f0))->b08 ||
        ((ByteFlags*)((char*)inner + 0x3f0))->b20 ||
        *(void**)((char*)inner + 0x7f8) != NULL ||
        ((ByteFlags*)((char*)inner + 0x3f0))->b02)
    {
        return 0;
    }
    if (inner->baddie.controlMode == 1 || inner->baddie.controlMode == 2 ||
        inner->baddie.controlMode == 0x26 ||
        (inner->baddie.controlMode == 0x18 &&
         (GameBit_Get(0x3e3) || *(s16*)((char*)inner->focusObject + 0x46) == 0x416)) ||
        inner->baddie.targetObj != NULL)
    {
        return 1;
    }
    return 0;
}

void fn_802AD204(int p1, int obj)
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

#pragma dont_inline on
void fn_802AB5A4(int obj, int p2, int flags)
{
    u8 f = (u8)flags;
    char* q = (char*)p2 + 4;
    if (f & 1)
    {
        curves_updateLocalPointTransforms(obj, (CurvesCollisionState*)q);
    }
    if (f & 2)
    {
        curves_preparePointCollisionFrame(obj, (CurvesCollisionState*)((char*)(int)p2 + 4));
        *(f32*)(q + 0x20) = ((GameObject*)obj)->anim.worldPosX;
        *(f32*)(q + 0x24) = lbl_803E80EC + ((GameObject*)obj)->anim.worldPosY;
        *(f32*)(q + 0x28) = ((GameObject*)obj)->anim.worldPosZ;
    }
    if (f & 4)
    {
        ((ObjHitsPriorityState*)((GameObject*)obj)->anim.hitReactState)->localPosX = ((GameObject*)obj)->anim.localPosX;
        ((ObjHitsPriorityState*)((GameObject*)obj)->anim.hitReactState)->localPosY = ((GameObject*)obj)->anim.localPosY;
        ((ObjHitsPriorityState*)((GameObject*)obj)->anim.hitReactState)->localPosZ = ((GameObject*)obj)->anim.localPosZ;
        ((ObjHitsPriorityState*)((GameObject*)obj)->anim.hitReactState)->worldPosX = ((GameObject*)obj)->anim.worldPosX;
        ((ObjHitsPriorityState*)((GameObject*)obj)->anim.hitReactState)->worldPosY = ((GameObject*)obj)->anim.worldPosY;
        ((ObjHitsPriorityState*)((GameObject*)obj)->anim.hitReactState)->worldPosZ = ((GameObject*)obj)->anim.worldPosZ;
    }
}
#pragma dont_inline reset

int fn_802A5048(int obj, int state, f32 fv)
{
    if (*(s8*)&((PlayerState*)state)->baddie.moveJustStartedA != 0)
    {
        ObjAnim_SetCurrentMove(obj, 0x8e, lbl_803E7EA4, 0);
        ((PlayerState*)state)->baddie.moveSpeed = lbl_803E8060;
    }
    (*(void (*)(int, int, f32, int))(*(int*)(*gPlayerInterface + 0x20)))(obj, state, fv, 3);
    if (*(s8*)&((PlayerState*)state)->baddie.moveDone != 0)
    {
        void** p;
        int i;
        lbl_803DE42C = 0;
        p = gPlayerSpawnedObjects;
        for (i = 0; i < 7; i++)
        {
            if (p[i] != NULL)
            {
                Obj_FreeObject((int)p[i]);
                p[i] = NULL;
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

int fn_8029D7F0(int obj, int state, f32 fv)
{
    ((PlayerState*)state)->baddie.unk34D = 3;
    if (*(s8*)&((PlayerState*)state)->baddie.moveJustStartedA != 0)
    {
        ObjAnim_SetCurrentMove(obj, 0x44c, lbl_803E7EA4, 0);
        ((PlayerState*)state)->baddie.moveSpeed = lbl_803E7FD4;
    }
    switch (((GameObject*)obj)->anim.currentMove)
    {
    case 0x44c:
        if (*(s8*)&((PlayerState*)state)->baddie.moveDone != 0)
        {
            ObjAnim_SetCurrentMove(obj, 0x44d, lbl_803E7EA4, 0);
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
    (*(void (*)(int, int, f32, int))(*(int*)(*gPlayerInterface + 0x20)))(obj, state, fv, 1);
    return 0;
}

#pragma dont_inline on
int fn_802A9A0C(int obj, int p2)
{
    PlayerState* inner = ((GameObject*)obj)->extra;
    int threshold;
    if (GameBit_Get(0xc55))
    {
        threshold = 0x14;
    }
    else
    {
        threshold = 0xa;
    }
    if (GameBit_Get(0x107) == 0 ||
        *(s16*)((char*)*(int*)((char*)*(int*)&((GameObject*)obj)->extra + 0x35c) + 4) < threshold ||
        inner->curAnimId == 0x44 ||
        *(void**)((char*)inner + 0x7f8) != NULL ||
        ((ByteFlags*)((char*)inner + 0x3f0))->b20 ||
        ((ByteFlags*)((char*)inner + 0x3f0))->b04 ||
        ((ByteFlags*)((char*)inner + 0x3f0))->b08 ||
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
#pragma dont_inline reset

#pragma dont_inline on
int fn_802A9C0C(int obj, int p2, int p3)
{
    PlayerState* inner = ((GameObject*)obj)->extra;
    u8 c;
    int v;
    if ((c = inner->curAnimId) == 0x48 || c == 0x47 || c == 0x44 ||
        *(void**)((char*)inner + 0x7f8) != NULL ||
        ((ByteFlags*)((char*)inner + 0x3f0))->b20 ||
        ((ByteFlags*)((char*)inner + 0x3f0))->b04 ||
        ((ByteFlags*)((char*)inner + 0x3f0))->b08 ||
        ((ByteFlags*)((char*)inner + 0x3f4))->b40 == 0)
    {
        return 0;
    }
    if (p3 == 0x2d)
    {
        if (*(s16*)((char*)inner->playerStatus + 4) < 2) return 0;
    }
    else
    {
        if (*(s16*)((char*)inner->playerStatus + 4) < 1) return 0;
    }
    if ((v = ((PlayerState*)p2)->baddie.controlMode) == 1 || v == 2 || (u16)(v - 0x24) <= 1 || (u16)(v - 0x2a) <= 2 ||
        (u16)(v - 0x2e) <= 1 || v == 0x2d)
    {
        return 1;
    }
    return 0;
}
#pragma dont_inline reset

void fn_8029C8C8(int obj, int p2)
{
    PlayerState* inner = ((GameObject*)obj)->extra;
    if (((PlayerState*)p2)->baddie.inputMagnitude < lbl_803E7F6C)
    {
        s16 h = ((GameObject*)obj)->anim.rotX;
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
        int i;
        inner->animState = -1;
        lbl_803DE42C = 0;
        for (i = 0; i < 7; i++)
        {
            if (gPlayerSpawnedObjects[i] != NULL)
            {
                Obj_FreeObject((int)gPlayerSpawnedObjects[i]);
                gPlayerSpawnedObjects[i] = NULL;
            }
        }
        if (gPlayerResource != NULL)
        {
            Resource_Release(gPlayerResource);
            gPlayerResource = NULL;
        }
    }
}

void fn_802B1B28(int obj, f32 fv)
{
    f32 x, y, z;
    f32 v;

    v = ((GameObject*)obj)->anim.velocityX;
    ((GameObject*)obj)->anim.velocityX =
        (v < lbl_803E801C) ? lbl_803E801C : ((v > lbl_803E7F10) ? lbl_803E7F10 : v);

    v = ((GameObject*)obj)->anim.velocityY;
    ((GameObject*)obj)->anim.velocityY =
        (v < lbl_803E811C) ? lbl_803E811C : ((v > lbl_803E80E4) ? lbl_803E80E4 : v);

    v = ((GameObject*)obj)->anim.velocityZ;
    ((GameObject*)obj)->anim.velocityZ =
        (v < lbl_803E801C) ? lbl_803E801C : ((v > lbl_803E7F10) ? lbl_803E7F10 : v);

    y = ((GameObject*)obj)->anim.velocityY * fv;
    if (y > lbl_803E7ED8)
    {
        y = lbl_803E7ED8;
    }
    x = ((GameObject*)obj)->anim.velocityX * fv;
    z = ((GameObject*)obj)->anim.velocityZ * fv;
    objMove(obj, x, y, z);
}

void Lightfoot_UpdateAttachedChild(int obj, int inner)
{
    int animState = *(int*)((char*)inner + 0x40c);
    int child;
    int setup;

    if (*(s16*)((char*)animState + 0x26) == *(s16*)((char*)animState + 0x28)) return;
    if (((GameObject*)obj)->anim.alpha == 0) return;

    child = *(int*)&((GameObject*)obj)->childObjs[0];
    if ((u32)child != 0)
    {
        ObjLink_DetachChild(obj, child);
        Obj_FreeObject(child);
    }
    if (Obj_IsLoadingLocked())
    {
        if (*(s16*)((char*)animState + 0x28) > 0)
        {
            setup = Obj_AllocObjectSetup(0x20, *(s16*)((char*)animState + 0x28));
            setup = Obj_SetupObject(setup, 4, ((GameObject*)obj)->anim.mapEventSlot, -1,
                                    *(int*)&((GameObject*)obj)->anim.parent);
            ObjLink_AttachChild(obj, setup, 0);
            *(s16*)((char*)animState + 0x26) = *(s16*)((char*)animState + 0x28);
        }
    }
    else
    {
        *(s16*)((char*)animState + 0x26) = 0;
    }
}

int Lightfoot_UpdateWanderSteering(int obj, int state, f32 fv)
{
    PlayerState* inner = ((GameObject*)obj)->extra;
    int sub = *(int*)((char*)inner + 0x40c);
    if (((PlayerState*)sub)->baddie.posX <= lbl_803E8180)
    {
        Sfx_PlayFromObject(obj, 0x4be);
        ((PlayerState*)sub)->baddie.posX = (f32)randomGetRange(0x78, 0xb4);
    }
    ((PlayerState*)state)->baddie.moveSpeed =
        lbl_803E8184 * (lbl_803E8188 -
            (f32)(u16) * (u16*)((char*)sub + 0x22) /
            (f32)(u16)
    inner->unk3FE
    )
    ;
    if (((PlayerState*)state)->baddie.moveSpeed < *(f32*)&lbl_803E818C)
    {
        ((PlayerState*)state)->baddie.moveSpeed = lbl_803E818C;
    }
    if (*(s8*)&((PlayerState*)state)->baddie.moveJustStartedA != 0 || *(s8*)&((PlayerState*)state)->baddie.moveDone !=
        0)
    {
        u8 r;
        if (*(u8*)((char*)sub + 0x2c) != 0)
        {
            *(u8*)((char*)sub + 0x2c) -= 1;
        }
        else
        {
            r = (*(u8 (*)(int, int, f32))(*(int*)(*gBaddieControlInterface + 0x18)))(
                obj, state, lbl_803E8190);
            if ((r & 1) == 0)
            {
                if (r & 4)
                {
                    ((GameObject*)obj)->anim.rotX += 0x7ff8;
                    *(u8*)((char*)sub + 0x2c) = 3;
                }
                else if (r & 2)
                {
                    ((GameObject*)obj)->anim.rotX -= 0x3ffc;
                    *(u8*)((char*)sub + 0x2c) = 3;
                }
                else if (r & 8)
                {
                    ((GameObject*)obj)->anim.rotX += 0x3ffc;
                    *(u8*)((char*)sub + 0x2c) = 3;
                }
            }
        }
        ObjAnim_SetCurrentMove(obj, 0x14, lbl_803E8180, 0);
    }
    if (*(u8*)((char*)sub + 0x2c) == 0)
    {
        {
            f32 t = (f32)(s32)((u16) * (u16*)((char*)sub + 0x20) - 0x7fff) * timeDelta;
            ((GameObject*)obj)->anim.rotX += (s16)(t * lbl_803E8194);
        }
    }
    (*(void (*)(int, int, f32, int))(*(int*)(*gPlayerInterface + 0x20)))(obj, state, fv, 1);
    return 0;
}

void Lightfoot_RecordCompletedChallengeTargetHit(int obj, int inner, int animState)
{
    int idx;

    if (*(u8*)((char*)animState + 0x2e) == 0) return;
    if ((*(u16*)((char*)inner + 0x400) & 2) == 0) return;

    idx = *(int*)&((GameObject*)obj)->anim.placementData;
    if (*(u32*)((char*)idx + 0x14) == 0x46A51 && GameBit_Get(0xc49) == 0)
    {
        GameBit_Set(0xc49, 1);
    }
    else if (*(u32*)((char*)idx + 0x14) == 0x46A55 && GameBit_Get(0xc4a) == 0)
    {
        GameBit_Set(0xc4a, 1);
    }
    else if (*(u32*)((char*)idx + 0x14) == 0x49928 && GameBit_Get(0xc4b) == 0)
    {
        GameBit_Set(0xc4b, 1);
    }
    *(u8*)((char*)animState + 0x2e) = 0;
}

void fn_802A96D8(void)
{
    int obj;
    s8 i;

    if (!Obj_IsLoadingLocked()) return;
    for (i = 0; i < 7; i++)
    {
        if (gPlayerSpawnedObjects[i] == NULL)
        {
            obj = Obj_AllocObjectSetup(0x24, 0x4ec);
            ObjPath_GetPointWorldPosition(gPlayerPathObject, 0, (char*)obj + 8,
                                          (char*)obj + 0xc, (char*)obj + 0x10, 0);
            *(u8*)((char*)obj + 4) = 2;
            *(u8*)((char*)obj + 5) = 1;
            *(u8*)((char*)obj + 6) = 0xff;
            *(u8*)((char*)obj + 7) = 0xff;
            *(s16*)((char*)obj + 0x1a) = (s16)(i * 3);
            *(s16*)((char*)obj + 0x1c) = 0;
            gPlayerSpawnedObjects[i] = (void*)Obj_SetupObject(obj, 5, -1, -1, 0);
        }
    }
}

void fn_802B4DE0(int obj)
{
    int off;
    int i;
    PlayerState* inner = ((GameObject*)obj)->extra;

    if ((u32)gPlayerEggObject != 0)
    {
        Obj_FreeObject(gPlayerEggObject);
        ObjLink_DetachChild(obj, gPlayerEggObject);
        gPlayerEggObject = 0;
    }
    if (gPlayerPathObject != NULL)
    {
        Obj_FreeObject((int)gPlayerPathObject);
        ObjLink_DetachChild(obj, gPlayerPathObject);
        gPlayerPathObject = NULL;
    }
    if ((u32)gPlayerStaffObject != 0)
    {
        gPlayerStaffObject = 0;
    }
    for (i = 0, off = 0; i < inner->moveSlotCount; i++)
    {
        int e = *(int*)(inner->moveSlots + off + 0x64);
        if ((u32)e != 0) mm_free((void*)e);
        off += 0xb0;
    }
    ObjGroup_RemoveObject(obj, 0);
    ObjGroup_RemoveObject(obj, 0x25);
    ObjModelChain_Free((ObjModelChain*)gPlayerModelChain);
}

void fn_802A13F4(int obj, int p2)
{
    PlayerState* inner = ((GameObject*)obj)->extra;
    int cell;
    int t;
    int sfx;

    if (*(int*)&((PlayerState*)p2)->baddie.eventFlags & 1)
    {
        cell = coordsToMapCell(((GameObject*)obj)->anim.localPosX, ((GameObject*)obj)->anim.localPosZ);
        if (cell == 0x12)
        {
            Sfx_PlayFromObject(obj, SFXthorntail_snort1);
        }
        else
        {
            Sfx_PlayFromObject(obj, SFXdn_rexhurt13);
        }
    }
    if (gPlayerSfxTimerB > 0)
    {
        t = gPlayerSfxTimerB - framesThisStep;
        gPlayerSfxTimerB = t;
        if (t < 0) gPlayerSfxTimerB = 0;
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
                Sfx_PlayFromObject(obj, (u16)sfx);
                gPlayerSfxTimerB = 0x3c;
            }
        }
    }
}

#pragma dont_inline on
int fn_802A98FC(int obj, int p2)
{
    PlayerState* inner = ((GameObject*)obj)->extra;
    s16 sel = ((PlayerState*)p2)->baddie.controlMode;

    if (sel == 1 || sel == 2)
    {
        void* slot = inner->cameraTargetObject;
        u8 af;
        u8 c;
        if (slot == NULL || *(s16*)((char*)slot + 0x46) != 0x414 ||
            ((af = *(u8*)((char*)slot + 0xaf)) & 4) == 0 || (af & 0x18) != 0)
        {
            return 0;
        }
        if (((PlayerState*)p2)->baddie.targetObj != NULL ||
            (c = inner->curAnimId) == 0x48 || c == 0x47 || c == 0x44 ||
            *(void**)((char*)inner + 0x7f8) != NULL ||
            ((ByteFlags*)((char*)inner + 0x3f0))->b20 ||
            ((ByteFlags*)((char*)inner + 0x3f0))->b04 ||
            ((ByteFlags*)((char*)inner + 0x3f0))->b08 ||
            ((ByteFlags*)((char*)inner + 0x3f4))->b40 == 0 ||
            *(s16*)((char*)inner->playerStatus + 4) < 0x14 ||
            !GameBit_Get(0x5bd))
        {
            return 0;
        }
        return 1;
    }
    return 0;
}
#pragma dont_inline reset

void Lightfoot_ResetScriptedPosition(int obj)
{
    switch (*(int*)((char*)*(int*)&((GameObject*)obj)->anim.placementData + 0x14))
    {
    case 0x34316:
        ((GameObject*)obj)->anim.worldPosX = lbl_803E81DC;
        ((GameObject*)obj)->anim.worldPosY = lbl_803E81E0;
        ((GameObject*)obj)->anim.worldPosZ = lbl_803E81E4;
        ((GameObject*)obj)->anim.rotX = 0x2565;
        break;
    case 0x33E3C:
        ((GameObject*)obj)->anim.worldPosX = lbl_803E81E8;
        ((GameObject*)obj)->anim.worldPosY = lbl_803E81EC;
        ((GameObject*)obj)->anim.worldPosZ = lbl_803E81F0;
        ((GameObject*)obj)->anim.rotX = 0x1c42;
        break;
    case 0x33E34:
        ((GameObject*)obj)->anim.worldPosX = lbl_803E81F4;
        ((GameObject*)obj)->anim.worldPosY = lbl_803E81EC;
        ((GameObject*)obj)->anim.worldPosZ = lbl_803E81F8;
        ((GameObject*)obj)->anim.rotX = 0x1d00;
        break;
    case 0x45C47:
        ((GameObject*)obj)->anim.worldPosX = lbl_803E81FC;
        ((GameObject*)obj)->anim.worldPosY = lbl_803E81E0;
        ((GameObject*)obj)->anim.worldPosZ = lbl_803E8200;
        ((GameObject*)obj)->anim.rotX = 0x32c1;
        break;
    case 0x460B6:
        ((GameObject*)obj)->anim.worldPosX = lbl_803E8204;
        ((GameObject*)obj)->anim.worldPosY = lbl_803E81E0;
        ((GameObject*)obj)->anim.worldPosZ = lbl_803E8208;
        ((GameObject*)obj)->anim.rotX = 0x119f;
        break;
    }
}

#pragma dont_inline on
int fn_802A97D0(int obj, int p2)
{
    PlayerState* inner = ((GameObject*)obj)->extra;
    void* slot;
    u8 af;
    u8 c;
    s16 sel = ((PlayerState*)p2)->baddie.controlMode;

    if (!((sel != 1 && sel != 2 && sel != 0x26) ||
        !GameBit_Get(0x957) ||
        (slot = inner->cameraTargetObject) == NULL ||
        *(s16*)((char*)slot + 0x46) != 0x64f ||
        ((af = *(u8*)((char*)slot + 0xaf)) & 4) == 0 ||
        (af & 0x18) != 0 ||
        ((PlayerState*)p2)->baddie.targetObj != NULL ||
        (c = inner->curAnimId) == 0x48 || c == 0x47 || c == 0x44 ||
        *(void**)((char*)inner + 0x7f8) != NULL ||
        ((ByteFlags*)((char*)inner + 0x3f0))->b20 ||
        ((ByteFlags*)((char*)inner + 0x3f0))->b04 ||
        ((ByteFlags*)((char*)inner + 0x3f0))->b08 ||
        ((ByteFlags*)((char*)inner + 0x3f4))->b40 == 0 ||
        *(s16*)((char*)*(int*)((char*)*(int*)&((GameObject*)obj)->extra + 0x35c) + 4) < 0xa))
    {
        return 1;
    }
    return 0;
}
#pragma dont_inline reset

#pragma dont_inline on
void fn_802B18BC(int obj, int state, f32 fv)
{
    f32 v;

    if ((((PlayerState*)state)->buttonsHeld & 0x100) && fn_802A9A0C(obj, state))
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

void fn_802B19F8(int obj, int state, f32 fv)
{
    u8 c;

    ((PlayerState*)state)->stickX = 0;
    ((PlayerState*)state)->stickY = 0;
    ((PlayerState*)state)->buttonsHeld = 0;
    ((PlayerState*)state)->buttonsJustPressed = 0;
    ((PlayerState*)state)->buttonsJustPressedIfNotBusy = 0;
    if ((((PlayerState*)state)->flags360 & 0x200000) == 0u &&
        ((PlayerState*)state)->characterId != -1 &&
        (c = ((PlayerState*)state)->curAnimId) != 0x44 && c != 0x4e)
    {
        ((PlayerState*)state)->stickX = padGetStickX(0);
        ((PlayerState*)state)->stickY = padGetStickY(0);
        ((PlayerState*)state)->buttonsHeld = (u16)getButtonsHeld(0);
        ((PlayerState*)state)->buttonsJustPressed = (u16)getButtonsJustPressed(0);
        ((PlayerState*)state)->buttonsJustPressedIfNotBusy = (u16)getButtonsJustPressedIfNotBusy(0);
    }
    ((PlayerState*)state)->stickXf = (f32) * (int*)((char*)state + 0x6d0);
    ((PlayerState*)state)->stickYf = (f32) * (int*)((char*)state + 0x6d4);
    fn_802B18BC(obj, state, fv);
}

void fn_802B1BF8(EmitObj* a, int b, int state)
{
    struct
    {
        s16 angles[4];
        f32 mat[4];
    } v;
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
        v.angles[0] = ((PlayerState*)b)->yaw;
        v.angles[1] = 0;
        v.angles[2] = 0;
        v.mat[0] = lbl_803E7EE0;
        v.mat[1] = lbl_803E7EA4;
        v.mat[2] = lbl_803E7EA4;
        v.mat[3] = lbl_803E7EA4;
        setMatrixFromObjectPos(mtx, v.angles);
        Matrix_TransformPoint(mtx, f30v, lbl_803E7EA4, -f31v, &a->x, &oy, &a->z);
        a->x = a->x + ((PlayerState*)b)->pushVelX;
        a->z = a->z + ((PlayerState*)b)->pushVelZ;
    }
    else
    {
        int cosI =
            (int)mathSinf(gPlayerPi * (f32) * (s16*)((char*)b + 0x484) / lbl_803E7F98);
        int sinI =
            (int)mathCosf(gPlayerPi * (f32) * (s16*)((char*)b + 0x484) / lbl_803E7F98);
        ((PlayerState*)state)->baddie.animSpeedB = a->x * (f32)sinI - a->z * (f32)cosI;
        ((PlayerState*)state)->baddie.animSpeedA = -a->z * (f32)sinI - a->x * (f32)cosI;
    }

    if ((*(int*)((char*)state) & 0x200000) == 0)
    {
        a->y = a->y * powfBitEstimate(lbl_803E8140, timeDelta);
        a->y = a->y - ((PlayerState*)state)->baddie.gravity * timeDelta;
    }
}

void fn_802B1E5C(int obj, int state, int cfg, f32 dt)
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
    f32** nearList;
    f32 pushX;
    f32 pushZ;


    found = 0;
    {
        f32 z = lbl_803E7EE0;
        ((PlayerState*)state)->targetAnimSpeed = z;
        ((PlayerState*)state)->unk834 = z;
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
        ((PlayerState*)state)->waterDepth =
            ((PlayerState*)state)->waterSurfaceY - ((GameObject*)obj)->anim.worldPosY;
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
        fv2 = lbl_803E7EE0;
        switch (((PlayerState*)state)->surfaceType)
        {
        case 13:
            ((PlayerState*)state)->targetAnimSpeed = lbl_803E8148;
            ((PlayerState*)state)->unk834 = lbl_803E814C;
            ((PlayerState*)state)->velSmoothRateBase = lbl_803E8118;
            break;
        case 3:
            ((PlayerState*)state)->targetAnimSpeed = lbl_803E7EE0;
            ((PlayerState*)state)->unk834 = fv2;
            ((PlayerState*)state)->velSmoothRateBase = lbl_803E7F6C;
            break;
        case 6:
            iv = (int)((f32) * (s16*)((char*)state + 0x808) - dt);
            *(s16*)&((PlayerState*)state)->hitIntervalTimer = iv;
            if (*(s16*)&((PlayerState*)state)->hitIntervalTimer <= 0)
            {
                *(s16*)&((PlayerState*)state)->hitIntervalTimer = 0x3c;
                ObjHits_RecordObjectHit(obj, 0, 0x14, 2, 0);
            }
            break;
        case 29:
            queryParams[0] = lbl_803E8150;
            found = (void*)ObjGroup_FindNearestObject(0x16, obj, queryParams);
            if (found != 0)
            {
                (*(void (*)(f32, int, int, f32*, f32*))(*(int*)(*(int*)(*(int*)((char*)found + 0x68)) + 0x20)))(
                    lbl_803E7EE0, (int)found, obj, &pushX, &pushZ);
            }
            break;
        case 26:
            iv = (int)((f32) * (s16*)((char*)state + 0x808) - dt);
            *(s16*)&((PlayerState*)state)->hitIntervalTimer = iv;
            if (*(s16*)&((PlayerState*)state)->hitIntervalTimer <= 0)
            {
                *(s16*)&((PlayerState*)state)->hitIntervalTimer = 0x3c;
                ObjPath_GetPointWorldPosition(obj, 0xb, &pos[0], &pos[1], &pos[2], 0);
                ObjHits_RecordPositionHit(pos[0], pos[1], pos[2], obj, 0, 0x14, 2, 0xffffffff);
            }
            break;
        case 8:
            ObjHits_RecordObjectHit(obj, 0, 1, 0, 0);
            break;
        case 28:
            if (GameBit_Get(0x21) == 0)
            {
                *(s16*)&((PlayerState*)state)->periodicHitTimer =
                    (s16)(int)((f32) * (u16*)((char*)state + 0x8a0) + dt);
                if (0x78 < ((PlayerState*)state)->periodicHitTimer)
                {
                    ((PlayerState*)state)->periodicHitTimer = ((PlayerState*)state)->periodicHitTimer - 0x78;
                    ObjPath_GetPointWorldPosition(obj, 0xb, &pos[0], &pos[1], &pos[2], 0);
                    ObjHits_RecordPositionHit(pos[0], pos[1], pos[2], obj, 0, 0x16, 2,
                                              0xffffffff);
                }
            }
            break;
        case 32:
            if (((PlayerState*)cfg)->baddie.animSpeedA > lbl_803E7E98)
            {
                r = lbl_803E7F6C + ((PlayerState*)state)->sinkOffsetY;
                ((PlayerState*)state)->sinkOffsetY = (r < clamp) ? r : clamp;
            }
            else
            {
                ((PlayerState*)state)->sinkOffsetY =
                    -(lbl_803E7E90 * dt - ((PlayerState*)state)->sinkOffsetY);
                if (lbl_803DE440 > clamp)
                {
                    lbl_803DE440 = lbl_803DE440 - dt;
                }
                else
                {
                    Sfx_PlayFromObject(obj, SFXmammoth_snowstep);
                    lbl_803DE440 = (f32)(int)
                    randomGetRange(0x27, 0x3c);
                }
            }
            iv = hitDetectFn_80065e50(obj, ((GameObject*)obj)->anim.localPosX,
                                      ((GameObject*)obj)->anim.localPosY, ((GameObject*)obj)->anim.localPosZ,
                                      (int***)&nearList, 0, 0x20);
            velMag = -((PlayerState*)state)->sinkOffsetY;
            if (1 < iv &&
                (velMag = velMag + (**nearList - *nearList[iv - 1]), velMag > lbl_803E7FA0))
            {
                int inner = *(int*)&((GameObject*)obj)->extra;
                s8* p = *(s8**)&((PlayerState *)inner)->playerStatus;
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
                if (**(s8**)&((PlayerState *)inner)->playerStatus <= 0)
                {
                    playerDie(obj);
                }
            }
            break;
        case 31:
            GameBit_Set(0x643, 1);
            break;
        default:
            *(s16*)&((PlayerState*)state)->hitIntervalTimer = 0;
            if (((PlayerState*)state)->sinkOffsetY < lbl_803E7EA4)
            {
                fv2 = lbl_803E7EFC * ((PlayerState*)cfg)->baddie.animSpeedA +
                    ((PlayerState*)state)->sinkOffsetY;
                ((PlayerState*)state)->sinkOffsetY = (fv2 < lbl_803E7EA4) ? fv2 : lbl_803E7EA4;
                velMag = -((PlayerState*)state)->sinkOffsetY;
            }
            break;
        }
        if (velMag != lbl_803E7EA4)
        {
            damp = lbl_803E7F14;
            r = -(lbl_803E7F6C * velMag - lbl_803E7EE0);
            damp = (damp > r) ? damp : r;
            ((GameObject*)obj)->anim.velocityX =
                ((GameObject*)obj)->anim.velocityX * powfBitEstimate(damp, dt);
            ((GameObject*)obj)->anim.velocityZ =
                ((GameObject*)obj)->anim.velocityZ * powfBitEstimate(damp, dt);
        }
    }
    r = interpolate(pushX - ((PlayerState*)state)->pushVelX, lbl_803E7FCC, timeDelta);
    ((PlayerState*)state)->pushVelX = ((PlayerState*)state)->pushVelX + r;
    r = interpolate(pushZ - ((PlayerState*)state)->pushVelZ, lbl_803E7FCC, timeDelta);
    ((PlayerState*)state)->pushVelZ = ((PlayerState*)state)->pushVelZ + r;
    if (found == 0)
    {
        ((PlayerState*)state)->pushVelX =
            ((PlayerState*)state)->pushVelX * powfBitEstimate(lbl_803E7FF4, timeDelta);
        ((PlayerState*)state)->pushVelZ =
            ((PlayerState*)state)->pushVelZ * powfBitEstimate(lbl_803E7FF4, timeDelta);
    }
    if (((PlayerState*)state)->pushVelX > lbl_803E7FEC &&
        ((PlayerState*)state)->pushVelX < lbl_803E7EF8)
    {
        ((PlayerState*)state)->pushVelX = lbl_803E7EA4;
    }
    if (((PlayerState*)state)->pushVelZ > lbl_803E7FEC &&
        ((PlayerState*)state)->pushVelZ < lbl_803E7EF8)
    {
        ((PlayerState*)state)->pushVelZ = lbl_803E7EA4;
    }
}

void fn_8029A4A8(int obj, int p2)
{
    int i;
    PlayerState* inner = ((GameObject*)obj)->extra;
    int sel = ((PlayerState*)p2)->baddie.controlMode;

    if (sel == 0x2a) return;
    if (sel == 0x2e) return;
    if (sel == 0x2f) return;
    if (sel == 0x2c) return;

    *(u32*)&((PlayerState*)inner)->flags360 |= 0x800000LL;
    inner->animState = -1;
    *(u32*)&((PlayerState*)inner)->flags360 &= ~0x2000400LL;

    if (((PlayerState*)p2)->baddie.controlMode != 0x2b)
    {
        if (inner->curAnimId != 0x42 && getCurSeqNo() == 0)
        {
            (*gCameraInterface)->setMode(
                0x42, 0, 1, 0, NULL, 0x3c, 0xfe);
        }
        ((ByteFlags*)((char*)inner + 0x3f6))->b40 = 0;
    }

    lbl_803DE42C = 0;
    for (i = 0; i < 7; i++)
    {
        if (gPlayerSpawnedObjects[i] != NULL)
        {
            Obj_FreeObject((int)gPlayerSpawnedObjects[i]);
            gPlayerSpawnedObjects[i] = NULL;
        }
    }
    if (gPlayerResource != NULL)
    {
        Resource_Release(gPlayerResource);
        gPlayerResource = NULL;
    }
}

void fn_802B07D8(int obj, int state)
{
    int setup;
    int b;

    if (gPlayerPathObject == NULL && Obj_IsLoadingLocked())
    {
        setup = Obj_AllocObjectSetup(0x18, 0x69);
        setup = Obj_SetupObject(setup, 4, -1, -1, *(int*)&((GameObject*)obj)->anim.parent);
        gPlayerPathObject = (void*)setup;
        ObjLink_AttachChild(obj, setup, 2);
    }
    if (gPlayerPathObject != NULL)
    {
        *(int*)&((GameObject*)gPlayerPathObject)->anim.parent = *(int*)&((GameObject*)obj)->anim.parent;
    }

    ((PlayerState*)state)->chargeLevel -= lbl_803E7E98 * timeDelta;
    if (((PlayerState*)state)->chargeLevel < *(f32*)&lbl_803E7EA4)
    {
        ((PlayerState*)state)->chargeLevel = lbl_803E7EA4;
    }
    ((PlayerState*)state)->unk7D8 -= lbl_803E7E98 * timeDelta;
    if (((PlayerState*)state)->unk7D8 < *(f32*)&lbl_803E7EA4)
    {
        ((PlayerState*)state)->unk7D8 = lbl_803E7EA4;
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
    if (b == 0 && GameBit_Get(0x75))
    {
        fn_80295CF4(obj, 0);
    }
}

int fn_8029D900(int obj, int state, f32 fv)
{
    PlayerState* inner = ((GameObject*)obj)->extra;
    int hit;

    ((PlayerState*)state)->baddie.unk34D = 3;
    if (*(s8*)&((PlayerState*)state)->baddie.moveJustStartedA != 0)
    {
        if (ObjHits_GetPriorityHit(obj, &hit, 0, 0))
        {
            inner->targetYaw =
                (s16)getAngle(-*(f32*)((char*)hit + 0x24), -*(f32*)((char*)hit + 0x2c));
            inner->yaw = inner->targetYaw;
        }
        ObjAnim_SetCurrentMove(obj, 0x407, lbl_803E7EA4, 0);
        ((PlayerState*)state)->baddie.moveSpeed = lbl_803E7F34;
    }
    switch (((GameObject*)obj)->anim.currentMove)
    {
    case 0x407:
        if (*(s8*)&((PlayerState*)state)->baddie.moveDone != 0)
        {
            ObjAnim_SetCurrentMove(obj, 0x408, lbl_803E7EA4, 0);
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
    (*(void (*)(int, int, f32, int))(*(int*)(*gPlayerInterface + 0x20)))(obj, state, fv, 1);
    return 0;
}

#pragma optimization_level 1
int fn_802957B4(int obj)
{
    PlayerState* inner = ((GameObject*)obj)->extra;
    int sub;

    if ((void*)obj == NULL)
    {
        return 0;
    }
    (*gCameraInterface)->loadTriggeredCamAction(0, 1, 0);
    (*gObjectTriggerInterface)->setCamVars(0x42, 4, 0, 0);

    sub = inner->focusObject;
    if ((void*)sub != NULL)
    {
        (*(void (*)(int, int))(*(int*)(*(int*)(*(int*)((char*)sub + 0x68)) + 0x3c)))(sub, 0);
        (*gCameraInterface)->setFocus((void*)obj, 0);
        ((GameObject*)obj)->anim.flags = ((GameObject*)obj)->anim.flags & ~8;
        ((GameObject*)obj)->anim.modelState->flags &= ~0x1000LL;
        inner->focusObject = 0;
        ((GameObject*)obj)->anim.activeMove = -1;
        (*(void (*)(int, int, int))(*(int*)(*gPlayerInterface + 0x14)))(obj, (int)inner, 1);
        *(int*)&((PlayerState*)inner)->baddie.unk304 = (int)fn_802A514C;
        Music_Trigger(0x1f, 0);
        Music_Trigger(0x97, 0);
        Music_Trigger(0xe6, 0);
        Music_Trigger(0xd5, 0);
        return 1;
    }
    return 0;
}
#pragma optimization_level reset

int fn_8029BC4C(int obj, int state, f32 fv)
{
    PlayerState* inner = ((GameObject*)obj)->extra;

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
        ObjAnim_SetCurrentMove(obj, (&lbl_803DC688)[lbl_803DE459 - 1], lbl_803E7EA4, 0);
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
        *(u32*)&((PlayerState*)inner)->flags360 |= 0x800000LL;
        *(int*)&((PlayerState*)state)->baddie.unk308 = (int)fn_802A514C;
        return 2;
    }
    (*(void (*)(int, int, f32, int))(*(int*)(*gPlayerInterface + 0x20)))(obj, state, fv, 1);
    return 0;
}

void Lightfoot_ProcessHitResponseFlags(int obj, int inner)
{
    if (*(int*)&((PlayerState*)inner)->baddie.eventFlags & 4)
    {
        *(int*)&((PlayerState*)inner)->baddie.eventFlags &= ~4;
        Sfx_PlayFromObject(obj, SFXtr_gal_prophit);
    }
    if (*(int*)&((PlayerState*)inner)->baddie.eventFlags & 2)
    {
        *(int*)&((PlayerState*)inner)->baddie.eventFlags &= ~2;
        Sfx_PlayFromObject(obj, SFXtr_gal_prophit);
    }
    if (*(int*)&((PlayerState*)inner)->baddie.eventFlags & 1)
    {
        *(int*)&((PlayerState*)inner)->baddie.eventFlags &= ~1;
        if (randomGetRange(0, 2) == 0)
        {
            Sfx_PlayFromObject(obj, 0x43c);
        }
    }
    if (*(int*)&((PlayerState*)inner)->baddie.eventFlags & 0x80)
    {
        *(int*)&((PlayerState*)inner)->baddie.eventFlags &= ~0x80;
        Sfx_PlayFromObject(obj, SFXtr_jbike_snowhit);
    }
    if (*(int*)&((PlayerState*)inner)->baddie.eventFlags & 0x200)
    {
        *(int*)&((PlayerState*)inner)->baddie.eventFlags &= ~0x200;
        Sfx_PlayFromObject(obj, SFXtr_barrelgrabber_eloop);
    }
    if (*(int*)&((PlayerState*)inner)->baddie.eventFlags & 0x40)
    {
        *(int*)&((PlayerState*)inner)->baddie.eventFlags &= ~0x40;
        Sfx_PlayFromObject(obj, SFXtr_jbike_snowspray);
    }
    if (*(int*)&((PlayerState*)inner)->baddie.eventFlags & 0x800)
    {
        *(int*)&((PlayerState*)inner)->baddie.eventFlags &= ~0x800;
        ObjHits_RecordObjectHit(Obj_GetPlayerObject(), obj, 0x19, 2, 1);
        Sfx_PlayFromObject(obj, SFXtr_jbike_boost);
        CameraShake_Start(lbl_803E81CC, lbl_803E81D0, lbl_803E81D4);
        doRumble(lbl_803E81D8);
    }
}

int fn_8029E3F4(int obj, int state)
{
    PlayerState* inner = ((GameObject*)obj)->extra;
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
    ((GameObject*)obj)->anim.velocityX = k;
    ((GameObject*)obj)->anim.velocityY = k;
    ((GameObject*)obj)->anim.velocityZ = k;
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
        ObjAnim_SetCurrentMove(obj, 0x57, lbl_803E7EA4, 0);
        ((PlayerState*)state)->baddie.moveSpeed = lbl_803E7FE8;
        Sfx_PlayFromObject(obj, (u16)(inner->characterId == 0 ? 0x2d3 : 0x2b));
    }
    if (*(s8*)&((PlayerState*)state)->baddie.moveDone != 0)
    {
        *(int*)&((PlayerState*)state)->baddie.unk308 = (int)fn_802A514C;
        return -1;
    }
    return 0;
}

int fn_802A49C8(int obj, int state)
{
    PlayerState* inner = ((GameObject*)obj)->extra;
    f32 k;

    if (*(s8*)&((PlayerState*)state)->baddie.moveJustStartedA != 0)
    {
        if (*(void**)((char*)inner + 0x7f8) != NULL)
        {
            ObjHits_MarkObjectPositionDirty(inner->heldObj);
        }
        ObjAnim_SetCurrentMove(obj, 0x443, lbl_803E7EAC, 0);
        *(s16*)((char*)state + 0x278) = 1;
        inner->stateHandler = (int)fn_802A514C;
    }
    k = lbl_803E7EA4;
    ((PlayerState*)state)->baddie.animSpeedC = k;
    ((PlayerState*)state)->baddie.animSpeedB = k;
    ((PlayerState*)state)->baddie.animSpeedA = k;
    ((GameObject*)obj)->anim.velocityX = k;
    ((GameObject*)obj)->anim.velocityY = k;
    ((GameObject*)obj)->anim.velocityZ = k;
    ((PlayerState*)state)->baddie.moveSpeed = lbl_803E8058;

    if (*(int*)&((PlayerState*)state)->baddie.eventFlags & 1)
    {
        Sfx_PlayFromObject(obj, (u16)(inner->characterId == 0 ? 0x327 : 0x379));
    }

    if (*(void**)((char*)inner + 0x7f8) == NULL && *(s8*)&((PlayerState*)state)->baddie.moveDone != 0)
    {
        *(int*)&((PlayerState*)state)->baddie.unk308 = (int)fn_802A514C;
        return 2;
    }
    if (*(void**)((char*)inner + 0x7f8) != NULL && ((GameObject*)obj)->anim.currentMoveProgress > lbl_803E7E9C)
    {
        inner->isHoldingObject = 0;
        if (*(void**)((char*)inner + 0x7f8) != NULL)
        {
            int s2 = inner->heldObj;
            s16 id = *(s16*)((char*)s2 + 0x46);
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

int fn_80298CCC(int obj, int state)
{
    PlayerState* inner = ((GameObject*)obj)->extra;
    f32 k;

    if (*(s8*)&((PlayerState*)state)->baddie.moveJustStartedA != 0)
    {
        ObjHits_MarkObjectPositionDirty(obj);
    }
    k = lbl_803E7EA4;
    ((PlayerState*)state)->baddie.animSpeedC = k;
    ((PlayerState*)state)->baddie.animSpeedB = k;
    ((PlayerState*)state)->baddie.animSpeedA = k;
    ((GameObject*)obj)->anim.velocityX = k;
    ((GameObject*)obj)->anim.velocityY = k;
    ((GameObject*)obj)->anim.velocityZ = k;

    switch (((GameObject*)obj)->anim.currentMove)
    {
    case 0xdd:
        if (((GameObject*)obj)->anim.currentMoveProgress > lbl_803E7F44)
        {
            cfPrisonGuard_setLiftHeight(gPlayerInteractTarget, 0);
        }
        if (((GameObject*)obj)->anim.currentMoveProgress > lbl_803E7F48 &&
            (((PlayerState*)state)->baddie.moveEventFlags & 1) == 0)
        {
            Sfx_PlayFromObject(obj, SFXbaddie_eggsnatch_sniff3);
            ((PlayerState*)state)->baddie.moveEventFlags |= 1;
        }
        if (*(s8*)&((PlayerState*)state)->baddie.moveDone != 0)
        {
            *(u32*)&((PlayerState*)inner)->flags360 |= 0x800000LL;
            *(int*)&((PlayerState*)state)->baddie.unk308 = (int)fn_802A514C;
            return 2;
        }
        break;
    default:
        ObjAnim_SetCurrentMove(obj, 0xdd, k, 0);
        staffactivated_calcInteractionTargetXZ(gPlayerInteractTarget, (char*)obj + 0xc, (char*)obj + 0x14);
        ((PlayerState*)state)->baddie.moveSpeed = lbl_803E7EF8;
        ((PlayerState*)state)->baddie.moveEventFlags = 0;
        inner->targetYaw = *(s16*)((char*)gPlayerInteractTarget);
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

void fn_80295CF4(int obj, int a)
{
    PlayerState* inner = ((GameObject*)obj)->extra;

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
            GameBit_Set(0x96b, 1);
            GameBit_Set(0x961, 1);
            GameBit_Set(0x969, 1);
            GameBit_Set(0x964, 1);
            GameBit_Set(0x965, 1);
            GameBit_Set(0x986, 1);
            GameBit_Set(0x960, 1);
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
            GameBit_Set(0x96b, 0);
            GameBit_Set(0x961, 0);
            GameBit_Set(0x969, 0);
            GameBit_Set(0x964, 0);
            GameBit_Set(0x965, 0);
            GameBit_Set(0x986, 0);
            GameBit_Set(0x960, 0);
        }
    }
    ((ByteFlags*)((char*)inner + 0x3f4))->b40 = a;
}

void fn_802AE83C(int obj, int inner)
{
    int sub;
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
    Sfx_StopFromObject(obj, (u16)(((PlayerState*)inner)->characterId == 0 ? 0x2d0 : 0x26));

    if ((void*)gPlayerPathObject != NULL && ((ByteFlags*)((char*)inner + 0x3f4))->b40)
    {
        ((PlayerState*)inner)->staffActionRequest = 1;
        ((ByteFlags*)((char*)inner + 0x3f4))->b08 = 1;
    }
    ((PlayerState*)inner)->isHoldingObject = 0;
    sub = ((PlayerState*)inner)->heldObj;
    if ((void*)sub != NULL)
    {
        s16 id = *(s16*)((char*)sub + 0x46);
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
        Sfx_PlayFromObject(obj, SFXthorntail_snort2);
        (*gWaterfxInterface)->spawnSplashBurst(
            (void*)obj, ((GameObject*)obj)->anim.localPosX,
            ((GameObject*)obj)->anim.localPosY, ((GameObject*)obj)->anim.localPosZ,
            lbl_803E7ED8);
    }
}

int fn_80298380(int obj, int state, f32 fv)
{
    PlayerState* inner = ((GameObject*)obj)->extra;
    int r;

    if (*(s8*)&((PlayerState*)state)->baddie.moveJustStartedA != 0)
    {
        f32 zero;
        ObjAnim_SetCurrentMove(obj, 0xfb, lbl_803E7EA4, 0);
        ((PlayerState*)state)->baddie.moveSpeed = lbl_803E7F28;
        zero = lbl_803E7EA4;
        ((PlayerState*)state)->baddie.animSpeedC = zero;
        ((PlayerState*)state)->baddie.animSpeedB = zero;
        ((PlayerState*)state)->baddie.animSpeedA = zero;
        ((GameObject*)obj)->anim.velocityX = zero;
        ((GameObject*)obj)->anim.velocityY = zero;
        ((GameObject*)obj)->anim.velocityZ = zero;
    }

    r = fn_8029B9FC(obj, state, fv);
    if (r != 0)
    {
        return r;
    }

    (*(void (*)(int, int, f32, int))(*(int*)(*gPlayerInterface + 0x30)))(obj, state, fv, 1);
    inner->targetYaw = inner->yaw = *(s16*)((char*)obj);
    (*(void (*)(int, int, f32, int))(*(int*)(*gPlayerInterface + 0x20)))(obj, state, fv, 2);

    if (*(s8*)&((PlayerState*)state)->baddie.moveDone != 0)
    {
        *(int*)&((PlayerState*)state)->baddie.unk308 = (int)fn_8029C8C8;
        return 0x25;
    }
    if (((GameObject*)obj)->anim.currentMoveProgress > lbl_803E7F2C)
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
        r = fn_80299E44(obj, state, fv);
        if (r != 0)
        {
            return r;
        }
    }
    return 0;
}

int fn_802A4B78(int obj, int state)
{
    PlayerState* inner = ((GameObject*)obj)->extra;
    int sub;

    if (*(s8*)&((PlayerState*)state)->baddie.moveJustStartedA != 0)
    {
        ObjAnim_SetCurrentMove(obj, 0x447, lbl_803E7EA4, 0);
        *(s16*)((char*)state + 0x278) = 1;
        inner->stateHandler = (int)fn_802A514C;
    }
    if ((*(int*)&((PlayerState*)state)->baddie.eventFlags & 1) &&
        (void*)(sub = inner->heldObj) != NULL)
    {
        switch (*(s16*)((char*)sub + 0x46))
        {
        case 0x6d:
        case 0x754:
            Sfx_PlayFromObject(obj, SFXspirit_pool_wobble2);
            break;
        case 0x1f4:
        case 0x1f5:
        case 0x1f6:
        case 0x1f7:
        case 0x1f8:
        case 0x1f9:
        case 0x519:
            Sfx_PlayFromObject(obj, 0x39b);
            break;
        default:
            Sfx_PlayFromObject(obj, SFXmn_dimraw26);
            break;
        }
    }
    ((PlayerState*)state)->baddie.animSpeedA = lbl_803E7EA4;
    ((PlayerState*)state)->baddie.moveSpeed = lbl_803E7F40;

    sub = inner->heldObj;
    if ((void*)sub == NULL && *(s8*)&((PlayerState*)state)->baddie.moveDone != 0)
    {
        *(u32*)&((PlayerState*)inner)->flags360 |= 0x800000LL;
        *(int*)&((PlayerState*)state)->baddie.unk308 = (int)fn_802A514C;
        return 2;
    }
    if ((void*)sub != NULL && ((GameObject*)obj)->anim.currentMoveProgress > lbl_803E7F48)
    {
        inner->isHoldingObject = 0;
        if (*(void**)((char*)inner + 0x7f8) != NULL)
        {
            int s2 = inner->heldObj;
            s16 id = *(s16*)((char*)s2 + 0x46);
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

int playerSetHeldObject(int obj, int held)
{
    PlayerState* inner = ((GameObject*)obj)->extra;
    int sub;

    if ((void*)held != NULL)
    {
        inner->heldObj = held;
        (*(void (*)(int, int, int))(*(int*)(*gPlayerInterface + 0x14)))(obj, (int)inner, 5);
        *(int*)&((PlayerState*)inner)->baddie.unk304 = (int)fn_802A4B4C;
    }
    else if ((void*)inner->heldObj != NULL)
    {
        inner->isHoldingObject = 0;
        sub = inner->heldObj;
        if ((void*)sub != NULL)
        {
            s16 id = ((GameObject*)sub)->anim.seqId;
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
            inner->heldObj = 0;
        }
        *(u32*)&((PlayerState*)inner)->flags360 |= 0x800000LL;
        (*(void (*)(int, int, int))(*(int*)(*gPlayerInterface + 0x14)))(obj, (int)inner, 1);
        *(int*)&((PlayerState*)inner)->baddie.unk304 = (int)fn_802A514C;
    }
    return (void*)inner->heldObj != NULL;
}

int fn_80298184(int obj, int state, f32 fv)
{
    PlayerState* inner = ((GameObject*)obj)->extra;
    int r;
    f32 k;
    s16 hdr;

    *(u32*)&((PlayerState*)inner)->flags360 |= 0x800LL;
    if (*(s8*)&((PlayerState*)state)->baddie.moveJustStartedA != 0)
    {
        ((PlayerState*)state)->baddie.moveSpeed = lbl_803E7EF8;
        k = lbl_803E7EA4;
        ((PlayerState*)state)->baddie.animSpeedC = k;
        ((PlayerState*)state)->baddie.animSpeedB = k;
        ((PlayerState*)state)->baddie.animSpeedA = k;
        ((GameObject*)obj)->anim.velocityX = k;
        ((GameObject*)obj)->anim.velocityY = k;
        ((GameObject*)obj)->anim.velocityZ = k;
    }
    r = fn_8029B9FC(obj, state, fv);
    if (r != 0)
    {
        return r;
    }
    (*(void (*)(int, int, f32, int))(*(int*)(*gPlayerInterface + 0x30)))(obj, state, fv, 1);
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
        if (((GameObject*)obj)->anim.currentMove != 0x455)
        {
            doRumble(lbl_803E7ED8);
            ObjAnim_SetCurrentMove(obj, 0x455, lbl_803E7EA4, 0);
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
        if (((GameObject*)obj)->anim.currentMove != 0x458 &&
            ((int (*)(ObjAnimComponent*))ObjAnim_GetCurrentEventCountdown)((ObjAnimComponent*)obj) == 0)
        {
            ObjAnim_SetCurrentMove(obj, 0x458, ((GameObject*)obj)->anim.currentMoveProgress, 0);
            ObjAnim_SetCurrentEventStepFrames((ObjAnimComponent*)obj, 8);
        }
    }
    ((PlayerState*)state)->baddie.animSpeedA =
        ((PlayerState*)state)->baddie.animSpeedA *
        powfBitEstimate(inner->animSpeedDecay, timeDelta);
    return 0;
}

int fn_80297AD0(int obj, int state, f32 fv)
{
    PlayerState* inner = ((GameObject*)obj)->extra;
    int r;
    f32 k;
    s16 hdr;

    if (*(s8*)&((PlayerState*)state)->baddie.moveJustStartedA != 0)
    {
        ObjAnim_SetCurrentMove(obj, gPlayerMoveSlotTable[*(s16*)((char*)gPlayerMoveSlotData + 0x422)],
                               lbl_803E7EA4, 0);
        ((PlayerState*)state)->baddie.moveSpeed = lbl_803E7F20;
        k = lbl_803E7EA4;
        ((PlayerState*)state)->baddie.animSpeedC = k;
        ((PlayerState*)state)->baddie.animSpeedB = k;
        ((PlayerState*)state)->baddie.animSpeedA = k;
        ((GameObject*)obj)->anim.velocityX = k;
        ((GameObject*)obj)->anim.velocityY = k;
        ((GameObject*)obj)->anim.velocityZ = k;
    }
    r = fn_8029B9FC(obj, state, fv);
    if (r != 0)
    {
        return r;
    }
    (*(void (*)(int, int, f32, int))(*(int*)(*gPlayerInterface + 0x30)))(obj, state, fv, 0x10);
    hdr = *(s16*)obj;
    inner->yaw = hdr;
    inner->targetYaw = hdr;
    (*(void (*)(int, int, f32, int))(*(int*)(*gPlayerInterface + 0x20)))(obj, state, fv, 1);
    if ((((PlayerState*)state)->baddie.moveEventFlags & 1) == 0 &&
        ((GameObject*)obj)->anim.currentMoveProgress > lbl_803E7F14)
    {
        Sfx_PlayFromObject(obj, SFXdn_hightop_hurt1);
        ((PlayerState*)state)->baddie.moveEventFlags |= 1;
    }
    if ((((PlayerState*)state)->baddie.moveEventFlags & 2) == 0 &&
        ((GameObject*)obj)->anim.currentMoveProgress > lbl_803E7F18)
    {
        Sfx_PlayFromObject(obj, SFXen_liftstpc);
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
        r = fn_80299E44(obj, state, fv);
        if (r != 0)
        {
            return r;
        }
    }
    return 0;
}

int fn_80297D0C(int obj, int state, f32 fv)
{
    PlayerState* inner = ((GameObject*)obj)->extra;
    int r;
    f32 k;
    s16 hdr;

    if (*(s8*)&((PlayerState*)state)->baddie.moveJustStartedA != 0)
    {
        ObjAnim_SetCurrentMove(obj, gPlayerMoveSlotTable[*(s16*)((char*)gPlayerMoveSlotData + 0x632)],
                               lbl_803E7EA4, 0);
        ((PlayerState*)state)->baddie.moveSpeed = lbl_803E7F24;
        ((PlayerState*)state)->baddie.moveEventFlags = 0;
        k = lbl_803E7EA4;
        ((PlayerState*)state)->baddie.animSpeedC = k;
        ((PlayerState*)state)->baddie.animSpeedB = k;
        ((PlayerState*)state)->baddie.animSpeedA = k;
        ((GameObject*)obj)->anim.velocityX = k;
        ((GameObject*)obj)->anim.velocityY = k;
        ((GameObject*)obj)->anim.velocityZ = k;
    }
    r = fn_8029B9FC(obj, state, fv);
    if (r != 0)
    {
        return r;
    }
    (*(void (*)(int, int, f32, int))(*(int*)(*gPlayerInterface + 0x30)))(obj, state, fv, 1);
    hdr = *(s16*)obj;
    inner->yaw = hdr;
    inner->targetYaw = hdr;
    (*(void (*)(int, int, f32, int))(*(int*)(*gPlayerInterface + 0x20)))(obj, state, fv, 2);
    if (*(int*)&((PlayerState*)state)->baddie.eventFlags & 0x200)
    {
        doRumble(lbl_803E7F10);
        Sfx_PlayFromObject(obj, 0x3cd);
        inner->pendingFxFlags |= 4;
    }
    if ((((PlayerState*)state)->baddie.moveEventFlags & 1) == 0 &&
        ((GameObject*)obj)->anim.currentMoveProgress > lbl_803E7F14)
    {
        Sfx_PlayFromObject(obj, SFXen_liftstpc);
        ((PlayerState*)state)->baddie.moveEventFlags |= 1;
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
        r = fn_80299E44(obj, state, fv);
        if (r != 0)
        {
            return r;
        }
    }
    return 0;
}

int fn_80297F48(int obj, int state, f32 fv)
{
    PlayerState* inner = ((GameObject*)obj)->extra;
    int r;
    f32 k;
    s16 hdr;

    if (*(s8*)&((PlayerState*)state)->baddie.moveJustStartedA != 0)
    {
        ObjAnim_SetCurrentMove(obj, gPlayerMoveSlotTable[*(s16*)((char*)gPlayerMoveSlotData + 0x582)],
                               lbl_803E7EA4, 0);
        ((PlayerState*)state)->baddie.moveSpeed = lbl_803E7F24;
        ((PlayerState*)state)->baddie.moveEventFlags = 0;
        k = lbl_803E7EA4;
        ((PlayerState*)state)->baddie.animSpeedC = k;
        ((PlayerState*)state)->baddie.animSpeedB = k;
        ((PlayerState*)state)->baddie.animSpeedA = k;
        ((GameObject*)obj)->anim.velocityX = k;
        ((GameObject*)obj)->anim.velocityY = k;
        ((GameObject*)obj)->anim.velocityZ = k;
    }
    r = fn_8029B9FC(obj, state, fv);
    if (r != 0)
    {
        return r;
    }
    (*(void (*)(int, int, f32, int))(*(int*)(*gPlayerInterface + 0x30)))(obj, state, fv, 1);
    hdr = *(s16*)obj;
    inner->yaw = hdr;
    inner->targetYaw = hdr;
    (*(void (*)(int, int, f32, int))(*(int*)(*gPlayerInterface + 0x20)))(obj, state, fv, 2);
    if (*(int*)&((PlayerState*)state)->baddie.eventFlags & 0x200)
    {
        doRumble(lbl_803E7F10);
        Sfx_PlayFromObject(obj, 0x3cd);
        inner->pendingFxFlags |= 4;
    }
    if ((((PlayerState*)state)->baddie.moveEventFlags & 1) == 0 &&
        ((GameObject*)obj)->anim.currentMoveProgress > lbl_803E7F14)
    {
        Sfx_PlayFromObject(obj, SFXen_liftstpc);
        ((PlayerState*)state)->baddie.moveEventFlags |= 1;
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
        r = fn_80299E44(obj, state, fv);
        if (r != 0)
        {
            return r;
        }
    }
    return 0;
}

int fn_8029D250(int obj, int state, f32 fv)
{
    MoveTable* mt = (MoveTable*)lbl_80332EC0;
    PlayerState* inner = ((GameObject*)obj)->extra;
    u32 flags;
    int idx;

    ((PlayerState*)state)->baddie.unk34D = 3;
    if (*(s8*)&((PlayerState*)state)->baddie.moveJustStartedA != 0)
    {
        if (((PlayerState*)state)->baddie.targetObj != NULL &&
            (inner->flags884 & 1))
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
            ObjAnim_SetCurrentMove(obj, mt->moves[idx], mt->blend[idx], 0);
            ((PlayerState*)state)->baddie.moveSpeed = mt->angles[idx];
            ((PlayerState*)state)->baddie.animSpeedA = -inner->animSpeedStart;
        }
        else
        {
            ObjAnim_SetCurrentMove(obj, mt->moves[inner->moveVariantIndex],
                                   lbl_803E7EA4, 0);
            ((PlayerState*)state)->baddie.moveSpeed = mt->angles[inner->moveVariantIndex];
        }
    }
    if (((PlayerState*)state)->baddie.targetObj != NULL)
    {
        inner->targetYaw = inner->targetYaw +
            (int)((f32)inner->targetObjectBearing / lbl_803E7FC0);
        inner->yaw = inner->targetYaw;
    }
    ((PlayerState*)state)->baddie.animSpeedA =
        ((PlayerState*)state)->baddie.animSpeedA *
        powfBitEstimate(inner->animSpeedDecay, fv);
    (*(void (*)(int, int, f32, int))(*(int*)(*gPlayerInterface + 0x20)))(obj, state, fv, 2);
    if (*(s8*)&((PlayerState*)state)->baddie.moveDone != 0)
    {
        *(int*)&((PlayerState*)state)->baddie.unk308 = (int)fn_802A514C;
        return 2;
    }
    return 0;
}

int fn_80297854(int obj, int state, f32 fv)
{
    PlayerState* inner = ((GameObject*)obj)->extra;
    int r;
    f32 k;
    s16 hdr;

    if (*(s8*)&((PlayerState*)state)->baddie.moveJustStartedA != 0)
    {
        ObjAnim_SetCurrentMove(obj, gPlayerMoveSlotTable[*(s16*)((char*)gPlayerMoveSlotData + 0x4d2)],
                               lbl_803E7EA4, 0);
        ((PlayerState*)state)->baddie.moveSpeed = lbl_803E7F0C;
        k = lbl_803E7EA4;
        ((PlayerState*)state)->baddie.animSpeedC = k;
        ((PlayerState*)state)->baddie.animSpeedB = k;
        ((PlayerState*)state)->baddie.animSpeedA = k;
        ((GameObject*)obj)->anim.velocityX = k;
        ((GameObject*)obj)->anim.velocityY = k;
        ((GameObject*)obj)->anim.velocityZ = k;
    }
    r = fn_8029B9FC(obj, state, fv);
    if (r != 0)
    {
        return r;
    }
    (*(void (*)(int, int, f32, int))(*(int*)(*gPlayerInterface + 0x30)))(obj, state, fv, 0x10);
    hdr = *(s16*)obj;
    inner->yaw = hdr;
    inner->targetYaw = hdr;
    (*(void (*)(int, int, f32, int))(*(int*)(*gPlayerInterface + 0x20)))(obj, state, fv, 1);
    if (*(int*)&((PlayerState*)state)->baddie.eventFlags & 0x200)
    {
        doRumble(lbl_803E7F10);
        Sfx_PlayFromObject(obj, 0x3cd);
        inner->pendingFxFlags |= 4;
    }
    if ((((PlayerState*)state)->baddie.moveEventFlags & 1) == 0 &&
        ((GameObject*)obj)->anim.currentMoveProgress > lbl_803E7F14)
    {
        Sfx_PlayFromObject(obj, SFXdn_hightop_hurt1);
        ((PlayerState*)state)->baddie.moveEventFlags |= 1;
    }
    if ((((PlayerState*)state)->baddie.moveEventFlags & 2) == 0 &&
        ((GameObject*)obj)->anim.currentMoveProgress > lbl_803E7F18)
    {
        Sfx_PlayFromObject(obj, audioPickSoundEffect_8006ed24(inner->surfaceType,
                                                              inner->footstepSoundId));
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
        r = fn_80299E44(obj, state, fv);
        if (r != 0)
        {
            return r;
        }
    }
    return 0;
}

#pragma dont_inline on
void Lightfoot_UpdatePlayerInteraction(int obj, int inner, int state)
{
    int p = *(int*)((char*)inner + 0x40c);
    int sub = *(int*)&((GameObject*)obj)->anim.placementData;
    int mode;
    int v;

    (*(void (*)(int, int, int, void*, void*, void*))(*(int*)(*gBaddieControlInterface + 0x14)))(
        obj, Obj_GetPlayerObject(), 0x10,
        (char*)p + 0x1e, (char*)p + 0x20, (char*)p + 0x22);
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
        characterDoEyeAnims(obj, inner + 0x3ac);
        *(int*)&((PlayerState*)state)->baddie.targetObj = Obj_GetPlayerObject();
        v = *(int*)&((PlayerState*)sub)->baddie.posX;
        if (v >= 0x49942 || v < 0x4993f)
        {
            (*(void (*)(int, int, f32, int))(*(int*)(*gBaddieControlInterface + 0x2c)))(
                obj, state, lbl_803E820C, 1);
        }
        ((PlayerState*)inner)->pendingParentObj = *(int*)&((GameObject*)obj)->pendingParentObj;
        *(int*)&((GameObject*)obj)->pendingParentObj = 0;
        (*(void (*)(int, int, f32, f32, void*, void*))(*(int*)(*gPlayerInterface + 0x8)))(
            obj, state, timeDelta, timeDelta, lbl_803DB0DC, lbl_803DB0D0);
        *(int*)&((GameObject*)obj)->pendingParentObj = ((PlayerState*)inner)->pendingParentObj;
        Lightfoot_ProcessHitResponseFlags(obj, inner);
    }
}
#pragma dont_inline reset

void fn_802B4C18(int obj, int state, f32 fv)
{
    u8 buf[0x40];

    ((PlayerState*)state)->baddie.gravity = lbl_803E7EB4;
    ((PlayerState*)state)->baddie.moveInputX = ((PlayerState*)state)->stickXf;
    ((PlayerState*)state)->baddie.moveInputZ = ((PlayerState*)state)->stickYf;
    *(int*)&((PlayerState*)state)->baddie.unk31C = ((PlayerState*)state)->buttonsJustPressed;
    *(int*)&((PlayerState*)state)->baddie.unk318 = ((PlayerState*)state)->buttonsHeld;
    Player_GetObjHitsState(obj)->hitVolumePriority = 0;
    Player_GetObjHitsState(obj)->hitVolumeId = 0;
    Player_GetObjHitsState(obj)->objectPairPriority = 0;
    Player_GetObjHitsState(obj)->objectPairHitVolume = 0;
    ((PlayerState*)state)->baddie.physicsActive = 1;
    *(u32*)((char*)state + 0x4) &= ~0x8100000;
    playerShadowFn_80062a30(obj);
    ((PlayerState*)state)->emissionState = 0;
    *(u32*)&((PlayerState*)state)->flags360 &= ~0x2000LL;
    *(int*)state |= 0x1000000;
    fn_802B0EA4(obj, state, state);
    if (fn_802A74A4(obj, state, state, buf, fv, 0x60) == 8)
    {
        *(int*)&((PlayerState*)state)->baddie.targetObj = 0;
        ((PlayerState*)state)->baddie.hasTarget = 0;
        (*gCameraInterface)->setTarget(0);
        if (gPlayerPathObject != 0 && ((ByteFlags*)((char*)state + 0x3f4))->b40)
        {
            ((PlayerState*)state)->staffActionRequest = 1;
            ((ByteFlags*)((char*)state + 0x3f4))->b08 = 1;
        }
        (*(void (*)(int, int, int))(*(int*)(*gPlayerInterface + 0x14)))(obj, state, 0xa);
        *(int*)&((PlayerState*)state)->baddie.unk304 = 0;
    }
    (*(void (*)(int, int, f32, f32, int*, int*))(*(int*)(*gPlayerInterface + 0x8)))(
        obj, state, fv, fv, gPlayerStateHandlers, &gPlayerDefaultStateHandler);
    *(int*)state &= ~0x1000000;
}

void fn_802AC32C(int p1, int p2, int p3)
{
    void* near;
    int angle1;
    int angle2;

    near = (void*)fn_802AB1D0(p1);
    if (near != NULL && ((ByteFlags*)((char*)p3 + 0x3f0))->b80 == 0 &&
        ((ByteFlags*)((char*)p3 + 0x3f0))->b40 == 0)
    {
        s16 cd = *(s16*)&((PlayerState*)p3)->unk4A0 - 1;
        f32 ratio;
        f32 clamped;
        f32 f5;
        f32 result;
        int delta;

        *(s16*)&((PlayerState*)p3)->unk4A0 = cd;
        if (cd <= 0)
        {
            *(s16*)&((PlayerState*)p3)->unk4A0 = (s16)randomGetRange(0x78, 0xf0);
            *(s16*)&((PlayerState*)p3)->unk4A2 = (s16)randomGetRange(0, 0x28);
        }
        delta = getAngle(-(*(f32*)((char*)near + 0xc) - ((GameObject*)p1)->anim.localPosX),
                         -(*(f32*)((char*)near + 0x14) - ((GameObject*)p1)->anim.localPosZ)) & 0xffff;
        delta -= (u16) * (s16*)((char*)p3 + 0x478);
        if (delta > 0x8000)
        {
            delta -= 0xFFFF;
        }
        if (delta < -0x8000)
        {
            delta += 0xFFFF;
        }
        ratio = lbl_803E7EE0 - (((PlayerState*)p2)->baddie.animSpeedC - lbl_803E7E9C) /
            (((PlayerState*)p3)->maxSpeed - lbl_803E7E9C);
        f5 = lbl_803E80C4;
        clamped = (ratio < lbl_803E7EA4) ? lbl_803E7EA4 : ((ratio > lbl_803E7EE0) ? lbl_803E7EE0 : ratio);
        f5 = f5 * clamped + lbl_803E80F4;
        result = ((f32)delta < lbl_803E80F8 * -f5) ? lbl_803E80F8 * -f5
            : (((f32)delta > lbl_803E80F8 * f5) ? lbl_803E80F8 * f5 : (f32)delta);
        angle1 = (int)result;
    }
    else
    {
        angle1 = 0;
        *(s16*)&((PlayerState*)p3)->unk4A0 = 0;
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
        if (v480 < -0x28)
        {
            v480 = -0x28;
        }
        else if (v480 > 0x28)
        {
            v480 = 0x28;
        }
        angle1 += v480 * 0xb6;
    }
    if (angle1 < -0x3ffc)
    {
        angle1 = -0x3ffc;
    }
    else if (angle1 > 0x3ffc)
    {
        angle1 = 0x3ffc;
    }
    angle1 -= (u16) * (s16*)((char*)p3 + 0x4d4);
    if (angle1 > 0x8000)
    {
        angle1 -= 0xFFFF;
    }
    if (angle1 < -0x8000)
    {
        angle1 += 0xFFFF;
    }
    angle1 = (int)((f32)angle1 * lbl_803E7EB4);
    if (angle1 < -0x16c)
    {
        angle1 = -0x16c;
    }
    else if (angle1 > 0x16c)
    {
        angle1 = 0x16c;
    }
    ((PlayerState*)p3)->bodyLeanAngle =
        (f32)angle1 * timeDelta + (f32) * (s16*)((char*)p3 + 0x4d4);
    ((PlayerState*)p3)->bodyLeanHalf = (s16)(((PlayerState*)p3)->bodyLeanAngle / 2);

    angle2 = ((PlayerState*)p3)->targetYaw - (u16) * (s16*)((char*)p3 + 0x492);
    if (angle2 > 0x8000)
    {
        angle2 -= 0xFFFF;
    }
    if (angle2 < -0x8000)
    {
        angle2 += 0xFFFF;
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
    if (angle2 < -0xccc)
    {
        angle2 = -0xccc;
    }
    else if (angle2 > 0xccc)
    {
        angle2 = 0xccc;
    }
    angle2 -= (u16) * (s16*)((char*)p3 + 0x4d0);
    if (angle2 > 0x8000)
    {
        angle2 -= 0xFFFF;
    }
    if (angle2 < -0x8000)
    {
        angle2 += 0xFFFF;
    }
    ((PlayerState*)p3)->headPitch =
        (f32) * (s16*)((char*)p3 + 0x4d0) +
            interpolate((f32)angle2, lbl_803E7EB4, timeDelta);
    ((PlayerState*)p3)->headYaw =
        (f32) * (s16*)((char*)p3 + 0x4d6) *
            powfBitEstimate(lbl_803E7F1C, timeDelta);
}

#pragma opt_loop_invariants off
int Lightfoot_SeqFn(int obj, int unused, ObjAnimUpdateState* animUpdate)
{
    int inner = *(int*)&((GameObject*)obj)->extra;
    int placement = *(int*)&((GameObject*)obj)->anim.placementData;
    int timerRec;
    int mode;
    u8 i;
    u8 j;
    f32 scale;
    f32 zero;
    f32 snd[3];
    f32 arr[6];

    timerRec = *(int*)((char*)inner + 0x40c);
    if (*(f32*)((char*)timerRec + 0x10) != (zero = lbl_803E8180) &&
        (*(f32*)((char*)timerRec + 0x10) = *(f32*)((char*)timerRec + 0x10) - timeDelta,
            *(f32*)((char*)timerRec + 0x10) <= zero))
    {
        Obj_FreeObject(obj);
    }
    for (i = 0; i < animUpdate->eventCount; i++)
    {
        switch (animUpdate->eventIds[i])
        {
        case 1:
            *(u8*)((char*)inner + 0x404) = *(u8*)((char*)inner + 0x404) | 1;
            GameBit_Set(*(s16*)((char*)placement + 0x1c), 1);
            arr[3] = lbl_803E8180;
            arr[4] = lbl_803E81C4;
            arr[5] = lbl_803E8180;
            j = 0x19;
            scale = lbl_803E8210;
            for (; j != 0; j--)
            {
                fn_80098B18(scale * ((GameObject*)obj)->anim.rootMotionScale, obj, 3, 0, 0, arr);
            }
            break;
        }
    }
    if (*(s16*)((char*)placement + 0x1a) == 0x64c)
    {
        Lightfoot_UpdatePlayerInteraction(obj, inner, inner);
        if ((*(u8*)((char*)inner + 0x404) & 1) != 0 &&
            (((GameObject*)obj)->objectFlags & 0x800) != 0)
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
            Sfx_KeepAliveLoopedObjectSound(obj, 0x455);
            fn_80098B18(lbl_803E81C8 * ((GameObject*)obj)->anim.rootMotionScale, obj, 3, mode, 0, snd);
        }
    }
    *(u16*)((char*)inner + 0x400) = *(u16*)((char*)inner + 0x400) | 2;
    return 0;
}
#pragma opt_loop_invariants reset

void objLoadPlayerFromSave(int obj)
{
    char* base = (char*)lbl_80332EC0;
    s16* gb;
    int inner = *(int*)&((GameObject*)obj)->extra;
    int i;
    f32 fz;
    int me;
    int off;
    u8* pathState;

    lbl_803DE459 = 0;
    ObjGroup_AddObject(obj, 0);
    ObjGroup_AddObject(obj, 0x25);
    objSetSlot(obj, 0x3c);
    ObjMsg_AllocQueue(obj, 0x14);
    ((GameObject*)obj)->animEventCallback = (void*)player_SeqFn;
    *(int*)&((GameObject*)obj)->anim.placementData = 0;
    ((PlayerState*)inner)->heldObj = 0;
    ((PlayerState*)inner)->playerStatus =
        (int)(*gMapEventInterface)->getCurCharacterState();
    *(u16*)&((PlayerState*)inner)->characterId =
        (*gMapEventInterface)->getCurChar();
    Obj_SetActiveModelIndex(obj, ((PlayerState*)inner)->characterId);
    me = (int)(*gMapEventInterface)->getCurCharPos();
    ((GameObject*)obj)->anim.rotX = (s16)(*(s8*)((char*)me + 0xc) << 8);
    ((PlayerState*)inner)->targetYaw = ((GameObject*)obj)->anim.rotX;
    ((PlayerState*)inner)->yaw = ((GameObject*)obj)->anim.rotX;
    ((PlayerState*)inner)->lastInputHeading = ((GameObject*)obj)->anim.rotX;
    fz = lbl_803E7EE0;
    ((PlayerState*)inner)->unk77C = fz;
    ((PlayerState*)inner)->queuedItemCommand = -1;
    ((PlayerState*)inner)->animState = -1;
    ((PlayerState*)inner)->targetAnimSpeed = fz;
    ((PlayerState*)inner)->unk834 = fz;
    ((PlayerState*)inner)->velSmoothRateBase = lbl_803E8144;
    ((ByteFlags*)((char*)inner + 0x3f1))->b01 = 1;
    ((PlayerState*)inner)->idleDelayTimer = lbl_803E7FA4;
    ((PlayerState*)inner)->walkAnimSoundId = 3;
    ((PlayerState*)inner)->runAnimSoundId = 4;
    ((PlayerState*)inner)->footstepSoundId = 5;
    ((PlayerState*)inner)->altAnimSoundId = 6;
    ((PlayerState*)inner)->animSoundId = ((PlayerState*)inner)->walkAnimSoundId;
    ((PlayerState*)inner)->unk8BF = 0;
    (*(void (*)(int, int, int, int))(*(int*)(*gPlayerInterface + 0x4)))(obj, inner, 0x42, 1);
    *(int*)((char*)inner + 0x27c) = inner + 0x6f0;
    pathState = (u8*)&((PlayerState*)inner)->baddie + 4;
    (*gPathControlInterface)->init(pathState, 1, 0x400a7, 1);
    (*gPathControlInterface)->setLocalPointCollision(pathState, 1,
                                                     base + 0x130,
                                                     &lbl_803DC6C0, 1);
    (*gPathControlInterface)->setup(pathState, 2, base + 0x118,
                                    &lbl_803DC6B8, &lbl_803DC6A4);
    pathState[0x258] = 0x64;
    fn_802AB5A4(obj, inner, 0xff);
    Player_GetObjHitsState(obj)->trackContactMask = 0x29;
    ((GameObject*)obj)->anim.alpha = 0xff;
    if (((GameObject*)obj)->anim.modelState != NULL)
    {
        ((GameObject*)obj)->anim.modelState->flags |= 0x4008;
    }
    (*(void (*)(GameUIInterface*))(*(int*)((char*)*gGameUIInterface + 0x14)))(*gGameUIInterface);
    gPlayerChildObject = NULL;
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
    for (i = 0, off = 0; i < ((PlayerState*)inner)->moveSlotCount; i++)
    {
        int da;
        *(int*)(((PlayerState*)inner)->moveSlots + off + 0x64) = (int)mmAlloc(0x800, 0x1a, 0);
        da = ((PlayerState*)inner)->moveSlots + off;
        objGetWeaponDa((u8*)obj, ((GameObject*)obj)->anim.seqId, (ObjWeaponDaTable*)(da + 0x60),
                       ((s16*)(base + 0x7fc))[*(s16*)((char*)da + 0x2)],
                       0);
        off += 0xb0;
    }
    fn_802AABE4(obj);
    gPlayerSelectedItem = 0x2d;
    gPlayerEggObject = 0;
    gb = (s16*)(base + 0x1b94);
    for (i = 0; (u32)i < 0xb; i++)
    {
        if (GameBit_Get(*gb) != 0)
        {
            ((PlayerState*)inner)->staffUnlockedFlags =
                (u8)(((PlayerState*)inner)->staffUnlockedFlags | (1 << i));
        }
        gb++;
    }
    if (((PlayerState*)inner)->characterId == 0)
    {
        ((PlayerState*)inner)->unk7DC = lbl_803E8168;
        ((PlayerState*)inner)->unk874 = lbl_803E816C;
    }
    else
    {
        ((PlayerState*)inner)->unk7DC = lbl_803E8170;
        ((PlayerState*)inner)->unk874 = lbl_803E8174;
    }
    gPlayerModelChain = (int)ObjModelChain_Alloc(&gPlayerModelChainConfig, 1);
    *(int*)((char*)obj + 0x108) = (int)fn_8029560C;
    if (gPlayerPendingHealth != 0)
    {
        int v = gPlayerPendingHealth;
        int hi;
        if (v < 0)
        {
            v = 0;
        }
        else if (v > 0x50)
        {
            v = 0x50;
        }
        *(s8*)(((PlayerState*)inner)->playerStatus + 1) = (s8)v;
        v = gPlayerPendingHealth;
        if (v < 0)
        {
            v = 0;
        }
        else
        {
            hi = *(s8*)(((PlayerState*)inner)->playerStatus + 1);
            if (v > hi)
            {
                v = hi;
            }
        }
        *(s8*)(((PlayerState*)inner)->playerStatus + 0) = (s8)v;
        gPlayerPendingHealth = 0;
    }
    gPlayerHeldObject = 0;
}

#pragma opt_strength_reduction off
int fn_802AB1D0(int obj)
{
    int cur;
    int objs;
    int best;
    int count;
    int i;
    f32 dist;
    f32 bestDist;
    f32 scale;
    s16 yaw;
    void* held;

    if (((GameObject*)obj)->objectFlags & 0x1000)
    {
        return 0;
    }
    held = *(void**)((char*)*(int*)&((GameObject*)obj)->extra + 0x2d0);
    if (held != NULL)
    {
        return (int)held;
    }
    best = 0;
    objs = (int)ObjGroup_GetObjects(8, &count);
    i = 0;
    bestDist = lbl_803E7EA4;
    for (; i < count;)
    {
        cur = ((int*)objs)[i++];
        if ((((GameObject*)cur)->anim.classId == 0x1c || ((GameObject*)cur)->anim.classId == 0x2a) &&
            ((GameObject*)cur)->anim.alpha == 0xff)
        {
            f32 dx = ((GameObject*)cur)->anim.worldPosX - ((GameObject*)obj)->anim.worldPosX;
            f32 dy = ((GameObject*)cur)->anim.worldPosY - ((GameObject*)obj)->anim.worldPosY;
            f32 dz = ((GameObject*)cur)->anim.worldPosZ - ((GameObject*)obj)->anim.worldPosZ;
            dist = dx * dx + dy * dy + dz * dz;
            if (dist < lbl_803E80E8)
            {
                if (dist <= lbl_803E7EA4)
                {
                    scale = (f32)((ObjAnimComponent*)cur)->modelInstance->group8RegistrationCount;
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
    return best;
}
#pragma opt_strength_reduction reset

int fn_802AE480(int obj, int inner, int state)
{
    f32 h;
    f32 lim;

    *(u32*)&((PlayerState*)inner)->flags360 |= 0x1000000LL;
    ((PlayerState*)state)->baddie.moveSpeed = lbl_803E7F20;
    h = ((GameObject*)obj)->anim.currentMoveProgress;
    if (h > lbl_803E7EFC && h < lbl_803E7F44 &&
        ((PlayerState*)state)->baddie.animSpeedC >
        *(f32*)((char*)((PlayerState*)inner)->moveParams + 0x1c) - lbl_803E7E9C &&
        ((PlayerState*)state)->baddie.inputMagnitude > lbl_803E7F2C &&
        ((PlayerState*)inner)->yawRateSigned >= 0x96)
    {
        ((ByteFlags*)((char*)inner + 0x3f0))->b40 = 1;
        ((ByteFlags*)((char*)inner + 0x3f0))->b80 = 0;
        ((PlayerState*)inner)->animSoundId = ((PlayerState*)inner)->altAnimSoundId;
        ((PlayerState*)state)->baddie.moveSpeed = lbl_803E8070;
        ObjAnim_SetCurrentMove(obj, *(s16*)((char*)((PlayerState*)inner)->moveAnimTable + 0x3a),
                               lbl_803E7EA4, 0);
        ObjAnim_SetCurrentEventStepFrames((ObjAnimComponent*)obj, 0x10);
        ((PlayerState*)inner)->unk858 = ((PlayerState*)inner)->yaw;
        ((PlayerState*)inner)->unk844 =
        (lbl_803E7F14 + (*(f32*)((char*)((PlayerState*)inner)->moveParams + 0x14) +
            ((PlayerState*)state)->baddie.animSpeedC)) / lbl_803E7F30;
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

void fn_80295E90(int obj, int mode)
{
    int inner = *(int*)&((GameObject*)obj)->extra;
    int oldModel;
    int newModel;
    void* tricky;

    objModelGetVecFn_800395d8(obj, 0);
    objModelGetVecFn_800395d8(obj, 9);
    if (mode != 0)
    {
        fn_80295CF4(obj, 0);
        ((ByteFlags*)((char*)inner + 0x3f3))->b08 = 1;
        tricky = getTrickyObject();
        if (tricky != NULL)
        {
            trickyImpress(tricky);
        }
        GameBit_Set(0xc30, 1);
        Sfx_PlayFromObject(obj, SFXmn_dimbos36);
        (*gBoneParticleEffectInterface)->spawnEffect((void*)obj, 0x801, NULL, 0x50, NULL);
        oldModel = Obj_GetActiveModel(obj);
        Obj_SetActiveModelIndex(obj, 2);
        newModel = Obj_GetActiveModel(obj);
        memcpy((void*)*(int*)((char*)newModel + 0x2c), (void*)*(int*)((char*)oldModel + 0x2c), 0x68);
        memcpy((void*)*(int*)((char*)newModel + 0x30), (void*)*(int*)((char*)oldModel + 0x30), 0x68);
        if (mode == 2)
        {
            ((ByteFlags*)((char*)inner + 0x3f4))->b80 = 1;
        }
    }
    else
    {
        fn_80295CF4(obj, 1);
        ((ByteFlags*)((char*)inner + 0x3f3))->b08 = 0;
        ((ByteFlags*)((char*)inner + 0x3f4))->b80 = 0;
        (*gBoneParticleEffectInterface)->spawnEffect((void*)obj, 0x801, NULL, 0x50, NULL);
        oldModel = Obj_GetActiveModel(obj);
        Obj_SetActiveModelIndex(obj, 1);
        newModel = Obj_GetActiveModel(obj);
        memcpy((void*)*(int*)((char*)newModel + 0x2c), (void*)*(int*)((char*)oldModel + 0x2c), 0x68);
        memcpy((void*)*(int*)((char*)newModel + 0x30), (void*)*(int*)((char*)oldModel + 0x30), 0x68);
        GameBit_Set(0xc30, 0);
        Sfx_PlayFromObject(obj, SFXmn_dimbos36);
    }
}

void fn_802AF7F8(int obj, int state)
{
    int inner;
    u8 result;
    void** p;
    int i;
    int v;
    if (fn_802A9C0C(obj, state, 0x2d) != 0)
    {
        GameBit_Set(0x965, 0);
        GameBit_Set(0x986, 0);
    }
    else
    {
        GameBit_Set(0x965, 1);
        GameBit_Set(0x986, 1);
    }
    if (fn_802A9C0C(obj, state, 0x5ce) != 0)
    {
        GameBit_Set(0x961, 0);
    }
    else
    {
        GameBit_Set(0x961, 1);
    }
    inner = *(int*)&((GameObject*)obj)->extra;
    if (((PlayerState*)state)->baddie.targetObj != NULL ||
        *(s16*)(((PlayerState *)inner)->playerStatus + 4) < 0xa ||
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
        GameBit_Set(0x969, 0);
    }
    else
    {
        GameBit_Set(0x969, 1);
    }
    if (fn_802A98FC(obj, state) != 0)
    {
        GameBit_Set(0x960, 0);
    }
    else
    {
        GameBit_Set(0x960, 1);
    }
    if (fn_802A97D0(obj, state) != 0)
    {
        GameBit_Set(0x964, 0);
    }
    else
    {
        GameBit_Set(0x964, 1);
    }
    if (fn_802A9A0C(obj, state) != 0)
    {
        GameBit_Set(0x96b, 0);
    }
    else
    {
        GameBit_Set(0x96b, 1);
    }
    switch (((PlayerState*)state)->animState)
    {
    case 0x2d:
        break;
    case 0x40:
        if ((((u32 (*)(int))getButtonsJustPressed)(0) & 0x200) != 0 &&
            ((ByteFlags*)((char*)state + 0x3f3))->b08 != 0 &&
            ((PlayerState*)state)->curAnimId != 0x44)
        {
            fn_80295E90(obj, 0);
            ((PlayerState*)state)->animState = -1;
            ((PlayerState*)state)->queuedItemCommand = -1;
            buttonDisable(0, 0x200);
        }
        ((PlayerState*)state)->stateTimer = ((PlayerState*)state)->stateTimer - timeDelta;
        if (((PlayerState*)state)->stateTimer <= lbl_803E7EA4)
        {
            if (*(s16*)((char*)*(int*)((char*)*(int*)&((GameObject*)obj)->extra + 0x35c) + 4) < 0)
            {
                v = 0;
            }
            else if (*(s16*)((char*)*(int*)((char*)*(int*)&((GameObject*)obj)->extra + 0x35c) + 4) > *(s16*)((char*)*(int*)((char*)*(int*)&((GameObject*)obj)->extra + 0x35c) + 6))
            {
                v = *(s16*)((char*)*(int*)((char*)*(int*)&((GameObject*)obj)->extra + 0x35c) + 6);
            }
            else
            {
                v = *(s16*)((char*)*(int*)((char*)*(int*)&((GameObject*)obj)->extra + 0x35c) + 4);
            }
            *(s16*)((char*)*(int*)((char*)*(int*)&((GameObject*)obj)->extra + 0x35c) + 4) = v;
            ((PlayerState*)state)->stateTimer = lbl_803E7EDC;
        }
        break;
    case 0x5ce:
        if (lbl_803DE42C != 0 && getCurSeqNo() != 0)
        {
            ((PlayerState*)state)->animState = -1;
            lbl_803DE42C = 0;
            p = gPlayerSpawnedObjects;
            for (i = 0; i < 7; i++)
            {
                if (p[i] != NULL)
                {
                    Obj_FreeObject((int)p[i]);
                    p[i] = NULL;
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

int fn_802A14F8(int obj, int state)
{
    int inner = *(int*)&((GameObject*)obj)->extra;
    f32 k;
    f32 pos[2];

    *(u32*)&((PlayerState*)inner)->flags360 &= ~2LL;
    *(u32*)&((PlayerState*)inner)->flags360 |= 0x2000LL;
    *(int*)((char*)state + 0x4) |= 0x100000;
    k = lbl_803E7EA4;
    ((PlayerState*)state)->baddie.animSpeedA = k;
    ((PlayerState*)state)->baddie.animSpeedB = k;
    *(int*)state |= 0x200000;
    ((GameObject*)obj)->anim.velocityX = k;
    ((GameObject*)obj)->anim.velocityZ = k;
    *(int*)((char*)state + 0x4) |= 0x8000000;
    ((GameObject*)obj)->anim.velocityY = k;
    if (*(s8*)&((PlayerState*)state)->baddie.moveJustStartedA != 0 && gPlayerPathObject != 0 &&
        ((ByteFlags*)((char*)inner + 0x3f4))->b40)
    {
        ((PlayerState*)inner)->staffActionRequest = 1;
        ((ByteFlags*)((char*)inner + 0x3f4))->b08 = 1;
    }
    switch (((GameObject*)obj)->anim.currentMove)
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
                (*gCameraInterface)->setMode(
                    0x4b, 1, 1, 8, pos, 0, 0xff);
            }
            ObjAnim_SetCurrentMove(obj, 0x41a, lbl_803E7EA4, 1);
            ((PlayerState*)inner)->targetYaw =
                getAngle(((PlayerState*)inner)->groundNormalX, ((PlayerState*)inner)->groundNormalZ);
            ((PlayerState*)inner)->yaw = ((PlayerState*)inner)->targetYaw;
            ((GameObject*)obj)->anim.localPosX = ((PlayerState*)inner)->unk58C;
            ((GameObject*)obj)->anim.localPosY = ((PlayerState*)inner)->savedPosY;
            ((GameObject*)obj)->anim.localPosZ = ((PlayerState*)inner)->unk594;
            ((PlayerState*)state)->baddie.moveSpeed = lbl_803E800C;
            break;
        }
    }
    fn_802AB5A4(obj, inner + 4, 5);
    return 0;
}

void fn_802972B4(int obj, int* flags, f32* p5, f32* p6, f32* p7, s16* p8)
{
    PlayerState* inner = ((GameObject*)obj)->extra;
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
            *flags |= *(int*)((inner->moveSlots + 8) +
                (u32)inner->moveSlotIndex * 0xb0 + idx * 4);
            *p6 = *(f32*)((inner->moveSlots + 0x70) +
                (u32)inner->moveSlotIndex * 0xb0 + inner->hitWindowIndex * 4);
            *p7 = *(f32*)((inner->moveSlots + 0x7c) +
                (u32)inner->moveSlotIndex * 0xb0 + inner->hitWindowIndex * 4);
            *p5 = *(f32*)((inner->moveSlots + 0x94) +
                (u32)inner->moveSlotIndex * 0xb0 + inner->hitWindowIndex * 4);
        }
        if (*(u8*)((inner->moveSlots + 0x88) +
            (u32)inner->moveSlotIndex * 0xb0) & 2)
        {
            if (inner->hitCount < inner->hitCountMax)
            {
                *p7 = *p6 = lbl_803E7EA4;
            }
        }
        if ((*(u8*)((inner->moveSlots + 0x88) +
                (u32)inner->moveSlotIndex * 0xb0) & 1) &&
            inner->cutsceneTimer >= lbl_803E7EF0)
        {
            *flags |= 0x80;
        }
    }
    mode = inner->unk8C1;
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

void fn_802B066C(int obj, int state)
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
        v = sqrtf(((GameObject*)obj)->anim.velocityZ * ((GameObject*)obj)->anim.velocityZ +
            (((GameObject*)obj)->anim.velocityX * ((GameObject*)obj)->anim.velocityX +
            ((GameObject*)obj)->anim.velocityY * ((GameObject*)obj)->anim.velocityY));
        ((PlayerState*)state)->knockbackDrainRate = v;
        v = ((PlayerState*)state)->knockbackDrainRate;
        ((PlayerState*)state)->knockbackDrainRate =
            (v < lbl_803E7EE0) ? lbl_803E7EE0 : ((v > lbl_803E8138) ? lbl_803E8138 : v);
    }
    ((PlayerState*)state)->knockbackTimer =
        ((PlayerState*)state)->knockbackTimer - timeDelta * ((PlayerState*)state)->knockbackDrainRate;
    if (((PlayerState*)state)->knockbackTimer <= (zero = lbl_803E7EA4))
    {
        if (Sfx_IsPlayingFromObject(obj, 0x394))
        {
            Sfx_StopFromObject(obj, 0x394);
            Sfx_PlayFromObject(obj, 0x395);
        }
        ((PlayerState*)state)->knockbackTimer = lbl_803E7EA4;
        return;
    }
    ((PlayerState*)state)->knockbackHitTimer = ((PlayerState*)state)->knockbackHitTimer - timeDelta;
    if (((PlayerState*)state)->knockbackHitTimer <= zero)
    {
        ObjPath_GetPointWorldPosition(obj, 0xb, &posWork[3], &posWork[4], &posWork[5], 0);
        ObjHits_RecordPositionHit(obj, 0, 0x1f, 1, -1, posWork[3], posWork[4], posWork[5]);
        ((PlayerState*)state)->knockbackHitTimer = lbl_803E8050;
    }
}

void playerDie(int obj)
{
    PlayerState* inner = ((GameObject*)obj)->extra;
    int setup;
    int variant;
    int i;
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
    ((ObjPlacement*)setup)->posX = ((GameObject*)obj)->anim.localPosX;
    ((ObjPlacement*)setup)->posY = ((GameObject*)obj)->anim.localPosY;
    ((ObjPlacement*)setup)->posZ = ((GameObject*)obj)->anim.localPosZ;
    inner->spawnedObject = Obj_SetupObject(setup, 5, -1, -1, 0);
    ((ByteFlags*)((char*)inner + 0x3f3))->b04 = 0;
    ((ByteFlags*)((char*)inner + 0x3f3))->b02 = 1;
    lbl_803DE42C = 0;
    for (i = 0; i < 7; i++)
    {
        if (gPlayerSpawnedObjects[i] != NULL)
        {
            Obj_FreeObject((int)gPlayerSpawnedObjects[i]);
            gPlayerSpawnedObjects[i] = NULL;
        }
    }
    if (gPlayerResource != NULL)
    {
        Resource_Release(gPlayerResource);
        gPlayerResource = NULL;
    }
    *(u32*)&((PlayerState*)inner)->flags360 &= ~0x400LL;
    AudioStream_StopCurrent();
    AudioStream_Play(0x51e0, AudioStream_StartPrepared);
}

#pragma opt_propagation off
void fn_802AABE4(int obj)
{
    s16* movp;
    f32* outp;
    int model;
    short i;
    f32 out2[2];
    f32 out1[5];

    model = (int)((ObjAnimComponent*)obj)->banks[((ObjAnimComponent*)obj)->bankIndex];

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
    ObjAnim_WriteStateWord((ObjAnimComponent*)obj, OBJANIM_STATE_INDEX_CURRENT,
                           OBJANIM_STATE_WORD_EVENT_COUNTDOWN, 0);
}
#pragma opt_propagation reset

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
                *(int*)&((PlayerState*)inner2)->baddie.targetObj = ObjGroup_FindNearestObject(3, obj, &dist);
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
            fn_8014C540(*(int*)&((PlayerState*)inner2)->baddie.targetObj, (char*)inner + 0x884, (char*)inner + 0x888,
                        (char*)inner + 0x88c);
        }
        else
        {
            ((PlayerState*)inner)->deferredItemCommand = -1;
        }
    }
}

int fn_8029A5E4(int obj, int state)
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
    if (lbl_803E7F30 == lbl_803DE45C || lbl_803E7FA0 == lbl_803DE45C ||
        lbl_803E7FA4 == lbl_803DE45C)
    {
        fn_802AA2B0(obj, state, inner->aimInputZ,
                    (f32)randomGetRange(-0xc8, 0xc8) / lbl_803E7F5C);
    }
    lbl_803DE45C = lbl_803DE45C - lbl_803E7EE0;
    if (lbl_803DE45C < lbl_803E7EA4)
    {
        *(int*)&((PlayerState*)state)->baddie.unk308 = (int)fn_8029A4A8;
        return 0x2d;
    }
    if (((PlayerState*)state)->baddie.targetObj == NULL)
    {
        if ((inner->buttonsJustPressed & 0x200) != 0 ||
            inner->curAnimId != 0x52)
        {
            *(int*)&((PlayerState*)state)->baddie.unk308 = (int)fn_8029A420;
            return 0x2c;
        }
    }
    return 0;
}

void fn_80296D20(int obj, void* arg)
{
    int state = (int)((GameObject*)obj)->extra;
    PlayerState* inner = ((GameObject*)obj)->extra;
    short type;

    if (((GameObject*)obj)->anim.parent == arg)
    {
        objHitDetectFn_80062e84(obj, 0, 1);
        type = ((PlayerState*)state)->baddie.controlMode;
        if (type == 0xa || type == 0xc)
        {
            *(int*)((char*)state + 4) &= ~0x100000;
            fn_802AB5A4(obj, (int)inner, 5);
            ((ByteFlags*)((char*)inner + 0x3f0))->b80 = 0;
            ((ByteFlags*)((char*)inner + 0x3f0))->b10 = 0;
            ((ByteFlags*)((char*)inner + 0x3f0))->b08 = 0;
            staffFn_80170380(gPlayerStaffObject, 2);
            ((ByteFlags*)((char*)inner + 0x3f0))->b02 = 0;
            *(u32*)&((PlayerState*)inner)->flags360 |= 0x800000LL;
            ObjHits_SyncObjectPositionIfDirty(obj);
            ((ByteFlags*)((char*)inner + 0x3f0))->b40 = 0;
            ((ByteFlags*)((char*)inner + 0x3f0))->b04 = 1;
            ((ByteFlags*)((char*)inner + 0x3f4))->b10 = 1;
            inner->isHoldingObject = 0;
            if (*(void**)((char*)inner + 0x7f8) != NULL)
            {
                short id = ((GameObject*)inner->heldObj)->anim.seqId;
                if (id == 0x3cf || id == 0x662)
                {
                    objThrowFn_80182504(inner->heldObj);
                }
                else
                {
                    objSaveFn_800ea774(inner->heldObj);
                }
                *(s16*)((char*)inner->heldObj + 6) &= ~0x4000;
                *(int*)((char*)inner->heldObj + 0xf8) = 0;
                inner->heldObj = 0;
            }
            (*(void (*)(int, int, int))(*(int*)(*gPlayerInterface + 0x14)))(obj, state, 2);
            *(int*)&((PlayerState*)state)->baddie.unk304 = (int)fn_802A514C;
        }
    }
}

void fn_802A81B8(int obj, int state, f32* out)
{
    f32 mag;
    u32 flag = (((PlayerState*)state)->flags3F1 >> 5) & 1;

    if (flag != 0 || ((PlayerState*)state)->baddie.targetObj != NULL)
    {
        out[0] = ((GameObject*)obj)->anim.velocityX;
        out[1] = lbl_803E7EA4;
        out[2] = ((GameObject*)obj)->anim.velocityZ;
        mag = PSVECMag(out);
        if (mag > lbl_803E7EA4)
        {
            extern void PSVECScale(f32 scale, f32* src, f32* dst);
            PSVECScale(lbl_803E7EE0 / mag, out, out);
        }
        else
        {
            out[0] = -mathSinf(gPlayerPi * (f32)((PlayerState*)state)->targetYaw /
                lbl_803E7F98);
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

int fn_8029B7B0(int obj, int state)
{
    PlayerState* inner = ((GameObject*)obj)->extra;
    int r = ((int (*)(int, int, int))fn_802AC7DC)(obj, state, (int)inner);
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
        ((GameObject*)obj)->anim.velocityX = z;
        ((GameObject*)obj)->anim.velocityY = z;
        ((GameObject*)obj)->anim.velocityZ = z;
    }
    setAButtonIcon(6);
    setBButtonIcon(0xa);
    switch (((GameObject*)obj)->anim.currentMove)
    {
    case 0x43d:
        if (*(s8*)&((PlayerState*)state)->baddie.moveDone != 0)
        {
            *(int*)&((PlayerState*)state)->baddie.unk308 = (int)fn_8029A4A8;
            return 0x2d;
        }
        break;
    case 0x448:
        if (((GameObject*)obj)->anim.currentMoveProgress > lbl_803E7E9C)
        {
            if (inner->staffGrown == 0)
            {
                Sfx_PlayFromObject(obj, SFXen_lflsh2_b);
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
            ObjAnim_SetCurrentMove(obj, 0x43d, lbl_803E7EA4, 0);
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
    if ((inner->buttonsJustPressed & 0x200) != 0 || inner->curAnimId != 0x52)
    {
        buttonDisable(0, 0x200);
        *(int*)&((PlayerState*)state)->baddie.unk308 = (int)fn_8029A420;
        return 0x2c;
    }
    return 0;
}

void fn_802B4ED8(int obj, int p2, int mode)
{
    PlayerState* inner = ((GameObject*)obj)->extra;
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
    if ((u32)((GameObject*)obj)->anim.alpha < 2)
    {
        return;
    }
    if (*(void**)((char*)inner + 0x7f0) != NULL)
    {
        if ((((GameObject*)obj)->objectFlags & 0x1000) != 0 ||
            arrayIndexOf(&lbl_803DC6C4, 2, inner->baddie.controlMode) != -1)
        {
            int p = inner->focusObject;
            (*(void (*)(int, f32))(*(int*)((char*)*(int*)*(int*)((char*)p + 0x68) + 0x50)))(
                p, ((GameObject*)obj)->anim.modelInstance->rootMotionScaleBase);
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
        ((GameObject*)obj)->anim.modelState->overrideWorldPosX = sx;
        ((GameObject*)obj)->anim.modelState->overrideWorldPosY = sy;
        ((GameObject*)obj)->anim.modelState->overrideWorldPosZ = sz;
    }
    ((GameObject*)obj)->anim.localPosY =
        ((GameObject*)obj)->anim.localPosY + inner->sinkOffsetY;
    m = (u32)(mode & 0xff);
    if (m == 1)
    {
        objRenderFuzz(obj);
    }
    else if (m == 2)
    {
        objRenderFn_800413d4(obj);
    }
    else if (m == 4)
    {
        fuzzRenderFn_800412dc(obj);
    }
    objSetMtxFn_800412d4(0);
    ((GameObject*)obj)->anim.localPosY =
        ((GameObject*)obj)->anim.localPosY - inner->sinkOffsetY;
    if ((*(u32*)&((PlayerState*)inner)->flags360 & 0x8000000) != 0)
    {
        ((GameObject*)obj)->anim.modelState->overrideWorldPosX = ((GameObject*)obj)->anim.localPosX;
        ((GameObject*)obj)->anim.modelState->overrideWorldPosY = ((GameObject*)obj)->anim.localPosY;
        ((GameObject*)obj)->anim.modelState->overrideWorldPosZ = ((GameObject*)obj)->anim.localPosZ;
        ((GameObject*)obj)->anim.localPosX = sx;
        ((GameObject*)obj)->anim.localPosY = sy;
        ((GameObject*)obj)->anim.localPosZ = sz;
    }
}

#pragma dont_inline on
void fn_802AA8D0(int obj)
{
    PlayerState* inner = ((GameObject*)obj)->extra;
    struct
    {
        u8 pad[0xc];
        f32 x;
        f32 y;
        f32 z;
    } buf;
    f32 base = lbl_803E80C4;
    f32 dy;
    int i;

    dy = base - inner->unk7D0;
    buf.y = dy;
    if (lbl_803DE478 < lbl_803E80D8)
    {
        inner->unk8CA = 0;
        return;
    }
    if (dy <= lbl_803E7EA4)
    {
        lbl_803DE478 = lbl_803DE478 - lbl_803E7F14 * timeDelta;
        return;
    }
    lbl_803DE478 = base;
    buf.y = dy + ((GameObject*)obj)->anim.localPosY;
    {
    f32 divisor = lbl_803E7ED8;
    for (i = 0; i < 10; i++)
    {
        buf.x = ((GameObject*)obj)->anim.localPosX + (f32)randomGetRange(-0x64, 0x64) / divisor;
        buf.z = ((GameObject*)obj)->anim.localPosZ + (f32)randomGetRange(-0x64, 0x64) / divisor;
        (*gPartfxInterface)->spawnObject(
            (void*)obj, randomGetRange(0, 2) + 0x3f4, &buf, 1, -1, NULL);
        (*gPartfxInterface)->spawnObject(
            (void*)obj, randomGetRange(0, 2) + 0x3f7, &buf, 1, -1, NULL);
    }
    }
}
#pragma dont_inline reset

int fn_8029C9C8(int obj, int state)
{
    PlayerState* inner = ((GameObject*)obj)->extra;
    f32 ratio, c, s, vx, vy, t0, curveOut;
    int r;

    if (*(s8*)&((PlayerState*)state)->baddie.moveJustStartedA != 0)
    {
        gPlayerSubState = 5;
    }
    r = fn_8029B9FC(obj, state, lbl_803E7EA4);
    if (r != 0)
    {
        return r;
    }
    {
        f32 x = (((PlayerState*)state)->baddie.inputMagnitude - lbl_803E7F14) / lbl_803E7F2C;
        ratio = (x < lbl_803E7EA4) ? lbl_803E7EA4 : ((x > lbl_803E7EE0) ? lbl_803E7EE0 : x);
    }
    {
        f32 ang = gPlayerPi * (f32)(int)
        inner->inputHeading / lbl_803E7F98;
        vx = inner->maxSpeed * (ratio * -mathSinf(ang));
    }
    {
        f32 ang = gPlayerPi * (f32)(int)
        inner->inputHeading / lbl_803E7F98;
        vy = inner->maxSpeed * (ratio * -mathCosf(ang));
    }
    {
        f32 a = interpolate(vx - inner->smoothVelX, lbl_803E7F44, timeDelta);
        f32 b = interpolate(vy - inner->smoothVelZ, lbl_803E7F44, timeDelta);
        inner->smoothVelX += a;
        inner->smoothVelZ += b;
    }
    ((PlayerState*)state)->baddie.animSpeedC =
        sqrtf(inner->smoothVelX * inner->smoothVelX +
            inner->smoothVelZ * inner->smoothVelZ);
    {
        f32 v = ((PlayerState*)state)->baddie.animSpeedC;
        f32 lo = *(f32*)inner->moveParams;
        ((PlayerState*)state)->baddie.animSpeedC =
            (v < lo) ? lo : ((v > inner->maxSpeed) ? inner->maxSpeed : v);
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
        f32 c8 = inner->smoothVelX;
        f32 cc = inner->smoothVelZ;
        ((PlayerState*)state)->baddie.animSpeedA +=
            interpolate(-cc * s - c8 * c - ((PlayerState*)state)->baddie.animSpeedA,
                        inner->targetAnimSpeed, timeDelta);
        ((PlayerState*)state)->baddie.animSpeedB +=
            interpolate(c8 * s - cc * c - ((PlayerState*)state)->baddie.animSpeedB,
                        inner->targetAnimSpeed, timeDelta);
    }
    t0 = ((GameObject*)obj)->anim.currentMoveProgress;
    {
        u8 phase = *(u8*)&((PlayerState*)inner)->gaitLevel;
        int idx = (u8)((s8)phase >> 1);
        if (((PlayerState*)state)->baddie.animSpeedC<gPlayerAnimSpeedThresholds[idx])
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
                *(u8*)&((PlayerState*)inner)->gaitLevel = phase - 4;
            }
        }
        else
        {
            if (((PlayerState*)state)->baddie.animSpeedC >= gPlayerAnimSpeedThresholds[idx + 1] &&
                (s8)phase < 8)
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
        f32 az = ((PlayerState*)state)->baddie.animSpeedB;
        f32 ax;
        if (az < lbl_803E7EA4)
        {
            az = -az;
        }
        ax = ((PlayerState*)state)->baddie.animSpeedA;
        if (ax < lbl_803E7EA4)
        {
            ax = -ax;
        }
        if (((int (*)(f32, int, f32*))ObjAnim_SampleRootCurvePhase)(((PlayerState*)state)->baddie.animSpeedC, obj,
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
    inner->targetYaw =
        (s16)(inner->targetYaw +
              (int)((f32)(int)inner->targetObjectBearing / lbl_803E7FC0)
    )
    ;
    inner->yaw = inner->targetYaw;
    *(u32*)&((PlayerState*)inner)->flags360 |= 0x2000000LL;
    fn_802ABFBC(obj, state, (int)inner);
    return 0;
}

extern int gameBitDecrement(int bit);
extern u8 objGetByteParam1C(int obj);
extern f32 lbl_803E8054;

int fn_802A418C(int obj, int state, f32 fv)
{
    PlayerState* inner = ((GameObject*)obj)->extra;
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
        c = ((s8 (*)(int, int, int, void*, int))fn_802A74A4)(obj, (int)inner, state, buf, 0x22);
    }
    else
    {
        c = ((s8 (*)(int, int, int, void*, int))fn_802A74A4)(obj, (int)inner, state, buf, -0x141);
    }
    if ((s8)c == -1)
    {
        inner->unk8C2 = -1;
        inner->unk8C3 = 0;
    }
    else if ((s8)c == inner->unk8C2)
    {
        int n = inner->unk8C3 + 1;
        inner->unk8C3 = n;
        if ((u8)n > 200)
        {
            inner->unk8C3 = 200;
        }
    }
    else
    {
        inner->unk8C2 = c;
        inner->unk8C3 = 0;
    }
    switch (inner->unk8C2)
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
        *(int*)&((PlayerState*)state)->baddie.unk308 = (int)fn_802A00C0;
        return 0x1c;
    case 10:
        *(int*)&((PlayerState*)state)->baddie.unk308 = 0;
        return 0x17;
    default:
    deflt:
        if (*(void**)((char*)inner + 0x7f8) == NULL &&
            ((ByteFlags*)((char*)inner + 0x3f4))->b40)
        {
            list = (int*)ObjGroup_GetObjects(0x41, &cnt41);
            for (i = 0; i < cnt41; i++)
            {
                int o = *list;
                gPlayerInteractTarget = o;
                if ((*(u8*)((char*)o + 0xaf) & 4) != 0 &&
                    (*(u8*)((char*)o + 0xaf) & 0x10) == 0)
                {
                    switch ((u8)objGetByteParam1C(o))
                    {
                    case 2:
                        setAButtonIcon(2);
                        if ((*(int*)&((PlayerState*)state)->baddie.unk31C & 0x100) != 0)
                        {
                            buttonDisable(0, 0x100);
                            *(int*)&((PlayerState*)state)->baddie.unk308 = (int)fn_80298924;
                            return 0x34;
                        }
                        break;
                    case 4:
                    case 5:
                        setAButtonIcon(0xe);
                        if ((*(int*)&((PlayerState*)state)->baddie.unk31C & 0x100) != 0)
                        {
                            buttonDisable(0, 0x100);
                            *(int*)&((PlayerState*)state)->baddie.unk308 = (int)fn_80298924;
                            return 0x36;
                        }
                        break;
                    case 3:
                        setAButtonIcon(2);
                        if ((*(int*)&((PlayerState*)state)->baddie.unk31C & 0x100) != 0)
                        {
                            buttonDisable(0, 0x100);
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
        ((void (*)(int, int*))ObjGroup_GetObjects)(0x20, &cnt20);
        GameBit_Set(0xeb5, !cnt20);
        if ((*gGameUIInterface)->isCurrentTriggerClear() != 0)
        {
            if ((*gGameUIInterface)->isEventReady(0x1ee) != 0)
            {
                char* found;
                s16* def = NULL;
                buttonDisable(0, 0x100);
                found = ((char *(*)(int, int, f32*))ObjGroup_FindNearestObject)(0xf, obj, &dist);
                if (found != NULL)
                {
                    def = *(s16**)((char*)found + 0x4c);
                }
                if (def != NULL && *def == 0x860 && (*(u8*)((char*)found + 0xaf) & 4) != 0)
                {
                    GameBit_Set(0x3f1, 1);
                    GameBit_Set(0x3d8, 1);
                    GameBit_Set(0x651, 1);
                }
                return 0;
            }
            if ((*gGameUIInterface)->isEventReady(0x953) != 0 &&
                gPlayerChildObject == NULL)
            {
                int player;
                void* att;
                buttonDisable(0, 0x100);
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
                    char* setup = (char*)Obj_AllocObjectSetup(0x24, 0x62d);
                    *(s16*)setup = 0x62d;
                    *(u8*)(setup + 0x4) = 2;
                    *(u8*)(setup + 0x6) = 0xff;
                    *(u8*)(setup + 0x5) = 1;
                    *(u8*)(setup + 0x7) = 0xff;
                    ((ObjPlacement*)setup)->posX = ((GameObject*)player)->anim.localPosX;
                    ((ObjPlacement*)setup)->posY = ((GameObject*)player)->anim.localPosY;
                    ((ObjPlacement*)setup)->posZ = ((GameObject*)player)->anim.localPosZ;
                    att = (void*)Obj_SetupObject((int)setup, 4, ((GameObject*)player)->anim.mapEventSlot,
                                                 -1, *(int*)&((GameObject*)player)->anim.parent);
                    gPlayerChildObject = att;
                }
                ((void (*)(int, void*, int))ObjLink_AttachChild)(obj, att, 1);
                (*gObjectTriggerInterface)
                    ->runSequence(0xd, (void*)obj, -1);
            }
        }
        if (inner->curAnimId != 0x44 &&
            (*gGameUIInterface)->isCurrentTriggerClear() != 0 &&
            (*gGameUIInterface)->isEventReady(0x13e) != 0 &&
            (((void (*)(int, int*))ObjGroup_GetObjects)(0x30, &cnt30), cnt30 == 0))
        {
            gameBitDecrement(0x13d);
            if (Obj_IsLoadingLocked() != 0)
            {
                char* setup = (char*)Obj_AllocObjectSetup(0x24, 0x43b);
                *(s16*)setup = 0x43b;
                *(u8*)(setup + 0x2) = 9;
                *(u8*)(setup + 0x4) = 2;
                *(u8*)(setup + 0x6) = 0xff;
                *(u8*)(setup + 0x5) = 1;
                *(u8*)(setup + 0x7) = 0xff;
                ((ObjPlacement*)setup)->posX = ((GameObject*)obj)->anim.localPosX;
                ((ObjPlacement*)setup)->posY = lbl_803E7F58 + ((GameObject*)obj)->anim.localPosY;
                ((ObjPlacement*)setup)->posZ = ((GameObject*)obj)->anim.localPosZ;
                *(u8*)(setup + 0x19) = 1;
                Obj_SetupObject((int)setup, 5, -1, -1, *(int*)&((GameObject*)obj)->anim.parent);
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
                    int in2 = *(int*)&((GameObject*)obj)->extra;
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
                    if (*(void**)((char*)inner + 0x7f8) != NULL ||
                        !((ByteFlags*)((char*)inner + 0x3f4))->b40 ||
                        ((ByteFlags*)((char*)inner + 0x3f0))->b20 ||
                        ((ByteFlags*)((char*)inner + 0x3f0))->b10)
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
                            (inner->cameraTargetObject != NULL &&
                                inner->targetObjectDist < lbl_803E8054 &&
                                inner->targetObjectBearingAbs < 0x4000 &&
                                ((PlayerState*)inner)->unk4B4 == 1))
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

extern int* gPlayerShadowInterface;
extern u8 gPlayerSurfacePfxModeTable[];
extern int lbl_803E7E68;
extern int lbl_803E7E6C;

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
            ((((GameObject*)obj)->objectFlags & 0x1000) != 0 ||
                arrayIndexOf(&lbl_803DC6C4, 2, ((PlayerState*)inner)->baddie.controlMode) != -1))
        {
            fn_802A9D0C(obj, inner, ((PlayerState*)inner)->focusObject, a, b, c, d, 1);
        }
        if (((PlayerState*)inner)->unk8CA == 1)
        {
            fn_802AAD44(obj);
        }
        (*(void (*)(int))(*(int*)(*gPlayerShadowInterface + 0x8)))(obj);
        if (*(void**)((char*)inner + 0x7f0) != NULL &&
            ((((GameObject*)obj)->objectFlags & 0x1000) != 0 ||
                arrayIndexOf(&lbl_803DC6C4, 2, ((PlayerState*)inner)->baddie.controlMode) != -1))
        {
            {
                int held = ((PlayerState*)inner)->focusObject;
                (*(void (*)(f32))*(int*)(*(int*)(*(int*)((char*)held + 0x68)) + 0x50))(
                    ((GameObject*)obj)->anim.modelInstance->rootMotionScaleBase);
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
        ((void (*)(int, int, int, int, int, f32))objRenderFn_8003b8f4)(obj, a, b, c, d, lbl_803E7EE0);
        ((GameObject*)obj)->anim.localPosY = ((GameObject*)obj)->anim.localPosY - ((PlayerState*)inner)->sinkOffsetY;
        if ((*(u32*)&((PlayerState*)inner)->flags360 & 0x8000000) != 0)
        {
            ((GameObject*)obj)->anim.localPosX = sx;
            ((GameObject*)obj)->anim.localPosY = sy;
            ((GameObject*)obj)->anim.localPosZ = sz;
        }
        if (flag != 0)
        {
            fn_802AAF80(obj, inner, a, b, c);
        }
        ((void (*)(int, int, int, int))ObjPath_GetPointWorldPositionArray)(obj, 6, 2,
                                                                           inner + 0x3c4);
        ObjPath_GetPointWorldPosition(obj, 0xb, (f32*)((char*)inner + 0x768),
                                      (f32*)((char*)inner + 0x76c),
                                      (f32*)((char*)inner + 0x770), 0);
        if (((int (*)(int, int))playerHasKrazoaSpirit)(1, 0) != 0)
        {
            if ((void*)gPlayerHeldObject == NULL)
            {
                int i;
                int m = *(int*)Obj_GetActiveModel(obj);
                for (i = 0; i < (int)(u32) * (u8*)((char*)m + 0xf8); i++)
                {
                    int op = ObjModel_GetRenderOp(m, i);
                    if (*(u8*)((char*)op + 0x41) == 2)
                    {
                        Shader_getLayer(op, 1);
                        gPlayerHeldObject = op;
                        *(u32*)((char*)op + 0x3c) |= 0x100000LL;
                        break;
                    }
                }
            }
        }
        else if ((void*)gPlayerHeldObject != NULL)
        {
            *(u32*)((char*)gPlayerHeldObject + 0x3c) &= ~0x100000LL;
            gPlayerHeldObject = 0;
        }
        {
            in2 = *(int*)&((GameObject*)obj)->extra;
            if (*(void**)((char*)in2 + 0x7f8) != NULL &&
                *(int*)((char*)*(int*)((char*)in2 + 0x7f8) + 0xf8) == 1)
            {
                ObjPath_GetPointWorldPosition(obj, 8, &px, &py, &pz, 0);
                ObjPath_GetPointWorldPosition(obj, 9, &qx, &qy, &qz, 0);
                px = lbl_803E7E98 * (px + qx);
                py = lbl_803E7E98 * (py + qy);
                pz = lbl_803E7E98 * (pz + qz);
                if (*(s16*)((char*)*(int*)((char*)in2 + 0x7f8) + 0x46) == 0x112)
                {
                    py = py + lbl_803E7ED4;
                }
                *(f32*)((char*)*(int*)((char*)in2 + 0x7f8) + 0x18) = px;
                *(f32*)((char*)*(int*)((char*)in2 + 0x7f8) + 0xc) = px;
                *(f32*)((char*)*(int*)((char*)in2 + 0x7f8) + 0x1c) = py;
                *(f32*)((char*)*(int*)((char*)in2 + 0x7f8) + 0x10) = py;
                *(f32*)((char*)*(int*)((char*)in2 + 0x7f8) + 0x20) = pz;
                *(f32*)((char*)*(int*)((char*)in2 + 0x7f8) + 0x14) = pz;
                if (*(s16**)&((GameObject*)obj)->anim.parent != NULL)
                {
                    *(s16*)*(int*)((char*)in2 + 0x7f8) =
                        **(s16**)&((GameObject*)obj)->anim.parent + ((GameObject*)obj)->anim.rotX;
                }
                else
                {
                    *(s16*)*(int*)((char*)in2 + 0x7f8) = *(s16*)((char*)in2 + 0x478);
                }
                (*(void (*)(int, int, int, int, int, int))*(int*)(
                    *(int*)(*(int*)((char*)*(int*)((char*)in2 + 0x7f8) + 0x68)) + 0x10))(
                    *(int*)((char*)in2 + 0x7f8), 0, 0, 0, 0, -1);
            }
        }
        if (((PlayerState*)inner)->knockbackTimer > lbl_803E7EA4 ||
            (((PlayerState*)inner)->pendingFxFlags & 2) != 0)
        {
            tbl[0] = lbl_803E7E68;
            tbl[1] = lbl_803E7E6C;
            objParticleFn_80099d84(obj, lbl_803E7E9C,
                                   tbl[(((PlayerState*)inner)->unk7A8 >> 5) & 7] & 0xff,
                                   lbl_803E7EE0, 0);
        }
        if ((((PlayerState*)inner)->pendingFxFlags & 1) != 0)
        {
            objParticleFn_80099d84(obj, lbl_803E7E9C, 8, lbl_803E7EE0, 0);
        }
        if (((PlayerState*)inner)->waterDepth > lbl_803E7EA4)
        {
            if ((((PlayerState*)inner)->pendingFxFlags & 4) != 0)
            {
                *(u32*)&((PlayerState*)inner)->flags360 |= 0x20000LL;
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
                    pfx.x = lbl_803E8018 * ((GameObject*)obj)->anim.velocityX + ((PlayerState*)inner)->fxOffsetX;
                    pfx.y = lbl_803E8018 * ((GameObject*)obj)->anim.velocityY + ((PlayerState*)inner)->fxOffsetY;
                    pfx.z = lbl_803E8018 * ((GameObject*)obj)->anim.velocityZ + ((PlayerState*)inner)->fxOffsetZ;
                    pfx.scale = lbl_803E7F18;
                    pfx.mode = gPlayerSurfacePfxModeTable[((PlayerState*)inner)->surfaceType];
                    for (n = 5; n != 0; n--)
                    {
                        (*gPartfxInterface)->spawnObject(
                            (void*)obj, 0x7e6, &pfx, 0x200001, -1, vel);
                    }
                    pfx.x = lbl_803E8018 * ((GameObject*)obj)->anim.velocityX + ((PlayerState*)inner)->fxOffset2X;
                    pfx.y = lbl_803E8018 * ((GameObject*)obj)->anim.velocityY + ((PlayerState*)inner)->fxOffset2Y;
                    pfx.z = lbl_803E8018 * ((GameObject*)obj)->anim.velocityZ + ((PlayerState*)inner)->fxOffset2Z;
                    pfx.scale = lbl_803E7F18;
                    pfx.mode = gPlayerSurfacePfxModeTable[((PlayerState*)inner)->surfaceType];
                    for (n = 5; n != 0; n--)
                    {
                        (*gPartfxInterface)->spawnObject(
                            (void*)obj, 0x7e6, &pfx, 0x200001, -1, vel);
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
                        (*gPartfxInterface)->spawnObject(
                            (void*)obj, 0x7e6, &pfx, 0x200001, -1, vel);
                    }
                    ((PlayerState*)inner)->pendingFxFlags = ((PlayerState*)inner)->pendingFxFlags & ~0x4;
                }
            }
        }
    }
}

extern u64 gPlayerLastSfxFrame;
extern u64 gPlayerFrameCounter;

typedef struct
{
    int a;
    int b;
} IntPair2;

extern int lbl_803E7E70;
extern f32 lbl_803E80FC;
extern f32 lbl_803E8100;

int fn_802AC7DC(int obj, int state, int inner, f32 fv)
{
    int r;
    int ok;
    IntPair2 camp;
    struct
    {
        s16 a;
        s16 b;
        s16 c;
        f32 d;
        f32 e;
        f32 f;
        f32 g;
    } pos;
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
    if (ok != 0 && (((PlayerState *)inner)->buttonsHeld & 0x40) != 0 && getCurSeqNo() == 0)
    {
        if (!((ByteFlags*)((char*)inner + 0x3f1))->b20 &&
            !((ByteFlags*)((char*)inner + 0x3f0))->b10)
        {
            f32 b;
            f32 a;
            a = ((PlayerState*)state)->baddie.animSpeedB;
            b = ((PlayerState*)state)->baddie.animSpeedA;
            pos.a = ((PlayerState*)inner)->yaw;
            pos.b = 0;
            pos.c = 0;
            pos.d = lbl_803E7EE0;
            pos.e = lbl_803E7EA4;
            pos.f = lbl_803E7EA4;
            pos.g = lbl_803E7EA4;
            setMatrixFromObjectPos(mtx, &pos.a);
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
            (*gCameraInterface)->setMode(
                0x52, 1, 0, 8, &camp, 0x1e, 0xff);
            if (gPlayerFrameCounter - gPlayerLastSfxFrame > 2)
            {
                Sfx_PlayFromObject(obj, 0x3e4);
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
            ((PlayerState*)inner)->curAnimId != 0x47 && getCurSeqNo() == 0)
        {
            (*gCameraInterface)->setMode(
                0x42, 0, 1, 0, NULL, 0x1e, 0xff);
            ((ByteFlags*)((char*)inner + 0x3f1))->b10 = 0;
        }
    }
    gPlayerFrameCounter = gPlayerFrameCounter + 1;
    if (!((ByteFlags*)((char*)inner + 0x3f0))->b20 &&
        ((PlayerState*)inner)->waterDepth > lbl_803E7FA0 &&
        *(f32*)((char*)state + 0x1b0) < lbl_803E80FC)
    {
        ((void (*)(int, int, int))fn_802AE83C)(obj, inner, state);
        return 0;
    }
    {
        if (!((ByteFlags*)((char*)inner + 0x3f0))->b20 &&
            !((ByteFlags*)((char*)inner + 0x3f0))->b08 &&
            !((ByteFlags*)((char*)inner + 0x3f0))->b04)
        {
            if (((ByteFlags*)((char*)inner + 0x3f1))->b01 ||
                *(f32*)((char*)state + 0x1b0) < lbl_803E7F58)
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
                *(u32*)&((PlayerState*)inner)->flags360 |= 0x800000LL;
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
                        objThrowFn_80182504(((PlayerState*)inner)->heldObj);
                    }
                    else
                    {
                        objSaveFn_800ea774(((PlayerState*)inner)->heldObj);
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
        if (!((ByteFlags*)((char*)inner + 0x3f0))->b20 &&
            lbl_803E7EA4 != ((PlayerState*)inner)->verticalVel)
        {
            *(int*)&((PlayerState*)state)->baddie.unk308 = 0;
            return 0x42;
        }
        if (!((ByteFlags*)((char*)inner + 0x3f0))->b20 &&
            !((ByteFlags*)((char*)inner + 0x3f0))->b08 &&
            !((ByteFlags*)((char*)inner + 0x3f0))->b04 &&
            ((PlayerState*)inner)->baddie.targetObj == NULL &&
            !((ByteFlags*)((char*)inner + 0x3f6))->b40 &&
            ((PlayerState*)inner)->baddie.controlMode != 0x26)
        {
            ok = 1;
        }
        else
        {
            ok = 0;
        }
        if (ok != 0 && *(void**)((char*)inner + 0x7f8) != NULL &&
            ((PlayerState*)inner)->isHoldingObject == 0)
        {
            if ((*(int*)((char*)state + 0x310) & 0x4000) != 0)
            {
                *(int*)&((PlayerState*)state)->baddie.unk308 = (int)fn_802A49A8;
                return 7;
            }
            *(int*)&((PlayerState*)state)->baddie.unk308 = (int)fn_802A49A8;
            return 8;
        }
        if (!((ByteFlags*)((char*)inner + 0x3f0))->b20 &&
            !((ByteFlags*)((char*)inner + 0x3f0))->b08 &&
            !((ByteFlags*)((char*)inner + 0x3f0))->b04 &&
            !((ByteFlags*)((char*)inner + 0x3f0))->b02 &&
            ((PlayerState*)inner)->baddie.targetObj == NULL &&
            !((ByteFlags*)((char*)inner + 0x3f6))->b40 &&
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
            r = ((int (*)(int, int, f32))fn_802A418C)(obj, state, fv);
            if (r != 0)
            {
                return r;
            }
        }
        if (((PlayerState*)state)->baddie.targetObj != NULL)
        {
            s16 t = ((PlayerState*)state)->baddie.controlMode;
            if (t != 0x24 && t != 0x25 && t != 0x26 &&
                !((ByteFlags*)((char*)inner + 0x3f6))->b20 &&
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
                if (((ByteFlags*)((char*)inner + 0x3f4))->b40 &&
                    !((ByteFlags*)((char*)inner + 0x3f0))->b20 &&
                    !((ByteFlags*)((char*)inner + 0x3f0))->b08 &&
                    !((ByteFlags*)((char*)inner + 0x3f0))->b04 &&
                    ((PlayerState*)inner)->curAnimId != 0x44 &&
                    *(void**)((char*)inner + 0x7f8) == NULL &&
                    ((PlayerState*)inner)->baddie.targetObj == NULL &&
                    !((ByteFlags*)((char*)inner + 0x3f6))->b40 &&
                    ((PlayerState*)inner)->baddie.controlMode != 0x26 &&
                    (((GameObject*)obj)->objectFlags & 0x1000) == 0 &&
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
                            objThrowFn_80182504(((PlayerState*)inner)->heldObj);
                        }
                        else
                        {
                            objSaveFn_800ea774(((PlayerState*)inner)->heldObj);
                        }
                        *(s16*)((char*)((PlayerState*)inner)->heldObj + 0x6) =
                            *(s16*)((char*)((PlayerState*)inner)->heldObj + 0x6) & ~0x4000;
                        *(int*)((char*)((PlayerState*)inner)->heldObj + 0xf8) = 0;
                        ((PlayerState*)inner)->heldObj = 0;
                    }
                    ((void (*)(int))ObjHits_MarkObjectPositionDirty)(obj);
                    *(int*)&((PlayerState*)state)->baddie.unk308 = (int)fn_802A514C;
                    return 3;
                }
            }
        }
        if (((ByteFlags*)((char*)inner + 0x3f0))->b08 ||
            ((ByteFlags*)((char*)inner + 0x3f0))->b04)
        {
            r = ((int (*)(int, int, int, void*, f32, u32))fn_802A74A4)(obj, inner, state, buf, fv, 0x14);
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
            r = ((int (*)(int, int, int, void*, f32, u32))fn_802A74A4)(obj, inner, state, buf, lbl_803E7EE0, 0x100);
            if (r == 5)
            {
                gPlayerCurrentMoveId = -1;
                *(int*)&((PlayerState*)state)->baddie.unk308 = 0;
                return 0xc;
            }
            if (((PlayerState*)inner)->waterDepth < lbl_803E7FC0 &&
                ((ByteFlags*)((char*)inner + 0x3f1))->b01)
            {
                ((ByteFlags*)((char*)inner + 0x3f0))->b20 = 0;
            }
        }
        return 0;
    }
}

extern f32 lbl_803E80C0;

int fn_802A87CC(int obj, char* cam, f32* out, f32* vec, f32 fa, f32 fb)
{
    void* parent;
    int verts;
    int wallHit;
    int tris;
    s8 mode;
    int inner;
    void** list;

    f32 x2;
    f32 x1;
    f32 z2;
    f32 z1;
    f32 y2;
    f32 y1;
    f32 dists[4];
    f32 z9c;
    f32 planes[8];

    mode = 0;
    inner = *(int*)&((GameObject*)obj)->extra;
    if (fa <= ((PlayerState*)inner)->baddie.animSpeedA * fb || fa <= lbl_803E80C0)
    {
        s8 st = *(s8*)((char*)cam + 0x50);
        if (st == 2 || st == 0x11)
        {
            mode = 4;
        }
        else if (((PlayerState*)inner)->baddie.animSpeedA >= lbl_803E80A0)
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
        char* cp;
        f32* pl;
        f32* dp;
        int i;
        f32* b6b8;
        f32* px2;
        f32* py2;
        f32* pz2;
        f32 thresh;
        wallHit = 0;
        if (parent != NULL)
        {
            tris = *(int*)((char*)*(int*)((char*)parent + 0x50) + 0x34);
            verts = *(int*)((char*)*(int*)((char*)parent + 0x50) + 0x3c);
        }
        else
        {
            tris = lbl_803DCF34;
            verts = lbl_803DCF38;
        }
        planes[0] = out[9];
        planes[1] = lbl_803E7EA4;
        planes[2] = -out[7];
        planes[3] = -(planes[0] * *(f32*)((char*)cam + 0x4) +
            planes[2] * ((GameObject*)cam)->anim.localPosZ);
        planes[4] = -planes[0];
        planes[5] = lbl_803E7EA4;
        planes[6] = -planes[2];
        planes[7] = -(planes[4] * ((GameObject*)cam)->anim.rootMotionScale +
            planes[6] * ((GameObject*)cam)->anim.worldPosX);
        i = 0;
        pl = planes;
        dp = dists;
        cp = cam;
        b6b8 = &lbl_803DC6B8;
        px2 = &x2;
        py2 = &y2;
        pz2 = &z2;
        thresh = lbl_803E7E98;
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
                    x1 = *(f32*)(verts + *(s16*)(tri + 4) * 0xc);
                    y1 = lbl_803E7EA4;
                    z1 = *(f32*)(verts + *(s16*)(tri + 4) * 0xc + 8);
                    x2 = *(f32*)(verts + *(s16*)(tri + 6) * 0xc);
                    y2 = lbl_803E7EA4;
                    z2 = *(f32*)(verts + *(s16*)(tri + 6) * 0xc + 8);
                    if (parent != NULL)
                    {
                        ((void (*)(f32*, f32*, f32*, void*))Obj_TransformLocalPointToWorld)(
                            &x1, &y1, &z1, parent);
                        ((void (*)(f32, f32, f32, f32*, f32*, f32*, void*))
                            Obj_TransformLocalPointToWorld)(x2, y2, z2, px2, py2, pz2, parent);
                    }
                    {
                        f32 dz = z2 - z1;
                        f32 dx = x1 - x2;
                        f32 inv = lbl_803E7EE0 / sqrtf(dz * dz + dx * dx);
                        dz = dz * inv;
                        dx = dx * inv;
                        if (dz * out[7] + dx * out[9] < lbl_803E7E98)
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
        }
        while (i < 2);
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
            out[0xb] = out[0xb] + ((lbl_803E7E98 + b6b8[1]) - dists[*(u8*)((char*)out + 0x5f)]) *
                planes[(u32) * (u8*)((char*)out + 0x5f) * 4];
            out[0xd] = out[0xd] + ((lbl_803E7E98 + b6b8[1]) - dists[*(u8*)((char*)out + 0x5f)]) *
                planes[(u32) * (u8*)((char*)out + 0x5f) * 4 + 2];
        }
        {
            f32 e2 = lbl_803E7E98;
            out[0x11] = -(out[7] * (e2 + lbl_803DC6C0) - out[0xb]);
            out[0x13] = -(out[9] * (e2 + lbl_803DC6C0) - out[0xd]);
        }
        {
            f32 f = lbl_803E7F10;
            out[0x14] = f * out[7] + out[0xb];
            out[0x16] = f * out[9] + out[0xd];
        }
        out[1] = ((GameObject*)cam)->anim.localPosX +
            *(f32*)((char*)cam + 0x48) *
            (((GameObject*)cam)->anim.localPosY - ((GameObject*)cam)->anim.localPosX);
        dists[2] = out[0x14];
        dists[3] = out[1];
        z9c = out[0x16];
        ((void (*)(f32*, f32*, f32*, int))Obj_TransformLocalPointToWorld)(
            &dists[2], &dists[3], &z9c, *(int*)&((GameObject*)obj)->anim.parent);
        {
            int cnt = hitDetectFn_80065e50(obj, dists[2], dists[3], z9c, (int***)&list, 0, 0x201);
            if (cnt != 0)
            {
                f32 best = lbl_803E80AC;
                f32 best2 = best;
                int bi = -1;
                int i2 = 0;
                void** pp = list;
                for (; cnt > 0; cnt--)
                {
                    f32 dy = dists[3] - *(f32*)*pp;
                    if (dy >= lbl_803E7EA4 && (best < lbl_803E7EA4 || dy < best))
                    {
                        best = dy;
                        bi = i2;
                    }
                    if (((f32*)*pp)[2] > lbl_803E80B0 && dy >= lbl_803E7EA4 &&
                        (best2 < lbl_803E7EA4 || dy < best2))
                    {
                        best2 = dy;
                    }
                    pp++;
                    i2++;
                }
                if (best < lbl_803E80C4 && bi != -1 && ((f32*)list[bi])[2] <= lbl_803E80B0 &&
                    ((f32*)list[bi])[2] > lbl_803E7EB0)
                {
                    return 0;
                }
                if (best2 < lbl_803E80C4)
                {
                    return 0;
                }
            }
        }
        dists[2] = out[0x11];
        dists[3] = out[1];
        z9c = out[0x13];
        ((void (*)(f32*, f32*, f32*, int))Obj_TransformLocalPointToWorld)(
            &dists[2], &dists[3], &z9c, *(int*)&((GameObject*)obj)->anim.parent);
        if (hitDetectFn_800658a4(obj, out + 0x12, 0x205, dists[2], dists[3], z9c) == 0)
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
        if (((GameObject*)obj)->anim.parent != NULL)
        {
            ((void (*)(f32, f32, f32, f32*, f32*, f32*))Obj_TransformLocalPointToWorld)(
                out[0xb], out[0xc], out[0xd], out + 0xb, out + 0xc, out + 0xd);
            ((void (*)(f32, f32, f32, f32*, f32*, f32*, int))Obj_TransformLocalPointToWorld)(
                out[0x11], out[0x12], out[0x13], out + 0x11, out + 0x12, out + 0x13,
                *(int*)&((GameObject*)obj)->anim.parent);
            ((void (*)(f32, f32, f32, f32*, f32*, f32*, int))Obj_TransformLocalPointToWorld)(
                out[0x14], out[0x15], out[0x16], out + 0x14, out + 0x15, out + 0x16,
                *(int*)&((GameObject*)obj)->anim.parent);
            ((PlayerState*)inner)->unk5AC =
                ((PlayerState*)inner)->unk5AC + *(f32*)(*(int*)&((GameObject*)obj)->anim.parent + 0x10);
            ((PlayerState*)inner)->unk5B0 =
                ((PlayerState*)inner)->unk5B0 + *(f32*)(*(int*)&((GameObject*)obj)->anim.parent + 0x10);
        }
        *(u8*)((char*)out + 0x61) = 1;
        if (parent != NULL && (((ObjAnimComponent*)parent)->modelInstance->flags & 0x8000) == 0)
        {
            *(void**)((char*)inner + 0x4c4) = parent;
        }
        else
        {
            ((PlayerState*)inner)->groundObject = 0;
        }
    }
    else
    {
        ((PlayerState*)inner)->groundObject = 0;
    }
    return mode;
}

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
    f32 bx, ax, bz, az, by, ay;
    f32 threshold;
    EmitPlane planes[2];

    ((PlayerState*)b)->groundObject = 0;
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
        tbl2 = lbl_803DCF38;
    }
    planes[0].nx = -*(f32*)((char*)d + 0x24);
    planes[0].ny = lbl_803E7EA4;
    planes[0].nz = *(f32*)((char*)d + 0x1c);
    planes[0].d = -(planes[0].nx * *(f32*)((char*)c + 0x4) +
        planes[0].nz * *(f32*)((char*)c + 0x14));
    planes[1].nx = -planes[0].nx;
    planes[1].ny = lbl_803E7EA4;
    planes[1].nz = -planes[0].nz;
    planes[1].d = -(planes[1].nx * *(f32*)((char*)c + 0x8) +
        planes[1].nz * *(f32*)((char*)c + 0x18));
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
                (((s8) * (s8*)((char*)face + 0x3) & 0x3f) == 6 ||
                 ((s8) * (s8*)((char*)face + 0x3) & 0x3f) == 0x10))
            {
                ax = ((f32*)tbl2)[*(s16*)((char*)face + 0x4) * 3];
                ay = lbl_803E7EA4;
                az = ((f32*)tbl2)[*(s16*)((char*)face + 0x4) * 3 + 2];
                bx = ((f32*)tbl2)[*(s16*)((char*)face + 0x6) * 3];
                by = lbl_803E7EA4;
                bz = ((f32*)tbl2)[*(s16*)((char*)face + 0x6) * 3 + 2];
                if (hit != NULL)
                {
                    ((void (*)(f32*, f32*, f32*, void*))Obj_TransformLocalPointToWorld)(&ax, &ay, &az, hit);
                    ((void (*)(f32*, f32*, f32*, void*))Obj_TransformLocalPointToWorld)(pbx, pby, pbz, hit);
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
    }
    while (i < 2);
    *(f32*)((char*)d + 0x2c) = *(f32*)((char*)e + 0x0);
    *(f32*)((char*)d + 0x30) = *(f32*)((char*)e + 0x4);
    *(f32*)((char*)d + 0x34) = *(f32*)((char*)e + 0x8);
    {
        f32 e2 = lbl_803E7E98;
        *(f32*)((char*)d + 0x44) =
            -(*(f32*)((char*)d + 0x1c) * (e2 + lbl_803DC6C0) - *(f32*)((char*)d + 0x2c));
        *(f32*)((char*)d + 0x4c) =
            -(*(f32*)((char*)d + 0x24) * (e2 + lbl_803DC6C0) - *(f32*)((char*)d + 0x34));
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
        *(f32*)((char*)c + 0x48) * (*(f32*)((char*)c + 0x40) - *(f32*)((char*)c + 0x3c)) +
        *(f32*)((char*)c + 0x3c);
    *(u8*)((char*)d + 0x5e) = *(u8*)((char*)c + 0x50);
    *(u8*)((char*)d + 0x61) = 1;
    if (((int (*)(int, f32, f32, f32, char*, int))hitDetectFn_800658a4)(
            a, *(f32*)((char*)d + 0x44), *(f32*)((char*)d + 0x4), *(f32*)((char*)d + 0x4c),
            (char*)d + 0x48, 0x205) != 0)
    {
        return 0;
    }
    *(f32*)((int)d + 0x48) = *(f32*)((char*)d + 0x4) - *(f32*)((int)d + 0x48);
    if ((s8) * (s8*)((char*)c + 0x50) != 0x10)
    {
        *(f32*)((char*)d + 0x8) = ((GameObject*)a)->anim.previousLocalPosY;
        *(f32*)((char*)d + 0x0) = *(f32*)((char*)d + 0x4) - *(f32*)((char*)d + 0x8);
        if ((((PlayerState*)b)->flags3F1 & 1) != 0u)
        {
            if (hit != NULL && (((ObjAnimComponent*)hit)->modelInstance->flags & 0x8000) == 0)
            {
                ((PlayerState*)b)->groundObject = (int)hit;
            }
            if (*(f32*)((char*)d + 0x0) <= lbl_803E80C8)
            {
                if (*(f32*)((char*)d + 0x0) > lbl_803E80C4)
                {
                    return 2;
                }
            }
            if (*(f32*)((char*)d + 0x0) <= lbl_803E80C4 &&
                *(f32*)((char*)d + 0x0) >= lbl_803E8018)
            {
                return 3;
            }
            return 0;
        }
        else
        {
            f32 q = *(f32*)((char*)d + 0x4) -
            (*(f32*)((char*)c + 0x48) * (*(f32*)((char*)c + 0x10) - *(f32*)((char*)c + 0xc)) +
                *(f32*)((char*)c + 0xc));
            if (!(*(f32*)((char*)d + 0x0) >= lbl_803E7ED8) ||
                !(*(f32*)((char*)d + 0x0) <= lbl_803E7FBC) ||
                !(q >= lbl_803E80C4))
            {
                return 0;
            }
            if (hit != NULL && (((ObjAnimComponent*)hit)->modelInstance->flags & 0x8000) == 0)
            {
                ((PlayerState*)b)->groundObject = (int)hit;
            }
            return 6;
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
            ((PlayerState*)b)->groundObject = (int)hit;
        }
        return 3;
    }
}
#pragma peephole reset

int fn_802A2918(int obj, int state, f32 fv)
{
    int flag;
    PlayerState* innerV = ((GameObject*)obj)->extra;
    PlayerState* inner = ((GameObject*)obj)->extra;

    *(u32*)&((PlayerState*)innerV)->flags360 &= ~0x2LL;
    *(u32*)&((PlayerState*)innerV)->flags360 |= 0x2000LL;
    *(int*)((char*)state + 0x4) |= 0x100000;
    {
        f32 z = lbl_803E7EA4;
        ((PlayerState*)state)->baddie.animSpeedA = z;
        ((PlayerState*)state)->baddie.animSpeedB = z;
        *(int*)((char*)state + 0x0) |= 0x200000;
        ((GameObject*)obj)->anim.velocityX = z;
        ((GameObject*)obj)->anim.velocityZ = z;
        *(int*)((char*)state + 0x4) |= 0x8000000;
        ((GameObject*)obj)->anim.velocityY = z;
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
        u16 sfxId = inner->characterId == 0 ? 0x398 : 0x1d;
        Sfx_PlayFromObject(obj, sfxId);
    }
    if ((*(int*)&((PlayerState*)state)->baddie.eventFlags & 1) != 0)
    {
        switch (inner->unk546)
        {
        case 4:
            Sfx_PlayFromObject(obj, SFXdrak_roar1);
            break;
        default:
            Sfx_PlayFromObject(obj, SFXdn_rexroarlng11);
            break;
        }
    }
    if (*(s8*)&((PlayerState*)state)->baddie.moveJustStartedA != 0)
    {
        extern s16 fn_802A71E0(int obj, int a, int b, int* p6, int* p7, f32 e, f32 f, int n, int flags);
        s16* tbl;
        int sel;
        struct
        {
            f32 vx;
            f32 sp1c;
            f32 vy;
            f32 vz;
        } vb;
        ObjHits_MarkObjectPositionDirty(obj);
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
            vb.vx = -inner->unk50C;
            vb.vy = -inner->unk514;
            vb.vz = -inner->unk518;
        }
        else
        {
            vb.vx = inner->unk50C;
            vb.vy = inner->unk514;
            vb.vz = inner->unk518;
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
            inner->targetYaw = (s16)(inner->targetYaw + delta);
            inner->yaw = inner->targetYaw;
        }
        inner->unk504 = ((GameObject*)obj)->anim.localPosX;
        inner->unk508 = ((GameObject*)obj)->anim.localPosZ;
        ((GameObject*)obj)->anim.localPosX = inner->unk52C;
        ((GameObject*)obj)->anim.localPosZ = inner->unk534;
        sel = inner->unk4FC >= *(f32*)&lbl_803E7EA4 ? 0 : 4;
        tbl = flag ? lbl_80332F88 : lbl_80332F78;
        inner->unk544 =
            fn_802A71E0(obj, tbl[sel], tbl[sel + 2], (int*)inner->unk538, (int*)&vb.vx,
                        lbl_803E7EA4, ((PlayerState*)state)->baddie.moveSpeed, 2, 9);
        {
            int f9 = 0x34;
            if (flag)
            {
                f9 |= 0x40;
            }
            fn_802A71E0(obj, tbl[sel], tbl[sel + 1], (int*)inner->unk538,
                        (int*)((char*)inner + 0x51c), lbl_803E7EA4,
                        ((PlayerState*)state)->baddie.moveSpeed, 0, f9);
        }
        fn_802A71E0(obj, tbl[sel + 2], tbl[sel + 3], (int*)inner->unk538,
                    (int*)((char*)inner + 0x51c), lbl_803E7EA4,
                    ((PlayerState*)state)->baddie.moveSpeed, 0, 0x1a);
        inner->climbTargetY =
            inner->climbStepHeight * (f32)(int)
        inner->climbStep +
            inner->climbBaseY;
        inner->climbStartY = ((GameObject*)obj)->anim.localPosY;
        {
            int joint = (int)Player_GetActiveModel(obj);
            f32 camBuf[2], scratch, jp[3];
            ObjModel_SampleJointTransform(joint, 0, 0, lbl_803E7EE0, ((GameObject*)obj)->anim.rootMotionScale,
                                          jp, &scratch);
            lbl_803DE438 = ((GameObject*)obj)->anim.localPosY + jp[0];
            lbl_803DE43C = inner->climbTargetY + lbl_803DAF88[1];
            camBuf[0] = inner->unk4E8;
            camBuf[1] = inner->climbBaseY;
            if (inner->curAnimId != 0x48 && inner->curAnimId != 0x47)
            {
                (*gCameraInterface)->setMode(
                    0x4b, 1, 1, 8, camBuf, 0, 0);
            }
        }
    }
    else
    {
        if (((GameObject*)obj)->anim.currentMoveProgress > lbl_803E7FF4)
        {
            ((int (*)(f32, f32, int, int))Object_ObjAnimAdvanceMove)(
                ((PlayerState*)state)->baddie.moveSpeed, fv, obj, 0);
            *(int*)&((PlayerState*)state)->baddie.unk308 = (int)fn_8029FFD0;
            return 0x10;
        }
    }
    if (((GameObject*)obj)->anim.currentMoveProgress >= lbl_803E7F18)
    {
        f32 g = lbl_803E8028 * (lbl_803E802C * ((GameObject*)obj)->anim.currentMoveProgress - lbl_803E7F18);
        f32 c;
        c = (g < lbl_803E7EA4) ? lbl_803E7EA4 : ((g > lbl_803E7EE0) ? lbl_803E7EE0 : g);
        ((GameObject*)obj)->anim.localPosY = c * (lbl_803DE43C - lbl_803DE438) + inner->climbStartY;
    }
    ((void (*)(int, int, int, int))ObjAnim_WriteStateWord)
        (obj, OBJANIM_STATE_INDEX_CURRENT, OBJANIM_STATE_WORD_PREV_EVENT_STATE, 0);
    ((void (*)(int, int, int, int))ObjAnim_WriteStateWord)
        (obj, OBJANIM_STATE_INDEX_ACTIVE, OBJANIM_STATE_WORD_PREV_EVENT_STATE, 0);
    ((void (*)(int, int, int, int))ObjAnim_WriteStateWord)
    (obj, OBJANIM_STATE_INDEX_ACTIVE, OBJANIM_STATE_WORD_EVENT_COUNTDOWN,
     inner->unk544);
    ((int (*)(f32, f32, int, int))Object_ObjAnimAdvanceMove)(
        ((PlayerState*)state)->baddie.moveSpeed, fv, obj, 0);
    (*gCameraInterface)->overridePos(
        ((GameObject*)obj)->anim.localPosX,
        ((GameObject*)obj)->anim.currentMoveProgress *
        (inner->climbTargetY - ((GameObject*)obj)->anim.localPosY) +
        ((GameObject*)obj)->anim.localPosY,
        ((GameObject*)obj)->anim.localPosZ);
    fn_802AB5A4(obj, (int)inner, 5);
    return 0;
}

int fn_8029FA24(int obj, int state, f32 fv)
{
    char* base = (char*)lbl_80332EC0;
    PlayerState* inner = ((GameObject*)obj)->extra;
    int sub = inner->focusObject;
    f32 wpos[3];

    inner->flags360 &= ~0x2LL;
    inner->flags360 |= 0x2000;
    *(int*)((char*)state + 0x4) |= 0x100000;
    {
        f32 z = lbl_803E7EA4;
        ((PlayerState*)state)->baddie.animSpeedA = z;
        ((PlayerState*)state)->baddie.animSpeedB = z;
        *(int*)((char*)state + 0x0) |= 0x200000;
        ((GameObject*)obj)->anim.velocityX = z;
        ((GameObject*)obj)->anim.velocityZ = z;
    }
    *(s8*)&((PlayerState*)state)->baddie.physicsActive = 0;
    if (*(s8*)&((PlayerState*)state)->baddie.moveJustStartedA != 0)
    {
        *(s16*)((char*)state + 0x278) = 0x16;
        inner->stateHandler = 0;
    }
    ObjHits_DisableObject(obj);
    ((GameObject*)obj)->anim.velocityY = lbl_803E7EA4;
    if (*(s8*)&((PlayerState*)state)->baddie.moveJustStartedA != 0)
    {
        int sel;
        int joint;
        f32 scratch;
        f32 j1[3];
        f32 j0[3];

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
            if (coordsToMapCell(((GameObject*)obj)->anim.localPosX, ((GameObject*)obj)->anim.localPosZ) == 0x13)
            {
                GameBit_Set(0xf0a, 1);
            }
            (*gCameraInterface)->setMode(
                0x45, 1, 0, 0, NULL, 0, 0xff);
            break;
        case 0x38c:
            inner->moveSequence = (int)(base + 0x3f0);
            inner->moveSequenceFlags = 3;
            (*gCameraInterface)->setFocus((void*)sub, 0);
            (*gCameraInterface)->setMode(
                0x45, 1, 0, 0, NULL, 0, 0xff);
            break;
        case 0x419:
            inner->moveSequence = (int)(base + 0x420);
            (*gCameraInterface)->setMode(
                0x53, 1, 0, 0, NULL, 0x2d, 0xff);
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
        ObjAnim_SetCurrentMove(obj, ((s16*)inner->moveSequence)[sel],
                               lbl_803E7EA4, 4);
        joint = (int)Player_GetActiveModel(obj);
        ObjModel_SampleJointTransform(joint, 0, 0, lbl_803E7EA4, ((GameObject*)obj)->anim.rootMotionScale,
                                      j0, &scratch);
        ObjModel_SampleJointTransform(joint, 0, 0, lbl_803E7EE0, ((GameObject*)obj)->anim.rootMotionScale,
                                      j1, &scratch);
        (*(void (*)(int, void*, void*, void*))(*(int*)(*(int*)(*(int*)((char*)sub + 0x68)) + 0x28)))(
            sub, &wpos[0], &wpos[1], &wpos[2]);
        wpos[0] = wpos[0] - ((GameObject*)obj)->anim.localPosX;
        wpos[1] = wpos[1] - ((GameObject*)obj)->anim.localPosY;
        wpos[2] = wpos[2] - ((GameObject*)obj)->anim.localPosZ;
        inner->warpStartX = ((GameObject*)obj)->anim.localPosX;
        inner->warpStartY = ((GameObject*)obj)->anim.localPosY;
        inner->warpStartZ = ((GameObject*)obj)->anim.localPosZ;
        inner->warpDeltaX = wpos[0];
        inner->warpDeltaY = wpos[1] - j1[1];
        inner->warpDeltaZ = wpos[2];
        ((GameObject*)obj)->anim.flags |= 8;
        ((GameObject*)obj)->anim.modelState->flags |= OBJ_MODEL_STATE_SHADOW_FADE_OUT;
        ((GameObject*)obj)->anim.modelState->shadowAlphaStep = 0;
        ((PlayerState*)state)->baddie.moveSpeed = lbl_803E7FD8;
    }
    {
        ((GameObject*)obj)->anim.localPosX =
            ((GameObject*)obj)->anim.currentMoveProgress * inner->warpDeltaX +
            inner->warpStartX;
        ((GameObject*)obj)->anim.localPosY =
            ((GameObject*)obj)->anim.currentMoveProgress * inner->warpDeltaY +
            inner->warpStartY;
        ((GameObject*)obj)->anim.localPosZ =
            ((GameObject*)obj)->anim.currentMoveProgress * inner->warpDeltaZ +
            inner->warpStartZ;
        (*(void (*)(int, void*, void*, void*))(*(int*)(*(int*)(*(int*)((char*)sub + 0x68)) + 0x34)))(
            sub, &wpos[0], &wpos[1], &wpos[2]);
        (*gCameraInterface)->overridePos(
            ((GameObject*)obj)->anim.currentMoveProgress * (wpos[0] - inner->warpStartX) +
            inner->warpStartX,
            ((GameObject*)obj)->anim.currentMoveProgress * (wpos[1] - inner->warpStartY) +
            inner->warpStartY,
            ((GameObject*)obj)->anim.currentMoveProgress * (wpos[2] - inner->warpStartZ) +
            inner->warpStartZ);
    }
    if (*(s8*)&((PlayerState*)state)->baddie.moveJustStartedA == 0 && *(s8*)&((PlayerState*)state)->baddie.moveDone !=
        0)
    {
        ObjAnim_SetCurrentMove(obj, *(s16*)inner->moveSequence, lbl_803E7EA4, 1);
        (*(void (*)(int, int))(*(int*)(*(int*)(*(int*)((char*)sub + 0x68)) + 0x3c)))(sub, 2);
        if (arrayIndexOf((s16*)(base + 0x160), 4, *(s16*)((char*)sub + 0x46)) != -1)
        {
            *(int*)&((PlayerState*)state)->baddie.unk308 = (int)fn_8029F67C;
            return 0x1b;
        }
        *(int*)&((PlayerState*)state)->baddie.unk308 = (int)fn_8029F67C;
        return 0x19;
    }
    return 0;
}

void fn_802ABFBC(int obj, int state, int inner)
{
    void* sub;
    f32 dx, dy, dz;
    f32 x1, y1, z1;
    f32 pos2[3];

    ((PlayerState*)inner)->headPitch =
        (f32)((PlayerState*)inner)->headPitch * powfBitEstimate(lbl_803E7FF4, timeDelta);
    sub = ((PlayerState*)inner)->cameraTargetObject;
    if (sub != NULL && *(u8*)(*(int*)((char*)sub + 0x50) + 0x58) != 0)
    {
        int d;
        int adj;

        ObjPath_GetPointWorldPosition(obj, 5, &x1, &y1, &z1, 0);
        if (objModelGetVecFn_800395d8((int)sub, 0) != 0)
        {
            objPosFn_80039510((int)sub, 0, pos2);
        }
        else
        {
            pos2[0] = *(f32*)((char*)sub + 0xc);
            pos2[1] = *(f32*)((char*)sub + 0x10);
            pos2[2] = ((PlayerState*)sub)->baddie.posX;
        }
        dx = pos2[0] - x1;
        dy = pos2[1] - y1;
        dz = pos2[2] - z1;

        d = getAngle(-dy, sqrtf(dx * dx + dz * dz)) & 0xffff;
        d -= (u16)((PlayerState*)inner)->headYaw;
        if (d > 0x8000) d -= 0xffff;
        if (d < -0x8000) d += 0xffff;
        adj = (int)((f32)d * lbl_803E7EB4);
        ((PlayerState*)inner)->headYaw =
            (f32)adj * timeDelta + (f32) * (s16*)((int)inner + 0x4d6);

        d = getAngle(-dx, -dz) & 0xffff;
        d -= (u16)((PlayerState*)inner)->targetYaw;
        if (d > 0x8000) d -= 0xffff;
        if (d < -0x8000) d += 0xffff;
        if (d < -0x1c70) d = -0x1c70;
        else if (d > 0x1c70) d = 0x1c70;
        d -= (u16)((PlayerState*)inner)->bodyLeanAngle;
        if (d > 0x8000) d -= 0xffff;
        if (d < -0x8000) d += 0xffff;
        adj = (int)((f32)d * lbl_803E7EB4);
        ((PlayerState*)inner)->bodyLeanAngle =
            (f32)adj * timeDelta + (f32) * (s16*)((int)inner + 0x4d4);
        ((PlayerState*)inner)->bodyLeanHalf = ((PlayerState*)inner)->bodyLeanAngle / 2;
    }
    else
    {
        ((PlayerState*)inner)->headYaw =
            (f32)((PlayerState*)inner)->headYaw * powfBitEstimate(lbl_803E7F1C, timeDelta);
    }
}

int fn_8029CF30(int obj, int state, f32 fv)
{
    PlayerState* inner = ((GameObject*)obj)->extra;
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

    r = fn_8029B9FC(obj, state, fv);
    if (r != 0)
    {
        return r;
    }

    t = (((PlayerState*)state)->baddie.inputMagnitude - lbl_803E7F14) / lbl_803E7F2C;
    ang = (t < lbl_803E7EA4) ? lbl_803E7EA4 : ((t > lbl_803E7EE0) ? lbl_803E7EE0 : t);
    vx = inner->maxSpeed *
        (ang * -mathSinf(gPlayerPi * (f32)inner->inputHeading / lbl_803E7F98));
    vy = inner->maxSpeed *
        (ang * -mathCosf(gPlayerPi * (f32)inner->inputHeading / lbl_803E7F98));
    dx = interpolate(vx - inner->smoothVelX, lbl_803E7F44, timeDelta);
    dy = interpolate(vy - inner->smoothVelZ, lbl_803E7F44, timeDelta);
    inner->smoothVelX += dx;
    inner->smoothVelZ += dy;
    ((PlayerState*)state)->baddie.animSpeedC =
        sqrtf(inner->smoothVelX * inner->smoothVelX +
            inner->smoothVelZ * inner->smoothVelZ);
    ((PlayerState*)state)->baddie.animSpeedC =
        (((PlayerState*)state)->baddie.animSpeedC < lbl_803E7EA4)
            ? lbl_803E7EA4
            : ((((PlayerState*)state)->baddie.animSpeedC > inner->maxSpeed)
                   ? inner->maxSpeed
                   : ((PlayerState*)state)->baddie.animSpeedC);

    if (*(f32*)&((PlayerState*)state)->baddie.trackedObj >= lbl_803E7FC8 &&
        ((PlayerState*)state)->baddie.inputMagnitude >= lbl_803E7FC8 &&
        ((PlayerState*)state)->baddie.animSpeedC >= gPlayerAnimSpeedThresholds[1])
    {
        *(int*)&((PlayerState*)state)->baddie.unk308 = (int)fn_8029C8C8;
        return 0x26;
    }

    if (((GameObject*)obj)->anim.currentMove != 0x8c)
    {
        ObjAnim_SetCurrentMove(obj, 0x8c, lbl_803E7EA4, 0);
        if (((PlayerState*)state)->baddie.unk276 == 0x39)
        {
            ObjAnim_SetCurrentEventStepFrames((ObjAnimComponent*)obj, 8);
        }
        ((PlayerState*)state)->baddie.moveSpeed = lbl_803E7F84;
    }

    inner->targetYaw += (int)((f32)inner->targetObjectBearing / lbl_803E7FC0);
    inner->yaw = inner->targetYaw;
    *(u32*)&((PlayerState*)inner)->flags360 |= 0x2000000LL;
    fn_802ABFBC(obj, state, (int)inner);
    return 0;
}

void fn_80295334(int a, int b, f32* vec, int c, int mode, f32 angle)
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

void fn_802AA014(int obj)
{
    PlayerState* inner = ((GameObject*)obj)->extra;
    int slot = Camera_GetCurrentViewSlot();

    if (Obj_IsLoadingLocked())
    {
        int setup = Obj_AllocObjectSetup(0x24, 0x14b);
        void* o;
        f32 v[3];

        *(u8*)((char*)setup + 4) = 2;
        *(u8*)((char*)setup + 5) = 1;
        *(u8*)((char*)setup + 6) = 0xff;
        *(u8*)((char*)setup + 7) = 0xff;
        ((ObjPlacement*)setup)->posX = *(f32*)((char*)slot + 0xc);
        ((ObjPlacement*)setup)->posY = *(f32*)((char*)slot + 0x10);
        ((ObjPlacement*)setup)->posZ = *(f32*)((char*)slot + 0x14);
        Sfx_PlayFromObject(obj, SFXmammoth_suck);
        o = (void*)Obj_SetupObject(setup, 5, -1, -1, 0);
        if (o != NULL)
        {
            f32 fov, cot, aspect, ycomp, xcomp, len;
            f32 scale;
            f32 mix;
            int res, h2, hw;

            *(s16*)((char*)o + 6) |= 0x2000;
            res = getScreenResolution();
            hw = res >> 17;
            *(s16*)((char*)o + 0) = *(s16*)((char*)slot + 0);
            fov = (gPlayerPi * (Camera_GetFovY() * lbl_803E80D4)) / lbl_803E7F98;
            cot = mathSinf(fov);
            cot = lbl_803E7F5C * (cot / mathCosf(fov));
            aspect = Camera_GetAspectRatio();
            h2 = (u16)res >> 1;
            ycomp = cot * -(((inner->aimScreenY - (f32)h2) / (f32)h2) * aspect);
            xcomp = cot * ((inner->aimScreenX - (f32)hw) / (f32)hw);
            len = sqrtf(lbl_803E80AC + (ycomp * ycomp + xcomp * xcomp));
            v[0] = ycomp / len;
            v[1] = xcomp / len;
            v[2] = lbl_803E7F5C / len;
            Matrix_TransformVector(fn_8000E814(), v, v);
            scale = lbl_803E80D8;
            *(f32*)((char*)o + 0x24) = v[0] * scale;
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

#pragma dont_inline on
void playerUpdatePathEffectCountdown(int obj, int inner)
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
            buf.z = lbl_803E7EC8 * (f32)(int)
            randomGetRange(t + 4, t + 8);
            PSMTXMultVec(mtx, &buf.x, outvec);
            buf.x = lbl_803E7EA4;
            buf.y = lbl_803E7ECC;
            buf.z = lbl_803E7ED0;
            ObjPath_GetPointWorldPosition(obj, 0xa, &buf.x, &buf.y, &buf.z, 1);
            (*gPartfxInterface)->spawnObject(
                (void*)obj, 0x7e5, &buf, 0x200001, -1, outvec);
        }
        ((PlayerState*)inner)->stepDustCount -= 1;
    }
}
#pragma dont_inline reset

void fn_802AAF80(int obj, int inner, int a, int b, int c)
{
    int v;
    if (gPlayerPathObject != NULL && (((u32)((PlayerState*)inner)->flags3F4 >> 6) & 1) != 0)
    {
        (*gModgfxInterface)->renderEffects((void*)a, b, c, 1, gPlayerPathObject);
    }
    if (((PlayerState*)inner)->pendingBoneEffectId != 0)
    {
        (*gBoneParticleEffectInterface)->spawnEffect((void*)obj, ((PlayerState*)inner)->pendingBoneEffectId,
                                                     NULL, 0x64, NULL);
    }
    ((PlayerState*)inner)->pendingBoneEffectId = 0;
    if (((PlayerState*)inner)->unk8CA == 1)
    {
        fn_802AA8D0(obj);
    }
    if ((*gSkyInterface)->getBlendStateBit20(2) != 0)
    {
        playerUpdatePathEffectCountdown(obj, inner);
    }
    v = ((PlayerState*)inner)->flags360;
    if ((v & 0x60000u) != 0)
    {
        ((PartFxSpawnParams*)gPlayerPartFxParams)->posX = ((GameObject*)obj)->anim.localPosX;
        ((PartFxSpawnParams*)gPlayerPartFxParams)->posY = ((GameObject*)obj)->anim.localPosY;
        ((PartFxSpawnParams*)gPlayerPartFxParams)->posZ = ((GameObject*)obj)->anim.localPosZ;
        if ((v & 0x40000u) != 0)
        {
            (*gPartfxInterface)->spawnObject(
                (void*)obj, 0x427, gPlayerPartFxParams, 0x200001, -1, NULL);
            (*gPartfxInterface)->spawnObject(
                (void*)obj, 0x427, gPlayerPartFxParams, 0x200001, -1, NULL);
            (*gPartfxInterface)->spawnObject(
                (void*)obj, 0x427, gPlayerPartFxParams, 0x200001, -1, NULL);
        }
        if ((((PlayerState*)inner)->flags360 & 0x20000u) != 0)
        {
            (*gWaterfxInterface)->spawnSplashBurst(
                (void*)obj, ((GameObject*)obj)->anim.localPosX,
                (((GameObject*)obj)->anim.localPosY + ((PlayerState*)inner)->waterDepth) -
                lbl_803E7F10,
                ((GameObject*)obj)->anim.localPosZ, lbl_803E7FFC);
            ((void (*)(f32, f32, f32, s16, f32, int))(*gWaterfxInterface)->spawnRipple)(
                ((GameObject*)obj)->anim.localPosX,
                ((GameObject*)obj)->anim.localPosY + ((PlayerState*)inner)->waterDepth,
                ((GameObject*)obj)->anim.localPosZ, 0, lbl_803E80E4, 2);
            *(u32*)&((PlayerState*)inner)->flags360 &= ~0x20000LL;
        }
    }
}

void fn_802AE650(int obj, int state, int p3)
{
    f32 v;
    u32 b;
    f32 ee0;

    (*(void (*)(int, int, f32, int))(*(int*)(*gPlayerInterface + 0x20)))(obj, p3, timeDelta, 1);
    if (((GameObject*)obj)->anim.currentMoveProgress >=
        (ee0 = lbl_803E7EE0) - lbl_803E7F50 * ((PlayerState*)p3)->baddie.moveSpeed)
    {
        ((PlayerState*)p3)->baddie.animSpeedA =
            ((PlayerState*)state)->unk844 *
            ((lbl_803E7F14 + *(f32*)((char*)((PlayerState*)state)->moveParams + 0x14)) -
                ((PlayerState*)p3)->baddie.animSpeedA) +
            *(f32*)&((PlayerState*)p3)->baddie.animSpeedA;
        ((PlayerState*)p3)->baddie.animSpeedC = ((PlayerState*)p3)->baddie.animSpeedA;
        ((PlayerState*)state)->unk844 =
            lbl_803E7EFC * timeDelta + ((PlayerState*)state)->unk844;
        v = ((PlayerState*)state)->unk844;
        ((PlayerState*)state)->unk844 =
            (v < lbl_803E7EA4) ? lbl_803E7EA4 : ((v > ee0) ? ee0 : v);
    }
    if ((*(int*)&((PlayerState*)p3)->baddie.eventFlags & 0x200) != 0)
    {
        doRumble(lbl_803E7F10);
        Sfx_PlayFromObject(obj, 0x3cd);
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
    if (((GameObject*)obj)->anim.currentMoveProgress >= lbl_803E7EE0)
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
        ObjAnim_SetCurrentMove(obj, ((s16*)gPlayerMoveTableA)[(s8) * (u8*)((char*)state + 0x8cc)],
                               lbl_803E7EA4, 0);
        ObjAnim_SetCurrentEventStepFrames((ObjAnimComponent*)obj, 1);
    }
}

void fn_802AA2B0(int obj, int state, f32 unused, f32 yoff)
{
    int slot = Camera_GetCurrentViewSlot();
    int setup;
    f32 x1, y1, z1, x0, y0, z0;
    f32 dx, dy, dz, len;

    if (Obj_IsLoadingLocked() != 0)
    {
        Sfx_PlayFromObject(0, SFXmammoth_suck);
        setup = Obj_AllocObjectSetup(0x24, 0x655);
        *(u8*)((char*)setup + 4) = 2;
        *(u8*)((char*)setup + 5) = 1;
        *(u8*)((char*)setup + 6) = 0xff;
        *(u8*)((char*)setup + 7) = 0xff;
        ObjPath_GetPointWorldPosition((int)gPlayerPathObject, 0, &x0, &y0, &z0, 0);
        ((ObjPlacement*)setup)->posX = x0 + yoff;
        ((ObjPlacement*)setup)->posY = y0 + yoff;
        ((ObjPlacement*)setup)->posZ = z0 + yoff;
        setup = Obj_SetupObject(setup, 5, -1, -1, 0);
        if ((void*)setup != NULL)
        {
            ObjPath_GetPointWorldPosition((int)gPlayerPathObject, 0, &x0, &y0, &z0, 0);
            ObjPath_GetPointWorldPosition((int)gPlayerPathObject, 1, &x1, &y1, &z1, 0);
            dx = x0 - x1;
            dy = y0 - y1;
            dz = z0 - z1;
            len = sqrtf(dx * dx + dy * dy + dz * dz);
            dx = dx / len;
            dy = dy / len;
            dz = dz / len;
            *(s16*)((char*)setup + 0) = (s16)getAngle(dx, dz);
            ((ObjPlacement*)setup)->unk02 = (s16)(-getAngle(dy, sqrtf(dx * dx + dz * dz)));
            ((ObjPlacement*)setup)->posX = ((ObjPlacement*)setup)->posX * lbl_803E7EF0;
            arwprojectile_placeForward(setup, lbl_803E7ED8);
            arwprojectile_setLifetime(setup, 0x32);
            if (slot == 1)
            {
                arwprojectile_createLinkedEffect(setup, 1);
            }
        }
    }
}

void fn_802AED2C(int obj, int state, int p3)
{
    u16 sound;
    u32 b;

    if (((PlayerState*)state)->staffGrown != 0)
    {
        ObjAnim_SetCurrentMove(obj, 0x47f, lbl_803E7EA4, 0);
    }
    else
    {
        ObjAnim_SetCurrentMove(obj, 0x47b, lbl_803E7EA4, 0);
    }
    ((PlayerState*)p3)->baddie.moveSpeed = lbl_803E7F20;
    ((PlayerState*)state)->targetYaw = ((PlayerState*)state)->yaw;
    ((PlayerState*)state)->unk844 = lbl_803E7EA4;
    ((ByteFlags*)((char*)state + 0x3f0))->b10 = 1;
    ((ByteFlags*)((char*)state + 0x3f0))->b80 = 0;
    staffFn_80170380(gPlayerStaffObject, 2);
    ((ByteFlags*)((char*)state + 0x3f0))->b02 = 0;
    *(u32*)&((PlayerState*)state)->flags360 |= 0x800000LL;
    ObjHits_SyncObjectPositionIfDirty(obj);
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
            objThrowFn_80182504(((PlayerState*)state)->heldObj);
        }
        else
        {
            objSaveFn_800ea774(((PlayerState*)state)->heldObj);
        }
        *(s16*)((char*)((PlayerState*)state)->heldObj + 6) &= ~0x4000;
        *(int*)((char*)((PlayerState*)state)->heldObj + 0xf8) = 0;
        ((PlayerState*)state)->heldObj = 0;
    }
    b = (((PlayerState*)state)->flags3F1 >> 5) & 1;
    if (b != 0)
    {
        short t = ((GameObject*)obj)->anim.rotX;
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
        Sfx_PlayFromObject(obj, sound);
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
        Sfx_PlayFromObject(obj, sound);
    }
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
    (*(void (*)(int, int, f32, int))(*(int*)(*gPlayerInterface + 0x20)))(obj, state, fv, 1);
    return 0;
}

int Lightfoot_UpdateTargetAnimationCycle(int obj, int state, f32 fv)
{
    int inner = *(int*)&((GameObject*)obj)->extra;
    int a4 = *(int*)((char*)inner + 0x40c);
    void* p = ((PlayerState*)state)->baddie.targetObj;
    if (p != NULL)
    {
        fn_8003B0D0(obj, (int)p, inner + 0x3ac, 0x19);
    }
    if (*(s8*)&((PlayerState*)state)->baddie.moveDone != 0 || *(s8*)&((PlayerState*)state)->baddie.moveJustStartedA !=
        0)
    {
        int q = *(int*)&((GameObject*)obj)->anim.placementData;
        ((GameObject*)obj)->anim.localPosX = *(f32*)((char*)q + 0x8);
        ((GameObject*)obj)->anim.localPosZ = *(f32*)((char*)q + 0x10);
        *(u16*)((char*)a4 + 0x24) += 1;
        if (gPlayerMoveTableC[*(u16*)((char*)a4 + 0x24)] == -1)
        {
            *(u16*)((char*)a4 + 0x24) = 0;
        }
        ObjAnim_SetCurrentMove(obj, gPlayerMoveTableC[*(u16*)((char*)a4 + 0x24)], lbl_803E8180, 0);
    }
    ((PlayerState*)state)->baddie.moveSpeed = gPlayerMoveSpeedTable[*(u16*)((char*)a4 + 0x24)];
    (*(void (*)(int, int, f32, int))(*(int*)(*gPlayerInterface + 0x20)))(obj, state, fv, 1);
    return 0;
}

int Lightfoot_UpdateButtonTimingChallenge(int obj, int state, f32 fv)
{
    EmitCtrlTbl* t = (EmitCtrlTbl*)lbl_80334EE8;
    int inner = *(int*)&((GameObject*)obj)->extra;
    int data = *(int*)((char*)inner + 0x40c);
    void* p = ((PlayerState*)state)->baddie.targetObj;
    if (p != NULL)
    {
        fn_8003B0D0(obj, (int)p, inner + 0x3ac, 0x19);
    }
    if (((GameObject*)obj)->unkF8 == 0)
    {
        *(u16*)((char*)data + 0x1a) = *(u16*)((char*)data + 0x1c);
        *(u16*)((char*)data + 0x1c) = *(u16*)((char*)data + 0x18);
        *(u16*)((char*)data + 0x18) += (int)(lbl_803E81AC * timeDelta);
    }
    if (*(u16*)((char*)data + 0x24) < 4)
    {
        int v = (s16)(int)(lbl_803E81B0 *
            mathSinf(gPlayerPi2 * (f32) * (u16*)((char*)data + 0x18) /
                lbl_803E81B8));
        int w = (u16)(int)(lbl_803E81B0 * t->scales[*(u8*)((char*)data + 0x2d)]);
        if (((GameObject*)obj)->unkF8 == 0)
        {
            if ((s16) * (u16*)((char*)data + 0x1c) * (s16) * (u16*)((char*)data + 0x18) < 0)
            {
                Sfx_PlayFromObject(0, 0x44c);
            }
        }
        setAButtonIcon(6);
        fearTestMeterSetRange(0x60, (u8)w, v);
        if ((((u32 (*)(int))getButtonsJustPressed)(0) & 0x100) && ((GameObject*)obj)->unkF8 == 0)
        {
            int a = v < 0 ? -v : v;
            if (a <= w)
            {
                Sfx_PlayFromObject(0, SFXsp_lf_mutter4);
                ((GameObject*)obj)->unkF8 = 2;
            }
            else
            {
                Sfx_PlayFromObject(0, 0x487);
                ((GameObject*)obj)->unkF8 = 3;
            }
            fn_8011F6D4(0);
        }
    }
    else
    {
        fn_8011F6D4(0);
    }
    if (*(s8*)&((PlayerState*)state)->baddie.moveDone != 0 || *(s8*)&((PlayerState*)state)->baddie.moveJustStartedA !=
        0)
    {
        int q;
        if (*(s8*)&((PlayerState*)state)->baddie.moveJustStartedA != 0)
        {
            int i;
            *(u8*)((char*)data + 0x2d) = 0;
            for (i = 0; i < 8; i++)
            {
                if (GameBit_Get(t->bits[i]) != 0)
                {
                    *(u8*)((char*)data + 0x2d) += 1;
                }
            }
            *(u16*)((char*)data + 0x18) = (u16)randomGetRange(0, 0xffff);
            *(u16*)((char*)data + 0x1c) = *(u16*)((char*)data + 0x18);
            *(u16*)((char*)data + 0x1a) = *(u16*)((char*)data + 0x1c);
            fearTestMeterSetRange(0x60,
                                  (u8)(int)(lbl_803E81BC * t->scales[*(u8*)((char*)data + 0x2d)]),
                                  (int)(lbl_803E81B0 *
                                      mathSinf(gPlayerPi2 * (f32) * (u16*)((char*)data + 0x18) /
                                          lbl_803E81B8)));
            fn_8011F6D4(1);
            setAButtonIcon(6);
        }
        q = *(int*)&((GameObject*)obj)->anim.placementData;
        if (*(s8*)&((PlayerState*)state)->baddie.moveJustStartedA != 0)
        {
            *(u16*)((char*)data + 0x24) = 0;
            ((GameObject*)obj)->anim.localPosX = *(f32*)((char*)q + 0x8);
            ((GameObject*)obj)->anim.localPosZ = *(f32*)((char*)q + 0x10);
        }
        else
        {
            *(u16*)((char*)data + 0x24) += 1;
        }
        if (t->anims[*(u16*)((char*)data + 0x24)] == -1)
        {
            *(u16*)((char*)data + 0x24) = 0;
            ((GameObject*)obj)->anim.localPosX = *(f32*)((char*)q + 0x8);
            ((GameObject*)obj)->anim.localPosZ = *(f32*)((char*)q + 0x10);
            GameBit_Set(*(s16*)((char*)q + 0x1a), 1);
            GameBit_Set(*(s16*)((char*)q + 0x30), 0);
            return 3;
        }
        ObjAnim_SetCurrentMove(obj, t->anims[*(u16*)((char*)data + 0x24)], lbl_803E8180, 0);
    }
    ((PlayerState*)state)->baddie.moveSpeed = t->blends[*(u16*)((char*)data + 0x24)];
    (*(void (*)(int, int, f32, int))(*(int*)(*gPlayerInterface + 0x20)))(obj, state, fv, 1);
    return 0;
}

int Lightfoot_UpdateCompletionInteraction(int obj, int state)
{
    int data = *(int*)&((GameObject*)obj)->anim.placementData;
    int inner = *(int*)&((GameObject*)obj)->extra;
    int a4 = *(int*)((char*)inner + 0x40c);
    if (*(s8*)&((PlayerState*)state)->baddie.moveJustStartedB != 0 || *(s8*)&((PlayerState*)state)->baddie.moveDone !=
        0)
    {
        if (GameBit_Get(*(s16*)((char*)data + 0x1c)) != 0)
        {
            *(u8*)((char*)inner + 0x404) |= 1;
        }
        if ((*(u8*)((char*)inner + 0x404) & 1) != 0)
        {
            if (((PlayerState*)state)->baddie.controlMode != 3)
            {
                *(u8*)((char*)a4 + 0x2c) = 4;
                (*(void (*)(int, int, int))(*(int*)(*gPlayerInterface + 0x14)))(obj, state, 3);
            }
            if (*(u8*)((char*)a4 + 0x2c) != 0)
            {
                *(u8*)((char*)a4 + 0x2c) -= 1;
                if (*(u8*)((char*)a4 + 0x2c) == 0)
                {
                    GameBit_Set(*(s16*)((char*)data + 0x1a), 1);
                    GameBit_Set(*(s16*)((char*)data + 0x30), 0);
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
                if (GameBit_Get(*(s16*)((char*)data + 0x30)) != 0)
                {
                    (*(void (*)(int, int, int))(*(int*)(*gPlayerInterface + 0x14)))(obj, state, 1);
                }
            }
        }
    }
    return 0;
}

int Lightfoot_UpdateAnimationCycle(int obj, int state, f32 fv)
{
    int inner = *(int*)&((GameObject*)obj)->extra;
    void* p = ((PlayerState*)state)->baddie.targetObj;
    int a4;
    s16* moves;
    f32* blends;
    if (p != NULL)
    {
        fn_8003B0D0(obj, (int)p, inner + 0x3ac, 0x19);
    }
    a4 = *(int*)((char*)inner + 0x40c);
    moves = *(s16**)((char*)a4 + 0);
    blends = *(f32**)((char*)a4 + 4);
    if (*(s8*)&((PlayerState*)state)->baddie.moveJustStartedA != 0 || *(s8*)&((PlayerState*)state)->baddie.moveDone !=
        0)
    {
        *(u8*)((char*)a4 + 0x2c) = 0;
        *(u16*)((char*)a4 + 0x24) += 1;
        if (moves[*(u16*)((char*)a4 + 0x24)] == -1)
        {
            *(u16*)((char*)a4 + 0x24) = 0;
        }
        if (*(s8*)&((PlayerState*)state)->baddie.moveJustStartedA != 0)
        {
            ((GameObject*)obj)->anim.currentMoveProgress = (f32)randomGetRange(0, 0x63) / lbl_803E817C;
            ObjAnim_SetCurrentMove(obj, moves[*(u16*)((char*)a4 + 0x24)], ((GameObject*)obj)->anim.currentMoveProgress,
                                   0);
        }
        else
        {
            ObjAnim_SetCurrentMove(obj, moves[*(u16*)((char*)a4 + 0x24)], lbl_803E8180, 0);
        }
    }
    ((PlayerState*)state)->baddie.moveSpeed = blends[*(u16*)((char*)a4 + 0x24)];
    (*(void (*)(int, int, f32, int))(*(int*)(*gPlayerInterface + 0x20)))(obj, state, fv, 0);
    return 0;
}

void fn_802AB38C(int a, int b, int c)
{
    switch (c)
    {
    case 0x2d:
        gPlayerSelectedItem = 0x2d;
        break;
    case 0x958:
        gPlayerSelectedItem = 0x958;
        break;
    case 0x5ce:
        gPlayerSelectedItem = 0x5ce;
        break;
    case 0x957:
        gPlayerInteractTarget = *(int*)&((PlayerState*)b)->cameraTargetObject;
        (*(void (*)(int, int, int))(*(int*)(*gPlayerInterface + 0x14)))(a, b, 0x32);
        *(int*)&((PlayerState*)b)->baddie.unk304 = (int)fn_802994A4;
        break;
    case 0x107:
    case 0xc55:
        (*(void (*)(int, int, int))(*(int*)(*gPlayerInterface + 0x14)))(a, b, 0x36);
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
        fn_80295E90(a, 1);
        Sfx_PlayFromObject(a, SFXmammoth_annoyed);
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

void fn_802A514C(int obj, int state)
{
    PlayerState* inner = ((GameObject*)obj)->extra;
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
                    objThrowFn_80182504((int)sub);
                }
                else
                {
                    objSaveFn_800ea774((int)sub);
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
                s16 t = ((GameObject*)obj)->anim.rotX;
                inner->yaw = t;
                inner->targetYaw = t;
                inner->lastInputHeading = t;
                inner->baddie.animSpeedB = lbl_803E7EA4;
            }
            ((ByteFlags*)((char*)inner + 0x3f1))->b20 = 0;
            if (((ByteFlags*)((char*)inner + 0x3f1))->b10)
            {
                u8 anim = inner->curAnimId;
                if (anim != 0x48 && anim != 0x47 && getCurSeqNo() == 0)
                {
                    (*gCameraInterface)->setMode(
                        0x42, 0, 1, 0, NULL, 0x1e, 0xff);
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
        *(u32*)&((PlayerState*)inner)->flags360 |= 0x800000LL;
        ObjHits_SyncObjectPositionIfDirty(obj);
    }
    gPlayerSubState = 1;
}

int fn_802A4D34(int obj, int state)
{
    PlayerState* inner = ((GameObject*)obj)->extra;
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
    switch (((GameObject*)obj)->anim.currentMove)
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
                if (((GameObject*)obj)->anim.currentMoveProgress > lbl_803E7E98)
                {
                    ((GameObject*)sub)->unkF8 = 1;
                }
                amt = interpolate((f32)inner->targetObjectBearing, lbl_803E805C, timeDelta);
                inner->targetYaw = (f32)inner->targetYaw + amt;
                inner->yaw = inner->targetYaw;
            }
            if (((GameObject*)obj)->anim.currentMoveProgress > lbl_803E7F2C)
            {
                inner->moveAnimTable = (int)lbl_80333110;
                ObjAnim_SetCurrentMove(obj, *(s16*)inner->moveAnimTable, lbl_803E7EA4, 0);
                *(u32*)&((PlayerState*)inner)->flags360 |= 0x800000LL;
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
                ObjAnim_SetCurrentMove(obj, *(s16*)inner->moveAnimTable, lbl_803E7EA4, 0);
                *(u32*)&((PlayerState*)inner)->flags360 |= 0x800000LL;
                *(int*)&((PlayerState*)state)->baddie.unk308 = (int)fn_802A514C;
                return 2;
            }
            else
            {
                ObjAnim_SetCurrentMove(obj, 5, lbl_803E7EA4, 0);
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
        Sfx_PlayFromObject(obj, snd);
    }
    return 0;
}

int fn_802ADC08(int obj, int inner, int p3)
{
    ((GameObject*)obj)->anim.velocityY = ((GameObject*)obj)->anim.velocityY - lbl_803DC67C * timeDelta;
    if (((PlayerState*)inner)->fallFrames > 5 && ((ByteFlags*)((char*)inner + 0x3f1))->b01)
    {
        u16 snd;
        doRumble(lbl_803E7F10);
        Sfx_PlayFromObject(obj, (u16)audioPickSoundEffect_8006ed24(((PlayerState*)inner)->surfaceType,
                                                                   ((PlayerState*)inner)->footstepSoundId));
        if (((PlayerState*)inner)->characterId == 0)
        {
            snd = 0x2cf;
        }
        else
        {
            snd = 0x25;
        }
        Sfx_PlayFromObject(obj, snd);
        ((ByteFlags*)((char*)inner + 0x3f0))->b08 = 0;
        ((ByteFlags*)((char*)inner + 0x3f1))->b08 = 1;
        ((ByteFlags*)((char*)inner + 0x3f2))->b10 = 1;
    }
    if (((GameObject*)obj)->anim.worldPosY <= ((PlayerState*)inner)->fallThresholdY
        || ((*(s8*)((char*)p3 + 0x264) & 2) && (*(s8*)((char*)p3 + 0x264) & 0x20) == 0)
        || *(u8*)((char*)p3 + 0x262) != 0)
    {
        void* sub;
        ((ByteFlags*)((char*)inner + 0x3f0))->b80 = 0;
        ((ByteFlags*)((char*)inner + 0x3f0))->b10 = 0;
        ((ByteFlags*)((char*)inner + 0x3f0))->b08 = 0;
        staffFn_80170380(gPlayerStaffObject, 2);
        ((ByteFlags*)((char*)inner + 0x3f0))->b02 = 0;
        *(u32*)&((PlayerState*)inner)->flags360 |= 0x800000LL;
        ObjHits_SyncObjectPositionIfDirty(obj);
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
                objThrowFn_80182504((int)sub);
            }
            else
            {
                objSaveFn_800ea774((int)sub);
            }
            *(s16*)((char*)((PlayerState*)inner)->heldObj + 0x6) &= ~0x4000;
            *(int*)((char*)((PlayerState*)inner)->heldObj + 0xf8) = 0;
            ((PlayerState*)inner)->heldObj = 0;
        }
    }
    ((PlayerState*)inner)->fallFrames += 1;
    {
        u32 v = ((PlayerState*)inner)->fallFrames;
        if (v > 0xa) v = 0xa;
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

int fn_8029B9FC(int obj, int state, f32 fv)
{
    PlayerState* inner = ((GameObject*)obj)->extra;
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
    v = ((int (*)(int, int, int, f32))fn_802AC7DC)(obj, state, (int)inner, fv);
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
    if ((*(int*)&((PlayerState*)state)->baddie.unk31C & 0x100) && gPlayerPathObject != NULL
        && ((ByteFlags*)((char*)inner + 0x3f4))->b40)
    {
        inner->staffActionRequest = 4;
        ((ByteFlags*)((char*)inner + 0x3f4))->b08 = 1;
    }
    v = fn_80299E44(obj, state, fv);
    if (v != 0) return v;
    return 0;
}

void fn_802B0920(int obj, int state)
{
    s16* vec9 = objModelGetVecFn_800395d8(obj, 9);
    s16* vec0 = objModelGetVecFn_800395d8(obj, 0);
    u8 doBlink = 0;
    PlayerState* inner = ((GameObject*)obj)->extra;
    f32 f31v;
    f32 f30v;

    if ((s8) * (s8*)(((PlayerState*)state)->playerStatus) > 0)
    {
        characterDoEyeAnims(obj, state + 0x364);
    }
    else
    {
        ObjTextureRuntimeSlot* t5 = objFindTexture((void*)obj, 5, 0);
        ObjTextureRuntimeSlot* t4 = objFindTexture((void*)obj, 4, 0);
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
        ((PlayerState*)state)->headYaw =
            (f32)((PlayerState*)state)->headYaw * powfBitEstimate(lbl_803E7F1C, timeDelta);
        ((PlayerState*)state)->bodyLeanAngle =
            (f32)((PlayerState*)state)->bodyLeanAngle * powfBitEstimate(lbl_803E7F1C, timeDelta);
        ((PlayerState*)state)->bodyLeanHalf =
            (f32)((PlayerState*)state)->bodyLeanHalf * powfBitEstimate(lbl_803E7F1C, timeDelta);
    }
    if (((ByteFlags*)((char*)state + 0x3f0))->b20)
    {
        f31v = inner->baddie.animSpeedC /
            *(f32*)((char*)(((PlayerState*)state)->moveParams) + 0x18);
        f31v = (f31v < lbl_803E7EA4) ? lbl_803E7EA4 : ((f31v > lbl_803E7EE0) ? lbl_803E7EE0 : f31v);
        f30v = lbl_803E7EE0 - f31v;
    }
    if (vec9 != NULL)
    {
        if (((ByteFlags*)((char*)state + 0x3f0))->b20)
        {
            f32 k = lbl_803E7E98;
            vec9[2] = k *
            ((f32)((PlayerState*)state)->headPitch * f30v +
                (f32)((PlayerState*)state)->bodyLeanHalf * f31v);
            vec9[1] = k *
            ((f32)((PlayerState*)state)->bodyLeanHalf * f30v +
                (f32)((PlayerState*)state)->headPitch * f31v);
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
        ((GameObject*)obj)->anim.rotZ = ((PlayerState*)state)->headPitch / 4;
    }
    else
    {
        ((GameObject*)obj)->anim.rotZ =
            (f32)((GameObject*)obj)->anim.rotZ * powfBitEstimate(lbl_803E7FF4, timeDelta);
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
        ((void (*)(int, int, u16))playerEyeAnimFn_80038988)(obj, state + 0x364, e);
    }
    if ((((GameObject*)obj)->objectFlags & 0x1000) == 0)
    {
        if (((ByteFlags*)((char*)state + 0x3f1))->b20)
        {
            gPlayerSubState = 5;
        }
        else
        {
            if (fn_80295A04(obj, 2) == 0 &&
                (s8) * (s8*)(((PlayerState*)state)->playerStatus) > 4 &&
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

void fn_802ADE80(int obj, int inner, int state)
{
    f32 tz;
    f32 ty;
    f32 tx;
    f32 waterX;
    f32 waterZ;
    struct
    {
        u8 pad[6];
        u16 mode;
        f32 scale;
        f32 x;
        f32 y;
        f32 z;
    } pfx;
    struct
    {
        s16 angles[4];
        f32 mat[4];
    } v;
    f32 mtx[20];
    f32 angle;
    int playEffect;
    int loopCount;
    int i;

    angle = ((PlayerState*)inner)->waterSurfaceY;
    angle = angle +
        mathSinf(gPlayerPi * (f32)(u32) * (u16*)((char*)inner + 0x89c) / lbl_803E7F98);
    *(s16*)&((PlayerState*)inner)->unk89C =
        lbl_803E8114 * timeDelta + (f32)(u32) * (u16*)((char*)inner + 0x89c);
    {
        f32 d = angle - ((GameObject*)obj)->anim.localPosY;
        if (d > lbl_803E7FA0)
        {
            d = lbl_803E7FA0;
        }
        d = d / lbl_803E7FA0 * lbl_803E8118;
        ((GameObject*)obj)->anim.velocityY =
            d * timeDelta + ((GameObject*)obj)->anim.velocityY;
    }
    ((GameObject*)obj)->anim.velocityY =
        ((GameObject*)obj)->anim.velocityY - lbl_803E7EFC * timeDelta;
    ((GameObject*)obj)->anim.velocityY =
        ((GameObject*)obj)->anim.velocityY * powfBitEstimate(lbl_803E7FD0, timeDelta);
    {
        f32 v = ((GameObject*)obj)->anim.velocityY;
        ((GameObject*)obj)->anim.velocityY =
            (v < lbl_803E811C) ? lbl_803E811C : ((v > lbl_803E8120) ? lbl_803E8120 : v);
    }
    ((void (*)(f32*, f32*, f32, int))playerCalcWaterCurrent)(&waterX, &waterZ, lbl_803E7EE0, obj);
    {
        f32 dt = timeDelta;
        f32 cosv = mathSinf(gPlayerPi * (f32) * (s16*)((char*)inner + 0x478) / lbl_803E7F98);
        f32 sinv = mathCosf(gPlayerPi * (f32) * (s16*)((char*)inner + 0x478) / lbl_803E7F98);
        f32 a = -waterZ * sinv - waterX * cosv;
        ((PlayerState*)inner)->waterCurrentVelB =
            dt * (lbl_803E7EFC * ((waterX * sinv - waterZ * cosv) - ((PlayerState*)inner)->waterCurrentVelB)) +
            ((PlayerState*)inner)->waterCurrentVelB;
        ((PlayerState*)inner)->waterCurrentVelA =
            dt * (lbl_803E7EFC * (a - ((PlayerState*)inner)->waterCurrentVelA)) +
            ((PlayerState*)inner)->waterCurrentVelA;
    }
    playEffect = 0;
    if (((PlayerState*)state)->baddie.controlMode == 1)
    {
        if ((*(int*)&((PlayerState*)state)->baddie.eventFlags & 0x200) != 0)
        {
            Sfx_PlayAtPositionFromObject(obj, 0xe, ((GameObject*)obj)->anim.localPosX,
                                         ((PlayerState*)inner)->waterSurfaceY, ((GameObject*)obj)->anim.localPosZ);
        }
        if (((PlayerState*)inner)->waterDepth < lbl_803E7FA0 &&
            (*(int*)&((PlayerState*)state)->baddie.eventFlags & 0x200) != 0)
        {
            tx = (f32)randomGetRange(-0x14, 0x14) / lbl_803E7ED8;
            tz = (f32)randomGetRange(-0x14, 0x14) / lbl_803E7ED8;
            playEffect = 1;
        }
    }
    else
    {
        if ((*(int*)&((PlayerState*)state)->baddie.eventFlags & 1) != 0)
        {
            Sfx_PlayAtPositionFromObject(obj, 0xf, ((GameObject*)obj)->anim.localPosX,
                                         ((PlayerState*)inner)->waterSurfaceY, ((GameObject*)obj)->anim.localPosZ);
        }
        if (((PlayerState*)inner)->waterDepth < lbl_803E7FA0 &&
            (*(int*)&((PlayerState*)state)->baddie.eventFlags & 0x200) != 0)
        {
            s8 c;
            tx = (f32)randomGetRange(-0x14, 0x14) / lbl_803E7ED8;
            c = ((PlayerState*)inner)->gaitLevel;
            if (c <= 8)
            {
                tz = lbl_803E8124;
            }
            else if (c <= 0xc)
            {
                tz = lbl_803E8124;
            }
            else
            {
                tz = lbl_803E8124;
            }
            playEffect = 1;
        }
    }
    if (playEffect != 0)
    {
        v.mat[1] = ((GameObject*)obj)->anim.localPosX;
        v.mat[2] = lbl_803E7EA4;
        v.mat[3] = ((GameObject*)obj)->anim.localPosZ;
        v.angles[0] = ((PlayerState*)inner)->targetYaw;
        v.angles[1] = 0;
        v.angles[2] = 0;
        v.mat[0] = lbl_803E7EE0;
        setMatrixFromObjectPos(mtx, v.angles);
        Matrix_TransformPoint(mtx, tx, lbl_803E7EA4, tz, &tx, &ty, &tz);
        ((void (*)(f32, f32, f32, s16, f32, int))(*gWaterfxInterface)->spawnRipple)(
            tx, ((PlayerState*)inner)->waterSurfaceY, tz, 0, lbl_803E7EA4, 5);
        if (((PlayerState*)inner)->waterDepth > lbl_803E8128 &&
            ((PlayerState*)state)->baddie.animSpeedC > lbl_803E7E9C)
        {
            u16 ang = ((PlayerState*)inner)->targetYaw -
                getAngle(((PlayerState*)state)->baddie.animSpeedB, ((PlayerState*)state)->baddie.animSpeedA);
            (*gWaterfxInterface)->spawnSimpleRipple(
                ang, tx, ((PlayerState*)inner)->waterSurfaceY, tz, lbl_803E7EA4);
        }
    }
    ObjPath_GetPointWorldPosition(obj, 0x13, &v.mat[1], &v.mat[2], &v.mat[3], 0);
    loopCount = (((PlayerState*)inner)->waterSurfaceY - v.mat[2] > lbl_803E7F10) ? 1 : 0;
    {
        f32 div0 = lbl_803E7FA4;
        f32 zero = lbl_803E7EA4;
        f32 div1 = lbl_803E808C;
        for (i = 0; i < loopCount; i++)
        {
            pfx.x = v.mat[1] + (f32)randomGetRange(-0x64, 0x64) / div0;
            pfx.y = v.mat[2] + (f32)randomGetRange(-0x64, 0x64) / div1;
            pfx.z = v.mat[3] + (f32)randomGetRange(-0x64, 0x64) / div0;
            pfx.scale = ((PlayerState*)inner)->waterSurfaceY - pfx.y;
            if (pfx.scale > zero)
        {
                (*gPartfxInterface)->spawnObject(
                    (void*)obj, 0x202, &pfx, 0x200001, -1, NULL);
            }
        }
    }
}

int fn_802A16CC(int obj, int state, f32 fv)
{
    PlayerState* inner = ((GameObject*)obj)->extra;
    if (*(s8*)&((PlayerState*)state)->baddie.moveJustStartedA != 0)
    {
        ObjHits_MarkObjectPositionDirty();
        lbl_803DE498 = lbl_803E7EA4;
        ObjAnim_SetCurrentMove(obj, 0x35, lbl_803E7EA4, 1);
        ((PlayerState*)state)->baddie.moveSpeed = lbl_803E7F20;
        inner->moveStartPosY = ((GameObject*)obj)->anim.localPosY;
        ((GameObject*)obj)->anim.localPosY = inner->savedPosY;
        fn_802AB5A4(obj, (int)inner, 5);
    }
    if (inner->waterDepth > lbl_803E7FA0)
    {
        fn_802AB5A4(obj, (int)inner, 5);
        ((void (*)(int, int, int))fn_802AE83C)(obj, (int)inner, state);
        *(int*)&((PlayerState*)state)->baddie.unk308 = (int)fn_802A514C;
        return 2;
    }
    *(int*)((char*)state + 0x4) |= 0x100000;
    *(int*)((char*)state + 0x4) |= 0x8000000;
    *(int*)((char*)state + 0) |= 0x200000;
    switch (((GameObject*)obj)->anim.currentMove)
    {
    case 0x35:
        if (*(s8*)&((PlayerState*)state)->baddie.moveDone != 0)
        {
            ObjAnim_SetCurrentMove(obj, 0x36, lbl_803E7EA4, 0);
            ((PlayerState*)state)->baddie.moveSpeed = lbl_803E7F20;
        }
    case 0x36:
        {
            f32 f30 = lbl_803E7ED8 * -lbl_803DE498;
            f32 f3;
            if ((*(int*)&((PlayerState*)state)->baddie.eventFlags & 1) != 0)
            {
                Sfx_PlayFromObject(obj, SFXthorntail_injured2);
            }
            f3 = ((GameObject*)obj)->anim.localPosY - (lbl_803E8010 + inner->climbBaseY);
            if (f3 < lbl_803E7EA4)
            {
                f3 = lbl_803E7EA4;
            }
            if (f3 < f30)
            {
                f32 ed4 = lbl_803E7ED4;
                f32 base = ed4 * (lbl_803DE498 * lbl_803DE498 / (ed4 * f30));
                ((GameObject*)obj)->anim.velocityY = -sqrtf(base * f3);
                if (((GameObject*)obj)->anim.velocityY >= lbl_803E7FEC)
                {
                    u8 anim = inner->curAnimId;
                    f32 v4ec;
                    if (anim != 0x48 && anim != 0x47 && anim != 0x42)
                    {
                        (*gCameraInterface)->setMode(
                            0x42, 0, 1, 0, NULL, 0, 0xff);
                        inner->curAnimId = 0x42;
                    }
                    inner->moveStartPosY = ((GameObject*)obj)->anim.localPosY;
                    v4ec = inner->climbBaseY;
                    ((GameObject*)obj)->anim.worldPosY = v4ec;
                    ((GameObject*)obj)->anim.localPosY = v4ec;
                    if (((ByteFlags*)((char*)inner + 0x547))->b80)
                    {
                        ObjAnim_SetCurrentMove(obj, 0x37, lbl_803E7EA4, 1);
                        ((PlayerState*)state)->baddie.moveSpeed = lbl_803E7FCC;
                        ((GameObject*)obj)->anim.velocityY = lbl_803E7EA4;
                    }
                    else
                    {
                        f32 zero = lbl_803E7EA4;
                        void* sub;
                        ((PlayerState*)state)->baddie.animSpeedC = zero;
                        ((PlayerState*)state)->baddie.animSpeedB = zero;
                        ((PlayerState*)state)->baddie.animSpeedA = zero;
                        ((GameObject*)obj)->anim.velocityX = zero;
                        ((GameObject*)obj)->anim.velocityY = zero;
                        ((GameObject*)obj)->anim.velocityZ = zero;
                        fn_802AB5A4(obj, (int)inner, 5);
                        ((ByteFlags*)((char*)inner + 0x3f0))->b80 = 0;
                        ((ByteFlags*)((char*)inner + 0x3f0))->b10 = 0;
                        ((ByteFlags*)((char*)inner + 0x3f0))->b08 = 0;
                        staffFn_80170380(gPlayerStaffObject, 2);
                        ((ByteFlags*)((char*)inner + 0x3f0))->b02 = 0;
                        *(u32*)&((PlayerState*)inner)->flags360 |= 0x800000LL;
                        ObjHits_SyncObjectPositionIfDirty(obj);
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
                                objThrowFn_80182504((int)sub);
                            }
                            else
                            {
                                objSaveFn_800ea774((int)sub);
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
                if (((GameObject*)obj)->anim.velocityY > lbl_803E8014)
                {
                    ((GameObject*)obj)->anim.velocityY =
                        ((GameObject*)obj)->anim.velocityY - lbl_803E7F6C * fv;
                }
                if (((GameObject*)obj)->anim.velocityY < *(f32*)&lbl_803E8014)
                {
                    ((GameObject*)obj)->anim.velocityY = lbl_803E8014;
                }
                if (((GameObject*)obj)->anim.velocityY < lbl_803DE498)
                {
                    lbl_803DE498 = ((GameObject*)obj)->anim.velocityY;
                }
            }
        }
        break;
    case 0x37:
        if ((*(int*)&((PlayerState*)state)->baddie.eventFlags & 1) != 0)
        {
            int snd = audioPickSoundEffect_8006ed24(inner->surfaceType,
                                                    inner->footstepSoundId);
            Sfx_PlayFromObject(obj, snd);
            doRumble(lbl_803E7F10);
            if (inner->waterDepth > lbl_803E7EA4)
            {
                (*gWaterfxInterface)->spawnSplashBurst(
                    (void*)obj, ((GameObject*)obj)->anim.localPosX,
                    ((GameObject*)obj)->anim.localPosY,
                    ((GameObject*)obj)->anim.localPosZ, lbl_803E8018);
            }
        }
        if (*(s8*)&((PlayerState*)state)->baddie.moveDone != 0)
        {
            f32 local;
            ((GameObject*)obj)->anim.worldPosX = inner->savedPosX;
            ((GameObject*)obj)->anim.worldPosZ = inner->savedPosZ;
            if (((GameObject*)obj)->anim.parent != NULL)
            {
                ((GameObject*)obj)->anim.worldPosX += playerMapOffsetX;
                ((GameObject*)obj)->anim.worldPosZ += playerMapOffsetZ;
            }
            Obj_TransformWorldPointToLocal(((GameObject*)obj)->anim.worldPosX, lbl_803E7EA4,
                                           ((GameObject*)obj)->anim.worldPosZ, &((GameObject*)obj)->anim.localPosX,
                                           &local, &((GameObject*)obj)->anim.localPosZ,
                                           *(int*)&((GameObject*)obj)->anim.parent);
            fn_802AB5A4(obj, (int)inner, 5);
            ObjAnim_SetCurrentMove(obj, *(s16*)(inner->moveAnimTable), lbl_803E7EA4, 1);
            *(u32*)&((PlayerState*)inner)->flags360 |= 0x800000LL;
            *(int*)&((PlayerState*)state)->baddie.unk308 = (int)fn_802A514C;
            return 2;
        }
        break;
    }
    {
        f32 cx = ((GameObject*)obj)->anim.localPosX;
        f32 cy;
        f32 cz = ((GameObject*)obj)->anim.localPosZ;
        switch (((GameObject*)obj)->anim.currentMove)
        {
        case 0x35:
            cy = ((GameObject*)obj)->anim.currentMoveProgress *
                (((GameObject*)obj)->anim.localPosY - inner->moveStartPosY) +
                inner->moveStartPosY;
            break;
        case 0x37:
            {
                f32 w = ((GameObject*)obj)->anim.currentMoveProgress;
                cx = w * (inner->savedPosX - cx) + cx;
                cy = (lbl_803E7EE0 - w) *
                    (inner->moveStartPosY - ((GameObject*)obj)->anim.localPosY) +
                    ((GameObject*)obj)->anim.localPosY;
                cz = w * (inner->savedPosZ - cz) + cz;
            }
            break;
        default:
            cy = ((GameObject*)obj)->anim.localPosY;
            break;
        }
        (*gCameraInterface)->overridePos(cx, cy, cz);
    }
    fn_802AB5A4(obj, (int)inner, 5);
    return 0;
}

int fn_80298E54(int obj, int state, f32 fv)
{
    PlayerState* inner = ((GameObject*)obj)->extra;
    if (*(s8*)&((PlayerState*)state)->baddie.moveJustStartedA != 0)
    {
        ObjHits_MarkObjectPositionDirty();
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
                Sfx_PlayFromObject(obj, SFXmammoth_breath1);
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
                buttonDisable(0, 0x100);
                lbl_803DE488 = lbl_803E7ED8;
                ObjAnim_SetCurrentMove(obj, 0xac, lbl_803E7EA4, 0);
                ((PlayerState*)state)->baddie.moveSpeed = lbl_803E7EA4;
            }
            else if ((flags & 0x200) != 0)
            {
                buttonDisable(0, 0x200);
                Sfx_PlayFromObject(obj, SFXmammoth_breath1);
                ObjAnim_SetCurrentMove(obj, 0xd1, lbl_803E7EA4, 0);
                ((PlayerState*)state)->baddie.moveSpeed = lbl_803E7F4C;
            }
            break;
        }
    case 0xd1:
        if (*(s8*)&((PlayerState*)state)->baddie.moveDone != 0)
        {
            *(u32*)&((PlayerState*)inner)->flags360 |= 0x800000LL;
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
            if ((inner->buttonsJustPressedIfNotBusy & 0x100) != 0 || getCurSeqNo() != 0)
            {
                buttonDisable(0, 0x100);
                lbl_803DE460 = lbl_803DE460 - fv;
                if (lbl_803DE460 < lbl_803E7EA4)
                {
                    Sfx_PlayFromObject(obj, (u16)(inner->characterId == 0 ? 0x2d3 : 0x2b));
                    lbl_803DE460 = (f32)(int)
                    randomGetRange(0xa, 0x12);
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
                fn_80189C68(gPlayerInteractTarget);
                Sfx_PlayFromObject(obj, (u16)(inner->characterId == 0 ? 0x2d3 : 0x2b));
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
            Sfx_PlayFromObject(obj, SFXsp_lf_mutter4);
            ObjAnim_SetCurrentMove(obj, 0xb2, lbl_803E7EA4, 0);
            ((PlayerState*)state)->baddie.moveSpeed = lbl_803E7EF8;
        }
        break;
    case 0xb2:
        cfPrisonGuard_setLiftHeight(gPlayerInteractTarget, 0x800);
        if ((inner->buttonsJustPressed & 0x200) != 0)
        {
            buttonDisable(0, 0x200);
            Sfx_PlayFromObject(obj, SFXmammoth_breath1);
            ObjAnim_SetCurrentMove(obj, 0xad, lbl_803E7EA4, 0);
            ((PlayerState*)state)->baddie.moveSpeed = lbl_803E7F4C;
        }
        break;
    case 0xad:
        if (*(s8*)&((PlayerState*)state)->baddie.moveDone != 0)
        {
            *(u32*)&((PlayerState*)inner)->flags360 |= 0x800000LL;
            *(int*)&((PlayerState*)state)->baddie.unk308 = (int)fn_802A514C;
            return 2;
        }
        break;
    default:
        ObjAnim_SetCurrentMove(obj, 0xab, lbl_803E7EA4, 0);
        ((PlayerState*)state)->baddie.moveSpeed = lbl_803E7F40;
        staffactivated_calcInteractionTargetXZ(gPlayerInteractTarget, &((GameObject*)obj)->anim.localPosX,
                                               &((GameObject*)obj)->anim.localPosZ);
        inner->targetYaw = *(s16*)gPlayerInteractTarget + 0x8000;
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
            (*gCameraInterface)->setMode(
                0x43, 1, 0, 4, &shk, 0, 0xff);
        }
        break;
    }
    return 0;
}

int fn_802994D0(int obj, int state, f32 fv)
{
    PlayerState* inner = ((GameObject*)obj)->extra;
    u32 mask;
    s16 item;
    if (*(s8*)&((PlayerState*)state)->baddie.moveJustStartedA != 0)
    {
        ObjHits_MarkObjectPositionDirty();
    }
    if ((s16)getYButtonItem(&item) == 1 && item == 0x957)
    {
        mask = 0x900;
    }
    else
    {
        mask = 0x100;
    }
    *(int*)((char*)state + 0) |= 0x200000;
    switch (((GameObject*)obj)->anim.currentMove)
    {
    case 0x4:
        if (lbl_803DE48D == 0)
        {
            if (((GameObject*)obj)->anim.currentMoveProgress > lbl_803E7F74)
            {
                Sfx_PlayFromObject(obj, SFXhightop_call1);
                lbl_803DE48D = 1;
            }
        }
        if (*(s8*)&((PlayerState*)state)->baddie.moveDone != 0)
        {
            if ((inner->buttonsHeld & mask) != 0)
            {
                Sfx_PlayFromObject(obj, SFXhightop_call2);
                ObjAnim_SetCurrentMove(obj, 0x87, lbl_803E7EA4, 0);
                ((PlayerState*)state)->baddie.moveSpeed = lbl_803E7EF8;
            }
            else
            {
                ObjAnim_SetCurrentMove(obj, 0x43, lbl_803E7EA4, 0);
                ((PlayerState*)state)->baddie.moveSpeed = lbl_803E7F78;
            }
        }
        break;
    case 0x87:
        if ((inner->buttonsHeld & mask) != 0 &&
            inner->chargeLevel <=
            (f32) * (s16*)((char*)*(int*)((char*)*(int*)&((GameObject*)obj)->extra + 0x35c) + 0x4))
        {
            ((PlayerState*)state)->baddie.moveSpeed = lbl_803E7F20 * fv + ((PlayerState*)state)->baddie.moveSpeed;
            if (((PlayerState*)state)->baddie.moveSpeed > lbl_803E7F6C)
            {
                ((PlayerState*)state)->baddie.moveSpeed = *(f32 *)&lbl_803E7F6C;
            }
            inner->chargeLevel = lbl_803E7F7C * fv + inner->chargeLevel;
            inner->chargeLevel = lbl_803E7E98 * fv + inner->chargeLevel;
            if (inner->chargeLevel >= lbl_803E7ED8)
            {
                int sub = *(int*)((char*)*(int*)&((GameObject*)obj)->extra + 0x35c);
                int v = *(s16*)((char*)sub + 0x4) - 0xa;
                inner->chargeLevel = lbl_803E7EA4;
                if (v < 0)
                {
                    v = 0;
                }
                else if (v > *(s16*)((char*)sub + 0x6))
                {
                    v = *(s16*)((char*)sub + 0x6);
                }
                *(s16*)((char*)sub + 0x4) = v;
                Sfx_PlayFromObject(obj, SFXmammoth_annoyed2);
                ObjAnim_SetCurrentMove(obj, 0x88, lbl_803E7EA4, 0);
                ((PlayerState*)state)->baddie.moveSpeed = lbl_803E7F6C;
            }
        }
        else
        {
            ObjAnim_SetCurrentMove(obj, 0x43, lbl_803E7EA4, 0);
            ((PlayerState*)state)->baddie.moveSpeed = lbl_803E7F78;
        }
        break;
    case 0x43:
        if ((inner->buttonsHeld & mask) != 0)
        {
            Sfx_PlayFromObject(obj, SFXhightop_call2);
            ObjAnim_SetCurrentMove(obj, 0x87, lbl_803E7EA4, 0);
            ((PlayerState*)state)->baddie.moveSpeed = lbl_803E7EF8;
        }
        else if ((inner->buttonsJustPressed & 0x200) != 0)
        {
            buttonDisable(0, 0x200);
            ObjAnim_SetCurrentMove(obj, 0x44, lbl_803E7EA4, 0);
            ((PlayerState*)state)->baddie.moveSpeed = lbl_803E7F80;
        }
        break;
    case 0x44:
        if (*(s8*)&((PlayerState*)state)->baddie.moveDone != 0)
        {
            *(u32*)&((PlayerState*)inner)->flags360 |= 0x800000LL;
            ((GameObject*)obj)->anim.velocityY = lbl_803E7EA4;
            inner->animState = -1;
            *(int*)&((PlayerState*)state)->baddie.unk308 = (int)fn_802A514C;
            return 2;
        }
        break;
    case 0x88:
        ((GameObject*)obj)->anim.velocityY = lbl_803E7F6C * fv + ((GameObject*)obj)->anim.velocityY;
        if (*(s8*)&((PlayerState*)state)->baddie.moveDone != 0)
        {
            void* t = getTrickyObject();
            if (t != NULL)
            {
                trickyImpress(t);
            }
            ObjAnim_SetCurrentMove(obj, 0x7f, lbl_803E7EA4, 0);
            ((PlayerState*)state)->baddie.moveSpeed = lbl_803E7EB4;
        }
        break;
    case 0x7f:
        ((GameObject*)obj)->anim.velocityY = lbl_803E7EFC * fv + ((GameObject*)obj)->anim.velocityY;
        if (((GameObject*)obj)->anim.velocityY > lbl_803E7F10)
        {
            ((GameObject*)obj)->anim.velocityY = lbl_803E7F10;
        }
        if (((GameObject*)obj)->anim.localPosY > lbl_803DE490)
        {
            ObjAnim_SetCurrentMove(obj, 0x80, lbl_803E7EA4, 0);
            ((PlayerState*)state)->baddie.moveSpeed = lbl_803E7F84;
        }
        break;
    case 0x80:
        {
            f32 p;
            ((GameObject*)obj)->anim.velocityY = ((GameObject*)obj)->anim.velocityY - lbl_803E7F88 * fv;
            p = powfBitEstimate(lbl_803E7F90, fv);
            ((GameObject*)obj)->anim.velocityY = ((GameObject*)obj)->anim.velocityY * p;
            (*(void (*)(int, int, f32, int))(*(int*)(*gPlayerInterface + 0x20)))(obj, state, fv, 1);
            if (*(s8*)&((PlayerState*)state)->baddie.moveDone != 0)
            {
                *(u32*)&((PlayerState*)inner)->flags360 |= 0x800000LL;
                ((GameObject*)obj)->anim.velocityY = lbl_803E7EA4;
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
            u8 hitBuf[0x40];
            f32 zero = lbl_803E7EA4;
            ((PlayerState*)state)->baddie.animSpeedC = zero;
            ((PlayerState*)state)->baddie.animSpeedB = zero;
            ((PlayerState*)state)->baddie.animSpeedA = zero;
            ((GameObject*)obj)->anim.velocityX = zero;
            ((GameObject*)obj)->anim.velocityY = zero;
            ((GameObject*)obj)->anim.velocityZ = zero;
            ObjAnim_SetCurrentMove(obj, 0x4, zero, 0);
            ((PlayerState*)state)->baddie.moveSpeed = lbl_803E7F84;
            lbl_803DE494 = ((GameObject*)obj)->anim.localPosY;
            inner->targetYaw = *(s16*)gPlayerInteractTarget;
            inner->yaw = inner->targetYaw;
            staffactivated_calcInteractionTargetXZ(gPlayerInteractTarget, (f32*)((char*)obj + 0xc), (f32*)((char*)obj + 0x14));
            fn_802AB5A4(obj, (int)inner, 7);
            *(int*)((char*)state + 0x4) |= 0x8000000;
            fromVec[0] = ((GameObject*)obj)->anim.localPosX;
            fromVec[1] = lbl_803E7ED8 + ((GameObject*)obj)->anim.localPosY;
            fromVec[2] = ((GameObject*)obj)->anim.localPosZ;
            toVec[0] = fromVec[0] -
                lbl_803E7F5C * mathSinf(gPlayerPi * (f32)(int)inner->targetYaw /
                                        lbl_803E7F98);
            toVec[1] = fromVec[1];
            toVec[2] = fromVec[2] -
                lbl_803E7F5C * mathCosf(gPlayerPi * (f32)(int)inner->targetYaw /
                                        lbl_803E7F98);
            if (objBboxFn_800640cc(lbl_803E7EA4, fromVec, toVec, 3, hitBuf, obj, 1, 1, 0xff, 0) != 0)
            {
                lbl_803DE490 = *(f32*)(hitBuf + 0x3c) - lbl_803E7F30;
            }
            else
            {
                lbl_803DE490 = lbl_803E7F5C + ((GameObject*)obj)->anim.localPosY;
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
                (*gCameraInterface)->setMode(
                    0x43, 1, 0, 4, &shk, 0, 0xff);
            }
            break;
        }
    }
    return 0;
}

int fn_8029E568(int obj, int state, f32 fv)
{
    PlayerState* inner = ((GameObject*)obj)->extra;
    int camArg = 0;
    f32 vec[3];
    if (*(s8*)&((PlayerState*)state)->baddie.moveJustStartedA != 0)
    {
        *(s16*)((char*)state + 0x278) = 0x1b;
        inner->stateHandler = (int)fn_802A00C0;
        ObjHits_MarkObjectPositionDirty();
    }
    {
        int in2 = *(int*)&((GameObject*)obj)->extra;
        *(int*)((char*)in2 + 0x360) &= ~2LL;
        *(u32*)((char*)in2 + 0x360) |= 0x2000LL;
    }
    *(int*)((char*)state + 0x4) |= 0x100000;
    {
        f32 zero = lbl_803E7EA4;
        ((PlayerState*)state)->baddie.animSpeedA = zero;
        ((PlayerState*)state)->baddie.animSpeedB = zero;
        *(int*)((char*)state + 0) |= 0x200000;
        ((GameObject*)obj)->anim.velocityX = zero;
        ((GameObject*)obj)->anim.velocityZ = zero;
        ((PlayerState*)state)->baddie.physicsActive = 0;
        ((GameObject*)obj)->anim.velocityY = zero;
    }
    switch (((GameObject*)obj)->anim.currentMove)
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
                    Sfx_PlayFromObject(0, 0x378);
                }
            }
            ((PlayerState*)state)->baddie.animSpeedC =
                ((PlayerState*)state)->baddie.animSpeedC +
                interpolate(spd - ((PlayerState*)state)->baddie.animSpeedC, lbl_803E7EFC, timeDelta);
            inner->traveledDistance =
                ((PlayerState*)state)->baddie.animSpeedC * timeDelta + inner->traveledDistance;
            {
                f32 ph = ((PlayerState*)state)->baddie.animSpeedC;
                if (ph < lbl_803E7EF8 && ph > lbl_803E7FEC)
                {
                    f32 zeroPh = lbl_803E7EA4;
                    ((PlayerState*)state)->baddie.animSpeedC = zeroPh;
                    if (((GameObject*)obj)->anim.currentMove != 0x76)
                    {
                        ObjAnim_SetCurrentMove(obj, 0x76, zeroPh, 0);
                    }
                    ((PlayerState*)state)->baddie.moveSpeed = lbl_803E7F78;
                }
                else
                {
                    if (((GameObject*)obj)->anim.currentMove != 0x40d)
                    {
                        ObjAnim_SetCurrentMove(obj, 0x40d, lbl_803E7EA4, 0);
                    }
                    ObjAnim_SampleRootCurvePhase(((PlayerState*)state)->baddie.animSpeedC, (ObjAnimComponent*)obj,
                                                 (f32*)((char*)state + 0x2a0));
                }
            }
            atDest = inner->traveledDistance > inner->travelTargetDistance ||
                     inner->traveledDistance < lbl_803E7EA4;
            if (atDest)
            {
                u8 anim;
                ObjAnim_SetCurrentMove(obj, 0x40f, lbl_803E7EA4, 0);
                anim = inner->curAnimId;
                if (anim != 0x48 && anim != 0x47)
                {
                    camArg = inner->traveledDistance < lbl_803E7EA4 ? 0 : 1;
                    (*(void (*)(int*))(*(int*)((char*)*gCameraInterface + 0x60)))(&camArg);
                }
            }
            else
            {
                inner->targetYaw =
                    (s16)getAngle(-*(f32*)((char*)inner + 0x634), -inner->unk63C);
                inner->yaw = inner->targetYaw;
                ((GameObject*)obj)->anim.rotY = 0;
            }
            break;
        }
    case 0x40f:
        ((PlayerState*)state)->baddie.moveSpeed = lbl_803E7F34;
        (*(void (*)(int, int, f32, int))(*(int*)(*gPlayerInterface + 0x20)))(obj, state, fv, 1);
        if (*(s8*)&((PlayerState*)state)->baddie.moveDone != 0)
        {
            u8 anim = inner->curAnimId;
            if (anim != 0x48 && anim != 0x47)
            {
                (*gCameraInterface)->setMode(
                    0x42, 1, 1, 0, NULL, 0, 0xff);
            }
            *(u32*)&((PlayerState*)inner)->flags360 |= 0x800000LL;
            *(int*)&((PlayerState*)state)->baddie.unk308 = (int)fn_802A514C;
            return 2;
        }
        break;
    case 0x40e:
        ((PlayerState*)state)->baddie.moveSpeed = lbl_803E7F34;
        (*(void (*)(int, int, f32, int))(*(int*)(*gPlayerInterface + 0x20)))(obj, state, fv, 1);
        inner->targetYaw =
            (s16)getAngle(inner->hitNormalX, inner->hitNormalZ);
        inner->yaw = inner->targetYaw;
        sqrtf(inner->hitNormalX * inner->hitNormalX +
            inner->hitNormalZ * inner->hitNormalZ);
        ((GameObject*)obj)->anim.rotY = 0;
        if (*(s8*)&((PlayerState*)state)->baddie.moveDone != 0)
        {
            ObjAnim_SetCurrentMove(obj, 0x40d, lbl_803E7EA4, 0);
        }
        break;
    default:
        {
            int curveId = 0x1f;
            int found = (*gRomCurveInterface)->find(&curveId, 1, 0, ((GameObject*)obj)->anim.localPosX,
                                                    ((GameObject*)obj)->anim.localPosY,
                                                    ((GameObject*)obj)->anim.localPosZ);
            if (found != -1)
            {
                int pt = (int)(*gRomCurveInterface)->getById(found);
                int pt2;
                *(f32*)((int)inner + 0x61c) = ((ObjHitVolumeRuntimeTransform*)pt)->jointZ;
                inner->unk620 = ((ObjHitVolumeRuntimeTransform*)pt)->centerX;
                inner->unk624 = ((ObjHitVolumeRuntimeTransform*)pt)->centerY;
                ((GameObject*)obj)->anim.localPosX = ((ObjHitVolumeRuntimeTransform*)pt)->jointZ;
                ((GameObject*)obj)->anim.localPosY = ((ObjHitVolumeRuntimeTransform*)pt)->centerX;
                ((GameObject*)obj)->anim.localPosZ = ((ObjHitVolumeRuntimeTransform*)pt)->centerY;
                inner->targetYaw =
                    (s16)getAngle(inner->hitNormalX, inner->hitNormalZ);
                inner->yaw = inner->targetYaw;
                sqrtf(inner->hitNormalX * inner->hitNormalX +
                    inner->hitNormalZ * inner->hitNormalZ);
                ((GameObject*)obj)->anim.rotY = 0;
                found = ((int (*)(int, int))(*gRomCurveInterface)->slot54)(pt, -1);
                if (found == -1)
                {
                    found = ((int (*)(int, int))(*gRomCurveInterface)->slot60)(pt, -1);
                }
                pt2 = (int)(*gRomCurveInterface)->getById(found);
                *(f32*)((int)inner + 0x628) = *(f32*)((char*)pt2 + 0x8);
                inner->unk62C = *(f32*)((char*)pt2 + 0xc);
                inner->unk630 = *(f32*)((char*)pt2 + 0x10);
                inner->traveledDistance = lbl_803E7EA4;
                PSVECSubtract((f32*)((char*)inner + 0x628), (f32*)((char*)inner + 0x61c), vec);
                inner->travelTargetDistance = PSVECMag(vec);
                PSVECNormalize(vec, (f32*)((char*)inner + 0x634));
            }
            ObjAnim_SetCurrentMove(obj, 0x40e, lbl_803E7EA4, 0);
            {
                u8 anim = inner->curAnimId;
                if (anim != 0x48 && anim != 0x47)
                {
                    (*gCameraInterface)->setMode(
                        0x50, 1, 0, 0, NULL, 0x28, 0xff);
                }
            }
            ((PlayerState*)state)->baddie.animSpeedC = lbl_803E7EA4;
            break;
        }
    }
    PSVECScale((f32*)((char*)inner + 0x634), vec, inner->traveledDistance);
    PSVECAdd((f32*)((char*)inner + 0x61c), vec, &((GameObject*)obj)->anim.localPosX);
    fn_802AB5A4(obj, (int)inner, 7);
    return 0;
}

void playerInitFuncPtrs(int obj)
{
    int* p = gPlayerStateHandlers;
    p[0] = (int)fn_802A7160;
    p[1] = (int)fn_802A6694;
    p[2] = (int)fn_802A5384;
    p[3] = (int)fn_802A5048;
    p[4] = (int)fn_802A4F8C;
    p[5] = (int)fn_802A4D34;
    p[6] = (int)fn_802A4B78;
    p[7] = (int)fn_802A49C8;
    p[8] = (int)fn_802A418C;
    p[9] = (int)fn_802A3F24;
    p[10] = (int)fn_802A3B04;
    p[11] = (int)fn_802A36EC;
    p[12] = (int)fn_802A2EE0;
    p[13] = (int)fn_802A2E8C;
    p[14] = (int)fn_802A2918;
    p[15] = (int)fn_802A1CA8;
    p[16] = (int)fn_802A16CC;
    p[17] = (int)fn_802A14F8;
    p[18] = (int)fn_802A1114;
    p[19] = (int)fn_802A0680;
    p[20] = (int)fn_802A03BC;
    p[21] = (int)fn_802A00E0;
    p[22] = (int)fn_8029FA24;
    p[23] = (int)fn_8029F9D4;
    p[24] = (int)fn_8029F6E4;
    p[25] = (int)fn_8029F108;
    p[26] = (int)fn_8029EBCC;
    p[27] = (int)fn_8029E568;
    p[28] = (int)fn_8029E3F4;
    p[29] = (int)fn_8029DB70;
    p[30] = (int)fn_8029DA60;
    p[31] = (int)fn_8029D900;
    p[32] = (int)fn_8029D7F0;
    p[33] = (int)fn_8029D4C0;
    p[34] = (int)fn_8029D454;
    p[35] = (int)fn_8029D250;
    p[36] = (int)fn_8029CF30;
    p[37] = (int)fn_8029C9C8;
    p[38] = (int)fn_8029BDB4;
    p[39] = (int)fn_8029BC4C;
    p[40] = (int)fn_8029B9FC;
    p[41] = (int)fn_8029B994;
    p[42] = (int)fn_8029B7B0;
    p[43] = (int)fn_8029B6BC;
    p[44] = (int)fn_8029AF9C;
    p[45] = (int)fn_8029ABD8;
    p[46] = (int)fn_8029A76C;
    p[47] = (int)fn_8029A5E4;
    p[48] = (int)fn_80299E44;
    p[49] = (int)fn_80299BB0;
    p[50] = (int)fn_802994D0;
    p[51] = (int)fn_80298E54;
    p[52] = (int)fn_80298CCC;
    p[53] = (int)fn_80298944;
    p[54] = (int)fn_802985FC;
    p[55] = (int)fn_8029852C;
    p[56] = (int)fn_80298380;
    p[57] = (int)fn_80298184;
    p[58] = (int)fn_80297F48;
    p[59] = (int)fn_80297D0C;
    p[60] = (int)fn_80297AD0;
    p[61] = (int)fn_80297854;
    p[62] = (int)fn_80297824;
    p[63] = (int)fn_802977A8;
    p[64] = (int)fn_80297748;
    p[65] = (int)fn_802974A0;
    gPlayerDefaultStateHandler = (int)fn_80297498;
}

int fn_80298944(int obj, int state)
{
    PlayerState* inner = ((GameObject*)obj)->extra;
    f32 f;

    if (*(s8*)&((PlayerState*)state)->baddie.moveJustStartedA != 0)
    {
        ObjHits_MarkObjectPositionDirty(obj);
    }
    f = lbl_803E7EA4;
    ((PlayerState*)state)->baddie.animSpeedC = f;
    ((PlayerState*)state)->baddie.animSpeedB = f;
    ((PlayerState*)state)->baddie.animSpeedA = f;
    ((GameObject*)obj)->anim.velocityX = f;
    ((GameObject*)obj)->anim.velocityY = f;
    ((GameObject*)obj)->anim.velocityZ = f;
    setAButtonIcon(0xe);
    setBButtonIcon(0xa);
    switch (((GameObject*)obj)->anim.currentMove)
    {
    case 0xe0:
        if (((GameObject*)obj)->anim.currentMoveProgress > lbl_803E7E98 &&
            (((PlayerState*)state)->baddie.moveEventFlags & 1) == 0)
        {
            ((PlayerState*)state)->baddie.moveEventFlags |= 1;
            Sfx_PlayFromObject(obj, 0x376);
        }
        if (*(s8*)&((PlayerState*)state)->baddie.moveDone != 0)
        {
            ObjAnim_SetCurrentMove(obj, 0xdf, lbl_803E7EA4, 0);
            ((PlayerState*)state)->baddie.moveSpeed = lbl_803E7F40;
            ((PlayerState*)state)->baddie.moveEventFlags = 0;
        }
        break;
    case 0xde:
        if (((GameObject*)obj)->anim.currentMoveProgress > lbl_803E7E9C &&
            (((PlayerState*)state)->baddie.moveEventFlags & 1) == 0)
        {
            ((PlayerState*)state)->baddie.moveEventFlags |= 1;
            doRumble(lbl_803E7F10);
            Sfx_PlayFromObject(obj, 0x377);
            cfPrisonGuard_setGameBitMirror(gPlayerInteractTarget, 0);
        }
        if (*(s8*)&((PlayerState*)state)->baddie.moveDone != 0)
        {
            ObjAnim_SetCurrentMove(obj, 0xe4, lbl_803E7EA4, 0);
            ((PlayerState*)state)->baddie.moveSpeed = lbl_803E7F40;
            Sfx_PlayFromObject(obj, 0x3c3);
        }
        break;
    case 0xe1:
        if (((GameObject*)obj)->anim.currentMoveProgress > lbl_803E7E98 &&
            (((PlayerState*)state)->baddie.moveEventFlags & 1) == 0)
        {
            ((PlayerState*)state)->baddie.moveEventFlags |= 1;
            Sfx_PlayFromObject(obj, 0x376);
        }
        if (*(s8*)&((PlayerState*)state)->baddie.moveDone != 0)
        {
            ObjAnim_SetCurrentMove(obj, 0xde, lbl_803E7EA4, 0);
            ((PlayerState*)state)->baddie.moveSpeed = lbl_803E7F40;
            ((PlayerState*)state)->baddie.moveEventFlags = 0;
        }
        break;
    case 0xdf:
        if (((GameObject*)obj)->anim.currentMoveProgress > lbl_803E7E9C &&
            (((PlayerState*)state)->baddie.moveEventFlags & 1) == 0)
        {
            ((PlayerState*)state)->baddie.moveEventFlags |= 1;
            doRumble(lbl_803E7F10);
            Sfx_PlayFromObject(obj, 0x377);
            cfPrisonGuard_setGameBitMirror(gPlayerInteractTarget, 1);
        }
        if (*(s8*)&((PlayerState*)state)->baddie.moveDone != 0)
        {
            ObjAnim_SetCurrentMove(obj, 0xe5, lbl_803E7EA4, 0);
            ((PlayerState*)state)->baddie.moveSpeed = lbl_803E7F40;
            Sfx_PlayFromObject(obj, 0x3c3);
        }
        break;
    case 0xe4:
    case 0xe5:
        if (*(s8*)&((PlayerState*)state)->baddie.moveDone != 0)
        {
            *(u32*)&((PlayerState*)inner)->flags360 |= 0x800000LL;
            *(int*)&((PlayerState*)state)->baddie.unk308 = (int)fn_802A514C;
            return 2;
        }
        break;
    default:
        if (cfPrisonGuard_isGameBitMirrorSet(gPlayerInteractTarget) != 0)
        {
            ObjAnim_SetCurrentMove(obj, 0xe1, lbl_803E7EA4, 0);
        }
        else
        {
            ObjAnim_SetCurrentMove(obj, 0xe0, lbl_803E7EA4, 0);
        }
        staffactivated_calcInteractionTargetXZ(gPlayerInteractTarget, (char*)obj + 0xc, (char*)obj + 0x14);
        ((PlayerState*)state)->baddie.moveSpeed = lbl_803E7F40;
        ((PlayerState*)state)->baddie.moveEventFlags = 0;
        inner->targetYaw = *(s16*)gPlayerInteractTarget;
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

int fn_802985FC(int obj, int state, f32 fv)
{
    PlayerState* inner = ((GameObject*)obj)->extra;
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
        ObjHits_MarkObjectPositionDirty(obj);
    }
    if (((ByteFlags*)((char*)inner + 0x3f0))->b20 == 0 &&
        lbl_803E7EA4 != inner->verticalVel)
    {
        *(int*)&((PlayerState*)state)->baddie.unk308 = 0;
        return 0x42;
    }
    switch (((GameObject*)obj)->anim.currentMove)
    {
    case 0x84:
        if (*(s8*)&((PlayerState*)state)->baddie.moveDone != 0)
        {
            ObjAnim_SetCurrentMove(obj, 0x85, lbl_803E7EA4, 0);
            ((PlayerState*)state)->baddie.moveSpeed = lbl_803E7EFC;
        }
        break;
    case 0x85:
        inner->chargeLevel =
            inner->chargeLevel + lbl_803E7ED4 * fv / lbl_803E7EF0;
        inner->chargeLevel =
            lbl_803E7E98 * fv + inner->chargeLevel;
        if (inner->chargeLevel >=
            (f32)(u32) * (u8*)((char*)inner + 0x41c))
        {
            int amt;
            int r35c;
            int v;
            int hi;
            Sfx_PlayFromObject(obj, SFXmammoth_breath2);
            amt = -((PlayerState*)inner)->chargeCapacity;
            r35c = *(int*)((char*)(*(int*)&((GameObject*)obj)->extra) + 0x35c);
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
                Sfx_PlayFromObject(0, SFXmammoth_dirtstep);
            }
            ObjAnim_SetCurrentMove(obj, 0x86, lbl_803E7EA4, 0);
            ((PlayerState*)state)->baddie.moveSpeed = lbl_803E7EF8;
        }
        break;
    case 0x86:
        if (((ByteFlags*)((char*)inner + 0x3f3))->b10 == 0 &&
            ((GameObject*)obj)->anim.currentMoveProgress > lbl_803E7EFC)
        {
            void* tricky = getTrickyObject();
            if (tricky != NULL)
            {
                trickyImpress(tricky);
            }
            Sfx_PlayFromObject(obj, SFXmammoth_huff1);
            superQuakeFn_8016d9fc((char*)obj + 0xc);
            ((ByteFlags*)((char*)inner + 0x3f3))->b10 = 1;
            doRumble(lbl_803E7F30);
        }
        if (*(s8*)&((PlayerState*)state)->baddie.moveDone != 0)
        {
            *(u32*)&((PlayerState*)inner)->flags360 |= 0x800000LL;
            *(int*)&((PlayerState*)state)->baddie.unk308 = (int)fn_802A514C;
            return 2;
        }
        break;
    default:
        Sfx_PlayFromObject(obj, SFXmammoth_huff2);
        f = lbl_803E7EA4;
        ((PlayerState*)state)->baddie.animSpeedC = f;
        ((PlayerState*)state)->baddie.animSpeedB = f;
        ((PlayerState*)state)->baddie.animSpeedA = f;
        ((GameObject*)obj)->anim.velocityX = f;
        ((GameObject*)obj)->anim.velocityY = f;
        ((GameObject*)obj)->anim.velocityZ = f;
        ObjAnim_SetCurrentMove(obj, 0x84, f, 0);
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

void fn_802AE9C8(int obj, int inner, int state)
{
    if (((GameObject*)obj)->anim.currentMoveProgress > lbl_803E7E98)
    {
        ObjAnim_SetCurrentMove(obj, 0x91, lbl_803E7EA4, 0);
    }
    else
    {
        ObjAnim_SetCurrentMove(obj, 0x12, lbl_803E7EA4, 0);
    }
    ObjAnim_SetCurrentEventStepFrames((ObjAnimComponent*)obj, 0xf);

    ((PlayerState*)inner)->maxSpeed = lbl_803E8068;
    ((PlayerState*)inner)->currentSpeed =
        lbl_803E7EA0 * (lbl_803E806C * ((PlayerState*)state)->baddie.inputMagnitude) +
        lbl_803E7EB4 * ((PlayerState*)state)->baddie.animSpeedC;
    ((PlayerState*)inner)->currentSpeed =
        (((PlayerState*)inner)->currentSpeed < lbl_803E7F18)
            ? lbl_803E7F18
            : ((((PlayerState*)inner)->currentSpeed > ((PlayerState*)inner)->maxSpeed)
                   ? ((PlayerState*)inner)->maxSpeed
                   : ((PlayerState*)inner)->currentSpeed);
    {
        f32 a = ((PlayerState*)inner)->currentSpeed;
        ((PlayerState*)state)->baddie.animSpeedA = a;
        ((PlayerState*)state)->baddie.animSpeedC = a;
    }

    ((GameObject*)obj)->anim.velocityY = ((PlayerState*)state)->baddie.animSpeedA / lbl_803E8068;
    {
        f32 v = ((GameObject*)obj)->anim.velocityY;
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
        ((GameObject*)obj)->anim.velocityY = clamped;
    }
    ((GameObject*)obj)->anim.velocityY = ((GameObject*)obj)->anim.velocityY * lbl_803DC680;
    ((GameObject*)obj)->anim.velocityY =
        (((GameObject*)obj)->anim.velocityY < lbl_803E7E98)
            ? lbl_803E7E98
            : ((((GameObject*)obj)->anim.velocityY > lbl_803DC680)
                   ? lbl_803DC680
                   : ((GameObject*)obj)->anim.velocityY);
    ((PlayerState*)state)->baddie.moveSpeed =
        lbl_803E7EE0 / (lbl_803E7ED4 * lbl_803DC680 / lbl_803DC67C);
    ((PlayerState*)inner)->groundRefY = ((GameObject*)obj)->anim.worldPosY;
    ((PlayerState*)inner)->fallThresholdY = ((GameObject*)obj)->anim.worldPosY - lbl_803E7ED8;

    ((ByteFlags*)((char*)inner + 0x3f0))->b08 = 1;
    ((ByteFlags*)((char*)inner + 0x3f0))->b04 = 0;
    ((PlayerState*)inner)->staffHoldFrames = 0;
    ((ByteFlags*)((char*)inner + 0x3f0))->b10 = 0;
    ((ByteFlags*)((char*)inner + 0x3f0))->b80 = 0;
    staffFn_80170380(gPlayerStaffObject, 2);
    ((ByteFlags*)((char*)inner + 0x3f0))->b02 = 0;
    *(u32*)&((PlayerState*)inner)->flags360 |= 0x800000LL;
    ObjHits_SyncObjectPositionIfDirty(obj);
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
    if (((ByteFlags*)((char*)inner + 0x3f1))->b10 &&
        ((PlayerState*)inner)->curAnimId != 0x48 &&
        ((PlayerState*)inner)->curAnimId != 0x47 && getCurSeqNo() == 0)
    {
        (*gCameraInterface)->setMode(
            0x42, 0, 1, 0, NULL, 0x1e, 0xff);
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
        Sfx_PlayFromObject(obj, sfxId);
    }
    ((PlayerState*)inner)->isHoldingObject = 0;
    {
        void* sub = *(void**)((char*)inner + 0x7f8);
        if (sub != NULL)
        {
            s16 id = ((GameObject*)sub)->anim.seqId;
            if (id == 0x3cf || id == 0x662)
            {
                objThrowFn_80182504((int)sub);
            }
            else
            {
                objSaveFn_800ea774((int)sub);
            }
            *(s16*)((char*)((PlayerState*)inner)->heldObj + 0x6) &= ~0x4000;
            *(int*)((char*)((PlayerState*)inner)->heldObj + 0xf8) = 0;
            ((PlayerState*)inner)->heldObj = 0;
        }
    }
}

int fn_8029D4C0(int obj, int state, f32 fv)
{
    PlayerState* inner = ((GameObject*)obj)->extra;
    u16 sfxId;
    int d;

    switch (((GameObject*)obj)->anim.currentMove)
    {
    case 0x450:
        ((PlayerState*)state)->baddie.moveSpeed = lbl_803E7FCC;
        if (((GameObject*)obj)->anim.velocityY < lbl_803E7EE0 &&
            ((ByteFlags*)((char*)inner + 0x3f1))->b01)
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
        if (((GameObject*)obj)->anim.velocityY < lbl_803E7EE0 &&
            ((ByteFlags*)((char*)inner + 0x3f1))->b01)
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
        ((GameObject*)obj)->anim.velocityZ =
            ((GameObject*)obj)->anim.velocityX = lbl_803E7EA4;
        break;
    case 0xc8:
        ((PlayerState*)state)->baddie.moveSpeed = lbl_803E7EF8;
        if (*(s8*)&((PlayerState*)state)->baddie.moveDone != 0)
        {
            *(u32*)&((PlayerState*)inner)->flags360 |= 0x800000LL;
            *(int*)&((PlayerState*)state)->baddie.unk308 = (int)fn_802A514C;
            return -1;
        }
        break;
    default:
        ObjAnim_SetCurrentMove(obj, 0xc4, lbl_803E7EA4, 0);
        break;
    }
    *(s8*)((char*)state + 0x34c) |= 2;
    ((GameObject*)obj)->anim.velocityX =
        ((GameObject*)obj)->anim.velocityX * powfBitEstimate(lbl_803E7FD0, fv);
    ((GameObject*)obj)->anim.velocityZ =
        ((GameObject*)obj)->anim.velocityZ * powfBitEstimate(lbl_803E7FD0, fv);
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
                if (GameBit_Get(0xc52))
                {
                    *(u8*)&((GameObject*)obj)->anim.resetHitboxMode |= INTERACT_FLAG_DISABLED;
                }
                break;
            case 0x46a55:
                if (GameBit_Get(0xc53))
                {
                    *(u8*)&((GameObject*)obj)->anim.resetHitboxMode |= INTERACT_FLAG_DISABLED;
                }
                break;
            case 0x49928:
                if (GameBit_Get(0xc54))
                {
                    *(u8*)&((GameObject*)obj)->anim.resetHitboxMode |= INTERACT_FLAG_DISABLED;
                }
                break;
            }
            if ((*(u8*)&((GameObject*)obj)->anim.resetHitboxMode & INTERACT_FLAG_ACTIVATED) != 0)
            {
                buttonDisable(0, 0x100);
                switch (*(int*)((char*)r4c + 0x14))
                {
                case 0x46a51:
                    if (GameBit_Get(0xc38) != 0 && GameBit_Get(0xc39) != 0 &&
                        GameBit_Get(0xc3a) != 0)
                    {
                        if (GameBit_Get(0xc52) == 0)
                        {
                            GameBit_Set(0xc52, 1);
                            (*gObjectTriggerInterface)
                                ->runSequence(3, (void*)obj, -1);
                            *(u8*)((char*)sub + 0x2e) = 1;
                            *(u8*)&((GameObject*)obj)->anim.resetHitboxMode |= INTERACT_FLAG_DISABLED;
                        }
                    }
                    else
                    {
                        (*gObjectTriggerInterface)
                            ->runSequence(2, (void*)obj, -1);
                    }
                    break;
                case 0x46a55:
                    if (GameBit_Get(0xc3b) != 0 && GameBit_Get(0xc3c) != 0 &&
                        GameBit_Get(0xc3d) != 0)
                    {
                        if (GameBit_Get(0xc53) == 0)
                        {
                            GameBit_Set(0xc53, 1);
                            (*gObjectTriggerInterface)
                                ->runSequence(5, (void*)obj, -1);
                            *(u8*)((char*)sub + 0x2e) = 1;
                            *(u8*)&((GameObject*)obj)->anim.resetHitboxMode |= INTERACT_FLAG_DISABLED;
                        }
                    }
                    else
                    {
                        (*gObjectTriggerInterface)
                            ->runSequence(4, (void*)obj, -1);
                    }
                    break;
                case 0x49928:
                    if (GameBit_Get(0xc3e) != 0 && GameBit_Get(0xc3f) != 0 &&
                        GameBit_Get(0xc40) != 0)
                    {
                        if (GameBit_Get(0xc54) == 0)
                        {
                            GameBit_Set(0xc54, 1);
                            (*gObjectTriggerInterface)
                                ->runSequence(7, (void*)obj, -1);
                            *(u8*)((char*)sub + 0x2e) = 1;
                            *(u8*)&((GameObject*)obj)->anim.resetHitboxMode |= INTERACT_FLAG_DISABLED;
                        }
                    }
                    else
                    {
                        (*gObjectTriggerInterface)
                            ->runSequence(6, (void*)obj, -1);
                    }
                    break;
                }
            }
        }
        else
        {
            *(u8*)&((GameObject*)obj)->anim.resetHitboxMode |= INTERACT_FLAG_DISABLED;
        }
        if (*(s8*)&((PlayerState*)state)->baddie.moveJustStartedB != 0 || *(s8*)&((PlayerState*)state)->baddie.moveDone
            != 0)
        {
            (*(void (*)(int, int, int))(*(int*)(*gPlayerInterface + 0x14)))(obj, state, 0);
        }
    }
    return 0;
}

void playerProcessQueuedItemCommand(int obj, int state)
{
    u8 noMatch;
    s16 cmd;
    s16 item;

    if (((PlayerState*)state)->buttonsJustPressed & 0x800)
    {
        int yButtonItemResult;
        if (((PlayerState*)state)->buttonsJustPressed & 0x800)
        {
            yButtonItemResult = getYButtonItem(&item);
        }
        if (yButtonItemResult == 1)
        {
            buttonDisable(0, 0x800);
            ((PlayerState*)state)->buttonsJustPressed &= ~0x800;
            ((PlayerState*)state)->queuedItemCommand = item;
        }
    }

    cmd = ((PlayerState*)state)->queuedItemCommand;
    if (cmd != -1 && cmd != ((PlayerState*)state)->animState && getCurSeqNo() == 0)
    {
        s16 sel = ((PlayerState*)state)->queuedItemCommand;
        noMatch = 0;
        switch (sel)
        {
        case 0x2d:
        case 0x958:
        case 0x5ce:
            if (fn_802A9B1C(obj, state, sel) != 0)
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
                if (c8 == 0x52 && !f1->b20 && !f1->b10 &&
                    ((PlayerState*)state)->baddie.controlMode != 0x1d)
                {
                    break;
                }
                if (f1->b20)
                {
                    s16 v = ((GameObject*)obj)->anim.rotX;
                    ((PlayerState*)state)->yaw = v;
                    ((PlayerState*)state)->targetYaw = v;
                    ((PlayerState*)state)->lastInputHeading = v;
                    ((PlayerState*)state)->baddie.animSpeedB = lbl_803E7EA4;
                }
                f1->b20 = 0;
                if (f1->b10)
                {
                    u8 c = ((PlayerState*)state)->curAnimId;
                    if (c != 0x48 && c != 0x47 && getCurSeqNo() == 0)
                    {
                        (*gCameraInterface)->setMode(
                            0x42, 0, 1, 0, NULL, 0x1e, 0xff);
                        f1->b10 = 0;
                    }
                }
                cameraSetInterpMode(2);
                (*gCameraInterface)->setMode(
                    0x52, 1, 0, 0, NULL, 0x2d, 0xff);
                ((ByteFlags*)((char*)state + 0x3f6))->b40 = 1;
                (*(void (*)(int, int, int))(*(int*)(*gPlayerInterface + 0x14)))(obj, state, 0x2a);
                *(int*)&((PlayerState*)state)->baddie.unk304 = (int)fn_8029A4A8;
                fn_802AB38C(obj, state, ((PlayerState*)state)->queuedItemCommand);
            }
            else
            {
                noMatch = 1;
            }
            break;
        case 0x957:
            if (fn_802A97D0(obj, state) != 0)
            {
                fn_802AB38C(obj, state, ((PlayerState*)state)->queuedItemCommand);
            }
            else
            {
                noMatch = 1;
            }
            break;
        case 0x107:
        case 0xc55:
            if (fn_802A9A0C(obj, state) != 0)
            {
                fn_802AB38C(obj, state, ((PlayerState*)state)->queuedItemCommand);
            }
            else
            {
                noMatch = 1;
            }
            break;
        case 0x40:
            {
                PlayerState* inner = ((GameObject*)obj)->extra;
                int ok;
                if (((PlayerState*)state)->baddie.targetObj != NULL ||
                    *(s16*)((char*)inner->playerStatus + 4) < 0xa ||
                    ((ByteFlags*)((char*)inner + 0x3f3))->b08)
                {
                    ok = 0;
                }
                else if (((PlayerState*)state)->baddie.controlMode == 1 ||
                    ((PlayerState*)state)->baddie.controlMode == 2)
                {
                    ok = 1;
                }
                else
                {
                    ok = 0;
                }
                if (ok && !((ByteFlags*)((char*)state + 0x3f3))->b08)
                {
                    fn_802AB38C(obj, state, sel);
                }
                else
                {
                    noMatch = 1;
                }
                break;
            }
        case 0x5bd:
            if (fn_802A98FC(obj, state) != 0)
            {
                fn_802AB38C(obj, state, ((PlayerState*)state)->queuedItemCommand);
            }
            else
            {
                noMatch = 1;
            }
            break;
        default:
            fn_802AB38C(obj, state, sel);
            break;
        }
        if (noMatch)
        {
            Sfx_PlayFromObject(0, SFXsp_skeep_mumb1);
        }
    }

    ((PlayerState*)state)->queuedItemCommand = -1;
}

void fn_802AAD44(int obj)
{
    int state = *(int*)&((GameObject*)obj)->extra;
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

    height = ((PlayerState*)state)->unk7D0;
    setTextColor((u32*)0, 0xff, 0xff, 0xff, 0x80);
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

    xf.px = ((GameObject*)obj)->anim.localPosX - playerMapOffsetX;
    xf.py = ((GameObject*)obj)->anim.localPosY;
    xf.pz = ((GameObject*)obj)->anim.localPosZ - playerMapOffsetZ;
    xf.rx = ((PlayerState*)state)->targetYaw;
    xf.ry = 0;
    xf.rz = 0;
    xf.scale = lbl_803E7F6C;
    setMatrixFromObjectTransposed(&xf, mtx);
    PSMTXConcat(Camera_GetViewMatrix(), mtx, mtx);
    GXLoadPosMtxImm(mtx, 0);
    drawFn_8005cf8c(vp, lbl_802C2B30, 0xc);

    if (((PlayerState*)state)->unk7D0 >= lbl_803E80E0)
    {
        int t = ((GameObject*)obj)->anim.alpha - (framesThisStep << 2);
        if (t < 0)
        {
            t = 0;
        }
        ((GameObject*)obj)->anim.alpha = t;
    }
    GXSetColorUpdate(1);
}

void fn_8029560C(int obj, void* statep)
{
    int* state = (int*)statep;
    int v = *state;
    if ((void*)gPlayerModelChain != NULL)
    {
        ObjModelChain_SetOrigin((ObjModelChain*)gPlayerModelChain, lbl_803DC670, lbl_803DC674, lbl_803DC678);
        playerTailFn_80026b3c(state, v, gPlayerModelChain, fn_80295334);
    }
}

void fn_80295918(int obj, int sel, f32 fval)
{
    int state = *(int*)&((GameObject*)obj)->extra;
    int iv = (int)fval;
    switch (sel)
    {
    case 1:
        {
            u8 n = ((PlayerState*)state)->queuedBitCount;
            u8 v = (u8)iv;
            if (n < 4)
            {
                ((PlayerState*)state)->queuedBitCount += 1;
                *((u8*)((char*)state + 0x8b9) + n) = v;
            }
            break;
        }
    case 6:
        (*(void (*)(int, int, int))(*(int*)(*gPlayerInterface + 0x14)))(obj, state, 0x3f);
        break;
    case 5:
        (*(void (*)(int, int, int))(*(int*)(*gPlayerInterface + 0x14)))(obj, state, 1);
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

int fn_80295A04(int obj, int sel)
{
    int state = *(int*)&((GameObject*)obj)->extra;
    switch (sel)
    {
    case 1:
        if ((*(int*)((char*)state + 0x310) & 0x1000) != 0 ||
            (((GameObject*)obj)->objectFlags & 0x1000) != 0)
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
                key = ((GameObject*)obj)->anim.currentMove;
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
        return *(s8*)&((PlayerState*)state)->baddie.unk34D == 3;
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
            if (p != 0) return *(s16*)((char*)p + 0x46);
            return 0;
        }
    }
    return 0;
}

/*
 * Mask passed to hitDetectFn_80065e50 / hitDetectFn_800691c0 to pick what a
 * collision query tests. Low byte = behaviour flags (decoded from
 * hitDetectFn_800691c0); the high bits select the map-surface type (consumed by
 * mapLoadBlocksFn_800685cc; per-type meanings not yet decoded). Only the climb
 * mask is meaning-confirmed so far (live-verified ladder probe); the others are
 * left as raw literals at their call sites until traced.
 */
enum HitQueryMask {
    HITQUERY_TEST_OBJECT_HITBOXES  = 0x01, /* also test reset-object hitboxes, not just map triangles */
    HITQUERY_REUSE_TRIANGLE_BUFFER = 0x10, /* reuse the loaded map-triangle buffer (skip block reload) */
    HITQUERY_SKIP_CULLED_OBJECTS   = 0x80, /* skip objects whose modelInstance flag 0x01000000 is set */
    /* Composite the player's ladder/climb probe issues: a climb-typed map
     * surface, map triangles only (no 0x01 -> no object hitboxes). Live-verified
     * in Dolphin as the query that detects a ladder and seeds the climb state. */
    HITQUERY_CLIMB_SURFACE = 0x204,
};

/*
 * Probe for a climbable map surface (a HITQUERY_CLIMB_SURFACE collision hit) and,
 * if one is found near the player, seed the climb state at `dst` (PlayerState's
 * climb block: climbStepCount = surface height / step size, climbStepHeight,
 * climbStep) and return 1; return 0 when no ladder is in range. Called per
 * candidate direction from the player move handler.
 */
int player_probeClimbable(int obj, int p4, int src, int dst, int flag)
{
    int** hits;
    f32 pos[3];
    f32 y;
    f32 minDist;
    int best;
    int i;
    int count;
    int* chosen;
    f32 zero;

    *(u8*)((char*)dst + 3) = 0;
    ((ByteFlags*)((char*)dst + 0x63))->b80 = 1;
    if ((*(s8*)((char*)src + 0x52) & 0x08) == 0)
    {
        ((ByteFlags*)((char*)dst + 0x63))->b80 = 0;
    }

    {
        f32 t = lbl_803E7E98;
        *(f32*)((char*)dst + 0x48) =
            *(f32*)((char*)src + 0x4) +
            t * (*(f32*)((char*)src + 0x8) - *(f32*)((char*)src + 0x4));
        *(f32*)((char*)dst + 0x4c) = *(f32*)((char*)src + 0xc);
        *(f32*)((char*)dst + 0x50) =
            *(f32*)((char*)src + 0x14) +
            t * (*(f32*)((char*)src + 0x18) - *(f32*)((char*)src + 0x14));
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
    *(f32*)((char*)dst + 0x3c) = zero = lbl_803E7EA4;
    *(f32*)((char*)dst + 0x40) = *(f32*)((int)src + 0x1c);
    *(f32*)((char*)dst + 0x44) =
        -(*(f32*)((char*)dst + 0x48) * *(f32*)((char*)dst + 0x38) +
            *(f32*)((char*)dst + 0x4c) * *(f32*)((char*)dst + 0x3c) +
            *(f32*)((char*)dst + 0x50) * *(f32*)((char*)dst + 0x40));

    *(f32*)((char*)dst + 0x54) = *(f32*)((char*)p4 + 0x768);
    *(f32*)((char*)dst + 0x58) = zero;
    *(f32*)((char*)dst + 0x5c) = *(f32*)((char*)p4 + 0x770);
    *(f32*)((char*)dst + 0x18) =
        *(f32*)((char*)dst + 0x54) * *(f32*)((char*)dst + 0x38) +
        *(f32*)((char*)dst + 0x58) * *(f32*)((char*)dst + 0x3c) +
        *(f32*)((char*)dst + 0x5c) * *(f32*)((char*)dst + 0x40) +
        *(f32*)((char*)dst + 0x44);

    *(s8*)((char*)dst + 0x62) = (s8)(int)*(s8*)((char*)src + 0x53);

    if (*(f32*)((char*)dst + 0x18) > lbl_803E80A4 &&
        *(f32*)((char*)dst + 0x18) < lbl_803E80A8)
    {
    *(f32*)((char*)dst + 0x8) = *(f32*)((char*)src + 0xc);
    PSVECScale((f32*)((char*)src + 0x1c), pos, -(&lbl_803DC6B8)[1]);
    PSVECAdd((f32*)((int)dst + 0x48), pos, pos);
    y = *(f32*)((char*)src + 0x3c);
    pos[1] = y;
    count = hitDetectFn_80065e50(obj, pos[0], y, pos[2], &hits, 0, HITQUERY_CLIMB_SURFACE);

    minDist = lbl_803E80AC;
    best = -1;
    for (i = 0; i < count; i++)
    {
        int* entry = hits[i];
        if (*(f32*)((char*)entry + 0x8) > lbl_803E80B0)
        {
            f32 d = pos[1] - *(f32*)((char*)entry + 0x0);
            if (d < lbl_803E7EA4)
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
    *(f32*)((char*)dst + 0x4) = *(f32*)((char*)chosen + 0x0);
    *(s8*)((char*)dst + 0x1) =
        (s8)(s32)((lbl_803E80B4 + (*(f32*)((char*)src + 0x3c) - *(f32*)((char*)dst + 0x8))) /
            lbl_803E80B8);
    *(f32*)((char*)dst + 0xc) =
        (*(f32*)((char*)src + 0x3c) - *(f32*)((char*)dst + 0x8)) /
        (f32) * (s8*)((char*)dst + 0x1);

    if (((GameObject*)obj)->anim.localPosY > *(f32*)((char*)dst + 0x4) - lbl_803E7ED8)
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

void fn_802AEF34(int obj, int state)
{
    int prevChanged;
    int changed;
    int model;
    f32 f31;
    void* p;

    model = *(int*)((char*)Obj_GetActiveModel(obj) + 0x30);
    prevChanged = 0;

    if (*(s16*)&((PlayerState*)state)->staffAnimState != 3)
    {
        u8 b = ((PlayerState*)state)->staffActionRequest;
        if (b == 1)
        {
            staffDoGrowShrinkAnim(gPlayerPathObject, 0, ((ByteFlags*)((char*)state + 0x3f4))->b08, 0);
            ((PlayerState*)state)->staffGrown = 0;
            if (*(s16*)&((PlayerState*)state)->staffAnimState != 0 && *(s16*)&((PlayerState*)state)->staffAnimState != 0xf)
            {
                *(s16*)&((PlayerState*)state)->staffAnimState = 3;
            }
        }
        else if (b == 4)
        {
            staffDoGrowShrinkAnim(gPlayerPathObject, 1, ((ByteFlags*)((char*)state + 0x3f4))->b08, 0);
            ((PlayerState*)state)->staffGrown = 1;
            if (*(s16*)&((PlayerState*)state)->staffAnimState != 0 && *(s16*)&((PlayerState*)state)->staffAnimState != 0xf)
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
                ((int (*)(int, int, f32, int))Object_ObjAnimSetMove)(
                    obj, ((GameObject*)obj)->anim.currentMove,
                    ((GameObject*)obj)->anim.currentMoveProgress, 0);
                p = *(void**)((char*)state + 0x4b8);
                if (p != NULL &&
                    (*(s16*)((char*)p + 0x44) == 0x1c || *(s16*)((char*)p + 0x44) == 0x2a))
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
                staffDoGrowShrinkAnim(gPlayerPathObject, 1, 0, 0);
                *(s16*)&((PlayerState*)state)->staffAnimState = 3;
                changed = 1;
            }
            else
            {
                ((int (*)(int, f32, f32, int))Object_ObjAnimAdvanceMove)(
                    obj, lbl_803E7F20, lbl_803E7EE0, 0);
            }
            break;
        case 1:
            if (prevChanged != 0)
            {
                ((int (*)(int, int, f32, int))Object_ObjAnimSetMove)(
                    obj, ((GameObject*)obj)->anim.currentMove,
                    ((GameObject*)obj)->anim.currentMoveProgress, 0);
                p = *(void**)((char*)state + 0x4b8);
                if (p != NULL &&
                    (*(s16*)((char*)p + 0x44) == 0x1c || *(s16*)((char*)p + 0x44) == 0x2a))
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
                ((int (*)(int, f32, f32, int))Object_ObjAnimAdvanceMove)(
                    obj, f31, lbl_803E7EE0, 0);
            }
            break;
        case 0xf:
            if (prevChanged != 0)
            {
                ((int (*)(int, int, f32, int))Object_ObjAnimSetMove)(
                    obj, ((GameObject*)obj)->anim.currentMove,
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
                if (bf->b10 || bf->b04 || bf->b08 || bf->b20 ||
                    ((PlayerState*)state)->baddie.controlMode == 0x36)
                {
                    ok = 0;
                }
                else
                {
                    s16 t = ((PlayerState*)state)->baddie.controlMode;
                    ok = (u16)(t - 1) <= 1 || (u16)(t - 0x24) <= 1 ||
                        ((PlayerState*)state)->baddie.targetObj != NULL;
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
                ((int (*)(int, int, f32, int))Object_ObjAnimSetMove)(
                    obj, ((GameObject*)obj)->anim.currentMove,
                    ((GameObject*)obj)->anim.currentMoveProgress, 0);
            }
            if (*(u16*)((char*)model + 0x58) == 0)
            {
                ((GameObject*)obj)->anim.activeMove = -1;
                *(s16*)&((PlayerState*)state)->staffAnimState = 0;
            }
            else
            {
                ((int (*)(int, f32, f32, int))Object_ObjAnimAdvanceMove)(
                    obj, lbl_803E7EA4, timeDelta, 0);
                Object_ObjAnimSetMoveProgress(((GameObject*)obj)->anim.currentMoveProgress, (ObjAnimComponent*)obj);
            }
            break;
        default:
            if (((PlayerState*)state)->staffGrown != 0)
            {
                if (((PlayerState*)state)->staffActionRequest == 0)
                {
                    staffDoGrowShrinkAnim(gPlayerPathObject, 0, 0, 0);
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
    }
    while (changed != 0);
}
