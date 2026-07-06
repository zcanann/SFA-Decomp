#include "main/audio/sfx.h"
#include "main/gamebits.h"
#include "main/game_object.h"
#include "main/audio/sfx_ids.h"
#include "main/objhits.h"
#include "main/objseq.h"
#include "main/obj_placement.h"
#include "main/sfa_shared_decls.h"

/* object group queried to find this object's target */
#define SNOWCLAW_TARGET_OBJGROUP 0x1e

typedef struct SnowclawState
{
    u8 pad0[0x4 - 0x0];
    s32 moveTablePtr;
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
    u8 pad98[0x9C - 0x98];
    s32 attackDelay;
    u8 mountAlpha; /* 0xA0: opacity byte (default 0xff) written to obj+0x37 while mounted */
    u8 hitFlag;
    u8 dropIndex;
    s8 dropIndexApplied;
    u8 health;
    s8 hitCooldown;
    u8 tickCounter;
    u8 padA7[0xA8 - 0xA7];
    s16 moveIdBase;
    u8 flags;
    u8 padAB[0xAC - 0xAB];
    f32 particleAlpha;
} SnowclawState;

typedef struct
{
    u8 b0 : 1;
    u8 flag6 : 1;
    u8 rest : 6;
} SnowclawAaFlags;

typedef struct
{
    s16 v[5];
} SnowClawAnimTbl;

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
    s8 launchMode;     /* 0x19: bomb launch/aim mode (switched on to pick launchAngle: 0=default drop, 1=aim at player) */
    s16 launchAngle;   /* 0x1a */
} SnowClawBombSetup;

extern void Obj_FreeObject(int obj);
extern int Obj_GetPlayerObject(void);
extern int fn_802972A8(int obj);
extern int ObjGroup_FindNearestObject(int kind, int obj, f32* maxDistance);
extern void s16toFloat(void* p, int duration);
extern u8 gSnowClawMoveTable[];
extern f32 lbl_803E66EC;
extern int gSnowClawDropBombAngle;
extern void storeZeroToFloatParam(void* p);
extern void objSeqInitFn_80080078(void* table, int n);
extern void objRenderModelAndHitVolumes(int obj, int p2, int p3, int p4, int p5, f32 scale);
extern int randomGetRange(int lo, int hi);
extern int Obj_SetupObject(int obj, int a, int b, int c, int d);
extern u8 Obj_IsLoadingLocked(void);
extern int Obj_AllocObjectSetup(int extraSize, int id);
extern int objUpdateOpacity(int sub);
extern void ObjLink_AttachChild(int parent, int child, u16 linkMode);
extern void ObjPath_GetPointWorldPosition(int obj, int pointIndex, float* outX, float* outY, float* outZ, int useInputPosition);
extern void objParticleFn_80099d84(int obj, f32 a, int b, f32 c, int d);
extern f32 lbl_803E66F0;
extern f32 lbl_803E6708;
extern f32 lbl_803E670C;
extern f32 lbl_803E6710;
extern int getAngle(float y, float x);
extern void* loadObjectAtObject(int obj, int spawn);
extern f32 lbl_803E66E0;
extern void ObjLink_DetachChild(int obj, int* child);
extern void spawnExplosion(int obj, f32 f, int a, int b, int c, int d, int e, int g, int h);


u32 gSnowClawHurtSfxTable[8] = {0x2EF, 0x2EE, 0x2ED, 0x2EC, 0x2EB, 0x0497049C, 0x03A2049C, 0x07D007D1};
extern u8 framesThisStep;
extern f32 lbl_803E6720;
extern f32 lbl_803E6724;
extern f32 lbl_803E6728;
extern f32 gSnowClawPi;
extern f32 lbl_803E6730;
extern f32 lbl_803E6734;
extern f32 lbl_803E6738;
extern f32 lbl_803E66F4;
extern SnowClawAnimTbl gSnowClawDropObjectTable;
extern f32 lbl_803DC224;
extern f32 lbl_803E66E4;
extern f32 lbl_803E66E8;
extern f32 lbl_803E66F8;
extern int Obj_GetYawDeltaToObject(int obj, int other, int flags);

extern int* ObjGroup_GetObjects(int group, int* countOut);
extern int seqStreamLookupFn_8007fff8(void* table, int count, int key);
extern int timerCountDown(void* timer);
extern int fn_801EC9F4(int obj);
extern int fn_801EC9BC(int obj);
extern void fn_80098B18(int obj, f32 scale, int type, int mode, int arg5, f32* vec);
extern u32 gSnowClawPulseTable[8];
extern s32 lbl_8032A340[];
extern int lbl_803DC220;
extern f32 lbl_803DC218;
extern f32 lbl_803DC21C;

int snowclaw_getExtraSize(void);
int snowclaw_getObjectTypeId(void);
void snowclaw_release(void);
void snowclaw_initialise(void);
void snowclaw_free(int obj);
void snowclaw_init(int* obj, u8* init);
void snowclaw_spawnDropBomb(int obj, int a, int b, int c);
void snowclaw_updateMountAttack(int obj, int mount);
void snowclaw_syncMountTransform(int obj, int sub, int p2, int p3, int p4, int p5, int opacity, int a8, int a9);
void snowclaw_render(int obj, int p2, int p3, int p4, int p5, int vis);
void snowclaw_hitDetect(int obj);
void snowclaw_update(int obj);
int snowclaw_animEventCallback(int obj, int a2, ObjSeqState* seq);

int snowclaw_getExtraSize(void) { return 0xb0; }

int snowclaw_getObjectTypeId(void) { return 0x3; }

void snowclaw_release(void)
{
}

void snowclaw_initialise(void)
{
}

void snowclaw_free(int obj)
{
    if (((GameObject*)obj)->childObjs[0] != NULL)
    {
        Obj_FreeObject(*(int*)&((GameObject*)obj)->childObjs[0]);
    }
}

void snowclaw_init(int* obj, u8* init)
{
    u8* table;
    int* inner;

    table = (u8*)(int)gSnowClawMoveTable;
    ((GameObject*)obj)->animEventCallback = snowclaw_animEventCallback;
    if (((GameObject*)obj)->anim.modelState != NULL)
    {
        ((GameObject*)obj)->anim.modelState->flags |= 0x4000;
        ((GameObject*)obj)->anim.modelState->shadowTintA = 0x64;
        ((GameObject*)obj)->anim.modelState->shadowTintB = 0x96;
    }
    inner = ((GameObject*)obj)->extra;
    *(int*)inner = 0;
    ((SnowclawState*)inner)->dropIndex = init[0x27];
    ((SnowclawState*)inner)->health = 4;
    ((SnowclawState*)inner)->hitCooldown = -1;
    switch (((GameObject*)obj)->anim.seqId)
    {
    case 0x16d:
    case 0x170:
    default:
        ((SnowclawState*)inner)->moveTablePtr = (int)(table + 0x58);
        ((SnowclawState*)inner)->moveIdBase = 0x100;
        break;
    case 0x389:
    case 0x38a:
    case 0x4d3:
        ((SnowclawState*)inner)->moveTablePtr = (int)(table + 0x54);
        ((SnowclawState*)inner)->moveIdBase = 0x400;
    case 0x3e8:
        ((SnowclawState*)inner)->moveTablePtr = (int)(table + 0x5c);
        ((SnowclawState*)inner)->moveIdBase = 0x400;
        break;
    }
    ((SnowclawState*)inner)->tickCounter = 0;
    ((SnowclawState*)inner)->attackDelay = 0x64;
    ((SnowclawState*)inner)->unk30 = lbl_803E66EC;
    storeZeroToFloatParam((char*)inner + 0x98);
    s16toFloat((char*)((int)inner + 0x98), (s16) * (int*)(table + 0x3c));
    objSeqInitFn_80080078((u8*)(int)gSnowClawMoveTable, 6);
    gSnowClawDropBombAngle = 0x96;
    ((SnowclawAaFlags*)&((SnowclawState*)inner)->flags)->b0 = 0;
}

#pragma dont_inline on
void snowclaw_spawnDropBomb(int obj, int a, int b, int c)
{
    int player;
    int obj2;
    char* spawned;

    player = Obj_GetPlayerObject();
    if (Obj_IsLoadingLocked() != 0)
    {
        obj2 = Obj_AllocObjectSetup(0x24, 0x5ff);
        *(s16*)(obj2 + 0x0) = 0x5ff;
        ((ObjPlacement*)obj2)->color[0] = 2;
        ((ObjPlacement*)obj2)->color[2] = 0xff;
        ((ObjPlacement*)obj2)->color[1] = 1;
        ((ObjPlacement*)obj2)->color[3] = 0xff;
        ((SnowClawBombSetup*)obj2)->launchMode = b;
        ((SnowClawBombSetup*)obj2)->head.posX = ((GameObject*)obj)->anim.localPosX;
        ((SnowClawBombSetup*)obj2)->head.posY = lbl_803E66E0 + ((GameObject*)obj)->anim.localPosY;
        ((SnowClawBombSetup*)obj2)->head.posZ = ((GameObject*)obj)->anim.localPosZ;
        ((SnowClawBombSetup*)obj2)->aimYaw = (s8)(u8)((((getAngle(
            ((GameObject*)player)->anim.localPosX - ((GameObject*)obj)->anim.localPosX,
            ((GameObject*)player)->anim.localPosZ - ((GameObject*)obj)->anim.localPosZ) & 0xffff) >> 8) + 0x8000) >> 8);
        Sfx_PlayFromObject(obj, SFXswapstone_mumble);
        switch ((u8)b)
        {
        case 0:
            ((SnowClawBombSetup*)obj2)->launchAngle = gSnowClawDropBombAngle;
            break;
        case 1:
            ((SnowClawBombSetup*)obj2)->launchAngle = (s16)(getAngle(
                ((GameObject*)player)->anim.localPosX - ((GameObject*)obj)->anim.localPosX,
                ((GameObject*)player)->anim.localPosZ - ((GameObject*)obj)->anim.localPosZ) + 0x8000);
            break;
        }
        spawned = loadObjectAtObject(obj, obj2);
        if (spawned != NULL)
        {
            ((GameObject*)spawned)->unkF4 = (u8)c;
            ((GameObject*)spawned)->ownerObj = (void*)a;
        }
    }
}
#pragma dont_inline reset

void snowclaw_updateMountAttack(int obj, int mount)
{
    char* inner;
    f32 mountPhase;
    f32 moveStep;
    f32 movePhase;
    int mountFlag;
    int magnitude;
    int turnSign;
    int moveId;
    int delay;

    inner = ((GameObject*)obj)->extra;
    movePhase = (*(f32 (*)(int, f32*))(*(int*)(*(int*)(*(int*)(mount + 0x68)) + 0x44)))(mount, &moveStep);
    moveStep = lbl_803DC224 + lbl_803E66E4 * (movePhase * lbl_803DC224);
    (*(void (*)(int, f32*, int*))(*(int*)(*(int*)(*(int*)(mount + 0x68)) + 0x40)))(mount, &mountPhase, &mountFlag);
    magnitude = (int)(lbl_803E66E8 * mountPhase);
    if (magnitude < 0)
    {
        magnitude = -magnitude;
    }

    if (mountFlag != 0 && ((GameObject*)obj)->anim.currentMove == *(u16*)&((SnowclawState*)inner)->moveIdBase)
    {
        Object_ObjAnimSetSecondaryBlendMove((ObjAnimComponent*)obj,
                                            *(u16*)&((SnowclawState*)inner)->moveIdBase + 1, magnitude);
    }
    else
    {
        Object_ObjAnimSetSecondaryBlendMove((ObjAnimComponent*)obj,
                                            *(u16*)&((SnowclawState*)inner)->moveIdBase + 2, magnitude);
    }

    if (((int (*)(int, f32, f32, void*))ObjAnim_AdvanceCurrentMove)(obj, moveStep, (f32)(u8)framesThisStep, NULL) != 0
        &&
        ((GameObject*)obj)->anim.currentMove != *(u16*)&((SnowclawState*)inner)->moveIdBase)
    {
        ((SnowclawState*)inner)->unk30 = lbl_803E66EC;
        delay = ((SnowclawState*)inner)->attackDelay;
        if (delay < 1)
        {
            delay = 1;
        }
        else if (delay > 0x190)
        {
            delay = 0x190;
        }
        ((SnowclawState*)inner)->attackDelay = delay;

        if (randFn_80080100(2) == 0)
        {
            ((ObjAnimSetCurrentMoveObjectFirstFn)ObjAnim_SetCurrentMove)
                (obj, *(u16*)&((SnowclawState*)inner)->moveIdBase, lbl_803E66F0, 0);
        }
        else
        {
            turnSign = (u32)(s16)
            Obj_GetYawDeltaToObject(obj, Obj_GetPlayerObject(), 0) >> 31;
            if (turnSign == 0)
            {
                ((SnowclawState*)inner)->unk30 = lbl_803E66F4;
                Sfx_PlayFromObject(obj, SFXswapstone_handhit);
            }
            else
            {
                ((SnowclawState*)inner)->unk30 = lbl_803E66F8;
                Sfx_PlayFromObject(obj, SFXswapstone_breatheout);
            }
            if (turnSign != 0)
            {
                moveId = *(u16*)&((SnowclawState*)inner)->moveIdBase + 4;
            }
            else
            {
                moveId = *(u16*)&((SnowclawState*)inner)->moveIdBase + 8;
            }
            ((ObjAnimSetCurrentMoveObjectFirstFn)ObjAnim_SetCurrentMove)
                (obj, moveId, lbl_803E66F0, 0);
            ((SnowclawState*)inner)->attackDelay += 0x64;
        }
    }
}

#pragma dont_inline on
void snowclaw_syncMountTransform(int obj, int sub, int p2, int p3, int p4, int p5, int opacity, int a8, int a9)
{
    f32 va, vb, vc;

    if (a9 != 0 && (s8)opacity != 0 && a8 > 0)
    {
        u8 saved = *(u8*)(sub + 0x37);
        *(u8*)(sub + 0x37) = a8;
        (*(void (**)(int, int, int, int, int, int))((char*)*((GameObject*)sub)->anim.dll + 0x10))(
            sub, p2, p3, p4, p5, -1);
        *(u8*)(sub + 0x37) = saved;
    }
    ((GameObject*)obj)->anim.previousWorldPosX = ((GameObject*)obj)->anim.worldPosX;
    ((GameObject*)obj)->anim.previousWorldPosY = ((GameObject*)obj)->anim.worldPosY;
    ((GameObject*)obj)->anim.previousWorldPosZ = ((GameObject*)obj)->anim.worldPosZ;
    ((GameObject*)obj)->anim.previousLocalPosX = ((GameObject*)obj)->anim.localPosX;
    ((GameObject*)obj)->anim.previousLocalPosY = ((GameObject*)obj)->anim.localPosY;
    ((GameObject*)obj)->anim.previousLocalPosZ = ((GameObject*)obj)->anim.localPosZ;
    (*(void (**)(int, f32*, f32*, f32*))((char*)*((GameObject*)sub)->anim.dll + 0x28))(sub, &va, &vb, &vc);
    ((GameObject*)obj)->anim.localPosX = va;
    ((GameObject*)obj)->anim.localPosY = vb;
    ((GameObject*)obj)->anim.localPosZ = vc;
    ((GameObject*)obj)->anim.rotX = ((GameObject*)sub)->anim.rotX;
    ((GameObject*)obj)->anim.rotY = ((GameObject*)sub)->anim.rotY;
    ((GameObject*)obj)->anim.rotZ = ((GameObject*)sub)->anim.rotZ;
    ((GameObject*)obj)->anim.worldPosX = ((GameObject*)obj)->anim.localPosX;
    ((GameObject*)obj)->anim.worldPosY = ((GameObject*)obj)->anim.localPosY;
    ((GameObject*)obj)->anim.worldPosZ = ((GameObject*)obj)->anim.localPosZ;
    ((GameObject*)obj)->anim.velocityX = ((GameObject*)sub)->anim.velocityX;
    ((GameObject*)obj)->anim.velocityY = ((GameObject*)sub)->anim.velocityY;
    ((GameObject*)obj)->anim.velocityZ = ((GameObject*)sub)->anim.velocityZ;
}
#pragma dont_inline reset

void snowclaw_render(int obj, int p2, int p3, int p4, int p5, int vis)
{
    int* inner;
    int sub;
    int found;
    int oldFlag;
    f32 dist;
    int near;

    dist = lbl_803E6708;
    inner = ((GameObject*)obj)->extra;
    sub = *(int*)inner;
    if (((GameObject*)obj)->anim.alpha < 5)
    {
        ((SnowclawState*)inner)->particleAlpha = lbl_803E66F0;
    }
    found = 0;
    if (*(s8*)&((SnowclawState*)inner)->health >= 0 && (u32)sub != 0)
    {
        if ((*(int (**)(int))((char*)*((GameObject*)sub)->anim.dll + 0x38))(sub) == 2)
        {
            found = 1;
        }
    }
    if (found != 0)
    {
        ((GameObject*)obj)->anim.flags |= 8;
        {
            extern s8 objUpdateOpacity(int);
            vis = objUpdateOpacity(sub);
        }
        snowclaw_syncMountTransform(obj, sub, p2, p3, p4, p5, vis, ((SnowclawState*)inner)->mountAlpha, 1);
    }
    else
    {
        ((GameObject*)obj)->anim.flags &= ~8;
    }
    if ((s8)vis != 0 && ((SnowclawState*)inner)->mountAlpha != 0)
    {
        oldFlag = *(u8*)((char*)obj + 0x37);
        if (found != 0)
        {
            *(u8*)((char*)obj + 0x37) = ((SnowclawState*)inner)->mountAlpha;
        }
        if (((GameObject*)obj)->childCount == 0 && ((GameObject*)obj)->anim.seqId == 0x389 &&
            ((SnowclawAaFlags*)&((SnowclawState*)inner)->flags)->b0 != 0)
        {
            near = ObjGroup_FindNearestObject(SNOWCLAW_TARGET_OBJGROUP, obj, &dist);
            if ((u32)near != 0 &&
                (*(int (**)(int))((char*)*((GameObject*)near)->anim.dll + 0x24))(near) != 0 &&
                (*(int (**)(int, int))((char*)*((GameObject*)near)->anim.dll + 0x20))(near, 0) != 0)
            {
                ObjLink_AttachChild(obj, near, 0);
            }
        }
        objRenderModelAndHitVolumes(obj, p2, p3, p4, p5, lbl_803E670C);
        ObjPath_GetPointWorldPosition(obj, 1, &((SnowclawState*)inner)->posX, &((SnowclawState*)inner)->posY,
                                      &((SnowclawState*)inner)->posZ, 0);
        *(u8*)((char*)obj + 0x37) = oldFlag;
        if (((SnowclawAaFlags*)&((SnowclawState*)inner)->flags)->flag6 != 0)
        {
            if (((SnowclawState*)inner)->particleAlpha != lbl_803E66F0)
            {
                ((SnowclawState*)inner)->particleAlpha = lbl_803E670C + (f32)(s32)(0xff - ((GameObject*)obj)->anim.alpha) /
                    lbl_803E6710;
            }
            else
            {
                ((SnowclawAaFlags*)&((SnowclawState*)inner)->flags)->flag6 = 0;
            }
            objParticleFn_80099d84(obj, lbl_803E670C, 3, ((SnowclawState*)inner)->particleAlpha, 0);
        }
    }
}

void snowclaw_hitDetect(int obj)
{
    int* inner;
    int sub;
    int* near;
    int* player;
    f32 dist;
    int hit;
    s8 a5;

    inner = ((GameObject*)obj)->extra;
    dist = lbl_803E6720;
    sub = *(int*)inner;
    if ((u32)sub == 0)
    {
        return;
    }
    if (ObjHits_GetPriorityHit(sub, &hit, 0, 0) == 0x15 && *(s8*)&((SnowclawState*)inner)->health >= 0)
    {
        ObjHits_RecordObjectHit(sub, hit, 0x15, 1, 0);
        if (((SnowclawState*)inner)->hitCooldown < 0)
        {
            *(s8*)&((SnowclawState*)inner)->health -= 1;
            Sfx_PlayFromObject(obj, SFXsp_sa_climb02);
            Sfx_PlayFromObject(obj, SFXdn_rexthrash11);
            Sfx_PlayFromObject(obj, gSnowClawHurtSfxTable[*(s8*)&((SnowclawState*)inner)->health]);
            ((SnowclawState*)inner)->hitCooldown = 0x14;
            ((SnowclawState*)inner)->attackDelay -= 0x28;
            if (*(s8*)&((SnowclawState*)inner)->health < 0)
            {
                int* sub2;

                spawnExplosion(obj, lbl_803E6724, 1, 1, 1, 1, 0, 1, 0);
                sub2 = *(int**)inner;
                if (sub2 != 0)
                {
                    (*(void (**)(int*, int))((char*)*((GameObject*)sub2)->anim.dll + 0x3c))(sub2, 0);
                }
                if (((GameObject*)obj)->anim.seqId == 0x389)
                {
                    near = (int*)ObjGroup_FindNearestObject(SNOWCLAW_TARGET_OBJGROUP, obj, &dist);
                    if (near != 0)
                    {
                        ObjLink_DetachChild(obj, near);
                        (*(void (**)(int*, int))((char*)*((GameObject*)near)->anim.dll + 0x20))(
                            near, 2);
                    }
                }
                if (((GameObject*)obj)->anim.seqId == 0x16d || ((GameObject*)obj)->anim.seqId == 0x170)
                {
                    (*gObjectTriggerInterface)->runSequence(0, (void*)obj, 1);
                }
                else
                {
                    (*gObjectTriggerInterface)->runSequence(0, (void*)obj, 3);
                }
                ((SnowclawAaFlags*)&((SnowclawState*)inner)->flags)->flag6 = 1;
                ((SnowclawState*)inner)->particleAlpha = lbl_803E670C;
                ((SnowclawState*)inner)->velX = lbl_803E6728 * mathSinf(
                    gSnowClawPi * (f32)((GameObject*)obj)->anim.rotX / lbl_803E6730);
                ((SnowclawState*)inner)->velY = lbl_803E6734 * (f32)(int)
                randomGetRange(0x28, 0x64);
                ((SnowclawState*)inner)->velZ = lbl_803E6728 * mathCosf(
                    gSnowClawPi * (f32)((GameObject*)obj)->anim.rotX / lbl_803E6730);
                player = (int*)fn_802972A8(Obj_GetPlayerObject());
                if (player != 0)
                {
                    int* sub3 = ((GameObject*)player)->extra;
                    if (sub3 != 0)
                    {
                        *(f32*)((char*)sub3 + 0x4c4) = lbl_803E6738;
                    }
                }
            }
            else
            {
                ((ObjAnimSetCurrentMoveObjectFirstFn)ObjAnim_SetCurrentMove)
                    (obj, *(u16*)&((SnowclawState*)inner)->moveIdBase + 9, lbl_803E66F0, 0);
                ((SnowclawState*)inner)->unk30 = lbl_803E66F4;
            }
        }
    }
    if (*(int**)inner != 0 &&
        (*(int (**)(int*))((char*)*((GameObject*)*(int**)inner)->anim.dll + 0x38))(*(int**)inner) == 2)
    {
        snowclaw_syncMountTransform(obj, (int)*(int**)inner, 0, 0, 0, 0, 0, 0, 0);
    }
    a5 = ((SnowclawState*)inner)->hitCooldown;
    if (a5 >= 0)
    {
        ((SnowclawState*)inner)->hitCooldown = a5 - framesThisStep;
    }
}

void snowclaw_update(int obj)
{
    char* inner;
    int* objects;
    int objectCount;
    int i;
    int targetType;
    int* sub;
    int choice;
    int turnSign;
    int pulseIndex;
    s8 healthState;
    u32* pulseTable;
    u32 pulseTypes[4];
    u32 pulseModes[4];
    f32 pulseVec[3];
    SnowClawAnimTbl dropTable;
    SnowClawPulse4* pulseSrc;

    pulseTable = gSnowClawPulseTable;
    inner = ((GameObject*)obj)->extra;
    if (((SnowclawState*)((GameObject*)obj)->extra)->hitFlag != 0 &&
        (u32)((((SnowclawState*)((GameObject*)obj)->extra)->flags >> 6) & 1) != 0)
    {
        ((SnowclawState*)inner)->particleAlpha = lbl_803E66F0;
    }
    ((SnowclawState*)inner)->hitFlag = 0;
    ((SnowclawState*)inner)->mountAlpha = 0xff;

    healthState = *(s8*)&((SnowclawState*)inner)->health;
    if (healthState < 0)
    {
        if (healthState < -10)
        {
            ((GameObject*)obj)->anim.flags |= OBJANIM_FLAG_HIDDEN;
            ((GameObject*)*(int*)inner)->anim.flags |= OBJANIM_FLAG_HIDDEN;
            ObjHits_DisableObject(obj);
            ObjHits_DisableObject(*(int*)inner);
        }
        else
        {
            ((SnowclawState*)inner)->health -= 1;
        }
        return;
    }

    ObjHits_EnableObject(obj);
    sub = *(int**)inner;
    if (sub != NULL)
    {
        ObjHits_EnableObject((int)sub);
    }

    dropTable = *(SnowClawAnimTbl*)(pulseTable + 8);
    if (*(s8*)&((SnowclawState*)inner)->dropIndex != ((SnowclawState*)inner)->dropIndexApplied)
    {
        if (((GameObject*)obj)->childObjs[0] != NULL)
        {
            Obj_FreeObject(*(int*)&((GameObject*)obj)->childObjs[0]);
            *(int*)&((GameObject*)obj)->childObjs[0] = 0;
            ((GameObject*)obj)->childCount = 0;
        }
        if (*(s8*)&((SnowclawState*)inner)->dropIndex > 0 && Obj_IsLoadingLocked() != 0)
        {
            *(int*)&((GameObject*)obj)->childObjs[0] =
                Obj_SetupObject(Obj_AllocObjectSetup(0x18, dropTable.v[*(s8*)&((SnowclawState*)inner)->dropIndex]),
                                4, ((GameObject*)obj)->anim.mapEventSlot, -1, *(int*)&((GameObject*)obj)->anim.parent);
            ((GameObject*)obj)->childCount = 1;
        }
        *(u8*)&((SnowclawState*)inner)->dropIndexApplied = ((SnowclawState*)inner)->dropIndex;
    }

    if (*(void**)inner == NULL)
    {
        objects = ObjGroup_GetObjects(0xa, &objectCount);
        targetType = seqStreamLookupFn_8007fff8(gSnowClawMoveTable, 6, ((GameObject*)obj)->anim.seqId);
        for (i = 0; i < objectCount; i++)
        {
            if (((GameObject*)objects[i])->anim.seqId == targetType)
            {
                *(int*)inner = objects[i];
                i = objectCount;
            }
        }
    }

    if (GameBit_Get(*(s16*)(((SnowclawState*)inner)->moveTablePtr)) == 0)
    {
        return;
    }

    sub = *(int**)inner;
    if (sub != 0 && *(s8*)&((SnowclawState*)inner)->health != 0 &&
        ((GameObject*)obj)->anim.currentMove == *(u16*)&((SnowclawState*)inner)->moveIdBase && fn_801EC9F4((int)sub) !=
        0 &&
        timerCountDown(inner + 0x98) != 0)
    {
        choice = randomGetRange(0, 1);
        ((SnowclawState*)inner)->pendingMoveId = *(u16*)&((SnowclawState*)inner)->moveIdBase + 5;
        turnSign = (u32)(s16)
        Obj_GetYawDeltaToObject(obj, Obj_GetPlayerObject(), 0) >> 31;
        if (turnSign == 0 || ((GameObject*)obj)->anim.seqId == 0x389)
        {
            ((ObjAnimSetCurrentMoveObjectFirstFn)ObjAnim_SetCurrentMove)
                (obj, *(u16*)&((SnowclawState*)inner)->moveIdBase + 6, lbl_803E66F0, 0);
            snowclaw_spawnDropBomb(*(int*)inner, obj, (u8)choice, 2);
        }
        else
        {
            ((ObjAnimSetCurrentMoveObjectFirstFn)ObjAnim_SetCurrentMove)
                (obj, *(u16*)&((SnowclawState*)inner)->moveIdBase + 5, lbl_803E66F0, 0);
            snowclaw_spawnDropBomb(*(int*)inner, obj, (u8)choice, 0);
        }
        s16toFloat(inner + 0x98, (s16)lbl_8032A340[fn_801EC9BC(*(int*)inner) - 1]);
    }

    sub = *(int**)inner;
    if (sub != NULL)
    {
        snowclaw_updateMountAttack(obj, (int)sub);
    }

    if (randFn_80080100(0x12c) != 0)
    {
        Sfx_PlayFromObject(obj, SFXswapstone_yawn);
    }

    if (*(s8*)&((SnowclawState*)inner)->health < 4)
    {
        *(SnowClawPulse4*)pulseTypes = *(SnowClawPulse4*)&pulseTable[0];
        pulseSrc = (SnowClawPulse4*)&pulseTable[4];
        *(SnowClawPulse4*)pulseModes = *pulseSrc;
        pulseIndex = 3 - *(s8*)&((SnowclawState*)inner)->health;
        i = ((SnowclawState*)inner)->tickCounter++;
        if ((i % lbl_803DC220) != 0)
        {
            pulseVec[0] = lbl_803E66F0;
            pulseVec[1] = lbl_803DC21C;
            pulseVec[2] = lbl_803E66F0;
            fn_80098B18(obj, lbl_803DC218, (u8)pulseTypes[pulseIndex],
                        (u8)pulseModes[pulseIndex], 0, pulseVec);
        }
    }
}

int snowclaw_animEventCallback(int obj, int a2, ObjSeqState* seq)
{
    int* sub;
    int* inner;
    int i;
    SnowClawAnimTbl tbl;
    f32 dist;

    dist = lbl_803E6708;
    inner = ((GameObject*)obj)->extra;
    ((SnowclawState*)inner)->hitFlag = 1;
    ObjHits_DisableObject(obj);
    if (*(int**)inner != 0)
    {
        ObjHits_DisableObject(*(int*)inner);
    }
    if (((GameObject*)obj)->seqIndex != -1 &&
        (((GameObject*)obj)->anim.seqId == 0x16d || ((GameObject*)obj)->anim.seqId == 0x170) &&
        GameBit_Get(0x3a3) != 0)
    {
        (*gObjectTriggerInterface)->endSequence(((GameObject*)obj)->seqIndex);
        ((SnowclawState*)inner)->particleAlpha = lbl_803E66F0;
        return 4;
    }
    ((GameObject*)obj)->anim.flags &= ~OBJANIM_FLAG_HIDDEN;
    sub = *(int**)inner;
    ((SnowclawState*)inner)->mountAlpha = 0xff;
    if (sub != 0)
    {
        s16 v6 = ((GameObject*)sub)->anim.flags;
        if (v6 & OBJANIM_FLAG_HIDDEN)
        {
            ((GameObject*)sub)->anim.flags = v6 & ~OBJANIM_FLAG_HIDDEN;
            (*(void (**)(int*, int))((char*)*((GameObject*)sub)->anim.dll + 0x3c))(sub, 2);
        }
    }
    if (seq->unk7E == 2)
    {
        seq->sequenceControlFlags |= OBJSEQ_CONTROL_CLEAR_LATCH_A;
    }
    seq->flags = seq->savedFlags;
    for (i = 0; i < seq->eventCount; i++)
    {
        switch (seq->eventIds[i])
        {
        case 3:
            *(s8*)&((SnowclawState*)inner)->dropIndex = -1;
            break;
        case 4:
            if (GameBit_Get(0xb7d) != 0)
            {
                seq->sequenceControlFlags |= OBJSEQ_CONTROL_SET_LATCH_A;
            }
            break;
        case 5:
            if (GameBit_Get(*(s16*)(((SnowclawState*)inner)->moveTablePtr)) != 0)
            {
                seq->sequenceControlFlags |= OBJSEQ_CONTROL_SET_LATCH_A;
            }
            break;
        case 2:
            if (sub != 0)
            {
                ((SnowclawState*)inner)->unk8 = lbl_803E670C;
                ((SnowclawState*)inner)->prevPosX = ((SnowclawState*)inner)->posX;
                ((SnowclawState*)inner)->prevPosY = ((SnowclawState*)inner)->posY;
                ((SnowclawState*)inner)->prevPosZ = ((SnowclawState*)inner)->posZ;
                (*(void (**)(int*, int))((char*)*((GameObject*)sub)->anim.dll + 0x3c))(sub, 2);
                ((ObjAnimSetCurrentMoveObjectFirstFn)ObjAnim_SetCurrentMove)
                    (obj, *(u16*)&((SnowclawState*)inner)->moveIdBase, lbl_803E66F0, 1);
                {
                    ObjModelState* gx = ((GameObject*)obj)->anim.modelState;
                    if (gx != 0)
                    {
                        gx->flags |= 0x1000;
                    }
                }
                seq->flags &= ~4;
            }
            break;
        case 1:
            sub = *(int**)inner;
            if (sub != 0)
            {
                (*(void (**)(int*, int))((char*)*((GameObject*)sub)->anim.dll + 0x3c))(sub, 0);
                seq->flags |= 4;
            }
            break;
        case 6:
            {
                int* found = (int*)ObjGroup_FindNearestObject(SNOWCLAW_TARGET_OBJGROUP, obj, &dist);
                if (found != 0)
                {
                    (*(void (**)(int*, int))((char*)*((GameObject*)found)->anim.dll + 0x20))(found, 2);
                    ((SnowclawAaFlags*)&((SnowclawState*)inner)->flags)->b0 = 0;
                }
                break;
            }
        case 7:
            {
                int* found = (int*)ObjGroup_FindNearestObject(SNOWCLAW_TARGET_OBJGROUP, obj, &dist);
                if (found != 0)
                {
                    (*(void (**)(int*, int))((char*)*((GameObject*)found)->anim.dll + 0x20))(found, 0);
                    ((SnowclawAaFlags*)&((SnowclawState*)inner)->flags)->b0 = 1;
                }
                break;
            }
        }
        seq->eventIds[i] = 0;
    }
    tbl = gSnowClawDropObjectTable;
    if (*(s8*)&((SnowclawState*)inner)->dropIndex != ((SnowclawState*)inner)->dropIndexApplied)
    {
        if (((GameObject*)obj)->childObjs[0] != 0)
        {
            Obj_FreeObject(*(int*)&((GameObject*)obj)->childObjs[0]);
            *(int*)&((GameObject*)obj)->childObjs[0] = 0;
            ((GameObject*)obj)->childCount = 0;
        }
        if (*(s8*)&((SnowclawState*)inner)->dropIndex > 0 && Obj_IsLoadingLocked() != 0)
        {
            *(int*)&((GameObject*)obj)->childObjs[0] =
                Obj_SetupObject(Obj_AllocObjectSetup(0x18, tbl.v[*(s8*)&((SnowclawState*)inner)->dropIndex]), 4,
                                ((GameObject*)obj)->anim.mapEventSlot, -1, *(int*)&((GameObject*)obj)->anim.parent);
            ((GameObject*)obj)->childCount = 1;
        }
        ((SnowclawState*)inner)->dropIndexApplied = *(s8*)&((SnowclawState*)inner)->dropIndex;
    }
    if (sub != 0 && (*(int (**)(int*))((char*)*((GameObject*)sub)->anim.dll + 0x38))(sub) == 2)
    {
        seq->flags &= ~3;
    }
    return 0;
}

u8 gSnowClawMoveTable[] = {
    0x00, 0x00, 0x03, 0x89, 0x00, 0x00, 0x03, 0x8D,
    0x00, 0x00, 0x03, 0x8A, 0x00, 0x00, 0x03, 0x8E,
    0x00, 0x00, 0x04, 0xD3, 0x00, 0x00, 0x04, 0xD4,
    0x00, 0x00, 0x01, 0x6D, 0x00, 0x00, 0x01, 0x6C,
    0x00, 0x00, 0x01, 0x70, 0x00, 0x00, 0x01, 0x6F,
    0x00, 0x00, 0x03, 0xE8, 0x00, 0x00, 0x03, 0xEA,
};

s32 lbl_8032A340[4] = {150, 200, 300, 400};
