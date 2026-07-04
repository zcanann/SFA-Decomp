/* DLL 0xEF - pushable object [80174A80-801755CC) */
#include "main/audio/sfx_ids.h"
#include "main/camera_interface.h"
#include "main/game_object.h"
#include "main/dll/pushable.h"
#include "main/obj_placement.h"
#include "main/dll/dll_00EF_pushable.h"
#include "main/objhits.h"
#include "main/objtexture.h"
#include "main/objseq.h"
#include "main/gamebits.h"
#include "main/vecmath.h"
#include "main/dll/fx_800944A0_shared.h"
#include "main/audio/sfx_trigger_ids.h"

extern int ObjMsg_Pop(int obj, int* outMessage, int* outSender, int* outParam);

extern f32 lbl_803E3528;
extern f32 lbl_803E3588;
extern f32 lbl_803E3598;
extern f32 lbl_803E3564;
extern f32 lbl_803E356C;
extern f32 lbl_803E3580;
extern f32 lbl_803E3584;
extern void Matrix_TransformPoint(f32* m, f32 x, f32 y, f32 z, f32* ox, f32* oy, f32* oz);
extern int getAngle(float y, float x);


extern void memcpy(void* dst, void* src, int n);
extern f32 lbl_803E358C;
extern f32 gPushablePi;
extern f32 gPushableYawHalfCircle;
extern u64 ObjGroup_RemoveObject();
extern u32 ObjGroup_AddObject();
extern void ObjMsg_AllocQueue(void* obj, int capacity);
extern int gPushableSavedMapIdCount;
extern int gPushableSavedMapIds[];
extern void objRenderFn_8003b8f4(int* obj, int a, int b, int c, int d, f32 scale);
extern int playerIsDisguised(void* player);
extern int fn_80295A04(void* player, int a);
extern void pushable_savePos(int* obj);
extern int fn_80174668(int* obj, PushableState* state);
extern void fn_80174438(int* obj, PushableState* state);
extern void Obj_RemoveFromUpdateList(int* obj);
extern f64 lbl_803E3530;
extern f64 lbl_803E3538;
extern s8 hitDetectFn_80065e50(int* obj, f32 x, f32 y, f32 z, f32*** list, int a, int b);
extern void objSetSlot(s16* obj, int slot);
extern int modelFileHeaderGetCullDistance(int hdr);
extern void Model_GetVertexPosition(int* model, int idx, f32* out);

char sPushPullObjectHitpointOverflow[] = "PUSHPULL OBJECT: hitpoint overflow\n";
extern int arrayIndexOf(int* arr, int count, int target);
extern void fn_8007FE04(int* array, int* count, int value);
extern f32 gPushableU16ScaleDenom;
extern f32 lbl_803E3558;
extern f32 lbl_803E3540;
extern int gPushableDefaultBox[];
extern int fn_802969F0(void);
extern void objMove(int* obj, f32 x, f32 y, f32 z);
extern void Obj_BuildTransformMatrices(int* obj);
extern void Obj_TransformLocalPointToWorld(f32 x, f32 y, f32 z, f32* ox, f32* oy, f32* oz, int* obj);
extern void hitDetect_calcSweptSphereBounds(int* boundsOut, f32* startPoints, f32* endPoints, int* box, int count);
extern void hitDetectFn_800691c0(int* obj, int* ranges, int a, int b);
extern f32 lbl_803E35A8;
extern f32 lbl_803E35AC;
extern f32 lbl_803E35B0;
extern f32 lbl_803E35B4;
extern f32 lbl_803E35B8;
extern f32 lbl_803E35BC;
extern f32 lbl_803E35C0;
extern f32 lbl_803E35C4;
extern f32 lbl_803E35C8;
extern int hitDetectFn_80067958(int a, f32* start, f32* end, int b, void* buf, int c);
extern f32 lbl_803E359C;
extern f32 lbl_803E35A0;
extern f32 lbl_803E35A4;
extern void fn_8003B5E0(int a, int b, int c, u8 d);

typedef struct PushablePlacement
{
    u8 pad0[0x18 - 0x0];
    s16 gameBit;
    s16 gameBit2; /* 0x1A second gamebit id; copied to PushableState.gameBit2 */
    s8 unk1C;
    s8 unk1D;
    s8 unk1E;
    u8 unk1F;
    u8 pad20[0x23 - 0x20];
    s8 requiredHitId;   /* 0x23 hit-region id that triggers this pushable (-1 = none) */
    u8 pad24[0x28 - 0x24];
} PushablePlacement;

typedef struct PushableObjectDef
{
    u8 pad0[0x18 - 0x0];
    s16 gameBit;
    s16 gameBit2; /* 0x1A second gamebit id (sibling of PushablePlacement.gameBit2) */
    void* unk1C;
    u16 scaleRaw;
    u8 rotXByte;
    u8 requiredHitId;   /* 0x23 hit-region id that triggers this pushable (-1 = none) */
    u8 pad24[0x28 - 0x24];
} PushableObjectDef;

void fn_80174A80(int obj, PushableState* ext)
{
    int def;
    ObjTextureRuntimeSlot* tex;
    f32 f;
    f32 v;
    f32 lim;

    def = *(int*)&((GameObject*)obj)->anim.placementData;
    ext->eyeOpenSpeed = lbl_803E3580;
    f = lbl_803E3584;
    ext->eyeDriftSpeedX = f;
    ext->eyeDriftSpeedY = f;
    ext->blinkInterval = lbl_803E3564 * (f32)(int)
    randomGetRange(0x19, 0x4b);
    ext->blinkStep = ext->blinkInterval / (f32)(int)
    randomGetRange(0x28, 0x46);
    f = lbl_803E3528;
    ext->blinkPhase = f;
    ext->gameBit = ((PushablePlacement*)def)->gameBit;
    ext->gameBit2 = ((PushablePlacement*)def)->gameBit2;
    ext->unk_F0 = f;
    ext->nearestObj = NULL;
    GameBit_Set(ext->gameBit, 0);
    tex = objFindTexture((void*)obj, 0, 0);

    ext->eyePosX = ext->eyePosX + ext->eyeDriftSpeedX;
    v = ext->eyePosX;
    lim = lbl_803E356C;
    if (v > lim)
    {
        ext->eyePosX = lim;
    }
    else if (v < lbl_803E3528)
    {
        ext->eyePosX = lim;
    }

    ext->eyePosY = ext->eyePosY + ext->eyeDriftSpeedY;
    v = ext->eyePosY;
    lim = lbl_803E356C;
    if (v > lim)
    {
        ext->eyePosY = lim;
    }
    else if (v < lbl_803E3528)
    {
        ext->eyePosY = lim;
    }

    tex->colorR = 10;
    tex->colorG = 10;
    tex->colorB = 10;
}

typedef struct Dll138PoseCopy
{
    s16 rot[3];
    f32 scale;
    f32 x;
    f32 y;
    f32 z;
} Dll138PoseCopy;

typedef struct Dll138HitInfo
{
    u8 pad0[0x1c];
    f32 angleX;
    u8 pad1[4];
    f32 angleZ;
    u8 pad2[0x29];
    s8 id;
    u8 pad3[2];
} Dll138HitInfo;

void fn_80174BFC(int obj, int ext)
{
    extern int objBboxFn_800640cc(f32* from, f32* to, f32 radius, int mode, void* hit, int obj, int p7, int p8, u8 p9, int p10); /* #57 */
    extern int Sfx_PlayFromObject(int a, int b); /* #57 */
 /* #57 */
    extern void saveGame_saveObjectPos(int obj); /* #57 */
    int def;
    int i;
    s8 bits;
    f32* velBase;
    int iter;
    f32 scale;
    f32 savedX;
    f32 savedY;
    f32 savedZ;
    Dll138PoseCopy pose;
    f32 mtx[16];
    f32 points[21];
    Dll138HitInfo hit;

    def = *(int*)&((GameObject*)obj)->anim.placementData;
    velBase = (f32*)((PushableState*)ext)->probeLocal;
    Obj_GetPlayerObject();
    savedX = ((GameObject*)obj)->anim.localPosX;
    savedY = ((GameObject*)obj)->anim.localPosY;
    savedZ = ((GameObject*)obj)->anim.localPosZ;
    bits = 0xf;
    iter = 0;
    scale = lbl_803E3588;
    while (bits != 0)
    {
        bits = 0xf;
        iter = iter + 1;
        if (iter > 4)
        {
            ((GameObject*)obj)->anim.localPosX = savedX;
            ((GameObject*)obj)->anim.localPosY = savedY;
            ((GameObject*)obj)->anim.localPosZ = savedZ;
            break;
        }
        i = 0;
        for (; i < ((PushableState*)ext)->pointCount; i++)
        {
            pose.rot[0] = ((GameObject*)obj)->anim.rotX;
            pose.rot[1] = ((GameObject*)obj)->anim.rotY;
            pose.rot[2] = ((GameObject*)obj)->anim.rotZ;
            pose.scale = scale;
            pose.x = ((GameObject*)obj)->anim.localPosX;
            pose.y = ((GameObject*)obj)->anim.localPosY;
            pose.z = ((GameObject*)obj)->anim.localPosZ;
            setMatrixFromObjectPos(mtx, (short*)&pose);
            Matrix_TransformPoint(mtx, velBase[i * 3], velBase[i * 3 + 1], velBase[i * 3 + 2],
                                  &points[i * 3], &points[i * 3 + 1], &points[i * 3 + 2]);
            if ((1 << i & 0xf) != 0)
            {
                if (objBboxFn_800640cc((f32*)(ext + i * 12 + 0x78), &points[i * 3], lbl_803E358C, 1, &hit, obj,
                                       8, 0xd, (u8)(i + 3), 10) == 0)
                {
                    bits = (s8)(bits & ~(1 << i));
                }
                else
                {
                    int angle;
                    int delta;
                    if (hit.id != -1 && (((PushableState*)ext)->flags & 1) == 0)
                    {
                        int gamebit;
                        ((PushableState*)ext)->flags |= 1;
                        gamebit = ((PushablePlacement*)def)->gameBit;
                        if (gamebit > -1)
                        {
                            switch (((GameObject*)obj)->anim.seqId)
                            {
                            case 0x411:
                            case 0x21e:
                                break;
                            case 0x7df:
                                ((PushableState*)ext)->flags &= ~1;
                                if (hit.id == ((PushableState*)ext)->requiredHitId)
                                {
                                    ObjTextureRuntimeSlot* tex = objFindTexture((void*)obj, 0, 0);
                                    if (tex != NULL)
                                    {
                                        tex->textureId = 0x100;
                                    }
                                    GameBit_Set(((PushablePlacement*)def)->gameBit, 1);
                                    *(u8*)&((GameObject*)obj)->anim.resetHitboxMode |= INTERACT_FLAG_DISABLED;
                                    ((PushableState*)ext)->flags |= 0x80;
                                }
                                break;
                            case 0x1cb:
                                if (hit.id == 1)
                                {
                                    GameBit_Set(gamebit, 1);
                                    Sfx_PlayFromObject(0, SFXsp_lf_mutter4);
                                    ((PushableState*)ext)->flags |= 0x80;
                                    *(u8*)&((GameObject*)obj)->anim.resetHitboxMode |= INTERACT_FLAG_DISABLED;
                                    saveGame_saveObjectPos(obj);
                                }
                                break;
                            default:
                                {
                                    s8 t = ((PushablePlacement*)def)->requiredHitId;
                                    if (t > -1 && t == hit.id)
                                    {
                                        GameBit_Set(gamebit, 1);
                                        Sfx_PlayFromObject(0, SFXsp_lf_mutter4);
                                    }
                                    break;
                                }
                            }
                        }
                    }
                    mathSinf(gPushablePi * (f32)((PushableState*)ext)->yaw / gPushableYawHalfCircle);
                    mathCosf(gPushablePi * (f32)((PushableState*)ext)->yaw / gPushableYawHalfCircle);
                    angle = getAngle(hit.angleX, hit.angleZ);
                    delta = ((PushableState*)ext)->yaw - (angle & 0xffff);
                    if (delta > 0x8000)
                    {
                        delta -= 0xffff;
                    }
                    if (delta < -0x8000)
                    {
                        delta += 0xffff;
                    }
                    delta = delta / 0xb6;
                    if (delta > -0x1e && delta < 0x1e)
                    {
                        ((PushableState*)ext)->flags |= 0x100;
                        ((PushableState*)ext)->pushAmountX = lbl_803E3528;
                    }
                    else if (delta > 0x96 || delta < -0x96)
                    {
                        ((PushableState*)ext)->flags |= 0x200;
                        ((PushableState*)ext)->pushAmountX = lbl_803E3528;
                    }
                    else if (delta > 0x3c && delta < 0x78)
                    {
                        ((PushableState*)ext)->flags |= 0x800;
                        ((PushableState*)ext)->pushAmountZ = lbl_803E3528;
                    }
                    else if (delta < -0x3c && delta > -0x78)
                    {
                        ((PushableState*)ext)->flags |= 0x400;
                        ((PushableState*)ext)->pushAmountZ = lbl_803E3528;
                    }
                    memcpy((void*)(ext + i * 12 + 0x78), &points[i * 3], 0xc);
                    mtx[12] = points[i * 3];
                    mtx[13] = points[i * 3 + 1];
                    mtx[14] = points[i * 3 + 2];
                    Matrix_TransformPoint(mtx, -velBase[i * 3], -velBase[i * 3 + 1],
                                          -velBase[i * 3 + 2], (f32*)(obj + 0xc),
                                          (f32*)(obj + 0x10), (f32*)(obj + 0x14));
                }
            }
        }
    }
    memcpy(((PushableState*)ext)->cornerWorld, points, ((PushableState*)ext)->pointCount * 0xc);
}

u32 fn_8017510C(short* obj, short* refObj, ObjAnimUpdateState* animUpdate)
{
    extern int Obj_GetPlayerObject(); /* #57 */
    u32 bitVal;
    int player;
    PushableState* state;
    f32 dx;
    f32 dz;
    f32 len;
    f32 k;

    state = *(PushableState**)(obj + 0x5c);
    state->savePosDelay = 0x3c;
    if (obj[0x5a] != -1)
    {
        (*gCameraInterface)->setTargetReticleOverride((int)obj);
    }
    animUpdate->activeHitVolumePair = -1;
    if ((s8)animUpdate->movementState != 0)
    {
        if ((s8)animUpdate->movementState != 2)
        {
            animUpdate->posOffsetScale = lbl_803E3588;
            animUpdate->posOffsetX = ((GameObject*)obj)->anim.localPosX - *(float*)(refObj + 6);
            animUpdate->posOffsetY = ((GameObject*)obj)->anim.localPosY - *(float*)(refObj + 8);
            animUpdate->posOffsetZ = ((GameObject*)obj)->anim.localPosZ - *(float*)(refObj + 10);
            animUpdate->rotOffsetX = *obj - (u16)*refObj;
            if (0x8000 < animUpdate->rotOffsetX)
            {
                animUpdate->rotOffsetX = animUpdate->rotOffsetX - 0xffff;
            }
            if (animUpdate->rotOffsetX < -0x8000)
            {
                animUpdate->rotOffsetX = animUpdate->rotOffsetX + 0xffff;
            }
            animUpdate->rotOffsetY = obj[1] - (u16)refObj[1];
            if (0x8000 < animUpdate->rotOffsetY)
            {
                animUpdate->rotOffsetY = animUpdate->rotOffsetY - 0xffff;
            }
            if (animUpdate->rotOffsetY < -0x8000)
            {
                animUpdate->rotOffsetY = animUpdate->rotOffsetY + 0xffff;
            }
            animUpdate->rotOffsetZ = (u16)refObj[2] - (u16)obj[2];
            if (0x8000 < animUpdate->rotOffsetZ)
            {
                animUpdate->rotOffsetZ = animUpdate->rotOffsetZ - 0xffff;
            }
            if (animUpdate->rotOffsetZ < -0x8000)
            {
                animUpdate->rotOffsetZ = animUpdate->rotOffsetZ + 0xffff;
            }
            animUpdate->movementState = 2;
        }
        animUpdate->posOffsetScale = -(animUpdate->posOffsetDecay * timeDelta - animUpdate->posOffsetScale);
        if (animUpdate->posOffsetScale <= lbl_803E3528)
        {
            animUpdate->movementState = 0;
        }
    }
    if (((GameObject*)obj)->unkF8 == 0)
    {
        ((GameObject*)obj)->unkF8 = 2;
    }
    if ((obj[0x23] == 0x21e) || (obj[0x23] == 0x411))
    {
        *(u8*)((int)obj + 0xaf) = *(u8*)((int)obj + 0xaf) | 8;
        if (('\0' < *(char*)(*(int*)(obj + 0x2c) + 0x10f)) &&
            ((*(short*)(*(int*)(*(int*)(obj + 0x2c) + 0x100) + 0x44) == 0x24 &&
                (bitVal = GameBit_Get(0x103), bitVal == 0))))
        {
            GameBit_Set(0x103, 1);
            *(u8*)((int)obj + 0xaf) = *(u8*)((int)obj + 0xaf) & ~8;
            player = Obj_GetPlayerObject();
            dx = ((GameObject*)obj)->anim.localPosX - ((GameObject*)player)->anim.localPosX;
            dz = ((GameObject*)obj)->anim.localPosZ - ((GameObject*)player)->anim.localPosZ;
            len = sqrtf(dx * dx + dz * dz);
            if (len != lbl_803E3528)
            {
                dx = dx / len;
                dz = dz / len;
            }
            k = lbl_803E3598;
            state->unk_C0 = k * dx;
            state->unk_C4 = lbl_803E3528;
            state->unk_C8 = k * dz;
            return 4;
        }
    }
    return 0;
}

void fn_80175428(int obj)
{
 /* #57 */
    PushableState* state;
    int msgSender;
    int msg;
    int msgParam;

    state = ((GameObject*)obj)->extra;
    msgParam = 0;
    while (ObjMsg_Pop(obj, &msg, &msgSender, &msgParam) != 0)
    {
        switch (msg)
        {
        case 0xf0003:
            state->msgSenderObj = msgSender;
            break;
        case 0xe:
            if ((((GameObject*)obj)->anim.seqId != 0x21e) && (((GameObject*)obj)->anim.seqId != 0x411))
            {
                Obj_FreeObject(obj);
            }
            break;
        case 0x40001:
            if (((GameObject*)obj)->anim.seqId == 0x21e)
            {
                state->unk_F0 = *(float*)msgParam;
            }
            if (((GameObject*)obj)->anim.seqId == 0x411)
            {
                state->unk_F0 = *(float*)msgParam;
            }
            break;
        }
    }
}

int pushable_render2(int obj)
{
    return (*(PushableState**)&((GameObject*)obj)->extra)->flags & 1;
}

void pushable_modelMtxFn(int obj, int modelNo)
{
    int extra = *(int*)&((GameObject*)obj)->extra;
    u32 flags = *(u32*)(extra + 0xa8);

    *(u32*)(extra + 0xa8) = flags | (1 << modelNo);
}

int pushable_func0B(int obj, int other)
{
    int state;
    f32 delta[3];
    f32* d;

    state = *(int*)&((GameObject*)obj)->extra;
    d = delta;
    d[0] = ((GameObject*)other)->anim.localPosX - ((GameObject*)obj)->anim.localPosX;
    d[1] = ((GameObject*)other)->anim.localPosY - ((GameObject*)obj)->anim.localPosY;
    d[2] = ((GameObject*)other)->anim.localPosZ - ((GameObject*)obj)->anim.localPosZ;
    return sqrtf(d[2] * d[2] + (d[0] * d[0] + d[1] * d[1])) <
        *(f32*)(state + 0xc);
}

#pragma scheduling on
#pragma peephole on
static inline int* Transporter_GetActiveModel(void* obj)
{
    ObjAnimComponent* objAnim = (ObjAnimComponent*)obj;
    return (int*)objAnim->banks[objAnim->bankIndex];
}

#pragma scheduling off
#pragma peephole off
void pushable_free(int* obj)
{
    extern int saveGame_saveObjectPos(int* obj); /* #57 */
    u8* def = *(u8**)&((GameObject*)obj)->anim.placementData;
    PushableState* sub = ((GameObject*)obj)->extra;
    s16 type = ((GameObject*)obj)->anim.seqId;
    int v;

    switch (type)
    {
    case 0x21e:
        GameBit_Set(sub->gameBit, 0);
        break;
    case 0x411:
        GameBit_Set(sub->gameBit, 0);
        break;
    default:
        if (((PushablePlacement*)def)->gameBit > -1 && type != 0x54a && type != 0x5ae && type != 0x108 && sub->
            savePosEnabled != 0)
        {
            saveGame_saveObjectPos(obj);
        }
        break;
    }
    if ((sub->flags & 1) != 0)
    {
        int val = ((ObjPlacement*)def)->mapId;
        v = gPushableSavedMapIdCount;
        gPushableSavedMapIdCount = v + 1;
        gPushableSavedMapIds[v] = val;
    }
    ObjGroup_RemoveObject(obj, 5);
}

int pushable_getExtraSize(void) { return 0x148; }
int pushable_getObjectTypeId(void) { return 0x48; }

#pragma opt_common_subs off
#pragma opt_common_subs reset

#pragma opt_common_subs off

#pragma opt_common_subs reset

void pushable_update(int* obj)
{
    extern void Sfx_PlayFromObject(int* obj, int sfxId); /* #57 */
    extern int saveGame_saveObjectPos(int* obj); /* #57 */
    PushableState* state;
    u8* def;
    void* player;

    def = *(u8**)&((GameObject*)obj)->anim.placementData;
    state = ((GameObject*)obj)->extra;
    state->flags = state->flags & ~2;
    state->moveFlags.b7 = 0;
    if (lbl_803E3528 != ((GameObject*)obj)->anim.velocityY)
    {
        state->flags = state->flags | 2;
    }
    if (state->moveFlags.b6 == 0)
    {
        if (playerIsDisguised(Obj_GetPlayerObject()) != 0) goto LAB_clear;
        *(u8*)&((GameObject*)obj)->anim.resetHitboxMode = *(u8*)&((GameObject*)obj)->anim.resetHitboxMode | INTERACT_FLAG_PROMPT_SUPPRESSED;
    }
    else
    {
    LAB_clear:
        *(u8*)&((GameObject*)obj)->anim.resetHitboxMode = *(u8*)&((GameObject*)obj)->anim.resetHitboxMode & ~INTERACT_FLAG_PROMPT_SUPPRESSED;
    }
    if ((*(u8*)&((GameObject*)obj)->anim.resetHitboxMode & INTERACT_FLAG_IN_RANGE) != 0 && GameBit_Get(0x913) == 0)
    {
        (*gObjectTriggerInterface)->runSequence(0, obj, -1);
        GameBit_Set(0x913, 1);
        return;
    }
    player = Obj_GetPlayerObject();
    if ((player != NULL && fn_80295A04(player, 10) != 0) || (state->flags & 4) != 0)
    {
        state->savePosDelay = 0x78;
    }
    if (state->savePosDelay != 0)
    {
        state->savePosDelay -= 1;
    }
    else
    {
        if (state->savePosEnabled != 0)
        {
            pushable_savePos(obj);
        }
    }
    switch (((GameObject*)obj)->anim.seqId)
    {
    case 0x21e:
        if (fn_80174668(obj, state) == 0) break;
        return;
    case 0x411:
        if (fn_80174668(obj, state) == 0) break;
        return;
    case 0x54a:
        if (GameBit_Get(state->gameBit) != 0)
        {
            ((GameObject*)obj)->anim.localPosX = (f32)((f64)((ObjPlacement*)def)->posX - lbl_803E3530);
            ((GameObject*)obj)->anim.localPosY = ((ObjPlacement*)def)->posY;
            ((GameObject*)obj)->anim.localPosZ = (f32)(lbl_803E3538 + (f64)((ObjPlacement*)def)->posZ);
        }
        fn_80174438(obj, state);
        break;
    case 0x108:
        if (lbl_803E3528 == state->prevWaterDepth && state->waterDepth > lbl_803E3528)
        {
            Sfx_PlayFromObject(obj, SFXTRIG_curtainopen16);
            GameBit_Set(0x272, 1);
        }
        if (GameBit_Get(0x272) != 0)
        {
            Obj_RemoveFromUpdateList(obj);
            ObjHits_DisableObject((u32)obj);
            ((GameObject*)obj)->anim.flags = ((GameObject*)obj)->anim.flags | OBJANIM_FLAG_HIDDEN;
        }
        break;
    }
    {
        s16 t = ((GameObject*)obj)->anim.seqId;
        if (t != 0x54a && t != 0x5ae && t != 0x108 && state->savePosEnabled != 0 &&
            (state->flags & 8) == 0)
        {
            saveGame_saveObjectPos(obj);
        }
    }
}

void pushable_init(s16* obj, char* def)
{
    extern int fn_80174A80(); /* #57 */
    PushableState* state;
    int* model;
    int* entry;
    int i;
    f32* mtx;
    f32 vtx[3];

    if (((ObjPlacement*)def)->mapId == 0x30398)
    {
        ((PushableObjectDef*)def)->requiredHitId = 1;
    }
    else
    {
        *(s8*)&((PushableObjectDef*)def)->requiredHitId = -1;
    }
    *obj = ((PushableObjectDef*)def)->rotXByte << 8;
    ((GameObject*)obj)->anim.localPosY = lbl_803E358C + ((ObjPlacement*)def)->posY;
    ObjGroup_AddObject(obj, 5);
    objSetSlot(obj, 0x5a);
    ((GameObject*)obj)->animEventCallback = fn_8017510C;
    state = ((GameObject*)obj)->extra;
    state->pointCount = 0;
    entry = Transporter_GetActiveModel(obj);
    model = (int*)*entry;
    state->unk_B0 = *(int*)&((PushableObjectDef*)def)->unk1C;
    state->scale = (f32) * &((PushableObjectDef*)def)->scaleRaw / gPushableU16ScaleDenom;
    state->scale = state->scale * ((GameObject*)obj)->anim.modelInstance->rootMotionScaleBase;
    state->cullDistance = state->scale * (f32)(u16)
    modelFileHeaderGetCullDistance(*entry) + lbl_803E3558;
    {
        f32 z0 = lbl_803E3528;
        state->timer_0x14 = z0;
        state->gameBit = ((PushableObjectDef*)def)->gameBit;
        ObjAnim_SetCurrentMove((int)obj, 0, z0, 0);
    }
    ObjMsg_AllocQueue(obj, 4);
    ObjHits_EnableObject((u32)obj);
    {
        f32 minY = lbl_803E3540;
        for (i = 0; i < *(u16*)((char*)model + 0xe4); i++)
        {
            Model_GetVertexPosition(model, i, vtx);
            if (vtx[1] < minY)
            {
                minY = vtx[1];
            }
        }
        for (i = 0; i < *(u16*)((char*)model + 0xe4); i++)
        {
            Model_GetVertexPosition(model, i, vtx);
            if (vtx[1] == minY)
            {
                int j;
                int found;
                f32 vx;
                f32 vz;

                found = 0;
                j = 0;
                vx = vtx[0];
                vz = vtx[2];

                for (; j < state->pointCount; j++)
                {
                    if (vx == state->cornerLocal[j].x && vz == state->cornerLocal[j].z)
                    {
                        found = 1;
                        j = state->pointCount;
                    }
                }
                if (found == 0)
                {
                    state->cornerLocal[state->pointCount].x = *(f32*)vtx;
                    state->cornerLocal[state->pointCount].y = vtx[1];
                    state->cornerLocal[state->pointCount].z = vtx[2];
                    state->pointCount += 1;
                }
            }
        }
    }
    if (state->pointCount > 4)
    {
        state->pointCount = 4;
        debugPrintf(sPushPullObjectHitpointOverflow);
    }
    {
        char* mi = *(char**)((char*)obj + 0x58);
        mtx = (f32*)(mi + ((*(u8*)(mi + 0x10c) + 2) << 4) * 4);
    }
    {
        for (i = 0; i < state->pointCount; i++)
        {
            f32 v;
            state->probeLocal[i].x = state->cornerLocal[i].x;
            state->probeLocal[i].y = state->cornerLocal[i].y;
            state->probeLocal[i].z = state->cornerLocal[i].z;
            v = state->probeLocal[i].x;
            if (v < 0.0f)
            {
                state->probeLocal[i].x = v + lbl_803E358C;
            }
            else
            {
                state->probeLocal[i].x = v - lbl_803E358C;
            }
            v = state->probeLocal[i].z;
            if (v < 0.0f)
            {
                state->probeLocal[i].z = v + lbl_803E358C;
            }
            else
            {
                state->probeLocal[i].z = v - lbl_803E358C;
            }
            v = state->cornerLocal[i].x;
            if (v < 0.0f)
            {
                state->cornerLocal[i].x = v + lbl_803E3588;
            }
            else
            {
                state->cornerLocal[i].x = v - lbl_803E3588;
                state->cornerIdxPosX = i;
            }
            v = state->cornerLocal[i].z;
            if (v < 0.0f)
            {
                state->cornerLocal[i].z = v + lbl_803E3588;
            }
            else
            {
                state->cornerLocal[i].z = v - lbl_803E3588;
                state->cornerIdxPosZ = i;
            }
            Matrix_TransformPoint(mtx, state->probeLocal[i].x, state->probeLocal[i].y,
                                  state->probeLocal[i].z,
                                  &state->cornerWorld[i].x, &state->cornerWorld[i].y, &state->cornerWorld[i].z);
        }
    }
    for (i = 0; i < state->pointCount; i++)
    {
        if (i != state->cornerIdxPosX && state->cornerLocal[i].x < lbl_803E3528)
        {
            if ((int)state->cornerLocal[i].z == (int)state->cornerLocal[state->cornerIdxPosX].z)
            {
                state->cornerIdxNegX = i;
            }
        }
        if (i != state->cornerIdxPosZ && state->cornerLocal[i].z < lbl_803E3528)
        {
            if ((int)state->cornerLocal[i].x == (int)state->cornerLocal[state->cornerIdxPosZ].x)
            {
                state->cornerIdxNegZ = i;
            }
        }
    }
    state->savePosEnabled = 1;
    switch (((GameObject*)obj)->anim.seqId)
    {
    case 0x21e:
        fn_80174A80(obj, state);
        break;
    case 0x411:
        fn_80174A80(obj, state);
        break;
    case 0x7df:
        fn_80174588(obj, state);
        break;
    case 0x1cb:
        if (((PushableObjectDef*)def)->gameBit > -1 && GameBit_Get(((PushableObjectDef*)def)->gameBit) != 0)
        {
            state->flags = state->flags | 0x81;
            *(u8*)&((GameObject*)obj)->anim.resetHitboxMode = *(u8*)&((GameObject*)obj)->anim.resetHitboxMode | INTERACT_FLAG_DISABLED;
            pushable_savePos((int*)obj);
        }
        state->savePosEnabled = 0;
        break;
    default:
        if (((PushableObjectDef*)def)->gameBit > -1 && GameBit_Get(((PushableObjectDef*)def)->gameBit) != 0)
        {
            state->flags = state->flags | 1;
        }
        break;
    }
    {
        char* r = *(char**)&((GameObject*)obj)->anim.modelState;
        if (r != NULL)
        {
            *(u32*)(r + 0x30) = *(u32*)(r + 0x30) | 0xa10;
            (*(char**)&((GameObject*)obj)->anim.modelState)[0x3a] = 0x60;
            (*(char**)&((GameObject*)obj)->anim.modelState)[0x3b] = 0x40;
        }
    }
    state->flags = state->flags | 0x40;
    if (arrayIndexOf(gPushableSavedMapIds, gPushableSavedMapIdCount, ((ObjPlacement*)def)->mapId) != -1)
    {
        state->flags = state->flags | 1;
        fn_8007FE04(gPushableSavedMapIds, &gPushableSavedMapIdCount, ((ObjPlacement*)def)->mapId);
    }
}

typedef struct
{
    int a, b, c, d;
} PushableBox16;

typedef struct
{
    u8 pad[0x24];
    f32 vx;
    u8 pad2[4];
    f32 vz;
} PushableObjPos;

#pragma opt_common_subs off
void pushable_hitDetect(int obj)
{
    extern u32 fn_80174BFC(); /* #57 */
    int i;
    PushableState* state;
    f32* wp;
    f32* hp;
    int cnt2;
    s8 cnt;
    int cntE;
    f32* w;
    u8* e;
    f32 acc;
    f32 wpos[12];
    f32 mtx[16];
    int sweep[6];
    struct
    {
        s16 dir[3];
        s16 pad;
        f32 pos[4];
    } vec;
    f32 hp4[4];
    PushableBox16 box;
    int list;
    f32 tmpY;

    box = *(PushableBox16*)gPushableDefaultBox;
    Obj_GetPlayerObject();
    state = ((GameObject*)obj)->extra;
    state->timer_0x110 = state->timer_0x110 - timeDelta;
    if (state->timer_0x110 <= *(f32*)&lbl_803E3528)
    {
        state->timer_0x110 = lbl_803E3528;
    }
    if (state->moveFlags.b7 == 0)
    {
        f32 k;
        if (fn_802969F0() == 0xd)
        {
            k = lbl_803E35A8;
        }
        else
        {
            k = lbl_803E35AC;
        }
        state->pushAmountX = state->pushAmountX * k;
        if (state->pushAmountX < lbl_803E35B0 && state->pushAmountX > lbl_803E35B4)
        {
            state->pushAmountX = lbl_803E3528;
        }
        state->pushAmountZ = state->pushAmountZ * k;
        if (state->pushAmountZ < lbl_803E35B0 && state->pushAmountZ > lbl_803E35B4)
        {
            state->pushAmountZ = lbl_803E3528;
        }
        if (lbl_803E3528 != state->pushAmountX || lbl_803E3528 != state->pushAmountZ)
        {
            vec.dir[0] = state->yaw;
            vec.dir[1] = 0;
            vec.dir[2] = 0;
            vec.pos[0] = lbl_803E3588;
            vec.pos[1] = 0.0f;
            vec.pos[2] = 0.0f;
            vec.pos[3] = 0.0f;
            setMatrixFromObjectPos(mtx, &vec);
            Matrix_TransformPoint(mtx, state->pushAmountZ, lbl_803E3528, state->pushAmountX,
                                  (f32*)((char*)obj + 0x24), &tmpY, (f32*)((char*)obj + 0x2c));
            objMove((int*)obj, ((PushableObjPos*)obj)->vx, lbl_803E3528, ((PushableObjPos*)obj)->vz);
            if ((state->flags & 4) == 0)
            {
                fn_80174BFC(obj, state);
            }
            state->flags = state->flags | 2;
        }
    }
    state->moveFlags.b6 = 1;
    switch (((GameObject*)obj)->anim.seqId)
    {
    case 0x108:
        if (GameBit_Get(0x272) != 0)
        {
            return;
        }
        break;
    case 0x21e:
        if (GameBit_Get(state->gameBit) != 0)
        {
            return;
        }
        break;
    case 0x411:
        if (GameBit_Get(state->gameBit) != 0)
        {
            return;
        }
        break;
    case 0x85a:
        state->moveFlags.b6 = 0;
        break;
    case 0x54a:
        break;
    }
    if ((state->flags & 4) != 0)
    {
        ((GameObject*)obj)->anim.velocityY = -(lbl_803E35B8 * timeDelta - ((GameObject*)obj)->anim.velocityY);
        ((GameObject*)obj)->anim.localPosY = ((GameObject*)obj)->anim.velocityY * timeDelta + ((GameObject*)obj)->anim.
            localPosY;
    }
    if ((state->flags & 2) != 0 || (state->flags & 4) != 0)
    {
        Obj_BuildTransformMatrices((int*)obj);
        i = 0;
        wp = wpos;
        w = wp;
        e = (u8*)state;
        for (; i < state->pointCount; i++)
        {
            Obj_TransformLocalPointToWorld(((PushableState*)e)->cornerLocal[0].x, ((PushableState*)e)->cornerLocal[0].y,
                                           ((PushableState*)e)->cornerLocal[0].z,
                                           w, w + 1, w + 2, (int*)obj);
            w += 3;
            e += 0xc;
        }
        hitDetect_calcSweptSphereBounds(sweep, (f32*)state->cornerWorld, wpos, (int*)&box, 4);
        sweep[1] = (int)((f32)sweep[1] - lbl_803E35BC);
        sweep[4] = (int)((f32)sweep[4] + lbl_803E35BC);
        hitDetectFn_800691c0((int*)obj, sweep, 1, 1);
        tmpY = lbl_803E3528;
        cnt2 = 0;
        cntE = 0;
        i = 0;
        hp = hp4;
        for (; i < state->pointCount; i++)
        {
            f32 y = wp[1];
            s8 found;

            *hp = y;
            acc = lbl_803E3528;
            cnt = hitDetectFn_80065e50((int*)obj, wp[0], y, wp[2], (f32***)&list, -1, 0);
            found = 0;
            if (cnt != 0)
            {
                int j = 0;
                int off = 0;

                for (; j < cnt; j++)
                {
                    f32* h = *(f32**)(list + off);
                    if (*(s8*)((char*)h + 0x14) == 0xe)
                    {
                        f32 d = h[0] - ((GameObject*)obj)->anim.localPosY;
                        if (d > lbl_803E3528)
                        {
                            acc = acc + d;
                            cntE++;
                        }
                    }
                    else if (found == 0)
                    {
                        f32 v = h[0];
                        if (v < lbl_803E3558 + wp[1] && v > wp[1] - lbl_803E35C0 && h[2] > lbl_803E35C4)
                        {
                            u32 o;
                            *hp = v;
                            tmpY = tmpY + v;
                            o = *(u32*)(*(int*)(list + off) + 0x10);
                            if (o != 0)
                            {
                                ObjHits_AddContactObject(o, obj);
                            }
                            cnt2++;
                            found = 1;
                        }
                    }
                    off += 4;
                }
            }
            wp += 3;
            hp++;
        }
        state->prevWaterDepth = state->waterDepth;
        if (cntE != 0)
        {
            state->waterDepth = acc / cntE;
        }
        else
        {
            state->waterDepth = lbl_803E3528;
        }
        if (cnt2 != 0 && state->timer_0x110 <= *(f32*)&lbl_803E3528)
        {
            ((GameObject*)obj)->anim.velocityY = lbl_803E3528;
            ((GameObject*)obj)->anim.localPosY = lbl_803E358C + tmpY / cnt2;
            state->flags = state->flags & ~0xc;
        }
        else
        {
            if ((state->flags & 4) == 0)
            {
                state->timer_0x110 = lbl_803E35C8;
            }
            state->flags = state->flags | 0xc;
        }
    }
    Obj_BuildTransformMatrices((int*)obj);
    i = 0;
    e = (u8*)state;
    for (; i < state->pointCount; i++)
    {
        Obj_TransformLocalPointToWorld(((PushableState*)e)->probeLocal[0].x, ((PushableState*)e)->probeLocal[0].y,
                                       ((PushableState*)e)->probeLocal[0].z,
                                       (f32*)(e + 0x78), (f32*)(e + 0x7c), (f32*)(e + 0x80), (int*)obj);
        e += 0xc;
    }
}
#pragma opt_common_subs reset


typedef struct
{
    f32 r[4];
    s8 b10;
    u8 pad1[3];
    u8 b14;
    u8 pad2[0x17];
    s16 h2c;
    s16 pad3;
} SetScaleParams;

int pushable_setScale(int* obj, s16* tgt, int flag, f32 dx, f32 dz)
{
    extern int objBboxFn_800640cc(f32* start, f32* end, f32 radius, int a, int b, int* obj, int c, int d, int e, int f); /* #57 */
    extern void Sfx_PlayFromObject(int* obj, int sfxId); /* #57 */
    extern u32 fn_80174BFC(); /* #57 */
    SetScaleParams* pp;
    PushableState* state;
    char ret;
    void* player;
    int hit;
    char* p;
    f32* w;
    f32* e2;
    f32* d;
    int i;
    SetScaleParams params;
    char hitbuf[64];
    f32 mtx[16];
    f32 wpos[12];
    f32 deltas[12];
    struct
    {
        s16 dir[3];
        s16 pad;
        f32 pos[4];
    } vec;
    int sweep[6];
    f32 start[3];
    f32 end[3];
    f32 tmpY;

    player = Obj_GetPlayerObject();
    state = ((GameObject*)obj)->extra;
    ret = 0;
    i = 5;
    p = (char*)state + 0x14;
    while (p -= 4, i-- != 0)
    {
        *(f32*)(p + 0x118) = *(f32*)(p + 0x114);
        *(f32*)(p + 0x12c) = *(f32*)(p + 0x128);
    }
    state->posHistX[0] = ((GameObject*)obj)->anim.localPosX;
    state->posHistZ[0] = ((GameObject*)obj)->anim.localPosZ;
    start[0] = ((GameObject*)tgt)->anim.localPosX;
    start[1] = lbl_803E359C + ((GameObject*)tgt)->anim.localPosY;
    start[2] = ((GameObject*)tgt)->anim.localPosZ;
    (pp = &params)->r[0] = lbl_803E35A0;
    pp->b10 = -1;
    pp->b14 = 3;
    pp->h2c = 0;
    hit = 0;
    if (dx > lbl_803E3528)
    {
        end[0] = lbl_803E35A0 * mathSinf(gPushablePi * state->yaw / gPushableYawHalfCircle) + start[0];
        end[1] = start[1];
        end[2] = lbl_803E35A0 * mathCosf(gPushablePi * state->yaw / gPushableYawHalfCircle) + start[2];
        hitDetect_calcSweptSphereBounds(sweep, start, end, (int*)pp, 1);
        hitDetectFn_800691c0(NULL, sweep, 0x208, 1);
        hit = hitDetectFn_80067958(0, start, end, 1, hitbuf, 8);
        if (hit == 0)
        {
            hit = objBboxFn_800640cc(start, end, pp->r[0], 0, 0, obj, 1, -1, 0xff, 0);
        }
        if (hit != 0)
        {
            f32 t;
            state->flags = state->flags | 0x200;
            t = lbl_803E3528;
            state->pushAmountX = t;
            state->pushAmountZ = t;
        }
    }
    else if (dz > lbl_803E3528)
    {
        end[0] = lbl_803E35A4 * mathSinf(gPushablePi * (f32)(state->yaw + 0x4000) / gPushableYawHalfCircle) + start[0];
        end[1] = start[1];
        end[2] = lbl_803E35A4 * mathCosf(gPushablePi * (f32)(state->yaw + 0x4000) / gPushableYawHalfCircle) + start[2];
        hitDetect_calcSweptSphereBounds(sweep, start, end, (int*)pp, 1);
        hitDetectFn_800691c0(NULL, sweep, 0x208, 1);
        hit = hitDetectFn_80067958(0, start, end, 1, hitbuf, 8);
        if (hit == 0)
        {
            hit = objBboxFn_800640cc(start, end, pp->r[0], 0, 0, obj, 1, -1, 0xff, 0);
        }
        if (hit != 0)
        {
            f32 t;
            state->flags = state->flags | 0x800;
            t = lbl_803E3528;
            state->pushAmountX = t;
            state->pushAmountZ = t;
        }
    }
    else if (dz < lbl_803E3528)
    {
        end[0] = lbl_803E35A4 * mathSinf(gPushablePi * (f32)(state->yaw - 0x4000) / gPushableYawHalfCircle) + start[0];
        end[1] = start[1];
        end[2] = lbl_803E35A4 * mathCosf(gPushablePi * (f32)(state->yaw - 0x4000) / gPushableYawHalfCircle) + start[2];
        hitDetect_calcSweptSphereBounds(sweep, start, end, (int*)pp, 1);
        hitDetectFn_800691c0(NULL, sweep, 0x208, 1);
        hit = hitDetectFn_80067958(0, start, end, 1, hitbuf, 8);
        if (hit == 0)
        {
            hit = objBboxFn_800640cc(start, end, pp->r[0], 0, 0, obj, 1, -1, 0xff, 0);
        }
        if (hit != 0)
        {
            f32 t;
            state->flags = state->flags | 0x400;
            t = lbl_803E3528;
            state->pushAmountX = t;
            state->pushAmountZ = t;
        }
    }
    if (playerIsDisguised(player) == 0 && state->moveFlags.b6 == 0)
    {
        hit = 1;
        if (dx > lbl_803E3528)
        {
            state->flags = state->flags | 0x200;
        }
        else if (dx < lbl_803E3528)
        {
            state->flags = state->flags | 0x100;
        }
        else if (dz > lbl_803E3528)
        {
            state->flags = state->flags | 0x800;
        }
        else
        {
            state->flags = state->flags | 0x400;
        }
        {
            f32 t = lbl_803E3528;
            state->pushAmountX = t;
            state->pushAmountZ = t;
        }
    }
    if (flag != 0 && (state->flags & 8) == 0)
    {
        state->flags = state->flags | 2;
        state->pushSfxTimer -= 1;
        if (state->pushSfxTimer <= 0)
        {
            state->pushSfxTimer = randomGetRange(0x28, 0x3c);
            state->flags = state->flags | 0x20;
        }
        if ((state->flags & 0x80) != 0)
        {
            f32 t = lbl_803E3528;
            state->pushAmountX = t;
            state->pushAmountZ = t;
        }
        else if (hit == 0)
        {
            state->pushAmountX = dx;
            state->pushAmountZ = dz;
        }
        state->yaw = *tgt;
        vec.dir[0] = *tgt;
        vec.dir[1] = 0;
        vec.dir[2] = 0;
        vec.pos[0] = lbl_803E3588;
        vec.pos[1] = lbl_803E3528;
        vec.pos[2] = lbl_803E3528;
        vec.pos[3] = lbl_803E3528;
        setMatrixFromObjectPos(mtx, &vec);
        Matrix_TransformPoint(mtx, state->pushAmountZ, lbl_803E3528, state->pushAmountX,
                              (f32*)((char*)obj + 0x24), &tmpY, (f32*)((char*)obj + 0x2c));
        state->moveFlags.b7 = 1;
        objMove(obj, ((PushableObjPos*)obj)->vx, lbl_803E3528, ((PushableObjPos*)obj)->vz);
        Obj_BuildTransformMatrices(obj);
        {
            int j;
            j = 0;
            w = wpos;
            e2 = (f32*)state;
            d = deltas;
            for (; j < state->pointCount; j++)
            {
                Obj_TransformLocalPointToWorld(*(f32*)((char*)e2 + 0x18), *(f32*)((char*)e2 + 0x1c),
                                               *(f32*)((char*)e2 + 0x20), w, w + 1, w + 2, obj);
                d[0] = ((GameObject*)obj)->anim.localPosX - w[0];
                d[1] = ((GameObject*)obj)->anim.localPosY - w[1];
                d[2] = ((GameObject*)obj)->anim.localPosZ - w[2];
                w += 3;
                e2 = (f32*)((char*)e2 + 0xc);
                d += 3;
            }
        }
        if ((state->flags & 4) == 0)
        {
            fn_80174BFC(obj, state);
        }
        Obj_BuildTransformMatrices(obj);
        if (lbl_803E3528 != state->pushAmountX || lbl_803E3528 != state->pushAmountZ)
        {
            PushableState* st2;
            char* def2;
            u16 fl2;
            def2 = *(char**)&((GameObject*)obj)->anim.placementData;
            st2 = ((GameObject*)obj)->extra;
            fl2 = st2->flags;
            if ((fl2 & 1) != 0)
            {
                s16 t;
                st2->flags = fl2 & ~1;
                t = ((PushablePlacement*)def2)->gameBit;
                if (t > -1)
                {
                    switch (((GameObject*)obj)->anim.seqId)
                    {
                    case 0x21e:
                        break;
                    case 0x411:
                        break;
                    case 0x7df:
                        break;
                    default:
                        if (((PushablePlacement*)def2)->requiredHitId > -1)
                        {
                            GameBit_Set(t, 0);
                        }
                        break;
                    }
                }
            }
        }
        {
            f32 f5 = ((GameObject*)obj)->anim.localPosX - state->posHistX[4];
            f32 f6 = ((GameObject*)obj)->anim.localPosZ - state->posHistZ[4];
            if (f5 * f5 + f6 * f6 > lbl_803E3588 && (state->flags & 0x20) != 0)
            {
                Sfx_PlayFromObject(obj, SFXTRIG_birdymornin11);
                state->flags = state->flags & ~0x20;
            }
        }
    }
    else
    {
        int j;
        char* mi = *(char**)((char*)obj + 0x58);
        f32* mtx2 = (f32*)(mi + ((*(u8*)(mi + 0x10c) + 2) << 4) * 4);
        j = 0;
        e2 = (f32*)state;
        for (; j < state->pointCount; j++)
        {
            Matrix_TransformPoint(mtx2, *(f32*)((char*)e2 + 0x18), *(f32*)((char*)e2 + 0x1c),
                                  *(f32*)((char*)e2 + 0x20), (f32*)((char*)e2 + 0x78),
                                  (f32*)((char*)e2 + 0x7c), (f32*)((char*)e2 + 0x80));
            e2 = (f32*)((char*)e2 + 0xc);
        }
    }
    {
        u16 fl = state->flags;
        if ((fl & 0x100) != 0)
        {
            ret = 1;
        }
        else if ((fl & 0x200) != 0)
        {
            ret = 2;
        }
        else if ((fl & 0x400) != 0)
        {
            ret = 3;
        }
        else if ((fl & 0x800) != 0)
        {
            ret = 4;
        }
        else if ((fl & 8) != 0)
        {
            ret = 5;
        }
        state->flags = *(u16*)((u8*)state + 0x100) & ~0xf00;
    }
    return ret;
}

void pushable_render(int* obj, int p1, int p2, int p3, int p4, s8 visible)
{
    if (visible != 0)
    {
        PushableState* state = ((GameObject*)obj)->extra;
        switch (((GameObject*)obj)->anim.seqId)
        {
        case 0x21e:
            if (GameBit_Get(state->gameBit) == 0)
            {
                break;
            }
            return;
        case 0x411:
            if (GameBit_Get(state->gameBit) == 0)
            {
                break;
            }
            return;
        case 0x54a:
            {
                f32 v = state->timer_0x14;
                f32 zero = lbl_803E3528;
                if (v > zero)
                {
                    state->timer_0x14 = v - timeDelta;
                    if (state->timer_0x14 <= zero)
                    {
                        state->timer_0x14 = zero;
                    }
                    else
                    {
                        fn_8003B5E0(0xc8, 0, 0, 0xff);
                    }
                }
                break;
            }
        }
        {
            char* hdr = (char*)Transporter_GetActiveModel(obj);
            *(u16*)(*(char**)hdr + 2) = *(u16*)(*(char**)hdr + 2) | 2;
        }
        objRenderFn_8003b8f4(obj, p1, p2, p3, p4, lbl_803E3588);
    }
}
