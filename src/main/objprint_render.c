#include "main/game_object.h"
#include "main/texture.h"
#include "main/model_light.h"
#include "main/rcp_dolphin_api.h"
#include "main/frame_timing.h"
#include "main/objprint_render_api.h"
#include "main/objprint_dolphin_api.h"
#include "main/objprintgxcolor.h"
#include "main/model.h"
#include "main/object_api.h"
#include "main/objlib_api.h"
#include "main/shader_api.h"
#include "main/pi_dolphin_api.h"
#include "main/curve_eval.h"
#include "main/audio/sfx.h"
#include "main/objprint_anim_api.h"
#include "main/objprint_character_api.h"
#include "main/objprint_sound_api.h"
#include "main/newshadows.h"
#include "main/objtexture.h"
#include "main/object_render.h"
#include "main/dll/modgfx.h"
#include "main/mm.h"
#include "dolphin/mtx.h"
#include "dolphin/os/OSCache.h"
#include "dolphin/gx/GXBump.h"
#include "dolphin/gx/GXCull.h"
#include "dolphin/gx/GXLighting.h"
#include "dolphin/gx/GXPixel.h"
#include "main/atan2f.h"
#include "dolphin/gx/GXBump.h"
#include "dolphin/gx/GXGeometry.h"
#include "dolphin/gx/GXTev.h"
#include "dolphin/gx/GXTransform.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/math_api.h"
#include "track/intersect_api.h"
#include "track/intersect_fog_api.h"
#include "main/newshadows_shadow_api.h"
#include "main/dll/player_api.h"
#include "main/objprint_internal.h"

extern f32 lbl_803DE9D8;
extern f32 lbl_803DE9DC;
extern f32 lbl_803DE9E0;
extern int lbl_803DCC48;
extern f32 lbl_803DEA04;
extern f32 lbl_803DE9E4;
extern int lbl_803DCC44;
extern u8 lbl_803DCC3E;
extern u32 lbl_803DB468;
extern f32 lbl_803DEA28;
extern f32 lbl_803DEA2C;
extern f32 lbl_803DEA30;
extern f32 lbl_803DEA04;
extern f32 lbl_803DEA1C;
extern f32 lbl_803DE9A4;
extern f32 lbl_803DE9C8;
extern f32 lbl_803DE99C;
extern f32 lbl_803DE9E8;

s16 lbl_803DCC18;
s16 lbl_803DCC16;
s16 lbl_803DCC14;
f32* gObjModelMatrixOverride;
u8 lbl_803DCC0D;
u8 lbl_803DCC0C;
u8 lbl_803DCC0B;
u8 lbl_803DCC0A;
u8 lbl_803DCC09;
u8 lbl_803DCC08;

void fn_8003B0D0(GameObject* obj, GameObject* target, CharacterEyeAnimState* state, int maxAngle)
{
    s16* found;

    found = objFindJointVecByKey(obj, 0);
    if (found != NULL)
    {
        state->headYaw =
            (s16)((s16)getAngle((obj)->anim.localPosX - target->anim.localPosX,
                                (obj)->anim.localPosZ - target->anim.localPosZ) -
                  (obj)->anim.rotX);
        maxAngle = (s16)(gObjPrintDegToAngle * maxAngle);
        if (state->headYaw > maxAngle)
        {
            state->headYaw = maxAngle;
        }
        if (state->headYaw < -maxAngle)
        {
            state->headYaw = -maxAngle;
        }
        found[1] = state->headYaw;
    }
}

void fn_8003B228(GameObject* obj, void* state)
{
    ObjTextureRuntimeSlot* foundA;
    ObjTextureRuntimeSlot* foundB;
    int val;

    foundA = characterFindEyeJoint(obj, 5);
    foundB = characterFindEyeJoint(obj, 4);
    if (foundA == NULL || foundB == NULL)
    {
        return;
    }
    val = foundB->textureId;
    val += framesThisStep * 0x30;
    if (val >= 0x200)
    {
        val = 0x200;
    }
    foundA->textureId = val;
    foundB->textureId = val;
    ((CharacterEyeAnimState*)state)->blinkState = 1;
}

void characterDoEyeMovements(GameObject* obj, CharacterEyeAnimState* state, f32 unused);

void characterDoEyeAnims(GameObject* obj, void* stateData)
{
    CharacterEyeAnimState* state = stateData;
    ObjTextureRuntimeSlot* a;
    ObjTextureRuntimeSlot* b;

    a = characterFindEyeJoint(obj, 5);
    b = characterFindEyeJoint(obj, 4);

    if (a == NULL || b == NULL)
    {
        return;
    }
    {
        int st;
        int v;

        v = b->textureId;
        st = state->blinkState;

        switch (st & 0xf)
        {
        case 0:
        {
            s8 blinkTimer = state->blinkTimer;
            if (blinkTimer > 0)
            {
                state->blinkTimer = blinkTimer - framesThisStep;
            }
            else if ((int)randomGetRange(0, 1000) > 0x3de)
            {
                state->blinkState = 1;
                state->blinkTimer = 0;
            }
        }
        break;
        case 1:
            if ((st & 0x80) != 0)
            {
                v = v - framesThisStep * 0x60;
                if (v < 0)
                {
                    v = 0;
                    state->blinkState = 0;
                    state->blinkTimer = 0;
                }
            }
            else
            {
                v = v + framesThisStep * 0x60;
                if (v > 0x200)
                {
                    if (v - 0x200 < 0)
                    {
                        v = 0;
                        state->blinkState = 0;
                    }
                    else
                    {
                        v = 0x2ff;
                        state->blinkState = -127;
                    }
                    state->blinkTimer = 0x28;
                }
            }
            a->textureId = v;
            b->textureId = v;
            break;
        }
        characterDoEyeMovements(obj, state, lbl_803DE9A4);
    }
}

void fn_8003B500(GameObject* obj, s16* state, f32 value)
{
    s16* found;

    found = objFindJointVecByKey(obj, 0);
    if (found != NULL)
    {
        if (found[0] != 0)
        {
            found[0] = (s16)(found[0] * 3 / 4);
        }
        fn_80039DF8(obj, state, found, lbl_803DE9A4);
        ((CharacterEyeAnimState*)state)->headTrackMode = (s16)(u16)(u8)((CharacterEyeAnimState*)state)->headTrackMode;
    }
}

void fn_8003B5E0(int a, int b, int c, u8 d)
{
    lbl_803DCC0D = a;
    lbl_803DCC0C = b;
    lbl_803DCC0B = c;
    lbl_803DCC09 = 1;
    lbl_803DCC0A = d;
}


void fn_8003B608(s16 a, s16 b, s16 c)
{
    lbl_803DCC18 = a;
    lbl_803DCC16 = b;
    lbl_803DCC14 = c;
    lbl_803DCC08 = 1;
}

typedef struct
{
    f32 pos[3];
    s16 rot[3];
    s8 joints[6];
} ChildEnt;

#define OBJPRINT_CHILD_TABLE(staff) (*(char**)(*(char**)((staff) + 0x50) + 0x2c))

void staffMtxFn_8003b620(int staffArg, GameObject* objArg, int modelArg, int a, int b, int c)
{
    f32 va[3];
    Vec vb;
    int k;
    char* q;
    Vec* vp;
    int i;
    char* base;
    u8* model;
    int obj;
    char* staff;

    staff = (char*)staffArg;
    obj = (int)objArg;
    model = (u8*)modelArg;

    if (*(u8*)(*(char**)(staff + 0x50) + 0x58) >= 2 && ((GameObject*)staff)->anim.classId == 0x2d)
    {
        int off;
        base = (char*)((GameObject*)staff)->extra;
        i = 0;
        k = 1;
        off = 0x18;
        q = base;
        vp = (Vec*)va;

        while (i < *(s16*)(base + 0xb0))
        {
            if (k < *(u8*)(*(char**)(staff + 0x50) + 0x58))
            {
                MtxPtr jm;
                int joint;
                joint = ((ChildEnt*)(OBJPRINT_CHILD_TABLE(staff) + off))[1].joints[OBJPRINT_ACTIVE_BANK_INDEX(staff)];
                jm = (MtxPtr)ObjModel_GetJointMatrix(model, joint);
                vp->x = ((ChildEnt*)(OBJPRINT_CHILD_TABLE(staff) + off))[1].pos[0];
                va[1] = ((ChildEnt*)(OBJPRINT_CHILD_TABLE(staff) + off))[1].pos[1];
                va[2] = ((ChildEnt*)(OBJPRINT_CHILD_TABLE(staff) + off))[1].pos[2];
                PSMTXMultVec(jm, vp, vp);
                vp->x = vp->x + playerMapOffsetX;
                va[2] = va[2] + playerMapOffsetZ;
                *(f32*)(q + 0x6c) = vp->x;
                *(f32*)(q + 0x74) = va[1];
                *(f32*)(q + 0x7c) = va[2];
            }
            if (k < *(u8*)(*(char**)(staff + 0x50) + 0x58))
            {
                ChildEnt* row = (ChildEnt*)(OBJPRINT_CHILD_TABLE(staff) + off);
                int idx2 = row->joints[OBJPRINT_ACTIVE_BANK_INDEX(staff)];
                MtxPtr mtx2;
                vb.x = row->pos[0];
                mtx2 = (MtxPtr)(*(char**)(model + ((((ObjModel*)model)->bufferFlags & 1) * 4) + 0xc) + idx2 * 0x40);
                vb.y = ((ChildEnt*)(OBJPRINT_CHILD_TABLE(staff) + off))->pos[1];
                vb.z = ((ChildEnt*)(OBJPRINT_CHILD_TABLE(staff) + off))->pos[2];
                PSMTXMultVec(mtx2, &vb, &vb);
                vb.x = vb.x + playerMapOffsetX;
                vb.z = vb.z + playerMapOffsetZ;
                *(f32*)(q + 0x54) = vb.x;
                *(f32*)(q + 0x5c) = vb.y;
                *(f32*)(q + 0x64) = vb.z;
            }
            k += 2;
            off += 0x30;
            q += 4;
            i++;
        }

        if (*(s16*)(base + 0xb0) != 0)
        {
            char* r = base + *(s16*)(base + 0xb2) * 4;
            va[0] = *(f32*)(r + 0x6c);
            va[1] = *(f32*)(r + 0x74);
            va[2] = *(f32*)(r + 0x7c);
            (*(void (**)(int, int, Vec*))(*(int*)((GameObject*)staff)->anim.dll + 0x28))((int)staff, obj, &vb);
            va[0] = va[0] - vb.x;
            va[1] = va[1] - vb.y;
            va[2] = va[2] - vb.z;
            ((GameObject*)staff)->anim.rotX = getAngle(va[0], va[2]);
            {
                f32 dx = va[0] * va[0];
                f32 dz = va[2] * va[2];
                ((GameObject*)staff)->anim.rotY = (s16)(-getAngle(va[1], sqrtf(dx + dz)) + 0x4000);
            }
            ((GameObject*)staff)->anim.rotZ = 0;
        }
    }
}


void objRenderShadowIfVisible(GameObject* obj, int wpad0, int wpad1, int wpad2, int wpad3, int wpad4)
{
    void** arr = *(void***)&(obj)->anim.banks;
    s8 idx = (obj)->anim.bankIndex;
    if (arr[idx] != NULL)
    {
        objRenderShadow(obj);
    }
}

int objNormalizeRotationMatrix(f32* matrix, f32* out);

void objRenderModelAndHitVolumes(GameObject* obj, int p2, int p3, int p4, int p5, f32 scale)
{
    int** table = OBJPRINT_BANK_TABLE((int*)obj);
    (void)scale;
    if (table[OBJPRINT_ACTIVE_BANK_INDEX(obj)] != NULL)
    {
        objRenderModel(obj);
        if (obj->anim.hitVolumeTransforms != NULL)
        {
            objRenderFn_80041018((GameObject*)obj);
        }
    }
}


void objSetModelMatrixOverride(f32* matrix)
{
    gObjModelMatrixOverride = matrix;
}


void objRender(int a, int b, int c, int d, GameObject* obj, int flag)
{
    void* sub;
    int walk;
    int i;
    void (*vfn)(int, int, int, int, int, int);

    if ((((GameObject*)obj)->objectFlags & OBJECT_OBJFLAG_FREED) != 0 || ((GameObject*)obj)->ownerObj != NULL)
        return;
    if ((((GameObject*)obj)->anim.flags & OBJANIM_FLAG_HIDDEN) != 0)
        return;
    sub = *(void**)&((GameObject*)obj)->anim.parent;
    if (sub != NULL && (((GameObject*)sub)->anim.flags & OBJANIM_FLAG_HIDDEN) != 0)
        return;

    doNothing_beforeRenderObject(4);
    ((GameObject*)obj)->objectFlags |= OBJECT_OBJFLAG_RENDERED;
    sub = *(void**)&((GameObject*)obj)->anim.dll;
    if (sub != NULL)
    {
        if ((((GameObject*)obj)->objectFlags & OBJECT_OBJFLAG_HIDDEN) == 0)
        {
            vfn = *(void (**)(int, int, int, int, int, int))(*(int*)sub + 0x10);
            if (vfn != NULL)
            {
                vfn((int)obj, a, b, c, d, flag);
            }
        }
        else if ((s8)flag != 0 && OBJPRINT_ACTIVE_BANK(obj) != NULL)
        {
            objRenderModel(obj);
            if (((GameObject*)obj)->anim.hitVolumeTransforms != NULL)
            {
                objRenderFn_80041018((GameObject*)obj);
            }
        }
    }
    else if ((s8)flag != 0)
    {
        switch (((GameObject*)obj)->anim.seqId)
        {
        case 0:
        case 0x1f:
            playerRender((int)obj, a, b, c, d, flag);
            break;
        default:
            if (OBJPRINT_ACTIVE_BANK(obj) != NULL)
            {
                objRenderModel(obj);
                if (((GameObject*)obj)->anim.hitVolumeTransforms != NULL)
                {
                    objRenderFn_80041018((GameObject*)obj);
                }
            }
            break;
        }
    }
    doNothing_afterRenderObject();
    for (i = 0, walk = (int)obj; i < (s32)(u32)((GameObject*)obj)->childCount; i++)
    {
        int staff = *(int*)&((GameObject*)walk)->childObjs[0];
        if (((GameObject*)staff)->anim.classId == 0x2d)
        {
            staffMtxFn_8003b620(staff, obj, (int)OBJPRINT_ACTIVE_BANK(staff), a, b, c);
        }
        walk += 4;
    }
}
int objGetAlphaCompareThreshold(void)
{
    return gObjAlphaCompareThreshold;
}

void objSetAlphaCompareThreshold(u8 x)
{
    gObjAlphaCompareThreshold = x;
}

int objNormalizeRotationMatrix(f32* matrix, f32* out)
{
    Vec v3;
    Vec v1;
    Vec v2;
    f32 zero;

    v1.x = matrix[0];
    v1.y = matrix[1];
    v1.z = matrix[2];
    v2.x = matrix[4];
    v2.y = matrix[5];
    v2.z = matrix[6];
    v3.x = matrix[8];
    v3.y = matrix[9];
    v3.z = matrix[10];

    if ((v1.x == lbl_803DEA04 && v1.y == lbl_803DEA04 && v1.z == lbl_803DEA04) ||
        (v2.x == *(f32*)&lbl_803DEA04 && v2.y == *(f32*)&lbl_803DEA04 && v2.z == *(f32*)&lbl_803DEA04) ||
        (v3.x == *(f32*)&lbl_803DEA04 && v3.y == *(f32*)&lbl_803DEA04 && v3.z == *(f32*)&lbl_803DEA04))
    {
        return 0;
    }

    PSVECNormalize(&v1, &v1);
    PSVECNormalize(&v2, &v2);
    PSVECNormalize(&v3, &v3);

    out[0] = v1.x;
    out[1] = v1.y;
    out[2] = v1.z;
    zero = lbl_803DEA04;
    out[3] = zero;
    out[4] = v2.x;
    out[5] = v2.y;
    out[6] = v2.z;
    out[7] = zero;
    out[8] = v3.x;
    out[9] = v3.y;
    out[10] = v3.z;
    out[11] = zero;
    return 1;
}

extern f32 gObjPrintHalfPi;
extern f32 gObjPrintNegHalfPi;
extern const f32 gObjPrintAngleUnitScale;
extern const f32 gObjPrintTwoPi;

int objRotateFn_8003bce8(f32* m, s16* outA, s16* outB, s16* outC)
{
    f32 buf[12];
    f32 x;
    f32 y;
    f32 z;

    if (objNormalizeRotationMatrix(m, buf) == 0)
    {
        return 0;
    }
    x = __kernel_sin(-buf[6]);
    if (x < gObjPrintHalfPi)
    {
        if (x > gObjPrintNegHalfPi)
        {
            y = __kernel_cos(buf[2], buf[10]);
            z = __kernel_cos(buf[4], buf[5]);
        }
        else
        {
            y = __kernel_cos(buf[1], buf[0]);
            z = lbl_803DEA04;
            y = z - y;
        }
    }
    else
    {
        y = __kernel_cos(buf[1], buf[0]);
        z = lbl_803DEA04;
        y = y - z;
    }
    *outC = (s16)(s32)(gObjPrintAngleUnitScale * z / gObjPrintTwoPi);
    *outB = (s16)(s32)(gObjPrintAngleUnitScale * x / gObjPrintTwoPi);
    *outA = (s16)(s32)(gObjPrintAngleUnitScale * y / gObjPrintTwoPi);
    return 1;
}


void modelMtxFn_8003be38(u8* def, int* model, f32* mtxA, f32* mtxB)
{
    void* cache;
    int count;
    int i;
    MtxPtr mid;
    MtxPtr dstB;
    MtxPtr dstA;
    f32 fill;

    cache = getCache();
    count = (s32)(u32)def[0xf3] + (s32)(u32)def[0xf4];
    dstA = (MtxPtr)((u8*)cache + 0x2700);
    mid = (MtxPtr)cache;
    dstB = (MtxPtr)((u8*)cache + 0x12c0);
    cacheQueueWait(0);
    i = 0;
    fill = lbl_803DEA04;
    for (; i < count; i++)
    {
        PSMTXConcat((MtxPtr)mtxA, dstA, mid);
        PSMTXConcat(mid, (MtxPtr)mtxB, dstB);
        dstB[0][3] = fill;
        dstB[1][3] = fill;
        dstB[2][3] = fill;
        dstA += 4;
        mid += 3;
        dstB += 3;
    }
    lbl_803DCC48 = 2;
}

void modelCalcVtxGroupMtxs(ModelFileHeader* def, ObjModel* model)
{
    Mtx ma;
    Mtx mb;
    Mtx trans;
    int off;
    int i;

    for (i = 0, off = 0; i < def->extraJointCount; i++)
    {
        MtxPtr out;
        MtxPtr m1;
        char* jd;
        MtxPtr m2;
        u8* grp;
        f32 w;
        f32 wi;

        grp = def->unk54 + off;
        out = (MtxPtr)ObjModel_GetJointMatrix((u8*)model, i + def->jointCount);
        m1 = (MtxPtr)ObjModel_GetJointMatrix((u8*)model, grp[0]);
        m2 = (MtxPtr)ObjModel_GetJointMatrix((u8*)model, grp[1]);

        w = (f32)grp[2] / 4.0f;
        wi = 1.0f - w;

        jd = (char*)def->jointData + grp[0] * 0x1c;
        PSMTXTrans(trans, -((ModelBone*)jd)->tail[0], -((ModelBone*)jd)->tail[1], -((ModelBone*)jd)->tail[2]);
        PSMTXConcat(m1, trans, ma);
        jd = (char*)def->jointData + grp[1] * 0x1c;
        PSMTXTrans(trans, -((ModelBone*)jd)->tail[0], -((ModelBone*)jd)->tail[1], -((ModelBone*)jd)->tail[2]);
        PSMTXConcat(m2, trans, mb);

        out[0][0] = ma[0][0] * w + mb[0][0] * wi;
        out[0][1] = ma[0][1] * w + mb[0][1] * wi;
        out[0][2] = ma[0][2] * w + mb[0][2] * wi;
        out[0][3] = ma[0][3] * w + mb[0][3] * wi;
        out[1][0] = ma[1][0] * w + mb[1][0] * wi;
        out[1][1] = ma[1][1] * w + mb[1][1] * wi;
        out[1][2] = ma[1][2] * w + mb[1][2] * wi;
        out[1][3] = ma[1][3] * w + mb[1][3] * wi;
        out[2][0] = ma[2][0] * w + mb[2][0] * wi;
        out[2][1] = ma[2][1] * w + mb[2][1] * wi;
        out[2][2] = ma[2][2] * w + mb[2][2] * wi;
        out[2][3] = ma[2][3] * w + mb[2][3] * wi;
        off += 4;
    }
}

void modelCalcVtxGroupMtxs(ModelFileHeader* def, ObjModel* model);

void modelInitMtxs(ModelFileHeader* def, ObjModel* model)
{
    int cache;
    int mtx;
    int count;
    u8 rem;

    cache = (int)getCache();
    if (def->extraJointCount != 0)
    {
        modelCalcVtxGroupMtxs(def, model);
    }
    count = (s32)(u32)def->jointCount + (s32)(u32)def->extraJointCount;
    if (count >= 2 && count <= 0x64)
    {
        mtx = (int)ObjModel_GetJointMatrix((u8*)model, 0);
        DCFlushRange((void*)mtx, count << 6);
        rem = (u8)(count << 1);
        cache += 0x2700;
        while (rem >= 0x80)
        {
            copyToCache((void*)cache, (void*)mtx, 0);
            rem -= 0x80;
            mtx += 0x1000;
            cache += 0x1000;
        }
        if (rem != 0)
        {
            copyToCache((void*)cache, (void*)mtx, rem);
        }
        lbl_803DCC48 = 1;
    }
    else
    {
        lbl_803DCC48 = 3;
    }
}

typedef struct IndTexMtx23
{
    f32 m[2][3];
} IndTexMtx23;

STATIC_ASSERT(sizeof(IndTexMtx23) == 0x18);

const IndTexMtx23 lbl_802C1B10 = {{{0.5f, 0.0f, 0.0f}, {0.0f, 0.5f, 0.0f}}};
const IndTexMtx23 lbl_802C1B28 = {{{0.0f, 0.5f, 0.0f}, {0.0f, 0.0f, 0.5f}}};
const IndTexMtx23 lbl_802C1B40 = {{{0.5f, 0.0f, 0.0f}, {0.0f, 0.5f, 0.0f}}};
const IndTexMtx23 lbl_802C1B58 = {{{0.0f, 0.5f, 0.0f}, {0.0f, 0.0f, 0.5f}}};

extern int lbl_803DCC44;
extern u8 lbl_803DCC3E;
extern u8 lbl_803DCC3D;
extern u32 lbl_803DE9FC;
extern u32 lbl_803DEA00;
extern u32 lbl_803DB470;
extern u32 lbl_803DB468;
extern int lbl_803DB498;
extern int lbl_803DB49C;
extern f32 lbl_803DEA28;
extern f32 lbl_803DEA2C;
extern f32 lbl_803DEA30;
extern f32 lbl_803DEA34;
extern f32 lbl_803DEA38;
extern f32 lbl_803DEA1C;

int modelRenderCb_8003c268(int obj, int* model, int ropIdx)
{
    Mtx mtx4;
    Mtx mtx3;
    Mtx mtx2;
    Mtx mtxR;
    Mtx mtx5;
    IndTexMtx23 mtxA;
    IndTexMtx23 mtxB;
    GXColor kc;
    Texture** noiseTextures;
    int noiseFrameCount;
    int t164;
    f32 sx;
    f32 sy;
    GXColor kc2;
    Texture** shadowTable;
    int shadowStride;
    int shadowRows;
    u8* rop;
    f32 fz;
    u8 v;

    kc = *(GXColor*)&lbl_803DE9FC;
    mtxA = lbl_802C1B40;
    mtxB = lbl_802C1B58;
    rop = (u8*)ObjModel_GetRenderOp((ModelFileHeader*)*model, ropIdx);
    if ((((ModelRenderOp*)rop)->flags & 0x200) == 0)
    {
        if ((lbl_803DCC44 & 3) != 0)
        {
            lbl_803DCC3E = 0;
            return 0;
        }
        lbl_803DCC3E = 1;
        objRenderFuzzFn_8003d6f8((void*)obj);
        return 1;
    }
    lbl_803DCC3E = 1;
    getNewShadowNoiseTextureFrames(&noiseTextures, &noiseFrameCount);
    fz = (f32)(s32)lbl_803DCC44 / (f32)(s32)noiseFrameCount;
    fz = fz * fz;
    fz = fz * lbl_803DEA28;
    selectTexture((Texture*)(textureIdxToPtr(*(u32*)Shader_getLayer(rop, 0))), 0);
    GXSetTexCoordGen2(GX_TEXCOORD2, GX_TG_MTX2x4, GX_TG_TEX0, GX_IDENTITY, GX_FALSE, GX_PTIDENTITY);
    GXSetTevDirect(GX_TEVSTAGE0);
    GXSetTevOrder(GX_TEVSTAGE0, GX_TEXCOORD2, GX_TEXMAP0, GX_COLOR_NULL);
    GXSetTevColorIn(GX_TEVSTAGE0, GX_CC_ZERO, GX_CC_ZERO, GX_CC_ZERO, GX_CC_TEXC);
    GXSetTevAlphaIn(GX_TEVSTAGE0, GX_CA_ZERO, GX_CA_ZERO, GX_CA_ZERO, GX_CA_ZERO);
    GXSetTevSwapMode(GX_TEVSTAGE0, GX_TEV_SWAP0, GX_TEV_SWAP0);
    GXSetTevColorOp(GX_TEVSTAGE0, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_FALSE, GX_TEVPREV);
    GXSetTevAlphaOp(GX_TEVSTAGE0, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    v = *(u8*)(obj + 0xf1);
    kc.b = v;
    kc.g = v;
    kc.r = v;
    GXSetTevKColor(GX_KCOLOR0, kc);
    GXSetTevKAlphaSel(GX_TEVSTAGE1, GX_TEV_KASEL_K0_A);
    GXSetTevKColorSel(GX_TEVSTAGE1, GX_TEV_KCSEL_K0);
    PSMTXScale(mtx3, lbl_803DEA2C, *(f32*)&lbl_803DEA2C, lbl_803DEA04);
    PSMTXTrans(mtx2, lbl_803DEA28, *(f32*)&lbl_803DEA28, lbl_803DEA1C);
    PSMTXConcat(mtx2, mtx3, mtx3);
    GXLoadTexMtxImm(mtx3, GX_PTTEXMTX1, GX_MTX3x4);
    GXSetTexCoordGen2(GX_TEXCOORD0, GX_TG_MTX2x4, GX_TG_NRM, GX_TEXMTX0, GX_FALSE, GX_PTTEXMTX1);
    selectTexture((Texture*)(ObjModel_GetRenderOpTextureRefs((ObjModel*)model, ropIdx)->texture0), 1);
    GXSetTevDirect(GX_TEVSTAGE1);
    GXSetTevOrder(GX_TEVSTAGE1, GX_TEXCOORD0, GX_TEXMAP1, GX_COLOR0A0);
    GXSetTevSwapMode(GX_TEVSTAGE1, GX_TEV_SWAP0, GX_TEV_SWAP0);
    GXSetTevColorIn(GX_TEVSTAGE1, GX_CC_ZERO, GX_CC_TEXC, GX_CC_KONST, GX_CC_RASC);
    GXSetTevAlphaIn(GX_TEVSTAGE1, GX_CA_ZERO, GX_CA_ZERO, GX_CA_ZERO, GX_CA_ZERO);
    GXSetTevColorOp(GX_TEVSTAGE1, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVREG1);
    GXSetTevAlphaOp(GX_TEVSTAGE1, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    getNewShadowCausticTexture((u32*)&t164);
    selectTexture((Texture*)((void*)t164), 4);
    newshadows_getReflectionScrollOffsets(&sx, &sy);
    PSMTXTrans(mtxR, lbl_803DEA28 * sx, *(f32*)&lbl_803DEA28 * sy, lbl_803DEA04);
    mtxR[0][0] = lbl_803DEA1C;
    mtxR[1][1] = lbl_803DEA1C;
    GXLoadTexMtxImm(mtxR, GX_PTTEXMTX2, GX_MTX3x4);
    GXSetTexCoordGen2(GX_TEXCOORD1, GX_TG_MTX2x4, GX_TG_TEX0, GX_IDENTITY, GX_FALSE, GX_PTTEXMTX2);
    GXSetIndTexOrder(GX_INDTEXSTAGE0, GX_TEXCOORD1, GX_TEXMAP4);
    GXSetIndTexCoordScale(0, 0, 0);
    mtxA.m[0][0] = fz;
    mtxA.m[1][1] = fz;
    GXSetIndTexMtx(GX_ITM_0, mtxA.m, (s8)lbl_803DB498);
    GXSetTevIndirect(2, 0, 0, 7, 1, 6, 6, 0, 0, 0);
    GXSetTevOrder(GX_TEVSTAGE2, GX_TEXCOORD_NULL, GX_TEXMAP_NULL, GX_COLOR_NULL);
    GXSetTevSwapMode(GX_TEVSTAGE2, GX_TEV_SWAP0, GX_TEV_SWAP0);
    GXSetTevColorIn(GX_TEVSTAGE2, GX_CC_ZERO, GX_CC_CPREV, GX_CC_C1, GX_CC_ZERO);
    GXSetTevAlphaIn(GX_TEVSTAGE2, GX_CA_ZERO, GX_CA_ZERO, GX_CA_ZERO, GX_CA_ZERO);
    GXSetTevColorOp(GX_TEVSTAGE2, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    GXSetTevAlphaOp(GX_TEVSTAGE2, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    selectTexture((Texture*)(textureIdxToPtr(*(int*)((u8*)rop + 0x38))), 2);
    GXSetTexCoordGen2(GX_TEXCOORD3, GX_TG_MTX2x4, GX_TG_TEX0, GX_IDENTITY, GX_FALSE, GX_PTIDENTITY);
    GXSetIndTexOrder(GX_INDTEXSTAGE1, GX_TEXCOORD3, GX_TEXMAP2);
    GXSetIndTexCoordScale(1, 0, 0);
    mtxB.m[0][1] = fz;
    mtxB.m[1][2] = fz;
    GXSetIndTexMtx(GX_ITM_1, mtxB.m, (s8)lbl_803DB49C);
    GXSetTevIndirect(3, 1, 0, 7, 2, 0, 0, 1, 0, 1);
    selectTexture(noiseTextures[lbl_803DCC44], 3);
    PSMTXScale(mtx4, lbl_803DEA30, *(f32*)&lbl_803DEA30, lbl_803DEA1C);
    GXLoadTexMtxImm(mtx4, GX_PTTEXMTX0, GX_MTX3x4);
    GXSetTexCoordGen2(GX_TEXCOORD4, GX_TG_MTX2x4, GX_TG_TEX0, GX_IDENTITY, GX_TRUE, GX_PTTEXMTX0);
    GXSetTevKColorSel(GX_TEVSTAGE3, GX_TEV_KCSEL_1_2);
    GXSetTevOrder(GX_TEVSTAGE3, GX_TEXCOORD4, GX_TEXMAP3, GX_ALPHA_BUMPN);
    GXSetTevColorIn(GX_TEVSTAGE3, GX_CC_TEXC, GX_CC_KONST, GX_CC_CPREV, GX_CC_CPREV);
    GXSetTevAlphaIn(GX_TEVSTAGE3, GX_CA_ZERO, GX_CA_TEXA, GX_CA_RASA, GX_CA_ZERO);
    GXSetTevSwapMode(GX_TEVSTAGE3, GX_TEV_SWAP0, GX_TEV_SWAP0);
    GXSetTevColorOp(GX_TEVSTAGE3, GX_TEV_SUB, GX_TB_ADDHALF, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    GXSetTevAlphaOp(GX_TEVSTAGE3, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    if (lbl_803DCC44 < 0xc)
    {
        GXSetNumTevStages(4);
        GXSetNumIndStages(2);
        GXSetNumTexGens(5);
    }
    else
    {
        ModelLightStruct* lt;
        kc2 = *(GXColor*)&lbl_803DEA00;
        lt = objCreateLight((void*)obj, 0);
        if (lt != NULL)
        {
            modelLightStruct_setLightKind(lt, MODEL_LIGHT_KIND_DIRECTIONAL);
            modelLightStruct_setDirection(lt, lbl_803DEA04, lbl_803DEA34, *(f32*)&lbl_803DEA04);
            modelLightStruct_setDiffuseColor(lt, 0xff, 0xff, 0xff, 0xff);
            modelLightChannels_reset(0);
            modelLightChannel_configure(2, 0, 0);
            GXSetChanAmbColor(GX_ALPHA0, *(GXColor*)&lbl_803DB470);
            GXSetChanMatColor(GX_ALPHA0, *(GXColor*)&lbl_803DB468);
            modelLightStruct_loadChannelLight(2, lt, (GameObject*)obj);
            modelLightChannels_applyGXControls();
            ModelLightStruct_free(lt);
        }
        GXSetTevKColor(GX_KCOLOR0, kc2);
        GXSetTevKAlphaSel(GX_TEVSTAGE5, GX_TEV_KASEL_K0_A);
        GXSetTevKColorSel(GX_TEVSTAGE5, GX_TEV_KCSEL_K0);
        newshadows_getShadowTextureTable4x8(&shadowTable, &shadowStride, &shadowRows);
        selectTexture(shadowTable[(lbl_803DCC44 - 0xc) + lbl_803DCC3D * shadowStride], 5);
        PSMTXScale(mtx5, lbl_803DEA38, *(f32*)&lbl_803DEA38, lbl_803DEA1C);
        GXLoadTexMtxImm(mtx5, GX_PTTEXMTX3, GX_MTX3x4);
        GXSetTexCoordGen2(GX_TEXCOORD5, GX_TG_MTX2x4, GX_TG_TEX0, GX_IDENTITY, GX_TRUE, GX_PTTEXMTX3);
        GXSetTevDirect(GX_TEVSTAGE4);
        GXSetTevOrder(GX_TEVSTAGE4, GX_TEXCOORD5, GX_TEXMAP5, GX_COLOR0A0);
        GXSetTevColorIn(GX_TEVSTAGE4, GX_CC_ZERO, GX_CC_ZERO, GX_CC_ZERO, GX_CC_CPREV);
        GXSetTevAlphaIn(GX_TEVSTAGE4, GX_CA_ZERO, GX_CA_TEXA, GX_CA_RASA, GX_CA_ZERO);
        GXSetTevSwapMode(GX_TEVSTAGE4, GX_TEV_SWAP0, GX_TEV_SWAP0);
        GXSetTevColorOp(GX_TEVSTAGE4, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
        GXSetTevAlphaOp(GX_TEVSTAGE4, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVREG1);
        GXSetTevDirect(GX_TEVSTAGE5);
        GXSetTevOrder(GX_TEVSTAGE5, GX_TEXCOORD_NULL, GX_TEXMAP_NULL, GX_COLOR_NULL);
        GXSetTevColorIn(GX_TEVSTAGE5, GX_CC_CPREV, GX_CC_KONST, GX_CC_A1, GX_CC_ZERO);
        GXSetTevAlphaIn(GX_TEVSTAGE5, GX_CA_APREV, GX_CA_A1, GX_CA_A1, GX_CA_ZERO);
        GXSetTevSwapMode(GX_TEVSTAGE5, GX_TEV_SWAP0, GX_TEV_SWAP0);
        GXSetTevColorOp(GX_TEVSTAGE5, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
        GXSetTevAlphaOp(GX_TEVSTAGE5, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
        GXSetNumTevStages(6);
        GXSetNumIndStages(2);
        GXSetNumTexGens(6);
    }
    GXSetCullMode(GX_CULL_BACK);
    {
        GXSetFog(GX_FOG_NONE, 0.0f, 0.0f, 0.0f, 0.0f, *(GXColor*)&lbl_803DB468);
    }
    gxSetZMode_(1, 3, 0);
    gxSetPeControl_ZCompLoc_(1);
    GXSetBlendMode(GX_BM_BLEND, GX_BL_SRCALPHA, GX_BL_INVSRCALPHA, GX_LO_NOOP);
    return 1;
}

extern GXColorS10 lbl_803DE9F4;
extern ObjPrintGXColor lbl_803DB494;
extern u8 lbl_803DCC35;
extern u8 lbl_803DCC36;
extern int lbl_803DCC5C;
extern u8 lbl_803DCC60;
extern int lbl_803DB48C;
extern int lbl_803DB490;

static inline int shaderProjDisabled(ModelLightStruct* light)
{
    int flag;
    int mode;
    modelLightStruct_getProjectionTevModes(light, &flag, &mode);
    return flag;
}

int shaderFuzzFn_8003cc1c(GameObject* obj, ObjModel* model, int ropIdx)
{
    Mtx mtx4;
    Mtx mtx3;
    Mtx mtx2;
    Mtx mtxR;
    IndTexMtx23 mtxA;
    IndTexMtx23 mtxB;
    GXColorS10 s10;
    int stage;
    int coord;
    Texture** noiseTextures;
    int noiseFrameCount;
    int texRef4;
    f32 sx;
    f32 sy;
    int projFlagOut1;
    u8* rop;
    f32 fz;
    int projBlendMode;
    u8 fancy;

    s10 = lbl_803DE9F4;
    mtxA = lbl_802C1B10;
    mtxB = lbl_802C1B28;
    rop = (u8*)ObjModel_GetRenderOp(model->file, ropIdx);
    if ((((ModelRenderOp*)rop)->flags & 0x200) == 0)
    {
        lbl_803DCC3E = 0;
        return 0;
    }
    lbl_803DCC3E = 1;
    getNewShadowNoiseTextureFrames(&noiseTextures, &noiseFrameCount);
    if (lbl_803DCC35 != 0)
    {
        fz = lbl_803DEA04;
    }
    else
    {
        fz = (f32)(s32)lbl_803DCC44 / (f32)(s32)noiseFrameCount;
        fz = fz * lbl_803DEA28;
    }
    selectTexture((Texture*)(textureIdxToPtr(*(u32*)Shader_getLayer(rop, 0))), 0);
    GXSetTexCoordGen2(GX_TEXCOORD2, GX_TG_MTX2x4, GX_TG_TEX0, GX_IDENTITY, GX_FALSE, GX_PTIDENTITY);
    if (lbl_803DCC36 == 0)
    {
        GXSetTevColorIn(GX_TEVSTAGE0, GX_CC_ZERO, GX_CC_ZERO, GX_CC_ZERO, GX_CC_TEXC);
    }
    else
    {
        if (lbl_803DCC36 == 1)
        {
            u8 v = lbl_803DCC44 << 4;
            lbl_803DB494.b = v;
            lbl_803DB494.g = v;
            lbl_803DB494.r = v;
            GXSetTevColorIn(GX_TEVSTAGE0, GX_CC_TEXC, GX_CC_ONE, GX_CC_KONST, GX_CC_ZERO);
        }
        else
        {
            if (lbl_803DCC44 < 8)
            {
                lbl_803DB494.b = lbl_803DCC44 << 5;
            }
            else
            {
                lbl_803DB494.b = 0xff;
            }
            lbl_803DB494.g = lbl_803DB494.b;
            lbl_803DB494.r = lbl_803DB494.b;
            GXSetTevColorIn(GX_TEVSTAGE0, GX_CC_TEXC, GX_CC_ZERO, GX_CC_KONST, GX_CC_ZERO);
        }
        GXSetTevKColor(GX_KCOLOR1, *(GXColor*)&lbl_803DB494);
        GXSetTevKAlphaSel(GX_TEVSTAGE0, GX_TEV_KASEL_K1_A);
        GXSetTevKColorSel(GX_TEVSTAGE0, GX_TEV_KCSEL_K1);
    }
    GXSetTevDirect(GX_TEVSTAGE0);
    GXSetTevOrder(GX_TEVSTAGE0, GX_TEXCOORD2, GX_TEXMAP0, GX_COLOR_NULL);
    GXSetTevAlphaIn(GX_TEVSTAGE0, GX_CA_ZERO, GX_CA_ZERO, GX_CA_ZERO, GX_CA_ZERO);
    GXSetTevSwapMode(GX_TEVSTAGE0, GX_TEV_SWAP0, GX_TEV_SWAP0);
    GXSetTevColorOp(GX_TEVSTAGE0, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_FALSE, GX_TEVPREV);
    GXSetTevAlphaOp(GX_TEVSTAGE0, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    {
        u8 v = obj->unkF1;
        s10.b = v;
        s10.g = v;
        s10.r = v;
        s10.a = obj->anim.pad37[0] - 0xff;
    }
    GXSetTevColorS10(GX_TEVREG2, s10);
    PSMTXScale(mtx3, lbl_803DEA2C, *(f32*)&lbl_803DEA2C, lbl_803DEA04);
    PSMTXTrans(mtx2, lbl_803DEA28, *(f32*)&lbl_803DEA28, lbl_803DEA1C);
    PSMTXConcat(mtx2, mtx3, mtx3);
    GXLoadTexMtxImm(mtx3, GX_PTTEXMTX1, GX_MTX3x4);
    GXSetTexCoordGen2(GX_TEXCOORD0, GX_TG_MTX2x4, GX_TG_NRM, GX_TEXMTX0, GX_FALSE, GX_PTTEXMTX1);
    selectTexture((Texture*)(ObjModel_GetRenderOpTextureRefs(model, ropIdx)->texture0), 1);
    GXSetTevDirect(GX_TEVSTAGE1);
    GXSetTevOrder(GX_TEVSTAGE1, GX_TEXCOORD0, GX_TEXMAP1, GX_COLOR0A0);
    GXSetTevSwapMode(GX_TEVSTAGE1, GX_TEV_SWAP0, GX_TEV_SWAP0);
    GXSetTevColorIn(GX_TEVSTAGE1, GX_CC_ZERO, GX_CC_TEXC, GX_CC_C2, GX_CC_RASC);
    GXSetTevAlphaIn(GX_TEVSTAGE1, GX_CA_ZERO, GX_CA_ZERO, GX_CA_ZERO, GX_CA_A2);
    GXSetTevColorOp(GX_TEVSTAGE1, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVREG1);
    GXSetTevAlphaOp(GX_TEVSTAGE1, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_FALSE, GX_TEVPREV);
    if (lbl_803DCC5C != 0 && shaderProjDisabled(lbl_803DCC64) == 0)
    {
        fancy = 1;
    }
    else
    {
        fancy = 0;
    }
    if (fancy)
    {
        GXSetTevDirect(GX_TEVSTAGE2);
        GXLoadTexMtxImm((MtxPtr)modelLightStruct_getProjectionTexMtx(lbl_803DCC64), GX_PTTEXMTX3, GX_MTX3x4);
        GXSetTexCoordGen2(GX_TEXCOORD1, GX_TG_MTX3x4, GX_TG_POS, GX_PNMTX0, GX_FALSE, GX_PTTEXMTX3);
        if (lbl_803DCC60 == 0 || lbl_803DCC60 == 2)
        {
            GXSetTevOrder(GX_TEVSTAGE2, GX_TEXCOORD1, GX_TEXMAP5, GX_COLOR0A0);
        }
        else
        {
            GXSetTevOrder(GX_TEVSTAGE2, GX_TEXCOORD1, GX_TEXMAP5, GX_COLOR1A1);
        }
        selectTexture((Texture*)(modelLightStruct_getProjectionTexture(lbl_803DCC64)), 5);
        modelLightStruct_getProjectionTevModes(lbl_803DCC64, &projFlagOut1, &projBlendMode);
        if (projBlendMode == 2)
        {
            GXSetTevColorIn(GX_TEVSTAGE2, GX_CC_ZERO, GX_CC_C1, GX_CC_TEXC, GX_CC_ZERO);
        }
        else if (projBlendMode == 3)
        {
            GXSetTevColorIn(GX_TEVSTAGE2, GX_CC_C1, GX_CC_ZERO, GX_CC_TEXC, GX_CC_ZERO);
        }
        else if (projBlendMode == 1)
        {
            GXSetTevColorIn(GX_TEVSTAGE2, GX_CC_ZERO, GX_CC_ZERO, GX_CC_TEXC, GX_CC_C1);
        }
        else if (lbl_803DCC60 == 0 || lbl_803DCC60 == 1)
        {
            GXSetTevColorIn(GX_TEVSTAGE2, GX_CC_ZERO, GX_CC_RASC, GX_CC_TEXC, GX_CC_C1);
        }
        else
        {
            GXSetTevColorIn(GX_TEVSTAGE2, GX_CC_ZERO, GX_CC_RASA, GX_CC_TEXC, GX_CC_C1);
        }
        GXSetTevSwapMode(GX_TEVSTAGE2, GX_TEV_SWAP0, GX_TEV_SWAP0);
        if (projBlendMode == 1)
        {
            GXSetTevColorOp(GX_TEVSTAGE2, GX_TEV_SUB, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVREG1);
        }
        else
        {
            GXSetTevColorOp(GX_TEVSTAGE2, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVREG1);
        }
        GXSetTevAlphaIn(GX_TEVSTAGE2, GX_CA_ZERO, GX_CA_ZERO, GX_CA_ZERO, GX_CA_APREV);
        GXSetTevAlphaOp(GX_TEVSTAGE2, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
        stage = 3;
        coord = 5;
    }
    else
    {
        stage = 2;
        coord = 1;
    }
    getNewShadowCausticTexture((u32*)&texRef4);
    selectTexture((Texture*)((void*)texRef4), 4);
    newshadows_getReflectionScrollOffsets(&sx, &sy);
    PSMTXTrans(mtxR, lbl_803DEA28 * sx, *(f32*)&lbl_803DEA28 * sy, lbl_803DEA04);
    mtxR[0][0] = lbl_803DEA1C;
    mtxR[1][1] = lbl_803DEA1C;
    GXLoadTexMtxImm(mtxR, GX_PTTEXMTX2, GX_MTX3x4);
    GXSetTexCoordGen2(coord, GX_TG_MTX2x4, GX_TG_TEX0, GX_IDENTITY, GX_FALSE, GX_PTTEXMTX2);
    GXSetIndTexOrder(GX_INDTEXSTAGE0, coord, GX_TEXMAP4);
    GXSetIndTexCoordScale(0, 0, 0);
    mtxA.m[0][0] = fz;
    mtxA.m[1][1] = fz;
    GXSetIndTexMtx(GX_ITM_0, mtxA.m, (s8)lbl_803DB48C);
    GXSetTevIndirect(stage, 0, 0, 7, 1, 6, 6, 0, 0, 0);
    GXSetTevOrder(stage, GX_TEXCOORD_NULL, GX_TEXMAP_NULL, GX_COLOR_NULL);
    GXSetTevSwapMode(stage, GX_TEV_SWAP0, GX_TEV_SWAP0);
    GXSetTevColorIn(stage, GX_CC_ZERO, GX_CC_CPREV, GX_CC_C1, GX_CC_ZERO);
    GXSetTevAlphaIn(stage, GX_CA_ZERO, GX_CA_ZERO, GX_CA_ZERO, GX_CA_APREV);
    GXSetTevColorOp(stage, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    GXSetTevAlphaOp(stage, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_FALSE, GX_TEVPREV);
    if (*(void**)(rop + 0x38) != NULL)
    {
        selectTexture((Texture*)(textureIdxToPtr(*(int*)((u8*)rop + 0x38))), 2);
        GXSetTexCoordGen2(GX_TEXCOORD3, GX_TG_MTX2x4, GX_TG_TEX0, GX_IDENTITY, GX_FALSE, GX_PTIDENTITY);
        GXSetIndTexOrder(GX_INDTEXSTAGE1, GX_TEXCOORD3, GX_TEXMAP2);
        GXSetIndTexCoordScale(1, 0, 0);
        mtxB.m[0][1] = fz;
        mtxB.m[1][2] = fz;
        GXSetIndTexMtx(GX_ITM_1, mtxB.m, (s8)lbl_803DB490);
        GXSetTevIndirect(stage + 1, 1, 0, 7, 2, 0, 0, 1, 0, 1);
    }
    else
    {
        GXSetIndTexOrder(GX_INDTEXSTAGE1, GX_TEXCOORD3, GX_TEXMAP2);
        GXSetIndTexCoordScale(1, 0, 0);
        mtxB.m[0][1] = lbl_803DEA04;
        mtxB.m[1][2] = lbl_803DEA04;
        GXSetIndTexMtx(GX_ITM_1, mtxB.m, -0xf);
        GXSetTevIndirect(stage + 1, 1, 0, 7, 2, 0, 0, 1, 0, 0);
    }
    selectTexture(noiseTextures[lbl_803DCC44], 3);
    PSMTXScale(mtx4, lbl_803DEA30, *(f32*)&lbl_803DEA30, lbl_803DEA1C);
    GXLoadTexMtxImm(mtx4, GX_PTTEXMTX0, GX_MTX3x4);
    GXSetTexCoordGen2(GX_TEXCOORD4, GX_TG_MTX2x4, GX_TG_TEX0, GX_IDENTITY, GX_TRUE, GX_PTTEXMTX0);
    GXSetTevKColorSel(stage + 1, GX_TEV_KCSEL_1_2);
    if (*(void**)(rop + 0x38) != NULL)
    {
        GXSetTevOrder(stage + 1, GX_TEXCOORD4, GX_TEXMAP3, GX_ALPHA_BUMPN);
        GXSetTevAlphaIn(stage + 1, GX_CA_ZERO, GX_CA_TEXA, GX_CA_RASA, GX_CA_APREV);
    }
    else
    {
        GXSetTevOrder(stage + 1, GX_TEXCOORD4, GX_TEXMAP3, GX_COLOR_NULL);
        GXSetTevAlphaIn(stage + 1, GX_CA_TEXA, GX_CA_ZERO, GX_CA_ZERO, GX_CA_APREV);
    }
    GXSetTevColorIn(stage + 1, GX_CC_TEXC, GX_CC_KONST, GX_CC_CPREV, GX_CC_CPREV);
    GXSetTevSwapMode(stage + 1, GX_TEV_SWAP0, GX_TEV_SWAP0);
    GXSetTevColorOp(stage + 1, GX_TEV_SUB, GX_TB_ADDHALF, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    GXSetTevAlphaOp(stage + 1, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    if (fancy)
    {
        GXSetNumTevStages(5);
        GXSetNumTexGens(6);
    }
    else
    {
        GXSetNumTevStages(4);
        GXSetNumTexGens(5);
    }
    GXSetNumIndStages(2);
    GXSetCullMode(GX_CULL_BACK);
    if ((model->file->flags & 0x100) != 0)
    {
        GXSetFog(GX_FOG_NONE, 0.0f, 0.0f, 0.0f, 0.0f, *(GXColor*)&lbl_803DB468);
    }
    else
    {
        _gxSetFogParams();
    }
    gxSetZMode_(1, 3, 0);
    gxSetPeControl_ZCompLoc_(1);
    GXSetBlendMode(GX_BM_BLEND, GX_BL_SRCALPHA, GX_BL_INVSRCALPHA, GX_LO_NOOP);
    return 1;
}
