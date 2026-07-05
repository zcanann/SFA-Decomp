#include "main/game_object.h"
#include "main/camera_interface.h"
#include "main/effect_interfaces.h"
#include "main/mapEvent.h"
#include "main/model.h"
#include "main/object_transform.h"
#include "main/objprint_dolphin.h"
#include "main/vecmath.h"
#include "main/camera.h"
#include "dolphin/gx/GXDispList.h"
#include "main/dll/FRONT/n_options.h"
#include "main/sfa_extern_decls.h"
#include "main/dll/DR/dll_80209FE0_shared.h"
#define GX_AOP_AND 0
#define GX_BL_ZERO 0
#define GX_BM_NONE 0
#define GX_COLOR0 0
#define GX_CS_SCALE_1 0
#define GX_DF_NONE 0
#define GX_FALSE 0
#define GX_SRC_REG 0
#define GX_TB_ZERO 0
#define GX_TEVPREV 0
#define GX_TEV_ADD 0
#define GX_BL_ONE 1
#define GX_BM_BLEND 1
#define GX_SRC_VTX 1
#define GX_TRUE 1
#define GX_AF_NONE 2
#define GX_ALPHA0 2
#define GX_BM_LOGIC 2
#define GX_CA_A2 3
#define GX_BL_SRCALPHA 4
#define GX_COLOR0A0 4
#define GX_GREATER 4
#define GX_BL_INVSRCALPHA 5
#define GX_COLOR1A1 5
#define GX_LO_NOOP 5
#define GX_CC_C2 6
#define GX_ALWAYS 7
#define GX_CA_ZERO 7
#define GX_LO_OR 7
#define GX_CC_ZERO 0xf
#define GX_TEXCOORD_NULL 0xff
#define GX_TEXMAP_NULL 0xff
#define GX_TEVSTAGE0 0
#define GX_TEV_SWAP0 0
#define GX_FOG_NONE 0
#define GX_VA_PNMTXIDX 0
#define GX_VA_TEX0MTXIDX 1
#define GX_VA_TEX1MTXIDX 2
#define GX_DIRECT 1
#define GX_VA_POS 9
#define GX_VA_NRM 10
#define GX_VA_CLR0 11
#define GX_VA_TEX0 13
#define GX_VA_TEX1 14
#define GX_TRIANGLES 0x90
#define GX_VTXFMT7 7
#define GX_CULL_NONE 0
#define GX_CULL_FRONT 1
#define GX_CULL_BACK 2
#define GX_TEVREG2 3
#define GX_KCOLOR0 0

typedef struct ObjPrintGXColor
{
    u8 r, g, b, a;
} ObjPrintGXColor;

/*
 * One render op ("shader") record from the model file's renderOps array,
 * bound by opcode 1 of the render-instruction stream.  Layer records
 * (Shader_getLayer) precede these fields; byte 0x41 holds the layer count
 * and byte 0x40 the layer blend flags (0x10 = additive path).
 * flags (+0x3C) bits seen in this file: 8 = backface cull, 0x100 = extra
 * projected-texture pass, 0x400 = alpha-test opaque, 0x200 = fuzz overlay
 * eligible, 0x20000 = water/caustic hook, 0x100000 = decal second layer,
 * 0x40000000 = force blend.
 */
typedef struct ObjModelRenderOp
{
    u8 pad0[0x18 - 0x0];
    u32 textureId;
    u32 unk1C;
    u8 pad20[0x24 - 0x20];
    u32 unk24;
    u8 pad28[0x34 - 0x28];
    u32 envTextureId;
    u8 pad38[0x3C - 0x38];
    u32 flags;
} ObjModelRenderOp;

#define OBJPRINT_MODEL_DEF(obj) (((ObjAnimComponent *)(obj))->modelInstance)
#define OBJPRINT_ACTIVE_BANK_INDEX(obj) (((ObjAnimComponent *)(obj))->bankIndex)

extern u32 FUN_8001759c();
extern u32 FUN_800175b0();
extern void FUN_800175d4(int* light, f32 x, f32 y, f32 z);
extern u32 FUN_800175fc();
extern u32 FUN_80017600();
extern u32 FUN_80017604();
extern u32 FUN_80017608();
extern u32 FUN_80017620();
extern void* FUN_80017624();

extern u32 FUN_8004812c();
extern void newshadows_getShadowTextureTable4x8();
extern void gxSetPeControl_ZCompLoc_(u8 zcomploc);
extern void gxSetZMode_(u8 enable, int func, u8 update);
extern void FUN_80247a7c(f32* m, f32 x, f32 y, f32 z);
extern u32 FUN_80258674();
extern u32 FUN_80258944();
extern u32 FUN_80259288();
extern u32 FUN_8025a2ec();
extern u32 FUN_8025a454();
extern u32 FUN_8025be54();
extern u32 FUN_8025be80();
extern u32 FUN_8025c1a4();
extern u32 FUN_8025c224();
extern u32 FUN_8025c2a8();
extern u32 FUN_8025c368();
extern u32 FUN_8025c510();
extern u32 GXSetBlendMode();
extern u32 FUN_8025c5f0();
extern u32 FUN_8025c65c();
extern u32 FUN_8025c828();
extern u32 FUN_8025ca04();
extern u32 FUN_8025ca38();
extern u32 FUN_8025cce8();
extern u32 FUN_8025d8c4();
extern u32 DAT_803dc0c8;
extern u32 DAT_803dc0d0;
extern u8 DAT_803dd8bd;
extern s32 gGameUiBlinkTexture;
extern u32 DAT_803df670;
extern f32 lbl_803DF684;
extern f32 lbl_803DF69C;
extern f32 lbl_803DF6B4;
extern f32 lbl_803DF6B8;

void objRenderFuzzFn_8003d6f8(void* objArg)
{
    int obj = (int)objArg;
    int* renderHandle;
    volatile u32 savedEnvColor;
    int shadowTable;
    int shadowStride;
    u32 shadowParam;
    u32 tevColor;
    u32 ambColor;
    u32 envColor;
    float mtx[12];

    savedEnvColor = DAT_803df670;
    renderHandle = FUN_80017624(obj, '\0');
    if (renderHandle != 0x0)
    {
        FUN_800175b0((int)renderHandle, 4);
        FUN_800175d4(renderHandle, lbl_803DF684, lbl_803DF6B4, *(f32*)&lbl_803DF684);
        FUN_8001759c((int)renderHandle, 0xff, 0xff, 0xff, 0xff);
        FUN_80017608(0);
        FUN_80017600(2, 0, 0);
        tevColor = DAT_803dc0d0;
        FUN_8025a2ec(2, &tevColor);
        ambColor = DAT_803dc0c8;
        FUN_8025a454(2, &ambColor);
        FUN_800175fc(2, renderHandle, obj);
        FUN_80017604();
        FUN_80017620((u32)renderHandle);
    }
    envColor = savedEnvColor;
    FUN_8025c510(0, (u8*)&envColor);
    FUN_8025c5f0(0, 0x1c);
    GXSetBlendMode(0, 0xc);
    newshadows_getShadowTextureTable4x8(&shadowTable, &shadowStride, &shadowParam);
    FUN_8004812c(*(int*)(shadowTable + ((gGameUiBlinkTexture >> 2) + DAT_803dd8bd * shadowStride) * 4), 0);
    FUN_80247a7c(mtx, lbl_803DF6B8, *(f32*)&lbl_803DF6B8, lbl_803DF69C);
    FUN_8025d8c4(mtx, 0x40, 0);
    FUN_80258674(1, 1, 4, 0x3c, 1, 0x40);
    FUN_8025be80(0);
    FUN_8025c828(0, 1, 0, 4);
    FUN_8025c1a4(0, 0xf, 0xf, 0xf, 0xe);
    FUN_8025c224(0, 7, 4, 5, 7);
    FUN_8025c65c(0, 0, 0);
    FUN_8025c2a8(0, 0, 0, 0, 1, 0);
    FUN_8025c368(0, 0, 0, 3, 1, 0);
    FUN_8025ca04(1);
    FUN_8025be54(0);
    FUN_80258944(2);
    FUN_80259288(2);
    {
        extern void FUN_8025ca38(int type, f32 a, f32 b, f32 c, f32 d, ObjPrintGXColor color);
        FUN_8025ca38(0, 0.0f, 0.0f, 0.0f, 0.0f, *(ObjPrintGXColor*)&DAT_803dc0c8);
    }
    gxSetZMode_(1, 3, 0);
    gxSetPeControl_ZCompLoc_(1);
    FUN_8025cce8(1, 4, 5, 5);
    return;
}

extern u32 curObjMtx;
extern u8 lbl_803DCC29;
extern u32 lbl_803DCC74;
void objSetMtxFn_800412d4(u32 x) { curObjMtx = x; }
void set_shadowFlag_803dcc29(u8 x) { lbl_803DCC29 = x; }
u32 isRomListLoading(void) { return lbl_803DCC74; }

extern u32 lbl_803DCC70;
void clearForceLoadImmediately(void) { lbl_803DCC70 = 0x0; }
void setForceLoadImmediately(void) { lbl_803DCC70 = 0x1; }

extern u8 gObjOverrideColorPending;
extern u8 gObjOverrideColor;

void fn_800412B8(u8 r, u8 g, u8 b)
{
    gObjOverrideColorPending = 1;
    gObjOverrideColor = r;
    (&gObjOverrideColor)[1] = g;
    (&gObjOverrideColor)[2] = b;
}

extern s32 gObjLevelLockSlots;

int lockLevel(s32 val, int idx)
{
    s32 cur = (&gObjLevelLockSlots)[idx];
    if (cur == -2)
    {
        (&gObjLevelLockSlots)[idx] = val;
        return -1;
    }
    return cur;
}

extern volatile int lbl_803DCC80;
extern int OSDisableInterrupts(void);
extern asm BOOL OSRestoreInterrupts(register BOOL level);

void setLoadedFileFlags_blocks1(void)
{
    int s = OSDisableInterrupts();
    lbl_803DCC80 |= 0x100000;
    OSRestoreInterrupts(s);
}

u32 getLoadedFileFlags(void)
{
    int s = OSDisableInterrupts();
    u32 v = lbl_803DCC80;
    OSRestoreInterrupts(s);
    return v;
}

void clearLoadedFileFlags_blocks1(void)
{
    int s = OSDisableInterrupts();
    if (lbl_803DCC80 & 0x100000)
    {
        lbl_803DCC80 ^= 0x100000;
    }
    OSRestoreInterrupts(s);
}

extern s16 gObjMapBlockInfo[];

s32 mapCheckCurBlocks(int v)
{
    if (((s16*)((char*)gObjMapBlockInfo + 0x4a))[0] == v) return 0;
    if (((s16*)((char*)gObjMapBlockInfo + 0x8e))[0] == v) return 1;
    return -1;
}

extern u8 gObjRenderSetupDone;
extern u32 gObjCachedTexture;
extern u32 gObjCachedModel;
extern u8 lbl_803DCC34;
extern u32 gObjGxVtxDescCache;
extern u8 gObjGxBlendModeCache;
extern u8 gObjGxZCompLocCache;
extern u32 gObjGxAlphaCompareCache;
extern u8 gObjGxZWriteCache;
extern u8 gObjGxZCompareCache;
extern u8 gObjGxCullModeCache;
extern u8 gObjGxKColorCache[4];

void renderResetFn_8003fc60(void)
{
    gObjRenderSetupDone = 0;
    gObjCachedTexture = 0;
    gObjCachedModel = 0;
    lbl_803DCC34 = 0;
    gObjGxVtxDescCache = -1;
    gObjGxBlendModeCache = 0xff;
    gObjGxZCompLocCache = 0xff;
    gObjGxAlphaCompareCache = -1;
    gObjGxZWriteCache = 0xff;
    gObjGxZCompareCache = 0xff;
    gObjGxCullModeCache = 0xff;
    gObjGxKColorCache[3] = 0;
    gObjGxKColorCache[2] = 0;
    gObjGxKColorCache[1] = 0;
    gObjGxKColorCache[0] = 0;
}

extern s32 DVDGetCommandBlockStatus(void* block);

// DVDGetCommandBlockStatus() command-block states (DVD_STATE_*)
#define DVD_STATE_FATAL_ERROR -1
#define DVD_STATE_END 0
#define DVD_STATE_BUSY 1
#define DVD_STATE_WAITING 2
#define DVD_STATE_COVER_CLOSED 3
#define DVD_STATE_NO_DISK 4
#define DVD_STATE_COVER_OPEN 5
#define DVD_STATE_WRONG_DISK 6
#define DVD_STATE_MOTOR_STOPPED 7
#define DVD_STATE_PAUSING 8
#define DVD_STATE_IGNORED 9
#define DVD_STATE_CANCELED 10
#define DVD_STATE_RETRY 11

int fn_80041D98(void* block)
{
    s32 status;
    if (block == NULL)
    {
        return -1;
    }
    status = DVDGetCommandBlockStatus(block);
    switch (status)
    {
    case DVD_STATE_FATAL_ERROR: return status;
    case DVD_STATE_END: return status;
    case DVD_STATE_BUSY: return status;
    case DVD_STATE_WAITING: return status;
    case DVD_STATE_COVER_CLOSED: return status;
    case DVD_STATE_NO_DISK: return status;
    case DVD_STATE_COVER_OPEN: return status;
    case DVD_STATE_WRONG_DISK: return status;
    case DVD_STATE_MOTOR_STOPPED: return status;
    case DVD_STATE_PAUSING: return status;
    case DVD_STATE_IGNORED: return status;
    case DVD_STATE_CANCELED: return status;
    case DVD_STATE_RETRY: return status;
    }
    return 0;
}

extern f32 lbl_803DEA04;
extern int* Obj_GetActiveModel(int* obj);
#pragma dont_inline on
void objRenderShadow(int* obj)
{
    if (lbl_803DEA04 == ((GameObject*)obj)->anim.rootMotionScale)
    {
        curObjMtx = 0;
        return;
    }
    {
        int* m = (int*)*Obj_GetActiveModel(obj);
        if (*(u8*)((char*)m + 246) != 0)
        {
            objRenderShadow2(obj, obj, (u8*)m, 1);
        }
        else
        {
            modelDoRenderInstrs(obj, obj, (u8*)m, 1);
        }
    }
    if (((GameObject*)obj)->anim.classId == 1)
    {
        u8* iter;
        int i = 0;
        iter = (u8*)obj;
        for (; i < ((GameObject*)obj)->childCount; i++)
        {
            int* child = *(int**)(iter + 200);
            if (child != NULL)
            {
                objRenderChild(child, obj, 1);
            }
            iter += 4;
        }
    }
}
#pragma dont_inline reset

extern s32 gObjFuzzStep;
extern s32 lbl_803DCC44;
extern u8 lbl_803DCC3D;
extern f32 gObjFuzzPhase;
extern f32 lbl_803DEA60;
extern f32 lbl_803DEA5C;
extern f32 lbl_803DEA64;
extern f32 lbl_803DEA68;
extern const f32 lbl_803DEA1C;
extern f32 lbl_803DEA6C;
extern f32 playerMapOffsetX;
extern f32 playerMapOffsetZ;
extern u8 gObjShadowColor[4];
extern void ObjModel_SetRenderCallback(int* model, void* cb);
extern void modelRenderCb_8003c268();
extern void shaderFuzzFn_8003cc1c();
extern void modelDoAltRenderInstrs(int* obj, int* obj2, u8* model, int p4);


extern void PSMTXMultVec(f32 * m, f32 * src, f32 * dst);
extern void PSMTXConcat(f32 * a, f32 * b, f32 * ab);
extern void setMatrixFromObjectTransposed(void* obj, f32* out);
extern void Matrix_TransformPoint(f32* m, f32 x, f32 y, f32 z, f32* ox, f32* oy, f32* oz);
extern void Obj_BuildWorldTransformMatrix(int* obj, f32* m, int p3);
extern void objRotateFn_8003bce8(f32 * m, s16 * a, s16 * b, s16 * c);
extern void Camera_ProjectWorldPointWithOffset(f32 x, f32 y, f32 z, f32 offset, f32* outX, f32* outY, f32* outZ);
extern void Camera_NdcToScreen(f32 a, f32 b, f32 c, int* x, int* y, int* z);
extern int depthReadRequestPoll(int x, int y, int* obj);
extern void objShadowFn_8006c5f0(int* obj, int* a, f32* b, int* c, int* d);
extern void hudDrawColored(int a, int b, int c, u32* col, int d, int e);
void objMtxFn_80041104(f32* mtx, f32* out, s16* in, int flag, int* obj, int e);
void objRenderModel(int* obj);

void objRenderFn_800413d4(int* obj)
{
    int* model;
    u32 savedMtx;
    gObjFuzzStep = 4;
    model = Obj_GetActiveModel(obj);
    savedMtx = curObjMtx;
    lbl_803DCC3D = gObjFuzzPhase;
    for (lbl_803DCC44 = 0; lbl_803DCC44 < 16; lbl_803DCC44 += gObjFuzzStep)
    {
        modelDoRenderInstrs(obj, ((GameObject*)obj)->ownerObj ? ((GameObject*)obj)->ownerObj : obj, (u8*)*model, 2);
        curObjMtx = savedMtx;
    }
    curObjMtx = 0;
    gObjFuzzPhase += timeDelta;
    if (gObjFuzzPhase > lbl_803DEA60)
    {
        gObjFuzzPhase -= lbl_803DEA5C;
    }
}

void fuzzRenderFn_800412dc(int* obj)
{
    int* model;
    u32 savedMtx;
    gObjFuzzStep = 1;
    model = Obj_GetActiveModel(obj);
    savedMtx = curObjMtx;
    lbl_803DCC3D = gObjFuzzPhase;
    ObjModel_SetRenderCallback(model, modelRenderCb_8003c268);
    for (lbl_803DCC44 = 0; lbl_803DCC44 < 16; lbl_803DCC44 += gObjFuzzStep)
    {
        modelDoRenderInstrs(obj, ((GameObject*)obj)->ownerObj ? ((GameObject*)obj)->ownerObj : obj, (u8*)*model, 8);
        curObjMtx = savedMtx;
    }
    curObjMtx = 0;
    ObjModel_SetRenderCallback(model, NULL);
    gObjFuzzPhase += timeDelta;
    if (gObjFuzzPhase > lbl_803DEA60)
    {
        gObjFuzzPhase -= lbl_803DEA5C;
    }
}

void objRenderFuzz(int* obj)
{
    int n;
    u8 maxN;
    int cnt;
    int* model;
    u32 savedMtx;
    u8 strong;
    f32 dx, dy, dz, dist;
    int* cam = Camera_GetCurrentViewSlot();
    if ((((GameObject*)obj)->objectFlags & OBJECT_OBJFLAG_PARENT_SLACK) || ((GameObject*)obj)->anim.mapEventSlot == 0x3f
        || ((GameObject*)obj)->anim.seqId == 0x882 || ((GameObject*)obj)->anim.seqId == 0x887)
    {
        strong = 1;
        if (((GameObject*)obj)->anim.classId == 1 || ((GameObject*)obj)->anim.seqId == 0x77d
            || ((GameObject*)obj)->anim.seqId == 0x882 || ((GameObject*)obj)->anim.seqId == 0x887)
        {
            maxN = 0xf;
        }
        else
        {
            maxN = 7;
        }
    }
    else
    {
        strong = 0;
        maxN = 3;
    }
    {
        u32 m = curObjMtx;
        if (m != 0)
        {
            dx = *(f32*)&((ModelFileHeader*)m)->dataSize - (((GameObject*)cam)->anim.localPosX - playerMapOffsetX);
            dy = *(f32*)&((ModelFileHeader*)m)->unk1C - ((GameObject*)cam)->anim.localPosY;
            dz = *(f32*)&((ModelFileHeader*)m)->normals - (((GameObject*)cam)->anim.localPosZ - playerMapOffsetZ);
        }
        else
        {
            dx = ((GameObject*)obj)->anim.worldPosX - ((GameObject*)cam)->anim.localPosX;
            dy = ((GameObject*)obj)->anim.worldPosY - ((GameObject*)cam)->anim.localPosY;
            dz = ((GameObject*)obj)->anim.worldPosZ - ((GameObject*)cam)->anim.localPosZ;
        }
    }
    dist = sqrtf(dx * dx + dy * dy + dz * dz);
    if (strong == 0)
    {
        cnt = (s32)(
            (lbl_803DEA64 * (lbl_803DEA68 * dist)) / (((GameObject*)obj)->anim.hitboxScale * ((GameObject*)obj)->anim.
                rootMotionScale));
        gObjFuzzStep = 2;
    }
    else
    {
        cnt = (s32)(
            (lbl_803DEA68 * dist) / (((GameObject*)obj)->anim.hitboxScale * ((GameObject*)obj)->anim.rootMotionScale));
        gObjFuzzStep = 1;
    }
    n = 16 - cnt;
    if (n > 0)
    {
        if (n > maxN)
        {
            n = maxN;
        }
        model = Obj_GetActiveModel(obj);
        savedMtx = curObjMtx;
        ObjModel_SetRenderCallback(model, shaderFuzzFn_8003cc1c);
        for (lbl_803DCC44 = 0; lbl_803DCC44 < n; lbl_803DCC44++)
        {
            modelDoRenderInstrs(obj, ((GameObject*)obj)->ownerObj ? ((GameObject*)obj)->ownerObj : obj, (u8*)*model, 4);
            curObjMtx = savedMtx;
        }
        curObjMtx = 0;
        ObjModel_SetRenderCallback(model, NULL);
    }
}

void objRenderFn_80041018(int* obj)
{
    ObjDefHitVolume* p;
    ObjHitVolumeRuntimeTransform* q;
    int* model;
    ObjDefHitVolume* base;
    int i;
    base = ((GameObject*)obj)->anim.modelInstance->hitVolumes;
    q = ((GameObject*)obj)->anim.hitVolumeTransforms;
    if (!(*(u8*)&((GameObject*)obj)->anim.resetHitboxMode & 0x28))
    {
        model = Obj_GetActiveModel(obj);
        i = 0;
        p = base;
        for (; i < ((GameObject*)obj)->anim.modelInstance->hitVolumeCount; i++)
        {
            int j = p->jointIndices[OBJPRINT_ACTIVE_BANK_INDEX(obj)];
            ObjModelJointMatrix* mtx;
            if (j >= 0)
            {
                mtx = ObjModel_GetJointMatrix((u8*)model, j);
            }
            else
            {
                mtx = NULL;
            }
            objMtxFn_80041104(NULL, &q->centerX, &p->posX, base->flags & 0x10, obj, 0);
            objMtxFn_80041104((f32*)mtx, &q->jointX, &p->jointOffsetX, base->flags & 0x10, obj, 1);
            p++;
            q++;
        }
    }
}

void objMtxFn_80041104(f32* mtx, f32* out, s16* in, int flag, int* obj, int e)
{
    f32 m[16];
    struct
    {
        s16 rot[3];
        f32 scale;
        f32 pos[3];
    } blk;
    f32 v[3];
    f32 res[3];
    v[0] = in[0];
    v[1] = in[1];
    v[2] = in[2];
    if (e != 0)
    {
        v[0] *= 0.00390625f;
        v[1] *= 0.00390625f;
        v[2] *= 0.00390625f;
    }
    if (mtx != NULL)
    {
        if (flag != 0)
        {
            out[0] = mtx[3] + v[0];
            out[1] = mtx[7] + v[1];
            out[2] = mtx[11] + v[2];
        }
        else
        {
            PSMTXMultVec(mtx, v, res);
            out[0] = res[0];
            out[1] = res[1];
            out[2] = res[2];
        }
        out[0] += playerMapOffsetX;
        out[2] += playerMapOffsetZ;
    }
    else
    {
        blk.pos[0] = ((GameObject*)obj)->anim.worldPosX;
        blk.pos[1] = ((GameObject*)obj)->anim.worldPosY;
        blk.pos[2] = ((GameObject*)obj)->anim.worldPosZ;
        if (flag != 0)
        {
            blk.rot[0] = 0;
            blk.rot[1] = 0;
            blk.rot[2] = 0;
        }
        else
        {
            blk.rot[0] = ((s16*)obj)[0];
            blk.rot[1] = ((s16*)obj)[1];
            blk.rot[2] = ((s16*)obj)[2];
        }
        blk.scale = lbl_803DEA1C;
        setMatrixFromObjectPos(m, &blk);
        Matrix_TransformPoint(m, v[0], v[1], v[2], &out[0], &out[1], &out[2]);
    }
}

void objRenderModel(int* obj)
{
    int d1;
    f32 d2;
    int d3;
    int d4;
    f32 px;
    f32 py;
    f32 pz;
    int sx;
    int sy;
    int sz;
    u32 col;
    int* model = Obj_GetActiveModel(obj);
    if (lbl_803DEA04 == ((GameObject*)obj)->anim.rootMotionScale)
    {
        curObjMtx = 0;
        return;
    }
    {
        int m0 = *model;
        if (*(u16*)(m0 + 2) & 0x8000)
        {
            modelDoAltRenderInstrs(obj, ((GameObject*)obj)->ownerObj ? ((GameObject*)obj)->ownerObj : obj, (u8*)m0, 0);
        }
        else
        {
            modelDoRenderInstrs(obj, ((GameObject*)obj)->ownerObj ? ((GameObject*)obj)->ownerObj : obj, (u8*)m0, 0);
        }
    }
    {
        u8* iter;
        int i = 0;
        iter = (u8*)obj;
        for (; i < ((GameObject*)obj)->childCount; i++)
        {
            int* child = *(int**)&((GameObject*)iter)->childObjs[0];
            if (child != NULL)
            {
                objRenderChild(child, obj, 0);
            }
            iter += 4;
        }
    }
    if (OBJPRINT_MODEL_DEF(obj)->shadowType != 4)
    {
        return;
    }
    if (lbl_803DCC29 != 0)
    {
        return;
    }
    {
        s16 t = ((GameObject*)obj)->anim.seqId;
        if (t == 0x6a8) return;
        if (t == 0x6a9) return;
        if (t == 0x6aa) return;
        if (t == 0x6ab) return;
        if (t == 0x6ac) return;
        if (t == 0x752) return;
    }
    Camera_ProjectWorldPointWithOffset(
        ((GameObject*)obj)->anim.localPosX - playerMapOffsetX,
        ((GameObject*)obj)->anim.localPosY,
        ((GameObject*)obj)->anim.localPosZ - playerMapOffsetZ,
        ((GameObject*)obj)->anim.hitboxScale * ((GameObject*)obj)->anim.rootMotionScale,
        &px, &py, &pz);
    Camera_NdcToScreen(px, py, pz, &sx, &sy, &sz);
    if (sz <= depthReadRequestPoll(sx, sy, obj))
    {
        ((GameObject*)obj)->anim.modelState->shadowAlphaStep = 0x20;
    }
    else
    {
        ((GameObject*)obj)->anim.modelState->shadowAlphaStep = -0x20;
    }
    {
        int a;
        ObjModelState* hud = ((GameObject*)obj)->anim.modelState;
        a = hud->shadowAlpha + hud->shadowAlphaStep;
        if (a > 0xff)
        {
            hud->shadowAlpha = 0xff;
        }
        else if (a < 0)
        {
            hud->shadowAlpha = 0;
        }
        else
        {
            hud->shadowAlpha = a;
        }
    }
    gObjShadowColor[3] = ((GameObject*)obj)->anim.modelState->shadowAlpha;
    objShadowFn_8006c5f0(obj, &d1, &d2, &d3, &d4);
    col = *(u32*)gObjShadowColor;
    hudDrawColored(d1, d3, d4, &col, (s32)(lbl_803DEA6C * d2), 1);
}

typedef struct
{
    f32 pos[3];
    s16 rot[3];
    s8 joints[6];
} ChildEnt;

void objRenderChild(int* child, int* parent, u8 p3)
{
    f32 res[3];
    struct
    {
        s16 rot[3];
        f32 scale;
        f32 pos[3];
    } blk;
    f32 wm[16];
    f32 m2[16];
    f32 dx, dz;
    int off;
    f32* mtx;
    if (lbl_803DEA04 == ((GameObject*)child)->anim.rootMotionScale)
    {
        curObjMtx = 0;
        return;
    }
    Obj_GetActiveModel(child);
    {
        int* pmodel = Obj_GetActiveModel(parent);
        ChildEnt* ent;
        int j;
        u8* tbl = *(u8**)(*(int*)&((GameObject*)parent)->anim.modelInstance + 0x2c);
        off = (((GameObject*)child)->objectFlags & 7) * 0x18;
        ent = (ChildEnt*)(tbl + off);
        j = ent->joints[OBJPRINT_ACTIVE_BANK_INDEX(parent)];
        blk.pos[0] = *(f32*)(off + (char*)tbl);
        blk.pos[1] = ent->pos[1];
        blk.pos[2] = ent->pos[2];
        if (j == -1)
        {
            Obj_BuildWorldTransformMatrix(parent, wm, 0);
            mtx = wm;
        }
        else
        {
            mtx = (f32*)ObjModel_GetJointMatrix((u8*)pmodel, j);
        }
    }
    if (OBJPRINT_MODEL_DEF(child)->renderFlags & 8)
    {
        int* cam = Camera_GetCurrentViewSlot();
        blk.scale = ((GameObject*)child)->anim.rootMotionScale;
        dx = ((GameObject*)child)->anim.localPosX - ((GameObject*)cam)->anim.localPosX;
        dz = ((GameObject*)child)->anim.localPosZ - ((GameObject*)cam)->anim.localPosZ;
        blk.rot[0] = getAngle(dx, dz) + 0x8000;
        blk.rot[1] = getAngle(((GameObject*)child)->anim.localPosY - ((GameObject*)cam)->anim.localPosY,
                              sqrtf(dx * dx + dz * dz));
        blk.rot[2] = ((s16*)cam)[2];
        setMatrixFromObjectTransposed(&blk, m2);
        res[0] = m2[3];
        res[1] = m2[7];
        res[2] = m2[11];
        PSMTXMultVec(mtx, res, res);
        m2[3] = res[0];
        m2[7] = res[1];
        m2[11] = res[2];
    }
    else
    {
        ChildEnt* pr;
        blk.scale = lbl_803DEA1C;
        pr = (ChildEnt*)(*(u8**)(*(int*)&((GameObject*)parent)->anim.modelInstance + 0x2c) + off);
        blk.rot[0] = pr->rot[0];
        blk.rot[1] = pr->rot[1];
        blk.rot[2] = pr->rot[2];
        setMatrixFromObjectTransposed(&blk, m2);
        PSMTXConcat(mtx, m2, m2);
    }
    if (p3 == 0)
    {
        void* space;
        ((GameObject*)child)->anim.worldPosX = m2[3] + playerMapOffsetX;
        ((GameObject*)child)->anim.worldPosY = m2[7];
        ((GameObject*)child)->anim.worldPosZ = m2[11] + playerMapOffsetZ;
        space = ((GameObject*)child)->anim.parent;
        if (space != NULL)
        {
            Obj_TransformWorldPointToLocal(((GameObject*)child)->anim.worldPosX, ((GameObject*)child)->anim.worldPosY,
                                           ((GameObject*)child)->anim.worldPosZ,
                                           &((GameObject*)child)->anim.localPosX, &((GameObject*)child)->anim.localPosY,
                                           &((GameObject*)child)->anim.localPosZ, (u32)space);
        }
        else
        {
            ((GameObject*)child)->anim.localPosX = ((GameObject*)child)->anim.worldPosX;
            ((GameObject*)child)->anim.localPosY = ((GameObject*)child)->anim.worldPosY;
            ((GameObject*)child)->anim.localPosZ = ((GameObject*)child)->anim.worldPosZ;
        }
        objRotateFn_8003bce8(m2, (s16*)child, (s16*)child + 1, (s16*)child + 2);
    }
    *(u8*)((char*)child + 0x37) = ((((GameObject*)child)->anim.alpha + 1) * *(u8*)((char*)parent + 0x37)) >> 8;
    *(u8*)((char*)child + 0xf1) = *(u8*)((char*)parent + 0xf1);
    if (!(((GameObject*)child)->anim.flags & OBJANIM_FLAG_HIDDEN))
    {
        curObjMtx = (u32)m2;
        if (p3 == 0)
        {
            ((GameObject*)child)->objectFlags |= OBJECT_OBJFLAG_RENDERED;
            objRenderModel(child);
        }
        else
        {
            objRenderShadow(child);
        }
    }
}

extern s32 lbl_803DCC48;
extern char* getCache(void);
extern void cacheQueueWait(int);
extern void GXLoadPosMtxImm(f32* m, int id);
u8 gObjGxPosMtxIdTable[12] = {0x00, 0x03, 0x06, 0x09, 0x0C, 0x0F, 0x12, 0x15, 0x18, 0x1B, 0x00, 0x00};

/*
 * Bit-cursor over the model's render-instruction stream
 * (ModelFileHeader.instrs, bit length at header +0xD8 * 8).  Every reader
 * fetches 3 bytes little-endian around the cursor and shifts by (pos & 7).
 * Stream grammar (4-bit opcodes):
 *   1 = bind render op: 6-bit renderOps index (shader state setup)
 *   2 = draw: 8-bit display-list index -> GXCallDisplayList
 *   3 = vertex descriptor block: 1-bit pos/nrm/clr/tex size selectors
 *   4 = load matrices: 4-bit count, then 8-bit joint-matrix indices
 *   5 = end of stream
 * The stream is walked through a MtxBitStream (data at +0, cursor at +0x10).
 */
typedef struct
{
    u8* data;
    int pad[3];
    int pos;
} MtxBitStream;

#pragma optimization_level 2
#pragma inline_max_size(4000)
#pragma dont_inline on
void modelLoadMtxsToGx(int obj, int* model, MtxBitStream* bs, f32* mtx)
{
    char* cache = getCache();
    if (lbl_803DCC48 == 1)
    {
        char* c2 = getCache();
        int i;
        char* dst;
        char* src;
        obj = *(u8*)(obj + 0xf3) + *(u8*)(obj + 0xf4);
        src = c2 + 0x2700;
        dst = c2;
        cacheQueueWait(0);
        for (i = 0; i < obj; i++)
        {
            PSMTXConcat(mtx, (f32*)src, (f32*)dst);
            src += 0x40;
            dst += 0x30;
        }
        lbl_803DCC48 = 2;
    }
    {
        u8* tbl;
        int i;
        int count;
        f32 tmp[12];
        {
            int pos = bs->pos;
            u32 w;
            int off = pos >> 3;
            u8* p;
            w = bs->data[off];
            p = (u8*)(off + (char*)bs->data);
            w |= p[1] << 8;
            w |= p[2] << 16;
            bs->pos = pos + 4;
            count = (w >> (pos & 7)) & 0xf;
        }
        i = 0;
        tbl = gObjGxPosMtxIdTable;
        for (; i < count; i++)
        {
            int idx;
            {
                int off;
                u8* p;
                int pos = bs->pos;
                u32 w;
                off = pos >> 3;
                p = (u8*)(off + bs->data);
                w = p[0];
                w |= p[1] << 8;
                w |= p[2] << 16;
                bs->pos = pos + 8;
                idx = (w >> (pos & 7)) & 0xff;
            }
            if (lbl_803DCC48 == 2)
            {
                GXLoadPosMtxImm((f32*)(cache + idx * 0x30), *tbl);
            }
            else
            {
                PSMTXConcat(mtx, (f32*)ObjModel_GetJointMatrix((u8*)model, idx), tmp);
                GXLoadPosMtxImm(tmp, *tbl);
            }
            tbl++;
        }
    }
}
#pragma dont_inline reset
#pragma inline_max_size reset
#pragma optimization_level reset
extern void GXClearVtxDesc(void);
extern void GXSetVtxDesc(int attr, int type);
extern void GXSetCurrentMtx(u32 id);
extern void GXSetAlphaCompare(int comp0, int ref0, int op, int comp1, int ref1);
extern void GXSetCullMode(int mode);

#pragma dont_inline on
void ModelHeader_setupPosTexFmt(u8* hdr, int* model, MtxBitStream* bs, int p4)
{
    u32 flags = 0;
    if (hdr[0xf3] > 1)
    {
        flags |= 1;
    }
    {
        u32 w;
        int pos = bs->pos;
        int off = pos >> 3;
        u8* p;
        w = bs->data[off];
        p = (u8*)(off + (char*)bs->data);
        w |= p[1] << 8;
        w |= p[2] << 16;
        bs->pos = pos + 1;
        flags |= ((int)(w >> (pos & 7)) & 1) ? 2 : 0;
    }
    {
        u32 w;
        int pos = bs->pos;
        int off = pos >> 3;
        u8* p;
        w = bs->data[off];
        p = (u8*)(off + (char*)bs->data);
        w |= p[1] << 8;
        w |= p[2] << 16;
        bs->pos = pos + 1;
        flags |= ((int)(w >> (pos & 7)) & 1) ? 4 : 0;
    }
    if (gObjGxVtxDescCache != flags)
    {
        GXClearVtxDesc();
        if (flags & 1)
        {
            GXSetVtxDesc(GX_VA_PNMTXIDX, GX_DIRECT);
        }
        else
        {
            GXSetCurrentMtx(gObjGxPosMtxIdTable[0]);
        }
        GXSetVtxDesc(GX_VA_POS, (flags & 2) ? 3 : 2);
        GXSetVtxDesc(GX_VA_TEX0, (flags & 4) ? 3 : 2);
        gObjGxVtxDescCache = flags;
    }
}
#pragma dont_inline reset

#pragma scheduling off
#pragma opt_common_subs off
void shaderSetGxFlags(u8* obj, u8* m, u8* shader)
{
    u8 blend;
    u8 zwrite;
    u8 zcmp;
    u8 zcomploc;
    u32 alpha;
    u8 cull;
    u32 sf;
    if (obj[0x37] < 0xff || ((sf = *(u32*)(shader + 0x3c)) & 0x40000000))
    {
        blend = 1;
        if (((ModelFileHeader*)m)->flags & 0x400)
        {
            zwrite = 0;
            zcmp = 0;
            zcomploc = 1;
            alpha = 0;
        }
        else if (((ModelFileHeader*)m)->flags & 0x2000)
        {
            zwrite = 1;
            zcmp = 1;
            zcomploc = 0;
            alpha = 0xdf;
        }
        else
        {
            zwrite = 1;
            zcmp = 0;
            zcomploc = 1;
            alpha = 0;
        }
    }
    else if (sf & 0x400)
    {
        blend = 0;
        if (((ModelFileHeader*)m)->flags & 0x400)
        {
            zwrite = 0;
            zcmp = 0;
        }
        else
        {
            zwrite = 1;
            zcmp = 1;
        }
        zcomploc = 0;
        alpha = 0x40;
    }
    else
    {
        blend = 0;
        if (((ModelFileHeader*)m)->flags & 0x400)
        {
            zwrite = 0;
            zcmp = 0;
        }
        else
        {
            zwrite = 1;
            zcmp = 1;
        }
        zcomploc = 1;
        alpha = 0;
    }
    if (*(u32*)(shader + 0x3c) & 8)
    {
        cull = 1;
    }
    else
    {
        cull = 0;
    }
    if (gObjGxBlendModeCache != blend)
    {
        if (blend != 0)
        {
            GXSetBlendMode(GX_BM_BLEND, GX_BL_SRCALPHA, GX_BL_INVSRCALPHA, GX_LO_NOOP);
        }
        else
        {
            GXSetBlendMode(GX_BM_NONE, GX_BL_ONE, GX_BL_ZERO, GX_LO_NOOP);
        }
        gObjGxBlendModeCache = blend;
    }
    if (gObjGxZWriteCache != zwrite || gObjGxZCompareCache != zcmp)
    {
        gxSetZMode_(zwrite, 3, zcmp);
        gObjGxZWriteCache = zwrite;
        gObjGxZCompareCache = zcmp;
    }
    if (gObjGxZCompLocCache != zcomploc)
    {
        gxSetPeControl_ZCompLoc_(zcomploc);
        gObjGxZCompLocCache = zcomploc;
    }
    if (gObjGxAlphaCompareCache != alpha)
    {
        gObjGxAlphaCompareCache = alpha;
        if (alpha != 0)
        {
            GXSetAlphaCompare(GX_GREATER, (u8)alpha, GX_AOP_AND, GX_GREATER, (u8)alpha);
        }
        else
        {
            GXSetAlphaCompare(GX_ALWAYS, 0, GX_AOP_AND, GX_ALWAYS, 0);
        }
    }
    if (cull != gObjGxCullModeCache)
    {
        gObjGxCullModeCache = cull;
        if (cull != 0)
        {
            GXSetCullMode(GX_CULL_BACK);
        }
        else
        {
            GXSetCullMode(GX_CULL_NONE);
        }
    }
}
#pragma opt_common_subs reset
#pragma scheduling reset

extern void modelMtxFn_8003be38(u8* hdr, int* model, f32* mtx, f32* m1);
extern void GXLoadTexMtxImm(f32* m, int id, int type);
extern void GXLoadNrmMtxImm(f32* m, int id);
extern void OSReport(const char* msg, ...);

#pragma optimization_level 2
void renderOpMatrix(u8* hdr, int* model, MtxBitStream* bs, f32* m1, f32* mtx, u8 nrm, u8 tex, u8 skip)
{
    u8* tbl = gObjGxPosMtxIdTable;
    char* cache = getCache();
    if (lbl_803DCC48 == 1)
    {
        if (skip == 0)
        {
            modelMtxFn_8003be38(hdr, model, mtx, m1);
        }
        else
        {
            char* c2 = getCache();
            char* dst;
            int i;
            int total = hdr[0xf3] + hdr[0xf4];
            hdr = (u8*)(c2 + 0x2700);
            dst = c2;
            cacheQueueWait(0);
            for (i = 0; i < total; i++)
            {
                PSMTXConcat(mtx, (f32*)hdr, (f32*)dst);
                hdr += 0x40;
                dst += 0x30;
            }
            lbl_803DCC48 = 2;
        }
    }
    {
        u8* tbl2;
        int i;
        int count;
        f32 tmp[12];
        {
            u32 w;
            int pos = bs->pos;
            int off = pos >> 3;
            u8* p;
            w = bs->data[off];
            p = (u8*)(off + (char*)bs->data);
            w |= p[1] << 8;
            w |= p[2] << 16;
            bs->pos = pos + 4;
            count = (w >> (pos & 7)) & 0xf;
        }
        if (count < 0 || count > 20)
        {
            OSReport((char*)&tbl[0x48], count);
        }
        i = 0;
        tbl2 = tbl + 0xc;
        for (; i < count; i++)
        {
            int idx;
            {
                u32 w;
                int pos = bs->pos;
                int off = pos >> 3;
                u8* p = (u8*)(off + bs->data);
                w = p[0];
                w |= p[1] << 8;
                w |= p[2] << 16;
                bs->pos = pos + 8;
                idx = (w >> (pos & 7)) & 0xff;
            }
            if (lbl_803DCC48 == 2)
            {
                u8* pm = (u8*)(cache + idx * 0x30);
                u8* nm = pm + 0x12c0;
                GXLoadPosMtxImm((f32*)pm, *tbl);
                if (skip == 0 && tex != 0)
                {
                    GXLoadTexMtxImm((f32*)nm, *tbl2, 0);
                }
                if (skip == 0 && nrm != 0)
                {
                    GXLoadNrmMtxImm((f32*)nm, *tbl);
                }
            }
            else
            {
                PSMTXConcat(mtx, (f32*)ObjModel_GetJointMatrix((u8*)model, idx), tmp);
                GXLoadPosMtxImm(tmp, *tbl);
                if (skip == 0 && (nrm != 0 || tex != 0))
                {
                    tmp[3] = lbl_803DEA04;
                    tmp[7] = lbl_803DEA04;
                    tmp[11] = lbl_803DEA04;
                    PSMTXConcat(tmp, m1, tmp);
                    if (tex != 0)
                    {
                        GXLoadTexMtxImm(tmp, *tbl2, 0);
                    }
                    if (nrm != 0)
                    {
                        GXLoadNrmMtxImm(tmp, *tbl);
                    }
                }
            }
            tbl++;
            tbl2++;
        }
    }
}
#pragma optimization_level reset

typedef union
{
    u8 u8;
    u16 u16;
    u32 u32;
    s16 s16;
    s32 s32;
    f32 f32;
} ObjWGPipe;

extern ObjWGPipe GXWGFifo : (0xCC008000);
extern void PSMTXScale(f32* m, f32 x, f32 y, f32 z);
extern void gxTextureFn_80072dfc(u8* obj, int* p2, int p3);
extern void GXBegin(int prim, int fmt, u16 count);

#pragma opt_propagation off
void objRenderFn_8003d980(u8* obj, int* p2)
{
    f32 wm[16];
    f32 cm[16];
    f32 sm[12];
    struct
    {
        s16 rot[3];
        f32 scale;
        f32 pos[3];
    } blk;
    int* mdl = p2;
    u8* data = (u8*)mdl[22];
    f32* vm = Camera_GetViewMatrix();
    s16* uvs;
    s16* verts;
    int i;
    int off;
    Obj_BuildWorldTransformMatrix((int*)obj, wm, 0);
    PSMTXConcat(vm, wm, cm);
    GXLoadPosMtxImm(cm, gObjGxPosMtxIdTable[0]);
    GXSetCurrentMtx(gObjGxPosMtxIdTable[0]);
    PSMTXScale(sm, lbl_803DEA1C / ((GameObject*)obj)->anim.rootMotionScale,
               lbl_803DEA1C / ((GameObject*)obj)->anim.rootMotionScale, lbl_803DEA1C);
    cm[3] = lbl_803DEA04;
    cm[7] = lbl_803DEA04;
    cm[11] = lbl_803DEA04;
    PSMTXConcat(cm, sm, cm);
    GXLoadTexMtxImm(cm, 0x1e, 0);
    gxTextureFn_80072dfc(obj, mdl, 0);
    GXClearVtxDesc();
    GXSetVtxDesc(GX_VA_POS, GX_DIRECT);
    GXSetVtxDesc(GX_VA_NRM, GX_DIRECT);
    GXSetVtxDesc(GX_VA_TEX0, GX_DIRECT);
    verts = *(s16**)(data + 4);
    uvs = *(s16**)(data + 8);
    GXBegin(GX_TRIANGLES, GX_VTXFMT7, *(u16*)(data + 0xc) * 3);
    {
        i = 0;
        off = 0;
        for (; i < *(u16*)(data + 0xc); i++)
        {
            u8* tri = *(u8**)data + off;
            u16* idx = (u16*)tri;
            int k;
            for (k = 0; k < 3; k++)
            {
                s16* v = verts + *idx * 3;
                s16 c = v[2];
                s16 b = v[1];
                s16 a = v[0];
                GXWGFifo.s16 = a;
                GXWGFifo.s16 = b;
                GXWGFifo.s16 = c;
                {
                    u8 c2 = tri[8];
                    u8 b2 = tri[7];
                    u8 a2 = tri[6];
                    GXWGFifo.u8 = a2;
                    GXWGFifo.u8 = b2;
                    GXWGFifo.u8 = c2;
                }
                {
                    s16* uv = uvs + *idx * 2;
                    s16 u1 = uv[1];
                    s16 u0 = uv[0];
                    GXWGFifo.s16 = u0;
                    GXWGFifo.s16 = u1;
                }
                idx++;
            }
            off += 0xa;
        }
    }
    GXSetCurrentMtx(0);
    if (randomGetRange(0, 5) == 0)
    {
        int r = randomGetRange(0, *(s16*)(data + 0xe) - 1);
        f32 fs = ((GameObject*)obj)->anim.rootMotionScale;
        int m = r * 3;
        int j = m << 1;
        s16* pv;
        blk.pos[0] = fs * (f32)(verts[m] >> 8) + ((GameObject*)obj)->anim.localPosX;
        pv = (s16*)((char*)verts + j);
        blk.pos[1] = fs * (f32)(pv[1] >> 8) + ((GameObject*)obj)->anim.localPosY;
        blk.pos[2] = fs * (f32)(pv[2] >> 8) + ((GameObject*)obj)->anim.localPosZ;
        blk.scale = lbl_803DEA1C;
        blk.rot[0] = 0;
        blk.rot[2] = 0;
        blk.rot[1] = 0;
        (*gPartfxInterface)->spawnObject(obj, 0x7fd, &blk, 0x200001, -1, NULL);
    }
}
#pragma opt_propagation reset

extern s32 lbl_803DCC5C;
extern int lbl_803DCC64;
extern void modelLightStruct_getProjectionTevModes(int p1, int* a, int* b);

typedef struct
{
    u8 r, g, b, a;
} ObjGXColor;

extern void modelTextureFn_80089970(int slot);
extern void textureColorFn_8008991c(int idx, u8* r, u8* g, u8* b);
extern void modelLightStruct_selectObjectLights(u8* model, int* arr, u32 n, s32* cnt, int mode);
extern void modelLightStruct_loadChannelLight(u8 chan, int light, u8* model);
extern int modelLightStruct_getProjectedLightChannelPreference(int light);
extern void GXSetChanAmbColor(u8 chan, ObjGXColor c);
extern void GXSetChanMatColor(u8 chan, ObjGXColor c);
extern void GXSetChanCtrl(int chan, int enable, int amb, int mat, int mask, int diff, int attn);
extern void GXSetNumChans(u8 nChans);
extern u32 lbl_803DB468;
extern u32 gObjGxDefaultChanColor;
extern u32 lbl_803DB470;
extern u32 gObjCurChanColor;
extern u8 gObjShadowNear;
extern u8 lbl_803DCC60;

void objFn_8003dc50(u8* obj, u8* model)
{
    int t2;
    int t10;
    int en2;
    int chan;
    u8 ch;
    u16 f;
    u8 b;
    int larr[6];
    s32 count;
    ObjGXColor c;

    count = 0;
    lbl_803DCC5C = 0;
    b = obj[0x24];
    t2 = b & 2;
    if (t2)
    {
        en2 = 1;
    }
    else
    {
        en2 = 0;
    }
    t10 = b & 0x10;
    chan = t10 ? 4 : 0;
    if (*(u16*)(obj + 0xe2) & 2)
    {
        if (t2 || t10)
        {
            ((u8*)&gObjCurChanColor)[3] = 0;
            GXSetChanAmbColor(chan, *(ObjGXColor*)&gObjCurChanColor);
            GXSetChanCtrl(GX_COLOR0, GX_TRUE, GX_SRC_REG, GX_SRC_VTX, 0, GX_DF_NONE, GX_AF_NONE);
            GXSetChanCtrl(GX_ALPHA0, GX_FALSE, GX_SRC_REG, GX_SRC_VTX, 0, GX_DF_NONE, GX_AF_NONE);
            GXSetNumChans(1);
        }
        else
        {
            GXSetChanCtrl(GX_COLOR0A0, GX_FALSE, GX_SRC_REG, GX_SRC_REG, 0, GX_DF_NONE, GX_AF_NONE);
            GXSetChanCtrl(GX_COLOR1A1, GX_FALSE, GX_SRC_REG, GX_SRC_REG, 0, GX_DF_NONE, GX_AF_NONE);
            GXSetNumChans(0);
        }
    }
    else
    {
        modelLightChannels_reset(0);
        ch = chan;
        modelLightChannel_configure(ch, 0, en2);
        f = *(u16*)(obj + 0xe2);
        if (!(f & 9))
        {
            int mode;
            if (f & 0xc)
            {
                mode = 2;
                GXSetChanAmbColor(ch, *(ObjGXColor*)&gObjGxDefaultChanColor);
            }
            else
            {
                int l;
                mode = 6;
                l = (*(u8**)(model + 0x50))[0x8d];
                if (l == 0)
                {
                    modelTextureFn_80089970(model[0xf2]);
                    textureColorFn_8008991c(model[0xf2], &c.r, &c.g, &c.b);
                }
                else
                {
                    lightGetColor(l, &c.r, &c.g, &c.b);
                }
                c.a = 0;
                GXSetChanAmbColor(ch, c);
            }
            {
                u32 nl = (*(u8**)(model + 0x50))[0x8c];
                if (nl != 0)
                {
                    modelLightStruct_selectObjectLights(model, larr, nl, &count, mode);
                }
            }
            if (count == 0)
            {
                GXSetChanMatColor(ch, *(ObjGXColor*)&gObjGxDefaultChanColor);
            }
            else
            {
                GXSetChanMatColor(ch, *(ObjGXColor*)&lbl_803DB468);
            }
            {
                int* p;
                int i;
                i = 0;
                p = larr;
                for (; i < count; i++)
                {
                    modelLightStruct_loadChannelLight(ch, *p, model);
                    p++;
                }
            }
        }
        else
        {
            if (f & 1)
            {
                GXSetChanMatColor(ch, *(ObjGXColor*)&lbl_803DB468);
            }
            else
            {
                GXSetChanMatColor(ch, *(ObjGXColor*)&gObjGxDefaultChanColor);
            }
        }
        {
            u32 nf = obj[0xfa];
            if (nf != 0)
            {
                modelLightStruct_selectObjectLights(model, &lbl_803DCC64, nf, &lbl_803DCC5C, 8);
                if ((OBJPRINT_MODEL_DEF(model)->renderFlags & OBJDEF_RENDERFLAG_PROJECTED_SHADOW) || gObjShadowNear)
                {
                    lbl_803DCC5C = 0;
                }
                {
                    u8 got;
                    int* lp;
                    u8* sp;
                    int k;
                    got = 0;
                    k = 0;
                    lp = &lbl_803DCC64;
                    sp = &lbl_803DCC60;
                    for (; k < lbl_803DCC5C; k++)
                    {
                        int t = modelLightStruct_getProjectedLightChannelPreference(*lp);
                        if (!got && t == 1)
                        {
                            *sp = 1;
                            got = 1;
                        }
                        else if (k == 0)
                        {
                            *sp = 2;
                        }
                        else
                        {
                            *sp = 3;
                        }
                        modelLightChannel_configure(*sp, 2, 0);
                        modelLightStruct_loadChannelLight(*sp, *lp, model);
                        GXSetChanAmbColor(*sp, *(ObjGXColor*)&lbl_803DB470);
                        GXSetChanMatColor(*sp, *(ObjGXColor*)&lbl_803DB468);
                        lp++;
                        sp++;
                    }
                }
            }
        }
        modelLightChannels_applyGXControls();
        {
            u8 b5f = OBJPRINT_MODEL_DEF(model)->renderFlags;
            if ((b5f & 4) || gObjShadowNear)
            {
                lbl_803DCC5C = 2;
            }
            else if (b5f & 0x11)
            {
                lbl_803DCC5C = 1;
            }
        }
    }
}

void modelRenderFn_setVtxDescr(u8* hdr, u8* m, u32* p3, MtxBitStream* bs, u8 p5, u8* out1, u8* out2)
{
    int next;
    int back;
    GXClearVtxDesc();
    if (hdr[0xf3] > 1)
    {
        GXSetVtxDesc(GX_VA_PNMTXIDX, GX_DIRECT);
        next = 1;
        back = 8;
        if (p3[0] != 0 || p3[1] != 0)
        {
            if (*(u32*)&((ModelFileHeader*)m)->unk34 != 0)
            {
                GXSetVtxDesc(GX_VA_TEX0MTXIDX, GX_DIRECT);
                next = 3;
                GXSetVtxDesc(GX_VA_TEX1MTXIDX, GX_DIRECT);
            }
            GXSetVtxDesc(next++, 1);
        }
        {
            u32 t;
            int i = 0;
            t = p5;
            for (; i < hdr[0xfa]; i++)
            {
                u8 use;
                if (t == 4 && i == 0)
                {
                    int b;
                    int a;
                    if (lbl_803DCC5C != 0)
                    {
                        modelLightStruct_getProjectionTevModes(lbl_803DCC64, &a, &b);
                        if (a == 0)
                        {
                            use = 1;
                        }
                        else
                        {
                            goto useZero;
                        }
                    }
                    else
                    {
                    useZero:
                        use = 0;
                    }
                }
                else if (i < lbl_803DCC5C && p5 == 0)
                {
                    use = 1;
                }
                else
                {
                    use = 0;
                }
                if (use)
                {
                    GXSetVtxDesc(next++, 1);
                }
                else
                {
                    GXSetVtxDesc(back--, 1);
                }
            }
        }
        if (next > 1)
        {
            *out2 = 1;
        }
        else
        {
            *out2 = 0;
        }
    }
    else
    {
        GXSetCurrentMtx(0);
        *out2 = 1;
    }
    {
        u32 w;
        int pos = bs->pos;
        int off = pos >> 3;
        u8* p;
        w = bs->data[off];
        p = (u8*)(off + (char*)bs->data);
        w |= p[1] << 8;
        w |= p[2] << 16;
        bs->pos = pos + 1;
        GXSetVtxDesc(GX_VA_POS, (((int)(w >> (pos & 7)) & 1) ? 3 : 2));
    }
    if (m[0x40] & 1)
    {
        int b;
        {
            u32 w;
            int pos = bs->pos;
            int off = pos >> 3;
            u8* p;
            w = bs->data[off];
            p = (u8*)(off + (char*)bs->data);
            w |= p[1] << 8;
            w |= p[2] << 16;
            bs->pos = pos + 1;
            b = (w >> (pos & 7)) & 1;
        }
        if (hdr[0x24] & 8)
        {
            GXSetVtxDesc(0x19, b ? 3 : 2);
        }
        else
        {
            GXSetVtxDesc(GX_VA_NRM, b ? 3 : 2);
        }
        *out1 = 1;
    }
    else
    {
        *out1 = 0;
    }
    if (m[0x40] & 2)
    {
        u32 w;
        int pos = bs->pos;
        int off = pos >> 3;
        u8* p;
        w = bs->data[off];
        p = (u8*)(off + (char*)bs->data);
        w |= p[1] << 8;
        w |= p[2] << 16;
        bs->pos = pos + 1;
        GXSetVtxDesc(GX_VA_CLR0, (((int)(w >> (pos & 7)) & 1) ? 3 : 2));
    }
    {
        int b;
        int i;
        {
            u32 w;
            int pos = bs->pos;
            int off = pos >> 3;
            u8* p;
            w = bs->data[off];
            p = (u8*)(off + (char*)bs->data);
            w |= p[1] << 8;
            w |= p[2] << 16;
            bs->pos = pos + 1;
            b = (w >> (pos & 7)) & 1;
        }
        i = 0;
        for (; i < m[0x41]; i++)
        {
            GXSetVtxDesc(i + 0xd, b ? 3 : 2);
        }
    }
}

extern void PSMTXCopy(f32 * src, f32 * dst);
extern f32 gObjJointMtxTemp[];
extern void ObjModel_UpdateAnimMatrices(int* am, u8* m, int* obj, f32* mtx);
extern void modelInitMtxs(u8* m, int* am);
extern void ObjModel_ToggleMatrixBuffer(int* am);
extern void modelRenderInstrsState_init(MtxBitStream* bs, u8* data, int len, int len2);
extern void objGetColor(int slot, u8* red, u8* green, u8* blue);
typedef u8 (*ObjModelRenderCb)(int* obj, int* am, int p3);
extern ObjModelRenderCb ObjModel_GetRenderCallback(int* am);
extern void Camera_RebuildProjectionMatrix(void);
extern void _gxSetFogParams(void);
extern void gxFn_80051fb8(void* tex, int p2, int p3, u8* color, int p5, int p6);
extern u8 isHeavyFogEnabled(void);
extern void getColor803dd01c(f32 * c);
extern void renderHeavyFog(f32 * c);
extern void selectTexture(u8* tex, int mapId);
extern void GXSetTevKColor(int id, u32* color);
extern void GXSetArray(int attr, int ptr, int stride);
extern u8* modelFileGetDisplayList(u8* m, int idx);

void modelDoAltRenderInstrs(int* obj, int* obj2, u8* m, int p4)
{
    f32 wm[16];
    f32 cm[12];
    MtxBitStream bs;
    u8 color[4];
    ObjModelRenderCb cb;
    int* am = Obj_GetActiveModel(obj);
    if (curObjMtx != 0)
    {
        PSMTXCopy((f32*)curObjMtx, wm);
        curObjMtx = 0;
    }
    else
    {
        Obj_BuildWorldTransformMatrix(obj, wm, 0);
    }
    PSMTXConcat(Camera_GetViewMatrix(), wm, cm);
    if (!(*(u16*)((char*)am + 0x18) & 8))
    {
        ((ObjDef*)am)->hitboxStateIndex = 0;
        if (((ModelFileHeader*)m)->animationCount != 0 && !(((ModelFileHeader*)m)->flags & 2) && ((ModelFileHeader*)m)->
            jointCount != 0)
        {
            if (gObjCachedModel != (u32)m)
            {
                ObjModel_UpdateAnimMatrices(am, m, obj, gObjJointMtxTemp);
                modelInitMtxs(m, am);
            }
            else
            {
                lbl_803DCC48 = 1;
            }
        }
        else
        {
            ObjModel_ToggleMatrixBuffer(am);
            PSMTXCopy(gObjJointMtxTemp, (f32*)ObjModel_GetJointMatrix((u8*)am, 0));
            lbl_803DCC48 = 3;
        }
        {
            u8* att = *(u8**)&((GameObject*)obj)->anim.hitReactState;
            if (att != NULL)
            {
                att[0xaf]--;
                if (*(s8*)(*(char**)&((GameObject*)obj)->anim.hitReactState + 0xaf) < 0)
                {
                    *(u8*)(*(char**)&((GameObject*)obj)->anim.hitReactState + 0xaf) = 0;
                }
            }
        }
        *(u16*)((char*)am + 0x18) |= 8;
    }
    modelRenderInstrsState_init(&bs, ((ModelFileHeader*)m)->instrs, *(u16*)(m + 0xd8) << 3, *(u16*)(m + 0xd8) << 3);
    if (((ModelFileHeader*)m)->shaderFlags & 2)
    {
        if (gObjOverrideColorPending != 0)
        {
            color[0] = gObjOverrideColor;
            color[1] = (&gObjOverrideColor)[1];
            color[2] = (&gObjOverrideColor)[2];
            gObjOverrideColorPending = 0;
        }
        else
        {
            objGetColor(*(u8*)((char*)obj + 0xf2), &color[0], &color[1], &color[2]);
        }
    }
    else
    {
        color[2] = 0xff;
        color[1] = 0xff;
        color[0] = 0xff;
    }
    color[3] = *(u8*)((char*)obj + 0x37);
    cb = ObjModel_GetRenderCallback(am);
    if (gObjRenderSetupDone == 0 || cb != NULL)
    {
        Camera_RebuildProjectionMatrix();
        if (cb == NULL || cb(obj, am, 0) == 0)
        {
            _gxSetFogParams();
            resetLotsOfRenderVars();
            gxFn_80051fb8(textureIdxToPtr(*(int*)(*(int*)&((ModelFileHeader*)m)->renderOps + 0x24)), 0, 0, color, 0, 0);
            if (isHeavyFogEnabled() != 0)
            {
                f32 c;
                getColor803dd01c(&c);
                renderHeavyFog(&c);
            }
            textureFn_800528bc();
            GXSetChanCtrl(GX_COLOR0A0, GX_FALSE, GX_SRC_REG, GX_SRC_REG, 0, GX_DF_NONE, GX_AF_NONE);
            GXSetChanCtrl(GX_COLOR1A1, GX_FALSE, GX_SRC_REG, GX_SRC_REG, 0, GX_DF_NONE, GX_AF_NONE);
            GXSetNumChans(0);
            gObjRenderSetupDone = 1;
            *(u32*)gObjGxKColorCache = *(u32*)color;
        }
    }
    else
    {
        void* tex = textureIdxToPtr(*(int*)(*(int*)&((ModelFileHeader*)m)->renderOps + 0x24));
        if (gObjCachedTexture != (u32)tex)
        {
            gObjCachedTexture = (u32)tex;
            selectTexture(tex, 0);
        }
        if (gObjGxKColorCache[0] != color[0] || gObjGxKColorCache[1] != color[1]
            || gObjGxKColorCache[2] != color[2] || gObjGxKColorCache[3] != color[3])
        {
            u32 kcol = *(u32*)color;
            GXSetTevKColor(GX_KCOLOR0, &kcol);
            *(u32*)gObjGxKColorCache = *(u32*)color;
        }
    }
    if (gObjCachedModel != (u32)m)
    {
        GXSetArray(GX_VA_POS, ((int*)((char*)am + 0x1c))[(*(u16*)((char*)am + 0x18) >> 1) & 1], 6);
        GXSetArray(GX_VA_TEX0, *(int*)&((ModelFileHeader*)m)->unk34, 4);
        gObjCachedModel = (u32)m;
    }
    shaderSetGxFlags((u8*)obj, m, ((ModelFileHeader*)m)->renderOps);
    bs.pos += 4;
    ModelHeader_setupPosTexFmt(m, (void*)((ModelFileHeader*)m)->renderOps, &bs, p4);
    bs.pos += 4;
    modelLoadMtxsToGx((int)m, am, &bs, cm);
    {
        u8* dl;
        int idx;
        {
            u32 w;
            int pos = (bs.pos += 4);
            int off = pos >> 3;
            u8* p;
            w = bs.data[off];
            p = (u8*)(off + (char*)bs.data);
            w |= p[1] << 8;
            w |= p[2] << 16;
            bs.pos = pos + 8;
            idx = (w >> (pos & 7)) & 0xff;
        }
        dl = modelFileGetDisplayList(m, idx);
        GXCallDisplayList(*(void**)dl, *(u16*)(dl + 4));
    }
}

extern void ObjModel_ToggleVertexBuffer(int* am);
extern void PSMTXIdentity(f32 * m);
extern void modelInitBoneMtxs2(int* am, f32* wm, f32* out);
f32 gObjBoneMtxBuffer[0xC00];
extern void ObjModel_ApplyBlendChannels(int* am);
extern void ObjModel_BlendPrimaryVertexStream(f32* mtxs, u8* p2, int p3, int p4, int p5);
extern void ObjModel_BlendSecondaryVertexStream(f32* mtxs, u8* p2, int p3, int p4, int p5);
extern void objUpdateHitSpheres(int* am, u8* m, int* obj, int p4, int* p5);
extern void GXSetNumTexGens(u8 nTexGens);
extern void GXSetNumTevStages(u8 nStages);
extern void GXSetNumIndStages(u8 nIndStages);
extern void GXSetTevOrder(int stage, int coord, int map, int color);
extern void GXSetTevDirect(int stage);
extern void GXSetTevColorIn(int stage, int a, int b, int c, int d);
extern void GXSetTevAlphaIn(int stage, int a, int b, int c, int d);
extern void GXSetTevSwapMode(int stage, int ras, int tex);
extern void GXSetTevColorOp(int stage, int op, int bias, int scale, int clamp, int out);
extern void GXSetTevAlphaOp(int stage, int op, int bias, int scale, int clamp, int out);
extern void GXSetFog(int type, f32 a, f32 b, f32 c, f32 d, ObjGXColor color);
typedef void (*ObjShadowCb)(int* obj, int* am, f32* wm);
extern int* ObjModel_GetRenderOp(u8* am0, int idx);
extern void GXSetTevColor(int id, u32* color);

void objRenderShadow2(int* obj, int* obj2, u8* m, int p4)
{
    f32 cm[16];
    f32 wm[16];
    f32 im[16];
    MtxBitStream bs;
    u8 color[4];
    u32 tev1;
    u32 tev2;
    int* am;
    f32* vm;
    u8 did;
    int* op;
    int done;
    u32 sh;

    am = Obj_GetActiveModel(obj);
    vm = Camera_GetViewMatrix();
    if (curObjMtx != 0)
    {
        PSMTXCopy((f32*)curObjMtx, wm);
        curObjMtx = 0;
    }
    else
    {
        Obj_BuildWorldTransformMatrix(obj, wm, 0);
    }
    if (!(*(u16*)((char*)am + 0x18) & 8))
    {
        did = 0;
        *(u8*)((char*)am + 0x60) = 0;
        ObjModel_ToggleVertexBuffer(am);
        if (((ModelFileHeader*)m)->animationCount != 0 && !(((ModelFileHeader*)m)->flags & 2) && ((ModelFileHeader*)m)->
            jointCount != 0)
        {
            if (*(u32*)&((ModelFileHeader*)m)->vertexAnimEntries != 0)
            {
                PSMTXIdentity(im);
                ObjModel_UpdateAnimMatrices(am, m, obj, im);
                modelInitBoneMtxs2(am, wm, gObjBoneMtxBuffer);
                did = 1;
            }
            else
            {
                ObjModel_UpdateAnimMatrices(am, m, obj, wm);
            }
            {
                ObjShadowCb cb = *(ObjShadowCb*)((char*)obj + 0x108);
                if (cb != NULL && obj2 == obj)
                {
                    cb(obj, am, wm);
                }
            }
        }
        else
        {
            ObjModel_ToggleMatrixBuffer(am);
            PSMTXCopy(wm, (f32*)ObjModel_GetJointMatrix((u8*)am, 0));
        }
        if (((ModelFileHeader*)m)->morphTargetCount != 0)
        {
            ObjModel_ApplyBlendChannels(am);
        }
        if (did != 0)
        {
            int vtx;
            if (*(u8*)((char*)am + 0x60) != 0)
            {
                vtx = ((int*)((char*)am + 0x1c))[(*(u16*)((char*)am + 0x18) >> 1) & 1];
            }
            else
            {
                vtx = *(int*)&((ModelFileHeader*)m)->vertices;
            }
            ObjModel_BlendPrimaryVertexStream(gObjBoneMtxBuffer, m + 0x88, vtx, *(int*)&((ModelFileHeader*)am)->unk40,
                                              ((int*)((char*)am + 0x1c))[(*(u16*)((char*)am + 0x18) >> 1) & 1]);
            ObjModel_BlendSecondaryVertexStream(gObjBoneMtxBuffer, m + 0xac, *(int*)&((ModelFileHeader*)m)->normals,
                                                *(int*)((char*)am + 0x44), ((ModelFileHeader*)m)->flags24 & 8);
        }
        if (((ModelFileHeader*)m)->unkF7 != 0)
        {
            objUpdateHitSpheres(am, m, obj, 0, obj2);
        }
        else
        {
            u8* att = *(u8**)&((GameObject*)obj)->anim.hitReactState;
            if (att != NULL)
            {
                att[0xaf]--;
                if (*(s8*)(*(char**)&((GameObject*)obj)->anim.hitReactState + 0xaf) < 0)
                {
                    *(u8*)(*(char**)&((GameObject*)obj)->anim.hitReactState + 0xaf) = 0;
                }
            }
        }
        *(u16*)((char*)am + 0x18) |= 8;
    }
    modelInitMtxs(m, am);
    modelRenderInstrsState_init(&bs, ((ModelFileHeader*)m)->instrs, *(u16*)(m + 0xd8) << 3, *(u16*)(m + 0xd8) << 3);
    if (*(u32*)&((ModelFileHeader*)m)->vertexAnimEntries != 0)
    {
        PSMTXConcat(vm, wm, cm);
        GXLoadPosMtxImm(cm, gObjGxPosMtxIdTable[9]);
    }
    {
        u8* o;
        u8* nxt;
        o = (u8*)obj;
        while ((nxt = *(u8**)&((GameObject*)o)->ownerObj) != NULL)
        {
            o = nxt;
        }
        sh = ((u8*)((GameObject*)o)->anim.modelState->shadowCastSlot)[0x65];
        if (sh == 0xff)
        {
            tev1 = lbl_803DB468;
            GXSetTevColor(GX_TEVREG2, &tev1);
            GXSetBlendMode(GX_BM_NONE, GX_BL_ONE, GX_BL_ZERO, GX_LO_NOOP);
        }
        else
        {
            if (sh < 8)
            {
                color[0] = 1 << sh;
                color[1] = 0;
                color[2] = 0;
            }
            else
            {
                color[0] = 0;
                color[1] = 1 << (sh - 8);
                color[2] = 0;
            }
            color[3] = 0xff;
            tev2 = *(u32*)color;
            GXSetTevColor(GX_TEVREG2, &tev2);
            GXSetBlendMode(GX_BM_LOGIC, GX_BL_ONE, GX_BL_ZERO, GX_LO_OR);
        }
    }
    GXSetNumTexGens(0);
    GXSetNumTevStages(1);
    GXSetNumIndStages(0);
    GXSetTevOrder(GX_TEVSTAGE0, GX_TEXCOORD_NULL, GX_TEXMAP_NULL, GX_COLOR0A0);
    GXSetTevDirect(GX_TEVSTAGE0);
    GXSetTevColorIn(GX_TEVSTAGE0, GX_CC_ZERO, GX_CC_ZERO, GX_CC_ZERO, GX_CC_C2);
    GXSetTevAlphaIn(GX_TEVSTAGE0, GX_CA_ZERO, GX_CA_ZERO, GX_CA_ZERO, GX_CA_A2);
    GXSetTevSwapMode(GX_TEVSTAGE0, GX_TEV_SWAP0, GX_TEV_SWAP0);
    GXSetTevColorOp(GX_TEVSTAGE0, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    GXSetTevAlphaOp(GX_TEVSTAGE0, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    GXSetFog(GX_FOG_NONE, 0.0f, 0.0f, 0.0f, 0.0f, *(ObjGXColor*)&lbl_803DB468);
    gxSetPeControl_ZCompLoc_(1);
    GXSetAlphaCompare(GX_ALWAYS, 0, GX_AOP_AND, GX_ALWAYS, 0);
    GXSetChanCtrl(GX_COLOR0A0, GX_FALSE, GX_SRC_REG, GX_SRC_REG, 0, GX_DF_NONE, GX_AF_NONE);
    GXSetNumChans(1);
    if (OBJPRINT_MODEL_DEF(obj)->renderFlags & OBJDEF_RENDERFLAG_PROJECTED_SHADOW)
    {
        gxSetZMode_(1, 3, 1);
        GXSetCullMode(GX_CULL_FRONT);
    }
    else
    {
        gxSetZMode_(0, 3, 0);
        GXSetCullMode(GX_CULL_NONE);
    }
    GXSetArray(GX_VA_POS, ((int*)((char*)am + 0x1c))[(*(u16*)((char*)am + 0x18) >> 1) & 1], 6);
    done = 0;
    while (!done)
    {
        u32 op4;
        {
            u32 w;
            int pos = bs.pos;
            u8* p = (u8*)((pos >> 3) + bs.data);
            w = p[0];
            w |= p[1] << 8;
            w |= p[2] << 16;
            bs.pos = pos + 4;
            op4 = (w >> (pos & 7)) & 0xf;
        }
        switch (op4)
        {
        case 3:
            GXClearVtxDesc();
            if (((ModelFileHeader*)m)->jointCount > 1)
            {
                GXSetVtxDesc(GX_VA_PNMTXIDX, GX_DIRECT);
            }
            {
                u32 w;
                int pos = bs.pos;
                u8* p = (u8*)((pos >> 3) + bs.data);
                w = p[0];
                w |= p[1] << 8;
                w |= p[2] << 16;
                bs.pos = pos + 1;
                GXSetVtxDesc(GX_VA_POS, (((int)(w >> (pos & 7)) & 1) ? 3 : 2));
            }
            if (((u8*)op)[0x40] & 1)
            {
                bs.pos += 1;
            }
            if (((u8*)op)[0x40] & 2)
            {
                bs.pos += 1;
            }
            GXSetVtxDesc(GX_VA_CLR0, GX_DIRECT);
            bs.pos += 1;
            break;
        case 1:
            {
                u32 w;
                int pos = bs.pos;
                u8* p = bs.data + (pos >> 3);
                w = p[0];
                w |= p[1] << 8;
                w |= p[2] << 16;
                bs.pos = pos + 6;
                op = ObjModel_GetRenderOp(m, (w >> (pos & 7)) & 0x3f);
            }
            break;
        case 2:
            {
                u8* dl;
                u32 w;
                int pos = bs.pos;
                u8* p = (u8*)((pos >> 3) + bs.data);
                w = p[0];
                w |= p[1] << 8;
                w |= p[2] << 16;
                bs.pos = pos + 8;
                dl = modelFileGetDisplayList(m, ((ModelFileHeader*)m)->unkF5 + ((w >> (pos & 7)) & 0xff));
                GXCallDisplayList(*(void**)dl, *(u16*)(dl + 4));
            }
            break;
        case 4:
            modelLoadMtxsToGx((int)m, am, &bs, vm);
            break;
        case 5:
            done = 1;
            break;
        }
    }
}


extern f32 Camera_DistanceToCurrentViewPosition(f32 x, f32 y, f32 z);
extern f32 lbl_803DEA38;
extern f32 lbl_803DEA4C;
extern f32 lbl_803DEA50;
extern f32 lbl_803DEA54;
extern f32 gObjShadowDist;
extern u8 lbl_803DCC35;
extern u8 lbl_803DCC20;
extern u8 lbl_803DCC3E;
u8 gObjGxTexMtxIdTable[12] = {0x1E, 0x21, 0x24, 0x27, 0x2A, 0x2D, 0x30, 0x33, 0x36, 0x39, 0x00, 0x00};
extern void modelInitBoneMtxs(int* am, f32* out);
extern void model_multMtxs(int* am, f32* wm);
u32 objRenderFn_8003edf4(u8* obj, u8* p2, int* am, MtxBitStream* bs);
extern u32* ObjModel_GetRenderOpTextureRefs(int* am, int idx);
extern void PSMTXTrans(f32* m, f32 x, f32 y, f32 z);

void modelDoRenderInstrs(int* obj, int* obj2, u8* m, u8 mode)
{
    f32 fm[16];
    f32 sm[16];
    f32 wm[16];
    f32 im[16];
    f32 tm[12];
    f32 t2m[12];
    MtxBitStream bs;
    u8 color[4];
    u32 tev1;
    u32 tev2;
    u8 o9;
    u8 o8;
    int* am;
    f32* vm;
    int mode8;
    int m4;
    int m2;
    int m1;
    u8 did;
    int* op;
    u32* refs;
    int done;
    f32 fade;

    gObjRenderSetupDone = 0;
    gObjCachedTexture = 0;
    gObjCachedModel = 0;
    lbl_803DCC34 = 0;
    gObjGxVtxDescCache = -1;
    gObjGxBlendModeCache = 0xff;
    gObjGxZCompLocCache = 0xff;
    gObjGxAlphaCompareCache = -1;
    gObjGxZWriteCache = 0xff;
    gObjGxZCompareCache = 0xff;
    gObjGxCullModeCache = 0xff;
    gObjGxKColorCache[3] = 0;
    gObjGxKColorCache[2] = 0;
    gObjGxKColorCache[1] = 0;
    gObjGxKColorCache[0] = 0;
    am = Obj_GetActiveModel(obj);
    vm = Camera_GetViewMatrix();
    if (curObjMtx != 0)
    {
        PSMTXCopy((f32*)curObjMtx, wm);
        curObjMtx = 0;
    }
    else
    {
        Obj_BuildWorldTransformMatrix(obj, wm, 0);
    }
    gObjShadowNear = 0;
    if (((ObjAnimComponent*)obj)->modelInstance->flags & 0x400)
    {
        int* player = Obj_GetPlayerObject();
        int* cam = (int*)(*gCameraInterface)->getCamera();
        if (player != NULL && !(((GameObject*)player)->objectFlags & OBJECT_OBJFLAG_PARENT_SLACK) && *(int**)&((GameObject*)cam)->anim.
            targetObj == player)
        {
            f32 d = lbl_803DEA38 + (((GameObject*)obj)->anim.hitboxScale * ((GameObject*)obj)->anim.rootMotionScale + *(
                f32*)&((GameObject*)obj)->anim.targetObj);
            f32 dist = Camera_DistanceToCurrentViewPosition(((GameObject*)player)->anim.worldPosX,
                                                            ((GameObject*)player)->anim.worldPosY,
                                                            ((GameObject*)player)->anim.worldPosZ);
            if (d > -dist)
            {
                gObjShadowNear = 1;
                gObjShadowDist = dist;
            }
        }
    }
    if (gObjOverrideColorPending != 0)
    {
        *(u8*)&gObjCurChanColor = gObjOverrideColor;
        ((u8*)&gObjCurChanColor)[1] = (&gObjOverrideColor)[1];
        ((u8*)&gObjCurChanColor)[2] = (&gObjOverrideColor)[2];
        gObjOverrideColorPending = 0;
    }
    else
    {
        objGetColor(*(u8*)((char*)obj + 0xf2), (u8*)&gObjCurChanColor, (u8*)&gObjCurChanColor + 1, (u8*)&gObjCurChanColor + 2);
    }
    mode8 = mode;
    m4 = mode8 & 4;
    if (m4 || (mode8 & 8))
    {
        fade = lbl_803DEA4C;
    }
    else if (mode8 & 2)
    {
        fade = lbl_803DEA50;
    }
    did = 0;
    if (!(*(u16*)((char*)am + 0x18) & 8))
    {
        *(u8*)((char*)am + 0x60) = 0;
        ObjModel_ToggleVertexBuffer(am);
        if (((ModelFileHeader*)m)->animationCount != 0 && !(((ModelFileHeader*)m)->flags & 2) && ((ModelFileHeader*)m)->
            jointCount != 0)
        {
            if (*(u32*)&((ModelFileHeader*)m)->vertexAnimEntries != 0)
            {
                PSMTXIdentity(im);
                ObjModel_UpdateAnimMatrices(am, m, obj, im);
                if (m4 == 0)
                {
                    modelInitBoneMtxs2(am, wm, gObjBoneMtxBuffer);
                }
                else
                {
                    modelInitBoneMtxs(am, gObjBoneMtxBuffer);
                }
                did = 1;
            }
            else
            {
                ObjModel_UpdateAnimMatrices(am, m, obj, wm);
            }
            {
                ObjShadowCb cb = *(ObjShadowCb*)((char*)obj + 0x108);
                if (cb != NULL && obj2 == obj)
                {
                    cb(obj, am, wm);
                }
            }
        }
        else
        {
            ObjModel_ToggleMatrixBuffer(am);
            PSMTXCopy(wm, (f32*)ObjModel_GetJointMatrix((u8*)am, 0));
        }
        if ((m4 == 0 && (mode8 & 8) == 0) || lbl_803DCC44 == 0)
        {
            if (((ModelFileHeader*)m)->morphTargetCount != 0)
            {
                ObjModel_ApplyBlendChannels(am);
            }
            if (did != 0)
            {
                int vtx;
                if (*(u8*)((char*)am + 0x60) != 0)
                {
                    vtx = ((int*)((char*)am + 0x1c))[(*(u16*)((char*)am + 0x18) >> 1) & 1];
                }
                else
                {
                    vtx = *(int*)&((ModelFileHeader*)m)->vertices;
                }
                ObjModel_BlendPrimaryVertexStream(gObjBoneMtxBuffer, m + 0x88, vtx, *(int*)&((ModelFileHeader*)am)->unk40,
                                                  ((int*)((char*)am + 0x1c))[(*(u16*)((char*)am + 0x18) >> 1) & 1]);
                ObjModel_BlendSecondaryVertexStream(gObjBoneMtxBuffer, m + 0xac, *(int*)&((ModelFileHeader*)m)->normals,
                                                    *(int*)((char*)am + 0x44), ((ModelFileHeader*)m)->flags24 & 8);
            }
        }
        if (((ModelFileHeader*)m)->unkF7 != 0)
        {
            objUpdateHitSpheres(am, m, obj, 0, obj2);
        }
        else
        {
            u8* att = *(u8**)&((GameObject*)obj)->anim.hitReactState;
            if (att != NULL)
            {
                att[0xaf]--;
                if (*(s8*)(*(char**)&((GameObject*)obj)->anim.hitReactState + 0xaf) < 0)
                {
                    *(u8*)(*(char**)&((GameObject*)obj)->anim.hitReactState + 0xaf) = 0;
                }
            }
        }
        *(u16*)((char*)am + 0x18) |= 8;
    }
    m2 = mode8 & 2;
    if (m2 || m4 || (mode8 & 8))
    {
        int joff;
        int j;
        j = 0;
        joff = 0;
        for (; j < ((ModelFileHeader*)m)->jointCount; j++)
        {
            f32 sc = (f32)gObjFuzzStep * (fade / *(f32*)(((ModelFileHeader*)m)->unk40 + joff + 0xc)) + lbl_803DEA1C;
            f32* jm = (f32*)ObjModel_GetJointMatrix((u8*)am, j);
            PSMTXScale(sm, sc, sc, sc);
            if (lbl_803DCC35 == 0)
            {
                {
                    char* jp = (char*)((ModelFileHeader*)m)->unk40 + joff;
                    PSMTXTrans(tm, -*(f32*)jp, -*(f32*)(jp + 4), -*(f32*)(jp + 8));
                }
                PSMTXConcat(sm, tm, sm);
                {
                    char* jp = (char*)((ModelFileHeader*)m)->unk40 + joff;
                    PSMTXTrans(tm, *(f32*)jp, *(f32*)(jp + 4), *(f32*)(jp + 8));
                }
                PSMTXConcat(tm, sm, sm);
            }
            PSMTXConcat(jm, sm, jm);
            joff += 0x10;
        }
        if (did != 0)
        {
            model_multMtxs(am, wm);
        }
    }
    modelInitMtxs(m, am);
    modelRenderInstrsState_init(&bs, ((ModelFileHeader*)m)->instrs, *(u16*)(m + 0xd8) << 3, *(u16*)(m + 0xd8) << 3);
    {
        f32 inv = lbl_803DEA1C / ((GameObject*)obj)->anim.rootMotionScale;
        PSMTXScale(sm, inv, inv, inv);
    }
    if (*(u32*)&((ModelFileHeader*)m)->vertexAnimEntries != 0)
    {
        if (m4 || m2 || (mode8 & 8))
        {
            f32 sc2 = lbl_803DEA1C + (lbl_803DEA54 * ((f32)(lbl_803DCC44 + 1) * fade)) / *(f32*)(m + 0x50);
            PSMTXTrans(tm, -*(f32*)(m + 0x44), -*(f32*)(m + 0x48), -*(f32*)(m + 0x4c));
            PSMTXScale(sm, sc2, sc2, sc2);
            PSMTXConcat(sm, tm, sm);
            PSMTXTrans(tm, *(f32*)(m + 0x44), *(f32*)(m + 0x48), *(f32*)(m + 0x4c));
            PSMTXConcat(tm, sm, sm);
            PSMTXConcat(wm, sm, t2m);
            PSMTXConcat(vm, t2m, fm);
        }
        else
        {
            PSMTXConcat(vm, wm, fm);
        }
        {
            u8* idp = gObjGxPosMtxIdTable;
            f32 z;
            GXLoadPosMtxImm(fm, idp[9]);
            z = lbl_803DEA04;
            fm[3] = z;
            fm[7] = z;
            fm[11] = z;
            PSMTXConcat(fm, sm, fm);
            GXLoadNrmMtxImm(fm, idp[9]);
            GXLoadTexMtxImm(fm, gObjGxTexMtxIdTable[9], 0);
        }
    }
    m1 = mode8 & 1;
    if (m1 != 0)
    {
        GXSetNumTexGens(0);
        GXSetNumTevStages(1);
        GXSetNumIndStages(0);
        GXSetTevOrder(GX_TEVSTAGE0, GX_TEXCOORD_NULL, GX_TEXMAP_NULL, GX_COLOR0A0);
        {
            u32 sh;
            u8* o;
            u8* nxt;
            o = (u8*)obj;
            while ((nxt = *(u8**)&((GameObject*)o)->ownerObj) != NULL)
            {
                o = nxt;
            }
            sh = ((u8*)((GameObject*)o)->anim.modelState->shadowCastSlot)[0x65];
            if (sh == 0xff)
            {
                tev1 = lbl_803DB468;
                GXSetTevColor(GX_TEVREG2, &tev1);
                GXSetBlendMode(GX_BM_NONE, GX_BL_ONE, GX_BL_ZERO, GX_LO_NOOP);
            }
            else
            {
                if (sh < 8)
                {
                    color[0] = 1 << sh;
                    color[1] = 0;
                    color[2] = 0;
                }
                else
                {
                    color[0] = 0;
                    color[1] = 1 << (sh - 8);
                    color[2] = 0;
                }
                color[3] = 0xff;
                tev2 = *(u32*)color;
                GXSetTevColor(GX_TEVREG2, &tev2);
                GXSetBlendMode(GX_BM_LOGIC, GX_BL_ONE, GX_BL_ZERO, GX_LO_OR);
            }
        }
        GXSetTevDirect(GX_TEVSTAGE0);
        GXSetTevColorIn(GX_TEVSTAGE0, GX_CC_ZERO, GX_CC_ZERO, GX_CC_ZERO, GX_CC_C2);
        GXSetTevAlphaIn(GX_TEVSTAGE0, GX_CA_ZERO, GX_CA_ZERO, GX_CA_ZERO, GX_CA_A2);
        GXSetTevSwapMode(GX_TEVSTAGE0, GX_TEV_SWAP0, GX_TEV_SWAP0);
        GXSetTevColorOp(GX_TEVSTAGE0, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
        GXSetTevAlphaOp(GX_TEVSTAGE0, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
        GXSetFog(GX_FOG_NONE, 0.0f, 0.0f, 0.0f, 0.0f, *(ObjGXColor*)&lbl_803DB468);
        gxSetPeControl_ZCompLoc_(1);
        GXSetAlphaCompare(GX_ALWAYS, 0, GX_AOP_AND, GX_ALWAYS, 0);
        GXSetChanCtrl(GX_COLOR0A0, GX_FALSE, GX_SRC_REG, GX_SRC_VTX, 0, GX_DF_NONE, GX_AF_NONE);
        GXSetNumChans(1);
        if (OBJPRINT_MODEL_DEF(obj)->renderFlags & OBJDEF_RENDERFLAG_PROJECTED_SHADOW)
        {
            gxSetZMode_(1, 3, 1);
            GXSetCullMode(GX_CULL_FRONT);
        }
        else
        {
            gxSetZMode_(0, 3, 0);
            GXSetCullMode(GX_CULL_NONE);
        }
    }
    else if (m2 != 0)
    {
        objRenderFuzzFn_8003d6f8((void*)obj);
    }
    else
    {
        Camera_RebuildProjectionMatrix();
        objFn_8003dc50(m, (u8*)obj);
        if (((ModelFileHeader*)m)->flags & 0x100)
        {
            GXSetFog(GX_FOG_NONE, 0.0f, 0.0f, 0.0f, 0.0f, *(ObjGXColor*)&lbl_803DB468);
        }
        else
        {
            _gxSetFogParams();
        }
    }
    GXSetArray(GX_VA_POS, ((int*)((char*)am + 0x1c))[(*(u16*)((char*)am + 0x18) >> 1) & 1], 6);
    if (((ModelFileHeader*)m)->flags24 & 8)
    {
        GXSetArray(GX_VA_NRM, *(int*)((char*)am + 0x24), 9);
    }
    else
    {
        GXSetArray(GX_VA_NRM, *(int*)((char*)am + 0x24), 3);
    }
    GXSetArray(GX_VA_CLR0, *(int*)&((ModelFileHeader*)m)->unk30, 2);
    GXSetArray(GX_VA_TEX0, *(int*)&((ModelFileHeader*)m)->unk34, 4);
    GXSetArray(GX_VA_TEX1, *(int*)&((ModelFileHeader*)m)->unk34, 4);
    done = 0;
    while (!done)
    {
        u32 op4;
        {
            u32 w;
            int pos = bs.pos;
            int off = pos >> 3;
            u8* p = (u8*)(off + bs.data);
            w = p[0];
            w |= p[1] << 8;
            w |= p[2] << 16;
            bs.pos = pos + 4;
            op4 = (w >> (pos & 7)) & 0xf;
        }
        switch (op4)
        {
        case 3:
            modelRenderFn_setVtxDescr(m, (u8*)op, refs, &bs, mode, &o9, &o8);
            break;
        case 1:
            if (mode == 0 || mode == 4 || mode == 8)
            {
                u32 idx;
                if (lbl_803DCC20 == 0)
                {
                    idx = objRenderFn_8003edf4((u8*)obj, m, am, &bs);
                    op = ObjModel_GetRenderOp(m, idx);
                }
                else
                {
                    u32 w;
                    int pos = bs.pos;
                    int off = pos >> 3;
                    u8* p = (u8*)(off + bs.data);
                    w = p[0];
                    w |= p[1] << 8;
                    w |= p[2] << 16;
                    bs.pos = pos + 6;
                    idx = (w >> (pos & 7)) & 0x3f;
                    op = ObjModel_GetRenderOp(m, idx);
                }
                refs = ObjModel_GetRenderOpTextureRefs(am, idx);
            }
            break;
        case 2:
            if ((mode != 4 && mode != 8) || lbl_803DCC3E != 0)
            {
                u8* dl;
                u32 w;
                int pos = bs.pos;
                int off = pos >> 3;
                u8* p = (u8*)(off + bs.data);
                w = p[0];
                w |= p[1] << 8;
                w |= p[2] << 16;
                bs.pos = pos + 8;
                dl = modelFileGetDisplayList(m, (w >> (pos & 7)) & 0xff);
                GXCallDisplayList(*(void**)dl, *(u16*)(dl + 4));
            }
            else
            {
                bs.pos += 8;
            }
            break;
        case 4:
            renderOpMatrix(m, am, &bs, sm, vm, o9, o8, m1);
            break;
        case 5:
            done = 1;
            break;
        }
    }
}

extern u8* Shader_getLayer(u8* shader, int idx);
extern void gxTextureFn_80050e28(int flag);
extern void* textureCrazyPointerFollowFn_80054c30(void* tex, int p2);
extern void fn_80051B00(void* tex, int mtx, int fl, u8* color);
extern void fn_80051868(void* tex, int mtx, int fl);
extern void fn_80051D5C(void* tex, int mtx, int fl, u8* color);
extern void gxColorFn_80052764(u8 * color);
extern void textureFn_800524ec(u8 * color);
extern f32 lbl_803DEA48;

#pragma opt_propagation off
u8 modelRenderFn_8003e98c(u8* obj, u8* shader, u32* p3, int mask, int p5, int p6)
{
    u16 alpha;
    u8* colp;
    void* tex;
    u8* prev;
    u8* layer;
    u8 ok;
    int layerIdx;
    u8 color[4];
    f32 m[12];

    ok = 1;
    if (p3[0] != 0 || p3[1] != 0)
    {
        int i;
        u8 cnt;
        cnt = 0;
        for (i = 0; i < shader[0x41]; i++)
        {
            u8* l = Shader_getLayer(shader, i);
            if (l[4] & 0x80)
            {
                cnt++;
            }
        }
        if (cnt > 1)
        {
            ok = 0;
        }
    }
    layerIdx = 0;
    colp = (u8*)&gObjCurChanColor;
    {
        for (; layerIdx < shader[0x41]; layerIdx++)
        {
            layer = Shader_getLayer(shader, layerIdx);
            if ((layer[4] & 0x80) == mask)
            {
                if ((*(u32*)(shader + 0x3c) & 0x100000) && layerIdx == 1)
                {
                    gxTextureFn_80050e28(p3[0] != 0 ? 1 : 0);
                    return 1;
                }
                alpha = ((obj[0x37] + 1) * shader[0xc]) >> 8;
                if (*(u32*)layer != 0)
                {
                    f32* mtxp;
                    u8 fl;
                    tex = textureIdxToPtr(*(u32*)layer);
                    {
                        u32 jid = layer[5];
                        if (jid != 0)
                        {
                            ObjTextureRuntimeSlot* slots = ((GameObject*)obj)->anim.textureSlots;
                            ObjDef* modelDef = ((GameObject*)obj)->anim.modelInstance;
                            ObjTextureSlotDef* q = modelDef->textureSlotDefs;
                            int n = modelDef->textureSlotCount;
                            int k;
                            for (k = 0; k < n; k++)
                            {
                                if ((int)jid == q->materialIndex)
                                {
                                    tex = textureCrazyPointerFollowFn_80054c30(tex, slots[k].textureId);
                                    break;
                                }
                                q++;
                            }
                            {
                                f32 tx;
                                f32 ty;
                                u32 jid2 = layer[5];
                                ObjTextureRuntimeSlot* slots2 = ((GameObject*)obj)->anim.textureSlots;
                                ObjDef* modelDef2 = ((GameObject*)obj)->anim.modelInstance;
                                ObjTextureSlotDef* q2 = modelDef2->textureSlotDefs;
                                int n2 = modelDef2->textureSlotCount;
                                int k2;
                                for (k2 = 0; k2 < n2; k2++)
                                {
                                    if ((int)jid2 == q2->materialIndex)
                                    {
                                        tx = lbl_803DEA48 * slots2[k2].offsetS;
                                        ty = lbl_803DEA48 * slots2[k2].offsetT;
                                        goto trans;
                                    }
                                    q2++;
                                }
                                ty = tx = lbl_803DEA04;
                            trans:
                                PSMTXTrans(m, tx, ty, lbl_803DEA04);
                                mtxp = m;
                            }
                        }
                        else
                        {
                            mtxp = NULL;
                        }
                    }
                    if (layerIdx == 0)
                    {
                        if ((p3[0] != 0 || p3[1] != 0 || p6 != 0) && ok)
                        {
                            fl = 8;
                        }
                        else
                        {
                            fl = 0;
                        }
                        color[3] = alpha;
                    }
                    else
                    {
                        fl = prev[4] & 0x7f;
                        color[3] = 0xff;
                    }
                    color[0] = 0xff;
                    color[1] = 0xff;
                    color[2] = 0xff;
                    if (p3[0] != 0 || (shader[0] == 0xff && shader[1] == 0xff && shader[2] == 0xff))
                    {
                        gxFn_80051fb8(tex, (int)mtxp, (u8)fl, color, *((u8*)p3 + 8), 1);
                    }
                    else if (p5 != 0)
                    {
                        colp[3] = color[3];
                        if (shader[0x40] & 0x10)
                        {
                            fn_80051B00(tex, (int)mtxp, (u8)fl, (u8*)&gObjCurChanColor);
                        }
                        else
                        {
                            gxFn_80051fb8(tex, (int)mtxp, (u8)fl, (u8*)&gObjCurChanColor, *((u8*)p3 + 8), 1);
                        }
                    }
                    else
                    {
                        if (shader[0x40] & 0x10)
                        {
                            fn_80051868(tex, (int)mtxp, (u8)fl);
                            if (color[3] < 0xff)
                            {
                                gxColorFn_80052764(color);
                            }
                        }
                        else
                        {
                            fn_80051D5C(tex, (int)mtxp, (u8)fl, color);
                        }
                    }
                }
                else
                {
                    color[0] = shader[4];
                    color[1] = shader[5];
                    color[2] = shader[6];
                    color[3] = alpha;
                    if (p3[0] != 0 || (shader[0] == 0xff && shader[1] == 0xff && shader[2] == 0xff))
                    {
                        gxColorFn_80052764(color);
                    }
                    else if (p5 != 0)
                    {
                        colp[3] = alpha;
                        gxColorFn_80052764((u8*)&gObjCurChanColor);
                    }
                    else
                    {
                        if (shader[0x40] & 0x10)
                        {
                            gxColorFn_800523d0();
                            if (color[3] < 0xff)
                            {
                                gxColorFn_80052764(color);
                            }
                        }
                        else
                        {
                            textureFn_800524ec(color);
                        }
                    }
                }
            }
            prev = layer;
        }
    }
    return ok;
}
#pragma opt_propagation reset

extern ObjModelRenderCb ObjModel_GetPostRenderCallback(int* am);
extern u8 textureFn_80050ad8(void* tex, int n, int p3, u32 p4);
extern void textureFn_80051348(u32 ref, int p2);
extern void fn_800510F0(u32 ref, int p2, int p3);
extern void fn_80050FF4(int p1);
extern void fn_8005011C(f32 * m);

extern u32 modelLightStruct_getProjectionTexture(int light);
extern void fn_80050558(u32 t, int p2, int p3, int p4, int p5);
extern void fn_80050A28(int t);

extern void textureFn_8004c330(void* tex, f32* m);
extern void gxTextureFn_8004d5b4(int* op);
extern void gxTextureFn_80052638(u8 * color);
extern f32 lbl_803967F0[];
extern u8 lbl_803DCC3C;

#pragma opt_propagation off
u32 objRenderFn_8003edf4(u8* obj, u8* p2, int* am, MtxBitStream* bs)
{
    int* op;
    u32* refs;
    u32 idx;
    u8 shad;
    int nlay;
    int envtex;
    ObjModelRenderCb cb;
    f32 m2[12];
    f32 t2[12];
    f32 wm[12];
    f32 t1[12];
    int a;
    int b;
    u8 color[4];
    f32 fogc;
    u32 tmp1;
    u32 tmp2;

    shad = 0;
    {
        u32 w;
        int pos = bs->pos;
        int off = pos >> 3;
        u8* p;
        w = bs->data[off];
        p = (u8*)(off + (char*)bs->data);
        w |= p[1] << 8;
        w |= p[2] << 16;
        bs->pos = pos + 6;
        idx = (w >> (pos & 7)) & 0x3f;
    }
    cb = ObjModel_GetRenderCallback(am);
    if (cb != NULL && cb((int*)obj, am, idx) != 0)
    {
        return idx;
    }
    op = ObjModel_GetRenderOp((u8*)*am, idx);
    refs = ObjModel_GetRenderOpTextureRefs(am, idx);
    resetLotsOfRenderVars();
    envtex = 0;
    if ((refs[0] != 0 || refs[1] != 0) && ((ObjModelRenderOp*)op)->envTextureId != 0)
    {
        void* t = textureIdxToPtr(((ObjModelRenderOp*)op)->envTextureId);
        int nl = lbl_803DCC5C + 1;
        if (refs[0] != 0)
        {
            nl += 1;
        }
        if (refs[1] != 0)
        {
            nl += 1;
        }
        envtex = textureFn_80050ad8(t, nl, ((u8*)op)[0x42], ((ObjModelRenderOp*)op)->unk24);
    }
    if (refs[0] != 0)
    {
        textureFn_80051348(refs[0], obj[0xf1]);
    }
    if (refs[1] != 0)
    {
        if (((ObjModelRenderOp*)op)->unk1C != 0)
        {
            color[0] = 0xff;
            color[1] = 0xff;
            color[2] = 0xff;
            color[3] = ((u8*)op)[0x22];
        }
        else
        {
            color[3] = 0;
        }
        tmp1 = *(u32*)color;
        GXSetTevColor(GX_TEVREG2, &tmp1);
        fn_800510F0(refs[1], refs[0] != 0 ? 1 : 0, ((u8*)op)[0x20]);
        if (color[3] != 0)
        {
            fn_80050FF4(refs[0] != 0 ? 1 : 0);
        }
    }
    else
    {
        tmp2 = gObjGxDefaultChanColor;
        GXSetTevColor(GX_TEVREG2, &tmp2);
    }
    nlay = lbl_803DCC5C;
    if (gObjShadowNear != 0)
    {
        fn_8004D230();
        shad = 1;
        nlay = 0;
    }
    else
    {
        int b4;
        f32* mx;
        u8 b5f = OBJPRINT_MODEL_DEF(obj)->renderFlags;
        b4 = b5f & 4;
        if (b4 && (mx = (f32*)((GameObject*)obj)->anim.modelState->shadowCastSlot) != NULL)
        {
            fn_8005011C(mx);
            nlay = 0;
        }
        else if (b5f & 0x10)
        {
            fn_8004D6D8();
            nlay = 0;
        }
        else if (b4 == 0)
        {
            int* lp;
            u8* sp;
            int i;
            i = 0;
            lp = &lbl_803DCC64;
            sp = &lbl_803DCC60;
            for (; i < lbl_803DCC5C; i++)
            {
                u32 t = modelLightStruct_getProjectionTexture(*lp);
                if (t != 0)
                {
                    modelLightStruct_getProjectionTevModes(*lp, &a, &b);
                    if (a == 2)
                    {
                        shad = 1;
                    }
                    {
                        int mtx = modelLightStruct_getProjectionTexMtx(*lp);
                        fn_80050558(t, mtx, a, b, *sp);
                    }
                }
                lp++;
                sp++;
            }
        }
    }
    if (envtex != 0)
    {
        fn_80050A28(envtex);
    }
    {
        u32 t18;
        if ((t18 = ((ObjModelRenderOp*)op)->textureId) != 0 && ((ObjModelRenderOp*)op)->unk1C == 0 && refs[1] != 0)
        {
            textureIdxToPtr(t18);
            fn_80050F2C();
        }
    }
    {
        u8 hl;
        if (modelRenderFn_8003e98c(obj, (u8*)op, refs, 0x80, hl = ((*(u16*)(p2 + 0xe2) & 2) && !(p2[0x24] & 2)),
                                   nlay) == 0)
        {
            gxTextureFn_80050e28(refs[0] != 0 ? 1 : 0);
        }
        if (((ObjModelRenderOp*)op)->flags & 0x100000)
        {
            u8* l1 = Shader_getLayer((u8*)op, 1);
            {
                f32 tx;
                f32 ty;
                u32 jid = l1[5];
                ObjTextureRuntimeSlot* slots = ((GameObject*)obj)->anim.textureSlots;
                ObjDef* modelDef = ((GameObject*)obj)->anim.modelInstance;
                ObjTextureSlotDef* q = modelDef->textureSlotDefs;
                int n = modelDef->textureSlotCount;
                int k;
                for (k = 0; k < n; k++)
                {
                    if ((int)jid == q->materialIndex)
                    {
                        tx = lbl_803DEA48 * slots[k].offsetS;
                        ty = lbl_803DEA48 * slots[k].offsetT;
                        goto trans2;
                    }
                    q++;
                }
                ty = tx = lbl_803DEA04;
            trans2:
                PSMTXTrans(m2, tx, ty, lbl_803DEA04);
            }
            textureFn_8004c330(textureIdxToPtr(*(u32*)l1), m2);
        }
        modelRenderFn_8003e98c(obj, (u8*)op, refs, 0, hl, nlay);
    }
    if (isHeavyFogEnabled() && !(*(u16*)(p2 + 2) & 0x100))
    {
        getColor803dd01c(&fogc);
        renderHeavyFog(&fogc);
    }
    if (((ObjModelRenderOp*)op)->flags & 0x100)
    {
        f32* vm = Camera_GetViewMatrix();
        Obj_BuildWorldTransformMatrix((int*)obj, wm, 0);
        PSMTXConcat(vm, wm, t1);
        PSMTXConcat(lbl_803967F0, t1, t2);
        GXLoadTexMtxImm(t2, 0x24, 0);
        fn_8004D928();
    }
    if (OBJPRINT_MODEL_DEF(obj)->renderFlags & OBJDEF_RENDERFLAG_DEFERRED_RENDER)
    {
        gxTextureFn_8004d5b4(op);
    }
    {
        u8 e5 = ((GameObject*)obj)->colorFadeFlags;
        if ((e5 & OBJ_COLOR_FADE_FLAG_ACTIVE) || (e5 & OBJ_COLOR_FADE_FLAG_OVERRIDE))
        {
            color[0] = obj[0xec];
            color[1] = obj[0xed];
            color[2] = obj[0xee];
            color[3] = obj[0xef];
            gxTextureFn_80052638(color);
        }
    }
    if (((ObjModelRenderOp*)op)->flags & 0x20000)
    {
        fn_80118240();
    }
    textureFn_800528bc();
    {
        ObjModelRenderCb pcb = ObjModel_GetPostRenderCallback(am);
        if (pcb != NULL)
        {
            pcb((int*)obj, am, idx);
        }
        else
        {
            u8 zon = 1;
            if (obj[0x37] < 0xff || (((ObjModelRenderOp*)op)->flags & 0x40000000) || shad)
            {
                u16 f2;
                GXSetBlendMode(GX_BM_BLEND, GX_BL_SRCALPHA, GX_BL_INVSRCALPHA, GX_LO_NOOP);
                f2 = *(u16*)(p2 + 2);
                if (f2 & 0x400)
                {
                    gxSetZMode_(0, 3, 0);
                    GXSetAlphaCompare(GX_ALWAYS, 0, GX_AOP_AND, GX_ALWAYS, 0);
                }
                else if (f2 & 0x2000)
                {
                    zon = 0;
                    gxSetZMode_(1, 3, 1);
                    GXSetAlphaCompare(GX_GREATER, lbl_803DCC3C, GX_AOP_AND, GX_GREATER, lbl_803DCC3C);
                }
                else
                {
                    gxSetZMode_(1, 3, 0);
                    GXSetAlphaCompare(GX_ALWAYS, 0, GX_AOP_AND, GX_ALWAYS, 0);
                }
            }
            else if (((ObjModelRenderOp*)op)->flags & 0x400)
            {
                GXSetBlendMode(GX_BM_NONE, GX_BL_ONE, GX_BL_ZERO, GX_LO_NOOP);
                if (*(u16*)(p2 + 2) & 0x400)
                {
                    gxSetZMode_(0, 3, 0);
                }
                else
                {
                    gxSetZMode_(1, 3, 1);
                }
                GXSetAlphaCompare(GX_GREATER, 0x40, GX_AOP_AND, GX_GREATER, 0x40);
            }
            else
            {
                GXSetBlendMode(GX_BM_NONE, GX_BL_ONE, GX_BL_ZERO, GX_LO_NOOP);
                if (*(u16*)(p2 + 2) & 0x400)
                {
                    gxSetZMode_(0, 3, 0);
                }
                else
                {
                    gxSetZMode_(1, 3, 1);
                }
                GXSetAlphaCompare(GX_ALWAYS, 0, GX_AOP_AND, GX_ALWAYS, 0);
            }
            if (((ObjModelRenderOp*)op)->flags & 0x400)
            {
                zon = 0;
            }
            gxSetPeControl_ZCompLoc_(zon);
        }
    }
    if (((ObjModelRenderOp*)op)->flags & 8)
    {
        GXSetCullMode(GX_CULL_BACK);
    }
    else
    {
        GXSetCullMode(GX_CULL_NONE);
    }
    return idx;
}
#pragma opt_propagation reset

u8 lbl_80345E10[0x160];
extern void mm_free(void* p);
extern s16 lbl_803DCC78;
extern void* mmAlloc(int size, int type, int flag);
extern void* memcpy(void*, void*, int);
extern int mmSetFreeDelay(int v);

#pragma optimization_level 2
void defragMemory(int mode)
{
    u8* base = lbl_80345E10;
    int done = 0;
    int pass = 0;
    texFlagFn_80023cbc(2);
    if ((int)getLoadedFileFlags() != 0)
    {
        return;
    }
    if (mode == 0 && lbl_803DCC78 == 0)
    {
        texRestructRefs(0);
        lbl_803DCC78 = 6;
        return;
    }
    if (mode != 0)
    {
        int i;
        char* p1;
        char* p2;
        char* p3;
        char* p4;
        testAndSet_onlyUseHeaps1and2(1);
        i = 0;
        {
            char* hi = (char*)base + 0x20000;
            p1 = hi - 0x6a28;
            p2 = hi - 0x68c8;
            p3 = hi - 0x6d68;
            p4 = hi - 0x6f20;
        }
        do
        {
            switch (i)
            {
            case 0xd:
            case 0x1b:
            case 0x23:
            case 0x25:
            case 0x2b:
            case 0x30:
            case 0x46:
            case 0x47:
            case 0x4a:
            case 0x4d:
            case 0x54:
            case 0x55:
                {
                    void* n;
                    if (*(void**)p1 == NULL)
                    {
                        break;
                    }
                    if (*(s16*)p2 == -1)
                    {
                        break;
                    }
                    if (mmGetRegionForPtr(*(void**)p1) != 0)
                    {
                        break;
                    }
                    if (mode == 2)
                    {
                        if (i == 0x20) break;
                        if (i == 0x4b) break;
                        if (i == 0x23) break;
                        if (i == 0x4d) break;
                    }
                    n = mmAlloc(*(int*)p3 + 0x20, 0x7d7d7d7d, 0);
                    if (n == NULL)
                    {
                        break;
                    }
                    memcpy(n, *(void**)p1, *(int*)p3);
                    {
                        int d = mmSetFreeDelay(0);
                        mm_free(*(void**)p1);
                        *(int*)p1 = 0;
                        *(void**)p1 = n;
                        mmSetFreeDelay(d);
                    }
                    break;
                }
            }
            *(u8*)p4 = 0;
            p1 += 4;
            p2 += 2;
            p3 += 4;
            p4 += 1;
            i++;
        } while (i <= 0x57);
        testAndSet_onlyUseHeaps1and2(-1);
    }
    base = (u8*)((char*)base + 0x20000);
    while (done == 0 && pass < 10)
    {
        char* q1;
        char* q2;
        char* q3;
        char* q4;
        int i;
        done = 1;
        i = 0;
        q1 = (char*)base - 0x6a28;
        q2 = (char*)base - 0x68c8;
        q3 = (char*)base - 0x6d68;
        q4 = (char*)base - 0x6f20;
        do
        {
            switch (i)
            {
            case 0xd:
            case 0x1b:
            case 0x23:
            case 0x25:
            case 0x2b:
            case 0x30:
            case 0x46:
            case 0x47:
            case 0x4a:
            case 0x4d:
            case 0x54:
            case 0x55:
                {
                    void* n;
                    if (*(void**)q1 != NULL && *(s16*)q2 != -1 && mmGetRegionForPtr(*(void**)q1) == 0)
                    {
                        n = mmAlloc(*(int*)q3 + 0x20, 0x7d7d7d7d, 0);
                        if (n == NULL)
                        {
                            break;
                        }
                        if (*(int*)q3 >= 0x33450 && *(u32*)q1 < (u32)n)
                        {
                            int d = mmSetFreeDelay(0);
                            mm_free(n);
                            mmSetFreeDelay(d);
                        }
                        else if (*(int*)q3 < 0x33450 && *(u32*)q1 > (u32)n)
                        {
                            int d = mmSetFreeDelay(0);
                            mm_free(n);
                            mmSetFreeDelay(d);
                        }
                        else
                        {
                            int d;
                            memcpy(n, *(void**)q1, *(int*)q3);
                            d = mmSetFreeDelay(0);
                            mm_free(*(void**)q1);
                            *(int*)q1 = 0;
                            *(void**)q1 = n;
                            mmSetFreeDelay(d);
                            done = 0;
                        }
                    }
                    else
                    {
                        if (mode == 2) break;
                        if (pass == 0) break;
                        if (*(void**)q1 == NULL) break;
                        if (*(s16*)q2 == -1) break;
                        if (mmGetRegionForPtr(*(void**)q1) != 1 && mmGetRegionForPtr(*(void**)q1) != 2)
                        {
                            break;
                        }
                        if (getHeapItemSize(*(void**)q1) < 0x3000)
                        {
                            break;
                        }
                        n = mmAlloc(*(int*)q3 + 0x20, 0x7d7d7d7d, 0);
                        if (n == NULL)
                        {
                            break;
                        }
                        if (mmGetRegionForPtr(n) != 0)
                        {
                            int d = mmSetFreeDelay(0);
                            mm_free(n);
                            mmSetFreeDelay(d);
                        }
                        else
                        {
                            int d;
                            memcpy(n, *(void**)q1, *(int*)q3);
                            d = mmSetFreeDelay(0);
                            mm_free(*(void**)q1);
                            *(int*)q1 = 0;
                            *(void**)q1 = n;
                            mmSetFreeDelay(d);
                            done = 0;
                        }
                    }
                    break;
                }
            }
            *(u8*)q4 = 0;
            q1 += 4;
            q2 += 2;
            q3 += 4;
            q4 += 1;
            i++;
        } while (i <= 0x57);
        pass++;
    }
    texFlagFn_80023cbc(0);
}
#pragma optimization_level reset

void* getCurrentDataFile(int id)
{
    u8* base = lbl_80345E10;
    switch (id)
    {
    case 42: return &base[0x170e0];
    case 47: return &base[0x14200];
    case 36: return &base[0x10200];
    case 33: return &base[0xc200];
    case 80: return *(void**)&base[0x19718];
    case 38: return &base[0xa200];
    case 26: return &base[0x8200];
    case 14: return &base[0x2c0];
    }
    return NULL;
}

extern u32 lbl_803DCC84;
extern void* lbl_803DCC8C;
extern u32 lbl_8035F3E8[];
u32 gObjBlockStatus[0x63F6];
extern void AtomicSList_Push(void** list, void* node);
extern int DVDClose(void* fileInfo);

void tex0tab1readCb(s32 result, void* fileInfo)
{
    if (result < 0)
    {
        DVDClose(fileInfo);
        AtomicSList_Push(lbl_803DCC8C, fileInfo);
        mm_free((void*)lbl_8035F3E8[36]);
        lbl_8035F3E8[36] = 0;
        gObjBlockStatus[36] = 0;
        if (lbl_803DCC80 & 0x400)
        {
            lbl_803DCC84 |= 0x400;
            gObjBlockStatus[36] = 0;
        }
    }
    else
    {
        DVDClose(fileInfo);
        AtomicSList_Push(lbl_803DCC8C, fileInfo);
        if (lbl_803DCC80 & 0x400)
        {
            lbl_803DCC84 |= 0x400;
            gObjBlockStatus[36] = 0;
        }
    }
}

void tex0tab2readCb(s32 result, void* fileInfo)
{
    if (result < 0)
    {
        DVDClose(fileInfo);
        AtomicSList_Push(lbl_803DCC8C, fileInfo);
        mm_free((void*)lbl_8035F3E8[78]);
        lbl_8035F3E8[78] = 0;
        gObjBlockStatus[78] = 0;
        if (lbl_803DCC80 & 0x800)
        {
            lbl_803DCC84 |= 0x800;
            gObjBlockStatus[78] = 0;
        }
    }
    else
    {
        DVDClose(fileInfo);
        AtomicSList_Push(lbl_803DCC8C, fileInfo);
        if (lbl_803DCC80 & 0x800)
        {
            lbl_803DCC84 |= 0x800;
            gObjBlockStatus[78] = 0;
        }
    }
}

void tex1tab1readCb(s32 result, void* fileInfo)
{
    if (result < 0)
    {
        DVDClose(fileInfo);
        AtomicSList_Push(lbl_803DCC8C, fileInfo);
        mm_free((void*)lbl_8035F3E8[78]);
        lbl_8035F3E8[78] = 0;
        gObjBlockStatus[78] = 0;
        if (lbl_803DCC80 & 0x4000)
        {
            lbl_803DCC84 |= 0x4000;
            gObjBlockStatus[33] = 0;
        }
    }
    else
    {
        DVDClose(fileInfo);
        AtomicSList_Push(lbl_803DCC8C, fileInfo);
        if (lbl_803DCC80 & 0x4000)
        {
            lbl_803DCC84 |= 0x4000;
            gObjBlockStatus[33] = 0;
        }
    }
}

void tex1tab2readCb(s32 result, void* fileInfo)
{
    if (result < 0)
    {
        DVDClose(fileInfo);
        AtomicSList_Push(lbl_803DCC8C, fileInfo);
        mm_free((void*)lbl_8035F3E8[78]);
        lbl_8035F3E8[78] = 0;
        gObjBlockStatus[78] = 0;
        if (lbl_803DCC80 & 0x8000)
        {
            lbl_803DCC84 |= 0x8000;
            gObjBlockStatus[76] = 0;
        }
    }
    else
    {
        DVDClose(fileInfo);
        AtomicSList_Push(lbl_803DCC8C, fileInfo);
        if (lbl_803DCC80 & 0x8000)
        {
            lbl_803DCC84 |= 0x8000;
            gObjBlockStatus[76] = 0;
        }
    }
}

void romListReadCb(s32 result, void* fileInfo)
{
    lbl_803DCC74 = 0;
    if (result < 0)
    {
        DVDClose(fileInfo);
        AtomicSList_Push(lbl_803DCC8C, fileInfo);
    }
    else
    {
        DVDClose(fileInfo);
        AtomicSList_Push(lbl_803DCC8C, fileInfo);
    }
}

int unlockLevel(s32 val, int idx, int flag)
{
    s32 cur;
    if (flag == 1)
    {
        (&gObjLevelLockSlots)[0] = -2;
        (&gObjLevelLockSlots)[1] = -2;
        return -1;
    }
    cur = (&gObjLevelLockSlots)[idx];
    if (val == cur || cur == -2)
    {
        (&gObjLevelLockSlots)[idx] = -2;
        return -1;
    }
    return cur;
}

extern int lbl_803DCC88;

void dvdReadCb_80041d30(s32 result, void* fileInfo)
{
    if (result < 0)
    {
        DVDClose(fileInfo);
        AtomicSList_Push(lbl_803DCC8C, fileInfo);
    }
    else
    {
        DVDClose(fileInfo);
        AtomicSList_Push(lbl_803DCC8C, fileInfo);
        lbl_803DCC88--;
    }
}

void animReadCb(s32 result, void* fileInfo)
{
    if (result < 0)
    {
        DVDClose(fileInfo);
        AtomicSList_Push(lbl_803DCC8C, fileInfo);
    }
    else
    {
        DVDClose(fileInfo);
        AtomicSList_Push(lbl_803DCC8C, fileInfo);
        if (lbl_803DCC80 & 0x10)
        {
            lbl_803DCC84 |= 0x10;
            gObjBlockStatus[0xc0 / 4] = 0;
        }
        else if (lbl_803DCC80 & 0x20)
        {
            lbl_803DCC84 |= 0x20;
            gObjBlockStatus[0x128 / 4] = 0;
        }
    }
}

void animCurvReadCb(s32 result, void* fileInfo)
{
    if (result < 0)
    {
        DVDClose(fileInfo);
        AtomicSList_Push(lbl_803DCC8C, fileInfo);
    }
    else
    {
        DVDClose(fileInfo);
        AtomicSList_Push(lbl_803DCC8C, fileInfo);
        if (lbl_803DCC80 & 0x10000000)
        {
            lbl_803DCC84 |= 0x10000000;
            gObjBlockStatus[0x34 / 4] = 0;
        }
        else if (lbl_803DCC80 & 0x40000000)
        {
            lbl_803DCC84 |= 0x40000000;
            gObjBlockStatus[0x154 / 4] = 0;
        }
    }
}

void animCurvTabReadCb(s32 result, void* fileInfo)
{
    if (result < 0)
    {
        DVDClose(fileInfo);
        AtomicSList_Push(lbl_803DCC8C, fileInfo);
    }
    else
    {
        DVDClose(fileInfo);
        AtomicSList_Push(lbl_803DCC8C, fileInfo);
        if (lbl_803DCC80 & 0x20000000)
        {
            lbl_803DCC84 |= 0x20000000;
            gObjBlockStatus[0x38 / 4] = 0;
        }
        else if (lbl_803DCC80 & 0x80000000)
        {
            lbl_803DCC84 |= 0x80000000;
            gObjBlockStatus[0x158 / 4] = 0;
        }
    }
}

void animTabReadCb(s32 result, void* fileInfo)
{
    if (result < 0)
    {
        DVDClose(fileInfo);
        AtomicSList_Push(lbl_803DCC8C, fileInfo);
    }
    else
    {
        DVDClose(fileInfo);
        AtomicSList_Push(lbl_803DCC8C, fileInfo);
        if (lbl_803DCC80 & 0x40)
        {
            lbl_803DCC84 |= 0x40;
            gObjBlockStatus[0xbc / 4] = 0;
        }
        else if (lbl_803DCC80 & 0x80)
        {
            lbl_803DCC84 |= 0x80;
            gObjBlockStatus[0x124 / 4] = 0;
        }
    }
}

void blocksReadCb(s32 result, void* fileInfo)
{
    if (result < 0)
    {
        DVDClose(fileInfo);
        AtomicSList_Push(lbl_803DCC8C, fileInfo);
    }
    else
    {
        DVDClose(fileInfo);
        AtomicSList_Push(lbl_803DCC8C, fileInfo);
        if (lbl_803DCC80 & 0x10000)
        {
            lbl_803DCC84 |= 0x10000;
            gObjBlockStatus[0x94 / 4] = 0;
        }
        else if (lbl_803DCC80 & 0x40000)
        {
            lbl_803DCC84 |= 0x40000;
            gObjBlockStatus[0x11c / 4] = 0;
        }
    }
}

void blocksTabReadCb(s32 result, void* fileInfo)
{
    if (result < 0)
    {
        DVDClose(fileInfo);
        AtomicSList_Push(lbl_803DCC8C, fileInfo);
    }
    else
    {
        DVDClose(fileInfo);
        AtomicSList_Push(lbl_803DCC8C, fileInfo);
        if (lbl_803DCC80 & 0x20000)
        {
            lbl_803DCC84 |= 0x20000;
            gObjBlockStatus[0x98 / 4] = 0;
        }
        else if (lbl_803DCC80 & 0x80000)
        {
            lbl_803DCC84 |= 0x80000;
            gObjBlockStatus[0x120 / 4] = 0;
        }
    }
}

void modelsReadCb(s32 result, void* fileInfo)
{
    if (result < 0)
    {
        DVDClose(fileInfo);
        AtomicSList_Push(lbl_803DCC8C, fileInfo);
    }
    else
    {
        DVDClose(fileInfo);
        AtomicSList_Push(lbl_803DCC8C, fileInfo);
        if (lbl_803DCC80 & 0x1)
        {
            lbl_803DCC84 |= 0x1;
            gObjBlockStatus[0xac / 4] = 0;
        }
        else if (lbl_803DCC80 & 0x2)
        {
            lbl_803DCC84 |= 0x2;
            gObjBlockStatus[0x118 / 4] = 0;
        }
    }
}

void modelsTabReadCb(s32 result, void* fileInfo)
{
    if (result < 0)
    {
        DVDClose(fileInfo);
        AtomicSList_Push(lbl_803DCC8C, fileInfo);
    }
    else
    {
        DVDClose(fileInfo);
        AtomicSList_Push(lbl_803DCC8C, fileInfo);
        if (lbl_803DCC80 & 0x4)
        {
            lbl_803DCC84 |= 0x4;
            gObjBlockStatus[0xa8 / 4] = 0;
        }
        else if (lbl_803DCC80 & 0x8)
        {
            lbl_803DCC84 |= 0x8;
            gObjBlockStatus[0x114 / 4] = 0;
        }
    }
}

void tex0readCb(s32 result, void* fileInfo)
{
    if (result < 0)
    {
        DVDClose(fileInfo);
        AtomicSList_Push(lbl_803DCC8C, fileInfo);
    }
    else
    {
        DVDClose(fileInfo);
        AtomicSList_Push(lbl_803DCC8C, fileInfo);
        if (lbl_803DCC80 & 0x100)
        {
            lbl_803DCC84 |= 0x100;
            gObjBlockStatus[0x8c / 4] = 0;
        }
        else if (lbl_803DCC80 & 0x200)
        {
            lbl_803DCC84 |= 0x200;
            gObjBlockStatus[0x134 / 4] = 0;
        }
    }
}

void tex1ReadCb(s32 result, void* fileInfo)
{
    if (result < 0)
    {
        DVDClose(fileInfo);
        AtomicSList_Push(lbl_803DCC8C, fileInfo);
    }
    else
    {
        DVDClose(fileInfo);
        AtomicSList_Push(lbl_803DCC8C, fileInfo);
        if (lbl_803DCC80 & 0x1000)
        {
            lbl_803DCC84 |= 0x1000;
            gObjBlockStatus[0x80 / 4] = 0;
        }
        else if (lbl_803DCC80 & 0x2000)
        {
            lbl_803DCC84 |= 0x2000;
            gObjBlockStatus[0x12c / 4] = 0;
        }
    }
}

void voxMapReadCb(s32 result, void* fileInfo)
{
    if (result < 0)
    {
        DVDClose(fileInfo);
        AtomicSList_Push(lbl_803DCC8C, fileInfo);
    }
    else
    {
        DVDClose(fileInfo);
        AtomicSList_Push(lbl_803DCC8C, fileInfo);
        if (lbl_803DCC80 & 0x1000000)
        {
            lbl_803DCC84 |= 0x1000000;
            gObjBlockStatus[0x6c / 4] = 0;
        }
        else if (lbl_803DCC80 & 0x4000000)
        {
            lbl_803DCC84 |= 0x4000000;
            gObjBlockStatus[0x150 / 4] = 0;
        }
    }
}

void voxMapTabReadCb(s32 result, void* fileInfo)
{
    if (result < 0)
    {
        DVDClose(fileInfo);
        AtomicSList_Push(lbl_803DCC8C, fileInfo);
    }
    else
    {
        DVDClose(fileInfo);
        AtomicSList_Push(lbl_803DCC8C, fileInfo);
        if (lbl_803DCC80 & 0x2000000)
        {
            lbl_803DCC84 |= 0x2000000;
            gObjBlockStatus[0x68 / 4] = 0;
        }
        else if (lbl_803DCC80 & 0x8000000)
        {
            lbl_803DCC84 |= 0x8000000;
            gObjBlockStatus[0x14c / 4] = 0;
        }
    }
}

extern int sMapFileNameIndexRemapTable[];
extern s16 sMapFileNameAdjacencyTable[];

int loadMapAndParent(int mapId)
{
    int idx;
    int parent;
    if (mapId >= 0x4b)
    {
        idx = 5;
    }
    else
    {
        idx = sMapFileNameIndexRemapTable[mapId];
    }
    parent = sMapFileNameAdjacencyTable[idx];
    if (parent != -1 && mapCheckCurBlocks(parent) == -1)
    {
        mapLoadDataFiles(parent);
        return parent;
    }
    mapLoadDataFiles(idx);
    return idx;
}

extern u32 mapLoadDataFile(int mapId, int fileId);

void mapLoadDataFiles(int mapIdx)
{
    if (sMapFileNameAdjacencyTable[mapIdx] != -1)
    {
        int* r = (int*)(*gMapEventInterface)->getCurCharPos();
        *(s8*)((char*)r + 0xe) = mapIdx;
    }
    mapLoadDataFile(mapIdx, 0x20);
    mapLoadDataFile(mapIdx, 0x21);
    mapLoadDataFile(mapIdx, 0x23);
    mapLoadDataFile(mapIdx, 0x24);
    mapLoadDataFile(mapIdx, 0x30);
    mapLoadDataFile(mapIdx, 0x2f);
    mapLoadDataFile(mapIdx, 0x2b);
    mapLoadDataFile(mapIdx, 0x2a);
    mapLoadDataFile(mapIdx, 0x26);
    mapLoadDataFile(mapIdx, 0x25);
    mapLoadDataFile(mapIdx, 0x1a);
    mapLoadDataFile(mapIdx, 0x1b);
    mapLoadDataFile(mapIdx, 0xe);
    mapLoadDataFile(mapIdx, 0xd);
}

extern void padUpdate(void);
extern void checkReset(void);
extern void waitNextFrame(void);
extern void loadDataFiles(int);
extern void dvdCheckError(void);
extern void mmFreeTick(int arg);
extern void gameTextRun(void);
extern int GXFlush_(u8 visible, int unused);
extern u8 gDvdErrorPauseActive;
int mergeTableFiles(u32* tbl, int id, int idx, int count_);

#define MAPTBL32(idx, disp) (*(int*)((char*)base + ((idx)*4 + 0x20000) + (disp)))
#define MAPTBLP(idx, disp) (*(int**)((char*)base + ((idx)*4 + 0x20000) + (disp)))
#define MAPTBL16(idx, disp) (*(s16*)((char*)base + ((idx)*2 + 0x20000) + (disp)))

int mapUnload(int mapId, int flags)
{
    u8* base;
    char* hi;
    int* e;
    int f20;
    int f10;
    u32 f80;
    int n;
    s32* lockp;
    u8 needWait;
    int i;
    int s;
    int j;
    int* st;

    base = lbl_80345E10;
    i = 0;
    needWait = 0;
    st = (int*)(*gMapEventInterface)->getCurCharPos();
    {
        int pairs[56] = {
            0x2b, 0x1, 0x2a, 0x2, 0x2f, 0x8, 0x30, 0x4,
            0x46, 0x1, 0x45, 0x2, 0x49, 0x8, 0x4a, 0x4,
            0x24, 0x20, 0x23, 0x10, 0x4e, 0x20, 0x4d, 0x10,
            0x21, 0x80, 0x20, 0x40, 0x4c, 0x80, 0x4b, 0x40,
            0x25, 0x100, 0x26, 0x200, 0x47, 0x100, 0x48, 0x200,
            0x1b, 0x1000, 0x1a, 0x2000, 0x54, 0x1000, 0x53, 0x2000,
            0xd, 0x400, 0xe, 0x800, 0x55, 0x400, 0x56, 0x800,
        };

        while (s = OSDisableInterrupts(), n = lbl_803DCC80, OSRestoreInterrupts(s), n != 0)
        {
            if (n == 0x100000)
            {
                break;
            }
            padUpdate();
            checkReset();
            if (needWait)
            {
                waitNextFrame();
            }
            loadDataFiles(0);
            dvdCheckError();
            if (needWait)
            {
                mmFreeTick(0);
                gameTextRun();
                GXFlush_(1, 0);
            }
            if (gDvdErrorPauseActive)
            {
                needWait = 1;
            }
        }

        st = (int*)(*gMapEventInterface)->getCurCharPos();
        {
            int v = *(s8*)((char*)st + 0xe);
            if (v != gObjLevelLockSlots && v != (&gObjLevelLockSlots)[1])
            {
                if ((flags & 0x10000000) && mapId != v)
                {
                    *((s8*)st + 0xe) = -1;
                }
                if ((flags & 0x20000000) && mapId == *((s8*)st + 0xe))
                {
                    *((s8*)st + 0xe) = -1;
                }
                if (flags & 0x80000000)
                {
                    *((s8*)st + 0xe) = -1;
                }
            }
        }

        e = pairs;
        f20 = flags & 0x20000000;
        f10 = flags & 0x10000000;
        f80 = flags & 0x80000000;
        lockp = &gObjLevelLockSlots;
        hi = (char*)base + 0x20000;
        for (; i < 0x38; i += 2)
        {
            if ((f20 && mapId == MAPTBL32(e[0], -0x6EC8))
                || (f10 && mapId != MAPTBL32(e[0], -0x6EC8))
                || ((flags & e[1]) && mapId == MAPTBL32(e[0], -0x6EC8)))
            {
                MAPTBL32(e[0], -0x6EC8) = -1;
            }
            {
                int idx = e[0];
                if (((int**)(hi + -0x6A28))[idx] != NULL)
                {
                    s16 v;
                    if (f80
                        || ((flags & e[1]) && mapId == ((s16*)(hi + -0x68C8))[idx])
                        || (f10 && mapId != MAPTBL16(idx, -0x68C8))
                        || (f20 && mapId == MAPTBL16(idx, -0x68C8)))
                    {
                        if (gObjLevelLockSlots != (v = MAPTBL16(idx, -0x68C8))
                            && lockp[1] != v)
                        {
                            switch (idx)
                            {
                            case 0xe:
                            case 0x1a:
                            case 0x21:
                            case 0x24:
                            case 0x2a:
                            case 0x2b:
                            case 0x2f:
                            case 0x30:
                            case 0x45:
                            case 0x46:
                            case 0x49:
                            case 0x4a:
                            case 0x4c:
                            case 0x4e:
                            case 0x53:
                            case 0x56:
                                mmSetFreeDelay(0);
                                break;
                            case 0x20:
                            case 0x23:
                            case 0x4b:
                            case 0x4d:
                                mmSetFreeDelay(0);
                                break;
                            case 0x26:
                            case 0x48:
                                mmSetFreeDelay(0);
                                for (j = 0; j < 75; j++)
                                {
                                    if (sMapFileNameIndexRemapTable[j] == MAPTBL16(e[0], -0x68C8))
                                    {
                                        break;
                                    }
                                }
                                if (j <= 0x50 && j != 0x49 && j != 0x43 && j != 5)
                                {
                                    int* slot = (int*)((char*)base + (j * 4 + 0x20000));
                                    mm_free((void*)slot[-0x6C08 / 4]);
                                    slot[-0x6C08 / 4] = 0;
                                }
                                break;
                            }
                            mm_free((void*)MAPTBL32(e[0], -0x6A28));
                            mmSetFreeDelay(2);
                            MAPTBL32(e[0], -0x6A28) = 0;
                            ((s16*)(hi + -0x68C8))[e[0]] = -1;
                            MAPTBL32(e[0], -0x6D68) = 0;
                            switch (e[0])
                            {
                            case 0x2a:
                            case 0x45:
                                mergeTableFiles((u32*)(base + 0x170e0), 0x2a, 0x45, 0x800);
                                break;
                            case 0x2f:
                            case 0x49:
                                mergeTableFiles((u32*)(base + 0x14200), 0x2f, 0x49, 0xbb8);
                                break;
                            case 0x24:
                            case 0x4e:
                                mergeTableFiles((u32*)(base + 0x10200), 0x24, 0x4e, 0x1000);
                                break;
                            case 0x21:
                            case 0x4c:
                                mergeTableFiles((u32*)(base + 0xc200), 0x21, 0x4c, 0x1000);
                                break;
                            case 0x26:
                            case 0x48:
                                mergeTableFiles((u32*)(base + 0xa200), 0x26, 0x48, 0x800);
                                break;
                            case 0x1a:
                            case 0x53:
                                mergeTableFiles((u32*)(base + 0x8200), 0x1a, 0x53, 0x800);
                                break;
                            case 0xe:
                            case 0x56:
                                mergeTableFiles((u32*)(base + 0x2c0), 0xe, 0x56, 0x1fd0);
                                break;
                            }
                        }
                    }
                }
            }
            e += 2;
        }
    }
    return 1;
}

extern char sAssetIndexOverflowError[];

int mergeTableFiles(u32* tbl, int id, int idx, int count_)
{
    u8* base = lbl_80345E10;
    int i = 0;
    int e1 = 0;
    int e2 = 0;
    int count = 0;
    int* p1;
    int* p2;
    int* src1 = MAPTBLP(id, -0x6A28);
    if (src1 == NULL || MAPTBLP(idx, -0x6A28) == NULL)
    {
        if (src1 == NULL)
        {
            e1 = 1;
        }
        if (MAPTBLP(idx, -0x6A28) == NULL)
        {
            e2 = 1;
        }
    }
    p1 = (int*)(u32)src1;
    p2 = MAPTBLP(idx, -0x6A28);
    if (tbl == (u32*)(base + 0x170e0))
    {
        count = 0x800;
    }
    else if (tbl == (u32*)(base + 0x14200))
    {
        count = 0xbb8;
    }
    else if (tbl == (u32*)(base + 0x10200))
    {
        count = 0x1000;
    }
    else if (tbl == (u32*)(base + 0xc200))
    {
        count = 0x1000;
    }
    else if (tbl == (u32*)(base + 0xa200))
    {
        count = 0x800;
    }
    else if (tbl == (u32*)(base + 0x8200))
    {
        count = 0x800;
    }
    else if (tbl == (u32*)(base + 0x2c0))
    {
        count = 0x1fd0;
    }
    if (tbl == (u32*)(base + 0x10200) || tbl == (u32*)(base + 0xc200))
    {
        int* w1 = p1;
        int* dst = (int*)tbl;
        int v;
        for (; count > 0; count--)
        {
            if (!e1 && *w1 == -1)
            {
                e1 = 1;
            }
            if (!e2 && *p2 == -1)
            {
                e2 = 1;
            }
            if (!e1 && (v = *w1, v != -1) && (v & 0x80000000))
            {
                *dst = v & 0x7fffffff;
                *dst = *dst | 0x40000000;
            }
            else if (!e2 && (v = *p2, v != -1) && (v & 0x80000000))
            {
                *dst = v;
            }
            else if (!e1 && *w1 != 0)
            {
                *dst = *w1;
            }
            else if (!e2 && *p2 != 0)
            {
                *dst = *p2;
            }
            else
            {
                *dst = 0;
            }
            w1++;
            p2++;
            dst++;
            i++;
        }
    }
    else if (tbl == (u32*)(base + 0xa200))
    {
        int* w1 = p1;
        int* dst = (int*)tbl;
        int* w2 = p2;
        int v;
        for (; count > 0; count--)
        {
            if (!e1 && (v = *w1, v != -1) && (v & 0x10000000))
            {
                *dst = v;
                if (p2 != NULL && *w2 == -1)
                {
                    e2 = 1;
                }
            }
            else if (!e2 && (v = *w2, v != -1) && (v & 0x10000000))
            {
                *dst = (v & 0xffffff) | 0x20000000;
                if (p1 != NULL && *w1 == -1)
                {
                    e1 = 1;
                }
            }
            else if (!e1 && *w1 == -1)
            {
                *dst = 0;
                e1 = 1;
            }
            else if (!e2 && *w2 == -1)
            {
                *dst = 0;
                e2 = 1;
            }
            else if (!e1 && *w1 != 0)
            {
                *dst = *w1;
            }
            else if (!e2 && *w2 != 0)
            {
                *dst = *w2;
            }
            else
            {
                *dst = 0;
            }
            w1++;
            dst++;
            w2++;
            i++;
        }
    }
    else if (tbl == (u32*)(base + 0x8200))
    {
        int* w1 = p1;
        int* dst = (int*)tbl;
        int v;
        for (; count > 0; count--)
        {
            if (!e1 && *w1 == -1)
            {
                *dst = 0;
                e1 = 1;
            }
            else if (!e2 && *p2 == -1)
            {
                *dst = 0;
                e2 = 1;
            }
            else if (!e1 && (v = *w1, v != -1) && (v & 0x80000000))
            {
                *dst = v;
            }
            else if (!e2 && (v = *p2, v != -1) && (v & 0x80000000))
            {
                *dst = (v & 0x7fffffff) | 0x20000000;
            }
            else if (!e1 && *w1 != 0)
            {
                *dst = *w1;
            }
            else if (!e2 && *p2 != 0)
            {
                *dst = *p2;
            }
            else
            {
                *dst = 0;
            }
            w1++;
            dst++;
            p2++;
            i++;
        }
    }
    else if (tbl == (u32*)(base + 0x2c0))
    {
        int* w1 = p1;
        int* dst = (int*)tbl;
        int v;
        for (; count > 0; count--)
        {
            if (!e1 && *w1 == -1)
            {
                *dst = 0;
                e1 = 1;
            }
            else if (!e2 && *p2 == -1)
            {
                *dst = 0;
                e2 = 1;
            }
            else if (!e1 && (v = *w1, v != -1) && (v & 0x80000000))
            {
                *dst = v;
            }
            else if (!e2 && (v = *p2, v != -1) && (v & 0x80000000))
            {
                *dst = (v & 0x7fffffff) | 0x20000000;
            }
            else if (!e1 && *w1 != 0)
            {
                *dst = *w1;
            }
            else if (!e2 && *p2 != 0)
            {
                *dst = *p2;
            }
            else
            {
                *dst = 0;
            }
            w1++;
            dst++;
            p2++;
            i++;
        }
    }
    else
    {
        int* w1 = p1;
        int* w2 = p2;
        int* dst = (int*)tbl;
        int v;
        for (; count > 0; count--)
        {
            if (!e1 && *w1 == -1)
            {
                e1 = 1;
            }
            if (!e2 && *w2 == -1)
            {
                e2 = 1;
            }
            if (!e1 && (v = *w1, v != -1) && (v & 0x10000000))
            {
                *dst = v;
            }
            else if (!e2 && (v = *w2, v != -1) && (v & 0x10000000))
            {
                *dst = (v & 0xffffff) | 0x20000000;
            }
            else if (!e1 && p1 != NULL)
            {
                *dst = *w1;
            }
            else if (!e2 && p2 != NULL)
            {
                *dst = *w2;
            }
            else
            {
                *dst = 0;
            }
            w1++;
            w2++;
            dst++;
            i++;
        }
    }
    {
        int last = i - 1;
        tbl[last] = 0xffffffff;
    }
    return 1;
}

#undef MAPTBL32
#undef MAPTBLP
#undef MAPTBL16

extern s32 gObjTableFileRequestFlags;

u32 loadTableFiles(void)
{
    u8* base = lbl_80345E10;
    int s = OSDisableInterrupts();
    int flags = getLoadedFileFlags();
    lbl_803DCC80;
    if ((gObjTableFileRequestFlags & 0x4) && !(flags & 0x4) && *(s32*)(base + 0x191e4) == -1)
    {
        mergeTableFiles((u32*)(base + 0x170e0), 0x2a, 0x45, 0x800);
    }
    if ((gObjTableFileRequestFlags & 0x8) && !(flags & 0x8) && *(s32*)(base + 0x19250) == -1)
    {
        mergeTableFiles((u32*)(base + 0x170e0), 0x2a, 0x45, 0x800);
    }
    if ((gObjTableFileRequestFlags & 0x40) && !(flags & 0x40) && *(s32*)(base + 0x191f8) == -1)
    {
        mergeTableFiles((u32*)(base + 0x14200), 0x2f, 0x49, 0xbb8);
    }
    if ((gObjTableFileRequestFlags & 0x80) && !(flags & 0x80) && *(s32*)(base + 0x19260) == -1)
    {
        mergeTableFiles((u32*)(base + 0x14200), 0x2f, 0x49, 0xbb8);
    }
    if ((gObjTableFileRequestFlags & 0x400) && !(flags & 0x400) && *(s32*)(base + 0x191c4) == -1)
    {
        mergeTableFiles((u32*)(base + 0x10200), 0x24, 0x4e, 0x1000);
    }
    if ((gObjTableFileRequestFlags & 0x800) && !(flags & 0x800) && *(s32*)(base + 0x1926c) == -1)
    {
        mergeTableFiles((u32*)(base + 0x10200), 0x24, 0x4e, 0x1000);
    }
    if ((gObjTableFileRequestFlags & 0x4000) && !(flags & 0x4000) && *(s32*)(base + 0x191b8) == -1)
    {
        mergeTableFiles((u32*)(base + 0xc200), 0x21, 0x4c, 0x1000);
    }
    if ((gObjTableFileRequestFlags & 0x8000) && !(flags & 0x8000) && *(s32*)(base + 0x19264) == -1)
    {
        mergeTableFiles((u32*)(base + 0xc200), 0x21, 0x4c, 0x1000);
    }
    if ((gObjTableFileRequestFlags & 0x20000) && !(flags & 0x20000) && *(s32*)(base + 0x191cc) == -1)
    {
        mergeTableFiles((u32*)(base + 0xa200), 0x26, 0x48, 0x800);
    }
    if ((gObjTableFileRequestFlags & 0x80000) && !(flags & 0x80000) && *(s32*)(base + 0x19254) == -1)
    {
        mergeTableFiles((u32*)(base + 0xa200), 0x26, 0x48, 0x800);
    }
    if ((gObjTableFileRequestFlags & 0x2000000) && !(flags & 0x2000000) && *(s32*)(base + 0x191a4) == -1)
    {
        mergeTableFiles((u32*)(base + 0x8200), 0x1a, 0x53, 0x800);
    }
    if ((gObjTableFileRequestFlags & 0x8000000) && !(flags & 0x8000000) && *(s32*)(base + 0x19288) == -1)
    {
        mergeTableFiles((u32*)(base + 0x8200), 0x1a, 0x53, 0x800);
    }
    if ((gObjTableFileRequestFlags & 0x20000000) && !(flags & 0x20000000) && *(s32*)(base + 0x1916c) == -1)
    {
        mergeTableFiles((u32*)(base + 0x2c0), 0xe, 0x56, 0x1fd0);
    }
    if ((gObjTableFileRequestFlags & 0x80000000) && !(flags & 0x80000000) && *(s32*)(base + 0x1928c) == -1)
    {
        mergeTableFiles((u32*)(base + 0x2c0), 0xe, 0x56, 0x1fd0);
    }
    gObjTableFileRequestFlags = flags;
    lbl_803DCC80 = lbl_803DCC80 ^ lbl_803DCC84;
    lbl_803DCC84 = 0;
    OSRestoreInterrupts(s);
    return lbl_803DCC80;
}

int getTableFileEntry(int fileId, int index, int* out)
{
    u8* base = lbl_80345E10;
    int count = 0;
    void* table = NULL;
    switch (fileId)
    {
    case 0x2a:
        count = 0x800;
        table = (u8*)(base + 0x10000) + 0x70e0;
        break;
    case 0x2f:
        count = 0xbb8;
        table = (u8*)(base + 0x10000) + 0x4200;
        break;
    case 0x24:
        count = 0x1000;
        table = (u8*)(base + 0x10000) + 0x200;
        break;
    case 0x21:
        count = 0x1000;
        table = (u8*)(base + 0x10000) - 0x3e00;
        break;
    case 0x50:
        table = *(void**)&base[0x19718];
        break;
    case 0x26:
        count = 0x800;
        table = (u8*)(base + 0x10000) - 0x5e00;
        break;
    case 0x1a:
        count = 0x800;
        table = (u8*)(base + 0x10000) - 0x7e00;
        break;
    case 0xe:
        count = 0x1fd0;
        table = &base[0x2c0];
        break;
    }
    if (index < 0 || index >= count)
    {
        debugPrintfxy(0x14, 0x28, sAssetIndexOverflowError);
        return 0;
    }
    if (table != NULL)
    {
        *out = ((int*)table)[index];
        return 1;
    }
    return 0;
}

f32 gObjJointMtxTemp[24] = {
    1.0f, 0.0f, 0.0f, 0.0f,
    0.0f, 1.0f, 0.0f, 0.0f,
    0.0f, 0.0f, 1.0f, 0.0f,
    0.014794691f, 1.6930165e+22f, 2.5424896e+29f, 4.6243438e+30f,
    1.6713787e-19f, 3.5253297e+09f, 13.204376f, 1.8988991e+28f,
    2.818281e+20f, 4.2326e+21f, 0.03909816f, 6.162976e-33f,
};
