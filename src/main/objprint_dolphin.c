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

u32 FUN_80043E64(u32* dstBuf, int srcIdxA, int srcIdxB);
extern u32 FUN_80003494();
extern u32 FUN_800068f4();
extern u32 FUN_80006938();
extern u32 FUN_80006940();
extern u32 FUN_80006974();
extern void* FUN_800069a8();
extern u32 FUN_800069d4();
extern u32 FUN_80006adc();
extern u32 FUN_80017550();
extern int FUN_80017558();
extern int FUN_80017570();
extern u32 FUN_8001759c();
extern u32 FUN_800175b0();
extern void FUN_800175d4(int* light, f32 x, f32 y, f32 z);
extern u32 FUN_800175fc();
extern u32 FUN_80017600();
extern u32 FUN_80017604();
extern u32 FUN_80017608();
extern u32 FUN_80017620();
extern void* FUN_80017624();
extern u32 FUN_80017700();
extern int FUN_80017730();
extern u32 FUN_80017754();

extern u32 FUN_80017778();
extern u32 FUN_80017794();
extern int FUN_8001779c();
extern u32 FUN_800177b4();
extern int FUN_80017800();
extern u32 FUN_80017814();
extern u32 FUN_80017818();
extern u32 FUN_80017824();
extern u32 FUN_8001782c();
extern u32 FUN_80017830();
extern u32 FUN_800178d0();
extern u32 FUN_800178d4();
extern u32 FUN_800178f0();
extern u32 FUN_80017914();
extern int FUN_8001792c();
extern u32 FUN_8001794c();
extern u32 FUN_8001795c();
extern u32 FUN_80017968();
extern u32 FUN_8001796c();
extern u32 FUN_80017970();
extern u32 FUN_80017978();
extern u32 FUN_80017988();
extern u32 FUN_800179c8();
extern u32 FUN_800179cc();
extern u32 FUN_80017a50();
extern u32 FUN_80017a54();
extern u32 FUN_8003bbfc();
extern u32 FUN_8003c10c();
extern u64 FUN_800443fc();
extern char FUN_80048094();
extern int FUN_800480a0();
extern u32 FUN_8004812c();
extern u32 FUN_80048178();
extern u32 FUN_80048bc4();
extern u32 FUN_80048f00();
extern u32 FUN_80049024();
extern u32 FUN_80049260();
extern u32 FUN_80049910();
extern u32 FUN_8004afc0();
extern u32 FUN_8004b41c();
extern u32 FUN_8004b8cc();
extern u32 FUN_8004b960();
extern u32 FUN_8004bc68();
extern u32 FUN_8004bd68();
extern u32 FUN_8004be30();
extern u32 FUN_8004bf28();
extern u32 FUN_8004c174();
extern u32 FUN_80051868();
extern u32 FUN_80051b04();
extern u32 FUN_80051d64();
extern u32 FUN_80051fc4();
extern u32 FUN_800523e4();
extern u32 FUN_80052500();
extern u32 FUN_8005264c();
extern u32 FUN_80052778();
extern u32 FUN_800528d0();
extern u32 FUN_80052904();
extern u32 FUN_80053078();
extern u32 FUN_800530b4();
extern u32 FUN_8005375c();
extern void newshadows_getShadowTextureTable4x8();
extern u32 FUN_8006b03c();
extern int FUN_8006f690();
extern void gxSetPeControl_ZCompLoc_(u8 zcomploc);
extern void gxSetZMode_(u8 enable, int func, u8 update);
extern void trackIntersect_drawColorBand(void);
extern void trackIntersect_getColorRgb();
extern u32 FUN_800709e4();
extern u32 FUN_80080f88();
extern u32 PlayControl();
extern u32 FUN_80243e74();
extern u32 FUN_80243e9c();
extern u32 FUN_802475b8();
extern u32 FUN_802475e4();
extern u32 FUN_80247618();
extern u32 FUN_80247a48();
extern void FUN_80247a7c(f32* m, f32 x, f32 y, f32 z);
extern u32 FUN_80247bf8();
extern u32 FUN_802570dc();
extern u32 FUN_80257b5c();
extern u32 FUN_802585d8();
extern u32 FUN_80258674();
extern u32 FUN_80258944();
extern u32 FUN_80259288();
extern u32 FUN_8025a2ec();
extern u32 FUN_8025a454();
extern u32 FUN_8025a5bc();
extern u32 FUN_8025a608();
extern u32 FUN_8025be54();
extern u32 FUN_8025be80();
extern u32 FUN_8025c1a4();
extern u32 FUN_8025c224();
extern u32 FUN_8025c2a8();
extern u32 FUN_8025c368();
extern u32 FUN_8025c428();
extern u32 FUN_8025c510();
extern u32 GXSetBlendMode();
extern u32 FUN_8025c5f0();
extern u32 FUN_8025c65c();
extern u32 FUN_8025c754();
extern u32 FUN_8025c828();
extern u32 FUN_8025ca04();
extern u32 FUN_8025ca38();
extern u32 FUN_8025cce8();
extern u32 FUN_8025d63c();
extern u32 FUN_8025d80c();
extern u32 FUN_8025d8c4();
extern u64 FUN_80286820();
extern int FUN_80286828();
extern u64 FUN_80286834();
extern u64 FUN_80286838();
extern u64 FUN_80286840();
extern u32 FUN_8028686c();
extern u32 FUN_80286874();
extern u32 FUN_80286880();
extern u32 FUN_80286884();
extern u32 FUN_8028688c();
extern double FUN_80293900();
extern u8 DAT_802cbaa8;
extern u32 DAT_802cbab1;
extern u32 DAT_802cbac0;
extern int DAT_802cc8a8;
extern u32 DAT_802cc9d4;
extern u32 DAT_80343a70;
extern u8 DAT_80346d30;
extern u8 DAT_8034ec70;
extern u8 DAT_80350c70;
extern u8 DAT_80352c70;
extern u8 DAT_80356c70;
extern u8 DAT_8035ac70;
extern u8 DAT_8035db50;
extern u8 DAT_8035fb50;
extern int DAT_8035fd08;
extern u32 DAT_80360048;
extern short DAT_803601a8;
extern u32 DAT_803601f2;
extern u32 DAT_80360236;
extern u32 DAT_80397450;
extern u32 DAT_803dc0c8;
extern u32 DAT_803dc0cc;
extern u32 DAT_803dc0d0;
extern u32 DAT_803dc0d4;
extern u32 DAT_803dc0d8;
extern u32 DAT_803dc0d9;
extern u32 DAT_803dc0dc;
extern u32 gDrCloudCageRouteDistGate;
extern u32 DAT_803dc0e1;
extern u32 DAT_803dc0e2;
extern u32 sSnowBikeVelDebugFmt;
extern u32 DAT_803dc0e8;
extern u32 gWorldObjVariantAlphaTable;
extern u32 gCMenuButtons;
extern u32 DAT_803dd8a8;
extern u32 DAT_803dd8a9;
extern u32 DAT_803dd8aa;
extern u32 gCMenuScriptedInput;
extern u32 gCMenuItemCount;
extern u32 gCMenuSelIndex;
extern u32 gCMenuSelUsedBit;
extern u8 DAT_803dd8bd;
extern s32 gGameUiBlinkTexture;
extern u32 DAT_803dd8c8;
extern u32 DAT_803dd8cc;
extern u32 DAT_803dd8d4;
extern u32 gGameUiCurHintTextMap;
extern u32 DAT_803dd8dc;
extern u8 DAT_803dd8e0;
extern int DAT_803dd8e4;
extern u32 linkFlag_803dd8f8;
extern u32 gTumbleweedBushBaseColorB;
extern u32 DAT_803df670;
extern f32 lbl_803DDA58;
extern f32 lbl_803DDA5C;
extern f32 lbl_803DF684;
extern f32 lbl_803DF69C;
extern f32 lbl_803DF6B4;
extern f32 lbl_803DF6B8;
extern f32 lbl_803DF6C8;
extern f32 lbl_803DF6D8;
extern f32 lbl_803DF6EC;
extern u32 uRam803dc214;

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

void FUN_8003df64(u32 obj, u32 owner, int* cmdStream, float* outMtx)
{
    u8 boneCount0;
    u8 boneCount1;
    u8 cmdByte1;
    u8 cmdByte2;
    u8 b0;
    u8 b1;
    u8 b2;
    u8 cmdByte0;
    int cache;
    float* srcMtx;
    u32 idx;
    u32 cursor;
    u8* cmdPtr;
    float* dstMtx;
    int tmp;
    u8* posMtxIds;
    u64 ctx;
    float localMtx[22];

    ctx = FUN_80286834();
    tmp = (int)((u64)ctx >> 0x20);
    cache = FUN_8001779c();
    if (DAT_803dd8c8 == 1)
    {
        srcMtx = (float*)FUN_8001779c();
        boneCount0 = *(u8*)(tmp + 0xf3);
        boneCount1 = *(u8*)(tmp + 0xf4);
        dstMtx = srcMtx + 0x9c0;
        FUN_80017794(0);
        for (tmp = 0; tmp < (int)((u32)boneCount0 + boneCount1); tmp = tmp + 1)
        {
            FUN_80247618(outMtx, dstMtx, srcMtx);
            dstMtx = dstMtx + 0x10;
            srcMtx = srcMtx + 0xc;
        }
        DAT_803dd8c8 = 2;
    }
    cursor = cmdStream[4];
    cmdByte0 = *(u8*)(*cmdStream + ((int)cursor >> 3));
    tmp = *cmdStream + ((int)cursor >> 3);
    cmdByte1 = *(u8*)(tmp + 1);
    cmdByte2 = *(u8*)(tmp + 2);
    cmdStream[4] = cursor + 4;
    posMtxIds = &DAT_802cbaa8;
    for (tmp = 0;
         tmp < (int)((u32)(((u32)(((u32)(u8)(cmdByte2) << 16) | (u16)(((u16)(((u16)(u8)(cmdByte1) << 8) | (u8)(cmdByte0)))))) >> (cursor & 7)) & 0xf);
         tmp = tmp + 1)
    {
        idx = cmdStream[4];
        cmdPtr = (u8*)(*cmdStream + ((int)idx >> 3));
        b0 = *cmdPtr;
        b1 = cmdPtr[1];
        b2 = cmdPtr[2];
        cmdStream[4] = idx + 8;
        idx = (u32)(((u32)(((u32)(u8)(b2) << 16) | (u16)(((u16)(((u16)(u8)(b1) << 8) | (u8)(b0)))))) >> (idx & 7)) & 0xff;
        if (DAT_803dd8c8 == 2)
        {
            FUN_8025d80c((float*)(cache + idx * 0x30), (u32) * posMtxIds);
        }
        else
        {
            srcMtx = (float*)FUN_80017970((int*)ctx, idx);
            FUN_80247618(outMtx, srcMtx, localMtx);
            FUN_8025d80c(localMtx, (u32) * posMtxIds);
        }
        posMtxIds = posMtxIds + 1;
    }
    FUN_80286880();
    return;
}

/*
 * Legacy shader-layer walker (duplicate export of the modelRenderFn_8003e98c
 * shape, kept for cross-TU linkage).  Conversion constraint: the raw
 * *(int*)(*(int*)&anim.modelInstance + 0xc) / + 0x59 spellings here and in
 * fn_8003EEEC (textureSlotDefs / textureSlotCount) are load-bearing -
 * retyping them as ObjDef field chains shifts the emitted object bytes.
 */
char fn_8003EA84(u32 obj, u32 owner, int* node, u32 phaseMask, int useDecal,
                 int extraFlags)
{
    char brightness;
    bool singleOpaque;
    u8 opaqueCount;
    u32 boneCount;
    int objPtr;
    u32* layer;
    u32* prevLayer;
    u32 texId;
    int slotDefPtr;
    char* shader;
    float* uvMtxPtr;
    int slotIdx;
    int i;
    double u;
    double v;
    u64 ctx;
    char r;
    char g;
    char b;
    char a;
    float uvMtx[13];
    u32 convHi0;
    u32 convLo0;
    u32 convHi1;
    u32 convLo1;

    ctx = FUN_80286820();
    objPtr = (int)((u64)ctx >> 0x20);
    shader = (char*)(u32)ctx;
    singleOpaque = true;
    if ((*node != 0) || (node[1] != 0))
    {
        opaqueCount = 0;
        for (i = 0; i < (int)(u32)(u8)shader[0x41];
        i = i + 1
        )
        {
            slotDefPtr = FUN_800480a0((int)shader, i);
            if ((*(u8*)(slotDefPtr + 4) & 0x80) != 0)
            {
                opaqueCount = opaqueCount + 1;
            }
        }
        if (1 < opaqueCount)
        {
            singleOpaque = false;
        }
    }
    prevLayer = 0x0;
    i = 0;
    do
    {
        if ((int)(u32)(u8)shader[0x41] <= i
        )
        {
            FUN_8028686c();
            return '\0';
        }
        layer = (u32*)FUN_800480a0((int)shader, i);
        if ((*(u8*)(layer + 1) & 0x80) == phaseMask)
        {
            if (((*(u32*)(shader + 0x3c) & 0x100000) != 0) && (i == 1))
            {
                FUN_8004bc68(*node != 0);
                FUN_8028686c();
                return '\x01';
            }
            brightness = (char)
            ((*(u8*)(objPtr + 0x37) + 1) * (u32)(u8)
            shader[0xc] >> 8
            )
            ;
            if (*layer == 0)
            {
                r = shader[4];
                g = shader[5];
                b = shader[6];
                if ((*node == 0) && (((*shader != -1 || (shader[1] != -1)) || (shader[2] != -1))))
                {
                    if (useDecal == 0)
                    {
                        if ((shader[0x40] & 0x10U) == 0)
                        {
                            a = brightness;
                            FUN_80052500(&r);
                        }
                        else
                        {
                            a = brightness;
                            FUN_800523e4();
                            if (a != -1)
                            {
                                FUN_80052778(&r);
                            }
                        }
                    }
                    else
                    {
                        *(char*)((int)&DAT_803dd8d4 + 3) = brightness;
                        a = brightness;
                        FUN_80052778((char*)&DAT_803dd8d4);
                    }
                }
                else
                {
                    a = brightness;
                    FUN_80052778(&r);
                }
            }
            else
            {
                texId = FUN_80053078(*layer);
                if (*(char*)((int)layer + 5) == '\0')
                {
                    uvMtxPtr = (float*)0x0;
                }
                else
                {
                    slotDefPtr = *(int*)(*(int*)&((GameObject*)objPtr)->anim.modelInstance + 0xc);
                    slotIdx = 0;
                    for (boneCount = ((GameObject*)objPtr)->anim.modelInstance->textureSlotCount; boneCount != 0;
                         boneCount = boneCount - 1)
                    {
                        if (*(char*)((int)layer + 5) == ((ObjTextureSlotDef*)slotDefPtr)->materialIndex)
                        {
                            texId = FUN_8005375c(texId, ((GameObject*)objPtr)->anim.textureSlots[slotIdx].textureId);
                            break;
                        }
                        slotDefPtr = (int)((ObjTextureSlotDef*)slotDefPtr + 1);
                        slotIdx = slotIdx + 1;
                    }
                    slotDefPtr = *(int*)(*(int*)&((GameObject*)objPtr)->anim.modelInstance + 0xc);
                    slotIdx = 0;
                    for (boneCount = ((GameObject*)objPtr)->anim.modelInstance->textureSlotCount; boneCount != 0;
                         boneCount = boneCount - 1)
                    {
                        if (*(char*)((int)layer + 5) == ((ObjTextureSlotDef*)slotDefPtr)->materialIndex)
                        {
                            ObjTextureRuntimeSlot* slot =
                                &((GameObject*)objPtr)->anim.textureSlots[slotIdx];
                            convLo0 = slot->offsetS ^ 0x80000000;
                            convHi0 = 0x43300000;
                            u = (double)(lbl_803DF6C8 *
                                (float)((double)(u32)convLo0));
                            convLo1 = slot->offsetT ^ 0x80000000;
                            convHi1 = 0x43300000;
                            v = (double)(lbl_803DF6C8 *
                                (float)((double)(u32)convLo1));
                            goto LAB_8003eca4;
                        }
                        slotDefPtr = (int)((ObjTextureSlotDef*)slotDefPtr + 1);
                        slotIdx = slotIdx + 1;
                    }
                    u = (double)lbl_803DF684;
                    v = u;
                LAB_8003eca4:
                    FUN_80247a48(u, v, (double)lbl_803DF684, uvMtx);
                    uvMtxPtr = uvMtx;
                }
                if (i == 0)
                {
                    if ((((*node == 0) && (node[1] == 0)) && (extraFlags == 0)) || (!singleOpaque))
                    {
                        boneCount = 0;
                        a = brightness;
                    }
                    else
                    {
                        boneCount = 8;
                        a = brightness;
                    }
                }
                else
                {
                    boneCount = *(u8*)(prevLayer + 1) & 0x7f;
                    a = -1;
                }
                r = -1;
                g = -1;
                b = -1;
                if ((*node == 0) && (((*shader != -1 || (shader[1] != -1)) || (shader[2] != -1))))
                {
                    if (useDecal == 0)
                    {
                        if ((shader[0x40] & 0x10U) == 0)
                        {
                            FUN_80051d64(texId, uvMtxPtr, boneCount, &r);
                        }
                        else
                        {
                            FUN_80051868(texId, uvMtxPtr, boneCount);
                            if (a != -1)
                            {
                                FUN_80052778(&r);
                            }
                        }
                    }
                    else
                    {
                        *(char*)((int)&DAT_803dd8d4 + 3) = a;
                        if ((shader[0x40] & 0x10U) == 0)
                        {
                            FUN_80051fc4(texId, uvMtxPtr, boneCount, &DAT_803dd8d4,
                                         (u32) * (u8*)(node + 2), 1);
                        }
                        else
                        {
                            FUN_80051b04(texId, uvMtxPtr, boneCount, &DAT_803dd8d4);
                        }
                    }
                }
                else
                {
                    FUN_80051fc4(texId, uvMtxPtr, boneCount, &r, (u32) * (u8*)(node + 2), 1);
                }
            }
        }
        i = i + 1;
        prevLayer = layer;
    }
    while (true);
}

void fn_8003EEEC(u32 objArg, u32 owner, int* node, int* cmdStream)
{
    u8 cmdByte1;
    u8 cmdByte2;
    u8 renderFlags;
    u8 cmdByte0;
    bool needsAlpha;
    u16* objPtr;
    int op;
    VtableFn* callback;
    char callbackResult;
    int* refs;
    u32* decalLayer;
    float* projMtx;
    int hdr;
    int lightCount;
    int lightSlot;
    u32 cmd;
    int light;
    int lightIdx;
    u8* lightFlags;
    u32 envTex;
    int* lightId;
    double u;
    double v;
    u64 ctx;
    u32 envColor;
    u32 matColor;
    u32 litColor;
    u32 alphaColor;
    int lightInfo;
    int lightType;
    float viewMtx[12];
    float localMtx[12];
    float worldMtx[12];
    u32 decalMtx[12];
    u32 convHi0;
    u32 convLo0;
    u32 convHi1;
    u32 convLo1;

    ctx = FUN_80286820();
    objPtr = (u16*)((u64)ctx >> 0x20);
    hdr = (int)(u32)ctx;
    needsAlpha = false;
    cmd = cmdStream[4];
    cmdByte0 = *(u8*)(*cmdStream + ((int)cmd >> 3));
    op = *cmdStream + ((int)cmd >> 3);
    cmdByte1 = *(u8*)(op + 1);
    cmdByte2 = *(u8*)(op + 2);
    cmdStream[4] = cmd + 6;
    cmd = (((u32)(((u32)(u8)(cmdByte2) << 16) | (u16)(((u16)(((u16)(u8)(cmdByte1) << 8) | (u8)(cmdByte0)))))) >> (cmd & 7)) & 0x3f;
    callback = (VtableFn*)FUN_8001795c((int)node);
    if ((callback == (VtableFn*)0x0) || (callbackResult = (*callback)(objPtr, node, cmd), callbackResult == '\0'))
    {
        op = FUN_8001792c(*node, cmd);
        refs = (int*)FUN_80017978((int)node, cmd);
        FUN_80052904();
        envTex = 0;
        if (((*refs != 0) || (refs[1] != 0)) && (*(u32*)(op + 0x34) != 0))
        {
            envTex = FUN_80053078(*(u32*)(op + 0x34));
            lightCount = DAT_803dd8dc + 1;
            if (*refs != 0)
            {
                lightCount = DAT_803dd8dc + 2;
            }
            if (refs[1] != 0)
            {
                lightCount = lightCount + 1;
            }
            envTex = FUN_8004b960(envTex, lightCount, (u32) * (u8*)(op + 0x42), *(u32*)(op + 0x24));
            envTex = envTex & 0xff;
        }
        if (*refs != 0)
        {
            FUN_8004c174(*refs, *(char*)((int)objPtr + 0xf1));
        }
        if (refs[1] == 0)
        {
            envColor = DAT_803dc0cc;
            FUN_8025c428(3, (u8*)&envColor);
        }
        else
        {
            alphaColor = DAT_803dd8d4 & 0xffffff00;
            if (*(int*)(op + 0x1c) != 0)
            {
                alphaColor = ((u32)(((u32)(0xffffff) << 8) | (u8)(*(u8*)(op + 0x22))));
            }
            matColor = alphaColor;
            FUN_8025c428(3, (u8*)&matColor);
            FUN_8004bf28(refs[1], *refs != 0, (u32) * (u8*)(op + 0x20));
            if ((char)alphaColor != '\0')
            {
                FUN_8004be30(*refs != 0);
            }
        }
        lightCount = DAT_803dd8dc;
        if (DAT_803dd8cc == '\0')
        {
            renderFlags = OBJPRINT_MODEL_DEF(objPtr)->renderFlags;
            if (((renderFlags & 4) == 0) || (*(float**)(*(int*)&((GameObject*)objPtr)->anim.modelState + 0xc) == (float*)0x0))
            {
                if ((renderFlags & 0x10) == 0)
                {
                    if ((renderFlags & 4) == 0)
                    {
                        lightId = &DAT_803dd8e4;
                        lightFlags = &DAT_803dd8e0;
                        for (lightIdx = 0; lightIdx < DAT_803dd8dc; lightIdx = lightIdx + 1)
                        {
                            light = FUN_80017570(*lightId);
                            if (light != 0)
                            {
                                FUN_80017550(*lightId, &lightType, &lightInfo);
                                if (lightType == 2)
                                {
                                    needsAlpha = true;
                                }
                                lightSlot = FUN_80017558(*lightId);
                                FUN_8004b41c(light, lightSlot, lightType, lightInfo, (u32) * lightFlags);
                            }
                            lightId = lightId + 1;
                            lightFlags = lightFlags + 1;
                        }
                    }
                }
                else
                {
                    FUN_80049024();
                    lightCount = 0;
                }
            }
            else
            {
                FUN_8004afc0(*(float**)(*(int*)&((GameObject*)objPtr)->anim.modelState + 0xc));
                lightCount = 0;
            }
        }
        else
        {
            FUN_80048bc4();
            needsAlpha = true;
            lightCount = 0;
        }
        if (envTex != 0)
        {
            FUN_8004b8cc(envTex);
        }
        if (((*(u32*)(op + 0x18) != 0) && (*(int*)(op + 0x1c) == 0)) && (refs[1] != 0))
        {
            FUN_80053078(*(u32*)(op + 0x18));
            FUN_8004bd68();
        }
        lightIdx = 0;
        if (((*(u16*)(hdr + 0xe2) & 2) != 0) && ((*(u8*)(hdr + 0x24) & 2) == 0))
        {
            lightIdx = 1;
        }
        callbackResult = fn_8003EA84((u32)(u32)objPtr, (u32)op, refs, 0x80, lightIdx, lightCount);
        if (callbackResult == '\0')
        {
            FUN_8004bc68(*refs != 0);
        }
        if ((*(u32*)(op + 0x3c) & 0x100000) != 0)
        {
            decalLayer = (u32*)FUN_800480a0(op, 1);
            light = *(int*)(*(int*)&((GameObject*)objPtr)->anim.modelInstance + 0xc);
            lightSlot = 0;
            for (envTex = (u32) * (u8*)(*(int*)&((GameObject*)objPtr)->anim.modelInstance + 0x59); envTex != 0;
                 envTex = envTex - 1)
            {
                if (*(char*)((int)decalLayer + 5) == *(char*)(light + 1))
                {
                    light = *(int*)(objPtr + 0x38) + lightSlot * 0x10;
                    convLo0 = (int)*(short*)(light + 8) ^ 0x80000000;
                    convHi0 = 0x43300000;
                    u = (double)(lbl_803DF6C8 *
                        (float)((double)(u32)convLo0));
                    convLo1 = (int)*(short*)(light + 10) ^ 0x80000000;
                    convHi1 = 0x43300000;
                    v = (double)(lbl_803DF6C8 *
                        (float)((double)(u32)convLo1));
                    goto LAB_8003f328;
                }
                light = light + 2;
                lightSlot = lightSlot + 1;
            }
            u = (double)lbl_803DF684;
            v = u;
        LAB_8003f328:
            FUN_80247a48(u, v, (double)lbl_803DF684, decalMtx);
            FUN_80053078(*decalLayer);
            FUN_80048178();
        }
        fn_8003EA84((u32)(u32)objPtr, (u32)op, refs, 0, lightIdx, lightCount);
        callbackResult = FUN_80048094();
        if ((callbackResult != '\0') && ((*(u16 *)&((GameObject *)hdr)->anim.rotY & 0x100) == 0))
        {
            trackIntersect_getColorRgb((u8*)&litColor);
            FUN_80049910(&litColor);
        }
        if ((*(u32*)(op + 0x3c) & 0x100) != 0)
        {
            projMtx = (float*)FUN_80006974();
            FUN_80017a50(objPtr, localMtx, '\0');
            FUN_80247618(projMtx, localMtx, viewMtx);
            FUN_80247618((float*)&DAT_80397450, viewMtx, worldMtx);
            FUN_8025d8c4(worldMtx, 0x24, 0);
            FUN_80049260();
        }
        if ((OBJPRINT_MODEL_DEF(objPtr)->renderFlags & 0x10) != 0)
        {
            FUN_80048f00(op);
        }
        if (((*(u8*)((int)objPtr + 0xe5) & 2) != 0) || ((*(u8*)((int)objPtr + 0xe5) & 0x10) != 0))
        {
            alphaColor = *(u32*)(objPtr + 0x76);
            FUN_8005264c((char*)&alphaColor);
        }
        if ((*(u32*)(op + 0x3c) & 0x20000) != 0)
        {
            PlayControl();
        }
        FUN_800528d0();
        callback = (VtableFn*)FUN_8001794c((int)node);
        if (callback == (VtableFn*)0x0)
        {
            cmd = 1;
            if (((*(char*)((int)objPtr + 0x37) != -1) || ((*(u32*)(op + 0x3c) & 0x40000000) != 0))
                || (needsAlpha))
            {
                FUN_8025cce8(1, 4, 5, 5);
                if ((*(u16 *)&((GameObject *)hdr)->anim.rotY & 0x400) == 0)
                {
                    if ((*(u16 *)&((GameObject *)hdr)->anim.rotY & 0x2000) == 0)
                    {
                        gxSetZMode_(1, 3, 0);
                        FUN_8025c754(7, 0, 0, 7, 0);
                    }
                    else
                    {
                        cmd = 0;
                        gxSetZMode_(1, 3, 1);
                        FUN_8025c754(4, gCMenuSelUsedBit, 0, 4, gCMenuSelUsedBit);
                    }
                }
                else
                {
                    gxSetZMode_(0, 3, 0);
                    FUN_8025c754(7, 0, 0, 7, 0);
                }
            }
            else if ((*(u32*)(op + 0x3c) & 0x400) == 0)
            {
                FUN_8025cce8(0, 1, 0, 5);
                if ((*(u16 *)&((GameObject *)hdr)->anim.rotY & 0x400) == 0)
                {
                    gxSetZMode_(1, 3, 1);
                }
                else
                {
                    gxSetZMode_(0, 3, 0);
                }
                FUN_8025c754(7, 0, 0, 7, 0);
            }
            else
            {
                FUN_8025cce8(0, 1, 0, 5);
                if ((*(u16 *)&((GameObject *)hdr)->anim.rotY & 0x400) == 0)
                {
                    gxSetZMode_(1, 3, 1);
                }
                else
                {
                    gxSetZMode_(0, 3, 0);
                }
                FUN_8025c754(4, 0x40, 0, 4, 0x40);
            }
            if ((*(u32*)(op + 0x3c) & 0x400) != 0)
            {
                cmd = 0;
            }
            gxSetPeControl_ZCompLoc_(cmd);
        }
        else
        {
            (*callback)(objPtr, node, cmd);
        }
        if ((*(u32*)(op + 0x3c) & 8) == 0)
        {
            FUN_80259288(0);
        }
        else
        {
            FUN_80259288(2);
        }
    }
    FUN_8028686c();
    return;
}

void fn_8003F8EC(u32 objArg, u32 owner, int hdr)
{
    u16* objPtr;
    int* am;
    float* mtx;
    VtableFn* callback;
    char callbackResult;
    u32 texId;
    int cmdPtr;
    u32* texEntry;
    int cmdOffset;
    u32 colorWord;
    u32 litColor;
    u32 color;
    int cmdDesc[4];
    int cmdCursor;
    float worldMtx[12];
    float localMtx[22];

    objPtr = (u16*)FUN_80286840();
    am = (int*)FUN_80017a54((int)objPtr);
    if (gCMenuButtons == 0)
    {
        FUN_80017a50(objPtr, localMtx, '\0');
    }
    else
    {
        FUN_802475e4((float*)gCMenuButtons, localMtx);
        gCMenuButtons = 0;
    }
    mtx = (float*)FUN_80006974();
    FUN_80247618(mtx, localMtx, worldMtx);
    if ((*(u16*)(am + 6) & 8) == 0)
    {
        *(u8*)(am + 0x18) = 0;
        if (((*(short*)(hdr + 0xec) == 0) || ((*(u16 *)&((GameObject *)hdr)->anim.rotY & 2) != 0)) ||
            (*(char*)(hdr + 0xf3) == '\0'))
        {
            FUN_8001796c((int)am);
            mtx = (float*)FUN_80017970(am, 0);
            FUN_802475e4((float*)&DAT_802cbac0, mtx);
            DAT_803dd8c8 = 3;
        }
        else if (gCMenuItemCount == hdr)
        {
            DAT_803dd8c8 = 1;
        }
        else
        {
            FUN_80017988(am, hdr, objPtr, &DAT_802cbac0);
            FUN_8003c10c(hdr, am);
        }
        cmdOffset = *(int*)(objPtr + 0x2a);
        if (cmdOffset != 0)
        {
            *(char*)(cmdOffset + 0xaf) = *(char*)(cmdOffset + 0xaf) + -1;
            if (*(char*)(*(int*)(objPtr + 0x2a) + 0xaf) < '\0')
            {
                *(u8*)(*(int*)(objPtr + 0x2a) + 0xaf) = 0;
            }
        }
        *(u16*)(am + 6) = *(u16*)(am + 6) | 8;
    }
    texId = (u32) * (u16*)(hdr + 0xd8) << 3;
    FUN_80006adc(cmdDesc, *(u32*)(hdr + 0xd4), texId, texId);
    if ((*(u16*)(hdr + 0xe2) & 2) == 0)
    {
        color = 0xffffff00;
    }
    else if (DAT_803dd8a8 == '\0')
    {
        FUN_80080f88((u32) * (u8*)(objPtr + 0x79), (u8*)&color, (u8*)((int)&color + 1),
                     (u8*)((int)&color + 2));
    }
    else
    {
        *(u8*)&color = *(u8*)&gGameUiCurHintTextMap;
        *(u8*)((int)&color + 1) = *(u8*)((int)&gGameUiCurHintTextMap + 1);
        *(u8*)((int)&color + 2) = *(u8*)((int)&gGameUiCurHintTextMap + 2);
        color = color << 8;
        DAT_803dd8a8 = '\0';
    }
    *(u8*)((int)&color + 3) = *(u8*)((int)objPtr + 0x37);
    callback = (VtableFn*)FUN_8001795c((int)am);
    if ((DAT_803dd8aa == '\0') || (callback != (VtableFn*)0x0))
    {
        FUN_800069d4();
        if ((callback == (VtableFn*)0x0) || (callbackResult = (*callback)(objPtr, am, 0), callbackResult == '\0'))
        {
            trackIntersect_drawColorBand();
            FUN_80052904();
            texId = FUN_80053078(*(u32*)(*(int*)(hdr + 0x38) + 0x24));
            FUN_80051fc4(texId, 0, 0, &color, 0, 0);
            callbackResult = FUN_80048094();
            if (callbackResult != '\0')
            {
                trackIntersect_getColorRgb((u8*)&litColor);
                FUN_80049910(&litColor);
            }
            FUN_800528d0();
            FUN_8025a608(4, 0, 0, 0, 0, 0, 2);
            FUN_8025a608(5, 0, 0, 0, 0, 0, 2);
            FUN_8025a5bc(0);
            DAT_803dd8aa = '\x01';
            sSnowBikeVelDebugFmt = color;
        }
    }
    else
    {
        texId = FUN_80053078(*(u32*)(*(int*)(hdr + 0x38) + 0x24));
        if (gCMenuScriptedInput != texId)
        {
            gCMenuScriptedInput = texId;
            FUN_8004812c(texId, 0);
        }
        if ((*(u8*)&sSnowBikeVelDebugFmt != *(u8*)&color) ||
            (*(u8*)((int)&sSnowBikeVelDebugFmt + 1) != *(u8*)((int)&color + 1)) ||
            (*(u8*)((int)&sSnowBikeVelDebugFmt + 2) != *(u8*)((int)&color + 2)) ||
            (*(u8*)((int)&sSnowBikeVelDebugFmt + 3) != *(u8*)((int)&color + 3)))
        {
            colorWord = color;
            FUN_8025c510(0, (u8*)&colorWord);
            sSnowBikeVelDebugFmt = color;
        }
    }
    if (gCMenuItemCount != hdr)
    {
        FUN_802585d8(9, am[(*(u16*)(am + 6) >> 1 & 1) + 7], 6);
        FUN_802585d8(0xd, *(u32*)(hdr + 0x34), 4);
        gCMenuItemCount = hdr;
    }
    FUN_8003f3b4((u32)(u32)objPtr, (u32)hdr, *(int*)(hdr + 0x38));
    cmdCursor = cmdCursor + 4;
    FUN_8003e358(hdr, *(u32*)(hdr + 0x38), cmdDesc);
    cmdCursor = cmdCursor + 4;
    FUN_8003df64((u32)hdr, (u32)am, cmdDesc, worldMtx);
    texId = cmdCursor + 4;
    cmdOffset = texId >> 3;
    cmdPtr = cmdDesc[0] + cmdOffset;
    cmdCursor = cmdCursor + 0xc;
    texEntry = (u32*)
        FUN_80017914(hdr, (((u32)(((u32)(u8)(*(u8*)(cmdPtr + 2)) << 16) | (u16)(((u16)(((u16)(u8)(*(u8*)(cmdPtr + 1)) << 8) | (u8)(*(u8*)(cmdDesc[0] + cmdOffset))))))) >>
                         (texId & 7)) & 0xff);
    FUN_8025d63c(*texEntry, (u32) * (u16*)(texEntry + 1));
    FUN_8028688c();
    return;
}

void FUN_8003f9f8(void)
{
    DAT_803dd8aa = 0;
    gCMenuScriptedInput = 0;
    gCMenuItemCount = 0;
    gCMenuSelIndex = 0;
    DAT_803dc0d4 = 0xffffffff;
    DAT_803dc0d8 = 0xff;
    DAT_803dc0d9 = 0xff;
    DAT_803dc0dc = 0xffffffff;
    gDrCloudCageRouteDistGate = 0xff;
    DAT_803dc0e1 = 0xff;
    DAT_803dc0e2 = 0xff;
    sSnowBikeVelDebugFmt = 0;
}

void fn_8003FDA8(u32 objArg, u32 owner, int hdr)
{
    bool done;
    u32 opcode;
    u32 nextCursor;
    u16* ownerIter;
    u16* objPtr;
    int* am;
    float* viewMtx;
    float* jointMtx;
    u16* rootObj;
    u32* texEntry;
    int node;
    u32 fadeLevel;
    u8* cmdPtr;
    int subNode;
    double fade;
    u64 ctx;
    u32 colorWord;
    u32 envColor;
    u32 matColor;
    u32 glowColor;
    int cmdDesc[4];
    u32 cmdCursor;
    float prevMtx[16];
    float localMtx[16];
    float worldMtx[25];

    ctx = FUN_80286838();
    objPtr = (u16*)((u64)ctx >> 0x20);
    am = (int*)FUN_80017a54((int)objPtr);
    viewMtx = (float*)FUN_80006974();
    if (gCMenuButtons == 0)
    {
        FUN_80017a50(objPtr, localMtx, '\0');
    }
    else
    {
        FUN_802475e4((float*)gCMenuButtons, localMtx);
        gCMenuButtons = 0;
    }
    if ((*(u16*)(am + 6) & 8) == 0)
    {
        done = false;
        *(u8*)(am + 0x18) = 0;
        FUN_80017968((int)am);
        if (((*(short*)(hdr + 0xec) == 0) || ((*(u16 *)&((GameObject *)hdr)->anim.rotY & 2) != 0)) ||
            (*(char*)(hdr + 0xf3) == '\0'))
        {
            FUN_8001796c((int)am);
            jointMtx = (float*)FUN_80017970(am, 0);
            FUN_802475e4(localMtx, jointMtx);
        }
        else
        {
            done = *(int *)&((GameObject *)hdr)->anim.targetObj == 0;
            if (done)
            {
                FUN_80017988(am, hdr, objPtr, localMtx);
            }
            else
            {
                FUN_802475b8(prevMtx);
                FUN_80017988(am, hdr, objPtr, prevMtx);
                FUN_800178d0(am, localMtx, (float*)&DAT_80343a70);
            }
            done = !done;
            if ((*(VtableFn**)(objPtr + 0x84) != (VtableFn*)0x0) && ((u16*)(u32)ctx == objPtr))
            {
                (**(VtableFn**)(objPtr + 0x84))(objPtr, am, localMtx);
            }
        }
        if (*(char*)(hdr + 0xf9) != '\0')
        {
            FUN_800178d4();
        }
        if (done)
        {
            if (*(char*)(am + 0x18) == '\0')
            {
                node = *(int *)&((GameObject *)hdr)->anim.velocityY;
            }
            else
            {
                node = am[(*(u16*)(am + 6) >> 1 & 1) + 7];
            }
            FUN_800179cc(&DAT_80343a70, hdr + 0x88, node, am[0x10],
                         am[(*(u16*)(am + 6) >> 1 & 1) + 7]);
            FUN_800179c8(&DAT_80343a70, hdr + 0xac, *(int *)&((GameObject *)hdr)->anim.velocityZ, am[0x11],
                         *(u8*)(hdr + 0x24) & 8);
        }
        if (*(char*)(hdr + 0xf7) == '\0')
        {
            node = *(int*)(objPtr + 0x2a);
            if (node != 0)
            {
                *(char*)(node + 0xaf) = *(char*)(node + 0xaf) + -1;
                if (*(char*)(*(int*)(objPtr + 0x2a) + 0xaf) < '\0')
                {
                    *(u8*)(*(int*)(objPtr + 0x2a) + 0xaf) = 0;
                }
            }
        }
        else
        {
            FUN_800178f0(am, hdr, objPtr, (float*)0x0, (int)(u16*)(u32)ctx);
        }
        *(u16*)(am + 6) = *(u16*)(am + 6) | 8;
    }
    FUN_8003c10c(hdr, am);
    fadeLevel = (u32) * (u16*)(hdr + 0xd8) << 3;
    FUN_80006adc(cmdDesc, *(u32*)(hdr + 0xd4), fadeLevel, fadeLevel);
    ownerIter = objPtr;
    if (*(int *)&((GameObject *)hdr)->anim.targetObj != 0)
    {
        FUN_80247618(viewMtx, localMtx, worldMtx);
        FUN_8025d80c(worldMtx, DAT_802cbab1);
    }
    do
    {
        rootObj = ownerIter;
        ownerIter = *(u16**)(rootObj + 0x62);
    }
    while (ownerIter != (u16*)0x0);
    fadeLevel = (u32) * (u8*)(*(int*)(*(int*)(rootObj + 0x32) + 0xc) + 0x65);
    if (fadeLevel == 0xff)
    {
        matColor = DAT_803dc0c8;
        FUN_8025c428(3, (u8*)&matColor);
        FUN_8025cce8(0, 1, 0, 5);
    }
    else
    {
        if (fadeLevel < 8)
        {
            glowColor = ((1 << fadeLevel) << 0x18) >> 0x10;
        }
        else
        {
            glowColor = (1 << (fadeLevel - 8)) & 0xff;
        }
        glowColor = glowColor << 0x10;
        glowColor = ((u32)(((u32)((u32)glowColor >> 8) << 8) | (u8)(0xff)));
        envColor = glowColor;
        FUN_8025c428(3, (u8*)&envColor);
        FUN_8025cce8(2, 1, 0, 7);
    }
    FUN_80258944(0);
    FUN_8025ca04(1);
    FUN_8025be54(0);
    FUN_8025c828(0, 0xff, 0xff, 4);
    FUN_8025be80(0);
    FUN_8025c1a4(0, 0xf, 0xf, 0xf, 6);
    FUN_8025c224(0, 7, 7, 7, 3);
    FUN_8025c65c(0, 0, 0);
    FUN_8025c2a8(0, 0, 0, 0, 1, 0);
    FUN_8025c368(0, 0, 0, 0, 1, 0);
    colorWord = DAT_803dc0c8;
    fade = (double)lbl_803DF684;
    FUN_8025ca38(fade, fade, fade, fade, 0, (u32*)&colorWord);
    gxSetPeControl_ZCompLoc_(1);
    FUN_8025c754(7, 0, 0, 7, 0);
    FUN_8025a608(4, 0, 0, 0, 0, 0, 2);
    FUN_8025a5bc(1);
    if ((OBJPRINT_MODEL_DEF(objPtr)->renderFlags & 4) == 0)
    {
        gxSetZMode_(0, 3, 0);
        FUN_80259288(0);
    }
    else
    {
        gxSetZMode_(1, 3, 1);
        FUN_80259288(1);
    }
    FUN_802585d8(9, am[(*(u16*)(am + 6) >> 1 & 1) + 7], 6);
    done = false;
    fadeLevel = cmdCursor;
    while (cmdCursor = fadeLevel, !done)
    {
        cmdPtr = (u8*)(cmdDesc[0] + ((int)cmdCursor >> 3));
        nextCursor = cmdCursor + 4;
        opcode = (((u32)(((u32)(u8)(cmdPtr[2]) << 16) | (u16)(((u16)(((u16)(u8)(cmdPtr[1]) << 8) | (u8)(*cmdPtr)))))) >> (cmdCursor & 7)) & 0xf;
        if (opcode == 3)
        {
            cmdCursor = nextCursor;
            FUN_80257b5c();
            if (1 < *(u8*)(hdr + 0xf3))
            {
                FUN_802570dc(0, 1);
            }
            cmdPtr = (u8*)(cmdDesc[0] + ((int)cmdCursor >> 3));
            if ((((u32)(((u32)(u8)(cmdPtr[2]) << 16) | (u16)(((u16)(((u16)(u8)(cmdPtr[1]) << 8) | (u8)(*cmdPtr)))))) >> (cmdCursor & 7) & 1) == 0)
            {
                fadeLevel = 2;
            }
            else
            {
                fadeLevel = 3;
            }
            cmdCursor = cmdCursor + 1;
            FUN_802570dc(9, fadeLevel);
            if ((*(u8*)(subNode + 0x40) & 1) != 0)
            {
                cmdCursor = cmdCursor + 1;
            }
            if ((*(u8*)(subNode + 0x40) & 2) != 0)
            {
                cmdCursor = cmdCursor + 1;
            }
            FUN_802570dc(0xb, 1);
            fadeLevel = cmdCursor + 1;
        }
        else if (opcode < 3)
        {
            if (opcode == 1)
            {
                cmdPtr = (u8*)(cmdDesc[0] + ((int)nextCursor >> 3));
                cmdCursor = cmdCursor + 10;
                subNode = FUN_8001792c(hdr,
                                      (((u32)(((u32)(u8)(cmdPtr[2]) << 16) | (u16)(((u16)(((u16)(u8)(cmdPtr[1]) << 8) | (u8)(*cmdPtr)))))) >>
                                          (nextCursor & 7)) & 0x3f);
                fadeLevel = cmdCursor;
            }
            else if (opcode != 0)
            {
                cmdPtr = (u8*)(cmdDesc[0] + ((int)nextCursor >> 3));
                cmdCursor = cmdCursor + 0xc;
                texEntry = (u32*)
                    FUN_80017914(hdr, (u32) * (u8*)(hdr + 0xf5) +
                                 ((((u32)(((u32)(u8)(cmdPtr[2]) << 16) | (u16)(((u16)(((u16)(u8)(cmdPtr[1]) << 8) | (u8)(*cmdPtr)))))) >>
                                     (nextCursor & 7)) & 0xff));
                FUN_8025d63c(*texEntry, (u32) * (u16*)(texEntry + 1));
                fadeLevel = cmdCursor;
            }
        }
        else if (opcode == 5)
        {
            done = true;
        }
        else if (opcode == 4)
        {
            cmdCursor = nextCursor;
            FUN_8003df64((u32)hdr, (u32)am, cmdDesc, viewMtx);
            fadeLevel = cmdCursor;
        }
    }
    FUN_80286884();
    return;
}

void FUN_800400ac(u32 obj, u32 owner, int model, u32 shadowMode)
{
}

void FUN_800400b0(void)
{
    u16* obj;
    int* renderNode;
    float* jointMtx;
    int jointIdx;
    int i;
    ObjDefHitVolume* volumes;
    float* outVol;
    ObjDefHitVolume* vol;

    obj = (u16*)FUN_80286838();
    volumes = ((GameObject*)obj)->anim.modelInstance->hitVolumes;
    outVol = *(float**)&((GameObject*)obj)->anim.hitVolumeTransforms;
    if ((*(u8*)((int)obj + 0xaf) & 0x28) == 0)
    {
        renderNode = (int*)FUN_80017a54((int)obj);
        vol = volumes;
        for (i = 0; i < (int)(u32)((GameObject*)obj)->anim.modelInstance->hitVolumeCount; i = i + 1)
        {
            jointIdx = vol->jointIndices[((GameObject*)obj)->anim.bankIndex];
            if (jointIdx < 0)
            {
                jointMtx = (float*)0x0;
            }
            else
            {
                jointMtx = (float*)FUN_80017970(renderNode, jointIdx);
            }
            FUN_800401a0((float*)0x0, outVol + 3, &vol->posX, volumes->flags & 0x10, obj, 0);
            FUN_800401a0(jointMtx, outVol, &vol->jointOffsetX, volumes->flags & 0x10, obj, 1);
            vol++;
            outVol = outVol + 6;
        }
    }
    FUN_80286884();
    return;
}

void FUN_800401a0(float* mtx, float* out, short* in, int flag, u16* obj,
                  int e)
{
    float outX;
    float outY;
    float outZ;
    float inX;
    float inY;
    float inZ;
    u16 rotX;
    u16 rotY;
    u16 rotZ;
    float scale;
    u32 posX;
    u32 posY;
    u32 posZ;
    float worldMtx[16];
    u32 cvtHiX;
    u32 cvtLoX;
    u32 cvtHiY;
    u32 cvtLoY;
    u32 cvtHiZ;
    u32 cvtLoZ;

    cvtLoX = (int)*in ^ 0x80000000;
    cvtHiX = 0x43300000;
    inX = (f32)(s32)
    cvtLoX;
    cvtLoY = in[1] ^ 0x80000000;
    cvtHiY = 0x43300000;
    inY = (f32)(s32)
    cvtLoY;
    cvtLoZ = in[2] ^ 0x80000000;
    cvtHiZ = 0x43300000;
    inZ = (f32)(s32)
    cvtLoZ;
    if (e != 0)
    {
        inX = inX * lbl_803DF6D8;
        inY = inY * lbl_803DF6D8;
        inZ = inZ * lbl_803DF6D8;
    }
    if (mtx == (float*)0x0)
    {
        posX = *(u32*)&((GameObject*)obj)->anim.worldPosX;
        posY = *(u32*)&((GameObject*)obj)->anim.worldPosY;
        posZ = *(u32*)&((GameObject*)obj)->anim.worldPosZ;
        if (flag == 0)
        {
            rotX = *obj;
            rotY = obj[1];
            rotZ = obj[2];
        }
        else
        {
            rotX = 0;
            rotY = 0;
            rotZ = 0;
        }
        scale = lbl_803DF69C;
        FUN_80017754(worldMtx, &rotX);
        FUN_80017778((double)inX, (double)inY, (double)inZ, worldMtx, out, out + 1,
                     out + 2);
    }
    else
    {
        if (flag == 0)
        {
            FUN_80247bf8(mtx, &inX, &outX);
            *out = outX;
            out[1] = outY;
            out[2] = outZ;
        }
        else
        {
            *out = mtx[3] + inX;
            out[1] = mtx[7] + inY;
            out[2] = mtx[0xb] + inZ;
        }
        *out = *out + lbl_803DDA58;
        out[2] = out[2] + lbl_803DDA5C;
    }
    return;
}

void FUN_8004036c(u32 mtx)
{
    gCMenuButtons = mtx;
    return;
}

void FUN_800406cc(int obj)
{
    int* renderNode;
    int model;
    int i;

    if (lbl_803DF684 == ((GameObject*)obj)->anim.rootMotionScale)
    {
        gCMenuButtons = 0;
    }
    else
    {
        renderNode = (int*)FUN_80017a54(obj);
        model = *renderNode;
        if (*(char*)(model + 0xf6) == '\0')
        {
            FUN_800400ac(obj, obj, model, 1);
        }
        else
        {
            fn_8003FDA8(obj, obj, model);
        }
        if (((GameObject*)obj)->anim.classId == 1)
        {
            model = obj;
            for (i = 0; i < (int)(u32)((GameObject*)obj)->childCount; i = i + 1)
            {
                if (*(int*)&((GameObject*)model)->childObjs[0] != 0)
                {
                    FUN_80040784(*(int*)&((GameObject*)model)->childObjs[0], obj, 1);
                }
                model = model + 4;
            }
        }
    }
    return;
}

void FUN_80040784(u32 obj, u32 owner, u32 shadowFlag)
{
    u16* child;
    int* parentAm;
    float* jointMtx;
    u16* cam;
    u16* parent;
    int jointIdx;
    int entPtr;
    int entOff;
    double in_f30;
    double dz;
    double in_f31;
    double dx;
    double in_ps30_1;
    double in_ps31_1;
    u64 pairWord;
    float posTmpX;
    u32 posTmpY;
    float posTmpZ;
    u16 rotX;
    u16 rotY;
    u16 rotZ;
    float tmpHeight;
    u32 entPosX;
    u32 entPosY;
    u32 entPosZ;
    float rot[3];
    float posX;
    u32 posY;
    float posZ;
    float jointMtxBuf[27];
    float spill18;
    float spill14;
    float spill8;
    float spill4;

    spill8 = (float)in_f31;
    spill4 = (float)in_ps31_1;
    spill18 = (float)in_f30;
    spill14 = (float)in_ps30_1;
    pairWord = FUN_80286840();
    child = (u16*)(u64)(pairWord >> 0x20);
    parent = (u16*)(u32)pairWord;
    if (lbl_803DF684 == *(float*)(child + 4))
    {
        gCMenuButtons = 0;
    }
    else
    {
        FUN_80017a54((int)child);
        parentAm = (int*)FUN_80017a54((int)parent);
        entOff = ((u16)child[0x58] & 7) * 0x18;
        entPtr = *(int*)(*(int*)(parent + 0x28) + 0x2c) + entOff;
        jointIdx = (int)*(char*)(entPtr + ((GameObject*)parent)->anim.bankIndex + 0x12);
        entPosX = *(u32*)(*(int*)(*(int*)(parent + 0x28) + 0x2c) + entOff);
        entPosY = *(u32*)(entPtr + 4);
        entPosZ = *(u32*)(entPtr + 8);
        if (jointIdx == -1)
        {
            FUN_80017a50(parent, jointMtxBuf, '\0');
            jointMtx = jointMtxBuf;
        }
        else
        {
            jointMtx = (float*)FUN_80017970(parentAm, jointIdx);
        }
        if ((OBJPRINT_MODEL_DEF(child)->renderFlags & 8) == 0)
        {
            tmpHeight = lbl_803DF69C;
            entOff = *(int*)(*(int*)(parent + 0x28) + 0x2c) + entOff;
            rotX = *(u16*)(entOff + 0xc);
            rotY = *(u16*)(entOff + 0xe);
            rotZ = *(u16*)(entOff + 0x10);
            FUN_80017700(&rotX, rot);
            FUN_80247618(jointMtx, rot, rot);
        }
        else
        {
            cam = FUN_800069a8();
            tmpHeight = *(float*)(child + 4);
            dx = (double)(*(float*)(child + 6) - *(float*)(cam + 6));
            dz = (double)(*(float*)(child + 10) - *(float*)(cam + 10));
            entOff = FUN_80017730();
            rotX = entOff + 0x8000;
            FUN_80293900((double)(float)(dx * dx + (double)(float)(dz * dz)));
            entOff = FUN_80017730();
            rotY = (u16)entOff;
            rotZ = cam[2];
            FUN_80017700(&rotX, rot);
            posTmpX = posX;
            posTmpY = posY;
            posTmpZ = posZ;
            FUN_80247bf8(jointMtx, &posTmpX, &posTmpX);
            posX = posTmpX;
            posY = posTmpY;
            posZ = posTmpZ;
        }
        if ((shadowFlag & 0xff) == 0)
        {
            *(float*)(child + 0xc) = posX + lbl_803DDA58;
            *(u32*)(child + 0xe) = posY;
            *(float*)(child + 0x10) = posZ + lbl_803DDA5C;
            if (*(int*)(child + 0x18) == 0)
            {
                *(u32*)(child + 6) = *(u32*)(child + 0xc);
                *(u32*)(child + 8) = *(u32*)(child + 0xe);
                *(u32*)(child + 10) = *(u32*)(child + 0x10);
            }
            else
            {
                FUN_800068f4((double)*(float*)(child + 0xc), (double)*(float*)(child + 0xe),
                             (double)*(float*)(child + 0x10), (float*)(child + 6),
                             (float*)(child + 8), (float*)(child + 10), *(int*)(child + 0x18));
            }
            FUN_8003bbfc(rot, child, child + 1, child + 2);
        }
        *(char*)((int)child + 0x37) =
            (char)((*(u8*)(child + 0x1b) + 1) * (u32) * (u8*)((int)parent + 0x37) >> 8);
        *(u8*)((int)child + 0xf1) = *(u8*)((int)parent + 0xf1);
        if ((child[3] & 0x4000) == 0)
        {
            gCMenuButtons = (u32)rot;
            if ((shadowFlag & 0xff) == 0)
            {
                child[0x58] = child[0x58] | 0x800;
                FUN_80040a88((int)child);
            }
            else
            {
                FUN_800406cc((int)child);
            }
        }
    }
    FUN_8028688c();
    return;
}

void FUN_80040a88(int obj)
{
    short seqId;
    int* am;
    int model;
    int sub;
    u32 shadowColor;
    int screenZ;
    int screenY;
    int screenX;
    float projZ;
    float projY;
    float projX;
    int d4;
    int d3;
    float d2;
    u32 d1[2];
    s64 shadowWidth;

    am = (int*)FUN_80017a54(obj);
    if (lbl_803DF684 == ((GameObject*)obj)->anim.rootMotionScale)
    {
        gCMenuButtons = 0;
    }
    else
    {
        model = *am;
        if ((*(u16*)(model + 2) & 0x8000) == 0)
        {
            sub = obj;
            if (*(int*)&((GameObject*)obj)->ownerObj != 0)
            {
                sub = *(int*)&((GameObject*)obj)->ownerObj;
            }
            FUN_800400ac(obj, sub, model, 0);
        }
        else
        {
            sub = obj;
            if (*(int*)&((GameObject*)obj)->ownerObj != 0)
            {
                sub = *(int*)&((GameObject*)obj)->ownerObj;
            }
            fn_8003F8EC(obj, sub, model);
        }
        model = obj;
        for (sub = 0; sub < (int)(u32)((GameObject*)obj)->childCount; sub = sub + 1)
        {
            if (*(int*)&((GameObject*)model)->childObjs[0] != 0)
            {
                FUN_80040784(*(int*)&((GameObject*)model)->childObjs[0], obj, 0);
            }
            model = model + 4;
        }
        if (((((OBJPRINT_MODEL_DEF(obj)->shadowType == 4) && (DAT_803dd8a9 == '\0')) &&
                    ((seqId = ((GameObject*)obj)->anim.seqId, seqId != 0x6a8 && (seqId != 0x6a9)))) &&
                ((seqId != 0x6aa && (seqId != 0x6ab)))) &&
            ((seqId != 0x6ac && (seqId != 0x752))))
        {
            FUN_80006940((double)(((GameObject*)obj)->anim.localPosX - lbl_803DDA58),
                         (double)((GameObject*)obj)->anim.localPosY,
                         (double)(((GameObject*)obj)->anim.localPosZ - lbl_803DDA5C),
                         (double)(((GameObject*)obj)->anim.hitboxScale * ((GameObject*)obj)->anim.
                             rootMotionScale), &projX,
                         &projY, &projZ);
            FUN_80006938((double)projX, (double)projY, (double)projZ, &screenX, &screenY,
                         &screenZ);
            model = FUN_8006f690(screenX, screenY, obj);
            if (model < screenZ)
            {
                ((ObjAnimComponent*)obj)->modelState->shadowAlphaStep = -0x20;
            }
            else
            {
                ((ObjAnimComponent*)obj)->modelState->shadowAlphaStep = 0x20;
            }
            sub = (int)((ObjAnimComponent*)obj)->modelState;
            model = ((ObjModelState*)sub)->shadowAlpha + ((ObjModelState*)sub)->shadowAlphaStep;
            if (model < 0x100)
            {
                if (model < 0)
                {
                    ((ObjModelState*)sub)->shadowAlpha = 0;
                }
                else
                {
                    ((ObjModelState*)sub)->shadowAlpha = model;
                }
            }
            else
            {
                ((ObjModelState*)sub)->shadowAlpha = 0xff;
            }
            *(u8*)((int)&DAT_803dc0e8 + 3) = ((ObjAnimComponent*)obj)->modelState->shadowAlpha;
            FUN_8006b03c(obj, d1, &d2, &d3, &d4);
            shadowColor = DAT_803dc0e8;
            shadowWidth = (s64)(int)(lbl_803DF6EC * d2);
            FUN_800709e4(d1[0], d3, d4, &shadowColor,
                         (int)(lbl_803DF6EC * d2), 1);
        }
    }
}

void FUN_80040cd0(u8 flag)
{
    DAT_803dd8a9 = flag;
    return;
}

void FUN_80040da0(void)
{
    bool done;
    int mode;
    int status;
    u32 newPtr;
    u32 delay;
    int i;
    u32* slotPtr;
    short* idTblPtr;
    int* sizePtr;
    u8* flagPtr;
    int pass;

    mode = FUN_80286828();
    done = false;
    pass = 0;
    FUN_8001782c(2);
    FUN_80243e74();
    i = gTumbleweedBushBaseColorB;
    FUN_80243e9c();
    if (i == 0)
    {
        if ((mode == 0) && (linkFlag_803dd8f8 == 0))
        {
            FUN_800530b4();
            linkFlag_803dd8f8 = 6;
        }
        else
        {
            if (mode != 0)
            {
                FUN_800177b4(1);
                i = 0;
                slotPtr = &DAT_80360048;
                idTblPtr = &DAT_803601a8;
                sizePtr = &DAT_8035fd08;
                flagPtr = &DAT_8035fb50;
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
                        if (((((*slotPtr != 0) && (*idTblPtr != -1)) && (status = FUN_80017800(*slotPtr), status == 0)
                        ) && ((mode != 2 ||
                            (((i != 0x20 && (i != 0x4b)) && ((i != 0x23 && (i != 0x4d))))
                            )))) && (newPtr = FUN_80017830(*sizePtr + 0x20, 0x7d7d7d7d), newPtr != 0))
                        {
                            FUN_80003494(newPtr, *slotPtr, *sizePtr);
                            delay = FUN_80017818(0);
                            FUN_80017814(*slotPtr);
                            *slotPtr = 0;
                            *slotPtr = newPtr;
                            FUN_80017818(delay);
                        }
                    }
                    *flagPtr = 0;
                    slotPtr = slotPtr + 1;
                    idTblPtr = idTblPtr + 1;
                    sizePtr = sizePtr + 1;
                    flagPtr = flagPtr + 1;
                    i = i + 1;
                }
                while (i < 0x58);
                FUN_800177b4(0xffffffff);
            }
            for (; (!done && (pass < 10)); pass = pass + 1)
            {
                done = true;
                i = 0;
                slotPtr = &DAT_80360048;
                idTblPtr = &DAT_803601a8;
                sizePtr = &DAT_8035fd08;
                flagPtr = &DAT_8035fb50;
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
                        if (((*slotPtr == 0) || (*idTblPtr == -1)) || (status = FUN_80017800(*slotPtr), status != 0))
                        {
                            if (((((mode != 2) && (pass != 0)) && ((*slotPtr != 0 && (*idTblPtr != -1)))) &&
                                    ((status = FUN_80017800(*slotPtr), status == 1 ||
                                        (status = FUN_80017800(*slotPtr), status == 2)))) &&
                                ((newPtr = FUN_80017824(*slotPtr), 0x2fff < newPtr &&
                                    (newPtr = FUN_80017830(*sizePtr + 0x20, 0x7d7d7d7d), newPtr != 0))))
                            {
                                status = FUN_80017800(newPtr);
                                if (status == 0)
                                {
                                    FUN_80003494(newPtr, *slotPtr, *sizePtr);
                                    delay = FUN_80017818(0);
                                    FUN_80017814(*slotPtr);
                                    *slotPtr = 0;
                                    *slotPtr = newPtr;
                                    FUN_80017818(delay);
                                    done = false;
                                }
                                else
                                {
                                    delay = FUN_80017818(0);
                                    FUN_80017814(newPtr);
                                    FUN_80017818(delay);
                                }
                            }
                        }
                        else
                        {
                            newPtr = FUN_80017830(*sizePtr + 0x20, 0x7d7d7d7d);
                            if (newPtr != 0)
                            {
                                status = *sizePtr;
                                if ((status < 210000) || (newPtr <= *slotPtr))
                                {
                                    if ((status < 210000) && (newPtr < *slotPtr))
                                    {
                                        delay = FUN_80017818(0);
                                        FUN_80017814(newPtr);
                                        FUN_80017818(delay);
                                    }
                                    else
                                    {
                                        FUN_80003494(newPtr, *slotPtr, status);
                                        delay = FUN_80017818(0);
                                        FUN_80017814(*slotPtr);
                                        *slotPtr = 0;
                                        *slotPtr = newPtr;
                                        FUN_80017818(delay);
                                        done = false;
                                    }
                                }
                                else
                                {
                                    delay = FUN_80017818(0);
                                    FUN_80017814(newPtr);
                                    FUN_80017818(delay);
                                }
                            }
                        }
                    }
                    *flagPtr = 0;
                    slotPtr = slotPtr + 1;
                    idTblPtr = idTblPtr + 1;
                    sizePtr = sizePtr + 1;
                    flagPtr = flagPtr + 1;
                    i = i + 1;
                }
                while (i < 0x58);
            }
            FUN_8001782c(0);
        }
    }
    FUN_80286874();
    return;
}

void FUN_80041c10(u64 arg1, u64 arg2, u64 arg3, u64 arg4,
                  u64 arg5, u64 arg6, u64 arg7, u64 arg8,
                  int charId)
{
    int charPos;
    u64 extraout_f1;
    u64 acc;

    if (*(short*)(&DAT_802cc9d4 + charId * 2) != -1)
    {
        charPos = (int)(*gMapEventInterface)->getCurCharPos();
        *(char*)(charPos + 0xe) = charId;
        arg1 = extraout_f1;
    }
    acc = FUN_800443fc(arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8);
    acc = FUN_800443fc(acc, arg2, arg3, arg4, arg5, arg6, arg7, arg8);
    acc = FUN_800443fc(acc, arg2, arg3, arg4, arg5, arg6, arg7, arg8);
    acc = FUN_800443fc(acc, arg2, arg3, arg4, arg5, arg6, arg7, arg8);
    acc = FUN_800443fc(acc, arg2, arg3, arg4, arg5, arg6, arg7, arg8);
    acc = FUN_800443fc(acc, arg2, arg3, arg4, arg5, arg6, arg7, arg8);
    acc = FUN_800443fc(acc, arg2, arg3, arg4, arg5, arg6, arg7, arg8);
    acc = FUN_800443fc(acc, arg2, arg3, arg4, arg5, arg6, arg7, arg8);
    acc = FUN_800443fc(acc, arg2, arg3, arg4, arg5, arg6, arg7, arg8);
    acc = FUN_800443fc(acc, arg2, arg3, arg4, arg5, arg6, arg7, arg8);
    acc = FUN_800443fc(acc, arg2, arg3, arg4, arg5, arg6, arg7, arg8);
    acc = FUN_800443fc(acc, arg2, arg3, arg4, arg5, arg6, arg7, arg8);
    acc = FUN_800443fc(acc, arg2, arg3, arg4, arg5, arg6, arg7, arg8);
    FUN_800443fc(acc, arg2, arg3, arg4, arg5, arg6, arg7, arg8);
    return;
}

int FUN_80041ff8(u64 arg1, u64 arg2, u64 arg3, u64 arg4,
                 u64 arg5, u64 arg6, u64 arg7, u64 arg8,
                 int mapId)
{
    int slot;
    int mapped;
    int charId;

    if (mapId < 0x4b)
    {
        charId = (&DAT_802cc8a8)[mapId];
    }
    else
    {
        charId = 5;
    }
    mapped = (int)*(short*)(&DAT_802cc9d4 + charId * 2);
    if (mapped != -1)
    {
        if (DAT_803601f2 == mapped)
        {
            slot = 0;
        }
        else if (DAT_80360236 == mapped)
        {
            slot = 1;
        }
        else
        {
            slot = -1;
        }
        if (slot == -1)
        {
            FUN_80041c10(arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, mapped);
            return mapped;
        }
    }
    FUN_80041c10(arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, charId);
    return charId;
}

void FUN_800427c8(void)
{
    FUN_80243e74();
    if ((gTumbleweedBushBaseColorB & 0x100000) != 0)
    {
        gTumbleweedBushBaseColorB = gTumbleweedBushBaseColorB ^ 0x100000;
    }
    FUN_80243e9c();
    return;
}

void FUN_80042800(void)
{
    FUN_80243e74();
    gTumbleweedBushBaseColorB = gTumbleweedBushBaseColorB | 0x100000;
    FUN_80243e9c();
    return;
}

u32 FUN_80042838(void)
{
    u32 flags;

    FUN_80243e74();
    flags = gTumbleweedBushBaseColorB;
    FUN_80243e9c();
    return flags;
}

int FUN_80042b9c(int val, int idx, int reset)
{
    int cur;

    if (reset == 1)
    {
        gWorldObjVariantAlphaTable = 0xfffffffe;
        uRam803dc214 = 0xfffffffe;
        return -1;
    }
    cur = (&gWorldObjVariantAlphaTable)[idx];
    if ((val != cur) && (cur != -2))
    {
        return cur;
    }
    (&gWorldObjVariantAlphaTable)[idx] = 0xfffffffe;
    return -1;
}

int FUN_80042bec(u32 val, int idx)
{
    if ((&gWorldObjVariantAlphaTable)[idx] == -2)
    {
        (&gWorldObjVariantAlphaTable)[idx] = val;
        return -1;
    }
    return (&gWorldObjVariantAlphaTable)[idx];
}

void FUN_80043030(u64 arg1, u64 arg2, u64 arg3, u64 arg4,
                  u64 arg5, u64 arg6, u64 arg7, u64 arg8)
{
}

u32 FUN_80043E64(u32* dstBuf, int srcIdxA, int srcIdxB)
{
    bool srcADone;
    bool srcBDone;
    u32* srcB;
    int writeIdx;
    int count;
    u32 val;
    u32* srcAlt;
    u32* srcA;
    u32* out;
    u32* outAlt;

    writeIdx = 0;
    srcADone = false;
    srcBDone = false;
    count = 0;
    srcA = (u32*)(&DAT_80360048)[srcIdxA];
    if (((srcA == 0x0) || ((&DAT_80360048)[srcIdxB] == 0)) &&
        (srcADone = srcA == 0x0, (&DAT_80360048)[srcIdxB] == 0))
    {
        srcBDone = true;
    }
    srcB = (u32*)(&DAT_80360048)[srcIdxB];
    if (dstBuf == (u32*)&DAT_8035db50)
    {
        count = 0x800;
    }
    else if (dstBuf == (u32*)&DAT_8035ac70)
    {
        count = 3000;
    }
    else if (dstBuf == (u32*)&DAT_80356c70)
    {
        count = 0x1000;
    }
    else if (dstBuf == (u32*)&DAT_80352c70)
    {
        count = 0x1000;
    }
    else if (dstBuf == (u32*)&DAT_80350c70)
    {
        count = 0x800;
    }
    else if (dstBuf == (u32*)&DAT_8034ec70)
    {
        count = 0x800;
    }
    else if (dstBuf == (u32*)&DAT_80346d30)
    {
        count = 0x1fd0;
    }
    out = dstBuf;
    if ((dstBuf == (u32*)&DAT_80356c70) || (dstBuf == (u32*)&DAT_80352c70))
    {
        for (; count != 0; count = count + -1)
        {
            if ((!srcADone) && (*srcA == 0xffffffff))
            {
                srcADone = true;
            }
            if ((!srcBDone) && (*srcB == 0xffffffff))
            {
                srcBDone = true;
            }
            if (((srcADone) || (val = *srcA, val == 0xffffffff)) || ((val & 0x80000000) == 0))
            {
                if (((srcBDone) || (val = *srcB, val == 0xffffffff)) || ((val & 0x80000000) == 0))
                {
                    if ((srcADone) || (*srcA == 0))
                    {
                        if ((srcBDone) || (*srcB == 0))
                        {
                            *out = 0;
                        }
                        else
                        {
                            *out = *srcB;
                        }
                    }
                    else
                    {
                        *out = *srcA;
                    }
                }
                else
                {
                    *out = val;
                }
            }
            else
            {
                *out = val & 0x7fffffff;
                *out = *out | 0x40000000;
            }
            srcA = srcA + 1;
            srcB = srcB + 1;
            writeIdx = writeIdx + 1;
            out = out + 1;
        }
    }
    else if (dstBuf == (u32*)&DAT_80350c70)
    {
        out = (u32*)&DAT_80350c70;
        srcAlt = srcA;
        outAlt = srcB;
        for (; count != 0; count = count + -1)
        {
            if (((srcADone) || (val = *srcAlt, val == 0xffffffff)) || ((val & 0x10000000) == 0))
            {
                if (((srcBDone) || (val = *outAlt, val == 0xffffffff)) || ((val & 0x10000000) == 0))
                {
                    if ((srcADone) || (*srcAlt != 0xffffffff))
                    {
                        if ((srcBDone) || (*outAlt != 0xffffffff))
                        {
                            if ((srcADone) || (*srcAlt == 0))
                            {
                                if ((srcBDone) || (*outAlt == 0))
                                {
                                    *out = 0;
                                }
                                else
                                {
                                    *out = *outAlt;
                                }
                            }
                            else
                            {
                                *out = *srcAlt;
                            }
                        }
                        else
                        {
                            *out = 0;
                            srcBDone = true;
                        }
                    }
                    else
                    {
                        *out = 0;
                        srcADone = true;
                    }
                }
                else
                {
                    *out = val & 0xffffff | 0x20000000;
                    if ((srcA != 0x0) && (*srcAlt == 0xffffffff))
                    {
                        srcADone = true;
                    }
                }
            }
            else
            {
                *out = val;
                if ((srcB != 0x0) && (*outAlt == 0xffffffff))
                {
                    srcBDone = true;
                }
            }
            srcAlt = srcAlt + 1;
            out = out + 1;
            outAlt = outAlt + 1;
            writeIdx = writeIdx + 1;
        }
    }
    else if (dstBuf == (u32*)&DAT_8034ec70)
    {
        out = (u32*)&DAT_8034ec70;
        for (; count != 0; count = count + -1)
        {
            if ((srcADone) || (*srcA != 0xffffffff))
            {
                if ((srcBDone) || (*srcB != 0xffffffff))
                {
                    if (((srcADone) || (val = *srcA, val == 0xffffffff)) || ((val & 0x80000000) == 0))
                    {
                        if (((srcBDone) || (val = *srcB, val == 0xffffffff)) || ((val & 0x80000000) == 0))
                        {
                            if ((srcADone) || (*srcA == 0))
                            {
                                if ((srcBDone) || (*srcB == 0))
                                {
                                    *out = 0;
                                }
                                else
                                {
                                    *out = *srcB;
                                }
                            }
                            else
                            {
                                *out = *srcA;
                            }
                        }
                        else
                        {
                            *out = val & 0x7fffffff | 0x20000000;
                        }
                    }
                    else
                    {
                        *out = val;
                    }
                }
                else
                {
                    *out = 0;
                    srcBDone = true;
                }
            }
            else
            {
                *out = 0;
                srcADone = true;
            }
            srcA = srcA + 1;
            out = out + 1;
            srcB = srcB + 1;
            writeIdx = writeIdx + 1;
        }
    }
    else
    {
        out = srcA;
        srcAlt = srcB;
        outAlt = dstBuf;
        if (dstBuf == (u32*)&DAT_80346d30)
        {
            out = (u32*)&DAT_80346d30;
            for (; count != 0; count = count + -1)
            {
                if ((srcADone) || (*srcA != 0xffffffff))
                {
                    if ((srcBDone) || (*srcB != 0xffffffff))
                    {
                        if (((srcADone) || (val = *srcA, val == 0xffffffff)) || ((val & 0x80000000) == 0))
                        {
                            if (((srcBDone) || (val = *srcB, val == 0xffffffff)) || ((val & 0x80000000) == 0)
                            )
                            {
                                if ((srcADone) || (*srcA == 0))
                                {
                                    if ((srcBDone) || (*srcB == 0))
                                    {
                                        *out = 0;
                                    }
                                    else
                                    {
                                        *out = *srcB;
                                    }
                                }
                                else
                                {
                                    *out = *srcA;
                                }
                            }
                            else
                            {
                                *out = val & 0x7fffffff | 0x20000000;
                            }
                        }
                        else
                        {
                            *out = val;
                        }
                    }
                    else
                    {
                        *out = 0;
                        srcBDone = true;
                    }
                }
                else
                {
                    *out = 0;
                    srcADone = true;
                }
                srcA = srcA + 1;
                out = out + 1;
                srcB = srcB + 1;
                writeIdx = writeIdx + 1;
            }
        }
        else
        {
            for (; count != 0; count = count + -1)
            {
                if ((!srcADone) && (*out == 0xffffffff))
                {
                    srcADone = true;
                }
                if ((!srcBDone) && (*srcAlt == 0xffffffff))
                {
                    srcBDone = true;
                }
                if (((srcADone) || (val = *out, val == 0xffffffff)) || ((val & 0x10000000) == 0))
                {
                    if (((srcBDone) || (val = *srcAlt, val == 0xffffffff)) || ((val & 0x10000000) == 0))
                    {
                        if ((srcADone) || (srcA == 0x0))
                        {
                            if ((srcBDone) || (srcB == 0x0))
                            {
                                *outAlt = 0;
                            }
                            else
                            {
                                *outAlt = *srcAlt;
                            }
                        }
                        else
                        {
                            *outAlt = *out;
                        }
                    }
                    else
                    {
                        *outAlt = val & 0xffffff | 0x20000000;
                    }
                }
                else
                {
                    *outAlt = val;
                }
                writeIdx = writeIdx + 1;
                out = out + 1;
                srcAlt = srcAlt + 1;
                outAlt = outAlt + 1;
            }
        }
    }
    dstBuf[writeIdx + -1] = 0xffffffff;
    return 1;
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
    if ((((GameObject*)obj)->objectFlags & 0x1000) || ((GameObject*)obj)->anim.mapEventSlot == 0x3f
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
            ((GameObject*)child)->objectFlags |= 0x800;
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
extern u8 gObjGxPosMtxIdTable[];

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
 * The legacy FUN_8003df64/fn_8003EEEC/fn_8003F8EC/fn_8003FDA8 bodies walk
 * the same stream through a raw int[5] (data at [0], cursor at [4]).
 */
typedef struct
{
    u8* data;
    int pad[3];
    int pos;
} MtxBitStream;

#pragma optimization_level 2
#pragma inline_max_size(4000)
static inline void modelLoadMtxsToGxBody(int obj, int* model, MtxBitStream* bs, f32* mtx)
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
        int count;
        int i;
        u8* tbl;
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

void modelLoadMtxsToGx(int obj, int* model, MtxBitStream* bs, f32* mtx)
{
    modelLoadMtxsToGxBody(obj, model, bs, mtx);
}
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
                if ((OBJPRINT_MODEL_DEF(model)->renderFlags & 4) || gObjShadowNear)
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
    if (OBJPRINT_MODEL_DEF(obj)->renderFlags & 4)
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
extern u8 gObjGxTexMtxIdTable[];
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
        if (player != NULL && !(((GameObject*)player)->objectFlags & 0x1000) && *(int**)&((GameObject*)cam)->anim.
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
        if (OBJPRINT_MODEL_DEF(obj)->renderFlags & 4)
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
    if (OBJPRINT_MODEL_DEF(obj)->renderFlags & 0x10)
    {
        gxTextureFn_8004d5b4(op);
    }
    {
        u8 e5 = ((GameObject*)obj)->colorFadeFlags;
        if ((e5 & 2) || (e5 & 0x10))
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
                            MAPTBL16(e[0], -0x68C8) = -1;
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
