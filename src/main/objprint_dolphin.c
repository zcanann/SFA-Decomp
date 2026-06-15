#include "main/game_object.h"
#include "main/camera_interface.h"
#include "main/effect_interfaces.h"
#include "main/mapEvent.h"
#include "main/model.h"
#include "main/object_transform.h"
#include "main/objprint_dolphin.h"
#include "main/objanim_internal.h"
#include "main/vecmath.h"

typedef struct ObjModelRenderOp
{
    u8 pad0[0x18 - 0x0];
    u32 unk18;
    u32 unk1C;
    u8 pad20[0x24 - 0x20];
    u32 unk24;
    u8 pad28[0x34 - 0x28];
    u32 unk34;
    u8 pad38[0x3C - 0x38];
    u32 unk3C;
} ObjModelRenderOp;

#define OBJPRINT_MODEL_DEF(obj) (((ObjAnimComponent *)(obj))->modelInstance)
#define OBJPRINT_ACTIVE_BANK_INDEX(obj) (((ObjAnimComponent *)(obj))->bankIndex)

undefined4 FUN_80043E64(uint* param_1, int param_2, int param_3);
extern undefined4 FUN_80003494();
extern undefined4 FUN_800068f4();
extern undefined4 FUN_80006938();
extern undefined4 FUN_80006940();
extern undefined4 FUN_80006974();
extern void* FUN_800069a8();
extern undefined4 FUN_800069d4();
extern undefined4 FUN_80006adc();
extern undefined4 FUN_80017550();
extern int FUN_80017558();
extern int FUN_80017570();
extern undefined4 FUN_8001759c();
extern undefined4 FUN_800175b0();
extern undefined4 FUN_800175d4();
extern undefined4 FUN_800175fc();
extern undefined4 FUN_80017600();
extern undefined4 FUN_80017604();
extern undefined4 FUN_80017608();
extern undefined4 FUN_80017620();
extern void* FUN_80017624();
extern undefined4 FUN_80017700();
extern int FUN_80017730();
extern undefined4 FUN_80017754();
extern u32 randomGetRange(int min, int max);
extern undefined4 FUN_80017778();
extern undefined4 FUN_80017794();
extern int FUN_8001779c();
extern undefined4 FUN_800177b4();
extern int FUN_80017800();
extern undefined4 FUN_80017814();
extern undefined4 FUN_80017818();
extern uint FUN_80017824();
extern undefined4 FUN_8001782c();
extern uint FUN_80017830();
extern undefined4 FUN_800178d0();
extern undefined4 FUN_800178d4();
extern undefined4 FUN_800178f0();
extern undefined4 FUN_80017914();
extern int FUN_8001792c();
extern undefined4 FUN_8001794c();
extern undefined4 FUN_8001795c();
extern undefined4 FUN_80017968();
extern undefined4 FUN_8001796c();
extern undefined4 FUN_80017970();
extern undefined4 FUN_80017978();
extern undefined4 FUN_80017988();
extern undefined4 FUN_800179c8();
extern undefined4 FUN_800179cc();
extern undefined4 FUN_80017a50();
extern undefined4 FUN_80017a54();
extern undefined4 FUN_8003bbfc();
extern undefined4 FUN_8003c10c();
extern undefined8 FUN_800443fc();
extern char FUN_80048094();
extern int FUN_800480a0();
extern undefined4 FUN_8004812c();
extern undefined4 FUN_80048178();
extern undefined4 FUN_80048bc4();
extern undefined4 FUN_80048f00();
extern undefined4 FUN_80049024();
extern undefined4 FUN_80049260();
extern undefined4 FUN_80049910();
extern undefined4 FUN_8004afc0();
extern undefined4 FUN_8004b41c();
extern undefined4 FUN_8004b8cc();
extern uint FUN_8004b960();
extern undefined4 FUN_8004bc68();
extern undefined4 FUN_8004bd68();
extern undefined4 FUN_8004be30();
extern undefined4 FUN_8004bf28();
extern undefined4 FUN_8004c174();
extern undefined4 FUN_80051868();
extern undefined4 FUN_80051b04();
extern undefined4 FUN_80051d64();
extern undefined4 FUN_80051fc4();
extern undefined4 FUN_800523e4();
extern undefined4 FUN_80052500();
extern undefined4 FUN_8005264c();
extern undefined4 FUN_80052778();
extern undefined4 FUN_800528d0();
extern undefined4 FUN_80052904();
extern uint FUN_80053078();
extern undefined4 FUN_800530b4();
extern uint FUN_8005375c();
extern void newshadows_getShadowTextureTable4x8();
extern undefined4 FUN_8006b03c();
extern int FUN_8006f690();
extern void gxSetPeControl_ZCompLoc_(u8 zcomploc);
extern void gxSetZMode_(u8 enable, int func, u8 update);
extern void trackIntersect_drawColorBand(void);
extern void trackIntersect_getColorRgb();
extern undefined4 FUN_800709e4();
extern undefined4 FUN_80080f88();
extern undefined4 PlayControl();
extern undefined4 FUN_80243e74();
extern undefined4 FUN_80243e9c();
extern undefined4 FUN_802475b8();
extern undefined4 FUN_802475e4();
extern undefined4 FUN_80247618();
extern undefined4 FUN_80247a48();
extern undefined4 FUN_80247a7c();
extern undefined4 FUN_80247bf8();
extern undefined4 FUN_802570dc();
extern undefined4 FUN_80257b5c();
extern undefined4 FUN_802585d8();
extern undefined4 FUN_80258674();
extern undefined4 FUN_80258944();
extern undefined4 FUN_80259288();
extern undefined4 FUN_8025a2ec();
extern undefined4 FUN_8025a454();
extern undefined4 FUN_8025a5bc();
extern undefined4 FUN_8025a608();
extern undefined4 FUN_8025be54();
extern undefined4 FUN_8025be80();
extern undefined4 FUN_8025c1a4();
extern undefined4 FUN_8025c224();
extern undefined4 FUN_8025c2a8();
extern undefined4 FUN_8025c368();
extern undefined4 FUN_8025c428();
extern undefined4 FUN_8025c510();
extern undefined4 GXSetBlendMode();
extern undefined4 FUN_8025c5f0();
extern undefined4 FUN_8025c65c();
extern undefined4 FUN_8025c754();
extern undefined4 FUN_8025c828();
extern undefined4 FUN_8025ca04();
extern undefined4 FUN_8025ca38();
extern undefined4 FUN_8025cce8();
extern undefined4 FUN_8025d63c();
extern undefined4 FUN_8025d80c();
extern undefined4 FUN_8025d8c4();
extern undefined8 FUN_80286820();
extern int FUN_80286828();
extern undefined8 FUN_80286834();
extern undefined8 FUN_80286838();
extern undefined8 FUN_80286840();
extern undefined4 FUN_8028686c();
extern undefined4 FUN_80286874();
extern undefined4 FUN_80286880();
extern undefined4 FUN_80286884();
extern undefined4 FUN_8028688c();
extern double FUN_80293900();

extern byte DAT_802cbaa8;
extern undefined4 DAT_802cbab1;
extern undefined4 DAT_802cbac0;
extern int DAT_802cc8a8;
extern undefined4 DAT_802cc9d4;
extern undefined4 DAT_80343a70;
extern undefined DAT_80346d30;
extern undefined DAT_8034ec70;
extern undefined DAT_80350c70;
extern undefined DAT_80352c70;
extern undefined DAT_80356c70;
extern undefined DAT_8035ac70;
extern undefined DAT_8035db50;
extern undefined DAT_8035fb50;
extern int DAT_8035fd08;
extern uint DAT_80360048;
extern short DAT_803601a8;
extern undefined4 DAT_803601f2;
extern undefined4 DAT_80360236;
extern undefined4 DAT_80397450;
extern undefined4 DAT_803dc0c8;
extern undefined4 DAT_803dc0cc;
extern undefined4 DAT_803dc0d0;
extern undefined4 DAT_803dc0d4;
extern undefined4 DAT_803dc0d8;
extern undefined4 DAT_803dc0d9;
extern undefined4 DAT_803dc0dc;
extern undefined4 DAT_803dc0e0;
extern undefined4 DAT_803dc0e1;
extern undefined4 DAT_803dc0e2;
extern undefined4 DAT_803dc0e4;
extern undefined4 DAT_803dc0e8;
extern undefined4 DAT_803dc210;
extern undefined4 DAT_803dd5d0;
extern undefined4 DAT_803dd8a0;
extern undefined4 DAT_803dd8a4;
extern undefined4 DAT_803dd8a8;
extern undefined4 DAT_803dd8a9;
extern undefined4 DAT_803dd8aa;
extern undefined4 DAT_803dd8ac;
extern undefined4 DAT_803dd8b0;
extern undefined4 DAT_803dd8b4;
extern undefined4 DAT_803dd8bc;
extern undefined4 DAT_803dd8bd;
extern undefined4 DAT_803dd8c4;
extern undefined4 DAT_803dd8c8;
extern undefined4 DAT_803dd8cc;
extern undefined4 DAT_803dd8d4;
extern undefined4 DAT_803dd8d8;
extern undefined4 DAT_803dd8dc;
extern byte DAT_803dd8e0;
extern int DAT_803dd8e4;
extern undefined4 DAT_803dd8f8;
extern undefined4 DAT_803dd900;
extern undefined4 DAT_803df670;
extern f64 DOUBLE_803df6c0;
extern f32 lbl_803DC074;
extern f32 lbl_803DD8B8;
extern f32 lbl_803DD8D0;
extern f32 lbl_803DDA58;
extern f32 lbl_803DDA5C;
extern f32 lbl_803DF684;
extern f32 lbl_803DF69C;
extern f32 lbl_803DF6B4;
extern f32 lbl_803DF6B8;
extern f32 lbl_803DF6C8;
extern f32 lbl_803DF6CC;
extern f32 lbl_803DF6D0;
extern f32 lbl_803DF6D4;
extern f32 lbl_803DF6D8;
extern f32 lbl_803DF6DC;
extern f32 lbl_803DF6E0;
extern f32 lbl_803DF6E4;
extern f32 lbl_803DF6E8;
extern f32 lbl_803DF6EC;
extern int iRam803dc214;
extern undefined4 uRam803dc214;

void objRenderFuzzFn_8003d6f8(void* objArg)
{
    int obj = (int)objArg;
    int* renderHandle;
    double fade;
    uint matColor;
    undefined4 envColor;
    uint ambColor;
    uint tevColor;
    undefined4 shadowParam;
    int shadowStride;
    int shadowTable;
    undefined4 savedEnvColor;
    float mtx[12];

    savedEnvColor = DAT_803df670;
    renderHandle = FUN_80017624(obj, '\0');
    if (renderHandle != (int*)0x0)
    {
        FUN_800175b0((int)renderHandle, 4);
        FUN_800175d4((double)lbl_803DF684, (double)lbl_803DF6B4, (double)lbl_803DF684, renderHandle);
        FUN_8001759c((int)renderHandle, 0xff, 0xff, 0xff, 0xff);
        FUN_80017608(0);
        FUN_80017600(2, 0, 0);
        tevColor = DAT_803dc0d0;
        FUN_8025a2ec(2, &tevColor);
        ambColor = DAT_803dc0c8;
        FUN_8025a454(2, &ambColor);
        FUN_800175fc(2, renderHandle, obj);
        FUN_80017604();
        FUN_80017620((uint)renderHandle);
    }
    envColor = savedEnvColor;
    FUN_8025c510(0, (byte*)&envColor);
    FUN_8025c5f0(0, 0x1c);
    GXSetBlendMode(0, 0xc);
    newshadows_getShadowTextureTable4x8(&shadowTable, &shadowStride, &shadowParam);
    FUN_8004812c(*(int*)(shadowTable + ((DAT_803dd8c4 >> 2) + (uint)DAT_803dd8bd * shadowStride) * 4), 0);
    FUN_80247a7c((double)lbl_803DF6B8, (double)lbl_803DF6B8, (double)lbl_803DF69C, mtx);
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
    matColor = DAT_803dc0c8;
    fade = (double)lbl_803DF684;
    FUN_8025ca38(fade, fade, fade, fade, 0, (uint3*)&matColor);
    gxSetZMode_(1, 3, 0);
    gxSetPeControl_ZCompLoc_(1);
    FUN_8025cce8(1, 4, 5, 5);
    return;
}

void FUN_8003df64(undefined4 param_1, undefined4 param_2, int* param_3, float* param_4)
{
    byte boneCount0;
    byte boneCount1;
    undefined cmdByte1;
    undefined cmdByte2;
    undefined b0;
    undefined b1;
    undefined b2;
    undefined cmdByte0;
    int cache;
    float* srcMtx;
    uint idx;
    uint cmd;
    undefined* cmdPtr;
    float* dstMtx;
    int iVar15;
    byte* tag;
    undefined8 ctx;
    float localMtx[22];

    ctx = FUN_80286834();
    iVar15 = (int)((ulonglong)ctx >> 0x20);
    cache = FUN_8001779c();
    if (DAT_803dd8c8 == 1)
    {
        srcMtx = (float*)FUN_8001779c();
        boneCount0 = *(byte*)(iVar15 + 0xf3);
        boneCount1 = *(byte*)(iVar15 + 0xf4);
        dstMtx = srcMtx + 0x9c0;
        FUN_80017794(0);
        for (iVar15 = 0; iVar15 < (int)((uint)boneCount0 + (uint)boneCount1); iVar15 = iVar15 + 1)
        {
            FUN_80247618(param_4, dstMtx, srcMtx);
            dstMtx = dstMtx + 0x10;
            srcMtx = srcMtx + 0xc;
        }
        DAT_803dd8c8 = 2;
    }
    cmd = param_3[4];
    cmdByte0 = *(undefined*)(*param_3 + ((int)cmd >> 3));
    iVar15 = *param_3 + ((int)cmd >> 3);
    cmdByte1 = *(undefined*)(iVar15 + 1);
    cmdByte2 = *(undefined*)(iVar15 + 2);
    param_3[4] = cmd + 4;
    tag = &DAT_802cbaa8;
    for (iVar15 = 0;
         iVar15 < (int)((uint3)(CONCAT12(cmdByte2, CONCAT11(cmdByte1, cmdByte0)) >> (cmd & 7)) & 0xf);
         iVar15 = iVar15 + 1)
    {
        idx = param_3[4];
        cmdPtr = (undefined*)(*param_3 + ((int)idx >> 3));
        b0 = *cmdPtr;
        b1 = cmdPtr[1];
        b2 = cmdPtr[2];
        param_3[4] = idx + 8;
        idx = (uint3)(CONCAT12(b2, CONCAT11(b1, b0)) >> (idx & 7)) & 0xff;
        if (DAT_803dd8c8 == 2)
        {
            FUN_8025d80c((float*)(cache + idx * 0x30), (uint) * tag);
        }
        else
        {
            srcMtx = (float*)FUN_80017970((int*)ctx, idx);
            FUN_80247618(param_4, srcMtx, localMtx);
            FUN_8025d80c(localMtx, (uint) * tag);
        }
        tag = tag + 1;
    }
    FUN_80286880();
    return;
}

char fn_8003EA84(undefined4 param_1, undefined4 param_2, int* node, uint phaseMask, int useDecal,
                 int extraFlags)
{
    char brightness;
    bool singleHit;
    byte hitCount;
    uint boneCount;
    int modelData;
    uint* entry;
    uint* prevEntry;
    uint texId;
    int boneEntry;
    char* desc;
    float* uvPtr;
    int boneIndex;
    int i;
    double u;
    double v;
    undefined8 ctx;
    char r;
    char g;
    char b;
    char a;
    float uvMtx[13];
    undefined4 convHi0;
    uint convLo0;
    undefined4 convHi1;
    uint convLo1;

    ctx = FUN_80286820();
    modelData = (int)((ulonglong)ctx >> 0x20);
    desc = (char*)(u32)ctx;
    singleHit = true;
    if ((*node != 0) || (node[1] != 0))
    {
        hitCount = 0;
        for (i = 0; i < (int)(uint)(byte)desc[0x41];
        i = i + 1
        )
        {
            boneEntry = FUN_800480a0((int)desc, i);
            if ((*(byte*)(boneEntry + 4) & 0x80) != 0)
            {
                hitCount = hitCount + 1;
            }
        }
        if (1 < hitCount)
        {
            singleHit = false;
        }
    }
    prevEntry = (uint*)0x0;
    i = 0;
    do
    {
        if ((int)(uint)(byte)desc[0x41] <= i
        )
        {
            FUN_8028686c();
            return '\0';
        }
        entry = (uint*)FUN_800480a0((int)desc, i);
        if ((*(byte*)(entry + 1) & 0x80) == phaseMask)
        {
            if (((*(uint*)(desc + 0x3c) & 0x100000) != 0) && (i == 1))
            {
                FUN_8004bc68(*node != 0);
                FUN_8028686c();
                return '\x01';
            }
            brightness = (char)
            ((*(byte*)(modelData + 0x37) + 1) * (uint)(byte)
            desc[0xc] >> 8
            )
            ;
            if (*entry == 0)
            {
                r = desc[4];
                g = desc[5];
                b = desc[6];
                if ((*node == 0) && (((*desc != -1 || (desc[1] != -1)) || (desc[2] != -1))))
                {
                    if (useDecal == 0)
                    {
                        if ((desc[0x40] & 0x10U) == 0)
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
                texId = FUN_80053078(*entry);
                if (*(char*)((int)entry + 5) == '\0')
                {
                    uvPtr = (float*)0x0;
                }
                else
                {
                    boneEntry = *(int*)(*(int*)(modelData + 0x50) + 0xc);
                    boneIndex = 0;
                    for (boneCount = ((GameObject*)modelData)->anim.modelInstance->textureSlotCount; boneCount != 0;
                         boneCount = boneCount - 1)
                    {
                        if (*(char*)((int)entry + 5) == ((ObjTextureSlotDef*)boneEntry)->materialIndex)
                        {
                            texId = FUN_8005375c(texId, ((GameObject*)modelData)->anim.textureSlots[boneIndex].textureId);
                            break;
                        }
                        boneEntry = (int)((ObjTextureSlotDef*)boneEntry + 1);
                        boneIndex = boneIndex + 1;
                    }
                    boneEntry = *(int*)(*(int*)(modelData + 0x50) + 0xc);
                    boneIndex = 0;
                    for (boneCount = ((GameObject*)modelData)->anim.modelInstance->textureSlotCount; boneCount != 0;
                         boneCount = boneCount - 1)
                    {
                        if (*(char*)((int)entry + 5) == ((ObjTextureSlotDef*)boneEntry)->materialIndex)
                        {
                            ObjTextureRuntimeSlot* slot =
                                &((GameObject*)modelData)->anim.textureSlots[boneIndex];
                            convLo0 = (int)slot->offsetS ^ 0x80000000;
                            convHi0 = 0x43300000;
                            u = (double)(lbl_803DF6C8 *
                                (float)((double)CONCAT44(0x43300000, convLo0) - DOUBLE_803df6c0));
                            convLo1 = (int)slot->offsetT ^ 0x80000000;
                            convHi1 = 0x43300000;
                            v = (double)(lbl_803DF6C8 *
                                (float)((double)CONCAT44(0x43300000, convLo1) - DOUBLE_803df6c0));
                            goto LAB_8003eca4;
                        }
                        boneEntry = (int)((ObjTextureSlotDef*)boneEntry + 1);
                        boneIndex = boneIndex + 1;
                    }
                    u = (double)lbl_803DF684;
                    v = u;
                LAB_8003eca4:
                    FUN_80247a48(u, v, (double)lbl_803DF684, uvMtx);
                    uvPtr = uvMtx;
                }
                if (i == 0)
                {
                    if ((((*node == 0) && (node[1] == 0)) && (extraFlags == 0)) || (!singleHit))
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
                    boneCount = *(byte*)(prevEntry + 1) & 0x7f;
                    a = -1;
                }
                r = -1;
                g = -1;
                b = -1;
                if ((*node == 0) && (((*desc != -1 || (desc[1] != -1)) || (desc[2] != -1))))
                {
                    if (useDecal == 0)
                    {
                        if ((desc[0x40] & 0x10U) == 0)
                        {
                            FUN_80051d64(texId, uvPtr, boneCount, &r);
                        }
                        else
                        {
                            FUN_80051868(texId, uvPtr, boneCount);
                            if (a != -1)
                            {
                                FUN_80052778(&r);
                            }
                        }
                    }
                    else
                    {
                        *(char*)((int)&DAT_803dd8d4 + 3) = a;
                        if ((desc[0x40] & 0x10U) == 0)
                        {
                            FUN_80051fc4(texId, uvPtr, boneCount, (char*)&DAT_803dd8d4,
                                         (uint) * (byte*)(node + 2), 1);
                        }
                        else
                        {
                            FUN_80051b04(texId, uvPtr, boneCount, (char*)&DAT_803dd8d4);
                        }
                    }
                }
                else
                {
                    FUN_80051fc4(texId, uvPtr, boneCount, &r, (uint) * (byte*)(node + 2), 1);
                }
            }
        }
        i = i + 1;
        prevEntry = entry;
    }
    while (true);
}

void fn_8003EEEC(undefined4 param_1, undefined4 param_2, int* node, int* cmdStream)
{
    undefined cmdByte1;
    undefined cmdByte2;
    byte renderFlags;
    undefined cmdByte0;
    bool needsAlpha;
    ushort* modelData;
    int subNode;
    code* callback;
    char callbackResult;
    int* hitList;
    uint* decalEntry;
    float* projMtx;
    int obj;
    int lightCount;
    int lightSlot;
    uint cmd;
    int light;
    int lightIdx;
    byte* lightFlags;
    uint texMaterial;
    int* lightId;
    double u;
    double v;
    undefined8 ctx;
    undefined4 envColor;
    uint matColor;
    undefined4 litColor;
    undefined4 alphaColor;
    int lightInfo;
    int lightType;
    float viewMtx[12];
    float localMtx[12];
    float worldMtx[12];
    undefined4 decalMtx[12];
    undefined4 convHi0;
    uint convLo0;
    undefined4 convHi1;
    uint convLo1;

    ctx = FUN_80286820();
    modelData = (ushort*)((ulonglong)ctx >> 0x20);
    obj = (int)(u32)ctx;
    needsAlpha = false;
    cmd = cmdStream[4];
    cmdByte0 = *(undefined*)(*cmdStream + ((int)cmd >> 3));
    subNode = *cmdStream + ((int)cmd >> 3);
    cmdByte1 = *(undefined*)(subNode + 1);
    cmdByte2 = *(undefined*)(subNode + 2);
    cmdStream[4] = cmd + 6;
    cmd = (CONCAT12(cmdByte2, CONCAT11(cmdByte1, cmdByte0)) >> (cmd & 7)) & 0x3f;
    callback = (code*)FUN_8001795c((int)node);
    if ((callback == (code*)0x0) || (callbackResult = (*callback)(modelData, node, cmd), callbackResult == '\0'))
    {
        subNode = FUN_8001792c(*node, cmd);
        hitList = (int*)FUN_80017978((int)node, cmd);
        FUN_80052904();
        texMaterial = 0;
        if (((*hitList != 0) || (hitList[1] != 0)) && (*(uint*)(subNode + 0x34) != 0))
        {
            texMaterial = FUN_80053078(*(uint*)(subNode + 0x34));
            lightCount = DAT_803dd8dc + 1;
            if (*hitList != 0)
            {
                lightCount = DAT_803dd8dc + 2;
            }
            if (hitList[1] != 0)
            {
                lightCount = lightCount + 1;
            }
            texMaterial = FUN_8004b960(texMaterial, lightCount, (uint) * (byte*)(subNode + 0x42), *(uint*)(subNode + 0x24));
            texMaterial = texMaterial & 0xff;
        }
        if (*hitList != 0)
        {
            FUN_8004c174(*hitList, *(char*)((int)modelData + 0xf1));
        }
        if (hitList[1] == 0)
        {
            envColor = DAT_803dc0cc;
            FUN_8025c428(3, (byte*)&envColor);
        }
        else
        {
            alphaColor = DAT_803dd8d4 & 0xffffff00;
            if (*(int*)(subNode + 0x1c) != 0)
            {
                alphaColor = CONCAT31(0xffffff, *(undefined*)(subNode + 0x22));
            }
            matColor = alphaColor;
            FUN_8025c428(3, (byte*)&matColor);
            FUN_8004bf28(hitList[1], *hitList != 0, (uint) * (byte*)(subNode + 0x20));
            if ((char)alphaColor != '\0')
            {
                FUN_8004be30(*hitList != 0);
            }
        }
        lightCount = DAT_803dd8dc;
        if (DAT_803dd8cc == '\0')
        {
            renderFlags = OBJPRINT_MODEL_DEF(modelData)->renderFlags;
            if (((renderFlags & 4) == 0) || (*(float**)(*(int*)(modelData + 0x32) + 0xc) == (float*)0x0))
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
                                FUN_8004b41c(light, lightSlot, lightType, lightInfo, (uint) * lightFlags);
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
                FUN_8004afc0(*(float**)(*(int*)(modelData + 0x32) + 0xc));
                lightCount = 0;
            }
        }
        else
        {
            FUN_80048bc4();
            needsAlpha = true;
            lightCount = 0;
        }
        if (texMaterial != 0)
        {
            FUN_8004b8cc(texMaterial);
        }
        if (((*(uint*)(subNode + 0x18) != 0) && (*(int*)(subNode + 0x1c) == 0)) && (hitList[1] != 0))
        {
            FUN_80053078(*(uint*)(subNode + 0x18));
            FUN_8004bd68();
        }
        lightIdx = 0;
        if (((*(ushort*)(obj + 0xe2) & 2) != 0) && ((*(byte*)(obj + 0x24) & 2) == 0))
        {
            lightIdx = 1;
        }
        callbackResult = fn_8003EA84((undefined4)(u32)modelData, (undefined4)subNode, hitList, 0x80, lightIdx, lightCount);
        if (callbackResult == '\0')
        {
            FUN_8004bc68(*hitList != 0);
        }
        if ((*(uint*)(subNode + 0x3c) & 0x100000) != 0)
        {
            decalEntry = (uint*)FUN_800480a0(subNode, 1);
            light = *(int*)(*(int*)(modelData + 0x28) + 0xc);
            lightSlot = 0;
            for (texMaterial = (uint) * (byte*)(*(int*)(modelData + 0x28) + 0x59); texMaterial != 0;
                 texMaterial = texMaterial - 1)
            {
                if (*(char*)((int)decalEntry + 5) == *(char*)(light + 1))
                {
                    light = *(int*)(modelData + 0x38) + lightSlot * 0x10;
                    convLo0 = (int)*(short*)(light + 8) ^ 0x80000000;
                    convHi0 = 0x43300000;
                    u = (double)(lbl_803DF6C8 *
                        (float)((double)CONCAT44(0x43300000, convLo0) - DOUBLE_803df6c0));
                    convLo1 = (int)*(short*)(light + 10) ^ 0x80000000;
                    convHi1 = 0x43300000;
                    v = (double)(lbl_803DF6C8 *
                        (float)((double)CONCAT44(0x43300000, convLo1) - DOUBLE_803df6c0));
                    goto LAB_8003f328;
                }
                light = light + 2;
                lightSlot = lightSlot + 1;
            }
            u = (double)lbl_803DF684;
            v = u;
        LAB_8003f328:
            FUN_80247a48(u, v, (double)lbl_803DF684, decalMtx);
            FUN_80053078(*decalEntry);
            FUN_80048178();
        }
        fn_8003EA84((undefined4)(u32)modelData, (undefined4)subNode, hitList, 0, lightIdx, lightCount);
        callbackResult = FUN_80048094();
        if ((callbackResult != '\0') && ((*(ushort *)&((GameObject *)obj)->anim.rotY & 0x100) == 0))
        {
            trackIntersect_getColorRgb((undefined*)&litColor);
            FUN_80049910(&litColor);
        }
        if ((*(uint*)(subNode + 0x3c) & 0x100) != 0)
        {
            projMtx = (float*)FUN_80006974();
            FUN_80017a50(modelData, localMtx, '\0');
            FUN_80247618(projMtx, localMtx, viewMtx);
            FUN_80247618((float*)&DAT_80397450, viewMtx, worldMtx);
            FUN_8025d8c4(worldMtx, 0x24, 0);
            FUN_80049260();
        }
        if ((OBJPRINT_MODEL_DEF(modelData)->renderFlags & 0x10) != 0)
        {
            FUN_80048f00(subNode);
        }
        if (((*(byte*)((int)modelData + 0xe5) & 2) != 0) || ((*(byte*)((int)modelData + 0xe5) & 0x10) != 0))
        {
            alphaColor = *(uint*)(modelData + 0x76);
            FUN_8005264c((char*)&alphaColor);
        }
        if ((*(uint*)(subNode + 0x3c) & 0x20000) != 0)
        {
            PlayControl();
        }
        FUN_800528d0();
        callback = (code*)FUN_8001794c((int)node);
        if (callback == (code*)0x0)
        {
            cmd = 1;
            if (((*(char*)((int)modelData + 0x37) != -1) || ((*(uint*)(subNode + 0x3c) & 0x40000000) != 0))
                || (needsAlpha))
            {
                FUN_8025cce8(1, 4, 5, 5);
                if ((*(ushort *)&((GameObject *)obj)->anim.rotY & 0x400) == 0)
                {
                    if ((*(ushort *)&((GameObject *)obj)->anim.rotY & 0x2000) == 0)
                    {
                        gxSetZMode_(1, 3, 0);
                        FUN_8025c754(7, 0, 0, 7, 0);
                    }
                    else
                    {
                        cmd = 0;
                        gxSetZMode_(1, 3, 1);
                        FUN_8025c754(4, (uint)DAT_803dd8bc, 0, 4, (uint)DAT_803dd8bc);
                    }
                }
                else
                {
                    gxSetZMode_(0, 3, 0);
                    FUN_8025c754(7, 0, 0, 7, 0);
                }
            }
            else if ((*(uint*)(subNode + 0x3c) & 0x400) == 0)
            {
                FUN_8025cce8(0, 1, 0, 5);
                if ((*(ushort *)&((GameObject *)obj)->anim.rotY & 0x400) == 0)
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
                if ((*(ushort *)&((GameObject *)obj)->anim.rotY & 0x400) == 0)
                {
                    gxSetZMode_(1, 3, 1);
                }
                else
                {
                    gxSetZMode_(0, 3, 0);
                }
                FUN_8025c754(4, 0x40, 0, 4, 0x40);
            }
            if ((*(uint*)(subNode + 0x3c) & 0x400) != 0)
            {
                cmd = 0;
            }
            gxSetPeControl_ZCompLoc_(cmd);
        }
        else
        {
            (*callback)(modelData, node, cmd);
        }
        if ((*(uint*)(subNode + 0x3c) & 8) == 0)
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

void fn_8003F8EC(undefined4 param_1, undefined4 param_2, int obj)
{
    ushort* modelData;
    int* renderNode;
    float* mtx;
    code* callback;
    char callbackResult;
    uint texId;
    int cmdPtr;
    undefined4* texEntry;
    int cmdOffset;
    uint colorWord;
    undefined4 litColor;
    undefined4 color;
    int cmdDesc[4];
    int cmdCursor;
    float worldMtx[12];
    float localMtx[22];

    modelData = (ushort*)FUN_80286840();
    renderNode = (int*)FUN_80017a54((int)modelData);
    if (DAT_803dd8a4 == 0)
    {
        FUN_80017a50(modelData, localMtx, '\0');
    }
    else
    {
        FUN_802475e4((float*)DAT_803dd8a4, localMtx);
        DAT_803dd8a4 = 0;
    }
    mtx = (float*)FUN_80006974();
    FUN_80247618(mtx, localMtx, worldMtx);
    if ((*(ushort*)(renderNode + 6) & 8) == 0)
    {
        *(undefined*)(renderNode + 0x18) = 0;
        if (((*(short*)(obj + 0xec) == 0) || ((*(ushort *)&((GameObject *)obj)->anim.rotY & 2) != 0)) ||
            (*(char*)(obj + 0xf3) == '\0'))
        {
            FUN_8001796c((int)renderNode);
            mtx = (float*)FUN_80017970(renderNode, 0);
            FUN_802475e4((float*)&DAT_802cbac0, mtx);
            DAT_803dd8c8 = 3;
        }
        else if (DAT_803dd8b0 == obj)
        {
            DAT_803dd8c8 = 1;
        }
        else
        {
            FUN_80017988(renderNode, obj, (int)modelData, &DAT_802cbac0);
            FUN_8003c10c(obj, renderNode);
        }
        cmdOffset = *(int*)(modelData + 0x2a);
        if (cmdOffset != 0)
        {
            *(char*)(cmdOffset + 0xaf) = *(char*)(cmdOffset + 0xaf) + -1;
            if (*(char*)(*(int*)(modelData + 0x2a) + 0xaf) < '\0')
            {
                *(undefined*)(*(int*)(modelData + 0x2a) + 0xaf) = 0;
            }
        }
        *(ushort*)(renderNode + 6) = *(ushort*)(renderNode + 6) | 8;
    }
    texId = (uint) * (ushort*)(obj + 0xd8) << 3;
    FUN_80006adc(cmdDesc, *(undefined4*)(obj + 0xd4), texId, texId);
    if ((*(ushort*)(obj + 0xe2) & 2) == 0)
    {
        color = 0xffffff00;
    }
    else if (DAT_803dd8a8 == '\0')
    {
        FUN_80080f88((uint) * (byte*)(modelData + 0x79), (byte*)&color, (byte*)((int)&color + 1),
                     (byte*)((int)&color + 2));
    }
    else
    {
        *(byte*)&color = *(byte*)&DAT_803dd8d8;
        *(byte*)((int)&color + 1) = *(byte*)((int)&DAT_803dd8d8 + 1);
        *(byte*)((int)&color + 2) = *(byte*)((int)&DAT_803dd8d8 + 2);
        color = color << 8;
        DAT_803dd8a8 = '\0';
    }
    *(undefined*)((int)&color + 3) = *(undefined*)((int)modelData + 0x37);
    callback = (code*)FUN_8001795c((int)renderNode);
    if ((DAT_803dd8aa == '\0') || (callback != (code*)0x0))
    {
        FUN_800069d4();
        if ((callback == (code*)0x0) || (callbackResult = (*callback)(modelData, renderNode, 0), callbackResult == '\0'))
        {
            trackIntersect_drawColorBand();
            FUN_80052904();
            texId = FUN_80053078(*(uint*)(*(int*)(obj + 0x38) + 0x24));
            FUN_80051fc4(texId, 0, 0, (char*)&color, 0, 0);
            callbackResult = FUN_80048094();
            if (callbackResult != '\0')
            {
                trackIntersect_getColorRgb((undefined*)&litColor);
                FUN_80049910(&litColor);
            }
            FUN_800528d0();
            FUN_8025a608(4, 0, 0, 0, 0, 0, 2);
            FUN_8025a608(5, 0, 0, 0, 0, 0, 2);
            FUN_8025a5bc(0);
            DAT_803dd8aa = '\x01';
            DAT_803dc0e4 = color;
        }
    }
    else
    {
        texId = FUN_80053078(*(uint*)(*(int*)(obj + 0x38) + 0x24));
        if (DAT_803dd8ac != texId)
        {
            DAT_803dd8ac = texId;
            FUN_8004812c(texId, 0);
        }
        if ((*(byte*)&DAT_803dc0e4 != *(byte*)&color) ||
            (*(byte*)((int)&DAT_803dc0e4 + 1) != *(byte*)((int)&color + 1)) ||
            (*(byte*)((int)&DAT_803dc0e4 + 2) != *(byte*)((int)&color + 2)) ||
            (*(byte*)((int)&DAT_803dc0e4 + 3) != *(byte*)((int)&color + 3)))
        {
            colorWord = color;
            FUN_8025c510(0, (byte*)&colorWord);
            DAT_803dc0e4 = color;
        }
    }
    if (DAT_803dd8b0 != obj)
    {
        FUN_802585d8(9, renderNode[(*(ushort*)(renderNode + 6) >> 1 & 1) + 7], 6);
        FUN_802585d8(0xd, *(uint*)(obj + 0x34), 4);
        DAT_803dd8b0 = obj;
    }
    FUN_8003f3b4((undefined4)(u32)modelData, (undefined4)obj, *(int*)(obj + 0x38));
    cmdCursor = cmdCursor + 4;
    FUN_8003e358(obj, *(undefined4*)(obj + 0x38), cmdDesc);
    cmdCursor = cmdCursor + 4;
    FUN_8003df64((undefined4)obj, (undefined4)renderNode, cmdDesc, worldMtx);
    texId = cmdCursor + 4;
    cmdOffset = (int)texId >> 3;
    cmdPtr = cmdDesc[0] + cmdOffset;
    cmdCursor = cmdCursor + 0xc;
    texEntry = (undefined4*)
        FUN_80017914(obj, (CONCAT12(*(undefined*)(cmdPtr + 2),
                                        CONCAT11(*(undefined*)(cmdPtr + 1),
                                                 *(undefined*)(cmdDesc[0] + cmdOffset))) >>
                         (texId & 7)) & 0xff);
    FUN_8025d63c(*texEntry, (uint) * (ushort*)(texEntry + 1));
    FUN_8028688c();
    return;
}

void FUN_8003f9f8(void)
{
    DAT_803dd8aa = 0;
    DAT_803dd8ac = 0;
    DAT_803dd8b0 = 0;
    DAT_803dd8b4 = 0;
    DAT_803dc0d4 = 0xffffffff;
    DAT_803dc0d8 = 0xff;
    DAT_803dc0d9 = 0xff;
    DAT_803dc0dc = 0xffffffff;
    DAT_803dc0e0 = 0xff;
    DAT_803dc0e1 = 0xff;
    DAT_803dc0e2 = 0xff;
    DAT_803dc0e4 = 0;
}

void fn_8003FDA8(undefined4 param_1, undefined4 param_2, int obj)
{
    bool done;
    uint opcode;
    uint nextCursor;
    ushort* childNode;
    ushort* modelData;
    int* renderNode;
    float* viewMtx;
    float* jointMtx;
    ushort* leafNode;
    undefined4* texEntry;
    int node;
    uint fadeLevel;
    undefined* cmdPtr;
    int subNode;
    double fade;
    undefined8 ctx;
    uint colorWord;
    undefined4 envColor;
    undefined4 matColor;
    undefined4 glowColor;
    int cmdDesc[4];
    uint cmdCursor;
    float prevMtx[16];
    float localMtx[16];
    float worldMtx[25];

    ctx = FUN_80286838();
    modelData = (ushort*)((ulonglong)ctx >> 0x20);
    renderNode = (int*)FUN_80017a54((int)modelData);
    viewMtx = (float*)FUN_80006974();
    if (DAT_803dd8a4 == 0)
    {
        FUN_80017a50(modelData, localMtx, '\0');
    }
    else
    {
        FUN_802475e4((float*)DAT_803dd8a4, localMtx);
        DAT_803dd8a4 = 0;
    }
    if ((*(ushort*)(renderNode + 6) & 8) == 0)
    {
        done = false;
        *(undefined*)(renderNode + 0x18) = 0;
        FUN_80017968((int)renderNode);
        if (((*(short*)(obj + 0xec) == 0) || ((*(ushort *)&((GameObject *)obj)->anim.rotY & 2) != 0)) ||
            (*(char*)(obj + 0xf3) == '\0'))
        {
            FUN_8001796c((int)renderNode);
            jointMtx = (float*)FUN_80017970(renderNode, 0);
            FUN_802475e4(localMtx, jointMtx);
        }
        else
        {
            done = *(int *)&((GameObject *)obj)->anim.targetObj == 0;
            if (done)
            {
                FUN_80017988(renderNode, obj, (int)modelData, localMtx);
            }
            else
            {
                FUN_802475b8(prevMtx);
                FUN_80017988(renderNode, obj, (int)modelData, prevMtx);
                FUN_800178d0(renderNode, localMtx, (float*)&DAT_80343a70);
            }
            done = !done;
            if ((*(code**)(modelData + 0x84) != (code*)0x0) && ((ushort*)(u32)ctx == modelData))
            {
                (**(code**)(modelData + 0x84))(modelData, renderNode, localMtx);
            }
        }
        if (*(char*)(obj + 0xf9) != '\0')
        {
            FUN_800178d4();
        }
        if (done)
        {
            if (*(char*)(renderNode + 0x18) == '\0')
            {
                node = *(int *)&((GameObject *)obj)->anim.velocityY;
            }
            else
            {
                node = renderNode[(*(ushort*)(renderNode + 6) >> 1 & 1) + 7];
            }
            FUN_800179cc(&DAT_80343a70, obj + 0x88, node, (int*)renderNode[0x10],
                         renderNode[(*(ushort*)(renderNode + 6) >> 1 & 1) + 7]);
            FUN_800179c8(&DAT_80343a70, obj + 0xac, *(int *)&((GameObject *)obj)->anim.velocityZ, (uint*)renderNode[0x11],
                         *(byte*)(obj + 0x24) & 8);
        }
        if (*(char*)(obj + 0xf7) == '\0')
        {
            node = *(int*)(modelData + 0x2a);
            if (node != 0)
            {
                *(char*)(node + 0xaf) = *(char*)(node + 0xaf) + -1;
                if (*(char*)(*(int*)(modelData + 0x2a) + 0xaf) < '\0')
                {
                    *(undefined*)(*(int*)(modelData + 0x2a) + 0xaf) = 0;
                }
            }
        }
        else
        {
            FUN_800178f0(renderNode, obj, (int)modelData, (float*)0x0, (int)(ushort*)(u32)ctx);
        }
        *(ushort*)(renderNode + 6) = *(ushort*)(renderNode + 6) | 8;
    }
    FUN_8003c10c(obj, renderNode);
    fadeLevel = (uint) * (ushort*)(obj + 0xd8) << 3;
    FUN_80006adc(cmdDesc, *(undefined4*)(obj + 0xd4), fadeLevel, fadeLevel);
    childNode = modelData;
    if (*(int *)&((GameObject *)obj)->anim.targetObj != 0)
    {
        FUN_80247618(viewMtx, localMtx, worldMtx);
        FUN_8025d80c(worldMtx, (uint)DAT_802cbab1);
    }
    do
    {
        leafNode = childNode;
        childNode = *(ushort**)(leafNode + 0x62);
    }
    while (childNode != (ushort*)0x0);
    fadeLevel = (uint) * (byte*)(*(int*)(*(int*)(leafNode + 0x32) + 0xc) + 0x65);
    if (fadeLevel == 0xff)
    {
        matColor = DAT_803dc0c8;
        FUN_8025c428(3, (byte*)&matColor);
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
        glowColor = CONCAT31((u32)glowColor >> 8, 0xff);
        envColor = glowColor;
        FUN_8025c428(3, (byte*)&envColor);
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
    FUN_8025ca38(fade, fade, fade, fade, 0, (uint3*)&colorWord);
    gxSetPeControl_ZCompLoc_(1);
    FUN_8025c754(7, 0, 0, 7, 0);
    FUN_8025a608(4, 0, 0, 0, 0, 0, 2);
    FUN_8025a5bc(1);
    if ((OBJPRINT_MODEL_DEF(modelData)->renderFlags & 4) == 0)
    {
        gxSetZMode_(0, 3, 0);
        FUN_80259288(0);
    }
    else
    {
        gxSetZMode_(1, 3, 1);
        FUN_80259288(1);
    }
    FUN_802585d8(9, renderNode[(*(ushort*)(renderNode + 6) >> 1 & 1) + 7], 6);
    done = false;
    fadeLevel = cmdCursor;
    while (cmdCursor = fadeLevel, !done)
    {
        cmdPtr = (undefined*)(cmdDesc[0] + ((int)cmdCursor >> 3));
        nextCursor = cmdCursor + 4;
        opcode = (CONCAT12(cmdPtr[2], CONCAT11(cmdPtr[1], *cmdPtr)) >> (cmdCursor & 7)) & 0xf;
        if (opcode == 3)
        {
            cmdCursor = nextCursor;
            FUN_80257b5c();
            if (1 < *(byte*)(obj + 0xf3))
            {
                FUN_802570dc(0, 1);
            }
            cmdPtr = (undefined*)(cmdDesc[0] + ((int)cmdCursor >> 3));
            if ((CONCAT12(cmdPtr[2], CONCAT11(cmdPtr[1], *cmdPtr)) >> (cmdCursor & 7) & 1) == 0)
            {
                fadeLevel = 2;
            }
            else
            {
                fadeLevel = 3;
            }
            cmdCursor = cmdCursor + 1;
            FUN_802570dc(9, fadeLevel);
            if ((*(byte*)(subNode + 0x40) & 1) != 0)
            {
                cmdCursor = cmdCursor + 1;
            }
            if ((*(byte*)(subNode + 0x40) & 2) != 0)
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
                cmdPtr = (undefined*)(cmdDesc[0] + ((int)nextCursor >> 3));
                cmdCursor = cmdCursor + 10;
                subNode = FUN_8001792c(obj,
                                      (CONCAT12(cmdPtr[2], CONCAT11(cmdPtr[1], *cmdPtr)) >>
                                          (nextCursor & 7)) & 0x3f);
                fadeLevel = cmdCursor;
            }
            else if (opcode != 0)
            {
                cmdPtr = (undefined*)(cmdDesc[0] + ((int)nextCursor >> 3));
                cmdCursor = cmdCursor + 0xc;
                texEntry = (undefined4*)
                    FUN_80017914(obj, (uint) * (byte*)(obj + 0xf5) +
                                 ((CONCAT12(cmdPtr[2], CONCAT11(cmdPtr[1], *cmdPtr)) >>
                                     (nextCursor & 7)) & 0xff));
                FUN_8025d63c(*texEntry, (uint) * (ushort*)(texEntry + 1));
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
            FUN_8003df64((undefined4)obj, (undefined4)renderNode, cmdDesc, viewMtx);
            fadeLevel = cmdCursor;
        }
    }
    FUN_80286884();
    return;
}

void FUN_800400ac(undefined4 obj, undefined4 owner, int model, uint shadowMode)
{
}

void FUN_800400b0(void)
{
    ushort* obj;
    int* renderNode;
    float* jointMtx;
    int jointIdx;
    int i;
    ObjDefHitVolume* volumes;
    float* outVol;
    ObjDefHitVolume* vol;

    obj = (ushort*)FUN_80286838();
    volumes = ((GameObject*)obj)->anim.modelInstance->hitVolumes;
    outVol = *(float**)(obj + 0x3a);
    if ((*(byte*)((int)obj + 0xaf) & 0x28) == 0)
    {
        renderNode = (int*)FUN_80017a54((int)obj);
        vol = volumes;
        for (i = 0; i < (int)(uint)((GameObject*)obj)->anim.modelInstance->hitVolumeCount; i = i + 1)
        {
            jointIdx = (int)vol->jointIndices[((GameObject*)obj)->anim.bankIndex];
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

void FUN_800401a0(float* mtx, float* out, short* in, int flag, ushort* obj,
                  int e)
{
    float local_98;
    float local_94;
    float local_90;
    float local_8c;
    float local_88;
    float local_84;
    ushort local_80;
    ushort local_7e;
    ushort local_7c;
    float local_78;
    undefined4 local_74;
    undefined4 local_70;
    undefined4 local_6c;
    float afStack_68[16];
    undefined4 local_28;
    uint uStack_24;
    undefined4 local_20;
    uint uStack_1c;
    undefined4 local_18;
    uint uStack_14;

    uStack_24 = (int)*in ^ 0x80000000;
    local_28 = 0x43300000;
    local_8c = (f32)(s32)
    uStack_24;
    uStack_1c = (int)in[1] ^ 0x80000000;
    local_20 = 0x43300000;
    local_88 = (f32)(s32)
    uStack_1c;
    uStack_14 = (int)in[2] ^ 0x80000000;
    local_18 = 0x43300000;
    local_84 = (f32)(s32)
    uStack_14;
    if (e != 0)
    {
        local_8c = local_8c * lbl_803DF6D8;
        local_88 = local_88 * lbl_803DF6D8;
        local_84 = local_84 * lbl_803DF6D8;
    }
    if (mtx == (float*)0x0)
    {
        local_74 = *(undefined4*)(obj + 0xc);
        local_70 = *(undefined4*)(obj + 0xe);
        local_6c = *(undefined4*)(obj + 0x10);
        if (flag == 0)
        {
            local_80 = *obj;
            local_7e = obj[1];
            local_7c = obj[2];
        }
        else
        {
            local_80 = 0;
            local_7e = 0;
            local_7c = 0;
        }
        local_78 = lbl_803DF69C;
        FUN_80017754(afStack_68, &local_80);
        FUN_80017778((double)local_8c, (double)local_88, (double)local_84, afStack_68, out, out + 1,
                     out + 2);
    }
    else
    {
        if (flag == 0)
        {
            FUN_80247bf8(mtx, &local_8c, &local_98);
            *out = local_98;
            out[1] = local_94;
            out[2] = local_90;
        }
        else
        {
            *out = mtx[3] + local_8c;
            out[1] = mtx[7] + local_88;
            out[2] = mtx[0xb] + local_84;
        }
        *out = *out + lbl_803DDA58;
        out[2] = out[2] + lbl_803DDA5C;
    }
    return;
}

void FUN_8004036c(undefined4 mtx)
{
    DAT_803dd8a4 = mtx;
    return;
}

void FUN_800406cc(int obj)
{
    int* renderNode;
    int model;
    int i;

    if (lbl_803DF684 == ((GameObject*)obj)->anim.rootMotionScale)
    {
        DAT_803dd8a4 = 0;
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
            for (i = 0; i < (int)(uint)((GameObject*)obj)->childCount; i = i + 1)
            {
                if (*(int*)(model + 200) != 0)
                {
                    FUN_80040784(*(int*)(model + 200), obj, 1);
                }
                model = model + 4;
            }
        }
    }
    return;
}

void FUN_80040784(undefined4 param_1, undefined4 param_2, uint shadowFlag)
{
    undefined2* child;
    int* parentNode;
    float* jointMtx;
    undefined2* cam;
    ushort* parent;
    int jointIdx;
    int iVar7;
    int iVar8;
    double in_f30;
    double dz;
    double in_f31;
    double dx;
    double in_ps30_1;
    double in_ps31_1;
    undefined8 uVar11;
    float local_e8;
    undefined4 local_e4;
    float local_e0;
    ushort local_dc;
    undefined2 local_da;
    undefined2 local_d8;
    float local_d4;
    undefined4 local_d0;
    undefined4 local_cc;
    undefined4 local_c8;
    float afStack_c4[3];
    float local_b8;
    undefined4 local_a8;
    float local_98;
    float afStack_84[27];
    float local_18;
    float fStack_14;
    float local_8;
    float fStack_4;

    local_8 = (float)in_f31;
    fStack_4 = (float)in_ps31_1;
    local_18 = (float)in_f30;
    fStack_14 = (float)in_ps30_1;
    uVar11 = FUN_80286840();
    child = (undefined2*)(ulonglong)(uVar11 >> 0x20);
    parent = (ushort*)(u32)uVar11;
    if (lbl_803DF684 == *(float*)(child + 4))
    {
        DAT_803dd8a4 = 0;
    }
    else
    {
        FUN_80017a54((int)child);
        parentNode = (int*)FUN_80017a54((int)parent);
        iVar8 = ((ushort)child[0x58] & 7) * 0x18;
        iVar7 = *(int*)(*(int*)(parent + 0x28) + 0x2c) + iVar8;
        jointIdx = (int)*(char*)(iVar7 + *(char*)((int)parent + 0xad) + 0x12);
        local_d0 = *(undefined4*)(*(int*)(*(int*)(parent + 0x28) + 0x2c) + iVar8);
        local_cc = *(undefined4*)(iVar7 + 4);
        local_c8 = *(undefined4*)(iVar7 + 8);
        if (jointIdx == -1)
        {
            FUN_80017a50(parent, afStack_84, '\0');
            jointMtx = afStack_84;
        }
        else
        {
            jointMtx = (float*)FUN_80017970(parentNode, jointIdx);
        }
        if ((OBJPRINT_MODEL_DEF(child)->renderFlags & 8) == 0)
        {
            local_d4 = lbl_803DF69C;
            iVar8 = *(int*)(*(int*)(parent + 0x28) + 0x2c) + iVar8;
            local_dc = *(ushort*)(iVar8 + 0xc);
            local_da = *(undefined2*)(iVar8 + 0xe);
            local_d8 = *(undefined2*)(iVar8 + 0x10);
            FUN_80017700(&local_dc, afStack_c4);
            FUN_80247618(jointMtx, afStack_c4, afStack_c4);
        }
        else
        {
            cam = FUN_800069a8();
            local_d4 = *(float*)(child + 4);
            dx = (double)(*(float*)(child + 6) - *(float*)(cam + 6));
            dz = (double)(*(float*)(child + 10) - *(float*)(cam + 10));
            iVar8 = FUN_80017730();
            local_dc = (short)iVar8 + 0x8000;
            FUN_80293900((double)(float)(dx * dx + (double)(float)(dz * dz)));
            iVar8 = FUN_80017730();
            local_da = (undefined2)iVar8;
            local_d8 = cam[2];
            FUN_80017700(&local_dc, afStack_c4);
            local_e8 = local_b8;
            local_e4 = local_a8;
            local_e0 = local_98;
            FUN_80247bf8(jointMtx, &local_e8, &local_e8);
            local_b8 = local_e8;
            local_a8 = local_e4;
            local_98 = local_e0;
        }
        if ((shadowFlag & 0xff) == 0)
        {
            *(float*)(child + 0xc) = local_b8 + lbl_803DDA58;
            *(undefined4*)(child + 0xe) = local_a8;
            *(float*)(child + 0x10) = local_98 + lbl_803DDA5C;
            if (*(int*)(child + 0x18) == 0)
            {
                *(undefined4*)(child + 6) = *(undefined4*)(child + 0xc);
                *(undefined4*)(child + 8) = *(undefined4*)(child + 0xe);
                *(undefined4*)(child + 10) = *(undefined4*)(child + 0x10);
            }
            else
            {
                FUN_800068f4((double)*(float*)(child + 0xc), (double)*(float*)(child + 0xe),
                             (double)*(float*)(child + 0x10), (float*)(child + 6),
                             (float*)(child + 8), (float*)(child + 10), *(int*)(child + 0x18));
            }
            FUN_8003bbfc(afStack_c4, child, child + 1, child + 2);
        }
        *(char*)((int)child + 0x37) =
            (char)((*(byte*)(child + 0x1b) + 1) * (uint) * (byte*)((int)parent + 0x37) >> 8);
        *(undefined*)((int)child + 0xf1) = *(undefined*)((int)parent + 0xf1);
        if ((child[3] & 0x4000) == 0)
        {
            DAT_803dd8a4 = (undefined4)afStack_c4;
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
    int* renderNode;
    int model;
    int sub;
    undefined4 shadowColor;
    int screenZ;
    int screenY;
    int screenX;
    float projZ;
    float projY;
    float projX;
    int d4;
    int d3;
    float d2;
    undefined4 d1[2];
    longlong shadowWidth;

    renderNode = (int*)FUN_80017a54(obj);
    if (lbl_803DF684 == ((GameObject*)obj)->anim.rootMotionScale)
    {
        DAT_803dd8a4 = 0;
    }
    else
    {
        model = *renderNode;
        if ((*(ushort*)(model + 2) & 0x8000) == 0)
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
        for (sub = 0; sub < (int)(uint)((GameObject*)obj)->childCount; sub = sub + 1)
        {
            if (*(int*)(model + 200) != 0)
            {
                FUN_80040784(*(int*)(model + 200), obj, 0);
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
            *(undefined*)((int)&DAT_803dc0e8 + 3) = ((ObjAnimComponent*)obj)->modelState->shadowAlpha;
            FUN_8006b03c(obj, d1, &d2, &d3, &d4);
            shadowColor = DAT_803dc0e8;
            shadowWidth = (longlong)(int)(lbl_803DF6EC * d2);
            FUN_800709e4(d1[0], d3, d4, &shadowColor,
                         (int)(lbl_803DF6EC * d2), 1);
        }
    }
}

void FUN_80040cd0(undefined flag)
{
    DAT_803dd8a9 = flag;
    return;
}

void FUN_80040da0(void)
{
    bool done;
    int mode;
    int status;
    uint newPtr;
    undefined4 delay;
    int i;
    uint* slotPtr;
    short* idTblPtr;
    int* sizePtr;
    undefined* flagPtr;
    int pass;

    mode = FUN_80286828();
    done = false;
    pass = 0;
    FUN_8001782c(2);
    FUN_80243e74();
    i = DAT_803dd900;
    FUN_80243e9c();
    if (i == 0)
    {
        if ((mode == 0) && (DAT_803dd8f8 == 0))
        {
            FUN_800530b4();
            DAT_803dd8f8 = 6;
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
                                ((newPtr = FUN_80017824(*slotPtr), 0x2fff < (int)newPtr &&
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

void FUN_80041c10(undefined8 param_1, undefined8 param_2, undefined8 param_3, undefined8 param_4,
                  undefined8 param_5, undefined8 param_6, undefined8 param_7, undefined8 param_8,
                  int charId)
{
    int charPos;
    undefined8 extraout_f1;
    undefined8 acc;

    if (*(short*)(&DAT_802cc9d4 + charId * 2) != -1)
    {
        charPos = (int)(*gMapEventInterface)->getCurCharPos();
        *(char*)(charPos + 0xe) = (char)charId;
        param_1 = extraout_f1;
    }
    acc = FUN_800443fc(param_1, param_2, param_3, param_4, param_5, param_6, param_7, param_8);
    acc = FUN_800443fc(acc, param_2, param_3, param_4, param_5, param_6, param_7, param_8);
    acc = FUN_800443fc(acc, param_2, param_3, param_4, param_5, param_6, param_7, param_8);
    acc = FUN_800443fc(acc, param_2, param_3, param_4, param_5, param_6, param_7, param_8);
    acc = FUN_800443fc(acc, param_2, param_3, param_4, param_5, param_6, param_7, param_8);
    acc = FUN_800443fc(acc, param_2, param_3, param_4, param_5, param_6, param_7, param_8);
    acc = FUN_800443fc(acc, param_2, param_3, param_4, param_5, param_6, param_7, param_8);
    acc = FUN_800443fc(acc, param_2, param_3, param_4, param_5, param_6, param_7, param_8);
    acc = FUN_800443fc(acc, param_2, param_3, param_4, param_5, param_6, param_7, param_8);
    acc = FUN_800443fc(acc, param_2, param_3, param_4, param_5, param_6, param_7, param_8);
    acc = FUN_800443fc(acc, param_2, param_3, param_4, param_5, param_6, param_7, param_8);
    acc = FUN_800443fc(acc, param_2, param_3, param_4, param_5, param_6, param_7, param_8);
    acc = FUN_800443fc(acc, param_2, param_3, param_4, param_5, param_6, param_7, param_8);
    FUN_800443fc(acc, param_2, param_3, param_4, param_5, param_6, param_7, param_8);
    return;
}

int FUN_80041ff8(undefined8 param_1, undefined8 param_2, undefined8 param_3, undefined8 param_4,
                 undefined8 param_5, undefined8 param_6, undefined8 param_7, undefined8 param_8,
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
            FUN_80041c10(param_1, param_2, param_3, param_4, param_5, param_6, param_7, param_8, mapped);
            return mapped;
        }
    }
    FUN_80041c10(param_1, param_2, param_3, param_4, param_5, param_6, param_7, param_8, charId);
    return charId;
}

void FUN_800427c8(void)
{
    FUN_80243e74();
    if ((DAT_803dd900 & 0x100000) != 0)
    {
        DAT_803dd900 = DAT_803dd900 ^ 0x100000;
    }
    FUN_80243e9c();
    return;
}

void FUN_80042800(void)
{
    FUN_80243e74();
    DAT_803dd900 = DAT_803dd900 | 0x100000;
    FUN_80243e9c();
    return;
}

undefined4 FUN_80042838(void)
{
    undefined4 flags;

    FUN_80243e74();
    flags = DAT_803dd900;
    FUN_80243e9c();
    return flags;
}

int FUN_80042b9c(int val, int idx, int reset)
{
    int cur;

    if (reset == 1)
    {
        DAT_803dc210 = 0xfffffffe;
        uRam803dc214 = 0xfffffffe;
        return -1;
    }
    cur = (&DAT_803dc210)[idx];
    if ((val != cur) && (cur != -2))
    {
        return cur;
    }
    (&DAT_803dc210)[idx] = 0xfffffffe;
    return -1;
}

int FUN_80042bec(undefined4 val, int idx)
{
    if ((&DAT_803dc210)[idx] == -2)
    {
        (&DAT_803dc210)[idx] = val;
        return -1;
    }
    return (&DAT_803dc210)[idx];
}

void FUN_80043030(undefined8 param_1, undefined8 param_2, undefined8 param_3, undefined8 param_4,
                  undefined8 param_5, undefined8 param_6, undefined8 param_7, undefined8 param_8)
{
}

undefined4 FUN_80043E64(uint* param_1, int param_2, int param_3)
{
    bool bVar1;
    bool bVar2;
    uint* puVar3;
    int iVar4;
    int iVar5;
    uint uVar6;
    uint* puVar7;
    uint* puVar8;
    uint* puVar9;
    uint* dst;

    iVar4 = 0;
    bVar1 = false;
    bVar2 = false;
    iVar5 = 0;
    puVar8 = (uint*)(&DAT_80360048)[param_2];
    if (((puVar8 == (uint*)0x0) || ((&DAT_80360048)[param_3] == 0)) &&
        (bVar1 = puVar8 == (uint*)0x0, (&DAT_80360048)[param_3] == 0))
    {
        bVar2 = true;
    }
    puVar3 = (uint*)(&DAT_80360048)[param_3];
    if (param_1 == (uint*)&DAT_8035db50)
    {
        iVar5 = 0x800;
    }
    else if (param_1 == (uint*)&DAT_8035ac70)
    {
        iVar5 = 3000;
    }
    else if (param_1 == (uint*)&DAT_80356c70)
    {
        iVar5 = 0x1000;
    }
    else if (param_1 == (uint*)&DAT_80352c70)
    {
        iVar5 = 0x1000;
    }
    else if (param_1 == (uint*)&DAT_80350c70)
    {
        iVar5 = 0x800;
    }
    else if (param_1 == (uint*)&DAT_8034ec70)
    {
        iVar5 = 0x800;
    }
    else if (param_1 == (uint*)&DAT_80346d30)
    {
        iVar5 = 0x1fd0;
    }
    puVar9 = param_1;
    if ((param_1 == (uint*)&DAT_80356c70) || (param_1 == (uint*)&DAT_80352c70))
    {
        for (; iVar5 != 0; iVar5 = iVar5 + -1)
        {
            if ((!bVar1) && (*puVar8 == 0xffffffff))
            {
                bVar1 = true;
            }
            if ((!bVar2) && (*puVar3 == 0xffffffff))
            {
                bVar2 = true;
            }
            if (((bVar1) || (uVar6 = *puVar8, uVar6 == 0xffffffff)) || ((uVar6 & 0x80000000) == 0))
            {
                if (((bVar2) || (uVar6 = *puVar3, uVar6 == 0xffffffff)) || ((uVar6 & 0x80000000) == 0))
                {
                    if ((bVar1) || (*puVar8 == 0))
                    {
                        if ((bVar2) || (*puVar3 == 0))
                        {
                            *puVar9 = 0;
                        }
                        else
                        {
                            *puVar9 = *puVar3;
                        }
                    }
                    else
                    {
                        *puVar9 = *puVar8;
                    }
                }
                else
                {
                    *puVar9 = uVar6;
                }
            }
            else
            {
                *puVar9 = uVar6 & 0x7fffffff;
                *puVar9 = *puVar9 | 0x40000000;
            }
            puVar8 = puVar8 + 1;
            puVar3 = puVar3 + 1;
            iVar4 = iVar4 + 1;
            puVar9 = puVar9 + 1;
        }
    }
    else if (param_1 == (uint*)&DAT_80350c70)
    {
        puVar9 = (uint*)&DAT_80350c70;
        puVar7 = puVar8;
        dst = puVar3;
        for (; iVar5 != 0; iVar5 = iVar5 + -1)
        {
            if (((bVar1) || (uVar6 = *puVar7, uVar6 == 0xffffffff)) || ((uVar6 & 0x10000000) == 0))
            {
                if (((bVar2) || (uVar6 = *dst, uVar6 == 0xffffffff)) || ((uVar6 & 0x10000000) == 0))
                {
                    if ((bVar1) || (*puVar7 != 0xffffffff))
                    {
                        if ((bVar2) || (*dst != 0xffffffff))
                        {
                            if ((bVar1) || (*puVar7 == 0))
                            {
                                if ((bVar2) || (*dst == 0))
                                {
                                    *puVar9 = 0;
                                }
                                else
                                {
                                    *puVar9 = *dst;
                                }
                            }
                            else
                            {
                                *puVar9 = *puVar7;
                            }
                        }
                        else
                        {
                            *puVar9 = 0;
                            bVar2 = true;
                        }
                    }
                    else
                    {
                        *puVar9 = 0;
                        bVar1 = true;
                    }
                }
                else
                {
                    *puVar9 = uVar6 & 0xffffff | 0x20000000;
                    if ((puVar8 != (uint*)0x0) && (*puVar7 == 0xffffffff))
                    {
                        bVar1 = true;
                    }
                }
            }
            else
            {
                *puVar9 = uVar6;
                if ((puVar3 != (uint*)0x0) && (*dst == 0xffffffff))
                {
                    bVar2 = true;
                }
            }
            puVar7 = puVar7 + 1;
            puVar9 = puVar9 + 1;
            dst = dst + 1;
            iVar4 = iVar4 + 1;
        }
    }
    else if (param_1 == (uint*)&DAT_8034ec70)
    {
        puVar9 = (uint*)&DAT_8034ec70;
        for (; iVar5 != 0; iVar5 = iVar5 + -1)
        {
            if ((bVar1) || (*puVar8 != 0xffffffff))
            {
                if ((bVar2) || (*puVar3 != 0xffffffff))
                {
                    if (((bVar1) || (uVar6 = *puVar8, uVar6 == 0xffffffff)) || ((uVar6 & 0x80000000) == 0))
                    {
                        if (((bVar2) || (uVar6 = *puVar3, uVar6 == 0xffffffff)) || ((uVar6 & 0x80000000) == 0))
                        {
                            if ((bVar1) || (*puVar8 == 0))
                            {
                                if ((bVar2) || (*puVar3 == 0))
                                {
                                    *puVar9 = 0;
                                }
                                else
                                {
                                    *puVar9 = *puVar3;
                                }
                            }
                            else
                            {
                                *puVar9 = *puVar8;
                            }
                        }
                        else
                        {
                            *puVar9 = uVar6 & 0x7fffffff | 0x20000000;
                        }
                    }
                    else
                    {
                        *puVar9 = uVar6;
                    }
                }
                else
                {
                    *puVar9 = 0;
                    bVar2 = true;
                }
            }
            else
            {
                *puVar9 = 0;
                bVar1 = true;
            }
            puVar8 = puVar8 + 1;
            puVar9 = puVar9 + 1;
            puVar3 = puVar3 + 1;
            iVar4 = iVar4 + 1;
        }
    }
    else
    {
        puVar9 = puVar8;
        puVar7 = puVar3;
        dst = param_1;
        if (param_1 == (uint*)&DAT_80346d30)
        {
            puVar9 = (uint*)&DAT_80346d30;
            for (; iVar5 != 0; iVar5 = iVar5 + -1)
            {
                if ((bVar1) || (*puVar8 != 0xffffffff))
                {
                    if ((bVar2) || (*puVar3 != 0xffffffff))
                    {
                        if (((bVar1) || (uVar6 = *puVar8, uVar6 == 0xffffffff)) || ((uVar6 & 0x80000000) == 0))
                        {
                            if (((bVar2) || (uVar6 = *puVar3, uVar6 == 0xffffffff)) || ((uVar6 & 0x80000000) == 0)
                            )
                            {
                                if ((bVar1) || (*puVar8 == 0))
                                {
                                    if ((bVar2) || (*puVar3 == 0))
                                    {
                                        *puVar9 = 0;
                                    }
                                    else
                                    {
                                        *puVar9 = *puVar3;
                                    }
                                }
                                else
                                {
                                    *puVar9 = *puVar8;
                                }
                            }
                            else
                            {
                                *puVar9 = uVar6 & 0x7fffffff | 0x20000000;
                            }
                        }
                        else
                        {
                            *puVar9 = uVar6;
                        }
                    }
                    else
                    {
                        *puVar9 = 0;
                        bVar2 = true;
                    }
                }
                else
                {
                    *puVar9 = 0;
                    bVar1 = true;
                }
                puVar8 = puVar8 + 1;
                puVar9 = puVar9 + 1;
                puVar3 = puVar3 + 1;
                iVar4 = iVar4 + 1;
            }
        }
        else
        {
            for (; iVar5 != 0; iVar5 = iVar5 + -1)
            {
                if ((!bVar1) && (*puVar9 == 0xffffffff))
                {
                    bVar1 = true;
                }
                if ((!bVar2) && (*puVar7 == 0xffffffff))
                {
                    bVar2 = true;
                }
                if (((bVar1) || (uVar6 = *puVar9, uVar6 == 0xffffffff)) || ((uVar6 & 0x10000000) == 0))
                {
                    if (((bVar2) || (uVar6 = *puVar7, uVar6 == 0xffffffff)) || ((uVar6 & 0x10000000) == 0))
                    {
                        if ((bVar1) || (puVar8 == (uint*)0x0))
                        {
                            if ((bVar2) || (puVar3 == (uint*)0x0))
                            {
                                *dst = 0;
                            }
                            else
                            {
                                *dst = *puVar7;
                            }
                        }
                        else
                        {
                            *dst = *puVar9;
                        }
                    }
                    else
                    {
                        *dst = uVar6 & 0xffffff | 0x20000000;
                    }
                }
                else
                {
                    *dst = uVar6;
                }
                iVar4 = iVar4 + 1;
                puVar9 = puVar9 + 1;
                puVar7 = puVar7 + 1;
                dst = dst + 1;
            }
        }
    }
    param_1[iVar4 + -1] = 0xffffffff;
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

extern u8 lbl_803DCC28;
extern u8 lbl_803DCC58;

void fn_800412B8(u8 r, u8 g, u8 b)
{
    lbl_803DCC28 = 1;
    lbl_803DCC58 = r;
    (&lbl_803DCC58)[1] = g;
    (&lbl_803DCC58)[2] = b;
}

extern s32 lbl_803DB5B0;

int lockLevel(s32 val, int idx)
{
    s32 cur = (&lbl_803DB5B0)[idx];
    if (cur == -2)
    {
        (&lbl_803DB5B0)[idx] = val;
        return -1;
    }
    return cur;
}

extern volatile int lbl_803DCC80;
extern int OSDisableInterrupts(void);
extern void OSRestoreInterrupts(int);

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

extern s16 lbl_8035F548[];

s32 mapCheckCurBlocks(int v)
{
    if (((s16*)((char*)lbl_8035F548 + 0x4a))[0] == v) return 0;
    if (((s16*)((char*)lbl_8035F548 + 0x8e))[0] == v) return 1;
    return -1;
}

extern u8 lbl_803DCC2A;
extern u32 lbl_803DCC2C;
extern u32 lbl_803DCC30;
extern u8 lbl_803DCC34;
extern u32 lbl_803DB474;
extern u8 lbl_803DB478;
extern u8 lbl_803DB479;
extern u32 lbl_803DB47C;
extern u8 lbl_803DB480;
extern u8 lbl_803DB481;
extern u8 lbl_803DB482;
extern u8 lbl_803DB484[4];

void renderResetFn_8003fc60(void)
{
    lbl_803DCC2A = 0;
    lbl_803DCC2C = 0;
    lbl_803DCC30 = 0;
    lbl_803DCC34 = 0;
    lbl_803DB474 = -1;
    lbl_803DB478 = 0xff;
    lbl_803DB479 = 0xff;
    lbl_803DB47C = -1;
    lbl_803DB480 = 0xff;
    lbl_803DB481 = 0xff;
    lbl_803DB482 = 0xff;
    lbl_803DB484[3] = 0;
    lbl_803DB484[2] = 0;
    lbl_803DB484[1] = 0;
    lbl_803DB484[0] = 0;
}

extern s32 DVDGetCommandBlockStatus(void* block);

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
    case -1: return status;
    case 0: return status;
    case 1: return status;
    case 2: return status;
    case 3: return status;
    case 4: return status;
    case 5: return status;
    case 6: return status;
    case 7: return status;
    case 8: return status;
    case 9: return status;
    case 10: return status;
    case 11: return status;
    }
    return 0;
}

extern f32 lbl_803DEA04;
extern int* Obj_GetActiveModel(int* obj);
extern void objRenderShadow2(int* obj, int* obj2, u8* m, int p4);
extern void modelDoRenderInstrs(int* obj, int* obj2, u8* m, u8 mode);
extern void objRenderChild(int* child, int* parent, u8 p3);
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

extern s32 lbl_803DCC40;
extern s32 lbl_803DCC44;
extern u8 lbl_803DCC3D;
extern f32 lbl_803DCC38;
extern f32 timeDelta;
extern f32 lbl_803DEA60;
extern f32 lbl_803DEA5C;
extern f32 lbl_803DEA64;
extern f32 lbl_803DEA68;
extern f32 lbl_803DEA58;
extern f32 lbl_803DEA1C;
extern f32 lbl_803DEA6C;
extern f32 playerMapOffsetX;
extern f32 playerMapOffsetZ;
extern u8 lbl_803DB488[4];
extern void ObjModel_SetRenderCallback(int* model, void* cb);
extern void modelRenderCb_8003c268();
extern void shaderFuzzFn_8003cc1c();
extern void modelDoAltRenderInstrs(int* obj, int* obj2, u8* model, int p4);
extern int* Camera_GetCurrentViewSlot(void);
extern f32 sqrtf(f32);
extern int getAngle(f32 a, f32 b);
extern void PSMTXMultVec(f32 * m, f32 * src, f32 * dst);
extern void PSMTXConcat(f32 * a, f32 * b, f32 * ab);
extern void setMatrixFromObjectTransposed(void* blk, f32* m);
extern void Matrix_TransformPoint(f32* m, f32 x, f32 y, f32 z, f32* ox, f32* oy, f32* oz);
extern void Obj_BuildWorldTransformMatrix(int* obj, f32* m, int p3);
extern void objRotateFn_8003bce8(f32 * m, s16 * a, s16 * b, s16 * c);
extern void Camera_ProjectWorldPointWithOffset(f32 x, f32 y, f32 z, f32 w, f32* a, f32* b, f32* c);
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
    lbl_803DCC40 = 4;
    model = Obj_GetActiveModel(obj);
    savedMtx = curObjMtx;
    lbl_803DCC3D = lbl_803DCC38;
    for (lbl_803DCC44 = 0; lbl_803DCC44 < 16; lbl_803DCC44 += lbl_803DCC40)
    {
        modelDoRenderInstrs(obj, ((GameObject*)obj)->ownerObj ? ((GameObject*)obj)->ownerObj : obj, (u8*)*model, 2);
        curObjMtx = savedMtx;
    }
    curObjMtx = 0;
    lbl_803DCC38 += timeDelta;
    if (lbl_803DCC38 > lbl_803DEA60)
    {
        lbl_803DCC38 -= lbl_803DEA5C;
    }
}

void fuzzRenderFn_800412dc(int* obj)
{
    int* model;
    u32 savedMtx;
    lbl_803DCC40 = 1;
    model = Obj_GetActiveModel(obj);
    savedMtx = curObjMtx;
    lbl_803DCC3D = lbl_803DCC38;
    ObjModel_SetRenderCallback(model, modelRenderCb_8003c268);
    for (lbl_803DCC44 = 0; lbl_803DCC44 < 16; lbl_803DCC44 += lbl_803DCC40)
    {
        modelDoRenderInstrs(obj, ((GameObject*)obj)->ownerObj ? ((GameObject*)obj)->ownerObj : obj, (u8*)*model, 8);
        curObjMtx = savedMtx;
    }
    curObjMtx = 0;
    ObjModel_SetRenderCallback(model, NULL);
    lbl_803DCC38 += timeDelta;
    if (lbl_803DCC38 > lbl_803DEA60)
    {
        lbl_803DCC38 -= lbl_803DEA5C;
    }
}

void objRenderFuzz(int* obj)
{
    int n;
    u8 maxN;
    u8 strong;
    int cnt;
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
        lbl_803DCC40 = 2;
    }
    else
    {
        cnt = (s32)(
            (lbl_803DEA68 * dist) / (((GameObject*)obj)->anim.hitboxScale * ((GameObject*)obj)->anim.rootMotionScale));
        lbl_803DCC40 = 1;
    }
    n = 16 - cnt;
    if (n > 0)
    {
        int* model;
        u32 savedMtx;
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
            int* child = *(int**)(iter + 0xc8);
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
    lbl_803DB488[3] = ((GameObject*)obj)->anim.modelState->shadowAlpha;
    objShadowFn_8006c5f0(obj, &d1, &d2, &d3, &d4);
    col = *(u32*)lbl_803DB488;
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
    if (!(((GameObject*)child)->anim.flags & 0x4000))
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
extern u8 lbl_802CAED0[];

typedef struct
{
    u8* data;
    int pad[3];
    int pos;
} MtxBitStream;

void modelLoadMtxsToGx(int obj, int* model, MtxBitStream* bs, f32* mtx)
{
    char* cache = getCache();
    if (lbl_803DCC48 == 1)
    {
        char* c2 = getCache();
        char* src;
        char* dst;
        int i;
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
        i = 0;
        tbl = lbl_802CAED0;
        for (; i < count; i++)
        {
            int idx;
            {
                u32 w;
                int pos = bs->pos;
                int off = pos >> 3;
                u8* p = (u8*)(off + (char*)bs->data);
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

extern void GXClearVtxDesc(void);
extern void GXSetVtxDesc(int attr, int type);
extern void GXSetCurrentMtx(int id);
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
    if (lbl_803DB474 != flags)
    {
        GXClearVtxDesc();
        if (flags & 1)
        {
            GXSetVtxDesc(0, 1);
        }
        else
        {
            GXSetCurrentMtx(lbl_802CAED0[0]);
        }
        GXSetVtxDesc(9, (flags & 2) ? 3 : 2);
        GXSetVtxDesc(13, (flags & 4) ? 3 : 2);
        lbl_803DB474 = flags;
    }
}
#pragma dont_inline reset

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
    if (lbl_803DB478 != blend)
    {
        if (blend != 0)
        {
            GXSetBlendMode(1, 4, 5, 5);
        }
        else
        {
            GXSetBlendMode(0, 1, 0, 5);
        }
        lbl_803DB478 = blend;
    }
    if (lbl_803DB480 != zwrite || lbl_803DB481 != zcmp)
    {
        gxSetZMode_(zwrite, 3, zcmp);
        lbl_803DB480 = zwrite;
        lbl_803DB481 = zcmp;
    }
    if (lbl_803DB479 != zcomploc)
    {
        gxSetPeControl_ZCompLoc_(zcomploc);
        lbl_803DB479 = zcomploc;
    }
    if (lbl_803DB47C != alpha)
    {
        lbl_803DB47C = alpha;
        if (alpha != 0)
        {
            GXSetAlphaCompare(4, (u8)alpha, 0, 4, (u8)alpha);
        }
        else
        {
            GXSetAlphaCompare(7, 0, 0, 7, 0);
        }
    }
    if (cull != lbl_803DB482)
    {
        lbl_803DB482 = cull;
        if (cull != 0)
        {
            GXSetCullMode(2);
        }
        else
        {
            GXSetCullMode(0);
        }
    }
}

extern void modelMtxFn_8003be38(u8* hdr, int* model, f32* mtx, f32* m1);
extern void GXLoadTexMtxImm(f32* m, int id, int type);
extern void GXLoadNrmMtxImm(f32* m, int id);
extern void OSReport(char* fmt, ...);

void renderOpMatrix(void* hdrArg, int* model, MtxBitStream* bs, f32* m1, f32* mtx, u8 nrm, u8 tex, u8 skip)
{
    u8* tbl = lbl_802CAED0;
    char* cache = getCache();
    u8* hdr = (u8*)hdrArg;
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
                u8* p = (u8*)(off + (char*)bs->data);
                w = p[0];
                w |= p[1] << 8;
                w |= p[2] << 16;
                bs->pos = pos + 8;
                idx = (w >> (pos & 7)) & 0xff;
            }
            if (lbl_803DCC48 == 2)
            {
                hdr = (u8*)(cache + idx * 0x30 + 0x12c0);
                GXLoadPosMtxImm((f32*)hdr, *tbl);
                if (skip == 0 && tex != 0)
                {
                    GXLoadTexMtxImm((f32*)hdr, *tbl2, 0);
                }
                if (skip == 0 && nrm != 0)
                {
                    GXLoadNrmMtxImm((f32*)hdr, *tbl);
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

typedef union
{
    u8 u8;
    u16 u16;
    u32 u32;
    s16 s16;
    s32 s32;
    f32 f32;
} ObjWGPipe;

extern volatile ObjWGPipe GXWGFifo : (0xCC008000);
extern f32* Camera_GetViewMatrix(void);
extern void PSMTXScale(f32* m, f32 x, f32 y, f32 z);
extern void gxTextureFn_80072dfc(u8* obj, int* p2, int p3);
extern void GXBegin(int prim, int fmt, u16 count);

void objRenderFn_8003d980(void* objArg, int* p2)
{
    u8* obj = (u8*)objArg;
    f32 wm[16];
    f32 cm[16];
    f32 sm[12];
    struct
    {
        s16 rot[3];
        f32 scale;
        f32 pos[3];
    } blk;
    f32* vm;
    s16* uvs;
    s16* verts;
    u8* data = *(u8**)((char*)p2 + 0x58);
    vm = Camera_GetViewMatrix();
    Obj_BuildWorldTransformMatrix((int*)obj, wm, 0);
    PSMTXConcat(vm, wm, cm);
    GXLoadPosMtxImm(cm, lbl_802CAED0[0]);
    GXSetCurrentMtx(lbl_802CAED0[0]);
    PSMTXScale(sm, lbl_803DEA1C / ((GameObject*)obj)->anim.rootMotionScale,
               lbl_803DEA1C / ((GameObject*)obj)->anim.rootMotionScale, lbl_803DEA1C);
    cm[3] = lbl_803DEA04;
    cm[7] = lbl_803DEA04;
    cm[11] = lbl_803DEA04;
    PSMTXConcat(cm, sm, cm);
    GXLoadTexMtxImm(cm, 0x1e, 0);
    gxTextureFn_80072dfc(obj, p2, 0);
    GXClearVtxDesc();
    GXSetVtxDesc(9, 1);
    GXSetVtxDesc(10, 1);
    GXSetVtxDesc(13, 1);
    verts = *(s16**)(data + 4);
    uvs = *(s16**)(data + 8);
    GXBegin(0x90, 7, *(u16*)(data + 0xc) * 3);
    {
        int i = 0;
        int off = 0;
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
        int j = (r * 3) << 1;
        s16* pv;
        blk.pos[0] = fs * (f32)(*(s16*)((char*)verts + j) >> 8) + ((GameObject*)obj)->anim.localPosX;
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

extern s32 lbl_803DCC5C;
extern int lbl_803DCC64;
extern void modelLightStruct_getProjectionTevModes(int p1, int* a, int* b);

typedef struct
{
    u8 r, g, b, a;
} ObjGXColor;

extern void modelLightChannels_reset(int);
extern void modelLightChannel_configure(u8 chan, int p2, int p3);
extern void modelTextureFn_80089970(int idx);
extern void textureColorFn_8008991c(int idx, u8* r, u8* g, u8* b);
extern void lightGetColor(int light, u8* r, u8* g, u8* b);
extern void modelLightStruct_selectObjectLights(u8* model, int* arr, u32 n, s32* cnt, int mode);
extern void modelLightStruct_loadChannelLight(u8 chan, int light, u8* model);
extern int modelLightStruct_getProjectedLightChannelPreference(int light);
extern void modelLightChannels_applyGXControls(void);
extern void GXSetChanAmbColor(u8 chan, ObjGXColor c);
extern void GXSetChanMatColor(u8 chan, ObjGXColor c);
extern void GXSetChanCtrl(int chan, int enable, int amb, int mat, int mask, int diff, int attn);
extern void GXSetNumChans(int n);
extern u32 lbl_803DB468;
extern u32 lbl_803DB46C;
extern u32 lbl_803DB470;
extern u32 lbl_803DCC54;
extern u8 lbl_803DCC4C;
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
            ((u8*)&lbl_803DCC54)[3] = 0;
            GXSetChanAmbColor(chan, *(ObjGXColor*)&lbl_803DCC54);
            GXSetChanCtrl(0, 1, 0, 1, 0, 0, 2);
            GXSetChanCtrl(2, 0, 0, 1, 0, 0, 2);
            GXSetNumChans(1);
        }
        else
        {
            GXSetChanCtrl(4, 0, 0, 0, 0, 0, 2);
            GXSetChanCtrl(5, 0, 0, 0, 0, 0, 2);
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
                GXSetChanAmbColor(ch, *(ObjGXColor*)&lbl_803DB46C);
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
                GXSetChanMatColor(ch, *(ObjGXColor*)&lbl_803DB46C);
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
                GXSetChanMatColor(ch, *(ObjGXColor*)&lbl_803DB46C);
            }
        }
        {
            u32 nf = obj[0xfa];
            if (nf != 0)
            {
                modelLightStruct_selectObjectLights(model, &lbl_803DCC64, nf, &lbl_803DCC5C, 8);
                if ((OBJPRINT_MODEL_DEF(model)->renderFlags & 4) || lbl_803DCC4C)
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
            if ((b5f & 4) || lbl_803DCC4C)
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
    GXClearVtxDesc();
    if (hdr[0xf3] > 1)
    {
        int next;
        int back;
        GXSetVtxDesc(0, 1);
        next = 1;
        back = 8;
        if (p3[0] != 0 || p3[1] != 0)
        {
            if (*(u32*)&((ModelFileHeader*)m)->unk34 != 0)
            {
                GXSetVtxDesc(1, 1);
                GXSetVtxDesc(2, 1);
                next = 3;
            }
            GXSetVtxDesc(next++, 1);
        }
        {
            int i = 0;
            u32 t = p5;
            for (; i < hdr[0xfa]; i++)
            {
                u8 use;
                if (t == 4 && i == 0)
                {
                    if (lbl_803DCC5C != 0)
                    {
                        int a;
                        int b;
                        modelLightStruct_getProjectionTevModes(lbl_803DCC64, &a, &b);
                        if (a == 0)
                        {
                            use = 1;
                        }
                        else
                        {
                            use = 0;
                        }
                    }
                    else
                    {
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
        GXSetVtxDesc(9, (((int)(w >> (pos & 7)) & 1) ? 3 : 2));
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
            GXSetVtxDesc(0xa, b ? 3 : 2);
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
        GXSetVtxDesc(0xb, (((int)(w >> (pos & 7)) & 1) ? 3 : 2));
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
extern f32 lbl_802CAEE8[];
extern void ObjModel_UpdateAnimMatrices(int* am, u8* m, int* obj, f32* mtx);
extern void modelInitMtxs(u8* m, int* am);
extern void ObjModel_ToggleMatrixBuffer(int* am);
extern void modelRenderInstrsState_init(MtxBitStream* bs, u8* data, int len, int len2);
extern void objGetColor(int idx, u8* r, u8* g, u8* b);
typedef u8 (*ObjModelRenderCb)(int* obj, int* am, int p3);
extern ObjModelRenderCb ObjModel_GetRenderCallback(int* am);
extern void Camera_RebuildProjectionMatrix(void);
extern void _gxSetFogParams(void);
extern void resetLotsOfRenderVars(void);
extern void* textureIdxToPtr(int idx);
extern void gxFn_80051fb8(void* tex, int p2, int p3, u8* color, int p5, int p6);
extern u8 isHeavyFogEnabled(void);
extern void getColor803dd01c(f32 * c);
extern void renderHeavyFog(f32 * c);
extern void textureFn_800528bc(void);
extern void selectTexture(void* tex, int p2);
extern void GXSetTevKColor(int id, u32* color);
extern void GXSetArray(int attr, int ptr, int stride);
extern u8* modelFileGetDisplayList(u8* m, int idx);
extern void GXCallDisplayList(void* list, int size);

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
            if (lbl_803DCC30 != (u32)m)
            {
                ObjModel_UpdateAnimMatrices(am, m, obj, lbl_802CAEE8);
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
            PSMTXCopy(lbl_802CAEE8, (f32*)ObjModel_GetJointMatrix((u8*)am, 0));
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
        if (lbl_803DCC28 != 0)
        {
            color[0] = lbl_803DCC58;
            color[1] = (&lbl_803DCC58)[1];
            color[2] = (&lbl_803DCC58)[2];
            lbl_803DCC28 = 0;
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
    if (lbl_803DCC2A == 0 || cb != NULL)
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
            GXSetChanCtrl(4, 0, 0, 0, 0, 0, 2);
            GXSetChanCtrl(5, 0, 0, 0, 0, 0, 2);
            GXSetNumChans(0);
            lbl_803DCC2A = 1;
            *(u32*)lbl_803DB484 = *(u32*)color;
        }
    }
    else
    {
        void* tex = textureIdxToPtr(*(int*)(*(int*)&((ModelFileHeader*)m)->renderOps + 0x24));
        if (lbl_803DCC2C != (u32)tex)
        {
            lbl_803DCC2C = (u32)tex;
            selectTexture(tex, 0);
        }
        if (lbl_803DB484[0] != color[0] || lbl_803DB484[1] != color[1]
            || lbl_803DB484[2] != color[2] || lbl_803DB484[3] != color[3])
        {
            u32 kcol = *(u32*)color;
            GXSetTevKColor(0, &kcol);
            *(u32*)lbl_803DB484 = *(u32*)color;
        }
    }
    if (lbl_803DCC30 != (u32)m)
    {
        GXSetArray(9, ((int*)((char*)am + 0x1c))[(*(u16*)((char*)am + 0x18) >> 1) & 1], 6);
        GXSetArray(13, *(int*)&((ModelFileHeader*)m)->unk34, 4);
        lbl_803DCC30 = (u32)m;
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
extern f32 lbl_80342E10[];
extern void ObjModel_ApplyBlendChannels(int* am);
extern void ObjModel_BlendPrimaryVertexStream(f32* mtxs, u8* p2, int p3, int p4, int p5);
extern void ObjModel_BlendSecondaryVertexStream(f32* mtxs, u8* p2, int p3, int p4, int p5);
extern void objUpdateHitSpheres(int* am, u8* m, int* obj, int p4, int* p5);
extern void GXSetNumTexGens(int n);
extern void GXSetNumTevStages(int n);
extern void GXSetNumIndStages(int n);
extern void GXSetTevOrder(int stage, int coord, int map, int color);
extern void GXSetTevDirect(int stage);
extern void GXSetTevColorIn(int stage, int a, int b, int c, int d);
extern void GXSetTevAlphaIn(int stage, int a, int b, int c, int d);
extern void GXSetTevSwapMode(int stage, int ras, int tex);
extern void GXSetTevColorOp(int stage, int op, int bias, int scale, int clamp, int out);
extern void GXSetTevAlphaOp(int stage, int op, int bias, int scale, int clamp, int out);
extern void GXSetFog(int type, f32 a, f32 b, f32 c, f32 d, ObjGXColor color);
typedef void (*ObjShadowCb)(int* obj, int* am, f32* wm);
extern int* ObjModel_GetRenderOp(int am0, int idx);
extern void GXSetTevColor(int id, u32* color);

void objRenderShadow2(int* obj, int* obj2, u8* m, int p4)
{
    f32 cm[12];
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
                modelInitBoneMtxs2(am, wm, lbl_80342E10);
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
            ObjModel_BlendPrimaryVertexStream(lbl_80342E10, m + 0x88, vtx, *(int*)&((ModelFileHeader*)am)->unk40,
                                              ((int*)((char*)am + 0x1c))[(*(u16*)((char*)am + 0x18) >> 1) & 1]);
            ObjModel_BlendSecondaryVertexStream(lbl_80342E10, m + 0xac, *(int*)&((ModelFileHeader*)m)->normals,
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
        GXLoadPosMtxImm(cm, lbl_802CAED0[9]);
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
            GXSetTevColor(3, &tev1);
            GXSetBlendMode(0, 1, 0, 5);
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
            GXSetTevColor(3, &tev2);
            GXSetBlendMode(2, 1, 0, 7);
        }
    }
    GXSetNumTexGens(0);
    GXSetNumTevStages(1);
    GXSetNumIndStages(0);
    GXSetTevOrder(0, 0xff, 0xff, 4);
    GXSetTevDirect(0);
    GXSetTevColorIn(0, 0xf, 0xf, 0xf, 6);
    GXSetTevAlphaIn(0, 7, 7, 7, 3);
    GXSetTevSwapMode(0, 0, 0);
    GXSetTevColorOp(0, 0, 0, 0, 1, 0);
    GXSetTevAlphaOp(0, 0, 0, 0, 1, 0);
    GXSetFog(0, lbl_803DEA04, lbl_803DEA04, lbl_803DEA04, lbl_803DEA04, *(ObjGXColor*)&lbl_803DB468);
    gxSetPeControl_ZCompLoc_(1);
    GXSetAlphaCompare(7, 0, 0, 7, 0);
    GXSetChanCtrl(4, 0, 0, 0, 0, 0, 2);
    GXSetNumChans(1);
    if (OBJPRINT_MODEL_DEF(obj)->renderFlags & 4)
    {
        gxSetZMode_(1, 3, 1);
        GXSetCullMode(1);
    }
    else
    {
        gxSetZMode_(0, 3, 0);
        GXSetCullMode(0);
    }
    GXSetArray(9, ((int*)((char*)am + 0x1c))[(*(u16*)((char*)am + 0x18) >> 1) & 1], 6);
    done = 0;
    while (!done)
    {
        u32 op4;
        {
            u32 w;
            int pos = bs.pos;
            u8* p = (u8*)((pos >> 3) + (char*)bs.data);
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
                GXSetVtxDesc(0, 1);
            }
            {
                u32 w;
                int pos = bs.pos;
                u8* p = (u8*)((pos >> 3) + (char*)bs.data);
                w = p[0];
                w |= p[1] << 8;
                w |= p[2] << 16;
                bs.pos = pos + 1;
                GXSetVtxDesc(9, (((int)(w >> (pos & 7)) & 1) ? 3 : 2));
            }
            if (((u8*)op)[0x40] & 1)
            {
                bs.pos += 1;
            }
            if (((u8*)op)[0x40] & 2)
            {
                bs.pos += 1;
            }
            GXSetVtxDesc(0xb, 1);
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
                op = ObjModel_GetRenderOp((int)m, (w >> (pos & 7)) & 0x3f);
            }
            break;
        case 2:
            {
                u8* dl;
                u32 w;
                int pos = bs.pos;
                u8* p = (u8*)((pos >> 3) + (char*)bs.data);
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

extern int* Obj_GetPlayerObject(void);
extern f32 Camera_DistanceToCurrentViewPosition(f32 x, f32 y, f32 z);
extern f32 lbl_803DEA38;
extern u16 lbl_803DEA4A[3];
extern f32 lbl_803DEA50;
extern f32 lbl_803DEA54;
extern f32 lbl_803DCC50;
extern u8 lbl_803DCC35;
extern u8 lbl_803DCC20;
extern u8 lbl_803DCC3E;
extern u8 lbl_802CAEDC[];
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

    lbl_803DCC2A = 0;
    lbl_803DCC2C = 0;
    lbl_803DCC30 = 0;
    lbl_803DCC34 = 0;
    lbl_803DB474 = -1;
    lbl_803DB478 = 0xff;
    lbl_803DB479 = 0xff;
    lbl_803DB47C = -1;
    lbl_803DB480 = 0xff;
    lbl_803DB481 = 0xff;
    lbl_803DB482 = 0xff;
    lbl_803DB484[3] = 0;
    lbl_803DB484[2] = 0;
    lbl_803DB484[1] = 0;
    lbl_803DB484[0] = 0;
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
    lbl_803DCC4C = 0;
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
                lbl_803DCC4C = 1;
                lbl_803DCC50 = dist;
            }
        }
    }
    if (lbl_803DCC28 != 0)
    {
        *(u8*)&lbl_803DCC54 = lbl_803DCC58;
        ((u8*)&lbl_803DCC54)[1] = (&lbl_803DCC58)[1];
        ((u8*)&lbl_803DCC54)[2] = (&lbl_803DCC58)[2];
        lbl_803DCC28 = 0;
    }
    else
    {
        objGetColor(*(u8*)((char*)obj + 0xf2), (u8*)&lbl_803DCC54, (u8*)&lbl_803DCC54 + 1, (u8*)&lbl_803DCC54 + 2);
    }
    mode8 = mode;
    m4 = mode8 & 4;
    if (m4 || (mode8 & 8))
    {
        fade = *(f32*)&lbl_803DEA4A[1];
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
                    modelInitBoneMtxs2(am, wm, lbl_80342E10);
                }
                else
                {
                    modelInitBoneMtxs(am, lbl_80342E10);
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
                ObjModel_BlendPrimaryVertexStream(lbl_80342E10, m + 0x88, vtx, *(int*)&((ModelFileHeader*)am)->unk40,
                                                  ((int*)((char*)am + 0x1c))[(*(u16*)((char*)am + 0x18) >> 1) & 1]);
                ObjModel_BlendSecondaryVertexStream(lbl_80342E10, m + 0xac, *(int*)&((ModelFileHeader*)m)->normals,
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
        int j;
        int joff;
        f32 a1c = lbl_803DEA1C;
        j = 0;
        joff = 0;
        for (; j < ((ModelFileHeader*)m)->jointCount; j++)
        {
            f32 sc = (f32)lbl_803DCC40 * (fade / *(f32*)(((ModelFileHeader*)m)->unk40 + joff + 0xc)) + a1c;
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
            u8* idp = lbl_802CAED0;
            f32 z;
            GXLoadPosMtxImm(fm, idp[9]);
            z = lbl_803DEA04;
            fm[3] = z;
            fm[7] = z;
            fm[11] = z;
            PSMTXConcat(fm, sm, fm);
            GXLoadNrmMtxImm(fm, idp[9]);
            GXLoadTexMtxImm(fm, lbl_802CAEDC[9], 0);
        }
    }
    m1 = mode8 & 1;
    if (m1 != 0)
    {
        GXSetNumTexGens(0);
        GXSetNumTevStages(1);
        GXSetNumIndStages(0);
        GXSetTevOrder(0, 0xff, 0xff, 4);
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
                GXSetTevColor(3, &tev1);
                GXSetBlendMode(0, 1, 0, 5);
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
                GXSetTevColor(3, &tev2);
                GXSetBlendMode(2, 1, 0, 7);
            }
        }
        GXSetTevDirect(0);
        GXSetTevColorIn(0, 0xf, 0xf, 0xf, 6);
        GXSetTevAlphaIn(0, 7, 7, 7, 3);
        GXSetTevSwapMode(0, 0, 0);
        GXSetTevColorOp(0, 0, 0, 0, 1, 0);
        GXSetTevAlphaOp(0, 0, 0, 0, 1, 0);
        GXSetFog(0, lbl_803DEA04, lbl_803DEA04, lbl_803DEA04, lbl_803DEA04, *(ObjGXColor*)&lbl_803DB468);
        gxSetPeControl_ZCompLoc_(1);
        GXSetAlphaCompare(7, 0, 0, 7, 0);
        GXSetChanCtrl(4, 0, 0, 1, 0, 0, 2);
        GXSetNumChans(1);
        if (OBJPRINT_MODEL_DEF(obj)->renderFlags & 4)
        {
            gxSetZMode_(1, 3, 1);
            GXSetCullMode(1);
        }
        else
        {
            gxSetZMode_(0, 3, 0);
            GXSetCullMode(0);
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
            GXSetFog(0, lbl_803DEA04, lbl_803DEA04, lbl_803DEA04, lbl_803DEA04, *(ObjGXColor*)&lbl_803DB468);
        }
        else
        {
            _gxSetFogParams();
        }
    }
    GXSetArray(9, ((int*)((char*)am + 0x1c))[(*(u16*)((char*)am + 0x18) >> 1) & 1], 6);
    if (((ModelFileHeader*)m)->flags24 & 8)
    {
        GXSetArray(0xa, *(int*)((char*)am + 0x24), 9);
    }
    else
    {
        GXSetArray(0xa, *(int*)((char*)am + 0x24), 3);
    }
    GXSetArray(0xb, *(int*)&((ModelFileHeader*)m)->unk30, 2);
    GXSetArray(0xd, *(int*)&((ModelFileHeader*)m)->unk34, 4);
    GXSetArray(0xe, *(int*)&((ModelFileHeader*)m)->unk34, 4);
    done = 0;
    while (!done)
    {
        u32 op4;
        {
            u32 w;
            int pos = bs.pos;
            u8* p = (u8*)((pos >> 3) + (char*)bs.data);
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
                if (lbl_803DCC20 == 0)
                {
                    u32 idx = objRenderFn_8003edf4((u8*)obj, m, am, &bs);
                    op = ObjModel_GetRenderOp((int)m, idx);
                }
                else
                {
                    u32 idx;
                    u32 w;
                    int pos = bs.pos;
                    u8* p = (u8*)((pos >> 3) + (char*)bs.data);
                    w = p[0];
                    w |= p[1] << 8;
                    w |= p[2] << 16;
                    bs.pos = pos + 6;
                    idx = (w >> (pos & 7)) & 0x3f;
                    op = ObjModel_GetRenderOp((int)m, idx);
                    refs = ObjModel_GetRenderOpTextureRefs(am, idx);
                }
            }
            break;
        case 2:
            if ((mode != 4 && mode != 8) || lbl_803DCC3E != 0)
            {
                u8* dl;
                u32 w;
                int pos = bs.pos;
                u8* p = (u8*)((pos >> 3) + (char*)bs.data);
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
extern void gxColorFn_800523d0(void);
extern void textureFn_800524ec(u8 * color);
extern f32 lbl_803DEA48;

u8 modelRenderFn_8003e98c(u8* obj, u8* shader, u32* p3, int mask, int p5, int p6)
{
    void* tex;
    u8* colp;
    u16 alpha;
    u8* prev;
    u8* layer;
    int layerIdx;
    u8 ok;
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
    colp = (u8*)&lbl_803DCC54;
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
                    int fl;
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
                                        tx = lbl_803DEA48 * (f32)slots2[k2].offsetS;
                                        ty = lbl_803DEA48 * (f32)slots2[k2].offsetT;
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
                            fn_80051B00(tex, (int)mtxp, (u8)fl, (u8*)&lbl_803DCC54);
                        }
                        else
                        {
                            gxFn_80051fb8(tex, (int)mtxp, (u8)fl, (u8*)&lbl_803DCC54, *((u8*)p3 + 8), 1);
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
                        gxColorFn_80052764((u8*)&lbl_803DCC54);
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

extern ObjModelRenderCb ObjModel_GetPostRenderCallback(int* am);
extern u8 textureFn_80050ad8(void* tex, int n, int p3, u32 p4);
extern void textureFn_80051348(u32 ref, int p2);
extern void fn_800510F0(u32 ref, int p2, int p3);
extern void fn_80050FF4(int p1);
extern void fn_8004D230(void);
extern void fn_8005011C(f32 * m);
extern void fn_8004D6D8(void);
extern u32 modelLightStruct_getProjectionTexture(int light);
extern void fn_80050558(u32 t, int p2, int p3, int p4, int p5);
extern void fn_80050A28(int t);
extern void fn_80050F2C(void);
extern void textureFn_8004c330(void* tex, f32* m);
extern void gxTextureFn_8004d5b4(int* op);
extern void gxTextureFn_80052638(u8 * color);
extern void fn_80118240(void);
extern void fn_8004D928(void);
extern f32 lbl_803967F0[];
extern u8 lbl_803DCC3C;

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
    op = ObjModel_GetRenderOp(*am, idx);
    refs = ObjModel_GetRenderOpTextureRefs(am, idx);
    resetLotsOfRenderVars();
    envtex = 0;
    if ((refs[0] != 0 || refs[1] != 0) && ((ObjModelRenderOp*)op)->unk34 != 0)
    {
        void* t = textureIdxToPtr(((ObjModelRenderOp*)op)->unk34);
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
        GXSetTevColor(3, &tmp1);
        fn_800510F0(refs[1], refs[0] != 0 ? 1 : 0, ((u8*)op)[0x20]);
        if (color[3] != 0)
        {
            fn_80050FF4(refs[0] != 0 ? 1 : 0);
        }
    }
    else
    {
        tmp2 = lbl_803DB46C;
        GXSetTevColor(3, &tmp2);
    }
    nlay = lbl_803DCC5C;
    if (lbl_803DCC4C != 0)
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
            int i;
            int* lp;
            u8* sp;
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
                    fn_80050558(t, modelLightStruct_getProjectionTexMtx(*lp), a, b, *sp);
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
        if ((t18 = ((ObjModelRenderOp*)op)->unk18) != 0 && ((ObjModelRenderOp*)op)->unk1C == 0 && refs[1] != 0)
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
        if (((ObjModelRenderOp*)op)->unk3C & 0x100000)
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
                        tx = lbl_803DEA48 * (f32)slots[k].offsetS;
                        ty = lbl_803DEA48 * (f32)slots[k].offsetT;
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
    if (((ObjModelRenderOp*)op)->unk3C & 0x100)
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
    if (((ObjModelRenderOp*)op)->unk3C & 0x20000)
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
            if (obj[0x37] < 0xff || (((ObjModelRenderOp*)op)->unk3C & 0x40000000) || shad)
            {
                u16 f2;
                GXSetBlendMode(1, 4, 5, 5);
                f2 = *(u16*)(p2 + 2);
                if (f2 & 0x400)
                {
                    gxSetZMode_(0, 3, 0);
                    GXSetAlphaCompare(7, 0, 0, 7, 0);
                }
                else if (f2 & 0x2000)
                {
                    zon = 0;
                    gxSetZMode_(1, 3, 1);
                    GXSetAlphaCompare(4, lbl_803DCC3C, 0, 4, lbl_803DCC3C);
                }
                else
                {
                    gxSetZMode_(1, 3, 0);
                    GXSetAlphaCompare(7, 0, 0, 7, 0);
                }
            }
            else if (((ObjModelRenderOp*)op)->unk3C & 0x400)
            {
                GXSetBlendMode(0, 1, 0, 5);
                if (*(u16*)(p2 + 2) & 0x400)
                {
                    gxSetZMode_(0, 3, 0);
                }
                else
                {
                    gxSetZMode_(1, 3, 1);
                }
                GXSetAlphaCompare(4, 0x40, 0, 4, 0x40);
            }
            else
            {
                GXSetBlendMode(0, 1, 0, 5);
                if (*(u16*)(p2 + 2) & 0x400)
                {
                    gxSetZMode_(0, 3, 0);
                }
                else
                {
                    gxSetZMode_(1, 3, 1);
                }
                GXSetAlphaCompare(7, 0, 0, 7, 0);
            }
            if (((ObjModelRenderOp*)op)->unk3C & 0x400)
            {
                zon = 0;
            }
            gxSetPeControl_ZCompLoc_(zon);
        }
    }
    if (((ObjModelRenderOp*)op)->unk3C & 8)
    {
        GXSetCullMode(2);
    }
    else
    {
        GXSetCullMode(0);
    }
    return idx;
}

extern u8 lbl_80345E10[];
extern void mm_free(void*);
extern void texFlagFn_80023cbc(int);
extern void texRestructRefs(int);
extern s16 lbl_803DCC78;
extern void testAndSet_onlyUseHeaps1and2(int);
extern int mmGetRegionForPtr(void*);
extern void* mmAlloc(int size, int tag, int p3);
extern void* memcpy(void*, void*, int);
extern int mmSetFreeDelay(int);
extern int getHeapItemSize(void*);

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
        char* p1;
        char* p2;
        char* p3;
        char* p4;
        int i;
        testAndSet_onlyUseHeaps1and2(1);
        i = 0;
        {
            char* hi = (char*)base + 0x20000;
            p1 = hi - 0x6a28;
            p2 = hi - 0x68c8;
            p3 = hi - 0x6d68;
            p4 = hi - 0x6f20;
        }
        for (; i <= 0x57; i++)
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
        }
        testAndSet_onlyUseHeaps1and2(-1);
    }
    base += 0x20000;
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
        for (; i <= 0x57; i++)
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
        }
        pass++;
    }
    texFlagFn_80023cbc(0);
}

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
extern u32 lbl_80345F70[];
extern void AtomicSList_Push(void* list, void* item);
extern int DVDClose(void* fileInfo);

void tex0tab1readCb(s32 result, void* fileInfo)
{
    if (result < 0)
    {
        DVDClose(fileInfo);
        AtomicSList_Push(lbl_803DCC8C, fileInfo);
        mm_free((void*)lbl_8035F3E8[36]);
        lbl_8035F3E8[36] = 0;
        lbl_80345F70[36] = 0;
        if (lbl_803DCC80 & 0x400)
        {
            lbl_803DCC84 |= 0x400;
            lbl_80345F70[36] = 0;
        }
    }
    else
    {
        DVDClose(fileInfo);
        AtomicSList_Push(lbl_803DCC8C, fileInfo);
        if (lbl_803DCC80 & 0x400)
        {
            lbl_803DCC84 |= 0x400;
            lbl_80345F70[36] = 0;
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
        lbl_80345F70[78] = 0;
        if (lbl_803DCC80 & 0x800)
        {
            lbl_803DCC84 |= 0x800;
            lbl_80345F70[78] = 0;
        }
    }
    else
    {
        DVDClose(fileInfo);
        AtomicSList_Push(lbl_803DCC8C, fileInfo);
        if (lbl_803DCC80 & 0x800)
        {
            lbl_803DCC84 |= 0x800;
            lbl_80345F70[78] = 0;
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
        lbl_80345F70[78] = 0;
        if (lbl_803DCC80 & 0x4000)
        {
            lbl_803DCC84 |= 0x4000;
            lbl_80345F70[33] = 0;
        }
    }
    else
    {
        DVDClose(fileInfo);
        AtomicSList_Push(lbl_803DCC8C, fileInfo);
        if (lbl_803DCC80 & 0x4000)
        {
            lbl_803DCC84 |= 0x4000;
            lbl_80345F70[33] = 0;
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
        lbl_80345F70[78] = 0;
        if (lbl_803DCC80 & 0x8000)
        {
            lbl_803DCC84 |= 0x8000;
            lbl_80345F70[76] = 0;
        }
    }
    else
    {
        DVDClose(fileInfo);
        AtomicSList_Push(lbl_803DCC8C, fileInfo);
        if (lbl_803DCC80 & 0x8000)
        {
            lbl_803DCC84 |= 0x8000;
            lbl_80345F70[76] = 0;
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
        (&lbl_803DB5B0)[0] = -2;
        (&lbl_803DB5B0)[1] = -2;
        return -1;
    }
    cur = (&lbl_803DB5B0)[idx];
    if (val == cur || cur == -2)
    {
        (&lbl_803DB5B0)[idx] = -2;
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
            lbl_80345F70[0xc0 / 4] = 0;
        }
        else if (lbl_803DCC80 & 0x20)
        {
            lbl_803DCC84 |= 0x20;
            lbl_80345F70[0x128 / 4] = 0;
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
            lbl_80345F70[0x34 / 4] = 0;
        }
        else if (lbl_803DCC80 & 0x40000000)
        {
            lbl_803DCC84 |= 0x40000000;
            lbl_80345F70[0x154 / 4] = 0;
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
            lbl_80345F70[0x38 / 4] = 0;
        }
        else if (lbl_803DCC80 & 0x80000000)
        {
            lbl_803DCC84 |= 0x80000000;
            lbl_80345F70[0x158 / 4] = 0;
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
            lbl_80345F70[0xbc / 4] = 0;
        }
        else if (lbl_803DCC80 & 0x80)
        {
            lbl_803DCC84 |= 0x80;
            lbl_80345F70[0x124 / 4] = 0;
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
            lbl_80345F70[0x94 / 4] = 0;
        }
        else if (lbl_803DCC80 & 0x40000)
        {
            lbl_803DCC84 |= 0x40000;
            lbl_80345F70[0x11c / 4] = 0;
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
            lbl_80345F70[0x98 / 4] = 0;
        }
        else if (lbl_803DCC80 & 0x80000)
        {
            lbl_803DCC84 |= 0x80000;
            lbl_80345F70[0x120 / 4] = 0;
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
            lbl_80345F70[0xac / 4] = 0;
        }
        else if (lbl_803DCC80 & 0x2)
        {
            lbl_803DCC84 |= 0x2;
            lbl_80345F70[0x118 / 4] = 0;
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
            lbl_80345F70[0xa8 / 4] = 0;
        }
        else if (lbl_803DCC80 & 0x8)
        {
            lbl_803DCC84 |= 0x8;
            lbl_80345F70[0x114 / 4] = 0;
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
            lbl_80345F70[0x8c / 4] = 0;
        }
        else if (lbl_803DCC80 & 0x200)
        {
            lbl_803DCC84 |= 0x200;
            lbl_80345F70[0x134 / 4] = 0;
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
            lbl_80345F70[0x80 / 4] = 0;
        }
        else if (lbl_803DCC80 & 0x2000)
        {
            lbl_803DCC84 |= 0x2000;
            lbl_80345F70[0x12c / 4] = 0;
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
            lbl_80345F70[0x6c / 4] = 0;
        }
        else if (lbl_803DCC80 & 0x4000000)
        {
            lbl_803DCC84 |= 0x4000000;
            lbl_80345F70[0x150 / 4] = 0;
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
            lbl_80345F70[0x68 / 4] = 0;
        }
        else if (lbl_803DCC80 & 0x8000000)
        {
            lbl_803DCC84 |= 0x8000000;
            lbl_80345F70[0x14c / 4] = 0;
        }
    }
}

extern void mapLoadDataFiles(int idx);
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

extern void mapLoadDataFile(int mapIdx, int fileType);

void mapLoadDataFiles(int mapIdx)
{
    if (sMapFileNameAdjacencyTable[mapIdx] != -1)
    {
        int* r = (int*)(*gMapEventInterface)->getCurCharPos();
        *(s8*)((char*)r + 0xe) = (s8)mapIdx;
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
extern void mmFreeTick(int);
extern void gameTextRun(void);
extern void GXFlush_(int, int);
extern u8 gDvdErrorPauseActive;
int mergeTableFiles(u32* tbl, int id, int idx, int count_);

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
            if (v != lbl_803DB5B0 && v != (&lbl_803DB5B0)[1])
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
        lockp = &lbl_803DB5B0;
        hi = (char*)base + 0x20000;
        for (; i < 0x38; i += 2)
        {
            if ((f20 && mapId == ((int*)((char*)base + 0x20000))[e[0] - 0x1bb2])
                || (f10 && mapId != ((int*)((char*)base + 0x20000))[e[0] - 0x1bb2])
                || ((flags & e[1]) && mapId == ((int*)((char*)base + 0x20000))[e[0] - 0x1bb2]))
            {
                ((int*)((char*)base + 0x20000))[e[0] - 0x1bb2] = -1;
            }
            {
                int idx = e[0];
                if (((int**)hi)[idx - 0x1a8a] != NULL)
                {
                    s16 v;
                    if (f80
                        || ((flags & e[1]) && mapId == ((s16*)hi)[idx - 0x3464])
                        || (f10 && mapId != ((s16*)((char*)base + 0x20000))[idx - 0x3464])
                        || (f20 && mapId == ((s16*)((char*)base + 0x20000))[idx - 0x3464]))
                    {
                        if (lbl_803DB5B0 != (v = ((s16*)((char*)base + 0x20000))[idx - 0x3464])
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
                                    if (sMapFileNameIndexRemapTable[j] == ((s16*)((char*)base + 0x20000))[e[0] -
                                        0x3464])
                                    {
                                        break;
                                    }
                                }
                                if (j <= 0x50 && j != 0x49 && j != 0x43 && j != 5)
                                {
                                    int* slot = &((int*)((char*)base + 0x20000))[j - 0x1b02];
                                    mm_free((void*)*slot);
                                    *slot = 0;
                                }
                                break;
                            }
                            mm_free((void*)((int*)((char*)base + 0x20000))[e[0] - 0x1a8a]);
                            mmSetFreeDelay(2);
                            ((int*)((char*)base + 0x20000))[e[0] - 0x1a8a] = 0;
                            ((s16*)((char*)base + 0x20000))[e[0] - 0x3464] = -1;
                            ((int*)((char*)base + 0x20000))[e[0] - 0x1b5a] = 0;
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

extern void debugPrintfxy(int x, int y, char* fmt, ...);
extern char sAssetIndexOverflowError[];

int mergeTableFiles(u32* tbl, int id, int idx, int count_)
{
    u8* base = lbl_80345E10;
    int i = 0;
    int e1 = 0;
    int e2 = 0;
    int count = 0;
    int v;
    int* p1;
    int* p2;
    int* dst;
    char* hi = (char*)base + 0x20000;
    int* src1 = *(int**)(hi + id * 4 - 0x6a28);
    if (src1 == NULL || ((int**)hi)[idx - 0x1a8a] == NULL)
    {
        if (src1 == NULL)
        {
            e1 = 1;
        }
        if (((int**)hi)[idx - 0x1a8a] == NULL)
        {
            e2 = 1;
        }
    }
    p1 = src1;
    p2 = ((int**)hi)[idx - 0x1a8a];
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
        dst = (int*)tbl;
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
        int* w2 = p2;
        dst = (int*)tbl;
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
        int* w2 = p2;
        dst = (int*)tbl;
        for (; count > 0; count--)
        {
            if (!e1 && *w1 == -1)
            {
                *dst = 0;
                e1 = 1;
            }
            else if (!e2 && *w2 == -1)
            {
                *dst = 0;
                e2 = 1;
            }
            else if (!e1 && (v = *w1, v != -1) && (v & 0x80000000))
            {
                *dst = v;
            }
            else if (!e2 && (v = *w2, v != -1) && (v & 0x80000000))
            {
                *dst = (v & 0x7fffffff) | 0x20000000;
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
    else if (tbl == (u32*)(base + 0x2c0))
    {
        int* w1 = p1;
        int* w2 = p2;
        dst = (int*)tbl;
        for (; count > 0; count--)
        {
            if (!e1 && *w1 == -1)
            {
                *dst = 0;
                e1 = 1;
            }
            else if (!e2 && *w2 == -1)
            {
                *dst = 0;
                e2 = 1;
            }
            else if (!e1 && (v = *w1, v != -1) && (v & 0x80000000))
            {
                *dst = v;
            }
            else if (!e2 && (v = *w2, v != -1) && (v & 0x80000000))
            {
                *dst = (v & 0x7fffffff) | 0x20000000;
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
    else
    {
        int* w1 = p1;
        int* w2 = p2;
        dst = (int*)tbl;
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
            i++;
            w1++;
            w2++;
            dst++;
        }
    }
    tbl[i - 1] = 0xffffffff;
    return 1;
}

extern s32 lbl_803DCC94;

u32 loadTableFiles(void)
{
    u8* base = lbl_80345E10;
    int s = OSDisableInterrupts();
    int flags = getLoadedFileFlags();
    lbl_803DCC80;
    if ((lbl_803DCC94 & 0x4) && !(flags & 0x4) && *(s32*)(base + 0x191e4) == -1)
    {
        mergeTableFiles((u32*)(base + 0x170e0), 0x2a, 0x45, 0x800);
    }
    if ((lbl_803DCC94 & 0x8) && !(flags & 0x8) && *(s32*)(base + 0x19250) == -1)
    {
        mergeTableFiles((u32*)(base + 0x170e0), 0x2a, 0x45, 0x800);
    }
    if ((lbl_803DCC94 & 0x40) && !(flags & 0x40) && *(s32*)(base + 0x191f8) == -1)
    {
        mergeTableFiles((u32*)(base + 0x14200), 0x2f, 0x49, 0xbb8);
    }
    if ((lbl_803DCC94 & 0x80) && !(flags & 0x80) && *(s32*)(base + 0x19260) == -1)
    {
        mergeTableFiles((u32*)(base + 0x14200), 0x2f, 0x49, 0xbb8);
    }
    if ((lbl_803DCC94 & 0x400) && !(flags & 0x400) && *(s32*)(base + 0x191c4) == -1)
    {
        mergeTableFiles((u32*)(base + 0x10200), 0x24, 0x4e, 0x1000);
    }
    if ((lbl_803DCC94 & 0x800) && !(flags & 0x800) && *(s32*)(base + 0x1926c) == -1)
    {
        mergeTableFiles((u32*)(base + 0x10200), 0x24, 0x4e, 0x1000);
    }
    if ((lbl_803DCC94 & 0x4000) && !(flags & 0x4000) && *(s32*)(base + 0x191b8) == -1)
    {
        mergeTableFiles((u32*)(base + 0xc200), 0x21, 0x4c, 0x1000);
    }
    if ((lbl_803DCC94 & 0x8000) && !(flags & 0x8000) && *(s32*)(base + 0x19264) == -1)
    {
        mergeTableFiles((u32*)(base + 0xc200), 0x21, 0x4c, 0x1000);
    }
    if ((lbl_803DCC94 & 0x20000) && !(flags & 0x20000) && *(s32*)(base + 0x191cc) == -1)
    {
        mergeTableFiles((u32*)(base + 0xa200), 0x26, 0x48, 0x800);
    }
    if ((lbl_803DCC94 & 0x80000) && !(flags & 0x80000) && *(s32*)(base + 0x19254) == -1)
    {
        mergeTableFiles((u32*)(base + 0xa200), 0x26, 0x48, 0x800);
    }
    if ((lbl_803DCC94 & 0x2000000) && !(flags & 0x2000000) && *(s32*)(base + 0x191a4) == -1)
    {
        mergeTableFiles((u32*)(base + 0x8200), 0x1a, 0x53, 0x800);
    }
    if ((lbl_803DCC94 & 0x8000000) && !(flags & 0x8000000) && *(s32*)(base + 0x19288) == -1)
    {
        mergeTableFiles((u32*)(base + 0x8200), 0x1a, 0x53, 0x800);
    }
    if ((lbl_803DCC94 & 0x20000000) && !(flags & 0x20000000) && *(s32*)(base + 0x1916c) == -1)
    {
        mergeTableFiles((u32*)(base + 0x2c0), 0xe, 0x56, 0x1fd0);
    }
    if ((lbl_803DCC94 & 0x80000000) && !(flags & 0x80000000) && *(s32*)(base + 0x1928c) == -1)
    {
        mergeTableFiles((u32*)(base + 0x2c0), 0xe, 0x56, 0x1fd0);
    }
    lbl_803DCC94 = flags;
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
        table = &base[0x170e0];
        break;
    case 0x2f:
        count = 0xbb8;
        table = &base[0x14200];
        break;
    case 0x24:
        count = 0x1000;
        table = &base[0x10200];
        break;
    case 0x21:
        count = 0x1000;
        table = &base[0xc200];
        break;
    case 0x50:
        table = *(void**)&base[0x19718];
        break;
    case 0x26:
        count = 0x800;
        table = &base[0xa200];
        break;
    case 0x1a:
        count = 0x800;
        table = &base[0x8200];
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
