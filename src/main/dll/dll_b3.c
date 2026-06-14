#include "main/dll/dll_B3.h"

typedef struct CamcontrolLockIconRenderOp {
    u8 pad00[0x24];
    s32 textureId;
    u8 pad28;
    u8 distanceTier;
} CamcontrolLockIconRenderOp;

typedef struct CamcontrolIconColor {
    u8 r;
    u8 g;
    u8 b;
    u8 a;
} CamcontrolIconColor;

extern CamcontrolLockIconRenderOp* ObjModel_GetRenderOp(int model, int idx);
extern void resetLotsOfRenderVars(void);
extern void textureFn_800528bc(void);
extern void* textureIdxToPtr(int idx);
extern void fn_80051D5C(void* tex, void* arg2, int arg3, CamcontrolIconColor* color);
extern void GXSetBlendMode(int mode, int srcFactor, int dstFactor, int op);
extern void gxSetZMode_(u32 enable, int func, u32 update);
extern void gxSetPeControl_ZCompLoc_(u32 ctrl);
extern void GXSetAlphaCompare(int compA, int refA, int op, int compB, int refB);
extern void GXSetCullMode(int mode);

int lockIconTexCb(GameObject* obj, int* modelPtr, int renderOpIdx)
{
    CamcontrolLockIconRenderOp* renderOp;
    u8 tier;
    CamcontrolIconColor color;
    f32 dist;
    int alphaVal;

    renderOp = ObjModel_GetRenderOp(*modelPtr, renderOpIdx);
    dist = CAMCONTROL_CAMERA->targetDistance;
    if (dist <= gCamcontrolNormalizedMin)
    {
        tier = 4;
    }
    else if (dist <= gCamcontrolTargetDistanceTier1)
    {
        tier = 3;
    }
    else if (dist <= gCamcontrolTargetDistanceTier2)
    {
        tier = 2;
    }
    else if (dist <= gCamcontrolTargetDistanceTier3)
    {
        tier = 1;
    }
    else
    {
        tier = 0;
    }
    resetLotsOfRenderVars();
    if (renderOp->distanceTier <= tier)
    {
        color.r = 0;
        color.g = 0;
        color.b = 0;
        alphaVal = ((obj->anim.alpha + 1) * 0x60) >> 8;
        color.a = alphaVal;
        fn_80051D5C(textureIdxToPtr(renderOp->textureId), 0, 0, &color);
    }
    else
    {
        color.r = 0xff;
        color.g = 0xff;
        color.b = 0xff;
        color.a = obj->anim.alpha;
        fn_80051D5C(textureIdxToPtr(renderOp->textureId), 0, 0, &color);
    }
    textureFn_800528bc();
    if (obj->anim.alpha < 0xff || renderOp->distanceTier <= tier)
    {
        GXSetBlendMode(1, 4, 5, 5);
        gxSetZMode_(1, 3, 0);
    }
    else
    {
        GXSetBlendMode(0, 1, 0, 5);
        gxSetZMode_(1, 3, 1);
    }
    gxSetPeControl_ZCompLoc_(1);
    GXSetAlphaCompare(7, 0, 0, 7, 0);
    GXSetCullMode(2);
    return 1;
}
