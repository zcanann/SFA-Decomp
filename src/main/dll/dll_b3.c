/*
 * dll_B3 - per-render-op texture callback for the camcontrol lock-on
 * reticle model, registered onto the active reticle model so the icon
 * fades by distance tier. Lives in its own DLL because the reticle model
 * is loaded on demand with the camcontrol HUD, not with the core renderer.
 */
#include "main/dll/dll_B3.h"
#include "dolphin/gx/GXStruct.h"
#include "main/dll/fx_800944A0_shared.h"

/* Single render op of the lock icon model (ObjModel_GetRenderOp slot). */
typedef struct CamcontrolLockIconRenderOp {
    u8 pad00[0x24];
    s32 textureId;          /* 0x24 */
    u8 pad28;               /* 0x28 */
    u8 distanceTier;        /* 0x29: tier at which this op switches to dim */
} CamcontrolLockIconRenderOp;

#define LOCK_ICON_DIM_ALPHA_SCALE 0x60

extern CamcontrolLockIconRenderOp* ObjModel_GetRenderOp(int model, int idx);
extern void fn_80051D5C(void* tex, void* arg2, int arg3, GXColor* color);

int lockIconTexCb(GameObject* obj, int* modelPtr, int renderOpIdx)
{
    CamcontrolLockIconRenderOp* renderOp;
    u8 tier;
    GXColor color;
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
        alphaVal = ((obj->anim.alpha + 1) * LOCK_ICON_DIM_ALPHA_SCALE) >> 8;
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
        GXSetBlendMode(GX_BM_BLEND, GX_BL_SRCALPHA, GX_BL_INVSRCALPHA, GX_LO_NOOP);
        gxSetZMode_(1, GX_LEQUAL, 0);
    }
    else
    {
        GXSetBlendMode(GX_BM_NONE, GX_BL_ONE, GX_BL_ZERO, GX_LO_NOOP);
        gxSetZMode_(1, GX_LEQUAL, 1);
    }
    gxSetPeControl_ZCompLoc_(1);
    GXSetAlphaCompare(GX_ALWAYS, 0, GX_AOP_AND, GX_ALWAYS, 0);
    GXSetCullMode(GX_CULL_BACK);
    return 1;
}
