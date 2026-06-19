/*
 * dll 0xB2 - per-render-op texture callback for the camcontrol A-button
 * reticle icon (registered by dll 0xB4 onto the active reticle model).
 *
 * For each render op of the reticle it picks the icon's vertex alpha:
 * the "press A" variant (variantId 1) is hidden unless the focused
 * camera target accepts input, otherwise it inherits the reticle
 * object's anim alpha. A suppressed target kind hides the icon
 * entirely. It then binds the op's texture, fades it in (blend +
 * non-writing Z when translucent, opaque path otherwise) and sets the
 * fixed alpha-compare / cull state used for HUD icons.
 */
#include "main/dll/dll_B2.h"
#include "main/dll/CAM/dll_0001_camcontrol.h"

typedef struct CamcontrolIconRenderOp {
    u8 pad00[0x24];
    s32 textureId;     /* 0x24 */
    u8 pad28;          /* 0x28 */
    u8 variantId;      /* 0x29: 1 = "press A" icon variant */
} CamcontrolIconRenderOp;

typedef struct CamcontrolIconColor {
    u8 r;
    u8 g;
    u8 b;
    u8 a;
} CamcontrolIconColor;

extern void* ObjModel_GetRenderOp(u8* model, int renderOpIndex);
extern void* textureIdxToPtr(int idx);
extern void resetLotsOfRenderVars(void);
extern void textureFn_800528bc(void);
extern void fn_80051D5C(void* tex, void* a, u32 b, CamcontrolIconColor* color);
extern void GXSetBlendMode(int type, int src, int dst, int op);
extern void gxSetZMode_(u32 compareEnable, int compareFunc, u32 updateEnable);
extern void gxSetPeControl_ZCompLoc_(u32 zCompLoc);
extern void GXSetAlphaCompare(int comp0, u8 ref0, int op, int comp1, u8 ref1);
extern void GXSetCullMode(int mode);

#define ICON_VARIANT_PRESS_A 1

int aButtonIconTexCb(GameObject* obj, void** objPtr, u32 renderOpIdx)
{
    CamcontrolIconRenderOp* renderOp;
    CamcontrolIconColor color; /* r/g/b intentionally left unset: callee reads only alpha for this op */

    renderOp = ObjModel_GetRenderOp(*objPtr, renderOpIdx);
    resetLotsOfRenderVars();
    if (renderOp->variantId == ICON_VARIANT_PRESS_A)
    {
        if ((CAMCONTROL_CAMERA->targetFlags & CAMCONTROL_CAMERA_TARGET_FLAG_ACCEPTS_INPUT) == 0)
        {
            color.a = 0;
        }
        else
        {
            color.a = obj->anim.alpha;
        }
    }
    else
    {
        color.a = obj->anim.alpha;
    }
    if (CAMCONTROL_CAMERA->targetKind == CAMCONTROL_TARGET_KIND_SUPPRESSED)
    {
        color.a = 0;
    }
    fn_80051D5C(textureIdxToPtr(renderOp->textureId), 0, 0, &color);
    textureFn_800528bc();
    if (color.a < 0xff)
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
