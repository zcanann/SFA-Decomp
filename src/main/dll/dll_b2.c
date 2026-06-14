#include "main/dll/dll_B2.h"
#include "main/dll/CAM/dll_0001_camcontrol.h"

typedef struct CamcontrolIconRenderOp {
    u8 pad00[0x24];
    s32 textureId;
    u8 pad28;
    u8 variantId;
} CamcontrolIconRenderOp;

typedef struct CamcontrolIconColor {
    u8 r;
    u8 g;
    u8 b;
    u8 a;
} CamcontrolIconColor;

extern CamcontrolIconRenderOp* ObjModel_GetRenderOp(void* model, undefined4 idx);
extern void* textureIdxToPtr(int idx);
extern void resetLotsOfRenderVars(void);
extern void textureFn_800528bc(void);
extern void fn_80051D5C(void* tex, undefined4 a, undefined4 b, CamcontrolIconColor* color);
extern void GXSetBlendMode(int type, int src, int dst, int op);
extern void gxSetZMode_(u32 a, int b, u32 c);
extern void gxSetPeControl_ZCompLoc_(u32 a);
extern void GXSetAlphaCompare(int comp0, u8 ref0, int op, int comp1, u8 ref1);
extern void GXSetCullMode(int mode);

int aButtonIconTexCb(GameObject* obj, void** objPtr, undefined4 arg3)
{
    CamcontrolIconRenderOp* renderOp;
    CamcontrolIconColor color;

    renderOp = ObjModel_GetRenderOp(*objPtr, arg3);
    resetLotsOfRenderVars();
    if (renderOp->variantId == 1)
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
