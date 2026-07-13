/*
 * DLL 0x125 - "curve" object DLL. TU range 0x80171300-0x801713D8.
 *
 * The curve object itself is a placement-only animator: curve_init reads the
 * ROMCURVE placement type to set rotation (rotX/rotY from the placement bytes,
 * rotZ from a special-angle field for the angle-8/1A types) and a root-motion
 * scale (overridden for the scale-15/16 types, otherwise the model default);
 * curve_render just forwards a render fn when visible. The remaining callbacks
 * (getExtraSize/getObjectTypeId/func11/setScale/free) are stubs.
 */
#include "main/dll/xyzanimator.h"
#include "main/dll/dll_0125_curve_api.h"
#include "main/dll/genprops.h"
#include "main/objlib.h"

extern f32 lbl_803E33F0;
extern f32 lbl_803E33F4;
extern f32 lbl_803E33F8;

int curve_func0B(void)
{
    return 0x0;
}

void curve_setScale(void)
{
}

int curve_getExtraSize(void)
{
    return 0x0;
}
int curve_getObjectTypeId(void)
{
    return 0x0;
}

void curve_free(void)
{
}

void curve_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0)
        objRenderModelAndHitVolumes(lbl_803E33F0);
}

void curve_init(ObjAnimComponent* obj, CurvePlacementParams* params)
{
    obj->rotX = (s16)(params->placement.rotZ << 8);
    obj->rotY = (s16)(params->placement.rotY << 8);
    if (params->placement.base.type == ROMCURVE_TYPE_SPECIAL_ANGLE_8 ||
        params->placement.base.type == ROMCURVE_TYPE_SPECIAL_ANGLE_1A)
    {
        obj->rotZ = params->specialAngle;
    }
    if (params->placement.base.type == ROMCURVE_TYPE_SCALE_OVERRIDE_15)
    {
        obj->rootMotionScale = lbl_803E33F4;
    }
    else if (params->placement.base.type == ROMCURVE_TYPE_SCALE_OVERRIDE_16)
    {
        obj->rootMotionScale = lbl_803E33F8;
    }
    else
    {
        obj->rootMotionScale = obj->modelInstance->rootMotionScaleBase;
    }
}

ObjectDescriptor12 gCurveObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_12_SLOTS,
    0,
    0,
    0,
    (ObjectDescriptorCallback)curve_init,
    0,
    0,
    (ObjectDescriptorCallback)curve_render,
    (ObjectDescriptorCallback)curve_free,
    (ObjectDescriptorCallback)curve_getObjectTypeId,
    curve_getExtraSize,
    (ObjectDescriptorCallback)curve_setScale,
    (ObjectDescriptorCallback)curve_func0B,
};
