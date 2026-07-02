/*
 * dll_B4 - lock-on / A-button reticle setup.
 *
 * Lazily creates the shared camcontrol reticle object (gCamcontrolTargetReticle)
 * on first use: spawns the object, registers the lock-on and A-button icon
 * render callbacks against its two model banks, and builds a directional light
 * (lbl_803DD4C4) aimed by the camcontrol normalized vector for lighting the icon.
 */
#include "main/dll/dll_B4.h"
#include "main/dll/dll_B3.h"
#include "main/dll/dll_B2.h"
#include "main/model_light.h"

#define MODEL_LIGHT_KIND_DIRECTIONAL 4

extern void* Obj_AllocObjectSetup(int size, int b);
extern u8* Obj_SetupObject(u8* obj, int a, int b, int c, int d);
extern void* Obj_GetActiveModel(u8* obj);
extern void ObjModel_SetRenderCallback(u8* model, void* callback);
extern void lightSetColor(int a, int b, int c, int d);
extern void* objCreateLight(int arg, u8 addToList);
extern void objSetEventName(ModelLightStruct* p, int a);
extern ModelLightStruct* lbl_803DD4C4;
extern f32 lbl_803E1640;

void lockIconInit(void)
{
    if (gCamcontrolTargetReticle == NULL)
    {
        gCamcontrolTargetReticle = (CamcontrolReticleObject*)Obj_SetupObject(
            Obj_AllocObjectSetup(0x18, 0x1FE), 4, -1, -1, 0);
        ObjModel_SetRenderCallback(Obj_GetActiveModel((u8*)gCamcontrolTargetReticle), lockIconTexCb);
        gCamcontrolTargetReticle->anim.bankIndex = CAMCONTROL_RETICLE_ICON_LOCKON;
        ObjModel_SetRenderCallback(Obj_GetActiveModel((u8*)gCamcontrolTargetReticle), aButtonIconTexCb);
        gCamcontrolTargetReticle->anim.bankIndex = CAMCONTROL_RETICLE_ICON_A_BUTTON;
        ObjModel_SetRenderCallback(Obj_GetActiveModel((u8*)gCamcontrolTargetReticle), aButtonIconTexCb);
        lightSetColor(1, 0x32, 0x3C, 0x28);
        lbl_803DD4C4 = objCreateLight(0, 1);
        if (lbl_803DD4C4 != NULL)
        {
            modelLightStruct_setLightKind(lbl_803DD4C4, MODEL_LIGHT_KIND_DIRECTIONAL);
            modelLightStruct_setObjectLightMaskIndex(lbl_803DD4C4, 1);
            objSetEventName(lbl_803DD4C4, 1);
            modelLightStruct_setDirection(lbl_803DD4C4, gCamcontrolNormalizedMax, gCamcontrolNormalizedMin, lbl_803E1640);
            modelLightStruct_setDiffuseColor(lbl_803DD4C4, 0xB4, 0xC8, 0xFF, 0xFF);
        }
    }
}
