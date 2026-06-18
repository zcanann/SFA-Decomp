/*
 * dll_8b (DLL 0x8B) - thin camera-query accessors layered over the
 * camcontrol DLL (0x0001) state. Exposes the active camera target kind
 * (CamcontrolCameraState.targetKind, e.g. lock-on / A-button / talk
 * icon) and the minimap help-text id selected by camera targeting.
 * Read-only; other DLLs (e.g. the GameUI dll) call cameraGetTargetType
 * to branch on what the camera is currently locked onto.
 */
#include "main/dll/dll_8B.h"
#include "main/dll/CAM/dll_0001_camcontrol.h"

u8 cameraGetTargetType(void)
{
    return CAMCONTROL_CAMERA->targetKind;
}

s16 Camera_getMinimapInfoText(void)
{
    return gCamcontrolTargetHelpTextId;
}
