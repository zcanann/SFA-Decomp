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
