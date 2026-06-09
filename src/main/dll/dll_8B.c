#include "main/dll/dll_8B.h"
#include "main/dll/CAM/camcontrol.h"

/*
 * --INFO--
 *
 * Function: projdfp1r_initialise
 * EN v1.0 Address: 0x80100A8C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80100A8C
 * EN v1.1 Size: 4b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void projdfp1r_initialise(void)
{
}

/*
 * --INFO--
 *
 * Function: cameraGetTargetType
 * EN v1.0 Address: 0x80100A90
 * EN v1.0 Size: 12b
 */
u8 cameraGetTargetType(void)
{
  return CAMCONTROL_CAMERA->targetKind;
}

/*
 * --INFO--
 *
 * Function: Camera_getMinimapInfoText
 * EN v1.0 Address: 0x80100A9C
 * EN v1.0 Size: 8b
 */
s16 Camera_getMinimapInfoText(void)
{
  return gCamcontrolTargetHelpTextId;
}
