/* DLL 0x00E6 (restartmarker) - restart-position marker object.
 * Its placement rotation seeds the marker heading; the marker itself stays
 * hidden because it exists only as a gameplay respawn anchor.
 */
#include "main/dll/dll_00E6_restartmarker.h"

void restartmarker_init(GameObject* obj, RestartMarkerPlacement* placement)
{
    obj->anim.rotX = (s16)(placement->rotXByte << 8);
    obj->objectFlags = (u16)(obj->objectFlags | OBJECT_OBJFLAG_HIDDEN);
}

ObjectDescriptor gReStartMarkerObjDescriptor = {
    0, 0, 0, OBJECT_DESCRIPTOR_FLAGS_10_SLOTS, 0, 0, 0, (ObjectDescriptorCallback)restartmarker_init, 0, 0, 0, 0, 0, 0,
};
