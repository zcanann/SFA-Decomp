/* DLL 0x00E6 (restartmarker) - Restart marker object [0x801713D8-0x801713FC).
 *
 * Retail TU = restartmarker_init plus the gReStartMarkerObjDescriptor .data
 * object at 0x80320B00. The drift-catalogue descriptors and dead staticCamera
 * bodies formerly carried here are all homed in sibling TUs' split ranges.
 */
#include "main/game_object.h"
#include "main/object_descriptor.h"

/* object group this object joins while active */
#define RESTARTMARKER_OBJGROUP 7

#define RESTARTMARKER_OBJFLAG_HIDDEN 0x4000

void restartmarker_init(int* obj, int* placement)
{
    *(s16*)obj = (s16)(*(u8*)((char*)placement + 0x18) << 8);
    ((GameObject*)obj)->objectFlags = (u16)(((GameObject*)obj)->objectFlags | RESTARTMARKER_OBJFLAG_HIDDEN);
}

ObjectDescriptor gReStartMarkerObjDescriptor = {
    0, 0, 0, OBJECT_DESCRIPTOR_FLAGS_10_SLOTS, 0, 0, 0, (ObjectDescriptorCallback)restartmarker_init, 0, 0, 0, 0, 0, 0,
};
