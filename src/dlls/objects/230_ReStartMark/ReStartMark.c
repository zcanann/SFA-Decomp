/*
 * ReStartMark object (DLL slot 230 / 0xE6).
 *
 * The placement rotation seeds the marker heading. The marker stays hidden
 * because it exists only as a gameplay respawn anchor.
 */
#include "dlls/objects/230_ReStartMark.h"
#include "game/objects/object.h"

ObjectDescriptor gReStartMarkObjDescriptor = {
    0,                                          /* reserved0 */
    0,                                          /* reserved1 */
    0,                                          /* reserved2 */
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,           /* slotCountAndFlags */
    0,                                          /* initialise */
    0,                                          /* release */
    0,                                          /* slot02 */
    (ObjectDescriptorCallback)ReStartMark_init, /* init */
    0,                                          /* update */
    0,                                          /* hitDetect */
    0,                                          /* render */
    0,                                          /* free */
    0,                                          /* getObjectTypeId */
    0,                                          /* getExtraSize */
};

void ReStartMark_init(GameObject* obj, ReStartMarkPlacement* placement) {
    obj->anim.rotX = (s16)(placement->rotXByte << 8);
    obj->objectFlags |= OBJECT_OBJFLAG_HIDDEN;
}
