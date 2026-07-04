/*
 * area (DLL 0xF6) - the trigger-area object class. A behaviourless
 * marker placed in a level: every per-frame callback (update / render /
 * hitDetect / free) is empty and it carries no extra state
 * (getExtraSize == 0). init() only stamps two bits (0xA000) into the
 * GameObject flag word; the object exists purely so the placement /
 * map-event system can reference an addressable region. Exported through
 * gAreaObjDescriptor with 10 callback slots.
 */
#include "main/object_descriptor.h"
#include "main/game_object.h"

#define AREA_OBJFLAG_UPDATE_DISABLED 0x8000
#define AREA_OBJFLAG_HITDETECT_DISABLED 0x2000

int area_getExtraSize(void) { return 0x0; }
int area_getObjectTypeId(void) { return 0x0; }

void area_free(void)
{
}

void area_render(void)
{
}

void area_hitDetect(void)
{
}

void area_update(void)
{
}

void area_init(GameObject* obj)
{
    obj->objectFlags = (u16)(obj->objectFlags | (AREA_OBJFLAG_UPDATE_DISABLED | AREA_OBJFLAG_HITDETECT_DISABLED));
}

void area_release(void)
{
}

void area_initialise(void)
{
}

ObjectDescriptor gAreaObjDescriptor = {
    0, 0, 0, OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    area_initialise,
    area_release,
    0,
    (ObjectDescriptorCallback)area_init,
    (ObjectDescriptorCallback)area_update,
    (ObjectDescriptorCallback)area_hitDetect,
    (ObjectDescriptorCallback)area_render,
    (ObjectDescriptorCallback)area_free,
    (ObjectDescriptorCallback)area_getObjectTypeId,
    area_getExtraSize,
};

/* auto 0x80320fd0-0x803211a0 */
extern void Door_getExtraSize(void);
extern void Door_init(void);
extern void Door_render(void);
extern void Door_update(void);
extern void InvisibleHitSwitch_getExtraSize(void);
extern void InvisibleHitSwitch_init(void);
extern void InvisibleHitSwitch_update(void);
extern void ProjectileSwitch_free(void);
extern void ProjectileSwitch_getExtraSize(void);
extern void ProjectileSwitch_getObjectTypeId(void);
extern void ProjectileSwitch_hitDetect(void);
extern void ProjectileSwitch_init(void);
extern void ProjectileSwitch_initialise(void);
extern void ProjectileSwitch_release(void);
extern void ProjectileSwitch_render(void);
extern void ProjectileSwitch_update(void);
extern void doorlock_free(void);
extern void doorlock_getExtraSize(void);
extern void doorlock_init(void);
extern void doorlock_render(void);
extern void doorlock_update(void);
extern void levelname_free(void);
extern void levelname_getExtraSize(void);
extern void levelname_getObjectTypeId(void);
extern void levelname_hitDetect(void);
extern void levelname_init(void);
extern void levelname_initialise(void);
extern void levelname_release(void);
extern void levelname_render(void);
extern void levelname_update(void);
extern void mmp_bridge_free(void);
extern void mmp_bridge_getExtraSize(void);
extern void mmp_bridge_getObjectTypeId(void);
extern void mmp_bridge_hitDetect(void);
extern void mmp_bridge_init(void);
extern void mmp_bridge_initialise(void);
extern void mmp_bridge_release(void);
extern void mmp_bridge_render(void);
extern void mmp_bridge_update(void);
extern void pressureswitchfb_free(void);
extern void pressureswitchfb_getExtraSize(void);
extern void pressureswitchfb_init(void);
extern void pressureswitchfb_update(void);
extern void seqobject_free(void);
extern void seqobject_getExtraSize(void);
extern void seqobject_getObjectTypeId(void);
extern void seqobject_init(void);
extern void seqobject_render(void);
extern void seqobject_update(void);

u32 gLevelNameObjDescriptor[14] = { 0x00000000, 0x00000000, 0x00000000, 0x00090000, (u32)levelname_initialise, (u32)levelname_release, 0x00000000, (u32)levelname_init, (u32)levelname_update, (u32)levelname_hitDetect, (u32)levelname_render, (u32)levelname_free, (u32)levelname_getObjectTypeId, (u32)levelname_getExtraSize };
u32 lbl_80321008[4] = { 0x00031ccf, 0x00000522, 0x00031ce0, 0x00000e6e };
u32 gProjectileSwitchObjDescriptor[14] = { 0x00000000, 0x00000000, 0x00000000, 0x00090000, (u32)ProjectileSwitch_initialise, (u32)ProjectileSwitch_release, 0x00000000, (u32)ProjectileSwitch_init, (u32)ProjectileSwitch_update, (u32)ProjectileSwitch_hitDetect, (u32)ProjectileSwitch_render, (u32)ProjectileSwitch_free, (u32)ProjectileSwitch_getObjectTypeId, (u32)ProjectileSwitch_getExtraSize };
u32 gInvisibleHitSwitchObjDescriptor[14] = { 0x00000000, 0x00000000, 0x00000000, 0x00090000, 0x00000000, 0x00000000, 0x00000000, (u32)InvisibleHitSwitch_init, (u32)InvisibleHitSwitch_update, 0x00000000, 0x00000000, 0x00000000, 0x00000000, (u32)InvisibleHitSwitch_getExtraSize };
u32 gPressureSwitchFBObjDescriptor[14] = { 0x00000000, 0x00000000, 0x00000000, 0x00090000, 0x00000000, 0x00000000, 0x00000000, (u32)pressureswitchfb_init, (u32)pressureswitchfb_update, 0x00000000, 0x00000000, (u32)pressureswitchfb_free, 0x00000000, (u32)pressureswitchfb_getExtraSize };
u32 gDoorObjDescriptor[14] = { 0x00000000, 0x00000000, 0x00000000, 0x00090000, 0x00000000, 0x00000000, 0x00000000, (u32)Door_init, (u32)Door_update, 0x00000000, (u32)Door_render, 0x00000000, 0x00000000, (u32)Door_getExtraSize };
u32 gMMP_BridgeObjDescriptor[14] = { 0x00000000, 0x00000000, 0x00000000, 0x00090000, (u32)mmp_bridge_initialise, (u32)mmp_bridge_release, 0x00000000, (u32)mmp_bridge_init, (u32)mmp_bridge_update, (u32)mmp_bridge_hitDetect, (u32)mmp_bridge_render, (u32)mmp_bridge_free, (u32)mmp_bridge_getObjectTypeId, (u32)mmp_bridge_getExtraSize };
u32 gDoorLockObjDescriptor[14] = { 0x00000000, 0x00000000, 0x00000000, 0x00090000, 0x00000000, 0x00000000, 0x00000000, (u32)doorlock_init, (u32)doorlock_update, 0x00000000, (u32)doorlock_render, (u32)doorlock_free, 0x00000000, (u32)doorlock_getExtraSize };
u32 gSeqObjectObjDescriptor[14] = { 0x00000000, 0x00000000, 0x00000000, 0x00090000, 0x00000000, 0x00000000, 0x00000000, (u32)seqobject_init, (u32)seqobject_update, 0x00000000, (u32)seqobject_render, (u32)seqobject_free, (u32)seqobject_getObjectTypeId, (u32)seqobject_getExtraSize };
