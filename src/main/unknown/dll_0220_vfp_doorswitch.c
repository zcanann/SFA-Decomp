// Non-built exploratory packet for the retail-backed VFP_DoorSwitch object family.
//
// Source evidence:
// - DLL 0x0220 is "VFP_DoorSwitch" in retail XML.
// - Object def 0x032E ("VFP_DoorSwi") resolves here.
// - Object def 0x032F ("VFP_LiftInd") shares this DLL family.
//
// Current EN descriptor:
// - gVFP_DoorSwitchObjDescriptor @ 0x803290C0
//
// Descriptor slots:
// - 0: vfpdoorswitch_initialise (0x801FC6F0)
// - 1: vfpdoorswitch_release (0x801FC6EC)
// - 3: vfpdoorswitch_init (0x801FC604)
// - 4: vfpdoorswitch_update (0x801FC55C)
// - 5: vfpdoorswitch_hitDetect (0x801FC558)
// - 6: vfpdoorswitch_render (0x801FC534)
// - 7: vfpdoorswitch_free (0x801FC504)
// - 8: vfpdoorswitch_func08 (0x801FC4FC)
// - 9: vfpdoorswitch_getExtraSize (0x801FC4F4)
