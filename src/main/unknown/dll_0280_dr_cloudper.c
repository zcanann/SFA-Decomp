// Non-built exploratory packet for the retail-backed DR_CloudPer object family.
//
// Source evidence:
// - DLL 0x0280 is "DR_CloudPer" in retail XML.
// - Object def 0x0480 ("DR_CloudPer") resolves to this family.
//
// Current EN descriptor:
// - gDrCloudPerObjDescriptor @ 0x8032ADD0
//
// Runtime notes:
// - init adds the object to groups 0x13 and 0x39, seeds yaw from map data byte +0x18,
//   and builds a plane equation in the 0x10-byte extra data from the object position/yaw.
// - map data byte +0x19 is a cloud selector. When it matches game bit 0x7A9, init toggles
//   the DAT_803DCAAC world effect hook for the object's model id.
// - drcloudper_selectActiveCloud writes map data byte +0x19 back to game bit 0x7A9 and
//   raises the object-trigger callback through DAT_803DCA54.
//
// Descriptor slots:
// - 0: drcloudper_initialise (0x8022142C)
// - 1: drcloudper_release (0x80221428)
// - 3: drcloudper_init (0x802212D4)
// - 4: drcloudper_update (0x802212D0)
// - 5: drcloudper_hitDetect (0x802212CC)
// - 6: drcloudper_render (0x802212C8)
// - 7: drcloudper_free (0x8022128C)
// - 8: drcloudper_func08 (0x80221284)
// - 9: drcloudper_getExtraSize (0x8022127C)
// - 10: drcloudper_setScale (0x80221178)
// - 11: drcloudper_selectActiveCloud (0x8022121C)
