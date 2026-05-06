// Non-built exploratory packet for the retail-backed WCFloorTile object family.
//
// Source evidence:
// - DLL 0x0298 is "WCFloorTile" in retail XML.
// - Object def 0x0146 ("WCFloorTile") resolves to this family.
//
// Current EN descriptor:
// - gWCFloorTileObjDescriptor @ 0x8032B3D0
//
// Runtime notes:
// - update watches game bit 0x338 as a force-reset path, restoring the object Y position
//   from object-def +0x0C and moving state byte extra +6 into the reset/open state.
// - after game bit 0x265 is raised, nearby child objects with object id 1 can trigger the
//   tile to drop, play sound 0xC6, and drive object byte +0x36 as its visibility/alpha.
// - falling state advances a timer at extra +0, tilts the model angles through
//   FUN_800221a0, accelerates object Y velocity from object +0x28, and notifies the
//   linked floor controller through object-def bit +0x1A when motion completes.
// - extra byte +7 stores one-shot flags for solved/opened, notification pending, and the
//   0x265 arming bit.
//
// Descriptor slots:
// - 0: wcfloortile_initialise (0x8022A66C)
// - 1: wcfloortile_release (0x8022A668)
// - 3: wcfloortile_init (0x8022A634)
// - 4: wcfloortile_update (0x8022A2E0)
// - 5: wcfloortile_hitDetect (0x8022A2DC)
// - 6: wcfloortile_render (0x8022A2AC)
// - 7: wcfloortile_free (0x8022A2A8)
// - 8: wcfloortile_func08 (0x8022A2A0)
// - 9: wcfloortile_getExtraSize (0x8022A298)
