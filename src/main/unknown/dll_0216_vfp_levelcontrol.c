// Non-built exploratory packet for the retail-backed VFP_LevelControl object family.
//
// Source evidence:
// - DLL 0x0216 is "VFP_LevelControl" in retail XML.
// - Object def 0x033D ("VFP_LevelCo") resolves here.
//
// Current EN descriptor:
// - gVFP_LevelControlObjDescriptor @ 0x80328E90
//
// Descriptor slots:
// - 0: vfplevelcontrol_initialise (0x801F9D6C)
// - 1: vfplevelcontrol_release (0x801F9D68)
// - 3: vfplevelcontrol_init (0x801F9C38)
// - 4: vfplevelcontrol_update (0x801F9998)
// - 5: vfplevelcontrol_hitDetect (0x801F9994)
// - 6: vfplevelcontrol_render (0x801F9990)
// - 7: vfplevelcontrol_free (0x801F994C)
// - 8: vfplevelcontrol_func08 (0x801F9944)
// - 9: vfplevelcontrol_getExtraSize (0x801F993C)
//
// Reference-only object parameter hints:
// - 0x18: unnamed undefined
// - 0x19: unnamed undefined
// - 0x1A: unnamed s16
