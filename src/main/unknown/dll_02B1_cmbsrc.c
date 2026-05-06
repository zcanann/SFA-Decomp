// Non-built exploratory packet for the retail-backed CmbSrc object family.
//
// Source evidence:
// - DLL 0x02B1 is "CmbSrc" in retail XML.
// - Object defs 0x059C-0x059F resolve to this family:
//   CmbSrc, CmbSrcTPole, CmbSrcTWall, and ThusterSour.
//
// Current EN descriptor:
// - gCmbSrcObjDescriptor @ 0x8032BDB0
//
// Descriptor slots:
// - 0: cmbsrc_initialise (0x80237570)
// - 1: cmbsrc_release (0x8023756C)
// - 3: cmbsrc_init (0x80236F90)
// - 4: cmbsrc_update (0x80236D84)
// - 5: cmbsrc_hitDetect (0x80236C9C)
// - 6: cmbsrc_render (0x80236BE4)
// - 7: cmbsrc_free (0x80236B80)
// - 8: cmbsrc_func08 (0x80236B78)
// - 9: cmbsrc_getExtraSize (0x80236B70)

// Helpers:
// - cmbsrc_shouldDeactivate (0x80236298): decides when an active source should
//   shut off from effect completion, switch state, external activity, or delay.
// - cmbsrc_shouldActivate (0x80236388): decides when an inactive source should
//   turn on from switch state, external activity, or timed reactivation.
// - cmbsrc_cycleColor (0x80236480): rotates the color table used by mode 0x0F
//   sources and applies the new colors to the active effect handle.
// - cmbsrc_updateVisuals (0x8023666C): updates source radius, color/effect mode,
//   proximity reactions, sound/light pulses, and active visual state.
// - cmbsrc_updateAndReturnZero (0x80236AEC): wrapper used by callers that need
//   to run update and return a false status.
// - cmbsrc_getColorIndex (0x80236B10): exposes the current mode-0x0F color index.
// - cmbsrc_setExternalActive (0x80236B38): sets/clears the external-active flag.

// Runtime shape:
// - update toggles extra byte +0x25 as the active state, mirrors that state into
//   the effect handle and optional switch id, enables/disables hit state, and
//   then delegates visual/sound behavior to cmbsrc_updateVisuals.
