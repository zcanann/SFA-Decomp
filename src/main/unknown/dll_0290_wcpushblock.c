// Non-built exploratory packet for the retail-backed WCPushBlock object family.
//
// Source evidence:
// - DLL 0x0290 is "WCPushBlock" in retail XML.
// - Object def 0x013A ("WCPushBlock") resolves to this family.
//
// Current EN descriptor:
// - gWCPushBlockObjDescriptor @ 0x8032AFB0
//
// Runtime notes:
// - init copies object-def byte +0x19 into object byte +0xAD, clamped against model data,
//   and seeds the path/grid selector fields in extra +0x27E/+0x280/+0x283.
// - update discovers its controller via object group 9 into extra +0x268, then runs a
//   high-bit state machine in extra byte +0x285 for idle, push, slide, reset, and lock states.
// - game bits 0x808/0x809/0x812/0x813 can force state transitions depending on object byte +0xAD.
// - helper 0x802242A8 validates movement bounds against the controller-provided tile extents.
//
// Descriptor slots:
// - 0: wcpushblock_initialise (0x802251B0)
// - 1: wcpushblock_release (0x802251AC)
// - 3: wcpushblock_init (0x8022511C)
// - 4: wcpushblock_update (0x80224464)
// - 5: wcpushblock_hitDetect (0x80224460)
// - 6: wcpushblock_render (0x80224430)
// - 7: wcpushblock_free (0x8022442C)
// - 8: wcpushblock_func08 (0x802243FC)
// - 9: wcpushblock_getExtraSize (0x802243F4)
