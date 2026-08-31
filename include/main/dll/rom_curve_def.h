#ifndef MAIN_DLL_ROM_CURVE_DEF_H_
#define MAIN_DLL_ROM_CURVE_DEF_H_

#include "global.h"

#define ROMCURVE_LINK_COUNT 4

/* RomCurveDef::subtype values observed for type-0x24 Tricky route nodes.
 * The editor/source names are not known yet; these names describe the proven
 * movement and path-search behavior in the retail code. */
#define ROMCURVE_TRICKY_SUBTYPE_JUMP              1
#define ROMCURVE_TRICKY_SUBTYPE_GROUND_SNAP_A     2
#define ROMCURVE_TRICKY_SUBTYPE_DIG_TUNNEL        ROMCURVE_TRICKY_SUBTYPE_GROUND_SNAP_A
#define ROMCURVE_TRICKY_SUBTYPE_CANNONBALL_ROUTE  3
#define ROMCURVE_TRICKY_SUBTYPE_FLAME_EDGE        4
#define ROMCURVE_TRICKY_SUBTYPE_JUMPUP            5
#define ROMCURVE_TRICKY_SUBTYPE_JUMPDOWN          6
#define ROMCURVE_TRICKY_SUBTYPE_GROUND_SNAP_B     7
#define ROMCURVE_TRICKY_SUBTYPE_BLOCKED_PAIR_A    8
#define ROMCURVE_TRICKY_SUBTYPE_BLOCKED_PAIR_B    9

typedef struct RomCurveDef
{
    s16 objectId;
    u8 size;
    u8 walkGroup;
    u8 linkWalkGroups[ROMCURVE_LINK_COUNT];
    f32 x;
    f32 y;
    f32 z;
    u32 id;
    s8 action;
    s8 type;
    s8 subtype; /* secondary curve classifier: HCurves p5_filter, plus Tricky path-search gates */
    s8 blockedLinkMask;
    s32 linkIds[ROMCURVE_LINK_COUNT];
    s8 yaw;
    s8 pitch;
    u8 tangentMag;
    u8 pad2F;
    s16 requiredBit;
    s16 forbiddenBit;
    u8 unk34;
    u8 pad35[3];
    s16 roll;
    u8 pad3A[0x44 - 0x3A];
} RomCurveDef;

STATIC_ASSERT(offsetof(RomCurveDef, size) == 0x02);
STATIC_ASSERT(offsetof(RomCurveDef, walkGroup) == 0x03);
STATIC_ASSERT(offsetof(RomCurveDef, linkWalkGroups) == 0x04);
STATIC_ASSERT(offsetof(RomCurveDef, x) == 0x08);
STATIC_ASSERT(offsetof(RomCurveDef, y) == 0x0C);
STATIC_ASSERT(offsetof(RomCurveDef, z) == 0x10);
STATIC_ASSERT(offsetof(RomCurveDef, id) == 0x14);
STATIC_ASSERT(offsetof(RomCurveDef, action) == 0x18);
STATIC_ASSERT(offsetof(RomCurveDef, type) == 0x19);
STATIC_ASSERT(offsetof(RomCurveDef, subtype) == 0x1A);
STATIC_ASSERT(offsetof(RomCurveDef, blockedLinkMask) == 0x1B);
STATIC_ASSERT(offsetof(RomCurveDef, linkIds) == 0x1C);
STATIC_ASSERT(offsetof(RomCurveDef, yaw) == 0x2C);
STATIC_ASSERT(offsetof(RomCurveDef, pitch) == 0x2D);
STATIC_ASSERT(offsetof(RomCurveDef, tangentMag) == 0x2E);
STATIC_ASSERT(offsetof(RomCurveDef, requiredBit) == 0x30);
STATIC_ASSERT(offsetof(RomCurveDef, forbiddenBit) == 0x32);
STATIC_ASSERT(offsetof(RomCurveDef, unk34) == 0x34);
STATIC_ASSERT(offsetof(RomCurveDef, roll) == 0x38);
STATIC_ASSERT(sizeof(RomCurveDef) == 0x44);

#endif /* MAIN_DLL_ROM_CURVE_DEF_H_ */
