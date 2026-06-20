#ifndef MAIN_DLL_CURVE_WALKER_H_
#define MAIN_DLL_CURVE_WALKER_H_

#include "global.h"

/* rom-curve walker record (the f32* "state" the RomCurve_* family walks) -
 * sits at the head of curve-following extra blocks (objfsa.c census, lifted
 * per the deref-cleanup wave). Kept in its own header so TUs with legacy
 * arity-0 externs (objfsa.c drift bodies) can take the typedef without
 * curves.h's prototype namespace; curves.h includes this, so its consumers
 * see RomCurveWalker as before. */
typedef struct RomCurveWalker {
    f32 phase; /* 0x00: position along the current segment */
    u8 unk04[0x10 - 0x04];
    s32 atSegmentEnd; /* 0x10: nonzero = segment end/advance flag (magicPlant/seqObj11E/NWsfx census) */
    u8 unk14[0x68 - 0x14];
    f32 posX; /* 0x68: current position X */
    f32 posY; /* 0x6C: current position Y */
    f32 posZ; /* 0x70: current position Z */
    f32 tangentX; /* 0x74 */
    f32 tangentY; /* 0x78: heading/derivative term (sign tested) */
    f32 tangentZ; /* 0x7C */
    s32 reverse; /* 0x80: walk direction */
    void *coeffX; /* 0x84: active hermite coefficient set, X (-> hermX/hermX2) */
    void *coeffY; /* 0x88: active hermite coefficient set, Y */
    void *coeffZ; /* 0x8C: active hermite coefficient set, Z */
    s32 moveNetwork; /* 0x90 */
    void *node94; /* curve-node history: oldest.. */
    void *node98;
    void *node9C;
    void *nodeA0; /* current node */
    void *nodeA4; /* next node */
    f32 hermX[4]; /* 0xA8: hermite endpoints+tangents, X */
    f32 hermX2[4]; /* 0xB8: previous-segment X set */
    f32 hermY[4]; /* 0xC8 */
    f32 hermY2[4]; /* 0xD8 */
    f32 hermZ[4]; /* 0xE8 */
    f32 hermZ2[4]; /* 0xF8 */
} RomCurveWalker;

STATIC_ASSERT(offsetof(RomCurveWalker, atSegmentEnd) == 0x10);
STATIC_ASSERT(offsetof(RomCurveWalker, posX) == 0x68);
STATIC_ASSERT(offsetof(RomCurveWalker, tangentX) == 0x74);
STATIC_ASSERT(offsetof(RomCurveWalker, reverse) == 0x80);
STATIC_ASSERT(offsetof(RomCurveWalker, hermX) == 0xA8);

#endif /* MAIN_DLL_CURVE_WALKER_H_ */
