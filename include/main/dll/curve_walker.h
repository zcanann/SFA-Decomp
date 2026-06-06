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
    u8 unk04[0x80 - 0x04];
    s32 reverse; /* 0x80: walk direction */
    void *unk84;
    void *unk88;
    void *unk8C;
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

#endif /* MAIN_DLL_CURVE_WALKER_H_ */
