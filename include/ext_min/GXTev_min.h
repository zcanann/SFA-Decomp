#ifndef EXT_MIN_GXTEV_MIN_H_
#define EXT_MIN_GXTEV_MIN_H_

#include "types.h"


void GXSetAlphaCompare(GXCompare comp0, u8 ref0, GXAlphaOp op, GXCompare comp1, u8 ref1);
void GXSetTevOp(GXTevStageID id, GXTevMode mode);
#endif /* EXT_MIN_GXTEV_MIN_H_ */
