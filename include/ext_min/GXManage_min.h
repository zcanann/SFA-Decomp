#ifndef EXT_MIN_GXMANAGE_MIN_H_
#define EXT_MIN_GXMANAGE_MIN_H_

#include "types.h"

u16 GXReadDrawSync(void);

void GXFlush(void);
void GXSetDrawSync(u16 token);
#endif /* EXT_MIN_GXMANAGE_MIN_H_ */
