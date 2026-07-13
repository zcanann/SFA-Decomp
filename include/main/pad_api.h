#ifndef MAIN_PAD_API_H_
#define MAIN_PAD_API_H_

#include "types.h"

u32 buttonGetDisabled(int port);
void buttonDisable(int port, u32 mask);
void doRumble(f32 duration);

#endif /* MAIN_PAD_API_H_ */
