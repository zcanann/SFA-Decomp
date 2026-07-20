#ifndef MAIN_GAMETEXT_COLOR_API_H_
#define MAIN_GAMETEXT_COLOR_API_H_

#include "types.h"

#ifdef GAMETEXT_COLOR_U8
void gameTextSetColor(u8 r, u8 g, u8 b, u8 a);
#else
void gameTextSetColor(int r, int g, int b, int a);
#endif

#endif /* MAIN_GAMETEXT_COLOR_API_H_ */
