#ifndef MAIN_DLL_FRONT_GAME_TEXT_BOX_API_H_
#define MAIN_DLL_FRONT_GAME_TEXT_BOX_API_H_

#include "types.h"

#ifdef FRONT_GAMETEXTBOX_NARROW
void gameTextBoxFn_80134d40(u8 alpha, int hideHighlight, u32 showArrows);
#else
void gameTextBoxFn_80134d40(int alpha, int hideHighlight, u32 showArrows);
#endif

#endif /* MAIN_DLL_FRONT_GAME_TEXT_BOX_API_H_ */
