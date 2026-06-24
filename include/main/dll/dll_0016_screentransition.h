#ifndef MAIN_DLL_DLL_0016_SCREENTRANSITION_H_
#define MAIN_DLL_DLL_0016_SCREENTRANSITION_H_

#include "main/game_object.h"
#include "main/screen_transition.h"
#include "dolphin/gx/GXCull.h"

/* gScreenTransitionType: which full-screen fade overlay screenTransition_do2
 * draws each step (color picked directly in the type switch). */
#define SCREEN_TRANSITION_BLACK 1     /* solid black rect fade */
#define SCREEN_TRANSITION_WHITE 2     /* solid white rect fade */
#define SCREEN_TRANSITION_WHITE_WIPE 3 /* white edge-wipe via screenRectFn_800d7568 */
#define SCREEN_TRANSITION_RED 4       /* solid red rect fade */
#define SCREEN_TRANSITION_HUD 5       /* no rect; drives HUD opacity at fade endpoints */

void screenRectFn_800d7568(int p1, int p2, int p3, u8 r, u8 g, u8 b);
void screenTransitionFn_800d7b04(int duration, int type);

#endif
