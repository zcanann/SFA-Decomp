#ifndef MAIN_DLL_DLL_011B_LANDEDARWING_H_
#define MAIN_DLL_DLL_011B_LANDEDARWING_H_

#include "main/obj_placement.h"
#include "main/game_object.h"
#include "main/gamebits.h"
#include "main/mapEvent.h"
#include "main/objhits.h"
#include "main/objseq.h"
#include "main/objtexture.h"
#include "main/dll/CF/CFBaby.h"

typedef struct LandedArwingObjectState LandedArwingObjectState;

void landed_arwing_renderPathEffects(GameObject* obj);
void landed_arwing_render(GameObject* obj, int p2, int p3, int p4, int p5, s8 visible);
void landed_arwing_updateHitReaction(GameObject* obj, LandedArwingObjectState* state);
void landed_arwing_updateDamageTexture(GameObject* obj, LandedArwingObjectState* state);

#endif /* MAIN_DLL_DLL_011B_LANDEDARWING_H_ */
