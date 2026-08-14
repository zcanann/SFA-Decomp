#ifndef H_MAIN_DLL_DRHIGHTOP_H
#define H_MAIN_DLL_DRHIGHTOP_H

#include "main/dll/dll_0255_snowbike.h"

void SnowBike_UpdateRouteFollowing(GameObject* obj, SnowBikeState* state);
void SnowBike_UpdateAirMeter(GameObject* obj, u8* stateRaw);
void SnowBike_UpdateCollisionResponse(GameObject* obj, int stateRaw);
void SnowBike_UpdateSteering(short* obj, int stateRaw);
void SnowBike_UpdateExhaustFx(GameObject* obj, int stateRaw);

#endif /* H_MAIN_DLL_DRHIGHTOP_H */
