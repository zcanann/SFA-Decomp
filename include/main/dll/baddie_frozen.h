#ifndef MAIN_DLL_BADDIE_FROZEN_H_
#define MAIN_DLL_BADDIE_FROZEN_H_

#include "main/game_object.h"
#include "dolphin/mtx/vec_types.h"

int sidekickToy_handleHitMessage(int obj, u8* state, int attacker, int hit, int p5, int p6, Vec* hitPos, int sector, f32 hDist, f32 vDist);
void guardClawUpdateWhileFrozen(int obj, u8* state, int attacker, int hit, int p5, int p6, Vec* hitPos, int sector);
void gcRobotPatrol_updateWhileFrozen(int obj, u8* state, int attacker, int hit, int p5, int p6, Vec* hitPos, int sector);
void mikaladon_updateWhileFrozen(int obj, u8* state, int attacker, int hit, int p5, int p6, Vec* hitPos, int sector);
void vambat_updateWhileFrozen(int obj, u8* state, int attacker, int hit, int p5, int p6, Vec* hitPos, int sector);
void kooshy_updateWhileFrozen(GameObject* obj, u8* state, int attacker, int hit, int p5, int p6, Vec* hitPos, int sector);
void weevil_updateWhileFrozen(GameObject* obj, u8* state, int attacker, int hit, int p5, int p6, Vec* hitPos, int sector);
void Baddie_HandleHitReaction(GameObject* obj, u8* state, int attacker, int hit, int p5, int p6, Vec* hitPos, int sector);
void wbUpdateWhileFrozen(int obj, u8* state, int attacker, int hit, int p5, int p6, Vec* hitPos, int sector);
void mutatedEbaUpdateWhileFrozen(int obj, u8* state, int attacker, int hit, int p5, int p6, Vec* hitPos, int sector);
void hoodedZyckUpdateWhileFrozen(int obj, u8* state, int attacker, int hit, int p5, int p6, Vec* hitPos, int sector);
void battleDroidUpdateWhileFrozen(int obj, u8* state, int attacker, int hit, int p5, int p6, Vec* hitPos, int sector);
void crawler_onHit(GameObject* obj, u8* state, int attacker, int hit, int p5, int p6, Vec* hitPos, int sector);
void hagabonMK2_updateWhileFrozen(int obj, u8* state, int attacker, int hit, int p5, int p6, Vec* hitPos, int sector);

#endif /* MAIN_DLL_BADDIE_FROZEN_H_ */
