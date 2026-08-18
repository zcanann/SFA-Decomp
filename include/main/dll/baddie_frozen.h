#ifndef MAIN_DLL_BADDIE_FROZEN_H_
#define MAIN_DLL_BADDIE_FROZEN_H_

#include "game/objects/object.h"
#include "dolphin/mtx/vec_types.h"
#include "main/dll/dll_00C9_enemy.h"

u8 sharpClawHandleHitMessage(GameObject* obj, u8* state, GameObject* attacker, int hit, int p5, int p6, Vec* hitPos,
                             int sector, f32 hDist, f32 vDist);
void guardClawUpdateWhileFrozen(GameObject* obj, u8* state, GameObject* attacker, int hit, int p5, int p6, Vec* hitPos,
                                int sector);
void gcRobotPatrol_updateWhileFrozen(GameObject* obj, u8* state, GameObject* attacker, int hit, int p5, int p6, Vec* hitPos,
                                     int sector);
void mikaladon_updateWhileFrozen(GameObject* obj, u8* state, GameObject* attacker, int hit, int p5, int p6, Vec* hitPos,
                                 int sector);
void vambat_updateWhileFrozen(GameObject* obj, u8* state, GameObject* attacker, int hit, int p5, int p6, Vec* hitPos,
                              int sector);
void kooshy_updateWhileFrozen(GameObject* obj, u8* state, GameObject* attacker, int hit, int p5, int p6, Vec* hitPos,
                              int sector);
void weevil_updateWhileFrozen(GameObject* obj, u8* state, GameObject* attacker, int hit, int p5, int p6, Vec* hitPos,
                              int sector);
void pinPon_updateWhileFrozen(GameObject* obj, EnemyState* state, GameObject* attacker, int hit, int p5, int p6, Vec* hitPos,
                              int sector);
void wbUpdateWhileFrozen(GameObject* obj, u8* state, GameObject* attacker, int hit, int p5, int p6, Vec* hitPos, int sector);
void mutatedEbaUpdateWhileFrozen(GameObject* obj, u8* state, GameObject* attacker, int hit, int p5, int p6, Vec* hitPos,
                                 int sector);
void hoodedZyckUpdateWhileFrozen(GameObject* obj, u8* state, GameObject* attacker, int hit, int p5, int p6, Vec* hitPos,
                                 int sector);
void battleDroidUpdateWhileFrozen(GameObject* obj, u8* state, GameObject* attacker, int hit, int p5, int p6, Vec* hitPos,
                                  int sector);
void crawler_onHit(GameObject* obj, u8* state, GameObject* attacker, int hit, int p5, int p6, Vec* hitPos, int sector);
void hagabonMK2_updateWhileFrozen(GameObject* obj, u8* state, GameObject* attacker, int hit, int p5, int p6, Vec* hitPos,
                                  int sector);

void rachnopUpdateWhileFrozen(GameObject* obj, u8* state, GameObject* attacker, int hit, int p5, int p6, Vec* hitPos,
                              int sector);
void spittingEbaUpdateWhileFrozen(GameObject* obj, u8* state, GameObject* attacker, int hit, int p5, int p6, Vec* hitPos,
                                  int sector);
void whirlpool_updateWhileFrozen(GameObject* obj, u8* state, GameObject* attacker, int hit, int p5, int p6, Vec* hitPos,
                                 int sector);
void snowworm_updateWhileFrozen(GameObject* obj, u8* state, GameObject* attacker, int hit, int p5, int p6, Vec* hitPos,
                                int sector);

#endif /* MAIN_DLL_BADDIE_FROZEN_H_ */
