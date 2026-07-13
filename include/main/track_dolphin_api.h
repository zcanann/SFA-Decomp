#ifndef MAIN_TRACK_DOLPHIN_API_H_
#define MAIN_TRACK_DOLPHIN_API_H_

#include "types.h"
#include "main/game_object.h"

int objShadowFn_80062498();
int fn_80065640(void);
void fn_80065574(int matchValue, GameObject* obj, int flag);
void doNothing_80062A50();
void objHitDetectFn_80062e84(GameObject* obj, GameObject* newParent, int mode);
void playerShadowFn_80062a30(int* obj);

extern int lbl_803DCF34;
extern f32* lbl_803DCF38;

#endif /* MAIN_TRACK_DOLPHIN_API_H_ */
