#ifndef MAIN_DLL_LGT_LGTCONTROLLIGHT_H_
#define MAIN_DLL_LGT_LGTCONTROLLIGHT_H_

#include "main/dll/LGT/lgtcontrollightrec_struct.h"
#include "main/game_object.h"

union LgtControlLightConstF32 { f32 f; };
extern const union LgtControlLightConstF32 lbl_803E5EAC;

int firefly_animEventCallback(GameObject* obj);
void fn_801F4C28(GameObject* obj, LgtFireFlyRec* record);
void fn_801F4D54(GameObject* obj, LgtFireFlyRec* record);

#endif /* MAIN_DLL_LGT_LGTCONTROLLIGHT_H_ */
