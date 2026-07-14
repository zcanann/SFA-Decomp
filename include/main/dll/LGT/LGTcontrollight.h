#ifndef MAIN_DLL_LGT_LGTCONTROLLIGHT_H_
#define MAIN_DLL_LGT_LGTCONTROLLIGHT_H_

#include "main/dll/LGT/lgtcontrollightrec_struct.h"
#include "main/game_object.h"

extern f32 lbl_803E5EAC;
extern f32 lbl_803E5EB0;
extern f32 lbl_803E5EB4;
extern f32 lbl_803E5EB8;
extern f32 lbl_803E5EBC;
extern f32 lbl_803E5EC0;
extern f32 lbl_803E5EC4;
extern f32 lbl_803E5EC8;

int firefly_animEventCallback(GameObject* obj);
void fn_801F4C28(GameObject* obj, LgtFireFlyRec* record);
void fn_801F4D54(GameObject* obj, LgtFireFlyRec* record);

#endif /* MAIN_DLL_LGT_LGTCONTROLLIGHT_H_ */
