#ifndef MAIN_DLL_SB_DLL_01E9_SBPROPELLER_H_
#define MAIN_DLL_SB_DLL_01E9_SBPROPELLER_H_

#include "main/dll/sbshipheadstate_struct.h"
#include "main/dll/sbpropellerstate_struct.h"
#include "main/objhits.h"
#include "main/dll/DB/DBstealerworm.h"

u32 sbGetPropeller(void);
int SB_Propeller_getExtraSize(void);
void SB_Propeller_render(int obj, int p2, int p3, int p4, int p5, s8 visible);
void SB_Propeller_hitDetect(GameObject* obj);
void SB_Propeller_update(GameObject* obj);
void SB_Propeller_init(GameObject* obj, int placement);

#endif
