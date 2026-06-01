#include "ghidra_import.h"
#include "main/dll/brokecannon.h"
#include "main/dll/SC/SCtotemstrength.h"

extern uint GameBit_Get(int eventId);
extern undefined4 GameBit_Set(int eventId, int value);
extern undefined4 FUN_80080f14();

extern undefined4* DAT_803dd6e8;

/*
 * --INFO--
 *
 * Function: SCtotemstrength_updateState
 * EN v1.0 Address: 0x801D80F4
 * EN v1.0 Size: 140b
 * EN v1.1 Address: 0x801D81A0
 * EN v1.1 Size: 100b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void SCtotemstrength_updateState
          (undefined8 param_1,double param_2,double param_3,undefined8 param_4,
           undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)
{
  uint uVar1;
  
  FUN_80080f14(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0);
  uVar1 = GameBit_Get(0x13f);
  if (uVar1 == 0) {
    (**(code **)(*DAT_803dd6e8 + 100))();
  }
  uVar1 = GameBit_Get(0x193);
  if (uVar1 != 0) {
    GameBit_Set(0x194,0);
  }
  return;
}
