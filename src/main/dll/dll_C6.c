#include "ghidra_import.h"
#include "main/dll/dll_C6.h"

extern undefined4 camcontrol_updateTargetReticle();
extern int FUN_80134f70();
extern undefined4 countLeadingZeros();

extern undefined4 DAT_803dc5f0;
extern undefined4 gCamcontrolCurrentActionId;
extern undefined4 gCamcontrolState;

/*
 * --INFO--
 *
 * Function: FUN_801023a8
 * EN v1.0 Address: 0x801023A8
 * EN v1.0 Size: 152b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801023a8(void)
{
  int iVar1;
  
  iVar1 = FUN_80134f70();
  if (iVar1 == 0) {
    DAT_803dc5f0 = 0xffff;
    countLeadingZeros(0x49 - gCamcontrolCurrentActionId);
    camcontrol_updateTargetReticle();
    *(undefined4 *)(gCamcontrolState + 0x120) = 0;
  }
  return;
}
