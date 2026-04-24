#include "ghidra_import.h"
#include "main/dll/dll_C6.h"

extern undefined4 camcontrol_updateTargetReticle();
extern int FUN_80133a28();
extern undefined4 countLeadingZeros();

extern undefined4 DAT_803dc5f0;
extern undefined4 gCamcontrolCurrentActionId;
extern undefined4 gCamcontrolState;

/*
 * --INFO--
 *
 * Function: FUN_8010224c
 * EN v1.0 Address: 0x8010224C
 * EN v1.0 Size: 80b
 * EN v1.1 Address: 0x801023A8
 * EN v1.1 Size: 152b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8010224c(void)
{
  int iVar1;
  
  iVar1 = FUN_80133a28();
  if (iVar1 == 0) {
    DAT_803dc5f0 = 0xffff;
    countLeadingZeros(0x49 - gCamcontrolCurrentActionId);
    camcontrol_updateTargetReticle();
    *(undefined4 *)(gCamcontrolState + 0x120) = 0;
  }
  return;
}
