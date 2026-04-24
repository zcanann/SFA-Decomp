#include "ghidra_import.h"
#include "main/dll/dll_C0.h"

extern undefined4 FUN_8011f6d0();
extern int FUN_80134f70();

extern undefined4 gCamcontrolState;

/*
 * --INFO--
 *
 * Function: camcontrol_playTargetTypeSfx
 * EN v1.0 Address: 0x8010224C
 * EN v1.0 Size: 168b
 * EN v1.1 Address: 0x80102440
 * EN v1.1 Size: 168b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void camcontrol_playTargetTypeSfx(void)
{
  byte bVar1;
  int iVar2;
  int iVar3;
  
  iVar3 = *(int *)(gCamcontrolState + 0x124);
  iVar2 = FUN_80134f70();
  if ((iVar2 == 0) && (iVar3 != 0)) {
    bVar1 = *(byte *)(*(int *)(iVar3 + 0x78) + (uint)*(byte *)(iVar3 + 0xe4) * 5 + 4) & 0xf;
    if (bVar1 == 6) {
      if (*(short *)(iVar3 + 0x44) == 6) {
        FUN_8011f6d0(8);
      }
      else {
        FUN_8011f6d0(9);
      }
    }
    else if (bVar1 == 2) {
      FUN_8011f6d0(7);
    }
    else if (bVar1 == 5) {
      FUN_8011f6d0(0xf);
    }
  }
  return;
}
