#include "ghidra_import.h"
#include "main/dll/CR/CRfueltank.h"

extern undefined4 FUN_8003b818();

/*
 * --INFO--
 *
 * Function: SB_ShipGun_update
 * EN v1.0 Address: 0x801E34C0
 * EN v1.0 Size: 92b
 * EN v1.1 Address: 0x801E3A44
 * EN v1.1 Size: 108b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void SB_ShipGun_update(int param_1, int param_2, int param_3, int param_4, int param_5, s8 visible)
{
  if ((((*(int *)(param_1 + 0x30) == 0) || (*(short *)(*(int *)(param_1 + 0x30) + 0x46) != 0x139))
      && (visible != 0)) &&
     ((*(char *)(*(int *)(param_1 + 0xb8) + 0xc) != '\0' &&
      (*(char *)(*(int *)(param_1 + 0xb8) + 0xd) != '\0')))) {
    FUN_8003b818(param_1);
  }
  return;
}
