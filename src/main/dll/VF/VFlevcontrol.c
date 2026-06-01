#include "ghidra_import.h"
#include "main/dll/VF/VFlevcontrol.h"

extern uint GameBit_Get(int eventId);
extern undefined4 GameBit_Set(int eventId, int value);
extern int FUN_8028683c();
extern undefined4 FUN_80286888();

extern undefined4 DAT_803286b0;

/*
 * --INFO--
 *
 * Function: sc_totemstrength_sortCompletionGameBits
 * EN v1.0 Address: 0x801DE914
 * EN v1.0 Size: 268b
 * EN v1.1 Address: 0x801DE910
 * EN v1.1 Size: 272b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void sc_totemstrength_sortCompletionGameBits(void)
{
  ushort uVar1;
  ushort uVar2;
  int iVar3;
  uint uVar4;
  undefined2 extraout_r4;
  byte bVar5;
  byte bVar6;
  ushort local_28 [20];
  
  iVar3 = FUN_8028683c();
  for (bVar6 = 0; bVar6 < 3; bVar6 = bVar6 + 1) {
    uVar4 = GameBit_Get((uint)*(ushort *)(iVar3 + (uint)bVar6 * 2));
    local_28[bVar6] = (ushort)uVar4;
  }
  local_28[3] = extraout_r4;
  for (bVar6 = 0; bVar6 < 3; bVar6 = bVar6 + 1) {
    for (bVar5 = 0; bVar5 < 3; bVar5 = bVar5 + 1) {
      uVar1 = local_28[bVar5 + 1];
      if (uVar1 != 0) {
        uVar2 = local_28[bVar5];
        if ((uVar1 < uVar2) || (uVar2 == 0)) {
          local_28[bVar5] = uVar1;
          local_28[bVar5 + 1] = uVar2;
        }
      }
    }
  }
  for (bVar6 = 0; bVar6 < 3; bVar6 = bVar6 + 1) {
    GameBit_Set((uint)*(ushort *)(iVar3 + (uint)bVar6 * 2),(uint)local_28[bVar6]);
  }
  FUN_80286888();
  return;
}
