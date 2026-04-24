// Function: FUN_800541ac
// Entry: 800541ac
// Size: 328 bytes

void FUN_800541ac(undefined4 param_1,undefined4 *param_2,undefined4 *param_3,uint param_4,
                 int param_5)

{
  undefined4 *puVar1;
  undefined4 *puVar2;
  int iVar3;
  int iVar4;
  uint uVar5;
  undefined4 *puVar6;
  
  if (param_2 != (undefined4 *)0x0) {
    param_5 = param_5 >> 0x10;
    if (*(ushort *)(param_2 + 4) == 0) {
      uVar5 = 0;
    }
    else {
      uVar5 = (int)(uint)*(ushort *)(param_2 + 4) >> 8;
    }
    puVar1 = param_2;
    puVar6 = param_2;
    if ((1 < uVar5) && (param_5 < (int)uVar5)) {
      iVar4 = 0;
      for (; (iVar4 < param_5 && (puVar6 != (undefined4 *)0x0)); puVar6 = (undefined4 *)*puVar6) {
        iVar4 = iVar4 + 1;
      }
      if (puVar6 != (undefined4 *)0x0) {
        puVar1 = puVar6;
      }
      puVar6 = puVar1;
      if ((param_4 & 0x40) != 0) {
        if ((param_4 & 0x80000) == 0) {
          iVar4 = param_5 + 1;
          if ((int)uVar5 <= iVar4) {
            if ((param_4 & 0x40000) == 0) {
              iVar4 = uVar5 - 1;
            }
            else {
              iVar4 = param_5 + -1;
            }
          }
        }
        else {
          iVar4 = param_5 + -1;
          if (iVar4 < 0) {
            if ((param_4 & 0x40000) == 0) {
              iVar4 = 0;
            }
            else {
              iVar4 = param_5 + 1;
            }
          }
        }
        iVar3 = 0;
        for (puVar2 = param_2; (iVar3 < iVar4 && (puVar2 != (undefined4 *)0x0));
            puVar2 = (undefined4 *)*puVar2) {
          iVar3 = iVar3 + 1;
        }
        puVar6 = param_2;
        if (puVar2 != (undefined4 *)0x0) {
          puVar6 = puVar2;
        }
      }
    }
    if (param_3 != (undefined4 *)0x0) {
      puVar6 = param_3;
    }
    FUN_8004c2e4(puVar1,0);
    FUN_8004c2e4(puVar6,1);
  }
  return;
}

