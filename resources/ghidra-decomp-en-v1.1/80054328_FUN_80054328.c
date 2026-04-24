// Function: FUN_80054328
// Entry: 80054328
// Size: 328 bytes

void FUN_80054328(undefined4 param_1,undefined4 *param_2,undefined4 *param_3,uint param_4,
                 int param_5)

{
  undefined4 *puVar1;
  undefined4 *puVar2;
  int iVar3;
  int iVar4;
  uint uVar5;
  undefined4 *puVar6;
  
  if (param_2 != (undefined4 *)0x0) {
    iVar4 = param_5 >> 0x10;
    if (*(ushort *)(param_2 + 4) == 0) {
      uVar5 = 0;
    }
    else {
      uVar5 = (int)(uint)*(ushort *)(param_2 + 4) >> 8;
    }
    puVar1 = param_2;
    puVar6 = param_2;
    if ((1 < uVar5) && (iVar4 < (int)uVar5)) {
      iVar3 = 0;
      for (; (iVar3 < iVar4 && (puVar6 != (undefined4 *)0x0)); puVar6 = (undefined4 *)*puVar6) {
        iVar3 = iVar3 + 1;
      }
      if (puVar6 != (undefined4 *)0x0) {
        puVar1 = puVar6;
      }
      puVar6 = puVar1;
      if ((param_4 & 0x40) != 0) {
        if ((param_4 & 0x80000) == 0) {
          iVar3 = iVar4 + 1;
          if ((int)uVar5 <= iVar3) {
            if ((param_4 & 0x40000) == 0) {
              iVar3 = uVar5 - 1;
            }
            else {
              iVar3 = iVar4 + -1;
            }
          }
        }
        else {
          iVar3 = iVar4 + -1;
          if (iVar3 < 0) {
            if ((param_4 & 0x40000) == 0) {
              iVar3 = 0;
            }
            else {
              iVar3 = iVar4 + 1;
            }
          }
        }
        iVar4 = 0;
        for (puVar2 = param_2; (iVar4 < iVar3 && (puVar2 != (undefined4 *)0x0));
            puVar2 = (undefined4 *)*puVar2) {
          iVar4 = iVar4 + 1;
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
    FUN_8004c460((int)puVar1,0);
    FUN_8004c460((int)puVar6,1);
  }
  return;
}

