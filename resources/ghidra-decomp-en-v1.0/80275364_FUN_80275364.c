// Function: FUN_80275364
// Entry: 80275364
// Size: 776 bytes

undefined4 FUN_80275364(int param_1,uint *param_2)

{
  int iVar1;
  uint uVar2;
  bool bVar3;
  uint local_18 [2];
  
  local_18[0] = param_2[1] >> 0x10;
  if (local_18[0] != 0) {
    if ((*param_2 >> 8 & 1) == 0) {
      *(uint *)(param_1 + 0x118) = *(uint *)(param_1 + 0x118) & 0xfffffffb;
      *(undefined4 *)(param_1 + 0x114) = *(undefined4 *)(param_1 + 0x114);
    }
    else {
      if ((*(uint *)(param_1 + 0x118) & 8) != 0) {
        if ((*(uint *)(param_1 + 0x114) & 0x100) == 0) {
          return 0;
        }
        *(uint *)(param_1 + 0x118) = *(uint *)(param_1 + 0x118);
        *(uint *)(param_1 + 0x114) = *(uint *)(param_1 + 0x114) | 0x400;
      }
      *(uint *)(param_1 + 0x118) = *(uint *)(param_1 + 0x118) | 4;
    }
    if ((*param_2 >> 0x18 & 1) == 0) {
      *(uint *)(param_1 + 0x118) = *(uint *)(param_1 + 0x118) & 0xfffbffff;
      *(undefined4 *)(param_1 + 0x114) = *(undefined4 *)(param_1 + 0x114);
    }
    else {
      if (((*(uint *)(param_1 + 0x118) & 0x20) == 0) &&
         (iVar1 = FUN_80283254(*(uint *)(param_1 + 0xf4) & 0xff), iVar1 == 0)) {
        return 0;
      }
      *(uint *)(param_1 + 0x118) = *(uint *)(param_1 + 0x118) | 0x40000;
    }
    if ((*param_2 >> 0x10 & 1) != 0) {
      uVar2 = FUN_80282e5c();
      local_18[0] = (uVar2 & 0xffff) - ((uVar2 & 0xffff) / local_18[0]) * local_18[0];
    }
    if (local_18[0] == 0xffff) {
      *(undefined4 *)(param_1 + 0x9c) = 0xffffffff;
      *(undefined4 *)(param_1 + 0x98) = 0xffffffff;
    }
    else {
      if ((param_2[1] >> 8 & 1) == 0) {
        FUN_80282f90(local_18,param_1);
        if ((param_2[1] & 1) == 0) {
          *(uint *)(param_1 + 0x9c) = *(uint *)(param_1 + 0xa4) + local_18[0];
          *(uint *)(param_1 + 0x98) =
               *(int *)(param_1 + 0xa0) + (uint)CARRY4(*(uint *)(param_1 + 0xa4),local_18[0]);
        }
        else {
          *(uint *)(param_1 + 0x9c) = local_18[0];
          *(undefined4 *)(param_1 + 0x98) = 0;
        }
      }
      else {
        FUN_80282f80(local_18);
        uVar2 = DAT_803de2e0;
        if ((param_2[1] & 1) == 0) {
          bVar3 = CARRY4(DAT_803de2e4,local_18[0]);
          *(uint *)(param_1 + 0x9c) = DAT_803de2e4 + local_18[0];
          *(uint *)(param_1 + 0x98) = uVar2 + bVar3;
        }
        else {
          *(uint *)(param_1 + 0x9c) = *(uint *)(param_1 + 0x94) + local_18[0];
          *(uint *)(param_1 + 0x98) =
               *(int *)(param_1 + 0x90) + (uint)CARRY4(*(uint *)(param_1 + 0x94),local_18[0]);
        }
      }
      if ((uint)(DAT_803de2e4 < *(uint *)(param_1 + 0x9c)) + *(int *)(param_1 + 0x98) <=
          DAT_803de2e0) {
        *(uint *)(param_1 + 0xa4) = *(uint *)(param_1 + 0x9c);
        *(int *)(param_1 + 0xa0) = *(int *)(param_1 + 0x98);
        *(undefined4 *)(param_1 + 0x9c) = 0;
        *(undefined4 *)(param_1 + 0x98) = 0;
      }
    }
    if ((*(uint *)(param_1 + 0x9c) | *(uint *)(param_1 + 0x98)) != 0) {
      if ((*(uint *)(param_1 + 0x9c) ^ 0xffffffff | *(uint *)(param_1 + 0x98) ^ 0xffffffff) != 0) {
        FUN_80278810(param_1);
      }
      FUN_80278a98(param_1,1);
      return 1;
    }
  }
  return 0;
}

