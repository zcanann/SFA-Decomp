// Function: FUN_8028ee38
// Entry: 8028ee38
// Size: 572 bytes

undefined4 FUN_8028ee38(undefined4 *param_1,uint param_2,int param_3)

{
  uint uVar1;
  ushort uVar2;
  int iVar3;
  uint local_18 [4];
  
  if (((*(ushort *)(param_1 + 1) >> 6 & 7) != 1) || (*(char *)((int)param_1 + 10) != '\0')) {
    DAT_803de408 = 0x28;
    return 0xffffffff;
  }
  local_18[0] = param_2;
  if ((*(byte *)(param_1 + 2) >> 5 == 1) && (iVar3 = FUN_8028e7fc(param_1,0), iVar3 != 0)) {
    *(undefined *)((int)param_1 + 10) = 1;
    param_1[10] = 0;
    DAT_803de408 = 0x28;
    return 0xffffffff;
  }
  if (param_3 == 1) {
    param_3 = 0;
    uVar2 = *(ushort *)(param_1 + 1) >> 6 & 7;
    if (((uVar2 == 1) || (uVar2 == 2)) && (*(char *)((int)param_1 + 10) == '\0')) {
      uVar1 = (uint)(*(byte *)(param_1 + 2) >> 5);
      if (uVar1 == 0) {
        iVar3 = param_1[6];
      }
      else {
        iVar3 = param_1[0xd] + (param_1[9] - param_1[7]);
        if (2 < uVar1) {
          iVar3 = iVar3 - (uVar1 - 2);
        }
      }
    }
    else {
      iVar3 = -1;
      DAT_803de408 = 0x28;
    }
    local_18[0] = local_18[0] + iVar3;
  }
  if (((param_3 == 2) || ((*(byte *)(param_1 + 1) >> 3 & 7) == 3)) ||
     ((*(byte *)(param_1 + 2) >> 5 != 2 && (*(byte *)(param_1 + 2) >> 5 != 3)))) {
    *(byte *)(param_1 + 2) = *(byte *)(param_1 + 2) & 0x1f;
  }
  else if ((local_18[0] < (uint)param_1[6]) && ((uint)param_1[0xd] <= local_18[0])) {
    param_1[9] = param_1[7] + (local_18[0] - param_1[0xd]);
    param_1[10] = param_1[6] - local_18[0];
    *(byte *)(param_1 + 2) = *(byte *)(param_1 + 2) & 0x1f | 0x40;
  }
  else {
    *(byte *)(param_1 + 2) = *(byte *)(param_1 + 2) & 0x1f;
  }
  if (*(byte *)(param_1 + 2) >> 5 == 0) {
    if (((code *)param_1[0xe] != (code *)0x0) &&
       (iVar3 = (*(code *)param_1[0xe])(*param_1,local_18,param_3,param_1[0x12]), iVar3 != 0)) {
      *(undefined *)((int)param_1 + 10) = 1;
      param_1[10] = 0;
      DAT_803de408 = 0x28;
      return 0xffffffff;
    }
    *(undefined *)((int)param_1 + 9) = 0;
    param_1[6] = local_18[0];
    param_1[10] = 0;
  }
  return 0;
}

