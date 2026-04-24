// Function: FUN_8028e8f4
// Entry: 8028e8f4
// Size: 780 bytes

uint FUN_8028e8f4(int param_1,uint param_2,int param_3,int param_4)

{
  bool bVar1;
  bool bVar2;
  ushort uVar3;
  int iVar4;
  int iVar5;
  undefined4 uVar6;
  uint uVar7;
  undefined4 uVar8;
  uint local_28 [3];
  
  iVar4 = FUN_802918c0(param_4,0);
  if (iVar4 == 0) {
    FUN_802918c0(param_4,0xffffffff);
  }
  uVar7 = param_2 * param_3;
  if (((uVar7 == 0) || (*(char *)(param_4 + 10) != '\0')) ||
     (uVar3 = *(ushort *)(param_4 + 4) >> 6 & 7, uVar3 == 0)) {
    return 0;
  }
  if (uVar3 == 2) {
    FUN_8028f678();
  }
  bVar2 = true;
  bVar1 = false;
  if (((*(byte *)(param_4 + 5) >> 3 & 1) == 0) || ((*(byte *)(param_4 + 4) >> 1 & 3) == 2)) {
    bVar1 = true;
  }
  if ((!bVar1) && ((*(byte *)(param_4 + 4) >> 1 & 3) != 1)) {
    bVar2 = false;
  }
  if ((*(byte *)(param_4 + 8) >> 5 == 0) && ((*(byte *)(param_4 + 4) >> 3 & 2) != 0)) {
    if (((*(byte *)(param_4 + 4) >> 3 & 4) != 0) && (iVar4 = FUN_8028ee18(param_4,0,2), iVar4 != 0))
    {
      return 0;
    }
    *(byte *)(param_4 + 8) = *(byte *)(param_4 + 8) & 0x1f | 0x20;
    FUN_8028e8c0(param_4);
  }
  if (*(byte *)(param_4 + 8) >> 5 != 1) {
    *(undefined *)(param_4 + 10) = 1;
    *(undefined4 *)(param_4 + 0x28) = 0;
    return 0;
  }
  iVar4 = 0;
  if (uVar7 != 0) {
    if ((*(int *)(param_4 + 0x24) != *(int *)(param_4 + 0x1c)) || (bVar2)) {
      *(int *)(param_4 + 0x28) =
           *(int *)(param_4 + 0x20) - (*(int *)(param_4 + 0x24) - *(int *)(param_4 + 0x1c));
      while( true ) {
        iVar5 = 0;
        local_28[0] = *(uint *)(param_4 + 0x28);
        if (uVar7 < *(uint *)(param_4 + 0x28)) {
          local_28[0] = uVar7;
        }
        if ((((*(byte *)(param_4 + 4) >> 1 & 3) == 1) && (local_28[0] != 0)) &&
           (iVar5 = FUN_8028f274(param_1,10), iVar5 != 0)) {
          local_28[0] = (iVar5 + 1) - param_1;
        }
        if (local_28[0] != 0) {
          FUN_80003494(*(undefined4 *)(param_4 + 0x24),param_1);
          param_1 = param_1 + local_28[0];
          iVar4 = iVar4 + local_28[0];
          uVar7 = uVar7 - local_28[0];
          *(uint *)(param_4 + 0x24) = *(int *)(param_4 + 0x24) + local_28[0];
          *(uint *)(param_4 + 0x28) = *(int *)(param_4 + 0x28) - local_28[0];
        }
        if ((((*(int *)(param_4 + 0x28) == 0) || (iVar5 != 0)) ||
            ((*(byte *)(param_4 + 4) >> 1 & 3) == 0)) &&
           (iVar5 = FUN_8028e7fc(param_4,0), iVar5 != 0)) break;
        if ((uVar7 == 0) || (!bVar2)) goto LAB_8028eb5c;
      }
      *(undefined *)(param_4 + 10) = 1;
      uVar7 = 0;
      *(undefined4 *)(param_4 + 0x28) = 0;
    }
  }
LAB_8028eb5c:
  if ((uVar7 != 0) && (!bVar2)) {
    uVar6 = *(undefined4 *)(param_4 + 0x1c);
    uVar8 = *(undefined4 *)(param_4 + 0x20);
    *(int *)(param_4 + 0x1c) = param_1;
    *(uint *)(param_4 + 0x20) = uVar7;
    *(uint *)(param_4 + 0x24) = param_1 + uVar7;
    iVar5 = FUN_8028e7fc(param_4,local_28);
    if (iVar5 != 0) {
      *(undefined *)(param_4 + 10) = 1;
      *(undefined4 *)(param_4 + 0x28) = 0;
    }
    *(undefined4 *)(param_4 + 0x1c) = uVar6;
    iVar4 = iVar4 + local_28[0];
    *(undefined4 *)(param_4 + 0x20) = uVar8;
    FUN_8028e8c0(param_4);
    *(undefined4 *)(param_4 + 0x28) = 0;
  }
  if ((*(byte *)(param_4 + 4) >> 1 & 3) != 2) {
    *(undefined4 *)(param_4 + 0x28) = 0;
  }
  return (iVar4 + (param_2 - 1)) / param_2;
}

