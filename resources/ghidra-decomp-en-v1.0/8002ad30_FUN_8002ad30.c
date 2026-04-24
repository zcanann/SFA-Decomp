// Function: FUN_8002ad30
// Entry: 8002ad30
// Size: 616 bytes

void FUN_8002ad30(undefined4 param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,
                 undefined4 param_5,uint param_6)

{
  uint uVar1;
  int iVar2;
  int iVar3;
  undefined uVar4;
  undefined uVar5;
  undefined uVar6;
  undefined uVar7;
  int iVar8;
  int iVar9;
  int iVar10;
  int iVar11;
  int iVar12;
  int iVar13;
  int iVar14;
  int iVar15;
  int iVar16;
  int iVar17;
  int iVar18;
  undefined8 uVar19;
  int local_54;
  int local_50;
  
  uVar19 = FUN_802860a8();
  iVar2 = (int)((ulonglong)uVar19 >> 0x20);
  uVar4 = (undefined)uVar19;
  uVar5 = (undefined)param_3;
  uVar6 = (undefined)param_4;
  uVar7 = (undefined)param_5;
  if ((param_6 & 0xff) == 0) {
    *(byte *)(iVar2 + 0xe5) = *(byte *)(iVar2 + 0xe5) & 0xef;
  }
  else {
    *(byte *)(iVar2 + 0xe5) = *(byte *)(iVar2 + 0xe5) | 0x10;
    *(undefined *)(iVar2 + 0xec) = uVar4;
    *(undefined *)(iVar2 + 0xed) = uVar5;
    *(undefined *)(iVar2 + 0xee) = uVar6;
    *(undefined *)(iVar2 + 0xef) = uVar7;
  }
  uVar1 = param_6 & 0xff;
  local_50 = iVar2;
  for (local_54 = 0; local_54 < (int)(uint)*(byte *)(iVar2 + 0xeb); local_54 = local_54 + 1) {
    iVar3 = *(int *)(local_50 + 200);
    if (uVar1 == 0) {
      *(byte *)(iVar3 + 0xe5) = *(byte *)(iVar3 + 0xe5) & 0xef;
    }
    else {
      *(byte *)(iVar3 + 0xe5) = *(byte *)(iVar3 + 0xe5) | 0x10;
      *(undefined *)(iVar3 + 0xec) = uVar4;
      *(undefined *)(iVar3 + 0xed) = uVar5;
      *(undefined *)(iVar3 + 0xee) = uVar6;
      *(undefined *)(iVar3 + 0xef) = uVar7;
    }
    iVar8 = iVar3;
    for (iVar18 = 0; iVar18 < (int)(uint)*(byte *)(iVar3 + 0xeb); iVar18 = iVar18 + 1) {
      iVar16 = *(int *)(iVar8 + 200);
      if (uVar1 == 0) {
        *(byte *)(iVar16 + 0xe5) = *(byte *)(iVar16 + 0xe5) & 0xef;
      }
      else {
        *(byte *)(iVar16 + 0xe5) = *(byte *)(iVar16 + 0xe5) | 0x10;
        *(undefined *)(iVar16 + 0xec) = uVar4;
        *(undefined *)(iVar16 + 0xed) = uVar5;
        *(undefined *)(iVar16 + 0xee) = uVar6;
        *(undefined *)(iVar16 + 0xef) = uVar7;
      }
      iVar9 = iVar16;
      for (iVar17 = 0; iVar17 < (int)(uint)*(byte *)(iVar16 + 0xeb); iVar17 = iVar17 + 1) {
        iVar14 = *(int *)(iVar9 + 200);
        if (uVar1 == 0) {
          *(byte *)(iVar14 + 0xe5) = *(byte *)(iVar14 + 0xe5) & 0xef;
        }
        else {
          *(byte *)(iVar14 + 0xe5) = *(byte *)(iVar14 + 0xe5) | 0x10;
          *(undefined *)(iVar14 + 0xec) = uVar4;
          *(undefined *)(iVar14 + 0xed) = uVar5;
          *(undefined *)(iVar14 + 0xee) = uVar6;
          *(undefined *)(iVar14 + 0xef) = uVar7;
        }
        iVar10 = iVar14;
        for (iVar15 = 0; iVar15 < (int)(uint)*(byte *)(iVar14 + 0xeb); iVar15 = iVar15 + 1) {
          iVar12 = *(int *)(iVar10 + 200);
          if (uVar1 == 0) {
            *(byte *)(iVar12 + 0xe5) = *(byte *)(iVar12 + 0xe5) & 0xef;
          }
          else {
            *(byte *)(iVar12 + 0xe5) = *(byte *)(iVar12 + 0xe5) | 0x10;
            *(undefined *)(iVar12 + 0xec) = uVar4;
            *(undefined *)(iVar12 + 0xed) = uVar5;
            *(undefined *)(iVar12 + 0xee) = uVar6;
            *(undefined *)(iVar12 + 0xef) = uVar7;
          }
          iVar11 = iVar12;
          for (iVar13 = 0; iVar13 < (int)(uint)*(byte *)(iVar12 + 0xeb); iVar13 = iVar13 + 1) {
            FUN_8002ad30(*(undefined4 *)(iVar11 + 200),(int)uVar19,param_3,param_4,param_5,param_6);
            iVar11 = iVar11 + 4;
          }
          iVar10 = iVar10 + 4;
        }
        iVar9 = iVar9 + 4;
      }
      iVar8 = iVar8 + 4;
    }
    local_50 = local_50 + 4;
  }
  FUN_802860f4();
  return;
}

