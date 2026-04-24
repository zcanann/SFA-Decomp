// Function: FUN_8002a814
// Entry: 8002a814
// Size: 692 bytes

void FUN_8002a814(void)

{
  int iVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  int iVar6;
  int iVar7;
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
  int iVar19;
  int iVar20;
  int iVar21;
  int local_74;
  int local_70;
  int local_6c;
  int local_68;
  int local_60;
  int local_58;
  
  iVar3 = FUN_802860a8();
  *(undefined2 *)(iVar3 + 0xe6) = 0;
  *(byte *)(iVar3 + 0xe5) = *(byte *)(iVar3 + 0xe5) & 0xf9;
  local_70 = iVar3;
  for (local_74 = 0; local_74 < (int)(uint)*(byte *)(iVar3 + 0xeb); local_74 = local_74 + 1) {
    iVar1 = *(int *)(local_70 + 200);
    local_58 = 0;
    *(undefined2 *)(iVar1 + 0xe6) = 0;
    *(byte *)(iVar1 + 0xe5) = *(byte *)(iVar1 + 0xe5) & 0xf9;
    local_6c = iVar1;
    for (; local_58 < (int)(uint)*(byte *)(iVar1 + 0xeb); local_58 = local_58 + 1) {
      iVar2 = *(int *)(local_6c + 200);
      local_60 = 0;
      *(undefined2 *)(iVar2 + 0xe6) = 0;
      *(byte *)(iVar2 + 0xe5) = *(byte *)(iVar2 + 0xe5) & 0xf9;
      local_68 = iVar2;
      for (; local_60 < (int)(uint)*(byte *)(iVar2 + 0xeb); local_60 = local_60 + 1) {
        iVar4 = *(int *)(local_68 + 200);
        *(undefined2 *)(iVar4 + 0xe6) = 0;
        *(byte *)(iVar4 + 0xe5) = *(byte *)(iVar4 + 0xe5) & 0xf9;
        iVar5 = iVar4;
        for (iVar21 = 0; iVar21 < (int)(uint)*(byte *)(iVar4 + 0xeb); iVar21 = iVar21 + 1) {
          iVar19 = *(int *)(iVar5 + 200);
          *(undefined2 *)(iVar19 + 0xe6) = 0;
          *(byte *)(iVar19 + 0xe5) = *(byte *)(iVar19 + 0xe5) & 0xf9;
          iVar6 = iVar19;
          for (iVar20 = 0; iVar20 < (int)(uint)*(byte *)(iVar19 + 0xeb); iVar20 = iVar20 + 1) {
            iVar17 = *(int *)(iVar6 + 200);
            *(undefined2 *)(iVar17 + 0xe6) = 0;
            *(byte *)(iVar17 + 0xe5) = *(byte *)(iVar17 + 0xe5) & 0xf9;
            iVar7 = iVar17;
            for (iVar18 = 0; iVar18 < (int)(uint)*(byte *)(iVar17 + 0xeb); iVar18 = iVar18 + 1) {
              iVar15 = *(int *)(iVar7 + 200);
              *(undefined2 *)(iVar15 + 0xe6) = 0;
              *(byte *)(iVar15 + 0xe5) = *(byte *)(iVar15 + 0xe5) & 0xf9;
              iVar8 = iVar15;
              for (iVar16 = 0; iVar16 < (int)(uint)*(byte *)(iVar15 + 0xeb); iVar16 = iVar16 + 1) {
                iVar13 = *(int *)(iVar8 + 200);
                *(undefined2 *)(iVar13 + 0xe6) = 0;
                *(byte *)(iVar13 + 0xe5) = *(byte *)(iVar13 + 0xe5) & 0xf9;
                iVar9 = iVar13;
                for (iVar14 = 0; iVar14 < (int)(uint)*(byte *)(iVar13 + 0xeb); iVar14 = iVar14 + 1)
                {
                  iVar11 = *(int *)(iVar9 + 200);
                  *(undefined2 *)(iVar11 + 0xe6) = 0;
                  *(byte *)(iVar11 + 0xe5) = *(byte *)(iVar11 + 0xe5) & 0xf9;
                  iVar10 = iVar11;
                  for (iVar12 = 0; iVar12 < (int)(uint)*(byte *)(iVar11 + 0xeb); iVar12 = iVar12 + 1
                      ) {
                    FUN_8002a814(*(undefined4 *)(iVar10 + 200));
                    iVar10 = iVar10 + 4;
                  }
                  iVar9 = iVar9 + 4;
                }
                iVar8 = iVar8 + 4;
              }
              iVar7 = iVar7 + 4;
            }
            iVar6 = iVar6 + 4;
          }
          iVar5 = iVar5 + 4;
        }
        local_68 = local_68 + 4;
      }
      local_6c = local_6c + 4;
    }
    local_70 = local_70 + 4;
  }
  FUN_802860f4();
  return;
}

