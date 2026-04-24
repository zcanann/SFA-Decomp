// Function: FUN_8002a8ec
// Entry: 8002a8ec
// Size: 692 bytes

void FUN_8002a8ec(void)

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
  undefined4 local_74;
  undefined4 local_70;
  undefined4 local_6c;
  undefined4 local_68;
  undefined4 local_60;
  undefined4 local_58;
  
  iVar3 = FUN_8028680c();
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
        for (iVar20 = 0; iVar20 < (int)(uint)*(byte *)(iVar4 + 0xeb); iVar20 = iVar20 + 1) {
          iVar18 = *(int *)(iVar5 + 200);
          *(undefined2 *)(iVar18 + 0xe6) = 0;
          *(byte *)(iVar18 + 0xe5) = *(byte *)(iVar18 + 0xe5) & 0xf9;
          iVar6 = iVar18;
          for (iVar19 = 0; iVar19 < (int)(uint)*(byte *)(iVar18 + 0xeb); iVar19 = iVar19 + 1) {
            iVar16 = *(int *)(iVar6 + 200);
            *(undefined2 *)(iVar16 + 0xe6) = 0;
            *(byte *)(iVar16 + 0xe5) = *(byte *)(iVar16 + 0xe5) & 0xf9;
            iVar7 = iVar16;
            for (iVar17 = 0; iVar17 < (int)(uint)*(byte *)(iVar16 + 0xeb); iVar17 = iVar17 + 1) {
              iVar14 = *(int *)(iVar7 + 200);
              *(undefined2 *)(iVar14 + 0xe6) = 0;
              *(byte *)(iVar14 + 0xe5) = *(byte *)(iVar14 + 0xe5) & 0xf9;
              iVar8 = iVar14;
              for (iVar15 = 0; iVar15 < (int)(uint)*(byte *)(iVar14 + 0xeb); iVar15 = iVar15 + 1) {
                iVar12 = *(int *)(iVar8 + 200);
                *(undefined2 *)(iVar12 + 0xe6) = 0;
                *(byte *)(iVar12 + 0xe5) = *(byte *)(iVar12 + 0xe5) & 0xf9;
                iVar9 = iVar12;
                for (iVar13 = 0; iVar13 < (int)(uint)*(byte *)(iVar12 + 0xeb); iVar13 = iVar13 + 1)
                {
                  iVar10 = *(int *)(iVar9 + 200);
                  *(undefined2 *)(iVar10 + 0xe6) = 0;
                  *(byte *)(iVar10 + 0xe5) = *(byte *)(iVar10 + 0xe5) & 0xf9;
                  for (iVar11 = 0; iVar11 < (int)(uint)*(byte *)(iVar10 + 0xeb); iVar11 = iVar11 + 1
                      ) {
                    FUN_8002a8ec();
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
  FUN_80286858();
  return;
}

