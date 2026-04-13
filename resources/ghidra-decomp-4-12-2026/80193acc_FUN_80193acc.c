// Function: FUN_80193acc
// Entry: 80193acc
// Size: 352 bytes

void FUN_80193acc(void)

{
  int iVar1;
  int iVar2;
  ushort *puVar3;
  ushort *puVar4;
  uint uVar5;
  uint uVar6;
  short *psVar7;
  int iVar8;
  uint *puVar9;
  int iVar10;
  int iVar11;
  int iVar12;
  int iVar13;
  int iVar14;
  undefined8 uVar15;
  float fStack_58;
  float local_54;
  undefined4 local_48;
  uint uStack_44;
  
  uVar15 = FUN_80286820();
  iVar1 = (int)((ulonglong)uVar15 >> 0x20);
  puVar9 = *(uint **)(iVar1 + 0xb8);
  iVar8 = *(int *)(iVar1 + 0x4c);
  if ((int)uVar15 == 0) {
    iVar2 = FUN_8005b478((double)*(float *)(iVar1 + 0xc),(double)*(float *)(iVar1 + 0x10));
    iVar2 = FUN_8005b068(iVar2);
    if (iVar2 != 0) {
      iVar12 = 0;
      for (iVar11 = 0; iVar11 < (int)(uint)*(ushort *)(iVar2 + 0x9a); iVar11 = iVar11 + 1) {
        puVar3 = (ushort *)FUN_80060868(iVar2,iVar11);
        uVar6 = FUN_800607f4((int)puVar3);
        if (*(byte *)(iVar8 + 0x25) == uVar6) {
          iVar13 = iVar12;
          for (uVar6 = (uint)*puVar3; (int)uVar6 < (int)(uint)puVar3[10]; uVar6 = uVar6 + 1) {
            puVar4 = (ushort *)FUN_80060858(iVar2,uVar6);
            iVar10 = 0;
            iVar14 = iVar13;
            do {
              psVar7 = (short *)(*(int *)(iVar2 + 0x58) + (uint)*puVar4 * 6);
              FUN_8006076c(psVar7,&fStack_58);
              uVar5 = puVar9[1];
              if (uVar5 != 0) {
                uStack_44 = (int)*(short *)(uVar5 + iVar14) ^ 0x80000000;
                local_48 = 0x43300000;
                local_54 = (float)((double)CONCAT44(0x43300000,uStack_44) - DOUBLE_803e4c60);
                FUN_80060708(psVar7,&fStack_58);
              }
              iVar14 = iVar14 + 2;
              iVar13 = iVar13 + 2;
              iVar12 = iVar12 + 2;
              puVar4 = puVar4 + 1;
              iVar10 = iVar10 + 1;
            } while (iVar10 < 3);
          }
        }
      }
    }
  }
  uVar6 = *puVar9;
  if (uVar6 != 0) {
    FUN_800238c4(uVar6);
  }
  FUN_8003709c(iVar1,0x31);
  FUN_8028686c();
  return;
}

