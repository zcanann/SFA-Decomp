// Function: FUN_8000a518
// Entry: 8000a518
// Size: 784 bytes

int * FUN_8000a518(int *param_1,int param_2)

{
  int iVar1;
  uint uVar2;
  ushort uVar3;
  int *piVar4;
  int *piVar5;
  int iVar6;
  uint uVar7;
  uint *puVar8;
  uint *puVar9;
  ushort *puVar10;
  int iVar11;
  
  if ((param_2 == 1) || (param_2 == 0)) {
    puVar10 = DAT_803dc800;
    iVar6 = DAT_803dc804;
    if (DAT_803dc804 != 0) {
      do {
        if ((int *)(uint)*puVar10 == param_1) goto LAB_8000a574;
        puVar10 = puVar10 + 8;
        iVar6 = iVar6 + -1;
      } while (iVar6 != 0);
    }
    puVar10 = (ushort *)0x0;
LAB_8000a574:
    if (puVar10 != (ushort *)0x0) {
      if ((param_1 == (int *)0xeb) && (param_2 == 1)) {
        piVar4 = &DAT_80335dc0;
        iVar6 = 0xf;
        iVar11 = 4;
        do {
          if ((((((*piVar4 == 0x5e) && (iVar1 = piVar4[3], iVar1 != 0)) && (iVar1 != 2)) &&
               (piVar5 = piVar4, iVar1 != 5)) ||
              (((piVar5 = piVar4 + 9, *piVar5 == 0x5e && (iVar1 = piVar4[0xc], iVar1 != 0)) &&
               ((iVar1 != 2 && (iVar1 != 5)))))) ||
             ((((piVar5 = piVar4 + 0x12, *piVar5 == 0x5e && (iVar1 = piVar4[0x15], iVar1 != 0)) &&
               ((iVar1 != 2 && (iVar1 != 5)))) ||
              ((((piVar5 = piVar4 + 0x1b, *piVar5 == 0x5e && (iVar1 = piVar4[0x1e], iVar1 != 0)) &&
                (iVar1 != 2)) && (iVar1 != 5)))))) goto LAB_8000a66c;
          piVar4 = piVar4 + 0x24;
          iVar6 = iVar6 + -3;
          iVar11 = iVar11 + -1;
        } while (iVar11 != 0);
        piVar5 = (int *)0x0;
LAB_8000a66c:
        if (piVar5 != (int *)0x0) {
          return piVar5;
        }
        piVar4 = (int *)FUN_8001ffb4(0xa7f,iVar6);
        if (piVar4 != (int *)0x0) {
          return piVar4;
        }
      }
      uVar7 = (uint)puVar10[1];
      puVar8 = &DAT_80335dc0;
      param_1 = (int *)0xf;
      iVar6 = 4;
      do {
        if (((((*puVar8 == uVar7) && (uVar2 = puVar8[3], uVar2 != 0)) &&
             ((uVar2 != 2 && (puVar9 = puVar8, uVar2 != 5)))) ||
            (((puVar9 = puVar8 + 9, *puVar9 == uVar7 && (uVar2 = puVar8[0xc], uVar2 != 0)) &&
             ((uVar2 != 2 && (uVar2 != 5)))))) ||
           (((((puVar9 = puVar8 + 0x12, *puVar9 == uVar7 && (uVar2 = puVar8[0x15], uVar2 != 0)) &&
              (uVar2 != 2)) && (uVar2 != 5)) ||
            (((puVar9 = puVar8 + 0x1b, *puVar9 == uVar7 && (uVar2 = puVar8[0x1e], uVar2 != 0)) &&
             ((uVar2 != 2 && (uVar2 != 5)))))))) goto LAB_8000a76c;
        puVar8 = puVar8 + 0x24;
        param_1 = (int *)((int)param_1 + -3);
        iVar6 = iVar6 + -1;
      } while (iVar6 != 0);
      puVar9 = (uint *)0x0;
LAB_8000a76c:
      if (param_2 == 1) {
        if (puVar9 == (uint *)0x0) {
          param_1 = (int *)FUN_8000b0d0(puVar10);
        }
        else if (puVar9[3] == 1) {
          param_1 = (int *)FUN_80272720(*(ushort *)(puVar9 + 5) & 0xff,puVar10[2],puVar9[1],0);
        }
      }
      else if (puVar9 != (uint *)0x0) {
        uVar3 = puVar10[2];
        param_1 = (int *)puVar9[3];
        if (param_1 != (int *)&DAT_00000002) {
          if ((param_1 == (int *)&DAT_00000004) || (param_1 == (int *)0x5)) {
            puVar9[3] = 5;
          }
          else {
            if (uVar3 < 500) {
              uVar3 = 500;
            }
            param_1 = (int *)FUN_80272720(0,uVar3,puVar9[1],1);
            puVar9[3] = 2;
          }
        }
      }
    }
  }
  return param_1;
}

