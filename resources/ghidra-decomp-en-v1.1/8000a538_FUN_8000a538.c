// Function: FUN_8000a538
// Entry: 8000a538
// Size: 784 bytes

int * FUN_8000a538(int *param_1,int param_2)

{
  int iVar1;
  uint uVar2;
  int *piVar3;
  int *piVar4;
  uint uVar5;
  uint *puVar6;
  uint *puVar7;
  ushort *puVar8;
  int iVar9;
  
  if ((param_2 == 1) || (param_2 == 0)) {
    puVar8 = DAT_803dd480;
    iVar9 = DAT_803dd484;
    if (DAT_803dd484 != 0) {
      do {
        if ((int *)(uint)*puVar8 == param_1) goto LAB_8000a594;
        puVar8 = puVar8 + 8;
        iVar9 = iVar9 + -1;
      } while (iVar9 != 0);
    }
    puVar8 = (ushort *)0x0;
LAB_8000a594:
    if (puVar8 != (ushort *)0x0) {
      if ((param_1 == (int *)0xeb) && (param_2 == 1)) {
        piVar3 = &DAT_80336a20;
        iVar9 = 4;
        do {
          if ((((((*piVar3 == 0x5e) && (iVar1 = piVar3[3], iVar1 != 0)) && (iVar1 != 2)) &&
               (piVar4 = piVar3, iVar1 != 5)) ||
              (((piVar4 = piVar3 + 9, *piVar4 == 0x5e && (iVar1 = piVar3[0xc], iVar1 != 0)) &&
               ((iVar1 != 2 && (iVar1 != 5)))))) ||
             ((((piVar4 = piVar3 + 0x12, *piVar4 == 0x5e && (iVar1 = piVar3[0x15], iVar1 != 0)) &&
               ((iVar1 != 2 && (iVar1 != 5)))) ||
              ((((piVar4 = piVar3 + 0x1b, *piVar4 == 0x5e && (iVar1 = piVar3[0x1e], iVar1 != 0)) &&
                (iVar1 != 2)) && (iVar1 != 5)))))) goto LAB_8000a68c;
          piVar3 = piVar3 + 0x24;
          iVar9 = iVar9 + -1;
        } while (iVar9 != 0);
        piVar4 = (int *)0x0;
LAB_8000a68c:
        if (piVar4 != (int *)0x0) {
          return piVar4;
        }
        piVar3 = (int *)FUN_80020078(0xa7f);
        if (piVar3 != (int *)0x0) {
          return piVar3;
        }
      }
      uVar5 = (uint)puVar8[1];
      puVar6 = &DAT_80336a20;
      param_1 = (int *)0xf;
      iVar9 = 4;
      do {
        if (((((*puVar6 == uVar5) && (uVar2 = puVar6[3], uVar2 != 0)) &&
             ((uVar2 != 2 && (puVar7 = puVar6, uVar2 != 5)))) ||
            (((puVar7 = puVar6 + 9, *puVar7 == uVar5 && (uVar2 = puVar6[0xc], uVar2 != 0)) &&
             ((uVar2 != 2 && (uVar2 != 5)))))) ||
           (((((puVar7 = puVar6 + 0x12, *puVar7 == uVar5 && (uVar2 = puVar6[0x15], uVar2 != 0)) &&
              (uVar2 != 2)) && (uVar2 != 5)) ||
            (((puVar7 = puVar6 + 0x1b, *puVar7 == uVar5 && (uVar2 = puVar6[0x1e], uVar2 != 0)) &&
             ((uVar2 != 2 && (uVar2 != 5)))))))) goto LAB_8000a78c;
        puVar6 = puVar6 + 0x24;
        param_1 = (int *)((int)param_1 + -3);
        iVar9 = iVar9 + -1;
      } while (iVar9 != 0);
      puVar7 = (uint *)0x0;
LAB_8000a78c:
      if (param_2 == 1) {
        if (puVar7 == (uint *)0x0) {
          param_1 = (int *)FUN_8000b0f0((uint)puVar8);
        }
        else if (puVar7[3] == 1) {
          param_1 = (int *)FUN_80272e84(*(ushort *)(puVar7 + 5) & 0xff,(uint)puVar8[2],puVar7[1],0);
        }
      }
      else if (puVar7 != (uint *)0x0) {
        uVar5 = (uint)puVar8[2];
        param_1 = (int *)puVar7[3];
        if (param_1 != (int *)0x2) {
          if ((param_1 == (int *)0x4) || (param_1 == (int *)0x5)) {
            puVar7[3] = 5;
          }
          else {
            if (uVar5 < 500) {
              uVar5 = 500;
            }
            param_1 = (int *)FUN_80272e84(0,uVar5,puVar7[1],1);
            puVar7[3] = 2;
          }
        }
      }
    }
  }
  return param_1;
}

