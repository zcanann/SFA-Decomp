// Function: FUN_8017ffd0
// Entry: 8017ffd0
// Size: 584 bytes

void FUN_8017ffd0(void)

{
  int iVar1;
  undefined4 uVar2;
  byte bVar8;
  int *piVar3;
  int iVar4;
  uint uVar5;
  int iVar6;
  int iVar7;
  byte *pbVar9;
  byte *pbVar10;
  int iVar11;
  undefined8 uVar12;
  int local_28 [10];
  
  uVar12 = FUN_802860d8();
  iVar4 = (int)((ulonglong)uVar12 >> 0x20);
  pbVar9 = (byte *)uVar12;
  iVar1 = FUN_8001ffb4(0x4e5);
  if (iVar1 == 0) {
    uVar2 = 0;
  }
  else {
    iVar1 = FUN_8002b9ac();
    if (iVar1 == 0) {
      uVar2 = 0;
    }
    else {
      if (*pbVar9 == 0) {
        bVar8 = FUN_800dbcfc(iVar4 + 0xc,0);
        *pbVar9 = bVar8;
        if (*pbVar9 == 0) {
          uVar2 = 0;
          goto LAB_80180200;
        }
        piVar3 = (int *)(**(code **)(*DAT_803dca9c + 0x10))(local_28);
        pbVar10 = pbVar9;
        for (iVar1 = 0; iVar1 < local_28[0]; iVar1 = iVar1 + 1) {
          iVar6 = *piVar3;
          if ((*(char *)(iVar6 + 0x19) == '$') && (*(char *)(iVar6 + 3) == '\0')) {
            iVar7 = 0;
            iVar11 = 4;
            do {
              if (*(byte *)(iVar6 + iVar7 + 4) == *pbVar9) {
                *(undefined4 *)(pbVar10 + 4) = *(undefined4 *)(iVar6 + 0x14);
                pbVar10 = pbVar10 + 4;
                break;
              }
              iVar7 = iVar7 + 1;
              iVar11 = iVar11 + -1;
            } while (iVar11 != 0);
          }
          piVar3 = piVar3 + 1;
        }
      }
      iVar4 = FUN_8005a10c((double)FLOAT_803e38a0,iVar4 + 0xc);
      if (iVar4 == 0) {
        iVar4 = FUN_8002b9ec();
        uVar5 = FUN_800dbcfc(iVar4 + 0xc,0);
        if (uVar5 != 0) {
          if (uVar5 == *pbVar9) {
            uVar2 = 1;
            goto LAB_80180200;
          }
          iVar1 = 0;
          pbVar10 = pbVar9;
          do {
            if (*(int *)(pbVar10 + 4) == 0) break;
            iVar6 = (**(code **)(*DAT_803dca9c + 0x1c))();
            if (((iVar6 != 0) &&
                ((*(short *)(iVar6 + 0x30) == -1 || (iVar7 = FUN_8001ffb4(), iVar7 != 0)))) &&
               ((*(short *)(iVar6 + 0x32) == -1 || (iVar7 = FUN_8001ffb4(), iVar7 == 0)))) {
              if (*(byte *)(iVar6 + 4) == uVar5) {
                uVar2 = 1;
                goto LAB_80180200;
              }
              if (*(byte *)(iVar6 + 5) == uVar5) {
                uVar2 = 1;
                goto LAB_80180200;
              }
              if (*(byte *)(iVar6 + 6) == uVar5) {
                uVar2 = 1;
                goto LAB_80180200;
              }
              if (*(byte *)(iVar6 + 7) == uVar5) {
                uVar2 = 1;
                goto LAB_80180200;
              }
            }
            pbVar10 = pbVar10 + 4;
            iVar1 = iVar1 + 1;
          } while (iVar1 < 0x18);
        }
        uVar2 = FUN_800dba4c(iVar4 + 0xc,*pbVar9);
      }
      else {
        uVar2 = 0;
      }
    }
  }
LAB_80180200:
  FUN_80286124(uVar2);
  return;
}

