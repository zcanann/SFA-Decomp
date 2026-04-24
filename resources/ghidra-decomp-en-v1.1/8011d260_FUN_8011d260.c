// Function: FUN_8011d260
// Entry: 8011d260
// Size: 1296 bytes

int FUN_8011d260(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)

{
  char cVar1;
  uint uVar2;
  char cVar7;
  int iVar3;
  int iVar4;
  undefined uVar8;
  undefined4 uVar5;
  int iVar6;
  byte bVar9;
  int *piVar10;
  undefined8 extraout_f1;
  
  cVar1 = DAT_803de384;
  bVar9 = DAT_803dc070;
  cVar7 = FUN_80134f44();
  if (cVar7 == '\0') {
    if (3 < bVar9) {
      bVar9 = 3;
    }
    if ('\0' < DAT_803de384) {
      DAT_803de384 = DAT_803de384 - bVar9;
    }
    iVar3 = (**(code **)(*DAT_803dd6cc + 0x14))();
    if (iVar3 == 0) {
      (**(code **)(*DAT_803dd720 + 0x34))();
      DAT_803de386 = 2;
    }
    if (DAT_803de385 == '\0') {
      iVar3 = (**(code **)(*DAT_803dd720 + 0xc))();
      iVar4 = (**(code **)(*DAT_803dd720 + 0x14))();
      if (iVar4 != DAT_803de380) {
        FUN_8000bb38(0,0xfc);
      }
      DAT_803de380 = iVar4;
      if (DAT_803dc690 == '\x02') {
        FUN_8011c5fc(iVar3,iVar4);
        if (iVar3 == 0) {
          uVar8 = (**(code **)(*DAT_803dd724 + 0x24))(DAT_803a9430);
          *(undefined *)(DAT_803de388 + 6) = uVar8;
          uVar5 = (**(code **)(*DAT_803dd724 + 0x24))(DAT_803a9434);
          uVar2 = countLeadingZeros(uVar5);
          *(char *)(DAT_803de388 + 8) = (char)(uVar2 >> 5);
          FUN_8005ced0(*(char *)(DAT_803de388 + 6));
          FUN_800154d0(*(undefined *)(DAT_803de388 + 8));
        }
      }
      else if (DAT_803dc690 < '\x02') {
        if (DAT_803dc690 == '\0') {
          DAT_803de38c = (undefined)iVar4;
          iVar3 = FUN_8011c800(iVar3,iVar4);
          if (iVar3 != 0) {
            return 0;
          }
        }
        else if ((-1 < DAT_803dc690) && (FUN_8011c2ac(iVar3,iVar4), iVar3 == 0)) {
          uVar8 = (**(code **)(*DAT_803dd724 + 0x24))(DAT_803a9430);
          *(undefined *)(DAT_803de388 + 9) = uVar8;
          uVar8 = (**(code **)(*DAT_803dd724 + 0x24))(DAT_803a9434);
          *(undefined *)(DAT_803de388 + 10) = uVar8;
          uVar8 = (**(code **)(*DAT_803dd724 + 0x24))(DAT_803a9438);
          *(undefined *)(DAT_803de388 + 0xb) = uVar8;
          uVar8 = (**(code **)(*DAT_803dd724 + 0x24))(DAT_803a943c);
          *(undefined *)(DAT_803de388 + 0xc) = uVar8;
        }
      }
      else if (DAT_803dc690 < '\x04') {
        if (iVar3 == 0) {
          FUN_8000bb38(0,0x100);
          (**(code **)(*DAT_803dd6cc + 8))(0x14,5);
          DAT_803de384 = '#';
          DAT_803de385 = '\x01';
        }
        if (((&DAT_803a9430)[iVar4] != 0) &&
           (iVar3 = (**(code **)(*DAT_803dd724 + 0x2c))(), iVar3 != 0)) {
          if (iVar4 == 0) {
            uVar5 = (**(code **)(*DAT_803dd724 + 0x24))(DAT_803a9430);
            uVar2 = countLeadingZeros(uVar5);
            *(char *)(DAT_803de388 + 2) = (char)(uVar2 >> 5);
            FUN_8001bd8c(extraout_f1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                         (uint)*(byte *)(DAT_803de388 + 2));
          }
          else {
            uVar5 = (**(code **)(*DAT_803dd724 + 0x24))((&DAT_803a9430)[iVar4]);
            uVar2 = countLeadingZeros(uVar5);
            FUN_800e80c4(3,(char)(uVar2 >> 5));
          }
        }
      }
      if (DAT_803dc690 != '\0') {
        iVar3 = 0;
        piVar10 = &DAT_803a9430;
        do {
          iVar6 = *piVar10;
          if (iVar6 != 0) {
            if (iVar3 == iVar4) {
              (**(code **)(*DAT_803dd724 + 0x20))(iVar6,1);
            }
            else {
              (**(code **)(*DAT_803dd724 + 0x20))(iVar6,0);
            }
            (**(code **)(*DAT_803dd724 + 0x14))(*piVar10);
          }
          piVar10 = piVar10 + 1;
          iVar3 = iVar3 + 1;
        } while (iVar3 < 8);
      }
      iVar3 = 0;
    }
    else {
      if (((cVar1 < '\r') || ('\f' < DAT_803de384)) && (DAT_803de384 < '\x01')) {
        if (DAT_803dc690 != -1) {
          (**(code **)(*DAT_803dd720 + 8))();
          DAT_803dc690 = -1;
        }
        iVar3 = 0;
        piVar10 = &DAT_803a9430;
        do {
          if (*piVar10 != 0) {
            (**(code **)(*DAT_803dd724 + 0x10))();
            *piVar10 = 0;
          }
          piVar10 = piVar10 + 1;
          iVar3 = iVar3 + 1;
        } while (iVar3 < 8);
        FUN_8005cf50(1);
        FUN_8005d06c(1);
        FUN_80014974(4);
      }
      iVar3 = (uint)((uint)(int)DAT_803de384 < 0xd) - ((int)DAT_803de384 >> 0x1f);
    }
  }
  else {
    iVar3 = 0;
  }
  return iVar3;
}

