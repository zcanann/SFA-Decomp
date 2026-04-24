// Function: FUN_8011cf7c
// Entry: 8011cf7c
// Size: 1296 bytes

int FUN_8011cf7c(void)

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
  
  cVar1 = DAT_803dd704;
  bVar9 = DAT_803db410;
  cVar7 = FUN_80134bbc();
  if (cVar7 == '\0') {
    if (3 < bVar9) {
      bVar9 = 3;
    }
    if ('\0' < DAT_803dd704) {
      DAT_803dd704 = DAT_803dd704 - bVar9;
    }
    iVar3 = (**(code **)(*DAT_803dca4c + 0x14))();
    if (iVar3 == 0) {
      (**(code **)(*DAT_803dcaa0 + 0x34))();
      DAT_803dd706 = 2;
    }
    if (DAT_803dd705 == '\0') {
      iVar3 = (**(code **)(*DAT_803dcaa0 + 0xc))();
      iVar4 = (**(code **)(*DAT_803dcaa0 + 0x14))();
      if (iVar4 != DAT_803dd700) {
        FUN_8000bb18(0,0xfc);
      }
      DAT_803dd700 = iVar4;
      if (DAT_803dba28 == '\x02') {
        FUN_8011c318(iVar3,iVar4);
        if (iVar3 == 0) {
          uVar8 = (**(code **)(*DAT_803dcaa4 + 0x24))(DAT_803a87d0);
          *(undefined *)(DAT_803dd708 + 6) = uVar8;
          uVar5 = (**(code **)(*DAT_803dcaa4 + 0x24))(DAT_803a87d4);
          uVar2 = countLeadingZeros(uVar5);
          *(char *)(DAT_803dd708 + 8) = (char)(uVar2 >> 5);
          FUN_8005cd54(*(undefined *)(DAT_803dd708 + 6));
          FUN_800154a4(*(undefined *)(DAT_803dd708 + 8));
        }
      }
      else if (DAT_803dba28 < '\x02') {
        if (DAT_803dba28 == '\0') {
          DAT_803dd70c = (undefined)iVar4;
          iVar3 = FUN_8011c51c(iVar3,iVar4);
          if (iVar3 != 0) {
            return 0;
          }
        }
        else if ((-1 < DAT_803dba28) && (FUN_8011bfc8(iVar3,iVar4), iVar3 == 0)) {
          uVar8 = (**(code **)(*DAT_803dcaa4 + 0x24))(DAT_803a87d0);
          *(undefined *)(DAT_803dd708 + 9) = uVar8;
          uVar8 = (**(code **)(*DAT_803dcaa4 + 0x24))(DAT_803a87d4);
          *(undefined *)(DAT_803dd708 + 10) = uVar8;
          uVar8 = (**(code **)(*DAT_803dcaa4 + 0x24))(DAT_803a87d8);
          *(undefined *)(DAT_803dd708 + 0xb) = uVar8;
          uVar8 = (**(code **)(*DAT_803dcaa4 + 0x24))(DAT_803a87dc);
          *(undefined *)(DAT_803dd708 + 0xc) = uVar8;
        }
      }
      else if (DAT_803dba28 < '\x04') {
        if (iVar3 == 0) {
          FUN_8000bb18(0,0x100);
          (**(code **)(*DAT_803dca4c + 8))(0x14,5);
          DAT_803dd704 = '#';
          DAT_803dd705 = '\x01';
        }
        if (((&DAT_803a87d0)[iVar4] != 0) &&
           (iVar3 = (**(code **)(*DAT_803dcaa4 + 0x2c))(), iVar3 != 0)) {
          if (iVar4 == 0) {
            uVar5 = (**(code **)(*DAT_803dcaa4 + 0x24))(DAT_803a87d0);
            uVar2 = countLeadingZeros(uVar5);
            *(char *)(DAT_803dd708 + 2) = (char)(uVar2 >> 5);
            FUN_8001bcd8(*(undefined *)(DAT_803dd708 + 2));
          }
          else {
            uVar5 = (**(code **)(*DAT_803dcaa4 + 0x24))((&DAT_803a87d0)[iVar4]);
            uVar2 = countLeadingZeros(uVar5);
            FUN_800e7e40(3,uVar2 >> 5 & 0xff);
          }
        }
      }
      if (DAT_803dba28 != '\0') {
        iVar3 = 0;
        piVar10 = &DAT_803a87d0;
        do {
          iVar6 = *piVar10;
          if (iVar6 != 0) {
            if (iVar3 == iVar4) {
              (**(code **)(*DAT_803dcaa4 + 0x20))(iVar6,1);
            }
            else {
              (**(code **)(*DAT_803dcaa4 + 0x20))(iVar6,0);
            }
            (**(code **)(*DAT_803dcaa4 + 0x14))(*piVar10);
          }
          piVar10 = piVar10 + 1;
          iVar3 = iVar3 + 1;
        } while (iVar3 < 8);
      }
      iVar3 = 0;
    }
    else {
      if (((cVar1 < '\r') || ('\f' < DAT_803dd704)) && (DAT_803dd704 < '\x01')) {
        if (DAT_803dba28 != -1) {
          (**(code **)(*DAT_803dcaa0 + 8))();
          DAT_803dba28 = -1;
        }
        iVar3 = 0;
        piVar10 = &DAT_803a87d0;
        do {
          if (*piVar10 != 0) {
            (**(code **)(*DAT_803dcaa4 + 0x10))();
            *piVar10 = 0;
          }
          piVar10 = piVar10 + 1;
          iVar3 = iVar3 + 1;
        } while (iVar3 < 8);
        FUN_8005cdd4(1);
        FUN_8005cef0(1);
        FUN_80014948(4);
      }
      iVar3 = (uint)((uint)(int)DAT_803dd704 < 0xd) - ((int)DAT_803dd704 >> 0x1f);
    }
  }
  else {
    iVar3 = 0;
  }
  return iVar3;
}

