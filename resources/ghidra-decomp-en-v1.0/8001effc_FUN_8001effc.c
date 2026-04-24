// Function: FUN_8001effc
// Entry: 8001effc
// Size: 904 bytes

void FUN_8001effc(void)

{
  int iVar1;
  double dVar2;
  undefined4 uVar3;
  undefined4 uVar4;
  int iVar5;
  int *piVar6;
  int **ppiVar7;
  float local_e8;
  int local_e4;
  float local_e0;
  undefined auStack220 [68];
  undefined4 local_98;
  uint uStack148;
  longlong local_90;
  undefined4 local_88;
  uint uStack132;
  longlong local_80;
  undefined4 local_78;
  uint uStack116;
  longlong local_70;
  undefined4 local_68;
  uint uStack100;
  longlong local_60;
  undefined4 local_58;
  uint uStack84;
  longlong local_50;
  undefined4 local_48;
  uint uStack68;
  longlong local_40;
  undefined4 local_38;
  uint uStack52;
  longlong local_30;
  undefined4 local_28;
  uint uStack36;
  longlong local_20;
  
  uVar3 = FUN_8000f54c();
  ppiVar7 = (int **)&DAT_8033bec0;
  for (iVar5 = 0; iVar5 < (int)(uint)DAT_803dca30; iVar5 = iVar5 + 1) {
    piVar6 = *ppiVar7;
    if (piVar6[0x16] == 1) {
      piVar6[0x4e] = (int)((float)piVar6[0x4e] + (float)piVar6[0x4f]);
      if (FLOAT_803de760 <= (float)piVar6[0x4e]) {
        piVar6[0x4e] = (int)FLOAT_803de760;
        piVar6[0x16] = 2;
      }
    }
    else if (piVar6[0x16] == 3) {
      piVar6[0x4e] = (int)((float)piVar6[0x4e] + (float)piVar6[0x4f]);
      if ((float)piVar6[0x4e] <= FLOAT_803de788) {
        piVar6[0x4e] = (int)FLOAT_803de788;
        piVar6[0x16] = 0;
        *(undefined *)(piVar6 + 0x13) = 0;
      }
    }
    if (*(char *)(piVar6 + 0x13) != '\0') {
      if (piVar6[0x14] != 4) {
        if (*piVar6 != 0) {
          FUN_8002b1e8(*piVar6,piVar6 + 1,piVar6 + 4,1);
        }
        if (piVar6[0x18] == 0) {
          local_e8 = (float)piVar6[4] - FLOAT_803dcdd8;
          local_e4 = piVar6[5];
          local_e0 = (float)piVar6[6] - FLOAT_803dcddc;
          FUN_80247494(uVar3,&local_e8,piVar6 + 7);
        }
        else {
          piVar6[7] = piVar6[4];
          piVar6[8] = piVar6[5];
          piVar6[9] = piVar6[6];
        }
      }
      if (*piVar6 != 0) {
        FUN_8002b198(*piVar6,piVar6 + 10,piVar6 + 0xd);
      }
      if (piVar6[0x18] == 0) {
        FUN_80247574(uVar3,piVar6 + 0xd,piVar6 + 0x10);
      }
      else {
        piVar6[0x10] = piVar6[0xd];
        piVar6[0x11] = piVar6[0xe];
        piVar6[0x12] = piVar6[0xf];
      }
      dVar2 = DOUBLE_803de770;
      if (piVar6[0xb6] == 0) {
        uStack148 = (uint)*(byte *)(piVar6 + 0x2b);
        local_98 = 0x43300000;
        iVar1 = (int)((float)((double)CONCAT44(0x43300000,uStack148) - DOUBLE_803de770) *
                     (float)piVar6[0x4e]);
        local_90 = (longlong)iVar1;
        *(char *)(piVar6 + 0x2a) = (char)iVar1;
        uStack132 = (uint)*(byte *)((int)piVar6 + 0xad);
        local_88 = 0x43300000;
        iVar1 = (int)((float)((double)CONCAT44(0x43300000,uStack132) - dVar2) * (float)piVar6[0x4e])
        ;
        local_80 = (longlong)iVar1;
        *(char *)((int)piVar6 + 0xa9) = (char)iVar1;
        uStack116 = (uint)*(byte *)((int)piVar6 + 0xae);
        local_78 = 0x43300000;
        iVar1 = (int)((float)((double)CONCAT44(0x43300000,uStack116) - dVar2) * (float)piVar6[0x4e])
        ;
        local_70 = (longlong)iVar1;
        *(char *)((int)piVar6 + 0xaa) = (char)iVar1;
        uStack100 = (uint)*(byte *)((int)piVar6 + 0xaf);
        local_68 = 0x43300000;
        iVar1 = (int)((float)((double)CONCAT44(0x43300000,uStack100) - dVar2) * (float)piVar6[0x4e])
        ;
        local_60 = (longlong)iVar1;
        *(char *)((int)piVar6 + 0xab) = (char)iVar1;
        uStack84 = (uint)*(byte *)(piVar6 + 0x41);
        local_58 = 0x43300000;
        iVar1 = (int)((float)((double)CONCAT44(0x43300000,uStack84) - dVar2) * (float)piVar6[0x4e]);
        local_50 = (longlong)iVar1;
        *(char *)(piVar6 + 0x40) = (char)iVar1;
        uStack68 = (uint)*(byte *)((int)piVar6 + 0x105);
        local_48 = 0x43300000;
        iVar1 = (int)((float)((double)CONCAT44(0x43300000,uStack68) - dVar2) * (float)piVar6[0x4e]);
        local_40 = (longlong)iVar1;
        *(char *)((int)piVar6 + 0x101) = (char)iVar1;
        uStack52 = (uint)*(byte *)((int)piVar6 + 0x106);
        local_38 = 0x43300000;
        iVar1 = (int)((float)((double)CONCAT44(0x43300000,uStack52) - dVar2) * (float)piVar6[0x4e]);
        local_30 = (longlong)iVar1;
        *(char *)((int)piVar6 + 0x102) = (char)iVar1;
        uStack36 = (uint)*(byte *)((int)piVar6 + 0x107);
        local_28 = 0x43300000;
        iVar1 = (int)((float)((double)CONCAT44(0x43300000,uStack36) - dVar2) * (float)piVar6[0x4e]);
        local_20 = (longlong)iVar1;
        *(char *)((int)piVar6 + 0x103) = (char)iVar1;
      }
      else {
        FUN_8001d168(piVar6);
      }
      if (piVar6[0x14] == 8) {
        FUN_8002b37c(*piVar6,piVar6 + 0x5c);
        uVar4 = FUN_8000f558();
        FUN_80246eb4(piVar6 + 0x5c,uVar4,auStack220);
        FUN_80246eb4(piVar6 + 0x6c,auStack220,piVar6 + 0x8c);
      }
    }
    ppiVar7 = ppiVar7 + 1;
  }
  return;
}

