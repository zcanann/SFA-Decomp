// Function: FUN_8012b77c
// Entry: 8012b77c
// Size: 508 bytes

void FUN_8012b77c(void)

{
  uint uVar1;
  int iVar2;
  byte bVar3;
  double dVar4;
  double dVar5;
  
  uVar1 = FUN_80014e70(0);
  dVar4 = (double)(float)((double)FLOAT_803dd764 * (double)FLOAT_803db414 + (double)FLOAT_803dd760);
  dVar5 = DOUBLE_803e2160;
  if (DOUBLE_803e2160 < dVar4) {
    dVar5 = dVar4;
  }
  dVar4 = DOUBLE_803e1f60;
  if ((double)(float)dVar5 < DOUBLE_803e1f60) {
    dVar4 = (double)(float)dVar5;
  }
  FLOAT_803dd760 = (float)dVar4;
  if ((((0xb < DAT_803dd780) || (DAT_803dd780 < 8)) && ((uVar1 & 0x200) != 0)) &&
     (DOUBLE_803e2160 < (double)FLOAT_803dd764)) {
    FUN_80014b3c(0,0x200);
    FLOAT_803dd764 = FLOAT_803e2168;
    if (DAT_803dd824 == &DAT_8031bd30) {
      DAT_803dd7d8 = 1;
    }
    DAT_803dd81c = 0;
    if (DAT_803dd780 == 4) {
      iVar2 = FUN_800221a0(0,1);
      FUN_8000d200(iVar2 + 0x2727,FUN_8000d138);
      DAT_803dd781 = '\x03';
    }
    else if (DAT_803dd780 < 4) {
      if (2 < DAT_803dd780) {
        iVar2 = FUN_800221a0(0,1);
        FUN_8000d200(iVar2 + 0x271b,FUN_8000d138);
        DAT_803dd781 = '\x02';
      }
    }
    else if (DAT_803dd780 < 6) {
      iVar2 = FUN_800221a0(0,1);
      FUN_8000d200(iVar2 + 0x2739,FUN_8000d138);
      DAT_803dd781 = '\x01';
    }
    for (bVar3 = 1; bVar3 < 4; bVar3 = bVar3 + 1) {
      uVar1 = countLeadingZeros((int)DAT_803dd781 - (uint)bVar3);
      FUN_80030334((double)FLOAT_803e1e3c,(&DAT_803a9410)[bVar3],uVar1 >> 5,0);
    }
  }
  DAT_803dd784 = DAT_803dd784 + (ushort)DAT_803db410 * -0x50;
  if (DAT_803dd784 < 0) {
    DAT_803dd784 = 0;
  }
  FUN_8012c000();
  return;
}

