// Function: FUN_8011acf8
// Entry: 8011acf8
// Size: 1024 bytes

void FUN_8011acf8(undefined8 param_1,undefined8 param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)

{
  uint uVar1;
  uint uVar2;
  undefined4 uVar3;
  int iVar4;
  int iVar5;
  undefined4 uVar6;
  undefined4 in_r6;
  byte bVar7;
  undefined4 in_r7;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  int iVar8;
  byte *pbVar9;
  int *piVar10;
  int iVar11;
  ushort *puVar12;
  int iVar13;
  uint uVar14;
  double dVar15;
  undefined8 uVar16;
  double dVar17;
  undefined8 local_38;
  
  uVar3 = FUN_80286830();
  iVar5 = DAT_803dc65b * 0xc;
  FUN_8001b4f8(FUN_80135e18);
  dVar15 = (double)(**(code **)(*DAT_803dd6cc + 0x18))();
  uVar1 = (uint)((double)FLOAT_803e29e4 - dVar15);
  if ((uVar1 & 0xff) < 0x80) {
    local_38 = (double)CONCAT44(0x43300000,(uVar1 & 0xff) * 0x86 ^ 0x80000000);
    param_3 = (double)(float)(local_38 - DOUBLE_803e29f8);
    dVar15 = -(double)(float)(param_3 * (double)FLOAT_803e29f0 - (double)FLOAT_803e29ec);
    FUN_80135ba8((double)FLOAT_803e29e8,dVar15);
    uVar14 = 0;
  }
  else {
    dVar15 = (double)FLOAT_803e29f4;
    FUN_80135ba8((double)FLOAT_803e29e8,dVar15);
    uVar14 = (uVar1 & 0x7f) << 1;
  }
  uVar2 = countLeadingZeros(3 - DAT_803dc65b);
  uVar6 = 0;
  uVar16 = FUN_801350c8(uVar14,uVar2 >> 5 & 0xff,0);
  bVar7 = (byte)uVar14;
  if (DAT_803dc65b != '\x02') {
    if (DAT_803dc65b < '\x02') {
      if (DAT_803dc65b == '\0') {
        uVar2 = uVar14;
        FUN_80019940(0xff,0xff,0xff,bVar7);
        uVar16 = (**(code **)(*DAT_803dd720 + 0x14))();
        if (DAT_803dc084 != '\0') {
          DAT_803de330 = DAT_803de328;
          iVar4 = 0;
          iVar13 = 0;
          piVar10 = &DAT_803a92b8;
          puVar12 = (ushort *)&DAT_803dc650;
          do {
            FUN_8028fde8(uVar16,dVar15,param_3,param_4,param_5,param_6,param_7,param_8,*piVar10,
                         &DAT_803dc688,(uint)*(byte *)(DAT_803de330 + iVar13 + 4),uVar2,in_r7,in_r8,
                         in_r9,in_r10);
            uVar2 = uVar14;
            FUN_80019940(0xff,0xff,0xff,bVar7);
            uVar16 = FUN_800161c4((byte *)*piVar10,(uint)*puVar12);
            iVar13 = iVar13 + 0x24;
            piVar10 = piVar10 + 1;
            puVar12 = puVar12 + 1;
            iVar4 = iVar4 + 1;
          } while (iVar4 < 3);
        }
      }
      else if (-1 < DAT_803dc65b) {
        FUN_8011a07c(uVar16,dVar15,param_3,param_4,param_5,param_6,param_7,param_8,uVar3,uVar14,
                     uVar6,in_r6,in_r7,in_r8,in_r9,in_r10);
        FUN_80019940(0xff,0xff,0xff,bVar7);
        iVar13 = 0;
        for (iVar4 = DAT_803de330 + DAT_803de324 * 0x24;
            (iVar13 < 3 && (*(int *)(iVar4 + 0xc) != 0)); iVar4 = iVar4 + 4) {
          iVar13 = iVar13 + 1;
        }
        iVar11 = 0x34;
        pbVar9 = &DAT_803dc658 + (3U - iVar13 & 0xff);
        iVar8 = 0;
        for (iVar4 = 0; iVar4 < iVar13; iVar4 = iVar4 + 1) {
          FUN_80019940(0xff,0xff,0xff,bVar7);
          FUN_80015e00(&DAT_803dc684,0x93,0x41,iVar11);
          FUN_800161c4(*(byte **)(DAT_803de330 + DAT_803de324 * 0x24 + iVar8 + 0xc),(uint)*pbVar9);
          iVar11 = iVar11 + 0x2a;
          pbVar9 = pbVar9 + 1;
          iVar8 = iVar8 + 4;
        }
        if (DAT_803de338 != 0) {
          (**(code **)(*DAT_803dd724 + 0x18))(DAT_803de338,0,uVar14);
        }
      }
    }
    else if (DAT_803dc65b < '\x04') {
      uVar16 = FUN_80019940(0xff,0xff,0xff,bVar7);
      FUN_800168a8(uVar16,dVar15,param_3,param_4,param_5,param_6,param_7,param_8,0x324);
    }
  }
  FUN_80019940(0xff,0xff,0xff,bVar7);
  if (*(short *)(&DAT_8031b412 + iVar5) != -1) {
    if (uVar14 < 0x7f) {
      uVar16 = FUN_80019940(0xff,0xff,0xff,-(char)(uVar14 << 1) - 1);
      FUN_800168a8(uVar16,dVar15,param_3,param_4,param_5,param_6,param_7,param_8,0x331);
    }
    else {
      uVar16 = FUN_80019940(0xff,0xff,0xff,(bVar7 + 0x81) * '\x02');
      FUN_800168a8(uVar16,dVar15,param_3,param_4,param_5,param_6,param_7,param_8,
                   (uint)*(ushort *)(&DAT_8031b412 + iVar5));
    }
  }
  if (*(short *)(&DAT_8031b414 + iVar5) != -1) {
    uVar16 = FUN_80019940(0xff,0xff,0xff,bVar7);
    FUN_800168a8(uVar16,dVar15,param_3,param_4,param_5,param_6,param_7,param_8,
                 (uint)*(ushort *)(&DAT_8031b414 + iVar5));
  }
  (**(code **)(*DAT_803dd720 + 0x30))(uVar1);
  (**(code **)(*DAT_803dd720 + 0x10))(uVar3);
  dVar17 = (double)FUN_8001b4f8(0);
  FUN_80134fb0(dVar17,dVar15,param_3,param_4,param_5,param_6,param_7,param_8,'\0');
  DAT_803de34e = DAT_803de34e + -1;
  if (DAT_803de34e < '\0') {
    DAT_803de34e = '\0';
  }
  FUN_8028687c();
  return;
}

