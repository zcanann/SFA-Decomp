// Function: FUN_801f3f18
// Entry: 801f3f18
// Size: 1284 bytes

void FUN_801f3f18(int param_1)

{
  uint uVar1;
  uint uVar2;
  uint uVar3;
  float fVar4;
  float fVar5;
  float fVar6;
  float fVar7;
  float fVar8;
  float fVar9;
  float fVar10;
  float fVar11;
  float fVar12;
  char cVar13;
  double dVar14;
  
  fVar12 = DAT_802c24e4;
  fVar11 = DAT_802c24e0;
  fVar10 = DAT_802c24dc;
  fVar9 = DAT_802c24d8;
  fVar8 = DAT_802c24d4;
  fVar7 = DAT_802c24d0;
  fVar6 = DAT_802c24cc;
  fVar5 = DAT_802c24c8;
  fVar4 = DAT_802c24c4;
  cVar13 = (**(code **)(*DAT_803dcaac + 0x40))((int)*(char *)(param_1 + 0xac));
  if (cVar13 != '\a') {
    FUN_8005cdf8(0);
    cVar13 = FUN_80088e08(0);
    if (cVar13 == '\0') {
      FUN_800891f0(1);
      FUN_800891dc(0x88,0xb7,0xba);
      if ((*(uint *)(param_1 + 0xf4) & 4) == 0) {
        FUN_80089710(1,1,0);
        *(uint *)(param_1 + 0xf4) = *(uint *)(param_1 + 0xf4) | 4;
      }
      else {
        FUN_80089710(1,1,1);
      }
      dVar14 = (double)FUN_8008ed88();
      if ((double)FLOAT_803e5e70 < dVar14) {
        FLOAT_803ddc88 = FLOAT_803e5e74;
        FLOAT_803ddc8c = FLOAT_803e5e74;
      }
      FLOAT_803ddc8c = -(FLOAT_803e5e78 * FLOAT_803db414 - FLOAT_803ddc8c);
      if (FLOAT_803ddc8c < FLOAT_803e5e70) {
        FLOAT_803ddc8c = FLOAT_803e5e70;
      }
      uVar1 = (uint)(FLOAT_803ddc8c *
                     (float)((double)CONCAT44(0x43300000,
                                              (uint)DAT_803dc11c - (uint)DAT_803dc118 ^ 0x80000000)
                            - DOUBLE_803e5e88) +
                    (float)((double)CONCAT44(0x43300000,DAT_803dc118 ^ 0x80000000) - DOUBLE_803e5e88
                           ));
      DAT_803ddc9c = (undefined)uVar1;
      uVar2 = (uint)(FLOAT_803ddc8c *
                     (float)((double)CONCAT44(0x43300000,
                                              (uint)bRam803dc11d - (uint)bRam803dc119 ^ 0x80000000)
                            - DOUBLE_803e5e88) +
                    (float)((double)CONCAT44(0x43300000,bRam803dc119 ^ 0x80000000) - DOUBLE_803e5e88
                           ));
      uRam803ddc9d = (undefined)uVar2;
      uVar3 = (uint)(FLOAT_803ddc8c *
                     (float)((double)CONCAT44(0x43300000,
                                              (uint)bRam803dc11e - (uint)bRam803dc11a ^ 0x80000000)
                            - DOUBLE_803e5e88) +
                    (float)((double)CONCAT44(0x43300000,bRam803dc11a ^ 0x80000000) - DOUBLE_803e5e88
                           ));
      uRam803ddc9e = (undefined)uVar3;
      FUN_800895e0(1,uVar1 & 0xff,uVar2 & 0xff,uVar3 & 0xff,0x40,0x40);
      uVar1 = (uint)(FLOAT_803ddc8c *
                     (float)((double)CONCAT44(0x43300000,
                                              (uint)DAT_803dc114 - (uint)DAT_803dc110 ^ 0x80000000)
                            - DOUBLE_803e5e88) +
                    (float)((double)CONCAT44(0x43300000,DAT_803dc110 ^ 0x80000000) - DOUBLE_803e5e88
                           ));
      DAT_803ddc98 = (undefined)uVar1;
      uVar2 = (uint)(FLOAT_803ddc8c *
                     (float)((double)CONCAT44(0x43300000,
                                              (uint)bRam803dc115 - (uint)bRam803dc111 ^ 0x80000000)
                            - DOUBLE_803e5e88) +
                    (float)((double)CONCAT44(0x43300000,bRam803dc111 ^ 0x80000000) - DOUBLE_803e5e88
                           ));
      uRam803ddc99 = (undefined)uVar2;
      uVar3 = (uint)(FLOAT_803ddc8c *
                     (float)((double)CONCAT44(0x43300000,
                                              (uint)bRam803dc116 - (uint)bRam803dc112 ^ 0x80000000)
                            - DOUBLE_803e5e88) +
                    (float)((double)CONCAT44(0x43300000,bRam803dc112 ^ 0x80000000) - DOUBLE_803e5e88
                           ));
      uRam803ddc9a = (undefined)uVar3;
      FUN_80089510(1,uVar1 & 0xff,uVar2 & 0xff,uVar3 & 0xff);
      uVar1 = (uint)(FLOAT_803ddc8c *
                     (float)((double)CONCAT44(0x43300000,
                                              (uint)DAT_803dc124 - (uint)DAT_803dc120 ^ 0x80000000)
                            - DOUBLE_803e5e88) +
                    (float)((double)CONCAT44(0x43300000,DAT_803dc120 ^ 0x80000000) - DOUBLE_803e5e88
                           ));
      DAT_803ddc94 = (undefined)uVar1;
      uVar2 = (uint)(FLOAT_803ddc8c *
                     (float)((double)CONCAT44(0x43300000,
                                              (uint)bRam803dc125 - (uint)bRam803dc121 ^ 0x80000000)
                            - DOUBLE_803e5e88) +
                    (float)((double)CONCAT44(0x43300000,bRam803dc121 ^ 0x80000000) - DOUBLE_803e5e88
                           ));
      uRam803ddc95 = (undefined)uVar2;
      uVar3 = (uint)(FLOAT_803ddc8c *
                     (float)((double)CONCAT44(0x43300000,
                                              (uint)bRam803dc126 - (uint)bRam803dc122 ^ 0x80000000)
                            - DOUBLE_803e5e88) +
                    (float)((double)CONCAT44(0x43300000,bRam803dc122 ^ 0x80000000) - DOUBLE_803e5e88
                           ));
      uRam803ddc96 = (undefined)uVar3;
      FUN_80089578(1,uVar1 & 0xff,uVar2 & 0xff,uVar3 & 0xff);
      DAT_803ddc90 = (undefined)(int)(FLOAT_803ddc8c * FLOAT_803e5e80 + FLOAT_803e5e7c);
      FUN_80089234(1);
      FUN_800891f8((double)(FLOAT_803ddc8c * (fVar10 - fVar7) + fVar7),
                   (double)(FLOAT_803ddc8c * (fVar11 - fVar8) + fVar8),
                   (double)(FLOAT_803ddc8c * (fVar12 - fVar9) + fVar9),(double)FLOAT_803e5e84);
      FUN_800894a8((double)fVar4,(double)fVar5,(double)fVar6,1);
    }
    else {
      FUN_800891f0(0);
      FUN_80089234(0);
      FUN_80089710(7,0,1);
    }
  }
  return;
}

