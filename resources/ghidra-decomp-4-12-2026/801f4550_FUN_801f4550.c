// Function: FUN_801f4550
// Entry: 801f4550
// Size: 1284 bytes

void FUN_801f4550(int param_1)

{
  float fVar1;
  float fVar2;
  float fVar3;
  float fVar4;
  float fVar5;
  float fVar6;
  float fVar7;
  float fVar8;
  float fVar9;
  char cVar10;
  byte bVar11;
  double dVar12;
  
  fVar9 = DAT_802c2c64;
  fVar8 = DAT_802c2c60;
  fVar7 = DAT_802c2c5c;
  fVar6 = DAT_802c2c58;
  fVar5 = DAT_802c2c54;
  fVar4 = DAT_802c2c50;
  fVar3 = DAT_802c2c4c;
  fVar2 = DAT_802c2c48;
  fVar1 = DAT_802c2c44;
  cVar10 = (**(code **)(*DAT_803dd72c + 0x40))((int)*(char *)(param_1 + 0xac));
  if (cVar10 != '\a') {
    FUN_8005cf74(0);
    bVar11 = FUN_80089094(0);
    if (bVar11 == 0) {
      FUN_8008947c(1);
      FUN_80089468(0x88,0xb7,0xba);
      if ((*(uint *)(param_1 + 0xf4) & 4) == 0) {
        FUN_8008999c(1,1,0);
        *(uint *)(param_1 + 0xf4) = *(uint *)(param_1 + 0xf4) | 4;
      }
      else {
        FUN_8008999c(1,1,1);
      }
      dVar12 = FUN_8008f014();
      if ((double)FLOAT_803e6b08 < dVar12) {
        FLOAT_803de908 = FLOAT_803e6b0c;
        FLOAT_803de90c = FLOAT_803e6b0c;
      }
      FLOAT_803de90c = -(FLOAT_803e6b10 * FLOAT_803dc074 - FLOAT_803de90c);
      if (FLOAT_803de90c < FLOAT_803e6b08) {
        FLOAT_803de90c = FLOAT_803e6b08;
      }
      DAT_803de91c = (byte)(int)(FLOAT_803de90c *
                                 (float)((double)CONCAT44(0x43300000,
                                                          (uint)DAT_803dcd84 - (uint)DAT_803dcd80 ^
                                                          0x80000000) - DOUBLE_803e6b20) +
                                (float)((double)CONCAT44(0x43300000,DAT_803dcd80 ^ 0x80000000) -
                                       DOUBLE_803e6b20));
      bRam803de91d = (byte)(int)(FLOAT_803de90c *
                                 (float)((double)CONCAT44(0x43300000,
                                                          (uint)bRam803dcd85 - (uint)bRam803dcd81 ^
                                                          0x80000000) - DOUBLE_803e6b20) +
                                (float)((double)CONCAT44(0x43300000,bRam803dcd81 ^ 0x80000000) -
                                       DOUBLE_803e6b20));
      bRam803de91e = (byte)(int)(FLOAT_803de90c *
                                 (float)((double)CONCAT44(0x43300000,
                                                          (uint)bRam803dcd86 - (uint)bRam803dcd82 ^
                                                          0x80000000) - DOUBLE_803e6b20) +
                                (float)((double)CONCAT44(0x43300000,bRam803dcd82 ^ 0x80000000) -
                                       DOUBLE_803e6b20));
      FUN_8008986c(1,DAT_803de91c,bRam803de91d,bRam803de91e,0x40,0x40);
      DAT_803de918 = (undefined)
                     (int)(FLOAT_803de90c *
                           (float)((double)CONCAT44(0x43300000,
                                                    (uint)DAT_803dcd7c - (uint)DAT_803dcd78 ^
                                                    0x80000000) - DOUBLE_803e6b20) +
                          (float)((double)CONCAT44(0x43300000,DAT_803dcd78 ^ 0x80000000) -
                                 DOUBLE_803e6b20));
      uRam803de919 = (undefined)
                     (int)(FLOAT_803de90c *
                           (float)((double)CONCAT44(0x43300000,
                                                    (uint)bRam803dcd7d - (uint)bRam803dcd79 ^
                                                    0x80000000) - DOUBLE_803e6b20) +
                          (float)((double)CONCAT44(0x43300000,bRam803dcd79 ^ 0x80000000) -
                                 DOUBLE_803e6b20));
      uRam803de91a = (undefined)
                     (int)(FLOAT_803de90c *
                           (float)((double)CONCAT44(0x43300000,
                                                    (uint)bRam803dcd7e - (uint)bRam803dcd7a ^
                                                    0x80000000) - DOUBLE_803e6b20) +
                          (float)((double)CONCAT44(0x43300000,bRam803dcd7a ^ 0x80000000) -
                                 DOUBLE_803e6b20));
      FUN_8008979c(1,DAT_803de918,uRam803de919,uRam803de91a);
      DAT_803de914 = (undefined)
                     (int)(FLOAT_803de90c *
                           (float)((double)CONCAT44(0x43300000,
                                                    (uint)DAT_803dcd8c - (uint)DAT_803dcd88 ^
                                                    0x80000000) - DOUBLE_803e6b20) +
                          (float)((double)CONCAT44(0x43300000,DAT_803dcd88 ^ 0x80000000) -
                                 DOUBLE_803e6b20));
      uRam803de915 = (undefined)
                     (int)(FLOAT_803de90c *
                           (float)((double)CONCAT44(0x43300000,
                                                    (uint)bRam803dcd8d - (uint)bRam803dcd89 ^
                                                    0x80000000) - DOUBLE_803e6b20) +
                          (float)((double)CONCAT44(0x43300000,bRam803dcd89 ^ 0x80000000) -
                                 DOUBLE_803e6b20));
      uRam803de916 = (undefined)
                     (int)(FLOAT_803de90c *
                           (float)((double)CONCAT44(0x43300000,
                                                    (uint)bRam803dcd8e - (uint)bRam803dcd8a ^
                                                    0x80000000) - DOUBLE_803e6b20) +
                          (float)((double)CONCAT44(0x43300000,bRam803dcd8a ^ 0x80000000) -
                                 DOUBLE_803e6b20));
      FUN_80089804(1,DAT_803de914,uRam803de915,uRam803de916);
      DAT_803de910 = (undefined)(int)(FLOAT_803de90c * FLOAT_803e6b18 + FLOAT_803e6b14);
      FUN_800894c0(1);
      FUN_80089484((double)(FLOAT_803de90c * (fVar7 - fVar4) + fVar4),
                   (double)(FLOAT_803de90c * (fVar8 - fVar5) + fVar5),
                   (double)(FLOAT_803de90c * (fVar9 - fVar6) + fVar6),(double)FLOAT_803e6b1c);
      FUN_80089734((double)fVar1,(double)fVar2,(double)fVar3,1);
    }
    else {
      FUN_8008947c(0);
      FUN_800894c0(0);
      FUN_8008999c(7,0,1);
    }
  }
  return;
}

