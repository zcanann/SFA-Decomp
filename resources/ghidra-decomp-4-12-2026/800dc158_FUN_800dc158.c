// Function: FUN_800dc158
// Entry: 800dc158
// Size: 292 bytes

undefined2 FUN_800dc158(float *param_1)

{
  uint uVar1;
  byte bVar2;
  undefined2 *puVar3;
  int iVar4;
  
  puVar3 = &DAT_8039d748;
  iVar4 = DAT_803de0e4;
  if (0 < DAT_803de0e4) {
    do {
      if ((param_1[1] <
           (float)((double)CONCAT44(0x43300000,(int)(short)puVar3[0x10] ^ 0x80000000) -
                  DOUBLE_803e1260)) &&
         ((float)((double)CONCAT44(0x43300000,(int)(short)puVar3[0x11] ^ 0x80000000) -
                 DOUBLE_803e1260) < param_1[1])) {
        bVar2 = 0;
        uVar1 = 0;
        while ((bVar2 < 4 &&
               (*(float *)(puVar3 + (uint)bVar2 * 2 + 8) +
                *param_1 *
                (float)((double)CONCAT44(0x43300000,(int)(short)puVar3[uVar1 & 0xff] ^ 0x80000000) -
                       DOUBLE_803e1260) +
                param_1[2] *
                (float)((double)CONCAT44(0x43300000,
                                         (int)(short)puVar3[(uVar1 & 0xff) + 1] ^ 0x80000000) -
                       DOUBLE_803e1260) <= FLOAT_803e1270))) {
          bVar2 = bVar2 + 1;
          uVar1 = uVar1 + 2;
        }
        if (bVar2 == 4) {
          return puVar3[0x12];
        }
      }
      puVar3 = puVar3 + 0x18;
      iVar4 = iVar4 + -1;
    } while (iVar4 != 0);
  }
  return 0;
}

