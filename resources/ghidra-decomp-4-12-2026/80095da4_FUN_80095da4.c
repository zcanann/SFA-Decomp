// Function: FUN_80095da4
// Entry: 80095da4
// Size: 408 bytes

/* WARNING: Removing unreachable block (ram,0x80095f1c) */
/* WARNING: Removing unreachable block (ram,0x80095db4) */

void FUN_80095da4(undefined4 param_1,undefined4 param_2,int param_3)

{
  undefined4 *puVar1;
  int iVar2;
  uint uVar3;
  undefined extraout_r4;
  int iVar4;
  undefined4 *puVar5;
  int iVar6;
  double extraout_f1;
  double dVar7;
  
  puVar1 = (undefined4 *)FUN_80286840();
  if (0x1e < param_3 + DAT_803ddea4) {
    param_3 = 0x1e - DAT_803ddea4;
  }
  if (param_3 != 0) {
    dVar7 = (double)(float)((double)FLOAT_803dffa4 * extraout_f1);
    for (iVar6 = 0; iVar6 < param_3; iVar6 = iVar6 + 1) {
      iVar4 = 0;
      for (iVar2 = DAT_803ddea0; (iVar4 < 0x1e && (*(char *)(iVar2 + 0x18) != -1));
          iVar2 = iVar2 + 0x1c) {
        iVar4 = iVar4 + 1;
      }
      if (iVar4 < 0x1e) {
        puVar5 = (undefined4 *)(DAT_803ddea0 + iVar4 * 0x1c);
        uVar3 = FUN_80022264(0xffffff06,0xfa);
        puVar5[3] = (float)((double)CONCAT44(0x43300000,uVar3 ^ 0x80000000) - DOUBLE_803dff88);
        puVar5[3] = (float)((double)(float)puVar5[3] * dVar7);
        uVar3 = FUN_80022264(0xffffff06,0xfa);
        puVar5[5] = (float)((double)CONCAT44(0x43300000,uVar3 ^ 0x80000000) - DOUBLE_803dff88);
        puVar5[5] = (float)((double)(float)puVar5[5] * dVar7);
        uVar3 = FUN_80022264(200,300);
        puVar5[4] = (float)((double)CONCAT44(0x43300000,uVar3 ^ 0x80000000) - DOUBLE_803dff88);
        puVar5[4] = (float)((double)(float)puVar5[4] * dVar7);
        *(undefined *)(puVar5 + 6) = extraout_r4;
        *puVar5 = *puVar1;
        puVar5[1] = puVar1[1];
        puVar5[2] = puVar1[2];
        DAT_803ddea4 = DAT_803ddea4 + 1;
      }
    }
  }
  FUN_8028688c();
  return;
}

