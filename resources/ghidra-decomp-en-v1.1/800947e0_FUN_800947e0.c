// Function: FUN_800947e0
// Entry: 800947e0
// Size: 1612 bytes

/* WARNING: Removing unreachable block (ram,0x80094e0c) */
/* WARNING: Removing unreachable block (ram,0x800947f0) */

void FUN_800947e0(undefined4 param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4)

{
  undefined4 uVar1;
  float fVar2;
  undefined4 uVar3;
  undefined2 *puVar4;
  int iVar5;
  uint uVar6;
  int *piVar7;
  float *pfVar8;
  undefined4 uVar9;
  double dVar10;
  double in_f31;
  double in_ps31_1;
  undefined8 uVar11;
  undefined uStack_98;
  undefined uStack_97;
  undefined uStack_96;
  undefined local_95;
  undefined local_94;
  undefined local_93 [3];
  int local_90;
  int local_8c;
  int local_88;
  int local_84;
  int local_80;
  int local_7c;
  int local_78;
  int local_74;
  float local_70;
  float local_6c;
  float local_68;
  float afStack_64 [13];
  undefined8 local_30;
  float local_8;
  float fStack_4;
  
  local_8 = (float)in_f31;
  fStack_4 = (float)in_ps31_1;
  uVar11 = FUN_8028683c();
  uVar3 = (undefined4)((ulonglong)uVar11 >> 0x20);
  uVar9 = (undefined4)uVar11;
  puVar4 = FUN_8000facc();
  (**(code **)(*DAT_803dd6d8 + 0x40))(local_93,&local_94,&local_95,&uStack_96,&uStack_97,&uStack_98)
  ;
  if (DAT_803dde70 == 0) {
    uVar6 = FUN_8005cf44();
    if (uVar6 != 0) {
      if (DAT_8039b78c != 0) {
        iVar5 = FUN_8002b660(DAT_8039b78c);
        *(ushort *)(iVar5 + 0x18) = *(ushort *)(iVar5 + 0x18) & 0xfff7;
        *(undefined *)(DAT_8039b78c + 0x37) = 0xff;
        if (DAT_803dde6c == '\0') {
          FUN_8008dd74(DAT_8039b78c);
          *(undefined4 *)(DAT_8039b78c + 0xc) = *(undefined4 *)(puVar4 + 6);
          *(undefined4 *)(DAT_8039b78c + 0x10) = *(undefined4 *)(puVar4 + 8);
          *(undefined4 *)(DAT_8039b78c + 0x14) = *(undefined4 *)(puVar4 + 10);
        }
        else {
          *(float *)(DAT_8039b78c + 0xc) = FLOAT_803dde68;
          *(float *)(DAT_8039b78c + 0x10) = FLOAT_803dff40 + FLOAT_803dde64;
          *(float *)(DAT_8039b78c + 0x14) = FLOAT_803dde60;
        }
        FUN_800413b0(local_93[0],local_94,local_95);
        FUN_8003ba50(uVar3,uVar9,param_3,param_4,DAT_8039b78c,1);
      }
      if (DAT_8039b788 != 0) {
        uVar6 = FUN_8005d00c();
        if ((uVar6 & 0xff) != 0) {
          FUN_8008dd74(DAT_8039b788);
        }
        piVar7 = (int *)FUN_8002b660(DAT_8039b788);
        *(ushort *)(piVar7 + 6) = *(ushort *)(piVar7 + 6) & 0xfff7;
        *(undefined *)(DAT_8039b788 + 0x37) = 0xff;
        uVar1 = *(undefined4 *)(puVar4 + 6);
        *(undefined4 *)(DAT_8039b788 + 0x18) = uVar1;
        *(undefined4 *)(DAT_8039b788 + 0xc) = uVar1;
        fVar2 = FLOAT_803dff44 + *(float *)(puVar4 + 8);
        *(float *)(DAT_8039b788 + 0x1c) = fVar2;
        *(float *)(DAT_8039b788 + 0x10) = fVar2;
        uVar1 = *(undefined4 *)(puVar4 + 10);
        *(undefined4 *)(DAT_8039b788 + 0x20) = uVar1;
        *(undefined4 *)(DAT_8039b788 + 0x14) = uVar1;
        *(undefined2 *)(DAT_8039b788 + 2) = 0;
        FUN_800413b0(local_93[0],local_94,local_95);
        FUN_8003ba50(uVar3,uVar9,param_3,param_4,DAT_8039b788,1);
        FUN_8006060c(&local_74,&local_78,&local_7c,&local_80);
        if ((0 < local_7c) && (0 < local_80)) {
          FUN_8025db38(&local_84,&local_88,&local_8c,&local_90);
          FUN_8025da88(local_74,local_78,local_7c,local_80);
          *(ushort *)(*piVar7 + 2) = *(ushort *)(*piVar7 + 2) | 0x2000;
          FUN_8003bc74(0x80);
          FUN_8025cdec(0);
          FUN_8003ba50(uVar3,uVar9,param_3,param_4,DAT_8039b788,1);
          *(ushort *)(*piVar7 + 2) = *(ushort *)(*piVar7 + 2) & 0xdfff;
          FUN_8003bc74(0);
          FUN_8025cdec(1);
          FUN_8025da88(local_84,local_88,local_8c,local_90);
        }
      }
      dVar10 = FUN_8008f014();
      if ((double)FLOAT_803dff34 < dVar10) {
        FUN_8008f074(&local_70);
        local_70 = local_70 - FLOAT_803dda58;
        local_68 = local_68 - FLOAT_803dda5c;
        pfVar8 = (float *)FUN_8000f56c();
        FUN_80259288(0);
        FUN_8000fb20();
        FUN_80257b5c();
        FUN_802570dc(9,1);
        FUN_802570dc(0xd,1);
        FUN_80079b3c();
        FUN_8007965c();
        FUN_80079980();
        FUN_80078b28();
        FUN_80247bf8(pfVar8,&local_70,&local_70);
        FUN_80247a48((double)local_70,(double)local_6c,(double)local_68,afStack_64);
        FUN_8025d80c(afStack_64,0);
        FUN_8025d888(0);
        iVar5 = FUN_800893b8();
        FUN_8004c460(iVar5,0);
        if (dVar10 < (double)FLOAT_803dff48) {
          iVar5 = (int)(FLOAT_803dff4c * (float)((double)FLOAT_803dff50 * dVar10));
          local_30 = (double)(longlong)iVar5;
          FUN_80079b60(0x80,0x80,0xff,(char)iVar5);
        }
        else {
          FUN_80079b60(0x80,0x80,0xff,0xff);
        }
        iVar5 = FUN_80020800();
        if (iVar5 == 0) {
          uVar6 = FUN_80022264(8000,12000);
          local_30 = (double)CONCAT44(0x43300000,uVar6 ^ 0x80000000);
          FLOAT_803dc3e0 = (float)(local_30 - DOUBLE_803dff38);
        }
        FUN_80259000(0x80,2,4);
        DAT_cc008000 = -FLOAT_803dc3e0;
        DAT_cc008000 = -FLOAT_803dc3e0;
        DAT_cc008000 = FLOAT_803dff34;
        DAT_cc008000 = FLOAT_803dff34;
        DAT_cc008000 = FLOAT_803dff34;
        DAT_cc008000 = FLOAT_803dc3e0;
        DAT_cc008000 = -FLOAT_803dc3e0;
        DAT_cc008000 = FLOAT_803dff34;
        DAT_cc008000 = FLOAT_803dff54;
        DAT_cc008000 = FLOAT_803dff34;
        DAT_cc008000 = FLOAT_803dc3e0;
        DAT_cc008000 = FLOAT_803dc3e0;
        DAT_cc008000 = FLOAT_803dff34;
        DAT_cc008000 = FLOAT_803dff54;
        DAT_cc008000 = FLOAT_803dff54;
        DAT_cc008000 = -FLOAT_803dc3e0;
        DAT_cc008000 = FLOAT_803dc3e0;
        DAT_cc008000 = FLOAT_803dff34;
        DAT_cc008000 = FLOAT_803dff34;
        DAT_cc008000 = FLOAT_803dff54;
      }
      if (DAT_8039b790 != 0) {
        iVar5 = FUN_8002b660(DAT_8039b790);
        *(ushort *)(iVar5 + 0x18) = *(ushort *)(iVar5 + 0x18) & 0xfff7;
        *(undefined *)(DAT_8039b790 + 0x37) = 0xff;
        if (DAT_803dde6c == '\0') {
          FUN_8008dd74(DAT_8039b790);
          *(undefined4 *)(DAT_8039b790 + 0xc) = *(undefined4 *)(puVar4 + 6);
          *(undefined4 *)(DAT_8039b790 + 0x10) = *(undefined4 *)(puVar4 + 8);
          *(undefined4 *)(DAT_8039b790 + 0x14) = *(undefined4 *)(puVar4 + 10);
        }
        else {
          *(float *)(DAT_8039b790 + 0xc) = FLOAT_803dde68;
          *(float *)(DAT_8039b790 + 0x10) = FLOAT_803dde64 - FLOAT_803dff58;
          *(float *)(DAT_8039b790 + 0x14) = FLOAT_803dde60;
        }
        FUN_8003ba50(uVar3,uVar9,param_3,param_4,DAT_8039b790,1);
      }
    }
  }
  else {
    FUN_8008dd74(DAT_803dde70);
    iVar5 = FUN_8002b660(DAT_803dde70);
    *(ushort *)(iVar5 + 0x18) = *(ushort *)(iVar5 + 0x18) & 0xfff7;
    *(undefined *)(DAT_803dde70 + 0x37) = 0xff;
    uVar1 = *(undefined4 *)(puVar4 + 6);
    *(undefined4 *)(DAT_803dde70 + 0x18) = uVar1;
    *(undefined4 *)(DAT_803dde70 + 0xc) = uVar1;
    uVar1 = *(undefined4 *)(puVar4 + 8);
    *(undefined4 *)(DAT_803dde70 + 0x1c) = uVar1;
    *(undefined4 *)(DAT_803dde70 + 0x10) = uVar1;
    uVar1 = *(undefined4 *)(puVar4 + 10);
    *(undefined4 *)(DAT_803dde70 + 0x20) = uVar1;
    *(undefined4 *)(DAT_803dde70 + 0x14) = uVar1;
    FUN_800413b0(local_93[0],local_94,local_95);
    FUN_8003ba50(uVar3,uVar9,param_3,param_4,DAT_803dde70,1);
  }
  FUN_80286888();
  return;
}

