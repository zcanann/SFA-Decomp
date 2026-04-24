// Function: FUN_800573d4
// Entry: 800573d4
// Size: 408 bytes

/* WARNING: Removing unreachable block (ram,0x8005754c) */
/* WARNING: Removing unreachable block (ram,0x800573e4) */

void FUN_800573d4(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,int *param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)

{
  uint uVar1;
  int iVar2;
  int iVar3;
  int unaff_r28;
  double dVar4;
  double dVar5;
  undefined8 uVar6;
  
  uVar6 = FUN_80286840();
  iVar2 = (int)((ulonglong)uVar6 >> 0x20);
  iVar3 = 0;
  if ((((DAT_803dc284 != iVar2) && (iVar3 = 1, cRam803dc285 != iVar2)) &&
      (iVar3 = 2, cRam803dc286 != iVar2)) &&
     ((iVar3 = 3, cRam803dc287 != iVar2 && (iVar3 = 4, cRam803dc288 != iVar2)))) {
    iVar3 = 5;
  }
  DAT_803dda61 = 0;
  dVar4 = (double)FUN_802925a0();
  dVar5 = (double)FUN_802925a0();
  iVar3 = FUN_80059c3c((int)dVar5,(int)dVar4,iVar3);
  uVar1 = FUN_8004908c(0x1f);
  iVar2 = DAT_803ddaf8;
  if ((iVar3 < 0) || ((int)(uVar1 >> 5) <= iVar3)) {
    DAT_803ddb24 = '\0';
    iVar2 = unaff_r28;
  }
  else {
    FUN_8001f7e0(dVar5,param_2,param_3,param_4,param_5,param_6,param_7,param_8,DAT_803ddaf8,0x1f,
                 iVar3 << 5,0x20,param_13,param_14,param_15,param_16);
    DAT_803ddb24 = *(char *)(iVar2 + 0x1c);
  }
  DAT_803ddb34 = 0;
  if (DAT_803ddb24 == '\x01') {
    DAT_803ddb36 = (undefined2)iVar3;
    DAT_803ddb34 = *(undefined2 *)(iVar2 + 0x1e);
  }
  *(int *)uVar6 = iVar3;
  if (iVar3 != -1) {
    iVar2 = (**(code **)(*DAT_803dd72c + 0x90))();
    *param_11 = (int)*(char *)(iVar2 + 0xe);
  }
  FUN_8028688c();
  return;
}

