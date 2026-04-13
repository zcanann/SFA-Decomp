// Function: FUN_801881c8
// Entry: 801881c8
// Size: 568 bytes

/* WARNING: Removing unreachable block (ram,0x80188204) */

void FUN_801881c8(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 uint param_9)

{
  byte bVar1;
  uint uVar2;
  undefined2 *puVar3;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  int iVar4;
  int iVar5;
  undefined8 uVar6;
  uint auStack_18 [3];
  
  iVar5 = *(int *)(param_9 + 0xb8);
  iVar4 = *(int *)(param_9 + 0x4c);
  bVar1 = *(byte *)(iVar5 + 10);
  if (bVar1 == 1) {
    FUN_80035ea4(param_9);
    FUN_80035ff8(param_9);
    *(byte *)(param_9 + 0xaf) = *(byte *)(param_9 + 0xaf) | 8;
    *(undefined *)(iVar5 + 10) = 2;
    *(float *)(iVar5 + 0xc) = FLOAT_803e47dc;
    *(undefined4 *)(param_9 + 0xc) = *(undefined4 *)(iVar4 + 8);
    *(undefined4 *)(param_9 + 0x10) = *(undefined4 *)(iVar4 + 0xc);
    *(undefined4 *)(param_9 + 0x14) = *(undefined4 *)(iVar4 + 0x10);
  }
  else if (bVar1 == 0) {
    (**(code **)(*DAT_803dd740 + 8))(param_9,iVar5);
    iVar4 = FUN_80036974(param_9,(undefined4 *)0x0,(int *)0x0,auStack_18);
    if (iVar4 != 0) {
      (**(code **)(*DAT_803dd740 + 0x30))(param_9,iVar5);
      FUN_8000bb38(param_9,0x48);
      FUN_80035a6c(param_9,0x28);
      uVar6 = FUN_80035eec(param_9,5,4,0);
      uVar2 = FUN_8002e144();
      if ((uVar2 & 0xff) != 0) {
        puVar3 = FUN_8002becc(0x24,0x253);
        *(undefined4 *)(puVar3 + 4) = *(undefined4 *)(param_9 + 0xc);
        *(undefined4 *)(puVar3 + 6) = *(undefined4 *)(param_9 + 0x10);
        *(undefined4 *)(puVar3 + 8) = *(undefined4 *)(param_9 + 0x14);
        FUN_8002e088(uVar6,param_2,param_3,param_4,param_5,param_6,param_7,param_8,puVar3,5,
                     *(undefined *)(param_9 + 0xac),0xffffffff,*(uint **)(param_9 + 0x30),in_r8,
                     in_r9,in_r10);
      }
      (**(code **)(*DAT_803dd708 + 8))(param_9,0x355,0,0,0xffffffff,0);
      (**(code **)(*DAT_803dd708 + 8))(param_9,0x352,0,0,0xffffffff,0);
      *(undefined *)(iVar5 + 10) = 1;
    }
  }
  else if (((bVar1 < 3) &&
           (*(float *)(iVar5 + 0xc) = *(float *)(iVar5 + 0xc) + FLOAT_803dc074,
           FLOAT_803e47e0 < *(float *)(iVar5 + 0xc))) &&
          (iVar4 = FUN_8005a288((double)(*(float *)(param_9 + 0xa8) * *(float *)(param_9 + 8)),
                                (float *)(param_9 + 0xc)), iVar4 == 0)) {
    FUN_80036018(param_9);
    *(byte *)(param_9 + 0xaf) = *(byte *)(param_9 + 0xaf) & 0xf7;
    *(undefined *)(iVar5 + 10) = 0;
  }
  return;
}

