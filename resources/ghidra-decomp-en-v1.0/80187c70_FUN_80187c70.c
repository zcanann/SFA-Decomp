// Function: FUN_80187c70
// Entry: 80187c70
// Size: 568 bytes

/* WARNING: Removing unreachable block (ram,0x80187cac) */

void FUN_80187c70(int param_1)

{
  byte bVar1;
  char cVar2;
  int iVar3;
  int iVar4;
  undefined auStack24 [12];
  
  iVar4 = *(int *)(param_1 + 0xb8);
  iVar3 = *(int *)(param_1 + 0x4c);
  bVar1 = *(byte *)(iVar4 + 10);
  if (bVar1 == 1) {
    FUN_80035dac();
    FUN_80035f00(param_1);
    *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) | 8;
    *(undefined *)(iVar4 + 10) = 2;
    *(float *)(iVar4 + 0xc) = FLOAT_803e3b44;
    *(undefined4 *)(param_1 + 0xc) = *(undefined4 *)(iVar3 + 8);
    *(undefined4 *)(param_1 + 0x10) = *(undefined4 *)(iVar3 + 0xc);
    *(undefined4 *)(param_1 + 0x14) = *(undefined4 *)(iVar3 + 0x10);
  }
  else if (bVar1 == 0) {
    (**(code **)(*DAT_803dcac0 + 8))(param_1,iVar4);
    iVar3 = FUN_8003687c(param_1,0,0,auStack24);
    if (iVar3 != 0) {
      (**(code **)(*DAT_803dcac0 + 0x30))(param_1,iVar4);
      FUN_8000bb18(param_1,0x48);
      FUN_80035974(param_1,0x28);
      FUN_80035df4(param_1,5,4,0);
      cVar2 = FUN_8002e04c();
      if (cVar2 != '\0') {
        iVar3 = FUN_8002bdf4(0x24,0x253);
        *(undefined4 *)(iVar3 + 8) = *(undefined4 *)(param_1 + 0xc);
        *(undefined4 *)(iVar3 + 0xc) = *(undefined4 *)(param_1 + 0x10);
        *(undefined4 *)(iVar3 + 0x10) = *(undefined4 *)(param_1 + 0x14);
        FUN_8002df90(iVar3,5,(int)*(char *)(param_1 + 0xac),0xffffffff,
                     *(undefined4 *)(param_1 + 0x30));
      }
      (**(code **)(*DAT_803dca88 + 8))(param_1,0x355,0,0,0xffffffff,0);
      (**(code **)(*DAT_803dca88 + 8))(param_1,0x352,0,0,0xffffffff,0);
      *(undefined *)(iVar4 + 10) = 1;
    }
  }
  else if (((bVar1 < 3) &&
           (*(float *)(iVar4 + 0xc) = *(float *)(iVar4 + 0xc) + FLOAT_803db414,
           FLOAT_803e3b48 < *(float *)(iVar4 + 0xc))) &&
          (iVar3 = FUN_8005a10c((double)(*(float *)(param_1 + 0xa8) * *(float *)(param_1 + 8)),
                                param_1 + 0xc), iVar3 == 0)) {
    FUN_80035f20(param_1);
    *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) & 0xf7;
    *(undefined *)(iVar4 + 10) = 0;
  }
  return;
}

