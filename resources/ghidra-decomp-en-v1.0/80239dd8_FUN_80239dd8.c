// Function: FUN_80239dd8
// Entry: 80239dd8
// Size: 212 bytes

void FUN_80239dd8(undefined4 param_1,int param_2)

{
  char cVar4;
  int iVar1;
  int iVar2;
  undefined4 uVar3;
  float local_18 [3];
  
  local_18[0] = FLOAT_803e7490;
  cVar4 = FUN_8002e04c();
  if ((cVar4 != '\0') && (iVar1 = FUN_800380e0(param_1,0x7e5,local_18), iVar1 != 0)) {
    iVar2 = FUN_8002bdf4(0x24,0x608);
    *(undefined4 *)(iVar2 + 8) = *(undefined4 *)(iVar1 + 0xc);
    *(undefined4 *)(iVar2 + 0xc) = *(undefined4 *)(iVar1 + 0x10);
    *(undefined4 *)(iVar2 + 0x10) = *(undefined4 *)(iVar1 + 0x14);
    *(undefined *)(iVar2 + 4) = 1;
    *(undefined *)(iVar2 + 5) = 1;
    uVar3 = FUN_8002b5a0(param_1);
    *(undefined4 *)(param_2 + 0x10) = uVar3;
    if (*(int *)(param_2 + 0x10) != 0) {
      *(undefined *)(*(int *)(param_2 + 0x10) + 0x36) = 0xff;
      *(undefined *)(*(int *)(param_2 + 0x10) + 0x37) = 0xff;
      *(undefined4 *)(param_2 + 0x90) = 300;
    }
  }
  return;
}

