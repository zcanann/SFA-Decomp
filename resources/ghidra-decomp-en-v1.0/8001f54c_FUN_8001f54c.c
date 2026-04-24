// Function: FUN_8001f54c
// Entry: 8001f54c
// Size: 300 bytes

void FUN_8001f54c(int param_1)

{
  undefined4 uVar1;
  undefined auStack24 [20];
  
  switch(*(undefined *)(param_1 + 1)) {
  case 0:
    uVar1 = FUN_80049144(*(undefined4 *)(param_1 + 4),0);
    **(undefined4 **)(param_1 + 8) = uVar1;
    break;
  case 1:
    FUN_8004908c(*(undefined4 *)(param_1 + 4),*(undefined4 *)(param_1 + 8));
    break;
  case 2:
    FUN_80048f48(*(undefined4 *)(param_1 + 4),*(undefined4 *)(param_1 + 8),
                 *(undefined4 *)(param_1 + 0x10),*(undefined4 *)(param_1 + 0xc));
    break;
  case 3:
    uVar1 = FUN_800544a4(*(undefined4 *)(param_1 + 4),0);
    **(undefined4 **)(param_1 + 8) = uVar1;
    break;
  case 4:
    uVar1 = FUN_8002d55c(*(undefined4 *)(param_1 + 0x18),*(undefined4 *)(param_1 + 0x1c),
                         *(undefined4 *)(param_1 + 0x24),*(undefined4 *)(param_1 + 0x20),
                         *(undefined4 *)(param_1 + 0x14),*(undefined4 *)(param_1 + 0x28));
    **(undefined4 **)(param_1 + 8) = uVar1;
    break;
  case 5:
    uVar1 = FUN_80013ec8(*(uint *)(param_1 + 4) & 0xffff,*(uint *)(param_1 + 0xc) & 0xffff);
    **(undefined4 **)(param_1 + 8) = uVar1;
    break;
  case 6:
    uVar1 = FUN_8002969c(*(undefined4 *)(param_1 + 4),*(undefined4 *)(param_1 + 0xc),auStack24);
    **(undefined4 **)(param_1 + 8) = uVar1;
    break;
  case 7:
    uVar1 = FUN_80028204(*(undefined4 *)(param_1 + 0x24),(int)(short)*(undefined4 *)(param_1 + 4),
                         (int)(short)*(undefined4 *)(param_1 + 0xc),*(undefined4 *)(param_1 + 0x20))
    ;
    **(undefined4 **)(param_1 + 8) = uVar1;
  }
  return;
}

