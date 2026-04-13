// Function: FUN_801fe7a4
// Entry: 801fe7a4
// Size: 432 bytes

void FUN_801fe7a4(int param_1)

{
  uint uVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  ushort *local_38;
  uint local_34;
  uint local_30;
  ushort local_2c [4];
  float local_24;
  float local_20;
  float local_1c;
  float local_18;
  
  local_30 = 0;
  local_34 = 0;
  iVar4 = *(int *)(param_1 + 0xb8);
  iVar3 = *(int *)(param_1 + 0x4c);
LAB_801fe91c:
  while( true ) {
    while( true ) {
      do {
        iVar2 = FUN_800375e4(param_1,&local_30,(uint *)&local_38,&local_34);
        if (iVar2 == 0) {
          return;
        }
      } while (local_30 != 0x11);
      if (local_34 != 0x12) break;
      if ((*(byte *)(iVar4 + 0x119) & 0x20) == 0) {
        FUN_8003709c(param_1,0x24);
      }
      FUN_80035ff8(param_1);
      *(undefined *)(iVar4 + 0x118) = 0xb;
      *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) | 8;
    }
    if ((int)local_34 < 0x12) {
      if (local_34 != 0x10) goto code_r0x801fe7fc;
      goto LAB_801fe8ac;
    }
    if (local_34 == 0x14) break;
    if ((int)local_34 < 0x14) {
      FUN_800201ac((int)*(short *)(iVar3 + 0x1e),1);
      uVar1 = (uint)*(short *)(iVar3 + 0x2c);
      if (0 < (int)uVar1) {
        FUN_80020000(uVar1);
      }
      FUN_8002cf80(param_1);
      *(ushort *)(param_1 + 6) = *(ushort *)(param_1 + 6) | 0x4000;
      FUN_8003709c(param_1,0x24);
    }
  }
  goto LAB_801fe8b8;
code_r0x801fe7fc:
  if (0xf < (int)local_34) {
    *(undefined4 *)(param_1 + 0x24) = *(undefined4 *)(iVar4 + 0x10c);
    *(undefined4 *)(param_1 + 0x28) = *(undefined4 *)(iVar4 + 0x110);
    *(float *)(param_1 + 0x2c) = -*(float *)(iVar4 + 0x114);
    local_20 = FLOAT_803e6e60;
    local_1c = FLOAT_803e6e60;
    local_18 = FLOAT_803e6e60;
    local_24 = FLOAT_803e6e64;
    local_2c[2] = 0;
    local_2c[1] = 0;
    local_2c[0] = *local_38;
    FUN_80021b8c(local_2c,(float *)(param_1 + 0x24));
LAB_801fe8ac:
    FUN_800372f8(param_1,0x24);
LAB_801fe8b8:
    *(undefined *)(iVar4 + 0x118) = 5;
    *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) & 0xf7;
    FUN_80036018(param_1);
  }
  goto LAB_801fe91c;
}

