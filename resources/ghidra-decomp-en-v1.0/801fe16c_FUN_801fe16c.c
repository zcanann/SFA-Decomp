// Function: FUN_801fe16c
// Entry: 801fe16c
// Size: 432 bytes

void FUN_801fe16c(int param_1)

{
  int iVar1;
  int iVar2;
  int iVar3;
  undefined2 *local_38;
  int local_34;
  int local_30;
  undefined2 local_2c;
  undefined2 local_2a;
  undefined2 local_28;
  float local_24;
  float local_20;
  float local_1c;
  float local_18;
  
  local_30 = 0;
  local_34 = 0;
  iVar3 = *(int *)(param_1 + 0xb8);
  iVar2 = *(int *)(param_1 + 0x4c);
LAB_801fe2e4:
  while( true ) {
    while( true ) {
      do {
        iVar1 = FUN_800374ec(param_1,&local_30,&local_38,&local_34);
        if (iVar1 == 0) {
          return;
        }
      } while (local_30 != 0x11);
      if (local_34 != 0x12) break;
      if ((*(byte *)(iVar3 + 0x119) & 0x20) == 0) {
        FUN_80036fa4(param_1,0x24);
      }
      FUN_80035f00(param_1);
      *(undefined *)(iVar3 + 0x118) = 0xb;
      *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) | 8;
    }
    if (local_34 < 0x12) {
      if (local_34 != 0x10) goto code_r0x801fe1c4;
      goto LAB_801fe274;
    }
    if (local_34 == 0x14) break;
    if (local_34 < 0x14) {
      FUN_800200e8((int)*(short *)(iVar2 + 0x1e),1);
      if (0 < *(short *)(iVar2 + 0x2c)) {
        FUN_8001ff3c();
      }
      FUN_8002ce88(param_1);
      *(ushort *)(param_1 + 6) = *(ushort *)(param_1 + 6) | 0x4000;
      FUN_80036fa4(param_1,0x24);
    }
  }
  goto LAB_801fe280;
code_r0x801fe1c4:
  if (0xf < local_34) {
    *(undefined4 *)(param_1 + 0x24) = *(undefined4 *)(iVar3 + 0x10c);
    *(undefined4 *)(param_1 + 0x28) = *(undefined4 *)(iVar3 + 0x110);
    *(float *)(param_1 + 0x2c) = -*(float *)(iVar3 + 0x114);
    local_20 = FLOAT_803e61c8;
    local_1c = FLOAT_803e61c8;
    local_18 = FLOAT_803e61c8;
    local_24 = FLOAT_803e61cc;
    local_28 = 0;
    local_2a = 0;
    local_2c = *local_38;
    FUN_80021ac8(&local_2c,param_1 + 0x24);
LAB_801fe274:
    FUN_80037200(param_1,0x24);
LAB_801fe280:
    *(undefined *)(iVar3 + 0x118) = 5;
    *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) & 0xf7;
    FUN_80035f20(param_1);
  }
  goto LAB_801fe2e4;
}

