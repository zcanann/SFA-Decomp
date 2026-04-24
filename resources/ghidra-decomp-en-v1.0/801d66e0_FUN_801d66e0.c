// Function: FUN_801d66e0
// Entry: 801d66e0
// Size: 564 bytes

/* WARNING: Removing unreachable block (ram,0x801d6738) */

void FUN_801d66e0(short *param_1,int param_2)

{
  byte bVar1;
  uint uVar2;
  int iVar3;
  int iVar4;
  undefined4 local_28 [2];
  undefined4 local_20;
  uint uStack28;
  
  iVar4 = *(int *)(param_1 + 0x5c);
  local_28[0] = DAT_803e5410;
  *param_1 = (ushort)*(byte *)(param_2 + 0x19) << 8;
  bVar1 = *(byte *)(param_2 + 0x18);
  if (bVar1 == 2) {
    *(undefined *)(iVar4 + 0x624) = 0;
    uVar2 = FUN_800221a0(1000,2000);
    *(float *)(iVar4 + 0x630) =
         (float)((double)CONCAT44(0x43300000,uVar2 ^ 0x80000000) - DOUBLE_803e5428);
  }
  else if (bVar1 < 2) {
    if (bVar1 == 0) {
      *(undefined *)(iVar4 + 0x624) = 0;
      uVar2 = FUN_800221a0(1000,2000);
      *(float *)(iVar4 + 0x630) =
           (float)((double)CONCAT44(0x43300000,uVar2 ^ 0x80000000) - DOUBLE_803e5428);
    }
    else {
      *(undefined *)(iVar4 + 0x627) = 2;
      *(undefined *)(iVar4 + 0x624) = 0xc;
    }
  }
  else if (bVar1 < 4) {
    *(undefined *)(iVar4 + 0x624) = 0;
    uVar2 = FUN_800221a0(1000,2000);
    *(float *)(iVar4 + 0x630) =
         (float)((double)CONCAT44(0x43300000,uVar2 ^ 0x80000000) - DOUBLE_803e5428);
  }
  uStack28 = (uint)*(ushort *)(param_2 + 0x1c);
  local_20 = 0x43300000;
  *(float *)(param_1 + 4) =
       *(float *)(*(int *)(param_1 + 0x28) + 4) *
       ((float)((double)CONCAT44(0x43300000,uStack28) - DOUBLE_803e5440) / FLOAT_803e545c);
  FUN_8002b588(param_1);
  FUN_8002cec0((double)*(float *)(param_1 + 4));
  iVar3 = iVar4 + 0x644;
  (**(code **)(*DAT_803dcaa8 + 4))(iVar3,3,0xa3,0);
  (**(code **)(*DAT_803dcaa8 + 0xc))(iVar3,4,&DAT_80326ef8,&DAT_80326f28,local_28);
  (**(code **)(*DAT_803dcaa8 + 0x20))(param_1,iVar3);
  *(code **)(param_1 + 0x5e) = FUN_801d5d48;
  FUN_80114f64(param_1,iVar4,0xffffdc72,0x2aaa,3);
  FUN_8011507c(iVar4,400,0x78);
  FUN_80037200(param_1,0x4d);
  return;
}

