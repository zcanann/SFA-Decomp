// Function: FUN_801e20f4
// Entry: 801e20f4
// Size: 184 bytes

void FUN_801e20f4(int param_1)

{
  byte bVar1;
  int iVar2;
  undefined auStack40 [6];
  undefined2 local_22;
  float local_20;
  float local_1c;
  float local_18;
  float local_14;
  
  iVar2 = *(int *)(param_1 + 0xb8);
  if ((*(char *)(iVar2 + 0x85) != '\0') && (*(int *)(iVar2 + 0x4c) != 0)) {
    local_20 = FLOAT_803e5738;
    local_22 = 0xc0a;
    local_1c = FLOAT_803e56cc;
    local_18 = FLOAT_803e56f0;
    local_14 = FLOAT_803e56c8;
    for (bVar1 = 0; bVar1 < DAT_803db410; bVar1 = bVar1 + 1) {
      (**(code **)(*DAT_803dca88 + 8))(*(undefined4 *)(iVar2 + 0x4c),0x7aa,auStack40,2,0xffffffff,0)
      ;
    }
  }
  return;
}

